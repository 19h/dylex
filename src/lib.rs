//! dylex - A high-performance dyld shared cache extractor.
//!
//! This library provides functionality for extracting Mach-O images from
//! Apple's dyld shared cache. The extraction process reverses the optimizations
//! applied by the SharedCacheBuilder to produce standalone dylib files.
//!
//! # Features
//!
//! - Fast memory-mapped file I/O
//! - Support for split caches (iOS 15+, macOS 12+)
//! - Slide info processing (v2, v3, v5)
//! - LINKEDIT optimization
//! - Stub fixing
//! - ObjC metadata restoration
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use dylex::{DyldContext, extract_image};
//!
//! fn main() -> dylex::Result<()> {
//!     let cache = Arc::new(DyldContext::open("/path/to/dyld_shared_cache")?);
//!
//!     // Find an image
//!     let image = cache.find_image("UIKit").expect("UIKit not found");
//!
//!     // Extract it
//!     extract_image(&cache, &image.path, "output/UIKit")?;
//!
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod arm64;
pub mod converter;
pub mod dyld;
pub mod error;
pub mod macho;

// Re-export main types
pub use dyld::{DyldContext, ImageEntry, MappingEntry};
pub use error::{Error, Result};
pub use macho::MachOContext;

use std::path::Path;
use std::sync::Arc;

use converter::{
    fix_objc, fix_stubs, optimize_linkedit, optimize_offsets, process_slide_info, write_macho,
    ExtractionContext,
};

/// Extracts a single image from the cache.
///
/// # Arguments
///
/// * `cache` - The dyld cache context
/// * `image_path` - Path of the image in the cache (e.g., "/usr/lib/libc.dylib")
/// * `output_path` - Path where the extracted dylib will be written
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if extraction fails.
pub fn extract_image<P: AsRef<Path>>(
    cache: &Arc<DyldContext>,
    image_path: &str,
    output_path: P,
) -> Result<()> {
    extract_image_with_options(cache, image_path, output_path, ExtractionOptions::default())
}

/// Options for image extraction.
#[derive(Debug, Clone)]
pub struct ExtractionOptions {
    /// Verbosity level (0=quiet, 1=warnings, 2=info, 3=debug)
    pub verbosity: u8,
    /// Skip slide info processing
    pub skip_slide_info: bool,
    /// Skip LINKEDIT optimization
    pub skip_linkedit: bool,
    /// Skip stub fixing
    pub skip_stubs: bool,
    /// Skip ObjC fixing
    pub skip_objc: bool,
}

impl Default for ExtractionOptions {
    fn default() -> Self {
        Self {
            verbosity: 1,
            skip_slide_info: false,
            skip_linkedit: false,
            skip_stubs: false,
            skip_objc: false,
        }
    }
}

/// Extracts a single image from the cache with custom options.
pub fn extract_image_with_options<P: AsRef<Path>>(
    cache: &Arc<DyldContext>,
    image_path: &str,
    output_path: P,
    options: ExtractionOptions,
) -> Result<()> {
    use macho::MachHeader64;
    use zerocopy::FromBytes;

    // Find the image
    let image = cache
        .find_image(image_path)
        .ok_or_else(|| Error::ImageNotFound {
            name: image_path.to_string(),
        })?;

    // Get the header data first to determine full image size
    let header_data = cache.data_at_addr(image.address, MachHeader64::SIZE)?;
    let header = MachHeader64::read_from_prefix(header_data)
        .map_err(|_| Error::InvalidMachoMagic(0))?
        .0;

    // Calculate how much data we need: header + all load commands
    let header_and_cmds_size = MachHeader64::SIZE + header.sizeofcmds as usize;

    // Read header + load commands to parse segments
    let header_and_cmds = cache.data_at_addr(image.address, header_and_cmds_size)?;

    // Parse load commands to find all segment info
    // We need to build a complete Mach-O buffer that contains all segment data
    // positioned at their file offsets as specified in the load commands
    #[derive(Clone)]
    struct SegmentToCopy {
        vmaddr: u64,
        fileoff: u64,
        filesize: u64,
    }
    let mut segments: Vec<SegmentToCopy> = Vec::new();
    let mut max_file_end: u64 = header_and_cmds_size as u64;

    let mut offset = MachHeader64::SIZE;
    for _ in 0..header.ncmds {
        if offset + 8 > header_and_cmds.len() {
            break;
        }
        let cmd = u32::from_le_bytes([
            header_and_cmds[offset],
            header_and_cmds[offset + 1],
            header_and_cmds[offset + 2],
            header_and_cmds[offset + 3],
        ]);
        let cmdsize = u32::from_le_bytes([
            header_and_cmds[offset + 4],
            header_and_cmds[offset + 5],
            header_and_cmds[offset + 6],
            header_and_cmds[offset + 7],
        ]);

        // LC_SEGMENT_64 = 0x19
        if cmd == 0x19 && offset + 72 <= header_and_cmds.len() {
            let vmaddr = u64::from_le_bytes([
                header_and_cmds[offset + 24],
                header_and_cmds[offset + 25],
                header_and_cmds[offset + 26],
                header_and_cmds[offset + 27],
                header_and_cmds[offset + 28],
                header_and_cmds[offset + 29],
                header_and_cmds[offset + 30],
                header_and_cmds[offset + 31],
            ]);
            let fileoff = u64::from_le_bytes([
                header_and_cmds[offset + 40],
                header_and_cmds[offset + 41],
                header_and_cmds[offset + 42],
                header_and_cmds[offset + 43],
                header_and_cmds[offset + 44],
                header_and_cmds[offset + 45],
                header_and_cmds[offset + 46],
                header_and_cmds[offset + 47],
            ]);
            let filesize = u64::from_le_bytes([
                header_and_cmds[offset + 48],
                header_and_cmds[offset + 49],
                header_and_cmds[offset + 50],
                header_and_cmds[offset + 51],
                header_and_cmds[offset + 52],
                header_and_cmds[offset + 53],
                header_and_cmds[offset + 54],
                header_and_cmds[offset + 55],
            ]);

            if filesize > 0 {
                segments.push(SegmentToCopy {
                    vmaddr,
                    fileoff,
                    filesize,
                });
            }

            let seg_end = fileoff + filesize;
            if seg_end > max_file_end {
                max_file_end = seg_end;
            }
        }

        offset += cmdsize as usize;
    }

    // Allocate buffer for the complete Mach-O
    let mut macho_buffer = vec![0u8; max_file_end as usize];

    // Copy header and load commands
    macho_buffer[..header_and_cmds_size].copy_from_slice(header_and_cmds);

    // Copy each segment's data from the cache
    for seg in &segments {
        // The segment data is at vmaddr in the cache, but goes to fileoff in our buffer
        if let Ok(seg_data) = cache.data_at_addr(seg.vmaddr, seg.filesize as usize) {
            let dst_start = seg.fileoff as usize;
            let dst_end = dst_start + seg.filesize as usize;
            if dst_end <= macho_buffer.len() {
                macho_buffer[dst_start..dst_end].copy_from_slice(seg_data);
            }
        }
    }

    // Create Mach-O context with the full buffer
    let macho_offset =
        cache
            .addr_to_offset(image.address)
            .ok_or_else(|| Error::AddressNotFound {
                addr: image.address,
            })?;
    let macho = MachOContext::new(&macho_buffer, macho_offset as usize)?;

    // Create extraction context
    let mut ctx =
        ExtractionContext::new(Arc::clone(cache), macho, image.path.clone(), image.address)
            .with_verbosity(options.verbosity);

    // Run extraction pipeline
    if !options.skip_slide_info {
        process_slide_info(&mut ctx)?;
    }

    if !options.skip_linkedit {
        optimize_linkedit(&mut ctx)?;
    }

    if !options.skip_stubs {
        fix_stubs(&mut ctx)?;
    }

    if !options.skip_objc {
        fix_objc(&mut ctx)?;
    }

    // Optimize offsets and write output
    let procedures = optimize_offsets(&mut ctx)?;
    write_macho(&ctx, &procedures, output_path)?;

    Ok(())
}

/// Lists all images in the cache.
pub fn list_images(cache: &DyldContext) -> impl Iterator<Item = &ImageEntry> {
    cache.iter_images()
}

/// Finds images matching a filter.
pub fn find_images<'a>(
    cache: &'a DyldContext,
    filter: &'a str,
) -> impl Iterator<Item = &'a ImageEntry> {
    cache
        .iter_images()
        .filter(move |img| img.matches_filter(filter))
}
