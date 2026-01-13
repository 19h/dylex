//! Segment merger for creating self-contained dylibs.
//!
//! This module merges multiple Mach-O images from the dyld shared cache into
//! a single self-contained dylib. All external references are resolved to
//! point to the merged code/data.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

use tracing::{debug, info, warn};
use zerocopy::FromBytes;

use super::stub::{StubFormat, detect_stub_format, generate_stub_auth};
use crate::arm64;
use crate::dyld::{
    DyldCacheSlideInfo2, DyldCacheSlideInfo3, DyldCacheSlideInfo5, DyldContext, SlidePointer3,
    SlidePointer5,
};
use crate::error::{Error, Result};
use crate::macho::*;

/// Page size for alignment (16KB for arm64)
const PAGE_SIZE: u64 = 0x4000;

/// Aligns a value up to the given alignment.
#[inline]
fn align_up(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}

/// Tracks the mapping of an image's segments to the merged output.
#[derive(Debug, Clone)]
pub struct ImageSegmentMapping {
    /// Original image path
    pub path: String,
    /// Original vmaddr base (typically __TEXT vmaddr)
    pub original_base: u64,
    /// New vmaddr base in merged output
    pub merged_base: u64,
    /// Size of the image's address space
    pub size: u64,
    /// Mapping of segment names to (original_vmaddr, merged_vmaddr, size)
    pub segments: HashMap<String, (u64, u64, u64)>,
}

impl ImageSegmentMapping {
    /// Checks if an address falls within this image's original segment ranges.
    pub fn contains_original(&self, addr: u64) -> bool {
        self.segments
            .values()
            .any(|(orig, _merged, size)| addr >= *orig && addr < *orig + *size)
    }

    /// Translates an original address to the merged address.
    pub fn translate(&self, addr: u64) -> Option<u64> {
        for (orig, merged, size) in self.segments.values() {
            if addr >= *orig && addr < *orig + *size {
                return Some(merged + (addr - *orig));
            }
        }
        None
    }
}

/// Information about a dependency segment to add to load commands.
#[derive(Debug, Clone)]
pub struct DependencySegment {
    /// Segment name (e.g., "__DEP_0_TEXT")
    pub name: String,
    /// Virtual memory address in merged output
    pub vmaddr: u64,
    /// Virtual memory size
    pub vmsize: u64,
    /// File offset in merged output
    pub fileoff: u64,
    /// File size
    pub filesize: u64,
    /// Maximum protection
    pub maxprot: u32,
    /// Initial protection
    pub initprot: u32,
}

/// Information about a shared cache region to include.
#[derive(Debug, Clone)]
pub struct SharedRegion {
    /// Region name (e.g., "__SHARED_DATA")
    pub name: String,
    /// Original virtual address in cache
    pub orig_vmaddr: u64,
    /// Size of the region
    pub size: u64,
    /// File offset in merged output
    pub fileoff: u64,
    /// Protection flags
    pub prot: u32,
}

/// Context for merging multiple images into one.
pub struct MergeContext {
    /// The dyld cache
    pub cache: Arc<DyldContext>,
    /// Primary image path
    pub primary_path: String,
    /// Merged image buffer
    pub data: Vec<u8>,
    /// Mappings for each merged image
    pub mappings: Vec<ImageSegmentMapping>,
    /// Set of image paths that have been processed
    pub processed: HashSet<String>,
    /// Maximum merge depth
    pub max_depth: usize,
    /// Verbosity level
    pub verbosity: u8,
    /// Dependency segments to add as load commands
    pub dependency_segments: Vec<DependencySegment>,
    /// Shared cache regions included in the merge
    pub shared_regions: Vec<SharedRegion>,
}

impl MergeContext {
    /// Creates a new merge context.
    pub fn new(cache: Arc<DyldContext>, primary_path: String, max_depth: usize) -> Self {
        Self {
            cache,
            primary_path,
            data: Vec::new(),
            mappings: Vec::new(),
            processed: HashSet::new(),
            max_depth,
            verbosity: 1,
            dependency_segments: Vec::new(),
            shared_regions: Vec::new(),
        }
    }

    /// Sets verbosity level.
    pub fn with_verbosity(mut self, verbosity: u8) -> Self {
        self.verbosity = verbosity;
        self
    }

    /// Translates an address from any original image to the merged address space.
    pub fn translate_addr(&self, addr: u64) -> Option<u64> {
        for mapping in &self.mappings {
            if let Some(translated) = mapping.translate(addr) {
                return Some(translated);
            }
        }
        None
    }

    /// Checks if an address belongs to any of the merged images.
    pub fn is_merged_addr(&self, addr: u64) -> bool {
        self.mappings.iter().any(|m| m.contains_original(addr))
    }

    /// Checks if an address is in a shared region we've included.
    pub fn is_in_shared_region(&self, addr: u64) -> bool {
        self.shared_regions
            .iter()
            .any(|r| addr >= r.orig_vmaddr && addr < r.orig_vmaddr + r.size)
    }

    /// Gets the file offset for an address in a shared region.
    pub fn shared_region_offset(&self, addr: u64) -> Option<u64> {
        for region in &self.shared_regions {
            if addr >= region.orig_vmaddr && addr < region.orig_vmaddr + region.size {
                return Some(region.fileoff + (addr - region.orig_vmaddr));
            }
        }
        None
    }
}

/// Represents an image's address range in the cache.
#[derive(Debug, Clone)]
struct ImageAddressRange {
    path: String,
    start: u64,
    end: u64,
}

/// Builds a sorted list of image address ranges for fast lookup.
fn build_image_address_map(cache: &DyldContext) -> Vec<ImageAddressRange> {
    let mut ranges = Vec::new();

    for image in cache.iter_images() {
        // Get image's segment ranges
        if let Ok((start, end)) = get_image_address_range(cache, &image.path) {
            ranges.push(ImageAddressRange {
                path: image.path.clone(),
                start,
                end,
            });
        }
    }

    // Sort by start address for binary search
    ranges.sort_by_key(|r| r.start);
    ranges
}

/// Gets the address range (min vmaddr, max vmaddr+vmsize) of an image.
fn get_image_address_range(cache: &DyldContext, image_path: &str) -> Result<(u64, u64)> {
    let image = cache
        .find_image(image_path)
        .ok_or_else(|| Error::ImageNotFound {
            name: image_path.to_string(),
        })?;

    let header_data = cache.data_at_addr(image.address, MachHeader64::SIZE)?;
    let header = MachHeader64::read_from_prefix(header_data)
        .map_err(|_| Error::InvalidMachoMagic(0))?
        .0;

    let header_and_cmds_size = MachHeader64::SIZE + header.sizeofcmds as usize;
    let header_and_cmds = cache.data_at_addr(image.address, header_and_cmds_size)?;

    let mut min_addr = u64::MAX;
    let mut max_addr = 0u64;

    let mut offset = MachHeader64::SIZE;
    for _ in 0..header.ncmds {
        if offset + 8 > header_and_cmds.len() {
            break;
        }
        // Optimized: single unaligned loads
        let cmd = crate::util::read_u32_le(&header_and_cmds[offset..]);
        let cmdsize = crate::util::read_u32_le(&header_and_cmds[offset + 4..]) as usize;

        if cmd == LC_SEGMENT_64 && offset + SegmentCommand64::SIZE <= header_and_cmds.len() {
            let vmaddr = crate::util::read_u64_le(&header_and_cmds[offset + 24..]);
            let vmsize = crate::util::read_u64_le(&header_and_cmds[offset + 32..]);

            if vmsize > 0 {
                min_addr = min_addr.min(vmaddr);
                max_addr = max_addr.max(vmaddr + vmsize);
            }
        }
        offset += cmdsize;
    }

    if min_addr == u64::MAX {
        min_addr = image.address;
        max_addr = image.address + 0x1000; // Default to 1 page
    }

    Ok((min_addr, max_addr))
}

/// Finds which image (if any) contains the given address.
fn find_image_for_address<'a>(addr: u64, ranges: &'a [ImageAddressRange]) -> Option<&'a str> {
    // Binary search for the image that might contain this address
    let idx = ranges.partition_point(|r| r.start <= addr);
    if idx == 0 {
        return None;
    }

    let range = &ranges[idx - 1];
    if addr >= range.start && addr < range.end {
        Some(&range.path)
    } else {
        None
    }
}

/// Scans all pointers in an image and returns the set of referenced image paths.
fn scan_image_pointers(
    cache: &DyldContext,
    image_path: &str,
    ranges: &[ImageAddressRange],
    verbosity: u8,
) -> HashSet<String> {
    let mut referenced = HashSet::new();

    let image = match cache.find_image(image_path) {
        Some(img) => img,
        None => return referenced,
    };

    let header_data = match cache.data_at_addr(image.address, MachHeader64::SIZE) {
        Ok(data) => data,
        Err(_) => return referenced,
    };

    let header = match MachHeader64::read_from_prefix(header_data) {
        Ok((h, _)) => h,
        Err(_) => return referenced,
    };

    let header_and_cmds_size = MachHeader64::SIZE + header.sizeofcmds as usize;
    let header_and_cmds = match cache.data_at_addr(image.address, header_and_cmds_size) {
        Ok(data) => data,
        Err(_) => return referenced,
    };

    let mut sections_scanned = 0usize;
    let mut pointers_scanned = 0usize;

    // Parse all segments and their sections
    let mut offset = MachHeader64::SIZE;
    for _ in 0..header.ncmds {
        if offset + 8 > header_and_cmds.len() {
            break;
        }
        let cmd = u32::from_le_bytes(header_and_cmds[offset..offset + 4].try_into().unwrap());
        let cmdsize =
            u32::from_le_bytes(header_and_cmds[offset + 4..offset + 8].try_into().unwrap())
                as usize;

        if cmd == LC_SEGMENT_64 && offset + SegmentCommand64::SIZE <= header_and_cmds.len() {
            let nsects = u32::from_le_bytes(
                header_and_cmds[offset + 64..offset + 68]
                    .try_into()
                    .unwrap(),
            );

            // Process each section in this segment
            let mut sect_offset = offset + SegmentCommand64::SIZE;
            for _ in 0..nsects {
                if sect_offset + Section64::SIZE > header_and_cmds.len() {
                    break;
                }

                let sect = match Section64::read_from_prefix(&header_and_cmds[sect_offset..]) {
                    Ok((s, _)) => s,
                    Err(_) => {
                        sect_offset += Section64::SIZE;
                        continue;
                    }
                };

                // Check if this section contains pointers
                if section_has_pointers(sect.name(), sect.segment_name()) {
                    // Read section data and scan for pointers
                    if let Ok(sect_data) = cache.data_at_addr(sect.addr, sect.size as usize) {
                        sections_scanned += 1;
                        let before = referenced.len();
                        scan_section_pointers(sect_data, &sect, ranges, &mut referenced);
                        pointers_scanned += sect_data.len() / 8;
                        if verbosity >= 3 {
                            debug!(
                                "  Section {}.{} @ 0x{:x} ({} bytes) -> {} new refs",
                                sect.segment_name(),
                                sect.name(),
                                sect.addr,
                                sect.size,
                                referenced.len() - before
                            );
                        }
                    }
                }

                sect_offset += Section64::SIZE;
            }
        }
        offset += cmdsize;
    }

    if verbosity >= 2 {
        debug!(
            "Scanned {} sections, {} pointers in {} - found {} referenced images",
            sections_scanned,
            pointers_scanned,
            image_path,
            referenced.len()
        );
    }

    referenced
}

/// Scans a section's data for pointer values and adds referenced images to the set.
///
/// # Performance
///
/// Uses optimized u64 reads that compile to single unaligned load instructions.
/// The inner loop is kept simple for LLVM auto-vectorization.
fn scan_section_pointers(
    data: &[u8],
    sect: &Section64,
    ranges: &[ImageAddressRange],
    referenced: &mut HashSet<String>,
) {
    let sect_name = sect.name();

    // Stubs have code, not raw pointers - skip
    if sect_name.contains("stub") {
        return;
    }

    // Use optimized pointer scanning from util module
    // This uses fast u64 reads and early-exit for null/small values
    for (_offset, ptr_value) in crate::util::scan_pointers_in_range(
        data,
        8, // 64-bit pointer stride
        crate::util::MIN_VALID_POINTER,
        u64::MAX,
    ) {
        // Strip pointer authentication bits (top byte on arm64e)
        let clean_ptr = ptr_value & crate::util::ADDR_MASK_48BIT;

        // Find which image this pointer references
        if let Some(target_path) = find_image_for_address(clean_ptr, ranges) {
            referenced.insert(target_path.to_string());
        }
    }
}

/// Gets the LC_LOAD_DYLIB dependencies of an image.
fn get_image_dependencies(cache: &DyldContext, image_path: &str) -> Vec<String> {
    let image = match cache.find_image(image_path) {
        Some(img) => img,
        None => return Vec::new(),
    };

    let header_data = match cache.data_at_addr(image.address, MachHeader64::SIZE) {
        Ok(data) => data,
        Err(_) => return Vec::new(),
    };

    let header = match MachHeader64::read_from_prefix(header_data) {
        Ok((h, _)) => h,
        Err(_) => return Vec::new(),
    };

    let header_and_cmds_size = MachHeader64::SIZE + header.sizeofcmds as usize;
    let header_and_cmds = match cache.data_at_addr(image.address, header_and_cmds_size) {
        Ok(data) => data,
        Err(_) => return Vec::new(),
    };

    let macho_offset = match cache.addr_to_offset(image.address) {
        Some(o) => o as usize,
        None => return Vec::new(),
    };

    match MachOContext::new(header_and_cmds, macho_offset) {
        Ok(macho) => macho.dependencies(),
        Err(_) => Vec::new(),
    }
}

/// Discovers all images to merge using BOTH LC_LOAD_DYLIB AND pointer scanning (BFS up to max_depth).
fn discover_images_to_merge(
    cache: &DyldContext,
    root_path: &str,
    max_depth: usize,
) -> Vec<(String, usize)> {
    // Build address map for fast lookup
    let ranges = build_image_address_map(cache);

    let mut result = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut queue: VecDeque<(String, usize)> = VecDeque::new();

    visited.insert(root_path.to_string());
    queue.push_back((root_path.to_string(), 0));

    while let Some((path, depth)) = queue.pop_front() {
        // Check if image exists in cache
        if cache.find_image(&path).is_none() {
            continue;
        }

        result.push((path.clone(), depth));

        // Don't traverse beyond max_depth
        if depth >= max_depth {
            continue;
        }

        // Method 1: LC_LOAD_DYLIB dependencies
        for dep in get_image_dependencies(cache, &path) {
            let normalized = normalize_path(&dep);
            if !visited.contains(&normalized) && cache.find_image(&normalized).is_some() {
                visited.insert(normalized.clone());
                queue.push_back((normalized, depth + 1));
            }
        }

        // Method 2: Pointer scanning for referenced images
        let referenced = scan_image_pointers(cache, &path, &ranges, 0);
        for ref_path in referenced {
            if !visited.contains(&ref_path) {
                visited.insert(ref_path.clone());
                queue.push_back((ref_path, depth + 1));
            }
        }
    }

    result
}

/// Normalizes a dependency path to a canonical form that can be found in the cache.
///
/// The dyld shared cache uses full absolute paths, so we need to convert:
/// - `@rpath/` prefixes to their likely locations
/// - `@executable_path/` and `@loader_path/` prefixes
/// - Handle versioned framework paths (e.g., Versions/A/)
/// - Private frameworks in various locations
fn normalize_path(path: &str) -> String {
    // Already an absolute path
    if path.starts_with('/') {
        return path.to_string();
    }

    // Handle @rpath prefix - most common case
    if let Some(rest) = path.strip_prefix("@rpath/") {
        // Check for framework paths (with or without versioned structure)
        if rest.contains(".framework/") || rest.contains(".framework") {
            // Extract framework name from path
            if let Some(fw_pos) = rest.find(".framework") {
                let fw_name = &rest[..fw_pos];

                // Get binary name from after ".framework/" if present
                let binary_name = if rest.contains(".framework/") {
                    let after_framework = &rest[fw_pos + 11..]; // skip ".framework/"
                    if after_framework.starts_with("Versions/") {
                        // Skip "Versions/X/" to get binary name
                        after_framework.split('/').skip(2).next().unwrap_or(fw_name)
                    } else {
                        after_framework.split('/').next().unwrap_or(fw_name)
                    }
                } else {
                    fw_name
                };

                // Determine if this is a private framework
                // Private frameworks typically have "Private" in the name or path
                let base_path = if fw_name.contains("Private") {
                    "/System/Library/PrivateFrameworks"
                } else {
                    "/System/Library/Frameworks"
                };

                return format!(
                    "{}/{}.framework/Versions/A/{}",
                    base_path, fw_name, binary_name
                );
            }
        }

        // Dylib with path components (e.g., @rpath/libfoo/libfoo.dylib)
        if rest.contains('/') {
            // Try as a path relative to /System/Library
            return format!("/System/Library/{}", rest);
        }

        // Plain dylib (e.g., @rpath/libfoo.dylib)
        if rest.ends_with(".dylib") {
            // Try common dylib locations
            return format!("/usr/lib/{}", rest);
        }

        // Looks like a framework name without .framework extension
        // e.g., @rpath/Foundation -> Foundation.framework/Foundation
        return format!(
            "/System/Library/Frameworks/{}.framework/Versions/A/{}",
            rest, rest
        );
    }

    // Handle @executable_path - typically relative to app binary
    if let Some(rest) = path.strip_prefix("@executable_path/") {
        // Usually points to ../Frameworks or similar
        if rest.starts_with("../Frameworks/") {
            let after_frameworks = &rest[14..]; // skip "../Frameworks/"
            if let Some(fw_pos) = after_frameworks.find(".framework") {
                let fw_name = &after_frameworks[..fw_pos];
                return format!(
                    "/System/Library/Frameworks/{}.framework/Versions/A/{}",
                    fw_name, fw_name
                );
            }
        }
        // Fall back to /usr/lib
        return format!("/usr/lib/{}", rest);
    }

    // Handle @loader_path - relative to loading binary
    if let Some(rest) = path.strip_prefix("@loader_path/") {
        // Similar handling to @executable_path
        if rest.starts_with("../Frameworks/") || rest.starts_with("Frameworks/") {
            let stripped = rest
                .strip_prefix("../Frameworks/")
                .or_else(|| rest.strip_prefix("Frameworks/"))
                .unwrap_or(rest);
            if let Some(fw_pos) = stripped.find(".framework") {
                let fw_name = &stripped[..fw_pos];
                return format!(
                    "/System/Library/Frameworks/{}.framework/Versions/A/{}",
                    fw_name, fw_name
                );
            }
        }
        return format!("/usr/lib/{}", rest);
    }

    // Unknown format, return as-is
    path.to_string()
}

/// Reads a complete Mach-O image from the cache into a compact buffer.
///
/// The resulting buffer has segments placed at compact file offsets starting
/// from 0, not at the original cache file offsets.
fn read_image_from_cache(cache: &DyldContext, image_path: &str) -> Result<(Vec<u8>, u64)> {
    let image = cache
        .find_image(image_path)
        .ok_or_else(|| Error::ImageNotFound {
            name: image_path.to_string(),
        })?;

    let header_data = cache.data_at_addr(image.address, MachHeader64::SIZE)?;
    let header = MachHeader64::read_from_prefix(header_data)
        .map_err(|_| Error::InvalidMachoMagic(0))?
        .0;

    let header_and_cmds_size = MachHeader64::SIZE + header.sizeofcmds as usize;
    let header_and_cmds = cache.data_at_addr(image.address, header_and_cmds_size)?;

    // Parse segments to find vmaddrs and sizes
    // We'll place segments at compact file offsets, not the original cache offsets
    #[derive(Clone)]
    struct SegmentToCopy {
        vmaddr: u64,
        #[allow(dead_code)]
        vmsize: u64,
        filesize: u64,
    }

    let mut segments: Vec<SegmentToCopy> = Vec::new();
    let mut base_vmaddr: u64 = 0;

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

        if cmd == LC_SEGMENT_64 && offset + 72 <= header_and_cmds.len() {
            let vmaddr = u64::from_le_bytes(
                header_and_cmds[offset + 24..offset + 32]
                    .try_into()
                    .unwrap(),
            );
            let vmsize = u64::from_le_bytes(
                header_and_cmds[offset + 32..offset + 40]
                    .try_into()
                    .unwrap(),
            );
            let filesize = u64::from_le_bytes(
                header_and_cmds[offset + 48..offset + 56]
                    .try_into()
                    .unwrap(),
            );

            // First segment is typically __TEXT and defines base
            if segments.is_empty() {
                base_vmaddr = vmaddr;
            }

            segments.push(SegmentToCopy {
                vmaddr,
                vmsize,
                filesize,
            });
        }
        offset += cmdsize as usize;
    }

    // Calculate total compact size - EXCLUDING __LINKEDIT which is shared in cache
    let header_size = align_up(header_and_cmds_size as u64, PAGE_SIZE);
    let total_data_size: u64 = segments
        .iter()
        .filter(|s| s.filesize > 0 && s.filesize < 0x10000000) // Exclude huge segments (like shared LINKEDIT)
        .map(|s| align_up(s.filesize, PAGE_SIZE))
        .sum();
    let total_size = header_size + total_data_size;

    debug!(
        "read_image_from_cache: {} segments, header_size={}, data_size={}, total={}",
        segments.len(),
        header_size,
        total_data_size,
        total_size
    );

    // Allocate buffer and copy data at compact offsets
    let mut buffer = vec![0u8; total_size as usize];
    buffer[..header_and_cmds_size].copy_from_slice(header_and_cmds);

    let mut current_fileoff = header_size;
    for seg in &segments {
        if seg.filesize > 0 {
            if let Ok(seg_data) = cache.data_at_addr(seg.vmaddr, seg.filesize as usize) {
                let dst_start = current_fileoff as usize;
                let dst_end = dst_start + seg.filesize as usize;
                if dst_end <= buffer.len() {
                    buffer[dst_start..dst_end].copy_from_slice(seg_data);
                }
            }
            current_fileoff += align_up(seg.filesize, PAGE_SIZE);
        }
    }

    Ok((buffer, base_vmaddr))
}

/// Information about a segment to merge.
#[derive(Debug, Clone)]
struct SegmentInfo {
    name: String,
    vmaddr: u64,
    #[allow(dead_code)]
    vmsize: u64,
    fileoff: u64,
    filesize: u64,
    #[allow(dead_code)]
    maxprot: u32,
    #[allow(dead_code)]
    initprot: u32,
}

/// Parses segment information from a Mach-O buffer.
///
/// Returns segments with compact file offsets (as they would be in a standalone
/// Mach-O file), not the original cache file offsets.
fn parse_segments(data: &[u8]) -> Result<Vec<SegmentInfo>> {
    if data.len() < MachHeader64::SIZE {
        return Err(Error::BufferTooSmall {
            needed: MachHeader64::SIZE,
            available: data.len(),
        });
    }

    let header = MachHeader64::read_from_prefix(data)
        .map_err(|_| Error::InvalidMachoMagic(0))?
        .0;

    let mut segments = Vec::new();
    let mut offset = MachHeader64::SIZE;

    // Compute compact file offsets
    let header_and_cmds_size = MachHeader64::SIZE + header.sizeofcmds as usize;
    let mut compact_fileoff = align_up(header_and_cmds_size as u64, PAGE_SIZE);

    for _ in 0..header.ncmds {
        if offset + 8 > data.len() {
            break;
        }
        let cmd = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let cmdsize = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);

        if cmd == LC_SEGMENT_64 && offset + SegmentCommand64::SIZE <= data.len() {
            let seg = SegmentCommand64::read_from_prefix(&data[offset..])
                .map_err(|_| Error::Parse {
                    offset,
                    reason: "failed to parse segment".into(),
                })?
                .0;

            // Use compact file offset instead of original
            let this_fileoff = if seg.filesize > 0 { compact_fileoff } else { 0 };

            segments.push(SegmentInfo {
                name: seg.name().to_string(),
                vmaddr: seg.vmaddr,
                vmsize: seg.vmsize,
                fileoff: this_fileoff,
                filesize: seg.filesize,
                maxprot: seg.maxprot,
                initprot: seg.initprot,
            });

            if seg.filesize > 0 {
                compact_fileoff += align_up(seg.filesize, PAGE_SIZE);
            }
        }

        offset += cmdsize as usize;
    }

    Ok(segments)
}

/// Performs the merge operation.
///
/// This creates a new Mach-O that contains the primary image with additional
/// segments for each dependency. All pointers are updated to reference the
/// merged locations.
pub fn merge_images(ctx: &mut MergeContext) -> Result<()> {
    let primary_path = ctx.primary_path.clone();

    // Discover all images to merge
    let images_to_merge = discover_images_to_merge(&ctx.cache, &primary_path, ctx.max_depth);

    if ctx.verbosity >= 2 {
        info!(
            "Discovered {} images to merge (depth {})",
            images_to_merge.len(),
            ctx.max_depth
        );
        for (path, depth) in &images_to_merge {
            debug!("  [depth {}] {}", depth, path);
        }
    }

    // Read primary image
    let (primary_data, primary_base) = read_image_from_cache(&ctx.cache, &primary_path)?;
    let primary_segments = parse_segments(&primary_data)?;

    if ctx.verbosity >= 2 {
        info!("Primary image size: {} bytes", primary_data.len());
    }

    // Calculate primary image's total VM size
    let primary_vm_end = primary_segments
        .iter()
        .filter(|s| s.name != "__LINKEDIT")
        .map(|s| s.vmaddr + s.vmsize)
        .max()
        .unwrap_or(primary_base);
    let primary_vm_size = primary_vm_end - primary_base;

    // Start building the merged output
    ctx.data = primary_data.clone();

    // Add primary image mapping
    let mut primary_mapping = ImageSegmentMapping {
        path: primary_path.clone(),
        original_base: primary_base,
        merged_base: primary_base, // Primary stays at same location
        size: primary_vm_size,
        segments: HashMap::new(),
    };
    for seg in &primary_segments {
        primary_mapping
            .segments
            .insert(seg.name.clone(), (seg.vmaddr, seg.vmaddr, seg.vmsize));
    }
    ctx.mappings.push(primary_mapping);
    ctx.processed.insert(primary_path.clone());

    // Track next available vmaddr for merged segments
    let mut next_vmaddr = align_up(primary_vm_end, PAGE_SIZE);
    let mut next_fileoff = align_up(ctx.data.len() as u64, PAGE_SIZE);

    // Process each dependency
    for (dep_path, depth) in &images_to_merge {
        if *depth == 0 {
            continue; // Skip primary
        }
        if ctx.processed.contains(dep_path) {
            continue;
        }

        // Read dependency image
        let (dep_data, dep_base) = match read_image_from_cache(&ctx.cache, dep_path) {
            Ok(result) => result,
            Err(e) => {
                warn!("Failed to read {}: {}", dep_path, e);
                continue;
            }
        };

        if ctx.verbosity >= 2 {
            info!(
                "Merging dependency: {} (depth {}, {} bytes)",
                dep_path,
                depth,
                dep_data.len()
            );
        }

        let dep_segments = match parse_segments(&dep_data) {
            Ok(segs) => segs,
            Err(e) => {
                warn!("Failed to parse {}: {}", dep_path, e);
                continue;
            }
        };

        // Calculate dependency's VM range
        let dep_vm_end = dep_segments
            .iter()
            .filter(|s| s.name != "__LINKEDIT")
            .map(|s| s.vmaddr + s.vmsize)
            .max()
            .unwrap_or(dep_base);
        let dep_vm_size = dep_vm_end - dep_base;

        // Create mapping for this dependency
        let mut dep_mapping = ImageSegmentMapping {
            path: dep_path.clone(),
            original_base: dep_base,
            merged_base: next_vmaddr,
            size: dep_vm_size,
            segments: HashMap::new(),
        };

        // Calculate total file size for this dependency (excluding LINKEDIT)
        let dep_total_filesize: u64 = dep_segments
            .iter()
            .filter(|s| s.name != "__LINKEDIT" && s.filesize > 0)
            .map(|s| s.filesize)
            .sum();

        // Ensure we have space for all dependency data
        let dep_start_fileoff = next_fileoff;
        let needed_size = dep_start_fileoff as usize + dep_total_filesize as usize;
        if needed_size > ctx.data.len() {
            ctx.data.resize(needed_size, 0);
        }

        // Track current file offset within this dependency's merged data
        let mut current_dep_fileoff = dep_start_fileoff;

        // Append each segment (except __LINKEDIT) to merged output
        let dep_index = ctx.dependency_segments.len();
        for seg in &dep_segments {
            if seg.name == "__LINKEDIT" {
                continue; // Skip LINKEDIT, we'll rebuild it
            }
            if seg.filesize == 0 {
                continue; // Skip empty segments
            }

            let seg_merged_vmaddr = next_vmaddr + (seg.vmaddr - dep_base);
            dep_mapping.segments.insert(
                seg.name.clone(),
                (seg.vmaddr, seg_merged_vmaddr, seg.vmsize),
            );

            // Copy segment data sequentially
            let src_start = seg.fileoff as usize;
            let src_end = src_start + seg.filesize as usize;
            if src_end <= dep_data.len() {
                let dst_start = current_dep_fileoff as usize;
                let dst_end = dst_start + seg.filesize as usize;
                ctx.data[dst_start..dst_end].copy_from_slice(&dep_data[src_start..src_end]);

                // Track this segment for load command injection
                // Create unique segment name: __DEP{index}_{origname without __}
                let seg_short_name = seg.name.trim_start_matches('_');
                let dep_seg_name = format!("__D{}_{}", dep_index, seg_short_name);
                // Truncate to 16 chars max
                let dep_seg_name = if dep_seg_name.len() > 16 {
                    dep_seg_name[..16].to_string()
                } else {
                    dep_seg_name
                };

                ctx.dependency_segments.push(DependencySegment {
                    name: dep_seg_name,
                    vmaddr: seg_merged_vmaddr,
                    vmsize: seg.vmsize,
                    fileoff: current_dep_fileoff,
                    filesize: seg.filesize,
                    maxprot: seg.maxprot,
                    initprot: seg.initprot,
                });

                current_dep_fileoff += seg.filesize;
            }
        }

        ctx.mappings.push(dep_mapping);
        ctx.processed.insert(dep_path.clone());

        // Update positions for next dependency
        next_vmaddr = align_up(next_vmaddr + dep_vm_size, PAGE_SIZE);
        next_fileoff = align_up(current_dep_fileoff, PAGE_SIZE);
    }

    if ctx.verbosity >= 1 {
        info!(
            "Merged {} images, total size: {} bytes",
            ctx.mappings.len(),
            ctx.data.len()
        );
    }

    Ok(())
}

/// Returns true if a section should be scanned for pointers.
///
/// We focus on sections known to contain pointers:
/// - Symbol pointer sections (GOT, lazy/non-lazy symbol ptrs)
/// - Objective-C metadata sections
/// - Initializer/terminator sections
/// - Const data sections (may contain vtables, etc.)
fn section_has_pointers(section_name: &str, segment_name: &str) -> bool {
    // Known pointer-containing sections
    match section_name {
        // Symbol pointers
        "__got" | "__la_symbol_ptr" | "__nl_symbol_ptr" => true,
        // Initializers/Terminators
        "__mod_init_func" | "__mod_term_func" => true,
        // Objective-C metadata (all contain pointers)
        s if s.starts_with("__objc_") => true,
        // CFString section
        "__cfstring" => true,
        // Const sections (vtables, function pointers)
        "__const" => true,
        // Data sections that commonly have pointers
        "__data" => true,
        "__common" => true,
        "__bss" => false, // BSS is uninitialized
        // AUTH sections have authenticated pointers
        _ if segment_name == "__AUTH_CONST" || segment_name.starts_with("__AUTH") => true,
        _ => false,
    }
}

/// Information about a section to scan for pointers.
struct SectionToScan {
    fileoff: u64,
    size: u64,
    addr: u64,
    #[allow(dead_code)]
    name: String,
}

/// Parses sections from a Mach-O buffer.
fn parse_sections(data: &[u8]) -> Result<Vec<SectionToScan>> {
    if data.len() < MachHeader64::SIZE {
        return Err(Error::BufferTooSmall {
            needed: MachHeader64::SIZE,
            available: data.len(),
        });
    }

    let header = MachHeader64::read_from_prefix(data)
        .map_err(|_| Error::InvalidMachoMagic(0))?
        .0;

    let mut sections = Vec::new();
    let mut offset = MachHeader64::SIZE;

    for _ in 0..header.ncmds {
        if offset + 8 > data.len() {
            break;
        }
        let cmd = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let cmdsize = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);

        if cmd == LC_SEGMENT_64 && offset + SegmentCommand64::SIZE <= data.len() {
            let seg = SegmentCommand64::read_from_prefix(&data[offset..])
                .map_err(|_| Error::Parse {
                    offset,
                    reason: "failed to parse segment".into(),
                })?
                .0;

            let seg_name = seg.name();

            // Parse sections within this segment
            let mut sect_offset = offset + SegmentCommand64::SIZE;

            for _ in 0..seg.nsects {
                if sect_offset + Section64::SIZE > data.len() {
                    break;
                }

                let sect = Section64::read_from_prefix(&data[sect_offset..])
                    .map_err(|_| Error::Parse {
                        offset: sect_offset,
                        reason: "failed to parse section".into(),
                    })?
                    .0;

                let sect_name = sect.name();
                let sect_fileoff = sect.offset as u64;

                // Check if this section should be scanned for pointers
                if section_has_pointers(sect_name, seg_name) && sect.size > 0 && sect_fileoff > 0 {
                    sections.push(SectionToScan {
                        fileoff: sect_fileoff,
                        size: sect.size,
                        addr: sect.addr,
                        name: format!("{},{}", seg_name, sect_name),
                    });
                }

                sect_offset += Section64::SIZE;
            }
        }

        offset += cmdsize as usize;
    }

    Ok(sections)
}

fn find_section(data: &[u8], seg_name: &str, sect_name: &str) -> Option<Section64> {
    let header = MachHeader64::read_from_prefix(data).ok()?.0;
    let mut offset = MachHeader64::SIZE;

    for _ in 0..header.ncmds {
        if offset + 8 > data.len() {
            break;
        }
        let cmd = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]);
        let cmdsize = u32::from_le_bytes([
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]) as usize;

        if cmd == LC_SEGMENT_64 && offset + SegmentCommand64::SIZE <= data.len() {
            let nsects = u32::from_le_bytes(data[offset + 64..offset + 68].try_into().ok()?);
            let mut sect_offset = offset + SegmentCommand64::SIZE;

            for _ in 0..nsects {
                if sect_offset + Section64::SIZE > data.len() {
                    break;
                }
                let sect = match Section64::read_from_prefix(&data[sect_offset..]) {
                    Ok((s, _)) => s,
                    Err(_) => {
                        sect_offset += Section64::SIZE;
                        continue;
                    }
                };

                if sect.segment_name() == seg_name && sect.name() == sect_name {
                    return Some(sect);
                }

                sect_offset += Section64::SIZE;
            }
        }

        offset += cmdsize;
    }

    None
}

/// Fixes auth stubs to use the local GOT and populates GOT entries.
pub fn fix_merged_stubs(ctx: &mut MergeContext) -> Result<()> {
    let header = MachHeader64::read_from_prefix(&ctx.data)
        .map_err(|_| Error::InvalidMachoMagic(0))?
        .0;

    if !header.is_arm64() || !header.is_arm64e() {
        return Ok(());
    }

    let Some(stubs) = find_section(&ctx.data, "__TEXT", "__auth_stubs") else {
        debug!("Stub section __TEXT/__auth_stubs not found");
        return Ok(());
    };

    let ptrs = find_section(&ctx.data, "__AUTH_CONST", "__auth_got")
        .or_else(|| find_section(&ctx.data, "__DATA_CONST", "__auth_got"))
        .or_else(|| find_section(&ctx.data, "__DATA", "__auth_got"));

    let Some(ptrs) = ptrs else {
        debug!("Pointer section __auth_got not found");
        return Ok(());
    };

    let stub_size = stubs.reserved2 as usize;
    if stub_size == 0 {
        return Ok(());
    }

    let stub_count = (stubs.size as usize) / stub_size;
    let ptr_count = (ptrs.size as usize) / 8;
    let count = stub_count.min(ptr_count);
    if count == 0 {
        return Ok(());
    }

    let local_got_start = ptrs.addr;
    let local_got_end = ptrs.addr + ptrs.size;
    let mut fixed = 0usize;

    for i in 0..count {
        let stub_offset = stubs.offset as usize + i * stub_size;
        let stub_addr = stubs.addr + (i * stub_size) as u64;
        let ptr_addr = ptrs.addr + (i * 8) as u64;
        let ptr_offset = ptrs.offset as usize + i * 8;

        if stub_offset + stub_size > ctx.data.len() {
            break;
        }

        let stub_data = &ctx.data[stub_offset..stub_offset + stub_size];
        let format = detect_stub_format(stub_data, true);

        if format == StubFormat::AuthNormal && stub_data.len() >= 16 {
            let instr0 =
                u32::from_le_bytes([stub_data[0], stub_data[1], stub_data[2], stub_data[3]]);
            let instr1 =
                u32::from_le_bytes([stub_data[4], stub_data[5], stub_data[6], stub_data[7]]);

            if let Some(current_got_addr) = arm64::follow_adrp_add(stub_addr, instr0, instr1) {
                let is_external =
                    current_got_addr < local_got_start || current_got_addr >= local_got_end;
                if is_external {
                    if let Ok(ptr_data) = ctx.cache.data_at_addr(current_got_addr, 8) {
                        let encoded_value = u64::from_le_bytes(ptr_data.try_into().unwrap());
                        if encoded_value != 0 {
                            let decoded_value =
                                decode_shared_pointer(&ctx.cache, current_got_addr, encoded_value);

                            let addr_mask = 0x0000_FFFF_FFFF_FFFFu64;
                            let clean_target = decoded_value & addr_mask;
                            let resolved_target =
                                if let Some(translated) = ctx.translate_addr(clean_target) {
                                    translated
                                } else {
                                    clean_target
                                };
                            let high_bits = decoded_value & !addr_mask;
                            let final_value = high_bits | resolved_target;

                            if ptr_offset + 8 <= ctx.data.len() {
                                ctx.data[ptr_offset..ptr_offset + 8]
                                    .copy_from_slice(&final_value.to_le_bytes());
                            }

                            let new_stub = generate_stub_auth(stub_addr, ptr_addr);
                            let mut padded = vec![0u8; stub_size];
                            padded[..16].copy_from_slice(&new_stub);

                            for j in (16..stub_size).step_by(4) {
                                let nop = arm64::encode_nop();
                                if j + 4 <= stub_size {
                                    padded[j..j + 4].copy_from_slice(&nop.to_le_bytes());
                                }
                            }

                            ctx.data[stub_offset..stub_offset + stub_size].copy_from_slice(&padded);
                            fixed += 1;
                        }
                    }
                    continue;
                }
            }
        }

        let expected_stub_size = 16;
        let needs_fix = matches!(format, StubFormat::AuthOptimized | StubFormat::Branch);
        if needs_fix && stub_size >= expected_stub_size {
            let new_stub = generate_stub_auth(stub_addr, ptr_addr);
            let mut padded = vec![0u8; stub_size];
            padded[..16].copy_from_slice(&new_stub);

            for j in (16..stub_size).step_by(4) {
                let nop = arm64::encode_nop();
                if j + 4 <= stub_size {
                    padded[j..j + 4].copy_from_slice(&nop.to_le_bytes());
                }
            }

            ctx.data[stub_offset..stub_offset + stub_size].copy_from_slice(&padded);
            fixed += 1;
        }
    }

    if fixed > 0 && ctx.verbosity >= 1 {
        info!("Fixed {} auth stubs", fixed);
    }

    Ok(())
}

/// Fixes all pointers in the merged image to point to merged locations.
///
/// This uses section-level analysis to only scan sections known to contain pointers,
/// avoiding false positives from non-pointer data that happens to look like addresses.
/// Fixes all pointers in the merged image to point to merged locations.
///
/// This uses section-level analysis to only scan sections known to contain pointers,
/// avoiding false positives from non-pointer data that happens to look like addresses.
///
/// # Performance
///
/// Uses optimized u64 reads/writes that compile to single unaligned load/store
/// instructions. The inner loop is kept simple for LLVM auto-vectorization potential.
pub fn fix_merged_pointers(ctx: &mut MergeContext) -> Result<()> {
    use byteorder::{ByteOrder, LittleEndian};

    // Parse sections that contain pointers
    let sections = parse_sections(&ctx.data)?;

    let mut fixed_count = 0u64;
    let addr_mask = crate::util::ADDR_MASK_48BIT;

    for section in &sections {
        if section.name.ends_with(",__auth_got") {
            continue;
        }

        let start = section.fileoff as usize;
        let end = start + section.size as usize;

        if end > ctx.data.len() {
            continue;
        }

        // Scan for pointers (8-byte aligned) with optimized reads
        let mut offset = start;
        while offset + 8 <= end.min(ctx.data.len()) {
            // Optimized: single unaligned load
            let raw_value = crate::util::read_u64_le(&ctx.data[offset..]);

            // Skip null pointers (fast path)
            if raw_value == 0 {
                offset += 8;
                continue;
            }

            let ptr_addr = section.addr + (offset - start) as u64;
            let raw_addr = raw_value & addr_mask;

            let needs_decode =
                !ctx.is_in_shared_region(raw_addr) && ctx.translate_addr(raw_addr).is_none();
            let decoded_value = if needs_decode {
                decode_shared_pointer(&ctx.cache, ptr_addr, raw_value)
            } else {
                raw_value
            };

            let high_bits = decoded_value & !addr_mask;
            let addr_value = decoded_value & addr_mask;

            // Skip if address portion is zero
            if addr_value != 0 {
                let new_addr = if let Some(translated) = ctx.translate_addr(addr_value) {
                    translated
                } else {
                    addr_value
                };

                let new_value = high_bits | new_addr;
                if new_value != raw_value {
                    // Optimized: single unaligned store
                    LittleEndian::write_u64(&mut ctx.data[offset..], new_value);
                    fixed_count += 1;
                }
            }

            offset += 8;
        }
    }

    if ctx.verbosity >= 2 {
        info!(
            "Fixed {} pointers across {} sections in merged image",
            fixed_count,
            sections.len()
        );
    }

    Ok(())
}

/// Injects LC_SEGMENT_64 commands for dependency segments into the Mach-O header.
///
/// This adds new segment commands so IDA and other analysis tools can recognize
/// the dependency code regions. The commands are inserted after the existing
/// load commands if there's space before the first segment data.
///
/// For TEXT segments, a __text section is added so IDA recognizes the code.
pub fn inject_dependency_segments(ctx: &mut MergeContext) -> Result<()> {
    if ctx.dependency_segments.is_empty() {
        return Ok(());
    }

    let header = MachHeader64::read_from_prefix(&ctx.data)
        .map_err(|_| Error::InvalidMachoMagic(0))?
        .0;

    let current_cmds_end = MachHeader64::SIZE + header.sizeofcmds as usize;

    // Find the first segment's file offset (where actual data starts)
    let mut first_data_offset = ctx.data.len();
    let mut offset = MachHeader64::SIZE;
    for _ in 0..header.ncmds {
        if offset + 8 > ctx.data.len() {
            break;
        }
        let cmd = u32::from_le_bytes(ctx.data[offset..offset + 4].try_into().unwrap());
        let cmdsize =
            u32::from_le_bytes(ctx.data[offset + 4..offset + 8].try_into().unwrap()) as usize;

        if cmd == LC_SEGMENT_64 && offset + 48 <= ctx.data.len() {
            let fileoff =
                u64::from_le_bytes(ctx.data[offset + 40..offset + 48].try_into().unwrap());
            if fileoff > 0 && (fileoff as usize) < first_data_offset {
                first_data_offset = fileoff as usize;
            }
        }
        offset += cmdsize;
    }

    // The merged buffer stores primary segment data at compact offsets.
    // Use the compact header size as the real start of data if it's earlier.
    let header_data_start = align_up(current_cmds_end as u64, PAGE_SIZE) as usize;
    if header_data_start < first_data_offset {
        first_data_offset = header_data_start;
    }

    // Calculate space needed for new segment commands
    // TEXT segments get 1 section (72 + 80 = 152 bytes), others get 0 sections (72 bytes)
    let mut bytes_needed = 0usize;
    for dep_seg in &ctx.dependency_segments {
        if dep_seg.name.contains("TEXT") {
            bytes_needed += SegmentCommand64::SIZE + Section64::SIZE; // 152 bytes
        } else {
            bytes_needed += SegmentCommand64::SIZE; // 72 bytes
        }
    }
    let mut available_space = first_data_offset.saturating_sub(current_cmds_end);

    if bytes_needed > available_space {
        let new_cmds_end = current_cmds_end + bytes_needed;
        let new_header_size = align_up(new_cmds_end as u64, PAGE_SIZE) as usize;

        if new_header_size > first_data_offset {
            let delta = new_header_size - first_data_offset;
            let old_len = ctx.data.len();
            ctx.data.resize(old_len + delta, 0);
            ctx.data
                .copy_within(first_data_offset..old_len, first_data_offset + delta);
            ctx.data[first_data_offset..first_data_offset + delta].fill(0);

            for dep_seg in &mut ctx.dependency_segments {
                if dep_seg.fileoff >= first_data_offset as u64 {
                    dep_seg.fileoff += delta as u64;
                }
            }
            for region in &mut ctx.shared_regions {
                if region.fileoff >= first_data_offset as u64 {
                    region.fileoff += delta as u64;
                }
            }

            first_data_offset = new_header_size;

            if ctx.verbosity >= 1 {
                info!("Expanded load command space by {} bytes", delta);
            }
        }

        available_space = first_data_offset.saturating_sub(current_cmds_end);
        if bytes_needed > available_space {
            warn!(
                "Not enough space for {} dependency segment commands ({} bytes needed, {} available)",
                ctx.dependency_segments.len(),
                bytes_needed,
                available_space
            );
            // Just skip adding segment commands - the merge will still work,
            // but IDA won't recognize the dependency code regions
            return Ok(());
        }
    }

    // Write new segment commands
    let mut write_offset = current_cmds_end;
    for dep_seg in &ctx.dependency_segments {
        let is_text = dep_seg.name.contains("TEXT");

        // Build LC_SEGMENT_64 command
        let mut seg_cmd = SegmentCommand64::default();
        seg_cmd.cmd = LC_SEGMENT_64;
        seg_cmd.cmdsize = if is_text {
            (SegmentCommand64::SIZE + Section64::SIZE) as u32
        } else {
            SegmentCommand64::SIZE as u32
        };

        // Set segment name (pad with zeros)
        let name_bytes = dep_seg.name.as_bytes();
        let copy_len = name_bytes.len().min(16);
        seg_cmd.segname[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

        seg_cmd.vmaddr = dep_seg.vmaddr;
        seg_cmd.vmsize = dep_seg.vmsize;
        seg_cmd.fileoff = dep_seg.fileoff;
        seg_cmd.filesize = dep_seg.filesize;
        seg_cmd.maxprot = dep_seg.maxprot;
        seg_cmd.initprot = dep_seg.initprot;
        seg_cmd.nsects = if is_text { 1 } else { 0 };
        seg_cmd.flags = 0;

        // Write the segment command
        use zerocopy::IntoBytes;
        let cmd_bytes = seg_cmd.as_bytes();
        ctx.data[write_offset..write_offset + cmd_bytes.len()].copy_from_slice(cmd_bytes);
        write_offset += SegmentCommand64::SIZE;

        // For TEXT segments, add a __text section
        if is_text {
            let mut section = Section64::default();

            // Section name: __text
            section.sectname[..6].copy_from_slice(b"__text");

            // Segment name: same as the segment
            section.segname[..copy_len].copy_from_slice(&name_bytes[..copy_len]);

            // Section covers the entire segment
            section.addr = dep_seg.vmaddr;
            section.size = dep_seg.vmsize;
            section.offset = dep_seg.fileoff as u32;
            section.align = 2; // 4-byte alignment (2^2)

            // Flags: S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
            // This tells IDA this section contains executable code
            section.flags = S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS;

            let sect_bytes = section.as_bytes();
            ctx.data[write_offset..write_offset + sect_bytes.len()].copy_from_slice(sect_bytes);
            write_offset += Section64::SIZE;
        }
    }

    // Update header ncmds and sizeofcmds
    let new_ncmds = header.ncmds + ctx.dependency_segments.len() as u32;
    let new_sizeofcmds = header.sizeofcmds + bytes_needed as u32;

    ctx.data[16..20].copy_from_slice(&new_ncmds.to_le_bytes());
    ctx.data[20..24].copy_from_slice(&new_sizeofcmds.to_le_bytes());

    if ctx.verbosity >= 1 {
        info!(
            "Injected {} dependency segment commands ({} bytes)",
            ctx.dependency_segments.len(),
            bytes_needed
        );
    }

    Ok(())
}

/// Updates the Mach-O header and load commands for the merged image.
///
/// This rewrites LC_SEGMENT_64 file offsets to match the compact layout,
/// clears the MH_DYLIB_IN_CACHE flag, and zeros out chained fixups.
pub fn update_merged_load_commands(ctx: &mut MergeContext) -> Result<()> {
    if ctx.data.len() < MachHeader64::SIZE {
        return Err(Error::BufferTooSmall {
            needed: MachHeader64::SIZE,
            available: ctx.data.len(),
        });
    }

    let header = MachHeader64::read_from_prefix(&ctx.data)
        .map_err(|_| Error::InvalidMachoMagic(0))?
        .0;

    // Clear MH_DYLIB_IN_CACHE flag
    let flags_offset = 24;
    let flags = u32::from_le_bytes([
        ctx.data[flags_offset],
        ctx.data[flags_offset + 1],
        ctx.data[flags_offset + 2],
        ctx.data[flags_offset + 3],
    ]);
    let new_flags = flags & !MH_DYLIB_IN_CACHE;
    ctx.data[flags_offset..flags_offset + 4].copy_from_slice(&new_flags.to_le_bytes());

    // Now rewrite segment file offsets to compact values
    let header_and_cmds_size = MachHeader64::SIZE + header.sizeofcmds as usize;
    let mut compact_fileoff = align_up(header_and_cmds_size as u64, PAGE_SIZE);

    let mut offset = MachHeader64::SIZE;
    for _ in 0..header.ncmds {
        if offset + 8 > ctx.data.len() {
            break;
        }
        let cmd = u32::from_le_bytes([
            ctx.data[offset],
            ctx.data[offset + 1],
            ctx.data[offset + 2],
            ctx.data[offset + 3],
        ]);
        let cmdsize = u32::from_le_bytes([
            ctx.data[offset + 4],
            ctx.data[offset + 5],
            ctx.data[offset + 6],
            ctx.data[offset + 7],
        ]) as usize;

        if cmd == LC_SEGMENT_64 && offset + SegmentCommand64::SIZE <= ctx.data.len() {
            // Read segment name to check if it's a dependency segment
            let segname_bytes = &ctx.data[offset + 8..offset + 24];
            let segname_end = segname_bytes.iter().position(|&b| b == 0).unwrap_or(16);
            let segname = std::str::from_utf8(&segname_bytes[..segname_end]).unwrap_or("");

            // Skip dependency segments (names like __D0_TEXT, __D1_DATA, etc.)
            // Their file offsets are already correct from inject_dependency_segments
            let is_dependency_segment = (segname.starts_with("__D")
                && segname.len() > 3
                && segname.chars().nth(3).map_or(false, |c| c.is_ascii_digit()))
                || (segname.starts_with("__S")
                    && segname.len() > 3
                    && segname.chars().nth(3).map_or(false, |c| c.is_ascii_digit()));

            // Read original segment info
            let seg_vmaddr =
                u64::from_le_bytes(ctx.data[offset + 24..offset + 32].try_into().unwrap());
            let filesize =
                u64::from_le_bytes(ctx.data[offset + 48..offset + 56].try_into().unwrap());
            let nsects = u32::from_le_bytes(ctx.data[offset + 64..offset + 68].try_into().unwrap());

            // Only update fileoff for primary image segments with data
            if !is_dependency_segment && filesize > 0 && filesize < 0x10000000 {
                // Update segment fileoff (offset 40 in LC_SEGMENT_64)
                ctx.data[offset + 40..offset + 48].copy_from_slice(&compact_fileoff.to_le_bytes());

                // Update section file offsets within this segment
                // Section offset = segment fileoff + (section addr - segment vmaddr)
                let mut sect_cmd_offset = offset + SegmentCommand64::SIZE;

                for _ in 0..nsects {
                    if sect_cmd_offset + Section64::SIZE > ctx.data.len() {
                        break;
                    }

                    // Read section addr and size
                    let sect_addr = u64::from_le_bytes(
                        ctx.data[sect_cmd_offset + 32..sect_cmd_offset + 40]
                            .try_into()
                            .unwrap(),
                    );
                    let sect_size = u64::from_le_bytes(
                        ctx.data[sect_cmd_offset + 40..sect_cmd_offset + 48]
                            .try_into()
                            .unwrap(),
                    );

                    // Update section offset (offset 48 in Section64) - only if section has data
                    let old_sect_offset = u32::from_le_bytes(
                        ctx.data[sect_cmd_offset + 48..sect_cmd_offset + 52]
                            .try_into()
                            .unwrap(),
                    );
                    if old_sect_offset != 0 && sect_size > 0 {
                        // Calculate correct section offset based on its position in the segment
                        let sect_rel_offset = sect_addr.saturating_sub(seg_vmaddr);
                        let new_sect_offset = compact_fileoff + sect_rel_offset;
                        ctx.data[sect_cmd_offset + 48..sect_cmd_offset + 52]
                            .copy_from_slice(&(new_sect_offset as u32).to_le_bytes());
                    }

                    sect_cmd_offset += Section64::SIZE;
                }

                compact_fileoff += align_up(filesize, PAGE_SIZE);
            } else if filesize == 0 {
                // Zero-fill segment: fileoff should be 0
                ctx.data[offset + 40..offset + 48].copy_from_slice(&0u64.to_le_bytes());
            }
        } else if cmd == LC_DYLD_CHAINED_FIXUPS
            || cmd == LC_DYLD_EXPORTS_TRIE
            || cmd == LC_FUNCTION_STARTS
            || cmd == LC_DATA_IN_CODE
            || cmd == LC_CODE_SIGNATURE
            || cmd == LC_SEGMENT_SPLIT_INFO
        {
            // Zero out LINKEDIT data commands (they're not valid after merge)
            // dataoff is at offset 8, datasize is at offset 12
            ctx.data[offset + 8..offset + 12].copy_from_slice(&0u32.to_le_bytes());
            ctx.data[offset + 12..offset + 16].copy_from_slice(&0u32.to_le_bytes());
        }

        offset += cmdsize;
    }

    if ctx.verbosity >= 2 {
        info!("Updated load commands with compact file offsets");
    }

    Ok(())
}

/// A merged symbol entry with adjusted address.
struct MergedSymbol {
    name: Vec<u8>,
    n_type: u8,
    n_sect: u8,
    n_desc: u16,
    n_value: u64,
}

/// State for building the merged LINKEDIT.
struct LinkeditBuilder {
    /// Function starts data
    function_starts: Vec<u8>,
    /// Data-in-code entries
    data_in_code: Vec<u8>,
    /// Local symbols
    local_symbols: Vec<MergedSymbol>,
    /// Exported symbols
    exported_symbols: Vec<MergedSymbol>,
    /// Undefined/imported symbols
    undefined_symbols: Vec<MergedSymbol>,
    /// String table (first byte is always null)
    strings: Vec<u8>,
}

impl LinkeditBuilder {
    fn new() -> Self {
        let mut strings = Vec::with_capacity(64 * 1024);
        strings.push(0); // First byte is null (empty string)
        Self {
            function_starts: Vec::new(),
            data_in_code: Vec::new(),
            local_symbols: Vec::new(),
            exported_symbols: Vec::new(),
            undefined_symbols: Vec::new(),
            strings,
        }
    }

    /// Adds a string to the string table and returns its offset.
    fn add_string(&mut self, name: &[u8]) -> u32 {
        let offset = self.strings.len() as u32;
        // Strip trailing null if present
        let name = if name.last() == Some(&0) {
            &name[..name.len() - 1]
        } else {
            name
        };
        self.strings.extend_from_slice(name);
        self.strings.push(0);
        offset
    }

    /// Builds the complete LINKEDIT data.
    fn build(mut self) -> (Vec<u8>, LinkeditOffsets) {
        let mut data = Vec::new();
        let mut offsets = LinkeditOffsets::default();

        // 1. Function starts (if any)
        if !self.function_starts.is_empty() {
            offsets.function_starts_off = data.len() as u32;
            offsets.function_starts_size = self.function_starts.len() as u32;
            data.extend_from_slice(&self.function_starts);
        }

        // 2. Data-in-code (if any)
        if !self.data_in_code.is_empty() {
            // Align to 4 bytes
            while data.len() % 4 != 0 {
                data.push(0);
            }
            offsets.data_in_code_off = data.len() as u32;
            offsets.data_in_code_size = self.data_in_code.len() as u32;
            data.extend_from_slice(&self.data_in_code);
        }

        // 3. Symbol table - align to 8 bytes
        while data.len() % 8 != 0 {
            data.push(0);
        }
        offsets.symtab_off = data.len() as u32;

        // Collect all symbol names first (to avoid borrow conflicts)
        let all_names: Vec<Vec<u8>> = self
            .local_symbols
            .iter()
            .chain(self.exported_symbols.iter())
            .chain(self.undefined_symbols.iter())
            .map(|s| s.name.clone())
            .collect();

        // Add all symbol names to the string table and record offsets
        let string_offsets: Vec<u32> = all_names
            .iter()
            .map(|name| {
                if name.is_empty() {
                    0u32
                } else {
                    self.add_string(name)
                }
            })
            .collect();

        // Now write symbols with correct string indices
        let all_symbols = self
            .local_symbols
            .iter()
            .chain(self.exported_symbols.iter())
            .chain(self.undefined_symbols.iter());

        for (sym, &n_strx) in all_symbols.zip(string_offsets.iter()) {
            // nlist64 structure: n_strx(4) + n_type(1) + n_sect(1) + n_desc(2) + n_value(8) = 16 bytes
            data.extend_from_slice(&n_strx.to_le_bytes());
            data.push(sym.n_type);
            data.push(sym.n_sect);
            data.extend_from_slice(&sym.n_desc.to_le_bytes());
            data.extend_from_slice(&sym.n_value.to_le_bytes());
        }

        offsets.nsyms = (self.local_symbols.len()
            + self.exported_symbols.len()
            + self.undefined_symbols.len()) as u32;
        offsets.nlocalsym = self.local_symbols.len() as u32;
        offsets.nextdefsym = self.exported_symbols.len() as u32;
        offsets.nundefsym = self.undefined_symbols.len() as u32;

        // 4. String table
        offsets.strtab_off = data.len() as u32;
        offsets.strtab_size = self.strings.len() as u32;
        data.extend_from_slice(&self.strings);

        // Pad to 8-byte alignment
        while data.len() % 8 != 0 {
            data.push(0);
        }

        (data, offsets)
    }
}

/// Offsets within the rebuilt LINKEDIT.
#[derive(Default)]
struct LinkeditOffsets {
    function_starts_off: u32,
    function_starts_size: u32,
    data_in_code_off: u32,
    data_in_code_size: u32,
    symtab_off: u32,
    nsyms: u32,
    strtab_off: u32,
    strtab_size: u32,
    nlocalsym: u32,
    nextdefsym: u32,
    nundefsym: u32,
}

/// Reads data at a file offset from the cache.
///
/// LINKEDIT data is referenced by file offset, not virtual address.
/// This helper converts file offset to address and reads.
fn read_cache_at_file_offset(cache: &DyldContext, offset: usize, len: usize) -> Option<&[u8]> {
    // Convert file offset to virtual address, then read
    let addr = cache.offset_to_addr(offset as u64)?;
    cache.data_at_addr(addr, len).ok()
}

/// Reads symbols from an image in the cache.
fn read_image_symbols(
    cache: &DyldContext,
    image_path: &str,
    mapping: &ImageSegmentMapping,
) -> Result<(Vec<MergedSymbol>, Vec<MergedSymbol>, Vec<MergedSymbol>)> {
    let image = cache
        .find_image(image_path)
        .ok_or_else(|| Error::ImageNotFound {
            name: image_path.to_string(),
        })?;

    let header_data = cache.data_at_addr(image.address, MachHeader64::SIZE)?;
    let header = MachHeader64::read_from_prefix(header_data)
        .map_err(|_| Error::InvalidMachoMagic(0))?
        .0;

    let header_and_cmds_size = MachHeader64::SIZE + header.sizeofcmds as usize;
    let header_and_cmds = cache.data_at_addr(image.address, header_and_cmds_size)?;

    // Find LC_SYMTAB and LC_DYSYMTAB
    let mut symtab: Option<SymtabCommand> = None;
    let mut dysymtab: Option<DysymtabCommand> = None;

    let mut offset = MachHeader64::SIZE;
    for _ in 0..header.ncmds {
        if offset + 8 > header_and_cmds.len() {
            break;
        }
        let cmd = u32::from_le_bytes(header_and_cmds[offset..offset + 4].try_into().unwrap());
        let cmdsize =
            u32::from_le_bytes(header_and_cmds[offset + 4..offset + 8].try_into().unwrap())
                as usize;

        if cmd == LC_SYMTAB && offset + SymtabCommand::SIZE <= header_and_cmds.len() {
            symtab = Some(
                SymtabCommand::read_from_prefix(&header_and_cmds[offset..])
                    .map_err(|_| Error::Parse {
                        offset,
                        reason: "failed to parse LC_SYMTAB".into(),
                    })?
                    .0,
            );
        } else if cmd == LC_DYSYMTAB && offset + DysymtabCommand::SIZE <= header_and_cmds.len() {
            dysymtab = Some(
                DysymtabCommand::read_from_prefix(&header_and_cmds[offset..])
                    .map_err(|_| Error::Parse {
                        offset,
                        reason: "failed to parse LC_DYSYMTAB".into(),
                    })?
                    .0,
            );
        }

        offset += cmdsize;
    }

    let mut local_syms = Vec::new();
    let mut exported_syms = Vec::new();
    let mut undefined_syms = Vec::new();

    let Some(symtab) = symtab else {
        return Ok((local_syms, exported_syms, undefined_syms));
    };
    let Some(dysymtab) = dysymtab else {
        return Ok((local_syms, exported_syms, undefined_syms));
    };

    // Helper to read a single symbol
    let read_symbol = |sym_index: u32| -> Option<MergedSymbol> {
        let nlist_offset = symtab.symoff as usize + (sym_index as usize * Nlist64::SIZE);

        // Read nlist data from cache at file offset
        let nlist_data = read_cache_at_file_offset(cache, nlist_offset, Nlist64::SIZE)?;

        let nlist = Nlist64::read_from_prefix(nlist_data).ok()?.0;

        // Read symbol name from string table
        let name_offset = symtab.stroff as usize + nlist.n_strx as usize;
        let name = if let Some(name_data) = read_cache_at_file_offset(cache, name_offset, 512) {
            let end = name_data
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_data.len());
            name_data[..end].to_vec()
        } else {
            Vec::new()
        };

        // Adjust symbol value if it's a defined symbol
        let mut n_value = nlist.n_value;
        if nlist.n_sect != 0 && n_value != 0 {
            // This is a defined symbol - translate its address
            if let Some(translated) = mapping.translate(n_value) {
                n_value = translated;
            }
        }

        Some(MergedSymbol {
            name,
            n_type: nlist.n_type,
            n_sect: nlist.n_sect,
            n_desc: nlist.n_desc,
            n_value,
        })
    };

    // Read local symbols
    for i in 0..dysymtab.nlocalsym.min(10000) {
        // Limit to prevent runaway
        let sym_index = dysymtab.ilocalsym + i;
        if let Some(sym) = read_symbol(sym_index) {
            local_syms.push(sym);
        }
    }

    // Read exported symbols
    for i in 0..dysymtab.nextdefsym.min(10000) {
        let sym_index = dysymtab.iextdefsym + i;
        if let Some(sym) = read_symbol(sym_index) {
            exported_syms.push(sym);
        }
    }

    // Read undefined symbols
    for i in 0..dysymtab.nundefsym.min(10000) {
        let sym_index = dysymtab.iundefsym + i;
        if let Some(sym) = read_symbol(sym_index) {
            undefined_syms.push(sym);
        }
    }

    Ok((local_syms, exported_syms, undefined_syms))
}

/// Reads function starts data from the primary image.
fn read_function_starts(cache: &DyldContext, image_path: &str) -> Result<Vec<u8>> {
    let image = cache
        .find_image(image_path)
        .ok_or_else(|| Error::ImageNotFound {
            name: image_path.to_string(),
        })?;

    let header_data = cache.data_at_addr(image.address, MachHeader64::SIZE)?;
    let header = MachHeader64::read_from_prefix(header_data)
        .map_err(|_| Error::InvalidMachoMagic(0))?
        .0;

    let header_and_cmds_size = MachHeader64::SIZE + header.sizeofcmds as usize;
    let header_and_cmds = cache.data_at_addr(image.address, header_and_cmds_size)?;

    let mut offset = MachHeader64::SIZE;
    for _ in 0..header.ncmds {
        if offset + 8 > header_and_cmds.len() {
            break;
        }
        let cmd = u32::from_le_bytes(header_and_cmds[offset..offset + 4].try_into().unwrap());
        let cmdsize =
            u32::from_le_bytes(header_and_cmds[offset + 4..offset + 8].try_into().unwrap())
                as usize;

        if cmd == LC_FUNCTION_STARTS && offset + 16 <= header_and_cmds.len() {
            let dataoff =
                u32::from_le_bytes(header_and_cmds[offset + 8..offset + 12].try_into().unwrap());
            let datasize = u32::from_le_bytes(
                header_and_cmds[offset + 12..offset + 16]
                    .try_into()
                    .unwrap(),
            );

            if datasize > 0 && datasize < 0x100000 {
                // Limit to 1MB for sanity
                if let Some(data) =
                    read_cache_at_file_offset(cache, dataoff as usize, datasize as usize)
                {
                    return Ok(data.to_vec());
                }
            }
        }

        offset += cmdsize;
    }

    Ok(Vec::new())
}

/// Rebuilds the LINKEDIT segment with merged symbol tables.
///
/// This combines the symbol tables from all merged images into a single
/// LINKEDIT segment at the end of the file. The LINKEDIT contains:
/// 1. Function starts (from primary image)
/// 2. Data-in-code (from primary image, if present)
/// 3. Merged symbol table (symbols from all images with adjusted addresses)
/// 4. Merged string table
pub fn rebuild_merged_linkedit(ctx: &mut MergeContext) -> Result<()> {
    let mut builder = LinkeditBuilder::new();

    // Read function starts from primary image
    if let Ok(func_starts) = read_function_starts(&ctx.cache, &ctx.primary_path) {
        builder.function_starts = func_starts;
    }

    // Collect symbols from all merged images
    let mut total_local = 0usize;
    let mut total_exported = 0usize;
    let mut total_undefined = 0usize;

    for mapping in &ctx.mappings {
        match read_image_symbols(&ctx.cache, &mapping.path, mapping) {
            Ok((local, exported, undefined)) => {
                let local_count = local.len();
                let exported_count = exported.len();
                let undefined_count = undefined.len();

                // Add symbols to builder
                builder.local_symbols.extend(local);
                builder.exported_symbols.extend(exported);
                builder.undefined_symbols.extend(undefined);

                total_local += local_count;
                total_exported += exported_count;
                total_undefined += undefined_count;

                if ctx.verbosity >= 2 {
                    debug!(
                        "Collected {} local, {} exported, {} undefined symbols from {}",
                        local_count, exported_count, undefined_count, mapping.path
                    );
                }
            }
            Err(e) => {
                if ctx.verbosity >= 2 {
                    warn!("Failed to read symbols from {}: {}", mapping.path, e);
                }
            }
        }
    }

    if ctx.verbosity >= 1 {
        info!(
            "Total symbols collected: {} local, {} exported, {} undefined",
            total_local, total_exported, total_undefined
        );
    }

    // Build the LINKEDIT data
    let (linkedit_data, offsets) = builder.build();

    // Find load command offsets
    let header = MachHeader64::read_from_prefix(&ctx.data)
        .map_err(|_| Error::InvalidMachoMagic(0))?
        .0;

    let mut symtab_cmd_offset: Option<usize> = None;
    let mut dysymtab_cmd_offset: Option<usize> = None;
    let mut linkedit_seg_offset: Option<usize> = None;
    let mut func_starts_cmd_offset: Option<usize> = None;
    let mut data_in_code_cmd_offset: Option<usize> = None;

    let mut offset = MachHeader64::SIZE;
    for _ in 0..header.ncmds {
        if offset + 8 > ctx.data.len() {
            break;
        }
        let cmd = u32::from_le_bytes(ctx.data[offset..offset + 4].try_into().unwrap());
        let cmdsize =
            u32::from_le_bytes(ctx.data[offset + 4..offset + 8].try_into().unwrap()) as usize;

        match cmd {
            LC_SYMTAB => symtab_cmd_offset = Some(offset),
            LC_DYSYMTAB => dysymtab_cmd_offset = Some(offset),
            LC_FUNCTION_STARTS => func_starts_cmd_offset = Some(offset),
            LC_DATA_IN_CODE => data_in_code_cmd_offset = Some(offset),
            LC_SEGMENT_64 if offset + 24 <= ctx.data.len() => {
                let mut name_bytes = [0u8; 16];
                name_bytes.copy_from_slice(&ctx.data[offset + 8..offset + 24]);
                let name_end = name_bytes.iter().position(|&b| b == 0).unwrap_or(16);
                if &name_bytes[..name_end] == b"__LINKEDIT" {
                    linkedit_seg_offset = Some(offset);
                }
            }
            _ => {}
        }

        offset += cmdsize;
    }

    // Calculate LINKEDIT position (page-aligned at end of data)
    let linkedit_start = align_up(ctx.data.len() as u64, PAGE_SIZE);
    let linkedit_size = align_up(linkedit_data.len() as u64, PAGE_SIZE);

    // Resize buffer and write LINKEDIT
    ctx.data
        .resize(linkedit_start as usize + linkedit_size as usize, 0);
    ctx.data[linkedit_start as usize..linkedit_start as usize + linkedit_data.len()]
        .copy_from_slice(&linkedit_data);

    let linkedit_fileoff = linkedit_start as u32;

    // Update __LINKEDIT segment
    if let Some(le_off) = linkedit_seg_offset {
        // fileoff
        ctx.data[le_off + 40..le_off + 48].copy_from_slice(&linkedit_start.to_le_bytes());
        // filesize
        ctx.data[le_off + 48..le_off + 56].copy_from_slice(&linkedit_size.to_le_bytes());
        // vmsize (page-aligned)
        ctx.data[le_off + 32..le_off + 40].copy_from_slice(&linkedit_size.to_le_bytes());
    }

    // Update LC_SYMTAB
    if let Some(sym_off) = symtab_cmd_offset {
        let symoff = linkedit_fileoff + offsets.symtab_off;
        let stroff = linkedit_fileoff + offsets.strtab_off;
        ctx.data[sym_off + 8..sym_off + 12].copy_from_slice(&symoff.to_le_bytes());
        ctx.data[sym_off + 12..sym_off + 16].copy_from_slice(&offsets.nsyms.to_le_bytes());
        ctx.data[sym_off + 16..sym_off + 20].copy_from_slice(&stroff.to_le_bytes());
        ctx.data[sym_off + 20..sym_off + 24].copy_from_slice(&offsets.strtab_size.to_le_bytes());
    }

    // Update LC_DYSYMTAB
    if let Some(dsym_off) = dysymtab_cmd_offset {
        // ilocalsym (offset 8)
        ctx.data[dsym_off + 8..dsym_off + 12].copy_from_slice(&0u32.to_le_bytes());
        // nlocalsym (offset 12)
        ctx.data[dsym_off + 12..dsym_off + 16].copy_from_slice(&offsets.nlocalsym.to_le_bytes());
        // iextdefsym (offset 16)
        ctx.data[dsym_off + 16..dsym_off + 20].copy_from_slice(&offsets.nlocalsym.to_le_bytes());
        // nextdefsym (offset 20)
        ctx.data[dsym_off + 20..dsym_off + 24].copy_from_slice(&offsets.nextdefsym.to_le_bytes());
        // iundefsym (offset 24)
        let iundefsym = offsets.nlocalsym + offsets.nextdefsym;
        ctx.data[dsym_off + 24..dsym_off + 28].copy_from_slice(&iundefsym.to_le_bytes());
        // nundefsym (offset 28)
        ctx.data[dsym_off + 28..dsym_off + 32].copy_from_slice(&offsets.nundefsym.to_le_bytes());
        // Zero out remaining fields
        for i in (dsym_off + 32..dsym_off + DysymtabCommand::SIZE).step_by(4) {
            if i + 4 <= ctx.data.len() {
                ctx.data[i..i + 4].copy_from_slice(&0u32.to_le_bytes());
            }
        }
    }

    // Update LC_FUNCTION_STARTS
    if let Some(fs_off) = func_starts_cmd_offset {
        if offsets.function_starts_size > 0 {
            let dataoff = linkedit_fileoff + offsets.function_starts_off;
            ctx.data[fs_off + 8..fs_off + 12].copy_from_slice(&dataoff.to_le_bytes());
            ctx.data[fs_off + 12..fs_off + 16]
                .copy_from_slice(&offsets.function_starts_size.to_le_bytes());
        } else {
            ctx.data[fs_off + 8..fs_off + 12].copy_from_slice(&0u32.to_le_bytes());
            ctx.data[fs_off + 12..fs_off + 16].copy_from_slice(&0u32.to_le_bytes());
        }
    }

    // Update LC_DATA_IN_CODE
    if let Some(dic_off) = data_in_code_cmd_offset {
        if offsets.data_in_code_size > 0 {
            let dataoff = linkedit_fileoff + offsets.data_in_code_off;
            ctx.data[dic_off + 8..dic_off + 12].copy_from_slice(&dataoff.to_le_bytes());
            ctx.data[dic_off + 12..dic_off + 16]
                .copy_from_slice(&offsets.data_in_code_size.to_le_bytes());
        } else {
            ctx.data[dic_off + 8..dic_off + 12].copy_from_slice(&0u32.to_le_bytes());
            ctx.data[dic_off + 12..dic_off + 16].copy_from_slice(&0u32.to_le_bytes());
        }
    }

    if ctx.verbosity >= 1 {
        info!(
            "Rebuilt LINKEDIT: {} symbols ({} local, {} exported, {} undefined), {} bytes",
            offsets.nsyms,
            offsets.nlocalsym,
            offsets.nextdefsym,
            offsets.nundefsym,
            linkedit_data.len()
        );
    }

    Ok(())
}

/// Flag for MH_DYLIB_IN_CACHE
const MH_DYLIB_IN_CACHE: u32 = 0x8000_0000;

/// Load command for chained fixups
const LC_DYLD_CHAINED_FIXUPS: u32 = 0x80000034;

/// Load command for exports trie
const LC_DYLD_EXPORTS_TRIE: u32 = 0x80000033;

/// Load command for function starts
const LC_FUNCTION_STARTS: u32 = 0x26;

/// Load command for data in code
const LC_DATA_IN_CODE: u32 = 0x29;

/// Load command for code signature
const LC_CODE_SIGNATURE: u32 = 0x1D;

/// Load command for segment split info
const LC_SEGMENT_SPLIT_INFO: u32 = 0x1E;

/// Scans the merged output for references to shared cache regions.
/// Returns a list of (start_addr, end_addr) for regions that need to be included.
pub fn scan_shared_region_refs(ctx: &MergeContext) -> Vec<(u64, u64)> {
    let mut refs: HashSet<u64> = HashSet::new();

    // Build set of all image address ranges for quick lookup
    let mut image_ranges: Vec<(u64, u64)> = Vec::new();
    for mapping in &ctx.mappings {
        image_ranges.push((mapping.original_base, mapping.original_base + mapping.size));
    }

    if ctx.verbosity >= 2 {
        debug!(
            "Scanning for shared region refs, {} image ranges",
            image_ranges.len()
        );
    }

    // Scan ALL dependency segments' DATA sections
    // The dependency segments know where data is in ctx.data
    for dep_seg in &ctx.dependency_segments {
        // Only scan DATA segments (not TEXT)
        if !dep_seg.name.contains("DATA")
            && !dep_seg.name.contains("AUTH")
            && !dep_seg.name.contains("CONST")
        {
            continue;
        }

        if dep_seg.fileoff > 0 && dep_seg.filesize > 0 {
            let start = dep_seg.fileoff as usize;
            let end = start + dep_seg.filesize as usize;

            if end <= ctx.data.len() {
                // Scan for 8-byte pointer values
                for i in (start..end).step_by(8) {
                    if i + 8 > ctx.data.len() {
                        break;
                    }
                    let ptr = u64::from_le_bytes(ctx.data[i..i + 8].try_into().unwrap());

                    // Skip null and values outside cache address range
                    // Cache typically starts at 0x180000000 for arm64
                    if ptr < 0x180000000 {
                        continue;
                    }

                    // Strip PAC bits
                    let clean_ptr = ptr & 0x0000_FFFF_FFFF_FFFF;

                    // Skip if still outside reasonable cache range
                    if clean_ptr < 0x180000000 || clean_ptr > 0x500000000 {
                        continue;
                    }

                    // Check if this points to a shared region (not in any image)
                    let in_image = image_ranges
                        .iter()
                        .any(|(s, e)| clean_ptr >= *s && clean_ptr < *e);

                    if !in_image {
                        // This might be a shared cache region reference
                        refs.insert(clean_ptr);
                    }
                }
            }
        }
    }

    // Also scan the primary image's DATA sections from the header
    let header = match MachHeader64::read_from_prefix(&ctx.data) {
        Ok((h, _)) => h,
        Err(_) => return Vec::new(),
    };

    let mut offset = MachHeader64::SIZE;
    for _ in 0..header.ncmds {
        if offset + 8 > ctx.data.len() {
            break;
        }
        let cmd = u32::from_le_bytes(ctx.data[offset..offset + 4].try_into().unwrap());
        let cmdsize =
            u32::from_le_bytes(ctx.data[offset + 4..offset + 8].try_into().unwrap()) as usize;

        if cmd == LC_SEGMENT_64 && offset + SegmentCommand64::SIZE <= ctx.data.len() {
            let seg = match SegmentCommand64::read_from_prefix(&ctx.data[offset..]) {
                Ok((s, _)) => s,
                Err(_) => {
                    offset += cmdsize;
                    continue;
                }
            };

            let segname = {
                let end = seg.segname.iter().position(|&b| b == 0).unwrap_or(16);
                std::str::from_utf8(&seg.segname[..end]).unwrap_or("")
            };

            // Scan DATA segments for pointer references (only primary, deps done above)
            if (segname.contains("DATA") || segname.contains("AUTH") || segname.contains("CONST"))
                && !segname.starts_with("__D")
            {
                if seg.fileoff > 0 && seg.filesize > 0 {
                    let start = seg.fileoff as usize;
                    let end = start + seg.filesize as usize;
                    if end <= ctx.data.len() {
                        // Scan for 8-byte pointer values
                        for i in (start..end).step_by(8) {
                            if i + 8 > ctx.data.len() {
                                break;
                            }
                            let ptr = u64::from_le_bytes(ctx.data[i..i + 8].try_into().unwrap());

                            // Skip values outside cache address range
                            if ptr < 0x180000000 {
                                continue;
                            }

                            // Strip PAC bits
                            let clean_ptr = ptr & 0x0000_FFFF_FFFF_FFFF;

                            // Skip if still outside reasonable cache range
                            if clean_ptr < 0x180000000 || clean_ptr > 0x500000000 {
                                continue;
                            }

                            // Check if this points to a shared region (not in any image)
                            let in_image = image_ranges
                                .iter()
                                .any(|(s, e)| clean_ptr >= *s && clean_ptr < *e);

                            if !in_image {
                                // This might be a shared cache region reference
                                refs.insert(clean_ptr);
                            }
                        }
                    }
                }
            }
        }
        offset += cmdsize;
    }

    if ctx.verbosity >= 2 {
        debug!(
            "Scanning for shared region refs, {} image ranges",
            image_ranges.len()
        );
    }

    // Scan the merged data for pointer-like values
    // Focus on DATA sections which contain GOT, objc metadata, etc.
    let header = match MachHeader64::read_from_prefix(&ctx.data) {
        Ok((h, _)) => h,
        Err(_) => return Vec::new(),
    };

    let mut offset = MachHeader64::SIZE;
    for _ in 0..header.ncmds {
        if offset + 8 > ctx.data.len() {
            break;
        }
        let cmd = u32::from_le_bytes(ctx.data[offset..offset + 4].try_into().unwrap());
        let cmdsize =
            u32::from_le_bytes(ctx.data[offset + 4..offset + 8].try_into().unwrap()) as usize;

        if cmd == LC_SEGMENT_64 && offset + SegmentCommand64::SIZE <= ctx.data.len() {
            let seg = match SegmentCommand64::read_from_prefix(&ctx.data[offset..]) {
                Ok((s, _)) => s,
                Err(_) => {
                    offset += cmdsize;
                    continue;
                }
            };

            let segname = {
                let end = seg.segname.iter().position(|&b| b == 0).unwrap_or(16);
                std::str::from_utf8(&seg.segname[..end]).unwrap_or("")
            };

            // Scan DATA segments for pointer references
            if segname.contains("DATA") || segname.contains("AUTH") || segname.contains("CONST") {
                if seg.fileoff > 0 && seg.filesize > 0 {
                    let start = seg.fileoff as usize;
                    let end = start + seg.filesize as usize;
                    if end <= ctx.data.len() {
                        // Scan for 8-byte pointer values
                        for i in (start..end).step_by(8) {
                            if i + 8 > ctx.data.len() {
                                break;
                            }
                            let raw_ptr =
                                u64::from_le_bytes(ctx.data[i..i + 8].try_into().unwrap());

                            // Skip null and small values
                            if raw_ptr < 0x100000000 {
                                continue;
                            }

                            let ptr_addr = seg.vmaddr + (i - start) as u64;
                            let decoded_ptr = decode_shared_pointer(&ctx.cache, ptr_addr, raw_ptr);

                            // Strip PAC bits
                            let clean_ptr = decoded_ptr & 0x0000_FFFF_FFFF_FFFF;

                            if clean_ptr < 0x100000000 {
                                continue;
                            }

                            // Check if this points to a shared region (not in any image)
                            let in_image = image_ranges
                                .iter()
                                .any(|(start, end)| clean_ptr >= *start && clean_ptr < *end);

                            if !in_image {
                                // This might be a shared cache region reference
                                refs.insert(clean_ptr);
                            }
                        }
                    }
                }
            }
        }
        offset += cmdsize;
    }

    if ctx.verbosity >= 2 {
        debug!("Found {} unique shared region refs", refs.len());
        if ctx.verbosity >= 3 && !refs.is_empty() {
            let mut sample: Vec<_> = refs.iter().take(10).copied().collect();
            sample.sort();
            for addr in sample {
                debug!("  Sample ref: 0x{:x}", addr);
            }
        }
    }

    if refs.is_empty() {
        return Vec::new();
    }

    // Group nearby references into contiguous regions
    let mut sorted_refs: Vec<u64> = refs.into_iter().collect();
    sorted_refs.sort();

    let mut regions = Vec::new();
    let mut region_start = sorted_refs[0];
    let mut region_end = region_start + 8;

    for &addr in &sorted_refs[1..] {
        // If this address is within 4KB of the current region, extend it
        if addr <= region_end + 0x1000 {
            region_end = addr + 8;
        } else {
            // Start a new region, but expand to page boundaries
            let aligned_start = region_start & !0xFFF;
            let aligned_end = (region_end + 0xFFF) & !0xFFF;
            regions.push((aligned_start, aligned_end));
            region_start = addr;
            region_end = addr + 8;
        }
    }

    // Don't forget the last region
    let aligned_start = region_start & !0xFFF;
    let aligned_end = (region_end + 0xFFF) & !0xFFF;
    regions.push((aligned_start, aligned_end));

    regions
}

/// Includes shared cache DATA regions in the merged output.
/// This copies the data from the cache and adds segment commands.
pub fn include_shared_regions(ctx: &mut MergeContext) -> Result<()> {
    let regions = scan_shared_region_refs(ctx);

    if regions.is_empty() {
        return Ok(());
    }

    let mut included_count = 0;
    let mut total_size = 0u64;

    // Current end of file (where we'll append shared regions)
    let mut next_fileoff = align_up(ctx.data.len() as u64, PAGE_SIZE);

    for (idx, (start, end)) in regions.iter().enumerate() {
        let size = end - start;

        // Limit region size to prevent including huge chunks
        if size > 0x1000000 {
            // Skip regions > 16MB
            if ctx.verbosity >= 2 {
                warn!(
                    "Skipping large shared region 0x{:x}-0x{:x} ({} MB)",
                    start,
                    end,
                    size / 0x100000
                );
            }
            continue;
        }

        // Read region data from cache
        let region_data = match ctx.cache.data_at_addr(*start, size as usize) {
            Ok(data) => data,
            Err(_) => {
                if ctx.verbosity >= 2 {
                    debug!("Could not read shared region 0x{:x}-0x{:x}", start, end);
                }
                continue;
            }
        };

        // Append to merged output
        let fileoff = next_fileoff;
        ctx.data.resize(fileoff as usize + size as usize, 0);
        ctx.data[fileoff as usize..fileoff as usize + size as usize].copy_from_slice(region_data);

        // Track this shared region
        ctx.shared_regions.push(SharedRegion {
            name: format!("__SHARED_{}", idx),
            orig_vmaddr: *start,
            size,
            fileoff,
            prot: 0x3, // RW
        });

        // Add a dependency segment for this region
        ctx.dependency_segments.push(DependencySegment {
            name: format!("__S{}_DATA", idx),
            vmaddr: *start,
            vmsize: size,
            fileoff,
            filesize: size,
            maxprot: 0x3,  // RW
            initprot: 0x1, // R
        });

        next_fileoff = align_up(fileoff + size, PAGE_SIZE);
        included_count += 1;
        total_size += size;
    }

    if ctx.verbosity >= 1 && included_count > 0 {
        info!(
            "Included {} shared cache regions ({} bytes)",
            included_count, total_size
        );
    }

    Ok(())
}

/// Decodes a pointer stored in a slid cache mapping.
fn decode_shared_pointer(cache: &DyldContext, addr: u64, raw: u64) -> u64 {
    let Some(mapping) = cache.mapping_for_addr(addr) else {
        return raw;
    };
    if !mapping.has_slide_info() {
        return raw;
    }

    let cache_data = cache.data_for_subcache(mapping.subcache_index);
    let offset = mapping.slide_info_offset as usize;
    if offset + 4 > cache_data.len() {
        return raw;
    }

    let version = u32::from_le_bytes([
        cache_data[offset],
        cache_data[offset + 1],
        cache_data[offset + 2],
        cache_data[offset + 3],
    ]);

    match version {
        5 => {
            if let Ok((slide_info, _)) =
                DyldCacheSlideInfo5::read_from_prefix(&cache_data[offset..])
            {
                let ptr = SlidePointer5(raw);
                if ptr.is_auth() {
                    return ptr.runtime_offset() + slide_info.value_add;
                }
                let runtime_offset = ptr.runtime_offset();
                let high8 = (ptr.high8() as u64) << 56;
                return runtime_offset + slide_info.value_add + high8;
            }
        }
        3 => {
            if let Ok((slide_info, _)) =
                DyldCacheSlideInfo3::read_from_prefix(&cache_data[offset..])
            {
                let ptr = SlidePointer3(raw);
                if ptr.is_auth() {
                    return ptr.auth_offset() as u64 + slide_info.auth_value_add;
                }
                return ptr.plain_value();
            }
        }
        2 => {
            if let Ok((slide_info, _)) =
                DyldCacheSlideInfo2::read_from_prefix(&cache_data[offset..])
            {
                return (raw & slide_info.value_mask()) + slide_info.value_add;
            }
        }
        _ => {}
    }

    raw
}

/// Resolves indirect pointers in GOT, auth, and selector sections.
/// This rewrites pointers to point directly to their targets.
pub fn resolve_indirect_pointers(ctx: &mut MergeContext) -> Result<()> {
    let mut resolved_count = 0usize;

    // Parse the header to find pointer sections
    let header = MachHeader64::read_from_prefix(&ctx.data)
        .map_err(|_| Error::InvalidMachoMagic(0))?
        .0;

    let mut offset = MachHeader64::SIZE;
    for _ in 0..header.ncmds {
        if offset + 8 > ctx.data.len() {
            break;
        }
        let cmd = u32::from_le_bytes(ctx.data[offset..offset + 4].try_into().unwrap());
        let cmdsize =
            u32::from_le_bytes(ctx.data[offset + 4..offset + 8].try_into().unwrap()) as usize;

        if cmd == LC_SEGMENT_64 && offset + SegmentCommand64::SIZE <= ctx.data.len() {
            let nsects = u32::from_le_bytes(ctx.data[offset + 64..offset + 68].try_into().unwrap());

            let mut sect_offset = offset + SegmentCommand64::SIZE;
            for _ in 0..nsects {
                if sect_offset + Section64::SIZE > ctx.data.len() {
                    break;
                }

                let sect = match Section64::read_from_prefix(&ctx.data[sect_offset..]) {
                    Ok((s, _)) => s,
                    Err(_) => {
                        sect_offset += Section64::SIZE;
                        continue;
                    }
                };

                let sect_name = sect.name();

                // Only process GOT and auth pointer sections
                if sect_name == "__got"
                    || sect_name == "__la_symbol_ptr"
                    || sect_name == "__nl_symbol_ptr"
                {
                    if sect.offset > 0 && sect.size > 0 {
                        let start = sect.offset as usize;
                        let end = start + sect.size as usize;

                        if end <= ctx.data.len() {
                            // Process each pointer in the section
                            for i in (start..end).step_by(8) {
                                if i + 8 > ctx.data.len() {
                                    break;
                                }

                                let raw_ptr =
                                    u64::from_le_bytes(ctx.data[i..i + 8].try_into().unwrap());
                                if raw_ptr == 0 {
                                    continue;
                                }

                                let ptr_addr = sect.addr + (i - start) as u64;
                                let decoded_ptr =
                                    decode_shared_pointer(&ctx.cache, ptr_addr, raw_ptr);

                                // Strip PAC bits for lookup
                                let clean_ptr = decoded_ptr & 0x0000_FFFF_FFFF_FFFF;

                                // Try to resolve: if the pointer is in a shared region we included,
                                // read the value at that location (which is the actual target)
                                if let Some(shared_offset) = ctx.shared_region_offset(clean_ptr) {
                                    let shared_off = shared_offset as usize;
                                    if shared_off + 8 <= ctx.data.len() {
                                        let raw_target = u64::from_le_bytes(
                                            ctx.data[shared_off..shared_off + 8]
                                                .try_into()
                                                .unwrap(),
                                        );

                                        if raw_target != 0 {
                                            let target = decode_shared_pointer(
                                                &ctx.cache, clean_ptr, raw_target,
                                            );

                                            // Try to translate the target to merged address
                                            let addr_mask = 0x0000_FFFF_FFFF_FFFF;
                                            let clean_target = target & addr_mask;
                                            let resolved_addr = if let Some(translated) =
                                                ctx.translate_addr(clean_target)
                                            {
                                                translated
                                            } else if ctx.is_in_shared_region(clean_target) {
                                                clean_target
                                            } else {
                                                continue;
                                            };

                                            // Preserve high bits (PAC/tag) from the resolved target
                                            let high_bits = target & !addr_mask;
                                            let new_ptr = high_bits | resolved_addr;
                                            ctx.data[i..i + 8]
                                                .copy_from_slice(&new_ptr.to_le_bytes());
                                            resolved_count += 1;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }

                sect_offset += Section64::SIZE;
            }
        }
        offset += cmdsize;
    }

    // Also resolve entries inside included shared regions (shared GOT pages).
    for region in &ctx.shared_regions {
        let start = region.fileoff as usize;
        let end = start + region.size as usize;
        if end > ctx.data.len() {
            continue;
        }

        for offset in (start..end).step_by(8) {
            if offset + 8 > ctx.data.len() {
                break;
            }

            let raw_value = u64::from_le_bytes(ctx.data[offset..offset + 8].try_into().unwrap());
            if raw_value == 0 {
                continue;
            }

            let ptr_addr = region.orig_vmaddr + (offset - start) as u64;
            let decoded_value = decode_shared_pointer(&ctx.cache, ptr_addr, raw_value);

            let addr_mask = 0x0000_FFFF_FFFF_FFFFu64;
            let high_bits = decoded_value & !addr_mask;
            let addr_value = decoded_value & addr_mask;

            if addr_value < 0x100000000 {
                continue;
            }

            let resolved_addr = if let Some(translated) = ctx.translate_addr(addr_value) {
                translated
            } else if ctx.is_in_shared_region(addr_value) {
                addr_value
            } else {
                continue;
            };

            let new_value = high_bits | resolved_addr;
            if new_value != raw_value {
                ctx.data[offset..offset + 8].copy_from_slice(&new_value.to_le_bytes());
                resolved_count += 1;
            }
        }
    }

    if ctx.verbosity >= 1 && resolved_count > 0 {
        info!("Resolved {} indirect pointers", resolved_count);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 0x1000), 0);
        assert_eq!(align_up(1, 0x1000), 0x1000);
        assert_eq!(align_up(0x1000, 0x1000), 0x1000);
        assert_eq!(align_up(0x1001, 0x1000), 0x2000);
    }

    #[test]
    fn test_normalize_path() {
        // Plain dylibs
        assert_eq!(
            normalize_path("@rpath/libobjc.A.dylib"),
            "/usr/lib/libobjc.A.dylib"
        );

        // Absolute paths pass through unchanged
        assert_eq!(normalize_path("/usr/lib/libc.dylib"), "/usr/lib/libc.dylib");

        // Public frameworks
        assert_eq!(
            normalize_path("@rpath/Foundation.framework/Versions/A/Foundation"),
            "/System/Library/Frameworks/Foundation.framework/Versions/A/Foundation"
        );

        // Private frameworks (must have "Private" in name for auto-detection)
        assert_eq!(
            normalize_path("@rpath/AppleAccountPrivate.framework/AppleAccountPrivate"),
            "/System/Library/PrivateFrameworks/AppleAccountPrivate.framework/Versions/A/AppleAccountPrivate"
        );

        // Regular framework (without "Private" in name goes to public frameworks)
        assert_eq!(
            normalize_path("@rpath/AppleAccount.framework/AppleAccount"),
            "/System/Library/Frameworks/AppleAccount.framework/Versions/A/AppleAccount"
        );

        // Simple framework name (without .framework)
        assert_eq!(
            normalize_path("@rpath/CoreFoundation"),
            "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
        );

        // @executable_path with Frameworks
        assert_eq!(
            normalize_path("@executable_path/../Frameworks/Foo.framework/Foo"),
            "/System/Library/Frameworks/Foo.framework/Versions/A/Foo"
        );

        // @loader_path fallback
        assert_eq!(
            normalize_path("@loader_path/libfoo.dylib"),
            "/usr/lib/libfoo.dylib"
        );
    }
}
