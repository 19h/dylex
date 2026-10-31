//! Kernelcache parsing, search, and extraction.
//!
//! Supports Mach-O kernel collections (`MH_FILESET`) and legacy prelinked
//! kernels (`MH_EXECUTE` with `__PRELINK_INFO`), either raw or wrapped in IMG4
//! or IM4P containers and compressed with LZFSE or complzss.
//!
//! File offsets in fileset members are collection-relative. Legacy prelinked
//! kexts use image-relative offsets and are located through prelink metadata.
//! Extracted images retain unslid virtual addresses and are intended for
//! static analysis.
//!
//! # Example
//!
//! ```no_run
//! use dylex::KernelCacheContext;
//!
//! fn main() -> dylex::Result<()> {
//!     let cache = KernelCacheContext::open("kernelcache.release.mac16j")?;
//!     let sandbox = cache.resolve_image("com.apple.security.sandbox")?;
//!     std::fs::write("sandbox.macho", cache.extract_image(sandbox)?)?;
//!     Ok(())
//! }
//! ```

mod compression;
mod container;
mod discovery;
mod extract;
mod fileset;
mod fixups;
mod lookup;
mod prelink;
mod reader;
mod strings;

pub use compression::Compression;
pub use container::Container;
pub use discovery::{
    CollectionIdentity, DiscoveryCommand, KernelCandidate, KernelDiscoveryReport, KernelUuid,
    discover_kernelcaches,
};

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::OnceLock;

use crate::error::{Error, Result};
use crate::macho::{MH_EXECUTE, MH_FILESET, MH_MAGIC, MH_MAGIC_64, MachOContext, SegmentInfo};

use fixups::Rebase;
use reader::{read_u32, slice, to_usize};

/// Upper bound on input, decoded, and extracted image sizes (1 GiB).
const MAX_SIZE: usize = 1 << 30;

/// Size of `mach_header` and `mach_header_64`.
const MACH_HEADER_SIZE: usize = 28;
const MACH_HEADER_64_SIZE: usize = 32;
/// Offset of `sizeofcmds` in either Mach-O header.
const SIZEOFCMDS_OFFSET: usize = 20;

/// Image ID of the kernel itself.
pub const KERNEL_IMAGE_ID: &str = "com.apple.kernel";

/// Segment whose data is shared collection metadata rather than image contents.
const LINKEDIT_SEGMENT: &str = "__LINKEDIT";

// =============================================================================
// Public Types
// =============================================================================

/// Layout of a decoded kernelcache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelCacheFormat {
    /// An `MH_FILESET` kernel collection with one `LC_FILESET_ENTRY` per image.
    Fileset,
    /// An `MH_EXECUTE` kernel whose kexts are described by `__PRELINK_INFO`.
    Prelinked,
}

impl fmt::Display for KernelCacheFormat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Fileset => "fileset (MH_FILESET)",
            Self::Prelinked => "prelinked (MH_EXECUTE)",
        })
    }
}

/// Container and compression removed while decoding the input.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InputEncoding {
    /// IMG4 or IM4P wrapper, if any.
    pub container: Option<Container>,
    /// Payload compression, if any.
    pub compression: Option<Compression>,
}

/// The kernel or an executable kext embedded in a kernelcache.
///
/// Codeless prelink records are not represented.
#[derive(Debug)]
pub struct KernelImage {
    /// Fileset entry ID or `CFBundleIdentifier`; the kernel is [`KERNEL_IMAGE_ID`].
    pub id: String,
    /// Unslid address of the embedded Mach-O header.
    pub address: u64,
    /// Offset of the embedded Mach-O header in the decoded collection.
    pub file_offset: u64,
    /// Parsed header and load commands. Segment contents remain in the collection.
    pub macho: MachOContext,
    offset_base: OffsetBase,
}

/// How the file offsets in an image's load commands are interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OffsetBase {
    /// Offsets are relative to the start of the collection (fileset members and the kernel).
    Collection,
    /// Offsets are relative to the image's own Mach-O header (legacy prelinked kexts).
    Image,
}

impl KernelImage {
    /// Returns the segment, other than `__LINKEDIT`, whose VM range contains `address`.
    pub fn segment_containing(&self, address: u64) -> Option<&SegmentInfo> {
        self.macho
            .segments()
            .find(|segment| segment.name() != LINKEDIT_SEGMENT && vm_contains(segment, address))
    }

    /// The image header's file offset, expressed in the image's own offset space.
    fn local_header_offset(&self) -> u64 {
        match self.offset_base {
            OffsetBase::Collection => self.file_offset,
            OffsetBase::Image => 0,
        }
    }
}

/// A decoded kernelcache with validated embedded Mach-O headers.
#[derive(Debug)]
pub struct KernelCacheContext {
    /// Decoded collection bytes.
    data: Vec<u8>,
    encoding: InputEncoding,
    /// Outer Mach-O header and load commands.
    pub macho: MachOContext,
    /// The kernel and executable kexts, in container order.
    pub images: Vec<KernelImage>,
    /// Chained-fixup targets for the whole collection, decoded on first use.
    /// Errors are stored as `(offset, reason)` because [`Error`] is not `Clone`.
    rebases: OnceLock<std::result::Result<Vec<Rebase>, (usize, String)>>,
}

// =============================================================================
// Opening and Validation
// =============================================================================

impl KernelCacheContext {
    /// Opens a raw Mach-O, IMG4/IM4P, LZFSE, or complzss kernelcache.
    ///
    /// Encrypted payloads must be decrypted before opening.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        if fs::metadata(path)?.len() > MAX_SIZE as u64 {
            return Err(Error::parse(0, "kernelcache input exceeds 1 GiB"));
        }
        Self::from_vec(fs::read(path)?)
    }

    /// Parses a kernelcache from bytes, removing any supported wrapper or compression.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        Self::from_vec(bytes.to_vec())
    }

    fn from_vec(input: Vec<u8>) -> Result<Self> {
        if input.len() > MAX_SIZE {
            return Err(Error::parse(0, "kernelcache input exceeds 1 GiB"));
        }
        let (data, encoding) = decode_input(input)?;
        let macho = parse_macho_at(&data, 0)?;
        for segment in macho.segments() {
            check_segment_extent(segment, "outer")?;
            let command = &segment.command;
            if command.filesize != 0 {
                slice(
                    &data,
                    to_usize(command.fileoff)?,
                    to_usize(command.filesize)?,
                )?;
            }
        }
        let images = match macho.header.filetype {
            MH_FILESET => fileset::read_images(&data, &macho)?,
            MH_EXECUTE if macho.segment(prelink::PRELINK_INFO_SEGMENT).is_some() => {
                prelink::read_images(&data, &macho)?
            }
            _ => {
                return Err(Error::parse(
                    0,
                    "expected MH_FILESET or a prelinked MH_EXECUTE kernel",
                ));
            }
        };
        let cache = Self {
            data,
            encoding,
            macho,
            images,
            rebases: OnceLock::new(),
        };
        cache.validate_images()?;
        Ok(cache)
    }

    /// Checks image IDs, CPU types, and segment and section extents.
    fn validate_images(&self) -> Result<()> {
        let mut ids = HashSet::with_capacity(self.images.len());
        for image in &self.images {
            if !ids.insert(image.id.as_str()) {
                return Err(Error::parse(
                    0,
                    format!("duplicate kernelcache image ID {:?}", image.id),
                ));
            }
            if image.macho.header.cputype != self.macho.header.cputype {
                return Err(Error::parse(0, "embedded CPU type differs from collection"));
            }
            for segment in image.macho.segments() {
                check_segment_extent(segment, "member")?;
                let command = &segment.command;
                for section in &segment.sections {
                    let within_segment = section
                        .section
                        .addr
                        .checked_sub(command.vmaddr)
                        .and_then(|start| start.checked_add(section.section.size))
                        .is_some_and(|end| end <= command.vmsize);
                    if section.section.size != 0 && !within_segment {
                        return Err(Error::parse(
                            section.struct_offset,
                            "section extends beyond segment VM range",
                        ));
                    }
                }
                if command.filesize != 0 {
                    self.member_bytes(image, command.fileoff, command.filesize)?;
                }
            }
        }
        Ok(())
    }
}

/// Removes an IMG4/IM4P wrapper and LZFSE or complzss compression, if present.
fn decode_input(input: Vec<u8>) -> Result<(Vec<u8>, InputEncoding)> {
    let (container, payload) = match container::unwrap(&input)? {
        Some((container, payload)) => (Some(container), payload),
        None => (None, input.as_slice()),
    };
    let compression = Compression::detect(payload);
    let encoding = InputEncoding {
        container,
        compression,
    };
    let data = match compression {
        Some(compression) => compression.decompress(payload)?,
        None if container.is_some() => payload.to_vec(),
        None => input,
    };
    Ok((data, encoding))
}

/// Parses the Mach-O header and load commands at `offset`.
///
/// Only the header and its commands are copied; segment contents stay in `data`.
fn parse_macho_at(data: &[u8], offset: usize) -> Result<MachOContext> {
    let header_size = match read_u32(data, offset)? {
        MH_MAGIC => MACH_HEADER_SIZE,
        MH_MAGIC_64 => MACH_HEADER_64_SIZE,
        magic => return Err(Error::InvalidMachoMagic(magic)),
    };
    let header = slice(data, offset, header_size)?;
    let commands_size = read_u32(header, SIZEOFCMDS_OFFSET)? as usize;
    let macho = MachOContext::new(slice(data, offset, header_size + commands_size)?, offset)?;
    let parsed_size: usize = macho
        .load_commands
        .iter()
        .map(|command| command.size() as usize)
        .sum();
    if parsed_size != commands_size {
        return Err(Error::parse(offset, "load command count and size disagree"));
    }
    Ok(macho)
}

/// Rejects segments whose VM range overflows or whose file size exceeds their VM size.
fn check_segment_extent(segment: &SegmentInfo, scope: &str) -> Result<()> {
    let command = &segment.command;
    if command.vmaddr.checked_add(command.vmsize).is_none() {
        return Err(Error::parse(
            0,
            format!("{scope} segment {} VM range overflow", segment.name()),
        ));
    }
    if command.filesize > command.vmsize {
        return Err(Error::parse(
            0,
            format!(
                "{scope} segment {} file size exceeds VM size",
                segment.name()
            ),
        ));
    }
    Ok(())
}

/// Returns whether `address` lies in the segment's VM range.
fn vm_contains(segment: &SegmentInfo, address: u64) -> bool {
    address
        .checked_sub(segment.command.vmaddr)
        .is_some_and(|delta| delta < segment.command.vmsize)
}

// =============================================================================
// Accessors
// =============================================================================

impl KernelCacheContext {
    /// Layout of the decoded collection.
    pub fn format(&self) -> KernelCacheFormat {
        if self.macho.header.filetype == MH_FILESET {
            KernelCacheFormat::Fileset
        } else {
            KernelCacheFormat::Prelinked
        }
    }

    /// Container and compression removed while decoding.
    pub fn encoding(&self) -> InputEncoding {
        self.encoding
    }

    /// Architecture recorded in the outer Mach-O header.
    pub fn architecture(&self) -> &str {
        self.macho.header.arch_name()
    }

    /// Size of the decoded collection in bytes.
    pub fn total_size(&self) -> usize {
        self.data.len()
    }

    /// Resolves an exact image ID, then a unique substring.
    ///
    /// Ambiguity is an error listing the candidates; the first match is never
    /// chosen silently.
    pub fn resolve_image(&self, query: &str) -> Result<&KernelImage> {
        if let Some(image) = self.images.iter().find(|image| image.id == query) {
            return Ok(image);
        }
        let candidates: Vec<_> = self
            .images
            .iter()
            .filter(|image| image.id.contains(query))
            .collect();
        match candidates.as_slice() {
            [image] => Ok(image),
            [] => Err(Error::ImageNotFound { name: query.into() }),
            _ => Err(Error::AmbiguousImage {
                query: query.into(),
                candidates: candidates.iter().map(|image| image.id.clone()).collect(),
            }),
        }
    }

    /// Maps an offset from an image's load commands to a collection offset.
    fn member_offset(&self, image: &KernelImage, offset: u64) -> Result<usize> {
        let offset = match image.offset_base {
            OffsetBase::Collection => Some(offset),
            OffsetBase::Image => offset.checked_add(image.file_offset),
        };
        to_usize(offset.ok_or_else(|| Error::parse(0, "member file offset overflow"))?)
    }

    /// Returns `size` bytes at an offset taken from an image's load commands.
    fn member_bytes(&self, image: &KernelImage, offset: u64, size: u64) -> Result<&[u8]> {
        slice(
            &self.data,
            self.member_offset(image, offset)?,
            to_usize(size)?,
        )
    }
}
