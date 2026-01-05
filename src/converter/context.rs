//! Extraction context that holds state during the conversion process.

use std::sync::Arc;

use tracing::{info, warn};

use crate::dyld::DyldContext;
use crate::error::Result;
use crate::macho::MachOContext;

/// Extra segment name for ObjC data that needs to be pulled into the image.
pub const EXTRA_SEGMENT_NAME: &str = "__EXTRA_OBJC";

/// Context for the extraction process.
///
/// This holds all state needed during the multi-step extraction process,
/// including the source cache, the target Mach-O being built, and any
/// extra data segments being created.
#[derive(Debug)]
pub struct ExtractionContext {
    /// Reference to the dyld cache
    pub cache: Arc<DyldContext>,
    /// The Mach-O being extracted and modified
    pub macho: MachOContext,
    /// Extra segment data (for ObjC metadata)
    pub extra_segment_data: Vec<u8>,
    /// Whether indirect symbols were redacted
    pub has_redacted_indirect: bool,
    /// Path of the image being extracted
    pub image_path: String,
    /// Image address in the cache
    pub image_address: u64,
    /// Verbosity level (0=quiet, 1=warnings, 2=info, 3=debug)
    pub verbosity: u8,
}

impl ExtractionContext {
    /// Creates a new extraction context for the given image.
    pub fn new(
        cache: Arc<DyldContext>,
        macho: MachOContext,
        image_path: String,
        image_address: u64,
    ) -> Self {
        Self {
            cache,
            macho,
            extra_segment_data: Vec::new(),
            has_redacted_indirect: false,
            image_path,
            image_address,
            verbosity: 1,
        }
    }

    /// Sets the verbosity level.
    pub fn with_verbosity(mut self, verbosity: u8) -> Self {
        self.verbosity = verbosity;
        self
    }

    /// Returns true if the image is ARM64e (pointer authentication).
    pub fn is_arm64e(&self) -> bool {
        self.macho.is_arm64e()
    }

    /// Returns the basename of the image path.
    pub fn image_name(&self) -> &str {
        self.image_path
            .rsplit('/')
            .next()
            .unwrap_or(&self.image_path)
    }

    /// Logs a warning message if verbosity is high enough.
    pub fn warn(&self, message: &str) {
        if self.verbosity >= 1 {
            warn!("{}: {}", self.image_name(), message);
        }
    }

    /// Logs an info message if verbosity is high enough.
    pub fn info(&self, message: &str) {
        if self.verbosity >= 2 {
            info!("{}: {}", self.image_name(), message);
        }
    }

    /// Reads data from the cache at a virtual address.
    pub fn read_cache_at(&self, addr: u64, len: usize) -> Result<&[u8]> {
        self.cache.data_at_addr(addr, len)
    }

    /// Converts a cache virtual address to the corresponding Mach-O file offset.
    pub fn cache_addr_to_macho_offset(&self, addr: u64) -> Option<usize> {
        self.macho.addr_to_offset(addr)
    }

    /// Adds data to the extra segment and returns its virtual address.
    pub fn add_to_extra_segment(&mut self, data: &[u8]) -> u64 {
        let offset = self.extra_segment_data.len();
        self.extra_segment_data.extend_from_slice(data);

        // The actual address will be determined when the segment is created
        // For now, return the offset as a placeholder
        offset as u64
    }

    /// Returns the size of the extra segment data.
    pub fn extra_segment_size(&self) -> usize {
        self.extra_segment_data.len()
    }

    /// Returns whether there is extra segment data.
    pub fn has_extra_segment(&self) -> bool {
        !self.extra_segment_data.is_empty()
    }
}

/// Write procedure for assembling the final output file.
#[derive(Debug, Clone)]
pub struct WriteProcedure {
    /// Offset in the output file
    pub write_offset: u64,
    /// Offset in the source data
    pub read_offset: u64,
    /// Number of bytes to copy
    pub size: u64,
    /// Source type (cache or extra segment)
    pub source: WriteSource,
}

/// Source of data for a write procedure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteSource {
    /// Data from the dyld cache
    Cache { subcache_index: usize },
    /// Data from the Mach-O being built
    Macho,
    /// Data from the extra segment
    ExtraSegment,
}

impl WriteProcedure {
    /// Creates a write procedure from the cache.
    pub fn from_cache(
        write_offset: u64,
        read_offset: u64,
        size: u64,
        subcache_index: usize,
    ) -> Self {
        Self {
            write_offset,
            read_offset,
            size,
            source: WriteSource::Cache { subcache_index },
        }
    }

    /// Creates a write procedure from the Mach-O data.
    pub fn from_macho(write_offset: u64, read_offset: u64, size: u64) -> Self {
        Self {
            write_offset,
            read_offset,
            size,
            source: WriteSource::Macho,
        }
    }

    /// Creates a write procedure from the extra segment.
    pub fn from_extra(write_offset: u64, read_offset: u64, size: u64) -> Self {
        Self {
            write_offset,
            read_offset,
            size,
            source: WriteSource::ExtraSegment,
        }
    }
}
