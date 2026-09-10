//! Dyld shared cache context and file handling.
//!
//! This module provides the main interface for working with dyld shared caches,
//! including memory mapping, address conversion, and subcache management.

use std::fs::File;
use std::mem::offset_of;
use std::path::{Path, PathBuf};

use memmap2::Mmap;
use zerocopy::FromBytes;

use super::structs::*;
use crate::error::{Error, Result};

// =============================================================================
// Mapping Entry
// =============================================================================

/// A unified mapping entry that works with both basic and extended mapping formats.
#[derive(Debug, Clone)]
pub struct MappingEntry {
    /// Virtual memory address
    pub address: u64,
    /// Size in bytes
    pub size: u64,
    /// File offset
    pub file_offset: u64,
    /// Maximum protection
    pub max_prot: u32,
    /// Initial protection
    pub init_prot: u32,
    /// File offset to slide info (0 if none)
    pub slide_info_offset: u64,
    /// Size of slide info (0 if none)
    pub slide_info_size: u64,
    /// Mapping flags
    pub flags: u64,
    /// Index of the subcache containing this mapping (0 = main cache)
    pub subcache_index: usize,
}

impl MappingEntry {
    /// Creates a mapping entry from basic mapping info.
    pub fn from_basic(info: &DyldCacheMappingInfo, subcache_index: usize) -> Self {
        Self {
            address: info.address,
            size: info.size,
            file_offset: info.file_offset,
            max_prot: info.max_prot,
            init_prot: info.init_prot,
            slide_info_offset: 0,
            slide_info_size: 0,
            flags: 0,
            subcache_index,
        }
    }

    /// Creates a mapping entry from extended mapping info.
    pub fn from_extended(info: &DyldCacheMappingAndSlideInfo, subcache_index: usize) -> Self {
        Self {
            address: info.address,
            size: info.size,
            file_offset: info.file_offset,
            max_prot: info.max_prot,
            init_prot: info.init_prot,
            slide_info_offset: info.slide_info_file_offset,
            slide_info_size: info.slide_info_file_size,
            flags: info.flags,
            subcache_index,
        }
    }

    /// Returns true if this mapping contains the given virtual address.
    #[inline]
    pub fn contains_addr(&self, addr: u64) -> bool {
        addr >= self.address && addr < self.address + self.size
    }

    /// Returns true if this mapping contains the given file offset.
    #[inline]
    pub fn contains_offset(&self, offset: u64) -> bool {
        offset >= self.file_offset && offset < self.file_offset + self.size
    }

    /// Converts a virtual address to a file offset.
    #[inline]
    pub fn addr_to_offset(&self, addr: u64) -> u64 {
        self.file_offset + (addr - self.address)
    }

    /// Converts a file offset to a virtual address.
    #[inline]
    pub fn offset_to_addr(&self, offset: u64) -> u64 {
        self.address + (offset - self.file_offset)
    }

    /// Returns true if this mapping is readable.
    #[inline]
    pub fn is_readable(&self) -> bool {
        (self.init_prot & 1) != 0
    }

    /// Returns true if this mapping is writable.
    #[inline]
    pub fn is_writable(&self) -> bool {
        (self.init_prot & 2) != 0
    }

    /// Returns true if this mapping is executable.
    #[inline]
    pub fn is_executable(&self) -> bool {
        (self.init_prot & 4) != 0
    }

    /// Returns true if this mapping has slide info.
    #[inline]
    pub fn has_slide_info(&self) -> bool {
        self.slide_info_size > 0
    }
}

// =============================================================================
// Image Entry
// =============================================================================

/// Information about a dylib in the cache.
#[derive(Debug, Clone)]
pub struct ImageEntry {
    /// Index in the images array
    pub index: usize,
    /// Virtual address of the Mach-O header
    pub address: u64,
    /// File offset to the Mach-O header
    pub file_offset: u64,
    /// Path of the dylib (e.g., "/usr/lib/libc.dylib")
    pub path: String,
    /// Modification time
    pub mod_time: u64,
    /// Inode
    pub inode: u64,
    /// Index of the subcache containing this image
    pub subcache_index: usize,
}

impl ImageEntry {
    /// Returns the basename of the path.
    pub fn basename(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }

    /// Returns true if the path matches the given filter.
    pub fn matches_filter(&self, filter: &str) -> bool {
        self.path.contains(filter) || self.basename().contains(filter)
    }
}

// =============================================================================
// Subcache Entry
// =============================================================================

/// A loaded subcache file.
#[derive(Debug)]
pub struct SubcacheFile {
    /// Memory-mapped file data
    pub mmap: Mmap,
    /// Path to the file
    pub path: PathBuf,
    /// UUID of the subcache
    pub uuid: [u8; 16],
    /// VM offset from the main cache
    pub vm_offset: u64,
    /// Parsed header
    pub header: DyldCacheHeader,
}

// =============================================================================
// Dyld Context
// =============================================================================

/// Main context for working with a dyld shared cache.
///
/// This struct holds all the state needed to read and extract images from
/// a dyld shared cache, including handling of subcaches.
#[derive(Debug)]
pub struct DyldContext {
    /// Main cache file (memory-mapped)
    pub mmap: Mmap,
    /// Path to the main cache file
    pub path: PathBuf,
    /// Parsed header
    pub header: DyldCacheHeader,
    /// All mappings (including from subcaches)
    pub mappings: Vec<MappingEntry>,
    /// All images
    pub images: Vec<ImageEntry>,
    /// Subcache files
    pub subcaches: Vec<SubcacheFile>,
    /// Symbols file (if separate)
    pub symbols_file: Option<SubcacheFile>,
    /// Local symbols info (if available)
    pub local_symbols_info: Option<DyldCacheLocalSymbolsInfo>,
    /// Shared region start address
    pub shared_region_start: u64,
}

impl DyldContext {
    /// Opens a dyld shared cache from the given path.
    ///
    /// This will automatically detect and load any subcaches.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();

        // Memory-map the main cache file
        let file = File::open(&path).map_err(|e| Error::FileOpen {
            path: path.clone(),
            source: e,
        })?;

        let mmap = unsafe { Mmap::map(&file) }.map_err(|e| Error::MemoryMap {
            path: path.clone(),
            source: e,
        })?;

        // Parse and validate the header
        let header = Self::parse_header(&mmap)?;

        // Parse mappings
        let mappings = Self::parse_mappings(&mmap, &header, 0)?;

        // Create initial context
        let mut ctx = Self {
            mmap,
            path: path.clone(),
            header,
            mappings,
            images: Vec::new(),
            subcaches: Vec::new(),
            symbols_file: None,
            local_symbols_info: None,
            shared_region_start: 0,
        };

        // Store shared region start if available
        if ctx
            .header
            .contains_field(offset_of!(super::DyldCacheHeader, shared_region_start))
        {
            ctx.shared_region_start = ctx.header.shared_region_start;
        }

        // Load subcaches if present
        ctx.load_subcaches(&path)?;

        // Files are not ordered by VM address in large caches.
        ctx.mappings.sort_by_key(|m| m.address);
        for pair in ctx.mappings.windows(2) {
            if pair[0].address + pair[0].size > pair[1].address {
                return Err(Error::Parse {
                    offset: 0,
                    reason: "overlapping cache VM mappings".into(),
                });
            }
        }

        // Load symbols file if present
        ctx.load_symbols_file(&path)?;

        // Parse images (after subcaches are loaded)
        ctx.images = ctx.parse_images()?;

        // Parse local symbols info if available
        ctx.parse_local_symbols()?;

        Ok(ctx)
    }

    /// Parses and validates the cache header.
    fn parse_header(data: &[u8]) -> Result<DyldCacheHeader> {
        // Only the fixed prefix is mandatory. Never interpret mapping bytes as
        // newer fields when opening an older, shorter header.
        if data.len() < 32 {
            return Err(Error::BufferTooSmall {
                needed: 32,
                available: data.len(),
            });
        }
        let header_size = crate::util::read_u32_le(&data[16..]) as usize;
        if header_size < 32 || header_size > data.len() {
            return Err(Error::Parse {
                offset: 16,
                reason: "invalid cache header extent".into(),
            });
        }
        let mut bytes = [0u8; std::mem::size_of::<DyldCacheHeader>()];
        let copy_size = bytes.len().min(header_size);
        bytes[..copy_size].copy_from_slice(&data[..copy_size]);
        let header = DyldCacheHeader::read_from_prefix(&bytes)
            .map_err(|_| Error::Parse {
                offset: 0,
                reason: "invalid cache header".into(),
            })?
            .0;
        if !header.is_valid() {
            return Err(Error::InvalidMagic(header.magic[..4].try_into().unwrap()));
        }
        Ok(header)
    }

    /// Parses mapping entries from the cache.
    fn parse_mappings(
        data: &[u8],
        header: &DyldCacheHeader,
        subcache_index: usize,
    ) -> Result<Vec<MappingEntry>> {
        let mut mappings = Vec::new();

        // Check if we have extended mapping info
        let use_extended = header.contains_field_range(
            offset_of!(super::DyldCacheHeader, mapping_with_slide_count),
            4,
        ) && header.mapping_with_slide_offset != 0;

        if use_extended {
            let offset = header.mapping_with_slide_offset as usize;
            checked_table(
                data,
                offset,
                header.mapping_with_slide_count as usize,
                std::mem::size_of::<DyldCacheMappingAndSlideInfo>(),
            )?;
            for i in 0..header.mapping_with_slide_count as usize {
                let entry_offset = offset + i * std::mem::size_of::<DyldCacheMappingAndSlideInfo>();
                let info = DyldCacheMappingAndSlideInfo::read_from_prefix(&data[entry_offset..])
                    .map_err(|_| Error::Parse {
                        offset: entry_offset,
                        reason: "failed to parse extended mapping".into(),
                    })?
                    .0;
                mappings.push(MappingEntry::from_extended(&info, subcache_index));
            }
        } else {
            let offset = header.mapping_offset as usize;
            checked_table(
                data,
                offset,
                header.mapping_count as usize,
                std::mem::size_of::<DyldCacheMappingInfo>(),
            )?;
            for i in 0..header.mapping_count as usize {
                let entry_offset = offset + i * std::mem::size_of::<DyldCacheMappingInfo>();
                let info = DyldCacheMappingInfo::read_from_prefix(&data[entry_offset..])
                    .map_err(|_| Error::Parse {
                        offset: entry_offset,
                        reason: "failed to parse mapping".into(),
                    })?
                    .0;
                mappings.push(MappingEntry::from_basic(&info, subcache_index));
            }
        }

        if !use_extended
            && header.contains_field_range(offset_of!(DyldCacheHeader, slide_info_size_unused), 8)
            && header.slide_info_offset_unused != 0
            && header.slide_info_size_unused != 0
        {
            if let Some(mapping) = mappings.iter_mut().find(|m| m.is_writable()) {
                mapping.slide_info_offset = header.slide_info_offset_unused;
                mapping.slide_info_size = header.slide_info_size_unused;
            }
        }
        for m in &mappings {
            if m.address.checked_add(m.size).is_none()
                || m.file_offset
                    .checked_add(m.size)
                    .is_none_or(|end| end > data.len() as u64)
            {
                return Err(Error::Parse {
                    offset: header.mapping_offset as usize,
                    reason: "cache mapping out of bounds".into(),
                });
            }
        }
        Ok(mappings)
    }

    /// Loads subcache files.
    fn load_subcaches(&mut self, main_path: &Path) -> Result<()> {
        if !self.header.has_subcaches() {
            return Ok(());
        }

        let parent_dir = main_path.parent().unwrap_or(Path::new("."));
        let main_name = main_path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        let count = self.header.sub_cache_array_count as usize;
        let offset = self.header.sub_cache_array_offset as usize;

        // Determine entry size (v1 vs v2)
        let entry_size = if self.has_v2_subcache_entries() {
            std::mem::size_of::<DyldSubcacheEntry2>()
        } else {
            std::mem::size_of::<DyldSubcacheEntry>()
        };

        checked_table(&self.mmap, offset, count, entry_size)?;
        for i in 0..count {
            let entry_offset = offset + i * entry_size;

            let (uuid, vm_offset, suffix) = if self.has_v2_subcache_entries() {
                let entry = DyldSubcacheEntry2::read_from_prefix(&self.mmap[entry_offset..])
                    .map_err(|_| Error::Parse {
                        offset: entry_offset,
                        reason: "failed to parse subcache entry v2".into(),
                    })?
                    .0;
                (
                    entry.uuid,
                    entry.cache_vm_offset,
                    entry.suffix_str().to_string(),
                )
            } else {
                let entry = DyldSubcacheEntry::read_from_prefix(&self.mmap[entry_offset..])
                    .map_err(|_| Error::Parse {
                        offset: entry_offset,
                        reason: "failed to parse subcache entry".into(),
                    })?
                    .0;
                (entry.uuid, entry.cache_vm_offset, format!(".{}", i + 1))
            };

            if !suffix.starts_with('.')
                || suffix.contains('/')
                || suffix.contains('\\')
                || suffix == "."
                || suffix == ".."
            {
                return Err(Error::Parse {
                    offset: entry_offset,
                    reason: "invalid subcache suffix".into(),
                });
            }
            // Load subcache file
            let subcache_path = parent_dir.join(format!("{}{}", main_name, suffix));
            self.load_subcache_file(&subcache_path, uuid, vm_offset, i + 1)?;
        }

        Ok(())
    }

    /// Loads a single subcache file.
    fn load_subcache_file(
        &mut self,
        path: &Path,
        expected_uuid: [u8; 16],
        vm_offset: u64,
        subcache_index: usize,
    ) -> Result<()> {
        let file = File::open(path).map_err(|_| Error::SubcacheNotFound {
            path: path.to_path_buf(),
        })?;

        let mmap = unsafe { Mmap::map(&file) }.map_err(|e| Error::MemoryMap {
            path: path.to_path_buf(),
            source: e,
        })?;

        let header = Self::parse_header(&mmap)?;

        // Validate UUID
        if header.uuid != expected_uuid {
            return Err(Error::SubcacheUuidMismatch {
                path: path.to_path_buf(),
                expected: format!("{:02x?}", expected_uuid),
                actual: format!("{:02x?}", header.uuid),
            });
        }

        // Parse and add mappings from this subcache
        let subcache_mappings = Self::parse_mappings(&mmap, &header, subcache_index)?;
        self.mappings.extend(subcache_mappings);

        self.subcaches.push(SubcacheFile {
            mmap,
            path: path.to_path_buf(),
            uuid: header.uuid,
            vm_offset,
            header,
        });

        Ok(())
    }

    /// Loads the symbols file if present.
    fn load_symbols_file(&mut self, main_path: &Path) -> Result<()> {
        if !self.header.has_symbol_file() {
            return Ok(());
        }

        let parent_dir = main_path.parent().unwrap_or(Path::new("."));
        let main_name = main_path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        let symbols_path = parent_dir.join(format!("{}.symbols", main_name));

        if !symbols_path.exists() {
            // Symbols file is optional
            return Ok(());
        }

        let file = File::open(&symbols_path).map_err(|e| Error::FileOpen {
            path: symbols_path.clone(),
            source: e,
        })?;

        let mmap = unsafe { Mmap::map(&file) }.map_err(|e| Error::MemoryMap {
            path: symbols_path.clone(),
            source: e,
        })?;

        let header = Self::parse_header(&mmap)?;

        // Validate UUID matches
        if header.uuid != self.header.symbol_file_uuid {
            return Err(Error::SubcacheUuidMismatch {
                path: symbols_path.clone(),
                expected: format!("{:02x?}", self.header.symbol_file_uuid),
                actual: format!("{:02x?}", header.uuid),
            });
        }

        self.symbols_file = Some(SubcacheFile {
            mmap,
            path: symbols_path,
            uuid: header.uuid,
            vm_offset: 0,
            header,
        });

        Ok(())
    }

    /// Parses the image list.
    fn parse_images(&self) -> Result<Vec<ImageEntry>> {
        let count = self.header.actual_images_count() as usize;
        let offset = self.header.actual_images_offset() as usize;

        checked_table(
            &self.mmap,
            offset,
            count,
            std::mem::size_of::<DyldCacheImageInfo>(),
        )?;
        let mut images = Vec::with_capacity(count);

        for i in 0..count {
            let entry_offset = offset + i * std::mem::size_of::<DyldCacheImageInfo>();
            let info = DyldCacheImageInfo::read_from_prefix(&self.mmap[entry_offset..])
                .map_err(|_| Error::Parse {
                    offset: entry_offset,
                    reason: "failed to parse image info".into(),
                })?
                .0;

            // Read the path string
            let path = self.read_string(info.path_file_offset as usize)?;

            // Find which subcache contains this address
            let subcache_index = self.find_subcache_for_addr(info.address);

            // Convert address to file offset
            let file_offset = self.addr_to_offset(info.address).unwrap_or(0);

            images.push(ImageEntry {
                index: i,
                address: info.address,
                file_offset,
                path,
                mod_time: info.mod_time,
                inode: info.inode,
                subcache_index,
            });
        }

        Ok(images)
    }

    /// Parses local symbols info.
    fn parse_local_symbols(&mut self) -> Result<()> {
        // Check if local symbols are in main cache or symbols file
        let (data, offset) =
            if self.header.local_symbols_offset != 0 && self.header.local_symbols_size != 0 {
                (&self.mmap[..], self.header.local_symbols_offset as usize)
            } else if let Some(ref symbols_file) = self.symbols_file {
                if symbols_file.header.local_symbols_offset != 0 {
                    (
                        &symbols_file.mmap[..],
                        symbols_file.header.local_symbols_offset as usize,
                    )
                } else {
                    return Ok(());
                }
            } else {
                return Ok(());
            };

        if offset + std::mem::size_of::<DyldCacheLocalSymbolsInfo>() > data.len() {
            return Ok(());
        }

        let info = DyldCacheLocalSymbolsInfo::read_from_prefix(&data[offset..])
            .map_err(|_| Error::Parse {
                offset,
                reason: "failed to parse local symbols info".into(),
            })?
            .0;

        self.local_symbols_info = Some(info);
        Ok(())
    }

    /// Checks if this cache uses v2 subcache entries.
    fn has_v2_subcache_entries(&self) -> bool {
        // IDA fmt/dsc/shared_cache_file_t.cpp: the cacheSubType extension
        // identifies suffix-bearing entries. Bytes in the next v1 entry are
        // not a reliable discriminator.
        self.header
            .contains_field_range(offset_of!(DyldCacheHeader, cache_sub_type), 4)
    }

    /// Finds which subcache contains the given address.
    fn find_subcache_for_addr(&self, addr: u64) -> usize {
        for mapping in &self.mappings {
            if mapping.contains_addr(addr) {
                return mapping.subcache_index;
            }
        }
        0 // Default to main cache
    }

    /// Reads a null-terminated string from the cache.
    ///
    /// # Performance
    ///
    /// Uses SIMD-accelerated null byte search (memchr).
    pub fn read_string(&self, offset: usize) -> Result<String> {
        if offset >= self.mmap.len() {
            return Err(Error::Parse {
                offset,
                reason: "string offset out of bounds".into(),
            });
        }

        let bytes = &self.mmap[offset..];
        let end = crate::util::memchr_null(bytes);
        String::from_utf8(bytes[..end].to_vec()).map_err(|_| Error::Parse {
            offset,
            reason: "invalid UTF-8 string".into(),
        })
    }

    /// Converts a virtual address to a file offset.
    /// Uses binary search for O(log n) lookup on sorted mappings.
    #[inline]
    pub fn addr_to_offset(&self, addr: u64) -> Option<u64> {
        // Binary search for the mapping containing this address
        let idx = self
            .mappings
            .partition_point(|m| m.address + m.size <= addr);
        if idx < self.mappings.len() {
            let mapping = &self.mappings[idx];
            if mapping.contains_addr(addr) {
                return Some(mapping.addr_to_offset(addr));
            }
        }
        // Fallback to linear search for edge cases
        self.mappings
            .iter()
            .find(|m| m.contains_addr(addr))
            .map(|m| m.addr_to_offset(addr))
    }

    /// Converts a file offset to a virtual address.
    #[inline]
    pub fn offset_to_addr(&self, offset: u64) -> Option<u64> {
        // Mappings aren't sorted by file offset, so linear scan is necessary
        self.mappings
            .iter()
            .find(|m| m.contains_offset(offset))
            .map(|m| m.offset_to_addr(offset))
    }

    /// Returns the file data for a given address.
    ///
    /// This handles both the main cache and subcaches.
    /// Uses binary search for efficient mapping lookup.
    #[inline]
    pub fn data_at_addr(&self, addr: u64, len: usize) -> Result<&[u8]> {
        // Binary search for the mapping containing this address
        let idx = self
            .mappings
            .partition_point(|m| m.address + m.size <= addr);
        if idx < self.mappings.len() {
            let mapping = &self.mappings[idx];
            if mapping.contains_addr(addr) {
                let offset = mapping.addr_to_offset(addr) as usize;
                let data = self.data_for_subcache(mapping.subcache_index);
                if len as u64 > mapping.size - (addr - mapping.address)
                    || offset.checked_add(len).is_none_or(|end| end > data.len())
                {
                    return Err(Error::BufferTooSmall {
                        needed: offset.saturating_add(len),
                        available: data.len(),
                    });
                }
                return Ok(&data[offset..offset + len]);
            }
        }
        Err(Error::AddressNotFound { addr })
    }

    /// Copies a virtual range across adjacent mappings and subcache boundaries.
    /// Gaps fail explicitly; unrelated bytes in the same file are never copied.
    pub fn copy_data_at_addr(&self, mut addr: u64, mut output: &mut [u8]) -> Result<()> {
        while !output.is_empty() {
            let mapping = self
                .mapping_for_addr(addr)
                .ok_or(Error::AddressNotFound { addr })?;
            let size = output
                .len()
                .min((mapping.size - (addr - mapping.address)) as usize);
            output[..size].copy_from_slice(self.data_at_addr(addr, size)?);
            addr = addr
                .checked_add(size as u64)
                .ok_or(Error::AddressNotFound { addr })?;
            output = &mut output[size..];
        }
        Ok(())
    }

    /// Returns the mmap data for a given subcache index.
    #[inline]
    pub fn data_for_subcache(&self, index: usize) -> &[u8] {
        if index == 0 {
            &self.mmap[..]
        } else if let Some(subcache) = self.subcaches.get(index - 1) {
            &subcache.mmap[..]
        } else {
            &[]
        }
    }

    /// Returns the mapping for a given virtual address.
    /// Uses binary search for O(log n) lookup.
    #[inline]
    pub fn mapping_for_addr(&self, addr: u64) -> Option<&MappingEntry> {
        let idx = self
            .mappings
            .partition_point(|m| m.address + m.size <= addr);
        if idx < self.mappings.len() {
            let mapping = &self.mappings[idx];
            if mapping.contains_addr(addr) {
                return Some(mapping);
            }
        }
        None
    }

    /// Returns an iterator over all images.
    pub fn iter_images(&self) -> impl Iterator<Item = &ImageEntry> {
        self.images.iter()
    }

    /// Finds an image by path or basename.
    pub fn find_image(&self, name: &str) -> Option<&ImageEntry> {
        self.images.iter().find(|img| img.matches_filter(name))
    }

    /// Returns the number of images in the cache.
    pub fn image_count(&self) -> usize {
        self.images.len()
    }

    /// Returns true if this cache has subcaches.
    pub fn has_subcaches(&self) -> bool {
        !self.subcaches.is_empty()
    }

    /// Returns the total size of all cache files.
    pub fn total_size(&self) -> u64 {
        let main_size = self.mmap.len() as u64;
        let subcache_size: u64 = self.subcaches.iter().map(|s| s.mmap.len() as u64).sum();
        let symbols_size = self
            .symbols_file
            .as_ref()
            .map(|s| s.mmap.len() as u64)
            .unwrap_or(0);
        main_size + subcache_size + symbols_size
    }

    /// Returns the architecture of this cache.
    pub fn architecture(&self) -> &str {
        self.header.architecture()
    }

    /// Returns the data for the symbols cache (either main cache or .symbols file).
    ///
    /// Local symbols are stored either in the main cache (older format) or in
    /// a separate .symbols file (newer format).
    pub fn symbols_cache_data(&self) -> Option<&[u8]> {
        // Check if symbols are in a separate file
        if let Some(ref symbols_file) = self.symbols_file {
            if symbols_file.header.local_symbols_offset != 0 {
                return Some(&symbols_file.mmap[..]);
            }
        }

        // Otherwise check main cache
        if self.header.local_symbols_offset != 0 && self.header.local_symbols_size != 0 {
            return Some(&self.mmap[..]);
        }

        None
    }

    /// Returns the local symbols offset in the symbols cache.
    pub fn local_symbols_offset(&self) -> Option<u64> {
        if let Some(ref symbols_file) = self.symbols_file {
            if symbols_file.header.local_symbols_offset != 0 {
                return Some(symbols_file.header.local_symbols_offset);
            }
        }

        if self.header.local_symbols_offset != 0 {
            return Some(self.header.local_symbols_offset);
        }

        None
    }

    /// Returns true if this cache uses 64-bit local symbol entries.
    ///
    /// Newer caches (with symbolFileUUID) use 64-bit dylib offsets in local symbol entries.
    pub fn uses_64bit_local_symbol_entries(&self) -> bool {
        self.header.has_symbol_file()
    }

    /// Reads a null-terminated string from the symbols cache.
    ///
    /// # Performance
    ///
    /// Uses SIMD-accelerated null byte search (memchr).
    pub fn read_symbols_string(&self, offset: usize) -> Result<String> {
        let data = self.symbols_cache_data().ok_or(Error::Parse {
            offset: 0,
            reason: "no symbols cache available".into(),
        })?;

        if offset >= data.len() {
            return Err(Error::Parse {
                offset,
                reason: "string offset out of bounds in symbols cache".into(),
            });
        }

        let bytes = &data[offset..];
        let end = crate::util::memchr_null(bytes);
        String::from_utf8(bytes[..end].to_vec()).map_err(|_| Error::Parse {
            offset,
            reason: "invalid UTF-8 string in symbols cache".into(),
        })
    }

    /// Returns the slide info value_add for the cache.
    ///
    /// This is the base address that needs to be added to rebased pointers.
    /// For arm64e caches, this is typically the shared region start (0x180000000).
    pub fn slide_info_value_add(&self) -> Option<u64> {
        // Find the first mapping with slide info
        for mapping in &self.mappings {
            if !mapping.has_slide_info() {
                continue;
            }

            // Read the slide info header to get the version
            let cache_data = self.data_for_subcache(mapping.subcache_index);
            let offset = mapping.slide_info_offset as usize;

            if offset + 4 > cache_data.len() {
                continue;
            }

            let version = crate::util::read_u32_le(&cache_data[offset..]);

            match version {
                2 => {
                    // Slide info v2 has value_add at offset 32
                    if offset + 40 <= cache_data.len() {
                        return Some(crate::util::read_u64_le(&cache_data[offset + 32..]));
                    }
                }
                3 => {
                    // Slide info v3 has auth_value_add at offset 16 (64-bit alignment)
                    if offset + 24 <= cache_data.len() {
                        return Some(crate::util::read_u64_le(&cache_data[offset + 16..]));
                    }
                }
                5 => {
                    // Slide info v5 has value_add at offset 16 (64-bit alignment)
                    if offset + 24 <= cache_data.len() {
                        return Some(crate::util::read_u64_le(&cache_data[offset + 16..]));
                    }
                }
                _ => {}
            }
        }

        None
    }
}

/// Validates a counted on-disk array before allocation or slicing.
fn checked_table(data: &[u8], offset: usize, count: usize, stride: usize) -> Result<()> {
    let end = count
        .checked_mul(stride)
        .and_then(|size| offset.checked_add(size));
    if end.is_none_or(|end| end > data.len()) {
        return Err(Error::Parse {
            offset,
            reason: "cache table out of bounds".into(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mapping_entry_contains() {
        let mapping = MappingEntry {
            address: 0x1000,
            size: 0x1000,
            file_offset: 0x0,
            max_prot: 7,
            init_prot: 5,
            slide_info_offset: 0,
            slide_info_size: 0,
            flags: 0,
            subcache_index: 0,
        };

        assert!(mapping.contains_addr(0x1000));
        assert!(mapping.contains_addr(0x1FFF));
        assert!(!mapping.contains_addr(0x2000));
        assert!(!mapping.contains_addr(0x0FFF));
    }

    #[test]
    fn test_mapping_conversion() {
        let mapping = MappingEntry {
            address: 0x1_0000_0000,
            size: 0x1000_0000,
            file_offset: 0x1000,
            max_prot: 7,
            init_prot: 5,
            slide_info_offset: 0,
            slide_info_size: 0,
            flags: 0,
            subcache_index: 0,
        };

        assert_eq!(mapping.addr_to_offset(0x1_0000_0000), 0x1000);
        assert_eq!(mapping.addr_to_offset(0x1_0001_0000), 0x11000);
        assert_eq!(mapping.offset_to_addr(0x1000), 0x1_0000_0000);
    }
}
