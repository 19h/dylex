//! Dyld shared cache binary structures.
//!
//! These structures match the on-disk format of Apple's dyld shared cache.
//! They are designed for zero-copy parsing using the `zerocopy` crate.

use std::fmt;
use std::mem::offset_of;

use bitflags::bitflags;
use zerocopy::{FromBytes, Immutable, KnownLayout};

/// The magic string prefix for all dyld caches.
pub const DYLD_CACHE_MAGIC_PREFIX: &[u8; 4] = b"dyld";

/// The page size for slide info calculations (typically 4KB or 16KB).
pub const PAGE_SIZE_4K: u32 = 0x1000;
/// 16KB page size for arm64.
pub const PAGE_SIZE_16K: u32 = 0x4000;

// =============================================================================
// Slide Info Constants
// =============================================================================

/// Page attributes for slide info.
pub const DYLD_CACHE_SLIDE_PAGE_ATTRS: u16 = 0xC000;
/// Extra page attribute.
pub const DYLD_CACHE_SLIDE_PAGE_ATTR_EXTRA: u16 = 0x8000;
/// No rebase needed page attribute.
pub const DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE: u16 = 0x4000;
/// V3 no rebase page attribute.
pub const DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE: u16 = 0xFFFF;
/// V5 no rebase page attribute.
pub const DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE: u16 = 0xFFFF;

// =============================================================================
// Header Structures
// =============================================================================

/// The main dyld shared cache header.
///
/// This is a variable-length structure. The actual size is determined by
/// `mapping_offset` - fields beyond `mapping_offset` may not exist in older caches.
///
/// Based on dyld source code and DyldExtractor reference implementation.
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct DyldCacheHeader {
    /// Magic identifier, e.g., "dyld_v0    i386" or "dyld_v1   arm64e"
    pub magic: [u8; 16],
    /// File offset to first `DyldCacheMappingInfo`
    pub mapping_offset: u32,
    /// Number of mapping entries
    pub mapping_count: u32,
    /// Legacy: file offset to `DyldCacheImageInfo` array
    pub images_offset_old: u32,
    /// Legacy: number of images
    pub images_count_old: u32,
    /// Base address of dyld when cache was built
    pub dyld_base_address: u64,
    /// File offset of code signature
    pub code_signature_offset: u64,
    /// Size of code signature
    pub code_signature_size: u64,
    /// Legacy: slide info offset (per-mapping slide info used in modern caches)
    pub slide_info_offset_unused: u64,
    /// Legacy: slide info size
    pub slide_info_size_unused: u64,
    /// File offset of local symbols info
    pub local_symbols_offset: u64,
    /// Size of local symbols info
    pub local_symbols_size: u64,
    /// UUID of this cache
    pub uuid: [u8; 16],
    /// Cache type: 0=development, 1=production, 2=multi-cache
    pub cache_type: u64,
    /// Offset to branch pool addresses
    pub branch_pools_offset: u32,
    /// Number of branch pool addresses
    pub branch_pools_count: u32,
    /// Unslid address of dyld in cache (mach_header)
    pub dyld_in_cache_mh: u64,
    /// Unslid address of dyld entry point in cache
    pub dyld_in_cache_entry: u64,
    /// File offset to array of image text info
    pub images_text_offset: u64,
    /// Number of image text info entries
    pub images_text_count: u64,
    /// Address of patch info
    pub patch_info_addr: u64,
    /// Size of patch info
    pub patch_info_size: u64,
    /// Unused (other image group addr)
    pub other_image_group_addr_unused: u64,
    /// Unused (other image group size)
    pub other_image_group_size_unused: u64,
    /// Address of program closures
    pub prog_closures_addr: u64,
    /// Size of program closures
    pub prog_closures_size: u64,
    /// Address of program closures trie
    pub prog_closures_trie_addr: u64,
    /// Size of program closures trie
    pub prog_closures_trie_size: u64,
    /// Platform type
    pub platform: u32,
    /// Format version and flags (8 bits version, followed by bit flags)
    pub format_version_and_flags: u32,
    /// Address of shared region start
    pub shared_region_start: u64,
    /// Size of shared region
    pub shared_region_size: u64,
    /// Maximum allowed slide value
    pub max_slide: u64,
    /// Address of dylibs image array
    pub dylibs_image_array_addr: u64,
    /// Size of dylibs image array
    pub dylibs_image_array_size: u64,
    /// Address of dylibs trie
    pub dylibs_trie_addr: u64,
    /// Size of dylibs trie
    pub dylibs_trie_size: u64,
    /// Address of other image array
    pub other_image_array_addr: u64,
    /// Size of other image array
    pub other_image_array_size: u64,
    /// Address of other trie
    pub other_trie_addr: u64,
    /// Size of other trie
    pub other_trie_size: u64,
    /// File offset to extended mappings with slide info
    pub mapping_with_slide_offset: u32,
    /// Count of extended mappings
    pub mapping_with_slide_count: u32,
    /// Unused (dylibs PBL state array addr)
    pub dylibs_pbl_state_array_addr_unused: u64,
    /// Address of dylibs PBL set
    pub dylibs_pbl_set_addr: u64,
    /// Address of programs PBL set pool
    pub programs_pbl_set_pool_addr: u64,
    /// Size of programs PBL set pool
    pub programs_pbl_set_pool_size: u64,
    /// Address of program trie
    pub program_trie_addr: u64,
    /// Size of program trie
    pub program_trie_size: u32,
    /// OS version
    pub os_version: u32,
    /// Alternative platform (e.g., iOSMac on macOS)
    pub alt_platform: u32,
    /// Alternative OS version
    pub alt_os_version: u32,
    /// VM offset to Swift optimizations header
    pub swift_opts_offset: u64,
    /// Size of Swift optimizations header
    pub swift_opts_size: u64,
    /// File offset to first subcache entry
    pub sub_cache_array_offset: u32,
    /// Number of subcache entries
    pub sub_cache_array_count: u32,
    /// UUID of the .symbols subcache file
    pub symbol_file_uuid: [u8; 16],
    /// Address of Rosetta read-only region
    pub rosetta_read_only_addr: u64,
    /// Size of Rosetta read-only region
    pub rosetta_read_only_size: u64,
    /// Address of Rosetta read-write region
    pub rosetta_read_write_addr: u64,
    /// Size of Rosetta read-write region
    pub rosetta_read_write_size: u64,
    /// File offset to new image info array
    pub images_offset: u32,
    /// Number of images (new location)
    pub images_count: u32,
    /// Sub-cache type: 0=development, 1=production
    pub cache_sub_type: u32,
    /// Padding
    _pad1: u32,
    /// VM offset to ObjC optimizations header
    pub objc_opts_offset: u64,
    /// Size of ObjC optimizations header
    pub objc_opts_size: u64,
    /// VM offset to cache atlas
    pub cache_atlas_offset: u64,
    /// Size of cache atlas
    pub cache_atlas_size: u64,
    /// VM offset to dynamic data header
    pub dynamic_data_offset: u64,
    /// Maximum size of dynamic data
    pub dynamic_data_max_size: u64,
}

impl DyldCacheHeader {
    /// Returns the architecture from the magic string.
    pub fn architecture(&self) -> &str {
        let magic_str = std::str::from_utf8(&self.magic).unwrap_or("");
        magic_str
            .trim_start_matches("dyld_v0")
            .trim_start_matches("dyld_v1")
            .trim()
    }

    /// Checks if a header field exists based on mapping_offset.
    pub fn contains_field(&self, field_offset: usize) -> bool {
        field_offset < self.mapping_offset as usize
    }

    /// Returns true if this is a valid dyld cache header.
    pub fn is_valid(&self) -> bool {
        &self.magic[..4] == DYLD_CACHE_MAGIC_PREFIX
    }

    /// Returns true if this cache has subcaches.
    pub fn has_subcaches(&self) -> bool {
        self.contains_field(offset_of!(Self, sub_cache_array_count))
            && self.sub_cache_array_count > 0
    }

    /// Returns true if this cache has a separate symbols file.
    pub fn has_symbol_file(&self) -> bool {
        self.contains_field(offset_of!(Self, symbol_file_uuid))
            && self.symbol_file_uuid != [0u8; 16]
    }

    /// Returns true if this cache uses the new images location.
    pub fn uses_new_images_offset(&self) -> bool {
        self.contains_field(offset_of!(Self, images_offset)) && self.images_offset != 0
    }

    /// Returns the actual images offset (new or legacy location).
    pub fn actual_images_offset(&self) -> u64 {
        if self.uses_new_images_offset() {
            self.images_offset as u64
        } else {
            self.images_offset_old as u64
        }
    }

    /// Returns the actual images count (new or legacy location).
    pub fn actual_images_count(&self) -> u64 {
        if self.uses_new_images_offset() {
            self.images_count as u64
        } else {
            self.images_count_old as u64
        }
    }
}

/// Flags from the dyld info structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, FromBytes, KnownLayout, Immutable)]
#[repr(transparent)]
pub struct DyldInfoFlags(pub u32);

impl DyldInfoFlags {
    /// Cache contains Swift precomputed data
    pub const HAS_SWIFT_PRECOMPUTED: u32 = 0x1;
    /// Cache contains codesigned pages
    pub const HAS_CODESIGNED_16K_PAGES: u32 = 0x2;

    /// Returns true if the given flag is set.
    pub fn has(&self, flag: u32) -> bool {
        (self.0 & flag) != 0
    }
}

// =============================================================================
// Mapping Structures
// =============================================================================

/// Basic mapping entry (older caches without slide info per-mapping).
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct DyldCacheMappingInfo {
    /// Virtual memory address
    pub address: u64,
    /// Size in bytes
    pub size: u64,
    /// File offset
    pub file_offset: u64,
    /// Maximum memory protection
    pub max_prot: u32,
    /// Initial memory protection
    pub init_prot: u32,
}

/// Extended mapping entry with per-mapping slide info.
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct DyldCacheMappingAndSlideInfo {
    /// Virtual memory address
    pub address: u64,
    /// Size in bytes
    pub size: u64,
    /// File offset
    pub file_offset: u64,
    /// Slide info file offset
    pub slide_info_file_offset: u64,
    /// Slide info file size
    pub slide_info_file_size: u64,
    /// Flags
    pub flags: u64,
    /// Maximum memory protection
    pub max_prot: u32,
    /// Initial memory protection
    pub init_prot: u32,
}

bitflags! {
    /// Flags for extended mapping entries.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MappingFlags: u64 {
        /// Mapping contains authenticated pointers
        const AUTH_DATA = 1 << 0;
        /// Mapping contains dirty data
        const DIRTY_DATA = 1 << 1;
        /// Mapping contains const data
        const CONST_DATA = 1 << 2;
        /// Mapping is in TEXT region
        const TEXT_STUBS = 1 << 3;
    }
}

// =============================================================================
// Image Structures
// =============================================================================

/// Information about a dylib in the cache.
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct DyldCacheImageInfo {
    /// Address of the Mach-O header
    pub address: u64,
    /// Modification time
    pub mod_time: u64,
    /// Inode
    pub inode: u64,
    /// Offset to path string
    pub path_file_offset: u32,
    /// Padding
    pub pad: u32,
}

/// Text segment info for an image.
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct DyldCacheImageTextInfo {
    /// UUID of the image
    pub uuid: [u8; 16],
    /// Load address of the image
    pub load_address: u64,
    /// Size of the text segment
    pub text_segment_size: u32,
    /// Offset to path string
    pub path_offset: u32,
}

// =============================================================================
// Slide Info Structures
// =============================================================================

/// Slide info version 2 (standard arm64).
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct DyldCacheSlideInfo2 {
    /// Version (should be 2)
    pub version: u32,
    /// Page size (typically 4KB)
    pub page_size: u32,
    /// Number of page starts entries
    pub page_starts_count: u32,
    /// Offset to page extras
    pub page_extras_offset: u32,
    /// Number of page extras entries
    pub page_extras_count: u32,
    /// Mask for delta field in pointer
    pub delta_mask: u64,
    /// Value to add to rebased pointers
    pub value_add: u64,
    /// Offset to page starts array
    pub page_starts_offset: u32,
}

impl DyldCacheSlideInfo2 {
    /// Returns the mask for the value portion of a pointer.
    pub fn value_mask(&self) -> u64 {
        !self.delta_mask
    }

    /// Returns the shift amount for the delta field.
    pub fn delta_shift(&self) -> u32 {
        self.delta_mask.trailing_zeros()
    }
}

/// Slide info version 3 (arm64e with PAC).
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct DyldCacheSlideInfo3 {
    /// Version (should be 3)
    pub version: u32,
    /// Page size (typically 16KB)
    pub page_size: u32,
    /// Number of page starts entries
    pub page_starts_count: u32,
    /// Value to add for authenticated pointers
    pub auth_value_add: u64,
    // Followed by page_starts array of u16
}

/// Slide info version 5 (arm64e iOS 18+).
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct DyldCacheSlideInfo5 {
    /// Version (should be 5)
    pub version: u32,
    /// Page size
    pub page_size: u32,
    /// Number of page starts entries
    pub page_starts_count: u32,
    /// Padding
    pub _pad: u32,
    /// Value to add to pointers
    pub value_add: u64,
    // Followed by page_starts array of u16
}

/// Encoded pointer for slide info v3.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct SlidePointer3(pub u64);

impl SlidePointer3 {
    /// Returns true if this is an authenticated pointer.
    #[inline]
    pub fn is_auth(&self) -> bool {
        (self.0 >> 63) & 1 != 0
    }

    /// Returns the offset to the next rebase location (in 8-byte units).
    #[inline]
    pub fn offset_to_next(&self) -> u64 {
        (self.0 >> 51) & 0x7FF
    }

    /// For authenticated pointers: returns the offset from the auth base.
    #[inline]
    pub fn auth_offset(&self) -> u32 {
        (self.0 & 0xFFFFFFFF) as u32
    }

    /// For plain pointers: returns the decoded value.
    #[inline]
    pub fn plain_value(&self) -> u64 {
        // Sign extend from 51 bits
        let value = self.0 & 0x0007_FFFF_FFFF_FFFF;
        let top8 = ((self.0 >> 43) & 0xFF) as u8;
        ((top8 as u64) << 56) | value
    }
}

/// Encoded pointer for slide info v5.
#[derive(Debug, Clone, Copy)]
#[repr(transparent)]
pub struct SlidePointer5(pub u64);

impl SlidePointer5 {
    /// Returns true if this is an authenticated pointer.
    #[inline]
    pub fn is_auth(&self) -> bool {
        (self.0 >> 63) & 1 != 0
    }

    /// Returns the offset to the next rebase (in 8-byte units).
    #[inline]
    pub fn next(&self) -> u64 {
        (self.0 >> 51) & 0x7FF
    }

    /// Returns the runtime offset (for both auth and non-auth).
    #[inline]
    pub fn runtime_offset(&self) -> u64 {
        self.0 & 0x0007_FFFF_FFFF_FFFF
    }

    /// For non-auth pointers: returns the high 8 bits.
    #[inline]
    pub fn high8(&self) -> u8 {
        ((self.0 >> 43) & 0xFF) as u8
    }
}

// =============================================================================
// Subcache Structures
// =============================================================================

/// Subcache entry (version 1, without explicit extension).
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct DyldSubcacheEntry {
    /// UUID of the subcache
    pub uuid: [u8; 16],
    /// VM offset from main cache
    pub cache_vm_offset: u64,
}

/// Subcache entry (version 2, newer format with explicit extension).
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct DyldSubcacheEntry2 {
    /// UUID of the subcache
    pub uuid: [u8; 16],
    /// VM offset from main cache
    pub cache_vm_offset: u64,
    /// File extension (e.g., ".01", ".symbols")
    pub file_suffix: [u8; 32],
}

impl DyldSubcacheEntry2 {
    /// Returns the file suffix as a string.
    pub fn suffix_str(&self) -> &str {
        let end = self.file_suffix.iter().position(|&b| b == 0).unwrap_or(32);
        std::str::from_utf8(&self.file_suffix[..end]).unwrap_or("")
    }
}

// =============================================================================
// Local Symbols
// =============================================================================

/// Local symbols information header.
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct DyldCacheLocalSymbolsInfo {
    /// Offset to nlist array (from start of this struct)
    pub nlist_offset: u32,
    /// Number of nlist entries
    pub nlist_count: u32,
    /// Offset to string pool
    pub strings_offset: u32,
    /// Size of string pool
    pub strings_size: u32,
    /// Offset to per-dylib entries
    pub entries_offset: u32,
    /// Number of entries
    pub entries_count: u32,
}

/// Per-dylib local symbol entry (32-bit dylib offset).
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct DyldCacheLocalSymbolsEntry {
    /// File offset to dylib header
    pub dylib_offset: u32,
    /// Index into nlist array
    pub nlist_start_index: u32,
    /// Number of nlist entries for this dylib
    pub nlist_count: u32,
}

/// Per-dylib local symbol entry (64-bit dylib offset, newer caches).
#[derive(Debug, Clone, Copy, FromBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct DyldCacheLocalSymbolsEntry64 {
    /// File offset to dylib header
    pub dylib_offset: u64,
    /// Index into nlist array
    pub nlist_start_index: u32,
    /// Number of nlist entries for this dylib
    pub nlist_count: u32,
}

// =============================================================================
// Display Implementations
// =============================================================================

impl fmt::Display for DyldCacheHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "DyldCache {{ magic: {:?}, arch: {}, uuid: {} }}",
            std::str::from_utf8(&self.magic).unwrap_or("???"),
            self.architecture(),
            uuid_to_string(&self.uuid)
        )
    }
}

/// Formats a UUID as a hex string.
pub fn uuid_to_string(uuid: &[u8; 16]) -> String {
    format!(
        "{:02X}{:02X}{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        uuid[0], uuid[1], uuid[2], uuid[3],
        uuid[4], uuid[5],
        uuid[6], uuid[7],
        uuid[8], uuid[9],
        uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]
    )
}
