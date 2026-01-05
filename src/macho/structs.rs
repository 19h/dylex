//! Mach-O binary structures.
//!
//! These structures match the on-disk format of Mach-O files.

use std::fmt;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use super::constants::*;

// =============================================================================
// Header Structures
// =============================================================================

/// 64-bit Mach-O header.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct MachHeader64 {
    /// Magic number (MH_MAGIC_64)
    pub magic: u32,
    /// CPU type
    pub cputype: u32,
    /// CPU subtype
    pub cpusubtype: u32,
    /// File type
    pub filetype: u32,
    /// Number of load commands
    pub ncmds: u32,
    /// Size of load commands
    pub sizeofcmds: u32,
    /// Flags
    pub flags: u32,
    /// Reserved
    pub reserved: u32,
}

impl MachHeader64 {
    /// Size of the header in bytes.
    pub const SIZE: usize = 32;

    /// Returns true if this is a valid 64-bit Mach-O header.
    #[inline]
    pub fn is_valid(&self) -> bool {
        self.magic == MH_MAGIC_64
    }

    /// Returns true if this is an ARM64 binary.
    #[inline]
    pub fn is_arm64(&self) -> bool {
        self.cputype == CPU_TYPE_ARM64
    }

    /// Returns true if this is an ARM64e binary (with pointer authentication).
    #[inline]
    pub fn is_arm64e(&self) -> bool {
        self.is_arm64() && (self.cpusubtype & 0xFF) == CPU_SUBTYPE_ARM64E
    }

    /// Returns true if this is an x86_64 binary.
    #[inline]
    pub fn is_x86_64(&self) -> bool {
        self.cputype == CPU_TYPE_X86_64
    }

    /// Returns true if this is a dylib.
    #[inline]
    pub fn is_dylib(&self) -> bool {
        self.filetype == MH_DYLIB
    }

    /// Returns the architecture as a string.
    pub fn arch_name(&self) -> &'static str {
        match self.cputype {
            CPU_TYPE_ARM64 => {
                if self.is_arm64e() {
                    "arm64e"
                } else {
                    "arm64"
                }
            }
            CPU_TYPE_X86_64 => "x86_64",
            CPU_TYPE_ARM => "arm",
            CPU_TYPE_X86 => "i386",
            _ => "unknown",
        }
    }
}

impl Default for MachHeader64 {
    fn default() -> Self {
        Self {
            magic: MH_MAGIC_64,
            cputype: 0,
            cpusubtype: 0,
            filetype: 0,
            ncmds: 0,
            sizeofcmds: 0,
            flags: 0,
            reserved: 0,
        }
    }
}

// =============================================================================
// Load Command Header
// =============================================================================

/// Generic load command header.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct LoadCommand {
    /// Type of load command
    pub cmd: u32,
    /// Size of load command
    pub cmdsize: u32,
}

impl LoadCommand {
    /// Size of the load command header.
    pub const SIZE: usize = 8;
}

// =============================================================================
// Segment Command
// =============================================================================

/// 64-bit segment command.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct SegmentCommand64 {
    /// LC_SEGMENT_64
    pub cmd: u32,
    /// Size of this load command
    pub cmdsize: u32,
    /// Segment name (16 bytes, null-padded)
    pub segname: [u8; 16],
    /// Virtual memory address
    pub vmaddr: u64,
    /// Virtual memory size
    pub vmsize: u64,
    /// File offset
    pub fileoff: u64,
    /// Amount of file to map
    pub filesize: u64,
    /// Maximum VM protection
    pub maxprot: u32,
    /// Initial VM protection
    pub initprot: u32,
    /// Number of sections
    pub nsects: u32,
    /// Flags
    pub flags: u32,
}

impl SegmentCommand64 {
    /// Size of the segment command (without sections).
    pub const SIZE: usize = 72;

    /// Returns the segment name as a string.
    pub fn name(&self) -> &str {
        let end = self.segname.iter().position(|&b| b == 0).unwrap_or(16);
        std::str::from_utf8(&self.segname[..end]).unwrap_or("")
    }

    /// Sets the segment name from a string.
    pub fn set_name(&mut self, name: &str) {
        self.segname = [0u8; 16];
        let bytes = name.as_bytes();
        let len = bytes.len().min(16);
        self.segname[..len].copy_from_slice(&bytes[..len]);
    }

    /// Returns true if this is the __TEXT segment.
    #[inline]
    pub fn is_text(&self) -> bool {
        &self.segname[..7] == b"__TEXT\0"
    }

    /// Returns true if this is the __DATA segment.
    #[inline]
    pub fn is_data(&self) -> bool {
        &self.segname[..7] == b"__DATA\0"
    }

    /// Returns true if this is the __LINKEDIT segment.
    #[inline]
    pub fn is_linkedit(&self) -> bool {
        &self.segname[..11] == b"__LINKEDIT\0"
    }
}

impl Default for SegmentCommand64 {
    fn default() -> Self {
        Self {
            cmd: LC_SEGMENT_64,
            cmdsize: Self::SIZE as u32,
            segname: [0u8; 16],
            vmaddr: 0,
            vmsize: 0,
            fileoff: 0,
            filesize: 0,
            maxprot: 0,
            initprot: 0,
            nsects: 0,
            flags: 0,
        }
    }
}

// =============================================================================
// Section
// =============================================================================

/// 64-bit section.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Section64 {
    /// Section name (16 bytes, null-padded)
    pub sectname: [u8; 16],
    /// Segment name (16 bytes, null-padded)
    pub segname: [u8; 16],
    /// Virtual memory address
    pub addr: u64,
    /// Size in bytes
    pub size: u64,
    /// File offset
    pub offset: u32,
    /// Alignment (power of 2)
    pub align: u32,
    /// File offset of relocation entries
    pub reloff: u32,
    /// Number of relocation entries
    pub nreloc: u32,
    /// Flags
    pub flags: u32,
    /// Reserved (for runtime use)
    pub reserved1: u32,
    /// Reserved (for runtime use)
    pub reserved2: u32,
    /// Reserved
    pub reserved3: u32,
}

impl Section64 {
    /// Size of a section entry.
    pub const SIZE: usize = 80;

    /// Returns the section name as a string.
    pub fn name(&self) -> &str {
        let end = self.sectname.iter().position(|&b| b == 0).unwrap_or(16);
        std::str::from_utf8(&self.sectname[..end]).unwrap_or("")
    }

    /// Returns the segment name as a string.
    pub fn segment_name(&self) -> &str {
        let end = self.segname.iter().position(|&b| b == 0).unwrap_or(16);
        std::str::from_utf8(&self.segname[..end]).unwrap_or("")
    }

    /// Sets the section name from a string.
    pub fn set_name(&mut self, name: &str) {
        self.sectname = [0u8; 16];
        let bytes = name.as_bytes();
        let len = bytes.len().min(16);
        self.sectname[..len].copy_from_slice(&bytes[..len]);
    }

    /// Returns the section type.
    #[inline]
    pub fn section_type(&self) -> u32 {
        self.flags & SECTION_TYPE
    }

    /// Returns true if this section has indirect symbol references.
    #[inline]
    pub fn has_indirect_symbols(&self) -> bool {
        matches!(
            self.section_type(),
            S_NON_LAZY_SYMBOL_POINTERS
                | S_LAZY_SYMBOL_POINTERS
                | S_SYMBOL_STUBS
                | S_LAZY_DYLIB_SYMBOL_POINTERS
        )
    }

    /// Returns the indirect symbol table index (from reserved1).
    #[inline]
    pub fn indirect_symbol_index(&self) -> u32 {
        self.reserved1
    }

    /// Returns the stub size (from reserved2) for stub sections.
    #[inline]
    pub fn stub_size(&self) -> u32 {
        self.reserved2
    }
}

impl Default for Section64 {
    fn default() -> Self {
        Self {
            sectname: [0u8; 16],
            segname: [0u8; 16],
            addr: 0,
            size: 0,
            offset: 0,
            align: 0,
            reloff: 0,
            nreloc: 0,
            flags: 0,
            reserved1: 0,
            reserved2: 0,
            reserved3: 0,
        }
    }
}

// =============================================================================
// Symbol Table Commands
// =============================================================================

/// Symbol table command.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct SymtabCommand {
    /// LC_SYMTAB
    pub cmd: u32,
    /// Size of this load command
    pub cmdsize: u32,
    /// Symbol table offset
    pub symoff: u32,
    /// Number of symbol table entries
    pub nsyms: u32,
    /// String table offset
    pub stroff: u32,
    /// String table size in bytes
    pub strsize: u32,
}

impl SymtabCommand {
    /// Size of this command.
    pub const SIZE: usize = 24;
}

impl Default for SymtabCommand {
    fn default() -> Self {
        Self {
            cmd: LC_SYMTAB,
            cmdsize: Self::SIZE as u32,
            symoff: 0,
            nsyms: 0,
            stroff: 0,
            strsize: 0,
        }
    }
}

/// Dynamic symbol table command.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct DysymtabCommand {
    /// LC_DYSYMTAB
    pub cmd: u32,
    /// Size of this load command
    pub cmdsize: u32,
    /// Index of local symbols
    pub ilocalsym: u32,
    /// Number of local symbols
    pub nlocalsym: u32,
    /// Index of externally defined symbols
    pub iextdefsym: u32,
    /// Number of externally defined symbols
    pub nextdefsym: u32,
    /// Index of undefined symbols
    pub iundefsym: u32,
    /// Number of undefined symbols
    pub nundefsym: u32,
    /// File offset to table of contents
    pub tocoff: u32,
    /// Number of entries in table of contents
    pub ntoc: u32,
    /// File offset to module table
    pub modtaboff: u32,
    /// Number of module table entries
    pub nmodtab: u32,
    /// Offset to referenced symbol table
    pub extrefsymoff: u32,
    /// Number of referenced symbol table entries
    pub nextrefsyms: u32,
    /// File offset to the indirect symbol table
    pub indirectsymoff: u32,
    /// Number of indirect symbol table entries
    pub nindirectsyms: u32,
    /// Offset to external relocation entries
    pub extreloff: u32,
    /// Number of external relocation entries
    pub nextrel: u32,
    /// Offset to local relocation entries
    pub locreloff: u32,
    /// Number of local relocation entries
    pub nlocrel: u32,
}

impl DysymtabCommand {
    /// Size of this command.
    pub const SIZE: usize = 80;
}

impl Default for DysymtabCommand {
    fn default() -> Self {
        Self {
            cmd: LC_DYSYMTAB,
            cmdsize: Self::SIZE as u32,
            ilocalsym: 0,
            nlocalsym: 0,
            iextdefsym: 0,
            nextdefsym: 0,
            iundefsym: 0,
            nundefsym: 0,
            tocoff: 0,
            ntoc: 0,
            modtaboff: 0,
            nmodtab: 0,
            extrefsymoff: 0,
            nextrefsyms: 0,
            indirectsymoff: 0,
            nindirectsyms: 0,
            extreloff: 0,
            nextrel: 0,
            locreloff: 0,
            nlocrel: 0,
        }
    }
}

/// 64-bit symbol table entry.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Nlist64 {
    /// Index into string table
    pub n_strx: u32,
    /// Type flag
    pub n_type: u8,
    /// Section number or NO_SECT
    pub n_sect: u8,
    /// Flags (see <mach-o/stab.h>)
    pub n_desc: u16,
    /// Value
    pub n_value: u64,
}

impl Nlist64 {
    /// Size of an nlist entry.
    pub const SIZE: usize = 16;

    /// Returns true if this is an external symbol.
    #[inline]
    pub fn is_external(&self) -> bool {
        (self.n_type & N_EXT) != 0
    }

    /// Returns true if this is an undefined symbol.
    #[inline]
    pub fn is_undefined(&self) -> bool {
        (self.n_type & N_TYPE) == N_UNDF
    }

    /// Returns true if this is a defined symbol.
    #[inline]
    pub fn is_defined(&self) -> bool {
        (self.n_type & N_TYPE) == N_SECT
    }

    /// Returns true if this is a debugging symbol.
    #[inline]
    pub fn is_debug(&self) -> bool {
        (self.n_type & N_STAB) != 0
    }
}

impl Default for Nlist64 {
    fn default() -> Self {
        Self {
            n_strx: 0,
            n_type: 0,
            n_sect: 0,
            n_desc: 0,
            n_value: 0,
        }
    }
}

// =============================================================================
// Dyld Info Command
// =============================================================================

/// Dyld info command (compressed LINKEDIT information).
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct DyldInfoCommand {
    /// LC_DYLD_INFO or LC_DYLD_INFO_ONLY
    pub cmd: u32,
    /// Size of this load command
    pub cmdsize: u32,
    /// File offset to rebase info
    pub rebase_off: u32,
    /// Size of rebase info
    pub rebase_size: u32,
    /// File offset to binding info
    pub bind_off: u32,
    /// Size of binding info
    pub bind_size: u32,
    /// File offset to weak binding info
    pub weak_bind_off: u32,
    /// Size of weak binding info
    pub weak_bind_size: u32,
    /// File offset to lazy binding info
    pub lazy_bind_off: u32,
    /// Size of lazy binding info
    pub lazy_bind_size: u32,
    /// File offset to export info
    pub export_off: u32,
    /// Size of export info
    pub export_size: u32,
}

impl DyldInfoCommand {
    /// Size of this command.
    pub const SIZE: usize = 48;
}

impl Default for DyldInfoCommand {
    fn default() -> Self {
        Self {
            cmd: LC_DYLD_INFO_ONLY,
            cmdsize: Self::SIZE as u32,
            rebase_off: 0,
            rebase_size: 0,
            bind_off: 0,
            bind_size: 0,
            weak_bind_off: 0,
            weak_bind_size: 0,
            lazy_bind_off: 0,
            lazy_bind_size: 0,
            export_off: 0,
            export_size: 0,
        }
    }
}

// =============================================================================
// Linkedit Data Command
// =============================================================================

/// Generic linkedit data command.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct LinkeditDataCommand {
    /// Command type (LC_CODE_SIGNATURE, LC_FUNCTION_STARTS, etc.)
    pub cmd: u32,
    /// Size of this load command
    pub cmdsize: u32,
    /// File offset
    pub dataoff: u32,
    /// Size
    pub datasize: u32,
}

impl LinkeditDataCommand {
    /// Size of this command.
    pub const SIZE: usize = 16;
}

impl Default for LinkeditDataCommand {
    fn default() -> Self {
        Self {
            cmd: 0,
            cmdsize: Self::SIZE as u32,
            dataoff: 0,
            datasize: 0,
        }
    }
}

// =============================================================================
// Dylib Command
// =============================================================================

/// Dylib reference (shared by several load commands).
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct Dylib {
    /// Library's path name offset
    pub name_offset: u32,
    /// Library's build timestamp
    pub timestamp: u32,
    /// Library's current version number
    pub current_version: u32,
    /// Library's compatibility version number
    pub compatibility_version: u32,
}

/// Dylib load command.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct DylibCommand {
    /// LC_LOAD_DYLIB, LC_ID_DYLIB, etc.
    pub cmd: u32,
    /// Total size (includes path string)
    pub cmdsize: u32,
    /// Library identification
    pub dylib: Dylib,
}

impl DylibCommand {
    /// Minimum size of this command (without path string).
    pub const SIZE: usize = 24;
}

// =============================================================================
// UUID Command
// =============================================================================

/// UUID command.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct UuidCommand {
    /// LC_UUID
    pub cmd: u32,
    /// Size of this load command
    pub cmdsize: u32,
    /// UUID
    pub uuid: [u8; 16],
}

impl UuidCommand {
    /// Size of this command.
    pub const SIZE: usize = 24;
}

impl Default for UuidCommand {
    fn default() -> Self {
        Self {
            cmd: LC_UUID,
            cmdsize: Self::SIZE as u32,
            uuid: [0u8; 16],
        }
    }
}

// =============================================================================
// Build Version Command
// =============================================================================

/// Build version command.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct BuildVersionCommand {
    /// LC_BUILD_VERSION
    pub cmd: u32,
    /// Size of this load command
    pub cmdsize: u32,
    /// Platform
    pub platform: u32,
    /// Minimum OS version (X.Y.Z packed into 32 bits)
    pub minos: u32,
    /// SDK version (X.Y.Z packed into 32 bits)
    pub sdk: u32,
    /// Number of tool entries following
    pub ntools: u32,
}

impl BuildVersionCommand {
    /// Size of this command (without tool entries).
    pub const SIZE: usize = 24;
}

// =============================================================================
// Fileset Entry Command (for kernelcaches)
// =============================================================================

/// Fileset entry command.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct FilesetEntryCommand {
    /// LC_FILESET_ENTRY
    pub cmd: u32,
    /// Size of this load command
    pub cmdsize: u32,
    /// Virtual memory address
    pub vmaddr: u64,
    /// File offset
    pub fileoff: u64,
    /// Offset to entry path name
    pub entry_id_offset: u32,
    /// Reserved
    pub reserved: u32,
}

impl FilesetEntryCommand {
    /// Minimum size of this command.
    pub const SIZE: usize = 32;
}

// =============================================================================
// Encryption Info Command
// =============================================================================

/// 64-bit encryption info command.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct EncryptionInfoCommand64 {
    /// LC_ENCRYPTION_INFO_64
    pub cmd: u32,
    /// Size of this load command
    pub cmdsize: u32,
    /// File offset of encrypted range
    pub cryptoff: u32,
    /// Size of encrypted range
    pub cryptsize: u32,
    /// Encryption system ID (0 = not encrypted yet)
    pub cryptid: u32,
    /// Padding
    pub pad: u32,
}

impl EncryptionInfoCommand64 {
    /// Size of this command.
    pub const SIZE: usize = 24;
}

// =============================================================================
// Source Version Command
// =============================================================================

/// Source version command.
#[derive(Debug, Clone, Copy, FromBytes, IntoBytes, KnownLayout, Immutable)]
#[repr(C)]
pub struct SourceVersionCommand {
    /// LC_SOURCE_VERSION
    pub cmd: u32,
    /// Size of this load command
    pub cmdsize: u32,
    /// A.B.C.D.E packed into 64 bits
    pub version: u64,
}

impl SourceVersionCommand {
    /// Size of this command.
    pub const SIZE: usize = 16;
}

// =============================================================================
// Display Implementations
// =============================================================================

impl fmt::Display for MachHeader64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MachO {{ arch: {}, type: {:#x}, cmds: {}, flags: {:#x} }}",
            self.arch_name(),
            self.filetype,
            self.ncmds,
            self.flags
        )
    }
}

impl fmt::Display for SegmentCommand64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Segment {{ name: \"{}\", vm: {:#x}+{:#x}, file: {:#x}+{:#x}, sects: {} }}",
            self.name(),
            self.vmaddr,
            self.vmsize,
            self.fileoff,
            self.filesize,
            self.nsects
        )
    }
}

impl fmt::Display for Section64 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Section {{ name: \"{},{}\", addr: {:#x}+{:#x}, offset: {:#x} }}",
            self.segment_name(),
            self.name(),
            self.addr,
            self.size,
            self.offset
        )
    }
}
