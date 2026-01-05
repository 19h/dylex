//! Mach-O constants and flags.

use bitflags::bitflags;

// =============================================================================
// Magic Numbers
// =============================================================================

/// 64-bit Mach-O magic (little-endian)
pub const MH_MAGIC_64: u32 = 0xFEEDFACF;

/// 64-bit Mach-O magic (big-endian, needs byte swap)
pub const MH_CIGAM_64: u32 = 0xCFFAEDFE;

/// 32-bit Mach-O magic (little-endian)
pub const MH_MAGIC: u32 = 0xFEEDFACE;

/// 32-bit Mach-O magic (big-endian)
pub const MH_CIGAM: u32 = 0xCEFAEDFE;

/// FAT binary magic
pub const FAT_MAGIC: u32 = 0xCAFEBABE;

// =============================================================================
// File Types
// =============================================================================

/// Object file
pub const MH_OBJECT: u32 = 0x1;
/// Executable
pub const MH_EXECUTE: u32 = 0x2;
/// Fixed VM shared library
pub const MH_FVMLIB: u32 = 0x3;
/// Core dump
pub const MH_CORE: u32 = 0x4;
/// Preloaded executable
pub const MH_PRELOAD: u32 = 0x5;
/// Dynamically bound shared library
pub const MH_DYLIB: u32 = 0x6;
/// Dynamic link editor
pub const MH_DYLINKER: u32 = 0x7;
/// Bundle
pub const MH_BUNDLE: u32 = 0x8;
/// Shared library stub
pub const MH_DYLIB_STUB: u32 = 0x9;
/// Debug symbols file
pub const MH_DSYM: u32 = 0xA;
/// Kernel extension bundle
pub const MH_KEXT_BUNDLE: u32 = 0xB;
/// File set (kernel cache)
pub const MH_FILESET: u32 = 0xC;

// =============================================================================
// CPU Types
// =============================================================================

/// 64-bit architecture flag
pub const CPU_ARCH_ABI64: u32 = 0x0100_0000;

/// ARM CPU type
pub const CPU_TYPE_ARM: u32 = 12;
/// ARM64 CPU type
pub const CPU_TYPE_ARM64: u32 = CPU_TYPE_ARM | CPU_ARCH_ABI64;

/// x86 CPU type
pub const CPU_TYPE_X86: u32 = 7;
/// x86_64 CPU type
pub const CPU_TYPE_X86_64: u32 = CPU_TYPE_X86 | CPU_ARCH_ABI64;

// =============================================================================
// CPU Subtypes
// =============================================================================

/// ARM64 all
pub const CPU_SUBTYPE_ARM64_ALL: u32 = 0;
/// ARM64 v8
pub const CPU_SUBTYPE_ARM64_V8: u32 = 1;
/// ARM64e (pointer authentication)
pub const CPU_SUBTYPE_ARM64E: u32 = 2;

// =============================================================================
// Load Commands
// =============================================================================

/// Load command requiring dynamic linker
pub const LC_REQ_DYLD: u32 = 0x8000_0000;

/// Segment of this file
pub const LC_SEGMENT: u32 = 0x1;
/// Link-edit symbol table info
pub const LC_SYMTAB: u32 = 0x2;
/// Link-edit thread local
pub const LC_SYMSEG: u32 = 0x3;
/// Thread
pub const LC_THREAD: u32 = 0x4;
/// Unix thread
pub const LC_UNIXTHREAD: u32 = 0x5;
/// Load a fixed VM shared library
pub const LC_LOADFVMLIB: u32 = 0x6;
/// Fixed VM shared library identification
pub const LC_IDFVMLIB: u32 = 0x7;
/// Object identification
pub const LC_IDENT: u32 = 0x8;
/// Fixed VM file inclusion
pub const LC_FVMFILE: u32 = 0x9;
/// Prepage command
pub const LC_PREPAGE: u32 = 0xA;
/// Dynamic link-edit symbol table info
pub const LC_DYSYMTAB: u32 = 0xB;
/// Load a dynamically linked shared library
pub const LC_LOAD_DYLIB: u32 = 0xC;
/// Dynamically linked shared lib identification
pub const LC_ID_DYLIB: u32 = 0xD;
/// Load a dynamic linker
pub const LC_LOAD_DYLINKER: u32 = 0xE;
/// Dynamic linker identification
pub const LC_ID_DYLINKER: u32 = 0xF;
/// Prebound modules
pub const LC_PREBOUND_DYLIB: u32 = 0x10;
/// Image routines
pub const LC_ROUTINES: u32 = 0x11;
/// Sub framework
pub const LC_SUB_FRAMEWORK: u32 = 0x12;
/// Sub umbrella
pub const LC_SUB_UMBRELLA: u32 = 0x13;
/// Sub client
pub const LC_SUB_CLIENT: u32 = 0x14;
/// Sub library
pub const LC_SUB_LIBRARY: u32 = 0x15;
/// Two-level namespace hints
pub const LC_TWOLEVEL_HINTS: u32 = 0x16;
/// Prebind checksum
pub const LC_PREBIND_CKSUM: u32 = 0x17;
/// Load a weak dynamically linked shared library
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x18 | LC_REQ_DYLD;
/// 64-bit segment
pub const LC_SEGMENT_64: u32 = 0x19;
/// 64-bit image routines
pub const LC_ROUTINES_64: u32 = 0x1A;
/// UUID
pub const LC_UUID: u32 = 0x1B;
/// Runpath additions
pub const LC_RPATH: u32 = 0x1C | LC_REQ_DYLD;
/// Local of code signature
pub const LC_CODE_SIGNATURE: u32 = 0x1D;
/// Local of segment split info
pub const LC_SEGMENT_SPLIT_INFO: u32 = 0x1E;
/// Load and re-export dylib
pub const LC_REEXPORT_DYLIB: u32 = 0x1F | LC_REQ_DYLD;
/// Delay load of dylib
pub const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
/// Encrypted segment information
pub const LC_ENCRYPTION_INFO: u32 = 0x21;
/// Compressed dyld info
pub const LC_DYLD_INFO: u32 = 0x22;
/// Compressed dyld info only
pub const LC_DYLD_INFO_ONLY: u32 = 0x22 | LC_REQ_DYLD;
/// Load upward dylib
pub const LC_LOAD_UPWARD_DYLIB: u32 = 0x23 | LC_REQ_DYLD;
/// Build for macOS min version
pub const LC_VERSION_MIN_MACOSX: u32 = 0x24;
/// Build for iOS min version
pub const LC_VERSION_MIN_IPHONEOS: u32 = 0x25;
/// Local of function starts
pub const LC_FUNCTION_STARTS: u32 = 0x26;
/// Environment variable string
pub const LC_DYLD_ENVIRONMENT: u32 = 0x27;
/// Main entry point (replacement for LC_UNIXTHREAD)
pub const LC_MAIN: u32 = 0x28 | LC_REQ_DYLD;
/// Table of non-instructions in __text
pub const LC_DATA_IN_CODE: u32 = 0x29;
/// Source version
pub const LC_SOURCE_VERSION: u32 = 0x2A;
/// Code signing DRs copied from linked dylibs
pub const LC_DYLIB_CODE_SIGN_DRS: u32 = 0x2B;
/// 64-bit encrypted segment information
pub const LC_ENCRYPTION_INFO_64: u32 = 0x2C;
/// Linker options
pub const LC_LINKER_OPTION: u32 = 0x2D;
/// Optimization hints
pub const LC_LINKER_OPTIMIZATION_HINT: u32 = 0x2E;
/// Build for tvOS min version
pub const LC_VERSION_MIN_TVOS: u32 = 0x2F;
/// Build for watchOS min version
pub const LC_VERSION_MIN_WATCHOS: u32 = 0x30;
/// Arbitrary data included within a Mach-O file
pub const LC_NOTE: u32 = 0x31;
/// Build for platform min version
pub const LC_BUILD_VERSION: u32 = 0x32;
/// Used with linkedit_data_command, payload is trie
pub const LC_DYLD_EXPORTS_TRIE: u32 = 0x33 | LC_REQ_DYLD;
/// Used with linkedit_data_command
pub const LC_DYLD_CHAINED_FIXUPS: u32 = 0x34 | LC_REQ_DYLD;
/// File set entry
pub const LC_FILESET_ENTRY: u32 = 0x35 | LC_REQ_DYLD;
/// Atom info
pub const LC_ATOM_INFO: u32 = 0x36;

// =============================================================================
// Section Types
// =============================================================================

/// Section types mask
pub const SECTION_TYPE: u32 = 0x0000_00FF;

/// Regular section
pub const S_REGULAR: u32 = 0x0;
/// Zero fill on demand
pub const S_ZEROFILL: u32 = 0x1;
/// Section with literal C strings
pub const S_CSTRING_LITERALS: u32 = 0x2;
/// Section with 4-byte literals
pub const S_4BYTE_LITERALS: u32 = 0x3;
/// Section with 8-byte literals
pub const S_8BYTE_LITERALS: u32 = 0x4;
/// Section with pointers to literals
pub const S_LITERAL_POINTERS: u32 = 0x5;
/// Section with non-lazy symbol pointers
pub const S_NON_LAZY_SYMBOL_POINTERS: u32 = 0x6;
/// Section with lazy symbol pointers
pub const S_LAZY_SYMBOL_POINTERS: u32 = 0x7;
/// Section with symbol stubs
pub const S_SYMBOL_STUBS: u32 = 0x8;
/// Section with only function pointers for initialization
pub const S_MOD_INIT_FUNC_POINTERS: u32 = 0x9;
/// Section with only function pointers for termination
pub const S_MOD_TERM_FUNC_POINTERS: u32 = 0xA;
/// Section contains symbols to be coalesced
pub const S_COALESCED: u32 = 0xB;
/// Zero fill on demand (>4GB)
pub const S_GB_ZEROFILL: u32 = 0xC;
/// Section with only pairs of function pointers for interposing
pub const S_INTERPOSING: u32 = 0xD;
/// Section with only 16-byte literals
pub const S_16BYTE_LITERALS: u32 = 0xE;
/// Section contains DTrace Object Format
pub const S_DTRACE_DOF: u32 = 0xF;
/// Section with only lazy symbol pointers to lazy loaded dylibs
pub const S_LAZY_DYLIB_SYMBOL_POINTERS: u32 = 0x10;
/// Thread local regular section
pub const S_THREAD_LOCAL_REGULAR: u32 = 0x11;
/// Thread local zerofill section
pub const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
/// Thread local variable section
pub const S_THREAD_LOCAL_VARIABLES: u32 = 0x13;
/// Thread local variable pointer section
pub const S_THREAD_LOCAL_VARIABLE_POINTERS: u32 = 0x14;
/// Thread local init function pointer section
pub const S_THREAD_LOCAL_INIT_FUNCTION_POINTERS: u32 = 0x15;
/// Init function offsets
pub const S_INIT_FUNC_OFFSETS: u32 = 0x16;

// =============================================================================
// Section Attributes
// =============================================================================

/// Section attributes mask
pub const SECTION_ATTRIBUTES: u32 = 0xFFFF_FF00;

/// System attributes mask
pub const SECTION_ATTRIBUTES_SYS: u32 = 0x00FF_FF00;

/// User attributes mask
pub const SECTION_ATTRIBUTES_USR: u32 = 0xFF00_0000;

/// Section contains only true machine instructions
pub const S_ATTR_PURE_INSTRUCTIONS: u32 = 0x8000_0000;

/// Section contains coalesced symbols
pub const S_ATTR_NO_TOC: u32 = 0x4000_0000;

/// OK to strip static symbols
pub const S_ATTR_STRIP_STATIC_SYMS: u32 = 0x2000_0000;

/// No dead stripping
pub const S_ATTR_NO_DEAD_STRIP: u32 = 0x1000_0000;

/// Live support
pub const S_ATTR_LIVE_SUPPORT: u32 = 0x0800_0000;

/// Self modifying code
pub const S_ATTR_SELF_MODIFYING_CODE: u32 = 0x0400_0000;

/// Debug section
pub const S_ATTR_DEBUG: u32 = 0x0200_0000;

/// Section contains some machine instructions
pub const S_ATTR_SOME_INSTRUCTIONS: u32 = 0x0000_0400;

/// Section has external relocation entries
pub const S_ATTR_EXT_RELOC: u32 = 0x0000_0200;

/// Section has local relocation entries
pub const S_ATTR_LOC_RELOC: u32 = 0x0000_0100;

// =============================================================================
// Symbol Types
// =============================================================================

/// If any of these bits set, a symbolic debugging entry
pub const N_STAB: u8 = 0xE0;
/// Private external symbol bit
pub const N_PEXT: u8 = 0x10;
/// Mask for the type bits
pub const N_TYPE: u8 = 0x0E;
/// External symbol bit
pub const N_EXT: u8 = 0x01;

/// Undefined symbol
pub const N_UNDF: u8 = 0x0;
/// Absolute symbol
pub const N_ABS: u8 = 0x2;
/// Defined in section number n_sect
pub const N_SECT: u8 = 0xE;
/// Prebound undefined
pub const N_PBUD: u8 = 0xC;
/// Indirect
pub const N_INDR: u8 = 0xA;

// =============================================================================
// Indirect Symbol Table
// =============================================================================

/// Symbol is local
pub const INDIRECT_SYMBOL_LOCAL: u32 = 0x8000_0000;
/// Symbol is absolute
pub const INDIRECT_SYMBOL_ABS: u32 = 0x4000_0000;

// =============================================================================
// Header Flags
// =============================================================================

bitflags! {
    /// Mach-O header flags.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct MachOFlags: u32 {
        /// The object file has no undefined references
        const NOUNDEFS = 0x1;
        /// The object file is the output of an incremental link
        const INCRLINK = 0x2;
        /// The object file is input for the dynamic linker
        const DYLDLINK = 0x4;
        /// The object file's undefined references are bound by the dynamic linker
        const BINDATLOAD = 0x8;
        /// The file has its dynamic undefined references prebound
        const PREBOUND = 0x10;
        /// The file has its read-only and read-write segments split
        const SPLIT_SEGS = 0x20;
        /// The shared library init routine is to be run lazily
        const LAZY_INIT = 0x40;
        /// The image is using two-level name space bindings
        const TWOLEVEL = 0x80;
        /// The executable is forcing all images to use flat name space bindings
        const FORCE_FLAT = 0x100;
        /// This umbrella guarantees no multiple definitions of symbols in its sub-images
        const NOMULTIDEFS = 0x200;
        /// Do not have dyld notify the prebinding agent about this executable
        const NOFIXPREBINDING = 0x400;
        /// The binary is not prebound but can have its prebinding redone
        const PREBINDABLE = 0x800;
        /// Indicates that this binary binds to all two-level namespace modules of its dependent libraries
        const ALLMODSBOUND = 0x1000;
        /// Safe to divide up the sections into sub-sections via symbols for dead code stripping
        const SUBSECTIONS_VIA_SYMBOLS = 0x2000;
        /// The binary has been canonicalized via the unprebind operation
        const CANONICAL = 0x4000;
        /// The final linked image contains external weak symbols
        const WEAK_DEFINES = 0x8000;
        /// The final linked image uses weak symbols
        const BINDS_TO_WEAK = 0x10000;
        /// When this bit is set, all stacks in the task will be given stack execution privilege
        const ALLOW_STACK_EXECUTION = 0x20000;
        /// When this bit is set, the binary declares it is safe for use in processes with uid zero
        const ROOT_SAFE = 0x40000;
        /// When this bit is set, the binary declares it is safe for use in processes when issetugid() is true
        const SETUID_SAFE = 0x80000;
        /// When this bit is set on a dylib, the static linker does not need to examine dependent dylibs to see if any are re-exported
        const NO_REEXPORTED_DYLIBS = 0x100000;
        /// When this bit is set, the OS will load the main executable at a random address
        const PIE = 0x200000;
        /// Only for use on dylibs: When linking against a dylib that has this bit set, the static linker will automatically not create a LC_LOAD_DYLIB load command to the dylib if no symbols are being referenced from the dylib
        const DEAD_STRIPPABLE_DYLIB = 0x400000;
        /// Contains a section of type S_THREAD_LOCAL_VARIABLES
        const HAS_TLV_DESCRIPTORS = 0x800000;
        /// When this bit is set, the OS will run the main executable with a non-executable heap even on platforms (e.g. i386) that don't require it. Only used in MH_EXECUTE filetypes
        const NO_HEAP_EXECUTION = 0x1000000;
        /// The code was linked for use in an application extension
        const APP_EXTENSION_SAFE = 0x2000000;
        /// The external symbols listed in the nlist symbol table do not include all the symbols listed in the dyld info
        const NLIST_OUTOFSYNC_WITH_DYLDINFO = 0x4000000;
        /// Allow LC_MIN_VERSION_MACOS and LC_BUILD_VERSION load commands with the platforms macOS, macCatalyst, iOSSimulator, tvOSSimulator and watchOSSimulator
        const SIM_SUPPORT = 0x8000000;
        /// The dylib is part of the dyld shared cache
        const DYLIB_IN_CACHE = 0x80000000;
    }
}
