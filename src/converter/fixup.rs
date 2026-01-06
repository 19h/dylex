//! Header and load command fixups for extracted binaries.
//!
//! This module handles critical fixups that Apple's dsc_extractor performs:
//! - Clearing the MH_DYLIB_IN_CACHE flag from the Mach-O header
//! - Zeroing out LC_DYLD_CHAINED_FIXUPS data (pointers already resolved)
//! - Zeroing out LC_DYLD_EXPORTS_TRIE data (exports are in symbol table)
//! - Optionally removing LC_SOURCE_VERSION load commands

use crate::error::Result;
use crate::macho::{LC_DYLD_CHAINED_FIXUPS, LC_DYLD_EXPORTS_TRIE};

use super::ExtractionContext;

// =============================================================================
// Header Flags
// =============================================================================

/// The MH_DYLIB_IN_CACHE flag (0x80000000) indicates the dylib is part of
/// the dyld shared cache. This MUST be cleared for standalone operation.
const MH_DYLIB_IN_CACHE: u32 = 0x8000_0000;

/// Offset of the flags field within the mach_header_64 structure.
/// Layout: magic(4) + cputype(4) + cpusubtype(4) + filetype(4) + ncmds(4) + sizeofcmds(4) + flags(4)
const HEADER_FLAGS_OFFSET: usize = 24;

// =============================================================================
// Chained Fixups Command Layout
// =============================================================================

/// LC_DYLD_CHAINED_FIXUPS command layout (linkedit_data_command):
/// - cmd (4 bytes) at offset 0
/// - cmdsize (4 bytes) at offset 4  
/// - dataoff (4 bytes) at offset 8
/// - datasize (4 bytes) at offset 12
const CHAINED_FIXUPS_DATAOFF_OFFSET: usize = 8;
const CHAINED_FIXUPS_DATASIZE_OFFSET: usize = 12;

// =============================================================================
// Public API
// =============================================================================

/// Performs critical header fixups on the extracted Mach-O.
///
/// This function:
/// 1. Clears the MH_DYLIB_IN_CACHE flag from the header
/// 2. Zeroes out LC_DYLD_CHAINED_FIXUPS data (pointers already rebased via slide info)
/// 3. Zeroes out LC_DYLD_EXPORTS_TRIE data (exports are in symbol table)
///
/// These fixups are essential for the binary to work as a standalone dylib.
/// Apple's dsc_extractor.bundle performs these same operations.
pub fn fix_header_and_load_commands(ctx: &mut ExtractionContext) -> Result<()> {
    ctx.info("Fixing header and load commands...");

    // 1. Clear MH_DYLIB_IN_CACHE flag
    clear_dylib_in_cache_flag(ctx)?;

    // 2. Zero out chained fixups (the pointers have been rebased via slide info)
    zero_chained_fixups(ctx)?;

    // 3. Zero out exports trie (the exports are in the symbol table)
    zero_exports_trie(ctx)?;

    Ok(())
}

/// Clears the MH_DYLIB_IN_CACHE flag from the Mach-O header.
///
/// This flag (0x80000000) indicates the binary is part of the dyld shared cache.
/// If not cleared, dyld will treat the extracted binary incorrectly and it
/// may fail to load or behave unexpectedly.
///
/// Apple's dsc_extractor does this at the very start:
/// ```c
/// *(_BYTE *)(a2 + 27) &= ~0x80u;  // Clear high byte of flags
/// ```
pub fn clear_dylib_in_cache_flag(ctx: &mut ExtractionContext) -> Result<()> {
    // Read current flags
    let flags = ctx.macho.read_u32(HEADER_FLAGS_OFFSET)?;

    if (flags & MH_DYLIB_IN_CACHE) != 0 {
        // Clear the flag
        let new_flags = flags & !MH_DYLIB_IN_CACHE;
        ctx.macho.write_u32(HEADER_FLAGS_OFFSET, new_flags)?;

        // Also update the header struct
        ctx.macho.header.flags = new_flags;

        ctx.info("Cleared MH_DYLIB_IN_CACHE flag");
    }

    Ok(())
}

/// Zeroes out LC_DYLD_CHAINED_FIXUPS command data.
///
/// In modern binaries (iOS 15+, macOS 12+), chained fixups replace the traditional
/// rebase/bind opcodes. When extracting from the cache, the pointers have already
/// been resolved via slide info processing, so the chained fixups data is no longer
/// needed and should be zeroed out.
///
/// Apple's dsc_extractor does this:
/// ```c
/// case 0x80000022: // LC_DYLD_CHAINED_FIXUPS
///     *(_OWORD *)(a2 + 6) = 0;   // Zero bytes 48-63 (padding)
///     *(_OWORD *)(a2 + 2) = 0;   // Zero bytes 16-31 (more padding)
///     *((_QWORD *)a2 + 5) = 0;   // Zero bytes 40-47
/// ```
pub fn zero_chained_fixups(ctx: &mut ExtractionContext) -> Result<()> {
    // Find LC_DYLD_CHAINED_FIXUPS load command
    let mut offset = 32usize; // Start after mach_header_64
    let end_offset = 32 + ctx.macho.header.sizeofcmds as usize;

    while offset < end_offset {
        if offset + 8 > ctx.macho.data.len() {
            break;
        }

        let cmd = ctx.macho.read_u32(offset)?;
        let cmdsize = ctx.macho.read_u32(offset + 4)?;

        if cmd == LC_DYLD_CHAINED_FIXUPS {
            // Zero out dataoff and datasize
            // The actual fixup data in LINKEDIT is handled separately
            ctx.macho
                .write_u32(offset + CHAINED_FIXUPS_DATAOFF_OFFSET, 0)?;
            ctx.macho
                .write_u32(offset + CHAINED_FIXUPS_DATASIZE_OFFSET, 0)?;

            ctx.info("Zeroed LC_DYLD_CHAINED_FIXUPS offsets");
        }

        offset += cmdsize as usize;
    }

    Ok(())
}

/// Zeroes out LC_DYLD_EXPORTS_TRIE command data.
///
/// Apple's dsc_extractor zeros out the exports trie for extracted binaries.
/// The export information is available in the symbol table, so the trie
/// is not needed and zeroing it makes the binary more compatible.
pub fn zero_exports_trie(ctx: &mut ExtractionContext) -> Result<()> {
    // Find LC_DYLD_EXPORTS_TRIE load command
    let mut offset = 32usize; // Start after mach_header_64
    let end_offset = 32 + ctx.macho.header.sizeofcmds as usize;

    while offset < end_offset {
        if offset + 8 > ctx.macho.data.len() {
            break;
        }

        let cmd = ctx.macho.read_u32(offset)?;
        let cmdsize = ctx.macho.read_u32(offset + 4)?;

        if cmd == LC_DYLD_EXPORTS_TRIE {
            // Zero out dataoff and datasize (same layout as linkedit_data_command)
            ctx.macho.write_u32(offset + 8, 0)?; // dataoff
            ctx.macho.write_u32(offset + 12, 0)?; // datasize

            ctx.info("Zeroed LC_DYLD_EXPORTS_TRIE offsets");
        }

        offset += cmdsize as usize;
    }

    Ok(())
}

/// Removes specified load commands by compacting the load command region.
///
/// Apple's dsc_extractor removes certain load commands like LC_SOURCE_VERSION.
/// This function removes commands matching the given type.
pub fn remove_load_command(ctx: &mut ExtractionContext, cmd_type: u32) -> Result<usize> {
    let mut removed = 0;
    let mut read_offset = 32usize;
    let mut write_offset = 32usize;
    let end_offset = 32 + ctx.macho.header.sizeofcmds as usize;

    // Copy load commands, skipping those we want to remove
    while read_offset < end_offset {
        if read_offset + 8 > ctx.macho.data.len() {
            break;
        }

        let cmd = ctx.macho.read_u32(read_offset)?;
        let cmdsize = ctx.macho.read_u32(read_offset + 4)?;

        if cmd == cmd_type {
            // Skip this command
            removed += 1;
        } else {
            // Copy this command if we're compacting
            if write_offset != read_offset {
                let cmd_data: Vec<u8> =
                    ctx.macho.data[read_offset..read_offset + cmdsize as usize].to_vec();
                ctx.macho.data[write_offset..write_offset + cmdsize as usize]
                    .copy_from_slice(&cmd_data);
            }
            write_offset += cmdsize as usize;
        }

        read_offset += cmdsize as usize;
    }

    if removed > 0 {
        // Update header
        ctx.macho.header.ncmds -= removed as u32;
        ctx.macho.header.sizeofcmds = (write_offset - 32) as u32;

        // Write updated header
        ctx.macho.write_u32(16, ctx.macho.header.ncmds)?; // ncmds offset
        ctx.macho.write_u32(20, ctx.macho.header.sizeofcmds)?; // sizeofcmds offset

        // Zero out the freed space
        for i in write_offset..end_offset {
            if i < ctx.macho.data.len() {
                ctx.macho.data[i] = 0;
            }
        }

        ctx.info(&format!(
            "Removed {} load command(s) of type {:#x}",
            removed, cmd_type
        ));
    }

    Ok(removed)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flag_value() {
        assert_eq!(MH_DYLIB_IN_CACHE, 0x80000000);
    }

    #[test]
    fn test_flag_clearing() {
        let flags: u32 = 0x80200085; // DYLIB_IN_CACHE | PIE | other flags
        let cleared = flags & !MH_DYLIB_IN_CACHE;
        assert_eq!(cleared, 0x00200085);
        assert_eq!(cleared & MH_DYLIB_IN_CACHE, 0);
    }

    #[test]
    fn test_header_offset() {
        // mach_header_64 layout verification
        // magic: 0-3, cputype: 4-7, cpusubtype: 8-11, filetype: 12-15
        // ncmds: 16-19, sizeofcmds: 20-23, flags: 24-27, reserved: 28-31
        assert_eq!(HEADER_FLAGS_OFFSET, 24);
    }
}
