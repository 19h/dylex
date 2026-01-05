//! ObjC metadata fixer.
//!
//! In the dyld shared cache, ObjC metadata is optimized and partially
//! moved to libobjc.A.dylib. This module restores it for extracted images.

use crate::error::Result;

use super::ExtractionContext;

/// ObjC image info flags.
pub const OBJC_IMAGE_IS_SIMULATED: u32 = 1 << 0;
pub const OBJC_IMAGE_IS_REPLACEMENT: u32 = 1 << 1;
pub const OBJC_IMAGE_SUPPORTS_GC: u32 = 1 << 2;
pub const OBJC_IMAGE_OPTIMIZED_BY_DYLD: u32 = 1 << 3;
pub const OBJC_IMAGE_SIGNED_CLASS_RO: u32 = 1 << 4;

/// Method list flags.
pub const METHOD_LIST_RELATIVE_FLAG: u32 = 0x8000_0000;
pub const METHOD_LIST_SELECTORS_DIRECT_FLAG: u32 = 0x4000_0000;
pub const METHOD_LIST_FLAGS_MASK: u32 = 0xFFFF_0000;

/// Fixes ObjC metadata in the extracted image.
pub fn fix_objc(ctx: &mut ExtractionContext) -> Result<()> {
    // Check if ObjC was optimized
    let imageinfo = match ctx.macho.section("__DATA", "__objc_imageinfo") {
        Some(sect) => sect,
        None => {
            // Try __DATA_CONST
            match ctx.macho.section("__DATA_CONST", "__objc_imageinfo") {
                Some(sect) => sect,
                None => {
                    ctx.info("No ObjC image info found, skipping ObjC fixing");
                    return Ok(());
                }
            }
        }
    };

    // Read image info flags
    let offset = imageinfo.section.offset as usize;
    if offset + 8 > ctx.macho.data.len() {
        return Ok(());
    }

    let flags = u32::from_le_bytes([
        ctx.macho.data[offset + 4],
        ctx.macho.data[offset + 5],
        ctx.macho.data[offset + 6],
        ctx.macho.data[offset + 7],
    ]);

    if (flags & OBJC_IMAGE_OPTIMIZED_BY_DYLD) == 0 {
        ctx.info("ObjC not optimized by dyld, skipping");
        return Ok(());
    }

    ctx.info("Fixing ObjC metadata...");

    // Clear the optimized flag
    let new_flags = flags & !OBJC_IMAGE_OPTIMIZED_BY_DYLD;
    ctx.macho.data[offset + 4..offset + 8].copy_from_slice(&new_flags.to_le_bytes());

    // TODO: Full ObjC fixing implementation
    // This requires:
    // 1. Creating an extra segment for pulled-in ObjC data
    // 2. Processing classes, categories, and protocols
    // 3. Fixing method lists and selector references
    // 4. Fixing selector direct loads in __text

    Ok(())
}
