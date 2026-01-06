//! ObjC metadata fixer.
//!
//! In the dyld shared cache, ObjC metadata is optimized:
//! - Selectors are uniqued and stored in libobjc's selector table
//! - Class data may reference shared RO data
//! - Method lists use direct selector references
//!
//! This module fixes these optimizations for standalone operation.

use crate::error::Result;

use super::ExtractionContext;

// =============================================================================
// ObjC Image Info Flags
// =============================================================================

/// Image is from the iOS Simulator.
pub const OBJC_IMAGE_IS_SIMULATED: u32 = 1 << 0;

/// Image replaces another image.
pub const OBJC_IMAGE_IS_REPLACEMENT: u32 = 1 << 1;

/// Image supports garbage collection (deprecated).
pub const OBJC_IMAGE_SUPPORTS_GC: u32 = 1 << 2;

/// Image has been optimized by dyld.
pub const OBJC_IMAGE_OPTIMIZED_BY_DYLD: u32 = 1 << 3;

/// Image has signed class_ro pointers (arm64e).
pub const OBJC_IMAGE_SIGNED_CLASS_RO: u32 = 1 << 4;

/// Image supports categorizing classes defined in this image.
pub const OBJC_IMAGE_SUPPORTS_COMPACTION: u32 = 1 << 5;

// =============================================================================
// Method List Flags
// =============================================================================

/// Method list uses relative method encoding.
pub const METHOD_LIST_RELATIVE_FLAG: u32 = 0x8000_0000;

/// Method list has direct selector references (no indirection).
pub const METHOD_LIST_DIRECT_SEL_FLAG: u32 = 0x4000_0000;

/// Method list uses uniqued selectors.
pub const METHOD_LIST_UNIQUED_FLAG: u32 = 0x2000_0000;

/// Mask for method list entry count.
pub const METHOD_LIST_COUNT_MASK: u32 = 0x00FF_FFFF;

// Reserved for future use when converting method list formats
#[allow(dead_code)]
const RELATIVE_METHOD_SIZE: usize = 12;
#[allow(dead_code)]
const OLD_METHOD_SIZE: usize = 24;

// =============================================================================
// ObjC Fixer Implementation
// =============================================================================

/// Fixes ObjC metadata in the extracted image.
///
/// This function performs the following fixes:
/// 1. Fixes method lists with direct selector references
/// 2. Clears the uniqued selectors flag from method lists
///
/// Note: The OBJC_IMAGE_OPTIMIZED_BY_DYLD flag is preserved because the
/// ObjC metadata is still in its optimized form after extraction.
/// Apple's dsc_extractor also preserves this flag.
pub fn fix_objc(ctx: &mut ExtractionContext) -> Result<()> {
    // Find __objc_imageinfo section
    let imageinfo = ctx
        .macho
        .section("__DATA", "__objc_imageinfo")
        .or_else(|| ctx.macho.section("__DATA_CONST", "__objc_imageinfo"));

    let imageinfo = match imageinfo {
        Some(sect) => sect.clone(),
        None => {
            ctx.info("No ObjC image info found, skipping ObjC fixing");
            return Ok(());
        }
    };

    // Read and check image info flags
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

    // Note: We preserve OBJC_IMAGE_OPTIMIZED_BY_DYLD flag - Apple's dsc_extractor
    // does the same. The metadata is still optimized after extraction.

    // Fix method lists in classes
    let mut fixed_methods = 0;
    fixed_methods += fix_class_method_lists(ctx)?;

    // Fix method lists in categories
    fixed_methods += fix_category_method_lists(ctx)?;

    if fixed_methods > 0 {
        ctx.info(&format!("Fixed {} method lists", fixed_methods));
    }

    Ok(())
}

/// Fixes method lists in all classes.
fn fix_class_method_lists(ctx: &mut ExtractionContext) -> Result<usize> {
    // Get __objc_classlist section
    let classlist = ctx
        .macho
        .section("__DATA", "__objc_classlist")
        .or_else(|| ctx.macho.section("__DATA_CONST", "__objc_classlist"));

    let classlist = match classlist {
        Some(s) => s.clone(),
        None => return Ok(0),
    };

    let count = classlist.section.size as usize / 8;
    let mut fixed = 0;

    for i in 0..count {
        let ptr_offset = classlist.section.offset as usize + i * 8;
        if ptr_offset + 8 > ctx.macho.data.len() {
            break;
        }

        // Read class pointer
        let class_addr = u64::from_le_bytes([
            ctx.macho.data[ptr_offset],
            ctx.macho.data[ptr_offset + 1],
            ctx.macho.data[ptr_offset + 2],
            ctx.macho.data[ptr_offset + 3],
            ctx.macho.data[ptr_offset + 4],
            ctx.macho.data[ptr_offset + 5],
            ctx.macho.data[ptr_offset + 6],
            ctx.macho.data[ptr_offset + 7],
        ]);

        // Unmask pointer (clear top byte for arm64e)
        let class_addr = class_addr & 0x0000_FFFF_FFFF_FFFF;

        if let Some(class_offset) = ctx.macho.addr_to_offset(class_addr) {
            fixed += fix_class_at(ctx, class_offset)?;
        }
    }

    Ok(fixed)
}

/// Fixes a single class's method lists.
fn fix_class_at(ctx: &mut ExtractionContext, class_offset: usize) -> Result<usize> {
    // objc_class structure:
    // +0:  isa (8 bytes)
    // +8:  superclass (8 bytes)
    // +16: cache (16 bytes)
    // +32: vtable (8 bytes)
    // +40: data (8 bytes) - points to class_ro_t or class_rw_t

    if class_offset + 48 > ctx.macho.data.len() {
        return Ok(0);
    }

    // Read data pointer (at offset 32 in the class)
    let data_addr = u64::from_le_bytes([
        ctx.macho.data[class_offset + 32],
        ctx.macho.data[class_offset + 33],
        ctx.macho.data[class_offset + 34],
        ctx.macho.data[class_offset + 35],
        ctx.macho.data[class_offset + 36],
        ctx.macho.data[class_offset + 37],
        ctx.macho.data[class_offset + 38],
        ctx.macho.data[class_offset + 39],
    ]);

    // Unmask and check low bits
    let data_addr = data_addr & 0x0000_FFFF_FFFF_FFF8; // Clear low 3 bits and top byte

    if let Some(data_offset) = ctx.macho.addr_to_offset(data_addr) {
        return fix_class_ro(ctx, data_offset);
    }

    Ok(0)
}

/// Fixes method lists in a class_ro_t structure.
fn fix_class_ro(ctx: &mut ExtractionContext, ro_offset: usize) -> Result<usize> {
    // class_ro_t structure (simplified):
    // +0:  flags (4 bytes)
    // +4:  instanceStart (4 bytes)
    // +8:  instanceSize (4 bytes)
    // +12: reserved (4 bytes) on 64-bit
    // +16: ivarLayout (8 bytes)
    // +24: name (8 bytes)
    // +32: baseMethods (8 bytes)
    // +40: baseProtocols (8 bytes)
    // +48: ivars (8 bytes)
    // +56: weakIvarLayout (8 bytes)
    // +64: baseProperties (8 bytes)

    if ro_offset + 72 > ctx.macho.data.len() {
        return Ok(0);
    }

    // Read baseMethods pointer
    let methods_addr = u64::from_le_bytes([
        ctx.macho.data[ro_offset + 32],
        ctx.macho.data[ro_offset + 33],
        ctx.macho.data[ro_offset + 34],
        ctx.macho.data[ro_offset + 35],
        ctx.macho.data[ro_offset + 36],
        ctx.macho.data[ro_offset + 37],
        ctx.macho.data[ro_offset + 38],
        ctx.macho.data[ro_offset + 39],
    ]);

    if methods_addr == 0 {
        return Ok(0);
    }

    let methods_addr = methods_addr & 0x0000_FFFF_FFFF_FFFF;

    if let Some(methods_offset) = ctx.macho.addr_to_offset(methods_addr) {
        return fix_method_list(ctx, methods_offset);
    }

    Ok(0)
}

/// Fixes method lists in all categories.
fn fix_category_method_lists(ctx: &mut ExtractionContext) -> Result<usize> {
    // Get __objc_catlist section
    let catlist = ctx
        .macho
        .section("__DATA", "__objc_catlist")
        .or_else(|| ctx.macho.section("__DATA_CONST", "__objc_catlist"));

    let catlist = match catlist {
        Some(s) => s.clone(),
        None => return Ok(0),
    };

    let count = catlist.section.size as usize / 8;
    let mut fixed = 0;

    for i in 0..count {
        let ptr_offset = catlist.section.offset as usize + i * 8;
        if ptr_offset + 8 > ctx.macho.data.len() {
            break;
        }

        // Read category pointer
        let cat_addr = u64::from_le_bytes([
            ctx.macho.data[ptr_offset],
            ctx.macho.data[ptr_offset + 1],
            ctx.macho.data[ptr_offset + 2],
            ctx.macho.data[ptr_offset + 3],
            ctx.macho.data[ptr_offset + 4],
            ctx.macho.data[ptr_offset + 5],
            ctx.macho.data[ptr_offset + 6],
            ctx.macho.data[ptr_offset + 7],
        ]);

        let cat_addr = cat_addr & 0x0000_FFFF_FFFF_FFFF;

        if let Some(cat_offset) = ctx.macho.addr_to_offset(cat_addr) {
            fixed += fix_category_at(ctx, cat_offset)?;
        }
    }

    Ok(fixed)
}

/// Fixes a single category's method lists.
fn fix_category_at(ctx: &mut ExtractionContext, cat_offset: usize) -> Result<usize> {
    // category_t structure:
    // +0:  name (8 bytes)
    // +8:  cls (8 bytes)
    // +16: instanceMethods (8 bytes)
    // +24: classMethods (8 bytes)
    // +32: protocols (8 bytes)
    // +40: instanceProperties (8 bytes)

    if cat_offset + 48 > ctx.macho.data.len() {
        return Ok(0);
    }

    let mut fixed = 0;

    // Fix instance methods
    let instance_methods = u64::from_le_bytes([
        ctx.macho.data[cat_offset + 16],
        ctx.macho.data[cat_offset + 17],
        ctx.macho.data[cat_offset + 18],
        ctx.macho.data[cat_offset + 19],
        ctx.macho.data[cat_offset + 20],
        ctx.macho.data[cat_offset + 21],
        ctx.macho.data[cat_offset + 22],
        ctx.macho.data[cat_offset + 23],
    ]);

    if instance_methods != 0 {
        let addr = instance_methods & 0x0000_FFFF_FFFF_FFFF;
        if let Some(offset) = ctx.macho.addr_to_offset(addr) {
            fixed += fix_method_list(ctx, offset)?;
        }
    }

    // Fix class methods
    let class_methods = u64::from_le_bytes([
        ctx.macho.data[cat_offset + 24],
        ctx.macho.data[cat_offset + 25],
        ctx.macho.data[cat_offset + 26],
        ctx.macho.data[cat_offset + 27],
        ctx.macho.data[cat_offset + 28],
        ctx.macho.data[cat_offset + 29],
        ctx.macho.data[cat_offset + 30],
        ctx.macho.data[cat_offset + 31],
    ]);

    if class_methods != 0 {
        let addr = class_methods & 0x0000_FFFF_FFFF_FFFF;
        if let Some(offset) = ctx.macho.addr_to_offset(addr) {
            fixed += fix_method_list(ctx, offset)?;
        }
    }

    Ok(fixed)
}

/// Fixes a method_list_t structure.
///
/// Clears the DIRECT_SEL and UNIQUED flags from the method list header.
fn fix_method_list(ctx: &mut ExtractionContext, offset: usize) -> Result<usize> {
    // method_list_t structure:
    // +0: entsize_and_flags (4 bytes) - contains size + flags in high bits
    // +4: count (4 bytes)
    // +8: methods[] - array of method entries

    if offset + 8 > ctx.macho.data.len() {
        return Ok(0);
    }

    // Read entsize_and_flags
    let entsize_and_flags = u32::from_le_bytes([
        ctx.macho.data[offset],
        ctx.macho.data[offset + 1],
        ctx.macho.data[offset + 2],
        ctx.macho.data[offset + 3],
    ]);

    // Check if method list has optimization flags that need clearing
    let has_direct_sel = (entsize_and_flags & METHOD_LIST_DIRECT_SEL_FLAG) != 0;
    let has_uniqued = (entsize_and_flags & METHOD_LIST_UNIQUED_FLAG) != 0;

    if !has_direct_sel && !has_uniqued {
        return Ok(0);
    }

    // Clear the direct selector and uniqued flags
    // Keep the relative flag if present, and preserve entry size
    let new_entsize_and_flags =
        entsize_and_flags & !(METHOD_LIST_DIRECT_SEL_FLAG | METHOD_LIST_UNIQUED_FLAG);

    ctx.macho.data[offset..offset + 4].copy_from_slice(&new_entsize_and_flags.to_le_bytes());

    Ok(1)
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flag_values() {
        assert_eq!(OBJC_IMAGE_IS_SIMULATED, 0x01);
        assert_eq!(OBJC_IMAGE_IS_REPLACEMENT, 0x02);
        assert_eq!(OBJC_IMAGE_SUPPORTS_GC, 0x04);
        assert_eq!(OBJC_IMAGE_OPTIMIZED_BY_DYLD, 0x08);
        assert_eq!(OBJC_IMAGE_SIGNED_CLASS_RO, 0x10);
    }

    #[test]
    fn test_method_list_flags() {
        assert_eq!(METHOD_LIST_RELATIVE_FLAG, 0x8000_0000);
        assert_eq!(METHOD_LIST_DIRECT_SEL_FLAG, 0x4000_0000);
        assert_eq!(METHOD_LIST_UNIQUED_FLAG, 0x2000_0000);
    }

    #[test]
    fn test_flag_clearing() {
        let original: u32 = 0x6000_0018; // DIRECT_SEL + UNIQUED + some size
        let expected: u32 = 0x0000_0018; // Just size
        let result = original & !(METHOD_LIST_DIRECT_SEL_FLAG | METHOD_LIST_UNIQUED_FLAG);
        assert_eq!(result, expected);
    }
}
