//! Slide info processing for pointer rebasing.
//!
//! In the dyld shared cache, pointers contain encoded information for ASLR.
//! This module removes that encoding to produce normal pointers.
//!
//! There are multiple slide info versions:
//! - V2: Standard arm64 (non-PAC)
//! - V3: arm64e with pointer authentication
//! - V5: arm64e (iOS 18+, macOS 14.4+)

use std::sync::Arc;

use tracing::{debug, trace};

use crate::dyld::*;
use crate::error::{Error, Result};
use crate::macho::MachOContext;

use super::ExtractionContext;

/// Mapping info needed for slide processing.
#[derive(Clone)]
struct SlideMapping {
    address: u64,
    #[allow(dead_code)]
    size: u64,
    slide_info_offset: u64,
    #[allow(dead_code)]
    slide_info_size: u64,
    subcache_index: usize,
}

/// Processes slide info for all mappings that overlap with the image.
pub fn process_slide_info(ctx: &mut ExtractionContext) -> Result<()> {
    ctx.info("Processing slide info...");

    // Clone the Arc to avoid borrow conflicts - this is cheap (just ref count bump)
    let cache = Arc::clone(&ctx.cache);

    // Collect mapping info we need
    let mappings: Vec<SlideMapping> = cache
        .mappings
        .iter()
        .filter(|m| m.has_slide_info())
        .filter(|mapping| {
            // Check if this mapping overlaps with any of our segments
            ctx.macho.segments().any(|seg| {
                let seg_start = seg.command.vmaddr;
                let seg_end = seg_start + seg.command.vmsize;
                let map_start = mapping.address;
                let map_end = map_start + mapping.size;
                seg_start < map_end && seg_end > map_start
            })
        })
        .map(|m| SlideMapping {
            address: m.address,
            size: m.size,
            slide_info_offset: m.slide_info_offset,
            slide_info_size: m.slide_info_size,
            subcache_index: m.subcache_index,
        })
        .collect();

    for mapping in mappings {
        // Get slide info data from the appropriate subcache
        let cache_data = cache.data_for_subcache(mapping.subcache_index);
        let slide_offset = mapping.slide_info_offset as usize;

        if slide_offset + 4 > cache_data.len() {
            ctx.warn(&format!(
                "Slide info at offset {:#x} is out of bounds",
                slide_offset
            ));
            continue;
        }

        // Read version
        let version = u32::from_le_bytes([
            cache_data[slide_offset],
            cache_data[slide_offset + 1],
            cache_data[slide_offset + 2],
            cache_data[slide_offset + 3],
        ]);

        debug!(
            "Processing slide info v{} for mapping at {:#x}",
            version, mapping.address
        );

        match version {
            2 => process_slide_info_v2(&mut ctx.macho, cache_data, slide_offset, &mapping)?,
            3 => process_slide_info_v3(&mut ctx.macho, cache_data, slide_offset, &mapping)?,
            5 => process_slide_info_v5(&mut ctx.macho, cache_data, slide_offset, &mapping)?,
            _ => {
                return Err(Error::UnsupportedSlideVersion(version));
            }
        }
    }

    Ok(())
}

/// Processes slide info version 2 (standard arm64).
fn process_slide_info_v2(
    macho: &mut MachOContext,
    cache_data: &[u8],
    offset: usize,
    mapping: &SlideMapping,
) -> Result<()> {
    use zerocopy::FromBytes;

    let slide_info = DyldCacheSlideInfo2::read_from_prefix(&cache_data[offset..])
        .map_err(|_| Error::InvalidSlideInfo {
            offset: offset as u64,
            reason: "failed to parse slide info v2".into(),
        })?
        .0;

    let page_size = slide_info.page_size as u64;
    let page_starts_offset = offset + slide_info.page_starts_offset as usize;

    let delta_mask = slide_info.delta_mask;
    let value_mask = slide_info.value_mask();
    let value_add = slide_info.value_add;
    let delta_shift = slide_info.delta_shift();

    // Process each page
    for page_idx in 0..slide_info.page_starts_count as usize {
        let page_start_offset = page_starts_offset + page_idx * 2;
        let page_start = u16::from_le_bytes([
            cache_data[page_start_offset],
            cache_data[page_start_offset + 1],
        ]);

        // Skip pages with no rebasing needed
        if page_start == (DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE & 0xFFFF) as u16 {
            continue;
        }

        let page_addr = mapping.address + (page_idx as u64 * page_size);

        // Normal page processing
        let start_offset = (page_start as u64) * 4; // 32-bit jumps
        rebase_v2_page(
            macho,
            page_addr + start_offset,
            delta_mask,
            value_mask,
            value_add,
            delta_shift,
        )?;
    }

    Ok(())
}

/// Rebases a single v2 page.
fn rebase_v2_page(
    macho: &mut MachOContext,
    mut addr: u64,
    delta_mask: u64,
    value_mask: u64,
    value_add: u64,
    delta_shift: u32,
) -> Result<()> {
    loop {
        // Try to convert address to Mach-O offset
        let macho_offset = match macho.addr_to_offset(addr) {
            Some(off) => off,
            None => {
                trace!("Address {:#x} not in Mach-O, skipping", addr);
                break;
            }
        };

        let raw_value = macho.read_u64(macho_offset)?;
        let delta = ((raw_value & delta_mask) >> delta_shift) as u64;

        // Calculate new value
        let mut new_value = raw_value & value_mask;
        if new_value != 0 {
            new_value += value_add;
        }

        // Write back
        macho.write_u64(macho_offset, new_value)?;

        if delta == 0 {
            break;
        }
        addr += delta;
    }

    Ok(())
}

/// Processes slide info version 3 (arm64e with PAC).
fn process_slide_info_v3(
    macho: &mut MachOContext,
    cache_data: &[u8],
    offset: usize,
    mapping: &SlideMapping,
) -> Result<()> {
    use zerocopy::FromBytes;

    let slide_info = DyldCacheSlideInfo3::read_from_prefix(&cache_data[offset..])
        .map_err(|_| Error::InvalidSlideInfo {
            offset: offset as u64,
            reason: "failed to parse slide info v3".into(),
        })?
        .0;

    let page_size = slide_info.page_size as u64;
    let auth_value_add = slide_info.auth_value_add;

    // Page starts immediately follow the header
    let page_starts_offset = offset + std::mem::size_of::<DyldCacheSlideInfo3>();

    for page_idx in 0..slide_info.page_starts_count as usize {
        let page_start_offset = page_starts_offset + page_idx * 2;
        let page_start = u16::from_le_bytes([
            cache_data[page_start_offset],
            cache_data[page_start_offset + 1],
        ]);

        // Skip pages with no rebasing
        if page_start == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE {
            continue;
        }

        let page_addr = mapping.address + (page_idx as u64 * page_size);
        let initial_offset = (page_start as u64) * 8; // 8-byte stride

        rebase_v3_page(macho, page_addr + initial_offset, auth_value_add)?;
    }

    Ok(())
}

/// Rebases a single v3 page.
fn rebase_v3_page(macho: &mut MachOContext, mut addr: u64, auth_value_add: u64) -> Result<()> {
    loop {
        let macho_offset = match macho.addr_to_offset(addr) {
            Some(off) => off,
            None => {
                trace!("Address {:#x} not in Mach-O, skipping", addr);
                break;
            }
        };

        let raw_value = macho.read_u64(macho_offset)?;
        let ptr = SlidePointer3(raw_value);
        let delta = ptr.offset_to_next() * 8;

        let new_value = if ptr.is_auth() {
            // Authenticated pointer
            ptr.auth_offset() as u64 + auth_value_add
        } else {
            // Plain pointer with packed high bits
            ptr.plain_value()
        };

        macho.write_u64(macho_offset, new_value)?;

        if delta == 0 {
            break;
        }
        addr += delta;
    }

    Ok(())
}

/// Processes slide info version 5 (arm64e iOS 18+).
fn process_slide_info_v5(
    macho: &mut MachOContext,
    cache_data: &[u8],
    offset: usize,
    mapping: &SlideMapping,
) -> Result<()> {
    use zerocopy::FromBytes;

    let slide_info = DyldCacheSlideInfo5::read_from_prefix(&cache_data[offset..])
        .map_err(|_| Error::InvalidSlideInfo {
            offset: offset as u64,
            reason: "failed to parse slide info v5".into(),
        })?
        .0;

    let page_size = slide_info.page_size as u64;
    let value_add = slide_info.value_add;

    // Page starts immediately follow the header
    let page_starts_offset = offset + std::mem::size_of::<DyldCacheSlideInfo5>();

    for page_idx in 0..slide_info.page_starts_count as usize {
        let page_start_offset = page_starts_offset + page_idx * 2;
        let page_start = u16::from_le_bytes([
            cache_data[page_start_offset],
            cache_data[page_start_offset + 1],
        ]);

        // Skip pages with no rebasing
        if page_start == DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE {
            continue;
        }

        let page_addr = mapping.address + (page_idx as u64 * page_size);
        let initial_offset = (page_start as u64) * 8;

        rebase_v5_page(macho, page_addr + initial_offset, value_add)?;
    }

    Ok(())
}

/// Rebases a single v5 page.
fn rebase_v5_page(macho: &mut MachOContext, mut addr: u64, value_add: u64) -> Result<()> {
    loop {
        let macho_offset = match macho.addr_to_offset(addr) {
            Some(off) => off,
            None => {
                trace!("Address {:#x} not in Mach-O, skipping", addr);
                break;
            }
        };

        let raw_value = macho.read_u64(macho_offset)?;
        let ptr = SlidePointer5(raw_value);
        let delta = ptr.next() * 8;

        let new_value = if ptr.is_auth() {
            // Authenticated pointer
            ptr.runtime_offset() + value_add
        } else {
            // Regular pointer with high8
            let runtime_offset = ptr.runtime_offset();
            let high8 = (ptr.high8() as u64) << 56;
            runtime_offset + value_add + high8
        };

        macho.write_u64(macho_offset, new_value)?;

        if delta == 0 {
            break;
        }
        addr += delta;
    }

    Ok(())
}
