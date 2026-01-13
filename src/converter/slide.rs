//! Slide info processing for pointer rebasing.
//!
//! In the dyld shared cache, pointers contain encoded information for ASLR.
//! This module removes that encoding to produce normal pointers.
//!
//! There are multiple slide info versions:
//! - V2: Standard arm64 (non-PAC)
//! - V3: arm64e with pointer authentication
//! - V5: arm64e (iOS 18+, macOS 14.4+)
//!
//! # Performance
//!
//! Page processing is parallelized using rayon for significant speedup on
//! multi-core systems. Each page is independent and can be processed in parallel.

use std::sync::Arc;

use rayon::prelude::*;
use tracing::{debug, trace};

use crate::dyld::*;
use crate::error::{Error, Result};
use crate::macho::MachOContext;

use super::ExtractionContext;

/// A single write operation to be applied to the Mach-O buffer.
/// Collected during parallel processing, applied sequentially.
#[derive(Clone, Copy)]
struct WriteOp {
    offset: usize,
    value: u64,
}

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

        // Read version (optimized: single unaligned load)
        let version = crate::util::read_u32_le(&cache_data[slide_offset..]);

        debug!(
            "Processing slide info v{} for mapping at {:#x}",
            version, mapping.address
        );

        match version {
            2 => process_slide_info_v2(&mut ctx.macho, cache_data, slide_offset, &mapping)?,
            3 => process_slide_info_v3(&mut ctx.macho, cache_data, slide_offset, &mapping)?,
            5 => process_slide_info_v5(&mut ctx.macho, &cache, cache_data, slide_offset, &mapping)?,
            _ => {
                return Err(Error::UnsupportedSlideVersion(version));
            }
        }
    }

    Ok(())
}

/// Processes slide info version 2 (standard arm64 and x86_64).
///
/// For x86_64: Pointers are already in offset format with embedded delta chain.
/// The extracted binary keeps this format - no rebasing needed.
///
/// For arm64 (non-PAC): Pointers need rebasing by adding value_add.
///
/// # Performance
///
/// Pages are processed in parallel using rayon. Each page's write operations
/// are collected independently, then applied in a single pass.
fn process_slide_info_v2(
    macho: &mut MachOContext,
    cache_data: &[u8],
    offset: usize,
    mapping: &SlideMapping,
) -> Result<()> {
    use zerocopy::FromBytes;

    // For x86_64, pointers are already in the correct format (offset + delta).
    // The extracted binary keeps this format for dyld to process at load time.
    // No rebasing transformation is needed.
    if macho.header.is_x86_64() {
        debug!("Slide v2: skipping rebasing for x86_64 (pointers already in offset format)");
        return Ok(());
    }

    let slide_info = DyldCacheSlideInfo2::read_from_prefix(&cache_data[offset..])
        .map_err(|_| Error::InvalidSlideInfo {
            offset: offset as u64,
            reason: "failed to parse slide info v2".into(),
        })?
        .0;

    let page_size = slide_info.page_size as u64;
    let page_starts_offset = offset + slide_info.page_starts_offset as usize;
    let page_count = slide_info.page_starts_count as usize;

    let delta_mask = slide_info.delta_mask;
    let value_mask = slide_info.value_mask();
    let value_add = slide_info.value_add;
    let delta_shift = slide_info.delta_shift();

    debug!(
        "Slide v2: delta_mask={:#018x}, value_mask={:#018x}, value_add={:#018x}, delta_shift={}, pages={}",
        delta_mask, value_mask, value_add, delta_shift, page_count
    );

    // Collect page info for parallel processing
    // Uses optimized u16 reads for better performance
    let page_infos: Vec<_> = (0..page_count)
        .filter_map(|page_idx| {
            let page_start_offset = page_starts_offset + page_idx * 2;
            if page_start_offset + 2 > cache_data.len() {
                return None;
            }
            let page_start = crate::util::read_u16_le(&cache_data[page_start_offset..]);

            // Skip pages with no rebasing needed
            if page_start == (DYLD_CACHE_SLIDE_PAGE_ATTR_NO_REBASE & 0xFFFF) as u16 {
                return None;
            }

            let page_addr = mapping.address + (page_idx as u64 * page_size);
            let start_offset = (page_start as u64) * 4; // 32-bit jumps
            Some((page_addr + start_offset, page_idx))
        })
        .collect();

    // Process pages in parallel, collecting write operations
    let macho_data: &[u8] = &macho.data;
    let all_writes: Vec<Vec<WriteOp>> = page_infos
        .par_iter()
        .map(|&(start_addr, _page_idx)| {
            collect_v2_page_writes(
                macho_data,
                macho,
                start_addr,
                delta_mask,
                value_mask,
                value_add,
                delta_shift,
            )
        })
        .collect();

    // Apply all writes (sequential, but the heavy computation was parallel)
    for writes in all_writes {
        for op in writes {
            macho.data[op.offset..op.offset + 8].copy_from_slice(&op.value.to_le_bytes());
        }
    }

    Ok(())
}

/// Collects write operations for a v2 page without modifying the buffer.
///
/// # Performance
///
/// Uses optimized u64 reads that compile to single unaligned load instructions.
#[inline]
fn collect_v2_page_writes(
    data: &[u8],
    macho: &MachOContext,
    mut addr: u64,
    delta_mask: u64,
    value_mask: u64,
    value_add: u64,
    delta_shift: u32,
) -> Vec<WriteOp> {
    let mut writes = Vec::with_capacity(64); // Pre-allocate for typical page

    loop {
        let macho_offset = match macho.addr_to_offset(addr) {
            Some(off) => off,
            None => {
                trace!("Address {:#x} not in Mach-O, skipping", addr);
                break;
            }
        };

        if macho_offset + 8 > data.len() {
            break;
        }

        // Optimized: single unaligned load instead of byte-by-byte
        let raw_value = crate::util::read_u64_le(&data[macho_offset..]);

        let delta = ((raw_value & delta_mask) >> delta_shift) as u64;

        // Calculate new value: mask out delta bits and add base address
        let mut new_value = raw_value & value_mask;
        if new_value != 0 {
            new_value += value_add;
        }

        writes.push(WriteOp {
            offset: macho_offset,
            value: new_value,
        });

        if delta == 0 {
            break;
        }
        // Delta is in 4-byte units for v2
        addr += delta * 4;
    }

    writes
}

// Note: rebase_v2_page removed - replaced by parallel collect_v2_page_writes

/// Processes slide info version 3 (arm64e with PAC).
///
/// # Performance
///
/// Pages are processed in parallel using rayon.
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
    let page_count = slide_info.page_starts_count as usize;

    // Page starts immediately follow the header
    let page_starts_offset = offset + std::mem::size_of::<DyldCacheSlideInfo3>();

    debug!(
        "Slide v3: auth_value_add={:#018x}, pages={}",
        auth_value_add, page_count
    );

    // Collect page info for parallel processing (optimized u16 reads)
    let page_infos: Vec<_> = (0..page_count)
        .filter_map(|page_idx| {
            let page_start_offset = page_starts_offset + page_idx * 2;
            if page_start_offset + 2 > cache_data.len() {
                return None;
            }
            let page_start = crate::util::read_u16_le(&cache_data[page_start_offset..]);

            // Skip pages with no rebasing
            if page_start == DYLD_CACHE_SLIDE_V3_PAGE_ATTR_NO_REBASE {
                return None;
            }

            let page_addr = mapping.address + (page_idx as u64 * page_size);
            let initial_offset = (page_start as u64) * 8; // 8-byte stride
            Some(page_addr + initial_offset)
        })
        .collect();

    // Process pages in parallel
    let macho_data: &[u8] = &macho.data;
    let all_writes: Vec<Vec<WriteOp>> = page_infos
        .par_iter()
        .map(|&start_addr| collect_v3_page_writes(macho_data, macho, start_addr, auth_value_add))
        .collect();

    // Apply all writes
    for writes in all_writes {
        for op in writes {
            macho.data[op.offset..op.offset + 8].copy_from_slice(&op.value.to_le_bytes());
        }
    }

    Ok(())
}

/// Collects write operations for a v3 page without modifying the buffer.
///
/// # Performance
///
/// Uses optimized u64 reads that compile to single unaligned load instructions.
#[inline]
fn collect_v3_page_writes(
    data: &[u8],
    macho: &MachOContext,
    mut addr: u64,
    auth_value_add: u64,
) -> Vec<WriteOp> {
    let mut writes = Vec::with_capacity(64);

    loop {
        let macho_offset = match macho.addr_to_offset(addr) {
            Some(off) => off,
            None => {
                trace!("Address {:#x} not in Mach-O, skipping", addr);
                break;
            }
        };

        if macho_offset + 8 > data.len() {
            break;
        }

        // Optimized: single unaligned load
        let raw_value = crate::util::read_u64_le(&data[macho_offset..]);

        let ptr = SlidePointer3(raw_value);
        let delta = ptr.offset_to_next() * 8;

        let new_value = if ptr.is_auth() {
            // Authenticated pointer
            ptr.auth_offset() as u64 + auth_value_add
        } else {
            // Plain pointer with packed high bits
            ptr.plain_value()
        };

        writes.push(WriteOp {
            offset: macho_offset,
            value: new_value,
        });

        if delta == 0 {
            break;
        }
        addr += delta;
    }

    writes
}

// Note: rebase_v3_page removed - replaced by parallel collect_v3_page_writes

/// Processes slide info version 5 (arm64e iOS 18+).
///
/// # Performance
///
/// Pages are processed in parallel using rayon.
fn process_slide_info_v5(
    macho: &mut MachOContext,
    cache: &Arc<DyldContext>,
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
    let page_count = slide_info.page_starts_count as usize;

    // Page starts immediately follow the header
    let page_starts_offset = offset + std::mem::size_of::<DyldCacheSlideInfo5>();

    debug!(
        "Slide v5: value_add={:#018x}, pages={}",
        value_add, page_count
    );

    // Collect page info for parallel processing (optimized u16 reads)
    let page_infos: Vec<_> = (0..page_count)
        .filter_map(|page_idx| {
            let page_start_offset = page_starts_offset + page_idx * 2;
            if page_start_offset + 2 > cache_data.len() {
                return None;
            }
            let page_start = crate::util::read_u16_le(&cache_data[page_start_offset..]);

            // Skip pages with no rebasing
            if page_start == DYLD_CACHE_SLIDE_V5_PAGE_ATTR_NO_REBASE {
                return None;
            }

            let page_addr = mapping.address + (page_idx as u64 * page_size);
            let initial_offset = (page_start as u64) * 8;
            Some(page_addr + initial_offset)
        })
        .collect();

    // Process pages in parallel
    // We need the cache (to follow delta chains through other images' regions)
    // and macho (to write rebased values)
    let all_writes: Vec<Vec<WriteOp>> = page_infos
        .par_iter()
        .map(|&start_addr| collect_v5_page_writes(cache, macho, start_addr, value_add))
        .collect();

    // Apply all writes
    for writes in all_writes {
        for op in writes {
            macho.data[op.offset..op.offset + 8].copy_from_slice(&op.value.to_le_bytes());
        }
    }

    Ok(())
}

/// Collects write operations for a v5 page without modifying the buffer.
///
/// IMPORTANT: We read the delta chain from the cache (which covers all images),
/// but only generate WriteOps for addresses that are in our macho's segments.
/// This handles the case where a page contains data from multiple images - we follow
/// the delta chain through other images' data to find our pointers.
#[inline]
fn collect_v5_page_writes(
    cache: &Arc<DyldContext>,
    macho: &MachOContext,
    mut addr: u64,
    value_add: u64,
) -> Vec<WriteOp> {
    let mut writes = Vec::with_capacity(64);

    loop {
        // First check if this address is in our macho
        let macho_offset = macho.addr_to_offset(addr);

        // Read the raw value from the cache to follow the delta chain
        // This works even for addresses not in our macho (other images' data)
        let raw_value = match cache.data_at_addr(addr, 8) {
            Ok(data) => u64::from_le_bytes(data.try_into().unwrap()),
            Err(_) => {
                break;
            }
        };

        let ptr = SlidePointer5(raw_value);
        let delta = ptr.next() * 8;

        // Only write if this address is in our macho
        if let Some(macho_off) = macho_offset {
            let new_value = if ptr.is_auth() {
                // Authenticated pointer
                ptr.runtime_offset() + value_add
            } else {
                // Regular pointer with high8
                let runtime_offset = ptr.runtime_offset();
                let high8 = (ptr.high8() as u64) << 56;
                runtime_offset + value_add + high8
            };

            writes.push(WriteOp {
                offset: macho_off,
                value: new_value,
            });
        }

        if delta == 0 {
            break;
        }
        addr += delta;
    }

    writes
}
