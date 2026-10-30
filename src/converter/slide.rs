//! Decode slide chains from the source cache, including portions belonging to
//! neighboring images on the same page. Only file-backed output slots are written.
use super::ExtractionContext;
use crate::dyld::{MappingEntry, decode_slide_pointer};
use crate::util::{read_u32_le, read_u64_le};
use crate::{Error, Result};
use std::collections::BTreeSet;

/// Processes v1 bitmaps and removes v2/v3/v4/v5 slide encoding from image pointers.
/// Each chain is bounded by its source page; malformed tables fail explicitly.
pub fn process_slide_info(ctx: &mut ExtractionContext) -> Result<()> {
    let cache = std::sync::Arc::clone(&ctx.cache);
    for mapping in cache.mappings.iter().filter(|m| m.has_slide_info()) {
        let data = cache.data_for_subcache(mapping.subcache_index);
        let off = usize::try_from(mapping.slide_info_offset)
            .map_err(|_| invalid(mapping, "slide offset overflow"))?;
        let end = off
            .checked_add(mapping.slide_info_size as usize)
            .filter(|e| *e <= data.len())
            .ok_or_else(|| invalid(mapping, "slide table outside file"))?;
        let slide = &data[off..end];
        if slide.len() < 24 {
            return Err(invalid(mapping, "truncated slide header"));
        }
        let version = read_u32_le(slide);
        if version == 1 {
            process_bitmap(ctx, mapping, slide)?;
            continue;
        }
        let width = ctx.macho.pointer_size() as u64;
        let page_size = read_u32_le(&slide[4..]) as u64;
        if page_size != 4096 && page_size != 16384 {
            return Err(invalid(mapping, "unsupported slide page size"));
        }
        let (count, starts, extras, extras_count, mask, _base) = match version {
            2 | 4 if slide.len() >= 40 => (
                read_u32_le(&slide[12..]) as usize,
                read_u32_le(&slide[8..]) as usize,
                read_u32_le(&slide[16..]) as usize,
                read_u32_le(&slide[20..]) as usize,
                read_u64_le(&slide[24..]),
                read_u64_le(&slide[32..]),
            ),
            3 | 5 => (
                read_u32_le(&slide[8..]) as usize,
                24,
                0,
                0,
                0,
                read_u64_le(&slide[16..]),
            ),
            _ => {
                return Err(invalid(
                    mapping,
                    &format!("unsupported slide version {version}"),
                ));
            }
        };
        let starts_data = table(slide, starts, count)
            .ok_or_else(|| invalid(mapping, "page starts outside slide table"))?;
        let extras_data = if extras_count == 0 {
            &[][..]
        } else {
            table(slide, extras, extras_count)
                .ok_or_else(|| invalid(mapping, "page extras outside slide table"))?
        };
        if matches!(version, 2 | 4) && (mask == 0 || mask.trailing_zeros() < 2) {
            return Err(invalid(mapping, "invalid v2 delta mask"));
        }
        // Examine only pages intersecting file-backed image segments. A chain
        // can begin in a neighboring image, so traversal still starts at the
        // page's recorded chain head and reads the unmodified cache bytes.
        let mut pages = BTreeSet::new();
        for seg in ctx.macho.segments() {
            let start = seg.command.vmaddr.max(mapping.address);
            let end =
                (seg.command.vmaddr + seg.command.filesize).min(mapping.address + mapping.size);
            if start < end {
                for page in
                    (start - mapping.address) / page_size..=(end - 1 - mapping.address) / page_size
                {
                    if page >= count as u64 {
                        return Err(invalid(mapping, "mapping page missing from slide table"));
                    }
                    pages.insert(page as usize);
                }
            }
        }
        for page in pages {
            let value = u16::from_le_bytes(starts_data[page * 2..page * 2 + 2].try_into().unwrap());
            let mut heads = Vec::new();
            if matches!(version, 2 | 4) {
                if value == if version == 4 { 0xffff } else { 0x4000 } {
                    continue;
                }
                if value & 0x8000 != 0 {
                    let mut index = (value & if version == 4 { 0x7fff } else { 0x3fff }) as usize;
                    loop {
                        let b = extras_data
                            .get(index * 2..index * 2 + 2)
                            .ok_or_else(|| invalid(mapping, "unterminated v2 page extras"))?;
                        let entry = u16::from_le_bytes(b.try_into().unwrap());
                        heads.push((entry & if version == 4 { 0x7fff } else { 0x3fff }) as u64 * 4);
                        if entry & 0x8000 != 0 {
                            break;
                        }
                        index += 1;
                    }
                } else {
                    heads.push(value as u64 * 4);
                }
            } else {
                if value == 0xffff {
                    continue;
                }
                heads.push(value as u64);
            }
            let page_start = mapping.address + page as u64 * page_size;
            let page_end = (page_start + page_size).min(mapping.address + mapping.size);
            for start in heads {
                let mut addr = page_start + start;
                loop {
                    if addr.checked_add(width).is_none_or(|end| end > page_end)
                        || (addr - page_start) % 4 != 0
                    {
                        return Err(invalid(mapping, "slide chain leaves page or is unaligned"));
                    }
                    let raw = if width == 4 {
                        read_u32_le(cache.data_at_addr(addr, 4)?) as u64
                    } else {
                        read_u64_le(cache.data_at_addr(addr, 8)?)
                    };
                    let (value, delta) = decode_slide_pointer(slide, raw, width as usize)?;
                    if let Some(offset) = ctx.macho.addr_to_offset(addr) {
                        if ctx.macho.addr_to_offset(addr + width - 1)
                            == Some(offset + width as usize - 1)
                        {
                            ctx.macho.write_pointer(offset, value)?;
                        }
                    }
                    if delta == 0 {
                        break;
                    }
                    addr = addr
                        .checked_add(delta)
                        .ok_or_else(|| invalid(mapping, "slide chain address overflow"))?;
                }
            }
        }
    }
    Ok(())
}

fn table(data: &[u8], offset: usize, count: usize) -> Option<&[u8]> {
    data.get(offset..offset.checked_add(count.checked_mul(2)?)?)
}
fn invalid(mapping: &MappingEntry, reason: &str) -> Error {
    Error::InvalidSlideInfo {
        offset: mapping.slide_info_offset,
        reason: reason.into(),
    }
}

// v1 stores one 128-byte bitmap per 4096-byte data page. Each bit denotes
// a 4-byte slot. There is no chain encoding to strip at slide zero.
fn process_bitmap(ctx: &mut ExtractionContext, mapping: &MappingEntry, slide: &[u8]) -> Result<()> {
    if slide.len() < 24 || ctx.macho.pointer_size() != 4 {
        return Err(invalid(mapping, "invalid v1 slide header or pointer width"));
    }
    let toc_offset = read_u32_le(&slide[4..]) as usize;
    let toc_count = read_u32_le(&slide[8..]) as usize;
    let entries_offset = read_u32_le(&slide[12..]) as usize;
    let entries_count = read_u32_le(&slide[16..]) as usize;
    let entry_size = read_u32_le(&slide[20..]) as usize;
    if entry_size != 128
        || table(slide, toc_offset, toc_count).is_none()
        || entries_count
            .checked_mul(entry_size)
            .and_then(|n| entries_offset.checked_add(n))
            .is_none_or(|end| end > slide.len())
    {
        return Err(invalid(mapping, "invalid v1 slide bitmap extent"));
    }
    for segment in ctx.macho.segments() {
        let start = segment.command.vmaddr.max(mapping.address);
        let end =
            (segment.command.vmaddr + segment.command.filesize).min(mapping.address + mapping.size);
        if start >= end {
            continue;
        }
        for page in (start - mapping.address) / 4096..=(end - 1 - mapping.address) / 4096 {
            if page >= toc_count as u64 {
                return Err(invalid(mapping, "v1 page missing from table"));
            }
            let pos = toc_offset + page as usize * 2;
            let entry = u16::from_le_bytes(slide[pos..pos + 2].try_into().unwrap()) as usize;
            if entry >= entries_count {
                return Err(invalid(mapping, "v1 bitmap index out of bounds"));
            }
        }
    }
    Ok(())
}
