//! Decode slide chains from the source cache, including portions belonging to
//! neighboring images on the same page. Only file-backed output slots are written.
use super::ExtractionContext;
use crate::dyld::{MappingEntry, SlidePointer3, SlidePointer5};
use crate::util::{read_u32_le, read_u64_le};
use crate::{Error, Result};
use std::collections::BTreeSet;

/// Removes v2/v3/v5 slide encoding from image pointers (including x86_64 v2).
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
        let page_size = read_u32_le(&slide[4..]) as u64;
        if page_size != 4096 && page_size != 16384 {
            return Err(invalid(mapping, "unsupported slide page size"));
        }
        let (count, starts, extras, extras_count, mask, base) = match version {
            2 if slide.len() >= 40 => (
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
        if version == 2 && (mask == 0 || mask.trailing_zeros() < 2) {
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
            if version == 2 {
                if value == 0x4000 {
                    continue;
                }
                if value & 0x8000 != 0 {
                    let mut index = (value & 0x3fff) as usize;
                    loop {
                        let b = extras_data
                            .get(index * 2..index * 2 + 2)
                            .ok_or_else(|| invalid(mapping, "unterminated v2 page extras"))?;
                        let entry = u16::from_le_bytes(b.try_into().unwrap());
                        heads.push((entry & 0x3fff) as u64 * 4);
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
                    if addr.checked_add(8).is_none_or(|end| end > page_end) {
                        return Err(invalid(mapping, "slide chain leaves page"));
                    }
                    let raw = read_u64_le(cache.data_at_addr(addr, 8)?);
                    let (value, delta) = match version {
                        2 => {
                            let raw_value = raw & !mask;
                            let value = if raw_value == 0 {
                                0
                            } else {
                                raw_value
                                    .checked_add(base)
                                    .ok_or_else(|| invalid(mapping, "v2 pointer overflow"))?
                            };
                            (value, ((raw & mask) >> mask.trailing_zeros()) * 4)
                        }
                        3 => {
                            let p = SlidePointer3(raw);
                            let value = if p.is_auth() {
                                base.checked_add(p.auth_offset() as u64)
                                    .ok_or_else(|| invalid(mapping, "v3 pointer overflow"))?
                            } else {
                                p.plain_value()
                            };
                            (value, p.offset_to_next() * 8)
                        }
                        5 => {
                            let p = SlidePointer5(raw);
                            let mut value = base
                                .checked_add(p.runtime_offset())
                                .ok_or_else(|| invalid(mapping, "v5 pointer overflow"))?;
                            if !p.is_auth() {
                                value |= (p.high8() as u64) << 56;
                            }
                            (value, p.next() * 8)
                        }
                        _ => unreachable!(),
                    };
                    if let Some(offset) = ctx.macho.addr_to_offset(addr) {
                        if ctx.macho.addr_to_offset(addr + 7) == Some(offset + 7) {
                            ctx.macho.write_u64(offset, value)?;
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
