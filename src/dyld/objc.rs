//! Cache-wide Objective-C metadata. All modern offsets are relative to the
//! main cache header's VM address, even when the tables reside in a subcache.

use super::{DyldCacheHeader, DyldContext, SlidePointer3, SlidePointer5};
use crate::error::{Error, Result};
use crate::macho::{MH_MAGIC, MachOContext};
use crate::util::{read_u32_le, read_u64_le};
use std::mem::offset_of;

/// Resolved Objective-C optimization metadata (unslid virtual addresses).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObjcOptimization {
    /// Optimization header version (16 for the legacy objc_opt_t fallback).
    pub version: u32,
    /// Virtual address of the optimization header.
    pub address: u64,
    /// Global base for direct relative selectors and base-relative types.
    pub selector_base: u64,
    /// Selector buffer size in bytes; absent before version 2.
    pub selector_size: Option<u64>,
    /// Type buffer size in bytes; starts after the selector buffer.
    pub types_size: Option<u64>,
}

impl DyldContext {
    /// Pointer width of images in this cache, in bytes (arm64_32 uses 4).
    pub fn pointer_size(&self) -> usize {
        let arch = self.architecture();
        if arch == "arm64_32" || (!arch.starts_with("arm64") && !arch.starts_with("x86_64")) {
            4
        } else {
            8
        }
    }

    /// Reads an image's header and commands without copying its segments.
    pub fn image_header(&self, address: u64) -> Result<MachOContext> {
        let header = self.data_at_addr(address, 28)?;
        let header_size = if read_u32_le(header) == MH_MAGIC {
            28
        } else {
            32
        };
        let size = header_size + read_u32_le(&header[20..]) as usize;
        MachOContext::new(self.data_at_addr(address, size)?, 0)
    }

    /// Returns the VM address corresponding to file offset zero in the main cache.
    pub fn header_address(&self) -> Result<u64> {
        self.mappings
            .iter()
            .find(|m| m.subcache_index == 0 && m.file_offset == 0)
            .map(|m| m.address)
            .ok_or(Error::Parse {
                offset: 0,
                reason: "cache header is not mapped".into(),
            })
    }

    /// Resolves modern v1/v2 objcOpts, or the older libobjc __objc_opt_ro header.
    /// Later versions retain the IDA-verified common prefix; version-specific
    /// buffer extents remain unknown unless their layout is established.
    pub fn objc_optimization(&self) -> Result<Option<ObjcOptimization>> {
        let h = &self.header;
        if h.contains_field_range(offset_of!(DyldCacheHeader, objc_opts_size), 8)
            && h.objc_opts_offset != 0
        {
            let base = self.header_address()?;
            let addr = checked_address(base, h.objc_opts_offset)?;
            if h.objc_opts_size < 56 {
                return Err(Error::Parse {
                    offset: 0,
                    reason: "truncated ObjC optimization header".into(),
                });
            }
            let data = self.data_at_addr(addr, 56)?;
            let version = read_u32_le(data);
            let offset = read_u64_le(&data[48..]);
            if offset == 0 {
                return Ok(None);
            }
            let mut opts = ObjcOptimization {
                version,
                address: addr,
                selector_base: checked_address(base, offset)?,
                selector_size: None,
                types_size: None,
            };
            if version == 2 {
                if h.objc_opts_size < 72 {
                    return Err(Error::Parse {
                        offset: 0,
                        reason: "truncated ObjC v2 optimization header".into(),
                    });
                }
                let data = self.data_at_addr(addr, 72)?;
                let selectors = read_u64_le(&data[56..]);
                let types = read_u64_le(&data[64..]);
                checked_address(checked_address(opts.selector_base, selectors)?, types)?;
                opts.selector_size = Some(selectors);
                opts.types_size = Some(types);
            }
            return Ok(Some(opts));
        }
        // objc_opt_t v16 has a signed self-relative base.
        if let Some(image) = self
            .images
            .iter()
            .find(|i| i.path == "/usr/lib/libobjc.A.dylib")
        {
            let macho = self.image_header(image.address)?;
            if let Some(section) = macho.section("__TEXT", "__objc_opt_ro") {
                if section.section.size < 48 {
                    return Ok(None);
                }
                let data = self.data_at_addr(section.section.addr, 48)?;
                let version = read_u32_le(data);
                if version >= 16 {
                    let base = section
                        .section
                        .addr
                        .checked_add_signed(read_u64_le(&data[40..]) as i64)
                        .ok_or(Error::Parse {
                            offset: 40,
                            reason: "legacy selector base overflow".into(),
                        })?;
                    return Ok(Some(ObjcOptimization {
                        version,
                        address: section.section.addr,
                        selector_base: base,
                        selector_size: None,
                        types_size: None,
                    }));
                }
            }
        }
        Ok(None)
    }

    /// Reads a NUL-terminated byte string, bounded by its containing mapping.
    pub fn cstring_at(&self, address: u64) -> Result<&[u8]> {
        let mapping = self
            .mapping_for_addr(address)
            .ok_or(Error::AddressNotFound { addr: address })?;
        let remaining = (mapping.size - (address - mapping.address)) as usize;
        let data = self.data_at_addr(address, remaining)?;
        let end = memchr::memchr(0, data).ok_or(Error::Parse {
            offset: 0,
            reason: "unterminated cache string".into(),
        })?;
        Ok(&data[..=end])
    }

    /// Decodes a known pointer slot using the containing mapping's slide format.
    /// This must only be used for pointer fields, not arbitrary data words.
    pub fn pointer_at(&self, address: u64) -> Result<u64> {
        let raw = if self.pointer_size() == 4 {
            read_u32_le(self.data_at_addr(address, 4)?) as u64
        } else {
            read_u64_le(self.data_at_addr(address, 8)?)
        };
        if raw == 0 {
            return Ok(0);
        }
        let m = self
            .mapping_for_addr(address)
            .ok_or(Error::AddressNotFound { addr: address })?;
        if !m.has_slide_info() {
            return Ok(raw);
        }
        let data = self.data_for_subcache(m.subcache_index);
        let off = m.slide_info_offset as usize;
        let end = off
            .checked_add(m.slide_info_size as usize)
            .filter(|end| *end <= data.len())
            .ok_or(Error::Parse {
                offset: off,
                reason: "slide info out of bounds".into(),
            })?;
        let slide = &data[off..end];
        if slide.len() < 16 {
            return Err(Error::Parse {
                offset: off,
                reason: "truncated slide info".into(),
            });
        }
        if self.pointer_size() == 4 && matches!(read_u32_le(slide), 2 | 4) {
            return self
                .slid_pointer32(address, m, slide, raw as u32)
                .map(u64::from);
        }
        decode_slide_pointer(slide, raw, self.pointer_size()).map(|(value, _)| value)
    }
    fn slid_pointer32(
        &self,
        address: u64,
        mapping: &super::MappingEntry,
        slide: &[u8],
        raw: u32,
    ) -> Result<u32> {
        let bad = |reason: &str| Error::InvalidSlideInfo {
            offset: mapping.slide_info_offset,
            reason: reason.into(),
        };
        if slide.len() < 40 {
            return Err(bad("truncated ARM slide table"));
        }
        let page_size = read_u32_le(&slide[4..]) as u64;
        if !matches!(page_size, 4096 | 16384) {
            return Err(bad("invalid ARM slide page size"));
        }
        let page = (address - mapping.address) / page_size;
        let page_start = mapping.address + page * page_size;
        let existing = self
            .slide32_pages
            .lock()
            .map_err(|_| bad("slide page cache poisoned"))?
            .get(&page_start)
            .cloned();
        let words = if let Some(words) = existing {
            words
        } else {
            let version = read_u32_le(slide);
            let count = read_u32_le(&slide[12..]) as u64;
            if page >= count {
                return Err(bad("ARM page missing from slide table"));
            }
            let table = |offset: usize, count: usize| {
                slide.get(offset..offset.checked_add(count.checked_mul(2)?)?)
            };
            let starts = table(read_u32_le(&slide[8..]) as usize, count as usize)
                .ok_or_else(|| bad("ARM page starts out of bounds"))?;
            let entry = u16::from_le_bytes(
                starts[page as usize * 2..page as usize * 2 + 2]
                    .try_into()
                    .unwrap(),
            );
            let mut heads = Vec::new();
            if entry != if version == 4 { 0xffff } else { 0x4000 } {
                if entry & 0x8000 != 0 {
                    let mask = if version == 4 { 0x7fff } else { 0x3fff };
                    let extras = table(
                        read_u32_le(&slide[16..]) as usize,
                        read_u32_le(&slide[20..]) as usize,
                    )
                    .ok_or_else(|| bad("ARM page extras out of bounds"))?;
                    let mut index = (entry & mask) as usize;
                    loop {
                        let bytes = extras
                            .get(index * 2..index * 2 + 2)
                            .ok_or_else(|| bad("unterminated ARM page extras"))?;
                        let value = u16::from_le_bytes(bytes.try_into().unwrap());
                        heads.push((value & mask) as u64 * 4);
                        if value & 0x8000 != 0 {
                            break;
                        }
                        index += 1;
                    }
                } else {
                    heads.push(entry as u64 * 4);
                }
            }
            let mut words = Vec::new();
            for mut offset in heads {
                loop {
                    if offset % 4 != 0
                        || offset.checked_add(4).is_none_or(|end| {
                            end > page_size || page_start + end > mapping.address + mapping.size
                        })
                    {
                        return Err(bad("ARM chain leaves page"));
                    }
                    let raw = read_u32_le(self.data_at_addr(page_start + offset, 4)?);
                    let (value, delta) = decode_slide_pointer(slide, raw as u64, 4)?;
                    words.push((offset as u16, value as u32));
                    if delta == 0 {
                        break;
                    }
                    offset = offset
                        .checked_add(delta)
                        .ok_or_else(|| bad("ARM chain offset overflow"))?;
                }
            }
            words.sort_unstable_by_key(|(offset, _)| *offset);
            words.dedup_by_key(|(offset, _)| *offset);
            let words = std::sync::Arc::new(words);
            self.slide32_pages
                .lock()
                .map_err(|_| bad("slide page cache poisoned"))?
                .entry(page_start)
                .or_insert_with(|| words.clone())
                .clone()
        };
        let offset = (address - page_start) as u16;
        Ok(words
            .binary_search_by_key(&offset, |(offset, _)| *offset)
            .map(|index| words[index].1)
            .unwrap_or(raw))
    }
}

fn checked_address(base: u64, offset: u64) -> Result<u64> {
    base.checked_add(offset).ok_or(Error::Parse {
        offset: 0,
        reason: "cache address overflow".into(),
    })
}

/// Decodes one slide-chain word and its byte distance to the next word.
/// v1 words are already unslid; bitmap membership is handled by the walker.
pub(crate) fn decode_slide_pointer(slide: &[u8], raw: u64, width: usize) -> Result<(u64, u64)> {
    let bad = || Error::Parse {
        offset: 0,
        reason: "invalid slide pointer encoding".into(),
    };
    if slide.len() < 4 {
        return Err(bad());
    }
    match read_u32_le(slide) {
        1 => Ok((raw, 0)),
        version @ (2 | 4) if slide.len() >= 40 => {
            if version == 4 && width != 4 {
                return Err(bad());
            }
            let mask = read_u64_le(&slide[24..]);
            if mask == 0 || mask.trailing_zeros() < 2 || (width == 4 && mask > u32::MAX as u64) {
                return Err(bad());
            }
            let bits = mask >> mask.trailing_zeros();
            if bits & bits.wrapping_add(1) != 0 {
                return Err(bad());
            }
            let base = read_u64_le(&slide[32..]);
            let value = raw & !mask;
            let value = if version == 4 {
                if value & 0xffff8000 == 0 {
                    value
                } else if value & 0x3fff8000 == 0x3fff8000 {
                    value | 0xc0000000
                } else {
                    checked_address(value, base)?
                }
            } else if value == 0 {
                0
            } else {
                checked_address(value, base)?
            };
            if width == 4 && value > u32::MAX as u64 {
                return Err(bad());
            }
            Ok((value, ((raw & mask) >> mask.trailing_zeros()) * 4))
        }
        3 if slide.len() >= 24 && width == 8 => {
            let p = SlidePointer3(raw);
            let value = if p.is_auth() {
                checked_address(read_u64_le(&slide[16..]), p.auth_offset() as u64)?
            } else {
                p.plain_value()
            };
            Ok((value, p.offset_to_next() * 8))
        }
        5 if slide.len() >= 24 && width == 8 => {
            let p = SlidePointer5(raw);
            let value = checked_address(read_u64_le(&slide[16..]), p.runtime_offset())?;
            Ok((
                if p.is_auth() {
                    value
                } else {
                    value | ((p.high8() as u64) << 56)
                },
                p.next() * 8,
            ))
        }
        version => Err(Error::Parse {
            offset: 0,
            reason: format!("unsupported pointer slide version {version}"),
        }),
    }
}
