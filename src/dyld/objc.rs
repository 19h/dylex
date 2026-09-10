//! Cache-wide Objective-C metadata. All modern offsets are relative to the
//! main cache header's VM address, even when the tables reside in a subcache.

use super::{DyldCacheHeader, DyldContext, SlidePointer3, SlidePointer5};
use crate::error::{Error, Result};
use crate::macho::{MachHeader64, MachOContext};
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
    /// Reads an image's header and commands without copying its segments.
    pub fn image_header(&self, address: u64) -> Result<MachOContext> {
        let header = self.data_at_addr(address, MachHeader64::SIZE)?;
        let size = MachHeader64::SIZE + read_u32_le(&header[20..]) as usize;
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
        // IDA ldr/dsc/dsc.cpp: objc_opt_t v16 has a signed self-relative base.
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
        let raw = read_u64_le(self.data_at_addr(address, 8)?);
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
        match read_u32_le(slide) {
            2 if slide.len() >= 40 => {
                let value = raw & !read_u64_le(&slide[24..]);
                if value == 0 {
                    Ok(0)
                } else {
                    checked_address(value, read_u64_le(&slide[32..]))
                }
            }
            3 if slide.len() >= 24 => {
                let p = SlidePointer3(raw);
                if p.is_auth() {
                    checked_address(read_u64_le(&slide[16..]), p.auth_offset() as u64)
                } else {
                    Ok(p.plain_value())
                }
            }
            5 if slide.len() >= 24 => {
                let p = SlidePointer5(raw);
                let value = checked_address(read_u64_le(&slide[16..]), p.runtime_offset())?;
                Ok(if p.is_auth() {
                    value
                } else {
                    value | ((p.high8() as u64) << 56)
                })
            }
            version => Err(Error::Parse {
                offset: off,
                reason: format!("unsupported pointer slide version {version}"),
            }),
        }
    }
}

fn checked_address(base: u64, offset: u64) -> Result<u64> {
    base.checked_add(offset).ok_or(Error::Parse {
        offset: 0,
        reason: "cache address overflow".into(),
    })
}
