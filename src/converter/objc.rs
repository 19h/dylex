//! Restore cache-coalesced Objective-C metadata for static analysis. Relative
//! method entries become ordinary 24-byte absolute entries, and referenced
//! strings/metadata are serialized into one mapped __EXTRA_OBJC segment.
use super::{ExtractionContext, support::append_segment};
use crate::dyld::ObjcOptimization;
use crate::util::{read_u32_le, read_u64_le};
use crate::{DyldContext, Error, Result};
use std::collections::{HashMap, HashSet};

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

/// Type string offsets are relative to the global selector base.
pub const METHOD_LIST_TYPE_OFFSETS_FLAG: u32 = 0x2000_0000;

/// Historical API alias; this bit encodes base-relative types, not uniquing.
#[deprecated(note = "use METHOD_LIST_TYPE_OFFSETS_FLAG; this is an encoding bit")]
pub const METHOD_LIST_UNIQUED_FLAG: u32 = METHOD_LIST_TYPE_OFFSETS_FLAG;

/// Mask for method list entry count.
pub const METHOD_LIST_COUNT_MASK: u32 = 0x00FF_FFFF;

/// Restores method encodings before clearing optimization flags. Source reads
/// always use cache VM addresses and mapping-specific slide formats.
pub fn fix_objc(ctx: &mut ExtractionContext) -> Result<()> {
    let roots: Vec<_> = ctx
        .macho
        .segments()
        .flat_map(|s| &s.sections)
        .filter(|s| {
            matches!(
                s.name(),
                "__objc_classlist"
                    | "__objc_nlclslist"
                    | "__objc_catlist"
                    | "__objc_nlcatlist"
                    | "__objc_protolist"
                    | "__objc_selrefs"
            )
        })
        .map(|s| (s.name().to_string(), s.section.addr, s.section.size))
        .collect();
    if roots.is_empty() {
        return Ok(());
    }
    let cache = std::sync::Arc::clone(&ctx.cache);
    // Absolute method entries have no signed-relative reach constraint. Place
    // new metadata beyond all cache VM ranges to avoid collision with imports.
    let end = cache
        .mappings
        .iter()
        .map(|m| m.address + m.size)
        .max()
        .unwrap_or(0);
    let base = end
        .checked_add(0x3fff)
        .map(|v| v & !0x3fff)
        .ok_or_else(|| invalid("ObjC output address overflow"))?;
    let category_class_properties = ctx
        .macho
        .segments()
        .flat_map(|s| &s.sections)
        .filter(|s| s.name() == "__objc_imageinfo" && s.section.size >= 8)
        .map(|s| {
            cache
                .data_at_addr(s.section.addr, 8)
                .map(|data| read_u32_le(&data[4..]) & (1 << 6) != 0)
        })
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .any(|v| v);
    let mut builder = ObjcBuilder {
        cache: &cache,
        opts: cache.objc_optimization()?,
        base,
        category_class_properties,
        data: Vec::new(),
        strings: HashMap::new(),
        objects: HashMap::new(),
        active_lists: HashSet::new(),
    };
    let mut patches = Vec::new();
    let mut classes = HashSet::new();
    for (kind, start, size) in roots {
        if size % 8 != 0 {
            return Err(invalid("misaligned ObjC pointer section"));
        }
        cache.data_at_addr(start, size as usize)?;
        for slot in (start..start + size).step_by(8) {
            let addr = clean(cache.pointer_at(slot)?);
            tracing::debug!("ObjC root {kind} at {slot:#x} -> {addr:#x}");
            if addr == 0 {
                continue;
            }
            match kind.as_str() {
                "__objc_classlist" | "__objc_nlclslist" => {
                    let mut pending = vec![addr];
                    while let Some(class) = pending.pop() {
                        if !classes.insert(class) || !ctx.macho.contains_addr(class) {
                            continue;
                        }
                        cache.data_at_addr(class, 40)?;
                        let ro = clean(cache.pointer_at(class + 32)?) & !7;
                        if ro != 0 {
                            let new_ro = builder.class_ro(ro)?;
                            let bits = cache.pointer_at(class + 32)? & 7;
                            patches.push((class + 32, new_ro | bits));
                        }
                        let isa = clean(cache.pointer_at(class)?);
                        if isa != 0 && isa != class {
                            pending.push(isa);
                        }
                    }
                }
                "__objc_catlist" | "__objc_nlcatlist" => {
                    patches.push((slot, builder.category(addr)?))
                }
                "__objc_protolist" => patches.push((slot, builder.protocol(addr)?)),
                "__objc_selrefs" => patches.push((slot, builder.string(addr)?)),
                _ => unreachable!(),
            }
        }
    }
    // Mutate only after the complete graph has been decoded successfully.
    if builder.data.is_empty() {
        return Ok(());
    }
    append_segment(ctx, "__EXTRA_OBJC", base, &builder.data, 1)?;
    for (addr, value) in patches {
        let offset = ctx
            .macho
            .addr_to_offset(addr)
            .ok_or(Error::AddressNotFound { addr })?;
        ctx.macho.write_u64(offset, value)?;
    }
    let image_infos: Vec<_> = ctx
        .macho
        .segments()
        .flat_map(|s| &s.sections)
        .filter(|s| s.name() == "__objc_imageinfo" && s.section.size >= 8)
        .map(|s| s.section.offset as usize)
        .collect();
    for offset in image_infos {
        let flags = ctx.macho.read_u32(offset + 4)?;
        ctx.macho
            .write_u32(offset + 4, flags & !OBJC_IMAGE_OPTIMIZED_BY_DYLD)?;
    }
    ctx.info(&format!(
        "Restored Objective-C metadata ({} bytes)",
        builder.data.len()
    ));
    Ok(())
}

struct ObjcBuilder<'a> {
    cache: &'a DyldContext,
    opts: Option<ObjcOptimization>,
    base: u64,
    data: Vec<u8>,
    category_class_properties: bool,
    strings: HashMap<u64, u64>,
    objects: HashMap<(u64, u8), u64>,
    active_lists: HashSet<(u64, u8)>,
}

impl ObjcBuilder<'_> {
    fn reserve(&mut self, size: usize) -> Result<(u64, usize)> {
        let off = self
            .data
            .len()
            .checked_add(7)
            .map(|v| v & !7)
            .ok_or_else(|| invalid("ObjC output size overflow"))?;
        let end = off
            .checked_add(size)
            .filter(|n| *n <= u32::MAX as usize)
            .ok_or_else(|| invalid("ObjC output exceeds file offset limit"))?;
        self.base
            .checked_add(end as u64)
            .ok_or_else(|| invalid("ObjC output address overflow"))?;
        self.data.resize(end, 0);
        Ok((self.base + off as u64, off))
    }
    fn put(&mut self, off: usize, value: u64) {
        self.data[off..off + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn ptr(&self, addr: u64) -> Result<u64> {
        Ok(clean(self.cache.pointer_at(addr).map_err(|e| {
            invalid(&format!("ObjC pointer at {addr:#x}: {e}"))
        })?))
    }
    fn string(&mut self, addr: u64) -> Result<u64> {
        if addr == 0 {
            return Ok(0);
        }
        if let Some(&value) = self.strings.get(&addr) {
            return Ok(value);
        }
        let string = self
            .cache
            .cstring_at(addr)
            .map_err(|e| invalid(&format!("ObjC string {addr:#x}: {e}")))?;
        let (value, off) = self.reserve(string.len())?;
        self.data[off..off + string.len()].copy_from_slice(string);
        self.strings.insert(addr, value);
        Ok(value)
    }
    fn string_field(&mut self, src: u64, dst: usize) -> Result<()> {
        let ptr = self.ptr(src)?;
        let value = self.string(ptr)?;
        self.put(dst, value);
        Ok(())
    }
    fn record(&mut self, addr: u64, size: usize, pointers: &[usize]) -> Result<(u64, usize)> {
        let bytes = self
            .cache
            .data_at_addr(addr, size)
            .map_err(|e| invalid(&format!("ObjC record {addr:#x} ({size} bytes): {e}")))?;
        let (value, off) = self.reserve(size)?;
        self.data[off..off + size].copy_from_slice(bytes);
        for &field in pointers {
            let p = self.ptr(addr + field as u64)?;
            self.put(off + field, p);
        }
        Ok((value, off))
    }
    fn class_ro(&mut self, addr: u64) -> Result<u64> {
        tracing::debug!("class_ro {addr:#x}");
        if let Some(&value) = self.objects.get(&(addr, 0)) {
            return Ok(value);
        }
        let (value, off) = self.record(addr, 72, &[16, 24, 32, 40, 48, 56, 64])?;
        self.objects.insert((addr, 0), value);
        for field in [16, 24, 56] {
            self.string_field(addr + field as u64, off + field)?;
        }
        let methods = self.methods(self.ptr(addr + 32)?)?;
        self.put(off + 32, methods);
        let protocols = self.protocol_list(self.ptr(addr + 40)?)?;
        self.put(off + 40, protocols);
        let ivars = self.fields(self.ptr(addr + 48)?, true)?;
        self.put(off + 48, ivars);
        let properties = self.fields(self.ptr(addr + 64)?, false)?;
        self.put(off + 64, properties);
        Ok(value)
    }
    fn category(&mut self, addr: u64) -> Result<u64> {
        if let Some(&value) = self.objects.get(&(addr, 1)) {
            return Ok(value);
        }
        let size = if self.category_class_properties {
            56
        } else {
            48
        };
        let (value, off) = self.record(addr, size, &[0, 8, 16, 24, 32, 40])?;
        self.objects.insert((addr, 1), value);
        self.string_field(addr, off)?;
        for field in [16, 24] {
            let methods = self.methods(self.ptr(addr + field)?)?;
            self.put(off + field as usize, methods);
        }
        let protocols = self.protocol_list(self.ptr(addr + 32)?)?;
        self.put(off + 32, protocols);
        let properties = self.fields(self.ptr(addr + 40)?, false)?;
        self.put(off + 40, properties);
        if self.category_class_properties {
            let properties = self.fields(self.ptr(addr + 48)?, false)?;
            self.put(off + 48, properties);
        }
        Ok(value)
    }
    fn protocol(&mut self, addr: u64) -> Result<u64> {
        if addr == 0 {
            return Ok(0);
        }
        if let Some(&value) = self.objects.get(&(addr, 2)) {
            return Ok(value);
        }
        let prefix = self.cache.data_at_addr(addr, 72)?;
        let size = read_u32_le(&prefix[64..]) as usize;
        if !(72..=4096).contains(&size) {
            return Err(invalid("invalid ObjC protocol size"));
        }
        let (value, off) = self.record(addr, size, &[0, 8, 16, 24, 32, 40, 48, 56])?;
        self.objects.insert((addr, 2), value);
        self.string_field(addr + 8, off + 8)?;
        let protocols = self.protocol_list(self.ptr(addr + 16)?)?;
        self.put(off + 16, protocols);
        let mut count = 0;
        for field in [24, 32, 40, 48] {
            let methods = self.methods(self.ptr(addr + field)?)?;
            if methods != 0 {
                count += read_u32_le(&self.data[(methods - self.base) as usize + 4..]) as usize;
            }
            self.put(off + field as usize, methods);
        }
        let properties = self.fields(self.ptr(addr + 56)?, false)?;
        self.put(off + 56, properties);
        if size >= 80 {
            let types = self.ptr(addr + 72)?;
            let new_types = if types == 0 {
                0
            } else {
                self.cache.data_at_addr(
                    types,
                    count
                        .checked_mul(8)
                        .ok_or_else(|| invalid("protocol type count overflow"))?,
                )?;
                let (v, o) = self.reserve(count * 8)?;
                for i in 0..count {
                    self.string_field(types + (i * 8) as u64, o + i * 8)?;
                }
                v
            };
            self.put(off + 72, new_types);
        }
        if size >= 88 {
            self.string_field(addr + 80, off + 80)?;
        }
        if size >= 96 {
            let props = self.fields(self.ptr(addr + 88)?, false)?;
            self.put(off + 88, props);
        }
        Ok(value)
    }
    // Expand a tagged relative list-of-lists with signed 48-bit offsets. The
    // cache is a static snapshot; all constituent lists are retained for analysis.
    fn lists(&mut self, addr: u64, kind: u8) -> Result<Vec<u64>> {
        if addr == 0 {
            return Ok(Vec::new());
        }
        if addr & 1 == 0 {
            return Ok(vec![addr]);
        }
        if !self.active_lists.insert((addr, kind)) {
            return Err(invalid("cyclic ObjC relative list"));
        }
        let start = addr & !1;
        let h = self.cache.data_at_addr(start, 8)?;
        if read_u32_le(h) != 8 {
            return Err(invalid("unsupported ObjC relative list entry size"));
        }
        let count = read_u32_le(&h[4..]) as usize;
        let bytes = self.cache.data_at_addr(
            start + 8,
            count
                .checked_mul(8)
                .ok_or_else(|| invalid("relative list size overflow"))?,
        )?;
        let mut out = Vec::new();
        for (i, entry) in bytes.chunks_exact(8).enumerate() {
            let field = start + 8 + (i * 8) as u64;
            let target = field
                .checked_add_signed((read_u64_le(entry) as i64) >> 16)
                .ok_or_else(|| invalid("relative list address overflow"))?;
            out.extend(self.lists(target, kind)?);
        }
        self.active_lists.remove(&(addr, kind));
        Ok(out)
    }
    fn methods(&mut self, addr: u64) -> Result<u64> {
        if addr == 0 {
            return Ok(0);
        }
        if let Some(&value) = self.objects.get(&(addr, 3)) {
            return Ok(value);
        }
        let mut methods = Vec::new();
        for list in self.lists(addr, 3)? {
            tracing::debug!("method list {list:#x}");
            let h = self.cache.data_at_addr(list, 8)?;
            let flags = read_u32_le(h);
            let count = read_u32_le(&h[4..]) as usize;
            let relative = flags & METHOD_LIST_RELATIVE_FLAG != 0;
            let stride = (flags & 0xfffc) as usize;
            if count == 0 {
                continue;
            }
            if stride < if relative { 12 } else { 24 } {
                return Err(invalid(&format!(
                    "invalid method entry size at {list:#x}: flags={flags:#x}, count={count}"
                )));
            }
            let entries = self.cache.data_at_addr(
                list + 8,
                count
                    .checked_mul(stride)
                    .ok_or_else(|| invalid("method list size overflow"))?,
            )?;
            for (i, entry) in entries.chunks_exact(stride).enumerate() {
                let field = list + 8 + (i * stride) as u64;
                let (name, types, imp) = if relative {
                    resolve_relative_method(self.cache, self.opts, flags, field, entry)?
                } else {
                    (
                        self.ptr(field)?,
                        self.ptr(field + 8)?,
                        self.ptr(field + 16)?,
                    )
                };
                methods.push((self.string(name)?, self.string(types)?, imp));
            }
        }
        let count = u32::try_from(methods.len()).map_err(|_| invalid("method count overflow"))?;
        let (value, off) = self.reserve(8 + methods.len() * 24)?;
        self.data[off..off + 4].copy_from_slice(&24u32.to_le_bytes());
        self.data[off + 4..off + 8].copy_from_slice(&count.to_le_bytes());
        for (i, (name, types, imp)) in methods.into_iter().enumerate() {
            self.put(off + 8 + i * 24, name);
            self.put(off + 16 + i * 24, types);
            self.put(off + 24 + i * 24, imp);
        }
        self.objects.insert((addr, 3), value);
        Ok(value)
    }
    fn protocol_list(&mut self, addr: u64) -> Result<u64> {
        if addr == 0 {
            return Ok(0);
        }
        if let Some(&value) = self.objects.get(&(addr, 4)) {
            return Ok(value);
        }
        let mut protocols = Vec::new();
        for list in self.lists(addr, 4)? {
            let count = usize::try_from(read_u64_le(self.cache.data_at_addr(list, 8)?))
                .map_err(|_| invalid("protocol list count overflow"))?;
            self.cache.data_at_addr(
                list + 8,
                count
                    .checked_mul(8)
                    .ok_or_else(|| invalid("protocol list size overflow"))?,
            )?;
            for i in 0..count {
                protocols.push(self.ptr(list + 8 + (i * 8) as u64)?);
            }
        }
        let (value, off) = self.reserve(8 + protocols.len() * 8)?;
        self.objects.insert((addr, 4), value);
        self.put(off, protocols.len() as u64);
        for (i, p) in protocols.into_iter().enumerate() {
            let v = self.protocol(p)?;
            self.put(off + 8 + i * 8, v);
        }
        Ok(value)
    }
    fn fields(&mut self, addr: u64, ivars: bool) -> Result<u64> {
        if addr == 0 {
            return Ok(0);
        }
        let kind = if ivars { 5 } else { 6 };
        if let Some(&value) = self.objects.get(&(addr, kind)) {
            return Ok(value);
        }
        let stride = if ivars { 32 } else { 16 };
        let mut entries = Vec::new();
        for list in self.lists(addr, kind)? {
            let h = self.cache.data_at_addr(list, 8)?;
            let source_stride = read_u32_le(h) as usize;
            let count = read_u32_le(&h[4..]) as usize;
            if count == 0 {
                continue;
            }
            if source_stride < stride {
                return Err(invalid(&format!(
                    "invalid property/ivar entry size {source_stride} at {list:#x} (ivars={ivars}, count={count})"
                )));
            }
            self.cache.data_at_addr(
                list + 8,
                count
                    .checked_mul(source_stride)
                    .ok_or_else(|| invalid("field list size overflow"))?,
            )?;
            for i in 0..count {
                entries.push(list + 8 + (i * source_stride) as u64);
            }
        }
        let (value, off) = self.reserve(8 + entries.len() * stride)?;
        self.data[off..off + 4].copy_from_slice(&(stride as u32).to_le_bytes());
        self.data[off + 4..off + 8].copy_from_slice(&(entries.len() as u32).to_le_bytes());
        for (i, src) in entries.into_iter().enumerate() {
            let dst = off + 8 + i * stride;
            self.data[dst..dst + stride].copy_from_slice(self.cache.data_at_addr(src, stride)?);
            if ivars {
                let ptr = self.ptr(src)?;
                if ptr != 0 {
                    let bytes = self.cache.data_at_addr(ptr, 4)?;
                    let (v, o) = self.reserve(4)?;
                    self.data[o..o + 4].copy_from_slice(bytes);
                    self.put(dst, v);
                }
                self.string_field(src + 8, dst + 8)?;
                self.string_field(src + 16, dst + 16)?;
            } else {
                self.string_field(src, dst)?;
                self.string_field(src + 8, dst + 8)?;
            }
        }
        self.objects.insert((addr, kind), value);
        Ok(value)
    }
}

fn resolve_relative_method(
    cache: &DyldContext,
    opts: Option<ObjcOptimization>,
    flags: u32,
    field: u64,
    entry: &[u8],
) -> Result<(u64, u64, u64)> {
    let relative = |base: u64, off: usize| {
        base.checked_add_signed(read_u32_le(&entry[off..]) as i32 as i64)
            .ok_or_else(|| invalid("relative method address overflow"))
    };
    let name = if flags & METHOD_LIST_DIRECT_SEL_FLAG != 0 {
        // Prior to global-base optimization, direct names were self-relative.
        relative(opts.map_or(field, |o| o.selector_base), 0)?
    } else {
        clean(cache.pointer_at(relative(field, 0)?)?)
    };
    let types = if flags & METHOD_LIST_TYPE_OFFSETS_FLAG != 0 {
        relative(
            opts.ok_or_else(|| invalid("base-relative method types without selector base"))?
                .selector_base,
            4,
        )?
    } else if read_u32_le(&entry[4..]) == 0 {
        0
    } else {
        relative(field + 4, 4)?
    };
    Ok((name, types, relative(field + 8, 8)?))
}

fn clean(pointer: u64) -> u64 {
    pointer & 0x0000_ffff_ffff_ffff
}
fn invalid(reason: &str) -> Error {
    Error::Parse {
        offset: 0,
        reason: reason.into(),
    }
}
