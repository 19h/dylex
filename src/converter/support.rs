//! Retain referenced cache island bytes at their original unslid addresses.
//! This preserves ADRP/B reach without synthesizing removed per-image stubs.
use super::{ExtractionContext, decode_cache_stub, remove_load_command};
use crate::dyld::MappingFlags;
use crate::macho::*;
use crate::{Error, Result};
use std::collections::{BTreeMap, HashSet};
use zerocopy::IntoBytes;

/// Adds a mapped analysis segment in verified unused load-command padding.
/// Rejects overlaps and insufficient padding instead of overwriting image code.
pub(crate) fn append_segment(
    ctx: &mut ExtractionContext,
    name: &str,
    addr: u64,
    bytes: &[u8],
    prot: u32,
) -> Result<()> {
    if bytes.is_empty() {
        return Ok(());
    }
    let end = addr
        .checked_add(bytes.len() as u64)
        .ok_or_else(|| invalid("support address overflow"))?;
    if ctx.macho.segments().any(|s| {
        s.command.vmsize > 0 && addr < s.command.vmaddr + s.command.vmsize && end > s.command.vmaddr
    }) {
        return Err(invalid("support segment overlaps image VM range"));
    }
    let size = SegmentCommand64::SIZE + Section64::SIZE;
    let boundary = |ctx: &ExtractionContext| {
        ctx.macho
            .segments()
            .flat_map(|s| &s.sections)
            .filter(|s| s.section.offset != 0 && s.section.size != 0)
            .map(|s| s.section.offset as usize)
            .min()
            .unwrap_or(32 + ctx.macho.header.sizeofcmds as usize)
    };
    let mut off = 32 + ctx.macho.header.sizeofcmds as usize;
    if off + size > boundary(ctx)
        || ctx
            .macho
            .data
            .get(off..off + size)
            .is_none_or(|b| b.iter().any(|v| *v != 0))
    {
        // These commands no longer describe valid data after cache extraction.
        for cmd in [
            LC_CODE_SIGNATURE,
            LC_SEGMENT_SPLIT_INFO,
            LC_DYLD_CHAINED_FIXUPS,
        ] {
            remove_load_command(ctx, cmd)?;
        }
        ctx.macho.refresh()?;
        off = 32 + ctx.macho.header.sizeofcmds as usize;
        if off + size > boundary(ctx)
            || ctx
                .macho
                .data
                .get(off..off + size)
                .is_none_or(|b| b.iter().any(|v| *v != 0))
        {
            move_header(ctx, size)?;
            off = 32 + ctx.macho.header.sizeofcmds as usize;
        }
    }
    let fileoff = ctx.macho.data.len();
    if fileoff
        .checked_add(bytes.len())
        .is_none_or(|end| end > u32::MAX as usize)
    {
        return Err(invalid("support data exceeds Mach-O file offset limit"));
    }
    let mut segname = [0u8; 16];
    segname[..name.len().min(16)].copy_from_slice(&name.as_bytes()[..name.len().min(16)]);
    let command = SegmentCommand64 {
        cmd: LC_SEGMENT_64,
        cmdsize: size as u32,
        segname,
        vmaddr: addr,
        vmsize: bytes.len() as u64,
        fileoff: fileoff as u64,
        filesize: bytes.len() as u64,
        maxprot: prot,
        initprot: prot,
        nsects: 1,
        flags: 0,
    };
    let mut section = Section64 {
        sectname: [0; 16],
        segname,
        addr,
        size: bytes.len() as u64,
        offset: fileoff as u32,
        align: 0,
        reloff: 0,
        nreloc: 0,
        flags: if prot & 4 != 0 {
            S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS
        } else {
            0
        },
        reserved1: 0,
        reserved2: 0,
        reserved3: 0,
    };
    section.set_name(if prot & 4 != 0 {
        "__text"
    } else {
        "__objc_const"
    });
    ctx.macho.data[off..off + 72].copy_from_slice(command.as_bytes());
    ctx.macho.data[off + 72..off + size].copy_from_slice(section.as_bytes());
    ctx.macho.write_u32(16, ctx.macho.header.ncmds + 1)?;
    ctx.macho
        .write_u32(20, ctx.macho.header.sizeofcmds + size as u32)?;
    ctx.macho.data.extend_from_slice(bytes);
    ctx.macho.refresh()
}

/// Includes referenced sectionless stubs, their selector strings, GOT slots,
/// and local libobjcMsgSend dispatcher modules. Ordinary external functions
/// remain external, as with legacy per-image stubs.
pub fn include_cache_support(ctx: &mut ExtractionContext) -> Result<()> {
    if !ctx.macho.is_arm64() {
        return Ok(());
    }
    let cache = std::sync::Arc::clone(&ctx.cache);
    let mut ranges: BTreeMap<usize, (u64, u64)> = BTreeMap::new();
    let mut images: Vec<_> = cache.images.iter().collect();
    images.sort_by_key(|i| i.address);
    let preceding_image = |addr| {
        images
            .partition_point(|i| i.address <= addr)
            .checked_sub(1)
            .map(|index| images[index])
    };
    let mut pointer_slots = BTreeMap::new();
    let mut pending = Vec::new();
    // Scan only declared instruction sections; marker sections may be empty.
    for seg in ctx.macho.segments() {
        for section in &seg.sections {
            let s = &section.section;
            if s.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) == 0 {
                continue;
            }
            let Some(bytes) = ctx
                .macho
                .data
                .get(s.offset as usize..(s.offset as usize).saturating_add(s.size as usize))
            else {
                return Err(invalid("instruction section out of bounds"));
            };
            for (i, word) in bytes.chunks_exact(4).enumerate() {
                let insn = crate::util::read_u32_le(word);
                if crate::arm64::is_branch(insn) {
                    let target = crate::arm64::decode_branch(insn, s.addr + (i * 4) as u64);
                    if !ctx.macho.contains_addr(target) {
                        pending.push((target, 0));
                    }
                }
            }
        }
    }
    let mut seen = HashSet::new();
    let mut dispatchers = HashSet::new();
    while let Some((addr, depth)) = pending.pop() {
        if ctx.macho.contains_addr(addr) || !seen.insert(addr) {
            continue;
        }
        if depth >= 64 {
            return Err(invalid("cache stub chain exceeds 64 hops"));
        }
        let Some(mapping) = cache.mapping_for_addr(addr).filter(|m| m.is_executable()) else {
            continue;
        };
        // Dispatcher images are identified by install name, not a fixed copy count.
        let image = preceding_image(addr);
        if let Some(img) = image.filter(|i| is_msgsend_image(&i.path)) {
            let header = cache.image_header(img.address)?;
            if let Some(seg) = header
                .segments()
                .find(|s| addr >= s.command.vmaddr && addr - s.command.vmaddr < s.command.filesize)
            {
                if dispatchers.insert(img.address) {
                    add_range(
                        &cache,
                        &mut ranges,
                        seg.command.vmaddr,
                        seg.command.filesize,
                    )?;
                }
                continue;
            }
        }
        let available = (mapping.size - (addr - mapping.address)).min(16) as usize;
        let Some(stub) = decode_cache_stub(cache.data_at_addr(addr, available)?, addr) else {
            continue;
        };
        // A bare B at an ordinary function entry is not sufficient evidence of
        // a sectionless stub. Dedicated TEXT_STUBS mappings are authoritative.
        if stub.size == 4 && mapping.flags & MappingFlags::TEXT_STUBS.bits() == 0 {
            continue;
        }
        if let Some(selector) = stub.selector {
            // Validate dispatcher ownership, like IDA's objc dispatcher check.
            let target_image = preceding_image(stub.target);
            let is_dispatcher = target_image
                .is_some_and(|i| is_msgsend_image(&i.path) || i.path == "/usr/lib/libobjc.A.dylib");
            if !is_dispatcher {
                continue;
            }
            add_range(
                &cache,
                &mut ranges,
                selector,
                cache.cstring_at(selector)?.len() as u64,
            )?;
        }
        add_range(&cache, &mut ranges, addr, stub.size as u64)?;
        if stub.indirect {
            let value = cache.pointer_at(stub.target)?;
            add_range(&cache, &mut ranges, stub.target, 8)?;
            pointer_slots.insert(stub.target, value);
            pending.push((value, depth + 1));
        } else {
            pending.push((stub.target, depth + 1));
        }
    }
    // Coalesce by cache mapping, subtracting all already-mapped image ranges.
    // This bounds the number of additional commands and preserves PC-relative
    // distances while avoiding virtual overlaps with the original image.
    let originals: Vec<_> = ctx
        .macho
        .segments()
        .map(|s| (s.command.vmaddr, s.command.vmaddr + s.command.vmsize))
        .collect();
    let mut index = 0;
    for (mapping_index, (start, end)) in ranges {
        let mut pieces = vec![(start, end)];
        for &(a, b) in &originals {
            pieces = pieces
                .into_iter()
                .flat_map(|(x, y)| {
                    if b <= x || a >= y {
                        vec![(x, y)]
                    } else {
                        [(x, a.min(y)), (b.max(x), y)]
                            .into_iter()
                            .filter(|(x, y)| x < y)
                            .collect()
                    }
                })
                .collect();
        }
        for (start, end) in pieces {
            let mut bytes = cache.data_at_addr(start, (end - start) as usize)?.to_vec();
            for (&slot, &value) in pointer_slots.range(start..end) {
                let off = (slot - start) as usize;
                if off + 8 <= bytes.len() {
                    bytes[off..off + 8].copy_from_slice(&value.to_le_bytes());
                }
            }
            append_segment(
                ctx,
                &format!("__DSC_{index}"),
                start,
                &bytes,
                cache.mappings[mapping_index].init_prot,
            )?;
            index += 1;
        }
    }
    if index != 0 {
        ctx.info(&format!("Retained {index} cache support ranges"));
    }
    Ok(())
}

fn add_range(
    cache: &crate::DyldContext,
    ranges: &mut BTreeMap<usize, (u64, u64)>,
    addr: u64,
    size: u64,
) -> Result<()> {
    cache.data_at_addr(addr, size as usize)?;
    let index = cache
        .mappings
        .partition_point(|m| m.address <= addr)
        .checked_sub(1)
        .ok_or(Error::AddressNotFound { addr })?;
    let end = addr
        .checked_add(size)
        .ok_or_else(|| invalid("support range overflow"))?;
    ranges
        .entry(index)
        .and_modify(|r| {
            r.0 = r.0.min(addr);
            r.1 = r.1.max(end);
        })
        .or_insert((addr, end));
    Ok(())
}

pub(crate) fn is_msgsend_image(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .is_some_and(|s| s.starts_with("libobjcMsgSend") && s.ends_with(".dylib"))
}

fn invalid(reason: &str) -> Error {
    Error::Parse {
        offset: 0,
        reason: reason.into(),
    }
}

// An analysis Mach-O can map its header separately from __TEXT. Relocating
// only file offsets preserves every original VM address, instruction, relative
// method IMP and function-start delta. A sectionless header segment also leaves
// all existing nlist section ordinals unchanged.
fn move_header(ctx: &mut ExtractionContext, required: usize) -> Result<()> {
    let header_end = 32 + ctx.macho.header.sizeofcmds as usize;
    let growth = (header_end + required + 72 + 0xffff) & !0xffff;
    let min_vm = ctx
        .cache
        .mappings
        .iter()
        .map(|m| m.address)
        .chain(ctx.macho.segments().map(|s| s.command.vmaddr))
        .filter(|v| *v != 0)
        .min()
        .ok_or_else(|| invalid("no VM space for analysis header"))?;
    let header_vm = (min_vm & !0x3fff)
        .checked_sub(growth as u64)
        .ok_or_else(|| invalid("no VM space for analysis header"))?;
    let mut old = ctx.macho.data.clone();
    let mut offset_fields = Vec::new();
    let mut data_in_code = None;
    for lc in &ctx.macho.load_commands {
        let off = lc.offset();
        match lc {
            LoadCommandInfo::Segment(seg) => {
                let fileoff = seg
                    .command
                    .fileoff
                    .checked_add(growth as u64)
                    .ok_or_else(|| invalid("file offset overflow"))?;
                old[off + 40..off + 48].copy_from_slice(&fileoff.to_le_bytes());
                for section in &seg.sections {
                    if section.section.offset != 0 {
                        offset_fields.push(section.struct_offset + 48);
                    }
                    if section.section.reloff != 0 {
                        offset_fields.push(section.struct_offset + 56);
                    }
                }
            }
            LoadCommandInfo::Symtab { .. } => offset_fields.extend([off + 8, off + 16]),
            LoadCommandInfo::Dysymtab { .. } => {
                offset_fields.extend([32, 40, 48, 56, 64, 72].map(|f| off + f))
            }
            LoadCommandInfo::DyldInfo { .. } => {
                offset_fields.extend([8, 16, 24, 32, 40].map(|f| off + f))
            }
            LoadCommandInfo::LinkeditData { command, .. } => {
                if command.cmd == LC_DATA_IN_CODE {
                    data_in_code = Some(*command);
                }
                offset_fields.push(off + 8);
            }
            _ => {}
        }
    }
    for off in offset_fields {
        let value = crate::util::read_u32_le(&old[off..]);
        if value != 0 {
            let value = value
                .checked_add(growth as u32)
                .ok_or_else(|| invalid("file offset overflow"))?;
            old[off..off + 4].copy_from_slice(&value.to_le_bytes());
        }
    }
    if let Some(cmd) = data_in_code {
        let start = cmd.dataoff as usize;
        let end = start
            .checked_add(cmd.datasize as usize)
            .filter(|end| *end <= old.len())
            .ok_or_else(|| invalid("data-in-code table out of bounds"))?;
        for entry in old[start..end].chunks_exact_mut(8) {
            let value = crate::util::read_u32_le(entry)
                .checked_add(growth as u32)
                .ok_or_else(|| invalid("data-in-code offset overflow"))?;
            entry[..4].copy_from_slice(&value.to_le_bytes());
        }
    }
    let mut data = vec![
        0;
        growth
            .checked_add(old.len())
            .ok_or_else(|| invalid("file size overflow"))?
    ];
    data[growth..].copy_from_slice(&old);
    data[..32].copy_from_slice(&old[..32]);
    data[104..104 + header_end - 32].copy_from_slice(&old[32..header_end]);
    let mut name = [0; 16];
    name[..11].copy_from_slice(b"__DYLEX_HDR");
    let segment = SegmentCommand64 {
        cmd: LC_SEGMENT_64,
        cmdsize: 72,
        segname: name,
        vmaddr: header_vm,
        vmsize: growth as u64,
        fileoff: 0,
        filesize: growth as u64,
        maxprot: 1,
        initprot: 1,
        nsects: 0,
        flags: 0,
    };
    data[32..104].copy_from_slice(segment.as_bytes());
    data[16..20].copy_from_slice(&(ctx.macho.header.ncmds + 1).to_le_bytes());
    data[20..24].copy_from_slice(&(ctx.macho.header.sizeofcmds + 72).to_le_bytes());
    ctx.macho.data = data;
    ctx.macho.refresh()?;
    ctx.info("Moved analysis header to __DYLEX_HDR; original code addresses preserved");
    Ok(())
}
