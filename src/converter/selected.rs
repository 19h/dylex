//! Explicit-image analysis merge: keep source virtual addresses and instruction
//! bytes; combine sections, symbols and indirect tables before cache/ObjC repair.
use super::*;
use crate::{DyldContext, Error, MachOContext, Result, macho::*};
use std::{collections::HashSet, path::Path, sync::Arc};
use zerocopy::{FromBytes, IntoBytes};

fn invalid(reason: &str) -> Error {
    Error::Parse {
        offset: 0,
        reason: reason.into(),
    }
}
fn u32size(n: usize) -> Result<u32> {
    u32::try_from(n).map_err(|_| invalid("merged file exceeds Mach-O 32-bit limits"))
}
fn bytes(data: &[u8], offset: u64, size: u64) -> Result<&[u8]> {
    if size == 0 {
        return Ok(&[]);
    }
    let end = offset
        .checked_add(size)
        .ok_or_else(|| invalid("merged source extent overflow"))?;
    data.get(
        usize::try_from(offset).map_err(|_| invalid("offset overflow"))?
            ..usize::try_from(end).map_err(|_| invalid("offset overflow"))?,
    )
    .ok_or_else(|| invalid("merged source data out of bounds"))
}
fn name(s: &str) -> [u8; 16] {
    let mut result = [0; 16];
    let n = s.len().min(16);
    result[..n].copy_from_slice(&s.as_bytes()[..n]);
    result
}
fn indirect_section(s: &Section64) -> bool {
    matches!(
        s.flags & SECTION_TYPE,
        S_SYMBOL_STUBS
            | S_NON_LAZY_SYMBOL_POINTERS
            | S_LAZY_SYMBOL_POINTERS
            | S_LAZY_DYLIB_SYMBOL_POINTERS
            | S_THREAD_LOCAL_VARIABLE_POINTERS
    )
}

/// Resolve exactly the primary image and requested additions, preserving order
/// and deduplicating canonical paths. Does not traverse dependencies.
pub fn selected_merge_images(
    cache: &DyldContext,
    primary: &str,
    additions: &[String],
) -> Result<Vec<String>> {
    let mut seen = HashSet::new();
    let mut paths = Vec::new();
    for query in std::iter::once(primary).chain(additions.iter().map(String::as_str)) {
        let path = &cache.resolve_image(query)?.path;
        if seen.insert(path.clone()) {
            paths.push(path.clone());
        }
    }
    Ok(paths)
}

/// Merge explicit images into one static-analysis Mach-O at original cache VAs.
/// Shared stubs/dispatchers and reconstructed ObjC metadata are added once for
/// the combined image. This does not reconstruct a runnable dylib.
pub fn extract_image_with_selected_images<P: AsRef<Path>>(
    cache: &Arc<DyldContext>,
    primary: &str,
    additions: &[String],
    output: P,
    verbosity: u8,
) -> Result<()> {
    let paths = selected_merge_images(cache, primary, additions)?;
    // Enforce predictable format limits before copying any image payload.
    let mut original_sections = 0usize;
    let mut original_bytes = 0u64;
    for path in &paths {
        let source = cache.image_header(cache.resolve_image(path)?.address)?;
        for segment in source.segments().filter(|s| s.name() != "__LINKEDIT") {
            original_sections = original_sections
                .checked_add(
                    segment
                        .sections
                        .iter()
                        .filter(|s| s.section.size != 0)
                        .count(),
                )
                .ok_or_else(|| invalid("section count overflow"))?;
            original_bytes = original_bytes
                .checked_add(segment.command.filesize)
                .ok_or_else(|| invalid("selected size overflow"))?;
        }
    }
    if original_sections > 255 {
        return Err(invalid(
            "selected merge exceeds 255 nonempty Mach-O symbol sections; select fewer images",
        ));
    }
    if original_bytes > u32::MAX as u64 {
        return Err(invalid(
            "selected segments exceed Mach-O 32-bit file offsets",
        ));
    }
    let mut images = Vec::new();
    for path in &paths {
        let image = cache.resolve_image(path)?;
        let macho = materialize_image(cache, image.address, false)?;
        let mut ctx = ExtractionContext::new(Arc::clone(cache), macho, path.clone(), image.address)
            .with_verbosity(verbosity);
        fix_header_and_load_commands(&mut ctx)?;
        process_slide_info(&mut ctx)?;
        optimize_linkedit(&mut ctx)?;
        // Keep branch/stub instructions unchanged: merged targets remain at
        // source VAs. Slide processing restores the corresponding pointer slots.
        images.push(ctx.macho);
    }
    let min_vm = cache
        .mappings
        .iter()
        .map(|m| m.address)
        .min()
        .ok_or_else(|| invalid("empty cache"))?;
    let macho = combine_images(&images, min_vm)?;
    let mut ctx = ExtractionContext::new(
        Arc::clone(cache),
        macho,
        paths[0].clone(),
        cache.resolve_image(&paths[0])?.address,
    )
    .with_verbosity(verbosity);
    include_cache_support(&mut ctx)?;
    fix_objc(&mut ctx)?;
    let writes = optimize_offsets(&mut ctx)?;
    write_macho(&ctx, &writes, output)
}

struct Symbol {
    entry: Nlist64,
    name: Vec<u8>,
    alias: Option<Vec<u8>>,
}
struct Segment {
    command: SegmentCommand64,
    sections: Vec<Section64>,
    data: Vec<u8>,
}

fn combine_images(images: &[MachOContext], min_vm: u64) -> Result<MachOContext> {
    let mut segments = Vec::<Segment>::new();
    let mut symbols = Vec::<Symbol>::new();
    let mut indirect = Vec::<u32>::new();
    let mut commands = Vec::<Vec<u8>>::new();
    let mut dylibs = HashSet::new();
    let mut section_count = 0usize;
    let mut data_in_code = Vec::<(u64, [u8; 4])>::new();
    let mut ranges = Vec::<(u64, u64)>::new();
    for (index, image) in images.iter().enumerate() {
        if image.header.cputype != images[0].header.cputype
            || image.header.cpusubtype != images[0].header.cpusubtype
        {
            return Err(invalid("cannot merge different CPU types"));
        }
        // Cache optimization leaves empty section markers behind. Keep an
        // empty marker only when an nlist still refers to it, and remap all
        // source ordinals explicitly rather than shifting them by a fixed base.
        let mut referenced_sections = HashSet::new();
        for lc in &image.load_commands {
            if let LoadCommandInfo::Symtab { command, .. } = lc {
                for n in bytes(
                    &image.data,
                    command.symoff as u64,
                    command.nsyms as u64 * 16,
                )?
                .chunks_exact(16)
                {
                    if n[5] != 0 {
                        referenced_sections.insert(n[5] as usize);
                    }
                }
            }
        }
        let mut section_remap = vec![0usize];
        let indirect_base = u32size(indirect.len())?;
        let symbol_base = u32size(symbols.len())?;
        for seg in image.segments().filter(|s| s.name() != "__LINKEDIT") {
            let mut command = seg.command;
            let end = command
                .vmaddr
                .checked_add(command.vmsize)
                .ok_or_else(|| invalid("segment VM extent overflow"))?;
            if command.vmsize != 0 {
                if ranges.iter().any(|&(a, b)| command.vmaddr < b && end > a) {
                    return Err(invalid("selected image segments overlap"));
                }
                ranges.push((command.vmaddr, end));
            }
            if command.filesize > command.vmsize {
                return Err(invalid("segment filesize exceeds vmsize"));
            }
            if index != 0 {
                command.segname = name(&format!(
                    "__M{index}_{}",
                    seg.name().trim_start_matches('_')
                ));
            }
            let mut sections = Vec::new();
            for s in &seg.sections {
                let source_ordinal = section_remap.len();
                if s.section.size == 0 && !referenced_sections.contains(&source_ordinal) {
                    section_remap.push(0);
                    continue;
                }
                section_remap.push(section_count + 1);
                let mut section = s.section;
                section.segname = command.segname;
                if section.addr < command.vmaddr
                    || section
                        .addr
                        .checked_add(section.size)
                        .is_none_or(|e| e > end)
                {
                    return Err(invalid("section outside segment"));
                }
                if indirect_section(&section) {
                    section.reserved1 = section
                        .reserved1
                        .checked_add(indirect_base)
                        .ok_or_else(|| invalid("indirect index overflow"))?;
                }
                if section.nreloc != 0 {
                    return Err(invalid(
                        "selected merge does not support section relocation tables",
                    ));
                }
                sections.push(section);
                section_count += 1;
            }
            if section_count > 255 {
                return Err(invalid(
                    "selected merge exceeds 255 symbol sections after removing unused empty sections; select fewer images",
                ));
            }
            command.nsects = u32size(sections.len())?;
            command.cmdsize = u32size(SegmentCommand64::SIZE + sections.len() * Section64::SIZE)?;
            segments.push(Segment {
                command,
                sections,
                data: bytes(&image.data, command.fileoff, command.filesize)?.to_vec(),
            });
        }
        let original_nsyms = image
            .load_commands
            .iter()
            .find_map(|lc| match lc {
                LoadCommandInfo::Symtab { command, .. } => Some(command.nsyms),
                _ => None,
            })
            .unwrap_or(0);
        let mut defined = HashSet::new();
        for lc in &image.load_commands {
            match lc {
                LoadCommandInfo::Symtab { command: c, .. } => {
                    let strings = bytes(&image.data, c.stroff as u64, c.strsize as u64)?;
                    for raw in
                        bytes(&image.data, c.symoff as u64, c.nsyms as u64 * 16)?.chunks_exact(16)
                    {
                        let (mut entry, _) = Nlist64::read_from_prefix(raw).unwrap();
                        let tail = strings
                            .get(entry.n_strx as usize..)
                            .ok_or_else(|| invalid("symbol name index outside string table"))?;
                        let end = tail
                            .iter()
                            .position(|b| *b == 0)
                            .ok_or_else(|| invalid("unterminated symbol name"))?;
                        let alias = if entry.n_type & N_STAB == 0 && entry.n_type & N_TYPE == N_INDR
                        {
                            let tail = strings
                                .get(
                                    usize::try_from(entry.n_value)
                                        .map_err(|_| invalid("alias index overflow"))?..,
                                )
                                .ok_or_else(|| invalid("alias index outside string table"))?;
                            let end = tail
                                .iter()
                                .position(|b| *b == 0)
                                .ok_or_else(|| invalid("unterminated alias target"))?;
                            Some(tail[..end].to_vec())
                        } else {
                            None
                        };
                        if entry.n_sect != 0 {
                            let ordinal = *section_remap
                                .get(entry.n_sect as usize)
                                .filter(|ordinal| **ordinal != 0)
                                .ok_or_else(|| invalid("symbol section ordinal out of bounds"))?;
                            entry.n_sect = u8::try_from(ordinal).map_err(|_| invalid("symbol section ordinal exceeds 255 after removing unused empty sections"))?;
                        }
                        if entry.n_type & N_STAB == 0 && entry.n_type & N_TYPE == N_PBUD {
                            entry.n_type = (entry.n_type & !N_TYPE) | N_UNDF;
                            entry.n_value = 0;
                        }
                        if entry.n_type & N_STAB == 0 && entry.n_type & N_TYPE == N_UNDF {
                            entry.n_desc = (entry.n_desc & 0xff) | 0xfe00; // flat lookup, not a stale source dylib ordinal
                        } else {
                            defined.insert(entry.n_value);
                        }
                        symbols.push(Symbol {
                            entry,
                            name: tail[..end].to_vec(),
                            alias,
                        });
                    }
                }
                LoadCommandInfo::Dysymtab { command: c, .. } => {
                    for raw in bytes(
                        &image.data,
                        c.indirectsymoff as u64,
                        c.nindirectsyms as u64 * 4,
                    )?
                    .chunks_exact(4)
                    {
                        let old = u32::from_le_bytes(raw.try_into().unwrap());
                        indirect.push(
                            if old & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS) != 0 {
                                old
                            } else {
                                if old >= original_nsyms {
                                    return Err(invalid(
                                        "source indirect symbol index out of bounds",
                                    ));
                                }
                                old.checked_add(symbol_base)
                                    .ok_or_else(|| invalid("symbol index overflow"))?
                            },
                        );
                    }
                }
                LoadCommandInfo::Dylib { command, name, .. }
                    if command.cmd != LC_ID_DYLIB || index == 0 =>
                {
                    if command.cmd == LC_ID_DYLIB || dylibs.insert(name.clone()) {
                        commands.push(
                            bytes(&image.data, lc.offset() as u64, lc.size() as u64)?.to_vec(),
                        );
                    }
                }
                LoadCommandInfo::Uuid { .. } | LoadCommandInfo::BuildVersion { .. }
                    if index == 0 =>
                {
                    commands
                        .push(bytes(&image.data, lc.offset() as u64, lc.size() as u64)?.to_vec())
                }
                LoadCommandInfo::LinkeditData { command: c, .. } if c.cmd == LC_DATA_IN_CODE => {
                    if c.datasize % 8 != 0 {
                        return Err(invalid("invalid data-in-code table size"));
                    }
                    for raw in
                        bytes(&image.data, c.dataoff as u64, c.datasize as u64)?.chunks_exact(8)
                    {
                        let offset = u32::from_le_bytes(raw[..4].try_into().unwrap()) as u64;
                        let seg = image
                            .segments()
                            .find(|s| {
                                offset >= s.command.fileoff
                                    && offset - s.command.fileoff < s.command.filesize
                            })
                            .ok_or_else(|| invalid("data-in-code entry outside segments"))?;
                        data_in_code.push((
                            seg.command.vmaddr + offset - seg.command.fileoff,
                            raw[4..].try_into().unwrap(),
                        ));
                    }
                }
                _ => {}
            }
        }
        // Represent starts below the primary __TEXT too: LC_FUNCTION_STARTS
        // cannot encode negative deltas, while N_SECT function labels can.
        for lc in &image.load_commands {
            if let LoadCommandInfo::LinkeditData { command: c, .. } = lc {
                if c.cmd != LC_FUNCTION_STARTS || c.datasize == 0 {
                    continue;
                }
                let mut encoded = bytes(&image.data, c.dataoff as u64, c.datasize as u64)?;
                let mut address = image
                    .text_segment()
                    .ok_or_else(|| invalid("no source TEXT segment"))?
                    .command
                    .vmaddr;
                while !encoded.is_empty() {
                    let (delta, n) = crate::dyld::read_uleb128(encoded)?;
                    encoded = &encoded[n..];
                    if delta == 0 {
                        break;
                    }
                    address = address
                        .checked_add(delta)
                        .ok_or_else(|| invalid("function address overflow"))?;
                    if defined.contains(&address) {
                        continue;
                    }
                    let ordinal = segments
                        .iter()
                        .flat_map(|s| &s.sections)
                        .position(|s| address >= s.addr && address - s.addr < s.size)
                        .ok_or_else(|| invalid("function start outside selected sections"))?
                        + 1;
                    symbols.push(Symbol {
                        entry: Nlist64 {
                            n_strx: 0,
                            n_type: N_SECT,
                            n_sect: ordinal as u8,
                            n_desc: 0,
                            n_value: address,
                        },
                        name: format!("sub_{address:X}").into_bytes(),
                        alias: None,
                    });
                }
            }
        }
    }
    // Mach-O dynamic symbol groups must be contiguous. Remap every indirect
    // entry after stable grouping, including per-image synthetic start labels.
    let class = |s: &Symbol| {
        if s.entry.n_type & N_STAB == 0 && s.entry.n_type & N_TYPE == N_UNDF {
            2
        } else if s.entry.n_type & N_STAB == 0 && s.entry.n_type & N_EXT != 0 {
            1
        } else {
            0
        }
    };
    let mut order: Vec<_> = (0..symbols.len()).collect();
    order.sort_by_key(|&i| class(&symbols[i]));
    let mut remap = vec![0u32; symbols.len()];
    let mut counts = [0u32; 3];
    let mut linkedit = Vec::new();
    let mut strings = vec![0];
    for (new, &old) in order.iter().enumerate() {
        remap[old] = u32size(new)?;
        counts[class(&symbols[old])] += 1;
        let mut entry = symbols[old].entry;
        entry.n_strx = u32size(strings.len())?;
        strings.extend_from_slice(&symbols[old].name);
        strings.push(0);
        if let Some(alias) = &symbols[old].alias {
            entry.n_value = u32size(strings.len())? as u64;
            strings.extend_from_slice(alias);
            strings.push(0);
        }
        linkedit.extend_from_slice(entry.as_bytes());
    }
    let indirect_offset = u32size(linkedit.len())?;
    for i in &indirect {
        let value = if i & (INDIRECT_SYMBOL_LOCAL | INDIRECT_SYMBOL_ABS) != 0 {
            *i
        } else {
            *remap
                .get(*i as usize)
                .ok_or_else(|| invalid("indirect symbol index out of bounds"))?
        };
        linkedit.extend_from_slice(&value.to_le_bytes());
    }
    let string_offset = u32size(linkedit.len())?;
    linkedit.extend_from_slice(&strings);
    while linkedit.len() % 8 != 0 {
        linkedit.push(0);
    }
    let dic_offset = u32size(linkedit.len())?;
    // Header capacity includes all final commands; later support imports use the
    // existing safe header-growth path if this padding is exhausted.
    let command_size = 2 * SegmentCommand64::SIZE
        + 24
        + 80
        + 16
        + commands.iter().map(Vec::len).sum::<usize>()
        + segments
            .iter()
            .map(|s| 72 + s.sections.len() * 80)
            .sum::<usize>();
    let header_size = (32 + command_size + 0xffff) & !0xffff;
    let header_vm = min_vm
        .checked_sub(header_size as u64)
        .ok_or_else(|| invalid("no address space for merged header"))?;
    let mut data = vec![0; header_size];
    let mut segment_commands = Vec::new();
    for segment in &mut segments {
        let old = segment.command.fileoff;
        segment.command.fileoff = if segment.data.is_empty() {
            0
        } else {
            data.len() as u64
        };
        for section in &mut segment.sections {
            if section.offset != 0 {
                let delta = (section.offset as u64)
                    .checked_sub(old)
                    .ok_or_else(|| invalid("section file offset before segment"))?;
                if delta
                    .checked_add(section.size)
                    .is_none_or(|e| e > segment.command.filesize)
                {
                    return Err(invalid("section file extent outside segment"));
                }
                section.offset = u32size(segment.command.fileoff as usize + delta as usize)?;
            }
        }
        segment_commands.push(segment.command.as_bytes().to_vec());
        for s in &segment.sections {
            segment_commands
                .last_mut()
                .unwrap()
                .extend_from_slice(s.as_bytes());
        }
        data.extend_from_slice(&segment.data);
        u32size(data.len())?;
    }
    for (address, tail) in data_in_code {
        let segment = segments
            .iter()
            .find(|s| {
                address >= s.command.vmaddr && address - s.command.vmaddr < s.command.filesize
            })
            .ok_or_else(|| invalid("data-in-code address missing"))?;
        let offset =
            u32size((segment.command.fileoff + address - segment.command.vmaddr) as usize)?;
        linkedit.extend_from_slice(&offset.to_le_bytes());
        linkedit.extend_from_slice(&tail);
    }
    let linkoff = u32size(data.len())?;
    let linksize = u32size(linkedit.len())?;
    let link_vm = header_vm
        .checked_sub((linksize as u64 + 0x3fff) & !0x3fff)
        .ok_or_else(|| invalid("no address space for merged LINKEDIT"))?;
    let header_segment = SegmentCommand64 {
        cmd: LC_SEGMENT_64,
        cmdsize: 72,
        segname: name("__DYLEX_HDR"),
        vmaddr: header_vm,
        vmsize: header_size as u64,
        fileoff: 0,
        filesize: header_size as u64,
        maxprot: 1,
        initprot: 1,
        nsects: 0,
        flags: 0,
    };
    let link_segment = SegmentCommand64 {
        segname: name("__LINKEDIT"),
        vmaddr: link_vm,
        vmsize: linksize as u64,
        fileoff: linkoff as u64,
        filesize: linksize as u64,
        ..header_segment
    };
    let symtab = SymtabCommand {
        cmd: LC_SYMTAB,
        cmdsize: 24,
        symoff: linkoff,
        nsyms: u32size(symbols.len())?,
        stroff: linkoff
            .checked_add(string_offset)
            .ok_or_else(|| invalid("string offset overflow"))?,
        strsize: u32size(strings.len())?,
    };
    let dysymtab = DysymtabCommand {
        cmd: LC_DYSYMTAB,
        cmdsize: 80,
        ilocalsym: 0,
        nlocalsym: counts[0],
        iextdefsym: counts[0],
        nextdefsym: counts[1],
        iundefsym: counts[0] + counts[1],
        nundefsym: counts[2],
        indirectsymoff: linkoff
            .checked_add(indirect_offset)
            .ok_or_else(|| invalid("indirect offset overflow"))?,
        nindirectsyms: u32size(indirect.len())?,
        ..Default::default()
    };
    let dic = LinkeditDataCommand {
        cmd: LC_DATA_IN_CODE,
        cmdsize: 16,
        dataoff: linkoff
            .checked_add(dic_offset)
            .ok_or_else(|| invalid("data-in-code offset overflow"))?,
        datasize: linksize - dic_offset,
    };
    let mut all = vec![header_segment.as_bytes().to_vec()];
    all.extend(segment_commands);
    all.push(link_segment.as_bytes().to_vec());
    all.extend(commands);
    all.extend([
        symtab.as_bytes().to_vec(),
        dysymtab.as_bytes().to_vec(),
        dic.as_bytes().to_vec(),
    ]);
    let mut header = images[0].header;
    header.ncmds = u32size(all.len())?;
    header.sizeofcmds = u32size(all.iter().map(Vec::len).sum())?;
    header.flags &= !(0x8000_0000 | 0x80); // MH_DYLIB_IN_CACHE | MH_TWOLEVEL
    data[..32].copy_from_slice(header.as_bytes());
    let mut cursor = 32;
    for cmd in all {
        data[cursor..cursor + cmd.len()].copy_from_slice(&cmd);
        cursor += cmd.len();
    }
    data.extend_from_slice(&linkedit);
    u32size(data.len())?;
    MachOContext::new(&data, 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn many_section_image(base: u64, referenced_empty: bool) -> MachOContext {
        let mut data = vec![0u8; 0x10100];
        let text = SegmentCommand64 {
            cmd: LC_SEGMENT_64,
            cmdsize: 72 + 200 * 80,
            segname: name("__TEXT"),
            vmaddr: base,
            vmsize: 0x10000,
            fileoff: 0,
            filesize: 0x10000,
            maxprot: 5,
            initprot: 5,
            nsects: 200,
            flags: 0,
        };
        let mut commands = text.as_bytes().to_vec();
        for i in 0..200 {
            let populated = i == 199;
            let section = Section64 {
                sectname: name(if populated { "__text" } else { "__empty" }),
                segname: name("__TEXT"),
                addr: base + if populated { 0x5000 } else { 0x6000 },
                size: if populated { 16 } else { 0 },
                offset: if populated { 0x5000 } else { 0 },
                align: 2,
                reloff: 0,
                nreloc: 0,
                flags: if populated {
                    S_ATTR_PURE_INSTRUCTIONS
                } else {
                    0
                },
                reserved1: 0,
                reserved2: 0,
                reserved3: 0,
            };
            commands.extend_from_slice(section.as_bytes());
        }
        let link = SegmentCommand64 {
            cmd: LC_SEGMENT_64,
            cmdsize: 72,
            segname: name("__LINKEDIT"),
            vmaddr: base + 0x20000,
            vmsize: 0x100,
            fileoff: 0x10000,
            filesize: 0x100,
            maxprot: 1,
            initprot: 1,
            nsects: 0,
            flags: 0,
        };
        commands.extend_from_slice(link.as_bytes());
        let symtab = SymtabCommand {
            cmd: LC_SYMTAB,
            cmdsize: 24,
            symoff: 0x10000,
            nsyms: if referenced_empty { 2 } else { 1 },
            stroff: 0x10040,
            strsize: 19,
        };
        commands.extend_from_slice(symtab.as_bytes());
        let header = MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64E,
            filetype: 6,
            ncmds: 3,
            sizeofcmds: commands.len() as u32,
            flags: 0,
            reserved: 0,
        };
        data[..32].copy_from_slice(header.as_bytes());
        data[32..32 + commands.len()].copy_from_slice(&commands);
        let symbol = Nlist64 {
            n_strx: 1,
            n_type: N_SECT,
            n_sect: 200,
            n_desc: 0,
            n_value: base + 0x5000,
        };
        data[0x10000..0x10010].copy_from_slice(symbol.as_bytes());
        if referenced_empty {
            let symbol = Nlist64 {
                n_strx: 11,
                n_type: N_SECT,
                n_sect: 1,
                n_desc: 0,
                n_value: base + 0x6000,
            };
            data[0x10010..0x10020].copy_from_slice(symbol.as_bytes());
        }
        data[0x10040..0x10053].copy_from_slice(b"\0_function\0_empty\0\0");
        data[0x5000..0x5010].fill(0x5a);
        MachOContext::new(&data, 0).unwrap()
    }
    #[test]
    fn more_than_255_source_sections_compact_without_losing_referenced_empty_sections() {
        let images = [
            many_section_image(0x180010000, false),
            many_section_image(0x180110000, true),
        ];
        let merged = combine_images(&images, 0x180000000).unwrap();
        assert_eq!(
            merged.segments().map(|s| s.sections.len()).sum::<usize>(),
            3
        );
        let table = merged
            .load_commands
            .iter()
            .find_map(|lc| {
                if let LoadCommandInfo::Symtab { command, .. } = lc {
                    Some(command)
                } else {
                    None
                }
            })
            .unwrap();
        assert_eq!(table.nsyms, 3);
        let ordinals: Vec<_> = merged.data[table.symoff as usize..table.symoff as usize + 48]
            .chunks_exact(16)
            .map(|n| n[5])
            .collect();
        assert_eq!(ordinals, [1, 3, 2]);
        for address in [0x180015000, 0x180115000] {
            let off = merged.addr_to_offset(address).unwrap();
            assert_eq!(&merged.data[off..off + 16], &[0x5a; 16]);
        }
    }
}
