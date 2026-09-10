//! Materialize file-backed image segments through VM mappings. Subcache file
//! offsets are local to each file and can overlap; they are not output offsets.
use crate::macho::*;
use crate::{DyldContext, Error, MachOContext, Result};
use zerocopy::IntoBytes;

/// Copies image segments into a compact, non-overlapping buffer. When rebuilding
/// LINKEDIT, its original offsets remain in commands until the optimizer reads
/// them through the source cache, avoiding a copy of the entire shared LINKEDIT.
pub fn materialize_image(
    cache: &DyldContext,
    address: u64,
    copy_linkedit: bool,
) -> Result<MachOContext> {
    let header = cache.image_header(address)?;
    let mut data = header.data.clone();
    let segments: Vec<_> = header.segments().cloned().collect();
    let mut cursor = 0usize;
    let mut linkedit_move = None;
    for seg in segments
        .iter()
        .filter(|s| s.name() != "__LINKEDIT")
        .chain(segments.iter().filter(|s| s.name() == "__LINKEDIT"))
    {
        if seg.name() == "__LINKEDIT" && !copy_linkedit {
            continue;
        }
        let size = usize::try_from(seg.command.filesize).map_err(|_| Error::Parse {
            offset: seg.command_offset,
            reason: "segment size overflow".into(),
        })?;
        // A zero-sized segment (including an empty marker) has no backing bytes.
        if size == 0 {
            continue;
        }
        let new_off = cursor;
        cursor = cursor.checked_add(size).ok_or(Error::Parse {
            offset: seg.command_offset,
            reason: "image size overflow".into(),
        })?;
        if cursor > u32::MAX as usize {
            return Err(Error::Parse {
                offset: seg.command_offset,
                reason: "extracted file exceeds Mach-O 32-bit offsets".into(),
            });
        }
        data.resize(cursor.max(header.data.len()), 0);
        cache.copy_data_at_addr(seg.command.vmaddr, &mut data[new_off..cursor])?;
        let mut cmd = seg.command;
        cmd.fileoff = new_off as u64;
        data[seg.command_offset..seg.command_offset + SegmentCommand64::SIZE]
            .copy_from_slice(cmd.as_bytes());
        for section in &seg.sections {
            let mut sect = section.section;
            if sect.offset != 0 {
                let delta = sect.addr.checked_sub(cmd.vmaddr).ok_or(Error::Parse {
                    offset: section.struct_offset,
                    reason: "section before segment".into(),
                })?;
                sect.offset = u32::try_from(new_off as u64 + delta).map_err(|_| Error::Parse {
                    offset: section.struct_offset,
                    reason: "section offset overflow".into(),
                })?;
            }
            data[section.struct_offset..section.struct_offset + Section64::SIZE]
                .copy_from_slice(sect.as_bytes());
        }
        if seg.name() == "__LINKEDIT" {
            linkedit_move = Some((seg.command.fileoff, new_off as u64));
        }
    }
    // Preserve header changes even if source segments use nonzero file offsets.
    let mut macho = MachOContext::new(&data, 0)?;
    if let Some((old, new)) = linkedit_move {
        relocate_linkedit_offsets(&mut macho, old, new)?;
        macho.refresh()?;
    }
    Ok(macho)
}

fn relocate_linkedit_offsets(macho: &mut MachOContext, old: u64, new: u64) -> Result<()> {
    let mut fields = Vec::new();
    for lc in &macho.load_commands {
        let off = lc.offset();
        match lc {
            LoadCommandInfo::Symtab { .. } => fields.extend([off + 8, off + 16]),
            LoadCommandInfo::Dysymtab { .. } => {
                fields.extend([32, 40, 48, 56, 64, 72].map(|i| off + i))
            }
            LoadCommandInfo::DyldInfo { .. } => fields.extend([8, 16, 24, 32, 40].map(|i| off + i)),
            LoadCommandInfo::LinkeditData { .. } => fields.push(off + 8),
            _ => {}
        }
    }
    for off in fields {
        let value = macho.read_u32(off)?;
        if value != 0 {
            let adjusted = (value as u64)
                .checked_sub(old)
                .and_then(|delta| new.checked_add(delta))
                .and_then(|value| u32::try_from(value).ok())
                .ok_or(Error::Parse {
                    offset: off,
                    reason: "LINKEDIT offset outside source segment".into(),
                })?;
            macho.write_u32(off, adjusted)?;
        }
    }
    Ok(())
}
