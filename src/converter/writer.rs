//! File writer for assembled Mach-O output.

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

use crate::error::{Error, Result};
use crate::macho::{
    LC_CODE_SIGNATURE, LC_DATA_IN_CODE, LC_DYLD_CHAINED_FIXUPS, LC_DYLD_EXPORTS_TRIE, LC_DYLD_INFO,
    LC_DYLD_INFO_ONLY, LC_DYSYMTAB, LC_FUNCTION_STARTS, LC_SEGMENT_SPLIT_INFO, LC_SYMTAB,
};

use super::{ExtractionContext, WriteProcedure, WriteSource};

/// Page size for alignment.
const PAGE_SIZE: u64 = 0x4000;

/// Optimizes file offsets and generates write procedures.
///
/// This function computes new, compact file offsets for all segments
/// and updates the segment commands in the Mach-O to reflect these new offsets.
pub fn optimize_offsets(ctx: &mut ExtractionContext) -> Result<Vec<WriteProcedure>> {
    ctx.info("Optimizing file offsets...");

    let mut procedures = Vec::new();
    let mut write_offset = 0u64;

    // Write header and load commands from the MachOContext (which may have been modified)
    let header_size = ctx.macho.header.sizeofcmds as u64 + 32; // Header + load commands
    procedures.push(WriteProcedure::from_macho(0, 0, header_size));
    write_offset = align_to(header_size, PAGE_SIZE);

    // Collect segment info first (to avoid borrow issues)
    // Also track the old and new LINKEDIT offset
    let segment_info: Vec<(usize, u64, u64, bool, String)> = ctx
        .macho
        .segments()
        .filter(|seg| seg.command.filesize > 0)
        .map(|seg| {
            let is_linkedit = seg.name() == "__LINKEDIT";
            (
                seg.command_offset,
                seg.command.fileoff,
                seg.command.filesize,
                is_linkedit,
                seg.name().to_string(),
            )
        })
        .collect();

    let mut old_linkedit_off: Option<u64> = None;
    let mut new_linkedit_off: Option<u64> = None;

    // Process each segment - update file offsets and create write procedures
    for (cmd_offset, old_fileoff, filesize, is_linkedit, _seg_name) in segment_info {
        if is_linkedit {
            old_linkedit_off = Some(old_fileoff);
            new_linkedit_off = Some(write_offset);
        }

        // Create write procedure: read from old offset in macho buffer, write at new offset
        procedures.push(WriteProcedure::from_macho(
            write_offset,
            old_fileoff,
            filesize,
        ));

        // Update the segment command's fileoff in the Mach-O buffer
        // The fileoff field is at offset 40 within the segment command
        let fileoff_offset = cmd_offset + 40;
        ctx.macho.write_u64(fileoff_offset, write_offset)?;

        // Also update section file offsets within this segment
        // Sections start after the segment command (72 bytes) and are 80 bytes each
        let nsects_offset = cmd_offset + 64;
        let nsects = ctx.macho.read_u32(nsects_offset)? as usize;

        for i in 0..nsects {
            let section_offset = cmd_offset + 72 + i * 80;
            // Section offset field is at offset 48 within the section
            let sect_offset_field = section_offset + 48;
            let old_sect_offset = ctx.macho.read_u32(sect_offset_field)?;

            if old_sect_offset != 0 {
                // Calculate new section offset relative to the new segment offset
                let delta = old_sect_offset as u64 - old_fileoff;
                let new_sect_offset = (write_offset + delta) as u32;
                ctx.macho.write_u32(sect_offset_field, new_sect_offset)?;
            }
        }

        write_offset += filesize;
        write_offset = align_to(write_offset, PAGE_SIZE);
    }

    // Add extra segment if present
    if ctx.has_extra_segment() {
        procedures.push(WriteProcedure::from_extra(
            write_offset,
            0,
            ctx.extra_segment_size() as u64,
        ));
        write_offset += ctx.extra_segment_size() as u64;
        write_offset = align_to(write_offset, PAGE_SIZE);
    }

    // Update LINKEDIT-related load commands if LINKEDIT moved
    if let (Some(old_off), Some(new_off)) = (old_linkedit_off, new_linkedit_off) {
        if old_off != new_off {
            update_linkedit_load_commands(ctx, old_off, new_off)?;
        }
    }

    Ok(procedures)
}

/// Updates all LINKEDIT-related load commands when LINKEDIT moves.
fn update_linkedit_load_commands(
    ctx: &mut ExtractionContext,
    old_linkedit_off: u64,
    new_linkedit_off: u64,
) -> Result<()> {
    let delta = new_linkedit_off as i64 - old_linkedit_off as i64;

    // Iterate through load commands and update offsets
    let mut offset = 32usize; // Start after mach_header_64
    let end_offset = 32 + ctx.macho.header.sizeofcmds as usize;

    while offset < end_offset {
        if offset + 8 > ctx.macho.data.len() {
            break;
        }

        let cmd = ctx.macho.read_u32(offset)?;
        let cmdsize = ctx.macho.read_u32(offset + 4)?;

        match cmd {
            LC_SYMTAB => {
                // symoff at offset 8, nsyms at 12, stroff at 16, strsize at 20
                // Only update if nsyms > 0 or strsize > 0
                let nsyms = ctx.macho.read_u32(offset + 12)?;
                let strsize = ctx.macho.read_u32(offset + 20)?;
                if nsyms > 0 {
                    update_offset_field(ctx, offset + 8, delta)?; // symoff
                }
                if strsize > 0 {
                    update_offset_field(ctx, offset + 16, delta)?; // stroff
                }
            }
            LC_DYSYMTAB => {
                // Only update offset fields if their corresponding count > 0
                // tocoff/ntoc at 32/36
                if ctx.macho.read_u32(offset + 36)? > 0 {
                    update_offset_field(ctx, offset + 32, delta)?;
                }
                // modtaboff/nmodtab at 40/44
                if ctx.macho.read_u32(offset + 44)? > 0 {
                    update_offset_field(ctx, offset + 40, delta)?;
                }
                // extrefsymoff/nextrefsyms at 48/52
                if ctx.macho.read_u32(offset + 52)? > 0 {
                    update_offset_field(ctx, offset + 48, delta)?;
                }
                // indirectsymoff/nindirectsyms at 56/60
                if ctx.macho.read_u32(offset + 60)? > 0 {
                    update_offset_field(ctx, offset + 56, delta)?;
                }
                // extreloff/nextrel at 64/68
                if ctx.macho.read_u32(offset + 68)? > 0 {
                    update_offset_field(ctx, offset + 64, delta)?;
                }
                // locreloff/nlocrel at 72/76
                if ctx.macho.read_u32(offset + 76)? > 0 {
                    update_offset_field(ctx, offset + 72, delta)?;
                }
            }
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                // offset/size pairs: rebase (8/12), bind (16/20), weak_bind (24/28),
                // lazy_bind (32/36), export (40/44)
                if ctx.macho.read_u32(offset + 12)? > 0 {
                    update_offset_field(ctx, offset + 8, delta)?;
                }
                if ctx.macho.read_u32(offset + 20)? > 0 {
                    update_offset_field(ctx, offset + 16, delta)?;
                }
                if ctx.macho.read_u32(offset + 28)? > 0 {
                    update_offset_field(ctx, offset + 24, delta)?;
                }
                if ctx.macho.read_u32(offset + 36)? > 0 {
                    update_offset_field(ctx, offset + 32, delta)?;
                }
                if ctx.macho.read_u32(offset + 44)? > 0 {
                    update_offset_field(ctx, offset + 40, delta)?;
                }
            }
            LC_FUNCTION_STARTS
            | LC_DATA_IN_CODE
            | LC_CODE_SIGNATURE
            | LC_SEGMENT_SPLIT_INFO
            | LC_DYLD_EXPORTS_TRIE
            | LC_DYLD_CHAINED_FIXUPS => {
                // linkedit_data_command: dataoff at offset 8, datasize at offset 12
                let datasize = ctx.macho.read_u32(offset + 12)?;
                if datasize > 0 {
                    update_offset_field(ctx, offset + 8, delta)?;
                }
            }
            _ => {}
        }

        offset += cmdsize as usize;
    }

    Ok(())
}

/// Updates an offset field by adding a delta.
fn update_offset_field(ctx: &mut ExtractionContext, offset: usize, delta: i64) -> Result<()> {
    let old_value = ctx.macho.read_u32(offset)?;
    if old_value != 0 {
        let new_value = (old_value as i64 + delta) as u32;
        ctx.macho.write_u32(offset, new_value)?;
    }
    Ok(())
}

/// Writes the extracted Mach-O to a file.
pub fn write_macho<P: AsRef<Path>>(
    ctx: &ExtractionContext,
    procedures: &[WriteProcedure],
    output_path: P,
) -> Result<()> {
    let path = output_path.as_ref();

    // Create parent directories if needed
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| Error::FileWrite {
            path: path.to_path_buf(),
            source: e,
        })?;
    }

    let file = File::create(path).map_err(|e| Error::FileWrite {
        path: path.to_path_buf(),
        source: e,
    })?;

    let mut writer = BufWriter::new(file);

    // Calculate total size
    let total_size = procedures
        .iter()
        .map(|p| p.write_offset + p.size)
        .max()
        .unwrap_or(0);

    // Pre-allocate the file
    let mut output = vec![0u8; total_size as usize];

    // Execute write procedures
    for proc in procedures {
        let src_data = match proc.source {
            WriteSource::Cache { subcache_index } => {
                let cache_data = ctx.cache.data_for_subcache(subcache_index);
                let start = proc.read_offset as usize;
                let end = start + proc.size as usize;
                if end <= cache_data.len() {
                    &cache_data[start..end]
                } else {
                    continue;
                }
            }
            WriteSource::Macho => {
                let start = proc.read_offset as usize;
                let end = start + proc.size as usize;
                if end <= ctx.macho.data.len() {
                    &ctx.macho.data[start..end]
                } else {
                    continue;
                }
            }
            WriteSource::ExtraSegment => {
                let start = proc.read_offset as usize;
                let end = start + proc.size as usize;
                if end <= ctx.extra_segment_data.len() {
                    &ctx.extra_segment_data[start..end]
                } else {
                    continue;
                }
            }
        };

        let dst_start = proc.write_offset as usize;
        let dst_end = dst_start + src_data.len();
        if dst_end <= output.len() {
            output[dst_start..dst_end].copy_from_slice(src_data);
        }
    }

    writer.write_all(&output).map_err(|e| Error::FileWrite {
        path: path.to_path_buf(),
        source: e,
    })?;

    writer.flush().map_err(|e| Error::FileWrite {
        path: path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

/// Aligns a value to the given boundary.
#[inline]
fn align_to(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}
