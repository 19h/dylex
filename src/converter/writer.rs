//! File writer for assembled Mach-O output.
//!
//! # Performance
//!
//! Uses memory-mapped I/O for large files to avoid intermediate buffer allocation.
//! Falls back to buffered I/O for smaller files where mmap overhead isn't worth it.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;

use memmap2::MmapMut;

use crate::error::{Error, Result};
use crate::macho::{
    LC_CODE_SIGNATURE, LC_DATA_IN_CODE, LC_DYLD_CHAINED_FIXUPS, LC_DYLD_EXPORTS_TRIE, LC_DYLD_INFO,
    LC_DYLD_INFO_ONLY, LC_DYSYMTAB, LC_FUNCTION_STARTS, LC_SEGMENT_SPLIT_INFO, LC_SYMTAB,
};

use super::{ExtractionContext, WriteProcedure, WriteSource};

/// Threshold for using mmap vs buffered I/O (1MB)
const MMAP_THRESHOLD: u64 = 1024 * 1024;

/// Page size for alignment.
#[allow(dead_code)]
const PAGE_SIZE: u64 = 0x4000;

/// Optimizes file offsets and generates write procedures.
///
/// This function computes new, compact file offsets for all segments
/// and updates the segment commands in the Mach-O to reflect these new offsets.
///
/// The TEXT segment starts at file offset 0 (standard Mach-O layout where
/// the header is part of the TEXT segment). The header and load commands
/// are written as part of the TEXT segment, not separately.
pub fn optimize_offsets(ctx: &mut ExtractionContext) -> Result<Vec<WriteProcedure>> {
    ctx.info("Optimizing file offsets...");

    let mut procedures = Vec::new();
    let header_size = (ctx.macho.header_size() + ctx.macho.header.sizeofcmds as usize) as u64;
    let segments: Vec<_> = ctx
        .macho
        .segments()
        .filter(|s| s.command.filesize > 0)
        .cloned()
        .collect();
    let mut old_linkedit_off = None;
    let mut new_linkedit_off = None;
    let mut write_offset = 0u64;
    for (index, segment) in segments.iter().enumerate() {
        let old_fileoff = segment.command.fileoff;
        let filesize = segment.command.filesize;
        if segment.name() == "__LINKEDIT" {
            old_linkedit_off = Some(old_fileoff);
            new_linkedit_off = Some(write_offset);
        }
        if index == 0 {
            let remainder = filesize.checked_sub(header_size).ok_or(Error::Parse {
                offset: segment.command_offset,
                reason: "first segment smaller than header".into(),
            })?;
            procedures.push(WriteProcedure::from_macho(0, 0, header_size));
            if remainder != 0 {
                procedures.push(WriteProcedure::from_macho(
                    header_size,
                    old_fileoff + header_size,
                    remainder,
                ));
            }
        } else {
            procedures.push(WriteProcedure::from_macho(
                write_offset,
                old_fileoff,
                filesize,
            ));
        }
        let mut command = segment.command;
        command.fileoff = write_offset;
        ctx.macho.write_segment(segment.command_offset, &command)?;
        for section in &segment.sections {
            let mut record = section.section;
            if record.offset != 0 {
                record.offset = (record.offset as u64)
                    .checked_sub(old_fileoff)
                    .and_then(|delta| write_offset.checked_add(delta))
                    .and_then(|value| u32::try_from(value).ok())
                    .ok_or(Error::Parse {
                        offset: section.struct_offset,
                        reason: "section offset overflow".into(),
                    })?;
            }
            ctx.macho.write_section(section.struct_offset, &record)?;
        }
        write_offset = write_offset.checked_add(filesize).ok_or(Error::Parse {
            offset: segment.command_offset,
            reason: "output size overflow".into(),
        })?;
    }

    // Add extra segment if present
    if ctx.has_extra_segment() {
        procedures.push(WriteProcedure::from_extra(
            write_offset,
            0,
            ctx.extra_segment_size() as u64,
        ));
        // Note: write_offset not updated here as it's the final segment
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
    let mut offset = ctx.macho.header_size(); // Start after mach_header_64
    let end_offset = ctx.macho.header_size() + ctx.macho.header.sizeofcmds as usize;

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
///
/// # Performance
///
/// For files larger than 1MB, uses memory-mapped I/O to avoid allocating
/// a large intermediate buffer. This reduces memory usage and can improve
/// throughput on systems with fast storage.
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

    // Calculate total size and round up to page boundary
    // Apple's dsc_extractor pads the file to page alignment (4096 bytes)
    let content_size = procedures
        .iter()
        .map(|p| p.write_offset + p.size)
        .max()
        .unwrap_or(0);

    // Round up to page boundary (4096 bytes)
    let page_size = 4096u64;
    let total_size = (content_size + page_size - 1) & !(page_size - 1);

    // Use mmap for large files, buffered I/O for small files
    if total_size >= MMAP_THRESHOLD {
        write_macho_mmap(ctx, procedures, path, total_size)
    } else {
        write_macho_buffered(ctx, procedures, path, total_size)
    }
}

/// Write using memory-mapped I/O (for large files).
#[inline(never)]
fn write_macho_mmap(
    ctx: &ExtractionContext,
    procedures: &[WriteProcedure],
    path: &Path,
    total_size: u64,
) -> Result<()> {
    // Create and set file size
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .map_err(|e| Error::FileWrite {
            path: path.to_path_buf(),
            source: e,
        })?;

    file.set_len(total_size).map_err(|e| Error::FileWrite {
        path: path.to_path_buf(),
        source: e,
    })?;

    // Memory map the file
    let mut mmap = unsafe {
        MmapMut::map_mut(&file).map_err(|e| Error::FileWrite {
            path: path.to_path_buf(),
            source: std::io::Error::new(std::io::ErrorKind::Other, e),
        })?
    };

    // Execute write procedures directly to mmap
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
        if dst_end <= mmap.len() {
            mmap[dst_start..dst_end].copy_from_slice(src_data);
        }
    }

    // Flush to disk
    mmap.flush().map_err(|e| Error::FileWrite {
        path: path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

/// Write using buffered I/O (for small files).
#[inline(never)]
fn write_macho_buffered(
    ctx: &ExtractionContext,
    procedures: &[WriteProcedure],
    path: &Path,
    total_size: u64,
) -> Result<()> {
    let file = File::create(path).map_err(|e| Error::FileWrite {
        path: path.to_path_buf(),
        source: e,
    })?;

    let mut writer = BufWriter::with_capacity(64 * 1024, file); // 64KB buffer

    // Pre-allocate the output buffer
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
#[allow(dead_code)]
fn align_to(value: u64, alignment: u64) -> u64 {
    (value + alignment - 1) & !(alignment - 1)
}

/// Assembles write procedures in memory, checking every source and destination.
pub(crate) fn assemble_macho(
    ctx: &ExtractionContext,
    procedures: &[WriteProcedure],
) -> Result<Vec<u8>> {
    let bad = || Error::Parse {
        offset: 0,
        reason: "Mach-O write extent out of bounds".into(),
    };
    let size = procedures.iter().try_fold(0u64, |size, p| {
        p.write_offset
            .checked_add(p.size)
            .map(|end| size.max(end))
            .ok_or_else(bad)
    })?;
    let size = size
        .checked_add(4095)
        .map(|v| v & !4095)
        .and_then(|v| usize::try_from(v).ok())
        .ok_or_else(bad)?;
    let mut output = vec![0; size];
    for p in procedures {
        let source = match p.source {
            WriteSource::Macho => &ctx.macho.data[..],
            WriteSource::ExtraSegment => &ctx.extra_segment_data[..],
            WriteSource::Cache { subcache_index } => ctx.cache.data_for_subcache(subcache_index),
        };
        let start = usize::try_from(p.read_offset).map_err(|_| bad())?;
        let len = usize::try_from(p.size).map_err(|_| bad())?;
        let end = start.checked_add(len).ok_or_else(bad)?;
        let dest = usize::try_from(p.write_offset).map_err(|_| bad())?;
        let dest_end = dest.checked_add(len).ok_or_else(bad)?;
        output
            .get_mut(dest..dest_end)
            .ok_or_else(bad)?
            .copy_from_slice(source.get(start..end).ok_or_else(bad)?);
    }
    Ok(output)
}
