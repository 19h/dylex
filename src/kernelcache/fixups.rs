//! Chained-fixup decoding for kernel collections.
//!
//! Pointer chains are decoded without modifying the collection; extraction
//! writes the decoded targets into its own copy of each segment. Chains that
//! reference another kernel collection (cache level other than 0) are rejected
//! rather than resolved against a guessed base address.

use crate::error::{Error, Result};
use crate::macho::{LC_DYLD_CHAINED_FIXUPS, LoadCommandInfo, MachOContext, SegmentInfo};

use super::reader::{read_u16, read_u32, read_u64, slice, to_usize};
use super::{KernelCacheContext, KernelImage};

/// `DYLD_CHAINED_PTR_ARM64E_KERNEL`: arm64e pointers with a 4-byte stride.
const PTR_ARM64E_KERNEL: u16 = 7;
/// `DYLD_CHAINED_PTR_64_KERNEL_CACHE`: 64-bit pointers with a 4-byte stride.
const PTR_64_KERNEL_CACHE: u16 = 8;
/// `DYLD_CHAINED_PTR_X86_64_KERNEL_CACHE`: x86-64 pointers with a 1-byte stride.
const PTR_X86_64_KERNEL_CACHE: u16 = 11;

/// `page_start` value for a page without fixups.
const PAGE_START_NONE: u16 = 0xffff;
/// `page_start` flag: the low bits index a list of chain starts.
const PAGE_START_MULTI: u16 = 0x8000;
/// Flag marking the final entry of a multi-start list.
const PAGE_START_LAST: u16 = 0x8000;

/// Size of `dyld_chained_fixups_header`.
const FIXUPS_HEADER_SIZE: usize = 28;
/// Size of `dyld_chained_starts_in_segment` before its `page_start` array.
const SEGMENT_STARTS_HEADER_SIZE: usize = 22;
/// Size of each chained pointer.
const POINTER_SIZE: u64 = 8;

/// A decoded chained pointer: its offset in the collection and its unslid target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Rebase {
    pub(super) offset: usize,
    pub(super) target: u64,
}

impl KernelCacheContext {
    /// Returns every chained pointer in the collection, sorted by offset.
    ///
    /// Decoded once and shared by all extractions.
    pub(super) fn rebases(&self) -> Result<&[Rebase]> {
        self.rebases
            .get_or_init(|| {
                self.collect_rebases().map_err(|error| match error {
                    Error::Parse { offset, reason } => (offset, reason),
                    other => (0, other.to_string()),
                })
            })
            .as_deref()
            .map_err(|(offset, reason)| Error::parse(*offset, reason.clone()))
    }

    fn collect_rebases(&self) -> Result<Vec<Rebase>> {
        let mut rebases = Vec::new();
        self.collect_chains(&self.macho, None, &mut rebases)?;
        // Images at offset zero share the outer header, whose chains are already decoded.
        for image in self.images.iter().filter(|image| image.file_offset != 0) {
            self.collect_chains(&image.macho, Some(image), &mut rebases)?;
        }
        rebases.sort_unstable();
        if let Some(pair) = rebases
            .windows(2)
            .find(|pair| pair[0].offset == pair[1].offset && pair[0].target != pair[1].target)
        {
            return Err(Error::parse(pair[0].offset, "conflicting chained fixups"));
        }
        rebases.dedup();
        Ok(rebases)
    }

    /// Decodes the chains of the outer collection (`image` is `None`) or of one image.
    fn collect_chains(
        &self,
        macho: &MachOContext,
        image: Option<&KernelImage>,
        rebases: &mut Vec<Rebase>,
    ) -> Result<()> {
        let to_collection = |offset: u64| match image {
            Some(image) => self.member_offset(image, offset),
            None => to_usize(offset),
        };
        let segments: Vec<_> = macho.segments().collect();
        let header_offset = image.map_or(0, KernelImage::local_header_offset);
        let base = segments
            .iter()
            .find(|segment| {
                segment.command.filesize > 0 && segment.command.fileoff == header_offset
            })
            .map(|segment| segment.command.vmaddr)
            .ok_or_else(|| Error::parse(0, "no mapped header for chained fixups"))?;

        for load_command in &macho.load_commands {
            let LoadCommandInfo::LinkeditData { command, .. } = load_command else {
                continue;
            };
            if command.cmd != LC_DYLD_CHAINED_FIXUPS || command.datasize == 0 {
                continue;
            }
            let fixups_offset = to_collection(command.dataoff.into())?;
            let walker = ChainWalker {
                collection: &self.data,
                fixups_offset,
                base,
                to_collection: &to_collection,
            };
            let fixups = slice(&self.data, fixups_offset, command.datasize as usize)?;
            walker.decode(fixups, &segments, rebases)?;
        }
        Ok(())
    }
}

/// Decodes one `LC_DYLD_CHAINED_FIXUPS` payload.
struct ChainWalker<'a, F> {
    collection: &'a [u8],
    /// Collection offset of the payload, reported in errors.
    fixups_offset: usize,
    /// VM address of the Mach-O header; chain targets are offsets from it.
    base: u64,
    /// Maps the Mach-O's own file offsets to collection offsets.
    to_collection: &'a F,
}

impl<F: Fn(u64) -> Result<usize>> ChainWalker<'_, F> {
    fn error(&self, reason: impl Into<String>) -> Error {
        Error::parse(self.fixups_offset, reason)
    }

    fn decode(
        &self,
        fixups: &[u8],
        segments: &[&SegmentInfo],
        rebases: &mut Vec<Rebase>,
    ) -> Result<()> {
        slice(fixups, 0, FIXUPS_HEADER_SIZE)?;
        let version = read_u32(fixups, 0)?;
        let imports_count = read_u32(fixups, 16)?;
        if version != 0 || imports_count != 0 {
            return Err(self.error("unsupported chained fixup version or unresolved imports"));
        }

        // dyld_chained_starts_in_image: seg_count, then seg_info_offset[seg_count].
        let starts = read_u32(fixups, 4)? as usize;
        let segment_count = read_u32(fixups, starts)? as usize;
        let table_size = segment_count
            .checked_mul(4)
            .ok_or_else(|| Error::parse(starts, "segment count overflow"))?;
        slice(fixups, starts + 4, table_size)?;
        if segment_count > segments.len() {
            return Err(Error::parse(
                starts,
                "chain segment count exceeds load commands",
            ));
        }
        for (index, segment) in segments.iter().enumerate().take(segment_count) {
            let info_offset = read_u32(fixups, starts + 4 + index * 4)? as usize;
            if info_offset == 0 {
                continue;
            }
            let info_start = starts
                .checked_add(info_offset)
                .ok_or_else(|| Error::parse(starts, "chain offset overflow"))?;
            let info_size = read_u32(fixups, info_start)? as usize;
            self.decode_segment(slice(fixups, info_start, info_size)?, segment, rebases)?;
        }
        Ok(())
    }

    /// Decodes a `dyld_chained_starts_in_segment` record.
    fn decode_segment(
        &self,
        info: &[u8],
        segment: &SegmentInfo,
        rebases: &mut Vec<Rebase>,
    ) -> Result<()> {
        slice(info, 0, SEGMENT_STARTS_HEADER_SIZE)?;
        let page_size = usize::from(read_u16(info, 4)?);
        let format = read_u16(info, 6)?;
        let supported_format = matches!(
            format,
            PTR_ARM64E_KERNEL | PTR_64_KERNEL_CACHE | PTR_X86_64_KERNEL_CACHE
        );
        if !matches!(page_size, 0x1000 | 0x4000) || !supported_format {
            return Err(self.error(format!(
                "unsupported chain page size {page_size} or pointer format {format}"
            )));
        }
        let segment_offset = read_u64(info, 8)?;
        if self.base.checked_add(segment_offset) != Some(segment.command.vmaddr) {
            return Err(self.error("chain segment offset disagrees with segment VM address"));
        }

        let page_count = usize::from(read_u16(info, 20)?);
        slice(info, SEGMENT_STARTS_HEADER_SIZE, page_count * 2)?;
        let page_start = |index: usize| read_u16(info, SEGMENT_STARTS_HEADER_SIZE + index * 2);
        for page in 0..page_count {
            for start in self.chain_starts(page_start(page)?, page_count, &page_start)? {
                self.walk_chain(segment, page * page_size, page_size, start, format, rebases)?;
            }
        }
        Ok(())
    }

    /// Returns the offsets within a page at which chains start.
    fn chain_starts(
        &self,
        entry: u16,
        page_count: usize,
        page_start: &impl Fn(usize) -> Result<u16>,
    ) -> Result<Vec<usize>> {
        if entry == PAGE_START_NONE {
            return Ok(Vec::new());
        }
        if entry & PAGE_START_MULTI == 0 {
            return Ok(vec![usize::from(entry)]);
        }
        // Multi-start lists live in the overflow area after the per-page entries.
        let mut index = usize::from(entry & !PAGE_START_MULTI);
        if index < page_count {
            return Err(self.error("chain overflow index overlaps page starts"));
        }
        let mut starts = Vec::new();
        loop {
            let value = page_start(index)?;
            starts.push(usize::from(value & !PAGE_START_LAST));
            if value & PAGE_START_LAST != 0 {
                return Ok(starts);
            }
            index += 1;
        }
    }

    /// Follows one chain, starting `offset_in_page` bytes into the page at `page_offset`.
    fn walk_chain(
        &self,
        segment: &SegmentInfo,
        page_offset: usize,
        page_size: usize,
        mut offset_in_page: usize,
        format: u16,
        rebases: &mut Vec<Rebase>,
    ) -> Result<()> {
        loop {
            // Formats with a 4-byte stride can place an 8-byte pointer in the
            // last four bytes of a page: the pointer must fit the segment, and
            // only its start must fit the page.
            if offset_in_page >= page_size {
                return Err(self.error("chain leaves page"));
            }
            let segment_offset = (page_offset + offset_in_page) as u64;
            if segment_offset
                .checked_add(POINTER_SIZE)
                .is_none_or(|end| end > segment.command.filesize)
            {
                return Err(self.error("chain leaves file-backed segment"));
            }
            let file_offset = segment
                .command
                .fileoff
                .checked_add(segment_offset)
                .ok_or_else(|| self.error("chain file offset overflow"))?;
            let location = (self.to_collection)(file_offset)?;
            let pointer = decode_pointer(
                read_u64(self.collection, location)?,
                format,
                self.base,
                location,
            )?;
            rebases.push(Rebase {
                offset: location,
                target: pointer.target,
            });
            if pointer.next == 0 {
                return Ok(());
            }
            offset_in_page += pointer.next;
        }
    }
}

/// A decoded chain entry.
#[derive(Debug, PartialEq, Eq)]
struct ChainedPointer {
    /// Unslid target address.
    target: u64,
    /// Distance in bytes to the next entry; zero ends the chain.
    next: usize,
}

/// Extracts `width` bits of `word`, starting at bit `shift`.
const fn bits(word: u64, shift: u32, width: u32) -> u64 {
    (word >> shift) & ((1 << width) - 1)
}

/// Decodes a chained pointer stored at `location`, relative to the header address `base`.
fn decode_pointer(word: u64, format: u16, base: u64, location: usize) -> Result<ChainedPointer> {
    let from_base = |offset: u64| {
        base.checked_add(offset)
            .ok_or_else(|| Error::parse(location, "chain target overflow"))
    };
    match format {
        PTR_ARM64E_KERNEL => {
            // dyld_chained_ptr_arm64e_rebase / _auth_rebase: next in bits 51..62
            // (4-byte units), bind in bit 62, auth in bit 63.
            if bits(word, 62, 1) != 0 {
                return Err(Error::parse(location, "unresolved ARM64e chained bind"));
            }
            let target = if bits(word, 63, 1) != 0 {
                from_base(bits(word, 0, 32))?
            } else {
                // The unauthenticated encoding is a VM offset plus a separate
                // high8 tag; apply unsigned address arithmetic and keep the tag.
                base.wrapping_add(bits(word, 0, 43) | (bits(word, 43, 8) << 56))
            };
            Ok(ChainedPointer {
                target,
                next: bits(word, 51, 11) as usize * 4,
            })
        }
        PTR_64_KERNEL_CACHE | PTR_X86_64_KERNEL_CACHE => {
            // dyld_chained_ptr_64_kernel_cache_rebase: target in bits 0..30,
            // cache level in bits 30..32, next in bits 51..63.
            let level = bits(word, 30, 2);
            if level != 0 {
                return Err(Error::parse(
                    location,
                    format!("chain references external kernel collection level {level}"),
                ));
            }
            let stride = if format == PTR_X86_64_KERNEL_CACHE {
                1
            } else {
                4
            };
            Ok(ChainedPointer {
                target: from_base(bits(word, 0, 30))?,
                next: bits(word, 51, 12) as usize * stride,
            })
        }
        _ => Err(Error::parse(
            location,
            format!("unsupported chained pointer format {format}"),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: u64 = 0xffff_fe00_0700_4000;

    fn decode(word: u64, format: u16) -> Result<ChainedPointer> {
        decode_pointer(word, format, BASE, 0)
    }

    fn pointer(target: u64, next: usize) -> ChainedPointer {
        ChainedPointer { target, next }
    }

    #[test]
    fn kernel_cache_pointers_use_format_specific_strides() {
        let word = (1 << 63) | (3 << 51) | 0x1234;
        assert_eq!(
            decode(word, PTR_64_KERNEL_CACHE).unwrap(),
            pointer(BASE + 0x1234, 12)
        );
        let word = (3 << 51) | 0x1234;
        assert_eq!(
            decode(word, PTR_X86_64_KERNEL_CACHE).unwrap(),
            pointer(BASE + 0x1234, 3)
        );
    }

    #[test]
    fn kernel_cache_pointers_into_other_collections_are_rejected() {
        assert!(decode(1 << 30, PTR_64_KERNEL_CACHE).is_err());
    }

    #[test]
    fn arm64e_pointers_decode_authenticated_and_tagged_targets() {
        let authenticated = (1 << 63) | (2 << 51) | 0x1234;
        assert_eq!(
            decode(authenticated, PTR_ARM64E_KERNEL).unwrap(),
            pointer(BASE + 0x1234, 8)
        );
        let tagged = (0xab << 43) | 0x10;
        assert_eq!(
            decode(tagged, PTR_ARM64E_KERNEL).unwrap(),
            pointer(BASE.wrapping_add(0x10 | (0xab << 56)), 0)
        );
    }

    #[test]
    fn arm64e_binds_are_rejected() {
        assert!(decode(1 << 62, PTR_ARM64E_KERNEL).is_err());
    }
}
