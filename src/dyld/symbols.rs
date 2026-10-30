//! Width-aware access to local symbols omitted from the cache's mapped LINKEDIT.
use super::DyldContext;
use crate::util::read_u32_le;
use crate::{
    Error, Result,
    macho::{Nlist64, read_nlist},
};

/// A symbol with widened fields and a borrowed, NUL-free name.
#[derive(Debug)]
pub struct CacheLocalSymbol<'a> {
    /// Symbol fields; n_value retains the source ABI's Thumb descriptor semantics.
    pub entry: Nlist64,
    /// Name bytes excluding the terminating NUL.
    pub name: &'a [u8],
}

impl DyldContext {
    /// Reads an image's omitted local symbols from the main cache or .symbols.
    /// Validates table extents, entry ranges, and NUL-terminated names. O(E+S+B)
    /// time and O(S) space for E image entries, S symbols, and B name bytes read.
    pub fn local_symbols_for_image(&self, address: u64) -> Result<Vec<CacheLocalSymbol<'_>>> {
        let (Some(data), Some(info), Some(base)) = (
            self.symbols_cache_data(),
            self.local_symbols_info,
            self.local_symbols_offset(),
        ) else {
            return Ok(Vec::new());
        };
        let bad = |reason: &str| Error::Parse {
            offset: base as usize,
            reason: reason.into(),
        };
        let region = if let Some(file) = &self.symbols_file {
            if file.header.local_symbols_offset == base {
                file.header.local_symbols_size
            } else {
                self.header.local_symbols_size
            }
        } else {
            self.header.local_symbols_size
        };
        let region_end =
            base.checked_add(region)
                .filter(|end| *end <= data.len() as u64)
                .ok_or_else(|| bad("local symbol region outside file"))? as usize;
        let read = |relative: u32, count: usize, stride: usize| -> Result<&[u8]> {
            let start = (base as usize)
                .checked_add(relative as usize)
                .ok_or_else(|| bad("local table offset overflow"))?;
            let end = count
                .checked_mul(stride)
                .and_then(|n| start.checked_add(n))
                .filter(|end| *end <= region_end)
                .ok_or_else(|| bad("local table outside symbol region"))?;
            Ok(&data[start..end])
        };
        let wide = self.uses_64bit_local_symbol_entries();
        let entry_size = if wide { 16 } else { 12 };
        let wanted = if wide {
            address
                .checked_sub(self.shared_region_start)
                .ok_or_else(|| bad("image before shared region"))?
        } else {
            self.addr_to_offset(address)
                .ok_or(Error::AddressNotFound { addr: address })?
        };
        let entries = read(info.entries_offset, info.entries_count as usize, entry_size)?;
        let nlist_size = if self.pointer_size() == 4 { 12 } else { 16 };
        let nlists = read(info.nlist_offset, info.nlist_count as usize, nlist_size)?;
        let strings = read(info.strings_offset, info.strings_size as usize, 1)?;
        for raw in entries.chunks_exact(entry_size) {
            let offset = if wide {
                crate::util::read_u64_le(raw)
            } else {
                read_u32_le(raw) as u64
            };
            if offset != wanted {
                continue;
            }
            let start = read_u32_le(&raw[entry_size - 8..]) as usize;
            let count = read_u32_le(&raw[entry_size - 4..]) as usize;
            let end = start
                .checked_add(count)
                .filter(|end| *end <= info.nlist_count as usize)
                .ok_or_else(|| bad("local symbol index outside nlist table"))?;
            let mut result = Vec::with_capacity(count);
            for raw in nlists[start * nlist_size..end * nlist_size].chunks_exact(nlist_size) {
                let entry = read_nlist(raw, nlist_size == 16)?;
                let tail = strings
                    .get(entry.n_strx as usize..)
                    .ok_or_else(|| bad("local string index outside table"))?;
                let end =
                    memchr::memchr(0, tail).ok_or_else(|| bad("unterminated local symbol name"))?;
                result.push(CacheLocalSymbol {
                    entry,
                    name: &tail[..end],
                });
            }
            return Ok(result);
        }
        Ok(Vec::new())
    }
}
