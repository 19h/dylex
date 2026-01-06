//! LINKEDIT segment optimizer.
//!
//! In the dyld shared cache, the LINKEDIT segment is merged across all images.
//! This module rebuilds a standalone LINKEDIT for extracted images.

use std::collections::HashMap;

use zerocopy::{FromBytes, IntoBytes};

use crate::dyld::{
    DyldCacheLocalSymbolsEntry, DyldCacheLocalSymbolsEntry64, DyldCacheLocalSymbolsInfo,
};
use crate::error::{Error, Result};
use crate::macho::{
    DyldInfoCommand, DysymtabCommand, INDIRECT_SYMBOL_ABS, INDIRECT_SYMBOL_LOCAL, LC_DATA_IN_CODE,
    LC_DYLD_CHAINED_FIXUPS, LC_DYLD_EXPORTS_TRIE, LC_FUNCTION_STARTS, LinkeditDataCommand,
    LoadCommandInfo, Nlist64, SymtabCommand,
};

use super::ExtractionContext;

// =============================================================================
// String Pool
// =============================================================================

/// A string pool for building the new LINKEDIT string table.
///
/// Stores strings sequentially without deduplication to match Apple's dsc_extractor.
#[derive(Debug)]
struct StringPool {
    /// Raw string data
    data: Vec<u8>,
}

impl StringPool {
    /// Creates a new string pool with the initial null byte.
    fn new() -> Self {
        let mut pool = Self { data: Vec::new() };
        // First byte is always a null byte (empty string at index 0)
        pool.data.push(0);
        pool
    }

    /// Adds a string to the pool and returns its offset.
    ///
    /// Unlike a traditional string pool, this does NOT deduplicate strings
    /// to match Apple's dsc_extractor behavior exactly.
    fn add(&mut self, s: &[u8]) -> u32 {
        let offset = self.data.len() as u32;

        // Copy the string (without null terminator if present)
        let s = if s.last() == Some(&0) {
            &s[..s.len() - 1]
        } else {
            s
        };

        self.data.extend_from_slice(s);
        self.data.push(0); // Add null terminator

        offset
    }

    /// Returns the compiled string pool data.
    fn compile(&self) -> Vec<u8> {
        self.data.clone()
    }
}

// =============================================================================
// LINKEDIT Optimizer
// =============================================================================

/// State for the LINKEDIT optimization process.
struct LinkeditOptimizer<'a> {
    ctx: &'a mut ExtractionContext,

    /// The new LINKEDIT data being built
    new_linkedit: Vec<u8>,

    /// String pool for symbol names
    string_pool: StringPool,

    /// Maps old symbol indices to new indices
    old_to_new_symbol_index: HashMap<u32, u32>,

    /// Number of symbols added so far
    symbol_count: u32,

    /// Number of redacted symbols found
    redacted_symbol_count: u32,

    // Load command references (offsets and data)
    symtab_offset: Option<usize>,
    symtab: Option<SymtabCommand>,
    dysymtab_offset: Option<usize>,
    dysymtab: Option<DysymtabCommand>,
    dyld_info_offset: Option<usize>,
    dyld_info: Option<DyldInfoCommand>,
    export_trie_offset: Option<usize>,
    export_trie: Option<LinkeditDataCommand>,
    function_starts_offset: Option<usize>,
    function_starts: Option<LinkeditDataCommand>,
    data_in_code_offset: Option<usize>,
    data_in_code: Option<LinkeditDataCommand>,
    chained_fixups_offset: Option<usize>,
    chained_fixups: Option<LinkeditDataCommand>,

    // New offsets within the rebuilt LINKEDIT
    new_bind_offset: u32,
    new_weak_bind_offset: u32,
    new_lazy_bind_offset: u32,
    new_export_offset: u32,
    new_symbol_table_offset: u32,
    new_function_starts_offset: u32,
    new_data_in_code_offset: u32,
    new_indirect_sym_offset: u32,
    new_string_pool_offset: u32,
    new_string_pool_size: u32,

    // Symbol table indices
    new_local_sym_index: u32,
    new_local_sym_count: u32,
    new_extdef_sym_index: u32,
    new_extdef_sym_count: u32,
    new_undef_sym_index: u32,
    new_undef_sym_count: u32,
}

impl<'a> LinkeditOptimizer<'a> {
    /// Creates a new optimizer for the given extraction context.
    fn new(ctx: &'a mut ExtractionContext) -> Self {
        Self {
            ctx,
            new_linkedit: Vec::new(),
            string_pool: StringPool::new(),
            old_to_new_symbol_index: HashMap::new(),
            symbol_count: 0,
            redacted_symbol_count: 0,
            symtab_offset: None,
            symtab: None,
            dysymtab_offset: None,
            dysymtab: None,
            dyld_info_offset: None,
            dyld_info: None,
            export_trie_offset: None,
            export_trie: None,
            function_starts_offset: None,
            function_starts: None,
            data_in_code_offset: None,
            data_in_code: None,
            chained_fixups_offset: None,
            chained_fixups: None,
            new_bind_offset: 0,
            new_weak_bind_offset: 0,
            new_lazy_bind_offset: 0,
            new_export_offset: 0,
            new_symbol_table_offset: 0,
            new_function_starts_offset: 0,
            new_data_in_code_offset: 0,
            new_indirect_sym_offset: 0,
            new_string_pool_offset: 0,
            new_string_pool_size: 0,
            new_local_sym_index: 0,
            new_local_sym_count: 0,
            new_extdef_sym_index: 0,
            new_extdef_sym_count: 0,
            new_undef_sym_index: 0,
            new_undef_sym_count: 0,
        }
    }

    /// Finds and caches load command references.
    fn find_load_commands(&mut self) {
        for lc in &self.ctx.macho.load_commands {
            match lc {
                LoadCommandInfo::Symtab { command, offset } => {
                    self.symtab = Some(*command);
                    self.symtab_offset = Some(*offset);
                }
                LoadCommandInfo::Dysymtab { command, offset } => {
                    self.dysymtab = Some(*command);
                    self.dysymtab_offset = Some(*offset);
                }
                LoadCommandInfo::DyldInfo { command, offset } => {
                    self.dyld_info = Some(*command);
                    self.dyld_info_offset = Some(*offset);
                }
                LoadCommandInfo::LinkeditData { command, offset } => match command.cmd {
                    LC_FUNCTION_STARTS => {
                        self.function_starts = Some(*command);
                        self.function_starts_offset = Some(*offset);
                    }
                    LC_DATA_IN_CODE => {
                        self.data_in_code = Some(*command);
                        self.data_in_code_offset = Some(*offset);
                    }
                    LC_DYLD_EXPORTS_TRIE => {
                        self.export_trie = Some(*command);
                        self.export_trie_offset = Some(*offset);
                    }
                    LC_DYLD_CHAINED_FIXUPS => {
                        self.chained_fixups = Some(*command);
                        self.chained_fixups_offset = Some(*offset);
                    }
                    _ => {}
                },
                _ => {}
            }
        }
    }

    /// Reads data from the LINKEDIT segment in the cache.
    fn read_linkedit_data(&self, offset: u32, size: u32) -> Result<&[u8]> {
        if size == 0 {
            return Ok(&[]);
        }

        // LINKEDIT data is referenced by file offset in the original cache
        // We need to read from the Mach-O data which was copied from the cache
        let offset = offset as usize;
        let size = size as usize;

        if offset + size > self.ctx.macho.data.len() {
            // Fall back to reading from cache if not in our buffer
            let linkedit = self.ctx.macho.linkedit_segment().ok_or(Error::Parse {
                offset: 0,
                reason: "no LINKEDIT segment".into(),
            })?;

            let linkedit_addr = linkedit.command.vmaddr;
            let linkedit_file_off = linkedit.command.fileoff as usize;

            // Convert file offset to cache address
            if offset >= linkedit_file_off {
                let rel_offset = offset - linkedit_file_off;
                let addr = linkedit_addr + rel_offset as u64;
                return self.ctx.cache.data_at_addr(addr, size);
            }

            return Err(Error::BufferTooSmall {
                needed: offset + size,
                available: self.ctx.macho.data.len(),
            });
        }

        Ok(&self.ctx.macho.data[offset..offset + size])
    }

    /// Copies binding info to the new LINKEDIT.
    #[allow(dead_code)]
    fn copy_binding_info(&mut self) -> Result<()> {
        let Some(dyld_info) = self.dyld_info else {
            return Ok(());
        };

        // Copy bind info
        if dyld_info.bind_size > 0 {
            let data = self
                .read_linkedit_data(dyld_info.bind_off, dyld_info.bind_size)?
                .to_vec();
            self.new_bind_offset = self.new_linkedit.len() as u32;
            self.new_linkedit.extend_from_slice(&data);
        }

        // Copy weak bind info
        if dyld_info.weak_bind_size > 0 {
            let data = self
                .read_linkedit_data(dyld_info.weak_bind_off, dyld_info.weak_bind_size)?
                .to_vec();
            self.new_weak_bind_offset = self.new_linkedit.len() as u32;
            self.new_linkedit.extend_from_slice(&data);
        }

        // Copy lazy bind info
        if dyld_info.lazy_bind_size > 0 {
            let data = self
                .read_linkedit_data(dyld_info.lazy_bind_off, dyld_info.lazy_bind_size)?
                .to_vec();
            self.new_lazy_bind_offset = self.new_linkedit.len() as u32;
            self.new_linkedit.extend_from_slice(&data);
        }

        Ok(())
    }

    /// Copies export info to the new LINKEDIT.
    #[allow(dead_code)]
    fn copy_export_info(&mut self) -> Result<()> {
        // Check for LC_DYLD_EXPORTS_TRIE first (newer format)
        if let Some(export_trie) = self.export_trie {
            if export_trie.datasize > 0 {
                let data = self
                    .read_linkedit_data(export_trie.dataoff, export_trie.datasize)?
                    .to_vec();
                self.new_export_offset = self.new_linkedit.len() as u32;
                self.new_linkedit.extend_from_slice(&data);
                return Ok(());
            }
        }

        // Fall back to dyld_info export
        if let Some(dyld_info) = self.dyld_info {
            if dyld_info.export_size > 0 {
                let data = self
                    .read_linkedit_data(dyld_info.export_off, dyld_info.export_size)?
                    .to_vec();
                self.new_export_offset = self.new_linkedit.len() as u32;
                self.new_linkedit.extend_from_slice(&data);
            }
        }

        Ok(())
    }

    /// Counts redacted indirect symbols and adds a placeholder entry.
    fn add_redacted_symbol(&mut self) -> Result<()> {
        let Some(dysymtab) = self.dysymtab else {
            return Ok(());
        };

        if dysymtab.nindirectsyms == 0 {
            return Ok(());
        }

        // Count indirect symbols that point to index 0 (redacted)
        let indirect_start = dysymtab.indirectsymoff as usize;
        let indirect_count = dysymtab.nindirectsyms as usize;

        for i in 0..indirect_count {
            let offset = indirect_start + i * 4;
            if offset + 4 > self.ctx.macho.data.len() {
                break;
            }

            let sym_index = u32::from_le_bytes([
                self.ctx.macho.data[offset],
                self.ctx.macho.data[offset + 1],
                self.ctx.macho.data[offset + 2],
                self.ctx.macho.data[offset + 3],
            ]);

            if sym_index == 0 {
                self.redacted_symbol_count += 1;
            }
        }

        // If we found redacted symbols, add a placeholder entry
        if self.redacted_symbol_count > 0 {
            let str_index = self.string_pool.add(b"<redacted>");

            let mut nlist = Nlist64::default();
            nlist.n_strx = str_index;
            nlist.n_type = 1; // N_EXT

            self.new_linkedit.extend_from_slice(nlist.as_bytes());
            self.symbol_count += 1;

            self.ctx.has_redacted_indirect = true;
        }

        Ok(())
    }

    /// Copies local symbols from the dylib's original symbol table.
    ///
    /// Local symbols are referenced by dysymtab.ilocalsym and dysymtab.nlocalsym,
    /// and the actual nlist entries are in the symtab at the appropriate offsets.
    fn copy_local_symbols(&mut self) -> Result<()> {
        let Some(dysymtab) = self.dysymtab else {
            return Ok(());
        };

        let Some(symtab) = self.symtab else {
            return Ok(());
        };

        if dysymtab.nlocalsym == 0 {
            return Ok(());
        }

        self.new_local_sym_index = self.symbol_count;

        let sym_start = dysymtab.ilocalsym;
        let sym_end = sym_start + dysymtab.nlocalsym;

        for sym_index in sym_start..sym_end {
            let nlist_offset = symtab.symoff as usize + (sym_index as usize * Nlist64::SIZE);

            let nlist_data = self.read_linkedit_data(nlist_offset as u32, Nlist64::SIZE as u32)?;
            let (nlist, _) = Nlist64::read_from_prefix(nlist_data).map_err(|_| Error::Parse {
                offset: nlist_offset,
                reason: "failed to parse nlist".into(),
            })?;

            // Read the symbol name
            let name_offset = symtab.stroff as usize + nlist.n_strx as usize;
            let name_data = self.read_linkedit_data(name_offset as u32, 4096)?;
            let name = self.extract_string(name_data);

            // Map old index to new
            self.old_to_new_symbol_index
                .insert(sym_index, self.symbol_count);

            // Add to our string pool and create new entry
            let new_strx = self.string_pool.add(&name);

            let mut new_nlist = nlist;
            new_nlist.n_strx = new_strx;

            self.new_linkedit.extend_from_slice(new_nlist.as_bytes());
            self.symbol_count += 1;
            self.new_local_sym_count += 1;
        }

        Ok(())
    }

    /// Copies local symbols from the symbols cache (for caches with separate local symbols).
    ///
    /// This is used for older caches that store local symbols in a separate table
    /// (local_symbols_offset != 0 or .symbols file exists).
    #[allow(dead_code)]
    fn copy_local_symbols_from_cache(&mut self) -> Result<()> {
        let Some(symbols_data) = self.ctx.cache.symbols_cache_data() else {
            return Ok(());
        };

        let Some(local_symbols_info) = self.ctx.cache.local_symbols_info else {
            return Ok(());
        };

        let Some(local_symbols_offset) = self.ctx.cache.local_symbols_offset() else {
            return Ok(());
        };

        // Find the entry for this image
        let text_seg = self.ctx.macho.text_segment().ok_or(Error::Parse {
            offset: 0,
            reason: "no __TEXT segment".into(),
        })?;

        let image_offset = if self.ctx.cache.uses_64bit_local_symbol_entries() {
            // Newer cache: use VM offset from shared region start
            text_seg.command.vmaddr - self.ctx.cache.shared_region_start
        } else {
            // Older cache: use file offset
            self.ctx
                .cache
                .addr_to_offset(text_seg.command.vmaddr)
                .unwrap_or(0)
        };

        // Find matching entry
        let entries_start =
            local_symbols_offset as usize + local_symbols_info.entries_offset as usize;

        let (nlist_start_index, nlist_count) = if self.ctx.cache.uses_64bit_local_symbol_entries() {
            self.find_local_symbols_entry_64(
                symbols_data,
                &local_symbols_info,
                entries_start,
                image_offset,
            )?
        } else {
            self.find_local_symbols_entry_32(
                symbols_data,
                &local_symbols_info,
                entries_start,
                image_offset as u32,
            )?
        };

        if nlist_count == 0 {
            return Ok(());
        }

        self.new_local_sym_index = self.symbol_count;

        // Copy the nlist entries
        let nlist_base = local_symbols_offset as usize + local_symbols_info.nlist_offset as usize;
        let string_base =
            local_symbols_offset as usize + local_symbols_info.strings_offset as usize;

        for i in 0..nlist_count {
            let nlist_offset = nlist_base + ((nlist_start_index + i) as usize * Nlist64::SIZE);

            if nlist_offset + Nlist64::SIZE > symbols_data.len() {
                break;
            }

            let (nlist, _) =
                Nlist64::read_from_prefix(&symbols_data[nlist_offset..]).map_err(|_| {
                    Error::Parse {
                        offset: nlist_offset,
                        reason: "failed to parse nlist".into(),
                    }
                })?;

            // Read the symbol name from the local symbols string table
            let name_offset = string_base + nlist.n_strx as usize;
            let name = self.read_string_from(symbols_data, name_offset)?;

            // Add to our string pool and create new entry
            let new_strx = self.string_pool.add(&name);

            let mut new_nlist = nlist;
            new_nlist.n_strx = new_strx;

            self.new_linkedit.extend_from_slice(new_nlist.as_bytes());
            self.symbol_count += 1;
            self.new_local_sym_count += 1;
        }

        Ok(())
    }

    /// Finds local symbols entry (32-bit format).
    fn find_local_symbols_entry_32(
        &self,
        data: &[u8],
        info: &DyldCacheLocalSymbolsInfo,
        entries_start: usize,
        image_offset: u32,
    ) -> Result<(u32, u32)> {
        for i in 0..info.entries_count {
            let entry_offset =
                entries_start + (i as usize * std::mem::size_of::<DyldCacheLocalSymbolsEntry>());

            if entry_offset + std::mem::size_of::<DyldCacheLocalSymbolsEntry>() > data.len() {
                break;
            }

            let (entry, _) = DyldCacheLocalSymbolsEntry::read_from_prefix(&data[entry_offset..])
                .map_err(|_| Error::Parse {
                    offset: entry_offset,
                    reason: "failed to parse local symbols entry".into(),
                })?;

            if entry.dylib_offset == image_offset {
                return Ok((entry.nlist_start_index, entry.nlist_count));
            }
        }

        Ok((0, 0))
    }

    /// Finds local symbols entry (64-bit format).
    fn find_local_symbols_entry_64(
        &self,
        data: &[u8],
        info: &DyldCacheLocalSymbolsInfo,
        entries_start: usize,
        image_offset: u64,
    ) -> Result<(u32, u32)> {
        for i in 0..info.entries_count {
            let entry_offset =
                entries_start + (i as usize * std::mem::size_of::<DyldCacheLocalSymbolsEntry64>());

            if entry_offset + std::mem::size_of::<DyldCacheLocalSymbolsEntry64>() > data.len() {
                break;
            }

            let (entry, _) = DyldCacheLocalSymbolsEntry64::read_from_prefix(&data[entry_offset..])
                .map_err(|_| Error::Parse {
                    offset: entry_offset,
                    reason: "failed to parse local symbols entry 64".into(),
                })?;

            if entry.dylib_offset == image_offset {
                return Ok((entry.nlist_start_index, entry.nlist_count));
            }
        }

        Ok((0, 0))
    }

    /// Reads a null-terminated string from a byte slice.
    fn read_string_from(&self, data: &[u8], offset: usize) -> Result<Vec<u8>> {
        if offset >= data.len() {
            return Err(Error::Parse {
                offset,
                reason: "string offset out of bounds".into(),
            });
        }

        let bytes = &data[offset..];
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        let mut result = bytes[..end].to_vec();
        result.push(0); // Null terminate
        Ok(result)
    }

    /// Copies exported symbols (from dysymtab iextdefsym/nextdefsym).
    fn copy_exported_symbols(&mut self) -> Result<()> {
        let Some(dysymtab) = self.dysymtab else {
            return Ok(());
        };

        let Some(symtab) = self.symtab else {
            return Ok(());
        };

        if dysymtab.nextdefsym == 0 {
            return Ok(());
        }

        self.new_extdef_sym_index = self.symbol_count;

        let sym_start = dysymtab.iextdefsym;
        let sym_end = sym_start + dysymtab.nextdefsym;

        for sym_index in sym_start..sym_end {
            let nlist_offset = symtab.symoff as usize + (sym_index as usize * Nlist64::SIZE);

            let nlist_data = self.read_linkedit_data(nlist_offset as u32, Nlist64::SIZE as u32)?;
            let (nlist, _) = Nlist64::read_from_prefix(nlist_data).map_err(|_| Error::Parse {
                offset: nlist_offset,
                reason: "failed to parse nlist".into(),
            })?;

            // Read the symbol name
            let name_offset = symtab.stroff as usize + nlist.n_strx as usize;
            let name_data = self.read_linkedit_data(name_offset as u32, 4096)?;
            let name = self.extract_string(name_data);

            // Map old index to new
            self.old_to_new_symbol_index
                .insert(sym_index, self.symbol_count);

            // Add to our string pool and create new entry
            let new_strx = self.string_pool.add(&name);

            let mut new_nlist = nlist;
            new_nlist.n_strx = new_strx;

            self.new_linkedit.extend_from_slice(new_nlist.as_bytes());
            self.symbol_count += 1;
            self.new_extdef_sym_count += 1;
        }

        Ok(())
    }

    /// Copies imported/undefined symbols (from dysymtab iundefsym/nundefsym).
    fn copy_imported_symbols(&mut self) -> Result<()> {
        let Some(dysymtab) = self.dysymtab else {
            return Ok(());
        };

        let Some(symtab) = self.symtab else {
            return Ok(());
        };

        if dysymtab.nundefsym == 0 {
            return Ok(());
        }

        self.new_undef_sym_index = self.symbol_count;

        let sym_start = dysymtab.iundefsym;
        let sym_end = sym_start + dysymtab.nundefsym;

        for sym_index in sym_start..sym_end {
            let nlist_offset = symtab.symoff as usize + (sym_index as usize * Nlist64::SIZE);

            let nlist_data = self.read_linkedit_data(nlist_offset as u32, Nlist64::SIZE as u32)?;
            let (nlist, _) = Nlist64::read_from_prefix(nlist_data).map_err(|_| Error::Parse {
                offset: nlist_offset,
                reason: "failed to parse nlist".into(),
            })?;

            // Read the symbol name
            let name_offset = symtab.stroff as usize + nlist.n_strx as usize;
            let name_data = self.read_linkedit_data(name_offset as u32, 4096)?;
            let name = self.extract_string(name_data);

            // Map old index to new
            self.old_to_new_symbol_index
                .insert(sym_index, self.symbol_count);

            // Add to our string pool and create new entry
            let new_strx = self.string_pool.add(&name);

            let mut new_nlist = nlist;
            new_nlist.n_strx = new_strx;

            self.new_linkedit.extend_from_slice(new_nlist.as_bytes());
            self.symbol_count += 1;
            self.new_undef_sym_count += 1;
        }

        // Reserve space for redacted symbols that might be fixed later
        if self.redacted_symbol_count > 0 {
            let padding = self.redacted_symbol_count as usize * Nlist64::SIZE;
            self.new_linkedit
                .resize(self.new_linkedit.len() + padding, 0);
        }

        Ok(())
    }

    /// Extracts a null-terminated string from bytes.
    fn extract_string(&self, data: &[u8]) -> Vec<u8> {
        let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        let mut result = data[..end].to_vec();
        result.push(0);
        result
    }

    /// Copies function starts data.
    fn copy_function_starts(&mut self) -> Result<()> {
        let Some(func_starts) = self.function_starts else {
            return Ok(());
        };

        if func_starts.datasize == 0 {
            return Ok(());
        }

        let data = self
            .read_linkedit_data(func_starts.dataoff, func_starts.datasize)?
            .to_vec();
        self.new_function_starts_offset = self.new_linkedit.len() as u32;
        self.new_linkedit.extend_from_slice(&data);

        Ok(())
    }

    /// Copies data-in-code entries.
    fn copy_data_in_code(&mut self) -> Result<()> {
        let Some(dic) = self.data_in_code else {
            return Ok(());
        };

        if dic.datasize == 0 {
            return Ok(());
        }

        let data = self.read_linkedit_data(dic.dataoff, dic.datasize)?.to_vec();
        self.new_data_in_code_offset = self.new_linkedit.len() as u32;
        self.new_linkedit.extend_from_slice(&data);

        Ok(())
    }

    /// Copies and remaps the indirect symbol table.
    fn copy_indirect_symbol_table(&mut self) -> Result<()> {
        let Some(dysymtab) = self.dysymtab else {
            return Ok(());
        };

        if dysymtab.nindirectsyms == 0 {
            return Ok(());
        }

        self.new_indirect_sym_offset = self.new_linkedit.len() as u32;

        let indirect_start = dysymtab.indirectsymoff as usize;
        let indirect_count = dysymtab.nindirectsyms as usize;

        for i in 0..indirect_count {
            let offset = indirect_start + i * 4;

            if offset + 4 > self.ctx.macho.data.len() {
                // Pad remaining entries with LOCAL
                self.new_linkedit
                    .extend_from_slice(&INDIRECT_SYMBOL_LOCAL.to_le_bytes());
                continue;
            }

            let sym_index = u32::from_le_bytes([
                self.ctx.macho.data[offset],
                self.ctx.macho.data[offset + 1],
                self.ctx.macho.data[offset + 2],
                self.ctx.macho.data[offset + 3],
            ]);

            // Check for special values
            if sym_index == INDIRECT_SYMBOL_ABS
                || sym_index == INDIRECT_SYMBOL_LOCAL
                || sym_index == (INDIRECT_SYMBOL_ABS | INDIRECT_SYMBOL_LOCAL)
            {
                self.new_linkedit
                    .extend_from_slice(&sym_index.to_le_bytes());
                continue;
            }

            // Handle redacted (index 0) entries
            if sym_index == 0 {
                // Point to the redacted placeholder symbol (index 0 in our new table)
                self.new_linkedit.extend_from_slice(&0u32.to_le_bytes());
                continue;
            }

            // Remap the symbol index
            if let Some(&new_index) = self.old_to_new_symbol_index.get(&sym_index) {
                self.new_linkedit
                    .extend_from_slice(&new_index.to_le_bytes());
            } else {
                // Symbol not found - use LOCAL marker
                self.new_linkedit
                    .extend_from_slice(&INDIRECT_SYMBOL_LOCAL.to_le_bytes());
            }
        }

        Ok(())
    }

    /// Aligns the LINKEDIT to 8 bytes.
    #[allow(dead_code)]
    fn align_linkedit(&mut self) {
        let alignment = 8;
        let remainder = self.new_linkedit.len() % alignment;
        if remainder != 0 {
            let padding = alignment - remainder;
            self.new_linkedit
                .resize(self.new_linkedit.len() + padding, 0);
        }
    }

    /// Copies the string pool to the LINKEDIT.
    ///
    /// The string pool is padded to 8-byte alignment to match Apple's dsc_extractor.
    fn copy_string_pool(&mut self) {
        self.new_string_pool_offset = self.new_linkedit.len() as u32;
        let mut pool = self.string_pool.compile();

        // Pad to 8-byte alignment (Apple's dsc_extractor does this)
        let padding = (8 - (pool.len() % 8)) % 8;
        for _ in 0..padding {
            pool.push(0);
        }

        self.new_string_pool_size = pool.len() as u32;
        self.new_linkedit.extend_from_slice(&pool);
    }

    /// Updates load commands with new offsets.
    fn update_load_commands(&mut self, new_linkedit_offset: u32) -> Result<()> {
        // Update __LINKEDIT segment
        if let Some(linkedit_seg) = self.ctx.macho.segment_mut("__LINKEDIT") {
            linkedit_seg.command.fileoff = new_linkedit_offset as u64;
            linkedit_seg.command.filesize = self.new_linkedit.len() as u64;
            // vmsize should be page-aligned (Apple's dsc_extractor does this)
            let filesize = self.new_linkedit.len() as u64;
            let page_size = 0x1000u64;
            linkedit_seg.command.vmsize = (filesize + page_size - 1) & !(page_size - 1);
        }

        // Write back to data buffer (separate borrow scope)
        if let Some(linkedit_seg) = self.ctx.macho.segment("__LINKEDIT") {
            let offset = linkedit_seg.command_offset;
            let command = linkedit_seg.command;
            self.ctx.macho.write_struct(offset, &command)?;
        }

        // Update symtab
        if let Some(offset) = self.symtab_offset {
            let mut symtab = self.symtab.unwrap();
            symtab.symoff = new_linkedit_offset + self.new_symbol_table_offset;
            symtab.nsyms = self.symbol_count;
            symtab.stroff = new_linkedit_offset + self.new_string_pool_offset;
            symtab.strsize = self.new_string_pool_size;
            self.ctx.macho.write_struct(offset, &symtab)?;
        }

        // Update dysymtab
        if let Some(offset) = self.dysymtab_offset {
            let mut dysymtab = self.dysymtab.unwrap();
            dysymtab.ilocalsym = self.new_local_sym_index;
            dysymtab.nlocalsym = self.new_local_sym_count;
            dysymtab.iextdefsym = self.new_extdef_sym_index;
            dysymtab.nextdefsym = self.new_extdef_sym_count;
            dysymtab.iundefsym = self.new_undef_sym_index;
            dysymtab.nundefsym = self.new_undef_sym_count;
            dysymtab.tocoff = 0;
            dysymtab.ntoc = 0;
            dysymtab.modtaboff = 0;
            dysymtab.nmodtab = 0;
            dysymtab.indirectsymoff = new_linkedit_offset + self.new_indirect_sym_offset;
            dysymtab.extrefsymoff = 0;
            dysymtab.nextrefsyms = 0;
            dysymtab.locreloff = 0;
            dysymtab.nlocrel = 0;
            self.ctx.macho.write_struct(offset, &dysymtab)?;
        }

        // Update dyld info
        if let Some(offset) = self.dyld_info_offset {
            let mut dyld_info = self.dyld_info.unwrap();
            if dyld_info.bind_size > 0 {
                dyld_info.bind_off = new_linkedit_offset + self.new_bind_offset;
            }
            if dyld_info.weak_bind_size > 0 {
                dyld_info.weak_bind_off = new_linkedit_offset + self.new_weak_bind_offset;
            }
            if dyld_info.lazy_bind_size > 0 {
                dyld_info.lazy_bind_off = new_linkedit_offset + self.new_lazy_bind_offset;
            }
            if dyld_info.export_size > 0 && self.export_trie.is_none() {
                dyld_info.export_off = new_linkedit_offset + self.new_export_offset;
            }
            self.ctx.macho.write_struct(offset, &dyld_info)?;
        }

        // Zero out export trie - Apple's dsc_extractor does this
        // The export info is available in the symbol table
        if let Some(offset) = self.export_trie_offset {
            let mut export_trie = self.export_trie.unwrap();
            export_trie.dataoff = 0;
            export_trie.datasize = 0;
            self.ctx.macho.write_struct(offset, &export_trie)?;
        }

        // Update function starts
        if let Some(offset) = self.function_starts_offset {
            let mut func_starts = self.function_starts.unwrap();
            if func_starts.datasize > 0 {
                func_starts.dataoff = new_linkedit_offset + self.new_function_starts_offset;
            } else {
                // Zero out dataoff when datasize is 0 to avoid stale cache offsets
                func_starts.dataoff = 0;
            }
            self.ctx.macho.write_struct(offset, &func_starts)?;
        }

        // Update data-in-code
        // Apple's dsc_extractor sets dataoff to symoff even when datasize is 0
        if let Some(offset) = self.data_in_code_offset {
            let mut dic = self.data_in_code.unwrap();
            if dic.datasize > 0 {
                dic.dataoff = new_linkedit_offset + self.new_data_in_code_offset;
            } else {
                // Point to symbol table location (same as symoff) even when size is 0
                dic.dataoff = new_linkedit_offset + self.new_symbol_table_offset;
            }
            self.ctx.macho.write_struct(offset, &dic)?;
        }

        // Zero out chained fixups - the pointers have been rebased via slide info
        // Apple's dsc_extractor does this to indicate fixups are already applied
        if let Some(offset) = self.chained_fixups_offset {
            let mut chained = self.chained_fixups.unwrap();
            chained.dataoff = 0;
            chained.datasize = 0;
            self.ctx.macho.write_struct(offset, &chained)?;
        }

        Ok(())
    }

    /// Runs the optimization process.
    ///
    /// The LINKEDIT layout must match Apple's dsc_extractor order:
    /// 1. function_starts
    /// 2. data_in_code (padding to 4-byte alignment for symbol table)
    /// 3. symbol table (nlist array)
    /// 4. indirect symbol table
    /// 5. string table
    fn optimize(mut self) -> Result<Vec<u8>> {
        self.find_load_commands();

        // 1. Copy function starts FIRST (Apple's order)
        self.copy_function_starts()?;

        // 2. Copy data in code (may be empty but provides alignment)
        self.copy_data_in_code()?;

        // Calculate the LINKEDIT base offset in the new file
        // In the output file, segments are written contiguously starting at offset 0,
        // so LINKEDIT starts at the sum of all non-LINKEDIT segment filesizes.
        let linkedit_base: usize = self
            .ctx
            .macho
            .segments()
            .filter(|s| s.name() != "__LINKEDIT" && s.command.filesize > 0)
            .map(|s| s.command.filesize as usize)
            .sum();

        // Align symbol table to 8-byte boundary in absolute file offset
        // (Apple's dsc_extractor does this)
        let current_abs_offset = linkedit_base + self.new_linkedit.len();
        let aligned_abs_offset = (current_abs_offset + 7) & !7;
        let padding = aligned_abs_offset - current_abs_offset;
        for _ in 0..padding {
            self.new_linkedit.push(0);
        }

        // 3. Symbol table
        self.new_symbol_table_offset = self.new_linkedit.len() as u32;

        // Add redacted symbol placeholder if needed
        self.add_redacted_symbol()?;

        // Copy symbols (order: local, exported, imported)
        self.copy_local_symbols()?;
        self.copy_exported_symbols()?;
        self.copy_imported_symbols()?;

        // 4. Copy indirect symbol table
        self.copy_indirect_symbol_table()?;

        // 5. Copy string pool (no alignment before - C tool puts it immediately after indirect syms)
        // The string pool itself is already 8-byte padded inside copy_string_pool()
        self.copy_string_pool();

        // No additional alignment - the string pool is already padded
        // and the file writer handles page alignment

        // Calculate where LINKEDIT will start in the output file.
        // In the output file, segments are written contiguously, so LINKEDIT
        // starts at the sum of all other segment filesizes (which reflect the
        // new, not cache, sizes).
        // Note: segment.command.filesize has already been updated by earlier processing
        // to reflect the data we'll actually write.
        let new_linkedit_offset: u32 = self
            .ctx
            .macho
            .segments()
            .filter(|s| s.name() != "__LINKEDIT" && s.command.filesize > 0)
            .map(|s| s.command.filesize as u32)
            .sum();

        // Update load commands with absolute offsets
        self.update_load_commands(new_linkedit_offset)?;

        self.ctx.info(&format!(
            "LINKEDIT optimized: {} symbols, {} bytes (was shared)",
            self.symbol_count,
            self.new_linkedit.len()
        ));

        Ok(self.new_linkedit)
    }
}

// =============================================================================
// Public API
// =============================================================================

/// Optimizes the LINKEDIT segment for the extracted image.
///
/// This rebuilds the symbol table, string table, and other LINKEDIT data
/// to be self-contained rather than referencing the shared cache.
pub fn optimize_linkedit(ctx: &mut ExtractionContext) -> Result<()> {
    ctx.info("Optimizing LINKEDIT...");

    // Run the optimizer - this builds the new LINKEDIT content and updates
    // the segment's fileoff to the new location (sum of other segment filesizes)
    let optimizer = LinkeditOptimizer::new(ctx);
    let new_linkedit = optimizer.optimize()?;

    // Get the UPDATED LINKEDIT location (after optimize() updated it)
    let linkedit_offset = {
        let linkedit = ctx.macho.linkedit_segment().ok_or(Error::Parse {
            offset: 0,
            reason: "no LINKEDIT segment".into(),
        })?;
        linkedit.command.fileoff as usize
    };

    // Write the new LINKEDIT content to the buffer at the new offset.
    // The optimizer has already updated the segment's fileoff to the new location,
    // so we write the new content there. We DON'T truncate because other segments'
    // data is at their original cache offsets and we need to preserve that.
    let required_size = linkedit_offset + new_linkedit.len();
    if ctx.macho.data.len() < required_size {
        ctx.macho.data.resize(required_size, 0);
    }

    // Write new LINKEDIT content at the new offset
    ctx.macho.data[linkedit_offset..linkedit_offset + new_linkedit.len()]
        .copy_from_slice(&new_linkedit);

    Ok(())
}
