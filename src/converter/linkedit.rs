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
    DyldInfoCommand, DysymtabCommand, LinkeditDataCommand, LoadCommandInfo, Nlist64, SymtabCommand,
    INDIRECT_SYMBOL_ABS, INDIRECT_SYMBOL_LOCAL, LC_DATA_IN_CODE, LC_DYLD_EXPORTS_TRIE,
    LC_FUNCTION_STARTS,
};

use super::ExtractionContext;

// =============================================================================
// String Pool
// =============================================================================

/// A string pool for building the new LINKEDIT string table.
///
/// Deduplicates strings and tracks their offsets in the final table.
#[derive(Debug)]
struct StringPool {
    /// Map from string content to offset in pool
    map: HashMap<Vec<u8>, u32>,
    /// Current size of the pool
    size: u32,
}

impl StringPool {
    /// Creates a new string pool with the initial null byte.
    fn new() -> Self {
        let mut pool = Self {
            map: HashMap::new(),
            size: 0,
        };
        // First string is always a null byte (index 0)
        pool.map.insert(vec![0], 0);
        pool.size = 1;
        pool
    }

    /// Adds a string to the pool and returns its offset.
    ///
    /// If the string already exists, returns the existing offset.
    fn add(&mut self, s: &[u8]) -> u32 {
        // Ensure null termination
        let mut key = s.to_vec();
        if key.last() != Some(&0) {
            key.push(0);
        }

        if let Some(&offset) = self.map.get(&key) {
            return offset;
        }

        let offset = self.size;
        self.size += key.len() as u32;
        self.map.insert(key, offset);
        offset
    }

    /// Compiles the string pool into a byte vector.
    fn compile(&self) -> Vec<u8> {
        let mut result = vec![0u8; self.size as usize];

        for (string, &offset) in &self.map {
            let offset = offset as usize;
            let len = string.len();
            if offset + len <= result.len() {
                result[offset..offset + len].copy_from_slice(string);
            }
        }

        result
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

    /// Copies local symbols from the symbols cache.
    fn copy_local_symbols(&mut self) -> Result<()> {
        let Some(symbols_data) = self.ctx.cache.symbols_cache_data() else {
            self.ctx
                .warn("No symbols cache available for local symbols");
            return Ok(());
        };

        let Some(local_symbols_info) = self.ctx.cache.local_symbols_info else {
            self.ctx.warn("No local symbols info available");
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
            let name_data = self.read_linkedit_data(name_offset as u32, 256)?; // Read up to 256 bytes
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
            let name_data = self.read_linkedit_data(name_offset as u32, 256)?;
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
    fn copy_string_pool(&mut self) {
        self.new_string_pool_offset = self.new_linkedit.len() as u32;
        let pool = self.string_pool.compile();
        self.new_string_pool_size = pool.len() as u32;
        self.new_linkedit.extend_from_slice(&pool);
    }

    /// Updates load commands with new offsets.
    fn update_load_commands(&mut self, new_linkedit_offset: u32) -> Result<()> {
        // Update __LINKEDIT segment
        if let Some(linkedit_seg) = self.ctx.macho.segment_mut("__LINKEDIT") {
            linkedit_seg.command.fileoff = new_linkedit_offset as u64;
            linkedit_seg.command.filesize = self.new_linkedit.len() as u64;
            linkedit_seg.command.vmsize = self.new_linkedit.len() as u64;
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

        // Update export trie
        if let Some(offset) = self.export_trie_offset {
            let mut export_trie = self.export_trie.unwrap();
            export_trie.dataoff = new_linkedit_offset + self.new_export_offset;
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
        if let Some(offset) = self.data_in_code_offset {
            let mut dic = self.data_in_code.unwrap();
            if dic.datasize > 0 {
                dic.dataoff = new_linkedit_offset + self.new_data_in_code_offset;
            } else {
                // Zero out dataoff when datasize is 0 to avoid stale cache offsets
                dic.dataoff = 0;
            }
            self.ctx.macho.write_struct(offset, &dic)?;
        }

        Ok(())
    }

    /// Runs the optimization process.
    fn optimize(mut self) -> Result<Vec<u8>> {
        self.find_load_commands();

        // Copy binding info
        self.copy_binding_info()?;
        self.copy_export_info()?;

        // Start symbol table
        self.new_symbol_table_offset = self.new_linkedit.len() as u32;

        // Add redacted symbol placeholder if needed
        self.add_redacted_symbol()?;

        // Copy symbols
        self.copy_local_symbols()?;
        self.copy_exported_symbols()?;
        self.copy_imported_symbols()?;

        // Copy other data
        self.copy_function_starts()?;
        self.copy_data_in_code()?;

        // Copy indirect symbol table
        self.copy_indirect_symbol_table()?;

        // Align before string pool
        self.align_linkedit();

        // Copy string pool
        self.copy_string_pool();

        // Final alignment
        self.align_linkedit();

        // Get the new LINKEDIT offset (where it will be written)
        let linkedit_seg = self.ctx.macho.linkedit_segment().ok_or(Error::Parse {
            offset: 0,
            reason: "no LINKEDIT segment".into(),
        })?;
        let new_linkedit_offset = linkedit_seg.command.fileoff as u32;

        // Update load commands
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

    // Get the current LINKEDIT location
    let linkedit_offset = {
        let linkedit = ctx.macho.linkedit_segment().ok_or(Error::Parse {
            offset: 0,
            reason: "no LINKEDIT segment".into(),
        })?;
        linkedit.command.fileoff as usize
    };

    // Run the optimizer
    let optimizer = LinkeditOptimizer::new(ctx);
    let new_linkedit = optimizer.optimize()?;

    // Write the new LINKEDIT to the Mach-O data buffer
    // First, ensure buffer is large enough
    let required_size = linkedit_offset + new_linkedit.len();
    if ctx.macho.data.len() < required_size {
        ctx.macho.data.resize(required_size, 0);
    }

    // Truncate to remove the old large LINKEDIT and write the new one
    ctx.macho.data.truncate(linkedit_offset);
    ctx.macho.data.extend_from_slice(&new_linkedit);

    Ok(())
}
