//! Standalone Mach-O extraction for kernelcache images.
//!
//! Extraction runs in three phases:
//!
//! 1. File-backed segments are copied with 8-byte alignment, and decoded
//!    chained pointers are written into the copies as unslid targets.
//! 2. The image's LINKEDIT records (symbols, relocations, function starts, and
//!    similar tables) are copied into a private `__LINKEDIT`, with symbol names
//!    re-interned into a compact string table.
//! 3. The header and load commands are rewritten in place over the first
//!    segment's original header.
//!
//! Virtual addresses are preserved throughout.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use zerocopy::{FromBytes, Immutable, IntoBytes};

use crate::error::{Error, Result};
use crate::macho::{
    DyldInfoCommand, DysymtabCommand, LC_ATOM_INFO, LC_BUILD_VERSION, LC_CODE_SIGNATURE,
    LC_DATA_IN_CODE, LC_DYLD_CHAINED_FIXUPS, LC_DYLD_ENVIRONMENT, LC_DYLD_EXPORTS_TRIE,
    LC_DYLD_INFO, LC_DYLD_INFO_ONLY, LC_DYLIB_CODE_SIGN_DRS, LC_DYSYMTAB, LC_ENCRYPTION_INFO,
    LC_ENCRYPTION_INFO_64, LC_FUNCTION_STARTS, LC_FVMFILE, LC_ID_DYLIB, LC_ID_DYLINKER, LC_IDENT,
    LC_IDFVMLIB, LC_LAZY_LOAD_DYLIB, LC_LINKER_OPTIMIZATION_HINT, LC_LINKER_OPTION, LC_LOAD_DYLIB,
    LC_LOAD_DYLINKER, LC_LOAD_UPWARD_DYLIB, LC_LOAD_WEAK_DYLIB, LC_LOADFVMLIB, LC_MAIN, LC_NOTE,
    LC_PREBIND_CKSUM, LC_PREBOUND_DYLIB, LC_PREPAGE, LC_REEXPORT_DYLIB, LC_ROUTINES,
    LC_ROUTINES_64, LC_RPATH, LC_SEGMENT, LC_SEGMENT_64, LC_SEGMENT_SPLIT_INFO, LC_SOURCE_VERSION,
    LC_SUB_CLIENT, LC_SUB_FRAMEWORK, LC_SUB_LIBRARY, LC_SUB_UMBRELLA, LC_SYMSEG, LC_SYMTAB,
    LC_THREAD, LC_TWOLEVEL_HINTS, LC_UNIXTHREAD, LC_UUID, LC_VERSION_MIN_IPHONEOS,
    LC_VERSION_MIN_MACOSX, LC_VERSION_MIN_TVOS, LC_VERSION_MIN_WATCHOS, LinkeditDataCommand,
    LoadCommandInfo, MachOContext, MachOFlags, N_INDR, N_STAB, N_TYPE, S_GB_ZEROFILL,
    S_THREAD_LOCAL_ZEROFILL, S_ZEROFILL, SECTION_TYPE, Section64, SegmentCommand64, SegmentInfo,
    SymtabCommand,
};

use super::fixups::Rebase;
use super::reader::{c_string_at, read_u16, read_u32, read_u64, slice, to_usize};
use super::{KernelCacheContext, KernelImage, LINKEDIT_SEGMENT, MAX_SIZE};

// =============================================================================
// Constants
// =============================================================================

/// LINKEDIT payloads that are dropped: signatures, split info, and decoded chains.
const DROPPED_LINKEDIT_COMMANDS: &[u32] = &[
    LC_CODE_SIGNATURE,
    LC_DYLD_CHAINED_FIXUPS,
    LC_SEGMENT_SPLIT_INFO,
    LC_DYLIB_CODE_SIGN_DRS,
];

/// LINKEDIT payloads that are copied unchanged.
const COPIED_LINKEDIT_COMMANDS: &[u32] = &[
    LC_FUNCTION_STARTS,
    LC_DYLD_EXPORTS_TRIE,
    LC_LINKER_OPTIMIZATION_HINT,
    LC_ATOM_INFO,
];

/// Commands with file offsets that extraction cannot relocate.
const UNSUPPORTED_COMMANDS: &[u32] = &[
    LC_NOTE,
    LC_MAIN,
    LC_SYMSEG,
    LC_TWOLEVEL_HINTS,
    LC_ENCRYPTION_INFO,
    LC_ENCRYPTION_INFO_64,
];

/// Commands without file offsets, which are kept unchanged.
const PASSTHROUGH_COMMANDS: &[u32] = &[
    LC_THREAD,
    LC_UNIXTHREAD,
    LC_LOADFVMLIB,
    LC_IDFVMLIB,
    LC_IDENT,
    LC_FVMFILE,
    LC_PREPAGE,
    LC_LOAD_DYLIB,
    LC_ID_DYLIB,
    LC_LOAD_DYLINKER,
    LC_ID_DYLINKER,
    LC_PREBOUND_DYLIB,
    LC_ROUTINES,
    LC_SUB_FRAMEWORK,
    LC_SUB_UMBRELLA,
    LC_SUB_CLIENT,
    LC_SUB_LIBRARY,
    LC_PREBIND_CKSUM,
    LC_LOAD_WEAK_DYLIB,
    LC_ROUTINES_64,
    LC_UUID,
    LC_RPATH,
    LC_REEXPORT_DYLIB,
    LC_LAZY_LOAD_DYLIB,
    LC_LOAD_UPWARD_DYLIB,
    LC_VERSION_MIN_MACOSX,
    LC_VERSION_MIN_IPHONEOS,
    LC_DYLD_ENVIRONMENT,
    LC_SOURCE_VERSION,
    LC_LINKER_OPTION,
    LC_VERSION_MIN_TVOS,
    LC_VERSION_MIN_WATCHOS,
    LC_BUILD_VERSION,
];

/// Sections holding legacy, section-based pointer chains.
const LEGACY_CHAIN_SECTIONS: &[&str] = &["__thread_starts", "__chain_starts"];

/// Alignment of copied segments and LINKEDIT tables.
const OUTPUT_ALIGNMENT: usize = 8;
/// Page size used for the rebuilt `__LINKEDIT` VM size.
const LINKEDIT_PAGE_SIZE: u64 = 0x1000;

/// Entry sizes of the tables referenced by load commands.
const RELOCATION_ENTRY_SIZE: u64 = 8;
const TOC_ENTRY_SIZE: u64 = 8;
const MODULE_ENTRY_SIZE: u64 = 52;
const MODULE_ENTRY_64_SIZE: u64 = 56;
const REFERENCE_ENTRY_SIZE: u64 = 4;
const INDIRECT_SYMBOL_SIZE: u64 = 4;
const DATA_IN_CODE_ENTRY_SIZE: usize = 8;

/// Offsets within an `nlist` entry.
const NLIST_TYPE_OFFSET: usize = 4;
const NLIST_VALUE_OFFSET: usize = 8;

// =============================================================================
// Public API
// =============================================================================

impl KernelCacheContext {
    /// Builds a standalone Mach-O for the image matching `query`.
    ///
    /// See [`resolve_image`](Self::resolve_image) for how `query` is matched
    /// and [`extract_image`](Self::extract_image) for the output.
    pub fn extract(&self, query: &str) -> Result<Vec<u8>> {
        self.extract_image(self.resolve_image(query)?)
    }

    /// Builds a standalone Mach-O of one image for static analysis.
    ///
    /// Virtual addresses are preserved. Chained pointers become unslid
    /// absolute pointers, code signatures are removed, and symbol names and
    /// LINKEDIT payloads are copied into a private `__LINKEDIT`.
    pub fn extract_image(&self, image: &KernelImage) -> Result<Vec<u8>> {
        reject_legacy_chains(&image.macho)?;
        let mut builder = ImageBuilder::new(self, image)?;
        builder.copy_segments()?;
        builder.copy_linkedit()?;
        builder.finish()
    }

    /// Extracts the image matching `query` to `path`, creating parent directories.
    pub fn extract_to(&self, query: &str, path: impl AsRef<Path>) -> Result<()> {
        let output = self.extract(query)?;
        let path = path.as_ref();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, output)?;
        Ok(())
    }
}

fn reject_legacy_chains(macho: &MachOContext) -> Result<()> {
    let has_legacy_chains = macho
        .segments()
        .flat_map(|segment| &segment.sections)
        .any(|section| {
            LEGACY_CHAIN_SECTIONS.contains(&section.name()) && section.section.size != 0
        });
    if has_legacy_chains {
        return Err(Error::parse(
            0,
            "legacy section-based pointer chains are not supported",
        ));
    }
    Ok(())
}

// =============================================================================
// Image Builder
// =============================================================================

/// A load command kept in the output.
struct OutputCommand {
    bytes: Vec<u8>,
    /// Rewritten sections of a segment command, keyed by their offset in `bytes`.
    /// Their relocation offsets are assigned in the LINKEDIT phase.
    sections: Vec<(usize, Section64)>,
}

impl OutputCommand {
    fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            sections: Vec::new(),
        }
    }
}

/// Where a source segment's file contents were copied.
struct Placement {
    source_offset: u64,
    size: u64,
    output_offset: usize,
}

/// Assembles one extracted image.
struct ImageBuilder<'a> {
    cache: &'a KernelCacheContext,
    image: &'a KernelImage,
    macho: &'a MachOContext,
    rebases: &'a [Rebase],
    output: Vec<u8>,
    commands: Vec<OutputCommand>,
    /// Index of the `__LINKEDIT` command in `commands`, and its original segment.
    linkedit: Option<(usize, SegmentCommand64)>,
    /// Output offset at which LINKEDIT tables begin.
    linkedit_start: usize,
    placements: Vec<Placement>,
}

impl<'a> ImageBuilder<'a> {
    fn new(cache: &'a KernelCacheContext, image: &'a KernelImage) -> Result<Self> {
        Ok(Self {
            cache,
            image,
            macho: &image.macho,
            rebases: cache.rebases()?,
            output: Vec::new(),
            commands: Vec::new(),
            linkedit: None,
            linkedit_start: 0,
            placements: Vec::new(),
        })
    }

    // -------------------------------------------------------------------------
    // Phase 1: segments
    // -------------------------------------------------------------------------

    fn copy_segments(&mut self) -> Result<()> {
        let mut header_copied = false;
        for load_command in &self.macho.load_commands {
            if is_dropped(load_command) {
                continue;
            }
            let bytes = slice(
                &self.macho.data,
                load_command.offset(),
                load_command.size() as usize,
            )?
            .to_vec();
            let command = match load_command {
                LoadCommandInfo::Segment(segment) if segment.name() == LINKEDIT_SEGMENT => {
                    if !segment.sections.is_empty() {
                        return Err(Error::parse(0, "sectioned LINKEDIT is unsupported"));
                    }
                    self.linkedit = Some((self.commands.len(), segment.command));
                    OutputCommand::new(bytes)
                }
                LoadCommandInfo::Segment(segment) => {
                    self.copy_segment(segment, bytes, &mut header_copied)?
                }
                _ => OutputCommand::new(bytes),
            };
            self.commands.push(command);
        }
        if !header_copied {
            return Err(Error::parse(0, "member has no file-backed header segment"));
        }
        Ok(())
    }

    /// Copies a segment's contents and rewrites its command and section file offsets.
    fn copy_segment(
        &mut self,
        segment: &SegmentInfo,
        mut bytes: Vec<u8>,
        header_copied: &mut bool,
    ) -> Result<OutputCommand> {
        let source = segment.command;
        let output_offset = if source.filesize == 0 {
            0
        } else {
            self.copy_segment_contents(&source, header_copied)?
        };

        let mut command = source;
        command.fileoff = output_offset as u64;
        let command_size = self.macho.segment_command_size();
        bytes[..command_size].copy_from_slice(&self.macho.segment_bytes(&command)?);

        let mut sections = Vec::with_capacity(segment.sections.len());
        for info in &segment.sections {
            let mut section = info.section;
            section.offset = if is_zerofill(&section) || section.size == 0 {
                0
            } else {
                let delta = u64::from(section.offset)
                    .checked_sub(source.fileoff)
                    .filter(|delta| {
                        delta
                            .checked_add(section.size)
                            .is_some_and(|end| end <= source.filesize)
                    })
                    .ok_or_else(|| {
                        Error::parse(
                            info.struct_offset,
                            "section is outside its file-backed segment",
                        )
                    })?;
                u32::try_from(output_offset as u64 + delta)
                    .map_err(|_| Error::parse(0, "section offset overflow"))?
            };
            sections.push((info.struct_offset - segment.command_offset, section));
        }
        Ok(OutputCommand { bytes, sections })
    }

    /// Appends a segment's file contents and applies the rebases that fall inside it.
    fn copy_segment_contents(
        &mut self,
        segment: &SegmentCommand64,
        header_copied: &mut bool,
    ) -> Result<usize> {
        let cache = self.cache;
        let source = cache.member_offset(self.image, segment.fileoff)?;
        let contents = cache.member_bytes(self.image, segment.fileoff, segment.filesize)?;
        let output_offset = append_aligned(&mut self.output, contents)?;
        self.placements.push(Placement {
            source_offset: segment.fileoff,
            size: segment.filesize,
            output_offset,
        });

        if source == to_usize(self.image.file_offset)? {
            // The header is rewritten in place in phase 3, so it must lead the output.
            if *header_copied || output_offset != 0 || contents.len() < self.macho.data.len() {
                return Err(Error::parse(
                    source,
                    "embedded header is not at start of first file-backed segment",
                ));
            }
            *header_copied = true;
        }

        let end = source + contents.len();
        let first = self
            .rebases
            .partition_point(|rebase| rebase.offset < source);
        for rebase in self.rebases[first..]
            .iter()
            .take_while(|rebase| rebase.offset < end)
        {
            if rebase.offset + 8 > end {
                return Err(Error::parse(
                    rebase.offset,
                    "fixup straddles member segment boundary",
                ));
            }
            let at = output_offset + (rebase.offset - source);
            self.output[at..at + 8].copy_from_slice(&rebase.target.to_le_bytes());
        }
        Ok(output_offset)
    }

    // -------------------------------------------------------------------------
    // Phase 2: LINKEDIT
    // -------------------------------------------------------------------------

    fn copy_linkedit(&mut self) -> Result<()> {
        self.linkedit_start = self.output.len().next_multiple_of(OUTPUT_ALIGNMENT);
        self.output.resize(self.linkedit_start, 0);
        let mut commands = std::mem::take(&mut self.commands);
        for command in &mut commands {
            self.copy_command_tables(command)?;
        }
        self.commands = commands;
        Ok(())
    }

    /// Copies the LINKEDIT tables a command references and updates its offsets.
    fn copy_command_tables(&mut self, command: &mut OutputCommand) -> Result<()> {
        match read_u32(&command.bytes, 0)? {
            LC_SEGMENT | LC_SEGMENT_64 => self.copy_relocations(command),
            LC_SYMTAB => self.copy_symtab(&mut command.bytes),
            LC_DYSYMTAB => self.copy_dysymtab(&mut command.bytes),
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => self.copy_dyld_info(&mut command.bytes),
            LC_DATA_IN_CODE => self.copy_data_in_code(&mut command.bytes),
            cmd if COPIED_LINKEDIT_COMMANDS.contains(&cmd) => {
                self.copy_linkedit_data(&mut command.bytes)
            }
            cmd if UNSUPPORTED_COMMANDS.contains(&cmd) => Err(Error::parse(
                0,
                format!("unsupported kernelcache extraction load command {cmd:#x}"),
            )),
            cmd if PASSTHROUGH_COMMANDS.contains(&cmd) => Ok(()),
            cmd => Err(Error::parse(
                0,
                format!("unknown kernelcache extraction load command {cmd:#x}"),
            )),
        }
    }

    /// Copies each section's relocation entries and serializes the final sections.
    fn copy_relocations(&mut self, command: &mut OutputCommand) -> Result<()> {
        let section_size = self.macho.section_size();
        for (offset, section) in &mut command.sections {
            section.reloff = self.copy_table(
                section.reloff.into(),
                u64::from(section.nreloc) * RELOCATION_ENTRY_SIZE,
            )?;
            command.bytes[*offset..*offset + section_size]
                .copy_from_slice(&self.macho.section_bytes(section)?);
        }
        Ok(())
    }

    /// Copies the symbol table and a string table holding only the names it references.
    fn copy_symtab(&mut self, bytes: &mut [u8]) -> Result<()> {
        let mut symtab: SymtabCommand = read_command(bytes)?;
        let cache = self.cache;
        let strings =
            cache.member_bytes(self.image, symtab.stroff.into(), symtab.strsize.into())?;
        let entry_size = self.macho.nlist_size();
        let mut symbols = cache
            .member_bytes(
                self.image,
                symtab.symoff.into(),
                u64::from(symtab.nsyms) * entry_size as u64,
            )?
            .to_vec();

        let mut names = StringTable::new(strings);
        for entry in symbols.chunks_exact_mut(entry_size) {
            let name = names.intern(read_u32(entry, 0)?)?;
            entry[..4].copy_from_slice(&name.to_le_bytes());

            // An indirect symbol's value is the string index of the name it aliases.
            let n_type = entry[NLIST_TYPE_OFFSET];
            if n_type & N_TYPE != N_INDR || n_type & N_STAB != 0 {
                continue;
            }
            let value = NLIST_VALUE_OFFSET;
            if self.macho.is_64() {
                let alias = u32::try_from(read_u64(entry, value)?)
                    .map_err(|_| Error::parse(0, "indirect symbol string index overflow"))?;
                let alias = u64::from(names.intern(alias)?);
                entry[value..value + 8].copy_from_slice(&alias.to_le_bytes());
            } else {
                let alias = names.intern(read_u32(entry, value)?)?;
                entry[value..value + 4].copy_from_slice(&alias.to_le_bytes());
            }
        }

        symtab.symoff = self.append(&symbols)?;
        symtab.stroff = self.append(&names.bytes)?;
        symtab.strsize = to_u32(names.bytes.len())?;
        write_command(bytes, &symtab);
        Ok(())
    }

    fn copy_dysymtab(&mut self, bytes: &mut [u8]) -> Result<()> {
        let mut dysymtab: DysymtabCommand = read_command(bytes)?;
        let module_size = if self.macho.is_64() {
            MODULE_ENTRY_64_SIZE
        } else {
            MODULE_ENTRY_SIZE
        };
        dysymtab.tocoff = self.copy_entries(dysymtab.tocoff, dysymtab.ntoc, TOC_ENTRY_SIZE)?;
        dysymtab.modtaboff =
            self.copy_entries(dysymtab.modtaboff, dysymtab.nmodtab, module_size)?;
        dysymtab.extrefsymoff = self.copy_entries(
            dysymtab.extrefsymoff,
            dysymtab.nextrefsyms,
            REFERENCE_ENTRY_SIZE,
        )?;
        dysymtab.indirectsymoff = self.copy_entries(
            dysymtab.indirectsymoff,
            dysymtab.nindirectsyms,
            INDIRECT_SYMBOL_SIZE,
        )?;
        dysymtab.extreloff =
            self.copy_entries(dysymtab.extreloff, dysymtab.nextrel, RELOCATION_ENTRY_SIZE)?;
        dysymtab.locreloff =
            self.copy_entries(dysymtab.locreloff, dysymtab.nlocrel, RELOCATION_ENTRY_SIZE)?;
        write_command(bytes, &dysymtab);
        Ok(())
    }

    fn copy_dyld_info(&mut self, bytes: &mut [u8]) -> Result<()> {
        let mut info: DyldInfoCommand = read_command(bytes)?;
        info.rebase_off = self.copy_table(info.rebase_off.into(), info.rebase_size.into())?;
        info.bind_off = self.copy_table(info.bind_off.into(), info.bind_size.into())?;
        info.weak_bind_off =
            self.copy_table(info.weak_bind_off.into(), info.weak_bind_size.into())?;
        info.lazy_bind_off =
            self.copy_table(info.lazy_bind_off.into(), info.lazy_bind_size.into())?;
        info.export_off = self.copy_table(info.export_off.into(), info.export_size.into())?;
        write_command(bytes, &info);
        Ok(())
    }

    fn copy_linkedit_data(&mut self, bytes: &mut [u8]) -> Result<()> {
        let mut command: LinkeditDataCommand = read_command(bytes)?;
        command.dataoff = self.copy_table(command.dataoff.into(), command.datasize.into())?;
        write_command(bytes, &command);
        Ok(())
    }

    /// Copies data-in-code entries, translating their file offsets into the output.
    fn copy_data_in_code(&mut self, bytes: &mut [u8]) -> Result<()> {
        let mut command: LinkeditDataCommand = read_command(bytes)?;
        let mut entries = self
            .cache
            .member_bytes(self.image, command.dataoff.into(), command.datasize.into())?
            .to_vec();
        if entries.len() % DATA_IN_CODE_ENTRY_SIZE != 0 {
            return Err(Error::parse(0, "invalid data-in-code table size"));
        }
        // data_in_code_entry: offset (u32), length (u16), kind (u16).
        for entry in entries.chunks_exact_mut(DATA_IN_CODE_ENTRY_SIZE) {
            let offset = u64::from(read_u32(entry, 0)?);
            let length = u64::from(read_u16(entry, 4)?);
            let relocated = self.relocate(offset, length).ok_or_else(|| {
                Error::parse(
                    offset as usize,
                    "data-in-code entry is outside member segments",
                )
            })?;
            entry[..4].copy_from_slice(&to_u32(relocated)?.to_le_bytes());
        }
        command.dataoff = if entries.is_empty() {
            0
        } else {
            self.append(&entries)?
        };
        write_command(bytes, &command);
        Ok(())
    }

    /// Translates a source file range to its output offset, if one segment copy holds it.
    fn relocate(&self, offset: u64, length: u64) -> Option<usize> {
        self.placements.iter().find_map(|placement| {
            let delta = offset.checked_sub(placement.source_offset)?;
            (delta + length <= placement.size).then(|| placement.output_offset + delta as usize)
        })
    }

    /// Copies `count` table entries of `entry_size` bytes; returns 0 for an empty table.
    fn copy_entries(&mut self, offset: u32, count: u32, entry_size: u64) -> Result<u32> {
        self.copy_table(offset.into(), u64::from(count) * entry_size)
    }

    /// Copies `size` bytes of a LINKEDIT table; returns 0 for an empty table.
    fn copy_table(&mut self, offset: u64, size: u64) -> Result<u32> {
        if size == 0 {
            return Ok(0);
        }
        let bytes = self.cache.member_bytes(self.image, offset, size)?;
        to_u32(append_aligned(&mut self.output, bytes)?)
    }

    fn append(&mut self, bytes: &[u8]) -> Result<u32> {
        to_u32(append_aligned(&mut self.output, bytes)?)
    }

    // -------------------------------------------------------------------------
    // Phase 3: header
    // -------------------------------------------------------------------------

    fn finish(mut self) -> Result<Vec<u8>> {
        let linkedit_size = (self.output.len() - self.linkedit_start) as u64;
        match self.linkedit {
            Some((index, mut segment)) => {
                segment.fileoff = self.linkedit_start as u64;
                segment.filesize = linkedit_size;
                segment.vmsize = linkedit_size.next_multiple_of(LINKEDIT_PAGE_SIZE);
                let command_size = self.macho.segment_command_size();
                self.commands[index].bytes[..command_size]
                    .copy_from_slice(&self.macho.segment_bytes(&segment)?);
            }
            None if linkedit_size > 0 => {
                return Err(Error::parse(
                    0,
                    "member has LINKEDIT data without a LINKEDIT segment",
                ));
            }
            None => {}
        }
        self.write_header()?;
        Ok(self.output)
    }

    /// Writes the header and commands over the original header region.
    fn write_header(&mut self) -> Result<()> {
        let header_size = self.macho.header_size();
        let original_size = self.macho.data.len();
        let commands_size: usize = self
            .commands
            .iter()
            .map(|command| command.bytes.len())
            .sum();
        if header_size + commands_size > original_size {
            return Err(Error::parse(0, "rewritten header exceeds original header"));
        }

        let mut header = self.macho.header;
        header.ncmds = to_u32(self.commands.len())?;
        header.sizeofcmds = to_u32(commands_size)?;
        header.flags &= !MachOFlags::DYLIB_IN_CACHE.bits();

        let region = &mut self.output[..original_size];
        region.fill(0);
        // A 32-bit header is a prefix of the widened 64-bit layout.
        region[..header_size].copy_from_slice(&header.as_bytes()[..header_size]);
        let mut offset = header_size;
        for command in &self.commands {
            region[offset..offset + command.bytes.len()].copy_from_slice(&command.bytes);
            offset += command.bytes.len();
        }
        Ok(())
    }
}

// =============================================================================
// Helpers
// =============================================================================

/// A string table that copies each referenced name once.
struct StringTable<'a> {
    source: &'a [u8],
    bytes: Vec<u8>,
    /// Source string index to output string index.
    remapped: HashMap<u32, u32>,
}

impl<'a> StringTable<'a> {
    fn new(source: &'a [u8]) -> Self {
        // Index 0 is the empty string in every string table.
        Self {
            source,
            bytes: vec![0],
            remapped: HashMap::from([(0, 0)]),
        }
    }

    fn intern(&mut self, index: u32) -> Result<u32> {
        if let Some(&remapped) = self.remapped.get(&index) {
            return Ok(remapped);
        }
        let name = c_string_at(self.source, index)?;
        let remapped = to_u32(self.bytes.len())?;
        self.bytes.extend_from_slice(name);
        self.bytes.push(0);
        self.remapped.insert(index, remapped);
        Ok(remapped)
    }
}

fn is_dropped(load_command: &LoadCommandInfo) -> bool {
    match load_command {
        LoadCommandInfo::FilesetEntry { .. } => true,
        LoadCommandInfo::LinkeditData { command, .. } => {
            DROPPED_LINKEDIT_COMMANDS.contains(&command.cmd)
        }
        _ => false,
    }
}

fn is_zerofill(section: &Section64) -> bool {
    matches!(
        section.flags & SECTION_TYPE,
        S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
    )
}

/// Appends `bytes` at the next aligned offset and returns that offset.
fn append_aligned(output: &mut Vec<u8>, bytes: &[u8]) -> Result<usize> {
    let offset = output
        .len()
        .checked_next_multiple_of(OUTPUT_ALIGNMENT)
        .ok_or_else(|| Error::parse(0, "output size overflow"))?;
    if offset
        .checked_add(bytes.len())
        .is_none_or(|end| end > MAX_SIZE)
    {
        return Err(Error::parse(offset, "extracted image exceeds 1 GiB"));
    }
    output.resize(offset, 0);
    output.extend_from_slice(bytes);
    Ok(offset)
}

/// Converts an output offset or size to a 32-bit load command field.
fn to_u32(value: usize) -> Result<u32> {
    u32::try_from(value).map_err(|_| Error::parse(0, "standalone file offset exceeds 32 bits"))
}

/// Reads a fixed-layout load command from the start of its bytes.
fn read_command<T: FromBytes>(bytes: &[u8]) -> Result<T> {
    T::read_from_prefix(bytes)
        .map(|(command, _)| command)
        .map_err(|_| Error::parse(0, "truncated load command"))
}

/// Writes a fixed-layout load command over the start of its bytes.
fn write_command<T: IntoBytes + Immutable>(bytes: &mut [u8], command: &T) {
    let encoded = command.as_bytes();
    bytes[..encoded.len()].copy_from_slice(encoded);
}
