//! Mach-O context for reading and modifying Mach-O files.

use std::collections::HashMap;

use zerocopy::{FromBytes, IntoBytes};

use super::constants::*;
use super::structs::*;
use crate::error::{Error, Result};

// =============================================================================
// Segment Info
// =============================================================================

/// Parsed segment information.
#[derive(Debug, Clone)]
pub struct SegmentInfo {
    /// Segment fields widened to 64-bit integers for either on-disk ABI.
    /// Serialize with MachOContext::write_segment to preserve the input ABI.
    pub command: SegmentCommand64,
    /// Offset of the segment command in the file
    pub command_offset: usize,
    /// Sections in this segment
    pub sections: Vec<SectionInfo>,
}

impl SegmentInfo {
    /// Returns the segment name.
    pub fn name(&self) -> &str {
        self.command.name()
    }

    /// Returns a section by name.
    pub fn section(&self, name: &str) -> Option<&SectionInfo> {
        self.sections.iter().find(|s| s.section.name() == name)
    }

    /// Returns a mutable reference to a section by name.
    pub fn section_mut(&mut self, name: &str) -> Option<&mut SectionInfo> {
        self.sections.iter_mut().find(|s| s.section.name() == name)
    }
}

/// Parsed section information.
#[derive(Debug, Clone)]
pub struct SectionInfo {
    /// Section fields widened to 64-bit integers for either on-disk ABI.
    /// Serialize with MachOContext::write_section to preserve the input ABI.
    pub section: Section64,
    /// Offset of the section structure in the file
    pub struct_offset: usize,
}

impl SectionInfo {
    /// Returns the section name.
    pub fn name(&self) -> &str {
        self.section.name()
    }

    /// Returns the full name (segment,section).
    pub fn full_name(&self) -> String {
        format!("{},{}", self.section.segment_name(), self.section.name())
    }
}

// =============================================================================
// Load Command Info
// =============================================================================

/// Parsed load command information.
///
/// Represents the various types of load commands found in a Mach-O file.
/// The variant names correspond to the load command types.
#[derive(Debug, Clone)]
#[allow(missing_docs)] // Variants are self-documenting via names
pub enum LoadCommandInfo {
    Segment(SegmentInfo),
    Symtab {
        command: SymtabCommand,
        offset: usize,
    },
    Dysymtab {
        command: DysymtabCommand,
        offset: usize,
    },
    DyldInfo {
        command: DyldInfoCommand,
        offset: usize,
    },
    LinkeditData {
        command: LinkeditDataCommand,
        offset: usize,
    },
    Dylib {
        command: DylibCommand,
        name: String,
        offset: usize,
    },
    Uuid {
        command: UuidCommand,
        offset: usize,
    },
    BuildVersion {
        command: BuildVersionCommand,
        offset: usize,
    },
    FilesetEntry {
        command: FilesetEntryCommand,
        entry_id: String,
        offset: usize,
    },
    Unknown {
        cmd: u32,
        cmdsize: u32,
        offset: usize,
    },
}

impl LoadCommandInfo {
    /// Returns the load command offset.
    pub fn offset(&self) -> usize {
        match self {
            LoadCommandInfo::Segment(s) => s.command_offset,
            LoadCommandInfo::Symtab { offset, .. } => *offset,
            LoadCommandInfo::Dysymtab { offset, .. } => *offset,
            LoadCommandInfo::DyldInfo { offset, .. } => *offset,
            LoadCommandInfo::LinkeditData { offset, .. } => *offset,
            LoadCommandInfo::Dylib { offset, .. } => *offset,
            LoadCommandInfo::Uuid { offset, .. } => *offset,
            LoadCommandInfo::BuildVersion { offset, .. } => *offset,
            LoadCommandInfo::FilesetEntry { offset, .. } => *offset,
            LoadCommandInfo::Unknown { offset, .. } => *offset,
        }
    }

    /// Returns the load command size.
    pub fn size(&self) -> u32 {
        match self {
            LoadCommandInfo::Segment(s) => s.command.cmdsize,
            LoadCommandInfo::Symtab { command, .. } => command.cmdsize,
            LoadCommandInfo::Dysymtab { command, .. } => command.cmdsize,
            LoadCommandInfo::DyldInfo { command, .. } => command.cmdsize,
            LoadCommandInfo::LinkeditData { command, .. } => command.cmdsize,
            LoadCommandInfo::Dylib { command, .. } => command.cmdsize,
            LoadCommandInfo::Uuid { command, .. } => command.cmdsize,
            LoadCommandInfo::BuildVersion { command, .. } => command.cmdsize,
            LoadCommandInfo::FilesetEntry { command, .. } => command.cmdsize,
            LoadCommandInfo::Unknown { cmdsize, .. } => *cmdsize,
        }
    }
}

// =============================================================================
// Mach-O Context
// =============================================================================

/// Pre-computed segment range for fast address lookups.
#[derive(Debug, Clone, Copy)]
struct SegmentRange {
    vmaddr: u64,
    vmsize: u64,
    fileoff: u64,
}

/// Context for working with a Mach-O file.
///
/// This provides a high-level interface for reading and modifying Mach-O files,
/// including segments, sections, load commands, and symbols.
#[derive(Debug)]
pub struct MachOContext {
    /// Widened header fields. For MH_MAGIC, `reserved` is synthetic zero;
    /// use `header_size()` and `sync_header()` for on-disk serialization.
    pub header: MachHeader64,
    /// Offset of this Mach-O within the containing file/cache
    pub base_offset: usize,
    /// Mutable copy of the Mach-O data
    pub data: Vec<u8>,
    /// Parsed load commands
    pub load_commands: Vec<LoadCommandInfo>,
    /// Segment lookup by name
    segment_indices: HashMap<String, usize>,
    /// Pre-computed segment ranges for fast address lookups (sorted by vmaddr)
    segment_ranges: Vec<SegmentRange>,
}

impl MachOContext {
    // Public parsed structures use widened integers, while raw bytes retain the
    // original ABI. Always serialize through these helpers for width-dependent data.
    fn read_header(data: &[u8]) -> Result<MachHeader64> {
        let magic = data
            .get(..4)
            .map(crate::util::read_u32_le)
            .ok_or(Error::BufferTooSmall {
                needed: 4,
                available: data.len(),
            })?;
        let size = match magic {
            MH_MAGIC => 28,
            MH_MAGIC_64 => 32,
            _ => return Err(Error::InvalidMachoMagic(magic)),
        };
        if data.len() < size {
            return Err(Error::BufferTooSmall {
                needed: size,
                available: data.len(),
            });
        }
        let mut bytes = [0u8; 32];
        bytes[..size].copy_from_slice(&data[..size]);
        Ok(MachHeader64::read_from_prefix(&bytes).unwrap().0)
    }

    /// Whether the on-disk image uses the 64-bit Mach-O ABI.
    pub fn is_64(&self) -> bool {
        self.header.magic == MH_MAGIC_64
    }
    /// On-disk header size in bytes.
    pub fn header_size(&self) -> usize {
        if self.is_64() { 32 } else { 28 }
    }
    /// On-disk pointer width in bytes.
    pub fn pointer_size(&self) -> usize {
        if self.is_64() { 8 } else { 4 }
    }
    /// On-disk segment command size in bytes, excluding sections.
    pub fn segment_command_size(&self) -> usize {
        if self.is_64() { 72 } else { 56 }
    }
    /// On-disk section record size in bytes.
    pub fn section_size(&self) -> usize {
        if self.is_64() { 80 } else { 68 }
    }
    /// On-disk symbol record size in bytes.
    pub fn nlist_size(&self) -> usize {
        if self.is_64() { 16 } else { 12 }
    }
    /// Reads a pointer without consuming an adjacent 32-bit slot.
    pub fn read_pointer(&self, offset: usize) -> Result<u64> {
        if self.is_64() {
            self.read_u64(offset)
        } else {
            Ok(self.read_u32(offset)? as u64)
        }
    }
    /// Writes an ABI-sized pointer, rejecting truncation.
    pub fn write_pointer(&mut self, offset: usize, value: u64) -> Result<()> {
        if self.is_64() {
            self.write_u64(offset, value)
        } else {
            let value = u32::try_from(value).map_err(|_| Error::Parse {
                offset,
                reason: "32-bit pointer overflow".into(),
            })?;
            self.write_u32(offset, value)
        }
    }
    /// Serializes a widened segment using this image's on-disk ABI.
    pub fn write_segment(&mut self, offset: usize, segment: &SegmentCommand64) -> Result<()> {
        self.write_at(offset, &self.segment_bytes(segment)?)
    }
    /// Encodes a widened segment without mutating the image.
    pub fn segment_bytes(&self, segment: &SegmentCommand64) -> Result<Vec<u8>> {
        let offset = 0;
        if self.is_64() {
            return Ok(segment.as_bytes().to_vec());
        }
        let mut bytes = Vec::with_capacity(56);
        bytes.extend_from_slice(&LC_SEGMENT.to_le_bytes());
        bytes.extend_from_slice(&segment.cmdsize.to_le_bytes());
        bytes.extend_from_slice(&segment.segname);
        for value in [
            segment.vmaddr,
            segment.vmsize,
            segment.fileoff,
            segment.filesize,
        ] {
            let value = u32::try_from(value).map_err(|_| Error::Parse {
                offset,
                reason: "32-bit segment field overflow".into(),
            })?;
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        for value in [
            segment.maxprot,
            segment.initprot,
            segment.nsects,
            segment.flags,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        Ok(bytes)
    }
    /// Serializes a widened section using this image's on-disk ABI.
    pub fn write_section(&mut self, offset: usize, section: &Section64) -> Result<()> {
        self.write_at(offset, &self.section_bytes(section)?)
    }
    /// Encodes a widened section without mutating the image.
    pub fn section_bytes(&self, section: &Section64) -> Result<Vec<u8>> {
        let offset = 0;
        if self.is_64() {
            return Ok(section.as_bytes().to_vec());
        }
        let mut bytes = Vec::with_capacity(68);
        bytes.extend_from_slice(&section.sectname);
        bytes.extend_from_slice(&section.segname);
        for value in [section.addr, section.size] {
            let value = u32::try_from(value).map_err(|_| Error::Parse {
                offset,
                reason: "32-bit section field overflow".into(),
            })?;
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        for value in [
            section.offset,
            section.align,
            section.reloff,
            section.nreloc,
            section.flags,
            section.reserved1,
            section.reserved2,
        ] {
            bytes.extend_from_slice(&value.to_le_bytes());
        }
        Ok(bytes)
    }

    /// Creates a new MachO context from raw data.
    ///
    /// # Arguments
    /// * `data` - The raw Mach-O data (will be copied)
    /// * `base_offset` - Offset of this Mach-O within a larger file (for address conversion)
    pub fn new(data: &[u8], base_offset: usize) -> Result<Self> {
        let header = Self::read_header(data)?;

        let mut ctx = Self {
            header: header.clone(),
            base_offset,
            data: data.to_vec(),
            load_commands: Vec::with_capacity(32), // Pre-allocate for typical dylib
            segment_indices: HashMap::new(),
            segment_ranges: Vec::with_capacity(8), // Pre-allocate for typical segments
        };

        ctx.parse_load_commands()?;
        ctx.build_segment_ranges();

        Ok(ctx)
    }

    /// Builds the segment_ranges cache for fast address lookups.
    fn build_segment_ranges(&mut self) {
        self.segment_ranges.clear();
        // Collect segment data without borrowing self
        for lc in &self.load_commands {
            if let LoadCommandInfo::Segment(seg) = lc {
                if seg.command.vmsize > 0 {
                    self.segment_ranges.push(SegmentRange {
                        vmaddr: seg.command.vmaddr,
                        vmsize: seg.command.filesize,
                        fileoff: seg.command.fileoff,
                    });
                }
            }
        }
        // Sort by vmaddr for binary search
        self.segment_ranges.sort_by_key(|r| r.vmaddr);
    }

    /// Rebuilds parsed commands and address indexes after changing raw commands.
    pub fn refresh(&mut self) -> Result<()> {
        self.header = Self::read_header(&self.data)?;
        self.load_commands.clear();
        self.segment_indices.clear();
        self.parse_load_commands()?;
        self.build_segment_ranges();
        Ok(())
    }

    /// Creates a context from a slice within a dyld cache.
    pub fn from_cache_slice(cache_data: &[u8], offset: usize, size: usize) -> Result<Self> {
        if offset + size > cache_data.len() {
            return Err(Error::BufferTooSmall {
                needed: offset + size,
                available: cache_data.len(),
            });
        }
        Self::new(&cache_data[offset..offset + size], offset)
    }

    /// Parses all load commands.
    fn parse_load_commands(&mut self) -> Result<()> {
        let mut offset = self.header_size();
        let end_offset = self.header_size() + self.header.sizeofcmds as usize;

        for _ in 0..self.header.ncmds {
            if offset + LoadCommand::SIZE > end_offset
                || offset + LoadCommand::SIZE > self.data.len()
            {
                return Err(Error::LoadCommandOverflow { offset });
            }

            let lc = LoadCommand::read_from_prefix(&self.data[offset..])
                .map_err(|_| Error::Parse {
                    offset,
                    reason: "failed to parse load command".into(),
                })?
                .0;

            if lc.cmdsize < 8
                || offset + lc.cmdsize as usize > end_offset
                || offset + lc.cmdsize as usize > self.data.len()
            {
                return Err(Error::LoadCommandOverflow { offset });
            }

            let cmd_data = &self.data[offset..offset + lc.cmdsize as usize];
            let cmd_info = self.parse_load_command(lc.cmd, cmd_data, offset)?;

            // Track segment indices
            if let LoadCommandInfo::Segment(ref seg) = cmd_info {
                self.segment_indices
                    .insert(seg.name().to_string(), self.load_commands.len());
            }

            self.load_commands.push(cmd_info);
            offset += lc.cmdsize as usize;
        }

        Ok(())
    }

    /// Parses a single load command.
    fn parse_load_command(&self, cmd: u32, data: &[u8], offset: usize) -> Result<LoadCommandInfo> {
        match cmd {
            LC_SEGMENT | LC_SEGMENT_64 => {
                let is_64 = cmd == LC_SEGMENT_64;
                if is_64 != self.is_64() {
                    return Err(Error::Parse {
                        offset,
                        reason: "segment command width differs from Mach-O header".into(),
                    });
                }
                let segment_size = self.segment_command_size();
                let section_size = self.section_size();
                if data.len() < segment_size {
                    return Err(Error::LoadCommandOverflow { offset });
                }
                let seg = if is_64 {
                    SegmentCommand64::read_from_prefix(data).unwrap().0
                } else {
                    let u = |i| crate::util::read_u32_le(&data[i..]);
                    SegmentCommand64 {
                        cmd,
                        cmdsize: u(4),
                        segname: data[8..24].try_into().unwrap(),
                        vmaddr: u(24) as u64,
                        vmsize: u(28) as u64,
                        fileoff: u(32) as u64,
                        filesize: u(36) as u64,
                        maxprot: u(40),
                        initprot: u(44),
                        nsects: u(48),
                        flags: u(52),
                    }
                };
                if (seg.nsects as usize)
                    .checked_mul(section_size)
                    .and_then(|n| segment_size.checked_add(n))
                    .is_none_or(|n| n > data.len())
                {
                    return Err(Error::LoadCommandOverflow { offset });
                }
                let mut sections = Vec::with_capacity(seg.nsects as usize);
                for i in 0..seg.nsects as usize {
                    let local = segment_size + i * section_size;
                    let raw = &data[local..local + section_size];
                    let section = if is_64 {
                        Section64::read_from_prefix(raw).unwrap().0
                    } else {
                        let u = |i| crate::util::read_u32_le(&raw[i..]);
                        Section64 {
                            sectname: raw[..16].try_into().unwrap(),
                            segname: raw[16..32].try_into().unwrap(),
                            addr: u(32) as u64,
                            size: u(36) as u64,
                            offset: u(40),
                            align: u(44),
                            reloff: u(48),
                            nreloc: u(52),
                            flags: u(56),
                            reserved1: u(60),
                            reserved2: u(64),
                            reserved3: 0,
                        }
                    };
                    sections.push(SectionInfo {
                        section,
                        struct_offset: offset + local,
                    });
                }
                Ok(LoadCommandInfo::Segment(SegmentInfo {
                    command: seg,
                    command_offset: offset,
                    sections,
                }))
            }

            LC_SYMTAB => {
                let symtab = SymtabCommand::read_from_prefix(data)
                    .map_err(|_| Error::Parse {
                        offset,
                        reason: "failed to parse symtab command".into(),
                    })?
                    .0;

                Ok(LoadCommandInfo::Symtab {
                    command: symtab.clone(),
                    offset,
                })
            }

            LC_DYSYMTAB => {
                let dysymtab = DysymtabCommand::read_from_prefix(data)
                    .map_err(|_| Error::Parse {
                        offset,
                        reason: "failed to parse dysymtab command".into(),
                    })?
                    .0;

                Ok(LoadCommandInfo::Dysymtab {
                    command: dysymtab.clone(),
                    offset,
                })
            }

            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => {
                let dyld_info = DyldInfoCommand::read_from_prefix(data)
                    .map_err(|_| Error::Parse {
                        offset,
                        reason: "failed to parse dyld info command".into(),
                    })?
                    .0;

                Ok(LoadCommandInfo::DyldInfo {
                    command: dyld_info.clone(),
                    offset,
                })
            }

            LC_CODE_SIGNATURE
            | LC_SEGMENT_SPLIT_INFO
            | LC_FUNCTION_STARTS
            | LC_DATA_IN_CODE
            | LC_DYLD_EXPORTS_TRIE
            | LC_DYLD_CHAINED_FIXUPS
            | LC_LINKER_OPTIMIZATION_HINT
            | LC_ATOM_INFO => {
                let linkedit = LinkeditDataCommand::read_from_prefix(data)
                    .map_err(|_| Error::Parse {
                        offset,
                        reason: "failed to parse linkedit data command".into(),
                    })?
                    .0;

                Ok(LoadCommandInfo::LinkeditData {
                    command: linkedit.clone(),
                    offset,
                })
            }

            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB | LC_LAZY_LOAD_DYLIB
            | LC_LOAD_UPWARD_DYLIB | LC_ID_DYLIB => {
                let dylib = DylibCommand::read_from_prefix(data)
                    .map_err(|_| Error::Parse {
                        offset,
                        reason: "failed to parse dylib command".into(),
                    })?
                    .0;

                // Read the dylib name
                let name_offset = dylib.dylib.name_offset as usize;
                let name = if name_offset < data.len() {
                    let name_bytes = &data[name_offset..];
                    let end = name_bytes
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(name_bytes.len());
                    String::from_utf8_lossy(&name_bytes[..end]).to_string()
                } else {
                    String::new()
                };

                Ok(LoadCommandInfo::Dylib {
                    command: dylib.clone(),
                    name,
                    offset,
                })
            }

            LC_UUID => {
                let uuid = UuidCommand::read_from_prefix(data)
                    .map_err(|_| Error::Parse {
                        offset,
                        reason: "failed to parse uuid command".into(),
                    })?
                    .0;

                Ok(LoadCommandInfo::Uuid {
                    command: uuid.clone(),
                    offset,
                })
            }

            LC_BUILD_VERSION => {
                let build_version = BuildVersionCommand::read_from_prefix(data)
                    .map_err(|_| Error::Parse {
                        offset,
                        reason: "failed to parse build version command".into(),
                    })?
                    .0;

                Ok(LoadCommandInfo::BuildVersion {
                    command: build_version.clone(),
                    offset,
                })
            }

            LC_FILESET_ENTRY => {
                let entry = FilesetEntryCommand::read_from_prefix(data)
                    .map_err(|_| Error::Parse {
                        offset,
                        reason: "failed to parse fileset entry command".into(),
                    })?
                    .0;

                // Read the entry ID
                let id_offset = entry.entry_id_offset as usize;
                let entry_id = if id_offset < data.len() {
                    let name_bytes = &data[id_offset..];
                    let end = name_bytes
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(name_bytes.len());
                    String::from_utf8_lossy(&name_bytes[..end]).to_string()
                } else {
                    String::new()
                };

                Ok(LoadCommandInfo::FilesetEntry {
                    command: entry.clone(),
                    entry_id,
                    offset,
                })
            }

            _ => {
                let lc = LoadCommand::read_from_prefix(data)
                    .map_err(|_| Error::Parse {
                        offset,
                        reason: "failed to parse load command".into(),
                    })?
                    .0;

                Ok(LoadCommandInfo::Unknown {
                    cmd,
                    cmdsize: lc.cmdsize,
                    offset,
                })
            }
        }
    }

    /// Returns a reference to a segment by name.
    pub fn segment(&self, name: &str) -> Option<&SegmentInfo> {
        self.segment_indices.get(name).and_then(|&idx| {
            if let LoadCommandInfo::Segment(ref seg) = self.load_commands[idx] {
                Some(seg)
            } else {
                None
            }
        })
    }

    /// Returns a mutable reference to a segment by name.
    pub fn segment_mut(&mut self, name: &str) -> Option<&mut SegmentInfo> {
        let idx = *self.segment_indices.get(name)?;
        if let LoadCommandInfo::Segment(ref mut seg) = self.load_commands[idx] {
            Some(seg)
        } else {
            None
        }
    }

    /// Returns an iterator over all segments.
    pub fn segments(&self) -> impl Iterator<Item = &SegmentInfo> {
        self.load_commands.iter().filter_map(|lc| {
            if let LoadCommandInfo::Segment(seg) = lc {
                Some(seg)
            } else {
                None
            }
        })
    }

    /// Returns a section by segment and section name.
    pub fn section(&self, segment: &str, section: &str) -> Option<&SectionInfo> {
        self.segment(segment)?.section(section)
    }

    /// Returns the __TEXT segment.
    pub fn text_segment(&self) -> Option<&SegmentInfo> {
        self.segment("__TEXT")
    }

    /// Returns the __DATA segment.
    pub fn data_segment(&self) -> Option<&SegmentInfo> {
        self.segment("__DATA")
    }

    /// Returns the __LINKEDIT segment.
    pub fn linkedit_segment(&self) -> Option<&SegmentInfo> {
        self.segment("__LINKEDIT")
    }

    /// Returns the symbol table command.
    pub fn symtab(&self) -> Option<&SymtabCommand> {
        self.load_commands.iter().find_map(|lc| {
            if let LoadCommandInfo::Symtab { command, .. } = lc {
                Some(command)
            } else {
                None
            }
        })
    }

    /// Returns the dynamic symbol table command.
    pub fn dysymtab(&self) -> Option<&DysymtabCommand> {
        self.load_commands.iter().find_map(|lc| {
            if let LoadCommandInfo::Dysymtab { command, .. } = lc {
                Some(command)
            } else {
                None
            }
        })
    }

    /// Returns the dyld info command.
    pub fn dyld_info(&self) -> Option<&DyldInfoCommand> {
        self.load_commands.iter().find_map(|lc| {
            if let LoadCommandInfo::DyldInfo { command, .. } = lc {
                Some(command)
            } else {
                None
            }
        })
    }

    /// Returns an iterator over dependency dylibs.
    pub fn dylibs(&self) -> impl Iterator<Item = (&str, u32)> {
        self.load_commands.iter().filter_map(|lc| {
            if let LoadCommandInfo::Dylib { command, name, .. } = lc {
                Some((name.as_str(), command.cmd))
            } else {
                None
            }
        })
    }

    /// Returns a list of all dependency paths (LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, etc.)
    /// excluding LC_ID_DYLIB (which identifies the image itself).
    pub fn dependencies(&self) -> Vec<String> {
        self.load_commands
            .iter()
            .filter_map(|lc| {
                if let LoadCommandInfo::Dylib { command, name, .. } = lc {
                    // Include all dylib load commands except LC_ID_DYLIB
                    match command.cmd {
                        LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB
                        | LC_LAZY_LOAD_DYLIB | LC_LOAD_UPWARD_DYLIB => Some(name.clone()),
                        _ => None,
                    }
                } else {
                    None
                }
            })
            .collect()
    }

    /// Returns true if this is an ARM64 binary.
    pub fn is_arm64(&self) -> bool {
        self.header.is_arm64()
    }

    /// Returns true if this is an ARM64e binary (with pointer authentication).
    pub fn is_arm64e(&self) -> bool {
        self.header.is_arm64e()
    }

    /// Reads data at the specified offset within the Mach-O.
    #[inline]
    pub fn read_at(&self, offset: usize, len: usize) -> Result<&[u8]> {
        if offset + len > self.data.len() {
            return Err(Error::BufferTooSmall {
                needed: offset + len,
                available: self.data.len(),
            });
        }
        Ok(&self.data[offset..offset + len])
    }

    /// Reads a u32 at the specified offset.
    #[inline(always)]
    pub fn read_u32(&self, offset: usize) -> Result<u32> {
        let bytes = self.read_at(offset, 4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Reads a u64 at the specified offset.
    #[inline(always)]
    pub fn read_u64(&self, offset: usize) -> Result<u64> {
        let bytes = self.read_at(offset, 8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    /// Writes data at the specified offset.
    #[inline]
    pub fn write_at(&mut self, offset: usize, data: &[u8]) -> Result<()> {
        if offset + data.len() > self.data.len() {
            return Err(Error::BufferTooSmall {
                needed: offset + data.len(),
                available: self.data.len(),
            });
        }
        self.data[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }

    /// Writes a u32 at the specified offset.
    #[inline(always)]
    pub fn write_u32(&mut self, offset: usize, value: u32) -> Result<()> {
        self.write_at(offset, &value.to_le_bytes())
    }

    /// Writes a u64 at the specified offset.
    #[inline(always)]
    pub fn write_u64(&mut self, offset: usize, value: u64) -> Result<()> {
        self.write_at(offset, &value.to_le_bytes())
    }

    /// Writes a structure at the specified offset.
    pub fn write_struct<T: IntoBytes + Immutable>(
        &mut self,
        offset: usize,
        value: &T,
    ) -> Result<()> {
        let bytes = value.as_bytes();
        self.write_at(offset, bytes)
    }

    /// Updates the header in the data buffer.
    pub fn sync_header(&mut self) -> Result<()> {
        let header = self.header.clone();
        self.write_at(0, &header.as_bytes()[..self.header_size()])
    }

    /// Returns the total size of load commands.
    pub fn load_commands_size(&self) -> usize {
        self.load_commands.iter().map(|lc| lc.size() as usize).sum()
    }

    /// Returns the available space for load commands.
    pub fn available_load_command_space(&self) -> usize {
        let text = self
            .text_segment()
            .map(|s| s.command.fileoff as usize)
            .unwrap_or(usize::MAX);
        let used = self.header_size() + self.load_commands_size();
        text.saturating_sub(used)
    }

    /// Converts a virtual address to a file offset within this Mach-O.
    /// Hot path - called for every pointer in slide info processing.
    /// Uses binary search on pre-computed segment ranges for O(log n) lookup.
    #[inline]
    pub fn addr_to_offset(&self, addr: u64) -> Option<usize> {
        // Binary search: find the first segment where vmaddr + vmsize > addr
        let idx = self
            .segment_ranges
            .partition_point(|r| r.vmaddr + r.vmsize <= addr);
        if idx < self.segment_ranges.len() {
            let range = &self.segment_ranges[idx];
            if addr >= range.vmaddr && addr < range.vmaddr + range.vmsize {
                let offset = range.fileoff + (addr - range.vmaddr);
                return Some(offset as usize);
            }
        }
        None
    }

    /// Converts a file offset to a virtual address.
    pub fn offset_to_addr(&self, offset: usize) -> Option<u64> {
        let offset = offset as u64;
        for seg in self.segments() {
            if offset >= seg.command.fileoff && offset < seg.command.fileoff + seg.command.filesize
            {
                let addr = seg.command.vmaddr + (offset - seg.command.fileoff);
                return Some(addr);
            }
        }
        None
    }

    /// Returns true if the address is within this Mach-O.
    pub fn contains_addr(&self, addr: u64) -> bool {
        self.segments()
            .any(|seg| addr >= seg.command.vmaddr && addr < seg.command.vmaddr + seg.command.vmsize)
    }

    /// Returns the raw data.
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Returns the raw data as mutable.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

use zerocopy::Immutable;

#[cfg(test)]
mod tests {
    use super::*;

    fn create_minimal_macho() -> Vec<u8> {
        let mut data = vec![0u8; 0x1000];

        // Write header
        let header = MachHeader64 {
            magic: MH_MAGIC_64,
            cputype: CPU_TYPE_ARM64,
            cpusubtype: CPU_SUBTYPE_ARM64_ALL,
            filetype: MH_DYLIB,
            ncmds: 1,
            sizeofcmds: SegmentCommand64::SIZE as u32,
            flags: 0,
            reserved: 0,
        };

        data[..MachHeader64::SIZE].copy_from_slice(header.as_bytes());

        // Write a simple TEXT segment
        let mut seg = SegmentCommand64::default();
        seg.set_name("__TEXT");
        seg.vmaddr = 0x100000000;
        seg.vmsize = 0x1000;
        seg.fileoff = 0;
        seg.filesize = 0x1000;

        data[MachHeader64::SIZE..MachHeader64::SIZE + SegmentCommand64::SIZE]
            .copy_from_slice(seg.as_bytes());

        data
    }

    #[test]
    fn test_parse_minimal_macho() {
        let data = create_minimal_macho();
        let ctx = MachOContext::new(&data, 0).unwrap();

        assert!(ctx.header.is_valid());
        assert!(ctx.is_arm64());
        assert_eq!(ctx.header.ncmds, 1);
        assert!(ctx.segment("__TEXT").is_some());
    }
}
