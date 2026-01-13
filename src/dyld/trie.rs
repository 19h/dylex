//! Export trie parsing for dyld caches.
//!
//! The export trie is a compact representation of exported symbols in a Mach-O file.
//! It uses a trie (prefix tree) structure where each node can contain:
//! - Terminal information (flags, address, optional other value)
//! - Children edges (label prefix + offset to child node)

use crate::error::{Error, Result};

// =============================================================================
// Export Flags
// =============================================================================

/// Export symbol kind mask.
pub const EXPORT_SYMBOL_FLAGS_KIND_MASK: u64 = 0x03;

/// Regular export.
pub const EXPORT_SYMBOL_FLAGS_KIND_REGULAR: u64 = 0x00;

/// Thread-local variable.
pub const EXPORT_SYMBOL_FLAGS_KIND_THREAD_LOCAL: u64 = 0x01;

/// Absolute symbol (not relative to any section).
pub const EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE: u64 = 0x02;

/// Weak definition.
pub const EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION: u64 = 0x04;

/// Re-export from another dylib.
pub const EXPORT_SYMBOL_FLAGS_REEXPORT: u64 = 0x08;

/// Stub and resolver.
pub const EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER: u64 = 0x10;

// =============================================================================
// LEB128 Decoding
// =============================================================================

/// Reads an unsigned LEB128 value from the given slice.
///
/// Returns the decoded value and the number of bytes consumed.
///
/// # Performance
///
/// Uses a fast path for 1-2 byte values which covers >95% of real-world cases.
/// Falls back to a loop only for larger values.
#[inline(always)]
pub fn read_uleb128(data: &[u8]) -> Result<(u64, usize)> {
    // Fast path: use the optimized implementation from util
    crate::util::read_uleb128_fast(data).ok_or(Error::InvalidUleb128 { offset: 0 })
}

/// Reads a signed LEB128 value from the given slice.
///
/// # Performance
///
/// Uses a fast path for common small values.
#[inline(always)]
pub fn read_sleb128(data: &[u8]) -> Result<(i64, usize)> {
    crate::util::read_sleb128_fast(data).ok_or(Error::InvalidUleb128 { offset: 0 })
}

/// Writes an unsigned LEB128 value to a buffer.
pub fn write_uleb128(mut value: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if value == 0 {
            break;
        }
    }
}

// =============================================================================
// Export Info
// =============================================================================

/// Information about an exported symbol.
#[derive(Debug, Clone)]
pub struct ExportInfo {
    /// Symbol name
    pub name: String,
    /// Export flags
    pub flags: u64,
    /// Symbol address (relative to image base)
    pub address: u64,
    /// For re-exports: ordinal of the source dylib
    pub reexport_ordinal: Option<u32>,
    /// For re-exports: imported symbol name (if different)
    pub reexport_name: Option<String>,
    /// For stub+resolver: resolver function address
    pub resolver_address: Option<u64>,
}

impl ExportInfo {
    /// Returns true if this is a re-export.
    #[inline]
    pub fn is_reexport(&self) -> bool {
        (self.flags & EXPORT_SYMBOL_FLAGS_REEXPORT) != 0
    }

    /// Returns true if this is a weak definition.
    #[inline]
    pub fn is_weak(&self) -> bool {
        (self.flags & EXPORT_SYMBOL_FLAGS_WEAK_DEFINITION) != 0
    }

    /// Returns true if this is a stub with resolver.
    #[inline]
    pub fn is_stub_and_resolver(&self) -> bool {
        (self.flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0
    }

    /// Returns the symbol kind.
    #[inline]
    pub fn kind(&self) -> u64 {
        self.flags & EXPORT_SYMBOL_FLAGS_KIND_MASK
    }
}

// =============================================================================
// Export Trie Parser
// =============================================================================

/// Parser for export tries.
pub struct ExportTrieParser<'a> {
    data: &'a [u8],
}

impl<'a> ExportTrieParser<'a> {
    /// Creates a new parser for the given export trie data.
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }

    /// Parses all exports from the trie.
    pub fn parse_all(&self) -> Result<Vec<ExportInfo>> {
        let mut exports = Vec::new();
        if !self.data.is_empty() {
            self.parse_node(0, String::new(), &mut exports)?;
        }
        Ok(exports)
    }

    /// Looks up a single symbol by name.
    pub fn lookup(&self, name: &str) -> Result<Option<ExportInfo>> {
        if self.data.is_empty() {
            return Ok(None);
        }

        self.lookup_recursive(0, name, 0)
    }

    /// Recursive node parser.
    fn parse_node(
        &self,
        offset: usize,
        prefix: String,
        exports: &mut Vec<ExportInfo>,
    ) -> Result<()> {
        if offset >= self.data.len() {
            return Err(Error::InvalidExportTrie { offset });
        }

        let node_data = &self.data[offset..];
        let (terminal_size, bytes_read) = read_uleb128(node_data)?;
        let mut cursor = bytes_read;

        // If this node is terminal (has export info)
        if terminal_size > 0 {
            let export = self.parse_terminal_info(&node_data[cursor..], &prefix)?;
            exports.push(export);
        }
        cursor += terminal_size as usize;

        // Parse children
        if cursor >= node_data.len() {
            return Ok(());
        }

        let child_count = node_data[cursor] as usize;
        cursor += 1;

        for _ in 0..child_count {
            // Read edge label (null-terminated string)
            let label_start = cursor;
            while cursor < node_data.len() && node_data[cursor] != 0 {
                cursor += 1;
            }
            let label = String::from_utf8_lossy(&node_data[label_start..cursor]).to_string();
            cursor += 1; // Skip null terminator

            // Read child offset
            let (child_offset, bytes) = read_uleb128(&node_data[cursor..])?;
            cursor += bytes;

            // Recurse into child
            let child_prefix = format!("{}{}", prefix, label);
            self.parse_node(child_offset as usize, child_prefix, exports)?;
        }

        Ok(())
    }

    /// Parses terminal export info.
    fn parse_terminal_info(&self, data: &[u8], name: &str) -> Result<ExportInfo> {
        let (flags, mut cursor) = read_uleb128(data)?;

        let mut export = ExportInfo {
            name: name.to_string(),
            flags,
            address: 0,
            reexport_ordinal: None,
            reexport_name: None,
            resolver_address: None,
        };

        if (flags & EXPORT_SYMBOL_FLAGS_REEXPORT) != 0 {
            // Re-export: ordinal + optional import name
            let (ordinal, bytes) = read_uleb128(&data[cursor..])?;
            cursor += bytes;
            export.reexport_ordinal = Some(ordinal as u32);

            // Import name (if different from export name)
            if cursor < data.len() && data[cursor] != 0 {
                let name_start = cursor;
                while cursor < data.len() && data[cursor] != 0 {
                    cursor += 1;
                }
                export.reexport_name =
                    Some(String::from_utf8_lossy(&data[name_start..cursor]).to_string());
            }
        } else {
            // Regular export: address
            let (addr, bytes) = read_uleb128(&data[cursor..])?;
            cursor += bytes;
            export.address = addr;

            // Check for stub+resolver
            if (flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0 {
                let (resolver, _) = read_uleb128(&data[cursor..])?;
                export.resolver_address = Some(resolver);
            }
        }

        Ok(export)
    }

    /// Recursive symbol lookup.
    fn lookup_recursive(
        &self,
        offset: usize,
        name: &str,
        name_offset: usize,
    ) -> Result<Option<ExportInfo>> {
        if offset >= self.data.len() {
            return Err(Error::InvalidExportTrie { offset });
        }

        let node_data = &self.data[offset..];
        let (terminal_size, bytes_read) = read_uleb128(node_data)?;
        let mut cursor = bytes_read;

        // If we've matched the full name and this is a terminal node
        if name_offset == name.len() && terminal_size > 0 {
            let export = self.parse_terminal_info(&node_data[cursor..], name)?;
            return Ok(Some(export));
        }

        // Skip terminal info
        cursor += terminal_size as usize;

        if cursor >= node_data.len() {
            return Ok(None);
        }

        // Check children
        let child_count = node_data[cursor] as usize;
        cursor += 1;

        let remaining_name = &name[name_offset..];

        for _ in 0..child_count {
            // Read edge label
            let label_start = cursor;
            while cursor < node_data.len() && node_data[cursor] != 0 {
                cursor += 1;
            }
            let label = &node_data[label_start..cursor];
            cursor += 1; // Skip null terminator

            // Read child offset
            let (child_offset, bytes) = read_uleb128(&node_data[cursor..])?;
            cursor += bytes;

            // Check if this edge matches
            if remaining_name.as_bytes().starts_with(label) {
                return self.lookup_recursive(
                    child_offset as usize,
                    name,
                    name_offset + label.len(),
                );
            }
        }

        Ok(None)
    }
}

// =============================================================================
// Bind Opcode Parser
// =============================================================================

/// Bind opcodes used in the dyld bind info.
///
/// These constants define the opcodes used in the compressed binding
/// information format found in LC_DYLD_INFO load commands.
#[allow(missing_docs)] // Constants are self-documenting via names
pub mod bind_opcodes {
    /// Terminates a binding sequence.
    pub const BIND_OPCODE_DONE: u8 = 0x00;
    pub const BIND_OPCODE_SET_DYLIB_ORDINAL_IMM: u8 = 0x10;
    pub const BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB: u8 = 0x20;
    pub const BIND_OPCODE_SET_DYLIB_SPECIAL_IMM: u8 = 0x30;
    pub const BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM: u8 = 0x40;
    pub const BIND_OPCODE_SET_TYPE_IMM: u8 = 0x50;
    pub const BIND_OPCODE_SET_ADDEND_SLEB: u8 = 0x60;
    pub const BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB: u8 = 0x70;
    pub const BIND_OPCODE_ADD_ADDR_ULEB: u8 = 0x80;
    pub const BIND_OPCODE_DO_BIND: u8 = 0x90;
    pub const BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB: u8 = 0xA0;
    pub const BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED: u8 = 0xB0;
    pub const BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB: u8 = 0xC0;
    pub const BIND_OPCODE_THREADED: u8 = 0xD0;

    pub const BIND_IMMEDIATE_MASK: u8 = 0x0F;
    pub const BIND_OPCODE_MASK: u8 = 0xF0;
}

/// A binding record from parsing bind opcodes.
#[derive(Debug, Clone)]
pub struct BindRecord {
    /// Segment index
    pub segment_index: u8,
    /// Offset within segment
    pub segment_offset: u64,
    /// Binding type
    pub bind_type: u8,
    /// Symbol name
    pub symbol_name: String,
    /// Dylib ordinal
    pub ordinal: i64,
    /// Addend
    pub addend: i64,
}

/// Parses bind info opcodes.
///
/// # Arguments
///
/// * `data` - The raw bind info data
/// * `_segment_addresses` - Segment base addresses (reserved for future use)
pub fn parse_bind_info(data: &[u8], _segment_addresses: &[u64]) -> Result<Vec<BindRecord>> {
    use bind_opcodes::*;

    let mut records = Vec::new();
    let mut cursor = 0usize;

    let mut segment_index: u8 = 0;
    let mut segment_offset: u64 = 0;
    let mut bind_type: u8 = 0;
    let mut symbol_name = String::new();
    let mut ordinal: i64 = 0;
    let mut addend: i64 = 0;

    while cursor < data.len() {
        let byte = data[cursor];
        let opcode = byte & BIND_OPCODE_MASK;
        let immediate = byte & BIND_IMMEDIATE_MASK;
        cursor += 1;

        match opcode {
            BIND_OPCODE_DONE => break,

            BIND_OPCODE_SET_DYLIB_ORDINAL_IMM => {
                ordinal = immediate as i64;
            }

            BIND_OPCODE_SET_DYLIB_ORDINAL_ULEB => {
                let (val, bytes) = read_uleb128(&data[cursor..])?;
                cursor += bytes;
                ordinal = val as i64;
            }

            BIND_OPCODE_SET_DYLIB_SPECIAL_IMM => {
                if immediate == 0 {
                    ordinal = 0;
                } else {
                    ordinal = (BIND_OPCODE_MASK | immediate) as i8 as i64;
                }
            }

            BIND_OPCODE_SET_SYMBOL_TRAILING_FLAGS_IMM => {
                let name_start = cursor;
                while cursor < data.len() && data[cursor] != 0 {
                    cursor += 1;
                }
                symbol_name = String::from_utf8_lossy(&data[name_start..cursor]).to_string();
                cursor += 1; // Skip null terminator
            }

            BIND_OPCODE_SET_TYPE_IMM => {
                bind_type = immediate;
            }

            BIND_OPCODE_SET_ADDEND_SLEB => {
                let (val, bytes) = read_sleb128(&data[cursor..])?;
                cursor += bytes;
                addend = val;
            }

            BIND_OPCODE_SET_SEGMENT_AND_OFFSET_ULEB => {
                segment_index = immediate;
                let (val, bytes) = read_uleb128(&data[cursor..])?;
                cursor += bytes;
                segment_offset = val;
            }

            BIND_OPCODE_ADD_ADDR_ULEB => {
                let (val, bytes) = read_uleb128(&data[cursor..])?;
                cursor += bytes;
                segment_offset = segment_offset.wrapping_add(val);
            }

            BIND_OPCODE_DO_BIND => {
                records.push(BindRecord {
                    segment_index,
                    segment_offset,
                    bind_type,
                    symbol_name: symbol_name.clone(),
                    ordinal,
                    addend,
                });
                segment_offset = segment_offset.wrapping_add(8);
            }

            BIND_OPCODE_DO_BIND_ADD_ADDR_ULEB => {
                records.push(BindRecord {
                    segment_index,
                    segment_offset,
                    bind_type,
                    symbol_name: symbol_name.clone(),
                    ordinal,
                    addend,
                });
                let (val, bytes) = read_uleb128(&data[cursor..])?;
                cursor += bytes;
                segment_offset = segment_offset.wrapping_add(8).wrapping_add(val);
            }

            BIND_OPCODE_DO_BIND_ADD_ADDR_IMM_SCALED => {
                records.push(BindRecord {
                    segment_index,
                    segment_offset,
                    bind_type,
                    symbol_name: symbol_name.clone(),
                    ordinal,
                    addend,
                });
                segment_offset = segment_offset.wrapping_add(8 + (immediate as u64 * 8));
            }

            BIND_OPCODE_DO_BIND_ULEB_TIMES_SKIPPING_ULEB => {
                let (count, bytes1) = read_uleb128(&data[cursor..])?;
                cursor += bytes1;
                let (skip, bytes2) = read_uleb128(&data[cursor..])?;
                cursor += bytes2;

                for _ in 0..count {
                    records.push(BindRecord {
                        segment_index,
                        segment_offset,
                        bind_type,
                        symbol_name: symbol_name.clone(),
                        ordinal,
                        addend,
                    });
                    segment_offset = segment_offset.wrapping_add(8).wrapping_add(skip);
                }
            }

            BIND_OPCODE_THREADED => {
                // Threaded binds are handled differently
                // For now, skip the sub-opcode
                match immediate {
                    0 => {
                        // BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB
                        let (_, bytes) = read_uleb128(&data[cursor..])?;
                        cursor += bytes;
                    }
                    1 => {
                        // BIND_SUBOPCODE_THREADED_APPLY
                        // This requires walking the chain in segment
                    }
                    _ => {}
                }
            }

            _ => {
                // Unknown opcode, skip
            }
        }
    }

    Ok(records)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uleb128() {
        // 0
        assert_eq!(read_uleb128(&[0x00]).unwrap(), (0, 1));
        // 1
        assert_eq!(read_uleb128(&[0x01]).unwrap(), (1, 1));
        // 127
        assert_eq!(read_uleb128(&[0x7F]).unwrap(), (127, 1));
        // 128
        assert_eq!(read_uleb128(&[0x80, 0x01]).unwrap(), (128, 2));
        // 16256
        assert_eq!(read_uleb128(&[0x80, 0x7F]).unwrap(), (16256, 2));
    }

    #[test]
    fn test_sleb128() {
        // 0
        assert_eq!(read_sleb128(&[0x00]).unwrap(), (0, 1));
        // -1
        assert_eq!(read_sleb128(&[0x7F]).unwrap(), (-1, 1));
        // 1
        assert_eq!(read_sleb128(&[0x01]).unwrap(), (1, 1));
        // -128
        assert_eq!(read_sleb128(&[0x80, 0x7F]).unwrap(), (-128, 2));
    }

    #[test]
    fn test_write_uleb128() {
        let mut buf = Vec::new();
        write_uleb128(0, &mut buf);
        assert_eq!(buf, vec![0x00]);

        buf.clear();
        write_uleb128(127, &mut buf);
        assert_eq!(buf, vec![0x7F]);

        buf.clear();
        write_uleb128(128, &mut buf);
        assert_eq!(buf, vec![0x80, 0x01]);
    }
}
