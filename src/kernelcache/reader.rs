//! Bounds-checked reads over untrusted kernelcache bytes.
//!
//! Every helper returns a parse error instead of panicking when a read would
//! leave the input.

use crate::error::{Error, Result};

/// Returns `data[offset..offset + len]`.
pub(super) fn slice(data: &[u8], offset: usize, len: usize) -> Result<&[u8]> {
    offset
        .checked_add(len)
        .and_then(|end| data.get(offset..end))
        .ok_or_else(|| out_of_bounds(offset))
}

/// Reads `N` bytes at `offset`.
pub(super) fn read_bytes<const N: usize>(data: &[u8], offset: usize) -> Result<[u8; N]> {
    data.get(offset..)
        .and_then(<[u8]>::first_chunk)
        .copied()
        .ok_or_else(|| out_of_bounds(offset))
}

/// Reads a little-endian `u16` at `offset`.
pub(super) fn read_u16(data: &[u8], offset: usize) -> Result<u16> {
    read_bytes(data, offset).map(u16::from_le_bytes)
}

/// Reads a little-endian `u32` at `offset`.
pub(super) fn read_u32(data: &[u8], offset: usize) -> Result<u32> {
    read_bytes(data, offset).map(u32::from_le_bytes)
}

/// Reads a big-endian `u32` at `offset`.
pub(super) fn read_u32_be(data: &[u8], offset: usize) -> Result<u32> {
    read_bytes(data, offset).map(u32::from_be_bytes)
}

/// Reads a little-endian `u64` at `offset`.
pub(super) fn read_u64(data: &[u8], offset: usize) -> Result<u64> {
    read_bytes(data, offset).map(u64::from_le_bytes)
}

/// Converts a Mach-O file offset or size to a host index.
pub(super) fn to_usize(value: u64) -> Result<usize> {
    usize::try_from(value).map_err(|_| Error::parse(0, "file offset exceeds host address space"))
}

/// Returns the NUL-terminated string at `index` in a string table, without its terminator.
pub(super) fn c_string_at(table: &[u8], index: u32) -> Result<&[u8]> {
    let start = index as usize;
    let tail = table
        .get(start..)
        .ok_or_else(|| Error::parse(start, "symbol string index out of range"))?;
    let len =
        memchr::memchr(0, tail).ok_or_else(|| Error::parse(start, "unterminated symbol name"))?;
    Ok(&tail[..len])
}

fn out_of_bounds(offset: usize) -> Error {
    Error::parse(offset, "kernelcache range exceeds input")
}
