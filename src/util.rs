//! High-performance utility functions for binary data processing.
//!
//! This module provides optimized primitives for:
//! - Unaligned memory reads (using byteorder for optimal codegen)
//! - SIMD-accelerated byte searches (via memchr)
//! - Fast pointer scanning for batch operations
//!
//! # Performance Notes
//!
//! All functions are aggressively inlined and designed to compile down to
//! optimal machine code. On x86-64 and ARM64:
//! - `read_u64_le` compiles to a single unaligned load instruction
//! - `read_u32_le` compiles to a single unaligned load instruction  
//! - `memchr_null` uses SIMD vectorization (AVX2/NEON when available)

use byteorder::{ByteOrder, LittleEndian};

// =============================================================================
// Fast Unaligned Reads
// =============================================================================

/// Reads a little-endian u64 from an unaligned byte slice.
///
/// # Performance
///
/// Compiles to a single `mov` instruction on x86-64 or `ldr` on ARM64.
/// The byteorder crate ensures optimal codegen for unaligned access.
///
/// # Panics
///
/// Panics if `data.len() < 8`.
#[inline(always)]
pub fn read_u64_le(data: &[u8]) -> u64 {
    LittleEndian::read_u64(data)
}

/// Reads a little-endian u64 from a byte slice at the given offset.
///
/// # Panics
///
/// Panics if `offset + 8 > data.len()`.
#[inline(always)]
pub fn read_u64_le_at(data: &[u8], offset: usize) -> u64 {
    LittleEndian::read_u64(&data[offset..])
}

/// Reads a little-endian u32 from an unaligned byte slice.
///
/// # Performance
///
/// Compiles to a single load instruction.
///
/// # Panics
///
/// Panics if `data.len() < 4`.
#[inline(always)]
pub fn read_u32_le(data: &[u8]) -> u32 {
    LittleEndian::read_u32(data)
}

/// Reads a little-endian u32 from a byte slice at the given offset.
///
/// # Panics
///
/// Panics if `offset + 4 > data.len()`.
#[inline(always)]
pub fn read_u32_le_at(data: &[u8], offset: usize) -> u32 {
    LittleEndian::read_u32(&data[offset..])
}

/// Reads a little-endian u16 from an unaligned byte slice.
///
/// # Panics
///
/// Panics if `data.len() < 2`.
#[inline(always)]
pub fn read_u16_le(data: &[u8]) -> u16 {
    LittleEndian::read_u16(data)
}

/// Reads a little-endian u16 from a byte slice at the given offset.
///
/// # Panics
///
/// Panics if `offset + 2 > data.len()`.
#[inline(always)]
pub fn read_u16_le_at(data: &[u8], offset: usize) -> u16 {
    LittleEndian::read_u16(&data[offset..])
}

// =============================================================================
// SIMD-Accelerated Byte Search
// =============================================================================

/// Finds the position of the first null byte in a slice.
///
/// # Performance
///
/// Uses the `memchr` crate which provides:
/// - AVX2 vectorization on x86-64 (processes 32 bytes/iteration)
/// - NEON vectorization on ARM64 (processes 16 bytes/iteration)
/// - Optimal fallback on other platforms
///
/// This is typically 4-8x faster than a naive byte-by-byte loop.
#[inline(always)]
pub fn memchr_null(data: &[u8]) -> usize {
    memchr::memchr(0, data).unwrap_or(data.len())
}

/// Finds the position of the first occurrence of `needle` in `haystack`.
///
/// Returns `None` if not found.
#[inline(always)]
pub fn memchr_find(needle: u8, haystack: &[u8]) -> Option<usize> {
    memchr::memchr(needle, haystack)
}

// =============================================================================
// Batch Pointer Scanning (SIMD-friendly)
// =============================================================================

/// Minimum valid pointer value (skip small values that are likely not pointers).
/// 0x100000000 = 4GB, typical minimum for 64-bit address space.
pub const MIN_VALID_POINTER: u64 = 0x100000000;

/// Address mask for stripping PAC/TBI bits from pointers.
/// Keeps lower 48 bits which is the actual address portion.
pub const ADDR_MASK_48BIT: u64 = 0x0000_FFFF_FFFF_FFFF;

/// Scans a data slice for potential 64-bit pointers.
///
/// This is optimized for batch scanning of data sections to find pointers
/// that reference other images. The function uses an inner loop that the
/// compiler can auto-vectorize.
///
/// # Arguments
///
/// * `data` - Byte slice to scan (must be at least 8 bytes)
/// * `stride` - Byte stride between pointer reads (typically 8)
/// * `min_addr` - Minimum valid address (pointers below this are skipped)
/// * `max_addr` - Maximum valid address (pointers above this are skipped)
///
/// # Returns
///
/// Iterator of (offset, pointer_value) pairs for valid-looking pointers.
#[inline]
pub fn scan_pointers_in_range<'a>(
    data: &'a [u8],
    stride: usize,
    min_addr: u64,
    max_addr: u64,
) -> impl Iterator<Item = (usize, u64)> + 'a {
    (0..data.len().saturating_sub(7))
        .step_by(stride)
        .filter_map(move |offset| {
            let raw = read_u64_le(&data[offset..]);
            if raw == 0 {
                return None;
            }
            // Strip PAC bits to get actual address
            let addr = raw & ADDR_MASK_48BIT;
            if addr >= min_addr && addr < max_addr {
                Some((offset, raw))
            } else {
                None
            }
        })
}

/// Batch processes an array of u64 values, applying a transformation function.
///
/// This is designed to be SIMD-friendly - the inner loop is kept simple
/// so the compiler can vectorize it.
///
/// # Arguments
///
/// * `data` - Mutable byte slice containing u64 values
/// * `transform` - Function that takes (offset, value) and returns new value
///
/// # Returns
///
/// Number of values that were modified.
#[inline]
pub fn batch_transform_u64<F>(data: &mut [u8], mut transform: F) -> usize
where
    F: FnMut(usize, u64) -> Option<u64>,
{
    let mut modified = 0;
    for offset in (0..data.len().saturating_sub(7)).step_by(8) {
        let value = read_u64_le(&data[offset..]);
        if let Some(new_value) = transform(offset, value) {
            if new_value != value {
                LittleEndian::write_u64(&mut data[offset..], new_value);
                modified += 1;
            }
        }
    }
    modified
}

// =============================================================================
// ULEB128 Fast Path
// =============================================================================

/// Reads an unsigned LEB128 value with fast paths for common cases.
///
/// # Performance
///
/// - 1-byte values (0-127): Single comparison, no loop
/// - 2-byte values (128-16383): Two comparisons, no loop
/// - Larger values: Fall back to loop
///
/// Since most LEB128 values in Mach-O files are small (symbol indices,
/// sizes, offsets), the fast paths handle >95% of cases.
///
/// # Returns
///
/// `(value, bytes_consumed)` or `None` if invalid.
#[inline(always)]
pub fn read_uleb128_fast(data: &[u8]) -> Option<(u64, usize)> {
    if data.is_empty() {
        return None;
    }

    let b0 = data[0];

    // Fast path: single byte (0-127) - most common case
    if b0 < 0x80 {
        return Some((b0 as u64, 1));
    }

    if data.len() < 2 {
        return None;
    }

    let b1 = data[1];

    // Fast path: two bytes (128-16383)
    if b1 < 0x80 {
        let value = ((b0 & 0x7F) as u64) | ((b1 as u64) << 7);
        return Some((value, 2));
    }

    // Fall back to general loop for larger values
    let mut result: u64 = 0;
    let mut shift = 0u32;

    for (i, &byte) in data.iter().enumerate() {
        if shift >= 64 {
            return None; // Overflow
        }

        result |= ((byte & 0x7F) as u64) << shift;
        shift += 7;

        if byte < 0x80 {
            return Some((result, i + 1));
        }
    }

    None
}

/// Reads a signed LEB128 value with fast paths for common cases.
///
/// # Performance
///
/// Similar optimization strategy to `read_uleb128_fast`.
#[inline(always)]
pub fn read_sleb128_fast(data: &[u8]) -> Option<(i64, usize)> {
    if data.is_empty() {
        return None;
    }

    let b0 = data[0];

    // Fast path: single byte
    if b0 < 0x80 {
        // Sign extend from 7 bits
        let value = if (b0 & 0x40) != 0 {
            (b0 as i64) | !0x7F_i64
        } else {
            b0 as i64
        };
        return Some((value, 1));
    }

    // Fall back to general loop
    let mut result: i64 = 0;
    let mut shift = 0u32;

    for (i, &byte) in data.iter().enumerate() {
        result |= ((byte & 0x7F) as i64) << shift;
        shift += 7;

        if byte < 0x80 {
            // Sign extend
            if shift < 64 && (byte & 0x40) != 0 {
                result |= !0_i64 << shift;
            }
            return Some((result, i + 1));
        }
    }

    None
}

// =============================================================================
// Alignment Utilities
// =============================================================================

/// Aligns a value up to the given power-of-two alignment.
///
/// # Performance
///
/// Single bitwise AND operation.
///
/// # Panics
///
/// Debug assertion fails if `alignment` is not a power of 2.
#[inline(always)]
pub const fn align_up(value: u64, alignment: u64) -> u64 {
    debug_assert!(alignment.is_power_of_two());
    (value + alignment - 1) & !(alignment - 1)
}

/// Aligns a value down to the given power-of-two alignment.
#[inline(always)]
pub const fn align_down(value: u64, alignment: u64) -> u64 {
    debug_assert!(alignment.is_power_of_two());
    value & !(alignment - 1)
}

/// Checks if a value is aligned to the given power-of-two alignment.
#[inline(always)]
pub const fn is_aligned(value: u64, alignment: u64) -> bool {
    debug_assert!(alignment.is_power_of_two());
    (value & (alignment - 1)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_u64_le() {
        let data = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        assert_eq!(read_u64_le(&data), 0x0807060504030201);
    }

    #[test]
    fn test_read_u32_le() {
        let data = [0x01, 0x02, 0x03, 0x04];
        assert_eq!(read_u32_le(&data), 0x04030201);
    }

    #[test]
    fn test_memchr_null() {
        assert_eq!(memchr_null(b"hello\0world"), 5);
        assert_eq!(memchr_null(b"\0"), 0);
        assert_eq!(memchr_null(b"hello"), 5);
    }

    #[test]
    fn test_uleb128_fast() {
        // Single byte
        assert_eq!(read_uleb128_fast(&[0x00]), Some((0, 1)));
        assert_eq!(read_uleb128_fast(&[0x01]), Some((1, 1)));
        assert_eq!(read_uleb128_fast(&[0x7F]), Some((127, 1)));

        // Two bytes
        assert_eq!(read_uleb128_fast(&[0x80, 0x01]), Some((128, 2)));
        assert_eq!(read_uleb128_fast(&[0xFF, 0x01]), Some((255, 2)));

        // Multi-byte
        assert_eq!(read_uleb128_fast(&[0xE5, 0x8E, 0x26]), Some((624485, 3)));
    }

    #[test]
    fn test_sleb128_fast() {
        // Positive single byte
        assert_eq!(read_sleb128_fast(&[0x00]), Some((0, 1)));
        assert_eq!(read_sleb128_fast(&[0x01]), Some((1, 1)));
        assert_eq!(read_sleb128_fast(&[0x3F]), Some((63, 1)));

        // Negative single byte
        assert_eq!(read_sleb128_fast(&[0x7F]), Some((-1, 1)));
        assert_eq!(read_sleb128_fast(&[0x40]), Some((-64, 1)));
    }

    #[test]
    fn test_align_up() {
        assert_eq!(align_up(0, 8), 0);
        assert_eq!(align_up(1, 8), 8);
        assert_eq!(align_up(7, 8), 8);
        assert_eq!(align_up(8, 8), 8);
        assert_eq!(align_up(9, 8), 16);
        assert_eq!(align_up(0x1000, 0x4000), 0x4000);
    }
}
