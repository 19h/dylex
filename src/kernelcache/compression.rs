//! LZFSE and complzss decompression with strict size validation.
//!
//! Decoded sizes are established from stream headers before any output is
//! allocated, and every stream must decode to exactly that size.

use std::fmt;

use crate::error::{Error, Result};

use super::MAX_SIZE;
use super::reader::{read_bytes, read_u32, read_u32_be, read_u64, slice};

// =============================================================================
// Format Constants
// =============================================================================

/// Prefix shared by every LZFSE block magic.
const LZFSE_MAGIC_PREFIX: &[u8] = b"bvx";
const LZFSE_END_OF_STREAM: &[u8] = b"bvx$";
const LZFSE_UNCOMPRESSED_BLOCK: &[u8] = b"bvx-";
const LZVN_BLOCK: &[u8] = b"bvxn";
const LZFSE_V1_BLOCK: &[u8] = b"bvx1";
const LZFSE_V2_BLOCK: &[u8] = b"bvx2";

const UNCOMPRESSED_BLOCK_HEADER_SIZE: usize = 8;
const LZVN_BLOCK_HEADER_SIZE: usize = 12;
const LZFSE_V1_BLOCK_HEADER_SIZE: usize = 772;
/// Bounds on the variable-size LZFSE v2 block header.
const LZFSE_V2_BLOCK_HEADER_SIZES: std::ops::RangeInclusive<usize> = 32..=752;

const COMPLZSS_MAGIC: &[u8] = b"complzss";
/// Size of the complzss header, including its reserved padding.
const COMPLZSS_HEADER_SIZE: usize = 0x180;
const COMPLZSS_CHECKSUM_OFFSET: usize = 8;
const COMPLZSS_DECODED_SIZE_OFFSET: usize = 12;
const COMPLZSS_ENCODED_SIZE_OFFSET: usize = 16;

/// Size of the LZSS ring buffer.
const LZSS_WINDOW_SIZE: usize = 4096;
/// Shortest and longest LZSS back-reference.
const LZSS_MIN_MATCH: usize = 3;
const LZSS_MAX_MATCH: usize = 18;

// =============================================================================
// Compression Detection
// =============================================================================

/// Compression applied to a kernelcache payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
    /// Apple LZFSE, including LZVN and uncompressed blocks.
    Lzfse,
    /// LZSS with a `complzss` header and an Adler-32 checksum.
    Complzss,
}

impl Compression {
    /// Identifies the compression from a stream's magic bytes.
    pub(super) fn detect(data: &[u8]) -> Option<Self> {
        if data.starts_with(COMPLZSS_MAGIC) {
            Some(Self::Complzss)
        } else if data.starts_with(LZFSE_MAGIC_PREFIX) {
            Some(Self::Lzfse)
        } else {
            None
        }
    }

    /// Decompresses a complete stream.
    pub(super) fn decompress(self, data: &[u8]) -> Result<Vec<u8>> {
        match self {
            Self::Lzfse => decompress_lzfse(data),
            Self::Complzss => decompress_complzss(data),
        }
    }
}

impl fmt::Display for Compression {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Lzfse => "LZFSE",
            Self::Complzss => "complzss",
        })
    }
}

// =============================================================================
// LZFSE
// =============================================================================

fn decompress_lzfse(data: &[u8]) -> Result<Vec<u8>> {
    let size = lzfse_decoded_size(data)?;
    // The reference decoder reports a full destination buffer the same way as
    // success, so allocate one spare byte and require the exact size.
    let mut output = vec![0; size + 1];
    let decoded = lzfse::decode_buffer(data, &mut output)
        .map_err(|error| Error::parse(0, format!("invalid LZFSE stream: {error:?}")))?;
    if decoded != size {
        return Err(Error::parse(
            0,
            "LZFSE decoded size disagrees with block headers",
        ));
    }
    output.truncate(decoded);
    Ok(output)
}

/// Walks the block headers of an LZFSE stream and returns its decoded size.
fn lzfse_decoded_size(data: &[u8]) -> Result<usize> {
    let mut position = 0;
    let mut total = 0usize;
    loop {
        let magic = slice(data, position, 4)?;
        if magic == LZFSE_END_OF_STREAM {
            if position + 4 != data.len() || total == 0 {
                return Err(Error::parse(
                    position,
                    "empty LZFSE stream or trailing bytes",
                ));
            }
            return Ok(total);
        }
        let decoded = read_u32(data, position + 4)? as usize;
        let block_size = lzfse_block_size(data, position, magic, decoded)?;
        total = total
            .checked_add(decoded)
            .filter(|&total| total <= MAX_SIZE)
            .ok_or_else(|| Error::parse(position, "LZFSE output exceeds 1 GiB"))?;
        slice(data, position, block_size)?;
        position += block_size;
    }
}

/// Returns the encoded size, header included, of the block at `position`.
fn lzfse_block_size(data: &[u8], position: usize, magic: &[u8], decoded: usize) -> Result<usize> {
    let (header, payload) = match magic {
        LZFSE_UNCOMPRESSED_BLOCK => (UNCOMPRESSED_BLOCK_HEADER_SIZE, decoded),
        LZVN_BLOCK => (
            LZVN_BLOCK_HEADER_SIZE,
            read_u32(data, position + 8)? as usize,
        ),
        LZFSE_V1_BLOCK => (
            LZFSE_V1_BLOCK_HEADER_SIZE,
            read_u32(data, position + 8)? as usize,
        ),
        LZFSE_V2_BLOCK => {
            slice(data, position, *LZFSE_V2_BLOCK_HEADER_SIZES.start())?;
            let header = read_u32(data, position + 24)? as usize;
            if !LZFSE_V2_BLOCK_HEADER_SIZES.contains(&header) {
                return Err(Error::parse(position, "invalid LZFSE v2 header size"));
            }
            // packed_fields[0] bits 20..40 hold n_literal_payload_bytes;
            // packed_fields[1] bits 40..60 hold n_lmd_payload_bytes.
            let literals = (read_u64(data, position + 8)? >> 20) & 0xf_ffff;
            let lmds = (read_u64(data, position + 16)? >> 40) & 0xf_ffff;
            (header, (literals + lmds) as usize)
        }
        _ => return Err(Error::parse(position, "unknown LZFSE block magic")),
    };
    header
        .checked_add(payload)
        .ok_or_else(|| Error::parse(position, "LZFSE block size overflow"))
}

// =============================================================================
// complzss
// =============================================================================

fn decompress_complzss(data: &[u8]) -> Result<Vec<u8>> {
    slice(data, 0, COMPLZSS_HEADER_SIZE)?;
    let decoded_size = read_u32_be(data, COMPLZSS_DECODED_SIZE_OFFSET)? as usize;
    if decoded_size > MAX_SIZE {
        return Err(Error::parse(
            COMPLZSS_DECODED_SIZE_OFFSET,
            "complzss output exceeds 1 GiB",
        ));
    }
    let encoded_size = read_u32_be(data, COMPLZSS_ENCODED_SIZE_OFFSET)? as usize;
    let encoded = slice(data, COMPLZSS_HEADER_SIZE, encoded_size)?;
    let output = LzssDecoder::new(encoded, decoded_size).decode()?;
    if adler32(&output) != read_u32_be(data, COMPLZSS_CHECKSUM_OFFSET)? {
        return Err(Error::parse(
            COMPLZSS_CHECKSUM_OFFSET,
            "complzss Adler-32 mismatch",
        ));
    }
    Ok(output)
}

/// Decoder for the LZSS variant used by complzss.
///
/// Each flag byte describes the next eight tokens, least significant bit
/// first: a set bit is a literal byte, a clear bit a two-byte back-reference
/// with a 12-bit window position and a 4-bit length. The window starts filled
/// with spaces.
struct LzssDecoder<'a> {
    input: &'a [u8],
    position: usize,
    output: Vec<u8>,
    expected: usize,
    window: [u8; LZSS_WINDOW_SIZE],
    cursor: usize,
}

impl<'a> LzssDecoder<'a> {
    fn new(input: &'a [u8], expected: usize) -> Self {
        // A two-byte back-reference expands to at most 18 bytes, which bounds
        // the output at nine times the input.
        let capacity = expected.min(input.len().saturating_mul(9));
        Self {
            input,
            position: 0,
            output: Vec::with_capacity(capacity),
            expected,
            window: [b' '; LZSS_WINDOW_SIZE],
            cursor: LZSS_WINDOW_SIZE - LZSS_MAX_MATCH,
        }
    }

    fn decode(mut self) -> Result<Vec<u8>> {
        while self.output.len() < self.expected {
            let flags = self.next_byte()?;
            for bit in 0..8 {
                if self.output.len() == self.expected {
                    break;
                }
                if flags & (1 << bit) != 0 {
                    let literal = self.next_byte()?;
                    self.emit(literal);
                } else {
                    self.copy_back_reference()?;
                }
            }
        }
        if self.position != self.input.len() {
            return Err(Error::parse(
                self.position,
                "trailing complzss compressed bytes",
            ));
        }
        Ok(self.output)
    }

    fn next_byte(&mut self) -> Result<u8> {
        let [byte] = read_bytes(self.input, self.position)?;
        self.position += 1;
        Ok(byte)
    }

    fn copy_back_reference(&mut self) -> Result<()> {
        let [low, high] = read_bytes(self.input, self.position)?;
        self.position += 2;
        let start = usize::from(low) | (usize::from(high & 0xf0) << 4);
        let len = usize::from(high & 0x0f) + LZSS_MIN_MATCH;
        if self.output.len() + len > self.expected {
            return Err(Error::parse(
                self.position,
                "complzss match exceeds declared output",
            ));
        }
        // Copy byte by byte: a reference may overlap the bytes it produces.
        for index in 0..len {
            self.emit(self.window[(start + index) % LZSS_WINDOW_SIZE]);
        }
        Ok(())
    }

    fn emit(&mut self, byte: u8) {
        self.output.push(byte);
        self.window[self.cursor] = byte;
        self.cursor = (self.cursor + 1) % LZSS_WINDOW_SIZE;
    }
}

/// Computes the Adler-32 checksum of `data`.
fn adler32(data: &[u8]) -> u32 {
    const MODULUS: u32 = 65_521;
    // The largest block length whose sums cannot overflow a u32 before reduction.
    const BLOCK: usize = 5_552;

    let (mut a, mut b) = (1u32, 0u32);
    for block in data.chunks(BLOCK) {
        for &byte in block {
            a += u32::from(byte);
            b += a;
        }
        a %= MODULUS;
        b %= MODULUS;
    }
    (b << 16) | a
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adler32_matches_reference_values() {
        assert_eq!(adler32(b""), 1);
        assert_eq!(adler32(b"Wikipedia"), 0x11e6_0398);
        // Exercise the deferred reduction across several blocks.
        let long = vec![0xff; 3 * 5_552 + 17];
        let (mut a, mut b) = (1u32, 0u32);
        for &byte in &long {
            a = (a + u32::from(byte)) % 65_521;
            b = (b + a) % 65_521;
        }
        assert_eq!(adler32(&long), (b << 16) | a);
    }

    #[test]
    fn detects_compression_by_magic() {
        assert_eq!(
            Compression::detect(b"complzss..."),
            Some(Compression::Complzss)
        );
        assert_eq!(Compression::detect(b"bvx2...."), Some(Compression::Lzfse));
        assert_eq!(Compression::detect(&[0xcf, 0xfa, 0xed, 0xfe]), None);
    }
}
