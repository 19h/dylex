//! IMG4 and IM4P containers: DER-encoded wrappers around a kernel payload.
//!
//! Only the structure needed to locate the payload is parsed. Signatures and
//! manifests are not verified, and encrypted payloads are not decrypted.

use std::fmt;

use crate::error::{Error, Result};

use super::reader::{read_bytes, slice};

/// DER `SEQUENCE` tag. Every IMG4 and IM4P container starts with it.
const DER_SEQUENCE: u8 = 0x30;
/// DER `IA5String` tag, used for the container and payload type names.
const DER_IA5_STRING: u8 = 0x16;
/// DER `OCTET STRING` tag, used for the payload itself.
const DER_OCTET_STRING: u8 = 0x04;

/// Container format that wrapped a kernelcache payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Container {
    /// An IMG4 image whose embedded IM4P holds the payload.
    Img4,
    /// A bare IM4P payload.
    Im4p,
}

impl fmt::Display for Container {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Img4 => "IMG4",
            Self::Im4p => "IM4P",
        })
    }
}

/// Returns the kernel payload of an IMG4 or IM4P container.
///
/// Returns `None` when `data` does not start with a DER sequence.
pub(super) fn unwrap(data: &[u8]) -> Result<Option<(Container, &[u8])>> {
    if data.first() != Some(&DER_SEQUENCE) {
        return Ok(None);
    }
    let (name, fields) = open_sequence(data)?;
    match name {
        b"IMG4" => {
            // The element following the IMG4 name is the IM4P that carries the payload.
            let im4p = Tlv::parse(fields)?;
            let (name, fields) = open_sequence(im4p.encoded)?;
            if name != b"IM4P" {
                return Err(Error::parse(0, "expected IMG4 or IM4P identifier"));
            }
            Ok(Some((Container::Img4, im4p_payload(fields)?)))
        }
        b"IM4P" => Ok(Some((Container::Im4p, im4p_payload(fields)?))),
        _ => Err(Error::parse(0, "expected IMG4 or IM4P identifier")),
    }
}

/// Parses a sequence that spans all of `data` and starts with a type name.
///
/// Returns the name and the encoded fields that follow it.
fn open_sequence(data: &[u8]) -> Result<(&[u8], &[u8])> {
    let sequence = Tlv::parse(data)?;
    if sequence.tag != DER_SEQUENCE || !sequence.rest.is_empty() {
        return Err(Error::parse(0, "expected IMG4 or IM4P DER sequence"));
    }
    let name = Tlv::parse(sequence.value)?;
    if name.tag != DER_IA5_STRING {
        return Err(Error::parse(0, "missing IMG4/IM4P identifier"));
    }
    Ok((name.value, name.rest))
}

/// Reads the IM4P fields after its name: payload type, description, and payload.
fn im4p_payload(fields: &[u8]) -> Result<&[u8]> {
    let kind = Tlv::parse(fields)?;
    if kind.tag != DER_IA5_STRING || !matches!(kind.value, b"krnl" | b"rkrn") {
        return Err(Error::parse(0, "IM4P payload is not a kernel (krnl/rkrn)"));
    }
    let description = Tlv::parse(kind.rest)?;
    if description.tag != DER_IA5_STRING {
        return Err(Error::parse(0, "missing IM4P description"));
    }
    let payload = Tlv::parse(description.rest)?;
    if payload.tag != DER_OCTET_STRING {
        return Err(Error::parse(0, "missing IM4P payload octet string"));
    }
    Ok(payload.value)
}

/// One DER tag-length-value element.
struct Tlv<'a> {
    tag: u8,
    /// Content bytes.
    value: &'a [u8],
    /// The complete element, including its tag and length.
    encoded: &'a [u8],
    /// Bytes following the element.
    rest: &'a [u8],
}

impl<'a> Tlv<'a> {
    /// Parses a definite-length element whose length occupies at most four bytes.
    fn parse(data: &'a [u8]) -> Result<Self> {
        let [tag, length] = read_bytes(data, 0)?;
        let (len, value_start) = if length & 0x80 == 0 {
            (usize::from(length), 2)
        } else {
            let count = usize::from(length & 0x7f);
            if !(1..=4).contains(&count) {
                return Err(Error::parse(1, "unsupported DER length"));
            }
            let len = slice(data, 2, count)?
                .iter()
                .fold(0, |len, &byte| (len << 8) | usize::from(byte));
            (len, 2 + count)
        };
        let value = slice(data, value_start, len)?;
        let end = value_start + len;
        Ok(Self {
            tag,
            value,
            encoded: &data[..end],
            rest: &data[end..],
        })
    }
}
