//! Legacy prelinked kernels, whose kexts are described by `__PRELINK_INFO` metadata.
//!
//! XML metadata uses OSUnserializeXML's backward `ID`/`IDREF` references,
//! which are expanded before the property list is handed to the `plist` crate.

use std::collections::HashMap;
use std::io::Cursor;

use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, Writer};

use crate::error::{Error, Result};
use crate::macho::MachOContext;

use super::reader::{slice, to_usize};
use super::{KERNEL_IMAGE_ID, KernelImage, OffsetBase, parse_macho_at};

/// Segment holding prelink metadata.
pub(super) const PRELINK_INFO_SEGMENT: &str = "__PRELINK_INFO";
/// Section holding prelink metadata, when the segment has sections.
const PRELINK_INFO_SECTION: &str = "__info";
const BINARY_PLIST_MAGIC: &[u8] = b"bplist";

/// Upper bound on metadata, expanded XML, and saved XML references (64 MiB each).
const MAX_METADATA_SIZE: usize = 64 * 1024 * 1024;
/// Upper bound on XML element nesting.
const MAX_XML_DEPTH: usize = 128;

// =============================================================================
// Prelinked Images
// =============================================================================

/// Reads the kernel and every executable kext described by the prelink metadata.
pub(super) fn read_images(data: &[u8], kernel: &MachOContext) -> Result<Vec<KernelImage>> {
    let metadata = parse_metadata(prelink_info(data, kernel)?)?;
    let records = metadata
        .as_dictionary()
        .and_then(|metadata| metadata.get("_PrelinkInfoDictionary"))
        .and_then(plist::Value::as_array)
        .ok_or_else(|| Error::parse(0, "missing _PrelinkInfoDictionary array"))?;
    let kernel_address = kernel
        .segments()
        .find(|segment| segment.command.fileoff == 0 && segment.command.filesize > 0)
        .map(|segment| segment.command.vmaddr)
        .ok_or_else(|| Error::parse(0, "kernel header is not mapped"))?;

    let mut images = vec![KernelImage {
        id: KERNEL_IMAGE_ID.into(),
        address: kernel_address,
        file_offset: 0,
        macho: parse_macho_at(data, 0)?,
        offset_base: OffsetBase::Collection,
    }];
    for record in records {
        let record = record
            .as_dictionary()
            .ok_or_else(|| Error::parse(0, "prelink record is not a dictionary"))?;
        images.extend(read_record(data, kernel, record)?);
    }
    Ok(images)
}

/// Returns the metadata bytes from `__PRELINK_INFO,__info`, or the whole segment.
fn prelink_info<'a>(data: &'a [u8], kernel: &MachOContext) -> Result<&'a [u8]> {
    let segment = kernel
        .segment(PRELINK_INFO_SEGMENT)
        .ok_or_else(|| Error::SegmentNotFound {
            name: PRELINK_INFO_SEGMENT.into(),
        })?;
    let (offset, size) = match segment.section(PRELINK_INFO_SECTION) {
        Some(section) => (u64::from(section.section.offset), section.section.size),
        None => (segment.command.fileoff, segment.command.filesize),
    };
    let bytes = slice(data, to_usize(offset)?, to_usize(size)?)?;
    if bytes.starts_with(BINARY_PLIST_MAGIC) {
        return Ok(bytes);
    }
    // XML metadata is NUL-terminated inside a zero-padded region.
    Ok(&bytes[..memchr::memchr(0, bytes).unwrap_or(bytes.len())])
}

/// Reads one prelink record. Codeless kexts have no executable and yield `None`.
fn read_record(
    data: &[u8],
    kernel: &MachOContext,
    record: &plist::Dictionary,
) -> Result<Option<KernelImage>> {
    let Some(size) = integer(record, "_PrelinkExecutableSize")?.filter(|&size| size != 0) else {
        return Ok(None);
    };
    let source_address = integer(record, "_PrelinkExecutableSourceAddr")?;
    let load_address = integer(record, "_PrelinkExecutableLoadAddr")?;
    let source_address = source_address
        .or(load_address)
        .ok_or_else(|| Error::parse(0, "executable prelink record has no source address"))?;

    let offset = collection_offset(kernel, source_address)?;
    slice(data, offset, to_usize(size)?)?;
    let id = record
        .get("CFBundleIdentifier")
        .and_then(plist::Value::as_string)
        .filter(|id| !id.is_empty())
        .ok_or_else(|| Error::parse(0, "prelink record has no CFBundleIdentifier"))?;
    let macho = parse_macho_at(data, offset)?;
    // Kexts linked at file offset zero use offsets relative to their own header.
    let offset_base = match macho.segments().find(|segment| segment.name() == "__TEXT") {
        Some(text) if text.command.fileoff == 0 => OffsetBase::Image,
        Some(_) => OffsetBase::Collection,
        None => {
            return Err(Error::parse(
                offset,
                "prelinked executable has no TEXT segment",
            ));
        }
    };
    Ok(Some(KernelImage {
        id: id.into(),
        address: load_address.unwrap_or(source_address),
        file_offset: offset as u64,
        macho,
        offset_base,
    }))
}

/// Reads an integer, also accepting the decimal and `0x` strings that prelink XML can contain.
fn integer(record: &plist::Dictionary, key: &str) -> Result<Option<u64>> {
    let Some(value) = record.get(key) else {
        return Ok(None);
    };
    value
        .as_unsigned_integer()
        .or_else(|| value.as_string().and_then(parse_integer))
        .map(Some)
        .ok_or_else(|| Error::parse(0, format!("invalid {key}")))
}

fn parse_integer(text: &str) -> Option<u64> {
    match text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

/// Maps an unslid address to a collection offset through the kernel's file-backed segments.
fn collection_offset(kernel: &MachOContext, address: u64) -> Result<usize> {
    let offset = kernel
        .segments()
        .find_map(|segment| {
            let delta = address.checked_sub(segment.command.vmaddr)?;
            (delta < segment.command.filesize).then(|| segment.command.fileoff + delta)
        })
        .ok_or(Error::AddressNotFound { addr: address })?;
    to_usize(offset)
}

// =============================================================================
// Metadata Parsing
// =============================================================================

/// Parses binary or XML prelink metadata.
fn parse_metadata(bytes: &[u8]) -> Result<plist::Value> {
    if bytes.len() > MAX_METADATA_SIZE {
        return Err(Error::parse(0, "prelink metadata exceeds 64 MiB"));
    }
    if bytes.starts_with(BINARY_PLIST_MAGIC) {
        return plist::Value::from_reader(Cursor::new(bytes))
            .map_err(|error| Error::parse(0, format!("invalid binary prelink plist: {error}")));
    }
    let expanded = expand_xml_references(bytes)?;
    plist::Value::from_reader(Cursor::new(expanded))
        .map_err(|error| Error::parse(0, format!("invalid prelink plist: {error}")))
}

/// Rewrites prelink XML, replacing each `IDREF` element with the element carrying that `ID`.
///
/// References only point backwards, so a single pass suffices.
fn expand_xml_references(xml: &[u8]) -> Result<Vec<u8>> {
    let mut reader = Reader::from_reader(xml);
    let mut expander = XmlExpander::new();
    loop {
        let event = reader
            .read_event()
            .map_err(|error| Error::parse(0, format!("invalid prelink XML: {error}")))?;
        match event {
            Event::Eof => break,
            Event::Start(element) => {
                let ids = ElementIds::parse(&element)?;
                if ids.reference.is_some() {
                    return Err(invalid_reference());
                }
                expander.open(element, ids.id)?;
            }
            Event::Empty(element) => {
                let ids = ElementIds::parse(&element)?;
                match ids.reference {
                    Some(_) if ids.id.is_some() => return Err(invalid_reference()),
                    Some(reference) => expander.expand(&reference)?,
                    None => expander.empty(element, ids.id)?,
                }
            }
            Event::End(_) => expander.close(event)?,
            event => expander.write(event)?,
        }
    }
    expander.finish()
}

fn invalid_reference() -> Error {
    Error::parse(0, "prelink IDREF must be an empty element without an ID")
}

/// The `ID` and `IDREF` attributes of one element.
struct ElementIds {
    id: Option<Vec<u8>>,
    reference: Option<Vec<u8>>,
}

impl ElementIds {
    fn parse(element: &BytesStart<'_>) -> Result<Self> {
        let mut ids = Self {
            id: None,
            reference: None,
        };
        for attribute in element.attributes() {
            let attribute = attribute.map_err(|error| {
                Error::parse(0, format!("invalid prelink XML attribute: {error}"))
            })?;
            match attribute.key.as_ref() {
                b"ID" => ids.id = Some(attribute.value.into_owned()),
                b"IDREF" => ids.reference = Some(attribute.value.into_owned()),
                _ => {}
            }
        }
        Ok(ids)
    }
}

/// Output state for [`expand_xml_references`].
struct XmlExpander {
    output: Writer<Vec<u8>>,
    references: ReferenceTable,
    /// Output offset and `ID` of each open element.
    open: Vec<(usize, Option<Vec<u8>>)>,
}

impl XmlExpander {
    fn new() -> Self {
        Self {
            output: Writer::new(Vec::new()),
            references: ReferenceTable::default(),
            open: Vec::new(),
        }
    }

    fn position(&self) -> usize {
        self.output.get_ref().len()
    }

    fn write(&mut self, event: Event<'_>) -> Result<()> {
        self.output
            .write_event(event)
            .map_err(|error| Error::parse(0, error.to_string()))?;
        if self.position() > MAX_METADATA_SIZE {
            return Err(Error::parse(0, "prelink XML exceeds 64 MiB"));
        }
        Ok(())
    }

    fn open(&mut self, element: BytesStart<'_>, id: Option<Vec<u8>>) -> Result<()> {
        if self.open.len() >= MAX_XML_DEPTH {
            return Err(Error::parse(0, "prelink XML nesting exceeds 128"));
        }
        self.open.push((self.position(), id));
        self.write(Event::Start(element))
    }

    fn close(&mut self, end: Event<'_>) -> Result<()> {
        let (start, id) = self
            .open
            .pop()
            .ok_or_else(|| Error::parse(0, "unbalanced prelink XML"))?;
        self.write(end)?;
        if let Some(id) = id {
            let element = self.output.get_ref()[start..].to_vec();
            self.references.insert(id, element)?;
        }
        Ok(())
    }

    fn empty(&mut self, element: BytesStart<'_>, id: Option<Vec<u8>>) -> Result<()> {
        if let Some(id) = id {
            let mut encoded = Writer::new(Vec::new());
            encoded
                .write_event(Event::Empty(element.borrow()))
                .map_err(|error| Error::parse(0, error.to_string()))?;
            self.references.insert(id, encoded.into_inner())?;
        }
        self.write(Event::Empty(element))
    }

    fn expand(&mut self, reference: &[u8]) -> Result<()> {
        let element = self.references.get(reference)?;
        if self.position() + element.len() > MAX_METADATA_SIZE {
            return Err(Error::parse(
                0,
                "prelink XML reference expansion exceeds 64 MiB",
            ));
        }
        self.output.get_mut().extend_from_slice(element);
        Ok(())
    }

    fn finish(self) -> Result<Vec<u8>> {
        if !self.open.is_empty() {
            return Err(Error::parse(0, "unclosed prelink XML elements"));
        }
        Ok(self.output.into_inner())
    }
}

/// Encoded elements saved by `ID`, bounded by their total size.
#[derive(Default)]
struct ReferenceTable {
    elements: HashMap<Vec<u8>, Vec<u8>>,
    stored_bytes: usize,
}

impl ReferenceTable {
    fn insert(&mut self, id: Vec<u8>, element: Vec<u8>) -> Result<()> {
        self.stored_bytes = self
            .stored_bytes
            .checked_add(id.len())
            .and_then(|total| total.checked_add(element.len()))
            .filter(|&total| total <= MAX_METADATA_SIZE)
            .ok_or_else(|| Error::parse(0, "prelink XML reference storage exceeds 64 MiB"))?;
        if self.elements.insert(id, element).is_some() {
            return Err(Error::parse(0, "duplicate prelink XML ID"));
        }
        Ok(())
    }

    fn get(&self, id: &[u8]) -> Result<&[u8]> {
        self.elements
            .get(id)
            .map(Vec::as_slice)
            .ok_or_else(|| Error::parse(0, "unresolved prelink XML IDREF"))
    }
}
