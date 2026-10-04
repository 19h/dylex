//! Literal string search across images in a dyld shared cache.

use std::collections::{HashMap, HashSet};

use rayon::prelude::*;

use super::DyldContext;
use super::context::{ImageEntry, MappingEntry};
use crate::error::{Error, Result};
use crate::macho::SegmentInfo;

/// How far around a match to look for the enclosing ASCII C string.
const CONTEXT_BYTES: u64 = 4096;
/// Longest C string copied into [`StringHit::text`].
const MAX_TEXT: usize = 512;

/// Literal-string search parameters.
#[derive(Debug, Clone)]
pub struct StringQuery {
    /// Bytes to find. The match is a substring of the image bytes.
    pub needle: Vec<u8>,
    /// Compare ASCII letters without regard to case.
    pub ignore_case: bool,
    /// When set, only images whose path contains this substring are searched.
    /// An empty filter searches every image.
    pub image_filter: Option<String>,
}

/// One string match inside a cache image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringHit {
    /// Image path inside the cache.
    pub image_path: String,
    /// Segment name, such as `__TEXT`.
    pub segment: String,
    /// Section name when the reported address falls in a section.
    pub section: Option<String>,
    /// Unslid virtual address of the match.
    ///
    /// For an ASCII C string this is the start of that string. Otherwise it is
    /// the address of the matched bytes.
    pub address: u64,
    /// Enclosing C string, or a short escaped snippet of the matched bytes.
    pub text: String,
}

/// Matches found by [`DyldContext::search_strings`], plus images that were skipped.
#[derive(Debug, Clone)]
pub struct StringSearchOutcome {
    /// Matches, ordered by image path and then address.
    pub hits: Vec<StringHit>,
    /// `path: reason` for images whose Mach-O headers could not be read.
    pub skipped: Vec<String>,
}

/// Images that contain [`StringQuery::needle`], in cache order.
#[derive(Debug, Clone)]
pub struct ContainingImages {
    /// Images with at least one match.
    pub images: Vec<ImageEntry>,
    /// `path: reason` for images whose Mach-O headers could not be read.
    pub skipped: Vec<String>,
}

/// Tail of the previous mapped slice, used to match a string that crosses slices.
struct Carry {
    base: u64,
    bytes: Vec<u8>,
}

impl DyldContext {
    /// Searches the file-backed bytes of each selected image for `query.needle`.
    ///
    /// A segment contributes `filesize` bytes starting at `vmaddr`. Bytes past
    /// that range stay unread. A range claimed by more than one image is
    /// skipped; on current caches that is the shared `__LINKEDIT` mapped by
    /// every image. Each hit names the segment and, when the address falls in
    /// one, the section. `on_image` runs after each image and may run on a
    /// worker thread.
    pub fn search_strings<F>(&self, query: &StringQuery, on_image: F) -> Result<StringSearchOutcome>
    where
        F: Fn() + Sync,
    {
        if query.needle.is_empty() {
            return Err(Error::Parse {
                offset: 0,
                reason: "search string is empty".into(),
            });
        }
        let on_image = &on_image;
        let shared = self.shared_segment_ranges();
        let images = self.images_for_string_search(query.image_filter.as_deref());
        let parts: Vec<std::result::Result<Vec<StringHit>, String>> = images
            .par_iter()
            .map(|image| {
                let result = self
                    .search_image_with_shared(image, query, &shared)
                    .map_err(|err| format!("{}: {err}", image.path));
                on_image();
                result
            })
            .collect();

        let mut hits = Vec::new();
        let mut skipped = Vec::new();
        for part in parts {
            match part {
                Ok(found) => hits.extend(found),
                Err(reason) => skipped.push(reason),
            }
        }
        hits.sort_by(|a, b| {
            a.image_path
                .cmp(&b.image_path)
                .then(a.address.cmp(&b.address))
                .then(a.segment.cmp(&b.segment))
                .then(a.text.cmp(&b.text))
        });
        Ok(StringSearchOutcome { hits, skipped })
    }

    /// Images selected by a path substring. An empty filter selects every image.
    pub fn images_for_string_search(&self, filter: Option<&str>) -> Vec<ImageEntry> {
        let filter = filter.filter(|value| !value.is_empty());
        self.images
            .iter()
            .filter(|image| filter.is_none_or(|value| image.matches_filter(value)))
            .cloned()
            .collect()
    }

    /// Images whose searched bytes contain `query`, in cache order.
    ///
    /// An image is included once when it has at least one hit. `image_filter`
    /// limits the search. Shared ranges are skipped, same as [`Self::search_strings`].
    /// `on_image` runs after each searched image and may run on a worker thread.
    pub fn images_containing<F>(&self, query: &StringQuery, on_image: F) -> Result<ContainingImages>
    where
        F: Fn() + Sync,
    {
        let outcome = self.search_strings(query, on_image)?;
        let matched: HashSet<&str> = outcome
            .hits
            .iter()
            .map(|hit| hit.image_path.as_str())
            .collect();
        let images = self
            .images
            .iter()
            .filter(|image| matched.contains(image.path.as_str()))
            .cloned()
            .collect();
        Ok(ContainingImages {
            images,
            skipped: outcome.skipped,
        })
    }

    /// Searches one image. `image_filter` on the query is ignored.
    ///
    /// Ranges shared with another image are omitted, same as [`Self::search_strings`].
    pub fn search_image(&self, image: &ImageEntry, query: &StringQuery) -> Result<Vec<StringHit>> {
        self.search_image_with_shared(image, query, &self.shared_segment_ranges())
    }

    /// File ranges mapped by more than one image, keyed by `(vmaddr, filesize)`.
    fn shared_segment_ranges(&self) -> HashSet<(u64, u64)> {
        let mut counts: HashMap<(u64, u64), u32> = HashMap::new();
        for image in &self.images {
            let Ok(header) = self.image_header(image.address) else {
                continue;
            };
            let mut seen = HashSet::new();
            for segment in header.segments() {
                if segment.command.filesize > 0 {
                    seen.insert((segment.command.vmaddr, segment.command.filesize));
                }
            }
            for key in seen {
                *counts.entry(key).or_default() += 1;
            }
        }
        counts
            .into_iter()
            .filter(|(_, count)| *count > 1)
            .map(|(key, _)| key)
            .collect()
    }

    fn search_image_with_shared(
        &self,
        image: &ImageEntry,
        query: &StringQuery,
        shared: &HashSet<(u64, u64)>,
    ) -> Result<Vec<StringHit>> {
        if query.needle.is_empty() {
            return Err(Error::Parse {
                offset: 0,
                reason: "search string is empty".into(),
            });
        }
        let header = self.image_header(image.address)?;
        let mut hits = Vec::new();
        for segment in header.segments() {
            if segment.command.filesize == 0 {
                continue;
            }
            if shared.contains(&(segment.command.vmaddr, segment.command.filesize)) {
                continue;
            }
            self.collect_segment_hits(image, segment, query, &mut hits)?;
        }
        Ok(hits)
    }

    fn collect_segment_hits(
        &self,
        image: &ImageEntry,
        segment: &SegmentInfo,
        query: &StringQuery,
        hits: &mut Vec<StringHit>,
    ) -> Result<()> {
        let start = segment.command.vmaddr;
        let end = start
            .checked_add(segment.command.filesize)
            .ok_or(Error::Parse {
                offset: 0,
                reason: format!(
                    "segment {} extent overflow in {}",
                    segment.name(),
                    image.path
                ),
            })?;

        let mut carry = Carry {
            base: start,
            bytes: Vec::new(),
        };
        let mut matches = Vec::new();
        let mut addr = start;
        while addr < end {
            let Some(mapping) = self.mapping_for_addr(addr) else {
                carry.bytes.clear();
                addr = next_mapping_address(&self.mappings, addr).unwrap_or(end);
                continue;
            };
            let slice_end = end.min(mapping.address.saturating_add(mapping.size));
            if slice_end <= addr {
                break;
            }
            let data = self.data_at_addr(addr, (slice_end - addr) as usize)?;
            let contiguous = !carry.bytes.is_empty()
                && carry.base.saturating_add(carry.bytes.len() as u64) == addr;
            matches.extend(matches_in_slice(
                data,
                addr,
                &query.needle,
                query.ignore_case,
                &carry,
                contiguous,
            ));
            remember_tail(&mut carry, data, addr, slice_end, query.needle.len());
            addr = slice_end;
        }
        matches.sort_unstable();
        matches.dedup();

        let mut seen_strings = HashSet::new();
        let mut seen_raw = HashSet::new();
        for match_addr in matches {
            let (text_addr, text, is_cstring) = self.display_at(match_addr, query.needle.len())?;
            let address = if is_cstring { text_addr } else { match_addr };
            if is_cstring {
                if !seen_strings.insert(address) {
                    continue;
                }
            } else if !seen_raw.insert(match_addr) {
                continue;
            }
            let section =
                section_name_at(segment, address).or_else(|| section_name_at(segment, match_addr));
            hits.push(StringHit {
                image_path: image.path.clone(),
                segment: segment.name().to_string(),
                section,
                address,
                text,
            });
        }
        Ok(())
    }

    /// Returns `(address, text, is_cstring)` for a match inside one mapping.
    fn display_at(&self, match_addr: u64, needle_len: usize) -> Result<(u64, String, bool)> {
        let mapping = self
            .mapping_for_addr(match_addr)
            .ok_or(Error::AddressNotFound { addr: match_addr })?;
        let map_end = mapping.address.saturating_add(mapping.size);
        let window_start = match_addr
            .saturating_sub(CONTEXT_BYTES)
            .max(mapping.address);
        let window_end = match_addr
            .saturating_add(needle_len as u64)
            .saturating_add(CONTEXT_BYTES)
            .min(map_end);
        if window_end <= window_start {
            return Ok((match_addr, String::new(), false));
        }
        let data = self.data_at_addr(window_start, (window_end - window_start) as usize)?;
        let rel = (match_addr - window_start) as usize;
        if let Some((start, end)) = ascii_cstring_span(data, rel, needle_len) {
            let mut text = String::from_utf8_lossy(&data[start..end]).into_owned();
            truncate_text(&mut text);
            return Ok((window_start + start as u64, text, true));
        }
        let snip_start = rel.saturating_sub(16);
        let snip_end = (rel + needle_len).saturating_add(16).min(data.len());
        Ok((
            match_addr,
            escape_snippet(&data[snip_start..snip_end]),
            false,
        ))
    }
}

fn next_mapping_address(mappings: &[MappingEntry], addr: u64) -> Option<u64> {
    mappings
        .iter()
        .find(|mapping| mapping.address > addr)
        .map(|mapping| mapping.address)
}

fn section_name_at(segment: &SegmentInfo, addr: u64) -> Option<String> {
    segment
        .sections
        .iter()
        .find(|section| {
            let start = section.section.addr;
            let size = section.section.size;
            size > 0 && addr >= start && addr - start < size
        })
        .map(|section| section.name().to_string())
}

fn matches_in_slice(
    data: &[u8],
    addr: u64,
    needle: &[u8],
    ignore_case: bool,
    carry: &Carry,
    contiguous: bool,
) -> Vec<u64> {
    let mut found = Vec::new();
    let overlap = needle.len().saturating_sub(1);
    if contiguous && overlap > 0 && !carry.bytes.is_empty() {
        let prefix_len = overlap.min(data.len());
        let mut window = Vec::with_capacity(carry.bytes.len() + prefix_len);
        window.extend_from_slice(&carry.bytes);
        window.extend_from_slice(&data[..prefix_len]);
        for rel in find_all(&window, needle, ignore_case) {
            let match_addr = carry.base + rel as u64;
            let match_end = match_addr + needle.len() as u64;
            if match_addr < addr && match_end > addr {
                found.push(match_addr);
            }
        }
    }
    for rel in find_all(data, needle, ignore_case) {
        found.push(addr + rel as u64);
    }
    found
}

fn remember_tail(carry: &mut Carry, data: &[u8], addr: u64, slice_end: u64, needle_len: usize) {
    let overlap = needle_len.saturating_sub(1);
    if overlap == 0 || data.is_empty() {
        carry.bytes.clear();
        return;
    }
    if data.len() >= overlap {
        carry.bytes.clear();
        carry.bytes.extend_from_slice(&data[data.len() - overlap..]);
        carry.base = slice_end - overlap as u64;
        return;
    }
    let adjacent =
        !carry.bytes.is_empty() && carry.base.saturating_add(carry.bytes.len() as u64) == addr;
    if adjacent {
        let need_from_old = overlap - data.len();
        if carry.bytes.len() > need_from_old {
            let drop_n = carry.bytes.len() - need_from_old;
            carry.bytes.drain(..drop_n);
            carry.base += drop_n as u64;
        }
        carry.bytes.extend_from_slice(data);
    } else {
        carry.bytes.clear();
        carry.bytes.extend_from_slice(data);
        carry.base = addr;
    }
}

fn find_all(haystack: &[u8], needle: &[u8], ignore_case: bool) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    if !ignore_case {
        let mut found = Vec::new();
        let mut from = 0;
        while from + needle.len() <= haystack.len() {
            let Some(rel) = memchr::memmem::find(&haystack[from..], needle) else {
                break;
            };
            found.push(from + rel);
            from += rel + 1;
        }
        return found;
    }

    let first = needle[0];
    let lower = first.to_ascii_lowercase();
    let upper = first.to_ascii_uppercase();
    let mut found = Vec::new();
    let mut from = 0;
    while from + needle.len() <= haystack.len() {
        let rest = &haystack[from..];
        let Some(rel) = (if lower == upper {
            memchr::memchr(lower, rest)
        } else {
            memchr::memchr2(lower, upper, rest)
        }) else {
            break;
        };
        let pos = from + rel;
        if pos + needle.len() <= haystack.len()
            && haystack[pos..pos + needle.len()].eq_ignore_ascii_case(needle)
        {
            found.push(pos);
        }
        from = pos + 1;
    }
    found
}

/// ASCII printable run that contains the needle and ends at a NUL.
fn ascii_cstring_span(data: &[u8], match_rel: usize, needle_len: usize) -> Option<(usize, usize)> {
    if needle_len == 0 || match_rel.saturating_add(needle_len) > data.len() {
        return None;
    }
    let mut start = match_rel;
    while start > 0 && is_ascii_printable(data[start - 1]) {
        start -= 1;
    }
    let mut end = match_rel + needle_len;
    while end < data.len() && data[end] != 0 && is_ascii_printable(data[end]) {
        end += 1;
    }
    if end < data.len()
        && data[end] == 0
        && start <= match_rel
        && end >= match_rel + needle_len
        && is_display_string(&data[start..end])
    {
        Some((start, end))
    } else {
        None
    }
}

fn is_ascii_printable(byte: u8) -> bool {
    byte == b'\t' || (0x20..=0x7e).contains(&byte)
}

fn is_display_string(bytes: &[u8]) -> bool {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return false;
    };
    !text.is_empty() && text.chars().all(|c| c == '\t' || !c.is_control())
}

fn truncate_text(text: &mut String) {
    if text.len() <= MAX_TEXT {
        return;
    }
    let mut cut = MAX_TEXT;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    text.truncate(cut);
    text.push_str("...");
}

fn escape_snippet(bytes: &[u8]) -> String {
    let mut out = String::new();
    for (index, byte) in bytes.iter().enumerate() {
        if index == 64 {
            out.push_str("...");
            break;
        }
        match byte {
            b'\\' => out.push_str("\\\\"),
            0x20..=0x7e => out.push(*byte as char),
            _ => out.push_str(&format!("\\x{byte:02x}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_overlapping_and_case_insensitive_matches() {
        assert_eq!(find_all(b"aaa", b"aa", false), vec![0, 1]);
        assert_eq!(find_all(b"AbC", b"abc", true), vec![0]);
        assert!(find_all(b"abc", b"abcd", false).is_empty());
        assert!(find_all(b"ab", b"", false).is_empty());
    }

    #[test]
    fn match_can_cross_adjacent_slices_and_stops_at_a_gap() {
        let mut carry = Carry {
            base: 0,
            bytes: Vec::new(),
        };
        let first = b"abwxy";
        let mut found = matches_in_slice(first, 0, b"wxyz", false, &carry, false);
        remember_tail(&mut carry, first, 0, first.len() as u64, 4);
        let second = b"zcd";
        found.extend(matches_in_slice(second, 5, b"wxyz", false, &carry, true));
        assert_eq!(found, vec![2]);

        let mut gapped = Carry {
            base: 0,
            bytes: Vec::new(),
        };
        let head = b"wxy";
        let mut across_gap = matches_in_slice(head, 0, b"wxyz", false, &gapped, false);
        remember_tail(&mut gapped, head, 0, head.len() as u64, 4);
        across_gap.extend(matches_in_slice(b"z", 10, b"wxyz", false, &gapped, false));
        assert!(across_gap.is_empty());
    }

    #[test]
    fn cstring_span_covers_the_whole_printable_run() {
        let data = b"\xffcom.apple.hid\0";
        assert_eq!(ascii_cstring_span(data, 5, 3), Some((1, 14)));
        assert_eq!(ascii_cstring_span(b"no-nul-here", 0, 2), None);
    }
}
