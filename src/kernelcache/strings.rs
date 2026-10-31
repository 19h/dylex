//! Literal string and hex byte search across kernelcache images.

use std::collections::HashSet;

use rayon::prelude::*;

use crate::dyld::{
    CONTEXT_BYTES, StringHit, StringQuery, describe_match, find_all, section_name_at,
};
use crate::error::{Error, Result};
use crate::macho::SegmentInfo;

use super::{KernelCacheContext, KernelImage, LINKEDIT_SEGMENT};

impl KernelCacheContext {
    /// Searches the file-backed segments of every image matching the query's filter.
    ///
    /// Hits are reported like [`DyldContext::search_strings`](crate::DyldContext::search_strings):
    /// a match inside an ASCII C string is reported once, at the start of that
    /// string. `__LINKEDIT` is skipped because it maps the collection's shared
    /// tables. A segment shared by several images reports its matches once per
    /// image. Matches do not span segment boundaries.
    pub fn search_strings(&self, query: &StringQuery) -> Result<Vec<StringHit>> {
        if query.needle.is_empty() {
            return Err(Error::parse(0, "empty search needle"));
        }
        let filter = query.image_filter.as_deref().unwrap_or_default();
        let hits: Vec<Vec<StringHit>> = self
            .images
            .par_iter()
            .filter(|image| image.id.contains(filter))
            .map(|image| self.search_image(image, query))
            .collect::<Result<_>>()?;
        Ok(hits.into_iter().flatten().collect())
    }

    fn search_image(&self, image: &KernelImage, query: &StringQuery) -> Result<Vec<StringHit>> {
        let mut hits = Vec::new();
        for segment in image.macho.segments() {
            if segment.name() != LINKEDIT_SEGMENT && segment.command.filesize != 0 {
                self.search_segment(image, segment, query, &mut hits)?;
            }
        }
        Ok(hits)
    }

    fn search_segment(
        &self,
        image: &KernelImage,
        segment: &SegmentInfo,
        query: &StringQuery,
        hits: &mut Vec<StringHit>,
    ) -> Result<()> {
        let bytes = self.member_bytes(image, segment.command.fileoff, segment.command.filesize)?;
        let needle_len = query.needle.len();
        let context = CONTEXT_BYTES as usize;
        let mut seen_strings = HashSet::new();
        let mut seen_raw = HashSet::new();
        for match_offset in find_all(bytes, &query.needle, query.ignore_case) {
            let window_start = match_offset.saturating_sub(context);
            let window_end = (match_offset + needle_len + context).min(bytes.len());
            let (offset, text, is_cstring) = describe_match(
                &bytes[window_start..window_end],
                match_offset - window_start,
                needle_len,
            );
            let address = segment.command.vmaddr + (window_start + offset) as u64;
            let match_address = segment.command.vmaddr + match_offset as u64;
            // Several matches inside one C string share its start address.
            let first = if is_cstring {
                seen_strings.insert(address)
            } else {
                seen_raw.insert(match_address)
            };
            if !first {
                continue;
            }
            hits.push(StringHit {
                image_path: image.id.clone(),
                segment: segment.name().to_string(),
                section: section_name_at(segment, address)
                    .or_else(|| section_name_at(segment, match_address)),
                address,
                text,
            });
        }
        Ok(())
    }
}
