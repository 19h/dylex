//! Infer directly referenced runtime images without dependency-graph traversal.
use crate::{DyldContext, Error, Result, arm64, macho::*};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Evidence for one directly referenced runtime image.
#[derive(Debug, Clone)]
pub struct RuntimeImageReference {
    /// Canonical path of the inferred image.
    pub image_path: String,
    /// Number of distinct branch/pointer sites in the selected roots.
    pub reference_count: usize,
    /// Source image for the first reference.
    pub source_image: String,
    /// Address of the first referring instruction or pointer slot.
    pub source_address: u64,
    /// Destination before following any stubs.
    pub via_address: u64,
    /// Final address inside the runtime image.
    pub target_address: u64,
}

fn invalid(reason: &str) -> Error {
    Error::Parse {
        offset: 0,
        reason: reason.into(),
    }
}

/// Runtime policy: libSystem components, Objective-C, C++, and Swift libraries.
/// Frameworks and arbitrary libraries are selected explicitly with --merge-image.
pub fn is_runtime_image(path: &str) -> bool {
    (path.starts_with("/usr/lib/system/") && path.ends_with(".dylib"))
        || matches!(
            path,
            "/usr/lib/libSystem.B.dylib"
                | "/usr/lib/libobjc.A.dylib"
                | "/usr/lib/libc++.1.dylib"
                | "/usr/lib/libc++abi.dylib"
        )
        || (path.starts_with("/usr/lib/swift/libswift") && path.ends_with(".dylib"))
}

struct Range {
    start: u64,
    end: u64,
    image: usize,
}
struct Ownership {
    ranges: Vec<Range>,
    prefix_end: Vec<u64>,
    stubs: Vec<(u64, u64)>,
    stub_prefix_end: Vec<u64>,
}
impl Ownership {
    fn new(cache: &DyldContext) -> Result<Self> {
        let mut ranges = Vec::new();
        let mut stubs = Vec::new();
        for (index, image) in cache.images.iter().enumerate() {
            for segment in cache
                .image_header(image.address)?
                .segments()
                .filter(|s| s.name() != "__LINKEDIT")
            {
                let start = segment.command.vmaddr;
                let end = start
                    .checked_add(segment.command.vmsize)
                    .ok_or_else(|| invalid("image VM extent overflow"))?;
                if start != end {
                    ranges.push(Range {
                        start,
                        end,
                        image: index,
                    });
                }
                for section in &segment.sections {
                    if section.section.flags & SECTION_TYPE == S_SYMBOL_STUBS
                        || matches!(section.name(), "__stubs" | "__auth_stubs" | "__objc_stubs")
                    {
                        let a = section.section.addr;
                        let b = a
                            .checked_add(section.section.size)
                            .ok_or_else(|| invalid("stub section extent overflow"))?;
                        if a < start || b > end {
                            return Err(invalid("stub section outside segment"));
                        }
                        if a != b {
                            stubs.push((a, b));
                        }
                    }
                }
            }
        }
        ranges.sort_by_key(|r| (r.start, r.image));
        let mut end = 0;
        let prefix_end = ranges
            .iter()
            .map(|r| {
                end = end.max(r.end);
                end
            })
            .collect();
        stubs.sort_unstable();
        let mut end = 0;
        let stub_prefix_end = stubs
            .iter()
            .map(|(_, b)| {
                end = end.max(*b);
                end
            })
            .collect();
        Ok(Self {
            ranges,
            prefix_end,
            stubs,
            stub_prefix_end,
        })
    }
    fn owner(&self, address: u64) -> Option<usize> {
        let mut i = self.ranges.partition_point(|r| r.start <= address);
        let mut owner = None;
        // Prefix maxima also handle image aliases/overlapping marker ranges;
        // retain cache-table order, matching ordinary address lookup.
        while i != 0 && self.prefix_end[i - 1] > address {
            i -= 1;
            let r = &self.ranges[i];
            if address < r.end {
                owner = Some(owner.map_or(r.image, |old: usize| old.min(r.image)));
            }
        }
        owner
    }
    fn is_stub(&self, address: u64) -> bool {
        let end = self.stubs.partition_point(|(a, _)| *a <= address);
        end != 0 && self.stub_prefix_end[end - 1] > address
    }
}

fn resolve_target(
    cache: &DyldContext,
    ownership: &Ownership,
    start: u64,
) -> Result<Option<(usize, u64)>> {
    let mut address = start;
    let mut seen = HashSet::new();
    for _ in 0..64 {
        if !seen.insert(address) {
            return Ok(None);
        }
        if let Some(index) = ownership.owner(address) {
            if is_runtime_image(&cache.images[index].path) {
                return Ok(Some((index, address)));
            }
            // An ordinary function in another image is not a trampoline just
            // because its first instruction branches into a runtime library.
            if !ownership.is_stub(address) {
                return Ok(None);
            }
            let Some(mapping) = cache
                .mapping_for_addr(address)
                .filter(|m| m.is_executable())
            else {
                return Ok(None);
            };
            let size = (mapping.size - (address - mapping.address)).min(16) as usize;
            let Some(stub) = super::decode_cache_stub(cache.data_at_addr(address, size)?, address)
            else {
                return Ok(None);
            };
            address = if stub.indirect {
                cache.pointer_at(stub.target)?
            } else {
                stub.target
            };
        } else if let Some((target, _)) = cache.cache_stub_target(address)? {
            address = target;
        } else {
            return Ok(None);
        }
    }
    Ok(None)
}

fn pointer_section(section: &Section64) -> bool {
    matches!(
        section.flags & SECTION_TYPE,
        S_NON_LAZY_SYMBOL_POINTERS
            | S_LAZY_SYMBOL_POINTERS
            | S_LAZY_DYLIB_SYMBOL_POINTERS
            | S_THREAD_LOCAL_VARIABLE_POINTERS
    ) || matches!(
        section.name(),
        "__got" | "__auth_got" | "__la_symbol_ptr" | "__nl_symbol_ptr"
    )
}

/// Infer runtime additions from the primary and explicitly selected images.
/// Scans ARM64 B/BL instructions (excluding LC_DATA_IN_CODE spans), and declared
/// pointer sections on all supported 64-bit architectures. Follows recognized
/// stubs for at most 64 hops. Newly inferred images are not scanned recursively.
/// Computed/register-only targets without static pointer evidence remain unknown.
pub fn referenced_runtime_images(
    cache: &DyldContext,
    roots: &[String],
) -> Result<Vec<RuntimeImageReference>> {
    let mut root_indexes = HashSet::new();
    for root in roots {
        root_indexes.insert(cache.resolve_image(root)?.index);
    }
    let ownership = Ownership::new(cache)?;
    let mut results = BTreeMap::<String, RuntimeImageReference>::new();
    let mut resolved = HashMap::<u64, Option<(usize, u64)>>::new();
    let mut sites = HashSet::new();
    for root in roots {
        let image = cache.resolve_image(root)?;
        let header = cache.image_header(image.address)?;
        let mut excluded = Vec::new();
        for lc in &header.load_commands {
            if let LoadCommandInfo::LinkeditData { command: c, .. } = lc {
                if c.cmd != LC_DATA_IN_CODE || c.datasize == 0 {
                    continue;
                }
                if c.datasize % 8 != 0 {
                    return Err(invalid("invalid data-in-code size"));
                }
                let link = header
                    .linkedit_segment()
                    .ok_or_else(|| invalid("no LINKEDIT for data-in-code"))?;
                let delta = (c.dataoff as u64)
                    .checked_sub(link.command.fileoff)
                    .filter(|d| {
                        d.checked_add(c.datasize as u64)
                            .is_some_and(|e| e <= link.command.filesize)
                    })
                    .ok_or_else(|| invalid("data-in-code outside LINKEDIT"))?;
                for entry in cache
                    .data_at_addr(link.command.vmaddr + delta, c.datasize as usize)?
                    .chunks_exact(8)
                {
                    let offset = u32::from_le_bytes(entry[..4].try_into().unwrap()) as u64;
                    let length = u16::from_le_bytes(entry[4..6].try_into().unwrap()) as u64;
                    let segment = header
                        .segments()
                        .find(|s| {
                            offset >= s.command.fileoff
                                && offset - s.command.fileoff < s.command.filesize
                        })
                        .ok_or_else(|| invalid("data-in-code outside source segments"))?;
                    let start = segment.command.vmaddr + offset - segment.command.fileoff;
                    let end = start
                        .checked_add(length)
                        .filter(|e| *e <= segment.command.vmaddr + segment.command.filesize)
                        .ok_or_else(|| invalid("data-in-code span outside segment"))?;
                    excluded.push((start, end));
                }
            }
        }
        excluded.sort_unstable();
        let mut record = |source_address, via_address| -> Result<()> {
            if !sites.insert((image.index, source_address)) {
                return Ok(());
            }
            let target = match resolved.get(&via_address) {
                Some(target) => *target,
                None => {
                    let target = resolve_target(cache, &ownership, via_address)?;
                    resolved.insert(via_address, target);
                    target
                }
            };
            let Some((index, target_address)) = target.filter(|(i, _)| !root_indexes.contains(i))
            else {
                return Ok(());
            };
            let path = &cache.images[index].path;
            results
                .entry(path.clone())
                .and_modify(|r| r.reference_count += 1)
                .or_insert_with(|| RuntimeImageReference {
                    image_path: path.clone(),
                    reference_count: 1,
                    source_image: image.path.clone(),
                    source_address,
                    via_address,
                    target_address,
                });
            Ok(())
        };
        for segment in header.segments().filter(|s| s.name() != "__LINKEDIT") {
            for item in &segment.sections {
                let s = &item.section;
                if s.size == 0 {
                    continue;
                }
                let delta = s.addr.checked_sub(segment.command.vmaddr).filter(|d| {
                    d.checked_add(s.size)
                        .is_some_and(|e| e <= segment.command.filesize)
                });
                if pointer_section(s) {
                    if delta.is_none() || s.size % 8 != 0 || s.addr % 8 != 0 {
                        return Err(invalid("invalid pointer section extent/alignment"));
                    }
                    for offset in (0..s.size).step_by(8) {
                        let address = s.addr + offset;
                        record(address, cache.pointer_at(address)?)?;
                    }
                } else if cache.architecture().starts_with("arm64")
                    && s.flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS) != 0
                {
                    if delta.is_none() || s.addr % 4 != 0 || s.size % 4 != 0 {
                        return Err(invalid(
                            "invalid ARM64 instruction section extent/alignment",
                        ));
                    }
                    let mut data = vec![
                        0;
                        usize::try_from(s.size)
                            .map_err(|_| invalid("instruction size overflow"))?
                    ];
                    cache.copy_data_at_addr(s.addr, &mut data)?;
                    for (i, word) in data.chunks_exact(4).enumerate() {
                        let pc = s.addr + i as u64 * 4;
                        if excluded.iter().any(|&(a, b)| pc < b && pc + 4 > a) {
                            continue;
                        }
                        let instruction = u32::from_le_bytes(word.try_into().unwrap());
                        if arm64::is_branch(instruction) {
                            record(pc, arm64::decode_branch(instruction, pc))?;
                        }
                    }
                }
            }
        }
    }
    Ok(results.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn runtime_policy_is_explicit_and_directory_bounded() {
        for p in [
            "/usr/lib/system/libdispatch.dylib",
            "/usr/lib/libobjc.A.dylib",
            "/usr/lib/libc++.1.dylib",
            "/usr/lib/swift/libswiftCore.dylib",
        ] {
            assert!(is_runtime_image(p));
        }
        for p in [
            "/System/Library/Frameworks/Foundation.framework/Foundation",
            "/usr/lib/libsqlite3.dylib",
            "/usr/lib/systematic/libfoo.dylib",
            "/tmp/usr/lib/system/libc.dylib",
        ] {
            assert!(!is_runtime_image(p));
        }
    }
}
