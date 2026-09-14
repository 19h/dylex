//! Address ownership and bounded traversal of sectionless cache stubs.
use super::*;
use crate::{Error, Result, macho::*};
use zerocopy::FromBytes;

/// Image segment containing an address. Shared LINKEDIT is not image ownership.
#[derive(Debug)]
pub struct AddressOwner<'a> {
    /// Source image.
    pub image: &'a ImageEntry,
    /// Segment name.
    pub segment: String,
    /// Start of segment, in unslid bytes.
    pub base: u64,
    /// Exact or nearest preceding symbol in the same section/segment.
    pub symbol: Option<(String, u64)>,
}

impl DyldContext {
    /// Resolve a full path, exact basename, then a unique substring. Ambiguity
    /// is an error listing all candidate paths; it never selects the first match.
    pub fn resolve_image(&self, query: &str) -> Result<&ImageEntry> {
        if let Some(image) = self.images.iter().find(|i| i.path == query) {
            return Ok(image);
        }
        let exact: Vec<_> = self
            .images
            .iter()
            .filter(|i| i.path.rsplit('/').next() == Some(query))
            .collect();
        let candidates = if exact.is_empty() {
            self.images
                .iter()
                .filter(|i| i.matches_filter(query))
                .collect()
        } else {
            exact
        };
        match candidates.as_slice() {
            [image] => Ok(image),
            [] => Err(Error::ImageNotFound { name: query.into() }),
            _ => Err(Error::Parse {
                offset: 0,
                reason: format!(
                    "ambiguous image {query:?}; use a full path:\n{}",
                    candidates
                        .iter()
                        .map(|i| format!("  {}", i.path))
                        .collect::<Vec<_>>()
                        .join("\n")
                ),
            }),
        }
    }

    /// Finds an address's owner by actual segment extents, including DATA.
    pub fn address_owner(&self, address: u64) -> Result<Option<AddressOwner<'_>>> {
        for image in &self.images {
            let header = self.image_header(image.address)?;
            let Some(segment) = header.segments().find(|s| {
                s.name() != "__LINKEDIT"
                    && address >= s.command.vmaddr
                    && address - s.command.vmaddr < s.command.vmsize
            }) else {
                continue;
            };
            let (start, size) = segment
                .sections
                .iter()
                .find(|s| address >= s.section.addr && address - s.section.addr < s.section.size)
                .map(|s| (s.section.addr, s.section.size))
                .unwrap_or((segment.command.vmaddr, segment.command.vmsize));
            let mut symbol: Option<(String, u64)> = None;
            let mut consider = |name: String, value: u64| {
                if value >= start
                    && value - start < size
                    && value <= address
                    && symbol.as_ref().is_none_or(|(_, old)| value > *old)
                    && !name.is_empty()
                {
                    symbol = Some((name, value));
                }
            };
            let read = |offset: u32, size: u32| -> Result<&[u8]> {
                let link = header.linkedit_segment().ok_or(Error::SegmentNotFound {
                    name: "__LINKEDIT".into(),
                })?;
                let delta = (offset as u64)
                    .checked_sub(link.command.fileoff)
                    .filter(|d| {
                        d.checked_add(size as u64)
                            .is_some_and(|e| e <= link.command.filesize)
                    })
                    .ok_or(Error::Parse {
                        offset: offset as usize,
                        reason: "symbol data outside LINKEDIT".into(),
                    })?;
                self.data_at_addr(link.command.vmaddr + delta, size as usize)
            };
            for lc in &header.load_commands {
                if let LoadCommandInfo::Symtab { command, .. } = lc {
                    let size = command.nsyms.checked_mul(16).ok_or(Error::Parse {
                        offset: command.symoff as usize,
                        reason: "symbol table size overflow".into(),
                    })?;
                    if size == 0 {
                        continue;
                    }
                    let table = read(command.symoff, size)?;
                    let strings = read(command.stroff, command.strsize)?;
                    for entry in table.chunks_exact(16) {
                        let (n, _) = Nlist64::read_from_prefix(entry).unwrap();
                        if n.n_type & N_STAB != 0 || !matches!(n.n_type & N_TYPE, N_SECT | N_ABS) {
                            continue;
                        }
                        let tail = strings.get(n.n_strx as usize..).ok_or(Error::Parse {
                            offset: n.n_strx as usize,
                            reason: "symbol string index outside table".into(),
                        })?;
                        let end = tail.iter().position(|b| *b == 0).ok_or(Error::Parse {
                            offset: n.n_strx as usize,
                            reason: "unterminated symbol name".into(),
                        })?;
                        consider(
                            String::from_utf8_lossy(&tail[..end]).into_owned(),
                            n.n_value,
                        );
                    }
                }
            }
            // Export-only caches can omit their nlist definitions.
            let export = header.load_commands.iter().find_map(|lc| match lc {
                LoadCommandInfo::LinkeditData { command, .. }
                    if command.cmd == LC_DYLD_EXPORTS_TRIE && command.datasize != 0 =>
                {
                    Some((command.dataoff, command.datasize))
                }
                LoadCommandInfo::DyldInfo { command, .. } if command.export_size != 0 => {
                    Some((command.export_off, command.export_size))
                }
                _ => None,
            });
            if let Some((offset, size)) = export {
                for e in ExportTrieParser::new(read(offset, size)?).parse_all()? {
                    if e.is_reexport() {
                        continue;
                    }
                    let value = if e.kind() == EXPORT_SYMBOL_FLAGS_KIND_ABSOLUTE {
                        Some(e.address)
                    } else {
                        image.address.checked_add(e.address)
                    };
                    if let Some(value) = value {
                        consider(e.name, value);
                    }
                }
            }
            return Ok(Some(AddressOwner {
                image,
                segment: segment.name().into(),
                base: segment.command.vmaddr,
                symbol,
            }));
        }
        Ok(None)
    }

    /// Decode an ARM64 cache-owned trampoline. Ordinary image code is not
    /// followed. The caller bounds traversal and detects cycles.
    pub fn cache_stub_target(&self, address: u64) -> Result<Option<(u64, Option<String>)>> {
        if !self.architecture().starts_with("arm64") {
            return Ok(None);
        }
        let Some(mapping) = self.mapping_for_addr(address).filter(|m| m.is_executable()) else {
            return Ok(None);
        };
        let size = (mapping.size - (address - mapping.address)).min(16) as usize;
        let Some(stub) =
            crate::converter::decode_cache_stub(self.data_at_addr(address, size)?, address)
        else {
            return Ok(None);
        };
        if stub.size == 4 && mapping.flags & MappingFlags::TEXT_STUBS.bits() == 0 {
            return Ok(None);
        }
        let target = if stub.indirect {
            self.pointer_at(stub.target)?
        } else {
            stub.target
        };
        let selector = stub
            .selector
            .map(|addr| {
                self.cstring_at(addr)
                    .map(|s| String::from_utf8_lossy(&s[..s.len() - 1]).into_owned())
            })
            .transpose()?;
        Ok(Some((target, selector)))
    }
}
