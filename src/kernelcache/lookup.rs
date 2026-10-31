//! Address ownership and nearest-symbol lookup.

use crate::error::Result;
use crate::macho::{N_SECT, N_STAB, N_TYPE, Nlist64, read_nlist};

use super::reader::c_string_at;
use super::{KernelCacheContext, KernelImage};

impl KernelCacheContext {
    /// Returns every image with a segment, other than `__LINKEDIT`, containing `address`.
    ///
    /// Fileset images can share segments, so an address may have several owners.
    /// Image `__LINKEDIT` segments map the collection's shared tables and do not
    /// imply ownership.
    pub fn images_containing(&self, address: u64) -> Vec<&KernelImage> {
        self.images
            .iter()
            .filter(|image| image.segment_containing(address).is_some())
            .collect()
    }

    /// Returns the nearest defined symbol at or before `address` in the same segment.
    ///
    /// The result is `(name, value)`. A nearest symbol is a label, not proof
    /// that `address` lies within that symbol's extent.
    pub fn nearest_symbol(
        &self,
        image: &KernelImage,
        address: u64,
    ) -> Result<Option<(String, u64)>> {
        let Some(segment) = image.segment_containing(address) else {
            return Ok(None);
        };
        let Some(symtab) = image.macho.symtab() else {
            return Ok(None);
        };
        let strings = self.member_bytes(image, symtab.stroff.into(), symtab.strsize.into())?;
        let entry_size = image.macho.nlist_size();
        let symbols = self.member_bytes(
            image,
            symtab.symoff.into(),
            u64::from(symtab.nsyms) * entry_size as u64,
        )?;

        let candidates = segment.command.vmaddr..=address;
        let mut nearest: Option<Nlist64> = None;
        for entry in symbols.chunks_exact(entry_size) {
            let symbol = read_nlist(entry, image.macho.is_64())?;
            let defined_in_section =
                symbol.n_type & N_STAB == 0 && symbol.n_type & N_TYPE == N_SECT;
            if defined_in_section
                && candidates.contains(&symbol.n_value)
                && nearest.is_none_or(|nearest| symbol.n_value > nearest.n_value)
            {
                nearest = Some(symbol);
            }
        }
        nearest
            .map(|symbol| {
                let name = c_string_at(strings, symbol.n_strx)?;
                Ok((String::from_utf8_lossy(name).into_owned(), symbol.n_value))
            })
            .transpose()
    }
}
