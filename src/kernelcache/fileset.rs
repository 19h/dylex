//! `MH_FILESET` kernel collections, which describe each image with an `LC_FILESET_ENTRY`.

use crate::error::{Error, Result};
use crate::macho::{LoadCommandInfo, MachOContext};

use super::reader::{slice, to_usize};
use super::{KernelImage, OffsetBase, parse_macho_at};

/// Size of `fileset_entry_command`; the entry ID string follows it.
const FILESET_ENTRY_COMMAND_SIZE: usize = 32;

/// Reads every fileset entry. Image offsets are collection-relative.
pub(super) fn read_images(data: &[u8], collection: &MachOContext) -> Result<Vec<KernelImage>> {
    let mut images = Vec::new();
    for load_command in &collection.load_commands {
        let LoadCommandInfo::FilesetEntry {
            command,
            entry_id,
            offset,
        } = load_command
        else {
            continue;
        };
        validate_entry_id(
            slice(&collection.data, *offset, command.cmdsize as usize)?,
            *offset,
            command.entry_id_offset as usize,
        )?;
        images.push(KernelImage {
            id: entry_id.clone(),
            address: command.vmaddr,
            file_offset: command.fileoff,
            macho: parse_macho_at(data, to_usize(command.fileoff)?)?,
            offset_base: OffsetBase::Collection,
        });
    }
    if images.is_empty() {
        return Err(Error::parse(0, "fileset has no entries"));
    }
    Ok(images)
}

/// Checks that an entry ID is a non-empty, NUL-terminated UTF-8 string inside its command.
fn validate_entry_id(command: &[u8], command_offset: usize, id_offset: usize) -> Result<()> {
    let id = (id_offset >= FILESET_ENTRY_COMMAND_SIZE)
        .then(|| command.get(id_offset..))
        .flatten()
        .and_then(|tail| memchr::memchr(0, tail).map(|len| &tail[..len]))
        .ok_or_else(|| Error::parse(command_offset, "invalid or unterminated fileset entry ID"))?;
    if id.is_empty() || std::str::from_utf8(id).is_err() {
        return Err(Error::parse(command_offset, "invalid fileset entry ID"));
    }
    Ok(())
}
