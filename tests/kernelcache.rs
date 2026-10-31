//! Kernelcache parsing, extraction, and CLI tests on independently constructed fixtures.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use dylex::macho::{
    CPU_TYPE_ARM, CPU_TYPE_ARM64, CPU_TYPE_X86_64, LC_CODE_SIGNATURE, LC_DYLD_CHAINED_FIXUPS,
    LC_FILESET_ENTRY, LC_FUNCTION_STARTS, LC_SEGMENT, LC_SEGMENT_64, LC_SYMTAB, LC_UUID,
    LoadCommandInfo, MH_EXECUTE, MH_FILESET, MH_KEXT_BUNDLE, MH_MAGIC, MH_MAGIC_64, N_EXT, N_SECT,
};
use dylex::{KernelCacheContext, MachOContext, StringQuery};

// =============================================================================
// Fixture Layout
// =============================================================================

/// Unslid address of the collection header.
const BASE: u64 = 0xffff_fe00_0700_4000;

/// Fileset fixture: an outer header, two images, and shared DATA and LINKEDIT.
const FILESET_SIZE: usize = 0x6000;
const KERNEL: usize = 0x1000;
const DRIVER: usize = 0x2000;
const DATA: usize = 0x3000;
const LINKEDIT: usize = 0x5000;
const SYMBOLS: usize = 0x5000;
const STRINGS: usize = 0x5400;
const FUNCTION_STARTS: usize = 0x5500;
const SIGNATURE: usize = 0x5600;
const FIXUPS: usize = 0x5800;
/// `dyld_chained_starts_in_segment` for DATA, inside the fixups payload.
const DATA_STARTS: usize = FIXUPS + 40;

/// Offset of `_sample` in the string table.
const SAMPLE_NAME: u32 = 17;
/// Marker written into each image's `__TEXT`.
const TEXT_MARKER: usize = 0x300;

/// Load command offsets within the outer header.
const MACH_HEADER_64_SIZE: usize = 32;
const SEGMENT_64_SIZE: usize = 72;
/// The DATA segment is the second command in the outer header and in each image.
const DATA_SEGMENT_COMMAND: usize = MACH_HEADER_64_SIZE + SEGMENT_64_SIZE;
const FIXUPS_COMMAND: usize = DATA_SEGMENT_COMMAND + SEGMENT_64_SIZE;
const KERNEL_ENTRY_COMMAND: usize = FIXUPS_COMMAND + 16;

const CPU_SUBTYPE_ARM64E: u32 = 2;
const CPU_SUBTYPE_ARM_V7: u32 = 9;

/// Little-endian writes into fixture buffers.
trait PutLe {
    fn put(&mut self, offset: usize, bytes: &[u8]);

    fn put_u16(&mut self, offset: usize, value: u16) {
        self.put(offset, &value.to_le_bytes());
    }

    fn put_u32(&mut self, offset: usize, value: u32) {
        self.put(offset, &value.to_le_bytes());
    }

    fn put_u64(&mut self, offset: usize, value: u64) {
        self.put(offset, &value.to_le_bytes());
    }

    /// Writes a pointer-sized field: 8 bytes for 64-bit Mach-O, 4 otherwise.
    fn put_word(&mut self, offset: usize, value: u64, is_64: bool) {
        if is_64 {
            self.put_u64(offset, value);
        } else {
            self.put_u32(offset, value as u32);
        }
    }
}

impl PutLe for [u8] {
    fn put(&mut self, offset: usize, bytes: &[u8]) {
        self[offset..offset + bytes.len()].copy_from_slice(bytes);
    }
}

fn u32_at(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}

// =============================================================================
// Fixture Builders
// =============================================================================

/// An `LC_SEGMENT(_64)` with `size` bytes of file and VM data and an optional `__data` section.
fn segment(
    name: &str,
    vmaddr: u64,
    fileoff: u64,
    size: u64,
    with_section: bool,
    is_64: bool,
) -> Vec<u8> {
    let (word, command_size, section_size) = if is_64 { (8, 72, 80) } else { (4, 56, 68) };
    let mut command = vec![0; command_size + if with_section { section_size } else { 0 }];
    let cmdsize = command.len() as u32;
    command.put_u32(0, if is_64 { LC_SEGMENT_64 } else { LC_SEGMENT });
    command.put_u32(4, cmdsize);
    command.put(8, name.as_bytes());
    for (index, value) in [vmaddr, size, fileoff, size].into_iter().enumerate() {
        command.put_word(24 + index * word, value, is_64);
    }
    let protections = 24 + 4 * word;
    command.put_u32(protections, 7); // maxprot: rwx
    command.put_u32(protections + 4, 3); // initprot: rw-
    command.put_u32(protections + 8, u32::from(with_section));
    if with_section {
        let section = command_size;
        command.put(section, b"__data");
        command.put(section + 16, name.as_bytes());
        command.put_word(section + 32, vmaddr, is_64);
        command.put_word(section + 32 + word, size, is_64);
        command.put_u32(section + 32 + 2 * word, fileoff as u32);
    }
    command
}

fn mach_header(filetype: u32, commands: &[Vec<u8>], is_64: bool) -> Vec<u8> {
    let mut header = vec![0; if is_64 { 32 } else { 28 }];
    let (magic, cputype, cpusubtype) = if is_64 {
        (MH_MAGIC_64, CPU_TYPE_ARM64, CPU_SUBTYPE_ARM64E)
    } else {
        (MH_MAGIC, CPU_TYPE_ARM, CPU_SUBTYPE_ARM_V7)
    };
    header.put_u32(0, magic);
    header.put_u32(4, cputype);
    header.put_u32(8, cpusubtype);
    header.put_u32(12, filetype);
    header.put_u32(16, commands.len() as u32);
    header.put_u32(20, commands.iter().map(Vec::len).sum::<usize>() as u32);
    header.extend(commands.concat());
    header
}

fn fileset_entry(id: &str, fileoff: usize) -> Vec<u8> {
    let mut command = vec![0; (32 + id.len() + 8) & !7];
    let cmdsize = command.len() as u32;
    command.put_u32(0, LC_FILESET_ENTRY);
    command.put_u32(4, cmdsize);
    command.put_u64(8, BASE + fileoff as u64);
    command.put_u64(16, fileoff as u64);
    command.put_u32(24, 32); // entry_id offset
    command.put(32, id.as_bytes());
    command
}

fn linkedit_data(cmd: u32, dataoff: usize, datasize: u32) -> Vec<u8> {
    let mut command = vec![0; 16];
    command.put_u32(0, cmd);
    command.put_u32(4, 16);
    command.put_u32(8, dataoff as u32);
    command.put_u32(12, datasize);
    command
}

fn symtab(symoff: usize, nsyms: u32, stroff: usize, strsize: u32) -> Vec<u8> {
    let mut command = vec![0; 24];
    command.put_u32(0, LC_SYMTAB);
    command.put_u32(4, 24);
    command.put_u32(8, symoff as u32);
    command.put_u32(12, nsyms);
    command.put_u32(16, stroff as u32);
    command.put_u32(20, strsize);
    command
}

/// An arm64e fileset with `com.apple.kernel` and `com.test.driver`.
///
/// Both images map the shared DATA segment, which holds two chained pointers
/// and the string `HelloKernel`, and the shared LINKEDIT, which holds one
/// `_sample` symbol, function starts, and a code signature.
fn fileset() -> Vec<u8> {
    let mut cache = vec![0; FILESET_SIZE];
    let outer = mach_header(
        MH_FILESET,
        &[
            segment("__TEXT", BASE, 0, 0x1000, false, true),
            segment(
                "__DATA",
                BASE + DATA as u64,
                DATA as u64,
                0x1000,
                false,
                true,
            ),
            linkedit_data(LC_DYLD_CHAINED_FIXUPS, FIXUPS, 64),
            fileset_entry("com.apple.kernel", KERNEL),
            fileset_entry("com.test.driver", DRIVER),
        ],
        true,
    );
    cache.put(0, &outer);

    for (offset, filetype) in [(KERNEL, MH_EXECUTE), (DRIVER, MH_KEXT_BUNDLE)] {
        let image = mach_header(
            filetype,
            &[
                segment(
                    "__TEXT",
                    BASE + offset as u64,
                    offset as u64,
                    0x400,
                    false,
                    true,
                ),
                segment(
                    "__DATA",
                    BASE + DATA as u64,
                    DATA as u64,
                    0x1000,
                    true,
                    true,
                ),
                segment(
                    "__LINKEDIT",
                    BASE + LINKEDIT as u64,
                    LINKEDIT as u64,
                    0x1000,
                    false,
                    true,
                ),
                symtab(SYMBOLS, 1, STRINGS, 0x40),
                linkedit_data(LC_FUNCTION_STARTS, FUNCTION_STARTS, 3),
                linkedit_data(LC_CODE_SIGNATURE, SIGNATURE, 8),
            ],
            true,
        );
        cache.put(offset, &image);
        cache.put(offset + TEXT_MARKER, b"CODE123");
    }

    // `_sample`: an external symbol in section 2 (__DATA,__data).
    cache.put_u32(SYMBOLS, SAMPLE_NAME);
    cache[SYMBOLS + 4] = N_SECT | N_EXT;
    cache[SYMBOLS + 5] = 2;
    cache.put_u64(SYMBOLS + 8, BASE + DATA as u64);
    cache.put(STRINGS + SAMPLE_NAME as usize, b"_sample\0");
    cache.put(FUNCTION_STARTS, &[0x80, 0x06, 0]);
    cache.put(DATA + 0x10, b"HelloKernel");

    // An authenticated rebase whose next pointer is two 4-byte strides on, then the chain end.
    cache.put_u64(DATA, (1 << 63) | (2 << 51) | 0x1234);
    cache.put_u64(DATA + 8, 0x2345);

    // dyld_chained_fixups_header, then starts_in_image with two segments
    // (DATA's starts at +12), then starts_in_segment for DATA.
    cache.put_u32(FIXUPS + 4, 28);
    cache.put_u32(FIXUPS + 28, 2);
    cache.put_u32(FIXUPS + 36, 12);
    cache.put_u32(DATA_STARTS, 24);
    cache.put_u16(DATA_STARTS + 4, 4096);
    cache.put_u16(DATA_STARTS + 6, 8); // DYLD_CHAINED_PTR_64_KERNEL_CACHE
    cache.put_u64(DATA_STARTS + 8, DATA as u64);
    cache.put_u16(DATA_STARTS + 20, 1);
    cache
}

/// A legacy prelinked kernel with one kext and one codeless record.
///
/// The kext's load address is an XML `IDREF` to its source address.
fn prelinked(is_64: bool) -> Vec<u8> {
    let base = if is_64 { BASE } else { 0x8000_0000 };
    let plist = format!(
        r#"<plist version="1.0"><dict><key>_PrelinkInfoDictionary</key><array>
        <dict><key>CFBundleIdentifier</key><string>com.test.legacy</string>
        <key>_PrelinkExecutableSourceAddr</key><integer ID="1" size="64">0x{:x}</integer>
        <key>_PrelinkExecutableLoadAddr</key><integer IDREF="1"/>
        <key>_PrelinkExecutableSize</key><integer>1024</integer></dict>
        <dict><key>CFBundleIdentifier</key><string>com.test.codeless</string></dict>
        </array></dict></plist>"#,
        base + 0x1000
    );
    let mut cache = vec![0; 0x3000];
    let kernel = mach_header(
        MH_EXECUTE,
        &[
            segment("__TEXT", base, 0, 0x1000, false, is_64),
            segment(
                "__PRELINK_TEXT",
                base + 0x1000,
                0x1000,
                0x1000,
                false,
                is_64,
            ),
            segment(
                "__PRELINK_INFO",
                base + 0x2000,
                0x2000,
                plist.len() as u64,
                false,
                is_64,
            ),
        ],
        is_64,
    );
    cache.put(0, &kernel);
    let kext = mach_header(
        MH_KEXT_BUNDLE,
        &[segment("__TEXT", base + 0x1000, 0, 0x400, false, is_64)],
        is_64,
    );
    cache.put(0x1000, &kext);
    cache.put(0x1000 + TEXT_MARKER, b"LEGACY!");
    cache.put(0x2000, plist.as_bytes());
    cache
}

/// A DER element with a four-byte long-form length.
fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut element = vec![tag, 0x84];
    element.extend_from_slice(&(body.len() as u32).to_be_bytes());
    element.extend_from_slice(body);
    element
}

fn im4p(payload: &[u8]) -> Vec<u8> {
    let body = [
        der(0x16, b"IM4P"),
        der(0x16, b"krnl"),
        der(0x16, b"test"),
        der(0x04, payload),
    ]
    .concat();
    der(0x30, &body)
}

fn img4(payload: &[u8]) -> Vec<u8> {
    der(0x30, &[der(0x16, b"IMG4"), im4p(payload)].concat())
}

fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for &byte in data {
        a = (a + u32::from(byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    (b << 16) | a
}

/// A complzss stream of literal-only LZSS tokens.
fn complzss(raw: &[u8]) -> Vec<u8> {
    let mut encoded = vec![0; 0x180];
    encoded[..8].copy_from_slice(b"complzss");
    encoded[8..12].copy_from_slice(&adler32(raw).to_be_bytes());
    encoded[12..16].copy_from_slice(&(raw.len() as u32).to_be_bytes());
    for chunk in raw.chunks(8) {
        encoded.push(0xff); // eight literals
        encoded.extend_from_slice(chunk);
    }
    let compressed_size = (encoded.len() - 0x180) as u32;
    encoded[16..20].copy_from_slice(&compressed_size.to_be_bytes());
    encoded
}

/// Appends an `LC_UUID` to the Mach-O header at `header`.
fn append_uuid(cache: &mut [u8], header: usize, uuid: [u8; 16]) {
    let ncmds = u32_at(cache, header + 16);
    let sizeofcmds = u32_at(cache, header + 20);
    let command = header + MACH_HEADER_64_SIZE + sizeofcmds as usize;
    cache.put_u32(command, LC_UUID);
    cache.put_u32(command + 4, 24);
    cache.put(command + 8, &uuid);
    cache.put_u32(header + 16, ncmds + 1);
    cache.put_u32(header + 20, sizeofcmds + 24);
}

fn data_fileoff(output: &[u8]) -> usize {
    let parsed = MachOContext::new(output, 0).unwrap();
    parsed.segment("__DATA").unwrap().command.fileoff as usize
}

// =============================================================================
// Parsing, Lookup, and Search
// =============================================================================

#[test]
fn fileset_images_are_resolved_owned_and_symbolized() {
    let cache = KernelCacheContext::from_bytes(&fileset()).unwrap();
    assert_eq!(cache.images.len(), 2);
    assert_eq!(cache.architecture(), "arm64e");
    assert!(cache.resolve_image("com.").is_err(), "ambiguous query");
    assert!(cache.resolve_image("missing").is_err());

    let address = BASE + DATA as u64 + 0x10;
    assert_eq!(cache.images_containing(address).len(), 2, "shared DATA");
    let driver = cache.resolve_image("driver").unwrap();
    assert_eq!(
        cache.nearest_symbol(driver, address).unwrap(),
        Some(("_sample".into(), BASE + DATA as u64))
    );
}

#[test]
fn string_search_reports_each_image_sharing_a_segment() {
    let cache = KernelCacheContext::from_bytes(&fileset()).unwrap();
    let query = |needle: &[u8], ignore_case, filter: Option<&str>| StringQuery {
        needle: needle.to_vec(),
        ignore_case,
        image_filter: filter.map(str::to_owned),
    };

    let hits = cache
        .search_strings(&query(b"hellokernel", true, None))
        .unwrap();
    assert_eq!(hits.len(), 2);
    let hit = &hits[0];
    assert_eq!(hit.image_path, "com.apple.kernel");
    assert_eq!(hit.segment, "__DATA");
    assert_eq!(hit.section.as_deref(), Some("__data"));
    assert_eq!(hit.address, BASE + DATA as u64 + 0x10);
    assert_eq!(hit.text, "HelloKernel");

    let filtered = cache
        .search_strings(&query(b"HelloKernel", false, Some("driver")))
        .unwrap();
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].image_path, "com.test.driver");
    assert!(cache.search_strings(&query(b"", false, None)).is_err());
}

#[test]
fn collection_identity_uses_exact_images_and_keeps_uuid_roles_distinct() {
    let mut raw = fileset();
    append_uuid(&mut raw, 0, [1; 16]);
    append_uuid(&mut raw, KERNEL, [2; 16]);
    append_uuid(&mut raw, DRIVER, [3; 16]);
    let cache = KernelCacheContext::from_bytes(&raw).unwrap();

    let identity = cache.identity(Some("com.test.driver")).unwrap();
    assert_eq!(identity.collection_uuid.unwrap().0, [1; 16]);
    assert_eq!(identity.kernel_uuid.0, [2; 16]);
    assert_eq!(identity.target_uuid.unwrap().0, [3; 16]);
    let substring = cache.identity(Some("driver")).unwrap();
    assert!(substring.target_uuid.is_none(), "targets match exactly");

    append_uuid(&mut raw, KERNEL, [4; 16]);
    let cache = KernelCacheContext::from_bytes(&raw).unwrap();
    assert!(cache.identity(None).is_err(), "two kernel LC_UUIDs");
}

// =============================================================================
// Extraction
// =============================================================================

#[test]
fn fileset_extraction_rewrites_pointers_symbols_and_linkedit() {
    let cache = KernelCacheContext::from_bytes(&fileset()).unwrap();
    let output = cache.extract("driver").unwrap();
    let parsed = MachOContext::new(&output, 0).unwrap();
    assert_eq!(parsed.header.filetype, MH_KEXT_BUNDLE);
    assert_eq!(&output[TEXT_MARKER..TEXT_MARKER + 7], b"CODE123");

    let data = parsed.segment("__DATA").unwrap().command;
    assert_eq!(data.vmaddr, BASE + DATA as u64);
    assert_eq!(u64_at(&output, data.fileoff as usize), BASE + 0x1234);
    assert_eq!(u64_at(&output, data.fileoff as usize + 8), BASE + 0x2345);

    for command in &parsed.load_commands {
        match command {
            LoadCommandInfo::Symtab { command, .. } => {
                assert_eq!(command.nsyms, 1);
                assert!(command.strsize < 0x40, "string table is compacted");
                let symbol = command.symoff as usize;
                let name = command.stroff as usize + u32_at(&output, symbol) as usize;
                assert_eq!(&output[name..name + 8], b"_sample\0");
                assert_eq!(u64_at(&output, symbol + 8), BASE + DATA as u64);
            }
            LoadCommandInfo::LinkeditData { command, .. } => {
                assert_ne!(command.cmd, LC_CODE_SIGNATURE);
                assert_ne!(command.cmd, LC_DYLD_CHAINED_FIXUPS);
                if command.cmd == LC_FUNCTION_STARTS {
                    let start = command.dataoff as usize;
                    assert_eq!(&output[start..start + 3], &[0x80, 0x06, 0]);
                }
            }
            _ => {}
        }
    }
    assert!(output.len() < 0x1500, "only the image's own data is copied");
}

#[test]
fn prelinked_arm32_and_arm64_kexts_use_image_relative_offsets() {
    for is_64 in [false, true] {
        let cache = KernelCacheContext::from_bytes(&prelinked(is_64)).unwrap();
        assert_eq!(cache.images.len(), 2, "kernel and one executable kext");
        let output = cache.extract("legacy").unwrap();
        assert_eq!(&output[TEXT_MARKER..TEXT_MARKER + 7], b"LEGACY!");
        let parsed = MachOContext::new(&output, 0).unwrap();
        assert_eq!(parsed.is_64(), is_64);
        assert_eq!(parsed.segment("__TEXT").unwrap().command.fileoff, 0);
    }
}

#[test]
fn multi_start_pages_and_page_straddling_pointers_are_decoded() {
    let mut raw = fileset();
    // Grow DATA to two pages in the outer header and both images.
    for header in [0, KERNEL, DRIVER] {
        let command = header + DATA_SEGMENT_COMMAND;
        raw.put_u64(command + 32, 0x2000); // vmsize
        raw.put_u64(command + 48, 0x2000); // filesize
    }
    // Page 0 has two starts, at 0 and 0xffc (a pointer in its last four bytes);
    // page 1 has none.
    raw.put_u32(DATA_STARTS, 30);
    raw.put_u16(DATA_STARTS + 20, 2);
    raw.put_u16(DATA_STARTS + 22, 0x8002);
    raw.put_u16(DATA_STARTS + 24, 0xffff);
    raw.put_u16(DATA_STARTS + 26, 0);
    raw.put_u16(DATA_STARTS + 28, 0x8ffc);
    raw.put_u32(FIXUPS_COMMAND + 12, 72); // datasize covers the overflow entries
    raw.put_u64(DATA + 0xffc, 0x3456);

    let cache = KernelCacheContext::from_bytes(&raw).unwrap();
    let output = cache.extract("driver").unwrap();
    assert_eq!(
        u64_at(&output, data_fileoff(&output) + 0xffc),
        BASE + 0x3456
    );
}

#[test]
fn arm64e_and_x86_64_kernel_pointer_formats_use_their_own_strides() {
    const PTR_ARM64E_KERNEL: u16 = 7;
    const PTR_X86_64_KERNEL_CACHE: u16 = 11;

    for format in [PTR_ARM64E_KERNEL, PTR_X86_64_KERNEL_CACHE] {
        let mut raw = fileset();
        raw.put_u16(DATA_STARTS + 6, format);
        let stride = if format == PTR_X86_64_KERNEL_CACHE {
            1
        } else {
            4
        };
        raw.put_u64(DATA, ((8 / stride) << 51) | 0x1234);
        if format == PTR_X86_64_KERNEL_CACHE {
            for header in [0, KERNEL, DRIVER] {
                raw.put_u32(header + 4, CPU_TYPE_X86_64);
            }
        }
        let output = KernelCacheContext::from_bytes(&raw)
            .unwrap()
            .extract("driver")
            .unwrap();
        let data = data_fileoff(&output);
        assert_eq!(u64_at(&output, data), BASE + 0x1234);
        assert_eq!(u64_at(&output, data + 8), BASE + 0x2345);

        if format == PTR_ARM64E_KERNEL {
            raw.put_u64(DATA, 1 << 62); // an unresolved bind
            let cache = KernelCacheContext::from_bytes(&raw).unwrap();
            assert!(cache.extract("driver").is_err());
        }
    }
}

// =============================================================================
// Containers and Compression
// =============================================================================

#[test]
fn img4_and_im4p_wrappers_are_unwrapped_structurally() {
    let raw = fileset();
    for wrapped in [im4p(&raw), img4(&raw)] {
        let cache = KernelCacheContext::from_bytes(&wrapped).unwrap();
        assert_eq!(cache.images.len(), 2);
    }
    let wrapped = img4(&raw);
    for len in [0, 1, 2, 4, 10, 29, wrapped.len() - 1] {
        assert!(
            KernelCacheContext::from_bytes(&wrapped[..len]).is_err(),
            "truncated to {len}"
        );
    }
}

#[test]
fn lzfse_payloads_decode_to_identical_extractions() {
    let raw = fileset();
    let mut encoded = vec![0; raw.len() + 4096];
    let len = lzfse::encode_buffer(&raw, &mut encoded).unwrap();
    encoded.truncate(len);

    let from_lzfse = KernelCacheContext::from_bytes(&im4p(&encoded)).unwrap();
    let from_raw = KernelCacheContext::from_bytes(&raw).unwrap();
    assert_eq!(
        from_lzfse.extract("driver").unwrap(),
        from_raw.extract("driver").unwrap()
    );

    encoded.pop();
    assert!(
        KernelCacheContext::from_bytes(&encoded).is_err(),
        "missing end-of-stream"
    );
}

#[test]
fn complzss_rejects_checksum_mismatches_and_truncated_tokens() {
    let mut encoded = complzss(&fileset());
    assert_eq!(
        KernelCacheContext::from_bytes(&encoded)
            .unwrap()
            .images
            .len(),
        2
    );

    encoded[8] ^= 1;
    assert!(
        KernelCacheContext::from_bytes(&encoded).is_err(),
        "checksum mismatch"
    );
    encoded[8] ^= 1;
    encoded.pop();
    assert!(
        KernelCacheContext::from_bytes(&encoded).is_err(),
        "truncated token"
    );
}

// =============================================================================
// Malformed Inputs
// =============================================================================

#[test]
fn corrupt_tables_and_chains_fail_without_panicking() {
    let raw = fileset();
    let corruptions = [
        (DATA_STARTS + 8, u64::MAX), // segment offset disagrees with the segment
        (DATA, 1 << 30),             // pointer into another kernel collection
        (DATA, 4095 << 51),          // chain leaves the page
    ];
    for (offset, value) in corruptions {
        let mut corrupt = raw.clone();
        corrupt.put_u64(offset, value);
        let result =
            KernelCacheContext::from_bytes(&corrupt).and_then(|cache| cache.extract("driver"));
        assert!(result.is_err(), "corruption at {offset:#x}");
    }

    let mut bad_symbol = raw.clone();
    bad_symbol.put_u32(SYMBOLS, u32::MAX);
    let cache = KernelCacheContext::from_bytes(&bad_symbol).unwrap();
    assert!(cache.extract("driver").is_err(), "symbol name out of range");

    for len in (0..raw.len()).step_by(137) {
        let result = std::panic::catch_unwind(|| {
            if let Ok(cache) = KernelCacheContext::from_bytes(&raw[..len]) {
                let _ = cache.extract("driver");
            }
        });
        assert!(result.is_ok(), "panic at truncation {len}");
    }
}

#[test]
fn fileset_entry_ids_and_unknown_load_commands_are_rejected() {
    let raw = fileset();

    let mut bad_id_offset = raw.clone();
    bad_id_offset.put_u32(KERNEL_ENTRY_COMMAND + 24, 4);
    assert!(KernelCacheContext::from_bytes(&bad_id_offset).is_err());

    let mut duplicate = raw.clone();
    let id = KERNEL_ENTRY_COMMAND + 32;
    duplicate[id..id + 24].fill(0);
    duplicate.put(id, b"com.test.driver");
    assert!(KernelCacheContext::from_bytes(&duplicate).is_err());

    let cache = KernelCacheContext::from_bytes(&raw).unwrap();
    let driver = cache.resolve_image("driver").unwrap();
    let last_command = driver.macho.load_commands.last().unwrap().offset();
    let mut unknown = raw.clone();
    unknown.put_u32(DRIVER + last_command, 0x1234);
    let cache = KernelCacheContext::from_bytes(&unknown).unwrap();
    assert!(cache.extract("driver").is_err());
}

// =============================================================================
// Command Line
// =============================================================================

fn dylex(args: &[&str], kernelcache: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_dylex"))
        .args(args)
        .arg(kernelcache)
        .output()
        .unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn cli_inspects_lists_searches_and_looks_up_addresses() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("kernelcache");
    fs::write(&input, fileset()).unwrap();

    let info = dylex(&["kernel", "info"], &input);
    assert!(info.status.success(), "{}", stderr(&info));
    let info = stdout(&info);
    assert!(info.contains("Format:       fileset (MH_FILESET)"));
    assert!(info.contains("Images:       2"));

    let list = stdout(&dylex(&["kernel", "list", "-A"], &input));
    assert_eq!(
        list.lines().collect::<Vec<_>>(),
        [
            "0xfffffe0007005000  com.apple.kernel",
            "0xfffffe0007006000  com.test.driver"
        ]
    );

    let strings = dylex(&["kc", "strings", "HelloKernel", "-f", "driver"], &input);
    assert!(strings.status.success(), "{}", stderr(&strings));
    assert_eq!(
        stdout(&strings).trim_end(),
        "arm64e  com.test.driver  __DATA,__data  0xfffffe0007007010  HelloKernel"
    );
    assert!(stderr(&strings).contains("1 matches in 1 images"));

    let lookup = stdout(&dylex(&["kernel", "lookup", "fffffe0007007010"], &input));
    assert!(lookup.contains("  Image: com.test.driver"));
    assert!(lookup.contains("  Section: __data"));
    assert!(lookup.contains("  Nearest symbol: _sample + 0x10"));
    assert!(lookup.contains("  Extract: dylex kernel extract -i 'com.test.driver' "));
}

#[test]
fn cli_extracts_selected_images_and_never_overwrites_the_input() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("kernelcache");
    let raw = fileset();
    fs::write(&input, &raw).unwrap();

    let single = dir.path().join("driver.macho");
    let result = dylex(
        &[
            "kernel",
            "extract",
            "-i",
            "driver",
            "-o",
            single.to_str().unwrap(),
        ],
        &input,
    );
    assert!(result.status.success(), "{}", stderr(&result));
    assert!(MachOContext::new(&fs::read(&single).unwrap(), 0).is_ok());

    let all = dir.path().join("all");
    let result = dylex(
        &["kernel", "extract", "--all", "-o", all.to_str().unwrap()],
        &input,
    );
    assert!(result.status.success(), "{}", stderr(&result));
    assert!(all.join("com.apple.kernel").is_file());
    assert!(all.join("com.test.driver").is_file());

    let found = dir.path().join("found");
    let result = dylex(
        &[
            "kernel",
            "extract",
            "--search",
            "hellokernel",
            "--ignore-case",
            "-o",
            found.to_str().unwrap(),
        ],
        &input,
    );
    assert!(stderr(&result).contains("2 images contain \"hellokernel\""));

    let ambiguous = dylex(&["kernel", "extract", "-i", "com."], &input);
    assert!(!ambiguous.status.success());
    assert!(stderr(&ambiguous).contains("com.apple.kernel"));
    assert!(stderr(&ambiguous).contains("com.test.driver"));

    let overwrite = dylex(
        &[
            "kernel",
            "extract",
            "-i",
            "driver",
            "-o",
            input.to_str().unwrap(),
        ],
        &input,
    );
    assert!(!overwrite.status.success());
    assert!(
        !dylex(&["kernel", "extract"], &input).status.success(),
        "no selection"
    );

    assert_eq!(fs::read(&input).unwrap(), raw);
}

#[test]
fn dyld_commands_point_kernelcaches_to_the_kernel_commands() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("kernelcache");
    fs::write(&input, im4p(&fileset())).unwrap();

    for command in [&["info"][..], &["list"], &["find", "kernel"]] {
        let result = dylex(command, &input);
        assert!(!result.status.success());
        assert!(
            stderr(&result).contains("dylex kernel"),
            "{command:?}: {}",
            stderr(&result)
        );
    }
}

// =============================================================================
// Live Kernelcache
// =============================================================================

#[test]
#[ignore = "requires a local fileset kernelcache; set DYLEX_TEST_KERNELCACHE"]
fn live_kernelcache_extracts_every_image() {
    let path = std::env::var("DYLEX_TEST_KERNELCACHE").unwrap();
    let cache = KernelCacheContext::open(&path).unwrap();
    for image in &cache.images {
        let output = cache.extract_image(image).unwrap();
        let parsed = MachOContext::new(&output, 0).unwrap();
        for segment in parsed.segments() {
            let end = segment.command.fileoff + segment.command.filesize;
            assert!(
                end <= output.len() as u64,
                "{}: {}",
                image.id,
                segment.name()
            );
        }
    }
}
