//! String search over a synthetic cache. No Apple binaries are distributed.
use dylex::{DyldContext, StringQuery, dyld::DyldCacheHeader, macho::*, parse_hex_bytes};
use std::{fs, mem::size_of, sync::Arc};
use tempfile::TempDir;
use zerocopy::IntoBytes;

const BASE: u64 = 0x180000000;
const IDENT: &[u8] = b"com.apple.hid.manager.user-access-device\0";
const DOUBLE: &[u8] = b"user-access-user-access\0";
const HELLO: &[u8] = b"hello\0";

fn u32at(buf: &mut [u8], off: usize, value: u32) {
    buf[off..off + 4].copy_from_slice(&value.to_le_bytes());
}

fn u64at(buf: &mut [u8], off: usize, value: u64) {
    buf[off..off + 8].copy_from_slice(&value.to_le_bytes());
}

fn cname(text: &str) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes[..text.len()].copy_from_slice(text.as_bytes());
    bytes
}

fn section(name: &str, segment: &str, addr: u64, off: u32, size: u64, flags: u32) -> Section64 {
    Section64 {
        sectname: cname(name),
        segname: cname(segment),
        addr,
        size,
        offset: off,
        align: 0,
        reloff: 0,
        nreloc: 0,
        flags,
        reserved1: 0,
        reserved2: 0,
        reserved3: 0,
    }
}

fn segment(
    name: &str,
    vmaddr: u64,
    fileoff: u64,
    filesize: u64,
    vmsize: u64,
    sections: &[Section64],
) -> Vec<u8> {
    let cmd = SegmentCommand64 {
        cmdsize: 72 + sections.len() as u32 * 80,
        segname: cname(name),
        vmaddr,
        vmsize,
        fileoff,
        filesize,
        maxprot: 7,
        initprot: 3,
        nsects: sections.len() as u32,
        ..Default::default()
    };
    let mut bytes = cmd.as_bytes().to_vec();
    for item in sections {
        bytes.extend_from_slice(item.as_bytes());
    }
    bytes
}

fn put_macho(
    buf: &mut [u8],
    file_off: usize,
    segname: &str,
    vmaddr: u64,
    filesize: u64,
    vmsize: u64,
    sections: &[Section64],
) {
    let commands = segment(segname, vmaddr, file_off as u64, filesize, vmsize, sections);
    let header = MachHeader64 {
        magic: MH_MAGIC_64,
        cputype: CPU_TYPE_ARM64,
        cpusubtype: CPU_SUBTYPE_ARM64E,
        filetype: MH_DYLIB,
        ncmds: 1,
        sizeofcmds: commands.len() as u32,
        flags: 0,
        reserved: 0,
    };
    buf[file_off..file_off + 32].copy_from_slice(header.as_bytes());
    let cmd_at = file_off + 32;
    buf[cmd_at..cmd_at + commands.len()].copy_from_slice(&commands);
}

fn add_image(buf: &mut [u8], index: usize, address: u64, path: &str) {
    use std::mem::offset_of;
    u32at(buf, offset_of!(DyldCacheHeader, images_offset), 0x600);
    u32at(
        buf,
        offset_of!(DyldCacheHeader, images_count),
        index as u32 + 1,
    );
    let entry = 0x600 + index * 32;
    let path_at = 0x800 + index * 128;
    u64at(buf, entry, address);
    u32at(buf, entry + 24, path_at as u32);
    buf[path_at..path_at + path.len()].copy_from_slice(path.as_bytes());
}

fn open_fixture() -> (TempDir, Arc<DyldContext>) {
    let len = 0x2200;
    let header_size = size_of::<DyldCacheHeader>();
    assert!(
        header_size + 32 < 0x600,
        "fixture image table overlaps the header"
    );
    let mut buf = vec![0u8; len];
    buf[..16].copy_from_slice(b"dyld_v1  arm64e\0");
    u32at(&mut buf, 16, header_size as u32);
    u32at(&mut buf, 20, 1);
    u64at(&mut buf, header_size, BASE);
    u64at(&mut buf, header_size + 8, len as u64);
    u64at(&mut buf, header_size + 16, 0);
    u32at(&mut buf, header_size + 24, 7);
    u32at(&mut buf, header_size + 28, 5);

    let ident_at = 0x1300usize;
    buf[ident_at..ident_at + IDENT.len()].copy_from_slice(IDENT);
    put_macho(
        &mut buf,
        0x1000,
        "__TEXT",
        BASE + 0x1000,
        0x500,
        0x500,
        &[section(
            "__cstring",
            "__TEXT",
            BASE + ident_at as u64,
            ident_at as u32,
            IDENT.len() as u64,
            S_CSTRING_LITERALS,
        )],
    );

    // filesize stops before the next image. vmsize runs through that image,
    // so a search of virtual size would report its string here.
    let hello_at = 0x16C0usize;
    buf[hello_at..hello_at + HELLO.len()].copy_from_slice(HELLO);
    put_macho(
        &mut buf,
        0x1600,
        "__TEXT",
        BASE + 0x1600,
        0x100,
        0xC00,
        &[section(
            "__cstring",
            "__TEXT",
            BASE + hello_at as u64,
            hello_at as u32,
            HELLO.len() as u64,
            S_CSTRING_LITERALS,
        )],
    );

    let double_at = 0x1900usize;
    buf[double_at..double_at + DOUBLE.len()].copy_from_slice(DOUBLE);
    put_macho(&mut buf, 0x1800, "__DATA", BASE + 0x1800, 0x200, 0x200, &[]);

    add_image(
        &mut buf,
        0,
        BASE + 0x1000,
        "/System/Library/Extensions/IOHIDFamily.kext/IOHIDFamily",
    );
    add_image(&mut buf, 1, BASE + 0x1600, "/usr/lib/libsystem_c.dylib");
    add_image(&mut buf, 2, BASE + 0x1800, "/usr/lib/libhidsupport.dylib");
    add_image(&mut buf, 3, BASE + 0x1C00, "/usr/lib/libbroken.dylib");

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dyld_shared_cache_arm64e");
    fs::write(&path, buf).unwrap();
    let cache = Arc::new(DyldContext::open(&path).unwrap());
    (dir, cache)
}

fn search(
    cache: &DyldContext,
    needle: &[u8],
    filter: Option<&str>,
    ignore_case: bool,
) -> dylex::StringSearchOutcome {
    cache
        .search_strings(
            &StringQuery {
                needle: needle.to_vec(),
                ignore_case,
                image_filter: filter.map(str::to_string),
            },
            || {},
        )
        .unwrap()
}

#[test]
fn searches_file_backed_bytes_of_all_images_or_a_filtered_subset() {
    let (_dir, cache) = open_fixture();
    let ident = search(
        &cache,
        b"com.apple.hid.manager.user-access-device",
        None,
        false,
    );
    assert_eq!(ident.hits.len(), 1);
    assert!(ident.hits[0].image_path.contains("IOHIDFamily"));
    assert_eq!(ident.hits[0].segment, "__TEXT");
    assert_eq!(ident.hits[0].section.as_deref(), Some("__cstring"));
    assert_eq!(ident.hits[0].address, BASE + 0x1300);
    assert_eq!(
        ident.hits[0].text,
        "com.apple.hid.manager.user-access-device"
    );
    assert!(
        ident
            .skipped
            .iter()
            .any(|reason| reason.contains("libbroken"))
    );
    assert!(
        ident
            .hits
            .iter()
            .all(|hit| !hit.image_path.contains("libsystem_c"))
    );

    let filtered = search(
        &cache,
        b"com.apple.hid.manager.user-access-device",
        Some("libsystem_c"),
        false,
    );
    assert!(filtered.hits.is_empty());
    assert!(filtered.skipped.is_empty());

    let folded = search(
        &cache,
        b"COM.APPLE.HID.MANAGER.USER-ACCESS-DEVICE",
        Some("IOHID"),
        true,
    );
    assert_eq!(folded.hits.len(), 1);
    assert_eq!(folded.hits[0].address, BASE + 0x1300);

    let repeated = search(&cache, b"user-access", None, false);
    assert_eq!(repeated.hits.len(), 2);
    let support = repeated
        .hits
        .iter()
        .find(|hit| hit.image_path.contains("libhidsupport"))
        .unwrap();
    assert_eq!(support.segment, "__DATA");
    assert_eq!(support.section, None);
    assert_eq!(support.address, BASE + 0x1900);
    assert_eq!(support.text, "user-access-user-access");

    let hello = search(&cache, b"hello", None, false);
    assert_eq!(hello.hits.len(), 1);
    assert!(hello.hits[0].image_path.contains("libsystem_c"));
    assert_eq!(hello.hits[0].address, BASE + 0x16C0);
    assert_eq!(hello.hits[0].text, "hello");
}

#[test]
fn hex_needle_finds_the_same_text_as_a_literal_string() {
    let (_dir, cache) = open_fixture();
    let hello = parse_hex_bytes("68 65 6c 6c 6f").unwrap();
    assert_eq!(parse_hex_bytes("68656c6c6f").unwrap(), hello);
    let found = search(&cache, &hello, None, false);
    assert_eq!(found.hits.len(), 1);
    assert!(found.hits[0].image_path.contains("libsystem_c"));
    assert_eq!(found.hits[0].address, BASE + 0x16C0);
    assert_eq!(found.hits[0].text, "hello");
}

#[test]
fn images_containing_returns_each_matching_image_once_in_cache_order() {
    let (_dir, cache) = open_fixture();
    let found = cache
        .images_containing(
            &StringQuery {
                needle: b"user-access".to_vec(),
                ignore_case: false,
                image_filter: None,
            },
            || {},
        )
        .unwrap();
    assert_eq!(found.images.len(), 2);
    assert!(found.images[0].path.contains("IOHIDFamily"));
    assert!(found.images[1].path.contains("libhidsupport"));
    assert!(
        found
            .skipped
            .iter()
            .any(|reason| reason.contains("libbroken"))
    );

    let filtered = cache
        .images_containing(
            &StringQuery {
                needle: b"user-access".to_vec(),
                ignore_case: false,
                image_filter: Some("libsystem_c".into()),
            },
            || {},
        )
        .unwrap();
    assert!(filtered.images.is_empty());
    assert!(filtered.skipped.is_empty());
}

#[test]
fn shared_linkedit_is_not_attributed_to_every_image() {
    let len = 0x1400;
    let header_size = size_of::<DyldCacheHeader>();
    let mut buf = vec![0u8; len];
    buf[..16].copy_from_slice(b"dyld_v1  arm64e\0");
    u32at(&mut buf, 16, header_size as u32);
    u32at(&mut buf, 20, 1);
    u64at(&mut buf, header_size, BASE);
    u64at(&mut buf, header_size + 8, len as u64);
    u64at(&mut buf, header_size + 16, 0);
    u32at(&mut buf, header_size + 24, 7);
    u32at(&mut buf, header_size + 28, 5);

    let owned_p = b"owned-by-p\0";
    let owned_q = b"owned-by-q\0";
    let shared = b"only-in-shared-linkedit\0";
    buf[0x10C0..0x10C0 + owned_p.len()].copy_from_slice(owned_p);
    buf[0x11C0..0x11C0 + owned_q.len()].copy_from_slice(owned_q);
    buf[0x1200..0x1200 + shared.len()].copy_from_slice(shared);

    let linkedit = segment("__LINKEDIT", BASE + 0x1200, 0x1200, 0x20, 0x20, &[]);
    put_commands(
        &mut buf,
        0x1000,
        &[
            segment("__TEXT", BASE + 0x1000, 0x1000, 0x100, 0x100, &[]),
            linkedit.clone(),
        ],
    );
    put_commands(
        &mut buf,
        0x1100,
        &[
            segment("__TEXT", BASE + 0x1100, 0x1100, 0x100, 0x100, &[]),
            linkedit,
        ],
    );
    add_image(&mut buf, 0, BASE + 0x1000, "/usr/lib/libp.dylib");
    add_image(&mut buf, 1, BASE + 0x1100, "/usr/lib/libq.dylib");

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("dyld_shared_cache_arm64e");
    fs::write(&path, buf).unwrap();
    let cache = DyldContext::open(&path).unwrap();

    let shared_hits = search(&cache, b"only-in-shared-linkedit", None, false);
    assert!(shared_hits.hits.is_empty(), "{:?}", shared_hits.hits);
    let owned = search(&cache, b"owned-by-p", None, false);
    assert_eq!(owned.hits.len(), 1);
    assert!(owned.hits[0].image_path.ends_with("libp.dylib"));
    let other = search(&cache, b"owned-by-q", None, false);
    assert_eq!(other.hits.len(), 1);
    assert!(other.hits[0].image_path.ends_with("libq.dylib"));
}

fn put_commands(buf: &mut [u8], file_off: usize, commands: &[Vec<u8>]) {
    let sizeofcmds: u32 = commands.iter().map(|command| command.len() as u32).sum();
    let header = MachHeader64 {
        magic: MH_MAGIC_64,
        cputype: CPU_TYPE_ARM64,
        cpusubtype: CPU_SUBTYPE_ARM64E,
        filetype: MH_DYLIB,
        ncmds: commands.len() as u32,
        sizeofcmds,
        flags: 0,
        reserved: 0,
    };
    buf[file_off..file_off + 32].copy_from_slice(header.as_bytes());
    let mut at = file_off + 32;
    for command in commands {
        buf[at..at + command.len()].copy_from_slice(command);
        at += command.len();
    }
}

#[test]
fn empty_search_string_is_rejected() {
    let (_dir, cache) = open_fixture();
    let error = cache
        .search_strings(
            &StringQuery {
                needle: Vec::new(),
                ignore_case: false,
                image_filter: None,
            },
            || {},
        )
        .unwrap_err()
        .to_string();
    assert!(error.contains("empty"));
}
