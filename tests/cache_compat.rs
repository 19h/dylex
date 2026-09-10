//! Synthetic format fixtures: no Apple binaries are distributed with these tests.
use dylex::{DyldContext, MachOContext, arm64, converter::*, dyld::*, macho::*};
use std::{
    fs,
    mem::{offset_of, size_of},
    sync::Arc,
};
use tempfile::TempDir;
use zerocopy::IntoBytes;
const BASE: u64 = 0x180000000;
fn u32at(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}
fn u64at(b: &mut [u8], off: usize, v: u64) {
    b[off..off + 8].copy_from_slice(&v.to_le_bytes());
}
fn q(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}
fn d(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}
fn put<T: IntoBytes + zerocopy::Immutable + ?Sized>(b: &mut [u8], off: usize, v: &T) {
    b[off..off + v.as_bytes().len()].copy_from_slice(v.as_bytes());
}
fn name(s: &str) -> [u8; 16] {
    let mut b = [0; 16];
    b[..s.len()].copy_from_slice(s.as_bytes());
    b
}
fn header(size: usize, len: usize, addr: u64) -> Vec<u8> {
    let mut b = vec![0; len];
    b[..16].copy_from_slice(b"dyld_v1  arm64e\0");
    u32at(&mut b, 16, size as u32);
    u32at(&mut b, 20, 1);
    u64at(&mut b, size, addr);
    u64at(&mut b, size + 8, len as u64);
    u64at(&mut b, size + 16, 0);
    u32at(&mut b, size + 24, 7);
    u32at(&mut b, size + 28, 5);
    b
}
fn modern(len: usize) -> Vec<u8> {
    header(size_of::<DyldCacheHeader>(), len, BASE)
}
fn open(b: &[u8]) -> (TempDir, Arc<DyldContext>) {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("dyld_shared_cache_arm64e");
    fs::write(&p, b).unwrap();
    let cache = Arc::new(DyldContext::open(&p).unwrap());
    (dir, cache)
}
fn image(b: &mut [u8], index: usize, address: u64, path: &str) {
    u32at(b, offset_of!(DyldCacheHeader, images_offset), 0x600);
    u32at(
        b,
        offset_of!(DyldCacheHeader, images_count),
        index as u32 + 1,
    );
    let entry = 0x600 + index * 32;
    let pathoff = 0x800 + index * 128;
    u64at(b, entry, address);
    u32at(b, entry + 24, pathoff as u32);
    b[pathoff..pathoff + path.len()].copy_from_slice(path.as_bytes());
}
fn segment(n: &str, addr: u64, off: u64, size: u64, sections: &[Section64]) -> Vec<u8> {
    let cmd = SegmentCommand64 {
        cmdsize: 72 + sections.len() as u32 * 80,
        segname: name(n),
        vmaddr: addr,
        vmsize: size,
        fileoff: off,
        filesize: size,
        maxprot: 7,
        initprot: if n == "__TEXT" { 5 } else { 3 },
        nsects: sections.len() as u32,
        ..Default::default()
    };
    let mut b = cmd.as_bytes().to_vec();
    for section in sections {
        b.extend_from_slice(section.as_bytes());
    }
    b
}
fn section(n: &str, seg: &str, addr: u64, off: u32, size: u64, flags: u32) -> Section64 {
    Section64 {
        sectname: name(n),
        segname: name(seg),
        addr,
        offset: off,
        size,
        align: 0,
        reloff: 0,
        nreloc: 0,
        flags,
        reserved1: 0,
        reserved2: 0,
        reserved3: 0,
    }
}
fn macho(b: &mut [u8], off: usize, cmds: Vec<Vec<u8>>, cpu: u32) {
    let h = MachHeader64 {
        magic: MH_MAGIC_64,
        cputype: cpu,
        cpusubtype: CPU_SUBTYPE_ARM64E,
        filetype: 6,
        ncmds: cmds.len() as u32,
        sizeofcmds: cmds.iter().map(|c| c.len() as u32).sum(),
        flags: 0x80000000,
        reserved: 0,
    };
    put(b, off, &h);
    let mut pos = off + 32;
    for cmd in cmds {
        b[pos..pos + cmd.len()].copy_from_slice(&cmd);
        pos += cmd.len();
    }
}
fn opts(b: &mut [u8], version: u32) {
    u64at(b, offset_of!(DyldCacheHeader, objc_opts_offset), 0xc00);
    u64at(
        b,
        offset_of!(DyldCacheHeader, objc_opts_size),
        if version == 1 { 56 } else { 136 },
    );
    u32at(b, 0xc00, version);
    u64at(b, 0xc00 + 48, 0x3000);
    if version == 2 {
        u64at(b, 0xc00 + 56, 0x100);
        u64at(b, 0xc00 + 64, 0x100);
    }
}

#[test]
fn short_legacy_header_does_not_consume_mapping_bytes() {
    let b = header(32, 64, BASE);
    let (_dir, c) = open(&b);
    assert_eq!(c.header.objc_opts_offset, 0);
    assert_eq!(c.mappings.len(), 1);
    assert_eq!(c.header.local_symbols_offset, 0);
    assert_eq!(c.image_count(), 0);
}
#[test]
fn malformed_tables_and_partial_headers_return_errors_not_panics() {
    for (off, value) in [
        (16, 0),
        (16, u32::MAX),
        (20, u32::MAX),
        (offset_of!(DyldCacheHeader, images_count), u32::MAX),
    ] {
        let mut b = modern(0x4000);
        u32at(&mut b, off, value);
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bad");
        fs::write(&p, b).unwrap();
        assert!(DyldContext::open(&p).is_err());
    }
}
#[test]
fn modern_empty_image_table_never_falls_back_to_legacy_garbage() {
    let mut b = modern(0x4000);
    u32at(&mut b, 24, 0xffff);
    u32at(&mut b, 28, 0xffff);
    let (_dir, c) = open(&b);
    assert!(c.images.is_empty());
}
#[test]
fn objc_versions_use_cache_header_vm_base_and_versioned_extents() {
    for version in [1, 2, 4] {
        let mut b = modern(0x4000);
        opts(&mut b, version);
        // On v4 this prefix extension must NOT be interpreted as v2 sizes.
        if version == 4 {
            u64at(&mut b, 0xc00 + 56, u64::MAX);
        }
        let (_dir, c) = open(&b);
        let o = c.objc_optimization().unwrap().unwrap();
        assert_eq!(o.selector_base, BASE + 0x3000);
        assert_eq!(o.address, BASE + 0xc00);
        assert_eq!(
            o.selector_size,
            if version == 2 { Some(0x100) } else { None }
        );
    }
}
#[test]
fn truncated_objc_v2_extension_is_rejected() {
    let mut b = modern(0x4000);
    opts(&mut b, 2);
    u64at(&mut b, offset_of!(DyldCacheHeader, objc_opts_size), 64);
    let (_dir, c) = open(&b);
    assert!(c.objc_optimization().is_err());
}

fn split(v2: bool) -> (TempDir, Arc<DyldContext>) {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("dyld_shared_cache_arm64e");
    let mut main = header(
        if v2 {
            size_of::<DyldCacheHeader>()
        } else {
            offset_of!(DyldCacheHeader, cache_sub_type)
        },
        0x4000,
        BASE,
    );
    u32at(
        &mut main,
        offset_of!(DyldCacheHeader, sub_cache_array_offset),
        0x400,
    );
    u32at(
        &mut main,
        offset_of!(DyldCacheHeader, sub_cache_array_count),
        2,
    );
    for i in 0..2 {
        let mut uuid = [i as u8 + 1; 16];
        if i == 1 {
            uuid[0] = b'.';
        }
        let entry = 0x400 + i * if v2 { 56 } else { 24 };
        main[entry..entry + 16].copy_from_slice(&uuid);
        let vm = BASE + if i == 0 { 0x8000 } else { 0x4000 };
        u64at(&mut main, entry + 16, vm - BASE);
        let suffix = if v2 {
            format!(".0{}.dylddata", i + 1)
        } else {
            format!(".{}", i + 1)
        };
        if v2 {
            main[entry + 24..entry + 24 + suffix.len()].copy_from_slice(suffix.as_bytes());
        }
        let mut sub = modern(0x4000);
        let mapoff = size_of::<DyldCacheHeader>();
        u64at(&mut sub, mapoff, vm);
        sub[offset_of!(DyldCacheHeader, uuid)..offset_of!(DyldCacheHeader, uuid) + 16]
            .copy_from_slice(&uuid);
        sub[0x2000] = 0xa0 + i as u8;
        fs::write(
            root.with_file_name(format!("dyld_shared_cache_arm64e{suffix}")),
            sub,
        )
        .unwrap();
    }
    fs::write(&root, main).unwrap();
    let c = Arc::new(DyldContext::open(root).unwrap());
    (dir, c)
}
#[test]
fn v1_and_v2_subcaches_are_selected_by_header_and_sorted_by_vm() {
    for v2 in [false, true] {
        let (_dir, c) = split(v2);
        assert_eq!(c.subcaches.len(), 2);
        assert_eq!(c.data_at_addr(BASE + 0x6000, 1).unwrap(), [0xa1]);
        assert_eq!(c.data_at_addr(BASE + 0xa000, 1).unwrap(), [0xa0]);
        assert!(c.mappings.windows(2).all(|w| w[0].address < w[1].address));
        assert!(c.data_at_addr(BASE + 0x3fff, 2).is_err());
        let mut bytes = [0; 2];
        c.copy_data_at_addr(BASE + 0x3fff, &mut bytes).unwrap();
        assert_eq!(bytes, [0, b'd']);
    }
}
#[test]
fn subcache_uuid_and_suffix_validation() {
    let (dir, c) = split(true);
    drop(c);
    let p = dir.path().join("dyld_shared_cache_arm64e.01.dylddata");
    let mut b = fs::read(&p).unwrap();
    b[offset_of!(DyldCacheHeader, uuid)] ^= 1;
    fs::write(p, b).unwrap();
    assert!(matches!(
        DyldContext::open(dir.path().join("dyld_shared_cache_arm64e")),
        Err(dylex::Error::SubcacheUuidMismatch { .. })
    ));
}

#[test]
fn slide_bitfields_separate_targets_tags_auth_and_chain_bits() {
    let target = 0x234567890;
    let plain = SlidePointer5(target | (0xabu64 << 34) | (0x123u64 << 52));
    assert_eq!(plain.runtime_offset(), target);
    assert_eq!(plain.high8(), 0xab);
    assert_eq!(plain.next(), 0x123);
    let auth =
        SlidePointer5(target | (0xffffu64 << 34) | (3u64 << 50) | (7u64 << 52) | (1u64 << 63));
    assert!(auth.is_auth());
    assert_eq!(auth.runtime_offset(), target);
    assert_eq!(auth.next(), 7);
    let p3 = SlidePointer3(0x123456789 | (0xabu64 << 43) | (0x234u64 << 51));
    assert_eq!(p3.plain_value(), 0xab00000123456789);
    assert_eq!(p3.offset_to_next(), 0x234);
}

#[test]
fn literal_assembler_stubs_and_negative_register_cases() {
    // Produced by clang -target arm64e-apple-macos; checked with otool -tv.
    let far: [u32; 4] = [0x10ffffd0, 0xd29ffff1, 0x8b115610, 0xd61f0200];
    let bytes: Vec<_> = far.iter().flat_map(|i| i.to_le_bytes()).collect();
    let stub = decode_cache_stub(&bytes, BASE).unwrap();
    assert_eq!(stub.target, BASE - 8 + (65535u64 << 21));
    assert_eq!(stub.size, 16);
    let mut wrong = bytes.clone();
    wrong[8] ^= 1;
    assert!(decode_cache_stub(&wrong, BASE).is_none());
    assert!(decode_cache_stub(&bytes[..12], BASE).is_none());
    assert!(decode_cache_stub(&0x94000000u32.to_le_bytes(), BASE).is_none());
    assert_eq!(
        decode_cache_stub(&0x17ffffffu32.to_le_bytes(), BASE)
            .unwrap()
            .target,
        BASE - 4
    );
    let auth = generate_stub_auth(BASE, BASE + 0x5000);
    let got = decode_cache_stub(&auth, BASE).unwrap();
    assert!(got.indirect);
    assert_eq!(got.target, BASE + 0x5000);
    let selector = [
        arm64::encode_adrp(1, BASE, BASE + 0x3000),
        arm64::encode_add_imm(1, 1, 0x18),
        arm64::encode_b(BASE + 8, BASE + 0x8000),
    ];
    let b: Vec<_> = selector.iter().flat_map(|i| i.to_le_bytes()).collect();
    let stub = decode_cache_stub(&b, BASE).unwrap();
    assert_eq!(stub.selector, Some(BASE + 0x3018));
    assert_eq!(stub.target, BASE + 0x8000);
}

fn objc_fixture(flags: u32, opt_version: Option<u32>) -> Vec<u8> {
    let mut b = modern(0x5000);
    image(&mut b, 0, BASE + 0x1000, "/usr/lib/test.dylib");
    if let Some(v) = opt_version {
        opts(&mut b, v);
    }
    let text = section(
        "__text",
        "__TEXT",
        BASE + 0x1400,
        0x1400,
        4,
        S_ATTR_PURE_INSTRUCTIONS,
    );
    let roots = section("__objc_classlist", "__DATA", BASE + 0x2000, 0x2000, 8, 0);
    let info = section("__objc_imageinfo", "__DATA", BASE + 0x2008, 0x2008, 8, 0);
    macho(
        &mut b,
        0x1000,
        vec![
            segment("__TEXT", BASE + 0x1000, 0x1000, 0x500, &[text]),
            segment("__DATA", BASE + 0x2000, 0x2000, 0x400, &[roots, info]),
        ],
        CPU_TYPE_ARM64,
    );
    u32at(&mut b, 0x1400, 0xd65f03c0);
    u64at(&mut b, 0x2000, BASE + 0x2040);
    u32at(&mut b, 0x200c, OBJC_IMAGE_OPTIMIZED_BY_DYLD);
    u64at(&mut b, 0x2040, BASE + 0x2040);
    u64at(&mut b, 0x2060, BASE + 0x2080);
    u64at(&mut b, 0x2098, BASE + 0x3020);
    u64at(&mut b, 0x20a0, BASE + 0x2100);
    u32at(&mut b, 0x2100, flags);
    u32at(&mut b, 0x2104, 1);
    b[0x3000..0x3005].copy_from_slice(b"ping\0");
    b[0x3010..0x3014].copy_from_slice(b"v@:\0");
    b[0x3020..0x3026].copy_from_slice(b"Thing\0");
    if flags & METHOD_LIST_RELATIVE_FLAG != 0 {
        let name_offset = if flags & METHOD_LIST_DIRECT_SEL_FLAG != 0 {
            if opt_version.is_some() {
                0
            } else {
                0x3000 - 0x2108
            }
        } else {
            u64at(&mut b, 0x2200, BASE + 0x3000);
            0x2200 - 0x2108
        };
        u32at(&mut b, 0x2108, name_offset);
        u32at(
            &mut b,
            0x210c,
            if flags & METHOD_LIST_TYPE_OFFSETS_FLAG != 0 {
                0x10
            } else {
                0x3010 - 0x210c
            },
        );
        u32at(&mut b, 0x2110, (0x1400i32 - 0x2110) as u32);
    } else {
        u64at(&mut b, 0x2108, BASE + 0x3000);
        u64at(&mut b, 0x2110, BASE + 0x3010);
        u64at(&mut b, 0x2118, BASE + 0x1400);
    }
    b
}
fn string_in(m: &MachOContext, addr: u64) -> &[u8] {
    let off = m.addr_to_offset(addr).unwrap();
    let end = m.data[off..].iter().position(|b| *b == 0).unwrap();
    &m.data[off..off + end]
}
#[test]
fn objc_absolute_self_relative_indirect_and_global_v1_v2_v4_roundtrip() {
    for (flags, v) in [
        (24, None),
        (0x8000000c, None),
        (0xc000000c, None),
        (0xc000000c, Some(1)),
        (0xe000000c, Some(2)),
        (0xe000000c, Some(4)),
    ] {
        let (_dir, cache) = open(&objc_fixture(flags, v));
        let macho = materialize_image(&cache, BASE + 0x1000, false).unwrap();
        let mut ctx = ExtractionContext::new(cache, macho, "test".into(), BASE + 0x1000);
        fix_objc(&mut ctx).unwrap();
        let ro = q(
            &ctx.macho.data,
            ctx.macho.addr_to_offset(BASE + 0x2060).unwrap(),
        );
        let off = ctx.macho.addr_to_offset(ro).unwrap();
        assert_eq!(
            string_in(&ctx.macho, q(&ctx.macho.data, off + 24)),
            b"Thing"
        );
        let methods = ctx
            .macho
            .addr_to_offset(q(&ctx.macho.data, off + 32))
            .unwrap();
        assert_eq!(d(&ctx.macho.data, methods), 24);
        assert_eq!(d(&ctx.macho.data, methods + 4), 1);
        assert_eq!(
            string_in(&ctx.macho, q(&ctx.macho.data, methods + 8)),
            b"ping"
        );
        assert_eq!(
            string_in(&ctx.macho, q(&ctx.macho.data, methods + 16)),
            b"v@:"
        );
        assert_eq!(q(&ctx.macho.data, methods + 24), BASE + 0x1400);
        let info = ctx.macho.addr_to_offset(BASE + 0x200c).unwrap();
        assert_eq!(d(&ctx.macho.data, info) & 8, 0);
    }
}

#[test]
fn overlapping_source_file_offsets_are_materialized_by_vm_address() {
    let (dir, cache) = split(true);
    drop(cache);
    let root = dir.path().join("dyld_shared_cache_arm64e");
    let mut b = fs::read(&root).unwrap();
    image(&mut b, 0, BASE + 0x1000, "/usr/lib/test.dylib");
    macho(
        &mut b,
        0x1000,
        vec![
            segment("__TEXT", BASE + 0x1000, 0x1000, 0x500, &[]),
            segment("__DATA", BASE + 0xa000, 0x1000, 8, &[]),
        ],
        CPU_TYPE_ARM64,
    );
    fs::write(&root, b).unwrap();
    let cache = DyldContext::open(root).unwrap();
    let m = materialize_image(&cache, BASE + 0x1000, false).unwrap();
    assert_eq!(d(&m.data, 0), MH_MAGIC_64);
    assert_eq!(m.data[m.addr_to_offset(BASE + 0xa000).unwrap()], 0xa0);
    assert_eq!(m.segment("__DATA").unwrap().command.fileoff, 0x500);
}

#[test]
fn sectionless_selector_island_and_arbitrary_dispatcher_copy_survive_writing() {
    let mut b = modern(0x5000);
    image(&mut b, 0, BASE + 0x1000, "/usr/lib/test.dylib");
    image(
        &mut b,
        1,
        BASE + 0x2800,
        "/usr/lib/objc/libobjcMsgSend97.dylib",
    );
    let code = 0x1000 + 32 + 152; // Deliberately no load-command padding.
    let text = section(
        "__text",
        "__TEXT",
        BASE + code,
        code as u32,
        4,
        S_ATTR_PURE_INSTRUCTIONS,
    );
    macho(
        &mut b,
        0x1000,
        vec![segment("__TEXT", BASE + 0x1000, 0x1000, 0x300, &[text])],
        CPU_TYPE_ARM64,
    );
    u32at(
        &mut b,
        code as usize,
        arm64::encode_b(BASE + code, BASE + 0x2000) | 0x80000000,
    );
    for (i, insn) in [
        arm64::encode_adrp(1, BASE + 0x2000, BASE + 0x3000),
        arm64::encode_add_imm(1, 1, 0),
        arm64::encode_b(BASE + 0x2008, BASE + 0x28c0),
    ]
    .into_iter()
    .enumerate()
    {
        u32at(&mut b, 0x2000 + i * 4, insn);
    }
    let dispatch = section(
        "__text",
        "__TEXT",
        BASE + 0x28c0,
        0x28c0,
        4,
        S_ATTR_PURE_INSTRUCTIONS,
    );
    macho(
        &mut b,
        0x2800,
        vec![segment("__TEXT", BASE + 0x2800, 0x2800, 0x200, &[dispatch])],
        CPU_TYPE_ARM64,
    );
    u32at(&mut b, 0x28c0, 0xd65f03c0);
    b[0x3000..0x3005].copy_from_slice(b"ping\0");
    let (dir, cache) = open(&b);
    let output = dir.path().join("out.dylib");
    dylex::extract_image_with_options(
        &cache,
        "/usr/lib/test.dylib",
        &output,
        dylex::ExtractionOptions {
            skip_linkedit: true,
            ..Default::default()
        },
    )
    .unwrap();
    let data = fs::read(output).unwrap();
    let m = MachOContext::new(&data, 0).unwrap();
    assert!(m.segment("__DYLEX_HDR").is_some());
    assert_eq!(m.segment("__TEXT").unwrap().command.vmaddr, BASE + 0x1000);
    for (addr, len) in [
        (BASE + code, 4),
        (BASE + 0x2000, 12),
        (BASE + 0x28c0, 4),
        (BASE + 0x3000, 5),
    ] {
        let off = m.addr_to_offset(addr).unwrap();
        assert_eq!(
            &data[off..off + len],
            cache.data_at_addr(addr, len).unwrap()
        );
    }
    for s in m.segments() {
        assert!(s.command.fileoff + s.command.filesize <= data.len() as u64);
    }
}

fn slide_fixture(version: u32) -> Vec<u8> {
    let mut b = modern(0x5000);
    image(&mut b, 0, BASE + 0x1000, "/usr/lib/test.dylib");
    macho(
        &mut b,
        0x1000,
        vec![
            segment("__TEXT", BASE + 0x1000, 0x1000, 0x300, &[]),
            segment("__DATA", BASE + 0x2180, 0x2180, 16, &[]),
        ],
        if version == 2 {
            CPU_TYPE_X86_64
        } else {
            CPU_TYPE_ARM64
        },
    );
    u32at(
        &mut b,
        offset_of!(DyldCacheHeader, mapping_with_slide_offset),
        0x300,
    );
    u32at(
        &mut b,
        offset_of!(DyldCacheHeader, mapping_with_slide_count),
        1,
    );
    u64at(&mut b, 0x300, BASE);
    u64at(&mut b, 0x308, 0x5000);
    u64at(&mut b, 0x318, 0x500);
    u64at(&mut b, 0x320, 0x100);
    u32at(&mut b, 0x330, 7);
    u32at(&mut b, 0x334, 3);
    u32at(&mut b, 0x500, version);
    u32at(&mut b, 0x504, 4096);
    let starts = if version == 2 {
        u32at(&mut b, 0x508, 40);
        u32at(&mut b, 0x50c, 5);
        u64at(&mut b, 0x518, 0x0fff000000000000);
        u64at(&mut b, 0x520, BASE);
        0x528
    } else {
        u32at(&mut b, 0x508, 5);
        u64at(&mut b, 0x510, BASE);
        0x518
    };
    for i in 0..5 {
        b[starts + i * 2..starts + i * 2 + 2]
            .copy_from_slice(&(if version == 2 { 0x4000u16 } else { 0xffffu16 }).to_le_bytes());
    }
    b[starts + 4..starts + 6]
        .copy_from_slice(&(if version == 2 { 0x40u16 } else { 0x100u16 }).to_le_bytes());
    let (head, first, last) = match version {
        2 => (0x3000 | (32u64 << 48), 0x4000 | (2u64 << 48), 0x5000),
        3 => (
            (BASE + 0x3000) | (16u64 << 51),
            0x4000 | (0xffffu64 << 32) | (1u64 << 51) | (1u64 << 63),
            BASE + 0x5000,
        ),
        5 => (
            0x3000 | (16u64 << 52),
            0x4000 | (0xffffu64 << 34) | (1u64 << 52) | (1u64 << 63),
            0x5000,
        ),
        _ => unreachable!(),
    };
    u64at(&mut b, 0x2100, head);
    u64at(&mut b, 0x2180, first);
    u64at(&mut b, 0x2188, last);
    b
}
#[test]
fn slide_chains_cross_neighboring_images_for_v2_v3_v5() {
    for version in [2, 3, 5] {
        let b = slide_fixture(version);
        let (_dir, cache) = open(&b);
        assert_eq!(cache.pointer_at(BASE + 0x2180).unwrap(), BASE + 0x4000);
        assert_eq!(cache.slide_info_value_add(), Some(BASE));
        let m = materialize_image(&cache, BASE + 0x1000, false).unwrap();
        let mut ctx = ExtractionContext::new(cache, m, "test".into(), BASE + 0x1000);
        process_slide_info(&mut ctx).unwrap();
        let off = ctx.macho.addr_to_offset(BASE + 0x2180).unwrap();
        assert_eq!(q(&ctx.macho.data, off), BASE + 0x4000);
        assert_eq!(q(&ctx.macho.data, off + 8), BASE + 0x5000);
    }
}
#[test]
fn v2_extra_chains_are_followed_and_unterminated_extras_fail() {
    for malformed in [false, true] {
        let mut b = slide_fixture(2);
        u32at(&mut b, 0x510, 64);
        u32at(&mut b, 0x514, 2);
        b[0x52c..0x52e].copy_from_slice(&0x8000u16.to_le_bytes());
        b[0x540..0x542].copy_from_slice(&0x40u16.to_le_bytes());
        b[0x542..0x544]
            .copy_from_slice(&(if malformed { 0x62u16 } else { 0x8062u16 }).to_le_bytes());
        u64at(&mut b, 0x2180, 0x4000);
        let (_dir, cache) = open(&b);
        let m = materialize_image(&cache, BASE + 0x1000, false).unwrap();
        let mut ctx = ExtractionContext::new(cache, m, "test".into(), BASE + 0x1000);
        let result = process_slide_info(&mut ctx);
        assert_eq!(result.is_err(), malformed);
        if !malformed {
            let off = ctx.macho.addr_to_offset(BASE + 0x2188).unwrap();
            assert_eq!(q(&ctx.macho.data, off), BASE + 0x5000);
        }
    }
}

#[test]
fn objc_opts_in_subcache_are_relative_to_main_header() {
    let (dir, cache) = split(true);
    drop(cache);
    let main = dir.path().join("dyld_shared_cache_arm64e");
    let sub = dir.path().join("dyld_shared_cache_arm64e.01.dylddata");
    let mut b = fs::read(&main).unwrap();
    u64at(
        &mut b,
        offset_of!(DyldCacheHeader, objc_opts_offset),
        0x9000,
    );
    u64at(&mut b, offset_of!(DyldCacheHeader, objc_opts_size), 72);
    fs::write(&main, b).unwrap();
    let mut b = fs::read(&sub).unwrap();
    u32at(&mut b, 0x1000, 2);
    u64at(&mut b, 0x1030, 0xb000);
    u64at(&mut b, 0x1038, 64);
    u64at(&mut b, 0x1040, 64);
    fs::write(sub, b).unwrap();
    let cache = DyldContext::open(main).unwrap();
    let opts = cache.objc_optimization().unwrap().unwrap();
    assert_eq!(opts.address, BASE + 0x9000);
    assert_eq!(opts.selector_base, BASE + 0xb000);
}
#[test]
fn legacy_objc_opt_v16_signed_self_relative_base() {
    let mut b = header(offset_of!(DyldCacheHeader, cache_sub_type), 0x4000, BASE);
    image(&mut b, 0, BASE + 0x1000, "/usr/lib/libobjc.A.dylib");
    let opt = section("__objc_opt_ro", "__TEXT", BASE + 0x1500, 0x1500, 48, 0);
    macho(
        &mut b,
        0x1000,
        vec![segment("__TEXT", BASE + 0x1000, 0x1000, 0x600, &[opt])],
        CPU_TYPE_ARM64,
    );
    u32at(&mut b, 0x1500, 16);
    u64at(&mut b, 0x1528, (-512i64) as u64);
    let (_dir, cache) = open(&b);
    let opts = cache.objc_optimization().unwrap().unwrap();
    assert_eq!(opts.selector_base, BASE + 0x1300);
    assert_eq!(opts.version, 16);
}
#[test]
fn malformed_slide_chain_cannot_escape_its_page() {
    let mut b = slide_fixture(5);
    u64at(&mut b, 0x2100, 0x3000 | (0x7ffu64 << 52));
    let (_dir, cache) = open(&b);
    let m = materialize_image(&cache, BASE + 0x1000, false).unwrap();
    let mut ctx = ExtractionContext::new(cache, m, "test".into(), BASE + 0x1000);
    assert!(process_slide_info(&mut ctx).is_err());
}
#[test]
fn tagged_relative_method_lists_are_flattened_without_reinterpreting_low_image_index() {
    let mut b = objc_fixture(0xe000000c, Some(4));
    u64at(&mut b, 0x20a0, BASE + 0x2301);
    u32at(&mut b, 0x2300, 8);
    u32at(&mut b, 0x2304, 1);
    u64at(&mut b, 0x2308, (((-520i64) as u64) << 16) | 37);
    let (_dir, cache) = open(&b);
    let m = materialize_image(&cache, BASE + 0x1000, false).unwrap();
    let mut ctx = ExtractionContext::new(cache, m, "test".into(), BASE + 0x1000);
    fix_objc(&mut ctx).unwrap();
    let ro = q(
        &ctx.macho.data,
        ctx.macho.addr_to_offset(BASE + 0x2060).unwrap(),
    );
    let rooff = ctx.macho.addr_to_offset(ro).unwrap();
    let list = ctx
        .macho
        .addr_to_offset(q(&ctx.macho.data, rooff + 32))
        .unwrap();
    assert_eq!(d(&ctx.macho.data, list + 4), 1);
    assert_eq!(q(&ctx.macho.data, list + 24), BASE + 0x1400);
}

/// Reproducible opt-in coverage without committing OS cache files. Set
/// DYLEX_TEST_CACHE to any real main cache and DYLEX_TEST_FILTER (default Safari).
#[test]
#[ignore = "requires a complete live or archived OS cache; set DYLEX_TEST_CACHE"]
fn live_cache_extraction_preserves_code_and_decodes_objc_roots() {
    let path = std::env::var("DYLEX_TEST_CACHE").expect("set DYLEX_TEST_CACHE");
    let filter = std::env::var("DYLEX_TEST_FILTER").unwrap_or_else(|_| "Safari".into());
    let cache = Arc::new(DyldContext::open(path).unwrap());
    let dir = tempfile::tempdir().unwrap();
    let images: Vec<_> = cache
        .images
        .iter()
        .filter(|i| i.path.contains(&filter))
        .collect();
    assert!(!images.is_empty());
    for (i, image) in images.iter().enumerate() {
        let output = dir.path().join(format!("{i}.dylib"));
        dylex::extract_image(&cache, &image.path, &output)
            .unwrap_or_else(|e| panic!("{}: {e}", image.path));
        let m = MachOContext::new(&fs::read(&output).unwrap(), 0).unwrap();
        let original = cache.image_header(image.address).unwrap();
        for seg in original.segments() {
            for section in &seg.sections {
                let s = &section.section;
                if s.size == 0 {
                    continue;
                }
                if s.name() == "__text" {
                    let off = m.addr_to_offset(s.addr).unwrap();
                    let mut source = vec![0; s.size as usize];
                    cache.copy_data_at_addr(s.addr, &mut source).unwrap();
                    assert_eq!(
                        &m.data[off..off + source.len()],
                        source,
                        "code changed: {}",
                        image.path
                    );
                }
                if matches!(s.name(), "__objc_classlist" | "__objc_nlclslist") {
                    for slot in (s.addr..s.addr + s.size).step_by(8) {
                        let off = m.addr_to_offset(slot).unwrap();
                        let output_ptr = q(&m.data, off);
                        assert_eq!(
                            output_ptr,
                            cache.pointer_at(slot).unwrap(),
                            "class root changed: {}",
                            image.path
                        );
                    }
                }
            }
        }
        let mut ranges: Vec<_> = m
            .segments()
            .filter(|s| s.command.vmsize != 0)
            .map(|s| (s.command.vmaddr, s.command.vmaddr + s.command.vmsize))
            .collect();
        ranges.sort();
        assert!(ranges.windows(2).all(|w| w[0].1 <= w[1].0));
    }
    eprintln!(
        "Verified {} images: code bytes, class pointers, VM ranges",
        images.len()
    );
}
