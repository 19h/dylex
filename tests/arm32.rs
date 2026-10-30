//! Independent raw ABI fixtures for legacy ARM caches. No Apple payloads.
use dylex::{converter::*, dyld::*, macho::*, *};
use std::{fs, sync::Arc};
use tempfile::TempDir;
const BASE: u64 = 0x4000_0000;
const TEXT: u64 = BASE + 0x1000;
const DATA: u64 = BASE + 0x10000;
const LINK: u64 = BASE + 0x20000;
fn d(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn q(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}
fn str_at(b: &mut [u8], o: usize, s: &str) {
    b[o..o + s.len()].copy_from_slice(s.as_bytes());
}
fn segment(
    name: &str,
    va: u64,
    off: u32,
    size: u32,
    sections: &[(&str, u32, u32, u32, u32, u32)],
) -> Vec<u8> {
    let mut b = vec![0; 56 + sections.len() * 68];
    let len = b.len() as u32;
    u(&mut b, 0, LC_SEGMENT);
    u(&mut b, 4, len);
    str_at(&mut b, 8, name);
    u(&mut b, 24, va as u32);
    u(&mut b, 28, size);
    u(&mut b, 32, off);
    u(&mut b, 36, size);
    u(&mut b, 40, 7);
    u(&mut b, 44, if name == "__TEXT" { 5 } else { 3 });
    u(&mut b, 48, sections.len() as u32);
    for (i, (n, delta, len, flags, r1, r2)) in sections.iter().enumerate() {
        let o = 56 + i * 68;
        str_at(&mut b, o, n);
        str_at(&mut b, o + 16, name);
        u(&mut b, o + 32, (va + *delta as u64) as u32);
        u(&mut b, o + 36, *len);
        u(&mut b, o + 40, off + delta);
        u(&mut b, o + 56, *flags);
        u(&mut b, o + 60, *r1);
        u(&mut b, o + 64, *r2);
    }
    b
}
fn fixture(arch: &str, subtype: u32, slide: u32, objc: bool) -> Vec<u8> {
    let mut b = vec![0; 0xa000];
    str_at(&mut b, 0, &format!("dyld_v1  {arch}"));
    u(&mut b, 16, 128);
    u(&mut b, 20, 3);
    u(&mut b, 24, 0x200);
    u(&mut b, 28, 1);
    for (i, (addr, size, off, prot)) in [
        (BASE, 0x5000, 0, 5),
        (DATA, 0x3000, 0x5000, 3),
        (LINK, 0x1000, 0x8000, 1),
    ]
    .into_iter()
    .enumerate()
    {
        let o = 128 + i * 32;
        q(&mut b, o, addr);
        q(&mut b, o + 8, size);
        q(&mut b, o + 16, off);
        u(&mut b, o + 24, prot);
        u(&mut b, o + 28, prot);
    }
    q(&mut b, 0x200, TEXT);
    u(&mut b, 0x218, 0x300);
    str_at(&mut b, 0x300, "/usr/lib/libfixture.dylib");
    let mut data_sections = vec![("__la_symbol_ptr", 0, 4, S_LAZY_SYMBOL_POINTERS, 0, 0)];
    if objc {
        data_sections.extend([
            ("__objc_classlist", 0x10, 4, 0, 0, 0),
            ("__objc_selrefs", 0x14, 4, 0, 0, 0),
            ("__objc_imageinfo", 0x18, 8, 0, 0, 0),
        ]);
    }
    let mut commands = vec![
        segment(
            "__TEXT",
            TEXT,
            0x1000,
            0x1000,
            &[
                ("__text", 0x400, 16, S_ATTR_PURE_INSTRUCTIONS, 0, 0),
                (
                    "__stubs",
                    0x800,
                    16,
                    S_SYMBOL_STUBS | S_ATTR_PURE_INSTRUCTIONS,
                    0,
                    16,
                ),
            ],
        ),
        segment("__DATA", DATA, 0x5000, 0x1000, &data_sections),
        segment("__LINKEDIT", LINK, 0x8000, 0x1000, &[]),
    ];
    let mut sym = vec![0; 24];
    u(&mut sym, 0, LC_SYMTAB);
    u(&mut sym, 4, 24);
    u(&mut sym, 8, 0x8100);
    u(&mut sym, 12, 3);
    u(&mut sym, 16, 0x8140);
    u(&mut sym, 20, 32);
    commands.push(sym);
    let mut dys = vec![0; 80];
    u(&mut dys, 0, LC_DYSYMTAB);
    u(&mut dys, 4, 80);
    for (off, value) in [
        (8, 0),
        (12, 1),
        (16, 1),
        (20, 1),
        (24, 2),
        (28, 1),
        (56, 0x8180),
        (60, 1),
    ] {
        u(&mut dys, off, value);
    }
    commands.push(dys);
    u(&mut b, 0x1000, MH_MAGIC);
    u(&mut b, 0x1004, CPU_TYPE_ARM);
    u(&mut b, 0x1008, subtype);
    u(&mut b, 0x100c, MH_DYLIB);
    u(&mut b, 0x1010, commands.len() as u32);
    u(
        &mut b,
        0x1014,
        commands.iter().map(Vec::len).sum::<usize>() as u32,
    );
    u(&mut b, 0x1018, 0x8000_0085);
    let mut cursor = 0x101c;
    for c in commands {
        b[cursor..cursor + c.len()].copy_from_slice(&c);
        cursor += c.len();
    }
    // Thumb instructions (BX LR plus NOPs) and an optimized ARM interworking stub.
    b[0x1400..0x1410].copy_from_slice(&[
        0x70, 0x47, 0x00, 0xbf, 0x00, 0xbf, 0x00, 0xbf, 0x00, 0xbf, 0x00, 0xbf, 0x00, 0xbf, 0x00,
        0xbf,
    ]);
    for (i, v) in [
        0xe59fc000,
        0xe08ff00c,
        ((TEXT + 0x401) as u32).wrapping_sub((TEXT + 0x80c) as u32),
        0xe7ffdefe,
    ]
    .into_iter()
    .enumerate()
    {
        u(&mut b, 0x1800 + i * 4, v);
    }
    u(&mut b, 0x5000, (TEXT + 0x401) as u32);
    // Three 12-byte nlists, with Thumb descriptor preserved.
    for (i, (strx, typ, sect, desc, val)) in [
        (1, N_SECT, 1, 8, TEXT + 0x400),
        (8, N_SECT | N_EXT, 1, 0, TEXT + 0x404),
        (16, N_UNDF | N_EXT, 0, 0, 0),
    ]
    .into_iter()
    .enumerate()
    {
        let o = 0x8100 + i * 12;
        u(&mut b, o, strx);
        b[o + 4] = typ;
        b[o + 5] = sect;
        b[o + 6..o + 8].copy_from_slice(&(desc as u16).to_le_bytes());
        u(&mut b, o + 8, val as u32);
    }
    str_at(&mut b, 0x8140, "\0_local\0_export\0_import\0");
    u(&mut b, 0x8180, 2);
    if objc {
        u(&mut b, 0x5010, (DATA + 0x100) as u32);
        u(&mut b, 0x5014, (TEXT + 0x900) as u32);
        u(&mut b, 0x501c, 8);
        // class_t: isa, superclass, cache[2], data bits.
        u(&mut b, 0x5100, (DATA + 0x100) as u32);
        u(&mut b, 0x5110, (DATA + 0x140) as u32 | 1);
        // 40-byte ARM class_ro_t: 12-byte scalar prefix and seven pointers.
        for (off, val) in [
            (12, TEXT + 0x920),
            (16, TEXT + 0x910),
            (20, DATA + 0x200),
            (28, DATA + 0x280),
            (32, TEXT + 0x920),
            (36, DATA + 0x2c0),
        ] {
            u(&mut b, 0x5140 + off, val as u32);
        }
        str_at(&mut b, 0x1900, "method:");
        str_at(&mut b, 0x1910, "FixtureClass");
        b[0x1920] = 0;
        str_at(&mut b, 0x1930, "v@:");
        str_at(&mut b, 0x1940, "ivar");
        str_at(&mut b, 0x1950, "i");
        str_at(&mut b, 0x1960, "property");
        str_at(&mut b, 0x1970, "Ti");
        u(&mut b, 0x5200, 12 | 3);
        u(&mut b, 0x5204, 1);
        u(&mut b, 0x5208, (TEXT + 0x900) as u32);
        u(&mut b, 0x520c, (TEXT + 0x930) as u32);
        u(&mut b, 0x5210, (TEXT + 0x401) as u32);
        u(&mut b, 0x5280, 20);
        u(&mut b, 0x5284, 1);
        for (off, val) in [(8, DATA + 0x2a0), (12, TEXT + 0x940), (16, TEXT + 0x950)] {
            u(&mut b, 0x5280 + off, val as u32);
        }
        u(&mut b, 0x5294, 2);
        u(&mut b, 0x5298, 4);
        u(&mut b, 0x52a0, 8);
        u(&mut b, 0x52c0, 8);
        u(&mut b, 0x52c4, 1);
        u(&mut b, 0x52c8, (TEXT + 0x960) as u32);
        u(&mut b, 0x52cc, (TEXT + 0x970) as u32);
    }
    if slide != 0 {
        q(&mut b, 56, 0x9000);
        q(&mut b, 64, 0x100);
        u(&mut b, 0x9000, slide);
        if slide == 1 {
            for (off, val) in [(4, 24), (8, 3), (12, 32), (16, 1), (20, 128)] {
                u(&mut b, 0x9000 + off, val);
            }
            b[0x9020] = 1;
        } else {
            for (off, val) in [(4, 4096), (8, 40), (12, 3), (16, 46), (20, 0)] {
                u(&mut b, 0x9000 + off, val);
            }
            q(
                &mut b,
                0x9018,
                if slide == 4 { 0xc000_0000 } else { 0xe000_0000 },
            );
            q(&mut b, 0x9020, BASE);
            let none = if slide == 4 { 0xffffu16 } else { 0x4000 };
            b[0x902a..0x902c].copy_from_slice(&none.to_le_bytes());
            b[0x902c..0x902e].copy_from_slice(&none.to_le_bytes());
            // One chain head, two adjacent 4-byte words, then an untouched canary.
            u(
                &mut b,
                0x5000,
                if slide == 4 { 0x4001_0401 } else { 0x2000_1401 },
            );
            u(&mut b, 0x5004, 0);
            u(&mut b, 0x5008, 0xdead_beef);
        }
    }
    b
}
fn open(b: &[u8]) -> (TempDir, Arc<DyldContext>) {
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("dyld_shared_cache_armv7s");
    fs::write(&p, b).unwrap();
    let cache = Arc::new(DyldContext::open(p).unwrap());
    (dir, cache)
}
fn output(cache: &Arc<DyldContext>, dir: &TempDir) -> MachOContext {
    let p = dir.path().join("fixture.dylib");
    extract_image(cache, "/usr/lib/libfixture.dylib", &p).unwrap();
    MachOContext::new(&fs::read(p).unwrap(), 0).unwrap()
}
#[test]
fn armv6_armv7_armv7s_and_armv7k_extract_with_original_abi_and_thumb_symbols() {
    for (arch, subtype) in [("armv6", 6), ("armv7", 9), ("armv7s", 11), ("armv7k", 12)] {
        let original = fixture(arch, subtype, 0, false);
        let (dir, cache) = open(&original);
        let m = output(&cache, &dir);
        assert!(!m.is_64());
        assert_eq!(m.header_size(), 28);
        assert_eq!(m.header.cpusubtype, subtype);
        assert_eq!(m.header.flags & 0x8000_0000, 0);
        assert!(m.segments().all(|s| s.command.cmd == LC_SEGMENT));
        let text = m.section("__TEXT", "__text").unwrap();
        assert_eq!(
            m.read_at(text.section.offset as usize, 16).unwrap(),
            &original[0x1400..0x1410]
        );
        let sym = m.symtab().unwrap();
        assert_eq!(sym.nsyms, 3);
        let n = read_nlist(&m.data[sym.symoff as usize..], false).unwrap();
        assert_eq!(n.n_desc, 8);
        assert_eq!(n.n_value, TEXT + 0x400);
        let stub = m.section("__TEXT", "__stubs").unwrap();
        assert_eq!(
            m.read_u32(stub.section.offset as usize).unwrap(),
            0xe59fc004
        );
        let p = m.section("__DATA", "__la_symbol_ptr").unwrap();
        assert_eq!(
            m.read_pointer(p.section.offset as usize).unwrap(),
            TEXT + 0x401
        );
    }
}
#[test]
fn slide_v1_v2_v4_preserve_adjacent_arm_words_and_decode_cache_pointer_reads() {
    for version in [1, 2, 4] {
        let (dir, cache) = open(&fixture("armv7s", 11, version, false));
        assert_eq!(cache.pointer_size(), 4);
        let target = if version == 4 {
            DATA + 0x401
        } else {
            TEXT + 0x401
        };
        assert_eq!(cache.pointer_at(DATA).unwrap(), target);
        let m = output(&cache, &dir);
        let off = m.addr_to_offset(DATA).unwrap();
        assert_eq!(m.read_u32(off).unwrap() as u64, target);
        if version != 1 {
            assert_eq!(m.read_u32(off + 4).unwrap(), 0);
            assert_eq!(m.read_u32(off + 8).unwrap(), 0xdead_beef);
        }
    }
}
#[test]
fn objc_arm_class_ro_methods_ivars_properties_and_selectors_are_self_contained() {
    let (dir, cache) = open(&fixture("armv7s", 11, 0, true));
    let m = output(&cache, &dir);
    let extra = m.segment("__EXTRA_OBJC").unwrap();
    assert_eq!(extra.command.cmdsize, 124);
    assert_eq!(extra.sections[0].section.size, extra.command.filesize);
    let ptr = |addr| m.read_pointer(m.addr_to_offset(addr).unwrap()).unwrap();
    let ro = ptr(DATA + 0x110) & !3;
    assert!(extra.command.vmaddr <= ro);
    assert_eq!(ptr(DATA + 0x110) & 3, 1);
    let name = ptr(ro + 16);
    let o = m.addr_to_offset(name).unwrap();
    assert_eq!(&m.data[o..o + 12], b"FixtureClass");
    let methods = ptr(ro + 20);
    let o = m.addr_to_offset(methods).unwrap();
    assert_eq!(d(&m.data, o), 12);
    assert_eq!(d(&m.data, o + 4), 1);
    assert_eq!(ptr(methods + 16), TEXT + 0x401);
    let ivars = ptr(ro + 28);
    let o = m.addr_to_offset(ivars).unwrap();
    assert_eq!(d(&m.data, o), 20);
    let ivar_offset = ptr(ivars + 8);
    assert_eq!(
        m.read_u32(m.addr_to_offset(ivar_offset).unwrap()).unwrap(),
        8
    );
    let props = ptr(ro + 36);
    assert_eq!(m.read_u32(m.addr_to_offset(props).unwrap()).unwrap(), 8);
    let selector = ptr(DATA + 0x14);
    assert_eq!(
        &m.data[m.addr_to_offset(selector).unwrap()..][..7],
        b"method:"
    );
    assert_eq!(
        m.read_u32(m.addr_to_offset(DATA + 0x1c).unwrap()).unwrap() & 8,
        0
    );
}
#[test]
fn malformed_arm_sections_headers_and_pointer_overflows_fail_without_panicking() {
    let mut b = fixture("armv7s", 11, 0, false);
    u(&mut b, 0x101c + 48, 10000);
    let (_, cache) = open(&b);
    assert!(cache.image_header(TEXT).is_err());
    assert!(MachOContext::new(&[0xce, 0xfa, 0xed, 0xfe], 0).is_err());
    let (_, cache) = open(&fixture("armv7s", 11, 0, false));
    let mut m = cache.image_header(TEXT).unwrap();
    assert!(m.write_pointer(24, 1u64 << 32).is_err());
    let original = m.data.clone();
    m.sync_header().unwrap();
    assert_eq!(m.data, original);
}
#[test]
fn selected_and_dependency_merges_keep_arm_code_addresses_and_symbol_width() {
    let (dir, cache) = open(&fixture("armv7s", 11, 0, true));
    for legacy in [false, true] {
        let p = dir.path().join(if legacy { "deps" } else { "selected" });
        if legacy {
            extract_image_with_merged_deps(
                &cache,
                "/usr/lib/libfixture.dylib",
                &p,
                MergeExtractionOptions::default(),
            )
            .unwrap();
        } else {
            extract_image_with_selected_images(&cache, "/usr/lib/libfixture.dylib", &[], &p, 0)
                .unwrap();
        }
        let m = MachOContext::new(&fs::read(p).unwrap(), 0).unwrap();
        assert!(!m.is_64());
        assert_eq!(m.header.cputype, CPU_TYPE_ARM);
        assert!(m.addr_to_offset(TEXT + 0x400).is_some());
        let sym = m.symtab().unwrap();
        assert!(sym.nsyms >= 3);
        assert!(m.segment("__EXTRA_OBJC").is_some());
    }
}

#[test]
fn cache_local_symbols_are_recovered_as_twelve_byte_entries() {
    let mut b = fixture("armv7s", 11, 0, false);
    q(&mut b, 72, 0x9200);
    q(&mut b, 80, 0x200);
    for (off, value) in [(0, 40), (4, 1), (8, 52), (12, 32), (16, 24), (20, 1)] {
        u(&mut b, 0x9200 + off, value);
    }
    u(&mut b, 0x9218, 0x1000);
    u(&mut b, 0x921c, 0);
    u(&mut b, 0x9220, 1);
    u(&mut b, 0x9228, 1);
    b[0x922c] = N_SECT;
    b[0x922d] = 1;
    b[0x922e] = 8;
    u(&mut b, 0x9230, (TEXT + 0x408) as u32);
    str_at(&mut b, 0x9234, "\0_cache_local\0");
    let (dir, cache) = open(&b);
    let m = output(&cache, &dir);
    let sym = m.symtab().unwrap();
    assert_eq!(sym.nsyms, 4);
    let n = read_nlist(&m.data[sym.symoff as usize + 12..], false).unwrap();
    assert_eq!(n.n_value, TEXT + 0x408);
    assert_eq!(n.n_desc, 8);
    assert_eq!(
        &m.data[sym.stroff as usize + n.n_strx as usize..][..12],
        b"_cache_local"
    );
    let dys = m.dysymtab().unwrap();
    assert_eq!(dys.nlocalsym, 2);
    assert_eq!(m.read_u32(dys.indirectsymoff as usize).unwrap(), 3);
}

#[test]
fn v4_extra_chains_reconstruct_small_integers_and_signed_nonpointers() {
    let mut b = fixture("armv7s", 11, 4, false);
    u(&mut b, 0x9014, 2); // two extras
    b[0x9028..0x902a].copy_from_slice(&0x8000u16.to_le_bytes());
    b[0x902e..0x9030].copy_from_slice(&0u16.to_le_bytes());
    b[0x9030..0x9032].copy_from_slice(&0x8002u16.to_le_bytes());
    u(&mut b, 0x5000, 0x1234);
    u(&mut b, 0x5008, 0x3fff_ffff);
    let (dir, cache) = open(&b);
    assert_eq!(cache.pointer_at(DATA).unwrap(), 0x1234);
    assert_eq!(cache.pointer_at(DATA + 8).unwrap(), 0xffff_ffff);
    let m = output(&cache, &dir);
    let off = m.addr_to_offset(DATA).unwrap();
    assert_eq!(m.read_u32(off).unwrap(), 0x1234);
    assert_eq!(m.read_u32(off + 8).unwrap(), 0xffff_ffff);
    b[0x9030..0x9032].copy_from_slice(&2u16.to_le_bytes());
    let (_, cache) = open(&b);
    let m = materialize_image(&cache, TEXT, false).unwrap();
    let mut ctx = ExtractionContext::new(cache, m, "fixture".into(), TEXT);
    assert!(process_slide_info(&mut ctx).is_err());
}

#[test]
fn objc_protocol_count_is_scalar_and_categories_use_four_byte_fields() {
    let mut b = fixture("armv7s", 11, 2, true);
    // Keep ObjC pointers in an unslid read-only mapping to isolate scalar count
    // decoding from the data mapping's chain encoding.
    let (_, cache) = open(&b);
    let header = cache.image_header(TEXT).unwrap();
    let classlist = header
        .section("__DATA", "__objc_classlist")
        .unwrap()
        .struct_offset
        + 0x1000;
    str_at(&mut b, classlist, "__objc_catlist\0\0\0");
    // Turn off v2 for normal records, then use a v2 encoded protocol-list count
    // test separately below; protocol count must always be read as raw uint32.
    q(&mut b, 56, 0);
    q(&mut b, 64, 0);
    u(&mut b, 0x5000, (TEXT + 0x401) as u32);
    u(&mut b, 0x5010, (DATA + 0x300) as u32);
    for (off, value) in [
        (0, TEXT + 0x910),
        (4, DATA + 0x100),
        (8, DATA + 0x200),
        (16, DATA + 0x340),
        (20, DATA + 0x2c0),
    ] {
        u(&mut b, 0x5300 + off, value as u32);
    }
    u(&mut b, 0x5340, 1);
    u(&mut b, 0x5344, (DATA + 0x380) as u32);
    // protocol_t prefix: 8 pointers followed by size and flags, plus extensions.
    for (off, value) in [
        (4, TEXT + 0x910),
        (8, DATA + 0x340),
        (12, DATA + 0x200),
        (28, DATA + 0x2c0),
        (32, 52),
        (40, DATA + 0x3d0),
        (44, TEXT + 0x910),
        (48, DATA + 0x2c0),
    ] {
        u(&mut b, 0x5380 + off, value as u32);
    }
    u(&mut b, 0x53d0, (TEXT + 0x930) as u32);
    let (dir, cache) = open(&b);
    let m = output(&cache, &dir);
    let ptr = |addr| m.read_pointer(m.addr_to_offset(addr).unwrap()).unwrap();
    let cat = ptr(DATA + 0x10);
    let list = ptr(cat + 16);
    assert_eq!(ptr(list), 1);
    let protocol = ptr(list + 4);
    assert_eq!(ptr(protocol + 8), list);
    assert_eq!(
        m.read_u32(m.addr_to_offset(protocol + 32).unwrap())
            .unwrap(),
        52
    );
    assert_ne!(ptr(protocol + 40), 0);
    assert_ne!(ptr(protocol + 48), 0);
}

#[test]
fn slide_membership_preserves_optional_absolute_fields_outside_chains() {
    let mut b = fixture("armv7s", 11, 2, false);
    u(&mut b, 0x5008, (DATA + 0x200) as u32);
    let (dir, cache) = open(&b);
    assert_eq!(cache.pointer_at(DATA).unwrap(), TEXT + 0x401);
    assert_eq!(cache.pointer_at(DATA + 8).unwrap(), DATA + 0x200);
    let m = output(&cache, &dir);
    assert_eq!(
        m.read_pointer(m.addr_to_offset(DATA + 8).unwrap()).unwrap(),
        DATA + 0x200
    );
}

#[test]
fn arm_stub_decoding_preserves_thumb_state_and_rejects_wrong_registers() {
    let pc = 0x1000u32;
    for (words, target, indirect) in [
        (
            [
                0xe59fc004,
                0xe08fc00c,
                0xe59cf000,
                0x2000u32.wrapping_sub(pc + 12),
            ],
            0x2000,
            true,
        ),
        (
            [
                0xe59fc000,
                0xe08ff00c,
                0x2001u32.wrapping_sub(pc + 12),
                0xe7ffdefe,
            ],
            0x2001,
            false,
        ),
        ([0xe59fc000, 0xe12fff1c, 0x2001, 0], 0x2001, false),
    ] {
        let bytes: Vec<_> = words.iter().flat_map(|w| w.to_le_bytes()).collect();
        let stub = decode_arm_cache_stub(&bytes, pc as u64).unwrap();
        assert_eq!(stub.target, target);
        assert_eq!(stub.indirect, indirect);
        assert!(decode_arm_cache_stub(&bytes[..7], pc as u64).is_none());
        let mut bad = bytes.clone();
        bad[0] ^= 1;
        assert!(decode_arm_cache_stub(&bad, pc as u64).is_none());
    }
    let (dir, cache) = open(&fixture("armv7s", 11, 0, false));
    let _ = dir;
    assert_eq!(
        cache.cache_stub_target(TEXT + 0x800).unwrap().unwrap().0,
        TEXT + 0x401
    );
}

fn second_image(b: &mut [u8]) {
    let source_text = b[0x1000..0x2000].to_vec();
    b[0x3000..0x4000].copy_from_slice(&source_text);
    let source_data = b[0x5000..0x6000].to_vec();
    b[0x6000..0x7000].copy_from_slice(&source_data);
    let mut cursor = 0x301c;
    for _ in 0..d(b, 0x3010) {
        let cmd = d(b, cursor);
        let size = d(b, cursor + 4) as usize;
        if cmd == LC_SEGMENT {
            let vm = d(b, cursor + 24);
            let delta = if vm == TEXT as u32 {
                0x2000
            } else if vm == DATA as u32 {
                0x1000
            } else {
                0
            };
            u(b, cursor + 24, vm + delta);
            let off = d(b, cursor + 32);
            u(b, cursor + 32, off + delta);
            for i in 0..d(b, cursor + 48) as usize {
                let s = cursor + 56 + i * 68;
                let addr = d(b, s + 32);
                let off = d(b, s + 40);
                u(b, s + 32, addr + delta);
                u(b, s + 40, off + delta);
            }
        } else if cmd == LC_SYMTAB {
            u(b, cursor + 8, 0x8200);
            u(b, cursor + 16, 0x8240);
        } else if cmd == LC_DYSYMTAB {
            u(b, cursor + 56, 0x8280);
        }
        cursor += size;
    }
    let syms = b[0x8100..0x8184].to_vec();
    b[0x8200..0x8284].copy_from_slice(&syms);
    u(b, 0x8208, (TEXT + 0x2400) as u32);
    u(b, 0x8214, (TEXT + 0x2404) as u32);
    u(b, 0x6000, (TEXT + 0x2401) as u32);
    u(b, 0x5000, (TEXT + 0x2401) as u32); // primary imports a Thumb runtime target
    u(
        b,
        0x1808,
        ((TEXT + 0x2401) as u32).wrapping_sub((TEXT + 0x80c) as u32),
    );
    u(b, 28, 3);
    q(b, 0x220, TEXT + 0x2000);
    u(b, 0x238, 0x340);
    str_at(b, 0x340, "/usr/lib/libobjc.A.dylib");
    q(b, 0x240, TEXT);
    u(b, 0x258, 0x380);
    str_at(b, 0x380, "/usr/lib/libfixture-alias.dylib");
    // Add a real dependency command to the primary header.
    let off = 0x101c + d(b, 0x1014) as usize;
    let path = "/usr/lib/libobjc.A.dylib";
    let size = (24 + path.len() + 1 + 3) & !3;
    u(b, off, LC_LOAD_DYLIB);
    u(b, off + 4, size as u32);
    u(b, off + 8, 24);
    str_at(b, off + 24, path);
    let count = d(b, 0x1010);
    let old = d(b, 0x1014);
    u(b, 0x1010, count + 1);
    u(b, 0x1014, old + size as u32);
}

#[test]
fn arm_multimage_aliases_dependencies_runtime_inference_and_symbol_ordinals() {
    let mut b = fixture("armv7s", 11, 0, false);
    second_image(&mut b);
    let (dir, cache) = open(&b);
    let additions = vec![
        "/usr/lib/libfixture-alias.dylib".into(),
        "/usr/lib/libobjc.A.dylib".into(),
    ];
    let selected = selected_merge_images(&cache, "/usr/lib/libfixture.dylib", &additions).unwrap();
    assert_eq!(selected.len(), 2);
    let runtime = referenced_runtime_images(&cache, &[selected[0].clone()]).unwrap();
    assert_eq!(runtime.len(), 1);
    assert_eq!(runtime[0].image_path, "/usr/lib/libobjc.A.dylib");
    assert_eq!(runtime[0].target_address, TEXT + 0x2401);
    let root = selected[0].clone();
    let stats = extract_images_with_dependencies(
        &cache,
        std::slice::from_ref(&root),
        dir.path().join("deps"),
        ExtractionOptions::default(),
        None,
        |_, _, _| {},
    )
    .unwrap();
    assert_eq!(stats.total_extracted, 2);
    assert_eq!(stats.failed, 0);
    for legacy in [false, true] {
        let output = dir
            .path()
            .join(if legacy { "legacy-2" } else { "selected-2" });
        if legacy {
            extract_image_with_merged_deps(
                &cache,
                &root,
                &output,
                MergeExtractionOptions::default(),
            )
            .unwrap();
        } else {
            extract_image_with_selected_images(&cache, &root, &additions, &output, 0).unwrap();
        }
        let m = MachOContext::new(&fs::read(output).unwrap(), 0).unwrap();
        let table = m.symtab().unwrap();
        assert_eq!(table.nsyms, 6);
        let symbols: Vec<_> = m.data[table.symoff as usize..][..table.nsyms as usize * 12]
            .chunks_exact(12)
            .map(|b| read_nlist(b, false).unwrap())
            .collect();
        assert!(
            symbols
                .iter()
                .any(|n| n.n_value == TEXT + 0x2400 && n.n_sect == 4 && n.n_desc == 8)
        );
        assert_eq!(
            m.read_pointer(m.addr_to_offset(DATA).unwrap()).unwrap(),
            TEXT + 0x2401
        );
        assert_eq!(
            m.read_at(m.addr_to_offset(TEXT + 0x2400).unwrap(), 16)
                .unwrap(),
            &b[0x3400..0x3410]
        );
    }
}

#[test]
fn runtime_inference_finds_arm_and_thumb_direct_calls_without_pointer_evidence() {
    for thumb in [false, true] {
        let mut b = fixture("armv7s", 11, 0, false);
        second_image(&mut b);
        u(&mut b, 0x5000, 0);
        b[0x8106] = if thumb { N_ARM_THUMB_DEF as u8 } else { 0 };
        if thumb {
            b[0x1400..0x1404].copy_from_slice(&[0x01, 0xf0, 0xfe, 0xff]);
        } else {
            u(&mut b, 0x1400, 0xeb00_07fe);
        }
        let (_dir, cache) = open(&b);
        let refs =
            referenced_runtime_images(&cache, &["/usr/lib/libfixture.dylib".into()]).unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].source_address, TEXT + 0x400);
        assert_eq!(refs[0].target_address, TEXT + 0x2400 + u64::from(thumb));
    }
}

#[test]
fn objc_coalesced_class_objects_are_mapped_with_their_metaclasses() {
    let mut b = fixture("armv7s", 11, 0, true);
    // A definition moved outside the source image's DATA segment, with its
    // self-referencing metaclass and superclass cycle encoded as raw pointers.
    u(&mut b, 0x5010, (DATA + 0x1100) as u32);
    let class = b[0x5100..0x5114].to_vec();
    b[0x6100..0x6114].copy_from_slice(&class);
    u(&mut b, 0x6100, (DATA + 0x1120) as u32);
    u(&mut b, 0x6104, (DATA + 0x1100) as u32);
    b[0x6120..0x6134].copy_from_slice(&class);
    u(&mut b, 0x6120, (DATA + 0x1120) as u32);
    let (dir, cache) = open(&b);
    let m = output(&cache, &dir);
    let ptr = |a| m.read_pointer(m.addr_to_offset(a).unwrap()).unwrap();
    let cls = ptr(DATA + 0x10);
    assert_ne!(cls, DATA + 0x1100);
    assert_eq!(ptr(cls + 4), cls);
    let meta = ptr(cls);
    assert_eq!(ptr(meta), meta);
    let ro = ptr(meta + 16) & !3;
    assert!(m.addr_to_offset(ptr(ro + 16)).is_some());
}

#[test]
fn arm_header_growth_preserves_original_code_addresses_and_nlist_ordinals() {
    let mut b = fixture("armv7s", 11, 0, true);
    let instructions = b[0x1400..0x1410].to_vec();
    b[0x1300..0x1310].copy_from_slice(&instructions);
    // First section follows the existing commands too closely for one more
    // segment command. Header growth must move file offsets, never code VAs.
    u(&mut b, 0x101c + 56 + 32, (TEXT + 0x300) as u32);
    u(&mut b, 0x101c + 56 + 40, 0x1300);
    u(&mut b, 0x8108, (TEXT + 0x300) as u32);
    u(&mut b, 0x8114, (TEXT + 0x304) as u32);
    u(&mut b, 0x5000, (TEXT + 0x301) as u32);
    u(&mut b, 0x5210, (TEXT + 0x301) as u32);
    let (dir, cache) = open(&b);
    let m = output(&cache, &dir);
    let header = m.segment("__DYLEX_HDR").unwrap();
    assert_eq!(header.command.cmdsize, 56);
    assert_eq!(header.command.fileoff, 0);
    let section = m.section("__TEXT", "__text").unwrap();
    assert_eq!(section.section.addr, TEXT + 0x300);
    assert_eq!(
        m.read_at(section.section.offset as usize, 16).unwrap(),
        instructions
    );
    let table = m.symtab().unwrap();
    let n = read_nlist(&m.data[table.symoff as usize..], false).unwrap();
    assert_eq!(n.n_value, TEXT + 0x300);
    assert_eq!(n.n_sect, 1);
    assert_eq!(
        m.read_u32(m.addr_to_offset(DATA + 0x1c).unwrap()).unwrap() & 8,
        0
    );
}

#[test]
fn install_name_aliases_do_not_hide_owned_strings_or_infer_the_root_again() {
    let mut b = fixture("armv7s", 11, 0, false);
    second_image(&mut b);
    str_at(&mut b, 0x1900, "ARM_ALIAS_STRING");
    let (_dir, cache) = open(&b);
    let query = StringQuery {
        needle: b"ARM_ALIAS_STRING".to_vec(),
        ignore_case: false,
        image_filter: Some("libfixture.dylib".into()),
    };
    let matches = cache.search_strings(&query, || {}).unwrap();
    assert_eq!(matches.hits.len(), 1);
    assert!(matches.skipped.is_empty());
    assert_eq!(matches.hits[0].address, TEXT + 0x900);
    let inferred =
        referenced_runtime_images(&cache, &["/usr/lib/libfixture-alias.dylib".into()]).unwrap();
    assert_eq!(inferred.len(), 1);
    assert_eq!(inferred[0].image_path, "/usr/lib/libobjc.A.dylib");
}
