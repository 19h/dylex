#!/usr/bin/env python3
"""Independently verify ARM32 dylex outputs against a monolithic source cache.

Uses only Python's standard library, raw Mach-O layouts, and source VM mappings.
This checks static-analysis artifacts, not execution by an iOS dynamic loader.
"""
import argparse
import collections
import json
import mmap
import struct
from pathlib import Path


def u32(data, offset):
    return struct.unpack_from('<I', data, offset)[0]


def cstring(data, offset, end=None):
    end = len(data) if end is None else end
    assert 0 <= offset < end <= len(data), ('string bounds', offset, end)
    stop = data.find(b'\0', offset, end)
    assert stop >= 0, ('unterminated string', offset)
    return data[offset:stop]


def macho(data, base=0):
    h = struct.unpack_from('<7I', data, base)
    assert h[0] == 0xfeedface and h[1] == 12, ('not ARM32', h[:3])
    end = base + 28 + h[5]
    assert end <= len(data)
    cursor = base + 28
    segments, commands, sections = [], {}, []
    for _ in range(h[4]):
        cmd, size = struct.unpack_from('<2I', data, cursor)
        assert size >= 8 and cursor + size <= end
        if cmd == 1:
            assert size >= 56
            name = data[cursor+8:cursor+24].split(b'\0')[0]
            addr, vmsize, off, filesz, _, _, count, _ = struct.unpack_from('<8I', data, cursor+24)
            assert 56 + count*68 <= size and filesz <= vmsize
            segment = dict(name=name, addr=addr, vmsize=vmsize, off=off, size=filesz, sections=[])
            for i in range(count):
                pos = cursor + 56 + i*68
                n = data[pos:pos+16].split(b'\0')[0]
                a, sz, o, align, rel, nrel, flags, r1, r2 = struct.unpack_from('<9I', data, pos+32)
                assert addr <= a and a + sz <= addr + vmsize
                section = dict(name=n, addr=a, size=sz, off=o, flags=flags, r1=r1, r2=r2, rel=rel, nrel=nrel)
                segment['sections'].append(section)
                sections.append(section)
            segments.append(segment)
        else:
            assert cmd != 0x19, '64-bit segment in ARM32 output'
            commands[cmd] = bytes(data[cursor:cursor+size])
        cursor += size
    assert cursor == end
    return h, segments, sections, commands


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('cache', type=Path)
    parser.add_argument('output', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    counts = collections.Counter()
    failures = []
    with args.cache.open('rb') as stream:
        cache = mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ)
        assert cache[:7] == b'dyld_v1'
        mo, mc, io, ic = struct.unpack_from('<4I', cache, 16)
        maps = [struct.unpack_from('<3Q2I', cache, mo+i*32) for i in range(mc)]
        def source_offset(addr, size=1):
            for start, length, off, *_ in maps:
                if start <= addr and addr + size <= start + length:
                    return off + addr-start
            raise AssertionError(('source unmapped', hex(addr), size))
        # Independent v2 chain decoder for this historical corpus. Build a sorted
        # address list once, including zero-valued words used as chain links.
        slide_off, slide_size = struct.unpack_from('<2Q', cache, 56)
        slide_words = []
        if slide_size:
            version, page_size, so, sc, eo, ec = struct.unpack_from('<6I', cache, slide_off)
            assert version == 2, ('corpus verifier requires v2', version)
            mask, add = struct.unpack_from('<2Q', cache, slide_off+24)
            shift = (mask & -mask).bit_length()-1
            mapping = next(m for m in maps if m[4] & 2)
            for page in range(sc):
                value = struct.unpack_from('<H', cache, slide_off+so+page*2)[0]
                if value == 0x4000:
                    continue
                if value & 0x8000:
                    index, starts = value & 0x3fff, []
                    while True:
                        assert index < ec
                        entry = struct.unpack_from('<H', cache, slide_off+eo+index*2)[0]
                        starts.append((entry & 0x3fff)*4)
                        index += 1
                        if entry & 0x8000:
                            break
                else:
                    starts = [value*4]
                for slot in starts:
                    while True:
                        assert slot+4 <= page_size
                        addr = mapping[0]+page*page_size+slot
                        raw = u32(cache, source_offset(addr, 4))
                        val = raw & ~mask
                        slide_words.append((addr, val+add if val else 0))
                        delta = ((raw & mask) >> shift)*4
                        if not delta:
                            break
                        slot += delta
            slide_words.sort()
        import bisect
        slide_addresses = [a for a, _ in slide_words]
        counts['source_slide_words'] = len(slide_words)
        for index in range(ic):
            image, _, _, pathoff, _ = struct.unpack_from('<3Q2I', cache, io+index*32)
            path = cstring(cache, pathoff).decode()
            try:
                raw = (args.output / path.lstrip('/')).read_bytes()
                h, segments, sections, cmds = macho(raw)
                sh, _, source_sections, _ = macho(cache, source_offset(image))
                assert h[1:4] == sh[1:4] and not h[6] & 0x80000000
                def offset(addr, size=1):
                    for seg in segments:
                        if seg['addr'] <= addr and addr+size <= seg['addr']+seg['size']:
                            return seg['off']+addr-seg['addr']
                    raise AssertionError(('output unmapped', hex(addr), size))
                def ptr(addr):
                    return u32(raw, offset(addr, 4))
                def text(addr):
                    return cstring(raw, offset(addr))
                for seg in segments:
                    assert seg['off']+seg['size'] <= len(raw)
                for sec in sections:
                    if sec['size'] and sec['flags'] & 0xff not in (1, 0xc, 0x12):
                        assert sec['off']+sec['size'] <= len(raw)
                    if sec['nrel']:
                        assert sec['rel']+sec['nrel']*8 <= len(raw)
                by_extent = {(s['addr'], s['size'], s['name']): s for s in sections}
                for source in source_sections:
                    # Dedicated stubs can be restored; all other declared code
                    # must retain the exact instruction bytes and original VAs.
                    if source['flags'] & 0x80000400 and source['flags'] & 0xff != 8 and source['size']:
                        sec = by_extent[(source['addr'], source['size'], source['name'])]
                        a = source_offset(source['addr'], source['size'])
                        assert raw[sec['off']:sec['off']+sec['size']] == cache[a:a+source['size']], ('code changed', sec['name'])
                        counts['code_sections'] += 1
                        counts['code_bytes'] += source['size']
                for seg in segments:
                    if seg['name'] not in (b'__DATA', b'__DATA_CONST', b'__DATA_DIRTY'):
                        continue
                    lo = bisect.bisect_left(slide_addresses, seg['addr'])
                    hi = bisect.bisect_left(slide_addresses, seg['addr']+seg['size'])
                    for address, value in slide_words[lo:hi]:
                        if address + 4 > seg['addr'] + seg['size']:
                            # A shared page's final chain word can intersect
                            # only 1-3 file-backed bytes of this image. The
                            # extractor must leave those partial bytes intact.
                            length = seg['addr'] + seg['size'] - address
                            a, o = source_offset(address, length), offset(address, length)
                            assert raw[o:o+length] == cache[a:a+length]
                            counts['partial_slide_words_preserved'] += 1
                            continue
                        actual = ptr(address)
                        if actual != value:
                            # ObjC root/class-data patches must point into the
                            # output's explicitly described metadata segment.
                            extra = next((s for s in segments if s['name'] == b'__EXTRA_OBJC'), None)
                            assert extra and extra['addr'] <= (actual & ~3) < extra['addr']+extra['size'], ('slide mismatch', hex(address), hex(actual), hex(value))
                            counts['objc_pointer_rewrites'] += 1
                        else:
                            counts['verified_slide_words'] += 1
                for sec in sections:
                    if sec['name'] == b'__objc_selrefs':
                        for addr in range(sec['addr'], sec['addr']+sec['size'], 4):
                            if ptr(addr):
                                text(ptr(addr))
                                counts['objc_selectors'] += 1
                    elif sec['name'] in (b'__objc_classlist', b'__objc_nlclslist'):
                        for addr in range(sec['addr'], sec['addr']+sec['size'], 4):
                            cls = ptr(addr)
                            if not cls:
                                continue
                            ro = ptr(cls+16) & ~3
                            text(ptr(ro+16))
                            methods = ptr(ro+20)
                            if methods:
                                off = offset(methods, 8)
                                stride, count = struct.unpack_from('<2I', raw, off)
                                assert stride == 12
                                offset(methods, 8+count*12)
                                for i in range(count):
                                    text(ptr(methods+8+i*12))
                                    if ptr(methods+12+i*12):
                                        text(ptr(methods+12+i*12))
                                    counts['objc_methods'] += 1
                            counts['objc_classes'] += 1
                if 2 in cmds:
                    _, _, symoff, nsyms, stroff, strsize = struct.unpack('<6I', cmds[2])
                    assert symoff+nsyms*12 <= len(raw) and stroff+strsize <= len(raw)
                    for i in range(nsyms):
                        sx, typ, sect, desc, value = struct.unpack_from('<IBBHI', raw, symoff+i*12)
                        cstring(raw, stroff+sx, stroff+strsize)
                        if not typ & 0xe0 and typ & 0xe == 0xa:
                            cstring(raw, stroff+value, stroff+strsize)
                        assert sect <= len(sections)
                    counts['symbols'] += nsyms
                    if 0xb in cmds:
                        dys = struct.unpack('<20I', cmds[0xb])
                        for field in (2, 4, 6):
                            assert dys[field]+dys[field+1] <= nsyms
                        off, count = dys[14:16]
                        assert off+count*4 <= len(raw)
                        for i in range(count):
                            symbol = u32(raw, off+i*4)
                            assert symbol & 0xc0000000 or symbol < nsyms
                        counts['indirect_symbols'] += count
                if 0x80000022 in cmds:
                    pairs = struct.unpack('<12I', cmds[0x80000022])[2:]
                    for off, size in zip(pairs[::2], pairs[1::2]):
                        assert not size or off+size <= len(raw), ('dyld info bounds', off, size)
                counts['images'] += 1
            except Exception as error:
                failures.append(dict(path=path, error=repr(error)))
        report = dict(cache=str(args.cache), output=str(args.output), expected_images=ic, counts=dict(counts), failures=failures)
        encoded = json.dumps(report, indent=2)
        if args.report:
            args.report.write_text(encoded+'\n')
        print(encoded)
        return bool(failures)


if __name__ == '__main__':
    raise SystemExit(main())
