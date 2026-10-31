#!/usr/bin/env python3
"""Independently verify raw 64-bit fileset extraction with only Python stdlib.

Checks every entry, code/data bytes, chained pointer targets, section fields,
symbol names/values, indirect symbols, relocation tables and LINKEDIT extents.
Does not import dylex or attempt to boot outputs. Input must be decompressed.
"""
import argparse
import bisect
import hashlib
import json
from pathlib import Path
import struct


def span(data, offset, size):
    assert 0 <= offset <= len(data) and 0 <= size <= len(data) - offset, (offset, size, len(data))
    return data[offset:offset + size]


def unpack(fmt, data, offset):
    return struct.unpack(fmt, span(data, offset, struct.calcsize(fmt)))


def parse(data, base=0):
    h = unpack('<8I', data, base)
    assert h[0] == 0xfeedfacf
    commands, segments = [], []
    pos = base + 32
    for _ in range(h[4]):
        cmd, size = unpack('<II', data, pos)
        assert size >= 8 and pos + size <= base + 32 + h[5]
        raw = span(data, pos, size)
        commands.append((cmd, raw))
        if cmd == 0x19:
            name, vm, vmsize, fileoff, filesize, maxprot, prot, nsects, flags = unpack('<16s4Q4I', raw, 8)
            sections = [unpack('<16s16sQQ8I', raw, 72 + i * 80) for i in range(nsects)]
            segments.append(dict(name=name, vm=vm, vmsize=vmsize, fileoff=fileoff, filesize=filesize,
                                 sections=sections, maxprot=maxprot, prot=prot, flags=flags))
        pos += size
    assert pos == base + 32 + h[5]
    return h, commands, segments


def chain_patches(data, commands, segments):
    patches = {}
    base = next(s['vm'] for s in segments if s['fileoff'] == 0 and s['filesize'])
    for cmd, raw in commands:
        if cmd != 0x80000034:
            continue
        off, size = unpack('<II', raw, 8)
        d = span(data, off, size)
        version, starts, _, _, imports, _, _ = unpack('<7I', d, 0)
        assert version == 0 and imports == 0
        count, = unpack('<I', d, starts)
        for i in range(count):
            rel, = unpack('<I', d, starts + 4 + i * 4)
            if not rel:
                continue
            pos = starts + rel
            length, page_size, fmt, segment_offset, _, pages = unpack('<IHHQIH', d, pos)
            info = span(d, pos, length)
            assert fmt in (7, 8, 11) and base + segment_offset == segments[i]['vm']
            for page in range(pages):
                start, = unpack('<H', info, 22 + 2 * page)
                if start == 65535:
                    continue
                offsets = []
                if start & 32768:
                    overflow = start & 32767
                    while True:
                        value, = unpack('<H', info, 22 + 2 * overflow)
                        offsets.append(value & 32767)
                        overflow += 1
                        if value & 32768:
                            break
                else:
                    offsets.append(start)
                for offset in offsets:
                    while True:
                        assert offset < page_size
                        delta = page * page_size + offset
                        assert delta + 8 <= segments[i]['filesize']
                        loc = segments[i]['fileoff'] + delta
                        word, = unpack('<Q', data, loc)
                        if fmt == 7:
                            assert not word & (1 << 62)
                            target = word & (0xffffffff if word >> 63 else (1 << 43) - 1)
                            if not word >> 63:
                                target |= ((word >> 43) & 255) << 56
                            target = (base + target) & ((1 << 64) - 1)
                            advance = ((word >> 51) & 2047) * 4
                        else:
                            assert ((word >> 30) & 3) == 0
                            target = base + (word & 0x3fffffff)
                            advance = ((word >> 51) & 4095) * (1 if fmt == 11 else 4)
                        assert loc not in patches or patches[loc] == target
                        patches[loc] = target
                        if advance == 0:
                            break
                        offset += advance
    return patches


def symbol_records(data, raw):
    offset, count, stroff, strsize = unpack('<4I', raw, 8)
    strings = span(data, stroff, strsize)
    result = []
    for i in range(count):
        index, kind, section, desc, value = unpack('<IBBHQ', data, offset + i * 16)
        assert index < len(strings)
        end = strings.index(b'\0', index)
        if kind & 0xe == 0xa and not kind & 0xe0:
            assert value < len(strings)
            value = strings[value:strings.index(b'\0', value)]
        result.append((strings[index:end], kind, section, desc, value))
    return result


def verify(source, directory):
    data = source.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    outer, commands, segments = parse(data)
    assert outer[3] == 12
    patches = chain_patches(data, commands, segments)
    patch_offsets = sorted(patches)
    entries = []
    for cmd, raw in commands:
        if cmd == 0x80000035:
            _, offset, nameoff = unpack('<QQI', raw, 8)
            name = raw[nameoff:raw.index(b'\0', nameoff)].decode()
            entries.append((name, offset))
    totals = dict(images=0, segments=0, sections=0, symbols=0, pointer_occurrences=0,
                  compared_segment_bytes=0, output_bytes=0, unique_collection_fixups=len(patches))
    for name, base in entries:
        relative = Path(name.lstrip('/'))
        assert not relative.is_absolute() and '..' not in relative.parts
        output = (directory / relative).read_bytes()
        h, old_commands, old_segments = parse(data, base)
        new_h, new_commands, new_segments = parse(output)
        assert h[:4] == new_h[:4] and len(old_segments) == len(new_segments), name
        for old, new in zip(old_segments, new_segments):
            assert (old['name'], old['vm'], old['prot'], old['maxprot'], old['flags']) == (new['name'], new['vm'], new['prot'], new['maxprot'], new['flags']), name
            actual = span(output, new['fileoff'], new['filesize'])
            if old['name'].rstrip(b'\0') == b'__LINKEDIT':
                continue
            assert (old['vmsize'], old['filesize']) == (new['vmsize'], new['filesize']), name
            expected = bytearray(span(data, old['fileoff'], old['filesize']))
            start, end = old['fileoff'], old['fileoff'] + old['filesize']
            lo, hi = bisect.bisect_left(patch_offsets, start), bisect.bisect_left(patch_offsets, end)
            for loc in patch_offsets[lo:hi]:
                assert loc + 8 <= end
                struct.pack_into('<Q', expected, loc - start, patches[loc])
                totals['pointer_occurrences'] += 1
            skip = 32 + h[5] if start == base else 0
            assert expected[skip:] == actual[skip:], (name, old['name'], 'segment bytes differ')
            totals['compared_segment_bytes'] += len(expected) - min(skip, len(expected))
            assert len(old['sections']) == len(new['sections'])
            for a, b in zip(old['sections'], new['sections']):
                # offset and relocation-table location may change; other fields retain meaning.
                assert a[:4] == b[:4] and a[5] == b[5] and a[7:] == b[7:], (name, 'section fields')
                if a[8] & 255 not in (1, 12, 18) and a[3]:
                    assert b[4] >= new['fileoff'] and b[4] + b[3] <= new['fileoff'] + new['filesize']
                if a[7]:
                    assert span(data, a[6], a[7] * 8) == span(output, b[6], b[7] * 8)
                totals['sections'] += 1
            totals['segments'] += 1
        old_by_cmd = dict(old_commands)
        for cmd, raw in new_commands:
            assert cmd not in (0x1d, 0x1e, 0x2b, 0x80000034, 0x80000035)
            if cmd == 2:
                old_records, new_records = symbol_records(data, old_by_cmd[cmd]), symbol_records(output, raw)
                assert old_records == new_records, (name, 'symbols differ')
                totals['symbols'] += len(new_records)
            elif cmd == 0xb:
                original = old_by_cmd[cmd]
                assert raw[8:32] == original[8:32]
                for field, width in [(32, 8), (40, 56), (48, 4), (56, 4), (64, 8), (72, 8)]:
                    oldoff, count = unpack('<II', original, field)
                    newoff, newcount = unpack('<II', raw, field)
                    assert count == newcount
                    assert span(data, oldoff, count * width) == span(output, newoff, count * width)
            elif cmd in (0x26, 0x29, 0x80000033, 0x2e, 0x36):
                off, size = unpack('<II', raw, 8)
                oldoff, oldsize = unpack('<II', old_by_cmd[cmd], 8)
                assert size == oldsize
                if cmd != 0x29:
                    assert span(output, off, size) == span(data, oldoff, size)
                else:
                    for i in range(0, size, 8):
                        oldloc, length, kind = unpack('<IHH', data, oldoff + i)
                        newloc, newlength, newkind = unpack('<IHH', output, off + i)
                        assert (length, kind) == (newlength, newkind)
                        assert span(data, oldloc, length) == span(output, newloc, length)
        totals['images'] += 1
        totals['output_bytes'] += len(output)
    assert hashlib.sha256(source.read_bytes()).hexdigest() == digest, 'input changed'
    return dict(source_sha256=digest, **totals)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--report', type=Path)
    args = parser.parse_args()
    report = verify(args.source, args.directory)
    text = json.dumps(report, indent=2) + '\n'
    if args.report:
        args.report.write_text(text)
    print(text, end='')


if __name__ == '__main__':
    main()
