# Cache compatibility implementation and validation

This change updates the normal single-image, filtered/batch, and `--with-deps`
extraction pipeline. Outputs are Mach-O files for static analysis. They retain
external function references and do not reconstruct a runnable operating-system
loader environment. The existing experimental `--merge-deps` relocation pipeline
is separate; its end-to-end behavior on Golden Gate is **unknown**.

## Observed inputs

Validation host: macOS **27.0**, build **26A5425a**. These observations apply to
that build, not an inferred RC or GA build.

| Product | Main file, relative to `/System/Volumes/Preboot/Cryptexes` | Images | Subcaches |
|---|---|---:|---:|
| Native | `OS/System/Library/dyld/dyld_shared_cache_arm64e` | 4083 | 79 |
| Full Rosetta | `Rosetta/System/Library/dyld/dyld_shared_cache_x86_64` | 3913 | 6 |
| Reduced x86Support | `Rosetta/System/x86Support/System/Library/dyld/dyld_shared_cache_x86_64` | 553 | 1 |

All three have Objective-C optimization header **version 4**, with size **136 B**
(`0x88`). The selector-base field at byte offset 48 retains the cache-header-relative
interpretation used by IDA. On the native cache its value is `0x74905180`, so:

```text
header VA       = 0x180000000
selector offset = 0x074905180
selector VA     = 0x1f4905180
```

These are integer byte addresses; arithmetic is exact, with checked overflow.
The version-4 fields after this prefix are **unknown**. In particular, byte offset
56 is not interpreted as a version-2 selector-buffer size. Buffer sizes are exposed
only for a header whose version is exactly 2. This avoids treating an observed
version-4 address-like value as an allocation size.

No new cache magic, fixed subcache count, dispatcher-copy count, release-number
switch, Rosetta boot argument, or active-environment assumption is introduced.

## Implementation

- Headers are zero-extended only through `mappingOffset`; later optional fields
  cannot accidentally read bytes from the first mapping. Array bounds are checked
  before allocation/indexing, and modern empty image tables remain empty.
- Subcache-entry width follows the header generation (`cacheSubType` presence),
  matching IDA. Suffixes and UUIDs are validated. VM mappings are sorted and checked
  for overlap before binary-search lookups; reads cannot escape a mapping into
  unrelated file bytes. Explicit copying can cross adjacent mappings/subcaches.
- Image segments are copied through their VM mappings into nonoverlapping output
  offsets. Shared LINKEDIT is read through its own source VM range and rebuilt,
  without copying the entire shared table. Equal file offsets in different
  subcaches no longer alias in the output buffer. This addresses the Safari and
  SafariSharedUI load-command corruption reported in this task.
- Slide v2/v3/v5 chains are read from the source cache, including chain heads in
  neighboring images. Only the selected image's file-backed slots are written.
  v2 page extras and x86_64 pointers are decoded. Each chain is page-bounded.
- v5 decoding separates the 34-bit target, high byte at bit 34, and next field at
  bit 52. v3 plain pointers separate the low 43 address bits and stored high byte.
  The v3/v5 base field is at byte offset 16, after alignment padding.
- Stub recognition validates register dataflow for ADRP/LDR/BR, authenticated
  forms, direct ADRP/ADD/BR, ADR/MOVZ/shifted-ADD/BR, and compact selector stubs.
  Referenced sectionless islands, selector strings, pointer slots, and dispatcher
  code are retained at their original VM addresses. Dispatcher images are found
  by install name rather than a hardcoded numerical suffix range.
- Relative Objective-C method entries are converted to ordinary 24 B absolute
  entries before encoding flags are cleared. `0x20000000` denotes base-relative
  **types**, not selector uniquing. Classes, metaclasses, categories, protocols,
  properties, ivars, selector references, and their strings are reconstructed in
  `__EXTRA_OBJC`. The historical flag constant remains as a deprecated API alias.
- When load-command padding is insufficient, `__DYLEX_HDR` maps a separate analysis
  header. Original `__TEXT` VM addresses, instructions, function-start deltas,
  and existing symbol section ordinals remain unchanged. This is an analysis
  container layout, not a claim of dyld execution compatibility.
- Discovery keeps full and reduced Rosetta products separate. No-argument commands
  retain the native system-cache default. An ambiguous `--arch x86` reports full
  paths instead of silently choosing. Staged `Incoming` and DriverKit trees are
  excluded from parent discovery but remain usable through explicit paths.
- Address lookup checks actual segment ranges; cache-owned gaps are reported as
  mappings, with decoded stub targets when recognized.

## Assumption register and falsification probes

| ID | Assumption and dependent behavior | Probe / outcome |
|---|---|---|
| A1 | Later optimization headers retain the common 56 B prefix. Modern selector resolution depends on this; unknown trailing layouts are unused. | Verified in local IDA source and all three live version-4 products. A changed prefix would require a new decoder. Tests poison the v4 extension and confirm it is not used as sizes. |
| A2 | Matched stub instruction dataflow describes an island or selector trampoline. Supplemental imports depend on this. | Tests use assembler-produced instruction words, negative ADR displacement, maximal MOVZ immediate, truncated forms, mismatched registers, and rejection of BL as a tail stub. A dedicated island mapping is required for a bare B. |
| A3 | A cache is a static snapshot. Tagged list-of-lists are expanded with all constituent lists for analysis. | Signed 48-bit list offsets and nonzero 16-bit image indexes are tested. Runtime loaded-image filtering is not reproduced. |
| A4 | The deliverable is an analysis Mach-O, with original code addresses preserved. Supplemental segments and absolute metadata depend on this. | All 26 Safari outputs were reparsed; their original `__text` bytes and class-list pointers were checked against source. Runtime execution and arbitrary third-party loader behavior are unknown. |
| A5 | Backward compatibility is established for tested field layouts, not every historical OS image. | Fixtures cover short legacy headers, v1/v2 subcache records, legacy objc_opt v16, modern ObjC v1/v2/v4, absolute/indirect/self-relative/global-base methods, and slide v2/v3/v5. A real pre-27 cache was not available for this validation. |

Malformed table extents, overlapping cache mappings, invalid subcache UUIDs,
truncated optimization headers, unsupported pointer slide encodings, invalid
method entry sizes, and chains leaving their page return errors. Undocumented
version-4 trailing fields and complete runtime reconstruction are outside the
implemented format contract.

## Algorithms and bounds

Let `M` be mapping count, `I` image count, `C` scanned instruction count, `B`
visited branch/stub targets, `P` slide-chain slots on intersecting pages, and `N`
visited Objective-C records/string bytes.

```text
load cache:       validate tables; sort mappings; reject overlaps
resolve VA:       binary search mapping; check full requested interval
resolve selector: header_VM + selector_base_offset + signed_method_offset
resolve type:     selector_base + signed_type_offset, when flag 0x20000000 is set
                  otherwise type_field_VM + signed_type_offset
resolve IMP:      IMP_field_VM + signed_IMP_offset
restore methods:  decode source entry; copy strings; emit three absolute u64s
follow slide:     visit source chain from page head; write only owned slots
retain islands:   scan code branches; validate stub; retain mapped dependencies
```

Mapping setup costs `O(M log M)` time and `O(M)` space; VA reads cost `O(log M)`.
Selector/type/IMP address arithmetic is `O(1)` time and space. Slide processing is
`O(P (log M + log S))`, where `S` is output segment count, plus page-set construction;
it does not walk every cache page. Stub import uses sorted image addresses,
`O(I log I + C + B(log I + log M))` plus dispatcher-command parsing, range copying,
and at most 64 hops per followed chain. Retained data is bounded by selected source
mapping spans and the 32-bit Mach-O file-offset limit. Metadata serialization uses
address memoization; strings and ordinary object records are copied once per
source address. Tagged list expansion additionally costs the number of constituent
list entries visited. Output metadata allocation and address addition are checked.

Branch displacement units are bytes: B/BL use signed 26-bit immediates multiplied
by 4, yielding `[-134217728, 134217724] B`. ADRP uses signed 21-bit page displacement
multiplied by 4096. The tested far stub adds `imm16 × 2^21 B`; its maximal addend is
`65535 × 2097152 B = 137436856320 B`. This instruction interpretation does not
introduce an on-disk relocation kind.

## Validation

Default tests: **45 tests and one doctest passed**, with the live-cache test
explicitly ignored unless requested. `cargo fmt --check` and `git diff --check`
pass. Clippy completes with pre-existing repository warnings; there is no claim
of a warning-free baseline.

Live checks on build 26A5425a:

- Safari filter: **26/26** successful extractions, including Safari and
  SafariSharedUI. Four-job debug extraction took **1.33 s** in the measured run;
  this is an observation, not a benchmark guarantee.
- Independent structural checks covered **313 segments** and **230156 symbols**:
  load-command extents, section/file bounds, nonoverlapping VM ranges, symbol
  string indexes, and symbol section indexes. `otool -l` reported no issues for
  any of the 26 files.
- The committed opt-in test verified byte-for-byte preservation of every original
  Safari `__text` section and decoded class-list pointers for all 26 images.
- Native libobjc and Foundation extracted successfully. `otool -ov` decoded the
  CloudKitAuthenticationPlugin class/method names, type strings, and IMPs from the
  reconstructed metadata.
- The same opt-in code/pointer validation passed for libobjc from both full and
  reduced x86 caches.

Reproduce without distributing Apple cache files:

```sh
cargo test
DYLEX_TEST_CACHE=/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e \
  cargo test --test cache_compat live_cache_extraction -- --ignored --nocapture
# For either Rosetta main file, additionally set:
# DYLEX_TEST_FILTER=libobjc.A.dylib
```

The live test uses a temporary directory and removes its extracted files on
completion. The installed release CLI was also tested with
`dylex extract -f Safari -j 4 -v 2`, without an architecture flag: 26/26 files,
exit status 0, 1.21 s, and all 26 `otool -l` checks passed. Task-generated
extraction files were removed after verification.

## Provenance

The local IDA tree was inspected read-only at commit
`52c649bbf78f43755d2f761cef567bd51ebcd839`. Source paths and SHA-256 fingerprints
record the actual inspected files, including any working-tree differences:

| IDA source | Evidence | SHA-256 |
|---|---|---|
| `fmt/dsc/shared_cache_file_t.cpp` | Header-generation subcache entries, cache-owned stub mappings | `dfa41ff44988a026485975f4705cbe00e32c76837928b2a9373a331fe0bf8bfd` |
| `ldr/dsc/dsc.cpp` | Cache-header-relative selector base; legacy objc_opt v16 fallback | `5d3b70f6cd409dd6d1dd1e71297913d57bb852047f826404b8263bcec51105df` |
| `fmt/dsc/dyld_cache_type_decls.cpp` | ObjC optimization prefix and version-2 extension | `12ccae4c8d0ee495f890d5df71cfdd2487acbbe91ab4d8cbea14fe4503a9a921` |
| `plugins/objc/objc_runtime.cpp` | Method flags, type/selector bases, signed list offsets | `ae893ae001632870ed7df476850ff6017dc9e052408bdd60b5c52ae1fc657884` |
| `module/arm/emu.cpp` | Pattern-based recognition of selector stubs outside image sections | `99c80937a6bcd687a303f51a44302abc84738d9d545ef9ba229046e20e56e42e` |

Primary published references used for established layouts, not as proof of the
Golden Gate release's complete implementation:

- [Apple dyld_cache_format.h](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/dyld_cache_format.h): legacy headers and slide structures.
- [Apple fixup-chains.h](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h): arm64e shared-cache pointer bitfields.
- [Apple DyldSharedCache.h](https://github.com/apple-oss-distributions/dyld/blob/main/common/DyldSharedCache.h): ObjC optimization prefix and v2 extension.
- [Apple objc-runtime-new.h](https://github.com/apple-oss-distributions/objc4/blob/main/runtime/objc-runtime-new.h): Objective-C metadata structures and tagged relative lists.
- [Hex-Rays IDA 9.4 release](https://hex-rays.com/blog/ida-9.4-release-a-new-dyld-shared-cache-swift-analysis-new-teams-add-on-and-more-): published iOS 27 DSC support.

The Apple OSS snapshot predates Golden Gate. Golden Gate-specific conclusions
above come from the local IDA implementation and measured cache contents.

## Bounded scope findings and delivery checks

- **High impact:** output file-offset aliasing was a distinct corruption source;
  changing stub recognition alone would not fix the reported Safari failures.
- **High impact:** flags and slide bitfields encode data representation. Clearing
  or masking them incorrectly can produce plausible but wrong analysis results.
- **Medium impact:** architecture alone no longer identifies a Rosetta product;
  discovery exposes paths without changing machine configuration.
- **Medium impact:** a separate analysis-header segment expands file size but
  preserves PC-relative code. Full runtime reconstruction and experimental merged
  extraction remain outside the verified contract.
- **Low impact:** version-4 trailing header fields remain available in source
  bytes for future investigation; the implementation does not guess their meanings.

QG1: no normative judgment required. QG2: assumptions and falsification probes
registered. QG3: normal extraction, discovery, metadata, stub, and compatibility
requirements covered with explicit mode boundaries. QG4: integer byte arithmetic
and bounds checked. QG5: unknown extensions excluded from the parsing contract;
malformed tested inputs fail explicitly. QG6: local source fingerprints, primary
references, and live evidence recorded. QG7: scope findings and impact recorded.
