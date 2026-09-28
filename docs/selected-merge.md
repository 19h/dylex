# Address lookup, explicit-image merging, and runtime inference

Observed and tested on macOS 27.0 build **26A5425a**, 2026-09-14. Section
counts beyond 255 were validated on macOS 27.2 build **26B5091g**, 2026-09-28.
All addresses below are **unslid virtual byte addresses** from those caches, not
addresses assumed to apply to another build.

## Result and usage

`lookup` follows recognized cache-owned ARM64 trampolines until it finds an
image segment. It prints the full image path, segment, symbol when present in
nlist/export tables, and commands for extraction and selected merging. It stops
on cycles, after 64 hops, at an unknown trampoline, or outside a mapping. Shared
LINKEDIT is excluded from image ownership. A nearest preceding symbol is labeled
as such; its extent is unknown.

| Input | Decoded target | Image | Exact symbol |
|---|---|---|---|
| `0x2480895f0` | `0x1806cf570` | `/usr/lib/system/libdispatch.dylib` | `_dispatch_once` |
| `0x2480896b0` | `0x180410d48` | `/usr/lib/libobjc.A.dylib` | `_objc_retainAutoreleaseReturnValue` |

```sh
dylex lookup 0x2480895f0
dylex extract -i GeoServicesCore \
  --merge-image libdispatch.dylib \
  --merge-image libobjc.A.dylib \
  -o GeoServicesCore.selected
```

`--merge-image` is repeatable. Selection includes exactly the primary image and
canonicalized additions, in first-occurrence order. Exact paths take precedence,
then exact basenames, then unique substrings. Ambiguous queries list candidate
paths. Duplicates are removed. Missing images are errors before output creation.
No dependency-list traversal occurs. Shared support imports can still retain
referenced trampolines/dispatcher code and strings; this is distinct from
selecting additional whole images.

The new mode cannot be combined with `--merge-deps`, `--merge-depth`,
`--with-deps`, or `--filter`. The original automatic `--merge-deps` relocation
pipeline remains available and experimental. Existing IDA databases do not
change when the CLI is updated; load the new extraction into a fresh database.

## Runtime inference and preview

```sh
dylex extract -i GeoServicesCore --merge-runtime --merge-plan
dylex extract -i GeoServicesCore --merge-runtime
```

`--merge-runtime` scans the primary image and any explicit `--merge-image`
additions. ARM64 B/BL instructions outside data-in-code records and declared
pointer sections provide reference evidence. Recognized cache islands and local
stub sections are followed, with cycle detection and a 64-hop bound. A target
inside an ordinary function of an unselected image does not cause its body to be
followed. Inferred images are not recursively scanned.

The runtime policy includes `/usr/lib/system/*.dylib`, `/usr/lib/libSystem.B.dylib`,
`/usr/lib/libobjc.A.dylib`, `/usr/lib/libc++.1.dylib`, `/usr/lib/libc++abi.dylib`, and
`/usr/lib/swift/libswift*.dylib`. Arbitrary libraries/frameworks require explicit
selection. Pointer-based inference works on supported 64-bit architectures;
ARM64 instruction scanning is not applied to x86. Computed targets without static
pointer evidence remain unknown.

Each candidate has a count of distinct reference sites and an example source
image, referring VA, initial target VA, and final target VA. `--merge-plan` prints
the selection/evidence and creates no output. It requires `--merge-runtime` or
`--merge-image`.

The live GeoServicesCore plan identifies ten runtime images and 461 reference
sites: libobjc, libdispatch, libsystem_blocks, libsystem_c, libsystem_kernel,
libsystem_malloc, libsystem_platform, libsystem_trace, libunwind, and libxpc.
The merged set comprises 11 images. Its 271 original section records contain 45
unused empty markers; removing those and remapping ordinals yields 226 retained
original sections. Populated sections and symbol-referenced empty sections remain.

Adding `--merge-image GeoServices` as a second root infers 29 runtime images on
26B5091g. The 31 selected images have 686 populated sections, 405 of them
referenced by symbols, so no ordering fits every symbol-bearing section into
`n_sect`. The output retains all of them: 724 sections, including support and
restored ObjC sections, and 200 segments in a 278 MB file.

## Implementation contract

- Materialize each selected image through VM mappings, decode slide pointers,
  and rebuild its LINKEDIT. Preserve original instruction bytes and VAs.
- Assemble all original segments and sections into one analysis Mach-O, keeping
  the primary's segment names and naming additions `__M1_*`, `__M2_*`, etc.
  A separate `__DYLEX_HDR` supplies load-command capacity. Synthetic LINKEDIT
  occupies unused addresses below the cache; restored ObjC data occupies unused
  addresses above it. Segments must not overlap.
- Retain every populated and symbol-referenced section; section count is not
  limited. `n_sect` is an 8-bit ordinal with zero reserved, so ordinals 1–255
  are written exactly. A symbol in a later section gets the first populated
  exact-ordinal section with the same name and flags, else the same section
  type and instruction attributes, else the first populated section. `n_value`
  remains exact and never lies inside the hinted section. `NO_SECT` and `N_ABS`
  are not used for these symbols (see S9).
- Remap nlist section ordinals and indirect-symbol indexes. Stably group local,
  external-definition, and undefined symbols. Undefined imports use flat lookup
  rather than source-image dylib ordinals; prebound undefined entries become
  ordinary undefined entries. `N_INDR.n_value` is a string-table index and is
  rewritten in both the ordinary LINKEDIT optimizer and selected merge.
- Preserve function starts as section-defined labels when no symbol already
  names the address. Each start is found by binary search over its image's
  populated sections. This represents dependency functions below the primary
  `__TEXT`, which a primary-relative unsigned delta stream cannot encode.
- Combine data-in-code records and remap their file offsets. Discard stale
  runtime binding/export/fixup streams; keep symbol tables for analysis.
- Import referenced cache support and restore Objective-C metadata once over the
  assembled image. Pointer memoization therefore applies across selected images.
- Fail before writing on overlapping segments, malformed symbol/alias indexes,
  unsupported section relocations, or format-limit violations. Empty sections
  without nlist references are omitted and every source section ordinal is
  remapped. File offsets are limited by their 32-bit Mach-O fields; the selected
  byte total is checked before payload copying.

Outputs are static-analysis containers. Runtime loading, code signing, and
complete resolution of unselected external targets are outside this contract.
Separate legacy `.symbols` tables are not an additional lookup symbol source;
if neither nlist nor export entries name the location, its symbol is unknown.

## Assumption register and falsification probes

| ID | Assumption; dependent result | Stress test / falsification probe |
|---|---|---|
| S1 | Input addresses are unslid and belong to the selected cache snapshot; lookup results above depend on this. | Read the exact instruction words and decode both targets in the live cache. Mapping end bounds and shared-LINKEDIT exclusion have fixtures. A slid address or different build can resolve differently. |
| S2 | Preserving source VAs preserves PC-relative relationships for selected code; the selected merge depends on this. | Compare every selected `__text` byte to source, require both island and final-target addresses to map, and reject VM overlaps. Relocating a dependency would falsify this condition. |
| S3 | Analysis consumers accept a separate header segment; the container layout depends on this. | Reparse all load commands, sections, and symbols; inspect with Apple's `otool`. Runtime loading is unknown and not inferred from these checks. |
| S4 | A preceding symbol is only a name anchor; nearest-symbol output depends on this distinction. | Query exact entry and entry+4 in fixtures, verify the label and offset; do not claim function containment without a size. |
| S5 | Source Mach-O tables obey documented nlist and indirect-symbol semantics; symbol remapping depends on this. | Fixtures combine aliases, undefined/prebound imports, synthetic function starts below the primary, and per-image indirect tables; poisoned indexes fail before output creation. |
| S6 | Automatic dependency relocation is a separate mode; this validation covers explicit selection. | CLI rejects mixed selection modes. The legacy automatic merge's instruction-relocation completeness remains unknown. |
| S7 | Runtime inference is a bounded static-reference analysis, not runtime call-graph completeness. | Tests exclude unreferenced libraries, framework targets, embedded data, and transitive runtime references; explicit additions become scan roots and pointer slots count as evidence. Register-only/computed targets remain unknown. |
| S8 | An empty section without any nlist references is a removable marker. | A fixture merges 400 source section records into three retained sections, preserves an explicitly referenced empty section, checks remapped ordinals, and compares code bytes. The live 271-record runtime set passes after compaction. |
| S9 | Analysis consumers place nlist symbols by `n_value`; `n_sect` past 255 is a same-kind hint. Retaining more than 255 sections depends on this. | Synthetic 300-section Mach-Os with symbols past 255 encoded as exact-wrapped, clamped, same-kind, cross-kind, `NO_SECT`, and `N_ABS`. **IDA 9.4** names every `N_SECT` variant by address and classifies code/data by the containing segment; it moves `N_ABS` symbols to an ABS segment and drops their names. **LLDB** resolves a nonzero hint to the section containing the address, with the correct code/data type; it drops `N_SECT` symbols with `NO_SECT`. Fixtures check exact ordinals through 255, same-name hints after, and fallback order. Tools that trust `n_sect` without checking the address print the hinted section name (for example, `nm -m`). |

## Validation

- **60 tests and one doctest pass**. Three live-cache tests are opt-in. On
  26B5091g, the two opt-in tests pinned to 26A5425a addresses fail identically
  with and without the section-ordinal change; the runtime-merge test passes.
- Fixtures cover canonical selection/deduplication/ambiguity, cache-owned and
  image-owned addresses, exact/nearest symbols, cycle and hop limits, preserved
  branches/island instructions, unselected image exclusion, symbol aliases,
  indirect-table remapping, prebound undefined symbols, unnamed function starts,
  malformed indexes, and overlapping segments.
- Live native selection: GeoServicesCore + libdispatch + libobjc passes bytewise
  comparison of every original `__text` section, VM nonoverlap, segment/section
  extent checks, symbol string/section indexes, and inclusion of both screenshot
  islands and their final targets. Ordinary libobjc extraction also passes its
  existing live code/Objective-C-root checks after the alias fix.
- `otool -l` and `otool -ov` accept the native three-image output.
- Targeted analysis in a fresh **IDA 9.4** database of the installed runtime
  output resolves `0x2480895f0` as `j__dispatch_once` and `0x2480896b0` as
  `j__objc_retainAutoreleaseReturnValue`. Decompiling `GEOGetTileLoadingLog`
  yields the named dispatch call and Objective-C return call, with neither
  `MEMORY[...]` nor `JUMPOUT`. Full whole-file autoanalysis was not required for
  this targeted check; compiler-generated return-address checks remain visible.
- Runtime inference: all 11 images pass `__text` byte comparison, structural and
  symbol checks, and mapping checks for the inferred targets. The installed CLI
  executed the user's exact `dylex extract -i GeoServicesCore --merge-runtime`
  command in a temporary directory: exit 0, **131756032 B** output, measured
  **0.16 s**. Both `otool -l` and `otool -ov` passed. Timing is one observation.
- Runtime fixtures cover pointer evidence, local/cache stubs, data-in-code
  exclusion, nonrecursive selection, explicit roots, policy boundaries, and a
  preview that does not write. A 400-section fixture verifies empty-marker
  compaction and retention of referenced empty sections. A second fixture keeps
  400 populated sections, hints symbol and function-start ordinals past 255,
  and compares their bytes.
- Beyond 255 sections (26B5091g): the 31-image command
  `dylex extract -i GeoServicesCore --merge-runtime --merge-image GeoServices`
  exits 0 in **1.26 s**, measured once. Of its N_SECT symbols inside retained
  sections, 320907 have exact ordinals, 30188 same-name hints, and 13 same-type
  hints. None has `NO_SECT`, and no hint contains its symbol's address. The
  remaining 15780 are symbols at addresses outside retained sections, mostly
  `objc_msgSend$` stubs in emptied `__objc_stubs`, as in earlier outputs.
  `otool -l` and `nm -m` accept the file. In a fresh IDA 9.4 database, 752
  segments load. Sampled names apply equally for exact and hinted sections.
  Unmatched samples are aliases at shared addresses. `GEOGetTileLoadingLog`
  decompiles with named `j__dispatch_once` and
  `objc_retainAutoreleaseReturnValue` calls, with libdispatch now past
  ordinal 255. `xpc_dictionary_get_string` (libxpc, image 30) and `dispatch_once`
  decompile with named callees. The 11-image runtime merge and the three-image
  selected merge are byte-identical to the previous build's output.
- Full and reduced Rosetta products each successfully merge libdispatch with
  libsystem_blocks; `otool -l` passes. Each measured output is **638976 B**.
- The measured native two-image output is **144531456 B**; the three-image output
  is **254607360 B**. The shared-support importer coalesces ranges within a cache
  mapping, so intermediate strings/islands can dominate file size. These are
  observations from this build, not size guarantees.
- `cargo fmt --check`, `git diff --check`, and Clippy complete. Clippy reports
  repository warnings; no warning-free baseline is asserted.

```sh
cargo test --locked --offline
DYLEX_TEST_CACHE=/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e \
  cargo test --test cache_compat live_selected_merge -- --ignored --nocapture
```

The opt-in test creates and removes its output in a temporary directory.

## Algorithms, bounds, and provenance

Let `I` be cache image count, `H <= 64` the number of followed trampolines, `S`
the number of selected sections/segments, `N` symbol count, `F` function-start
count, `B` materialized bytes, and `Q` selection-query count.

```text
resolve selection: exact path -> exact basename -> unique substring -> deduplicate
lookup: owner by segment -> symbol anchor; otherwise decode stub -> repeat
merge: preflight -> materialize/decode -> preserve VM segments -> remap symbols
       -> retain support -> restore ObjC -> compact file offsets -> write
```

Selection uses `O(Q I)` matching time and `O(Q)` retained paths. Lookup scans
image segment commands for each hop, plus the terminal image's nlist/export
entries; memory includes the parsed header, terminal symbols/trie and at most
64 visited addresses. Runtime inference builds a sorted segment ownership index
with prefix maxima (`O(R log R)` time, `O(R)` space for `R` cache segments), scans
source instructions/pointer slots, memoizes each unique target, and uses bounded
stub traversal. Each ownership query is `O(log R + K)` for `K` overlapping ranges;
normal nonoverlapping ranges have `K = 1`. Data-in-code exclusion checks its
recorded intervals per instruction. Candidate paths are sorted for stable output. Merge uses `O(B + N log N + S² + F log S)` time before the
existing slide/support/ObjC stages and `O(B + N + S)` memory, with multiple
materialized copies contributing to the constant factor. Source-pointer,
trampoline and metadata-stage bounds are described in
[cache compatibility](cache-compatibility.md). All address/offset arithmetic is
in integer bytes. No floating-point error bounds apply to those exact fields.

Primary provenance:

- Local live cache bytes and Mach-O symbol tables produce the two address/name
  results; no release-note inference is used.
- Apple's installed SDK `mach-o/nlist.h` defines `N_INDR.n_value`, `n_sect`, and
  `DYNAMIC_LOOKUP_ORDINAL`; `mach-o/loader.h` defines segment/section and symbol
  table commands. SDK location used:
  `/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk/usr/include/mach-o/`.
  SHA-256: `nlist.h` =
  `7614a0c4f918b19b5a95cdf6202140b668c9a34e0ebaa9583645614061990d25`;
  `loader.h` =
  `5862aeb7fbf183453080bc887c0d502fe25a86ff5bd81291bbcc408bd7fe6e74`.
- Relevant source implementation: `src/dyld/lookup.rs`,
  `src/converter/selected.rs`, `src/converter/runtime.rs`, `src/converter/linkedit.rs`, and
  `tests/cache_compat.rs`. The earlier cache-format provenance remains in the
  compatibility report; unpublished version-4 extensions are not interpreted.

## Bounded scope findings and quality gates

- **High impact [S2]:** selecting fewer images reduces the dependency set, but
  relocating their bytes would still invalidate unrewritten PC-relative code.
  The explicit mode preserves addresses throughout.
- **High impact [S5]:** alias values are not VAs; an apparently valid symbol
  table can otherwise resolve aliases to unrelated strings. The ordinary
  extractor receives the same alias-index correction.
- **Medium impact [S3]:** coalesced cache-support ranges explain why selecting
  a few small dylibs can produce a large analysis file. Sparse support importing
  is a future optimization, not an assumption of this interface.
- **Medium impact [S4]:** nearest-symbol lookup cannot determine function extent;
  the CLI exposes that uncertainty rather than asserting containment.
- **Low impact [S6]:** automatic and explicit merging remain separate modes;
  explicit CLI conflicts prevent accidentally triggering dependency traversal.

- **High impact [S9]:** a 31-image runtime merge was rejected at the 255-section
  check. It has 405 symbol-bearing sections, so neither compaction nor ordering
  could fit it. Hinted ordinals remove the section-count limit; merges that
  already fit produce byte-identical output.
- **High impact [S8]:** counting empty cache-optimizer markers against the nlist
  limit rejected an otherwise representable runtime merge. Referenced-section
  retention and ordinal remapping remove that failure without truncating ordinals.
- **Medium impact [S7]:** direct evidence and preview bound automatic selection;
  this does not claim completeness for computed calls or recursively required code.

QG1: no normative content required. QG2: S1–S8 and probes registered. QG3: target
image identification, explicit selection, runtime inference, preview, and the
reported section-limit failure are covered. QG4:
byte addresses, offsets, counts, and format limits are consistent. QG5: excluded
runtime/legacy-relocation behavior and unknown symbol extents are explicit;
tested malformed inputs fail. QG6: live cache evidence and primary SDK layouts
used. QG7: bounded findings and impact labels recorded.

Task-generated extraction and IDA database files were removed after validation.
