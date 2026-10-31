# Kernelcache support

Kernelcaches use the `dylex kernel` command group (aliases `kc` and
`kernelcache`), which mirrors the dyld commands:

| Command | Purpose |
| --- | --- |
| `dylex kernel locate` | Find boot kernelcaches that match the running kernel (macOS) |
| `dylex kernel info` | Format, encoding, architecture, UUIDs, and outer segments |
| `dylex kernel list` | Image IDs, optionally filtered (`-f`) and with addresses (`-A`) |
| `dylex kernel extract` | Standalone Mach-O files for one (`-i`), several (`-f`, `--search`), or all (`--all`) images |
| `dylex kernel strings` | Literal or hex (`-x`) search, reported like `dylex strings` |
| `dylex kernel lookup` | Owning image, segment, section, and nearest symbol for an address |

Every command except `locate` takes an optional positional `[KERNELCACHE]`:
a raw Mach-O, IMG4/IM4P, LZFSE, or complzss file, recognized by content
rather than by name. On macOS, omitting it uses the running system's boot
kernelcache: the KernelManagement selection, or else the first verified
fallback copy (see [runtime-aware discovery](#runtime-aware-discovery)).

```sh
cargo build --release --locked
./target/release/dylex kernel info
./target/release/dylex kernel list -A
./target/release/dylex kernel extract -i com.apple.security.sandbox -o sandbox.macho
./target/release/dylex kernel extract --all -o ./kernelcache-images
./target/release/dylex kernel strings -f sandbox Seatbelt
./target/release/dylex kernel lookup 0xfffffe0007d342aa

cache=/path/to/kernelcache.release.mac16j
./target/release/dylex kernel extract -i com.apple.kernel -o kernel.macho "$cache"
./target/release/dylex kernel extract --search Seatbelt -o ./matching-images "$cache"
```

Image IDs, such as `com.apple.kernel`, identify outputs. `--image` first
matches an exact ID, then accepts a unique substring; an ambiguous query fails
and lists its candidates. `--filter` is a case-sensitive ID substring and
combines with `--search`. A single image is written to `--output`, into
`--output` if it is an existing directory, or to its ID in the current
directory. Several images are written as `<directory>/<ID>`, defaulting to
`./extracted`. Batch extraction uses Rayon; `--jobs` sets its thread count, and
a failed image makes the command fail after the others are written. Unsafe IDs
and output collisions are rejected before extraction, and outputs are compared
with the input by file identity, including through hard and symbolic links.

`strings` supports literal and hex needles, ASCII case folding (`-i`), and ID
filtering. Hits use the same format as `dylex strings`: architecture, image ID,
segment and section, address, and the enclosing C string or an escaped byte
snippet. It searches file-backed segments except `__LINKEDIT`; a segment
shared by several images reports its matches under each ID. Matches do not
span segment boundaries. `lookup` reports every owning image, ignoring
`__LINKEDIT`, and prints the command that extracts it; a nearest symbol is a
label and does not establish function extent.

The dyld commands reject kernelcache files with a pointer to `dylex kernel`,
and `dylex kernel` rejects dyld caches likewise. Dependency extraction and
merge modes apply to dyld caches only.

## Runtime-aware discovery

```sh
dylex kernel locate
dylex kernel locate --target com.apple.driver.FairPlayIOKit
dylex kernel locate --target com.apple.driver.FairPlayIOKit --paths-only
dylex kernel locate --verbose
```

`locate` is a macOS command. It obtains `kern.uuid` with
`/usr/sbin/sysctl -n kern.uuid`, then runs
`/usr/bin/kmutil inspect --show-kernel-uuid-only` with `LC_ALL=C`. Executables
and arguments are passed directly, without a shell. The report records each
exit status and captures stdout and stderr separately. The boot-collection
header parser requires an absolute path and a canonical UUID; unrecognized
text or unsuccessful command status is an explicit discovery failure.

For each candidate, Dylex opens the selected file, unwraps/decompresses it,
and reads `LC_UUID` from the outer Mach-O and exact `com.apple.kernel` member.
The outer collection UUID is compared only with the collection UUID advertised
by KernelManagement. The embedded kernel UUID is compared with `kern.uuid`.
When `--target` is given, `kmutil showloaded -b ID` must report that exact bundle
identifier and its UUID must match the exact embedded member's `LC_UUID`.
An unloaded/missing target cannot pass this stronger verification. No substring
matching is used for target identities.

```text
runtime kernel UUID + optional loaded-target UUID
                        |
kmutil selected path --> direct binary identity checks
                        |
                        +-- verified --> record selected match
                        |
                        +-- failed ----> preserve failure; enumerate fallback
                                             |
                                             +--> inspect every candidate
                                                       |
                                                       v
                               recheck runtime identities; return matching set
```

Fallback traversal visits only these patterns, without following directory
symlinks or hardcoding volume/build identifiers:

```text
/System/Volumes/Preboot/*/boot/*/System/Library/Caches/com.apple.kernelcaches/kernelcache*
/System/Library/KernelCollections/*.kc*
```

A successfully verified system selection distinguishes its path without
enumerating fallback copies. If selection or its verification fails, every
fallback candidate is checked sequentially; all matching copies are returned.
Mismatches, unreadable candidates, and traversal errors remain in the report.
No newest-file heuristic is used. The final runtime identity query must still
agree with the initial one; otherwise previously matching candidates are
invalidated. Runtime selection and UUID checks are observations at discovery
time; later filesystem/runtime changes can invalidate them.

The report lists the running kernel (and target) UUIDs, then each matching
and each rejected candidate with its source (`kmutil boot selection` or
`fallback search`), its collection, kernel, and target UUIDs, and the reason
for any rejection. Discovery issues are printed to stderr as warnings, and
`--verbose` adds every command run with its exit status, stdout, and stderr.
`--paths-only` prints only verified paths on stdout; without a match, the
rejections go to stderr. Zero matches returns a nonzero status. Multiple
matches remain multiple output lines. Search completeness is unknown where
traversal or inspection errors remain. UUID equality establishes build
identity; byte-for-byte integrity and signature validity are untested.

When the other `dylex kernel` commands are run without a path, they use the
first verified candidate: the KernelManagement selection if it verifies,
otherwise the first matching fallback copy. All matching copies carry the same
verified collection and kernel UUIDs. If nothing verifies, the command fails
and lists the discovery issues and rejections.

The library exposes `dylex::kernelcache::discover_kernelcaches(target)`, returning
a `KernelDiscoveryReport` containing runtime identities, candidates, commands,
and issues. `KernelCacheContext::identity(target)` provides direct binary
identities for explicitly supplied offline inputs; discovery itself targets
the running OS. Local command behavior was checked against the installed
`kmutil(8)` manual and captured command output; its text format remains
version-dependent.

Local discovery verified the selected boot collection and the exact loaded
`com.apple.driver.FairPlayIOKit` member by direct binary UUID inspection.
Portable tests cover stale selections, duplicate matching copies, unreadable
candidates/directories, changed text formats, nonzero command status, UUID-role
separation, exact target IDs, unloaded/mismatched targets, and runtime changes.
The complete portable suite passed 129 tests; four live tests remain opt-in.

Fallback traversal visits O(D) directory entries; sorting N candidate paths
adds O(N log N) comparisons. Inspection costs O(B + H)
for total input/decoded bytes B and parsed header bytes H, without decoding
pointer chains. Candidates are inspected sequentially, with O(U) decoding space
for the largest candidate, plus its parsed header storage and O(D + P + C)
enumeration, retained path/report, and command-output bytes. This is not an
integrity measurement.

## Formats

| Input or encoding | Handling | Validation |
| --- | --- | --- |
| Thin little-endian `MH_FILESET` | Read `LC_FILESET_ENTRY`; member offsets are collection-relative | Portable fixtures and supplied arm64e collection |
| Prelinked `MH_EXECUTE`, 32/64 bit | Read `__PRELINK_INFO,__info` or the info segment; use executable source/load addresses | Portable ARM32 and ARM64 fixtures |
| XML prelink metadata | Expand backward `ID`/`IDREF` references; parse decimal/hex integers | Portable fixtures |
| Binary prelink metadata | Parse binary plist | Parser support; no archived binary-plist kernelcache tested |
| IMG4 / IM4P `krnl` or `rkrn` | Select the payload structurally through DER lengths | Synthetic wrappers; local IM4P input |
| LZFSE / LZVN | Validate block framing and declared decoded size; decode with `lzfse` | Synthetic compression and local LZFSE v2 input |
| `complzss` | Decode the 4096-byte dictionary; check exact sizes and Adler-32 | Portable literal-stream and malformed-input fixtures |
| Chained pointer formats 7 / 8 / 11 | Decode ARM64e kernel / 64-bit kernel-cache / x86-64 kernel-cache words | Pointer fixtures; full collection validation for format 8 |

Only cache level 0 is resolved. Chains requiring a different kernel collection,
unresolved imports/binds, unknown pointer formats, and legacy section-based
`__thread_starts`/`__chain_starts` encodings fail extraction explicitly. Listing
and information commands do not require chain decoding. Fat/universal files,
big-endian Mach-O, decryption, and IMG4 signature verification are unsupported.
Decode wrappers/decrypt or thin the input externally where necessary.

Input and decoded/output files are bounded to 1 GiB each. Prelink metadata,
expanded XML, and saved XML references are bounded to 64 MiB each; XML nesting
is bounded to 128 elements. These are implementation resource limits.

## Extraction semantics

```text
container bytes
    |
    +--> wrapper / decompression --> collection Mach-O
                                      |
                                      +--> fileset entries / prelink records
                                      |         |
                                      |         +--> member segments
                                      |
                                      +--> chained fixups --> absolute unslid pointers
                                                |
                                                v
                               private LINKEDIT + rewritten file offsets
                                                |
                                                v
                                     analysis Mach-O output
```

Code addresses, section order, symbol values, and external targets retain their
unslid addresses. File-backed segments are packed with 8-byte alignment. Segment
and section file offsets, relocation-table offsets, symbol/string tables,
indirect symbols, dyld-info extents, function-start blobs, data-in-code entries,
and supported LINKEDIT payloads are rewritten. The shared string table is
reduced to names referenced by the member's symbols, including `N_INDR` names.
Original signatures, split-segment information, and decoded chain commands are
removed. Unknown extraction load commands fail rather than retaining unknown
file offsets. Known unsupported offset-bearing commands also fail explicitly.

Outputs are for static analysis. Compact file alignment and unresolved references
to other images do not reconstruct a bootable kernel or independently loadable
kext. Legacy ordinary relocations are preserved as metadata; extraction does not
perform runtime linking. The legacy root kernel retains its prelink segments.

For processed input bytes B (container plus decoded data), header bytes H, fixup words F, member output bytes E,
and member symbol/string bytes S, opening takes O(B + H) time/space. First
extraction indexes chains in O(F log F) time and O(F) space; subsequent extractions
reuse that index. Each extraction takes O(E + S + K log F) time, where K is the
number of segments, plus copied relocation/LINKEDIT bytes, and O(E + S) working
space. Literal search uses O(T * M) worst-case comparisons for needle length M
over T searched member bytes and O(R) result space for R hits; shared ranges
can be visited once per member.

## Library API

```rust,no_run
use dylex::{KernelCacheContext, StringQuery};

fn main() -> dylex::Result<()> {
    let cache = KernelCacheContext::open("kernelcache.release.mac16j")?;
    println!("{} {} ({} images)", cache.format(), cache.architecture(), cache.images.len());
    for image in &cache.images {
        println!("{:#x} {}", image.address, image.id);
    }

    let sandbox = cache.resolve_image("com.apple.security.sandbox")?;
    std::fs::write("sandbox.macho", cache.extract_image(sandbox)?)?;
    cache.extract_to("com.apple.kernel", "kernel.macho")?;

    let query = StringQuery {
        needle: b"Seatbelt".to_vec(),
        ignore_case: false,
        image_filter: None,
    };
    for hit in cache.search_strings(&query)? {
        println!("{} {:#x} {}", hit.image_path, hit.address, hit.text);
    }
    Ok(())
}
```

`from_bytes` accepts the same encodings as `open`, and `encoding` reports the
container and compression that were removed. `resolve_image` matches an exact
ID, then a unique substring, and returns `Error::AmbiguousImage` otherwise.
`images_containing`, `KernelImage::segment_containing`, and `nearest_symbol`
answer address queries. `search_strings` takes the same `StringQuery` and
returns the same `StringHit` values as `DyldContext::search_strings`, with the
image ID in `image_path`. `extract` and `extract_image` return bytes;
`extract_to` writes an explicitly selected output path.

## Reproducible validation

```sh
cargo test --all-targets --locked
cargo +1.85.0 check --all-targets --locked
DYLEX_TEST_KERNELCACHE="$cache" cargo test --test kernelcache -- --ignored
./target/release/dylex kernel extract --all -o ./kernelcache-images "$cache"
python3 scripts/verify_kernelcache.py "$cache" ./kernelcache-images --report verification.json
```

The Python verifier uses only the standard library and reads the source and
outputs independently of Dylex. It currently targets raw 64-bit filesets and
level-0 chain formats 7/8/11. It verifies full member coverage, segment bytes
excluding rewritten headers, decoded pointers, section fields, symbol names and
values, indirect-symbol and relocation tables, and supported LINKEDIT extents.
It verifies the input SHA-256 again after reading outputs.

The supplied collection had SHA-256
`d5f0b4d49520744ebcd777a66be7ff69225a8ef2879773340854eab0b1370afe`,
126205952 input bytes, 362 members, and format-8 fixups. Independent verification
passed for 92259637 non-header segment bytes, 1036413 pointers, 504045 symbols,
and 4746 section records. Total extracted size was 126932592 bytes. Extraction
from a local compressed IM4P payload produced identical SHA-256 values for all
362 outputs. After the module and CLI restructuring, all 362 outputs from a
local IM4P/LZFSE payload were byte-identical to those of the implementation
verified above. The portable suite passed 129 tests (four live tests skipped);
the kernelcache live test was then run explicitly and passed. The release
build and Rust 1.85 checks passed. Clippy reports no warnings in the
kernelcache implementation; strict Clippy remains blocked by existing warnings
elsewhere. This establishes
static extraction fidelity for that collection, not runtime execution or
coverage of every historical kernelcache format.

## Assumption register and bounded findings

| ID | Assumption / dependent result | Stress test or falsification probe |
| --- | --- | --- |
| A1 | Member file offsets use the declared fileset or legacy coordinate system; extraction depends on this | Validate header/segment bounds and compare every output segment against independently parsed source bytes |
| A2 | Level-0 chain targets use this collection's mapped-header base; decoded targets depend on this | Independently decode all chain words; reject nonzero cache levels and binds |
| A3 | Original unslid VAs are the intended static-analysis coordinates | Compare every member segment VM address and symbol value; runtime loadability remains untested |
| A4 | Prelink executable source/load/size fields identify executable members | Exercise image-relative ARM32/ARM64 fixtures, codeless records, XML references, and truncated metadata; archived legacy coverage is unknown |
| A5 | The supplied sample represents one supported modern layout | Exercise all 362 members; do not infer coverage of other OS builds or architectures from this sample |
| A6 | Discovery targets the running OS and its currently loaded target | Compare initial/final runtime UUIDs; offline targets instead require explicit input/identity handling |
| A7 | KernelManagement text identifies a selected boot artifact in the current CLI version | Check command status and strict header parsing; preserve parse failures and independently read binary UUIDs |
| A8 | A matching UUID need not identify a unique filesystem path | Return every matching fallback copy; retain selection evidence where it distinguishes a path |

| Impact | Additional pattern | Consequence |
| --- | --- | --- |
| High | Kexts share large LINKEDIT/string ranges | Per-member symbol/string reconstruction avoids duplicating the entire shared string table |
| High | Format-8 words can begin four bytes before a page boundary | Validate word starts against page bounds and all eight bytes against segment bounds |
| Medium | Auxiliary collections can reference another cache level | Such references require additional collection bases; extraction currently rejects them |
| Medium | Shared segments have multiple member owners | Search and lookup can legitimately produce multiple owners |
| Low | File identities can alias the input through links | CLI output preflight prevents overwriting the selected source file |
| High | On-disk updates can precede the next boot | Preserve selected/runtime mismatches and inspect bounded fallbacks instead of choosing the newest artifact |

## Primary format references

- Apple's [Mach-O loader definitions](https://github.com/apple-oss-distributions/xnu/blob/main/EXTERNAL_HEADERS/mach-o/loader.h): fileset entries and Mach-O offsets.
- Apple's [prelink definitions](https://github.com/apple-oss-distributions/xnu/blob/main/libkern/libkern/prelink.h): executable source/load addresses and prelink metadata keys.
- Apple's [chained fixup layouts](https://github.com/apple-oss-distributions/dyld/blob/main/include/mach-o/fixup-chains.h) and [chain interpretation](https://github.com/apple-oss-distributions/dyld/blob/main/mach_o/ChainedFixups.cpp): pointer bit fields and strides.
- Apple's [LZFSE framing](https://github.com/lzfse/lzfse/blob/master/src/lzfse_internal.h): compressed block headers.
- [RFC 1950](https://www.rfc-editor.org/rfc/rfc1950): Adler-32.
