# macOS CI builds

`.github/workflows/build-macos.yml` runs on pushes, pull requests, and manual
dispatch. Its independent matrix jobs use stable Rust, the committed lockfile,
the default test suite, and a release build. Live-cache tests remain opt-in.

| Architecture | Native runner | Rust target | Artifact |
|---|---|---|---|
| Intel x86_64 | `macos-15-intel` | `x86_64-apple-darwin` | `dylex-x86_64-apple-darwin` |
| Apple Silicon arm64 | `macos-15` | `aarch64-apple-darwin` | `dylex-aarch64-apple-darwin` |

Each job checks the host architecture, verifies the resulting Mach-O architecture
with `lipo`, and runs the binary's version/help commands. Artifacts contain a
tar archive of `dylex` and `LICENSE`, and its SHA-256 checksum. They are retained
for 14 days; GitHub Releases are not created by this workflow.

## Assumptions and falsification checks

| Assumption | Dependent behavior | Check |
|---|---|---|
| “x86” means 64-bit Intel macOS. | Target is `x86_64-apple-darwin`; no i386 build. | Target triple and `lipo -verify_arch x86_64`. |
| GitHub provides the documented native runner labels. | Each architecture runs its tests natively in CI. | `uname -m` must match the matrix; mismatches fail. |
| Build artifacts should not require the CI host's particular CPU. | CI overrides repository `target-cpu=native` with `x86-64` or `generic`. | The same explicit flags are used for tests and release compilation. |
| The current stable toolchain is the CI compiler. | The workflow is not an MSRV test or a byte-reproducible compiler pin. | Compiler/Cargo versions are logged; dependencies use `--locked`. |

GitHub execution and compatibility with every older macOS release are unknown
until exercised on those hosts. Local workflow validation uses `actionlint`;
local target builds and tests do not establish a successful GitHub-hosted run.

Local validation on 2026-09-14 passed with Rust 1.98.1: `actionlint`, release
builds for both targets, and 58 tests plus one doctest per target. The arm64
binaries ran natively; x86_64 binaries ran under Rosetta. The workflow's actual
verification/packaging commands also passed, including archive contents,
executable permissions, and checksum verification. Temporary build/package
directories were removed afterward.

## Bounded findings and provenance

- **High impact:** the repository's native CPU tuning can make distributed
  binaries depend on a runner's instruction set; CI explicitly overrides it.
- **Medium impact:** artifact upload does not preserve executable permissions
  directly. Packaging with tar preserves them through download/extraction.
- **Low impact:** stable Rust and hosted runner images evolve. Version logging
  and locked dependencies make build inputs inspectable, without claiming that
  the complete toolchain is immutable.

Primary references: [GitHub runner labels](https://docs.github.com/en/actions/reference/runners/github-hosted-runners),
[Cargo configuration precedence](https://doc.rust-lang.org/cargo/reference/config.html#buildrustflags),
and [artifact permission behavior](https://github.com/actions/upload-artifact/tree/v7.0.1#permission-loss).
Checkout and artifact-upload actions are pinned to verified v7.0.1 commit IDs.
