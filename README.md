# dylex

[![Crates.io](https://img.shields.io/crates/v/dylex.svg)](https://crates.io/crates/dylex)
[![Documentation](https://docs.rs/dylex/badge.svg)](https://docs.rs/dylex)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-blue.svg)](https://www.rust-lang.org)

A high-performance dyld shared cache extractor for macOS and iOS, written in Rust.

dylex extracts individual Mach-O binaries from Apple's dyld shared cache with full symbol table reconstruction, pointer rebasing, and proper LINKEDIT optimization. Extracted binaries are suitable for reverse engineering, analysis, and research.

## Features

- **Fast Extraction** - Memory-mapped I/O and parallel processing for maximum speed
- **Automatic Cache Discovery** - Finds system caches automatically on macOS
- **Architecture Selection** - Support for arm64, arm64e, and x86_64 caches
- **Symbol Table Reconstruction** - Rebuilds standalone LINKEDIT with proper symbol tables
- **Pointer Rebasing** - Handles slide info v3/v5 for correct pointer values
- **ObjC Metadata Fixing** - Clears optimization flags for standalone operation
- **Directory Structure Preservation** - Optionally preserves full framework paths
- **Batch Extraction** - Extract multiple images with filters and parallel processing

## Installation

### From crates.io

```bash
cargo install dylex
```

### From Source

```bash
git clone https://github.com/19h/dylex
cd dylex
cargo install --path .
```

## Quick Start

```bash
# List available architectures in the system cache
dylex arches

# Show cache information
dylex info -a arm64e

# List all images containing "UIKit"
dylex list -a arm64e -f UIKit

# Extract a single library
dylex extract -a arm64e -i libobjc.A.dylib -o libobjc.A.dylib

# Extract all MapKit-related frameworks with preserved paths
dylex extract -a arm64e -f MapKit -o ./extracted
```

## Commands

### `dylex extract`

Extract images from the dyld shared cache.

```
Usage: dylex extract [OPTIONS] [CACHE]

Arguments:
  [CACHE]  Path to the dyld shared cache (file or directory).
           If not specified, searches default system locations.

Options:
  -i, --image <IMAGE>           Image to extract (e.g., "UIKit" or full path)
  -f, --filter <FILTER>         Filter images by substring match
  -a, --arch <ARCH>             Architecture (arm64e, arm64, x86_64)
  -o, --output <OUTPUT>         Output path (file or directory)
      --preserve-paths <BOOL>   Preserve directory structure [default: auto]
  -v, --verbosity <LEVEL>       Verbosity (0=quiet, 1=warn, 2=info, 3=debug)
  -j, --jobs <N>                Parallel jobs (default: CPU count)
  -h, --help                    Print help
```

#### Examples

```bash
# Extract single image to specific file
dylex extract -a arm64e -i libobjc.A.dylib -o /tmp/libobjc.dylib

# Extract by full path
dylex extract -a arm64e -i /System/Library/Frameworks/UIKit.framework/UIKit

# Extract all Foundation-related images
dylex extract -a arm64e -f Foundation -o ./foundation_libs

# Extract everything (warning: large!)
dylex extract -a arm64e -f "" -o ./all_binaries

# Extract with verbose output
dylex extract -a arm64e -i CoreFoundation -v 2

# Use custom cache path
dylex extract -a arm64e -i libobjc.A.dylib /path/to/dyld_shared_cache_arm64e
```

### `dylex list`

List images in the cache.

```
Usage: dylex list [OPTIONS] [CACHE]

Options:
  -a, --arch <ARCH>       Architecture to use
  -f, --filter <FILTER>   Filter images by name
  -A, --addresses         Show virtual addresses
  -b, --basenames         Show only basenames (not full paths)
  -h, --help              Print help
```

#### Examples

```bash
# List all images
dylex list -a arm64e

# List with addresses
dylex list -a arm64e -A

# Filter and show basenames
dylex list -a arm64e -f Swift -b

# Count images matching filter
dylex list -a arm64e -f Framework | wc -l
```

### `dylex info`

Display detailed cache information.

```
Usage: dylex info [OPTIONS] [CACHE]

Options:
  -a, --arch <ARCH>   Architecture to use
  -h, --help          Print help
```

#### Example Output

```
Dyld Shared Cache Information
==============================
Path:         /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e
Architecture: arm64e
Images:       3554
Mappings:     22
Subcaches:    2
Total size:   5307.38 MB

Mappings:
  [ 0] 0x0000000180000000 - 0x00000001e6660000 (    1.6G) r-x
  [ 1] 0x00000001e6660000 - 0x00000001e8874000 (   34.1M) r-- [slide]
  ...

Subcaches:
  [ 1] dyld_shared_cache_arm64e.01 (2543.53 MB)
  [ 2] dyld_shared_cache_arm64e.02 (196.12 MB)
```

### `dylex arches`

List available cache architectures.

```
Usage: dylex arches [PATH]

Arguments:
  [PATH]  Directory to search. If not specified, uses system default.
```

#### Example Output

```
Available architectures in /System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld:
  arm64e - dyld_shared_cache_arm64e
  x86_64 - dyld_shared_cache_x86_64
```

### `dylex lookup`

Find which image contains a specific address.

```
Usage: dylex lookup [OPTIONS] <ADDRESS> [CACHE]

Arguments:
  <ADDRESS>   Address to lookup (hex, e.g., 0x180000000)

Options:
  -a, --arch <ARCH>   Architecture to use
  -h, --help          Print help
```

## Default Cache Locations

When no cache path is specified, dylex searches these locations in order:

1. `/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld` (macOS Ventura+)
2. `/System/Library/dyld` (older macOS)
3. `/var/db/dyld`

## Architecture Selection

The `--arch` flag uses substring matching:

| Flag | Matches |
|------|---------|
| `-a arm64e` | `arm64e` only |
| `-a arm64` | `arm64` and `arm64e` |
| `-a x86` | `x86_64` and `x86_64h` |

If multiple architectures match, you'll be prompted to be more specific.

## Output Structure

### Single Image Extraction

By default, single images are extracted to the current directory with their basename:

```bash
dylex extract -a arm64e -i libobjc.A.dylib
# Creates: ./libobjc.A.dylib
```

### Batch Extraction with Filter

When using `-f/--filter`, directory structure is preserved by default:

```bash
dylex extract -a arm64e -f MapKit -o ./extracted

# Creates:
# ./extracted/System/Library/Frameworks/MapKit.framework/Versions/A/MapKit
# ./extracted/System/Library/Frameworks/_MapKit_SwiftUI.framework/Versions/A/_MapKit_SwiftUI
# ./extracted/usr/lib/swift/libswiftMapKit.dylib
# ...
```

Use `--preserve-paths false` to flatten:

```bash
dylex extract -a arm64e -f MapKit -o ./flat --preserve-paths false

# Creates:
# ./flat/MapKit
# ./flat/_MapKit_SwiftUI
# ./flat/libswiftMapKit.dylib
```

## What dylex Does

When extracting an image, dylex performs these operations:

1. **Copies Segment Data** - Extracts __TEXT, __DATA, __LINKEDIT, etc.
2. **Rebases Pointers** - Applies slide info to fix pointer values
3. **Rebuilds LINKEDIT** - Creates standalone symbol table, string table, and other metadata (replaces ~600MB shared LINKEDIT)
4. **Fixes ObjC Metadata** - Clears `OBJC_IMAGE_OPTIMIZED_BY_DYLD` flag
5. **Updates Load Commands** - Adjusts offsets for standalone operation
6. **Optimizes File Layout** - Removes unnecessary padding

## Library Usage

dylex can be used as a library:

```rust
use dylex::{DyldContext, extract_image_with_options, ExtractionOptions};

fn main() -> anyhow::Result<()> {
    // Open the cache
    let cache = DyldContext::open("/path/to/dyld_shared_cache_arm64e")?;
    
    // List images
    for image in cache.iter_images() {
        println!("{}: {:#x}", image.path, image.address);
    }
    
    // Extract an image
    let options = ExtractionOptions::default();
    extract_image_with_options(
        &cache,
        "/usr/lib/libobjc.A.dylib",
        "libobjc.A.dylib",
        options,
    )?;
    
    Ok(())
}
```

## Performance

dylex is designed for speed:

- **Memory-mapped I/O** - No unnecessary copying
- **Parallel extraction** - Uses all CPU cores for batch operations
- **Efficient data structures** - FxHashMap for fast lookups
- **LTO-optimized release builds** - Maximum binary performance

Typical extraction times on Apple M1:
- Single library: ~0.3s
- 100 libraries: ~5s
- Full cache (~3500 images): ~3-5 minutes

## Limitations

- **macOS/iOS only** - dyld caches are Apple-specific
- **Read-only** - Cannot modify or repack caches
- **No code signing** - Extracted binaries need re-signing for execution
- **Stub fixing** - Some inter-library stubs may not be fully resolved

## Comparison with Other Tools

| Feature | dylex | dsc_extractor | DyldExtractor |
|---------|-------|---------------|---------------|
| Language | Rust | C++ | Python |
| Speed | Fast | Medium | Slow |
| LINKEDIT rebuild | Yes | Partial | Yes |
| Slide info v5 | Yes | Yes | Yes |
| Parallel extraction | Yes | No | No |
| Library API | Yes | No | Yes |

## Troubleshooting

### "No dyld shared caches found"

The default cache locations may not exist on your system. Specify the path explicitly:

```bash
dylex info /path/to/cache/directory
```

### "Multiple caches match"

Be more specific with the architecture:

```bash
# Instead of -a arm64 (matches arm64 and arm64e)
dylex info -a arm64e
```

### Extracted binary won't run

Extracted binaries are not code-signed. For research/analysis only:

```bash
# Re-sign for local execution (macOS)
codesign -f -s - extracted_binary
```

### Large extracted file sizes

Some libraries (like libobjc) include large shared ObjC metadata segments. This is expected behavior.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- Inspired by [DyldExtractor](https://github.com/arandomdev/DyldExtractor)
- Apple's dyld source code for format documentation
- The reverse engineering community
