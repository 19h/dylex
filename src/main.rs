//! dylex - A high-performance dyld shared cache extractor.
//!
//! Extract individual dylibs or all frameworks from Apple's dyld shared cache.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use tracing::{Level, error, info, warn};
use tracing_subscriber::FmtSubscriber;

use dylex::{
    DyldContext, ExtractionOptions, ImageEntry, StringHit, StringQuery, extract_image_with_options,
    extract_images_with_dependencies,
};

/// Default locations to search for dyld shared caches on macOS.
const DEFAULT_CACHE_PATHS: &[&str] = &[
    // Discover native and both Rosetta products under their separate cryptexes.
    "/System/Volumes/Preboot/Cryptexes",
    // macOS Ventura+ (cryptex)
    "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld",
    // Traditional location
    "/System/Library/dyld",
    // Alternative location
    "/var/db/dyld",
];

/// A high-performance dyld shared cache extractor.
#[derive(Parser, Debug)]
#[command(name = "dylex")]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Extract images from the cache
    Extract {
        /// Image to extract (e.g., "UIKit" or "/System/Library/Frameworks/UIKit.framework/UIKit")
        /// If not specified, requires --filter or --search to select images
        #[arg(short, long)]
        image: Option<String>,

        /// Filter images by substring match (can extract multiple images).
        /// With --search, only images whose path contains this substring are searched.
        #[arg(short, long)]
        filter: Option<String>,

        /// Extract every image that contains this literal string.
        /// Combines with --filter. A range mapped by more than one image is not searched.
        #[arg(
            long,
            conflicts_with = "image",
            conflicts_with_all = ["merge_deps", "merge_images", "merge_runtime", "merge_plan"]
        )]
        search: Option<String>,

        /// Compare ASCII letters without regard to case. Requires --search.
        #[arg(long, requires = "search")]
        ignore_case: bool,

        /// Architecture to use (e.g., "arm64e", "arm64", "x86_64")
        /// Substring match: "arm64" matches "arm64e"
        /// Pass cache paths as the positional [CACHE] argument, without -a
        #[arg(short, long, value_parser = parse_arch)]
        arch: Option<String>,

        /// Output path (file for single image, directory for multiple)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Preserve directory structure (default: true for filter, false for single image)
        #[arg(long)]
        preserve_paths: Option<bool>,

        /// Verbosity level (0=quiet, 1=warnings, 2=info, 3=debug)
        #[arg(short, long, default_value = "1")]
        verbosity: u8,

        /// Number of parallel jobs (default: number of CPUs)
        #[arg(short, long)]
        jobs: Option<usize>,

        /// Extract dependencies (referenced images) along with the target image
        #[arg(long)]
        with_deps: bool,

        /// Maximum depth for dependency extraction (default: unlimited)
        /// Only used with --with-deps
        #[arg(long)]
        deps_depth: Option<usize>,

        /// Merge dependencies into a single output binary
        /// Experimental relocation pipeline; use --merge-image for selected images at cache addresses
        #[arg(long)]
        merge_deps: bool,

        /// Merge only these additional images (repeatable; full path, basename, or unique substring)
        /// Includes the primary image, without traversing dependency lists
        #[arg(long = "merge-image", requires = "image", conflicts_with_all = ["merge_deps", "with_deps", "filter", "merge_depth"])]
        merge_images: Vec<String>,

        /// Infer and merge directly referenced system/ObjC/C++/Swift runtime libraries
        /// Scans the primary and explicit additions; does not recurse into inferred images
        #[arg(long, requires = "image", conflicts_with_all = ["merge_deps", "with_deps", "filter", "merge_depth"])]
        merge_runtime: bool,

        /// Print the selected merge plan and reference evidence without writing output
        /// Requires --merge-runtime or --merge-image
        #[arg(long, requires = "image", conflicts_with_all = ["merge_deps", "with_deps", "filter", "merge_depth"])]
        merge_plan: bool,

        /// Maximum depth for dependency merging (default: 1 = direct dependencies only)
        /// Only used with --merge-deps
        #[arg(long, default_value = "1")]
        merge_depth: usize,

        /// Path to the dyld shared cache (file or directory).
        /// If not specified, searches default system locations.
        cache: Option<PathBuf>,
    },

    /// List all images in the cache
    List {
        /// Architecture to use (e.g., "arm64e", "arm64", "x86_64")
        /// Pass cache paths as the positional [CACHE] argument, without -a
        #[arg(short, long, value_parser = parse_arch)]
        arch: Option<String>,

        /// Filter images by name
        #[arg(short, long)]
        filter: Option<String>,

        /// Show addresses
        #[arg(short = 'A', long)]
        addresses: bool,

        /// Show only basenames
        #[arg(short, long)]
        basenames: bool,

        /// Path to the dyld shared cache (file or directory).
        /// If not specified, searches default system locations.
        cache: Option<PathBuf>,
    },

    /// Search images for a literal string
    Strings {
        /// Literal string to find, such as com.apple.hid.manager.user-access-device
        needle: String,

        /// Only search images whose path contains this substring.
        /// Omit to search every image.
        #[arg(short, long)]
        filter: Option<String>,

        /// Architecture to search, repeatable (for example arm64e or x86_64).
        /// Omit to use the default cache.
        /// Pass cache paths as the positional [CACHE] argument, without -a
        #[arg(short, long, value_parser = parse_arch)]
        arch: Vec<String>,

        /// Search every discovered architecture cache
        #[arg(long, conflicts_with = "arch")]
        all_arches: bool,

        /// Compare ASCII letters without regard to case
        #[arg(short = 'i', long)]
        ignore_case: bool,

        /// Number of parallel jobs (default: number of CPUs)
        #[arg(short, long)]
        jobs: Option<usize>,

        /// Path to the dyld shared cache (file or directory).
        /// If not specified, searches default system locations.
        cache: Option<PathBuf>,
    },

    /// Show cache information
    Info {
        /// Architecture to use (e.g., "arm64e", "arm64", "x86_64")
        /// Pass cache paths as the positional [CACHE] argument, without -a
        #[arg(short, long, value_parser = parse_arch)]
        arch: Option<String>,

        /// Path to the dyld shared cache (file or directory).
        /// If not specified, searches default system locations.
        cache: Option<PathBuf>,
    },

    /// List available cache architectures
    Arches {
        /// Path to the dyld shared cache directory.
        /// If not specified, searches default system locations.
        path: Option<PathBuf>,
    },

    /// Lookup which image contains an address
    Lookup {
        /// Address to lookup (hex, e.g., 0x180000000)
        address: String,

        /// Architecture to use
        /// Pass cache paths as the positional [CACHE] argument, without -a
        #[arg(short, long, value_parser = parse_arch)]
        arch: Option<String>,

        /// Path to the dyld shared cache.
        /// If not specified, searches default system locations.
        cache: Option<PathBuf>,
    },
}

/// Reject cache paths supplied where an architecture filter is expected.
/// Scans n input bytes in O(n) time; accepted filters use O(n) output space.
fn parse_arch(value: &str) -> std::result::Result<String, String> {
    if value.contains('/') {
        return Err(
            "--arch takes an architecture name (e.g., x86_64), not a cache path. \
             Pass the cache path as the positional [CACHE] argument, without -a/--arch."
                .to_string(),
        );
    }
    Ok(value.to_string())
}

/// Information about a discovered cache file.
#[derive(Debug, Clone)]
struct CacheInfo {
    /// Path to the cache file
    path: PathBuf,
    /// Architecture string (e.g., "arm64e")
    arch: String,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Extract {
            cache,
            image,
            filter,
            search,
            ignore_case,
            arch,
            output,
            preserve_paths,
            verbosity,
            jobs,
            with_deps,
            deps_depth,
            merge_deps,
            merge_images,
            merge_runtime,
            merge_plan,
            merge_depth,
        } => {
            setup_logging(verbosity);
            cmd_extract(
                cache,
                image,
                filter,
                search,
                ignore_case,
                arch,
                output,
                preserve_paths,
                verbosity,
                jobs,
                with_deps,
                deps_depth,
                merge_deps,
                merge_images,
                merge_runtime,
                merge_plan,
                merge_depth,
            )
        }
        Commands::List {
            cache,
            arch,
            filter,
            addresses,
            basenames,
        } => cmd_list(cache, arch, filter, addresses, basenames),
        Commands::Strings {
            cache,
            needle,
            filter,
            arch,
            all_arches,
            ignore_case,
            jobs,
        } => cmd_strings(cache, needle, filter, arch, all_arches, ignore_case, jobs),
        Commands::Info { cache, arch } => cmd_info(cache, arch),
        Commands::Arches { path } => cmd_arches(path),
        Commands::Lookup {
            cache,
            arch,
            address,
        } => cmd_lookup(cache, arch, address),
    }
}

fn setup_logging(verbosity: u8) {
    let level = match verbosity {
        0 => Level::ERROR,
        1 => Level::WARN,
        2 => Level::INFO,
        _ => Level::DEBUG,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(false)
        .without_time()
        .finish();

    tracing::subscriber::set_global_default(subscriber).ok();
}

/// Finds the default dyld cache directory by checking known locations.
fn find_default_cache_dir() -> Result<PathBuf> {
    for path_str in DEFAULT_CACHE_PATHS {
        let path = Path::new(path_str);
        if path.is_dir() {
            // Check if it actually contains cache files
            if let Ok(caches) = discover_caches(path) {
                if !caches.is_empty() {
                    return Ok(path.to_path_buf());
                }
            }
        }
    }

    bail!(
        "No dyld shared cache found in default locations:\n  {}",
        DEFAULT_CACHE_PATHS.join("\n  ")
    );
}

/// Gets the cache path, using defaults if not specified.
fn get_cache_path(cache: Option<PathBuf>) -> Result<PathBuf> {
    match cache {
        Some(path) => Ok(path),
        None => find_default_cache_dir(),
    }
}

/// Reads the architecture name from a dyld cache magic field.
fn arch_from_magic(magic: &[u8]) -> Option<String> {
    if magic.len() < 16 || !(magic.starts_with(b"dyld_v0 ") || magic.starts_with(b"dyld_v1 ")) {
        return None;
    }
    let arch = std::str::from_utf8(&magic[7..])
        .unwrap_or("")
        .trim_matches(|c: char| c.is_ascii_whitespace() || c == '\0')
        .to_string();
    if arch.is_empty() { None } else { Some(arch) }
}

/// Reads the architecture from a cache file's magic.
fn architecture_of(path: &Path) -> Result<String> {
    let mut magic = [0u8; 16];
    let mut file = fs::File::open(path)
        .with_context(|| format!("Failed to open cache: {}", path.display()))?;
    file.read_exact(&mut magic)
        .with_context(|| format!("Failed to read cache magic: {}", path.display()))?;
    arch_from_magic(&magic).with_context(|| format!("Not a dyld shared cache: {}", path.display()))
}

/// Discovers all dyld shared cache files in a directory.
fn discover_caches(dir: &Path) -> Result<Vec<CacheInfo>> {
    let mut caches = Vec::new();

    if !dir.is_dir() {
        bail!("Path is not a directory: {}", dir.display());
    }

    let mut pending = vec![(dir.to_path_buf(), 0usize)];
    while let Some((directory, depth)) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let path = entry.path();
            let ty = entry.file_type()?;
            // Bounded traversal; never follow directory symlinks into cycles.
            if ty.is_dir() && depth < 8 {
                // Staged updates and DriverKit caches are separate products.
                // They remain usable when their directory/file is explicit.
                if matches!(entry.file_name().to_str(), Some("Incoming" | "DriverKit")) {
                    continue;
                }
                pending.push((path, depth + 1));
                continue;
            }
            if !ty.is_file() {
                continue;
            }
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.starts_with("dyld_shared_cache_") {
                continue;
            }
            if name.contains('.') && !name.ends_with(".development") {
                continue;
            }
            let mut magic = [0u8; 16];
            if fs::File::open(&path)
                .and_then(|mut f| f.read_exact(&mut magic))
                .is_err()
            {
                continue;
            }
            let Some(arch) = arch_from_magic(&magic) else {
                continue;
            };
            caches.push(CacheInfo { path, arch });
        }
    }
    caches.sort_by(|a, b| a.arch.cmp(&b.arch).then(a.path.cmp(&b.path)));

    Ok(caches)
}

/// Resolves a cache path with optional architecture filter.
///
/// If path is a file, returns it directly.
/// If path is a directory, discovers caches and filters by arch.
fn resolve_cache_path(path: &Path, arch: Option<&str>) -> Result<PathBuf> {
    if path.is_file() {
        return Ok(path.to_path_buf());
    }

    if !path.is_dir() {
        bail!("Cache path does not exist: {}", path.display());
    }

    // Preserve the historical no-argument native-cache default while exposing
    // both Rosetta products to explicit architecture selection and `arches`.
    if arch.is_none() && path == Path::new(DEFAULT_CACHE_PATHS[0]) {
        let native_arches: &[&str] = match std::env::consts::ARCH {
            "aarch64" => &["arm64e", "arm64"],
            "x86_64" => &["x86_64h", "x86_64"],
            _ => &[],
        };
        for native in native_arches {
            let candidate = path.join(format!("OS/System/Library/dyld/dyld_shared_cache_{native}"));
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    let caches = discover_caches(path)?;

    if caches.is_empty() {
        bail!("No dyld shared caches found in: {}", path.display());
    }

    // Filter by architecture if specified
    let matching: Vec<_> = if let Some(arch_filter) = arch {
        caches
            .iter()
            .filter(|c| c.arch.contains(arch_filter))
            .collect()
    } else {
        caches.iter().collect()
    };

    if matching.is_empty() {
        let available: Vec<_> = caches.iter().map(|c| c.arch.as_str()).collect();
        bail!(
            "No cache matches architecture '{}'. Available: {}",
            arch.unwrap_or(""),
            available.join(", ")
        );
    }

    if matching.len() > 1 {
        let available: Vec<_> = matching
            .iter()
            .map(|c| format!("{}: {}", c.arch, c.path.display()))
            .collect();
        bail!(
            "Multiple caches match. Pass an exact cache file path as the positional [CACHE] argument, without -a/--arch. Available:\n  {}",
            available.join("\n  ")
        );
    }

    Ok(matching[0].path.clone())
}

/// Resolves one cache, several architectures, or every discovered cache.
fn resolve_search_caches(
    cache: Option<PathBuf>,
    arches: &[String],
    all_arches: bool,
) -> Result<Vec<CacheInfo>> {
    let cache_path = get_cache_path(cache)?;
    if cache_path.is_file() {
        let info = CacheInfo {
            arch: architecture_of(&cache_path)?,
            path: cache_path,
        };
        if !all_arches
            && !arches.is_empty()
            && !arches.iter().any(|arch| info.arch.contains(arch.as_str()))
        {
            bail!(
                "cache architecture '{}' does not match {}",
                info.arch,
                arches.join(", ")
            );
        }
        return Ok(vec![info]);
    }
    if !cache_path.is_dir() {
        bail!("Cache path does not exist: {}", cache_path.display());
    }
    if all_arches {
        let caches = discover_caches(&cache_path)?;
        if caches.is_empty() {
            bail!("No dyld shared caches found in: {}", cache_path.display());
        }
        return Ok(caches);
    }
    if arches.is_empty() {
        let path = resolve_cache_path(&cache_path, None)?;
        return Ok(vec![CacheInfo {
            arch: architecture_of(&path)?,
            path,
        }]);
    }

    let mut selected = Vec::new();
    for arch in arches {
        let path = resolve_cache_path(&cache_path, Some(arch))?;
        if selected.iter().any(|info: &CacheInfo| info.path == path) {
            continue;
        }
        selected.push(CacheInfo {
            arch: architecture_of(&path)?,
            path,
        });
    }
    Ok(selected)
}

/// Converts an image path to a relative output path.
fn image_to_output_path(image_path: &str, preserve_paths: bool) -> PathBuf {
    if preserve_paths {
        // Strip leading slash and convert to relative path
        let relative = image_path.trim_start_matches('/');
        PathBuf::from(relative)
    } else {
        // Just use the basename
        let basename = image_path.rsplit('/').next().unwrap_or(image_path);
        PathBuf::from(basename)
    }
}

fn images_containing_query(
    cache: &DyldContext,
    query: &str,
    filter: Option<&str>,
    ignore_case: bool,
    jobs: Option<usize>,
) -> Result<Vec<ImageEntry>> {
    if jobs == Some(0) {
        bail!("--jobs must be at least 1");
    }
    if let Some(n) = jobs {
        rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .build_global()
            .ok();
    }
    let image_count = cache.images_for_string_search(filter).len();
    let progress = ProgressBar::new(image_count as u64);
    if image_count > 0 {
        progress.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}",
                )
                .unwrap()
                .progress_chars("#>-"),
        );
        progress.set_message("search");
    }
    let found = cache.images_containing(
        &StringQuery {
            needle: query.as_bytes().to_vec(),
            ignore_case,
            image_filter: filter.map(str::to_string),
        },
        || progress.inc(1),
    )?;
    progress.finish_and_clear();
    if !found.skipped.is_empty() {
        eprintln!(
            "skipped {} images with unreadable Mach-O headers",
            found.skipped.len()
        );
        for (index, reason) in found.skipped.iter().take(20).enumerate() {
            eprintln!("  {reason}");
            if index == 19 && found.skipped.len() > 20 {
                eprintln!("  and {} more", found.skipped.len() - 20);
            }
        }
    }
    Ok(found.images)
}

fn cmd_extract(
    cache: Option<PathBuf>,
    image: Option<String>,
    filter: Option<String>,
    search: Option<String>,
    ignore_case: bool,
    arch: Option<String>,
    output: Option<PathBuf>,
    preserve_paths: Option<bool>,
    verbosity: u8,
    jobs: Option<usize>,
    with_deps: bool,
    deps_depth: Option<usize>,
    merge_deps: bool,
    merge_images: Vec<String>,
    merge_runtime: bool,
    merge_plan: bool,
    merge_depth: usize,
) -> Result<()> {
    let start = Instant::now();
    if search.as_ref().is_some_and(|query| query.is_empty()) {
        bail!("search string is empty");
    }
    if merge_plan && !merge_runtime && merge_images.is_empty() {
        anyhow::bail!("--merge-plan requires --merge-runtime or --merge-image");
    }

    // Get cache path (use default if not specified)
    let cache_path = get_cache_path(cache)?;

    // Resolve cache path with architecture filter
    let resolved_path = resolve_cache_path(&cache_path, arch.as_deref())?;

    info!("Opening cache: {}", resolved_path.display());
    let cache = Arc::new(
        DyldContext::open(&resolved_path)
            .with_context(|| format!("Failed to open cache: {}", resolved_path.display()))?,
    );

    if merge_runtime || !merge_images.is_empty() {
        let primary =
            cache.resolve_image(image.as_deref().context("--merge-image requires --image")?)?;
        let mut paths = dylex::selected_merge_images(&cache, &primary.path, &merge_images)?;
        if merge_runtime {
            let inferred = dylex::referenced_runtime_images(&cache, &paths)?;
            println!(
                "Inferred {} directly referenced runtime images:",
                inferred.len()
            );
            for candidate in inferred {
                println!(
                    "  {} (reference sites: {})",
                    candidate.image_path, candidate.reference_count
                );
                println!(
                    "    {} at {:#x} -> {:#x} -> {:#x}",
                    candidate.source_image,
                    candidate.source_address,
                    candidate.via_address,
                    candidate.target_address
                );
                paths.push(candidate.image_path);
            }
        }
        let output_path =
            output.unwrap_or_else(|| PathBuf::from(format!("{}.merged", primary.basename())));
        println!("Merging {} selected images:", paths.len());
        for (index, path) in paths.iter().enumerate() {
            println!("  [{index}] {path}");
        }
        if merge_plan {
            return Ok(());
        }
        dylex::extract_image_with_selected_images(
            &cache,
            &primary.path,
            &paths[1..],
            &output_path,
            verbosity,
        )?;
        println!(
            "Wrote {} ({:.2} s)",
            output_path.display(),
            start.elapsed().as_secs_f64()
        );
        return Ok(());
    }

    // Handle merge mode - single image only
    if merge_deps {
        let img_name = image.as_ref().ok_or_else(|| {
            anyhow::anyhow!("--merge-deps requires --image to specify the target image")
        })?;

        let img = cache
            .find_image(img_name)
            .with_context(|| format!("Image not found: {}", img_name))?;

        let output_path = output.unwrap_or_else(|| {
            let basename = img.path.rsplit('/').next().unwrap_or(&img.path);
            PathBuf::from(format!("{}.merged", basename))
        });

        info!(
            "Extracting {} with merged dependencies (depth {}) to {}",
            img.path,
            merge_depth,
            output_path.display()
        );

        let options = dylex::MergeExtractionOptions {
            verbosity,
            max_depth: merge_depth,
        };

        dylex::extract_image_with_merged_deps(&cache, &img.path, &output_path, options)
            .with_context(|| format!("Failed to extract with merged deps: {}", img.path))?;

        let elapsed = start.elapsed();
        info!("Extracted merged binary in {:.2}s", elapsed.as_secs_f64());

        return Ok(());
    }

    // Determine what to extract
    let from_search = search.is_some();
    let images_to_extract: Vec<_> = if let Some(ref query) = search {
        images_containing_query(&cache, query, filter.as_deref(), ignore_case, jobs)?
    } else if let Some(ref img_name) = image {
        // Single image mode
        let img = cache
            .find_image(img_name)
            .with_context(|| format!("Image not found: {}", img_name))?;
        vec![img.clone()]
    } else if let Some(ref filter_str) = filter {
        // Filter mode - extract multiple images
        cache
            .iter_images()
            .filter(|img| img.matches_filter(filter_str))
            .cloned()
            .collect()
    } else {
        bail!("Either --image, --filter, or --search must be specified");
    };

    if images_to_extract.is_empty() {
        warn!("No images match the criteria");
        return Ok(());
    }
    if from_search {
        let dest = output.as_deref().map_or_else(
            || "extracted".to_string(),
            |path| path.display().to_string(),
        );
        let count = images_to_extract.len();
        let images = if count == 1 { "image" } else { "images" };
        let verb = if count == 1 { "contains" } else { "contain" };
        eprintln!(
            "{count} {images} {verb} {:?} into {dest}",
            search.as_deref().unwrap_or("")
        );
    }

    // Handle dependency extraction mode
    if with_deps {
        // Must output to a directory when extracting with dependencies
        let output_dir = output.unwrap_or_else(|| PathBuf::from("extracted"));

        info!(
            "Extracting {} images with dependencies to {}",
            images_to_extract.len(),
            output_dir.display()
        );

        // Configure thread pool
        if let Some(n) = jobs {
            rayon::ThreadPoolBuilder::new()
                .num_threads(n)
                .build_global()
                .ok();
        }

        let options = ExtractionOptions {
            verbosity,
            ..Default::default()
        };

        // Collect root image paths
        let root_paths: Vec<String> = images_to_extract
            .iter()
            .map(|img| img.path.clone())
            .collect();

        // Extract with dependencies
        let result = extract_images_with_dependencies(
            &cache,
            &root_paths,
            &output_dir,
            options,
            deps_depth,
            |current, total, path| {
                if verbosity >= 2 {
                    info!("[{}/{}] Extracting: {}", current, total, path);
                }
            },
        );

        match result {
            Ok(stats) => {
                let elapsed = start.elapsed();
                info!(
                    "Extracted {} images ({} root + {} dependencies) in {:.2}s",
                    stats.total_extracted,
                    stats.root_images,
                    stats.dependencies,
                    elapsed.as_secs_f64()
                );
                if stats.failed > 0 {
                    warn!("{} images failed to extract", stats.failed);
                }
                if stats.skipped > 0 {
                    info!("{} images skipped (not in cache)", stats.skipped);
                }
            }
            Err(e) => {
                error!("Extraction failed: {}", e);
                return Err(e.into());
            }
        }

        return Ok(());
    }

    // Determine if we should preserve paths
    let should_preserve = preserve_paths.unwrap_or_else(|| {
        // A search extracts a set, so keep cache paths even for one hit.
        from_search || images_to_extract.len() > 1
    });

    // Single image extraction (without dependencies).
    // --search always writes a directory, including when one image matches.
    if !from_search && images_to_extract.len() == 1 {
        let img = &images_to_extract[0];
        let output_path =
            output.unwrap_or_else(|| image_to_output_path(&img.path, should_preserve));

        // Create parent directories if needed
        if let Some(parent) = output_path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }

        info!("Extracting {} to {}", img.path, output_path.display());

        let options = ExtractionOptions {
            verbosity,
            ..Default::default()
        };

        extract_image_with_options(&cache, &img.path, &output_path, options)
            .with_context(|| format!("Failed to extract: {}", img.path))?;

        let elapsed = start.elapsed();
        info!(
            "Extracted {} in {:.2}s",
            img.basename(),
            elapsed.as_secs_f64()
        );

        return Ok(());
    }

    // Multiple image extraction (without dependencies)
    let output_dir = output.unwrap_or_else(|| PathBuf::from("extracted"));

    info!(
        "Extracting {} images to {}",
        images_to_extract.len(),
        output_dir.display()
    );

    // Setup progress bar
    let progress = ProgressBar::new(images_to_extract.len() as u64);
    progress.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .progress_chars("#>-"),
    );

    // Configure thread pool
    if let Some(n) = jobs {
        rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .build_global()
            .ok();
    }

    // Extract in parallel
    let options = ExtractionOptions {
        verbosity: verbosity.saturating_sub(1), // Less verbose for batch
        ..Default::default()
    };

    let errors: Vec<_> = images_to_extract
        .par_iter()
        .filter_map(|img| {
            let relative_path = image_to_output_path(&img.path, should_preserve);
            let output_path = output_dir.join(&relative_path);

            // Create parent directories
            if let Some(parent) = output_path.parent() {
                if let Err(e) = fs::create_dir_all(parent) {
                    return Some((
                        img.path.clone(),
                        anyhow::anyhow!("Failed to create directory: {}", e),
                    ));
                }
            }

            let result =
                extract_image_with_options(&cache, &img.path, &output_path, options.clone());

            progress.inc(1);

            if let Err(e) = result {
                Some((img.path.clone(), e.into()))
            } else {
                None
            }
        })
        .collect();

    progress.finish_with_message("Done");

    let elapsed = start.elapsed();
    let success = images_to_extract.len() - errors.len();

    if !errors.is_empty() {
        warn!("{} images failed to extract:", errors.len());
        for (path, err) in &errors {
            error!("  {}: {}", path, err);
        }
    }

    info!(
        "Extracted {}/{} images in {:.2}s",
        success,
        images_to_extract.len(),
        elapsed.as_secs_f64()
    );

    Ok(())
}

fn cmd_list(
    cache: Option<PathBuf>,
    arch: Option<String>,
    filter: Option<String>,
    addresses: bool,
    basenames: bool,
) -> Result<()> {
    let cache_path = get_cache_path(cache)?;
    let resolved_path = resolve_cache_path(&cache_path, arch.as_deref())?;

    let cache = DyldContext::open(&resolved_path)
        .with_context(|| format!("Failed to open cache: {}", resolved_path.display()))?;

    for img in cache.iter_images() {
        if let Some(ref f) = filter {
            if !img.matches_filter(f) {
                continue;
            }
        }

        let name = if basenames { img.basename() } else { &img.path };

        if addresses {
            println!("{:#018x}  {}", img.address, name);
        } else {
            println!("{}", name);
        }
    }

    Ok(())
}

fn cmd_strings(
    cache: Option<PathBuf>,
    needle: String,
    filter: Option<String>,
    arches: Vec<String>,
    all_arches: bool,
    ignore_case: bool,
    jobs: Option<usize>,
) -> Result<()> {
    if needle.is_empty() {
        bail!("search string is empty");
    }
    if jobs == Some(0) {
        bail!("--jobs must be at least 1");
    }
    if let Some(n) = jobs {
        rayon::ThreadPoolBuilder::new()
            .num_threads(n)
            .build_global()
            .ok();
    }

    let caches = resolve_search_caches(cache, &arches, all_arches)?;
    let labels = cache_labels(&caches);
    let query = StringQuery {
        needle: needle.into_bytes(),
        ignore_case,
        image_filter: filter.clone(),
    };
    let started = Instant::now();
    let mut total_hits = 0usize;
    let mut images_with_hits = 0usize;
    let mut skipped = Vec::new();

    for (info, label) in caches.iter().zip(labels.iter()) {
        let cache = DyldContext::open(&info.path)
            .with_context(|| format!("Failed to open cache: {}", info.path.display()))?;
        let image_count = cache.images_for_string_search(filter.as_deref()).len();
        if image_count == 0 {
            let where_cache = label.as_deref().unwrap_or(&info.arch);
            if filter.as_deref().unwrap_or("").is_empty() {
                eprintln!("no images in {where_cache} ({})", info.path.display());
            } else {
                eprintln!(
                    "no images match filter {:?} in {where_cache} ({})",
                    filter.as_deref().unwrap_or(""),
                    info.path.display()
                );
            }
            continue;
        }

        let progress = ProgressBar::new(image_count as u64);
        progress.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) {msg}",
                )
                .unwrap()
                .progress_chars("#>-"),
        );
        progress.set_message(info.arch.clone());
        let outcome = cache.search_strings(&query, || {
            progress.inc(1);
        })?;
        progress.finish_and_clear();

        let mut seen_in_cache = std::collections::HashSet::new();
        for hit in &outcome.hits {
            seen_in_cache.insert(hit.image_path.as_str());
            println!("{}", format_string_hit(&info.arch, label.as_deref(), hit));
        }
        images_with_hits += seen_in_cache.len();
        total_hits += outcome.hits.len();
        skipped.extend(outcome.skipped);
    }

    if !skipped.is_empty() {
        eprintln!(
            "skipped {} images with unreadable Mach-O headers",
            skipped.len()
        );
        for (index, reason) in skipped.iter().take(20).enumerate() {
            eprintln!("  {reason}");
            if index == 19 && skipped.len() > 20 {
                eprintln!("  and {} more", skipped.len() - 20);
            }
        }
    }

    let elapsed = started.elapsed().as_secs_f64();
    if caches.len() > 1 {
        eprintln!(
            "{total_hits} matches in {images_with_hits} images across {} caches ({elapsed:.2}s)",
            caches.len()
        );
    } else {
        eprintln!("{total_hits} matches in {images_with_hits} images ({elapsed:.2}s)");
    }
    Ok(())
}

fn cache_labels(caches: &[CacheInfo]) -> Vec<Option<String>> {
    if caches.len() < 2 {
        return vec![None; caches.len()];
    }
    caches
        .iter()
        .map(|info| {
            let name = info
                .path
                .file_name()
                .map(|file_name| file_name.to_string_lossy().into_owned())
                .unwrap_or_else(|| info.path.display().to_string());
            let unique = caches
                .iter()
                .filter(|other| other.path.file_name() == info.path.file_name())
                .count()
                == 1;
            Some(if unique {
                name
            } else {
                info.path.display().to_string()
            })
        })
        .collect()
}

fn format_string_hit(arch: &str, cache_label: Option<&str>, hit: &StringHit) -> String {
    let location = match &hit.section {
        Some(section) => format!("{},{section}", hit.segment),
        None => hit.segment.clone(),
    };
    let text = single_line(&hit.text);
    match cache_label {
        Some(label) => format!(
            "{arch}  {label}  {}  {location}  {:#x}  {text}",
            hit.image_path, hit.address
        ),
        None => format!(
            "{arch}  {}  {location}  {:#x}  {text}",
            hit.image_path, hit.address
        ),
    }
}

fn single_line(text: &str) -> String {
    text.chars()
        .map(|c| match c {
            '\t' | '\n' | '\r' => ' ',
            _ => c,
        })
        .collect()
}

fn cmd_info(cache: Option<PathBuf>, arch: Option<String>) -> Result<()> {
    let cache_path = get_cache_path(cache)?;
    let resolved_path = resolve_cache_path(&cache_path, arch.as_deref())?;

    let cache = DyldContext::open(&resolved_path)
        .with_context(|| format!("Failed to open cache: {}", resolved_path.display()))?;

    println!("Dyld Shared Cache Information");
    println!("==============================");
    println!("Path:         {}", resolved_path.display());
    println!("Architecture: {}", cache.architecture());
    println!("Images:       {}", cache.image_count());
    println!("Mappings:     {}", cache.mappings.len());
    println!("Subcaches:    {}", cache.subcaches.len());
    println!(
        "Total size:   {:.2} MB",
        cache.total_size() as f64 / 1024.0 / 1024.0
    );

    if let Some(opts) = cache.objc_optimization()? {
        println!("ObjC opts:    v{} at {:#x}", opts.version, opts.address);
        println!("Selector base: {:#x}", opts.selector_base);
        if let (Some(selectors), Some(types)) = (opts.selector_size, opts.types_size) {
            println!(
                "ObjC strings: {} selector bytes, {} type bytes",
                selectors, types
            );
        }
    }

    println!("\nMappings:");
    for (i, mapping) in cache.mappings.iter().enumerate() {
        let prot = format!(
            "{}{}{}",
            if mapping.is_readable() { "r" } else { "-" },
            if mapping.is_writable() { "w" } else { "-" },
            if mapping.is_executable() { "x" } else { "-" },
        );
        println!(
            "  [{:2}] {:#018x} - {:#018x} ({:>8}) {} {}",
            i,
            mapping.address,
            mapping.address + mapping.size,
            format_size(mapping.size),
            prot,
            if mapping.has_slide_info() {
                "[slide]"
            } else {
                ""
            }
        );
    }

    if !cache.subcaches.is_empty() {
        println!("\nSubcaches:");
        for (i, sc) in cache.subcaches.iter().enumerate() {
            println!(
                "  [{:2}] {} ({:.2} MB)",
                i + 1,
                sc.path.file_name().unwrap_or_default().to_string_lossy(),
                sc.mmap.len() as f64 / 1024.0 / 1024.0
            );
        }
    }

    if let Some(ref symbols) = cache.symbols_file {
        println!("\nSymbols file:");
        println!(
            "  {} ({:.2} MB)",
            symbols
                .path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy(),
            symbols.mmap.len() as f64 / 1024.0 / 1024.0
        );
    }

    Ok(())
}

fn cmd_arches(path: Option<PathBuf>) -> Result<()> {
    let cache_path = get_cache_path(path)?;
    let caches = discover_caches(&cache_path)?;

    if caches.is_empty() {
        println!("No dyld shared caches found in: {}", cache_path.display());
        return Ok(());
    }

    println!("Available architectures in {}:", cache_path.display());
    for cache in &caches {
        println!("  {} - {}", cache.arch, cache.path.display());
    }

    Ok(())
}

fn cmd_lookup(cache: Option<PathBuf>, arch: Option<String>, address_str: String) -> Result<()> {
    let cache_path = get_cache_path(cache)?;
    let resolved_path = resolve_cache_path(&cache_path, arch.as_deref())?;

    let cache = DyldContext::open(&resolved_path)
        .with_context(|| format!("Failed to open cache: {}", resolved_path.display()))?;

    // Parse address
    let address_str = address_str
        .trim_start_matches("0x")
        .trim_start_matches("0X");
    let address = u64::from_str_radix(address_str, 16)
        .with_context(|| format!("Invalid address: {}", address_str))?;

    let mut current = address;
    let mut visited = std::collections::HashSet::new();
    for _ in 0..64 {
        if !visited.insert(current) {
            println!("  Resolution stopped: stub cycle at {current:#x}");
            return Ok(());
        }
        if let Some(owner) = cache.address_owner(current)? {
            println!("Address {current:#x} is in:");
            println!("  Image: {}", owner.image.path);
            println!("  Segment: {}", owner.segment);
            println!("  Base: {:#x}", owner.base);
            match owner.symbol {
                Some((name, value)) if value == current => println!("  Symbol: {name}"),
                Some((name, value)) => println!(
                    "  Nearest symbol: {name} + {:#x} (symbol extent unknown)",
                    current - value
                ),
                None => println!("  Symbol: unknown"),
            }
            println!(
                "  Extract: dylex extract -i {} {}",
                shell_quote(&owner.image.path),
                shell_quote(&cache.path.to_string_lossy())
            );
            println!(
                "  Merge option: --merge-image {}",
                shell_quote(&owner.image.path)
            );
            return Ok(());
        }
        let Some(mapping) = cache.mapping_for_addr(current) else {
            println!("Address {current:#x} not found in any cache mapping");
            return Ok(());
        };
        println!("Address {current:#x} is in a cache-owned mapping:");
        let path = if mapping.subcache_index == 0 {
            &cache.path
        } else {
            &cache.subcaches[mapping.subcache_index - 1].path
        };
        println!("  Subcache: {}", path.display());
        println!(
            "  Mapping: {:#x}–{:#x}",
            mapping.address,
            mapping.address + mapping.size
        );
        let Some((target, selector)) = cache.cache_stub_target(current)? else {
            println!("  Image: none; no recognized stub target");
            return Ok(());
        };
        println!("  Stub target: {target:#x}");
        if let Some(selector) = selector {
            println!("  Selector: {selector}");
        }
        current = target;
    }
    println!("  Resolution stopped: stub chain exceeds 64 hops");

    Ok(())
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn format_size(size: u64) -> String {
    if size >= 1024 * 1024 * 1024 {
        format!("{:.1}G", size as f64 / 1024.0 / 1024.0 / 1024.0)
    } else if size >= 1024 * 1024 {
        format!("{:.1}M", size as f64 / 1024.0 / 1024.0)
    } else if size >= 1024 {
        format!("{:.1}K", size as f64 / 1024.0)
    } else {
        format!("{}B", size)
    }
}

#[cfg(test)]
mod discovery_tests {
    use super::*;
    fn cache(root: &Path, relative: &str, magic: &[u8]) -> PathBuf {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, magic).unwrap();
        path
    }
    #[test]
    fn separate_rosetta_products_remain_distinct_and_explicitly_selectable() {
        let dir = tempfile::tempdir().unwrap();
        let full = cache(
            dir.path(),
            "Rosetta/System/Library/dyld/dyld_shared_cache_x86_64",
            b"dyld_v1  x86_64\0",
        );
        let reduced = cache(
            dir.path(),
            "Rosetta/System/x86Support/System/Library/dyld/dyld_shared_cache_x86_64",
            b"dyld_v1  x86_64\0",
        );
        let native = cache(
            dir.path(),
            "OS/System/Library/dyld/dyld_shared_cache_arm64e",
            b"dyld_v1  arm64e\0",
        );
        cache(
            dir.path(),
            "OS/System/Library/dyld/dyld_shared_cache_arm64e.01",
            b"dyld_v1  arm64e\0",
        );
        cache(
            dir.path(),
            "Incoming/OS/System/Library/dyld/dyld_shared_cache_arm64e",
            b"dyld_v1  arm64e\0",
        );
        cache(
            dir.path(),
            "Rosetta/System/DriverKit/System/Library/dyld/dyld_shared_cache_x86_64",
            b"dyld_v1  x86_64\0",
        );
        assert_eq!(discover_caches(dir.path()).unwrap().len(), 3);
        assert_eq!(
            resolve_cache_path(dir.path(), Some("arm64e")).unwrap(),
            native
        );
        let error = resolve_cache_path(dir.path(), Some("x86"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("positional [CACHE] argument, without -a/--arch"));
        assert!(error.contains(full.to_str().unwrap()));
        assert!(error.contains(reduced.to_str().unwrap()));
        assert_eq!(resolve_cache_path(&reduced, None).unwrap(), reduced);

        let all = resolve_search_caches(Some(dir.path().to_path_buf()), &[], true).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(
            resolve_search_caches(Some(dir.path().to_path_buf()), &["arm64e".into()], false)
                .unwrap()
                .len(),
            1
        );
        assert!(
            resolve_search_caches(Some(dir.path().to_path_buf()), &["x86".into()], false).is_err()
        );
        let explicit = resolve_search_caches(Some(reduced.clone()), &[], false).unwrap();
        assert_eq!(explicit.len(), 1);
        assert_eq!(explicit[0].arch, "x86_64");
        assert_eq!(explicit[0].path, reduced);
        assert!(
            resolve_search_caches(Some(reduced), &["arm64e".into()], false)
                .unwrap_err()
                .to_string()
                .contains("does not match")
        );
    }
    #[test]
    fn discovery_uses_magic_not_filename_and_ignores_invalid_files() {
        let dir = tempfile::tempdir().unwrap();
        cache(
            dir.path(),
            "dyld_shared_cache_anyname",
            b"dyld_v1  x86_64\0",
        );
        cache(dir.path(), "dyld_shared_cache_invalid", b"not a cache");
        let caches = discover_caches(dir.path()).unwrap();
        assert_eq!(caches.len(), 1);
        assert_eq!(caches[0].arch, "x86_64");
    }
}

#[cfg(test)]
mod selection_cli_tests {
    use super::*;

    #[test]
    fn cache_paths_are_positional_and_rejected_as_architectures() {
        let path = "/System/Volumes/Preboot/Cryptexes/Rosetta/System/x86Support/System/Library/dyld/dyld_shared_cache_x86_64";
        for command in ["extract", "list", "info", "lookup", "strings"] {
            let mut args = vec!["dylex", command];
            if command == "lookup" {
                args.push("0x180000000");
            }
            if command == "strings" {
                args.push("needle");
            }

            let mut invalid = args.clone();
            invalid.extend(["-a", path]);
            let error = Cli::try_parse_from(invalid).unwrap_err().to_string();
            assert!(error.contains("positional [CACHE] argument, without -a/--arch"));

            args.extend(["-a", "x86_64", path]);
            let cli = Cli::try_parse_from(args).unwrap();
            if command == "strings" {
                match cli.command {
                    Commands::Strings {
                        arch,
                        cache,
                        needle,
                        ..
                    } => {
                        assert_eq!(arch, vec!["x86_64".to_string()]);
                        assert_eq!(cache, Some(PathBuf::from(path)));
                        assert_eq!(needle, "needle");
                    }
                    _ => unreachable!(),
                }
                continue;
            }
            let (arch, cache) = match cli.command {
                Commands::Extract { arch, cache, .. }
                | Commands::List { arch, cache, .. }
                | Commands::Info { arch, cache }
                | Commands::Lookup { arch, cache, .. } => (arch, cache),
                Commands::Strings { .. } | Commands::Arches { .. } => unreachable!(),
            };
            assert_eq!(arch.as_deref(), Some("x86_64"));
            assert_eq!(cache, Some(PathBuf::from(path)));
        }
    }

    #[test]
    fn extract_search_accepts_a_filter_and_case_fold_and_rejects_single_image_modes() {
        let cli = Cli::try_parse_from([
            "dylex",
            "extract",
            "--search",
            "com.apple.hid.manager.user-access-device",
            "-f",
            "IOHID",
            "--ignore-case",
            "-o",
            "hid",
        ])
        .unwrap();
        match cli.command {
            Commands::Extract {
                search,
                filter,
                ignore_case,
                image,
                output,
                ..
            } => {
                assert_eq!(
                    search.as_deref(),
                    Some("com.apple.hid.manager.user-access-device")
                );
                assert_eq!(filter.as_deref(), Some("IOHID"));
                assert!(ignore_case);
                assert!(image.is_none());
                assert_eq!(output, Some(PathBuf::from("hid")));
            }
            _ => unreachable!(),
        }
        assert!(Cli::try_parse_from(["dylex", "extract", "--ignore-case"]).is_err());
        assert!(
            Cli::try_parse_from(["dylex", "extract", "-i", "Root", "--search", "needle"]).is_err()
        );
        assert!(
            Cli::try_parse_from([
                "dylex",
                "extract",
                "-i",
                "Root",
                "--search",
                "needle",
                "--merge-deps"
            ])
            .is_err()
        );
    }

    #[test]
    fn strings_accepts_a_filter_case_fold_and_all_arches() {
        let cli = Cli::try_parse_from([
            "dylex",
            "strings",
            "-f",
            "IOHID",
            "-i",
            "--all-arches",
            "com.apple.hid.manager.user-access-device",
        ])
        .unwrap();
        match cli.command {
            Commands::Strings {
                needle,
                filter,
                all_arches,
                ignore_case,
                arch,
                ..
            } => {
                assert_eq!(needle, "com.apple.hid.manager.user-access-device");
                assert_eq!(filter.as_deref(), Some("IOHID"));
                assert!(all_arches);
                assert!(ignore_case);
                assert!(arch.is_empty());
            }
            _ => unreachable!(),
        }
        assert!(
            Cli::try_parse_from(["dylex", "strings", "--all-arches", "-a", "arm64e", "needle"])
                .is_err()
        );
    }

    #[test]
    fn runtime_merge_accepts_explicit_additions_and_a_plan_but_not_recursive_modes() {
        assert!(
            Cli::try_parse_from([
                "dylex",
                "extract",
                "-i",
                "Root",
                "--merge-runtime",
                "--merge-image",
                "Example",
                "--merge-plan"
            ])
            .is_ok()
        );
        for flag in ["--merge-deps", "--with-deps"] {
            assert!(
                Cli::try_parse_from(["dylex", "extract", "-i", "Root", "--merge-runtime", flag])
                    .is_err()
            );
        }
        assert!(Cli::try_parse_from(["dylex", "extract", "--merge-runtime"]).is_err());
    }
    #[test]
    fn explicit_merge_flags_are_repeatable_and_conflicting_modes_are_rejected() {
        assert!(
            Cli::try_parse_from([
                "dylex",
                "extract",
                "-i",
                "Root",
                "--merge-image",
                "A",
                "--merge-image",
                "B"
            ])
            .is_ok()
        );
        for extra in ["--merge-deps", "--with-deps"] {
            assert!(
                Cli::try_parse_from([
                    "dylex",
                    "extract",
                    "-i",
                    "Root",
                    "--merge-image",
                    "A",
                    extra
                ])
                .is_err()
            );
        }
        assert!(Cli::try_parse_from(["dylex", "extract", "--merge-image", "A"]).is_err());
        assert!(
            Cli::try_parse_from([
                "dylex",
                "extract",
                "-i",
                "Root",
                "--merge-image",
                "A",
                "--merge-depth",
                "2"
            ])
            .is_err()
        );
    }
}
