//! dylex - A high-performance dyld shared cache extractor.
//!
//! Extract individual dylibs or all frameworks from Apple's dyld shared cache.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

use dylex::{extract_image_with_options, DyldContext, ExtractionOptions};

/// Default locations to search for dyld shared caches on macOS.
const DEFAULT_CACHE_PATHS: &[&str] = &[
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
        /// If not specified, requires --filter to select images
        #[arg(short, long)]
        image: Option<String>,

        /// Filter images by substring match (can extract multiple images)
        #[arg(short, long)]
        filter: Option<String>,

        /// Architecture to use (e.g., "arm64e", "arm64", "x86_64")
        /// Substring match: "arm64" matches "arm64e"
        #[arg(short, long)]
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

        /// Path to the dyld shared cache (file or directory).
        /// If not specified, searches default system locations.
        cache: Option<PathBuf>,
    },

    /// List all images in the cache
    List {
        /// Architecture to use (e.g., "arm64e", "arm64", "x86_64")
        #[arg(short, long)]
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

    /// Show cache information
    Info {
        /// Architecture to use (e.g., "arm64e", "arm64", "x86_64")
        #[arg(short, long)]
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
        #[arg(short, long)]
        arch: Option<String>,

        /// Path to the dyld shared cache.
        /// If not specified, searches default system locations.
        cache: Option<PathBuf>,
    },
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
            arch,
            output,
            preserve_paths,
            verbosity,
            jobs,
        } => {
            setup_logging(verbosity);
            cmd_extract(
                cache,
                image,
                filter,
                arch,
                output,
                preserve_paths,
                verbosity,
                jobs,
            )
        }
        Commands::List {
            cache,
            arch,
            filter,
            addresses,
            basenames,
        } => cmd_list(cache, arch, filter, addresses, basenames),
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

/// Discovers all dyld shared cache files in a directory.
fn discover_caches(dir: &Path) -> Result<Vec<CacheInfo>> {
    let mut caches = Vec::new();

    if !dir.is_dir() {
        bail!("Path is not a directory: {}", dir.display());
    }

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        // Skip subcaches (.01, .02, .symbols, etc.)
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.contains('.') && !name.starts_with("dyld_shared_cache_") {
            continue;
        }

        // Look for dyld_shared_cache_* files
        if !name.starts_with("dyld_shared_cache_") {
            continue;
        }

        // Skip subcache files (have extensions like .01, .02, .symbols)
        if name.contains('.') {
            continue;
        }

        // Try to parse the architecture from the filename
        // Format: dyld_shared_cache_<arch> (e.g., dyld_shared_cache_arm64e)
        if let Some(arch) = name.strip_prefix("dyld_shared_cache_") {
            caches.push(CacheInfo {
                path: path.clone(),
                arch: arch.to_string(),
            });
        }
    }

    // Sort by architecture name for consistent ordering
    caches.sort_by(|a, b| a.arch.cmp(&b.arch));

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
        let available: Vec<_> = matching.iter().map(|c| c.arch.as_str()).collect();
        bail!(
            "Multiple caches match. Please specify --arch. Available: {}",
            available.join(", ")
        );
    }

    Ok(matching[0].path.clone())
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

fn cmd_extract(
    cache: Option<PathBuf>,
    image: Option<String>,
    filter: Option<String>,
    arch: Option<String>,
    output: Option<PathBuf>,
    preserve_paths: Option<bool>,
    verbosity: u8,
    jobs: Option<usize>,
) -> Result<()> {
    let start = Instant::now();

    // Get cache path (use default if not specified)
    let cache_path = get_cache_path(cache)?;

    // Resolve cache path with architecture filter
    let resolved_path = resolve_cache_path(&cache_path, arch.as_deref())?;

    info!("Opening cache: {}", resolved_path.display());
    let cache = Arc::new(
        DyldContext::open(&resolved_path)
            .with_context(|| format!("Failed to open cache: {}", resolved_path.display()))?,
    );

    // Determine what to extract
    let images_to_extract: Vec<_> = if let Some(ref img_name) = image {
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
        bail!("Either --image or --filter must be specified");
    };

    if images_to_extract.is_empty() {
        warn!("No images match the criteria");
        return Ok(());
    }

    // Determine if we should preserve paths
    let should_preserve = preserve_paths.unwrap_or_else(|| {
        // Default: preserve paths when extracting multiple images
        images_to_extract.len() > 1
    });

    // Single image extraction
    if images_to_extract.len() == 1 {
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

    // Multiple image extraction
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

    // Find which image contains this address
    for img in cache.iter_images() {
        // Check if address is within image's range
        // This is a simplified check - ideally we'd check against segments
        if address >= img.address {
            // Check the next image to see if we're still in range
            println!("Address {:#x} is in:", address);
            println!("  Image: {}", img.path);
            println!("  Base:  {:#x}", img.address);
            return Ok(());
        }
    }

    println!("Address {:#x} not found in any image", address);
    Ok(())
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
