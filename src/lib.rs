//! dylex - A high-performance dyld shared cache extractor.
//!
//! This library provides functionality for extracting Mach-O images from
//! Apple's dyld shared cache. The extraction process reverses the optimizations
//! applied by the SharedCacheBuilder to produce standalone dylib files.
//!
//! # Features
//!
//! - Fast memory-mapped file I/O
//! - Support for split caches (iOS 15+, macOS 12+)
//! - Slide info processing (v2, v3, v5)
//! - LINKEDIT optimization
//! - Stub fixing
//! - ObjC metadata restoration
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use dylex::{DyldContext, extract_image};
//!
//! fn main() -> dylex::Result<()> {
//!     let cache = Arc::new(DyldContext::open("/path/to/dyld_shared_cache")?);
//!
//!     // Find an image
//!     let image = cache.find_image("UIKit").expect("UIKit not found");
//!
//!     // Extract it
//!     extract_image(&cache, &image.path, "output/UIKit")?;
//!
//!     Ok(())
//! }
//! ```

#![warn(missing_docs)]
#![warn(clippy::all)]

pub mod arm64;
pub mod converter;
pub mod dyld;
pub mod error;
pub mod macho;
pub mod util;

// Re-export main types
pub use dyld::{DyldContext, ImageEntry, MappingEntry};
pub use error::{Error, Result};
pub use macho::MachOContext;

use std::collections::{HashSet, VecDeque};
use std::fs;
use std::path::Path;
use std::sync::Arc;

use converter::{
    ExtractionContext, MergeContext, fix_header_and_load_commands, fix_merged_pointers,
    fix_merged_stubs, fix_objc, fix_stubs, include_shared_regions, inject_dependency_segments,
    merge_images, optimize_linkedit, optimize_offsets, process_slide_info, rebuild_merged_linkedit,
    resolve_indirect_pointers, update_merged_load_commands, write_macho,
};

/// Extracts a single image from the cache.
///
/// # Arguments
///
/// * `cache` - The dyld cache context
/// * `image_path` - Path of the image in the cache (e.g., "/usr/lib/libc.dylib")
/// * `output_path` - Path where the extracted dylib will be written
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if extraction fails.
pub fn extract_image<P: AsRef<Path>>(
    cache: &Arc<DyldContext>,
    image_path: &str,
    output_path: P,
) -> Result<()> {
    extract_image_with_options(cache, image_path, output_path, ExtractionOptions::default())
}

/// Options for image extraction.
#[derive(Debug, Clone)]
pub struct ExtractionOptions {
    /// Verbosity level (0=quiet, 1=warnings, 2=info, 3=debug)
    pub verbosity: u8,
    /// Skip slide info processing
    pub skip_slide_info: bool,
    /// Skip LINKEDIT optimization
    pub skip_linkedit: bool,
    /// Skip stub fixing
    pub skip_stubs: bool,
    /// Skip ObjC fixing
    pub skip_objc: bool,
}

impl Default for ExtractionOptions {
    fn default() -> Self {
        Self {
            verbosity: 1,
            skip_slide_info: false,
            skip_linkedit: false,
            skip_stubs: false,
            skip_objc: false,
        }
    }
}

/// Options for merged dependency extraction.
#[derive(Debug, Clone)]
pub struct MergeExtractionOptions {
    /// Verbosity level (0=quiet, 1=warnings, 2=info, 3=debug)
    pub verbosity: u8,
    /// Maximum depth for dependency traversal (1 = direct dependencies only)
    pub max_depth: usize,
}

impl Default for MergeExtractionOptions {
    fn default() -> Self {
        Self {
            verbosity: 1,
            max_depth: 1,
        }
    }
}

/// Extracts a single image with all its dependencies merged into one binary.
///
/// This creates a self-contained dylib where all referenced code/data from
/// dependencies are merged into the output. Pointers are adjusted to reference
/// the merged locations.
///
/// The output structure is:
/// 1. Primary image (fully extracted with proper load commands)
/// 2. Dependency segments appended (as raw data, not described in load commands)
/// 3. Pointers in primary image updated to reference appended data
///
/// This allows reverse engineering tools to analyze the primary image with
/// all referenced external code/data present in the file.
///
/// # Arguments
///
/// * `cache` - The dyld cache context
/// * `image_path` - Path of the image in the cache
/// * `output_path` - Path where the merged dylib will be written
/// * `options` - Merge extraction options
///
/// # Returns
///
/// Returns `Ok(())` on success, or an error if extraction fails.
pub fn extract_image_with_merged_deps<P: AsRef<Path>>(
    cache: &Arc<DyldContext>,
    image_path: &str,
    output_path: P,
    options: MergeExtractionOptions,
) -> Result<()> {
    let output_path = output_path.as_ref();

    // Create merge context
    let mut ctx = MergeContext::new(Arc::clone(cache), image_path.to_string(), options.max_depth)
        .with_verbosity(options.verbosity);

    // Perform the merge
    merge_images(&mut ctx)?;

    // Include shared cache DATA regions that are referenced
    include_shared_regions(&mut ctx)?;

    // Inject segment commands for dependency code regions
    inject_dependency_segments(&mut ctx)?;

    // Update load commands with correct file offsets
    update_merged_load_commands(&mut ctx)?;

    // Fix auth stubs to populate the local GOT
    fix_merged_stubs(&mut ctx)?;

    // Fix pointers to point to merged locations
    fix_merged_pointers(&mut ctx)?;

    // Resolve indirect pointers (GOT, auth) to their targets
    resolve_indirect_pointers(&mut ctx)?;

    // Rebuild LINKEDIT segment
    rebuild_merged_linkedit(&mut ctx)?;

    // Write output
    if let Some(parent) = output_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| Error::FileOpen {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }
    }

    fs::write(output_path, &ctx.data).map_err(|e| Error::FileOpen {
        path: output_path.to_path_buf(),
        source: e,
    })?;

    Ok(())
}

/// Extracts a single image from the cache with custom options.
pub fn extract_image_with_options<P: AsRef<Path>>(
    cache: &Arc<DyldContext>,
    image_path: &str,
    output_path: P,
    options: ExtractionOptions,
) -> Result<()> {
    let image = cache
        .find_image(image_path)
        .ok_or_else(|| Error::ImageNotFound {
            name: image_path.to_string(),
        })?;
    let macho = converter::materialize_image(cache, image.address, options.skip_linkedit)?;

    // Create extraction context
    let mut ctx =
        ExtractionContext::new(Arc::clone(cache), macho, image.path.clone(), image.address)
            .with_verbosity(options.verbosity);

    // CRITICAL: Fix header and load commands first
    // This clears MH_DYLIB_IN_CACHE flag and zeros chained fixups
    // Apple's dsc_extractor does this at the very start
    fix_header_and_load_commands(&mut ctx)?;

    // Run extraction pipeline
    if !options.skip_slide_info {
        process_slide_info(&mut ctx)?;
    }

    if !options.skip_linkedit {
        optimize_linkedit(&mut ctx)?;
    }

    if !options.skip_stubs {
        fix_stubs(&mut ctx)?;
        converter::include_cache_support(&mut ctx)?;
    }

    if !options.skip_objc {
        fix_objc(&mut ctx)?;
    }

    // Optimize offsets and write output
    let procedures = optimize_offsets(&mut ctx)?;
    write_macho(&ctx, &procedures, output_path)?;

    Ok(())
}

/// Lists all images in the cache.
pub fn list_images(cache: &DyldContext) -> impl Iterator<Item = &ImageEntry> {
    cache.iter_images()
}

/// Finds images matching a filter.
pub fn find_images<'a>(
    cache: &'a DyldContext,
    filter: &'a str,
) -> impl Iterator<Item = &'a ImageEntry> {
    cache
        .iter_images()
        .filter(move |img| img.matches_filter(filter))
}

// =============================================================================
// Dependency Extraction
// =============================================================================

/// Statistics from dependency extraction.
#[derive(Debug, Clone, Default)]
pub struct DependencyExtractionStats {
    /// Number of root images requested
    pub root_images: usize,
    /// Number of dependency images discovered and extracted
    pub dependencies: usize,
    /// Total images extracted
    pub total_extracted: usize,
    /// Number of images that failed to extract
    pub failed: usize,
    /// Number of images skipped (not in cache)
    pub skipped: usize,
}

/// Information about an image to extract, with its dependency depth.
#[derive(Debug, Clone)]
struct ImageToExtract {
    /// Path of the image in the cache
    path: String,
    /// Depth in the dependency tree (0 = root)
    depth: usize,
}

/// Gets the dependencies of an image from its Mach-O header.
///
/// This reads the image directly from the cache and parses its load commands
/// to find LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB, etc.
fn get_image_dependencies(cache: &DyldContext, image_path: &str) -> Result<Vec<String>> {
    use macho::MachHeader64;
    use zerocopy::FromBytes;

    // Find the image
    let image = cache
        .find_image(image_path)
        .ok_or_else(|| Error::ImageNotFound {
            name: image_path.to_string(),
        })?;

    // Read the Mach-O header
    let header_data = cache.data_at_addr(image.address, MachHeader64::SIZE)?;
    let header = MachHeader64::read_from_prefix(header_data)
        .map_err(|_| Error::InvalidMachoMagic(0))?
        .0;

    // Calculate size for header + load commands
    let header_and_cmds_size = MachHeader64::SIZE + header.sizeofcmds as usize;
    let header_and_cmds = cache.data_at_addr(image.address, header_and_cmds_size)?;

    // Create a temporary MachOContext to parse load commands
    let macho_offset =
        cache
            .addr_to_offset(image.address)
            .ok_or_else(|| Error::AddressNotFound {
                addr: image.address,
            })? as usize;
    let macho = MachOContext::new(header_and_cmds, macho_offset)?;

    Ok(macho.dependencies())
}

/// Builds a complete dependency graph starting from the root images.
///
/// Uses breadth-first search to discover all dependencies up to the specified depth.
/// Returns a list of all images to extract in dependency order (roots first, then
/// dependencies at increasing depths).
fn build_dependency_graph(
    cache: &DyldContext,
    root_paths: &[String],
    max_depth: Option<usize>,
) -> (Vec<ImageToExtract>, Vec<String>) {
    let mut to_extract: Vec<ImageToExtract> = Vec::new();
    let mut visited: HashSet<String> = HashSet::new();
    let mut not_in_cache: Vec<String> = Vec::new();
    let mut queue: VecDeque<ImageToExtract> = VecDeque::new();

    // Seed the queue with root images
    for path in root_paths {
        if !visited.contains(path) {
            visited.insert(path.clone());
            queue.push_back(ImageToExtract {
                path: path.clone(),
                depth: 0,
            });
        }
    }

    // Process the queue (BFS)
    while let Some(item) = queue.pop_front() {
        // Check if we've exceeded the depth limit
        if let Some(max) = max_depth {
            if item.depth > max {
                continue;
            }
        }

        // Check if image exists in cache
        if cache.find_image(&item.path).is_none() {
            if !not_in_cache.contains(&item.path) {
                not_in_cache.push(item.path.clone());
            }
            continue;
        }

        // Add to extraction list
        to_extract.push(item.clone());

        // Get dependencies (skip if we're at max depth)
        let should_traverse = match max_depth {
            Some(max) => item.depth < max,
            None => true,
        };

        if should_traverse {
            match get_image_dependencies(cache, &item.path) {
                Ok(deps) => {
                    for dep_path in deps {
                        // Normalize the path (some dependencies use @rpath, @executable_path, etc.)
                        let normalized = normalize_dependency_path(&dep_path);

                        if !visited.contains(&normalized) {
                            visited.insert(normalized.clone());
                            queue.push_back(ImageToExtract {
                                path: normalized,
                                depth: item.depth + 1,
                            });
                        }
                    }
                }
                Err(_) => {
                    // Failed to get dependencies, but continue with extraction
                }
            }
        }
    }

    (to_extract, not_in_cache)
}

/// Normalizes a dependency path, handling @rpath, @executable_path, etc.
///
/// For now, this just strips the prefix and keeps the path as-is.
/// In practice, most dylibs in the shared cache use absolute paths.
fn normalize_dependency_path(path: &str) -> String {
    // Handle common path prefixes
    if let Some(rest) = path.strip_prefix("@rpath/") {
        // Try to resolve @rpath - typically points to /usr/lib or framework paths
        // Prefer the path as given if it looks like a full path
        if rest.contains('/') {
            return format!("/System/Library/{}", rest);
        }

        // Check if it looks like a framework
        if rest.ends_with(".dylib") {
            return format!("/usr/lib/{}", rest);
        }

        // Try as framework
        let framework_name = rest.trim_end_matches(".dylib");
        return format!(
            "/System/Library/Frameworks/{}.framework/{}",
            framework_name, framework_name
        );
    }

    if let Some(rest) = path.strip_prefix("@executable_path/") {
        return format!("/usr/lib/{}", rest);
    }

    if let Some(rest) = path.strip_prefix("@loader_path/") {
        return format!("/usr/lib/{}", rest);
    }

    // Already an absolute path
    path.to_string()
}

/// Extracts images along with all their dependencies.
///
/// This function:
/// 1. Builds a dependency graph starting from the root images
/// 2. Discovers all transitive dependencies (up to the optional depth limit)
/// 3. Extracts all images in dependency order
///
/// # Arguments
///
/// * `cache` - The dyld cache context
/// * `root_paths` - Paths of the root images to extract
/// * `output_dir` - Directory where extracted dylibs will be written
/// * `options` - Extraction options
/// * `max_depth` - Optional maximum dependency depth (None for unlimited)
/// * `progress_callback` - Called for each image being extracted (current, total, path)
///
/// # Returns
///
/// Returns statistics about the extraction process.
pub fn extract_images_with_dependencies<P, F>(
    cache: &Arc<DyldContext>,
    root_paths: &[String],
    output_dir: P,
    options: ExtractionOptions,
    max_depth: Option<usize>,
    mut progress_callback: F,
) -> Result<DependencyExtractionStats>
where
    P: AsRef<Path>,
    F: FnMut(usize, usize, &str),
{
    let output_dir = output_dir.as_ref();
    let root_count = root_paths.len();

    // Build dependency graph
    let (images_to_extract, not_in_cache) = build_dependency_graph(cache, root_paths, max_depth);

    let total = images_to_extract.len();
    let mut stats = DependencyExtractionStats {
        root_images: root_count,
        dependencies: total.saturating_sub(root_count),
        total_extracted: 0,
        failed: 0,
        skipped: not_in_cache.len(),
    };

    // Create output directory
    fs::create_dir_all(output_dir).map_err(|e| Error::FileOpen {
        path: output_dir.to_path_buf(),
        source: e,
    })?;

    // Track what we've already extracted to avoid duplicates
    let mut extracted: HashSet<String> = HashSet::new();

    // Extract each image
    for (index, item) in images_to_extract.iter().enumerate() {
        if extracted.contains(&item.path) {
            continue;
        }

        progress_callback(index + 1, total, &item.path);

        // Compute output path (preserve directory structure)
        let relative_path = item.path.trim_start_matches('/');
        let output_path = output_dir.join(relative_path);

        // Create parent directories
        if let Some(parent) = output_path.parent() {
            if let Err(_) = fs::create_dir_all(parent) {
                stats.failed += 1;
                continue;
            }
        }

        // Extract the image
        match extract_image_with_options(cache, &item.path, &output_path, options.clone()) {
            Ok(_) => {
                stats.total_extracted += 1;
                extracted.insert(item.path.clone());
            }
            Err(_) => {
                stats.failed += 1;
            }
        }
    }

    Ok(stats)
}
