//! `dylex kernel`: inspect, search, and extract kernelcaches.
//!
//! Every command takes an optional kernelcache path and otherwise uses the
//! running system's boot kernelcache, just as the dyld commands default to the
//! system shared cache.

use std::collections::HashSet;
use std::fs;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use clap::{ArgGroup, Args, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use rayon::prelude::*;
use tracing::{error, info, warn};

use dylex::kernelcache::{
    InputEncoding, KernelCandidate, KernelDiscoveryReport, KernelUuid, discover_kernelcaches,
};
use dylex::macho::{MH_EXECUTE, MH_FILESET, MH_MAGIC, MH_MAGIC_64, SegmentInfo};
use dylex::{KernelCacheContext, KernelImage, StringQuery};

use super::{
    FileIdentity, file_identity, format_size, format_string_hit, search_needle, setup_logging,
    shell_quote,
};

const LOCATE_ABOUT: &str = "\
Locate boot kernelcaches that match the running kernel (macOS)

Asks KernelManagement (kmutil) which collection was selected for this boot and
verifies it by reading build UUIDs from the binary. If that fails, searches
/System/Volumes/Preboot and /System/Library/KernelCollections instead.

A UUID match establishes build identity, not integrity or signature validity.";

/// Default directory for extracting several images.
const DEFAULT_OUTPUT_DIRECTORY: &str = "extracted";

// =============================================================================
// Arguments
// =============================================================================

/// Kernelcache subcommands.
#[derive(Subcommand, Debug)]
pub(super) enum KernelCommand {
    /// Locate boot kernelcaches that match the running kernel (macOS)
    #[command(long_about = LOCATE_ABOUT)]
    Locate(LocateArgs),

    /// Show kernelcache information
    Info {
        #[command(flatten)]
        input: KernelcacheInput,
    },

    /// List the kernel and kexts in a kernelcache
    List {
        /// Filter images by ID substring
        #[arg(short, long)]
        filter: Option<String>,

        /// Show addresses
        #[arg(short = 'A', long)]
        addresses: bool,

        #[command(flatten)]
        input: KernelcacheInput,
    },

    /// Extract the kernel or kexts as standalone Mach-O files
    Extract(ExtractArgs),

    /// Search images for a literal string or a hex byte sequence
    Strings(StringsArgs),

    /// Lookup which image contains an address
    Lookup {
        /// Address to lookup (hex, e.g., 0xfffffe0007004000)
        address: String,

        #[command(flatten)]
        input: KernelcacheInput,
    },
}

/// The kernelcache a command operates on.
#[derive(Args, Debug)]
pub(super) struct KernelcacheInput {
    /// Kernelcache file (Mach-O, IMG4/IM4P, LZFSE, or complzss).
    /// If not specified, uses the running system's boot kernelcache.
    #[arg(value_name = "KERNELCACHE")]
    kernelcache: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub(super) struct LocateArgs {
    /// Also require this exact kext bundle ID to match the loaded driver's UUID
    #[arg(long, value_name = "BUNDLE_ID")]
    target: Option<String>,

    /// Print only verified paths, one per line
    #[arg(long)]
    paths_only: bool,

    /// Print the commands run and their output to stderr
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Args, Debug)]
#[command(group(
    ArgGroup::new("selection")
        .required(true)
        .multiple(true)
        .args(["image", "filter", "search", "all"])
))]
pub(super) struct ExtractArgs {
    /// Image to extract: an exact ID (e.g., "com.apple.security.sandbox") or a unique substring
    #[arg(short, long, conflicts_with_all = ["filter", "search", "all"])]
    image: Option<String>,

    /// Extract every image whose ID contains this substring.
    /// With --search, only images whose ID contains this substring are searched.
    #[arg(short, long)]
    filter: Option<String>,

    /// Extract every image that contains this literal string.
    /// With --hex, a byte sequence such as "de ad be ef" or "deadbeef".
    #[arg(long)]
    search: Option<String>,

    /// Interpret --search as hex bytes. Requires --search.
    #[arg(long, short = 'x', requires = "search")]
    hex: bool,

    /// Compare ASCII letters without regard to case. Requires --search.
    #[arg(long, requires = "search")]
    ignore_case: bool,

    /// Extract every image
    #[arg(long, conflicts_with_all = ["filter", "search"])]
    all: bool,

    /// Output path: a file for --image, otherwise a directory.
    /// Defaults to the image ID, or ./extracted for several images.
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Verbosity level (0=quiet, 1=warnings, 2=info, 3=debug)
    #[arg(short, long, default_value = "1")]
    verbosity: u8,

    /// Number of parallel jobs (default: number of CPUs)
    #[arg(short, long, value_parser = parse_jobs)]
    jobs: Option<usize>,

    #[command(flatten)]
    input: KernelcacheInput,
}

#[derive(Args, Debug)]
pub(super) struct StringsArgs {
    /// Literal string to find, such as "Seatbelt sandbox policy".
    /// With --hex, a byte sequence such as "de ad be ef" or "deadbeef".
    needle: String,

    /// Interpret the needle as hex bytes
    #[arg(long, short = 'x')]
    hex: bool,

    /// Only search images whose ID contains this substring.
    /// Omit to search every image.
    #[arg(short, long)]
    filter: Option<String>,

    /// Compare ASCII letters without regard to case
    #[arg(short = 'i', long)]
    ignore_case: bool,

    /// Number of parallel jobs (default: number of CPUs)
    #[arg(short, long, value_parser = parse_jobs)]
    jobs: Option<usize>,

    #[command(flatten)]
    input: KernelcacheInput,
}

fn parse_jobs(value: &str) -> std::result::Result<usize, String> {
    match value.parse::<usize>() {
        Ok(0) => Err("must be at least 1".into()),
        Ok(jobs) => Ok(jobs),
        Err(error) => Err(error.to_string()),
    }
}

// =============================================================================
// Dispatch
// =============================================================================

pub(super) fn run(command: KernelCommand) -> Result<()> {
    match command {
        KernelCommand::Locate(args) => cmd_locate(&args),
        KernelCommand::Info { input } => cmd_info(&input),
        KernelCommand::List {
            filter,
            addresses,
            input,
        } => cmd_list(&input, filter.as_deref(), addresses),
        KernelCommand::Extract(args) => {
            setup_logging(args.verbosity);
            cmd_extract(args)
        }
        KernelCommand::Strings(args) => cmd_strings(&args),
        KernelCommand::Lookup { address, input } => cmd_lookup(&input, &address),
    }
}

/// Fails with a pointer to `dylex kernel` when a dyld command is given a kernelcache.
pub(super) fn reject_kernelcache(path: &Path) -> Result<()> {
    if path.is_file() && file_prefix(path).is_ok_and(|prefix| looks_like_kernelcache(&prefix)) {
        bail!(
            "{} looks like a kernelcache, not a dyld shared cache; \
             use the `dylex kernel` commands, e.g. `dylex kernel info {}`",
            path.display(),
            shell_quote(&path.to_string_lossy())
        );
    }
    Ok(())
}

// =============================================================================
// Opening Kernelcaches
// =============================================================================

/// An opened kernelcache and where it came from.
struct Opened {
    path: PathBuf,
    /// Whether the path was given on the command line rather than discovered.
    explicit: bool,
    cache: KernelCacheContext,
}

impl KernelcacheInput {
    fn open(&self) -> Result<Opened> {
        let (path, explicit) = match &self.kernelcache {
            Some(path) => (path.clone(), true),
            None => (running_kernelcache()?, false),
        };
        let cache = open_kernelcache(&path)?;
        Ok(Opened {
            path,
            explicit,
            cache,
        })
    }
}

fn open_kernelcache(path: &Path) -> Result<KernelCacheContext> {
    if !path.exists() {
        bail!("Kernelcache path does not exist: {}", path.display());
    }
    if path.is_dir() {
        bail!(
            "Kernelcache path is a directory: {}; pass a kernelcache file",
            path.display()
        );
    }
    if file_prefix(path).is_ok_and(|prefix| prefix.starts_with(b"dyld")) {
        bail!(
            "{} is a dyld shared cache, not a kernelcache; \
             use the dyld commands, e.g. `dylex info {}`",
            path.display(),
            shell_quote(&path.to_string_lossy())
        );
    }
    KernelCacheContext::open(path)
        .with_context(|| format!("Failed to open kernelcache: {}", path.display()))
}

/// Locates the running system's boot kernelcache.
fn running_kernelcache() -> Result<PathBuf> {
    let report = discover_kernelcaches(None);
    if let Some(candidate) = report.matches().next() {
        return Ok(candidate.path.clone());
    }
    let mut message = String::from(
        "No kernelcache given, and the running system's boot kernelcache could not be located",
    );
    for problem in discovery_problems(&report) {
        message.push_str("\n  ");
        message.push_str(&problem);
    }
    message.push_str("\nPass a kernelcache file as the positional [KERNELCACHE] argument");
    bail!(message)
}

/// Discovery issues and candidate rejections, one line each.
fn discovery_problems(report: &KernelDiscoveryReport) -> Vec<String> {
    let rejections = report.candidates.iter().filter_map(|candidate| {
        let error = candidate.error.as_ref()?;
        Some(format!("{}: {error}", candidate.path.display()))
    });
    report.issues.iter().cloned().chain(rejections).collect()
}

/// Reads the first bytes of a file, enough to recognize its format.
fn file_prefix(path: &Path) -> std::io::Result<Vec<u8>> {
    const PREFIX_SIZE: u64 = 16;

    let mut prefix = Vec::new();
    fs::File::open(path)?
        .take(PREFIX_SIZE)
        .read_to_end(&mut prefix)?;
    Ok(prefix)
}

/// Whether a file prefix looks like a kernelcache rather than a dyld shared cache.
fn looks_like_kernelcache(prefix: &[u8]) -> bool {
    let word = |offset: usize| {
        prefix
            .get(offset..)
            .and_then(<[u8]>::first_chunk)
            .copied()
            .map(u32::from_le_bytes)
    };
    match word(0) {
        Some(MH_MAGIC | MH_MAGIC_64) => matches!(word(12), Some(MH_FILESET | MH_EXECUTE)),
        _ => {
            let img4 = prefix.first() == Some(&0x30)
                && prefix
                    .windows(4)
                    .any(|name| name == b"IM4P" || name == b"IMG4");
            img4 || prefix.starts_with(b"complzss") || prefix.starts_with(b"bvx")
        }
    }
}

// =============================================================================
// locate
// =============================================================================

fn cmd_locate(args: &LocateArgs) -> Result<()> {
    let target = args.target.as_deref();
    let report = discover_kernelcaches(target);
    if args.verbose {
        print_commands(&report);
    }

    if args.paths_only {
        for candidate in report.matches() {
            println!("{}", candidate.path.display());
        }
    } else {
        print_locate_report(&report);
    }
    for issue in &report.issues {
        eprintln!("warning: {issue}");
    }

    if report.matches().next().is_none() {
        if args.paths_only {
            for problem in discovery_problems(&report) {
                eprintln!("rejected: {problem}");
            }
        }
        match target {
            Some(target) => bail!("No kernelcache matches the running kernel and {target}"),
            None => bail!("No kernelcache matches the running kernel"),
        }
    }
    Ok(())
}

fn print_locate_report(report: &KernelDiscoveryReport) {
    println!(
        "Running kernel: {}",
        uuid_or_unknown(report.runtime_kernel_uuid)
    );
    if let Some(target) = &report.target {
        println!(
            "Loaded target:  {target} ({})",
            uuid_or_unknown(report.runtime_target_uuid)
        );
    }

    let with_target = report.target.is_some();
    let (matching, rejected): (Vec<_>, Vec<_>) = report
        .candidates
        .iter()
        .partition(|candidate| candidate.verified);
    for (heading, candidates) in [
        ("Matching kernelcaches", matching),
        ("Rejected candidates", rejected),
    ] {
        if candidates.is_empty() {
            continue;
        }
        println!("\n{heading}:");
        for candidate in candidates {
            print_candidate(candidate, with_target);
        }
    }
}

fn print_candidate(candidate: &KernelCandidate, with_target: bool) {
    println!("  {}", candidate.path.display());
    let source = if candidate.selected {
        "kmutil boot selection"
    } else {
        "fallback search"
    };
    println!("    Source:     {source}");
    if let Some(identity) = &candidate.identity {
        println!(
            "    Collection: {}",
            uuid_or_unknown(identity.collection_uuid)
        );
        println!("    Kernel:     {}", identity.kernel_uuid);
        if with_target {
            println!("    Target:     {}", uuid_or_unknown(identity.target_uuid));
        }
    }
    if let Some(error) = &candidate.error {
        println!("    Rejected:   {error}");
    }
}

fn print_commands(report: &KernelDiscoveryReport) {
    for command in &report.commands {
        let status = command
            .exit_code
            .map_or_else(|| "unknown".to_string(), |code| code.to_string());
        eprintln!(
            "$ {} {} (exit status {status})",
            command.program,
            command.args.join(" ")
        );
        for line in command.stdout.lines() {
            eprintln!("  stdout: {line}");
        }
        for line in command.stderr.lines() {
            eprintln!("  stderr: {line}");
        }
        if let Some(error) = &command.error {
            eprintln!("  error:  {error}");
        }
    }
}

fn uuid_or_unknown(uuid: Option<KernelUuid>) -> String {
    uuid.map_or_else(|| "unknown".to_string(), |uuid| uuid.to_string())
}

// =============================================================================
// info / list
// =============================================================================

fn cmd_info(input: &KernelcacheInput) -> Result<()> {
    let Opened { path, cache, .. } = input.open()?;

    println!("Kernelcache Information");
    println!("=======================");
    println!("Path:         {}", path.display());
    println!("Format:       {}", cache.format());
    println!("Encoding:     {}", describe_encoding(cache.encoding()));
    println!("Architecture: {}", cache.architecture());
    println!("Images:       {}", cache.images.len());
    println!(
        "Decoded size: {:.2} MB",
        cache.total_size() as f64 / 1024.0 / 1024.0
    );
    if let Ok(identity) = cache.identity(None) {
        println!(
            "UUID:         {}",
            uuid_or_unknown(identity.collection_uuid)
        );
        println!("Kernel UUID:  {}", identity.kernel_uuid);
    }

    println!("\nSegments:");
    for (index, segment) in cache.macho.segments().enumerate() {
        let command = &segment.command;
        println!(
            "  [{index:2}] {:<16} {:#018x} - {:#018x} ({:>8}) {}",
            segment.name(),
            command.vmaddr,
            command.vmaddr + command.vmsize,
            format_size(command.vmsize),
            protection(command.initprot),
        );
    }
    Ok(())
}

fn describe_encoding(encoding: InputEncoding) -> String {
    let layers: Vec<_> = [
        encoding.container.map(|container| container.to_string()),
        encoding
            .compression
            .map(|compression| compression.to_string()),
    ]
    .into_iter()
    .flatten()
    .collect();
    if layers.is_empty() {
        "none (raw Mach-O)".to_string()
    } else {
        layers.join(", ")
    }
}

fn protection(prot: u32) -> String {
    const READ: u32 = 0x1;
    const WRITE: u32 = 0x2;
    const EXECUTE: u32 = 0x4;

    [(READ, 'r'), (WRITE, 'w'), (EXECUTE, 'x')]
        .into_iter()
        .map(|(bit, flag)| if prot & bit != 0 { flag } else { '-' })
        .collect()
}

fn cmd_list(input: &KernelcacheInput, filter: Option<&str>, addresses: bool) -> Result<()> {
    let Opened { cache, .. } = input.open()?;
    let filter = filter.unwrap_or_default();
    for image in cache
        .images
        .iter()
        .filter(|image| image.id.contains(filter))
    {
        if addresses {
            println!("{:#018x}  {}", image.address, image.id);
        } else {
            println!("{}", image.id);
        }
    }
    Ok(())
}

// =============================================================================
// strings / lookup
// =============================================================================

fn cmd_strings(args: &StringsArgs) -> Result<()> {
    let started = Instant::now();
    let needle = search_needle(&args.needle, args.hex)?;
    configure_jobs(args.jobs);
    let Opened { path, cache, .. } = args.input.open()?;

    let filter = args.filter.as_deref().unwrap_or_default();
    if !cache.images.iter().any(|image| image.id.contains(filter)) {
        eprintln!(
            "no images match filter {filter:?} in {} ({})",
            cache.architecture(),
            path.display()
        );
        return Ok(());
    }

    let query = StringQuery {
        needle,
        ignore_case: args.ignore_case,
        image_filter: args.filter.clone(),
    };
    let hits = cache.search_strings(&query)?;
    for hit in &hits {
        println!("{}", format_string_hit(cache.architecture(), None, hit));
    }
    let images: HashSet<_> = hits.iter().map(|hit| hit.image_path.as_str()).collect();
    eprintln!(
        "{} matches in {} images ({:.2}s)",
        hits.len(),
        images.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

fn cmd_lookup(input: &KernelcacheInput, address: &str) -> Result<()> {
    let digits = address.trim_start_matches("0x").trim_start_matches("0X");
    let address =
        u64::from_str_radix(digits, 16).with_context(|| format!("Invalid address: {digits}"))?;
    let opened = input.open()?;
    let cache = &opened.cache;

    let owners: Vec<_> = cache
        .images
        .iter()
        .filter_map(|image| Some((image, image.segment_containing(address)?)))
        .collect();
    if owners.is_empty() {
        let collection_segment = cache.macho.segments().find(|segment| {
            address
                .checked_sub(segment.command.vmaddr)
                .is_some_and(|delta| delta < segment.command.vmsize)
        });
        match collection_segment {
            Some(segment) => println!(
                "Address {address:#x} is in collection segment {} (not owned by a single image)",
                segment.name()
            ),
            None => println!("Address {address:#x} not found in any kernelcache segment"),
        }
        return Ok(());
    }

    for (image, segment) in owners {
        println!("Address {address:#x} is in:");
        println!("  Image: {}", image.id);
        println!("  Segment: {}", segment.name());
        if let Some(section) = section_containing(segment, address) {
            println!("  Section: {section}");
        }
        println!("  Base: {:#x}", segment.command.vmaddr);
        match cache.nearest_symbol(image, address)? {
            Some((name, value)) if value == address => println!("  Symbol: {name}"),
            Some((name, value)) => println!(
                "  Nearest symbol: {name} + {:#x} (symbol extent unknown)",
                address - value
            ),
            None => println!("  Symbol: unknown"),
        }
        println!("  Extract: {}", extract_command(&image.id, &opened));
    }
    Ok(())
}

fn section_containing(segment: &SegmentInfo, address: u64) -> Option<&str> {
    segment
        .sections
        .iter()
        .find(|section| {
            address
                .checked_sub(section.section.addr)
                .is_some_and(|delta| delta < section.section.size)
        })
        .map(|section| section.name())
}

/// The command that extracts `id` from the kernelcache that was opened.
fn extract_command(id: &str, opened: &Opened) -> String {
    let mut command = format!("dylex kernel extract -i {}", shell_quote(id));
    if opened.explicit {
        command.push(' ');
        command.push_str(&shell_quote(&opened.path.to_string_lossy()));
    }
    command
}

// =============================================================================
// extract
// =============================================================================

fn cmd_extract(args: ExtractArgs) -> Result<()> {
    let started = Instant::now();
    let needle = args
        .search
        .as_deref()
        .map(|search| search_needle(search, args.hex))
        .transpose()?;
    configure_jobs(args.jobs);
    let Opened {
        path: input, cache, ..
    } = args.input.open()?;
    let input_identity = file_identity(&input)?;

    if let Some(query) = &args.image {
        let image = cache.resolve_image(query)?;
        let output = single_output_path(image, args.output)?;
        ensure_not_input(&output, &input_identity)?;
        info!("Extracting {} to {}", image.id, output.display());
        write_image(&cache, image, &output)?;
        info!(
            "Extracted {} in {:.2}s",
            image.id,
            started.elapsed().as_secs_f64()
        );
        return Ok(());
    }

    let images = select_images(&cache, args.filter.as_deref(), needle, args.ignore_case)?;
    if images.is_empty() {
        warn!("No images match the criteria");
        return Ok(());
    }
    let output_dir = args
        .output
        .unwrap_or_else(|| PathBuf::from(DEFAULT_OUTPUT_DIRECTORY));
    if let Some(search) = &args.search {
        let count = images.len();
        let (noun, verb) = if count == 1 {
            ("image", "contains")
        } else {
            ("images", "contain")
        };
        eprintln!(
            "{count} {noun} {verb} {search:?} into {}",
            output_dir.display()
        );
    }
    let plan = plan_outputs(&images, &output_dir, &input_identity)?;

    info!(
        "Extracting {} images to {}",
        plan.len(),
        output_dir.display()
    );
    let progress = progress_bar(plan.len());
    let failures: Vec<_> = plan
        .par_iter()
        .filter_map(|(image, path)| {
            let result = write_image(&cache, image, path);
            progress.inc(1);
            result.err().map(|error| (image.id.as_str(), error))
        })
        .collect();
    progress.finish_with_message("Done");

    if !failures.is_empty() {
        warn!("{} images failed to extract:", failures.len());
        for (id, failure) in &failures {
            error!("  {id}: {failure:#}");
        }
        bail!(
            "{} of {} images failed to extract",
            failures.len(),
            plan.len()
        );
    }
    info!(
        "Extracted {} images in {:.2}s",
        plan.len(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}

/// Images whose ID contains `filter` and, with a needle, that contain the needle.
fn select_images<'a>(
    cache: &'a KernelCacheContext,
    filter: Option<&str>,
    needle: Option<Vec<u8>>,
    ignore_case: bool,
) -> Result<Vec<&'a KernelImage>> {
    let containing: Option<HashSet<String>> = match needle {
        Some(needle) => {
            let query = StringQuery {
                needle,
                ignore_case,
                image_filter: filter.map(str::to_owned),
            };
            let hits = cache.search_strings(&query)?;
            Some(hits.into_iter().map(|hit| hit.image_path).collect())
        }
        None => None,
    };
    let filter = filter.unwrap_or_default();
    Ok(cache
        .images
        .iter()
        .filter(|image| image.id.contains(filter))
        .filter(|image| {
            containing
                .as_ref()
                .is_none_or(|ids| ids.contains(&image.id))
        })
        .collect())
}

/// Output path for one image: `--output`, the image ID inside an existing
/// `--output` directory, or the image ID in the current directory.
fn single_output_path(image: &KernelImage, output: Option<PathBuf>) -> Result<PathBuf> {
    let file_name = safe_relative_path(&image.id)?
        .file_name()
        .context("Image ID has no file name")?;
    Ok(match output {
        Some(directory) if directory.is_dir() => directory.join(file_name),
        Some(path) => path,
        None => PathBuf::from(file_name),
    })
}

/// Maps each image to `<directory>/<image ID>`, rejecting collisions and the input file.
fn plan_outputs<'a>(
    images: &[&'a KernelImage],
    directory: &Path,
    input: &FileIdentity,
) -> Result<Vec<(&'a KernelImage, PathBuf)>> {
    let mut seen = HashSet::with_capacity(images.len());
    images
        .iter()
        .map(|&image| {
            let path = directory.join(safe_relative_path(&image.id)?);
            if !seen.insert(path.clone()) {
                bail!("Multiple images map to output {}", path.display());
            }
            ensure_not_input(&path, input)?;
            Ok((image, path))
        })
        .collect()
}

/// Converts an untrusted image ID into a relative path that stays inside the output directory.
fn safe_relative_path(id: &str) -> Result<&Path> {
    let path = Path::new(id.trim_start_matches('/'));
    let is_safe = path.components().next().is_some()
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)));
    if !is_safe {
        bail!("Unsafe kernelcache image ID: {id:?}");
    }
    Ok(path)
}

/// Refuses to overwrite the input kernelcache, including through hard or symbolic links.
fn ensure_not_input(path: &Path, input: &FileIdentity) -> Result<()> {
    if path.exists() && file_identity(path)? == *input {
        bail!(
            "Output would overwrite input kernelcache: {}",
            path.display()
        );
    }
    Ok(())
}

fn write_image(cache: &KernelCacheContext, image: &KernelImage, path: &Path) -> Result<()> {
    let bytes = cache
        .extract_image(image)
        .with_context(|| format!("Failed to extract: {}", image.id))?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }
    fs::write(path, bytes).with_context(|| format!("Failed to write: {}", path.display()))
}

fn configure_jobs(jobs: Option<usize>) {
    if let Some(jobs) = jobs {
        rayon::ThreadPoolBuilder::new()
            .num_threads(jobs)
            .build_global()
            .ok();
    }
}

fn progress_bar(len: usize) -> ProgressBar {
    let progress = ProgressBar::new(len as u64);
    progress.set_style(
        ProgressStyle::default_bar()
            .template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .expect("progress template is valid")
            .progress_chars("#>-"),
    );
    progress
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_kernelcache_prefixes() {
        let macho = |filetype: u32| {
            let mut prefix = MH_MAGIC_64.to_le_bytes().to_vec();
            prefix.extend_from_slice(&[0; 8]);
            prefix.extend_from_slice(&filetype.to_le_bytes());
            prefix
        };
        assert!(looks_like_kernelcache(&macho(MH_FILESET)));
        assert!(looks_like_kernelcache(&macho(MH_EXECUTE)));
        assert!(!looks_like_kernelcache(&macho(0x6))); // MH_DYLIB
        assert!(looks_like_kernelcache(
            b"0\x84\x02\x01ZO\x16\x04IM4P\x16\x04"
        ));
        assert!(looks_like_kernelcache(b"complzss"));
        assert!(looks_like_kernelcache(b"bvx2"));
        assert!(!looks_like_kernelcache(b"dyld_v1   arm64e"));
        assert!(!looks_like_kernelcache(b"0123456789"));
    }

    #[test]
    fn image_ids_cannot_escape_the_output_directory() {
        assert_eq!(
            safe_relative_path("com.apple.kernel").unwrap(),
            Path::new("com.apple.kernel")
        );
        assert_eq!(safe_relative_path("/a/b").unwrap(), Path::new("a/b"));
        for unsafe_id in ["", "/", "..", "a/../b", "./a"] {
            assert!(safe_relative_path(unsafe_id).is_err(), "{unsafe_id:?}");
        }
    }

    #[test]
    fn protection_flags_render_like_ls() {
        assert_eq!(protection(0x1 | 0x4), "r-x");
        assert_eq!(protection(0x3), "rw-");
        assert_eq!(protection(0), "---");
    }
}
