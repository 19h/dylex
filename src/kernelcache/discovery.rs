//! Runtime discovery of the boot kernelcache on macOS.
//!
//! The collection selected by KernelManagement (`kmutil`) is checked first, by
//! reading build UUIDs directly from the binary. Fallback locations are
//! searched only if that check fails. Command text is version-dependent and is
//! never treated as binary evidence. A UUID match establishes build identity,
//! not integrity or signature validity.

use std::collections::HashSet;
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::str::FromStr;

use crate::error::{Error, Result};
use crate::macho::{LoadCommandInfo, MachOContext};

use super::{KERNEL_IMAGE_ID, KernelCacheContext};

const SYSCTL: &str = "/usr/sbin/sysctl";
const KMUTIL: &str = "/usr/bin/kmutil";

/// Fallback search roots.
const PREBOOT_VOLUMES: &str = "/System/Volumes/Preboot";
const KERNEL_COLLECTIONS: &str = "/System/Library/KernelCollections";
/// Kernelcache directory inside each Preboot boot directory.
const PREBOOT_KERNELCACHES: &str = "System/Library/Caches/com.apple.kernelcaches";

/// A discovery problem, recorded as text in [`KernelDiscoveryReport::issues`].
type Issue = String;

// =============================================================================
// Identities
// =============================================================================

/// A 128-bit Mach-O build UUID.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct KernelUuid(pub [u8; 16]);

impl KernelUuid {
    /// Reads the `LC_UUID` of a Mach-O, if it has one.
    fn of(macho: &MachOContext) -> Result<Option<Self>> {
        let mut uuids = macho
            .load_commands
            .iter()
            .filter_map(|command| match command {
                LoadCommandInfo::Uuid { command, .. } => Some(Self(command.uuid)),
                _ => None,
            });
        let uuid = uuids.next();
        if uuids.next().is_some() {
            return Err(Error::parse(0, "multiple LC_UUID commands"));
        }
        Ok(uuid)
    }
}

impl FromStr for KernelUuid {
    type Err = Error;

    /// Parses the canonical 8-4-4-4-12 hexadecimal form, in either case.
    fn from_str(text: &str) -> Result<Self> {
        const HYPHENS: [usize; 4] = [8, 13, 18, 23];

        let text = text.as_bytes();
        if text.len() != 36 || HYPHENS.iter().any(|&index| text[index] != b'-') {
            return Err(Error::parse(0, "invalid UUID syntax"));
        }
        let digits: Vec<u8> = text
            .iter()
            .enumerate()
            .filter(|(index, _)| !HYPHENS.contains(index))
            .map(|(_, &digit)| digit)
            .collect();
        let mut uuid = [0; 16];
        for (byte, pair) in uuid.iter_mut().zip(digits.chunks_exact(2)) {
            *byte = (hex_digit(pair[0])? << 4) | hex_digit(pair[1])?;
        }
        Ok(Self(uuid))
    }
}

fn hex_digit(digit: u8) -> Result<u8> {
    char::from(digit)
        .to_digit(16)
        .map(|value| value as u8)
        .ok_or_else(|| Error::parse(0, "invalid UUID digit"))
}

impl fmt::Display for KernelUuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, byte) in self.0.iter().enumerate() {
            if matches!(index, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{byte:02X}")?;
        }
        Ok(())
    }
}

/// Build identities read from a kernelcache.
///
/// The collection, kernel, and target UUIDs are distinct and never conflated.
#[derive(Debug, Clone)]
pub struct CollectionIdentity {
    /// UUID of the outer Mach-O, if present.
    pub collection_uuid: Option<KernelUuid>,
    /// UUID of the exact `com.apple.kernel` image.
    pub kernel_uuid: KernelUuid,
    /// UUID of the exact requested image, if it is present.
    pub target_uuid: Option<KernelUuid>,
}

impl KernelCacheContext {
    /// Reads build identities, optionally including the image whose ID is exactly `target`.
    pub fn identity(&self, target: Option<&str>) -> Result<CollectionIdentity> {
        let kernel = self
            .images
            .iter()
            .find(|image| image.id == KERNEL_IMAGE_ID)
            .ok_or_else(|| Error::parse(0, "collection has no exact com.apple.kernel member"))?;
        let kernel_uuid = KernelUuid::of(&kernel.macho)?
            .ok_or_else(|| Error::parse(0, "embedded kernel has no LC_UUID"))?;
        let target_uuid = target
            .and_then(|id| self.images.iter().find(|image| image.id == id))
            .map(|image| {
                KernelUuid::of(&image.macho)?
                    .ok_or_else(|| Error::parse(0, "target member has no LC_UUID"))
            })
            .transpose()?;
        Ok(CollectionIdentity {
            collection_uuid: KernelUuid::of(&self.macho)?,
            kernel_uuid,
            target_uuid,
        })
    }
}

// =============================================================================
// Report
// =============================================================================

/// One captured command execution. Standard output and error are kept separate.
#[derive(Debug)]
pub struct DiscoveryCommand {
    /// Executable, invoked with `LC_ALL=C`.
    pub program: String,
    /// Individual arguments; no shell is involved.
    pub args: Vec<String>,
    /// Exit status, or `None` if spawning failed or the process was signalled.
    pub exit_code: Option<i32>,
    /// Captured standard output.
    pub stdout: String,
    /// Captured standard error.
    pub stderr: String,
    /// Spawn, exit-status, or UTF-8 decoding failure.
    pub error: Option<String>,
}

/// The inspection result for one candidate kernelcache.
#[derive(Debug)]
pub struct KernelCandidate {
    /// Candidate path, exactly as reported by `kmutil` or found by fallback search.
    pub path: PathBuf,
    /// Whether KernelManagement selected this path for the current boot.
    pub selected: bool,
    /// Collection UUID advertised by KernelManagement (not the kernel UUID).
    pub advertised_collection_uuid: Option<KernelUuid>,
    /// Identities read from the binary, if inspection succeeded.
    pub identity: Option<CollectionIdentity>,
    /// Whether every requested runtime identity check passed.
    pub verified: bool,
    /// Mismatch or inspection failure, kept even when another candidate matches.
    pub error: Option<String>,
}

/// Runtime identities, inspected candidates, command evidence, and issues.
#[derive(Debug, Default)]
pub struct KernelDiscoveryReport {
    /// UUID of the running kernel, from `kern.uuid`.
    pub runtime_kernel_uuid: Option<KernelUuid>,
    /// Requested exact bundle identifier.
    pub target: Option<String>,
    /// UUID of the loaded target kext, if requested and found.
    pub runtime_target_uuid: Option<KernelUuid>,
    /// Every inspected candidate, including mismatches and unreadable files.
    pub candidates: Vec<KernelCandidate>,
    /// Commands executed, in order.
    pub commands: Vec<DiscoveryCommand>,
    /// Problems that made discovery fail or left the search incomplete.
    pub issues: Vec<String>,
}

impl KernelDiscoveryReport {
    /// Every verified candidate. Several matching copies remain several results.
    pub fn matches(&self) -> impl Iterator<Item = &KernelCandidate> {
        self.candidates
            .iter()
            .filter(|candidate| candidate.verified)
    }
}

// =============================================================================
// Discovery
// =============================================================================

/// Locates boot kernelcaches matching the running macOS kernel and, optionally,
/// the loaded kext whose bundle identifier is exactly `target`.
///
/// The KernelManagement selection is checked first; bounded fallback locations
/// are searched only if it does not verify. UUID matches establish build
/// identity, not integrity or signature validity.
pub fn discover_kernelcaches(target: Option<&str>) -> KernelDiscoveryReport {
    if !cfg!(target_os = "macos") {
        return KernelDiscoveryReport {
            issues: vec!["runtime kernelcache discovery requires macOS".into()],
            ..Default::default()
        };
    }
    discover_with(
        target,
        &mut |program, args| Command::new(program).args(args).env("LC_ALL", "C").output(),
        &mut |path| KernelCacheContext::open(path)?.identity(target),
        || fallback_candidates(Path::new(PREBOOT_VOLUMES), Path::new(KERNEL_COLLECTIONS)),
    )
}

/// Identity of the running kernel and, optionally, a loaded kext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RuntimeIdentity {
    kernel: KernelUuid,
    target: Option<KernelUuid>,
}

impl fmt::Display for RuntimeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "kernel {}", self.kernel)?;
        if let Some(target) = self.target {
            write!(f, ", target {target}")?;
        }
        Ok(())
    }
}

/// Discovery with injectable command execution, inspection, and fallback search.
fn discover_with<R, I, F>(
    target: Option<&str>,
    run: &mut R,
    inspect: &mut I,
    fallback: F,
) -> KernelDiscoveryReport
where
    R: FnMut(&str, &[&str]) -> io::Result<Output>,
    I: FnMut(&Path) -> Result<CollectionIdentity>,
    F: FnOnce() -> (Vec<PathBuf>, Vec<String>),
{
    let mut discovery = Discovery {
        report: KernelDiscoveryReport {
            target: target.map(str::to_owned),
            ..Default::default()
        },
        run,
    };
    let Some(runtime) = discovery.runtime_identity(target) else {
        return discovery.report;
    };
    discovery.inspect_selected(runtime, inspect);
    if discovery.report.matches().next().is_none() {
        discovery.inspect_fallback(fallback, runtime, inspect);
    }
    discovery.confirm_unchanged(runtime, target);
    discovery.report
}

/// Discovery state: the report under construction and the command runner.
struct Discovery<'r, R> {
    report: KernelDiscoveryReport,
    run: &'r mut R,
}

impl<R> Discovery<'_, R>
where
    R: FnMut(&str, &[&str]) -> io::Result<Output>,
{
    /// Queries the runtime identities, recording a failure as an issue.
    fn runtime_identity(&mut self, target: Option<&str>) -> Option<RuntimeIdentity> {
        let kernel = self
            .kernel_uuid()
            .map_err(|issue| self.report.issues.push(issue))
            .ok()?;
        self.report.runtime_kernel_uuid = Some(kernel);
        let target = target
            .map(|target| self.target_uuid(target))
            .transpose()
            .map_err(|issue| self.report.issues.push(issue))
            .ok()?;
        self.report.runtime_target_uuid = target;
        Some(RuntimeIdentity { kernel, target })
    }

    /// Inspects the collections KernelManagement selected for this boot.
    fn inspect_selected<I>(&mut self, runtime: RuntimeIdentity, inspect: &mut I)
    where
        I: FnMut(&Path) -> Result<CollectionIdentity>,
    {
        match self.boot_collections() {
            Ok(collections) => {
                for (path, collection_uuid) in collections {
                    let candidate =
                        inspect_candidate(path, true, Some(collection_uuid), runtime, inspect);
                    self.report.candidates.push(candidate);
                }
            }
            Err(issue) => self.report.issues.push(issue),
        }
    }

    /// Inspects every fallback candidate not already inspected.
    fn inspect_fallback<I, F>(&mut self, fallback: F, runtime: RuntimeIdentity, inspect: &mut I)
    where
        I: FnMut(&Path) -> Result<CollectionIdentity>,
        F: FnOnce() -> (Vec<PathBuf>, Vec<String>),
    {
        let (paths, issues) = fallback();
        self.report.issues.extend(issues);
        let mut seen: HashSet<PathBuf> = self
            .report
            .candidates
            .iter()
            .map(|candidate| candidate.path.clone())
            .collect();
        for path in paths {
            if seen.insert(path.clone()) {
                let candidate = inspect_candidate(path, false, None, runtime, inspect);
                self.report.candidates.push(candidate);
            }
        }
    }

    /// Invalidates every match if the runtime identity changed during discovery,
    /// rather than combining evidence from different runtime states.
    fn confirm_unchanged(&mut self, initial: RuntimeIdentity, target: Option<&str>) {
        let kernel = self.kernel_uuid();
        let target = target.map(|target| self.loaded_uuid(target)).transpose();
        let issue = match (kernel, target) {
            (Ok(kernel), Ok(target)) => {
                let current = RuntimeIdentity { kernel, target };
                if current == initial {
                    return;
                }
                format!("runtime identity changed during discovery: was {initial}, now {current}")
            }
            (Err(issue), _) | (_, Err(issue)) => {
                format!("final runtime identity query failed: {issue}")
            }
        };
        self.report.issues.push(issue);
        for candidate in self
            .report
            .candidates
            .iter_mut()
            .filter(|candidate| candidate.verified)
        {
            candidate.verified = false;
            candidate.error = Some("runtime identity was not stable across discovery".into());
        }
    }

    fn kernel_uuid(&mut self) -> std::result::Result<KernelUuid, Issue> {
        let output = self.run(SYSCTL, &["-n", "kern.uuid"])?;
        output.trim().parse().map_err(describe)
    }

    fn target_uuid(&mut self, target: &str) -> std::result::Result<KernelUuid, Issue> {
        if target.is_empty() || target.chars().any(char::is_whitespace) {
            return Err("target must be one exact bundle identifier".into());
        }
        self.loaded_uuid(target)
    }

    fn loaded_uuid(&mut self, target: &str) -> std::result::Result<KernelUuid, Issue> {
        let output = self.run(KMUTIL, &["showloaded", "-b", target])?;
        parse_loaded_uuid(&output, target)
    }

    fn boot_collections(&mut self) -> std::result::Result<Vec<(PathBuf, KernelUuid)>, Issue> {
        let output = self.run(KMUTIL, &["inspect", "--show-kernel-uuid-only"])?;
        parse_boot_collections(&output)
    }

    /// Runs a command, records its evidence, and returns its standard output.
    fn run(&mut self, program: &str, args: &[&str]) -> std::result::Result<String, Issue> {
        let mut evidence = DiscoveryCommand {
            program: program.into(),
            args: args.iter().map(|arg| arg.to_string()).collect(),
            exit_code: None,
            stdout: String::new(),
            stderr: String::new(),
            error: None,
        };
        match (self.run)(program, args) {
            Ok(output) => {
                evidence.exit_code = output.status.code();
                evidence.stdout = String::from_utf8_lossy(&output.stdout).into_owned();
                evidence.stderr = String::from_utf8_lossy(&output.stderr).into_owned();
                if !output.status.success() {
                    evidence.error = Some(format!(
                        "{program} failed with status {:?}",
                        output.status.code()
                    ));
                } else if std::str::from_utf8(&output.stdout).is_err() {
                    evidence.error = Some(format!("{program} stdout is not UTF-8"));
                }
            }
            Err(error) => evidence.error = Some(format!("{program}: {error}")),
        }
        let result = match &evidence.error {
            Some(error) => Err(error.clone()),
            None => Ok(evidence.stdout.clone()),
        };
        self.report.commands.push(evidence);
        result
    }
}

fn inspect_candidate<I>(
    path: PathBuf,
    selected: bool,
    advertised_collection_uuid: Option<KernelUuid>,
    runtime: RuntimeIdentity,
    inspect: &mut I,
) -> KernelCandidate
where
    I: FnMut(&Path) -> Result<CollectionIdentity>,
{
    let (identity, error) = match inspect(&path) {
        Ok(identity) => {
            let mismatch = identity_mismatch(&identity, advertised_collection_uuid, runtime);
            (Some(identity), mismatch)
        }
        Err(error) => (None, Some(error.to_string())),
    };
    KernelCandidate {
        verified: identity.is_some() && error.is_none(),
        path,
        selected,
        advertised_collection_uuid,
        identity,
        error,
    }
}

/// Explains why a candidate does not match the runtime, or returns `None` if it does.
fn identity_mismatch(
    identity: &CollectionIdentity,
    advertised_collection_uuid: Option<KernelUuid>,
    runtime: RuntimeIdentity,
) -> Option<String> {
    if advertised_collection_uuid.is_some_and(|uuid| Some(uuid) != identity.collection_uuid) {
        return Some("selected collection UUID differs from direct binary inspection".into());
    }
    if identity.kernel_uuid != runtime.kernel {
        return Some(format!(
            "kernel UUID mismatch: embedded {}, runtime {}",
            identity.kernel_uuid, runtime.kernel
        ));
    }
    let expected = runtime.target?;
    (identity.target_uuid != Some(expected)).then(|| {
        let embedded = identity
            .target_uuid
            .map_or_else(|| "unknown".to_string(), |uuid| uuid.to_string());
        format!("target UUID mismatch or missing: embedded {embedded}, runtime {expected}")
    })
}

fn describe(error: Error) -> Issue {
    match error {
        Error::Parse { reason, .. } => reason,
        other => other.to_string(),
    }
}

// =============================================================================
// Command Output Parsing
// =============================================================================

/// Parses `kmutil inspect --show-kernel-uuid-only` boot collection headers:
/// `boot kernel collection at <path> (<collection UUID>):`.
fn parse_boot_collections(text: &str) -> std::result::Result<Vec<(PathBuf, KernelUuid)>, Issue> {
    let mut collections = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("boot kernel collection at ") else {
            continue;
        };
        let (path, uuid) = rest
            .rsplit_once(" (")
            .ok_or("kmutil boot header structure changed")?;
        let uuid = uuid
            .strip_suffix("):")
            .ok_or("kmutil boot header terminator changed")?;
        if !Path::new(path).is_absolute() {
            return Err("kmutil boot collection path is not absolute".into());
        }
        collections.push((PathBuf::from(path), uuid.parse().map_err(describe)?));
    }
    if collections.is_empty() {
        return Err(
            "kmutil boot collection header not found; output structure may have changed".into(),
        );
    }
    Ok(collections)
}

/// Finds the UUID of the exact `target` row in `kmutil showloaded` output.
fn parse_loaded_uuid(text: &str, target: &str) -> std::result::Result<KernelUuid, Issue> {
    let has_header = text.lines().any(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        fields.starts_with(&["Index", "Refs", "Address"])
            && fields
                .windows(3)
                .any(|window| window == ["Name", "(Version)", "UUID"])
    });
    if !has_header {
        return Err(
            "kmutil showloaded table header not found; output structure may have changed".into(),
        );
    }

    let mut found = None;
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        for row in fields.windows(3) {
            let [name, version, uuid] = row else {
                continue;
            };
            let is_target = *name == target && version.starts_with('(') && version.ends_with(')');
            if is_target && found.replace(uuid.parse().map_err(describe)?).is_some() {
                return Err("multiple loaded target rows".into());
            }
        }
    }
    found.ok_or_else(|| {
        format!(
            "exact loaded target UUID not found for {target}; driver may be unloaded or output changed"
        )
    })
}

// =============================================================================
// Fallback Search
// =============================================================================

#[derive(Debug, Clone, Copy)]
enum EntryKind {
    Directory,
    File,
}

/// Lists fallback candidates without following directory symlinks:
///
/// - `<preboot>/*/boot/*/System/Library/Caches/com.apple.kernelcaches/kernelcache*`
/// - `<collections>/*.kc*`
fn fallback_candidates(preboot: &Path, collections: &Path) -> (Vec<PathBuf>, Vec<String>) {
    let mut issues = Vec::new();
    let mut paths = Vec::new();
    let any_name = |_: &str| true;
    for volume in entries(preboot, EntryKind::Directory, any_name, &mut issues) {
        for boot in entries(
            &volume.join("boot"),
            EntryKind::Directory,
            any_name,
            &mut issues,
        ) {
            paths.extend(entries(
                &boot.join(PREBOOT_KERNELCACHES),
                EntryKind::File,
                |name| name.starts_with("kernelcache"),
                &mut issues,
            ));
        }
    }
    paths.extend(entries(
        collections,
        EntryKind::File,
        |name| name.contains(".kc"),
        &mut issues,
    ));
    paths.sort();
    paths.dedup();
    (paths, issues)
}

/// Lists the entries of `directory` with a matching name and kind.
///
/// A missing directory is empty; other failures are recorded as issues.
fn entries(
    directory: &Path,
    kind: EntryKind,
    matches_name: impl Fn(&str) -> bool,
    issues: &mut Vec<String>,
) -> Vec<PathBuf> {
    let read = match fs::read_dir(directory) {
        Ok(read) => read,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => {
            issues.push(format!("{}: {error}", directory.display()));
            return Vec::new();
        }
    };
    let mut paths = Vec::new();
    for entry in read {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) => {
                issues.push(format!("{}: {error}", directory.display()));
                continue;
            }
        };
        if !matches_name(&entry.file_name().to_string_lossy()) {
            continue;
        }
        // DirEntry::file_type does not follow symlinks, which bounds the traversal.
        match entry.file_type() {
            Ok(file_type) => {
                let matches_kind = match kind {
                    EntryKind::Directory => file_type.is_dir(),
                    EntryKind::File => file_type.is_file(),
                };
                if matches_kind {
                    paths.push(entry.path());
                }
            }
            Err(error) => issues.push(format!("{}: {error}", entry.path().display())),
        }
    }
    paths
}

#[cfg(all(test, unix))]
mod tests {
    use std::cell::Cell;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    use super::*;

    const KERNEL: &str = "9B65BD6E-027B-34D1-A22B-AC03DCCFFC84";
    const COLLECTION: &str = "B729A46E-1EE1-4DB2-3BE3-F2B6AE0D783E";
    const TARGET_UUID: &str = "227F9DF7-645D-39B8-B74A-685303D16B4B";
    const TARGET: &str = "com.apple.driver.FairPlayIOKit";

    fn output(stdout: String, code: i32) -> io::Result<Output> {
        Ok(Output {
            status: ExitStatus::from_raw(code << 8),
            stdout: stdout.into_bytes(),
            stderr: b"separate stderr\n".to_vec(),
        })
    }

    fn boot_header(path: &str) -> String {
        format!(
            "boot kernel collection at {path} ({COLLECTION}):\n\
             com.apple.kernel\tversion\t<unknown>\t({KERNEL})\n"
        )
    }

    fn loaded_table(id: &str, uuid: &str) -> String {
        format!(
            "Index Refs Address Size Wired Name (Version) UUID <Linked Against>\n\
             31 3 0xffff 0x10 0x10 {id} (72.19.0) {uuid} <9 8>\n"
        )
    }

    fn identity(with_target: bool) -> CollectionIdentity {
        CollectionIdentity {
            collection_uuid: Some(COLLECTION.parse().unwrap()),
            kernel_uuid: KERNEL.parse().unwrap(),
            target_uuid: with_target.then(|| TARGET_UUID.parse().unwrap()),
        }
    }

    fn no_fallback() -> (Vec<PathBuf>, Vec<String>) {
        (Vec::new(), Vec::new())
    }

    #[test]
    fn uuids_round_trip_and_reject_malformed_text() {
        let uuid: KernelUuid = KERNEL.to_lowercase().parse().unwrap();
        assert_eq!(uuid.to_string(), KERNEL);
        for malformed in [
            "",
            "9B65BD6E027B34D1A22BAC03DCCFFC84",
            "9B65BD6E-027B-34D1-A22B-AC03DCCFFC8Z",
        ] {
            assert!(malformed.parse::<KernelUuid>().is_err(), "{malformed:?}");
        }
    }

    #[test]
    fn boot_collection_headers_are_parsed_strictly() {
        let collections = parse_boot_collections(&boot_header("/path with spaces/cache")).unwrap();
        assert_eq!(collections[0].0, Path::new("/path with spaces/cache"));
        for malformed in [
            "changed output",
            "boot kernel collection at relative/path (invalid):",
            "boot kernel collection at /cache (invalid):",
        ] {
            assert!(parse_boot_collections(malformed).is_err(), "{malformed:?}");
        }
    }

    #[test]
    fn loaded_target_rows_require_an_exact_unique_match() {
        let uuid = parse_loaded_uuid(&loaded_table(TARGET, TARGET_UUID), TARGET).unwrap();
        assert_eq!(uuid.to_string(), TARGET_UUID);

        let longer_id = loaded_table(&format!("{TARGET}Extra"), TARGET_UUID);
        assert!(parse_loaded_uuid(&longer_id, TARGET).is_err());
        let without_header = format!("{TARGET} (1.0) {TARGET_UUID}");
        assert!(parse_loaded_uuid(&without_header, TARGET).is_err());
        let duplicated = loaded_table(TARGET, TARGET_UUID).repeat(2);
        assert!(parse_loaded_uuid(&duplicated, TARGET).is_err());
    }

    #[test]
    fn selected_candidate_checks_kernel_and_target_separately_and_retains_commands() {
        let fallback_called = Cell::new(false);
        let mut run = |program: &str, args: &[&str]| {
            let stdout = if program == SYSCTL {
                format!("{KERNEL}\n")
            } else if args[0] == "showloaded" {
                loaded_table(TARGET, TARGET_UUID)
            } else {
                boot_header("/selected")
            };
            output(stdout, 0)
        };
        let report = discover_with(Some(TARGET), &mut run, &mut |_| Ok(identity(true)), || {
            fallback_called.set(true);
            no_fallback()
        });

        assert!(!fallback_called.get());
        assert_eq!(report.matches().count(), 1);
        let candidate = &report.candidates[0];
        assert_ne!(
            report.runtime_kernel_uuid,
            candidate.identity.as_ref().unwrap().collection_uuid
        );
        assert_eq!(report.runtime_target_uuid.unwrap().to_string(), TARGET_UUID);
        assert_eq!(report.commands.len(), 5);
        assert!(
            report.commands.iter().all(
                |command| command.exit_code == Some(0) && command.stderr == "separate stderr\n"
            )
        );
    }

    #[test]
    fn stale_selection_is_kept_while_every_matching_fallback_copy_is_returned() {
        let mut run = |program: &str, _: &[&str]| {
            let stdout = if program == SYSCTL {
                KERNEL.to_string()
            } else {
                boot_header("/stale")
            };
            output(stdout, 0)
        };
        let mut inspect = |path: &Path| {
            if path == Path::new("/unreadable") {
                return Err(Error::parse(0, "permission denied"));
            }
            let mut found = identity(false);
            if path == Path::new("/stale") {
                found.kernel_uuid = TARGET_UUID.parse().unwrap();
            }
            Ok(found)
        };
        let report = discover_with(None, &mut run, &mut inspect, || {
            let paths = ["/copy-a", "/copy-b", "/copy-a", "/unreadable"];
            (
                paths.into_iter().map(PathBuf::from).collect(),
                vec!["unreadable fallback directory".into()],
            )
        });

        let matches: Vec<_> = report
            .matches()
            .map(|candidate| candidate.path.to_str().unwrap())
            .collect();
        assert_eq!(matches, ["/copy-a", "/copy-b"]);
        let stale = report.candidates[0].error.as_deref().unwrap();
        assert!(stale.contains("kernel UUID mismatch"));
        let unreadable = report.candidates.last().unwrap().error.as_deref().unwrap();
        assert!(unreadable.contains("permission denied"));
        assert_eq!(report.issues.len(), 1);
    }

    #[test]
    fn failed_command_status_and_changed_text_trigger_fallback() {
        for (text, code) in [
            (boot_header("/do-not-trust"), 1),
            ("new output format".into(), 0),
        ] {
            let mut run = |program: &str, _: &[&str]| {
                if program == SYSCTL {
                    output(KERNEL.into(), 0)
                } else {
                    output(text.clone(), code)
                }
            };
            let report = discover_with(None, &mut run, &mut |_| Ok(identity(false)), || {
                (vec!["/fallback".into()], Vec::new())
            });
            assert_eq!(report.matches().count(), 1);
            assert!(!report.candidates[0].selected);
            assert!(!report.issues.is_empty());
        }
    }

    #[test]
    fn unloaded_or_mismatched_target_never_verifies_a_candidate() {
        let tables = [
            loaded_table(&format!("{TARGET}Extra"), TARGET_UUID),
            loaded_table(TARGET, KERNEL),
        ];
        for table in tables {
            let mut run = |program: &str, args: &[&str]| {
                let stdout = if program == SYSCTL {
                    KERNEL.to_string()
                } else if args[0] == "showloaded" {
                    table.clone()
                } else {
                    boot_header("/selected")
                };
                output(stdout, 0)
            };
            let report = discover_with(
                Some(TARGET),
                &mut run,
                &mut |_| Ok(identity(true)),
                no_fallback,
            );
            assert_eq!(report.matches().count(), 0);
        }
    }

    #[test]
    fn changing_runtime_invalidates_an_earlier_match() {
        let mut kernel_queries = 0;
        let mut run = |program: &str, _: &[&str]| {
            if program == SYSCTL {
                kernel_queries += 1;
                let uuid = if kernel_queries == 1 {
                    KERNEL
                } else {
                    TARGET_UUID
                };
                output(uuid.into(), 0)
            } else {
                output(boot_header("/selected"), 0)
            }
        };
        let report = discover_with(None, &mut run, &mut |_| Ok(identity(false)), no_fallback);
        assert_eq!(report.matches().count(), 0);
        assert!(report.issues[0].contains("runtime identity changed"));
    }

    #[test]
    fn fallback_search_is_bounded_and_reports_unreadable_paths() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path();
        let cache_dir = root
            .join("preboot/volume/boot/build")
            .join(PREBOOT_KERNELCACHES);
        fs::create_dir_all(&cache_dir).unwrap();
        fs::write(cache_dir.join("kernelcache.release"), []).unwrap();
        fs::write(cache_dir.join("other"), []).unwrap();
        let collections = root.join("kc");
        fs::create_dir(&collections).unwrap();
        fs::write(collections.join("BootKernelExtensions.kc"), []).unwrap();
        std::os::unix::fs::symlink(root, root.join("preboot/loop")).unwrap();

        let (paths, issues) = fallback_candidates(&root.join("preboot"), &collections);
        assert_eq!(paths.len(), 2);
        assert!(issues.is_empty());

        // Reading a regular file as a directory is reported, not ignored.
        let not_a_directory = cache_dir.join("kernelcache.release");
        let (_, issues) = fallback_candidates(&root.join("preboot"), &not_a_directory);
        assert_eq!(issues.len(), 1);
    }
}
