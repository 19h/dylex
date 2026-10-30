//! End-to-end image lookup using synthetic cache headers and image tables.
use dylex::dyld::DyldCacheHeader;
use std::{
    fs,
    mem::{offset_of, size_of},
    path::Path,
    process::Command,
};

fn cache(path: &Path, image: &str) {
    let mut bytes = vec![0u8; 0x1000];
    bytes[..16].copy_from_slice(b"dyld_v1  arm64e\0");
    let mapping = size_of::<DyldCacheHeader>();
    bytes[16..20].copy_from_slice(&(mapping as u32).to_le_bytes());
    bytes[20..24].copy_from_slice(&1u32.to_le_bytes());
    bytes[mapping..mapping + 8].copy_from_slice(&0x180000000u64.to_le_bytes());
    bytes[mapping + 8..mapping + 16].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[mapping + 24..mapping + 28].copy_from_slice(&7u32.to_le_bytes());
    bytes[mapping + 28..mapping + 32].copy_from_slice(&5u32.to_le_bytes());
    let images = offset_of!(DyldCacheHeader, images_offset);
    bytes[images..images + 4].copy_from_slice(&0x600u32.to_le_bytes());
    let count = offset_of!(DyldCacheHeader, images_count);
    bytes[count..count + 4].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x600..0x608].copy_from_slice(&0x180000000u64.to_le_bytes());
    bytes[0x618..0x61c].copy_from_slice(&0x800u32.to_le_bytes());
    bytes[0x800..0x800 + image.len()].copy_from_slice(image.as_bytes());
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

#[test]
fn find_searches_every_cache_and_disk_roots_and_reports_partial_failures() {
    let dir = tempfile::tempdir().unwrap();
    let known = dir.path().join("known");
    let extra = dir.path().join("extra");
    let first = known.join("OS/System/Library/dyld/dyld_shared_cache_arm64e");
    let staged = known.join("Incoming/OS/System/Library/dyld/dyld_shared_cache_arm64e");
    let deep = extra.join("a/b/c/d/e/f/g/h/i/j/dyld_shared_cache_arm64e");
    for path in [&first, &staged, &deep] {
        cache(path, "/usr/lib/libExample.dylib");
    }
    let output = Command::new(env!("CARGO_BIN_EXE_dylex"))
        .args(["find", "LIBEXAMPLE.DYLIB", "--exact", "-i", "-a", "arm"])
        .arg(&known)
        .arg("--scan-root")
        .arg(&extra)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).unwrap();
    for path in [&first, &staged, &deep] {
        assert!(stdout.contains(&format!(
            "arm64e\t{}\t/usr/lib/libExample.dylib",
            path.display()
        )));
    }
    assert_eq!(stdout.lines().count(), 4);

    let corrupt = known.join("dyld_shared_cache_broken");
    fs::write(&corrupt, b"dyld_v1  arm64e\0").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_dylex"))
        .args(["find", "libExample.dylib", "--exact"])
        .arg(&known)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Search incomplete"));
    assert_eq!(String::from_utf8_lossy(&output.stdout).lines().count(), 3);

    fs::remove_file(corrupt).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_dylex"))
        .args(["find", "no-such-image", "--exact"])
        .arg(&known)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(String::from_utf8_lossy(&output.stdout).lines().count(), 1);
    let output = Command::new(env!("CARGO_BIN_EXE_dylex"))
        .args(["find", ""])
        .arg(&known)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("must not be empty"));

    let output = Command::new(env!("CARGO_BIN_EXE_dylex"))
        .arg("arches")
        .arg(&extra)
        .arg("--scan-root")
        .arg(&extra)
        .output()
        .unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8_lossy(&output.stdout)
            .matches("arm64e - ")
            .count(),
        1
    );
}
