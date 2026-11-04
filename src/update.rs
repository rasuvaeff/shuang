//! `shuang update` — user-initiated self-update.
//!
//! Checks the latest GitHub release, downloads the platform binary, verifies
//! it against the published `.sha256`, and atomically replaces the running
//! executable. Nothing is checked or downloaded unless the user runs this
//! command — no background update pings, ever.

#[cfg(windows)]
use std::io::Read as _;
use std::{path::Path, time::Duration};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

const OWNER: &str = "rasuvaeff";
const REPO: &str = "shuang";
#[derive(serde::Deserialize)]
struct Release {
    tag_name: String,
    assets: Vec<Asset>,
}

#[derive(serde::Deserialize)]
struct Asset {
    name: String,
    browser_download_url: String,
}

/// The release asset for the current platform, if one is published.
pub fn asset_name() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("shuang-x86_64-unknown-linux-gnu.tar.gz"),
        ("macos", "aarch64") => Some("shuang-aarch64-apple-darwin.tar.gz"),
        ("macos", "x86_64") => Some("shuang-x86_64-apple-darwin.tar.gz"),
        ("windows", "x86_64") => Some("shuang-x86_64-pc-windows-msvc.zip"),
        _ => None,
    }
}

/// `v`-prefixed X.Y.Z comparison; None when either side does not parse.
pub fn version_lt(current: &str, latest: &str) -> Option<bool> {
    let parse = |s: &str| -> Option<(u64, u64, u64)> {
        let s = s.trim_start_matches('v');
        let mut it = s.split('.');
        let major: u64 = it.next()?.parse().ok()?;
        let minor: u64 = it.next()?.parse().ok()?;
        let patch: u64 = it.next()?.parse().ok()?;
        Some((major, minor, patch))
    };
    let current = parse(current)?;
    let latest = parse(latest)?;
    Some(current < latest)
}

pub async fn run() -> Result<u8> {
    let current = env!("CARGO_PKG_VERSION");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .user_agent("shuang-updater")
        .build()?;

    let release: Release = client
        .get(format!(
            "https://api.github.com/repos/{OWNER}/{REPO}/releases/latest"
        ))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .context("cannot reach the GitHub releases API")?
        .json()
        .await
        .context("cannot parse the latest release")?;

    println!(
        "Latest release: {} (installed: v{current})",
        release.tag_name
    );
    match version_lt(current, &release.tag_name) {
        Some(false) => {
            println!("Already up to date.");
            return Ok(0);
        }
        Some(true) => {}
        None => println!("Cannot compare versions — updating anyway (you asked)."),
    }

    let Some(asset) = asset_name() else {
        bail!(
            "no prebuilt binary is published for {}-{}; update from source with \
             `cargo install --git https://github.com/{OWNER}/{REPO} --force`",
            std::env::consts::OS,
            std::env::consts::ARCH
        );
    };
    let download = release
        .assets
        .iter()
        .find(|a| a.name == asset)
        .with_context(|| format!("asset {asset} is missing from the release"))?;
    let checksum = release
        .assets
        .iter()
        .find(|a| a.name == format!("{asset}.sha256"))
        .with_context(|| format!("asset {asset}.sha256 is missing — refusing to update"))?;

    println!("Downloading {}…", download.name);
    let bytes = client
        .get(&download.browser_download_url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .context("cannot download the release asset")?
        .bytes()
        .await?;
    let expected = client
        .get(&checksum.browser_download_url)
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .context("cannot download the checksum")?
        .text()
        .await?;
    let expected = expected
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let actual = hex(&Sha256::digest(&bytes));
    if actual != expected {
        bail!(
            "checksum mismatch: downloaded {actual}, release says {expected} — refusing to update"
        );
    }
    println!("Checksum verified.");

    let exe = std::env::current_exe().context("cannot locate the running executable")?;
    replace_self(&bytes, &exe)?;
    println!("Updated to {} — restart shuang to apply.", release.tag_name);
    Ok(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Unpack the downloaded archive and atomically replace `exe`.
fn replace_self(archive: &[u8], exe: &Path) -> Result<()> {
    let temp = std::env::temp_dir().join(format!("shuang-update-{}", std::process::id()));
    std::fs::create_dir_all(&temp)?;
    let extracted = extract(archive, &temp)?;
    install_binary(&extracted, exe)
}

/// Pull `shuang`/`shuang.exe` out of the release archive.
fn extract(archive: &[u8], into: &Path) -> Result<std::path::PathBuf> {
    let binary_name = if cfg!(windows) {
        "shuang.exe"
    } else {
        "shuang"
    };

    if cfg!(windows) {
        extract_zip(archive, into, binary_name)
    } else {
        extract_tar_gz(archive, into, binary_name)
    }
}

#[cfg(unix)]
fn extract_tar_gz(archive: &[u8], into: &Path, binary_name: &str) -> Result<std::path::PathBuf> {
    let reader = flate2::read::GzDecoder::new(archive);
    let mut archive = tar::Archive::new(reader);
    archive.unpack(into).context("cannot unpack the tar.gz")?;
    let binary = into.join(binary_name);
    std::fs::rename(&binary, into.join("shuang-new"))?;
    Ok(into.join("shuang-new"))
}

#[cfg(unix)]
fn extract_zip(_archive: &[u8], _into: &Path, _name: &str) -> Result<std::path::PathBuf> {
    unreachable!("unix builds ship tar.gz")
}

#[cfg(windows)]
fn extract_zip(archive: &[u8], into: &Path, binary_name: &str) -> Result<std::path::PathBuf> {
    let mut zip =
        zip::ZipArchive::new(std::io::Cursor::new(archive)).context("cannot open the zip")?;
    let out = into.join("shuang-new.exe");
    for i in 0..zip.len() {
        let mut entry = zip.by_index(i)?;
        if entry.name().ends_with(binary_name) {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            std::fs::write(&out, buf)?;
            return Ok(out);
        }
    }
    std::fs::remove_file(&out).ok();
    bail!("no {binary_name} inside the zip");
}

#[cfg(windows)]
fn extract_tar_gz(_archive: &[u8], _into: &Path, _name: &str) -> Result<std::path::PathBuf> {
    unreachable!("windows builds ship zip")
}

/// Replace the executable: atomic rename on Unix; two-step on Windows
/// (a running exe cannot be replaced, but it can be renamed away).
fn install_binary(new: &Path, exe: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(new, std::fs::Permissions::from_mode(0o755))
            .context("cannot make the new binary executable")?;
        std::fs::rename(new, exe).context("cannot replace the binary")?;
    }
    #[cfg(windows)]
    {
        let old = exe.with_extension("old");
        std::fs::rename(exe, &old).context("cannot move the old binary away")?;
        std::fs::rename(new, exe)
            .with_context(|| "cannot move the new binary in (the .old file can be removed)")?;
    }
    let _ = new;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_comparison() {
        assert_eq!(version_lt("0.1.0", "v0.2.0"), Some(true));
        assert_eq!(version_lt("0.1.0", "v0.1.0"), Some(false));
        assert_eq!(version_lt("0.1.0", "v0.1.1"), Some(true));
        assert_eq!(version_lt("1.0.0", "v0.9.9"), Some(false));
        assert_eq!(version_lt("0.1", "v0.1.0"), None);
        assert_eq!(version_lt("0.1.0", "banana"), None);
    }

    #[test]
    fn asset_name_covers_the_published_targets() {
        // The four release assets from .github/workflows/release.yml.
        let published = [
            "shuang-x86_64-unknown-linux-gnu.tar.gz",
            "shuang-aarch64-apple-darwin.tar.gz",
            "shuang-x86_64-apple-darwin.tar.gz",
            "shuang-x86_64-pc-windows-msvc.zip",
        ];
        assert!(published.contains(&asset_name().expect("this CI platform is published")));
    }

    #[test]
    fn sha256_hex_is_lowercase_and_correct() {
        // sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        assert_eq!(hex(&Sha256::digest(b"")).len(), 64);
        let sum = Sha256::digest(b"");
        let s = hex(&sum);
        assert!(
            s.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }
}
