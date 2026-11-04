//! Append-only event history (`history.log` next to the config file) and
//! `shuang events` to read it back.
//!
//! The format is one line per event: `<iso8601-utc>\t<kind>\t<detail>`.
//! IP addresses and countries appear in events — the file lives next to the
//! user's own config and never leaves the machine.

use std::{
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

pub fn history_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("history.log")
}

/// Append one event. A failing append must never kill protection: errors are
/// returned but callers log-and-continue.
pub fn append_line(config_path: &Path, kind: &str, detail: &str) -> Result<()> {
    use std::io::Write;
    let path = history_path(config_path);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .with_context(|| format!("cannot open {}", path.display()))?;
    writeln!(file, "{}\t{kind}\t{detail}", iso8601_utc(now_secs()))
        .with_context(|| format!("cannot write {}", path.display()))
}

pub fn read_tail(config_path: &Path, tail: usize) -> Result<Vec<String>> {
    let path = history_path(config_path);
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err).with_context(|| format!("cannot read {}", path.display())),
    };
    let lines: Vec<String> = raw.lines().map(String::from).collect();
    let start = lines.len().saturating_sub(tail);
    Ok(lines[start..].to_vec())
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parse an ISO line timestamp back to unix seconds (inverse of
/// `iso8601_utc`); None for malformed lines.
pub fn parse_iso8601(line: &str) -> Option<u64> {
    let ts = line.split('\t').next()?;
    let date_time = ts.strip_suffix('Z')?;
    let [date, time] = date_time.split('T').collect::<Vec<_>>().try_into().ok()?;
    let [y, m, d] = date.split('-').collect::<Vec<_>>().try_into().ok()?;
    let [h, min, s] = time.split(':').collect::<Vec<_>>().try_into().ok()?;
    let (y, m, d): (i64, u64, u64) = (y.parse().ok()?, m.parse().ok()?, d.parse().ok()?);
    let (h, min, s): (u64, u64, u64) = (h.parse().ok()?, min.parse().ok()?, s.parse().ok()?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) || h > 23 || min > 59 || s > 59 {
        return None;
    }
    // Days from civil (Hinnant), inverse of the algorithm in iso8601_utc.
    let yy = if m <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy.rem_euclid(400) as u64;
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe as i64 - 719_468;
    Some((days * 86_400 + (h * 3600 + min * 60 + s) as i64) as u64)
}

/// UTC ISO-8601 (`2026-11-04T21:09:55Z`) from unix seconds, no external
/// crates. Civil-from-days per Howard Hinnant's algorithm.
pub fn iso8601_utc(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);

    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    let mut out = String::new();
    let _ = write!(
        out,
        "{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z"
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_formats() {
        assert_eq!(iso8601_utc(0), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn known_dates() {
        // Cross-checked with `date -u -d … +%s`.
        assert_eq!(iso8601_utc(1_793_750_400), "2026-11-04T00:00:00Z");
        assert_eq!(iso8601_utc(1_709_210_096), "2024-02-29T12:34:56Z");
        assert_eq!(iso8601_utc(1_735_689_600), "2025-01-01T00:00:00Z");
    }

    #[test]
    fn append_and_read_tail() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("config.toml");
        for i in 0..5 {
            append_line(&cfg, "freeze", &format!("event {i}")).unwrap();
        }
        let tail = read_tail(&cfg, 3).unwrap();
        assert_eq!(tail.len(), 3);
        assert!(tail[2].ends_with("event 4"));
        assert!(tail[2].contains("\tfreeze\t"));
        // Missing history reads as empty, not an error (its own directory).
        let other = tempfile::tempdir().unwrap();
        assert!(
            read_tail(&other.path().join("none.toml"), 5)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn iso8601_roundtrip() {
        for secs in [0u64, 1_700_000_000, 1_793_750_400] {
            let rendered = iso8601_utc(secs);
            assert_eq!(parse_iso8601(&rendered), Some(secs), "{rendered}");
        }
        assert_eq!(parse_iso8601("garbage"), None);
        assert_eq!(parse_iso8601("2026-13-40T99:99:99Z\tfreeze\tx"), None);
    }
}
