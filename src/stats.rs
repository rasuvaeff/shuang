//! `shuang stats` — VPN health from `history.log`: freeze counts, average
//! freeze duration, and how often the allowed IP never came back (closes).
//! The raw material is already written by `run`/`daemon`; this only reads.

use std::path::Path;

use anyhow::Result;

use crate::events;

#[derive(Debug, Default)]
pub struct WeeklyStats {
    pub freezes: usize,
    pub closes: usize,
    pub resumes: usize,
    pub avg_freeze_secs: Option<u64>,
    /// Per-app freeze counts ("claude-code: 12").
    pub per_app: Vec<(String, usize)>,
}

pub fn parse(lines: &[String], since_secs: u64) -> WeeklyStats {
    let mut stats = WeeklyStats::default();
    let mut open_freezes: Vec<(String, u64)> = Vec::new(); // (app-ish detail, ts)
    let mut durations: Vec<u64> = Vec::new();
    let mut counts: std::collections::BTreeMap<String, usize> = std::collections::BTreeMap::new();

    for line in lines {
        let Some(ts) = events::parse_iso8601(line) else {
            continue;
        };
        if ts < since_secs {
            continue;
        }
        let mut parts = line.splitn(3, '\t');
        let kind = parts.nth(1).unwrap_or_default();
        let detail = parts.next().unwrap_or_default().to_string();
        // Freeze details look like "<app>: <reason>"; resume/close are "<app>".
        let app = detail
            .split(':')
            .next()
            .unwrap_or(&detail)
            .trim()
            .to_string();
        match kind {
            "freeze" => {
                stats.freezes += 1;
                *counts.entry(app.clone()).or_default() += 1;
                open_freezes.push((app, ts));
            }
            "resume" => {
                stats.resumes += 1;
                if let Some(pos) = open_freezes.iter().rposition(|(a, _)| *a == app) {
                    let (_, start) = open_freezes.remove(pos);
                    durations.push(ts.saturating_sub(start));
                }
            }
            "close" => {
                stats.closes += 1;
                if let Some(pos) = open_freezes.iter().rposition(|(a, _)| *a == app) {
                    open_freezes.remove(pos);
                }
            }
            _ => {}
        }
    }

    if !durations.is_empty() {
        stats.avg_freeze_secs = Some(durations.iter().sum::<u64>() / durations.len() as u64);
    }
    stats.per_app = counts.into_iter().collect();
    stats
}

pub fn run(config_path: &Path, tail: usize) -> Result<u8> {
    let lines = if tail == 0 {
        events::read_tail(config_path, usize::MAX)?
    } else {
        events::read_tail(config_path, tail)?
    };
    let now = events::now_secs();
    let week = 7 * 24 * 3600;
    let stats = parse(&lines, now.saturating_sub(week));

    println!("Last 7 days ({} history lines):", lines.len());
    println!("  freezes: {}", stats.freezes);
    println!("  resumes: {}", stats.resumes);
    println!("  closes (allowed IP never returned): {}", stats.closes);
    match stats.avg_freeze_secs {
        Some(avg) => println!("  average freeze duration: {avg}s"),
        None => println!("  average freeze duration: n/a (no freeze/resume pairs)"),
    }
    if !stats.per_app.is_empty() {
        println!("  per app:");
        for (app, count) in &stats.per_app {
            println!("    {app}: {count}");
        }
    }
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines() -> Vec<String> {
        vec![
            "2026-11-01T00:00:00Z\tfreeze\tclaude-code: IP changed".to_string(),
            "2026-11-01T00:00:08Z\tresume\tclaude-code".to_string(),
            "2026-11-02T00:00:00Z\tfreeze\tclaude-code: no quorum".to_string(),
            "2026-11-02T00:00:35Z\tresume\tclaude-code".to_string(),
            "2026-11-03T00:00:00Z\tfreeze\tcursor: IP changed".to_string(),
            "2026-11-03T00:00:25Z\tclose\tcursor".to_string(),
            "2020-01-01T00:00:00Z\tfreeze\told-app: ancient".to_string(), // out of window
        ]
    }

    #[test]
    fn weekly_counts_and_durations() {
        // Window starts at 2026-11-01T00:00:00Z (the first fixture line).
        let stats = parse(&lines(), 1_793_491_200);
        assert_eq!(stats.freezes, 3);
        assert_eq!(stats.resumes, 2);
        assert_eq!(stats.closes, 1);
        // (8 + 35) / 2
        assert_eq!(stats.avg_freeze_secs, Some(21));
        assert_eq!(stats.per_app.len(), 2);
        assert!(stats.per_app.contains(&("claude-code".to_string(), 2)));
        assert!(stats.per_app.contains(&("cursor".to_string(), 1)));
    }

    #[test]
    fn window_filters_old_events() {
        // Everything before 2026-11-03 falls out of a window starting there.
        let since = 1_793_664_000; // 2026-11-03T00:00:00Z
        let stats = parse(&lines(), since);
        assert_eq!(stats.freezes, 1);
        assert_eq!(stats.closes, 1);
        assert_eq!(stats.avg_freeze_secs, None);
    }
}
