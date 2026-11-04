//! `shuang daemon` — watch the configured apps continuously.
//!
//! Every tick the external IP is checked; while it is not allowed the whole
//! process tree of every matching app is frozen, after the grace period the
//! trees are stopped. The daemon keeps running: a stopped app that the user
//! restarts is frozen again on the next tick while the IP stays bad.

use std::{collections::HashSet, path::Path, time::Duration};

use anyhow::{Result, bail};
use sysinfo::System;

use crate::{
    config,
    guard::{Guard, Stage},
    ipcheck, net,
    net::Allowlist,
    platform, procs,
};

pub async fn run(config_path: &Path, explicit: bool) -> Result<u8> {
    let cfg = config::load(config_path, explicit)?;
    if cfg.ip_check.interval_secs == 0 {
        bail!("ip_check.interval_secs must be at least 1");
    }
    if cfg.apps.is_empty() {
        bail!("no [apps]] configured — add one to config.toml (see README)");
    }
    let state = config::load_state(config_path);
    let list = Allowlist::merged(&cfg.allow, &state.allow);

    let patterns: Vec<String> = cfg.apps.iter().flat_map(|a| a.r#match.clone()).collect();
    let interval = Duration::from_secs(cfg.ip_check.interval_secs);
    let grace = Duration::from_secs(cfg.timing.grace_secs);
    let close_timeout = Duration::from_secs(cfg.timing.close_secs);
    let mut guard = Guard::new(grace);
    let mut suspended: HashSet<u32> = HashSet::new();

    eprintln!(
        "shuang: daemon started, watching {} pattern(s)",
        patterns.len()
    );

    loop {
        let verdict = ipcheck::check(&cfg.ip_check).await;
        let system = System::new_all();
        let targets = procs::find_targets(&patterns, &system);
        let target_pids: Vec<u32> = targets.iter().map(|(_, pid)| *pid).collect();

        if net::allowed(&verdict, &list) {
            if guard.good() && !suspended.is_empty() {
                for pid in suspended.drain() {
                    let _ = platform::resume(pid);
                }
                eprintln!("shuang: allowed IP is back — resumed");
            }
            tokio::time::sleep(interval).await;
            continue;
        }

        let ip = verdict
            .ipv4
            .map(|i| i.to_string())
            .unwrap_or_else(|| "unknown".into());
        match guard.bad() {
            Stage::Freeze => {
                freeze_new(&target_pids, &system, &mut suspended);
                eprintln!(
                    "shuang: IP {ip} not allowed — froze {} process(es)",
                    suspended.len()
                );
            }
            Stage::Frozen(elapsed) => {
                // New matching processes started while frozen: freeze them too.
                freeze_new(&target_pids, &system, &mut suspended);
                let left = grace.saturating_sub(elapsed).as_secs();
                eprintln!("shuang: frozen, {left}s left for the allowed IP to come back");
            }
            Stage::MustClose => {
                eprintln!("shuang: allowed IP never came back — stopping protected apps");
                for pid in suspended.drain() {
                    let _ = platform::terminate(pid);
                }
                std::thread::sleep(close_timeout);
                // A fresh scan: the app may have spawned or exited meanwhile.
                for (_, pid) in procs::find_targets(&patterns, &system) {
                    let _ = platform::kill(pid);
                }
                // The daemon keeps watching; the guard restarts on the next bad tick.
                guard.good();
            }
        }

        tokio::time::sleep(interval).await;
    }
}

fn freeze_new(target_pids: &[u32], system: &System, suspended: &mut HashSet<u32>) {
    for pid in target_pids {
        if suspended.contains(pid) {
            continue;
        }
        for tree_pid in procs::tree(*pid, system) {
            if suspended.contains(&tree_pid) {
                continue;
            }
            if platform::suspend(tree_pid).is_ok() {
                suspended.insert(tree_pid);
            }
        }
    }
}
