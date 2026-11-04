//! `shuang run` — kill switch for a single command.
//!
//! Exit codes: 0 — command finished; 69 — IP not allowed at start; 75 — the
//! allowed IP never came back and the command was stopped.

use std::{collections::HashSet, path::Path, process::Stdio, time::Duration};

use anyhow::{Context, Result, bail};
use sysinfo::System;
use tokio::process::Command;

use crate::{
    config,
    guard::{Guard, Stage},
    ipcheck, net,
    net::Allowlist,
    platform, procs,
};

pub async fn run(config_path: &Path, command: Vec<String>) -> Result<u8> {
    let cfg = config::load(config_path)?;
    if cfg.ip_check.interval_secs == 0 {
        bail!("ip_check.interval_secs must be at least 1");
    }
    let state = config::load_state(config_path);
    let mut list = Allowlist::merged(&cfg.allow, &state.allow);

    let mut verdict = ipcheck::check(&cfg.ip_check).await;
    // First-run semantics: with an empty allowlist the IP observed at start is
    // the allowed one (Kordon's "remember the current IP" behavior).
    if list.is_empty() && verdict.quorum && verdict.ipv4.is_some() {
        if let Some(ip) = verdict.ipv4 {
            eprintln!("shuang: allowlist empty, allowing the startup IP {ip}");
            list.push_ip(ip);
        }
    }
    if !net::allowed(&verdict, &list) {
        let ip = verdict
            .ipv4
            .map(|i| i.to_string())
            .unwrap_or_else(|| "unknown".into());
        let country = verdict.country.as_deref().unwrap_or("??");
        eprintln!("shuang: IP {ip} ({country}) is not allowed — refusing to start");
        return Ok(69);
    }

    let program = &command[0];
    let mut child = Command::new(program)
        .args(&command[1..])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .with_context(|| format!("cannot start {program}"))?;
    let child_pid = child
        .id()
        .context("child exited before we could watch it")?;
    eprintln!("shuang: protecting {program} (pid {child_pid})");

    let interval = Duration::from_secs(cfg.ip_check.interval_secs);
    let grace = Duration::from_secs(cfg.timing.grace_secs);
    let close_timeout = Duration::from_secs(cfg.timing.close_secs);
    let mut guard = Guard::new(grace);
    let mut suspended: HashSet<u32> = HashSet::new();

    loop {
        tokio::time::sleep(interval).await;

        if let Some(status) = child.try_wait()? {
            let code = status
                .code()
                .unwrap_or(if status.success() { 0 } else { 1 });
            eprintln!("shuang: {program} exited with {code}");
            return Ok(code as u8);
        }

        verdict = ipcheck::check(&cfg.ip_check).await;
        if net::allowed(&verdict, &list) {
            if guard.good() {
                resume_all(&mut suspended);
                eprintln!("shuang: allowed IP is back — resumed");
            }
            continue;
        }

        let ip = verdict
            .ipv4
            .map(|i| i.to_string())
            .unwrap_or_else(|| "unknown".into());
        match guard.bad() {
            Stage::Freeze => {
                let system = System::new_all();
                let tree = procs::tree(child_pid, &system);
                freeze_tree(&tree, &mut suspended);
                eprintln!(
                    "shuang: IP {ip} not allowed — froze {} process(es)",
                    suspended.len()
                );
            }
            Stage::Frozen(elapsed) => {
                let left = grace.saturating_sub(elapsed).as_secs();
                eprintln!("shuang: frozen, {left}s left for the allowed IP to come back");
            }
            Stage::MustClose => {
                eprintln!("shuang: allowed IP never came back — stopping {program}");
                stop_all(&mut suspended, close_timeout);
                let _ = child.wait().await;
                return Ok(75);
            }
        }
    }
}

fn freeze_tree(tree: &[u32], suspended: &mut HashSet<u32>) {
    for pid in tree {
        if platform::suspend(*pid).is_ok() {
            suspended.insert(*pid);
        }
    }
}

fn resume_all(suspended: &mut HashSet<u32>) {
    for pid in suspended.drain() {
        // The process may be gone already: a resume failure is not an error.
        let _ = platform::resume(pid);
    }
}

fn stop_all(suspended: &mut HashSet<u32>, close_timeout: Duration) {
    let pids: Vec<u32> = suspended.drain().collect();
    for pid in &pids {
        let _ = platform::terminate(*pid);
    }
    std::thread::sleep(close_timeout);
    for pid in &pids {
        let _ = platform::kill(*pid);
    }
}
