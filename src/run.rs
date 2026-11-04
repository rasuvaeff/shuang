//! `shuang run` — kill switch for a single command.
//!
//! Exit codes: 0 — command finished (or clean shutdown); 69 — IP not allowed
//! at start; 75 — the allowed IP never came back and the command was stopped.
//!
//! Safety: Ctrl+C/SIGTERM resumes everything frozen before exiting; a crash
//! leaves the frozen pid set in `state.toml` and the next run recovers it.

use std::{path::Path, process::Stdio, time::Duration};

use anyhow::{Context, Result, bail};
use sysinfo::System;
use tokio::process::Command;

use crate::{
    config, events,
    guard::{Guard, Stage},
    ipcheck::{self, CountryCache},
    net, netwatch,
    notify::Notifier,
    procs,
    supervisor::{Frozen, Shutdown},
};

const OWNER: &str = "run";

pub async fn run(config_path: &Path, command: Vec<String>, explicit: bool) -> Result<u8> {
    let cfg = config::load(config_path, explicit)?;
    if cfg.ip_check.interval_secs == 0 {
        bail!("ip_check.interval_secs must be at least 1");
    }
    for warning in cfg.warnings() {
        eprintln!("shuang: warning: {warning}");
    }
    let state = config::load_state(config_path);
    let (mut list, profile_warning) = net::effective(&cfg, &state);
    if let Some(w) = profile_warning {
        eprintln!("shuang: {w}");
    }
    let mut countries = CountryCache::new();
    let mut notifier = Notifier::desktop(true);

    let mut verdict = ipcheck::check(&cfg.ip_check).await;
    countries.fill(&mut verdict);
    // First-run semantics: with an empty allowlist the addresses observed at
    // start are the allowed ones (Kordon's "remember the current IP" behavior).
    if list.is_empty() && verdict.quorum {
        if let Some(ip) = verdict.ipv4 {
            eprintln!("shuang: allowlist empty, allowing the startup IP {ip}");
            list.push_ip(ip);
        }
        if let Some(v6) = verdict.ipv6 {
            list.push_ip(v6);
        }
    }
    if let Some(reason) = net::deny_reason(&verdict, &list) {
        eprintln!("shuang: {} — refusing to start", reason.message());
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
    let mut frozen = Frozen::recover(config_path);

    let (net_tx, mut net_rx) = tokio::sync::mpsc::unbounded_channel();
    netwatch::spawn(net_tx);
    let mut shutdown = Shutdown::new()?;

    loop {
        tokio::select! {
            _ = tokio::time::sleep(interval) => {},
            // Netlink event: verify right now instead of waiting for the tick.
            _ = net_rx.recv() => {},
            // Clean shutdown resumes everything we froze.
            _ = shutdown.recv() => {
                eprintln!("shuang: shutting down — resuming and stopping the command");
                frozen.resume_all();
                let _ = Frozen::persist_cleared(config_path);
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Ok(0);
            }
        }

        if let Some(status) = child.try_wait()? {
            let code = status
                .code()
                .unwrap_or(if status.success() { 0 } else { 1 });
            eprintln!("shuang: {program} exited with {code}");
            let _ = Frozen::persist_cleared(config_path);
            return Ok(code as u8);
        }

        verdict = ipcheck::check(&cfg.ip_check).await;
        countries.fill(&mut verdict);
        if net::allowed(&verdict, &list) {
            if guard.good() && !frozen.is_empty() {
                frozen.resume_all();
                let _ = Frozen::persist_cleared(config_path);
                eprintln!("shuang: allowed IP is back — resumed");
                log_event(config_path, "resume", program);
                notifier.resumed();
            }
            continue;
        }

        // deny_reason is guaranteed Some here (allowed returned false).
        let message = net::deny_reason(&verdict, &list)
            .map(|r| r.message())
            .unwrap_or_else(|| "not allowed".into());
        match guard.bad() {
            Stage::Freeze => {
                let system = System::new_all();
                let tree = procs::tree(child_pid, &system);
                frozen.freeze_tree(&tree, OWNER);
                let _ = frozen.persist(config_path);
                eprintln!("shuang: {message} — froze {} process(es)", frozen.len());
                log_event(config_path, "freeze", &format!("{program}: {message}"));
                notifier.freeze_started(&message);
            }
            Stage::Frozen(elapsed) => {
                let left = grace.saturating_sub(elapsed).as_secs();
                notifier.still_frozen(&message);
                eprintln!("shuang: frozen, {left}s left for the allowed IP to come back");
            }
            Stage::MustClose => {
                eprintln!("shuang: allowed IP never came back — stopping {program}");
                log_event(config_path, "close", program);
                let pids = frozen.take_owner(OWNER);
                frozen.stop_pids(pids, close_timeout);
                let _ = Frozen::persist_cleared(config_path);
                let _ = child.wait().await;
                return Ok(75);
            }
        }
    }
}

fn log_event(config_path: &Path, kind: &str, detail: &str) {
    if let Err(err) = events::append_line(config_path, kind, detail) {
        eprintln!("shuang: cannot write history: {err:#}");
    }
}
