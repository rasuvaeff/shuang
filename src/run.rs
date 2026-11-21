//! `shuang run` — kill switch for a single command.
//!
//! Exit codes: 0 — command finished (or clean shutdown); 69 — IP not allowed
//! at start; 75 — the allowed IP never came back and the command was stopped.
//!
//! Safety: Ctrl+C/SIGTERM stops the command without resuming it; a crash
//! leaves its claims in the shared journal for manual recovery.

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

pub async fn run(
    config_path: &Path,
    command: Vec<String>,
    explicit: bool,
    tz_from_exit: bool,
) -> Result<u8> {
    let mut cfg = config::load(config_path, explicit)?;
    let state = config::try_load_state(config_path)?;
    cfg.apply_overrides(&state);
    Frozen::warn_legacy(&state);
    if cfg.ip_check.interval_secs == 0 {
        bail!("ip_check.interval_secs must be at least 1");
    }
    if cfg.ip_check.min_agree == 0 {
        bail!("ip_check.min_agree must be at least 1");
    }
    for warning in cfg.warnings() {
        eprintln!("shuang: warning: {warning}");
    }
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

    let mut frozen = Frozen::new()?;
    let scope = Frozen::scope(
        config_path,
        ("run", &command, &list, &cfg.ip_check, &cfg.timing),
    )?;
    let mut shutdown = Shutdown::new()?;

    let program = &command[0];
    let mut cmd = Command::new(program);
    cmd.args(&command[1..])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    if tz_from_exit {
        // Claude Code reads the machine's time zone: give the child the exit
        // country's zone so the TZ matches the IP the model side sees.
        match verdict
            .country
            .as_deref()
            .and_then(crate::tz::zone_for_country)
        {
            Some(zone) => {
                eprintln!("shuang: child TZ set to {zone} (exit country)");
                cmd.env("TZ", zone);
            }
            None => eprintln!(
                "shuang: --tz-from-exit: no zone mapped for {:?} — leaving TZ as is",
                verdict.country
            ),
        }
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("cannot start {program}"))?;
    let child_pid = child
        .id()
        .context("child exited before we could watch it")?;
    eprintln!("shuang: protecting {program} (pid {child_pid})");

    let interval = Duration::from_secs(cfg.ip_check.interval_secs);
    let grace = Duration::from_secs(cfg.timing.grace_secs);
    let close_timeout = Duration::from_secs(cfg.timing.close_secs);
    let deadline = grace.saturating_add(close_timeout);
    let mut guard = Guard::new(deadline);

    let (net_tx, mut net_rx) = tokio::sync::mpsc::unbounded_channel();
    netwatch::spawn(net_tx);

    loop {
        let network_event = tokio::select! {
            _ = tokio::time::sleep(interval) => false,
            // Netlink event: verify right now instead of waiting for the tick.
            _ = net_rx.recv(), if !net_rx.is_closed() => true,
            // Clean shutdown stops the child and its frozen descendants.
            _ = shutdown.recv() => {
                eprintln!("shuang: shutting down — stopping the command");
                frozen.kill_owner(OWNER)?;
                let _ = child.start_kill();
                let _ = child.wait().await;
                return Ok(0);
            }
        };

        if network_event && cfg.timing.freeze_on_event_first {
            let system = System::new_all();
            let tree = procs::tree(child_pid, &system);
            frozen.freeze_tree(&tree, OWNER, &scope, &system)?;
            let _ = guard.bad();
        }

        if let Some(status) = child.try_wait()? {
            let code = status
                .code()
                .unwrap_or(if status.success() { 0 } else { 1 });
            eprintln!("shuang: {program} exited with {code}");
            frozen.kill_owner(OWNER)?;
            return Ok(code as u8);
        }

        verdict = ipcheck::check(&cfg.ip_check).await;
        countries.fill(&mut verdict);
        if net::allowed(&verdict, &list) {
            if guard.good_stable(Duration::from_secs(cfg.timing.stability_secs))
                && !frozen.is_empty()
            {
                frozen.resume_all()?;
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
                frozen.freeze_tree(&tree, OWNER, &scope, &system)?;
                eprintln!("shuang: {message} — froze {} process(es)", frozen.len());
                log_event(config_path, "freeze", &format!("{program}: {message}"));
                notifier.freeze_started(&message);
            }
            Stage::Frozen(elapsed) => {
                let system = System::new_all();
                let tree = procs::tree(child_pid, &system);
                frozen.freeze_tree(&tree, OWNER, &scope, &system)?;
                let left = deadline.saturating_sub(elapsed).as_secs();
                notifier.still_frozen(&message);
                eprintln!("shuang: frozen, {left}s left for the allowed IP to come back");
            }
            Stage::MustClose => {
                eprintln!("shuang: allowed IP never came back — stopping {program}");
                log_event(config_path, "close", program);
                let system = System::new_all();
                let tree = procs::tree(child_pid, &system);
                frozen.freeze_tree(&tree, OWNER, &scope, &system)?;
                frozen.kill_owner(OWNER)?;
                let _ = child.start_kill();
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
