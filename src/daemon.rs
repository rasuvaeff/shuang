//! `shuang daemon` — watch the configured apps continuously.
//!
//! Per-app rules: each app may carry its own `[apps.allow]` merged on top of
//! the global allowlist (+ active profile), so Claude can be frozen while
//! Cursor keeps running. On a trusted network (gateway MAC in
//! `trusted_networks`) protection is off entirely.
//!
//! Safety: netlink events trigger an immediate re-check (no 5s window);
//! Ctrl+C/SIGTERM resumes everything; a crash leaves the frozen set in
//! `state.toml` and the next run recovers it. Events land in `history.log`
//! (`shuang events`), state changes go to the tray and to desktop
//! notifications with anti-noise debouncing.

use std::{path::Path, sync::Arc, time::Duration};

use anyhow::{Result, bail};
use sysinfo::System;

use crate::{
    config, events,
    guard::{Guard, Stage},
    ipcheck::{self, CountryCache},
    net::{self, Allowlist},
    netwatch,
    notify::Notifier,
    panel, platform, procs,
    supervisor::{Frozen, Shutdown},
    tray::{self, TrayHandle},
    trusted,
};

pub async fn run(
    config_path: &Path,
    explicit: bool,
    no_tray: bool,
    no_notify: bool,
    no_panel: bool,
    prebuilt_tray: Option<TrayHandle>,
) -> Result<u8> {
    let mut cfg = config::load(config_path, explicit)?;
    if cfg.ip_check.interval_secs == 0 {
        bail!("ip_check.interval_secs must be at least 1");
    }
    if cfg.apps.is_empty() {
        bail!("no [[apps]] configured — add one to config.toml (see README)");
    }
    for warning in cfg.warnings() {
        eprintln!("shuang: warning: {warning}");
    }
    let state = config::load_state(config_path);
    cfg.apply_overrides(&state);
    let (global_list, profile_warning) = net::effective(&cfg, &state);
    if let Some(w) = profile_warning {
        eprintln!("shuang: {w}");
    }

    // Per-app effective allowlist = global ∪ app's own rules.
    let app_lists: Vec<Allowlist> = cfg
        .apps
        .iter()
        .map(|app| match &app.allow {
            Some(extra) => global_list.with_extra(extra),
            None => global_list.clone(),
        })
        .collect();

    let interval = Duration::from_secs(cfg.ip_check.interval_secs);
    let grace = Duration::from_secs(cfg.timing.grace_secs);
    let close_timeout = Duration::from_secs(cfg.timing.close_secs);
    let mut countries = CountryCache::new();
    let mut guards: Vec<Guard> = cfg.apps.iter().map(|_| Guard::new(grace)).collect();
    let mut frozen = Frozen::recover(config_path);

    // macOS hands us a tray built on the main thread; other platforms spawn
    // their own here.
    let tray = match prebuilt_tray {
        Some(handle) => handle,
        None => TrayHandle::spawn(no_tray).await,
    };
    let quit = tray.quit_flag();
    let mut notifier = Notifier::desktop(!no_notify);
    tray.status(tray::Status::Ok, "starting…").await;

    let panel_shared = panel::shared();
    let panel = panel::spawn(
        Arc::clone(&panel_shared),
        config_path.to_path_buf(),
        no_panel,
    )
    .await;
    if let Some(panel) = &panel {
        eprintln!("shuang: panel: {}", panel.url);
        tray.set_panel_url(&panel.url).await;
    }

    let (net_tx, mut net_rx) = tokio::sync::mpsc::unbounded_channel();
    netwatch::spawn(net_tx);
    let mut shutdown = Shutdown::new()?;

    eprintln!(
        "shuang: daemon started, watching {} app(s), trusted networks: {}",
        cfg.apps.len(),
        if cfg.trusted_networks.is_empty() {
            "none".to_string()
        } else {
            format!("{} MAC(s)", cfg.trusted_networks.len())
        }
    );

    loop {
        let mut verdict = ipcheck::check(&cfg.ip_check).await;
        countries.fill(&mut verdict);
        let summary = tray::summary(&verdict);
        let system = System::new_all();

        // Refresh the panel snapshot (best-effort; a poisoned lock skips a tick).
        let global_ok = net::allowed(&verdict, &global_list);
        let apps_running: Vec<String> = cfg
            .apps
            .iter()
            .filter(|app| !procs::find_targets(&app.r#match, &system).is_empty())
            .map(|app| app.name.clone())
            .collect();
        if let Ok(mut snap) = panel_shared.write() {
            let deny = net::deny_reason(&verdict, &global_list).map(|r| r.message());
            *snap = panel::Snapshot {
                ipv4: verdict.ipv4.map(|i| i.to_string()),
                ipv6: verdict.ipv6.map(|i| i.to_string()),
                country: verdict.country.clone(),
                quorum: verdict.quorum,
                allowed: global_ok,
                frozen: frozen.len(),
                apps: apps_running,
                deny_reason: deny,
            };
        }

        if quit.load(std::sync::atomic::Ordering::SeqCst) {
            eprintln!("shuang: quit from the tray — resuming frozen processes");
            if let Some(panel) = &panel {
                panel.quit.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            frozen.resume_all();
            let _ = Frozen::persist_cleared(config_path);
            return Ok(0);
        }

        // Trusted network: protection off, everything resumes.
        if trusted::is_trusted(&cfg.trusted_networks) {
            for guard in guards.iter_mut() {
                if guard.good() && !frozen.is_empty() {
                    frozen.resume_all();
                    let _ = Frozen::persist_cleared(config_path);
                    notifier.resumed();
                    eprintln!("shuang: trusted network — resumed");
                    log_event(config_path, "resume", "trusted network");
                }
            }
            tray.status(tray::Status::Ok, &format!("{summary} — trusted network"))
                .await;
            wait_tick(
                interval,
                &mut net_rx,
                &mut shutdown,
                &mut frozen,
                config_path,
            )
            .await;
            continue;
        }

        let mut any_frozen = false;
        let mut worst_detail = String::new();

        for (idx, app) in cfg.apps.iter().enumerate() {
            let list = &app_lists[idx];
            let targets = procs::find_targets(&app.r#match, &system);
            let target_pids: Vec<u32> = targets.iter().map(|(_, pid)| *pid).collect();
            let guard = &mut guards[idx];

            if net::allowed(&verdict, list) {
                if guard.good() && !frozen.is_empty() {
                    let pids = frozen.take_owner(&app.name);
                    for pid in &pids {
                        let _ = platform::resume(*pid);
                    }
                    let _ = frozen.persist(config_path);
                    eprintln!("shuang: [{}] allowed IP is back — resumed", app.name);
                    log_event(config_path, "resume", &app.name);
                    notifier.resumed();
                }
                continue;
            }

            let message = net::deny_reason(&verdict, list)
                .map(|r| r.message())
                .unwrap_or_else(|| "not allowed".into());
            any_frozen = true;
            if worst_detail.is_empty() {
                worst_detail = format!("[{}] {message}", app.name);
            }

            match guard.bad() {
                Stage::Freeze => {
                    for pid in &target_pids {
                        let tree = procs::tree(*pid, &system);
                        frozen.freeze_tree(&tree, &app.name);
                    }
                    let _ = frozen.persist(config_path);
                    eprintln!(
                        "shuang: [{}] {message} — froze {} process(es)",
                        app.name,
                        frozen.len()
                    );
                    log_event(config_path, "freeze", &format!("{}: {message}", app.name));
                    notifier.freeze_started(&message);
                }
                Stage::Frozen(elapsed) => {
                    for pid in &target_pids {
                        let tree = procs::tree(*pid, &system);
                        frozen.freeze_tree(&tree, &app.name);
                    }
                    let left = grace.saturating_sub(elapsed).as_secs();
                    notifier.still_frozen(&message);
                    eprintln!(
                        "shuang: [{}] frozen, {left}s left for the allowed IP",
                        app.name
                    );
                }
                Stage::MustClose => {
                    eprintln!(
                        "shuang: [{}] allowed IP never came back — stopping",
                        app.name
                    );
                    log_event(config_path, "close", &app.name);
                    let pids = frozen.take_owner(&app.name);
                    frozen.stop_pids(pids, close_timeout);
                    let _ = frozen.persist(config_path);
                    // The daemon keeps watching; the guard restarts on the next bad tick.
                    guard.good();
                }
            }
        }

        if any_frozen {
            tray.status(tray::Status::Frozen, &worst_detail).await;
        } else {
            tray.status(tray::Status::Ok, &summary).await;
        }

        wait_tick(
            interval,
            &mut net_rx,
            &mut shutdown,
            &mut frozen,
            config_path,
        )
        .await;
    }
}

/// Sleep until the next tick, a netlink event, or a shutdown signal —
/// whichever comes first. On shutdown resumes everything and exits the task.
async fn wait_tick(
    interval: Duration,
    net_rx: &mut tokio::sync::mpsc::UnboundedReceiver<()>,
    shutdown: &mut Shutdown,
    frozen: &mut Frozen,
    config_path: &Path,
) {
    tokio::select! {
        _ = tokio::time::sleep(interval) => {},
        _ = net_rx.recv() => {},
        _ = shutdown.recv() => {
            eprintln!("shuang: shutting down — resuming frozen processes");
            frozen.resume_all();
            let _ = Frozen::persist_cleared(config_path);
            std::process::exit(0);
        }
    }
}

fn log_event(config_path: &Path, kind: &str, detail: &str) {
    if let Err(err) = events::append_line(config_path, kind, detail) {
        eprintln!("shuang: cannot write history: {err:#}");
    }
}
