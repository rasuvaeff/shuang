//! `shuang daemon` — watch the configured apps continuously.
//!
//! Per-app rules: each app may carry its own `[apps.allow]` merged on top of
//! the global allowlist (+ active profile), so Claude can be frozen while
//! Cursor keeps running. On a trusted network (gateway MAC in
//! `trusted_networks`) protection is off entirely.
//!
//! Safety: netlink events trigger an immediate re-check (no 5s window);
//! Ctrl+C/SIGTERM resumes everything; a crash leaves the frozen set in
//! a shared journal and a daemon with the same policy can recover it. Events land in `history.log`
//! (`shuang events`), state changes go to the tray and to desktop
//! notifications with anti-noise debouncing.

use std::{collections::HashMap, path::Path, sync::Arc, time::Duration};

use anyhow::{Result, bail};
use sysinfo::System;

use crate::{
    config, events,
    guard::{Guard, Stage},
    ipcheck::{self, CountryCache},
    leaks,
    net::{self, Allowlist},
    netwatch,
    notify::Notifier,
    panel, probe, procs,
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
    mut shutdown: Shutdown,
) -> Result<u8> {
    let mut base_cfg = config::load(config_path, explicit)?;
    let mut applied_config = format!("{base_cfg:?}");
    let mut cfg = base_cfg.clone();
    let state = config::try_load_state(config_path)?;
    cfg.apply_overrides(&state);
    Frozen::warn_legacy(&state);
    if cfg.ip_check.interval_secs == 0 {
        bail!("ip_check.interval_secs must be at least 1");
    }
    if cfg.ip_check.min_agree == 0 {
        bail!("ip_check.min_agree must be at least 1");
    }
    if cfg.apps.is_empty() && no_panel {
        bail!("no [[apps]] configured — add one to config.toml (see README)");
    }
    let mut applied_state = state_marker(&state)?;
    // Warnings after the overrides: the panel may already fix what the raw
    // config gets wrong (e.g. interval vs timeout).
    for warning in cfg.warnings() {
        crate::logging::line(format_args!("shuang: warning: {warning}"));
    }
    let (mut global_list, profile_warning) = net::effective(&cfg, &state);
    if let Some(w) = profile_warning {
        crate::logging::line(format_args!("shuang: {w}"));
    }

    // Per-app effective allowlist = global ∪ app's own rules.
    let mut app_lists: Vec<Allowlist> = cfg
        .apps
        .iter()
        .map(|app| match &app.allow {
            Some(extra) => global_list.with_extra(extra),
            None => global_list.clone(),
        })
        .collect();

    let mut interval = Duration::from_secs(cfg.ip_check.interval_secs);
    let mut grace = Duration::from_secs(cfg.timing.grace_secs);
    let mut close_timeout = Duration::from_secs(cfg.timing.close_secs);
    let mut countries = CountryCache::new();
    let mut guards: Vec<Guard> = cfg
        .apps
        .iter()
        .map(|_| Guard::new(grace.saturating_add(close_timeout)))
        .collect();
    let mut guard_names: Vec<String> = cfg.apps.iter().map(|app| app.name.clone()).collect();
    let mut frozen = Frozen::new()?;
    let mut scopes = recovery_scopes(config_path, &cfg, &app_lists)?;
    // Split-routing check: "" while OK, Some(reason) while leaking.
    let mut route_client = route_client_for(&cfg.ip_check);
    let mut route_state: Option<RouteResult> = None;
    let mut reputation_state: Option<(String, std::time::Instant)> = None;
    let mut last_exit: Option<String> = None;

    // macOS hands us a tray built on the main thread; other platforms spawn
    // their own here.
    let tray = match prebuilt_tray {
        Some(handle) => handle,
        None => TrayHandle::spawn(no_tray).await,
    };
    let quit = tray.quit_flag();
    let mut notifier = Notifier::desktop(!no_notify && state.settings.notify.unwrap_or(true));
    tray.status(tray::Status::Ok, "starting…").await;

    let panel_shared = panel::shared();
    let apply = Arc::new(tokio::sync::Notify::new());
    let panel = panel::spawn(
        Arc::clone(&panel_shared),
        config_path.to_path_buf(),
        no_panel,
        Arc::clone(&apply),
        explicit,
    )
    .await;
    if cfg.apps.is_empty() && panel.is_none() {
        bail!("no protected apps configured and the panel could not start");
    }
    if let Some(panel) = &panel {
        crate::logging::panel_url(&panel.url);
        tray.set_panel_url(&panel.url).await;
    }

    let (net_tx, mut net_rx) = tokio::sync::mpsc::unbounded_channel();
    netwatch::spawn(net_tx.clone());
    let (probe_tx, mut probe_rx) = tokio::sync::mpsc::unbounded_channel();
    let mut probe_handle =
        probe::spawn_with_proxy(&cfg.probe, probe_tx.clone(), cfg.ip_check.proxy.clone());

    crate::logging::line(format_args!(
        "shuang: daemon started, watching {} app(s), trusted networks: {}",
        cfg.apps.len(),
        if cfg.trusted_networks.is_empty() {
            "none".to_string()
        } else {
            format!("{} MAC(s)", cfg.trusted_networks.len())
        }
    ));

    let mut event_pending = false;
    let mut probe_down = false;
    let mut probe_transition = false;
    let mut previous_error = None;
    let mut notify_enabled = !no_notify && state.settings.notify.unwrap_or(true);
    'watch: loop {
        // Consume transport, link and shutdown events even when an HTTP check is in flight.
        macro_rules! while_current {
            ($operation:expr) => {{
                let operation = $operation;
                tokio::pin!(operation);
                let result = loop {
                    tokio::select! {
                        biased;
                        signal = wait_signal(&mut net_rx, &mut probe_rx, &mut shutdown, &apply) => break Err(signal),
                        value = &mut operation => break Ok(value),
                        _ = tokio::time::sleep(Duration::from_secs(1)), if !frozen.is_empty() => {
                            freeze_apps(&mut frozen, &cfg, &scopes, |idx| guards[idx].is_frozen())?;
                        }
                    }
                };
                match result {
                    Ok(value) => value,
                    Err(Some((event, down))) => {
                        event_pending |= event;
                        if let Some(down) = down {
                            // Remember a failure even if the next probe recovers before this loop wakes.
                            probe_transition |= down;
                            probe_down = down;
                        }
                        continue 'watch;
                    }
                    Err(None) => {
                        frozen.resume_all()?;
                        return Ok(0);
                    }
                }
            }};
        }

        let revision = panel_shared.write().ok().map_or(0, |mut snapshot| {
            snapshot.checking = true;
            snapshot.requested_revision
        });
        let mut rules_error = None;
        let loaded = config::load(config_path, explicit);
        match loaded {
            Ok(next) => {
                let marker = format!("{next:?}");
                if marker != applied_config {
                    base_cfg = next;
                    applied_config = marker;
                    applied_state.clear();
                }
            }
            Err(err) => rules_error = Some(format!("{err:#}")),
        }
        match config::try_load_state(config_path) {
            Ok(state) if rules_error.is_none() => {
                let marker = state_marker(&state)?;
                if marker != applied_state {
                    let mut next = base_cfg.clone();
                    next.apply_overrides(&state);
                    if next.ip_check.interval_secs == 0 || next.ip_check.min_agree == 0 {
                        rules_error =
                            Some("interval_secs and min_agree must be at least 1".to_string());
                    } else {
                        let mut old: HashMap<String, Guard> = guard_names
                            .drain(..)
                            .zip(std::mem::take(&mut guards))
                            .collect();
                        grace = Duration::from_secs(next.timing.grace_secs);
                        close_timeout = Duration::from_secs(next.timing.close_secs);
                        let deadline = grace.saturating_add(close_timeout);
                        guards = next
                            .apps
                            .iter()
                            .map(|app| {
                                let mut guard = old
                                    .remove(&app.name)
                                    .unwrap_or_else(|| Guard::new(deadline));
                                guard.set_grace(deadline);
                                guard.reset_stability();
                                guard
                            })
                            .collect();
                        guard_names = next.apps.iter().map(|app| app.name.clone()).collect();
                        let (global, warning) = net::effective(&next, &state);
                        if let Some(warning) = warning {
                            crate::logging::line(format_args!("shuang: {warning}"));
                        }
                        global_list = global.clone();
                        app_lists = next
                            .apps
                            .iter()
                            .map(|app| match &app.allow {
                                Some(extra) => global.with_extra(extra),
                                None => global.clone(),
                            })
                            .collect();
                        interval = Duration::from_secs(next.ip_check.interval_secs);
                        scopes = recovery_scopes(config_path, &next, &app_lists)?;
                        notify_enabled = !no_notify && state.settings.notify.unwrap_or(true);
                        notifier = Notifier::desktop(notify_enabled);
                        route_client = route_client_for(&next.ip_check);
                        route_state = None;
                        if !next.probe.enabled {
                            probe_down = false;
                            probe_transition = false;
                        }
                        reputation_state = None;
                        if let Some(handle) = probe_handle.take() {
                            handle.abort();
                            let _ = handle.await;
                        }
                        while probe_rx.try_recv().is_ok() {}
                        probe_handle = probe::spawn_with_proxy(
                            &next.probe,
                            probe_tx.clone(),
                            next.ip_check.proxy.clone(),
                        );
                        cfg = next;
                        applied_state = marker;
                        if !cfg.protection_paused && !trusted::is_trusted(&cfg.trusted_networks) {
                            freeze_apps(&mut frozen, &cfg, &scopes, |_| true)?;
                            guards_rotate(&mut guards);
                        }
                        for removed in old.keys() {
                            frozen.resume_owner(removed, None)?;
                        }
                        crate::logging::line(format_args!(
                            "shuang: applied updated rules and settings"
                        ));
                    }
                }
            }
            Ok(_) => {}
            Err(err) => {
                rules_error.get_or_insert_with(|| format!("{err:#}"));
            }
        }
        if rules_error != previous_error {
            if let Some(error) = &rules_error {
                crate::logging::line(format_args!("shuang: {error}; freezing protected apps"));
            }
            previous_error = rules_error.clone();
        }
        let state_error = rules_error.is_some();
        if state_error {
            freeze_apps(&mut frozen, &cfg, &scopes, |_| true)?;
            guards_rotate(&mut guards);
            if let Ok(mut snapshot) = panel_shared.write() {
                snapshot.evaluated_revision = Some(revision);
                snapshot.rules_error = rules_error.clone();
                snapshot.allowed = false;
            }
        }
        // Master pause: the safety valve. No freezing, everything resumes.
        if cfg.protection_paused && !state_error {
            if !frozen.is_empty() {
                frozen.resume_all()?;
                crate::logging::line(format_args!(
                    "shuang: protection PAUSED — everything resumed"
                ));
            }
            for guard in guards.iter_mut() {
                guard.good();
            }
            if let Ok(mut snapshot) = panel_shared.write() {
                snapshot.applications = bypass_statuses(&cfg, "paused", &procs::snapshot());
                snapshot.apps = running_names(&snapshot.applications);
                snapshot.frozen = frozen.len();
                snapshot.evaluated_revision = Some(revision);
                snapshot.rules_error = None;
                snapshot.checking = false;
            }
            tray.status(tray::Status::Ok, "protection PAUSED").await;
            let Some((ev, down)) =
                wait_tick(interval, &mut net_rx, &mut probe_rx, &mut shutdown, &apply).await
            else {
                crate::logging::line(format_args!(
                    "shuang: shutting down — releasing frozen processes"
                ));
                frozen.resume_all()?;
                return Ok(0);
            };
            event_pending = ev;
            if let Some(down) = down {
                probe_transition = down;
                probe_down = down;
            }
            continue;
        }

        // Probe-down always freezes (a dead transport leaks nothing good);
        // paranoid mode additionally freezes on plain network events.
        if (probe_down || probe_transition) && !trusted::is_trusted(&cfg.trusted_networks) {
            freeze_apps(&mut frozen, &cfg, &scopes, |_| true)?;
            guards_rotate(&mut guards);
            if probe_transition {
                probe_transition = false;
                log_event(config_path, "probe-down", "transport probe failed");
                let ip = cfg.ip_check.clone();
                let path = config_path.to_path_buf();
                tokio::spawn(async move {
                    if let Some(state) = probe::classify(&ip.ip_services, ip.timeout_secs).await {
                        log_event(&path, state.event_kind(), state.message());
                    }
                });
            }
        }
        // Paranoid mode: freeze FIRST on a network event, verify after.
        if event_pending
            && cfg.timing.freeze_on_event_first
            && !trusted::is_trusted(&cfg.trusted_networks)
        {
            crate::logging::line(format_args!("shuang: network change — frozen preemptively"));
            freeze_apps(&mut frozen, &cfg, &scopes, |_| true)?;
            guards_rotate(&mut guards);
        }
        if event_pending {
            route_state = None;
        }
        event_pending = false;
        let mut verdict = while_current!(ipcheck::check(&cfg.ip_check));
        countries.fill(&mut verdict);
        let summary = tray::summary(&verdict);
        let system = procs::snapshot();

        if let Ok(mut snapshot) = panel_shared.write() {
            snapshot.ipv4 = verdict.ipv4.map(|ip| ip.to_string());
            snapshot.ipv6 = verdict.ipv6.map(|ip| ip.to_string());
            snapshot.ipv6_status = verdict.ipv6_state.label();
            snapshot.country = verdict.country.clone();
            snapshot.quorum = verdict.quorum;
            snapshot.allowed = net::allowed(&verdict, &global_list) && !state_error;
            snapshot.deny_reason = rules_error.clone().or_else(|| {
                net::deny_reason(&verdict, &global_list).map(|reason| reason.message())
            });
        }

        if quit.load(std::sync::atomic::Ordering::SeqCst) {
            crate::logging::line(format_args!(
                "shuang: quit from the tray — resuming frozen processes"
            ));
            if let Some(panel) = &panel {
                panel.quit.store(true, std::sync::atomic::Ordering::SeqCst);
            }
            frozen.resume_all()?;
            return Ok(0);
        }

        // Trusted network: protection off, everything resumes.
        if trusted::is_trusted(&cfg.trusted_networks) && !state_error {
            for guard in guards.iter_mut() {
                if guard.good_stable(Duration::from_secs(cfg.timing.stability_secs))
                    && !frozen.is_empty()
                {
                    frozen.resume_all()?;
                    notifier.resumed();
                    crate::logging::line(format_args!("shuang: trusted network — resumed"));
                    log_event(config_path, "resume", "trusted network");
                }
            }
            if let Ok(mut snapshot) = panel_shared.write() {
                snapshot.applications = bypass_statuses(&cfg, "trusted", &procs::snapshot());
                snapshot.apps = running_names(&snapshot.applications);
                snapshot.frozen = frozen.len();
                snapshot.evaluated_revision = Some(revision);
                snapshot.rules_error = None;
                snapshot.checking = false;
            }
            tray.status(tray::Status::Ok, &format!("{summary} — trusted network"))
                .await;
            let Some((ev, down)) =
                wait_tick(interval, &mut net_rx, &mut probe_rx, &mut shutdown, &apply).await
            else {
                crate::logging::line(format_args!(
                    "shuang: shutting down — releasing frozen processes"
                ));
                frozen.resume_all()?;
                return Ok(0);
            };
            event_pending = ev;
            if let Some(down) = down {
                probe_transition = down;
                probe_down = down;
            }
            continue;
        }

        let watchdog_dead = !cfg.watchdog.processes.is_empty()
            && procs::find_targets(&cfg.watchdog.processes, &system).is_empty();
        let transport_denied = state_error || watchdog_dead || probe_down;
        // Act on a known denial before any optional requests.
        freeze_apps(&mut frozen, &cfg, &scopes, |idx| {
            transport_denied || !net::allowed(&verdict, &app_lists[idx])
        })?;

        if cfg.route_check.enabled
            && !transport_denied
            && app_lists.iter().any(|list| net::allowed(&verdict, list))
        {
            let exits = (verdict.ipv4, verdict.ipv6);
            if route_state.as_ref().is_none_or(|result| {
                result.exits != exits
                    || matches!(result.status, RouteStatus::Unavailable(_))
                    || result.checked_at.elapsed().as_secs() >= cfg.route_check.every_secs.max(1)
            }) {
                let status = while_current!(check_routes(
                    route_client.as_ref(),
                    &cfg.route_check.services,
                    exits,
                ));
                route_state = Some(RouteResult {
                    exits,
                    status,
                    checked_at: std::time::Instant::now(),
                });
            }
        }
        let route_reason = route_state
            .as_ref()
            .and_then(|result| match &result.status {
                RouteStatus::Mismatch(reason) => Some(reason.as_str()),
                RouteStatus::Unavailable(reason) if cfg.route_check.strict => Some(reason.as_str()),
                _ => None,
            });
        if route_reason.is_some() {
            freeze_apps(&mut frozen, &cfg, &scopes, |_| true)?;
        }
        // Exit-reputation guard (opt-in, periodic).
        if cfg.reputation.enabled && !transport_denied && route_reason.is_none() {
            let due = reputation_state
                .as_ref()
                .is_none_or(|(_, at)| at.elapsed().as_secs() >= cfg.reputation.every_secs.max(1));
            if due {
                reputation_state = if let (Some(client), Some(ip)) = (&route_client, verdict.ipv4) {
                    let address = ip.to_string();
                    let rep = while_current!(leaks::fetch_reputation(client, &address));
                    let hit = cfg
                        .reputation
                        .fail_flags
                        .iter()
                        .any(|flag| match flag.as_str() {
                            "proxy" => rep.proxy == Some(true),
                            "hosting" => rep.hosting == Some(true),
                            "tor" => rep.tor == Some(true),
                            _ => false,
                        });
                    let now = std::time::Instant::now();
                    if hit {
                        let reason =
                            format!("exit {ip} is flagged: {} — reputation guard", rep.render());
                        crate::logging::line(format_args!("shuang: {reason}"));
                        log_event(config_path, "reputation", &reason);
                        Some((reason, now))
                    } else {
                        None
                    }
                } else {
                    None
                };
            }
        }
        let reputation_bad = reputation_state.is_some();

        // Exit rotation: every change is an event (exit flapping is itself
        // a ban signal for AI accounts).
        if let Some(ip) = verdict.ipv4 {
            let ip = ip.to_string();
            if last_exit.as_ref().is_some_and(|old| *old != ip) {
                log_event(
                    config_path,
                    "exit-change",
                    &format!("{ip} (was {})", last_exit.as_deref().unwrap_or_default()),
                );
                if let Some(client) = route_client.clone() {
                    let ip = ip.clone();
                    let path = config_path.to_path_buf();
                    let notify = notify_enabled;
                    tokio::spawn(async move {
                        let rep = leaks::fetch_reputation(&client, &ip).await;
                        if rep.proxy == Some(false) && rep.hosting == Some(false) {
                            let msg = format!(
                                "exit {ip} is reported as residential by the reputation service"
                            );
                            log_event(&path, "home-ip-leak", &msg);
                            Notifier::desktop(notify).alert(&msg);
                        }
                    });
                }
            }
            last_exit = Some(ip);
        }

        if let Ok(mut snapshot) = panel_shared.write() {
            snapshot.route_status = if !cfg.route_check.enabled {
                "disabled"
            } else if let Some(result) = &route_state {
                match result.status {
                    RouteStatus::Confirmed => "confirmed",
                    RouteStatus::Mismatch(_) => "mismatch",
                    RouteStatus::Unavailable(_) => "unavailable",
                }
            } else {
                "pending"
            };
        }
        while_current!(std::future::ready(()));
        let denied = transport_denied || route_reason.is_some() || reputation_bad;

        let mut any_frozen = false;
        let mut worst_detail = String::new();
        let mut ready_to_resume = Vec::new();
        let mut applications = Vec::new();

        for (idx, app) in cfg.apps.iter().enumerate() {
            let list = &app_lists[idx];
            let targets = procs::find_targets(&app.r#match, &system);
            let target_pids: Vec<u32> = targets.iter().map(|(_, pid)| *pid).collect();
            let guard = &mut guards[idx];

            let mut status = panel::AppStatus {
                name: app.name.clone(),
                state: if targets.is_empty() {
                    "waiting"
                } else {
                    "running"
                },
                reason: None,
                seconds_left: None,
                matched: targets.len(),
            };
            if net::allowed(&verdict, list) && !denied {
                if guard.policy_stable(Duration::from_secs(cfg.timing.stability_secs)) {
                    ready_to_resume.push(idx);
                } else if !targets.is_empty() {
                    status.state = "stabilizing";
                }
                applications.push(status);
                continue;
            }

            let message = if state_error {
                "configuration or state cannot be read — frozen".to_string()
            } else if watchdog_dead {
                format!(
                    "proxy client ({}) is not running — frozen",
                    cfg.watchdog.processes.join(", ")
                )
            } else if let Some((reason, _)) = &reputation_state {
                reason.clone()
            } else if probe_down {
                "transport probe failed".to_string()
            } else if let Some(reason) = route_reason {
                reason.to_string()
            } else {
                net::deny_reason(&verdict, list)
                    .map(|r| r.message())
                    .unwrap_or_else(|| "not allowed".into())
            };
            any_frozen = true;
            if worst_detail.is_empty() {
                worst_detail = format!("[{}] {message}", app.name);
            }

            status.reason = Some(message.clone());
            if !targets.is_empty() {
                status.state = "frozen";
            }
            match guard.bad() {
                Stage::Freeze => {
                    status.seconds_left = Some(grace.saturating_add(close_timeout).as_secs());
                    if !frozen.freeze_roots(&target_pids, &app.name, &scopes[idx], &system)? {
                        status.state = "denied";
                    }
                    crate::logging::line(format_args!(
                        "shuang: [{}] {message} — froze {} process(es)",
                        app.name,
                        frozen.len()
                    ));
                    log_event(config_path, "freeze", &format!("{}: {message}", app.name));
                    notifier.freeze_started(&message);
                }
                Stage::Frozen(elapsed) => {
                    if !frozen.freeze_roots(&target_pids, &app.name, &scopes[idx], &system)? {
                        status.state = "denied";
                    }
                    let left = grace
                        .saturating_add(close_timeout)
                        .saturating_sub(elapsed)
                        .as_secs();
                    status.seconds_left = Some(left);
                    notifier.still_frozen(&message);
                    crate::logging::line(format_args!(
                        "shuang: [{}] frozen, {left}s left for the allowed IP",
                        app.name
                    ));
                }
                Stage::MustClose => {
                    crate::logging::line(format_args!(
                        "shuang: [{}] allowed IP never came back — stopping",
                        app.name
                    ));
                    log_event(config_path, "close", &app.name);
                    if !frozen.freeze_roots(&target_pids, &app.name, &scopes[idx], &system)? {
                        status.state = "denied";
                    }
                    if frozen.kill_owner(&app.name)? > 0 {
                        status.state = "stopped";
                    }
                    // The daemon keeps watching; the guard restarts on the next bad tick.
                    guard.good();
                }
            }
            if status.state == "waiting" {
                status.seconds_left = None;
            }
            applications.push(status);
        }

        // Register all denied apps before releasing any overlapping claim.
        for idx in ready_to_resume {
            let app = &cfg.apps[idx];
            if frozen.resume_owner(&app.name, Some(&scopes[idx]))? > 0 {
                crate::logging::line(format_args!(
                    "shuang: [{}] allowed IP is stable — resumed",
                    app.name
                ));
                log_event(config_path, "resume", &app.name);
                notifier.resumed();
            }
        }

        #[cfg(unix)]
        refresh_process_status(&mut applications, &cfg, system);
        if let Ok(mut snapshot) = panel_shared.write() {
            snapshot.apps = running_names(&applications);
            snapshot.applications = applications;
            snapshot.frozen = frozen.len();
            snapshot.evaluated_revision = Some(revision);
            snapshot.rules_error = rules_error;
            snapshot.checking = false;
        }
        if any_frozen {
            tray.status(tray::Status::Frozen, &worst_detail).await;
        } else {
            tray.status(tray::Status::Ok, &summary).await;
        }

        let wait = if any_frozen {
            interval.min(Duration::from_secs(1))
        } else {
            interval
        };
        let Some((ev, down)) =
            wait_tick(wait, &mut net_rx, &mut probe_rx, &mut shutdown, &apply).await
        else {
            crate::logging::line(format_args!(
                "shuang: shutting down — releasing frozen processes"
            ));
            frozen.resume_all()?;
            return Ok(0);
        };
        event_pending = ev;
        if let Some(down) = down {
            probe_transition = down;
            probe_down = down;
        }
    }
}

#[cfg(unix)]
fn refresh_process_status(
    applications: &mut [panel::AppStatus],
    cfg: &config::Config,
    mut system: System,
) {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessStatus, ProcessesToUpdate};

    let targets: Vec<Vec<Pid>> = cfg
        .apps
        .iter()
        .map(|app| {
            procs::find_targets(&app.r#match, &system)
                .into_iter()
                .map(|(_, pid)| Pid::from_u32(pid))
                .collect()
        })
        .collect();
    let mut pids: Vec<Pid> = targets.iter().flatten().copied().collect();
    pids.sort_unstable();
    pids.dedup();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&pids),
        true,
        ProcessRefreshKind::nothing().without_tasks(),
    );
    for (app, targets) in applications.iter_mut().zip(targets) {
        if targets.is_empty() || app.state == "stopped" {
            continue;
        }
        let mut alive = 0;
        let mut stopped = 0;
        for pid in targets {
            if let Some(process) = system.process(pid) {
                match process.status() {
                    status if crate::platform::is_suspended(pid.as_u32(), status) => {
                        stopped += 1;
                        alive += 1;
                    }
                    ProcessStatus::Zombie | ProcessStatus::Dead => {}
                    _ => alive += 1,
                }
            }
        }
        app.matched = alive;
        app.state = match (app.state, alive, stopped) {
            (_, 0, _) => "waiting",
            ("frozen", alive, stopped) if stopped < alive => "denied",
            ("running", _, stopped) if stopped > 0 => {
                app.reason = Some("A matching process is still suspended".to_string());
                "suspended"
            }
            (state, _, _) => state,
        };
    }
}

fn bypass_statuses(
    cfg: &config::Config,
    state: &'static str,
    system: &System,
) -> Vec<panel::AppStatus> {
    cfg.apps
        .iter()
        .map(|app| panel::AppStatus {
            name: app.name.clone(),
            state,
            reason: None,
            seconds_left: None,
            matched: procs::find_targets(&app.r#match, system).len(),
        })
        .collect()
}

fn running_names(applications: &[panel::AppStatus]) -> Vec<String> {
    applications
        .iter()
        .filter(|app| app.matched > 0)
        .map(|app| app.name.clone())
        .collect()
}

/// Sleep until the next tick, a netlink event, or a shutdown signal —
/// whichever comes first. Returns None on shutdown.
async fn wait_tick(
    interval: Duration,
    net_rx: &mut tokio::sync::mpsc::UnboundedReceiver<()>,
    probe_rx: &mut tokio::sync::mpsc::UnboundedReceiver<bool>,
    shutdown: &mut Shutdown,
    apply: &tokio::sync::Notify,
) -> Option<(bool, Option<bool>)> {
    tokio::select! {
        signal = wait_signal(net_rx, probe_rx, shutdown, apply) => signal,
        _ = tokio::time::sleep(interval) => Some((false, None)),
    }
}

async fn wait_signal(
    net_rx: &mut tokio::sync::mpsc::UnboundedReceiver<()>,
    probe_rx: &mut tokio::sync::mpsc::UnboundedReceiver<bool>,
    shutdown: &mut Shutdown,
    apply: &tokio::sync::Notify,
) -> Option<(bool, Option<bool>)> {
    tokio::select! {
        biased;
        _ = shutdown.recv() => None,
        down = probe_rx.recv(), if !probe_rx.is_closed() || !probe_rx.is_empty() => Some((false, down)),
        _ = apply.notified() => Some((false, None)),
        result = net_rx.recv(), if !net_rx.is_closed() || !net_rx.is_empty() => {
            // Coalesce the burst generated by a single link change.
            for _ in 0..64 {
                if net_rx.try_recv().is_err() { break; }
            }
            Some((result.is_some(), None))
        }
    }
}

fn freeze_apps(
    frozen: &mut Frozen,
    cfg: &config::Config,
    scopes: &[String],
    denied: impl Fn(usize) -> bool,
) -> Result<()> {
    if !cfg.apps.iter().enumerate().any(|(idx, _)| denied(idx)) {
        return Ok(());
    }
    let system = procs::snapshot();
    for (idx, app) in cfg.apps.iter().enumerate().filter(|(idx, _)| denied(*idx)) {
        let roots = procs::find_targets(&app.r#match, &system);
        frozen.freeze_roots(
            &roots.iter().map(|(_, pid)| *pid).collect::<Vec<_>>(),
            &app.name,
            &scopes[idx],
            &system,
        )?;
    }
    Ok(())
}

fn recovery_scopes(
    config_path: &Path,
    cfg: &config::Config,
    lists: &[Allowlist],
) -> Result<Vec<String>> {
    cfg.apps
        .iter()
        .zip(lists)
        .map(|(app, list)| {
            Frozen::scope(
                config_path,
                (
                    "daemon",
                    app,
                    list,
                    &cfg.ip_check,
                    &cfg.route_check,
                    &cfg.watchdog,
                    &cfg.reputation,
                    &cfg.probe,
                    &cfg.trusted_networks,
                    &cfg.timing,
                ),
            )
        })
        .collect()
}

type Exits = (Option<std::net::IpAddr>, Option<std::net::IpAddr>);

struct RouteResult {
    exits: Exits,
    status: RouteStatus,
    checked_at: std::time::Instant,
}

enum RouteStatus {
    Confirmed,
    Mismatch(String),
    Unavailable(String),
}

async fn check_routes(
    client: Option<&reqwest::Client>,
    services: &[String],
    exits: Exits,
) -> RouteStatus {
    let Some(client) = client.filter(|_| !services.is_empty()) else {
        return RouteStatus::Unavailable("no route checks are configured or available".to_string());
    };
    let mut tasks = tokio::task::JoinSet::new();
    for service in services {
        let service = service.clone();
        let client = client.clone();
        tasks.spawn(async move { leaks::fetch_trace_public(&client, &service).await });
    }
    let v4 = exits.0.map(|ip| ip.to_string());
    let v6 = exits.1.map(|ip| ip.to_string());
    let mut missing = 0;
    while let Some(answer) = tasks.join_next().await {
        match answer.ok().and_then(|a| a.ip.map(|ip| (a.service, ip))) {
            Some((service, ip)) if !leaks::trace_matches(&ip, v4.as_deref(), v6.as_deref()) => {
                return RouteStatus::Mismatch(format!(
                    "{service} reports exit {ip} which differs from the verified addresses"
                ));
            }
            Some(_) => {}
            None => missing += 1,
        }
    }
    if missing > 0 {
        RouteStatus::Unavailable(format!(
            "{missing} of {} route checks did not confirm the exit",
            services.len()
        ))
    } else {
        RouteStatus::Confirmed
    }
}

fn route_client_for(cfg: &config::IpCheckConfig) -> Option<reqwest::Client> {
    let mut builder =
        reqwest::Client::builder().timeout(Duration::from_secs(cfg.timeout_secs.max(1)));
    if let Some(url) = &cfg.proxy {
        builder = builder.proxy(reqwest::Proxy::all(url).ok()?);
    }
    builder.build().ok()
}

fn state_marker(state: &config::State) -> Result<String> {
    Ok(serde_json::to_string(&(
        &state.allow,
        &state.active_profile,
        &state.settings,
        &state.apps,
        &state.trusted_networks,
    ))?)
}

/// Advance every guard one "bad" tick so the preemptive freeze is bookkept.
fn guards_rotate(guards: &mut [Guard]) {
    for guard in guards.iter_mut() {
        let _ = guard.bad();
    }
}

fn log_event(config_path: &Path, kind: &str, detail: &str) {
    if let Err(err) = events::append_line(config_path, kind, detail) {
        crate::logging::line(format_args!("shuang: cannot write history: {err:#}"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression (2026-11-21): a recv() on a CLOSED channel is instantly
    /// ready forever — a disabled probe made wait_tick return `down=true` on
    /// every tick and froze every protected app at launch. The select guards
    /// must keep a closed channel silent.
    #[tokio::test]
    async fn closed_channels_do_not_fire_events_or_probe() {
        let (net_tx, mut net_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let (probe_tx, mut probe_rx) = tokio::sync::mpsc::unbounded_channel::<bool>();
        drop(net_tx); // netwatch died / probe disabled: senders gone
        drop(probe_tx);

        let mut shutdown = Shutdown::daemon().unwrap();
        let (event, down) = wait_tick(
            Duration::from_millis(50),
            &mut net_rx,
            &mut probe_rx,
            &mut shutdown,
            &tokio::sync::Notify::new(),
        )
        .await
        .unwrap();
        assert!(
            !event,
            "closed net channel must not look like a network event"
        );
        assert!(
            down.is_none(),
            "closed probe channel must not look like a dead transport"
        );
    }

    /// Sanity: a LIVE probe channel still reports down.
    #[tokio::test]
    async fn live_probe_channel_reports_down() {
        let (_net_tx, mut net_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let (probe_tx, mut probe_rx) = tokio::sync::mpsc::unbounded_channel::<bool>();
        let mut shutdown = Shutdown::daemon().unwrap();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let _ = probe_tx.send(true);
        });
        let (_event, down) = wait_tick(
            Duration::from_secs(5),
            &mut net_rx,
            &mut probe_rx,
            &mut shutdown,
            &tokio::sync::Notify::new(),
        )
        .await
        .unwrap();
        assert_eq!(down, Some(true), "a real probe signal must come through");
    }

    #[tokio::test]
    async fn apply_notification_wakes_the_daemon() {
        let (_net_tx, mut net_rx) = tokio::sync::mpsc::unbounded_channel::<()>();
        let (_probe_tx, mut probe_rx) = tokio::sync::mpsc::unbounded_channel::<bool>();
        let mut shutdown = Shutdown::daemon().unwrap();
        let apply = Arc::new(tokio::sync::Notify::new());
        let wake = Arc::clone(&apply);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(10)).await;
            wake.notify_one();
        });
        let start = std::time::Instant::now();
        let (event, down) = wait_tick(
            Duration::from_secs(5),
            &mut net_rx,
            &mut probe_rx,
            &mut shutdown,
            &apply,
        )
        .await
        .unwrap();
        assert!(start.elapsed() < Duration::from_secs(1));
        assert!(!event);
        assert!(down.is_none());
    }
}
