//! `shuang doctor` — environment diagnostics: everything a "why does it not
//! work?" support request would ask, in one command. Exit 0 = healthy,
//! 4 = problems found.

use std::path::Path;

use anyhow::Result;

use crate::{config, ipcheck, trusted};

/// Collect checks; the CLI prints them, the panel returns them as JSON.
pub async fn check(config_path: &Path, explicit: bool) -> (Vec<(bool, String)>, Vec<String>) {
    let mut problems: Vec<String> = Vec::new();
    let mut checks: Vec<(bool, String)> = Vec::new();

    // 1. Config loads.
    let cfg = match config::load(config_path, explicit) {
        Ok(cfg) => {
            checks.push((true, format!("config readable ({})", config_path.display())));
            for w in cfg.warnings() {
                problems.push(format!("config: {w}"));
            }
            cfg
        }
        Err(err) => {
            checks.push((false, format!("config readable: {err:#}")));
            return (checks, problems);
        }
    };

    // 2. State merges.
    let state = config::load_state(config_path);
    if !state.frozen.is_empty() {
        problems.push(format!(
            "state.toml lists {} pid(s) as frozen — the next run/daemon start resumes them",
            state.frozen.len()
        ));
    }
    checks.push((true, "state.toml readable".to_string()));

    // 3. IP verdict with quorum.
    let verdict = ipcheck::check(&cfg.ip_check).await;
    match (&verdict.ipv4, verdict.quorum) {
        (Some(ip), true) => checks.push((true, format!("external IP: {ip} (quorum met)"))),
        (Some(ip), false) => {
            checks.push((false, format!("external IP: {ip} (quorum NOT met)")));
            problems.push(
                "the IP quorum is not met: fewer services agreed than min_agree — check \
                 ip_services reachability"
                    .to_string(),
            );
        }
        (None, _) => {
            checks.push((
                false,
                "external IP: unknown (no service answered)".to_string(),
            ));
            problems
                .push("no IP service answered — the network or the services are down".to_string());
        }
    }
    if let Some(country) = &verdict.country {
        checks.push((true, format!("country: {country}")));
    } else {
        checks.push((
            false,
            "country: unknown (country service unreachable)".to_string(),
        ));
    }

    // 4. Timezone vs country (manual comparison; see `shuang leaks`).
    let tz = std::fs::read_link("/etc/localtime").ok().and_then(|p| {
        p.to_string_lossy()
            .split("zoneinfo/")
            .nth(1)
            .map(String::from)
    });
    checks.push((
        true,
        format!("local timezone: {}", tz.as_deref().unwrap_or("unknown")),
    ));

    // 4b. CN-environment signals: Claude Code reads the system time zone —
    // both the TZ env var and /etc/localtime contribute on Linux.
    let tz_env = std::env::var("TZ").ok();
    let tz = tz_env.as_deref().or(tz.as_deref());
    if tz.is_some_and(crate::tz::is_cn_timezone) {
        checks.push((false, format!("system timezone {tz:?} is a CN/HK/MO zone")));
        problems.push(format!(
            "the system timezone is {tz:?} — Claude Code reports it next to your exit country; \
             start the daemon/agent with TZ matching the exit (e.g. TZ=Europe/Amsterdam)"
        ));
    }
    for var in ["LANG", "LC_ALL"] {
        if let Some(value) = std::env::var(var)
            .ok()
            .filter(|v| crate::tz::is_cn_locale(v))
        {
            problems.push(format!(
                "{var}={value:?} is a zh_CN locale — another CN-environment signal"
            ));
        }
    }

    // 5. Trusted network state.
    match trusted::gateway_mac() {
        Some(mac) => {
            let trusted_now = trusted::is_trusted(&cfg.trusted_networks);
            checks.push((true, format!("gateway MAC: {mac} (trusted: {trusted_now})")));
        }
        None => checks.push((true, "gateway MAC: not detected".to_string())),
    }

    // 6. Tray/notifications environment (informational).
    #[cfg(unix)]
    {
        let dbus = std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some();
        checks.push((dbus, "D-Bus session (tray/notifications)".to_string()));
        if !dbus {
            problems.push(
                "no D-Bus session: the tray icon and desktop notifications will not work"
                    .to_string(),
            );
        }
    }

    (checks, problems)
}

pub fn render_checks(checks: &[(bool, String)], problems: &[String]) -> String {
    let mut out = String::new();
    for (ok, text) in checks {
        out.push_str(&format!("{} {text}\n", if *ok { "ok " } else { "!!" }));
    }
    if !problems.is_empty() {
        out.push_str("Problems:\n");
        for p in problems {
            out.push_str(&format!("  ! {p}\n"));
        }
    } else {
        out.push_str("All checks passed.\n");
    }
    out
}

pub async fn run(config_path: &Path, explicit: bool) -> Result<u8> {
    let (checks, problems) = check(config_path, explicit).await;
    print!("{}", render_checks(&checks, &problems));
    Ok(if problems.is_empty() { 0 } else { 4 })
}
