//! `shuang check` — one-shot verdict: what the IP services see and whether the
//! current exit is allowed.
//!
//! Exit codes: 0 — allowed; 3 — not allowed; 1 — error (bad config, etc).

use std::path::Path;

use anyhow::Result;

use crate::{config, ipcheck, net, net::Allowlist};

pub async fn run(config_path: &Path, json: bool, explicit: bool) -> Result<u8> {
    let mut cfg = config::load(config_path, explicit)?;
    let state = config::load_state(config_path);
    cfg.apply_overrides(&state);
    let list = Allowlist::merged(&cfg.allow, &state.allow);
    let verdict = ipcheck::check(&cfg.ip_check).await;
    let allowed = net::allowed(&verdict, &list);

    if json {
        let doc = serde_json::json!({
            "ipv4": verdict.ipv4.map(|i| i.to_string()),
            "ipv6": verdict.ipv6.map(|i| i.to_string()),
            "country": verdict.country,
            "quorum": verdict.quorum,
            "allowed": allowed,
        });
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
    } else {
        let ip = verdict
            .ipv4
            .map(|i| i.to_string())
            .unwrap_or_else(|| "unknown (no quorum)".into());
        let country = verdict.country.as_deref().unwrap_or("??");
        println!("IP: {ip} ({country})");
        if let Some(v6) = verdict.ipv6 {
            println!("IPv6: {v6}");
        }
        if allowed {
            println!("Allowed: yes");
        } else if !verdict.quorum {
            println!("Allowed: no (fewer than the required services agreed on the IP)");
        } else {
            println!("Allowed: no");
        }
    }

    Ok(if allowed { 0 } else { 3 })
}
