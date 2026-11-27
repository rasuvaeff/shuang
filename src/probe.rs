//! Fast transport probe: a 1-second direct TCP ping that catches a dead
//! network long before the HTTP IP checks time out — the largest remaining
//! leak window (interval + timeout ≈ 10 s shrinks to ~1-2 s).
//!
//! Also classifies the failure: when the transport is down, one direct
//! (proxy-less) IP check distinguishes `vpn-down` (the direct internet is
//! alive, the tunnel is not) from `offline` (no internet at all).

use std::time::Duration;

use tokio::sync::mpsc::UnboundedSender;

/// Spawn the probe loop. Reports changes in transport health.
/// Best-effort: any error stops the loop silently (the IP checks remain).
/// `app_proxy` (from ip_check.proxy) overrides the environment when set —
/// it is THE path the protected apps use, per the panel field.
pub fn spawn_with_proxy(
    cfg: &crate::config::ProbeConfig,
    tx: UnboundedSender<bool>,
    app_proxy: Option<String>,
) -> Option<tokio::task::JoinHandle<()>> {
    if !cfg.enabled {
        return None;
    }
    let hosts = cfg.hosts.clone();
    let via = cfg.effective_via();
    crate::logging::line(format_args!(
        "shuang: probe path: {}",
        match via {
            crate::config::ProbeVia::Proxy => "through http(s)_proxy (the apps' path)",
            crate::config::ProbeVia::Direct => "raw TCP (the system-tunnel path)",
            crate::config::ProbeVia::Auto => unreachable!("resolved at spawn"),
        }
    ));
    Some(tokio::spawn(async move {
        let mut previous = None;
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let down = match via {
                crate::config::ProbeVia::Proxy => proxy_down(&hosts, app_proxy.as_deref()).await,
                _ => transport_down(&hosts).await,
            };
            if Some(down) != previous {
                if tx.send(down).is_err() {
                    return;
                }
                previous = Some(down);
            }
        }
    }))
}

/// The apps' path: an HTTP HEAD through the system proxy to each host.
/// One healthy hop = transport alive.
async fn proxy_down(hosts: &[String], explicit: Option<&str>) -> bool {
    let mut builder = reqwest::Client::builder().timeout(Duration::from_millis(1500));
    if let Some(url) = explicit {
        let Ok(proxy) = reqwest::Proxy::all(url) else {
            return true;
        };
        builder = builder.proxy(proxy);
    }
    let Ok(client) = builder.redirect(reqwest::redirect::Policy::none()).build() else {
        return true;
    };
    let mut tasks = tokio::task::JoinSet::new();
    for host in hosts {
        let client = client.clone();
        let url = format!("http://{host}/");
        tasks.spawn(async move {
            client
                .head(url)
                .send()
                .await
                .is_ok_and(|r| r.status().is_success() || r.status().is_redirection())
        });
    }
    all_failed(tasks).await
}

/// All hosts unreachable over a direct TCP connect.
async fn transport_down(hosts: &[String]) -> bool {
    let mut tasks = tokio::task::JoinSet::new();
    for host in hosts {
        let host = host.clone();
        tasks.spawn(async move {
            tokio::time::timeout(
                Duration::from_millis(1500),
                tokio::net::TcpStream::connect(host),
            )
            .await
            .is_ok_and(|result| result.is_ok())
        });
    }
    all_failed(tasks).await
}

async fn all_failed(mut tasks: tokio::task::JoinSet<bool>) -> bool {
    while let Some(result) = tasks.join_next().await {
        if matches!(result, Ok(true)) {
            return false;
        }
    }
    true
}

/// `vpn-down` vs `offline`: one direct (no proxy) IP check.
pub async fn classify(services: &[String], timeout_secs: u64) -> Option<TransportState> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(timeout_secs.max(1)))
        .no_proxy()
        .build()
        .ok()?;
    for url in services {
        if let Ok(resp) = client.get(url).send().await
            && let Ok(body) = resp.text().await
            && body.trim().parse::<std::net::IpAddr>().is_ok()
        {
            return Some(TransportState::VpnDown);
        }
    }
    Some(TransportState::Offline)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportState {
    /// The direct internet answers: the tunnel/proxy is what died.
    VpnDown,
    /// Nothing answers at all.
    Offline,
}

impl TransportState {
    pub fn message(&self) -> &'static str {
        match self {
            TransportState::VpnDown => "transport down, direct internet alive — VPN/proxy is down",
            TransportState::Offline => "no internet at all (offline)",
        }
    }

    pub fn event_kind(&self) -> &'static str {
        match self {
            TransportState::VpnDown => "vpn-down",
            TransportState::Offline => "offline",
        }
    }
}
