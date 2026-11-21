//! Fast transport probe: a 1-second direct TCP ping that catches a dead
//! network long before the HTTP IP checks time out — the largest remaining
//! leak window (interval + timeout ≈ 10 s shrinks to ~1-2 s).
//!
//! Also classifies the failure: when the transport is down, one direct
//! (proxy-less) IP check distinguishes `vpn-down` (the direct internet is
//! alive, the tunnel is not) from `offline` (no internet at all).

use std::time::Duration;

use tokio::sync::mpsc::UnboundedSender;

/// Spawn the probe loop. Sends `()` on every tick where ALL hosts failed.
/// Best-effort: any error stops the loop silently (the IP checks remain).
/// `app_proxy` (from ip_check.proxy) overrides the environment when set —
/// it is THE path the protected apps use, per the panel field.
pub fn spawn_with_proxy(
    cfg: &crate::config::ProbeConfig,
    tx: UnboundedSender<()>,
    app_proxy: Option<String>,
) {
    if !cfg.enabled {
        return;
    }
    let hosts = cfg.hosts.clone();
    let via = cfg.effective_via();
    eprintln!(
        "shuang: probe path: {}",
        match via {
            crate::config::ProbeVia::Proxy => "through http(s)_proxy (the apps' path)",
            crate::config::ProbeVia::Direct => "raw TCP (the system-tunnel path)",
            crate::config::ProbeVia::Auto => unreachable!("resolved at spawn"),
        }
    );
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(1)).await;
            let down = match via {
                crate::config::ProbeVia::Proxy => proxy_down(&hosts, app_proxy.as_deref()).await,
                _ => transport_down(&hosts).await,
            };
            if down && tx.send(()).is_err() {
                return;
            }
        }
    });
}

/// The apps' path: an HTTP HEAD through the system proxy to each host.
/// One healthy hop = transport alive.
async fn proxy_down(hosts: &[String], explicit: Option<&str>) -> bool {
    let mut builder = reqwest::Client::builder().timeout(Duration::from_millis(1500));
    if let Some(url) = explicit
        && let Ok(p) = reqwest::Proxy::all(url)
    {
        builder = builder.proxy(p);
    }
    let Ok(client) = builder.build() else {
        return false;
    };
    for host in hosts {
        let addr = host.split(':').next().unwrap_or(host);
        let url = format!("http://{addr}/");
        if client.head(&url).send().await.is_ok() {
            return false;
        }
    }
    true
}

/// All hosts unreachable over a direct TCP connect.
async fn transport_down(hosts: &[String]) -> bool {
    !hosts.is_empty()
        && futures_all(hosts.iter().map(|host| async move {
            let addr = tokio::net::TcpStream::connect(host)
                .await
                .map(|s: tokio::net::TcpStream| s)
                .is_ok();
            !addr
        }))
        .await
}

/// Join helper without pulling futures crate: runs all checks concurrently
/// and returns true only when every predicate is true.
async fn futures_all<F>(futs: impl Iterator<Item = F>) -> bool
where
    F: std::future::Future<Output = bool>,
{
    let mut results = Vec::new();
    for fut in futs {
        results.push(fut);
    }
    // Sequential is fine for 2-3 hosts at 1 s cadence; keeps the helper lazy.
    for fut in results {
        if !fut.await {
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
