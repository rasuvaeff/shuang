//! `shuang leaks` — one-button leak report.
//!
//! Shows, side by side: what every IP service sees individually, the IPv6
//! exit, the address the AI services' own edge sees (`/cdn-cgi/trace` — this
//! catches split routing where the VPN tunnels everything except
//! claude.ai/chatgpt.com), the local timezone vs the exit country, the proxy
//! environment, and the current gateway MAC for a trusted-network entry.
//!
//! Exit codes: `0` — no leaks; `4` — at least one leak/inconsistency; `1` —
//! error. `4` is part of the public contract.

use std::{path::Path, time::Duration};

use anyhow::Result;

use crate::{config, ipcheck, trusted};

#[derive(Debug, Default)]
pub struct LeakReport {
    pub service_answers: Vec<(String, String)>, // (url, "ip" | "error: …")
    pub ipv6_answers: Vec<(String, String)>,
    pub route_answers: Vec<RouteAnswer>,
    pub quorum_ip: Option<String>,
    /// The IPv6 exit: a trace over IPv6 legitimately differs from the v4
    /// quorum — it must match *this*, not the v4 address.
    pub ipv6_exit: Option<String>,
    pub country: Option<String>,
    pub timezone: Option<String>,
    pub proxy_env: Vec<(String, String)>,
    pub gateway_mac: Option<String>,
    /// DNS resolvers (from resolv.conf) with their country, when known.
    pub dns_servers: Vec<(String, String)>,
    /// Exit IP reputation (ip-api.com): residential/datacenter, proxy flags.
    pub reputation: Option<Reputation>,
}

/// Does a trace answer match one of the known exits? Dual-stack is normal:
/// a v6 trace must match the v6 exit, a v4 trace the v4 quorum.
pub fn trace_matches(trace_ip: &str, v4_exit: Option<&str>, v6_exit: Option<&str>) -> bool {
    [v4_exit, v6_exit].contains(&Some(trace_ip))
}

#[derive(Debug)]
pub struct RouteAnswer {
    pub service: String,
    pub ip: Option<String>,
    pub country: Option<String>,
    pub error: Option<String>,
    /// How long the /cdn-cgi/trace request took.
    pub latency_ms: Option<u128>,
}

/// Exit IP reputation (ip-api.com): residential vs datacenter, proxy/Tor
/// flags — the "IP purity" Claude risk-detection sites show.
#[derive(Debug, Default)]
pub struct Reputation {
    pub isp: Option<String>,
    pub asn: Option<String>,
    /// true = datacenter/hosting IP (机房), false = residential/native.
    pub hosting: Option<bool>,
    pub proxy: Option<bool>,
    pub tor: Option<bool>,
    pub mobile: Option<bool>,
    pub error: Option<String>,
}

impl Reputation {
    pub fn render(&self) -> String {
        match &self.error {
            Some(err) => format!("error: {err}"),
            None => {
                let kind = match (self.hosting, self.mobile) {
                    (Some(true), _) => "datacenter".to_string(),
                    (_, Some(true)) => "mobile".to_string(),
                    (Some(false), _) => "residential".to_string(),
                    _ => "unknown".to_string(),
                };
                let flags = [
                    self.proxy.map(|v| v.then_some("proxy")),
                    self.tor.map(|v| v.then_some("tor")),
                ]
                .into_iter()
                .flatten()
                .flatten()
                .collect::<Vec<_>>()
                .join(", ");
                let flags = if flags.is_empty() {
                    "none".to_string()
                } else {
                    flags
                };
                format!(
                    "{} (isp: {}, asn: {}, flags: {})",
                    kind,
                    self.isp.as_deref().unwrap_or("?"),
                    self.asn.as_deref().unwrap_or("?"),
                    flags
                )
            }
        }
    }

    pub fn problems(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.proxy == Some(true) {
            out.push("exit IP is flagged as a proxy".to_string());
        }
        if self.tor == Some(true) {
            out.push("exit IP is flagged as a Tor exit".to_string());
        }
        if self.hosting == Some(true) {
            out.push(
                "exit IP is a datacenter/hosting IP — AI services risk-block these more \
                 aggressively than residential ones"
                    .to_string(),
            );
        }
        out
    }
}

/// Countries where Claude is officially available (approximate static list;
/// Anthropic changes it occasionally — treat a warning, not a verdict).
pub const CLAUDE_SUPPORTED: &[&str] = &[
    "AL", "AR", "AU", "AT", "BE", "BA", "BR", "BG", "CA", "CL", "CO", "CR", "HR", "CY", "CZ", "DK",
    "EC", "EE", "FI", "FR", "DE", "GR", "HK", "HU", "IS", "IN", "ID", "IE", "IL", "IT", "JP", "KR",
    "LV", "LI", "LT", "LU", "MK", "MY", "MT", "MX", "MD", "ME", "NL", "NZ", "NG", "NO", "PA", "PY",
    "PE", "PH", "PL", "PT", "RO", "RS", "SG", "SK", "SI", "ZA", "ES", "SE", "CH", "TW", "TH", "TR",
    "UA", "AE", "GB", "US", "UY", "VN",
];

pub fn claude_region_problem(country: Option<&str>) -> Option<String> {
    let c = country?;
    (!CLAUDE_SUPPORTED.contains(&c)).then(|| {
        format!("exit country {c} is not on Claude's supported list — Claude may refuse to serve")
    })
}

/// ip.net.coffee-style advice: IPv6 exits are flagged more aggressively by
/// AI edge networks than IPv4 ones.
pub fn ipv6_exit_problem(trace_ips: &[Option<&str>], v6_exit: Option<&str>) -> Option<String> {
    let _ = v6_exit;
    let any_v6_trace = trace_ips
        .iter()
        .flatten()
        .any(|ip| ip.parse::<std::net::IpAddr>().is_ok_and(|i| i.is_ipv6()));
    if any_v6_trace {
        Some(
            "the AI edge sees you over IPv6 — IPv6 ranges are flagged more aggressively; \
             prefer an IPv4 exit for AI work"
                .to_string(),
        )
    } else {
        None
    }
}

impl LeakReport {
    /// Human-readable multi-line report + the list of problems found.
    pub fn render(&self) -> (String, Vec<String>) {
        let mut out = String::new();
        let mut problems = Vec::new();

        out.push_str("IP services (each asked separately):\n");
        let mut distinct_v4: Vec<&str> = Vec::new();
        for (url, answer) in &self.service_answers {
            out.push_str(&format!("  {url} → {answer}\n"));
            if !answer.starts_with("error:") && !distinct_v4.contains(&answer.as_str()) {
                distinct_v4.push(answer);
            }
        }
        if distinct_v4.len() > 1 {
            problems.push(format!("IP services disagree: {}", distinct_v4.join(", ")));
        }

        out.push_str("IPv6 services:\n");
        if self.ipv6_answers.is_empty() {
            out.push_str("  (none configured)\n");
        }
        let mut distinct_v6: Vec<&str> = Vec::new();
        for (url, answer) in &self.ipv6_answers {
            out.push_str(&format!("  {url} → {answer}\n"));
            if !answer.starts_with("error:") && !distinct_v6.contains(&answer.as_str()) {
                distinct_v6.push(answer);
            }
        }
        if distinct_v6.len() > 1 {
            problems.push(format!(
                "IPv6 services disagree: {}",
                distinct_v6.join(", ")
            ));
        }
        if !distinct_v6.is_empty()
            && self.quorum_ip.is_some()
            && !self.service_answers.is_empty()
            && distinct_v6.len() == 1
        {
            // Both families present is normal; the per-app allowlist still
            // has to allow the v6 address — noted, not a leak by itself.
        }

        out.push_str("AI services' own edge (/cdn-cgi/trace):\n");
        let expected = [self.quorum_ip.as_deref(), self.ipv6_exit.as_deref()];
        for route in &self.route_answers {
            match (&route.ip, &route.error) {
                (Some(ip), _) => {
                    let latency = route
                        .latency_ms
                        .map(|ms| format!(", {ms} ms"))
                        .unwrap_or_default();
                    out.push_str(&format!(
                        "  {} → {ip} ({}){latency}\n",
                        route.service,
                        route.country.as_deref().unwrap_or("??")
                    ));
                    if !trace_matches(ip, self.quorum_ip.as_deref(), self.ipv6_exit.as_deref()) {
                        problems.push(format!(
                            "{} sees {ip} but the exits are {} — split routing leak",
                            route.service,
                            expected
                                .iter()
                                .flatten()
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(" / ")
                        ));
                    }
                }
                (None, Some(err)) => {
                    out.push_str(&format!("  {} → error: {err}\n", route.service));
                }
                (None, None) => out.push_str(&format!("  {} → no answer\n", route.service)),
            }
        }

        let country = self.country.as_deref().unwrap_or("??");
        out.push_str(&format!(
            "Country: {country}; local timezone: {}\n",
            self.timezone.as_deref().unwrap_or("unknown")
        ));

        out.push_str("DNS resolvers (/etc/resolv.conf):\n");
        if self.dns_servers.is_empty() {
            out.push_str("  (none detected — resolv.conf not available on this platform)\n");
        }
        for (ip, answer) in &self.dns_servers {
            out.push_str(&format!("  {ip} → {answer}\n"));
            if answer.starts_with("error:") {
                continue;
            }
            if answer.starts_with("local") {
                continue; // a local forwarder: its upstream is unknown, not a leak
            }
            if let Some(exit_country) = &self.country
                && answer != exit_country
            {
                problems.push(format!(
                    "DNS resolver {ip} is in {answer} while the exit is in {exit_country} — DNS leak?"
                ));
            }
        }

        if self.proxy_env.is_empty() {
            out.push_str("Proxy environment: none (direct connection)\n");
        } else {
            out.push_str("Proxy environment (IP checks go through it):\n");
            for (k, v) in &self.proxy_env {
                out.push_str(&format!("  {k}={v}\n"));
            }
        }

        match &self.gateway_mac {
            Some(mac) => out.push_str(&format!("Gateway MAC (for trusted_networks): {mac}\n")),
            None => out.push_str("Gateway MAC: not detected\n"),
        }

        // All AI edges must agree with EACH OTHER too: per-domain routing
        // rules (claude.ai via VPN, api.anthropic.com direct) are a real
        // proxy-client configuration.
        let mut seen: Vec<&str> = Vec::new();
        for route in &self.route_answers {
            if let Some(ip) = &route.ip
                && !seen.contains(&ip.as_str())
            {
                seen.push(ip);
            }
        }
        if seen.len() > 1 {
            problems.push(format!(
                "the AI edges disagree on your exit: {} — per-domain routing leak",
                seen.join(" vs ")
            ));
        }

        if let Some(rep) = &self.reputation {
            out.push_str(&format!("Exit IP reputation: {}\n", rep.render()));
            problems.extend(rep.problems());
        }
        if let Some(p) = claude_region_problem(self.country.as_deref()) {
            problems.push(p);
        }
        let trace_ips: Vec<Option<&str>> =
            self.route_answers.iter().map(|r| r.ip.as_deref()).collect();
        if let Some(p) = ipv6_exit_problem(&trace_ips, self.ipv6_exit.as_deref()) {
            problems.push(p);
        }

        if problems.is_empty() {
            out.push_str("No leaks detected.\n");
        } else {
            out.push_str("Problems:\n");
            for p in &problems {
                out.push_str(&format!("  ! {p}\n"));
            }
        }

        (out, problems)
    }
}

/// Local timezone name from the `/etc/localtime` symlink
/// (`…/zoneinfo/Europe/Moscow` → `Europe/Moscow`). Linux-only, None elsewhere.
fn local_timezone() -> Option<String> {
    let target = std::fs::read_link("/etc/localtime").ok()?;
    let s = target.to_string_lossy();
    s.split("zoneinfo/").nth(1).map(String::from)
}

fn proxy_env() -> Vec<(String, String)> {
    ["http_proxy", "https_proxy", "all_proxy", "no_proxy"]
        .iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| ((*k).to_string(), v)))
        .collect()
}

/// Parse a `/cdn-cgi/trace` body: `ip=1.2.3.4` and `loc=NL` lines.
pub fn parse_trace(body: &str) -> (Option<String>, Option<String>) {
    let mut ip = None;
    let mut loc = None;
    for line in body.lines() {
        if let Some(v) = line.strip_prefix("ip=") {
            ip = Some(v.trim().to_string());
        }
        if let Some(v) = line.strip_prefix("loc=") {
            loc = Some(v.trim().to_string());
        }
    }
    (ip, loc)
}

/// Parse `/etc/resolv.conf` nameservers (Linux/macOS; None elsewhere).
pub fn resolv_conf_servers(content: &str) -> Vec<String> {
    content
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            l.strip_prefix("nameserver ")
                .or_else(|| l.strip_prefix("nameserver\t"))
                .map(str::trim)
                .filter(|s| s.parse::<std::net::IpAddr>().is_ok())
                .map(String::from)
        })
        .collect()
}

fn read_dns_servers() -> Vec<String> {
    std::fs::read_to_string("/etc/resolv.conf")
        .map(|raw| resolv_conf_servers(&raw))
        .unwrap_or_default()
}

/// Geolocate a DNS resolver via the first country service that supports
/// `GET /<ip>` (api.country.is does). Loopback addresses are local forwarders.
async fn dns_country(client: &reqwest::Client, services: &[String], ip: &str) -> String {
    #[derive(serde::Deserialize)]
    struct CountryReply {
        country: String,
    }
    if ip.starts_with("127.") || ip.starts_with("::1") {
        return "local forwarder (upstream unknown)".to_string();
    }
    for svc in services {
        let url = format!("{svc}/{ip}");
        if let Ok(resp) = client.get(&url).send().await
            && let Ok(body) = resp.text().await
            && let Ok(reply) = serde_json::from_str::<CountryReply>(&body)
        {
            return reply.country;
        }
    }
    "error: no country service could resolve it".to_string()
}

/// Build the report; the CLI prints it, the panel returns it as JSON.
pub async fn report(config_path: &Path, explicit: bool) -> Result<(String, Vec<String>)> {
    let cfg = config::load(config_path, explicit)?;
    let timeout = Duration::from_secs(cfg.ip_check.timeout_secs.max(1));
    let client = reqwest::Client::builder().timeout(timeout).build()?;

    // Each service individually (no quorum): the point is to see disagreement.
    let mut service_answers = Vec::new();
    for url in &cfg.ip_check.ip_services {
        service_answers.push((url.clone(), fetch_ip(&client, url).await));
    }
    let mut ipv6_answers = Vec::new();
    for url in &cfg.ip_check.ipv6_services {
        ipv6_answers.push((url.clone(), fetch_ip(&client, url).await));
    }

    // The quorum verdict for comparison.
    let verdict = ipcheck::check(&cfg.ip_check).await;

    let mut route_answers = Vec::new();
    for service in &cfg.route_check.services {
        route_answers.push(fetch_trace(&client, service).await);
    }

    let mut dns_servers = Vec::new();
    for ip in read_dns_servers() {
        let country = dns_country(&client, &cfg.ip_check.country_services, &ip).await;
        dns_servers.push((ip, country));
    }

    let reputation = match verdict.ipv4 {
        Some(ip) => Some(fetch_reputation(&client, &ip.to_string()).await),
        None => None,
    };

    let leak_report = LeakReport {
        service_answers,
        ipv6_answers,
        route_answers,
        quorum_ip: verdict.ipv4.map(|i| i.to_string()),
        ipv6_exit: verdict.ipv6.map(|i| i.to_string()),
        country: verdict.country.clone(),
        timezone: local_timezone(),
        proxy_env: proxy_env(),
        gateway_mac: trusted::gateway_mac(),
        dns_servers,
        reputation,
    };

    Ok(leak_report.render())
}

pub async fn run(config_path: &Path, explicit: bool) -> Result<u8> {
    let (text, problems) = report(config_path, explicit).await?;
    print!("{text}");
    Ok(if problems.is_empty() { 0 } else { 4 })
}

async fn fetch_ip(client: &reqwest::Client, url: &str) -> String {
    match client.get(url).send().await {
        Ok(resp) => match resp.text().await {
            Ok(body) => {
                let trimmed = body.trim();
                if trimmed.parse::<std::net::IpAddr>().is_ok() {
                    trimmed.to_string()
                } else {
                    format!("error: not an IP: {}", &trimmed[..trimmed.len().min(40)])
                }
            }
            Err(err) => format!("error: {err}"),
        },
        Err(err) => format!("error: {err}"),
    }
}

/// Ask one AI service's own edge where the request came from (and how fast).
pub(crate) async fn fetch_trace_public(client: &reqwest::Client, service: &str) -> RouteAnswer {
    fetch_trace(client, service).await
}

async fn fetch_trace(client: &reqwest::Client, service: &str) -> RouteAnswer {
    let url = format!("https://{service}/cdn-cgi/trace");
    let started = std::time::Instant::now();
    match client.get(&url).send().await {
        Ok(resp) => match resp.text().await {
            Ok(body) => {
                let latency_ms = Some(started.elapsed().as_millis());
                let (ip, country) = parse_trace(&body);
                let error = if ip.is_none() {
                    Some("unparseable /cdn-cgi/trace answer".to_string())
                } else {
                    None
                };
                RouteAnswer {
                    service: service.to_string(),
                    ip,
                    country,
                    error,
                    latency_ms,
                }
            }
            Err(err) => RouteAnswer {
                service: service.to_string(),
                ip: None,
                country: None,
                error: Some(err.to_string()),
                latency_ms: Some(started.elapsed().as_millis()),
            },
        },
        Err(err) => RouteAnswer {
            service: service.to_string(),
            ip: None,
            country: None,
            error: Some(err.to_string()),
            latency_ms: Some(started.elapsed().as_millis()),
        },
    }
}

/// Fetch the exit IP's reputation from ip-api.com (free, no key, HTTP).
pub async fn fetch_reputation(client: &reqwest::Client, ip: &str) -> Reputation {
    #[derive(serde::Deserialize)]
    struct IpApiReply {
        #[serde(default)]
        status: String,
        #[serde(default)]
        isp: Option<String>,
        #[serde(default)]
        r#as: Option<String>,
        #[serde(default)]
        mobile: Option<bool>,
        #[serde(default)]
        proxy: Option<bool>,
        #[serde(default)]
        hosting: Option<bool>,
    }
    let url =
        format!("http://ip-api.com/json/{ip}?fields=status,message,isp,as,mobile,proxy,hosting");
    match client.get(&url).send().await {
        Ok(resp) => match resp.text().await {
            Ok(body) => match serde_json::from_str::<IpApiReply>(&body) {
                Ok(reply) if reply.status == "success" => Reputation {
                    isp: reply.isp,
                    asn: reply.r#as,
                    hosting: reply.hosting,
                    proxy: reply.proxy,
                    tor: None, // ip-api merges Tor into proxy
                    mobile: reply.mobile,
                    error: None,
                },
                Ok(reply) => Reputation {
                    error: Some(format!("ip-api status: {}", reply.status)),
                    ..Reputation::default()
                },
                Err(err) => Reputation {
                    error: Some(err.to_string()),
                    ..Reputation::default()
                },
            },
            Err(err) => Reputation {
                error: Some(err.to_string()),
                ..Reputation::default()
            },
        },
        Err(err) => Reputation {
            error: Some(err.to_string()),
            ..Reputation::default()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cloudflare_trace() {
        let body = "fl=abc\nh=claude.ai\nip=203.0.113.9\nts=1\nloc=NL\ntls=1.3\n";
        let (ip, loc) = parse_trace(body);
        assert_eq!(ip.as_deref(), Some("203.0.113.9"));
        assert_eq!(loc.as_deref(), Some("NL"));
    }

    #[test]
    fn trace_without_fields_is_none() {
        let (ip, loc) = parse_trace("fl=abc\nh=x\n");
        assert_eq!(ip, None);
        assert_eq!(loc, None);
    }

    fn report_with(routes: Vec<RouteAnswer>, quorum_ip: Option<&str>) -> LeakReport {
        LeakReport {
            service_answers: vec![("https://a".into(), "203.0.113.7".into())],
            ipv6_answers: vec![],
            route_answers: routes,
            quorum_ip: quorum_ip.map(String::from),
            ipv6_exit: None,
            country: Some("NL".into()),
            timezone: None,
            proxy_env: vec![],
            gateway_mac: None,
            dns_servers: vec![],
            reputation: None,
        }
    }

    #[test]
    fn matching_route_is_not_a_leak() {
        let r = report_with(
            vec![RouteAnswer {
                service: "claude.ai".into(),
                ip: Some("203.0.113.7".into()),
                country: Some("NL".into()),
                error: None,
                latency_ms: None,
            }],
            Some("203.0.113.7"),
        );
        let (_, problems) = r.render();
        assert!(problems.is_empty(), "{problems:?}");
    }

    #[test]
    fn trace_matches_is_dual_stack_aware() {
        let v4 = Some("203.0.113.7");
        let v6 = Some("2001:db8::1");
        assert!(trace_matches("203.0.113.7", v4, v6));
        assert!(trace_matches("2001:db8::1", v4, v6));
        assert!(!trace_matches("198.51.100.9", v4, v6));
        assert!(!trace_matches("203.0.113.7", None, v6));
    }

    #[test]
    fn ipv6_trace_matching_the_v6_exit_is_not_a_leak() {
        let mut r = report_with(
            vec![RouteAnswer {
                service: "claude.ai".into(),
                ip: Some("2001:db8::1".into()),
                country: Some("NL".into()),
                error: None,
                latency_ms: None,
            }],
            Some("203.0.113.7"),
        );
        r.ipv6_exit = Some("2001:db8::1".into());
        let (_, problems) = r.render();
        // No split-routing problem — but the advisory IPv6 warning fires.
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("IPv6"));
    }

    #[test]
    fn diverging_route_is_a_split_routing_leak() {
        let r = report_with(
            vec![RouteAnswer {
                service: "claude.ai".into(),
                ip: Some("198.51.100.9".into()),
                country: Some("RU".into()),
                error: None,
                latency_ms: None,
            }],
            Some("203.0.113.7"),
        );
        let (_, problems) = r.render();
        assert_eq!(problems.len(), 1);
        assert!(problems[0].contains("split routing"));
    }

    #[test]
    fn unsupported_claude_region_is_a_problem() {
        assert!(claude_region_problem(Some("RU")).is_some());
        assert!(claude_region_problem(Some("NL")).is_none());
        assert!(claude_region_problem(None).is_none());
    }

    #[test]
    fn ipv6_trace_to_the_edge_warns() {
        let traces = [Some("2001:db8::1"), Some("203.0.113.7"), None];
        assert!(ipv6_exit_problem(&traces, None).is_some());
        let v4_only = [Some("203.0.113.7")];
        assert!(ipv6_exit_problem(&v4_only, Some("2001:db8::1")).is_none());
    }

    #[test]
    fn reputation_problems_flag_proxy_and_datacenter() {
        let mut rep = Reputation {
            hosting: Some(true),
            ..Reputation::default()
        };
        assert_eq!(rep.problems().len(), 1);
        rep.proxy = Some(true);
        rep.tor = Some(true);
        rep.hosting = Some(false);
        assert_eq!(rep.problems().len(), 2);
        let clean = Reputation {
            hosting: Some(false),
            proxy: Some(false),
            tor: Some(false),
            mobile: Some(false),
            ..Reputation::default()
        };
        assert!(clean.problems().is_empty());
        assert!(clean.render().starts_with("residential"));
    }

    #[test]
    fn edges_disagreeing_with_each_other_is_a_problem() {
        let mut r = report_with(vec![], Some("203.0.113.7"));
        r.route_answers = vec![
            RouteAnswer {
                service: "claude.ai".into(),
                ip: Some("203.0.113.7".into()),
                country: None,
                error: None,
                latency_ms: None,
            },
            RouteAnswer {
                service: "api.anthropic.com".into(),
                ip: Some("198.51.100.9".into()), // also matches nothing
                country: None,
                error: None,
                latency_ms: None,
            },
        ];
        r.ipv6_exit = Some("198.51.100.9".into()); // each trace matches SOME exit
        let (_, problems) = r.render();
        assert!(
            problems.iter().any(|p| p.contains("edges disagree")),
            "{problems:?}"
        );
    }

    #[test]
    fn disagreeing_services_are_a_problem() {
        let mut r = report_with(vec![], Some("203.0.113.7"));
        r.service_answers = vec![
            ("https://a".into(), "203.0.113.7".into()),
            ("https://b".into(), "198.51.100.9".into()),
        ];
        let (_, problems) = r.render();
        assert!(problems.iter().any(|p| p.contains("disagree")));
    }
}
