//! Allowlist evaluation — pure logic, no I/O, heavily unit-tested.
//!
//! The rule is fail-closed: an unknown verdict (no quorum, no answer) is
//! never allowed. A known address is allowed when it is listed directly, its
//! subnet is listed, or the country reported for the current exit is listed.

use std::net::IpAddr;

use crate::{config::AllowConfig, ipcheck::Verdict};

#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    ips: Vec<IpAddr>,
    nets: Vec<IpNet2>,
    countries: Vec<String>,
}

// Re-export alias keeps the public field types tidy.
use ipnet::IpNet as IpNet2;

impl Allowlist {
    /// The effective allowlist is the union of the config and the runtime
    /// state (`shuang allow` writes to `state.toml`).
    pub fn merged(config: &AllowConfig, state: &AllowConfig) -> Self {
        let mut ips = config.ips.clone();
        let mut nets = config.nets.clone();
        let mut countries = config.countries.clone();
        for ip in &state.ips {
            if !ips.contains(ip) {
                ips.push(*ip);
            }
        }
        for net in &state.nets {
            if !nets.contains(net) {
                nets.push(*net);
            }
        }
        for country in &state.countries {
            let country = country.clone();
            if !countries.contains(&country) {
                countries.push(country);
            }
        }
        Self {
            ips,
            nets,
            countries,
        }
    }

    pub fn allows_ip(&self, ip: IpAddr) -> bool {
        self.ips.contains(&ip) || self.nets.iter().any(|net| net.contains(&ip))
    }

    pub fn allows_country(&self, country: &str) -> bool {
        self.countries.iter().any(|c| c == country)
    }

    pub fn is_empty(&self) -> bool {
        self.ips.is_empty() && self.nets.is_empty() && self.countries.is_empty()
    }

    /// Add a directly allowed IP at runtime (first-run semantics of
    /// `shuang run`: with an empty allowlist, the IP observed at start becomes
    /// the allowed one).
    pub fn push_ip(&mut self, ip: IpAddr) {
        if !self.ips.contains(&ip) {
            self.ips.push(ip);
        }
    }
}

/// Fail-closed evaluation of a verdict against the allowlist.
///
/// - no quorum / no IPv4 answer → not allowed (unknown is unsafe);
/// - the IPv4 answer must be allowed (direct IP, subnet, or country);
/// - every known IPv6 answer must be allowed too — a VPN that tunnels only
///   IPv4 while the machine keeps a direct IPv6 route is exactly the leak
///   this tool exists to catch.
pub fn allowed(verdict: &Verdict, list: &Allowlist) -> bool {
    let Some(v4) = verdict.ipv4 else {
        return false;
    };
    if !verdict.quorum {
        return false;
    }
    if !one_allowed(v4, verdict.country.as_deref(), list) {
        return false;
    }
    if let Some(v6) = verdict.ipv6
        && !one_allowed(v6, verdict.country.as_deref(), list)
    {
        return false;
    }
    true
}

fn one_allowed(ip: IpAddr, country: Option<&str>, list: &Allowlist) -> bool {
    list.allows_ip(ip) || country.is_some_and(|c| list.allows_country(c))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verdict(v4: Option<&str>, v6: Option<&str>, country: Option<&str>) -> Verdict {
        Verdict {
            ipv4: v4.and_then(|s| s.parse().ok()),
            ipv6: v6.and_then(|s| s.parse().ok()),
            country: country.map(String::from),
            quorum: true,
        }
    }

    fn list_with(ips: &[&str], nets: &[&str], countries: &[&str]) -> Allowlist {
        Allowlist::merged(
            &AllowConfig {
                ips: ips.iter().map(|s| s.parse().unwrap()).collect(),
                nets: nets.iter().map(|s| s.parse().unwrap()).collect(),
                countries: countries.iter().map(|s| s.to_string()).collect(),
            },
            &AllowConfig::default(),
        )
    }

    #[test]
    fn exact_ip_is_allowed() {
        let list = list_with(&["203.0.113.4"], &[], &[]);
        assert!(allowed(&verdict(Some("203.0.113.4"), None, None), &list));
        assert!(!allowed(&verdict(Some("203.0.113.5"), None, None), &list));
    }

    #[test]
    fn subnet_is_allowed() {
        let list = list_with(&[], &["185.12.40.0/24"], &[]);
        assert!(allowed(&verdict(Some("185.12.40.77"), None, None), &list));
        assert!(!allowed(&verdict(Some("185.12.41.1"), None, None), &list));
    }

    #[test]
    fn country_is_allowed() {
        let list = list_with(&[], &[], &["NL"]);
        assert!(allowed(
            &verdict(Some("198.51.100.1"), None, Some("NL")),
            &list
        ));
        assert!(!allowed(
            &verdict(Some("198.51.100.1"), None, Some("DE")),
            &list
        ));
        // Country unknown: fail closed for an unlisted IP.
        assert!(!allowed(&verdict(Some("198.51.100.1"), None, None), &list));
    }

    #[test]
    fn unknown_verdict_is_never_allowed() {
        let list = list_with(&["203.0.113.4"], &[], &[]);
        let unknown = Verdict {
            ipv4: None,
            ipv6: None,
            country: None,
            quorum: false,
        };
        assert!(!allowed(&unknown, &list));
        // Quorum missing: even a listed IP is not trusted.
        let no_quorum = Verdict {
            quorum: false,
            ..verdict(Some("203.0.113.4"), None, None)
        };
        assert!(!allowed(&no_quorum, &list));
    }

    #[test]
    fn ipv6_leak_is_caught() {
        // IPv4 allowed via subnet, but a direct IPv6 route is not allowed.
        let list = list_with(&[], &["185.12.40.0/24"], &[]);
        let leak = verdict(Some("185.12.40.1"), Some("2001:db8::1"), None);
        assert!(!allowed(&leak, &list));
        // Same verdict, IPv6 inside the allowed country → allowed.
        let mut ok = leak.clone();
        ok.country = Some("NL".to_string());
        let list_nl = list_with(&[], &["185.12.40.0/24"], &["NL"]);
        assert!(allowed(&ok, &list_nl));
    }

    #[test]
    fn state_merges_without_duplicates() {
        let config = AllowConfig {
            ips: vec!["203.0.113.4".parse().unwrap()],
            nets: vec!["10.0.0.0/8".parse().unwrap()],
            countries: vec!["NL".to_string()],
        };
        let state = AllowConfig {
            ips: vec!["203.0.113.4".parse().unwrap(), "192.0.2.1".parse().unwrap()],
            nets: vec![],
            countries: vec!["NL".to_string(), "DE".to_string()],
        };
        let merged = Allowlist::merged(&config, &state);
        assert_eq!(merged.ips.len(), 2);
        assert_eq!(merged.nets.len(), 1);
        assert_eq!(merged.countries, ["NL", "DE"]);
    }

    #[test]
    fn push_ip_is_idempotent() {
        let mut list = list_with(&["203.0.113.4"], &[], &[]);
        list.push_ip("203.0.113.4".parse().unwrap());
        assert_eq!(list.ips.len(), 1);
        list.push_ip("203.0.113.5".parse().unwrap());
        assert_eq!(list.ips.len(), 2);
    }
}
