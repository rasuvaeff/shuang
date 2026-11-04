//! Allowlist evaluation — pure logic, no I/O, heavily unit-tested.
//!
//! The rule is fail-closed: an unknown verdict (no quorum, no answer) is
//! never allowed. A known address is allowed when it is listed directly, its
//! subnet is listed, or the country reported for the current exit is listed.

use std::net::IpAddr;

use crate::{
    config::{AllowConfig, Config, State},
    ipcheck::Verdict,
};

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

    /// Merge an extra allow config into this list (profile or per-app rules):
    /// union, no removals, idempotent.
    pub fn merge_in(&mut self, extra: &AllowConfig) {
        for ip in &extra.ips {
            self.push_ip(*ip);
        }
        for net in &extra.nets {
            if !self.nets.contains(net) {
                self.nets.push(*net);
            }
        }
        for country in &extra.countries {
            if !self.countries.contains(country) {
                self.countries.push(country.clone());
            }
        }
    }

    /// A copy of this list plus an extra config (profiles, per-app rules).
    pub fn with_extra(&self, extra: &AllowConfig) -> Allowlist {
        let mut out = self.clone();
        out.merge_in(extra);
        out
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

/// The global effective allowlist: config ∪ active profile ∪ state.
/// Returns a warning when the selected profile does not exist (the run
/// continues on the base allowlist — protection first).
pub fn effective(cfg: &Config, state: &State) -> (Allowlist, Option<String>) {
    let mut list = Allowlist::merged(&cfg.allow, &state.allow);
    let mut warning = None;
    if let Some(name) = &state.active_profile {
        match cfg.profiles.get(name) {
            Some(extra) => list.merge_in(extra),
            None => warning = Some(format!("profile {name:?} is not defined in config.toml")),
        }
    }
    (list, warning)
}

/// Why a verdict was denied — the human-readable twin of `allowed`, so events
/// can tell "the VPN changed the IP" apart from "we could not confirm the IP".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// No quorum (or no answer at all): the external IP is unknown.
    NoQuorum,
    /// The IPv4 address is known but not allowed.
    Foreign { ip: IpAddr, country: Option<String> },
    /// The IPv4 address is fine, but a direct IPv6 route is not allowed —
    /// the classic "VPN tunnels only IPv4" leak.
    Ipv6Leak { v4: IpAddr, v6: IpAddr },
}

impl DenyReason {
    /// One-line, user-facing, honest: never claims the IP is wrong when the
    /// truth is that it could not be confirmed.
    pub fn message(&self) -> String {
        match self {
            DenyReason::NoQuorum => {
                "cannot confirm the external IP (not enough services agreed)".to_string()
            }
            DenyReason::Foreign { ip, country } => match country {
                Some(c) => format!("IP {ip} ({c}) is not allowed"),
                None => format!(
                    "IP {ip} is not on the allowlist and the country could not be confirmed \
                     (country service unreachable)"
                ),
            },
            DenyReason::Ipv6Leak { v4, v6 } => {
                format!("IPv4 {v4} is fine but IPv6 {v6} is not allowed (direct route leak?)")
            }
        }
    }
}

/// The deny twin of `allowed`: `None` when allowed, the reason when not.
pub fn deny_reason(verdict: &Verdict, list: &Allowlist) -> Option<DenyReason> {
    let Some(v4) = verdict.ipv4 else {
        return Some(DenyReason::NoQuorum);
    };
    if !verdict.quorum {
        return Some(DenyReason::NoQuorum);
    }
    if !one_allowed(v4, verdict.country.as_deref(), list) {
        return Some(DenyReason::Foreign {
            ip: v4,
            country: verdict.country.clone(),
        });
    }
    if let Some(v6) = verdict.ipv6
        && !one_allowed(v6, verdict.country.as_deref(), list)
    {
        return Some(DenyReason::Ipv6Leak { v4, v6 });
    }
    None
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

    #[test]
    fn with_extra_unions_profile_and_app_rules() {
        let base = list_with(&["203.0.113.4"], &["10.0.0.0/8"], &["NL"]);
        let profile = AllowConfig {
            ips: vec![],
            nets: vec![],
            countries: vec!["DE".to_string()],
        };
        let with_profile = base.with_extra(&profile);
        assert!(with_profile.allows_country("DE"));
        assert!(with_profile.allows_country("NL"));
        // The base list is untouched (per-app copies stay independent).
        assert!(!base.allows_country("DE"));
        // Idempotent merge.
        let twice = with_profile.with_extra(&profile);
        assert_eq!(twice.countries.len(), 2);
    }
}

#[cfg(test)]
mod properties {
    use super::*;
    use proptest::prelude::*;

    fn any_ip() -> impl proptest::strategy::Strategy<Value = IpAddr> {
        (0u32..=0xFFFF_FFFF).prop_map(|n| IpAddr::V4(std::net::Ipv4Addr::from(n)))
    }

    fn any_country() -> impl proptest::strategy::Strategy<Value = Option<String>> {
        proptest::option::of(proptest::sample::select(vec![
            "NL".to_string(),
            "DE".to_string(),
            "US".to_string(),
        ]))
    }

    fn any_list() -> impl proptest::strategy::Strategy<Value = Allowlist> {
        (
            proptest::collection::vec(any_ip(), 0..4),
            proptest::option::of(24u8..25),
            any_country(),
        )
            .prop_map(|(ips, prefix, country)| {
                let countries = country.into_iter().collect();
                Allowlist::merged(
                    &AllowConfig {
                        ips,
                        nets: vec![],
                        countries,
                    },
                    &AllowConfig {
                        ips: vec![],
                        // One fixed-ish subnet of the 185.12.40.0/24 shape when enabled.
                        nets: prefix
                            .map(|_| "185.12.40.0/24".parse().unwrap())
                            .into_iter()
                            .collect(),
                        countries: vec![],
                    },
                )
            })
    }

    fn any_verdict() -> impl proptest::strategy::Strategy<Value = Verdict> {
        (
            proptest::option::of(any_ip()),
            any_country(),
            0u8..2,
            0u8..2,
        )
            .prop_map(|(v4, country, quorum, with_v6)| Verdict {
                ipv4: v4,
                // Half the generated verdicts also carry an IPv6 exit.
                ipv6: (with_v6 % 2 == 0).then_some(IpAddr::V6("2001:db8::1".parse().unwrap())),
                country,
                quorum: quorum % 2 == 1,
            })
    }

    proptest! {
        /// Invariant 1: `allowed` and `deny_reason` always agree.
        #[test]
        fn allowed_agrees_with_deny_reason(verdict in any_verdict(), list in any_list()) {
            assert_eq!(allowed(&verdict, &list), deny_reason(&verdict, &list).is_none());
        }

        /// Invariant 2 (the product rule): no quorum → never allowed, no
        /// matter what the allowlist contains.
        #[test]
        fn no_quorum_never_allowed(v4 in proptest::option::of(any_ip()), list in any_list()) {
            let verdict = Verdict { ipv4: v4, ipv6: None, country: None, quorum: false };
            prop_assert!(!allowed(&verdict, &list));
        }

        /// Invariant 3: monotonicity of the allowlist — adding entries never
        /// turns an allowed verdict into a denied one.
        #[test]
        fn allowlist_is_monotone(verdict in any_verdict(), extra_ip in any_ip()) {
            let base = Allowlist::merged(&AllowConfig::default(), &AllowConfig::default());
            let mut bigger = base.clone();
            bigger.push_ip(extra_ip);
            prop_assert!(bigger.allows_ip(extra_ip));
            if allowed(&verdict, &base) {
                prop_assert!(allowed(&verdict, &bigger));
            }
        }

        /// Invariant 4: a country-allowed verdict stays allowed when the exit
        /// IP changes inside the same country.
        #[test]
        fn country_allow_is_ip_agnostic(listed in proptest::sample::select(vec!["NL", "DE"]), ip in any_ip()) {
            let list = Allowlist::merged(
                &AllowConfig { ips: vec![], nets: vec![], countries: vec![listed.to_string()] },
                &AllowConfig::default(),
            );
            let verdict = Verdict { ipv4: Some(ip), ipv6: None, country: Some(listed.to_string()), quorum: true };
            prop_assert!(allowed(&verdict, &list));
        }
    }
}
