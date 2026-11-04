//! External IP discovery with a quorum.
//!
//! Every configured service is asked concurrently; an answer counts only when
//! at least `min_agree` services name the same address. Anything less is
//! "unknown", and unknown is never allowed (fail-closed).

use std::{collections::HashMap, net::IpAddr, time::Duration};

use serde::Deserialize;

use crate::config::IpCheckConfig;

/// What the check services said about the current exit.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Verdict {
    /// IPv4 address confirmed by the quorum, if any.
    pub ipv4: Option<IpAddr>,
    /// IPv6 address, single answer is enough (checked separately from IPv4).
    pub ipv6: Option<IpAddr>,
    /// Country of the current exit (best-effort, from `country_services`).
    pub country: Option<String>,
    /// Whether the IPv4 quorum was met. `false` means "unknown — not allowed".
    pub quorum: bool,
}

#[derive(Deserialize)]
struct CountryReply {
    country: String,
}

pub async fn check(cfg: &IpCheckConfig) -> Verdict {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(cfg.timeout_secs.max(1)))
        .build()
    {
        Ok(client) => client,
        Err(_) => return Verdict::default(),
    };

    let v4 = query_all(&client, &cfg.ip_services, Family::V4).await;
    let v6 = query_all(&client, &cfg.ipv6_services, Family::V6).await;
    let country = query_country(&client, &cfg.country_services).await;

    let (ipv4, quorum) = resolve(v4, cfg.min_agree);
    Verdict {
        ipv4,
        ipv6: resolve(v6, 1).0,
        country,
        quorum,
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Family {
    V4,
    V6,
}

impl Family {
    fn parse(&self, body: &str) -> Option<IpAddr> {
        let ip: IpAddr = body.trim().parse().ok()?;
        match (self, ip) {
            (Family::V4, IpAddr::V4(_)) | (Family::V6, IpAddr::V6(_)) => Some(ip),
            _ => None,
        }
    }
}

async fn query_all(client: &reqwest::Client, urls: &[String], family: Family) -> Vec<IpAddr> {
    let mut answers = Vec::new();
    let mut tasks = tokio::task::JoinSet::new();
    for url in urls {
        let client = client.clone();
        let url = url.clone();
        tasks.spawn(async move {
            let body = client.get(&url).send().await.ok()?.text().await.ok()?;
            family.parse(&body)
        });
    }
    while let Some(joined) = tasks.join_next().await {
        if let Ok(Some(ip)) = joined {
            answers.push(ip);
        }
    }
    answers
}

async fn query_country(client: &reqwest::Client, urls: &[String]) -> Option<String> {
    let mut tasks = tokio::task::JoinSet::new();
    for url in urls {
        let client = client.clone();
        let url = url.clone();
        tasks.spawn(async move {
            let body = client.get(&url).send().await.ok()?.text().await.ok()?;
            let reply: CountryReply = serde_json::from_str(&body).ok()?;
            let country = reply.country.trim().to_ascii_uppercase();
            let ok = country.len() == 2 && country.chars().all(|c| c.is_ascii_alphabetic());
            ok.then_some(country)
        });
    }
    while let Some(joined) = tasks.join_next().await {
        if let Ok(Some(country)) = joined {
            return Some(country);
        }
    }
    None
}

/// Pick the address named by at least `min_agree` answers. A tie between two
/// different addresses is ambiguous and resolves to `None`.
fn resolve(answers: Vec<IpAddr>, min_agree: usize) -> (Option<IpAddr>, bool) {
    let mut tally: HashMap<IpAddr, usize> = HashMap::new();
    for ip in &answers {
        *tally.entry(*ip).or_default() += 1;
    }
    let mut counts: Vec<(IpAddr, usize)> = tally.into_iter().collect();
    counts.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.to_string().cmp(&b.0.to_string())));
    match counts.first() {
        Some((ip, count))
            if *count >= min_agree && counts.get(1).is_none_or(|(_, c)| *c < *count) =>
        {
            (Some(*ip), true)
        }
        _ => (None, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(n: u8) -> IpAddr {
        IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, n))
    }

    #[test]
    fn quorum_of_two_agrees() {
        let (ip, ok) = resolve(vec![v4(1), v4(1), v4(2)], 2);
        assert_eq!(ip, Some(v4(1)));
        assert!(ok);
    }

    #[test]
    fn single_answer_is_not_enough_for_min_agree_two() {
        let (ip, ok) = resolve(vec![v4(1), none_ip(), v4(2)], 2);
        assert_eq!(ip, None);
        assert!(!ok);
    }

    #[test]
    fn tie_is_ambiguous() {
        let (ip, ok) = resolve(vec![v4(1), v4(1), v4(2), v4(2)], 2);
        assert_eq!(ip, None);
        assert!(!ok);
    }

    #[test]
    fn no_answers_is_unknown() {
        let (ip, ok) = resolve(vec![], 2);
        assert_eq!(ip, None);
        assert!(!ok);
    }

    #[test]
    fn ipv6_single_answer_suffices() {
        let ip6: IpAddr = "2001:db8::1".parse().unwrap();
        let (ip, ok) = resolve(vec![ip6], 1);
        assert_eq!(ip, Some(ip6));
        assert!(ok);
    }

    #[test]
    fn family_rejects_wrong_version() {
        assert!(Family::V4.parse("2001:db8::1").is_none());
        assert!(Family::V6.parse("203.0.113.4").is_none());
        assert_eq!(Family::V4.parse(" 203.0.113.4\n"), Some(v4(4)));
    }

    fn none_ip() -> IpAddr {
        // A distinct address that simply splits the vote further.
        v4(3)
    }
}
