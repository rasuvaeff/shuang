//! `shuang allow` — persist an allowlist entry to `state.toml`.
//!
//! The hand-written `config.toml` (with its comments) is never rewritten:
//! runtime additions live in a sibling `state.toml` and merge on load.

use std::{net::IpAddr, path::Path, str::FromStr};

use anyhow::{Context, Result, bail};
use ipnet::IpNet;

use crate::config;

pub fn run(config_path: &Path, value: &str) -> Result<u8> {
    let mut state = config::load_state(config_path);

    if let Ok(ip) = IpAddr::from_str(value) {
        if !state.allow.ips.contains(&ip) {
            state.allow.ips.push(ip);
        }
        config::save_state(config_path, &state)?;
        println!(
            "Allowed IP {ip} ({})",
            config::state_path(config_path).display()
        );
        return Ok(0);
    }

    if let Ok(net) = IpNet::from_str(value) {
        if !state.allow.nets.contains(&net) {
            state.allow.nets.push(net);
        }
        config::save_state(config_path, &state)?;
        println!(
            "Allowed subnet {net} ({})",
            config::state_path(config_path).display()
        );
        return Ok(0);
    }

    let country = value.trim().to_ascii_uppercase();
    if country.len() == 2 && country.chars().all(|c| c.is_ascii_alphabetic()) {
        if !state.allow.countries.contains(&country) {
            state.allow.countries.push(country.clone());
        }
        config::save_state(config_path, &state)?;
        println!(
            "Allowed country {country} ({})",
            config::state_path(config_path).display()
        );
        return Ok(0);
    }

    bail!("not an IP address, CIDR subnet, or two-letter country code: {value:?}");
}

/// Remove an allowlist entry from `state.toml` (the panel's "×" button).
/// Mirrors the parse order of `run`: IP → subnet → country.
pub fn remove(config_path: &Path, value: &str) -> Result<bool> {
    let mut state = config::load_state(config_path);
    let removed = if let Ok(ip) = IpAddr::from_str(value) {
        let before = state.allow.ips.len();
        state.allow.ips.retain(|i| *i != ip);
        state.allow.ips.len() != before
    } else if let Ok(net) = IpNet::from_str(value) {
        let before = state.allow.nets.len();
        state.allow.nets.retain(|n| *n != net);
        state.allow.nets.len() != before
    } else {
        let country = value.trim().to_ascii_uppercase();
        let before = state.allow.countries.len();
        state.allow.countries.retain(|c| *c != country);
        state.allow.countries.len() != before
    };

    if removed {
        config::save_state(config_path, &state).context("cannot write state.toml")?;
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_ip_writes_state() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        run(&cfg_path, "203.0.113.10").unwrap();
        let state = config::load_state(&cfg_path);
        assert_eq!(state.allow.ips.len(), 1);
        // Idempotent.
        run(&cfg_path, "203.0.113.10").unwrap();
        let state = config::load_state(&cfg_path);
        assert_eq!(state.allow.ips.len(), 1);
    }

    #[test]
    fn allow_subnet_and_country() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        run(&cfg_path, "185.12.40.0/24").unwrap();
        run(&cfg_path, "nl").unwrap(); // normalized to uppercase
        let state = config::load_state(&cfg_path);
        assert_eq!(state.allow.nets.len(), 1);
        assert_eq!(state.allow.countries, ["NL"]);
    }

    #[test]
    fn garbage_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        assert!(run(&cfg_path, "not a thing").is_err());
        assert!(run(&cfg_path, "NLD").is_err());
        assert!(config::load_state(&cfg_path).allow.ips.is_empty());
    }

    #[test]
    fn remove_deletes_only_the_matching_entry() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        run(&cfg_path, "203.0.113.10").unwrap();
        run(&cfg_path, "203.0.113.11").unwrap();
        run(&cfg_path, "NL").unwrap();

        assert!(remove(&cfg_path, "203.0.113.10").unwrap());
        let state = config::load_state(&cfg_path);
        assert_eq!(state.allow.ips.len(), 1);
        assert_eq!(state.allow.countries, ["NL"]);

        // Removing a non-existing entry reports false and writes nothing.
        assert!(!remove(&cfg_path, "198.51.100.1").unwrap());
        assert!(remove(&cfg_path, "nl").unwrap()); // case-insensitive
        assert!(config::load_state(&cfg_path).allow.countries.is_empty());
    }
}
