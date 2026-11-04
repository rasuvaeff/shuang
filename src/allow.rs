//! `shuang allow` — persist an allowlist entry to `state.toml`.
//!
//! The hand-written `config.toml` (with its comments) is never rewritten:
//! runtime additions live in a sibling `state.toml` and merge on load.

use std::{net::IpAddr, path::Path, str::FromStr};

use anyhow::{Result, bail};
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
}
