//! `shuang profile` — show, select, or clear the active allowlist profile.
//!
//! Profiles live in the config (`[profiles.work] countries = ["NL"]`); the
//! *selection* lives in `state.toml` so switching never rewrites the config.

use std::path::Path;

use anyhow::{Context, Result, bail};

use crate::config;

pub fn run(config_path: &Path, name: &Option<String>) -> Result<u8> {
    let cfg = config::load(config_path, false)?;
    let mut state = config::load_state(config_path);

    match name {
        None => {
            let active = state.active_profile.as_deref().unwrap_or("none");
            if cfg.profiles.is_empty() {
                println!("No profiles configured — add [profiles.<name>] to config.toml");
            } else {
                println!("Profiles (active: {active}):");
                for (name, allow) in &cfg.profiles {
                    let mut parts = Vec::new();
                    if !allow.ips.is_empty() {
                        parts.push(format!("{} ip(s)", allow.ips.len()));
                    }
                    if !allow.nets.is_empty() {
                        parts.push(format!("{} net(s)", allow.nets.len()));
                    }
                    if !allow.countries.is_empty() {
                        parts.push(format!("countries {}", allow.countries.join(",")));
                    }
                    println!("  {name}: {}", parts.join(", "));
                }
            }
            Ok(0)
        }
        Some(name) if name == "none" => {
            state.active_profile = None;
            config::save_state(config_path, &state).context("cannot write state.toml")?;
            println!("Profile deactivated");
            Ok(0)
        }
        Some(name) => {
            if !cfg.profiles.contains_key(name) {
                bail!("profile {name:?} is not defined in config.toml ([profiles.{name}])");
            }
            state.active_profile = Some(name.clone());
            config::save_state(config_path, &state).context("cannot write state.toml")?;
            println!("Active profile: {name}");
            Ok(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selecting_an_undefined_profile_fails() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "").unwrap();
        assert!(run(&path, &Some("work".to_string())).is_err());
    }

    #[test]
    fn select_none_deactivates() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        std::fs::write(&path, "[profiles.work]\ncountries = [\"NL\"]\n").unwrap();
        run(&path, &Some("work".to_string())).unwrap();
        let state = config::load_state(&path);
        assert_eq!(state.active_profile.as_deref(), Some("work"));
        run(&path, &Some("none".to_string())).unwrap();
        let state = config::load_state(&path);
        assert_eq!(state.active_profile, None);
    }
}
