//! Config (`config.toml`) and runtime state (`state.toml`).
//!
//! `state.toml` holds allowlist entries added via `shuang allow` so that the
//! hand-written config (with its comments) is never rewritten by the tool.
//! The effective allowlist is the union of both.

use std::{
    fs,
    net::IpAddr,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    /// Applications to protect in `daemon` mode.
    pub apps: Vec<AppSpec>,
    pub allow: AllowConfig,
    pub ip_check: IpCheckConfig,
    pub timing: TimingConfig,
    /// Named allowlist profiles ("work", "personal"): merged on top of
    /// `allow` when active. Selected via `shuang profile <name>`.
    pub profiles: std::collections::BTreeMap<String, AllowConfig>,
    /// MAC addresses of trusted routers: on these networks protection is off
    /// (home/office), everywhere else it is on.
    pub trusted_networks: Vec<String>,
    /// Split-routing check (`shuang leaks`): asks these services' own edge
    /// where the request came from.
    pub route_check: RouteCheckConfig,
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(deny_unknown_fields, default)]
pub struct AppSpec {
    /// Human-readable name shown in events.
    pub name: String,
    /// Match patterns: a bare name matches the process file name, a pattern
    /// containing `/` matches the executable path substring, an `args:`
    /// prefix matches the command line substring.
    pub r#match: Vec<String>,
    /// Optional per-app allowlist merged on top of the global one (Claude
    /// only from NL, Cursor from anywhere in the default list, …).
    pub allow: Option<AllowConfig>,
}

impl Config {
    /// Configuration sanity warnings, printed at `run`/`daemon` start.
    /// Warnings never block the run — they explain surprising behavior.
    pub fn warnings(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.ip_check.ip_services.is_empty() {
            out.push(
                "ip_check.ip_services is empty: the external IP can never be confirmed \
                 (every verdict will fail closed)"
                    .to_string(),
            );
        } else if self.ip_check.min_agree > self.ip_check.ip_services.len() {
            out.push(format!(
                "ip_check.min_agree ({}) is higher than the number of ip_services ({}): \
                 the quorum can never be met",
                self.ip_check.min_agree,
                self.ip_check.ip_services.len()
            ));
        }
        if self.ip_check.ipv6_services.is_empty() {
            out.push(
                "ip_check.ipv6_services is empty: a direct IPv6 leak will not be detected"
                    .to_string(),
            );
        }
        if self.ip_check.timeout_secs > self.ip_check.interval_secs
            && !self.ip_check.ip_services.is_empty()
        {
            out.push(format!(
                "ip_check.timeout_secs ({}) >= interval_secs ({}): a slow service can \
                 delay every tick beyond the interval",
                self.ip_check.timeout_secs, self.ip_check.interval_secs
            ));
        }
        if !self.apps.is_empty() && self.timing.grace_secs == 0 {
            out.push(
                "timing.grace_secs is 0: apps are stopped after a single frozen tick — \
                 a one-second VPN blip kills them"
                    .to_string(),
            );
        }
        out
    }
}

#[derive(Debug, Deserialize, Clone, Default, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct AllowConfig {
    pub ips: Vec<IpAddr>,
    pub nets: Vec<IpNet>,
    /// Two-letter country codes (ISO 3166-1 alpha-2), uppercase.
    pub countries: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields, default)]
pub struct IpCheckConfig {
    /// URLs that answer with the caller's IPv4 address as plain text.
    pub ip_services: Vec<String>,
    /// URLs that answer with the caller's IPv6 address as plain text.
    pub ipv6_services: Vec<String>,
    /// URLs that answer with a JSON object carrying a `country` key.
    pub country_services: Vec<String>,
    /// How many services must name the same IPv4 address for the answer to
    /// count. Fewer agreeing answers means "unknown" — and unknown is never
    /// allowed.
    pub min_agree: usize,
    /// Seconds between IP checks while the command runs / the daemon watches.
    pub interval_secs: u64,
    /// Per-request timeout in seconds.
    pub timeout_secs: u64,
}

impl Default for IpCheckConfig {
    fn default() -> Self {
        Self {
            ip_services: [
                "https://api.ipify.org",
                "https://ipv4.icanhazip.com",
                "https://v4.ident.me",
                "https://checkip.amazonaws.com",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            ipv6_services: [
                "https://api6.ipify.org",
                "https://ipv6.icanhazip.com",
                "https://v6.ident.me",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
            country_services: vec!["https://api.country.is".to_string()],
            min_agree: 2,
            interval_secs: 5,
            timeout_secs: 5,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields, default)]
pub struct TimingConfig {
    /// How long a frozen tree waits for the allowed IP to come back before it
    /// is stopped.
    pub grace_secs: u64,
    /// How long the polite stop is awaited before a forced kill.
    pub close_secs: u64,
}

impl Default for TimingConfig {
    fn default() -> Self {
        Self {
            grace_secs: 20,
            close_secs: 5,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields, default)]
pub struct RouteCheckConfig {
    /// Services whose `/cdn-cgi/trace` is asked where the request came from.
    pub services: Vec<String>,
}

impl Default for RouteCheckConfig {
    fn default() -> Self {
        Self {
            services: [
                "claude.ai",
                "api.anthropic.com",
                "chatgpt.com",
                "api.openai.com",
                "www.perplexity.ai",
            ]
            .into_iter()
            .map(String::from)
            .collect(),
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct State {
    #[serde(flatten)]
    pub allow: AllowConfig,
    /// Active profile name (set by `shuang profile <name>`), or None.
    pub active_profile: Option<String>,
    /// Pids left frozen by the current/previous run (crash recovery).
    pub frozen: Vec<u32>,
    /// Panel-set overrides: applied on top of config.toml so the hand-written
    /// file is never rewritten.
    pub settings: SettingsOverride,
    /// Protected apps added via the panel (merged with config apps).
    pub apps: Vec<AppSpec>,
    /// Trusted gateway MACs added via the panel.
    pub trusted_networks: Vec<String>,
}

/// Per-setting overrides written by the panel; `None` = keep the config value.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct SettingsOverride {
    pub interval_secs: Option<u64>,
    pub grace_secs: Option<u64>,
    pub close_secs: Option<u64>,
    pub min_agree: Option<usize>,
    /// false disables desktop notifications for `daemon`.
    pub notify: Option<bool>,
}

/// Default config path: `$XDG_CONFIG_HOME/shuang/config.toml`, falling back to
/// `~/.config/shuang/config.toml`.
pub fn resolve_path(explicit: &Option<PathBuf>) -> PathBuf {
    explicit.clone().unwrap_or_else(|| {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(home_config)
            .unwrap_or_else(|| PathBuf::from(".config"));
        base.join("shuang").join("config.toml")
    })
}

fn home_config() -> Option<PathBuf> {
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config"))
}

/// Companion of a config file: same directory, `state.toml`.
pub fn state_path(config_path: &Path) -> PathBuf {
    config_path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join("state.toml")
}

impl Config {
    /// Apply `state.settings` on top of the config values (panel overrides).
    pub fn apply_overrides(&mut self, state: &State) {
        if let Some(v) = state.settings.interval_secs {
            self.ip_check.interval_secs = v;
        }
        if let Some(v) = state.settings.grace_secs {
            self.timing.grace_secs = v;
        }
        if let Some(v) = state.settings.close_secs {
            self.timing.close_secs = v;
        }
        if let Some(v) = state.settings.min_agree {
            self.ip_check.min_agree = v;
        }
        for mac in &state.trusted_networks {
            if !self.trusted_networks.contains(mac) {
                self.trusted_networks.push(mac.clone());
            }
        }
        for app in &state.apps {
            if !self.apps.iter().any(|a| a.name == app.name) {
                self.apps.push(app.clone());
            }
        }
    }
}

/// Load the config. A missing file is fine when the path came from the
/// default location (first run: everything falls back to `Config::default`,
/// so `check`/`run` work before the user ever writes a config). An explicitly
/// requested path that does not exist is an error — a typo in `--config`
/// must not silently run with defaults.
pub fn load(config_path: &Path, explicit: bool) -> Result<Config> {
    let raw = match fs::read_to_string(config_path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound && !explicit => {
            return Ok(Config::default());
        }
        Err(err) => {
            return Err(anyhow::Error::new(err)
                .context(format!("cannot read config {}", config_path.display())));
        }
    };
    let cfg: Config = toml::from_str(&raw)
        .with_context(|| format!("invalid config {}", config_path.display()))?;
    Ok(cfg)
}

pub fn load_state(config_path: &Path) -> State {
    let path = state_path(config_path);
    let Ok(raw) = fs::read_to_string(&path) else {
        return State::default();
    };
    toml::from_str(&raw).unwrap_or_default()
}

pub fn save_state(config_path: &Path, state: &State) -> Result<()> {
    let path = state_path(config_path);
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    }
    let raw = toml::to_string_pretty(state).context("cannot serialize state")?;
    fs::write(&path, raw).with_context(|| format!("cannot write {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_config_uses_defaults() {
        let cfg: Config = toml::from_str("").unwrap();
        assert!(cfg.apps.is_empty());
        assert_eq!(cfg.ip_check.min_agree, 2);
        assert_eq!(cfg.ip_check.interval_secs, 5);
        assert_eq!(cfg.timing.grace_secs, 20);
        assert!(cfg.ip_check.ip_services.len() >= 2);
    }

    #[test]
    fn parses_a_full_config() {
        let raw = r#"
[[apps]]
name = "claude-code"
match = ["claude", "args:claude"]

[allow]
ips = ["203.0.113.42"]
nets = ["185.12.40.0/24"]
countries = ["NL"]

[ip_check]
min_agree = 3
interval_secs = 2

[timing]
grace_secs = 10
close_secs = 3
"#;
        let cfg: Config = toml::from_str(raw).unwrap();
        assert_eq!(cfg.apps.len(), 1);
        assert_eq!(cfg.apps[0].r#match, ["claude", "args:claude"]);
        assert_eq!(cfg.allow.ips.len(), 1);
        assert_eq!(cfg.allow.nets.len(), 1);
        assert_eq!(cfg.allow.countries, ["NL"]);
        assert_eq!(cfg.ip_check.min_agree, 3);
        assert_eq!(cfg.ip_check.interval_secs, 2);
        assert_eq!(cfg.timing.grace_secs, 10);
        // Service lists keep their defaults: the snippet did not touch them.
        assert_eq!(cfg.ip_check.ip_services.len(), 4);
    }

    #[test]
    fn rejects_unknown_keys() {
        let raw = "[alllow]\nips = []\n";
        let err = toml::from_str::<Config>(raw).unwrap_err();
        assert!(err.to_string().contains("alllow"));
    }

    #[test]
    fn missing_default_config_falls_back_to_defaults() {
        // First run: no config file at the default location — work with defaults.
        let missing = Path::new("/nonexistent/shuang/config.toml");
        let cfg = load(missing, false).unwrap();
        assert_eq!(cfg.ip_check.min_agree, 2);
        assert!(cfg.allow.ips.is_empty());
    }

    #[test]
    fn missing_explicit_config_is_an_error() {
        // A typo in --config must not silently run with defaults.
        let missing = Path::new("/nonexistent/shuang/config.toml");
        assert!(load(missing, true).is_err());
    }

    #[test]
    fn state_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.toml");
        let mut state = State::default();
        state.allow.ips.push("203.0.113.9".parse().unwrap());
        state.allow.countries.push("NL".to_string());
        save_state(&cfg_path, &state).unwrap();
        let loaded = load_state(&cfg_path);
        assert_eq!(loaded.allow.ips, state.allow.ips);
        assert_eq!(loaded.allow.countries, ["NL"]);
    }
}
