//! CLI flags. Dispatch happens in `main.rs`; modes live in `check`, `allow`,
//! `run`, and `daemon`.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "shuang",
    version,
    about = "Freeze apps when the VPN drops: a per-application kill switch that suspends instead of killing",
    after_help = "See README.md for the config file format and exit codes."
)]
pub struct Cli {
    /// Path to the config file (default: ~/.config/shuang/config.toml).
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Check the current external IP against the allowlist and exit.
    Check {
        /// Print a JSON document instead of human-readable text.
        #[arg(long)]
        json: bool,
    },
    /// Allow an IP, subnet (CIDR), or country code (e.g. NL) persistently.
    Allow {
        /// An IP address ("203.0.113.4"), a subnet ("203.0.113.0/24"), or a
        /// two-letter country code ("NL").
        value: String,
    },
    /// Remove an allowlist entry from state.toml (same as the panel's ×).
    Deny {
        /// The exact IP, subnet, or country code to remove.
        value: String,
    },
    /// Run a command under the kill switch.
    ///
    /// The command and its whole process tree are frozen while the external IP
    /// is not allowed, resumed when it is, and stopped after the grace period.
    /// Exit codes: 0 — command finished; 1 — error; 69 — IP not allowed at
    /// start; 75 — stopped because the allowed IP never came back.
    Run {
        /// The command to run, after `--`.
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
    /// Watch the configured apps: freeze while the IP is not allowed, close
    /// after the grace period.
    Daemon {
        /// Run without the tray icon (servers, SSH sessions).
        #[arg(long)]
        no_tray: bool,
        /// Skip desktop notifications (with --no-tray for fully headless runs).
        #[arg(long)]
        no_notify: bool,
        /// Do not serve the local settings panel.
        #[arg(long)]
        no_panel: bool,
    },
    /// One-button leak report: every IP service individually, the AI services'
    /// own edge (/cdn-cgi/trace), timezone, proxy environment, gateway MAC.
    /// Exit 0 clean, 4 leaks found.
    Leaks,
    /// Show the last events from history.log.
    Events {
        /// How many events to show (default 20).
        #[arg(long, default_value_t = 20)]
        tail: usize,
    },
    /// Show or select the active allowlist profile (from [profiles] in the
    /// config). `shuang profile work` activates it, `shuang profile` lists.
    Profile {
        /// Profile name to activate; omit to list. Use "none" to deactivate.
        name: Option<String>,
    },
    /// VPN health from history.log: freeze/close counts and average freeze
    /// duration over the last 7 days.
    Stats {
        /// How many history lines to consider (default: all).
        #[arg(long)]
        tail: usize,
    },
    /// Self-update: download the latest release binary for this platform,
    /// verify the published .sha256, and replace this executable.
    Update,
    /// Environment diagnostics: config, IP quorum, country, timezone,
    /// gateway MAC, D-Bus. Exit 0 healthy, 4 problems found.
    Doctor,
    /// Close a leak where the OS allows it: disable-ipv6, enable-ipv6,
    /// dns-public. Prints the applied change or the exact sudo command.
    Fix {
        /// Which fix to apply: disable-ipv6, enable-ipv6, dns-public.
        kind: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_requires_a_command() {
        let cli = Cli::try_parse_from(["shuang", "run", "--", "sleep", "1"]).expect("parses");
        assert!(matches!(cli.command, Command::Run { ref command } if command == &["sleep", "1"]));
    }
}
