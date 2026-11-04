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
    Daemon,
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
