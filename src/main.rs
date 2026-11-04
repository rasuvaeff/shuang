//! shuang — freeze apps when the VPN drops.
//!
//! Per-application kill switch: instead of cutting the whole network it
//! suspends (`SIGSTOP` / `NtSuspendProcess`) the process trees of the chosen
//! applications while the external IP is not on the allowlist, and resumes
//! them when the correct IP is back.

#![deny(unsafe_code)]

mod allow;
mod check;
mod cli;
mod config;
mod daemon;
mod guard;
mod ipcheck;
mod net;
mod platform;
mod procs;
mod run;

use std::process::ExitCode;

use clap::Parser;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = cli::Cli::parse();
    let path = config::resolve_path(&cli.config);
    let explicit = cli.config.is_some();

    let code = match cli.command {
        cli::Command::Check { json } => check::run(&path, json, explicit).await,
        cli::Command::Allow { value } => allow::run(&path, &value),
        cli::Command::Run { command } => run::run(&path, command, explicit).await,
        cli::Command::Daemon => daemon::run(&path, explicit).await,
    };

    match code {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("Error: {err:#}");
            ExitCode::from(1)
        }
    }
}
