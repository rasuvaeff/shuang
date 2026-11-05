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
mod doctor;
mod events;
mod fix;
mod guard;
mod ipcheck;
mod leaks;
mod mono;
mod net;
mod netwatch;
mod notify;
mod panel;
mod platform;
mod procs;
mod profile;
mod run;
mod stats;
mod supervisor;
mod tray;
mod trusted;
mod update;

use std::path::Path;
use std::process::ExitCode;

use clap::Parser;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = cli::Cli::parse();
    let path = config::resolve_path(&cli.config);
    let explicit = cli.config.is_some();

    // macOS: the winit event loop must own the main thread. For the daemon
    // with a tray we build the tray here, run the daemon on a worker, and
    // block in the loop; every other command takes the regular async path.
    #[cfg(target_os = "macos")]
    if let cli::Command::Daemon {
        no_tray: false,
        no_notify,
        no_panel,
    } = &cli.command
    {
        if let Some(main_tray) = tray::macos_main::build() {
            let tray_handle = tray::TrayHandle::from_main(&main_tray);
            let path = path.clone();
            let no_notify = *no_notify;
            let no_panel = *no_panel;
            std::thread::spawn(move || {
                let rt = tokio::runtime::Runtime::new().expect("tokio runtime");
                rt.block_on(async move {
                    if let Err(err) = daemon::run(
                        &path,
                        explicit,
                        false,
                        no_notify,
                        no_panel,
                        Some(tray_handle),
                    )
                    .await
                    {
                        eprintln!("Error: {err:#}");
                    }
                });
            });
            tray::macos_main::run(main_tray);
            return ExitCode::from(0);
        }
    }

    let code = match cli.command {
        cli::Command::Check { json } => check::run(&path, json, explicit).await,
        cli::Command::Allow { value } => allow::run(&path, &value),
        cli::Command::Deny { value } => match allow::remove(&path, &value) {
            Ok(true) => Ok(0),
            Ok(false) => {
                eprintln!("shuang: {value:?} is not in state.toml");
                Ok(1)
            }
            Err(err) => Err(err),
        },
        cli::Command::Run { command } => run::run(&path, command, explicit).await,
        cli::Command::Daemon {
            no_tray,
            no_notify,
            no_panel,
        } => daemon::run(&path, explicit, no_tray, no_notify, no_panel, None).await,
        cli::Command::Leaks => leaks::run(&path, explicit).await,
        cli::Command::Events { tail } => events_cmd(&path, tail),
        cli::Command::Profile { name } => profile::run(&path, &name),
        cli::Command::Stats { tail } => stats::run(&path, tail),
        cli::Command::Update => update::run().await,
        cli::Command::Doctor => doctor::run(&path, explicit).await,
        cli::Command::Fix { kind } => match fix::Kind::parse(&kind) {
            Some(kind) => {
                println!("{}", kind.apply().message());
                Ok(0)
            }
            None => Err(anyhow::anyhow!(
                "unknown fix {kind:?}: expected disable-ipv6, enable-ipv6, or dns-public"
            )),
        },
    };

    match code {
        Ok(code) => ExitCode::from(code),
        Err(err) => {
            eprintln!("Error: {err:#}");
            ExitCode::from(1)
        }
    }
}

fn events_cmd(path: &Path, tail: usize) -> Result<u8, anyhow::Error> {
    for line in events::read_tail(path, tail)? {
        println!("{line}");
    }
    Ok(0)
}
