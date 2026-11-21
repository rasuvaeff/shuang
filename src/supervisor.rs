//! Serialize claims on each process across supervisors. A process may resume
//! only when the last claim on that process is released.

use std::{
    collections::HashSet,
    fs::{self, File},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sysinfo::{Pid, ProcessStatus, ProcessesToUpdate, System};

use crate::{config, platform};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
struct Identity {
    pid: u32,
    started_at: u64,
}

impl Identity {
    fn lookup(system: &System, pid: u32) -> Option<Self> {
        let process = system.process(Pid::from_u32(pid))?;
        if matches!(
            process.status(),
            ProcessStatus::Zombie | ProcessStatus::Dead
        ) {
            return None;
        }
        Some(Self {
            pid,
            started_at: process.start_time(),
        })
    }

    fn alive(self, system: &System) -> bool {
        Self::lookup(system, self.pid) == Some(self)
    }
}

#[derive(Serialize, Deserialize)]
struct Claim {
    target: Identity,
    supervisor: Identity,
    owner: String,
    scope: String,
}

#[derive(Default, Serialize, Deserialize)]
struct Journal {
    boot: Option<String>,
    claims: Vec<Claim>,
}

pub struct Frozen {
    dir: PathBuf,
    supervisor: Identity,
    count: usize,
}

impl Frozen {
    pub fn new() -> Result<Self> {
        let system = System::new_all();
        let supervisor = Identity::lookup(&system, std::process::id())
            .context("current process is missing from the process table")?;
        #[cfg(unix)]
        let dir = {
            use std::os::unix::fs::{DirBuilderExt, MetadataExt};

            let pid = Pid::from_u32(supervisor.pid);
            let uid = **system
                .process(pid)
                .and_then(sysinfo::Process::effective_user_id)
                .context("cannot identify the current user")?;
            let dir = PathBuf::from(format!("/tmp/shuang-freeze-{uid}"));
            match fs::DirBuilder::new().mode(0o700).create(&dir) {
                Ok(()) => {}
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(err) => return Err(err).context("cannot create freeze journal directory"),
            }
            let meta = fs::symlink_metadata(&dir)?;
            anyhow::ensure!(
                meta.is_dir() && meta.uid() == uid && meta.mode() & 0o077 == 0,
                "unsafe freeze journal directory: {}",
                dir.display()
            );
            dir
        };
        #[cfg(windows)]
        let dir = {
            let base = std::env::var_os("LOCALAPPDATA").context("LOCALAPPDATA is missing")?;
            let dir = PathBuf::from(base).join("shuang");
            fs::create_dir_all(&dir)?;
            dir
        };
        let frozen = Self {
            dir,
            supervisor,
            count: 0,
        };
        frozen.open_journal()?;
        Ok(frozen)
    }

    pub fn scope(config_path: &Path, policy: impl std::fmt::Debug) -> Result<String> {
        // Hash the policy so credentials from proxy URLs do not enter the journal.
        let path = match config_path.canonicalize() {
            Ok(path) => path,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                std::path::absolute(config_path)?
            }
            Err(err) => return Err(err).context("cannot resolve config path for freeze recovery"),
        };
        Ok(Sha256::digest(format!("v1:{path:?}:{policy:?}"))
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect())
    }

    pub fn warn_legacy(state: &config::State) {
        if !state.frozen.is_empty() {
            eprintln!(
                "shuang: state.toml contains old freeze records without a recoverable policy. Inspect the PIDs manually."
            );
        }
    }

    fn open_journal(&self) -> Result<(File, Journal)> {
        let lock = config::lock_file(&self.dir.join("frozen.toml.lock"))?;
        let mut journal: Journal = match fs::read_to_string(self.dir.join("frozen.toml")) {
            Ok(raw) => toml::from_str(&raw).context("cannot read freeze journal")?,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Journal::default(),
            Err(err) => return Err(err).context("cannot open freeze journal"),
        };
        // Linux btime and Windows System::boot_time() can shift when the
        // wall clock is corrected. Where available, use the kernel's boot ID.
        // Other platforms rely on the process identities in each claim.
        #[cfg(target_os = "linux")]
        let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id")
            .ok()
            .map(|id| id.trim().to_owned());
        #[cfg(not(target_os = "linux"))]
        let boot = None;
        if boot.is_some() && journal.boot != boot {
            journal = Journal {
                boot,
                claims: Vec::new(),
            };
        }
        Ok((lock, journal))
    }

    fn save(&mut self, journal: &Journal) -> Result<()> {
        config::write_atomic(&self.dir.join("frozen.toml"), &toml::to_string(journal)?)?;
        self.count = journal
            .claims
            .iter()
            .filter(|claim| claim.supervisor == self.supervisor)
            .map(|claim| claim.target)
            .collect::<HashSet<_>>()
            .len();
        Ok(())
    }

    pub fn freeze_tree(
        &mut self,
        tree: &[u32],
        owner: &str,
        scope: &str,
        system: &System,
    ) -> Result<()> {
        let (_lock, mut journal) = self.open_journal()?;
        let mut fresh = Vec::new();
        for target in tree.iter().filter_map(|pid| Identity::lookup(system, *pid)) {
            if target == self.supervisor
                || journal.claims.iter().any(|claim| {
                    claim.target == target
                        && claim.supervisor == self.supervisor
                        && claim.owner == owner
                })
            {
                continue;
            }
            let first = !journal.claims.iter().any(|claim| claim.target == target);
            journal.claims.push(Claim {
                target,
                supervisor: self.supervisor,
                owner: owner.to_string(),
                scope: scope.to_string(),
            });
            fresh.push((target, first));
        }
        if fresh.is_empty() {
            return Ok(());
        }
        // Record every new target before sending signals, including processes
        // discovered on later ticks. Hold the lock through both operations.
        self.save(&journal)?;
        let system = process_snapshot(fresh.iter().map(|(target, _)| target.pid));
        let mut failed = false;
        for (target, first) in fresh {
            // SIGSTOP is idempotent. Windows suspend is counted and must only
            // happen once even when multiple supervisors claim the same tree.
            if !target.alive(&system)
                || ((first || cfg!(unix)) && platform::suspend(target.pid).is_err())
            {
                failed = true;
                journal.claims.retain(|claim| {
                    !(claim.target == target
                        && claim.supervisor == self.supervisor
                        && claim.owner == owner)
                });
                eprintln!("shuang: could not suspend PID {}", target.pid);
            }
        }
        if failed {
            self.save(&journal)?;
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn resume_all(&mut self) -> Result<usize> {
        self.release(None, None, false)
    }

    pub fn resume_owner(&mut self, owner: &str, recovery_scope: Option<&str>) -> Result<usize> {
        self.release(Some(owner), recovery_scope, false)
    }

    pub fn kill_owner(&mut self, owner: &str) -> Result<usize> {
        self.release(Some(owner), None, true)
    }

    fn release(
        &mut self,
        owner: Option<&str>,
        recovery_scope: Option<&str>,
        kill: bool,
    ) -> Result<usize> {
        let (_lock, mut journal) = self.open_journal()?;
        if journal.claims.is_empty() {
            self.count = 0;
            return Ok(0);
        }
        let system = process_snapshot(
            journal
                .claims
                .iter()
                .flat_map(|claim| [claim.target.pid, claim.supervisor.pid]),
        );
        let supervisor = self.supervisor;
        let selected = |claim: &Claim| {
            owner.is_none_or(|owner| claim.owner == owner)
                && (claim.supervisor == supervisor
                    || (recovery_scope == Some(claim.scope.as_str())
                        && !claim.supervisor.alive(&system)))
        };
        let mut retained = HashSet::new();
        let mut released = HashSet::new();
        for claim in &journal.claims {
            if selected(claim) {
                released.insert(claim.target);
            } else {
                retained.insert(claim.target);
            }
        }
        let mut signalled = 0;
        released.retain(|target| {
            if !target.alive(&system) || (!kill && retained.contains(target)) {
                return true;
            }
            let result = if kill {
                // A frozen process must never execute a shutdown handler on a
                // denied network. SIGKILL also works on stopped Unix tasks.
                platform::kill(target.pid)
            } else {
                platform::resume(target.pid)
            };
            match result {
                Ok(()) => {
                    signalled += 1;
                    true
                }
                Err(err) => {
                    eprintln!("shuang: cannot signal PID {}: {err:#}", target.pid);
                    false
                }
            }
        });
        let before = journal.claims.len();
        journal.claims.retain(|claim| {
            claim.target.alive(&system)
                && !(released.contains(&claim.target) && (kill || selected(claim)))
        });
        if journal.claims.len() != before {
            self.save(&journal)?;
        } else {
            // Another supervisor can have killed the last process we claimed.
            self.count = journal
                .claims
                .iter()
                .filter(|claim| claim.supervisor == supervisor)
                .map(|claim| claim.target)
                .collect::<HashSet<_>>()
                .len();
        }
        Ok(signalled)
    }
}
fn process_snapshot(pids: impl Iterator<Item = u32>) -> System {
    let mut pids: Vec<_> = pids.map(Pid::from_u32).collect();
    pids.sort_unstable();
    pids.dedup();
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::Some(&pids), true);
    system
}

/// Ctrl+C + SIGTERM (where it exists) with one async receiver.
pub struct Shutdown {
    #[cfg(unix)]
    signals: [tokio::signal::unix::Signal; 3], // SIGINT, SIGTERM, SIGHUP
    #[cfg(not(unix))]
    ctrl_c: std::pin::Pin<Box<dyn std::future::Future<Output = std::io::Result<()>> + Send>>,
}

impl Shutdown {
    pub fn new() -> Result<Self> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let int = signal(SignalKind::interrupt())?;
            let term = signal(SignalKind::terminate())?;
            let hup = signal(SignalKind::hangup())?;
            Ok(Self {
                signals: [int, term, hup],
            })
        }
        #[cfg(not(unix))]
        Ok(Self {
            ctrl_c: Box::pin(tokio::signal::ctrl_c()),
        })
    }

    /// Resolves when a shutdown signal arrived.
    pub async fn recv(&mut self) {
        #[cfg(unix)]
        {
            let [int, term, hup] = &mut self.signals;
            tokio::select! {
                _ = int.recv() => {},
                _ = term.recv() => {},
                _ = hup.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (&mut self.ctrl_c).await;
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::{
        process::{Child, Command, Stdio},
        thread,
        time::{Duration, Instant},
    };

    struct Target(Child);

    impl Target {
        fn spawn() -> Self {
            Self(Command::new("sleep").arg("30").spawn().unwrap())
        }

        fn identity(&self) -> Identity {
            let pid = self.0.id();
            Identity::lookup(&process_snapshot([pid].into_iter()), pid).unwrap()
        }

        fn wait_stopped(&self, stopped: bool) {
            let started = Instant::now();
            loop {
                let status = fs::read_to_string(format!("/proc/{}/status", self.0.id())).unwrap();
                if status
                    .lines()
                    .any(|line| line.starts_with("State:") && line.contains('T'))
                    == stopped
                {
                    return;
                }
                assert!(started.elapsed() < Duration::from_secs(2));
                thread::sleep(Duration::from_millis(5));
            }
        }
    }

    impl Drop for Target {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn supervisor(dir: &Path, pid: u32) -> Frozen {
        Frozen {
            dir: dir.to_path_buf(),
            supervisor: Identity::lookup(&process_snapshot([pid].into_iter()), pid).unwrap(),
            count: 0,
        }
    }

    #[test]
    fn shared_target_waits_for_both_supervisors_to_release() {
        let dir = tempfile::tempdir().unwrap();
        let second_instance = Target::spawn();
        let target = Target::spawn();
        let pid = target.0.id();
        let system = process_snapshot([pid].into_iter());
        let mut first = supervisor(dir.path(), std::process::id());
        let mut second = supervisor(dir.path(), second_instance.0.id());
        first
            .freeze_tree(&[pid], "app", "policy-a", &system)
            .unwrap();
        second
            .freeze_tree(&[pid], "app", "policy-b", &system)
            .unwrap();

        assert_eq!(first.resume_all().unwrap(), 0);
        target.wait_stopped(true);
        assert_eq!(second.resume_all().unwrap(), 1);
        target.wait_stopped(false);
    }

    #[test]
    fn orphan_recovery_matches_policy_and_journals_late_arrivals() {
        let dir = tempfile::tempdir().unwrap();
        let mut crashed = Target::spawn();
        let first = Target::spawn();
        let later = Target::spawn();
        let mut old = supervisor(dir.path(), crashed.0.id());
        let mut new = supervisor(dir.path(), std::process::id());
        let system = process_snapshot([first.0.id(), later.0.id()].into_iter());
        old.freeze_tree(&[first.0.id()], "app", "policy-a", &system)
            .unwrap();
        old.freeze_tree(&[later.0.id()], "app", "policy-a", &system)
            .unwrap();
        let (_lock, journal) = old.open_journal().unwrap();
        assert_eq!(journal.claims.len(), 2);
        assert_eq!(journal.claims[1].target, later.identity());
        drop(_lock);

        assert_eq!(new.resume_owner("app", Some("policy-a")).unwrap(), 0);
        crashed.0.kill().unwrap();
        crashed.0.wait().unwrap();
        assert_eq!(new.resume_owner("app", Some("policy-b")).unwrap(), 0);
        first.wait_stopped(true);
        later.wait_stopped(true);
        assert_eq!(new.resume_owner("app", Some("policy-a")).unwrap(), 2);
        first.wait_stopped(false);
        later.wait_stopped(false);
    }

    #[test]
    fn forced_close_kills_without_running_the_term_handler() {
        use std::io::{BufRead, BufReader};
        use std::os::unix::process::ExitStatusExt;

        let dir = tempfile::tempdir().unwrap();
        let mut target = Target(
            Command::new("sh")
                .args(["-c", "trap 'exit 42' TERM; echo ready; while :; do :; done"])
                .stdout(Stdio::piped())
                .spawn()
                .unwrap(),
        );
        let mut ready = String::new();
        BufReader::new(target.0.stdout.take().unwrap())
            .read_line(&mut ready)
            .unwrap();
        assert_eq!(ready.trim(), "ready");

        let pid = target.0.id();
        let mut frozen = supervisor(dir.path(), std::process::id());
        let system = process_snapshot([pid].into_iter());
        frozen
            .freeze_tree(&[pid], "app", "policy-a", &system)
            .unwrap();
        target.wait_stopped(true);

        assert_eq!(frozen.kill_owner("app").unwrap(), 1);
        assert_eq!(target.0.wait().unwrap().signal(), Some(9));
    }
}
