//! Shared freeze bookkeeping for `run` and `daemon`.
//!
//! Three safety properties live here:
//! - **Clean exit:** when shuang gets Ctrl+C/SIGTERM it resumes everything it
//!   froze before exiting — a kill switch must never leave apps frozen behind.
//! - **Crash recovery:** the frozen pid set is persisted into `state.toml` on
//!   every change; the next run resumes those pids ("frozen orphans" from a
//!   killed shuang).
//! - **Ownership:** every frozen pid remembers which app it belongs to, so a
//!   per-app MustClose stops only that app's tree.

use std::{
    collections::{HashMap, HashSet},
    path::Path,
    time::Duration,
};

use crate::{config, events, platform};
use anyhow::Result;

pub struct Frozen {
    pids: HashSet<u32>,
    owners: HashMap<u32, String>,
}

impl Frozen {
    pub fn new() -> Self {
        Self {
            pids: HashSet::new(),
            owners: HashMap::new(),
        }
    }

    /// Resume pid sets left frozen by a previous (crashed or killed) run and
    /// clear them from the state. Called at mode start, before any freezing.
    pub fn recover(config_path: &Path) -> Self {
        let mut state = config::load_state(config_path);
        if state.frozen.is_empty() {
            return Self::new();
        }
        let mut resumed = 0usize;
        for pid in std::mem::take(&mut state.frozen) {
            if platform::resume(pid).is_ok() {
                resumed += 1;
            }
        }
        if config::save_state(config_path, &state).is_ok() {
            eprintln!("shuang: recovered {resumed} process(es) left frozen by a previous run");
            let _ = events::append_line(config_path, "recover", &format!("{resumed} pid(s)"));
        }
        Self::new()
    }

    /// Suspend every pid of `tree` that is not frozen yet. Returns how many
    /// new pids were frozen.
    pub fn freeze_tree(&mut self, tree: &[u32], owner: &str) -> usize {
        let mut added = 0;
        for pid in tree {
            if self.pids.contains(pid) {
                continue;
            }
            if platform::suspend(*pid).is_ok() {
                self.pids.insert(*pid);
                self.owners.insert(*pid, owner.to_string());
                added += 1;
            }
        }
        added
    }

    pub fn len(&self) -> usize {
        self.pids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pids.is_empty()
    }

    /// Resume everything; used on recovery and clean exit.
    pub fn resume_all(&mut self) {
        for pid in self.pids.drain() {
            // The process may be gone already: a resume failure is not an error.
            let _ = platform::resume(pid);
        }
        self.owners.clear();
    }

    /// Take out and return the pids belonging to `owner` (for per-app close).
    pub fn take_owner(&mut self, owner: &str) -> Vec<u32> {
        let taken: Vec<u32> = self
            .pids
            .iter()
            .copied()
            .filter(|pid| self.owners.get(pid).is_some_and(|o| o == owner))
            .collect();
        for pid in &taken {
            self.pids.remove(pid);
            self.owners.remove(pid);
        }
        taken
    }

    /// Polite stop then forced kill of exactly these pids.
    pub fn stop_pids(&mut self, pids: Vec<u32>, close_timeout: Duration) {
        for pid in &pids {
            let _ = platform::terminate(*pid);
        }
        std::thread::sleep(close_timeout);
        for pid in &pids {
            let _ = platform::kill(*pid);
        }
    }

    /// Persist the current frozen set (crash recovery). Errors are logged by
    /// the caller, never fatal.
    pub fn persist(&self, config_path: &Path) -> Result<()> {
        let mut state = config::load_state(config_path);
        let mut frozen: Vec<u32> = self.pids.iter().copied().collect();
        frozen.sort_unstable();
        if frozen == state.frozen {
            return Ok(()); // nothing changed, avoid the rewrite
        }
        state.frozen = frozen;
        config::save_state(config_path, &state)
    }

    /// Clear the persisted set (after resume_all / take on empty).
    pub fn persist_cleared(config_path: &Path) -> Result<()> {
        let mut state = config::load_state(config_path);
        if state.frozen.is_empty() {
            return Ok(());
        }
        state.frozen = Vec::new();
        config::save_state(config_path, &state)
    }
}

/// Ctrl+C + SIGTERM (where it exists) with one async receiver.
pub struct Shutdown {
    #[cfg(unix)]
    signals: [tokio::signal::unix::Signal; 2], // SIGINT, SIGTERM
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
            Ok(Self {
                signals: [int, term],
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
            let [int, term] = &mut self.signals;
            tokio::select! {
                _ = int.recv() => {},
                _ = term.recv() => {},
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (&mut self.ctrl_c).await;
        }
    }
}
