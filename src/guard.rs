//! Freeze/grace/close decision state — pure time logic, no process I/O.
//!
//! Time is measured with the suspend-aware boot clock (`crate::mono`), not
//! `Instant`: a grace timer that stops while the laptop sleeps would unfreeze
//! hours later as "within 20s". Kept separate from `platform` so the state
//! machine itself is trivially testable: `run` and `daemon` execute the
//! decisions, `Guard` makes them.

use std::time::Duration;

use crate::mono;

/// What the supervisor should do this tick.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stage {
    /// IP went bad just now: suspend the tree.
    Freeze,
    /// Already frozen, still inside the grace period; `Duration` is how long
    /// the tree has been frozen (wall+suspend time).
    Frozen(Duration),
    /// Grace is over and the IP never came back: stop the tree.
    MustClose,
}

#[derive(Debug)]
pub struct Guard {
    frozen_since: Option<Duration>, // boot-clock timestamp
    grace: Duration,
}

impl Guard {
    pub fn new(grace: Duration) -> Self {
        Self {
            frozen_since: None,
            grace,
        }
    }

    /// Test constructor: pretend the freeze happened `ago` ago.
    #[cfg(test)]
    pub fn frozen_for(grace: Duration, ago: Duration) -> Self {
        Self {
            frozen_since: Some(mono::now() - ago),
            grace,
        }
    }

    /// The verdict turned good. Returns `true` when a frozen tree must be
    /// resumed (i.e. this call cleared the freeze).
    pub fn good(&mut self) -> bool {
        self.frozen_since.take().is_some()
    }

    /// The verdict turned bad. Never panics, never sleeps.
    pub fn bad(&mut self) -> Stage {
        match self.frozen_since {
            None => {
                self.frozen_since = Some(mono::now());
                Stage::Freeze
            }
            Some(since) => {
                let elapsed = mono::now().saturating_sub(since);
                if elapsed >= self.grace {
                    Stage::MustClose
                } else {
                    Stage::Frozen(elapsed)
                }
            }
        }
    }

    /// Test-only introspection.
    #[cfg(test)]
    pub fn is_frozen(&self) -> bool {
        self.frozen_since.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn freeze_then_resume_within_grace() {
        let mut guard = Guard::new(Duration::from_secs(20));
        assert!(!guard.is_frozen());
        assert_eq!(guard.bad(), Stage::Freeze);
        assert!(guard.is_frozen());
        assert!(matches!(guard.bad(), Stage::Frozen(_)));
        // Good verdict resumes.
        assert!(guard.good());
        assert!(!guard.is_frozen());
        // A second good verdict must not report a resume again.
        assert!(!guard.good());
    }

    #[test]
    fn zero_grace_closes_on_next_tick() {
        let mut guard = Guard::new(Duration::ZERO);
        assert_eq!(guard.bad(), Stage::Freeze);
        // Even with zero grace the close happens on the next tick, not the
        // same one — the freeze itself must always happen first.
        assert_eq!(guard.bad(), Stage::MustClose);
    }

    #[test]
    fn grace_expired_after_simulated_sleep() {
        // Frozen 30s ago (suspend included, thanks to the boot clock) with a
        // 20s grace: the next bad tick must close, not report Frozen.
        let mut guard = Guard::frozen_for(Duration::from_secs(20), Duration::from_secs(30));
        assert_eq!(guard.bad(), Stage::MustClose);
    }

    #[test]
    fn refreeze_after_close_cycle() {
        let mut guard = Guard::new(Duration::ZERO);
        guard.bad();
        guard.bad();
        // After a close the guard is reset by the caller via good()/new cycle;
        // calling good() clears the freeze bookkeeping.
        assert!(guard.good());
        assert_eq!(guard.bad(), Stage::Freeze);
    }
}
