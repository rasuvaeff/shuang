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
    /// When stability gating: the boot-clock time the verdict first turned
    /// good again (the resume waits for it to hold).
    stable_since: Option<Duration>,
    #[cfg(test)]
    clock: fn() -> Duration,
}

impl Guard {
    pub fn new(grace: Duration) -> Self {
        Self {
            frozen_since: None,
            grace,
            stable_since: None,
            #[cfg(test)]
            clock: mono::now,
        }
    }

    /// Test helper: pretend the freeze happened `ago` ago (on the injected
    /// clock this is exact, unlike rewinding the real one).
    #[cfg(test)]
    pub fn frozen_for(grace: Duration, ago: Duration) -> Self {
        Self {
            frozen_since: Some(ago), // timestamps before the freeze; bad() computes now - since
            grace,
            stable_since: None,
            clock: || Duration::from_secs(1_000),
        }
    }

    #[cfg(test)]
    fn now(&self) -> Duration {
        (self.clock)()
    }

    #[cfg(not(test))]
    fn now(&self) -> Duration {
        mono::now()
    }

    /// The verdict turned good. Returns `true` when a frozen tree must be
    /// resumed (i.e. this call cleared the freeze).
    pub fn good(&mut self) -> bool {
        self.stable_since = None;
        self.frozen_since.take().is_some()
    }

    /// Stability-gated resume: `true` only when a freeze is cleared AND the
    /// verdict has stayed good for `stability` (measured from the first good
    /// tick after the freeze). A bad tick in between resets the gate — a
    /// flapping exit never resumes the tree.
    pub fn good_stable(&mut self, stability: Duration) -> bool {
        if self.frozen_since.is_none() {
            return false; // nothing frozen, nothing to resume
        }
        if stability.is_zero() {
            return self.good();
        }
        let now = self.now();
        match self.stable_since {
            None => {
                self.stable_since = Some(now);
                false
            }
            Some(since) if now.saturating_sub(since) >= stability => self.good(),
            Some(_) => false,
        }
    }

    /// The verdict turned bad. Never panics, never sleeps.
    pub fn bad(&mut self) -> Stage {
        match self.frozen_since {
            None => {
                self.frozen_since = Some(self.now());
                Stage::Freeze
            }
            Some(since) => {
                self.stable_since = None;
                let elapsed = self.now().saturating_sub(since);
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
        // Frozen 30s ago (timestamp 30, injected clock now at 1000 → elapsed
        // 970s) with a 20s grace: the next bad tick must close, not Freeze.
        let mut guard = Guard::frozen_for(Duration::from_secs(20), Duration::from_secs(30));
        assert_eq!(guard.bad(), Stage::MustClose);
        // And within grace it reports Frozen with the elapsed time.
        let mut guard = Guard::frozen_for(Duration::from_secs(2000), Duration::from_secs(30));
        assert!(
            matches!(guard.bad(), Stage::Frozen(elapsed) if elapsed > Duration::from_secs(960))
        );
    }

    #[test]
    fn stability_gate_waits_and_resets() {
        let mut guard = Guard::new(Duration::from_secs(1000));
        guard.bad();
        // First good tick opens the gate, does not resume.
        assert!(!guard.good_stable(Duration::from_secs(5)));
        // Inject the passage of time by rewinding stable_since.
        let past = mono::now().saturating_sub(Duration::from_secs(10));
        guard.stable_since = Some(past);
        assert!(guard.good_stable(Duration::from_secs(5)));
        // Not frozen anymore → good_stable stays false.
        assert!(!guard.good_stable(Duration::from_secs(5)));
    }

    #[test]
    fn stability_gate_resets_on_a_flap() {
        let mut guard = Guard::new(Duration::from_secs(1000));
        guard.bad();
        assert!(!guard.good_stable(Duration::from_secs(5)));
        let past = mono::now().saturating_sub(Duration::from_secs(10));
        guard.stable_since = Some(past);
        // A bad tick before the gate elapses resets it.
        let _ = guard.bad();
        assert!(!guard.good_stable(Duration::from_secs(5)));
        assert!(!guard.good_stable(Duration::from_secs(5)));
    }

    #[test]
    fn zero_stability_is_immediate() {
        let mut guard = Guard::new(Duration::from_secs(1000));
        guard.bad();
        assert!(guard.good_stable(Duration::ZERO));
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
