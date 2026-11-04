//! A monotonic clock that keeps ticking through system suspend.
//!
//! `std::time::Instant` is `CLOCK_MONOTONIC` on Linux, which stops while the
//! machine sleeps. Our whole point is surviving "lid closed, lid opened, VPN
//! changed" — so the grace timer must use `CLOCK_BOOTTIME` (suspend-aware).
//! Non-Linux platforms fall back to a process-wide `Instant` base (macOS and
//! Windows monotonic clocks already include sleep).

use std::sync::OnceLock;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
pub fn now() -> Duration {
    use nix::time::{ClockId, clock_gettime};
    clock_gettime(ClockId::CLOCK_BOOTTIME)
        .map(|ts| Duration::new(ts.tv_sec() as u64, ts.tv_nsec() as u32))
        .unwrap_or_else(|_| fallback())
}

#[cfg(not(target_os = "linux"))]
pub fn now() -> Duration {
    fallback()
}

fn fallback() -> Duration {
    static BASE: OnceLock<Instant> = OnceLock::new();
    BASE.get_or_init(Instant::now).elapsed()
}
