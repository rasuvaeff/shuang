//! Desktop notifications with anti-noise semantics (Kordon-style).
//!
//! Rules:
//! - a freeze does NOT notify immediately — short blips are not worth a popup;
//! - a resume after less than `BLINK_MAX` (30s) sends ONE low-urgency
//!   notification ("VPN blinked for 8s");
//! - a freeze that lasts longer than `ALERT_AFTER` (60s) sends one
//!   normal-urgency notification ("still frozen, Ns");
//! - every notification kind fires at most once per freeze episode.
//!
//! The actual desktop call is injected as a sink: tests collect strings,
//! production uses `notify_rust`. A failing desktop call is ignored —
//! notifications are sugar, never load-bearing.

use std::time::{Duration, Instant};

pub const BLINK_MAX: Duration = Duration::from_secs(30);
pub const ALERT_AFTER: Duration = Duration::from_secs(60);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Urgency {
    Low,
    Normal,
}

/// Notification sink: (summary, body, urgency).
pub type Sink = Box<dyn FnMut(&str, &str, Urgency) + Send>;

pub struct Notifier {
    sink: Sink,
    enabled: bool,
    frozen_since: Option<Instant>,
    long_alert_sent: bool,
}

impl Notifier {
    pub fn desktop(enabled: bool) -> Self {
        #[cfg(unix)]
        {
            // notify-rust BLOCKS on D-Bus and panics when called from inside
            // the tokio runtime ("Cannot start a runtime from within a
            // runtime" — v0.3.0 crash-looped on this, 46 systemd restarts).
            // A dedicated worker thread owns every desktop call.
            let (tx, rx) = std::sync::mpsc::channel::<(String, String)>();
            std::thread::spawn(move || {
                while let Ok((summary, body)) = rx.recv() {
                    let mut n = notify_rust::Notification::new();
                    n.summary(&summary).body(&body);
                    let _ = n.show();
                }
            });
            Self::new(
                Box::new(move |summary, body, _urgency| {
                    // A full channel means the desktop is unresponsive: drop
                    // the notification rather than block (or crash) the daemon.
                    let _ = tx.send((summary.to_string(), body.to_string()));
                }),
                enabled,
            )
        }
        // Windows toasts land with the Windows tray polish; until then the
        // sink is a silent no-op (the state machine and tests still run).
        #[cfg(not(unix))]
        {
            Self::new(Box::new(|_, _, _| {}), enabled)
        }
    }

    pub fn new(sink: Sink, enabled: bool) -> Self {
        Self {
            sink,
            enabled,
            frozen_since: None,
            long_alert_sent: false,
        }
    }

    /// A freeze episode started. No notification yet (anti-noise).
    pub fn freeze_started(&mut self, reason: &str) {
        if self.frozen_since.is_none() {
            self.frozen_since = Some(Instant::now());
            self.long_alert_sent = false;
            let _ = reason; // kept for the long alert below
        }
    }

    /// Call every tick while frozen: after `ALERT_AFTER` sends one alert.
    pub fn still_frozen(&mut self, reason: &str) {
        let Some(since) = self.frozen_since else {
            return;
        };
        if !self.long_alert_sent && since.elapsed() >= ALERT_AFTER {
            self.long_alert_sent = true;
            self.send(
                "shuang: still frozen",
                &format!(
                    "{} — {}s without the allowed IP",
                    reason,
                    since.elapsed().as_secs()
                ),
                Urgency::Normal,
            );
        }
    }

    /// The freeze episode ended: one notification summarizing it.
    pub fn resumed(&mut self) {
        if let Some(since) = self.frozen_since.take() {
            let elapsed = since.elapsed();
            if elapsed <= BLINK_MAX {
                self.send(
                    "shuang: VPN blinked",
                    &format!("frozen for {}s, then recovered", elapsed.as_secs()),
                    Urgency::Low,
                );
            } else if !self.long_alert_sent {
                // Long freeze we never alerted about (user was away): tell now.
                self.send(
                    "shuang: recovered",
                    &format!("frozen for {}s, now allowed again", elapsed.as_secs()),
                    Urgency::Normal,
                );
            } else {
                self.send(
                    "shuang: recovered",
                    &format!("after {}s the allowed IP is back", elapsed.as_secs()),
                    Urgency::Normal,
                );
            }
        }
    }

    fn send(&mut self, summary: &str, body: &str, urgency: Urgency) {
        if self.enabled {
            (self.sink)(summary, body, urgency);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    fn collector() -> (Arc<Mutex<Vec<String>>>, Sink) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let sink_log = Arc::clone(&log);
        (
            log,
            Box::new(move |s, b, _u| {
                sink_log.lock().unwrap().push(format!("{s}: {b}"));
            }),
        )
    }

    #[test]
    fn short_blink_is_one_quiet_notification() {
        let (log, sink) = collector();
        let mut n = Notifier::new(sink, true);
        n.freeze_started("IP changed");
        n.still_frozen("IP changed"); // < 60s: no alert yet
        n.resumed();
        let sent = log.lock().unwrap().clone();
        assert_eq!(sent.len(), 1, "exactly one notification: {sent:?}");
        assert!(sent[0].contains("blinked"), "{sent:?}");
    }

    #[test]
    fn long_freeze_alerts_once_then_reports_recovery() {
        let (log, sink) = collector();
        let mut n = Notifier::new(sink, true);
        n.freeze_started("no quorum");
        // Simulate the passage of ALERT_AFTER by rewinding the clock:
        // freeze, then force the long-elapsed branch.
        n.frozen_since = Some(Instant::now() - Duration::from_secs(90));
        n.still_frozen("no quorum");
        n.frozen_since = Some(Instant::now() - Duration::from_secs(120));
        n.resumed();
        let sent = log.lock().unwrap().clone();
        assert_eq!(sent.len(), 2, "{sent:?}");
        assert!(sent[0].contains("still frozen"));
        assert!(sent[1].contains("allowed IP is back"));
    }

    #[test]
    fn disabled_notifier_sends_nothing() {
        let (log, sink) = collector();
        let mut n = Notifier::new(sink, false);
        n.freeze_started("x");
        n.frozen_since = Some(Instant::now() - Duration::from_secs(90));
        n.still_frozen("x");
        n.resumed();
        assert!(log.lock().unwrap().is_empty());
    }

    #[test]
    fn resume_without_freeze_is_silent() {
        let (log, sink) = collector();
        let mut n = Notifier::new(sink, true);
        n.resumed();
        assert!(log.lock().unwrap().is_empty());
    }
}
