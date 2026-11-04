//! Tray icon for the daemon (Linux: KSNI over D-Bus, shown by GNOME via the
//! AppIndicator extension, natively by KDE/XFCE/Cinnamon).
//!
//! The tray is display-only plus Quit: status color (green/orange), IP and
//! country in the tooltip, freeze reason + grace countdown in the menu label.
//! Editing settings happens in the panel/CLI, not in the menu.
//!
//! When D-Bus is unavailable (a server, SSH without forwarding) or `--no-tray`
//! is passed, the handle degrades to headless: every method becomes a no-op
//! and the daemon keeps working — the tray must never be load-bearing for
//! protection.

use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use crate::ipcheck::Verdict;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Frozen,
}

impl Status {
    fn icon_name(self) -> &'static str {
        // Stock freedesktop icon names present in Ubuntu's theme.
        match self {
            Status::Ok => "emblem-default",
            Status::Frozen => "dialog-warning",
        }
    }
}

/// One-line human summary of a verdict, reused by the tray and the logs.
pub fn summary(verdict: &Verdict) -> String {
    let ip = verdict
        .ipv4
        .map(|i| i.to_string())
        .unwrap_or_else(|| "IP unknown".into());
    let country = verdict.country.as_deref().unwrap_or("??");
    format!("{ip} ({country})")
}

struct ShuangTray {
    status: Status,
    detail: String,
    quit: Arc<AtomicBool>,
}

impl ksni::Tray for ShuangTray {
    fn id(&self) -> String {
        "shuang".to_string()
    }

    fn title(&self) -> String {
        "shuang".to_string()
    }

    fn icon_name(&self) -> String {
        self.status.icon_name().to_string()
    }

    fn tool_tip(&self) -> ksni::ToolTip {
        ksni::ToolTip {
            title: "shuang".to_string(),
            description: self.detail.clone(),
            ..ksni::ToolTip::default()
        }
    }

    fn menu(&self) -> Vec<ksni::MenuItem<Self>> {
        use ksni::menu::StandardItem;
        vec![
            StandardItem {
                label: self.detail.clone(),
                enabled: false,
                ..StandardItem::default()
            }
            .into(),
            ksni::MenuItem::Separator,
            StandardItem {
                label: "Quit shuang".to_string(),
                activate: Box::new(|tray: &mut Self| {
                    tray.quit.store(true, Ordering::SeqCst);
                }),
                ..StandardItem::default()
            }
            .into(),
        ]
    }
}

/// Handle to the (possibly headless) tray.
#[derive(Clone)]
pub struct TrayHandle {
    inner: Option<ksni::blocking::Handle<ShuangTray>>,
    quit: Arc<AtomicBool>,
}

impl TrayHandle {
    /// Spawn the tray unless suppressed. No D-Bus session (servers, plain
    /// SSH) → headless with a warning, never an error: protection runs on.
    pub fn spawn(no_tray: bool) -> Self {
        use ksni::blocking::TrayMethods as _;

        let quit = Arc::new(AtomicBool::new(false));
        if no_tray {
            return Self { inner: None, quit };
        }

        let tray = ShuangTray {
            status: Status::Ok,
            detail: "starting…".to_string(),
            quit: Arc::clone(&quit),
        };
        match tray.spawn() {
            Ok(handle) => Self {
                inner: Some(handle),
                quit,
            },
            Err(err) => {
                eprintln!("shuang: no tray icon ({err}) — running headless");
                Self { inner: None, quit }
            }
        }
    }

    /// Update the icon and the status line. Headless: no-op.
    pub fn status(&self, status: Status, detail: &str) {
        if let Some(handle) = &self.inner {
            let detail = detail.to_string();
            handle.update(move |tray| {
                tray.status = status;
                tray.detail = detail;
            });
        }
    }

    /// Shared quit flag, set by the tray's Quit menu item.
    pub fn quit_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.quit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn headless_handle_is_a_silent_no_op() {
        let handle = TrayHandle::spawn(true);
        assert!(handle.inner.is_none());
        // Must not panic:
        handle.status(Status::Frozen, "no D-Bus");
        assert!(!handle.quit_flag().load(Ordering::SeqCst));
    }

    #[test]
    fn summary_formats_ip_and_country() {
        let verdict = Verdict {
            ipv4: Some("203.0.113.7".parse().unwrap()),
            ipv6: None,
            country: Some("NL".to_string()),
            quorum: true,
        };
        assert_eq!(summary(&verdict), "203.0.113.7 (NL)");
        let unknown = Verdict::default();
        assert_eq!(summary(&unknown), "IP unknown (??)");
    }

    #[test]
    fn status_maps_to_icons() {
        assert_eq!(Status::Ok.icon_name(), "emblem-default");
        assert_eq!(Status::Frozen.icon_name(), "dialog-warning");
    }
}
