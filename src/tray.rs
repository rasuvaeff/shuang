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

#[cfg(windows)]
mod win {
    use std::sync::{Arc, atomic::AtomicBool};

    use crate::tray::{Msg, Status};

    /// Generate a 32x32 RGBA icon: a filled circle in the status color.
    fn icon_rgba(status: Status) -> Vec<u8> {
        let (r, g, b) = match status {
            Status::Ok => (76u8, 175u8, 80u8), // green
            Status::Frozen => (255, 152, 0),   // orange
        };
        let mut out = Vec::with_capacity(32 * 32 * 4);
        let (cy, cx, radius) = (15.5f32, 15.5f32, 12.0f32);
        for y in 0..32 {
            for x in 0..32 {
                let d = ((x as f32 - cx).powi(2) + (y as f32 - cy).powi(2)).sqrt();
                if d <= radius {
                    out.extend_from_slice(&[r, g, b, 255]);
                } else {
                    out.extend_from_slice(&[0, 0, 0, 0]);
                }
            }
        }
        out
    }

    struct App {
        tray: Option<tray_icon::TrayIcon>,
        status_item: tray_icon::menu::MenuItem,
        panel_item: tray_icon::menu::MenuItem,
        panel_url: Option<String>,
        quit: Arc<AtomicBool>,
        status: Status,
    }

    impl winit::application::ApplicationHandler<Msg> for App {
        fn resumed(&mut self, _event_loop: &winit::event_loop::ActiveEventLoop) {}

        fn user_event(&mut self, _event_loop: &winit::event_loop::ActiveEventLoop, event: Msg) {
            match event {
                Msg::Status(status, detail) => {
                    self.status = status;
                    if let Some(tray) = &self.tray {
                        if let Ok(icon) = tray_icon::Icon::from_rgba(icon_rgba(status), 32, 32) {
                            tray.set_icon(Some(icon));
                        }
                        tray.set_tooltip(Some(format!("shuang: {detail}")));
                    }
                    let _ = self.status_item.set_text(detail);
                }
                Msg::PanelUrl(url) => {
                    self.panel_url = Some(url);
                    let _ = self.panel_item.set_enabled(true);
                }
            }
        }

        fn window_event(
            &mut self,
            _event_loop: &winit::event_loop::ActiveEventLoop,
            _window_id: winit::window::WindowId,
            _event: winit::event::WindowEvent,
        ) {
        }

        fn about_to_wait(&mut self, _event_loop: &winit::event_loop::ActiveEventLoop) {
            // muda menu events arrive on this thread's channel.
            while let Ok(event) = tray_icon::menu::MenuEvent::receiver().try_recv() {
                match event.id().as_ref() {
                    "quit" => {
                        self.quit.store(true, std::sync::atomic::Ordering::SeqCst);
                    }
                    "panel" => {
                        if let Some(url) = &self.panel_url {
                            crate::tray::open_url(url);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    /// Spawn the tray thread (Windows allows a message loop on any thread).
    /// Returns the proxy for status updates, or None when the tray failed.
    pub fn spawn(quit: Arc<AtomicBool>) -> Option<winit::event_loop::EventLoopProxy<Msg>> {
        let event_loop = winit::event_loop::EventLoop::with_user_event()
            .build()
            .ok()?;
        let proxy = event_loop.create_proxy();

        let status_item =
            tray_icon::menu::MenuItem::with_id("status", "starting…", false, None).ok()?;
        let panel_item =
            tray_icon::menu::MenuItem::with_id("panel", "Open panel", false, None).ok()?;
        let quit_item =
            tray_icon::menu::MenuItem::with_id("quit", "Quit shuang", true, None).ok()?;
        let menu = tray_icon::menu::Menu::new().ok()?;
        menu.append(&status_item).ok()?;
        menu.append(&tray_icon::menu::PredefinedMenuItem::separator())
            .ok()?;
        menu.append(&panel_item).ok()?;
        menu.append(&quit_item).ok()?;

        let icon = tray_icon::Icon::from_rgba(icon_rgba(Status::Ok), 32, 32).ok()?;
        let tray = tray_icon::TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("shuang")
            .with_icon(icon)
            .build()
            .ok()?;

        std::thread::spawn(move || {
            let mut app = App {
                tray: Some(tray),
                status_item,
                panel_item,
                panel_url: None,
                quit,
                status: Status::Ok,
            };
            let _ = event_loop.run_app(&mut app);
        });
        Some(proxy)
    }
}

#[cfg(windows)]
use win as win_tray;

/// One-line human summary of a verdict, reused by the tray and the logs.
pub fn summary(verdict: &Verdict) -> String {
    let ip = verdict
        .ipv4
        .map(|i| i.to_string())
        .unwrap_or_else(|| "IP unknown".into());
    let country = verdict.country.as_deref().unwrap_or("??");
    format!("{ip} ({country})")
}

#[cfg(unix)]
struct ShuangTray {
    status: Status,
    detail: String,
    panel_url: Option<String>,
    quit: Arc<AtomicBool>,
}

/// Open the panel URL in the system browser (best-effort, failures ignored).
fn open_url(url: &str) {
    #[cfg(target_os = "macos")]
    let mut cmd = std::process::Command::new("open");
    #[cfg(target_os = "windows")]
    let mut cmd = {
        let mut c = std::process::Command::new("cmd");
        c.args(["/C", "start", "", url]);
        c
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = std::process::Command::new("xdg-open");
    #[cfg(not(target_os = "windows"))]
    {
        cmd.arg(url);
    }
    let _ = cmd.spawn();
}

#[cfg(unix)]
#[cfg(unix)]
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
        let mut items = vec![
            StandardItem {
                label: self.detail.clone(),
                enabled: false,
                ..StandardItem::default()
            }
            .into(),
            ksni::MenuItem::Separator,
        ];
        if let Some(url) = &self.panel_url {
            let url = url.clone();
            items.push(
                StandardItem {
                    label: "Open panel".to_string(),
                    activate: Box::new(move |_| open_url(&url)),
                    ..StandardItem::default()
                }
                .into(),
            );
        }
        items.push(
            StandardItem {
                label: "Quit shuang".to_string(),
                activate: Box::new(|tray: &mut Self| {
                    tray.quit.store(true, Ordering::SeqCst);
                }),
                ..StandardItem::default()
            }
            .into(),
        );
        items
    }
}

/// Status/detail message for the Windows tray thread.
#[cfg(windows)]
#[derive(Debug, Clone)]
pub enum Msg {
    Status(crate::tray::Status, String),
    PanelUrl(String),
}

/// Handle to the (possibly headless) tray.
#[derive(Clone)]
pub struct TrayHandle {
    #[cfg(unix)]
    inner: Option<ksni::Handle<ShuangTray>>,
    #[cfg(windows)]
    inner: Option<winit::event_loop::EventLoopProxy<Msg>>,
    /// macOS: headless for now (see the platform table in README).
    #[cfg(not(any(unix, windows)))]
    inner: Option<()>,
    quit: Arc<AtomicBool>,
}

impl TrayHandle {
    /// Spawn the tray unless suppressed. No D-Bus session (servers, plain
    /// SSH) → headless with a warning, never an error: protection runs on.
    /// Async end to end: ksni's async API runs on our tokio runtime (the
    /// `blocking` facade panics when called from inside a runtime).
    pub async fn spawn(no_tray: bool) -> Self {
        let quit = Arc::new(AtomicBool::new(false));
        if no_tray {
            return Self { inner: None, quit };
        }

        #[cfg(windows)]
        {
            let proxy = win_tray::spawn(Arc::clone(&quit));
            if proxy.is_none() {
                eprintln!("shuang: no tray icon — running headless");
            }
            return Self { inner: proxy, quit };
        }

        // macOS: the tray needs a main-thread run loop, which a daemon
        // binary does not own — headless until a GUI-focused integration.
        #[cfg(not(any(unix, windows)))]
        {
            eprintln!("shuang: tray is not available on this platform yet — running headless");
            return Self { inner: None, quit };
        }

        #[cfg(unix)]
        let tray = ShuangTray {
            status: Status::Ok,
            detail: "starting…".to_string(),
            panel_url: None,
            quit: Arc::clone(&quit),
        };
        use ksni::TrayMethods as _;
        #[cfg(unix)]
        match tray.spawn().await {
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
    pub async fn status(&self, status: Status, detail: &str) {
        #[cfg(windows)]
        if let Some(proxy) = &self.inner {
            let _ = proxy.send_event(Msg::Status(status, detail.to_string()));
            return;
        }
        #[cfg(any(unix, windows))]
        if self.inner.is_none() {
            return;
        }
        #[cfg(unix)]
        if let Some(handle) = &self.inner {
            let detail = detail.to_string();
            handle
                .update(move |tray| {
                    tray.status = status;
                    tray.detail = detail;
                })
                .await;
        }
    }

    /// Remember the panel URL so the tray menu gets an "Open panel" item.
    pub async fn set_panel_url(&self, url: &str) {
        #[cfg(windows)]
        if let Some(proxy) = &self.inner {
            let _ = proxy.send_event(Msg::PanelUrl(url.to_string()));
        }
        #[cfg(unix)]
        if let Some(handle) = &self.inner {
            let url = url.to_string();
            let _ = handle.update(move |tray| tray.panel_url = Some(url)).await;
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

    #[tokio::test]
    async fn headless_handle_is_a_silent_no_op() {
        let handle = TrayHandle::spawn(true).await;
        assert!(handle.inner.is_none());
        // Must not panic:
        handle.status(Status::Frozen, "no D-Bus").await;
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
