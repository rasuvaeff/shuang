//! Tray icon for the daemon.
//!
//! - Linux: KSNI over D-Bus (GNOME shows it via the AppIndicator extension,
//!   KDE/XFCE/Cinnamon natively).
//! - Windows + macOS: the `native` module (tray-icon + a winit event loop).
//!   Windows runs the loop on a dedicated thread; macOS must own the main
//!   thread, so `main.rs` builds the parts there (`macos_main`) and runs the
//!   daemon on a worker.
//!
//! The tray is display-only plus Quit/Open panel: status color
//! (green/orange), IP and country in the tooltip, freeze reason + grace
//! countdown in the menu label. Editing settings happens in the panel/CLI.
//!
//! When the platform tray is unavailable (a server, SSH, `--no-tray`) the
//! handle degrades to headless: every method becomes a no-op and the daemon
//! keeps working — the tray must never be load-bearing for protection.

use std::sync::{Arc, atomic::AtomicBool};

use crate::ipcheck::Verdict;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    Frozen,
}

impl Status {
    #[cfg(any(target_os = "linux", test))]
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

/// Open the panel URL in the system browser (best-effort, failures ignored).
pub fn open_url(url: &str) {
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

// ─────────────────────────────────────────────────────────────────────────────
// Windows + macOS: tray-icon over a winit event loop.
// ─────────────────────────────────────────────────────────────────────────────

/// Status/detail message for the native (winit) tray loop.
#[cfg(any(windows, target_os = "macos"))]
#[derive(Debug, Clone)]
pub enum Msg {
    Status(Status, String),
    PanelUrl(String),
}

#[cfg(any(windows, target_os = "macos"))]
mod native {
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

    /// Lives on the tray thread: tray-icon/muda types are `!Send`.
    pub(super) struct App {
        tray: Option<tray_icon::TrayIcon>,
        status_item: tray_icon::menu::MenuItem,
        panel_item: tray_icon::menu::MenuItem,
        panel_url: Option<String>,
        pub(super) quit: Arc<AtomicBool>,
    }

    /// Everything `build` needs to hand back to the caller before the loop
    /// starts; `run` consumes it on the loop thread.
    pub(super) struct Parts {
        pub event_loop: winit::event_loop::EventLoop<Msg>,
        pub proxy: winit::event_loop::EventLoopProxy<Msg>,
        pub app: App,
    }

    impl winit::application::ApplicationHandler<Msg> for App {
        fn resumed(&mut self, _event_loop: &winit::event_loop::ActiveEventLoop) {}

        fn user_event(&mut self, _event_loop: &winit::event_loop::ActiveEventLoop, event: Msg) {
            match event {
                Msg::Status(status, detail) => {
                    if let Some(tray) = &self.tray {
                        if let Ok(icon) = tray_icon::Icon::from_rgba(icon_rgba(status), 32, 32) {
                            let _ = tray.set_icon(Some(icon));
                        }
                        let _ = tray.set_tooltip(Some(format!("shuang: {detail}")));
                    }
                    self.status_item.set_text(detail);
                }
                Msg::PanelUrl(url) => {
                    self.panel_url = Some(url);
                    self.panel_item.set_enabled(true);
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

    /// Build the loop/menu/tray on THIS thread (Windows: any thread; macOS:
    /// the main thread only). `None` = tray could not be created.
    pub(super) fn build(quit: Arc<AtomicBool>) -> Option<Parts> {
        let event_loop = winit::event_loop::EventLoop::with_user_event()
            .build()
            .ok()?;
        let proxy = event_loop.create_proxy();

        let status_item = tray_icon::menu::MenuItem::with_id("status", "starting…", false, None);
        let panel_item = tray_icon::menu::MenuItem::with_id("panel", "Open panel", false, None);
        let quit_item = tray_icon::menu::MenuItem::with_id("quit", "Quit shuang", true, None);
        let menu = tray_icon::menu::Menu::new();
        let _ = menu.append(&status_item);
        let _ = menu.append(&tray_icon::menu::PredefinedMenuItem::separator());
        let _ = menu.append(&panel_item);
        let _ = menu.append(&quit_item);

        let tray = tray_icon::TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("shuang")
            .with_icon(tray_icon::Icon::from_rgba(icon_rgba(Status::Ok), 32, 32).ok()?)
            .build()
            .ok()?;

        Some(Parts {
            event_loop,
            proxy,
            app: App {
                tray: Some(tray),
                status_item,
                panel_item,
                panel_url: None,
                quit,
            },
        })
    }

    /// Run the event loop until exit (blocks; consumes the parts).
    pub(super) fn run(mut parts: Parts) {
        let _ = parts.event_loop.run_app(&mut parts.app);
    }

    /// Windows: spawn the tray on a dedicated thread (a message loop may run
    /// on any thread there). Returns the proxy, or None when it failed.
    #[cfg(windows)]
    pub fn spawn_threaded(quit: Arc<AtomicBool>) -> Option<winit::event_loop::EventLoopProxy<Msg>> {
        let (tx, rx) = std::sync::mpsc::channel::<Option<winit::event_loop::EventLoopProxy<Msg>>>();
        // Build AND run on this one thread: the tray types are !Send, so
        // only the (Send) proxy may cross back to the caller.
        std::thread::spawn(move || match build(Arc::clone(&quit)) {
            Some(parts) => {
                let _ = tx.send(Some(parts.proxy.clone()));
                run(parts); // blocks this thread until exit
            }
            None => {
                let _ = tx.send(None);
            }
        });
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .ok()
            .flatten()
    }
}

/// macOS: winit's event loop must run on the main thread. `main.rs` calls
/// `macos_main::build` there, runs the daemon on a worker thread, and then
/// blocks in `macos_main::run`.
#[cfg(target_os = "macos")]
pub mod macos_main {
    use super::Msg;
    use super::native::{self, Parts};

    pub struct MainTray {
        parts: Parts,
    }

    impl MainTray {
        pub fn proxy(&self) -> winit::event_loop::EventLoopProxy<Msg> {
            self.parts.proxy.clone()
        }

        pub fn quit_flag(&self) -> std::sync::Arc<std::sync::atomic::AtomicBool> {
            std::sync::Arc::clone(&self.parts.app.quit)
        }
    }

    /// Build on the main thread. `None` = no tray (headless fallback).
    pub fn build() -> Option<MainTray> {
        let quit = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        native::build(quit).map(|parts| MainTray { parts })
    }

    /// Run the event loop on the main thread (blocks until exit).
    pub fn run(tray: MainTray) {
        native::run(tray.parts);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Linux: KSNI (D-Bus).
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
struct ShuangTray {
    status: Status,
    detail: String,
    panel_url: Option<String>,
    quit: Arc<AtomicBool>,
}

#[cfg(target_os = "linux")]
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
                    tray.quit.store(true, std::sync::atomic::Ordering::SeqCst);
                }),
                ..StandardItem::default()
            }
            .into(),
        );
        items
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The platform-agnostic handle.
// ─────────────────────────────────────────────────────────────────────────────

/// Handle to the (possibly headless) tray.
#[derive(Clone)]
pub struct TrayHandle {
    #[cfg(target_os = "linux")]
    inner: Option<ksni::Handle<ShuangTray>>,
    #[cfg(any(windows, target_os = "macos"))]
    inner: Option<winit::event_loop::EventLoopProxy<Msg>>,
    quit: Arc<AtomicBool>,
}

impl TrayHandle {
    /// Spawn the tray unless suppressed. Missing platform tray → headless
    /// with a warning, never an error: protection runs on.
    ///
    /// Async end to end on Linux: ksni's async API runs on our tokio runtime
    /// (its `blocking` facade panics inside a runtime).
    pub async fn spawn(no_tray: bool) -> Self {
        let quit = Arc::new(AtomicBool::new(false));
        if no_tray {
            return Self { inner: None, quit };
        }

        #[cfg(windows)]
        {
            let proxy = native::spawn_threaded(Arc::clone(&quit));
            if proxy.is_none() {
                eprintln!("shuang: no tray icon — running headless");
            }
            Self { inner: proxy, quit }
        }

        // macOS: `main.rs` builds the tray on the main thread and hands it to
        // the daemon; landing here means that did not happen — headless.
        #[cfg(target_os = "macos")]
        {
            eprintln!("shuang: tray must be built on the main thread — running headless");
            Self { inner: None, quit }
        }

        // Any other platform: headless.
        #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))]
        {
            eprintln!("shuang: tray is not available on this platform — running headless");
            Self { inner: None, quit }
        }

        // Linux: fall through to the ksni arm below.
        #[cfg(target_os = "linux")]
        {
            let tray = ShuangTray {
                status: Status::Ok,
                detail: "starting…".to_string(),
                panel_url: None,
                quit: Arc::clone(&quit),
            };
            use ksni::TrayMethods as _;
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
    }

    /// macOS: assemble from the parts built on the main thread.
    #[cfg(target_os = "macos")]
    pub fn from_main(tray: &crate::tray::macos_main::MainTray) -> Self {
        Self {
            inner: Some(tray.proxy()),
            quit: tray.quit_flag(),
        }
    }

    /// Update the icon and the status line. Headless: no-op.
    pub async fn status(&self, status: Status, detail: &str) {
        #[cfg(any(windows, target_os = "macos"))]
        if let Some(proxy) = &self.inner {
            let _ = proxy.send_event(Msg::Status(status, detail.to_string()));
        }
        #[cfg(target_os = "linux")]
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
        #[cfg(any(windows, target_os = "macos"))]
        if let Some(proxy) = &self.inner {
            let _ = proxy.send_event(Msg::PanelUrl(url.to_string()));
        }
        #[cfg(target_os = "linux")]
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
        handle.status(Status::Frozen, "no tray").await;
        handle.set_panel_url("http://127.0.0.1:1/").await;
        assert!(!handle.quit_flag().load(std::sync::atomic::Ordering::SeqCst));
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
