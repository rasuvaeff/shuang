//! Native GUI window: the panel inside a real application window (no browser
//! chrome), built on wry — the same webview engine Tauri uses.
//!
//! `shuang panel` opens the window using the daemon's persisted panel URL;
//! the tray's "Open panel" spawns this same command as a subprocess. Falls
//! back to the system browser when the webview cannot start (server hosts,
//! minimal WMs without webkit).
//!
//! Platform split: Linux builds a plain GTK window with the webview in it
//! (the wry-recommended path); Windows/macOS use a tao window.

use anyhow::Result;

pub fn run(url: &str) -> Result<()> {
    run_webview(url).or_else(|err| {
        eprintln!("shuang: native window unavailable ({err:#}) — opening the browser");
        crate::tray::open_url(url);
        Ok(())
    })
}

#[cfg(target_os = "linux")]
fn run_webview(url: &str) -> Result<()> {
    use gtk::prelude::*;
    use wry::WebViewBuilderExtUnix;

    gtk::init()?;
    let window = gtk::Window::new(gtk::WindowType::Toplevel);
    window.set_title("shuang");
    window.set_default_size(1100, 950);

    let _webview = wry::WebViewBuilder::new()
        .with_url(url)
        .with_initialization_script(
            // A native window should not offer a browser context menu.
            "document.addEventListener('contextmenu', e => e.preventDefault());",
        )
        .build_gtk(&window)
        .map_err(|e| anyhow::anyhow!("webview: {e:?}"))?;

    window.show_all();
    window.connect_delete_event(|_, _| {
        // wry's webview keeps its own nested GTK loop; main_quit() may only
        // unwind one level and leave the process lingering. This is a
        // dedicated window process — exit outright.
        std::process::exit(0);
    });
    gtk::main();
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn run_webview(url: &str) -> Result<()> {
    use tao::{
        event_loop::{ControlFlow, EventLoop},
        window::WindowBuilder,
    };

    let event_loop = EventLoop::new();
    let window = WindowBuilder::new()
        .with_title("shuang")
        .with_inner_size(tao::dpi::LogicalSize::new(1100.0, 950.0))
        .build(&event_loop)?;

    let builder = wry::WebViewBuilder::new()
        .with_url(url)
        .with_initialization_script(
            "document.addEventListener('contextmenu', e => e.preventDefault());",
        );
    let _webview = builder
        .build(&window)
        .map_err(|e| anyhow::anyhow!("webview: {e:?}"))?;

    // `run` never returns (it blocks until the window closes); its `!` type
    // satisfies the Result return.
    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        if let tao::event::Event::WindowEvent {
            event: tao::event::WindowEvent::CloseRequested,
            ..
        } = event
        {
            *control_flow = ControlFlow::Exit;
        }
    })
}
