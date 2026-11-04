//! Instant network-change reaction on Linux: subscribe to netlink route,
//! address, and link notifications. Any event = "verify the IP right now"
//! instead of waiting for the next poll tick.
//!
//! Best-effort by design: the thread exits silently on any error and the
//! daemon falls back to pure polling — protection must not depend on the
//! watcher. (Kordon freezes blindly on the event; we re-verify first, which
//! avoids false freezes on harmless route changes.)

use tokio::sync::mpsc::UnboundedSender;

/// Spawn the watcher thread. Every netlink notification sends `()` to `tx`.
#[cfg(target_os = "linux")]
pub fn spawn(tx: UnboundedSender<()>) {
    std::thread::spawn(move || {
        if let Err(err) = watch(&tx) {
            eprintln!("shuang: network event watcher stopped ({err}); polling only");
        }
    });
}

#[cfg(not(target_os = "linux"))]
pub fn spawn(_tx: UnboundedSender<()>) {
    // macOS/Windows network events come with the 0.2 tray integration.
}

#[cfg(target_os = "linux")]
fn watch(tx: &UnboundedSender<()>) -> anyhow::Result<()> {
    use netlink_sys::constants::NETLINK_ROUTE;
    use netlink_sys::{Socket, SocketAddr};

    let mut socket = Socket::new(NETLINK_ROUTE)?;
    socket.bind_auto()?;
    socket.connect(&SocketAddr::new(0, 0))?;
    for group in [
        RTNLGRP_LINK,
        RTNLGRP_IPV4_IFADDR,
        RTNLGRP_IPV4_ROUTE,
        RTNLGRP_IPV6_IFADDR,
        RTNLGRP_IPV6_ROUTE,
    ] {
        socket.add_membership(group)?;
    }

    let mut buffer = vec![0u8; 4096];
    loop {
        let (len, _) = socket.recv_from(&mut buffer, 0)?;
        if len > 0 && tx.send(()).is_err() {
            return Ok(()); // receiver dropped: mode is exiting
        }
    }
}

/// linux/rtnetlink.h membership group numbers (stable kernel ABI).
#[cfg(target_os = "linux")]
const RTNLGRP_LINK: u32 = 1;
#[cfg(target_os = "linux")]
const RTNLGRP_IPV4_IFADDR: u32 = 5;
#[cfg(target_os = "linux")]
const RTNLGRP_IPV4_ROUTE: u32 = 7;
#[cfg(target_os = "linux")]
const RTNLGRP_IPV6_IFADDR: u32 = 9;
#[cfg(target_os = "linux")]
const RTNLGRP_IPV6_ROUTE: u32 = 11;
