//! Trusted networks: recognized by the default gateway's MAC address.
//!
//! At home or in the office protection can be off; in a café it is on again.
//! The router's MAC identifies the network without any geolocation permission.
//!
//! Linux reads `/proc/net/route` (default gateway) + `/proc/net/arp` (its
//! MAC). Other platforms return `None` — trusted networks silently do not
//! match there, which fails closed (protection stays on).

/// MAC of the current default gateway, lowercase `aa:bb:cc:dd:ee:ff`.
#[cfg(target_os = "linux")]
pub fn gateway_mac() -> Option<String> {
    use std::fs;
    let route = fs::read_to_string("/proc/net/route").ok()?;
    let gw_ip = default_gateway_ip(&route)?;
    let arp = fs::read_to_string("/proc/net/arp").ok()?;
    arp_mac(&arp, &gw_ip)
}

/// Windows: `route print 0.0.0.0` names the gateway, `arp -a` its MAC.
#[cfg(windows)]
pub fn gateway_mac() -> Option<String> {
    let route = std::process::Command::new("route")
        .args(["print", "0.0.0.0"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&route.stdout).to_string();
    let gw = route_print_gateway(&text)?;
    let arp = std::process::Command::new("arp").arg("-a").output().ok()?;
    let text = String::from_utf8_lossy(&arp.stdout).to_string();
    arp_table_mac(&text, &gw)
}

/// Parse `route print 0.0.0.0`: the default-route line "0.0.0.0  0.0.0.0  <gw> …".
#[cfg(any(windows, test))]
pub fn route_print_gateway(route_output: &str) -> Option<String> {
    for line in route_output.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 3 && cols[0] == "0.0.0.0" && cols[1] == "0.0.0.0" {
            let gw = cols[2].to_string();
            if gw.parse::<std::net::IpAddr>().is_ok() {
                return Some(gw);
            }
        }
    }
    None
}

/// Parse `arp -a`: "192.168.1.1  aa-bb-cc-dd-ee-ff  dynamic" — dashes on Windows.
#[cfg(any(windows, test))]
pub fn arp_table_mac(arp_output: &str, gw: &str) -> Option<String> {
    for line in arp_output.lines() {
        if !line.contains(gw) {
            continue;
        }
        for col in line.split_whitespace() {
            if col.len() == 17 && col.matches('-').count() == 5 {
                return Some(col.replace('-', ":").to_ascii_lowercase());
            }
        }
    }
    None
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
pub fn gateway_mac() -> Option<String> {
    None
}

/// macOS: `route -n get default` names the gateway, `arp` its MAC.
#[cfg(target_os = "macos")]
pub fn gateway_mac() -> Option<String> {
    let route = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&route.stdout).to_string();
    let gw = route_default_gateway(&text)?;
    let arp = std::process::Command::new("arp")
        .arg("-n")
        .arg(&gw)
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&arp.stdout).to_string();
    arp_output_mac(&text)
}

/// Parse `route -n get default`: the `gateway: x.x.x.x` line.
#[cfg(any(target_os = "macos", test))]
pub fn route_default_gateway(route_output: &str) -> Option<String> {
    route_output
        .lines()
        .find_map(|l| l.trim().strip_prefix("gateway:"))
        .map(|ip| ip.trim().to_string())
        .filter(|ip| ip.parse::<std::net::IpAddr>().is_ok())
}

/// Parse `arp -n <ip>`: whichever column looks like a MAC
/// (`aa:bb:cc:dd:ee:ff`) — the column index differs between outputs.
#[cfg(any(target_os = "macos", test))]
pub fn arp_output_mac(arp_output: &str) -> Option<String> {
    for line in arp_output.lines().skip(1) {
        for col in line.split_whitespace() {
            let col = col.to_ascii_lowercase();
            let bytes = col.as_bytes();
            if bytes.len() == 17
                && bytes[2] == b':'
                && bytes[5] == b':'
                && bytes[8] == b':'
                && bytes[11] == b':'
                && bytes[14] == b':'
            {
                return Some(col);
            }
        }
    }
    None
}

/// Is the current network trusted? (config MACs are normalized lowercase.)
pub fn is_trusted(configured: &[String]) -> bool {
    match gateway_mac() {
        Some(mac) => configured.iter().any(|c| c.to_ascii_lowercase() == mac),
        None => false,
    }
}

/// Parse `/proc/net/route`: the default route's gateway as dotted quad.
#[cfg(any(target_os = "linux", test))]
/// Gateway hex is little-endian (`0100A8C0` → `192.168.0.1`).
pub fn default_gateway_ip(route_table: &str) -> Option<String> {
    for line in route_table.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 3 || cols[1] != "00000000" {
            continue;
        }
        let hex = cols[2];
        if hex == "00000000" {
            continue;
        }
        let bytes = hex.as_bytes();
        if bytes.len() != 8 {
            return None;
        }
        let octet = |i: usize| -> Option<u8> {
            u8::from_str_radix(std::str::from_utf8(&bytes[i..i + 2]).ok()?, 16).ok()
        };
        let (o3, o2, o1, o0) = (octet(0)?, octet(2)?, octet(4)?, octet(6)?);
        return Some(format!("{o0}.{o1}.{o2}.{o3}"));
    }
    None
}

/// Parse `/proc/net/arp`: the MAC for the given IP, normalized lowercase.
#[cfg(any(target_os = "linux", test))]
pub fn arp_mac(arp_table: &str, ip: &str) -> Option<String> {
    for line in arp_table.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() >= 4 && cols[0] == ip {
            let mac = cols[3].to_ascii_lowercase();
            if mac.contains(':') {
                return Some(mac);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_default_gateway_from_route() {
        let table = "Iface\tDestination\tGateway\tFlags\n\
                     wlan0\t00000000\t0100A8C0\t0003\n\
                     wlan0\t0008A8C0\t00000000\t0001\n";
        assert_eq!(default_gateway_ip(table).as_deref(), Some("192.168.0.1"));
    }

    #[test]
    fn no_default_route_is_none() {
        let table = "Iface\tDestination\tGateway\tFlags\n\
                     eth0\t0008A8C0\t0100A8C0\t0003\n";
        assert_eq!(default_gateway_ip(table), None);
    }

    #[test]
    fn parses_arp_mac_case_insensitively() {
        let arp = "IP address\tHW type\tFlags\tHW address\n\
                   192.168.0.1\t0x1\t0x2\tAA:BB:CC:11:22:33\n\
                   192.168.0.2\t0x1\t0x2\tdd:ee:ff:00:11:22\n";
        assert_eq!(
            arp_mac(arp, "192.168.0.1").as_deref(),
            Some("aa:bb:cc:11:22:33")
        );
        assert_eq!(arp_mac(arp, "10.0.0.9"), None);
    }

    #[test]
    fn parses_route_and_arp_output() {
        let route = "   route to: default\ndestination: default\n        gateway: 192.168.1.1\n";
        assert_eq!(route_default_gateway(route).as_deref(), Some("192.168.1.1"));
        assert_eq!(route_default_gateway("no gateway here"), None);

        let arp = "Address      HWtype   HWaddress\n192.168.1.1  ether    aa:bb:cc:11:22:33\n";
        assert_eq!(arp_output_mac(arp).as_deref(), Some("aa:bb:cc:11:22:33"));
        assert_eq!(arp_output_mac("Address\n(nothing)"), None);
    }

    #[test]
    fn parses_windows_route_and_arp() {
        let route = "Active Routes:\n  0.0.0.0    0.0.0.0    192.168.0.1   192.168.0.42   25\n";
        assert_eq!(route_print_gateway(route).as_deref(), Some("192.168.0.1"));
        assert_eq!(route_print_gateway("no match"), None);

        let arp = "Internet Address    Physical Address     Type\n  192.168.0.1    aa-bb-cc-11-22-33    dynamic\n";
        assert_eq!(
            arp_table_mac(arp, "192.168.0.1").as_deref(),
            Some("aa:bb:cc:11:22:33")
        );
        assert_eq!(arp_table_mac(arp, "10.0.0.9"), None);
    }

    #[test]
    fn trust_check_matches_current_gateway_or_fails_closed() {
        match gateway_mac() {
            Some(mac) => {
                // Case-insensitive match against the live gateway.
                assert!(is_trusted(&[mac.to_uppercase()]));
                assert!(!is_trusted(&["00:00:00:00:00:00".to_string()]));
            }
            // No gateway detected (non-Linux): never trusted — fail closed.
            None => assert!(!is_trusted(&["aa:bb:cc:dd:ee:ff".to_string()])),
        }
    }
}
