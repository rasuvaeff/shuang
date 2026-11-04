//! Trusted networks: recognized by the default gateway's MAC address.
//!
//! At home or in the office protection can be off; in a café it is on again.
//! The router's MAC identifies the network without any geolocation permission.
//!
//! Linux reads `/proc/net/route` (default gateway) + `/proc/net/arp` (its
//! MAC). Other platforms return `None` — trusted networks silently do not
//! match there, which fails closed (protection stays on).

use std::fs;

/// MAC of the current default gateway, lowercase `aa:bb:cc:dd:ee:ff`.
#[cfg(target_os = "linux")]
pub fn gateway_mac() -> Option<String> {
    let route = fs::read_to_string("/proc/net/route").ok()?;
    let gw_ip = default_gateway_ip(&route)?;
    let arp = fs::read_to_string("/proc/net/arp").ok()?;
    arp_mac(&arp, &gw_ip)
}

#[cfg(not(target_os = "linux"))]
pub fn gateway_mac() -> Option<String> {
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
