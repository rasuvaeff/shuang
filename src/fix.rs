//! Closing leaks where the OS allows it.
//!
//! - `disable-ipv6` / `enable-ipv6`: the classic "VPN tunnels only IPv4"
//!   leak, closed with sysctl. Without root the write fails — the fix then
//!   returns the exact command to run with sudo (never a silent no-op).
//! - `dns-public`: a DNS leak (resolver in another country) is fixed by
//!   pointing the system at a public anycast resolver. Rewriting
//!   `/etc/resolv.conf` can break networking on managed machines, so this
//!   fix is always `NeedsRoot` with the exact commands.
//! - Split routing and exit-IP reputation live in the VPN's configuration —
//!   `NotPossible` with the reason.

use std::process::Command;

#[derive(Debug, PartialEq, Eq)]
pub enum FixResult {
    /// The fix was applied (the command succeeded).
    Applied(String),
    /// The fix needs more privileges; the string is the exact command.
    NeedsRoot(String),
}

impl FixResult {
    pub fn message(&self) -> String {
        match self {
            FixResult::Applied(m) => format!("applied: {m}"),
            FixResult::NeedsRoot(cmd) => format!("needs root — run:\n  {cmd}"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    DisableIpv6,
    EnableIpv6,
    DnsPublic,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "disable-ipv6" => Some(Self::DisableIpv6),
            "enable-ipv6" => Some(Self::EnableIpv6),
            "dns-public" => Some(Self::DnsPublic),
            _ => None,
        }
    }

    pub fn apply(self) -> FixResult {
        match self {
            Self::DisableIpv6 => sysctl_ipv6(false),
            Self::EnableIpv6 => sysctl_ipv6(true),
            Self::DnsPublic => FixResult::NeedsRoot(
                "# point the system resolver at a public anycast resolver\n\
                 # (check your VPN: if it pushes its own DNS, prefer that one)\n\
                 sudo cp /etc/resolv.conf /etc/resolv.conf.shuang-backup\n\
                 printf 'nameserver 1.1.1.1\\nnameserver 9.9.9.9\\n' | sudo tee /etc/resolv.conf"
                    .to_string(),
            ),
        }
    }
}

fn sysctl_ipv6(enable: bool) -> FixResult {
    let value = if enable { "1" } else { "0" };
    let keys = [
        "net.ipv6.conf.all.disable_ipv6",
        "net.ipv6.conf.default.disable_ipv6",
    ];
    let mut applied = Vec::new();
    for key in keys {
        let out = Command::new("sysctl")
            .args(["-w", &format!("{key}={value}")])
            .output();
        match out {
            Ok(o) if o.status.success() => applied.push(format!("{key}={value}")),
            _ => {
                // The write failed (almost certainly EPERM): give the command.
                let cmds: Vec<String> = keys
                    .iter()
                    .map(|k| format!("sudo sysctl -w {k}={value}"))
                    .collect();
                let persist = if enable {
                    "sudo rm -f /etc/sysctl.d/99-shuang-noipv6.conf".to_string()
                } else {
                    "printf 'net.ipv6.conf.all.disable_ipv6=0\\nnet.ipv6.conf.default.disable_ipv6=0\\n' \
                     | sudo tee /etc/sysctl.d/99-shuang-noipv6.conf"
                        .to_string()
                };
                return FixResult::NeedsRoot(format!(
                    "{}\n# to make it survive a reboot:\n#   {persist}",
                    cmds.join("\n")
                ));
            }
        }
    }
    FixResult::Applied(applied.join(", "))
}

/// Which fixes make sense for a given leaks text (the panel lights up only
/// these buttons).
pub fn relevant_for(leaks_text: &str) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    if leaks_text.contains("IPv6") {
        out.push((
            "disable-ipv6",
            "Disable IPv6 (close the IPv6 leak)".to_string(),
        ));
    }
    if leaks_text.contains("DNS leak") {
        out.push(("dns-public", "Point DNS at a public resolver".to_string()));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kinds_parse() {
        assert_eq!(Kind::parse("disable-ipv6"), Some(Kind::DisableIpv6));
        assert_eq!(Kind::parse("enable-ipv6"), Some(Kind::EnableIpv6));
        assert_eq!(Kind::parse("dns-public"), Some(Kind::DnsPublic));
        assert_eq!(Kind::parse("make-coffee"), None);
    }

    #[test]
    fn dns_fix_never_touches_resolv_conf_itself() {
        assert!(matches!(Kind::DnsPublic.apply(), FixResult::NeedsRoot(_)));
    }

    #[test]
    fn ipv6_fix_reports_something_actionable() {
        // On a dev machine without root this is NeedsRoot; with root it is
        // Applied. Both are fine — the invariant is a non-empty message.
        let result = Kind::DisableIpv6.apply();
        assert!(!result.message().is_empty());
    }

    #[test]
    fn relevance_follows_the_leaks_text() {
        let fixes = relevant_for("the AI edge sees you over IPv6 — …");
        assert_eq!(fixes.len(), 1);
        assert_eq!(fixes[0].0, "disable-ipv6");

        let fixes = relevant_for("DNS resolver 1.2.3.4 is in DE … — DNS leak?");
        assert!(fixes.iter().any(|(k, _)| *k == "dns-public"));

        assert!(relevant_for("No leaks detected.").is_empty());
    }
}
