# shuang — 霜 / frost

**Freeze your apps when the VPN drops. Suspend, don't kill.**

`shuang` is a free, open-source per-application kill switch. While your
external IP is not on the allowlist, the whole process tree of the chosen
application is **suspended** (`SIGSTOP`) — it runs zero instructions and sends
nothing. When the right IP is back, it resumes exactly where it stopped.
If the IP never comes back within the grace period, the tree is stopped.

Built for AI coding agents (Claude Code, Codex, Gemini CLI) and any app that
must never talk to the network from the wrong address. No server, no account,
no telemetry — a single binary.

## Why

A VPN client's built-in kill switch cuts the whole network. `shuang` works
per-application: the frozen app leaks nothing, everything else keeps working.
And unlike firewall rules, suspension is reversible — a two-second VPN blip
pauses Claude Code and lets it continue from the same place, session intact.

## Install

Requires `git`-less setup: just a binary. Linux and macOS today; Windows is
planned for 0.2 together with the tray icon.

### One-line (Linux & macOS)

```bash
curl -fsSL https://raw.githubusercontent.com/rasuvaeff/shuang/master/scripts/install.sh | sh
```

The download is verified against the `.sha256` published with the release; a
mismatch aborts the install. Override the location with `INSTALL_DIR=…`, pin a
version with `VERSION=vX.Y.Z` (see the release page).

### Cargo

```bash
cargo install --git https://github.com/rasuvaeff/shuang
```

## Usage

### Kill switch for one command

```bash
shuang run -- claude -p "fix the tests"
```

- IP not allowed **at start** → the command never runs, exit code **69**;
- IP goes bad **mid-run** → the whole process tree (MCP servers, `curl`,
  `git`, …) is frozen; if the allowed IP returns within the grace period, the
  command continues — otherwise it is stopped, exit code **75**;
- otherwise the exit code is the command's own.

With an **empty allowlist** the first run remembers the startup IP as the
allowed one (freeze on *change*). Add entries with `shuang allow`:

```bash
shuang allow 203.0.113.42      # an IP
shuang allow 185.12.40.0/24    # a subnet
shuang allow NL                # a whole country
```

### One-shot check

```bash
shuang check          # human-readable
shuang check --json   # {"ipv4": "...", "ipv6": "...", "country": "NL", "quorum": true, "allowed": true}
```

Exit codes: `0` allowed, `3` not allowed, `1` error.

### Daemon: watch apps

```toml
# ~/.config/shuang/config.toml
[[apps]]
name = "claude-code"
match = ["claude", "args:claude"]   # process name / path substring / args: substring

[allow]
countries = ["NL"]

[ip_check]
min_agree = 2        # at least 2 services must name the same IP
interval_secs = 5

[timing]
grace_secs = 20      # how long a frozen tree waits for the right IP
close_secs = 5       # polite stop before a forced kill
```

```bash
shuang daemon
```

## How the check works

Every `interval_secs` the configured services are asked concurrently for the
caller's IPv4 **and** IPv6 address. An answer counts only when `min_agree`
services agree — fewer agreeing answers means *unknown*, and **unknown is
never allowed** (fail-closed). A direct IPv6 route that the VPN does not
tunnel is caught by the separate IPv6 check.

Runtime allowlist entries (`shuang allow`) are stored in `state.toml` next to
the config — your commented `config.toml` is never rewritten.

## What shuang sends over the network

Only the IP checks you configured (defaults: `api.ipify.org`,
`ipv4.icanhazip.com`, `v4.ident.me`, `checkip.amazonaws.com`, and the IPv6
counterparts; country: `api.country.is`). No telemetry, no update pings, no
server of ours. Point `ip_services` at your own endpoint that answers with
plain-text IPs if you prefer.

## Platform support

| Platform | Status |
|---|---|
| Linux | ✅ v0.1 |
| macOS | ✅ v0.1 |
| Windows | 🚧 0.2 (with tray + `NtSuspendProcess`) |
| HarmonyOS PC | 📋 possible later via the Rust `aarch64-unknown-linux-ohos` target — not planned yet |

v0.1 targets servers, CI, and terminals (headless). The tray icon, network
event subscription (instant reaction instead of polling), and Telegram
notifications are on the roadmap — the cloud/Telegram parts of proprietary
tools are intentionally out of scope for the core.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | allowed / command finished successfully |
| `1` | error (bad config, cannot start the command, …) |
| `3` | `check`: current IP not allowed |
| `69` | `run`: IP not allowed at start, command never ran |
| `75` | `run`: stopped — the allowed IP never came back |

## Security notes

- A suspended process sends nothing, but the freeze happens milliseconds
  *after* the network change: for a hard "not a single packet" guarantee,
  combine `shuang` with your VPN client's network-level kill switch — this
  tool complements it, it does not replace it.
- Processes running as root/system services are not touched; `shuang` works
  with the privileges of the user who started it.
- `daemon` matches processes by name — an attacker process named like your
  app is out of scope for v0.1.

## Development

```bash
cargo fmt
cargo clippy --all-targets --locked -- -D warnings
cargo test --all --locked
```

Rust 1.85+ (edition 2024). `Cargo.lock` is committed (binary crate).

## License

[GPL-3.0-or-later](./COPYING). Forks must stay open.
