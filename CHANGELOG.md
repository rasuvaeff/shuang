# Changelog

## 0.1.0 — 2026-11-04

- Initial implementation: `run` (kill switch for one command, exit codes
  69/75), `check` (one-shot IP verdict, JSON and human output, exit code 3),
  `allow` (persistent IP/subnet/country entries in `state.toml`), and
  `daemon` (watch configured apps).
- Quorum-based IPv4 + IPv6 checks with fail-closed evaluation; IPv6 leak
  detection; freeze/resume of whole process trees via `SIGSTOP`/`SIGCONT`
  on Linux and macOS, `NtSuspendProcess` on Windows.
- A missing config file at the default location falls back to built-in
  defaults (first run works with no setup); an explicitly passed `--config`
  that does not exist is an error, not a silent default.
- Tray icon (Linux/KSNI): status color, IP/country tooltip, freeze reason
  and grace countdown in the menu, Quit that resumes everything.
- Desktop notifications with anti-noise: a short VPN blink produces one
  quiet "blinked for Ns" notification on recovery; freezes longer than 60s
  alert once.
- `shuang leaks`: per-service IP answers, AI services' own edge
  (`/cdn-cgi/trace`) with latency, split-routing detection (dual-stack
  aware), DNS resolvers with country, exit IP reputation
  (residential/datacenter/proxy flags via ip-api.com), timezone, proxy
  environment, gateway MAC; warns on non-supported Claude exit countries
  and IPv6-visible edges. Exit code 4.
- `shuang doctor` (environment diagnostics) and `shuang stats` (VPN health
  from history.log) and `shuang events`.
- Per-app allowlist rules (`[apps.allow]`), allowlist profiles
  (`[profiles.name]` + `shuang profile`), trusted networks by gateway MAC.
- Reliability: netlink instant re-check on network changes (Linux),
  suspend-aware grace timer (`CLOCK_BOOTTIME`), clean exit on Ctrl+C/SIGTERM
  (resumes everything), frozen-pid persistence and orphan recovery after a
  crash, country cache per exit subnet, config sanity warnings.
- Property-based tests for the allowlist invariants (proptest).
- Local web panel (127.0.0.1 + per-run token, opened from the tray menu):
  live status, allowlist management (add/remove), profiles, one-click
  leaks/doctor/stats, leak fixes, and settings (interval, grace, close,
  quorum, notifications, trust-this-network) written as `state.toml`
  overrides — `config.toml` is never rewritten.
- `shuang deny` (CLI twin of the panel's ×) and `shuang fix`
  (disable-ipv6 / enable-ipv6 / dns-public; without root prints the exact
  sudo command).
- Network-change events on macOS/Windows via a local configuration poller;
  Windows tray via `tray-icon` (Linux keeps KSNI; macOS tray pending a
  main-thread run loop integration).

## 0.2.1 — 2026-11-05

- Fix: the v0.2.0 binaries reported version `0.1.0` — the `Cargo.toml`
  version was not bumped for that release. v0.2.1 is the same code with the
  correct version (and makes `shuang update` from v0.2.0 work).

## 0.2.0 — 2026-11-05

- `shuang update`: self-update from GitHub Releases with mandatory `.sha256`
  verification and atomic replace; strictly user-initiated.
- Panel: manage protected apps — `[[apps]]` in `state.toml` merged with the
  config, a picker of running processes, per-source labels and deletion.
- macOS tray: the daemon runs on a worker thread while the winit event loop
  owns the main thread (tray-icon).

## 0.3.2 — 2026-11-05

- Fix: desktop notifications crashed the daemon inside the tokio runtime
  ("Cannot start a runtime from within a runtime"; a production daemon
  restart-looped 46 times on this). Notifications now go through a dedicated
  worker thread; a full channel drops the notification instead of blocking.

## 0.3.1 — 2026-11-05

- Fix: `shuang update` failed with `Invalid cross-device link` when /tmp is a
  different filesystem — the archive now extracts next to the binary so the
  final rename stays on one filesystem.

## 0.3.0 — 2026-11-05

- Daemon split-routing freeze (opt-in `[route_check] enabled`): re-asks the
  AI services' own edge and freezes when the trace address matches neither
  exit; `route-leak` events land in history.log.
- Trusted networks on every platform: gateway MAC via /proc (Linux),
  `route`/`arp` (macOS, Windows).
- Panel: per-app allow countries when adding an app.
- `shuang update` self-update (from 0.2.x), panel-managed protected apps,
  macOS tray — shipped in 0.2.x, listed for completeness.

## 0.4.0 — 2026-11-05

- Proxy-client watchdog (`[watchdog] processes`): freeze when the local
  v2ray/clash/… client dies — its death may not move routes, so netlink
  stays silent.
- Paranoid mode (`freeze_on_event_first`): a network event freezes before
  the IP re-check — zero-leak window at the cost of short pauses.
- Reputation guard (`[reputation]`): freeze while the exit IP carries any
  of the configured flags (proxy/hosting/tor), checked periodically.
- Exit-rotation counter: every exit change lands in history as
  `exit-change`; `shuang stats` shows the weekly count.
- All four are panel-editable (Settings card) and live in `state.toml`
  overrides; nothing requires editing config.toml.

## Unreleased

- Stability gate (`stability_secs`): after a freeze, the resume waits for
  the good verdict to hold — a flapping exit never resumes the trees.
- Fast transport probe (`[probe]`): a 1-second direct TCP ping that freezes
  the instant the transport dies (vs ~10 s of IP-check timeouts), and
  classifies `vpn-down` vs `offline` in events.
- Panel: probe toggle and stability seconds next to the existing guards.

## Unreleased

- Route check: the AI edges must agree with EACH OTHER, not only with the
  quorum — per-domain routing (claude.ai via VPN, api.anthropic.com direct)
  is now caught as a leak, in both `shuang leaks` and the daemon.
- Doctor: CN-environment signals — a CN/HK/MO system timezone or a zh_CN
  locale behind a foreign exit is reported (Claude Code reads the system
  time zone).
- `shuang run --tz-from-exit`: the child gets `TZ` of the exit country, so
  the timezone Claude Code reports matches the IP it comes from.

## Planned

