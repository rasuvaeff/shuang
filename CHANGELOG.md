# Changelog

## Unreleased

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

## Planned

- Panel: manage protected apps — `[[apps]]` in `state.toml` merged with the
  config (same never-rewrite-config pattern as settings), plus a picker of
  running processes with auto-generated match patterns.
- `shuang update`: check GitHub Releases, download the platform binary,
  verify the published `.sha256`, atomically replace self (explicit,
  user-initiated — no background checks).
