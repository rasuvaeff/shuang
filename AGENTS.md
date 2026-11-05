# AGENTS.md — shuang

Guidance for AI agents working on this package. Read before changing code.

## What this is

`shuang` (霜, "frost") is a per-application kill switch written in Rust: when
the external IP is not on the allowlist, the whole process tree of a protected
application is suspended (`SIGSTOP` on Unix; `NtSuspendProcess` on Windows in
0.2), and resumed when the right IP is back. Modes: `run` (kill switch for one
command, exit 69/75), `check` (one-shot verdict, exit 3), `allow` (persist an
allowlist entry), `daemon` (watch configured apps, tray + notifications),
`leaks` (per-service/edge/DNS/reputation report, exit 4), `doctor`
(environment diagnostics, exit 4), `events`/`stats` (history and VPN health),
`profile` (allowlist profiles). It follows the monorepo's
non-PHP conventions established by `git-gone` (docs, CHANGELOG, SHA-pinned CI)
and ignores the PHP/Composer rules. Public surface: CLI flags, exit codes,
config schema, and the `check --json` document.

## Golden rules

1. **Verification is mandatory.** Never claim "done" without a fresh green
   `cargo fmt --all -- --check` + `cargo clippy --all-targets --locked -- -D warnings`
   + `cargo test --all --locked`. "Should work" does not count.
2. **No suppressions.** No `#[allow(...)]` to silence clippy or
   `dead_code`. Fix the root cause. (`#![deny(unsafe_code)]` stays; when the
   Windows suspend lands, unsafe goes into one module with a documented
   invariant and a file-level exception — discussed, never silent.)
3. **Fail-closed is the product.** An unknown verdict (no quorum, no answer,
   tie between services) is NEVER allowed. Every new code path that cannot
   determine the IP must end in "not allowed". There are no exceptions to
   this rule, including "just one service failed".
4. **Preserve the public contract.** Update `README.md`, `README.ru.md`,
   **and `README.zh.md`** (three languages, same commit), `llms.txt`,
   `CHANGELOG.md`, and tests with any change to flags, exit codes, config, or
   the JSON shape.

## Commands

Rust is on the host (`~/.cargo/bin`; source `$HOME/.cargo/env` if the shell
does not see it).

```bash
cargo fmt
cargo clippy --all-targets --locked -- -D warnings
cargo test --all --locked
cargo run -- check
cargo build --release
```

Full release gate:

```bash
cargo fmt --all -- --check && cargo clippy --all-targets --locked -- -D warnings && cargo test --all --locked
```

`Cargo.lock` is committed (binary crate).

## Invariants & gotchas

- **Fail-closed evaluation** lives in `net::allowed` — the single entry point.
  No mode may evaluate the allowlist any other way. Covered by
  `unknown_verdict_is_never_allowed` and `no_quorum_means_not_allowed`.
- **The quorum is per family.** IPv4 needs `min_agree` agreeing services;
  IPv6 needs one answer but is evaluated with the same `net::allowed` rule —
  an unlisted IPv6 route fails the whole verdict (IPv6 leak detection).
- **The config is never rewritten.** `shuang allow` appends to `state.toml`
  next to the config file; the effective allowlist is the union
  (`Allowlist::merged`). Keep it that way: users keep comments in
  `config.toml`.
- **First-run semantics of `run`:** an empty allowlist allows the startup IP
  (freeze-on-change). This is intentional and documented; do not "fix" it.
- **Freeze before close, always.** The `guard` state machine must freeze on
  the tick the verdict goes bad and may only report `MustClose` on a later
  tick. A zero grace still gets one frozen tick (`zero_grace_closes_on_next_tick`).
- **The whole process tree is frozen**, not just the root pid — Claude Code
  spawns MCP servers, `curl`, `git`. `procs::tree` collects descendants via
  the sysinfo parent map; pids that vanish mid-scan are skipped (nothing to
  freeze). Processes that detached from the parent (daemonized) are out of
  scope for v0.1 — documented, not fixed.
- **Resume exactly what was suspended.** Modes track suspended pids in a
  `HashSet`; resume failures are ignored (the process may be gone), freeze
  failures are simply not recorded. Never resume a pid you did not suspend.
- **Windows is an explicit error, never a silent no-op** (`platform::imp`).
  0.2 brings `NtSuspendProcess` with the tray; until then every control call
  bails with "not implemented on Windows yet".
- **`check --json` is a public contract** (like git-gone's): fields are added
  in minors, never renamed or removed outside a major. Currently:
  `ipv4`, `ipv6`, `country`, `quorum`, `allowed` (all nullable/bool).
- **Config loading is asymmetric by design:** a missing file at the *default*
  path means first run → `Config::default()` (so `check`/`run` work with zero
  setup), while a missing *explicit* `--config` path is an error — a typo must
  never silently run with defaults. Covered by
  `missing_default_config_falls_back_to_defaults` /
  `missing_explicit_config_is_an_error`; keep `explicit` plumbed through every
  mode.
- **Exit codes are a public contract:** 0 ok, 1 error, 3 check-not-allowed,
  4 leaks/doctor-problems-found, 69 run-refused-at-start, 75
  run-stopped-mid-run. 69/75 mirror Kordon so scripts ported from it keep
  working.
- **Clean exit and crash recovery are load-bearing.** Ctrl+C/SIGTERM resumes
  everything frozen (`supervisor::Shutdown` + `Frozen::resume_all`); the
  frozen pid set persists to `state.toml` on every change and
  `Frozen::recover` resumes orphans at mode start. Any new freeze path must
  go through `Frozen` (never raw `platform::suspend`) or recovery breaks.
- **The tray must never block or panic the runtime.** ksni's *blocking*
  facade calls `block_on` and panics inside tokio — always use the async API
  (`TrayHandle::spawn(...).await` / `.status(...).await`). A missing D-Bus
  degrades to headless with a warning, never an error: protection runs on.
- **Notifications are anti-noise by contract** (`notify.rs`): a freeze does
  not notify; a resume under 30s sends ONE low-urgency "blinked for Ns"; a
  freeze over 60s alerts once. The sink is injected — tests collect strings,
  never call the desktop.
- **The grace timer uses `CLOCK_BOOTTIME`** (`mono.rs`), not `Instant`:
  `Instant` stops during suspend and would unfreeze hours later as
  "within grace". All timing in `guard.rs` goes through `crate::mono`.
- **Netlink events mean "verify now", not "freeze now"** (`netwatch.rs`):
  freezing blindly on any route change produces false freezes. The watcher
  is best-effort — polling stays as the backstop.
- **Country cache is keyed by /24 (v4) / /64 (v6)**: one flaky country-service
  answer must not re-freeze a confirmed exit, but a *different prefix* is a
  different exit and must be re-verified. Do not widen the key.
- **Per-app rules are additive unions** (`Allowlist::with_extra`): app rules
  only widen, never narrow, the global allowlist — a stricter app config is
  expressed by a stricter global/profile list, not by subtractive rules.
- **Property tests must keep passing** (`net.rs::properties`): allowed ⇔
  deny_reason is None; no quorum is never allowed; the allowlist is
  monotone; country allows are IP-agnostic. A failing property is a design
  bug, not a flaky test.
- **Tests never touch the real network.** Integration tests point
  `ip_services` at a local mock HTTP server (`tests/integration.rs`); the
  quorum logic runs exactly as in production. A test that needs the real
  services is a bug.
- **`min_agree` ties are ambiguous → unknown.** Two different IPs with equal
  counts resolve to `None`, not to the first answer (`tie_is_ambiguous`).
- **Interval validation:** `interval_secs = 0` must be rejected at mode entry
  (`run`/`daemon` bail), not patched with `.max(1)` at every use site.
- **Module layout:** `cli.rs` (flags), `config.rs` (config + state I/O),
  `ipcheck.rs` (HTTP checks + quorum), `net.rs` (pure allowlist logic — no
  I/O, heavily unit-tested), `procs.rs` (tree + matching via sysinfo),
  `platform.rs` (process control per OS), `guard.rs` (pure freeze/grace/close
  state machine), `run.rs`/`daemon.rs`/`check.rs`/`allow.rs` (modes),
  `main.rs` (dispatch only). Keep I/O out of `net.rs` and `guard.rs`.
- **`main` returns `ExitCode`**, it does not call `std::process::exit`.
- Code: `#![deny(unsafe_code)]`, `cargo fmt` formatting, explicit types, `?`
  for propagation. Unit tests next to the code; `tests/integration.rs` drives
  the built binary (`CARGO_BIN_EXE_shuang`).
- **CI workflows are SHA-pinned** (copied from git-gone's, same conventions:
  `permissions: { contents: read }`, `persist-credentials: false`,
  `concurrency`, Dependabot with a 7-day cooldown). Verify with
  `zizmor --persona=auditor .github/` before release. The release workflow
  publishes `.sha256` files that both installers verify — a release without
  them makes the installers fail closed (deliberate).
- **Installer contract:** `INSTALL_DIR` honored or fail; only the default may
  fall back. `VERSION=vX.Y.Z` selects the release asset. Adapted from
  git-gone's scripts — keep them in sync when the asset naming changes.
- **Docs are trilingual:** `README.md` (EN), `README.ru.md` (RU),
  `README.zh.md` (ZH) — the Chinese README is first-class (the tool's
  audience includes China); any doc change lands in all three in one commit.

## Roadmap (keep the exit-code and config contracts stable)

- 0.2: Windows suspend/resume (`NtSuspendProcess`), tray icon, network event
  subscription (netlink / SCNetworkReachability / INetworkListManager) for
  instant reaction instead of polling.
- Later: system notifications (`notify-rust` / Windows toasts), route checks
  against the AI services' own `/cdn-cgi/trace`, `aarch64-unknown-linux-ohos`
  build if HarmonyOS PC demand appears.
- Out of scope by design: any cloud component, accounts, telemetry.

## Releases

- Bump `version` in `Cargo.toml` **in the release commit** (2026-11-05: the
  v0.2.0 binaries reported `0.1.0` because this was forgotten — cost a v0.2.1
  re-release, since re-tagging is forbidden). The binary reports
  `CARGO_PKG_VERSION`, and `shuang update` compares it with the release tag.
- `fs::rename` does not cross filesystems (EXDEV): temp files that will be
  renamed over the target must live next to the target, not in `/tmp`
  (2026-11-05: `shuang update` shipped broken in v0.3.0 because of this).
- The rest of the flow: CHANGELOG dated → PR → green CI → merge → tag on the
  merged HEAD (once) → verify clean install.

## When you finish

- Update `README.md`, `README.ru.md`, **and `README.zh.md`** (same commit) and
  `llms.txt`; update `CHANGELOG.md` when flags, exit codes, or the JSON shape
  change.
- Re-run the full release gate and paste the output.
- If `.github/workflows/*.yml` changed, run `zizmor --persona=auditor .github/`
  and confirm it is clean.
