# Changelog

## Unreleased

- Initial implementation: `run` (kill switch for one command, exit codes
  69/75), `check` (one-shot IP verdict, JSON and human output, exit code 3),
  `allow` (persistent IP/subnet/country entries in `state.toml`), and
  `daemon` (watch configured apps).
- Quorum-based IPv4 + IPv6 checks with fail-closed evaluation; IPv6 leak
  detection; freeze/resume of whole process trees via `SIGSTOP`/`SIGCONT`
  on Linux and macOS.
- A missing config file at the default location falls back to built-in
  defaults (first run works with no setup); an explicitly passed `--config`
  that does not exist is an error, not a silent default.
