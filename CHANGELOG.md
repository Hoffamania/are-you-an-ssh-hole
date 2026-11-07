# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-11-07

Initial release — a **local** detector for *sshole*
([CVE-2026-123158](https://nvd.nist.gov/vuln/detail/CVE-2026-123158)), the
OpenSSH authentication bypass on musl-based Linux.

### Added
- `are-you-an-ssh-hole.sh` — on-host audit returning `VULNERABLE` /
  `NOT_VULNERABLE` / `NEEDS_REVIEW` via exit code (`1` / `0` / `2`). Checks:
  libc is musl; the `crypt()` defect reproduced in isolation
  (`crypt(<300 bytes>, "$6$...") == "*"`); OpenSSH patch status (Alpine per-branch
  table verified against Alpine `secdb`, else upstream `10.6p2`); a `*` shadow
  account; a SHA-256/512 donor account; and PAM shielding.
- `--json` structured output (schema `are-you-an-ssh-hole/v1`): the verdict plus
  the evidence behind it.
- `--crypt-probe` — just the isolated `crypt()` behavior check.
- `are-you-an-ssh-hole-fleet.sh` — run the audit across a hosts file over your
  own SSH (`BatchMode`, key-only; `--sudo`, `--jobs`, `--out`). `--json` emits an
  aggregated fleet report (schema `are-you-an-ssh-hole-fleet/v1`) with a summary
  and per-host records.
- `examples/ansible/` — a playbook and example inventory to audit an inventory
  of hosts.
- GitHub Actions CI validating the detector on real **musl** (`alpine:3.20`) and
  **glibc** (`debian:bookworm-slim`) images, plus a 46-test suite.
- Project README, tool README, MIT `LICENSE`, `SECURITY.md`, and an original
  asterisk logo.

### Security
- Detect-only by design: the tooling makes no network connections and attempts
  no authentication against any host. There is no remote-probe or exploitation
  mode.

[1.0.0]: https://github.com/Hoffamania/take_home_test/releases/tag/v1.0.0
