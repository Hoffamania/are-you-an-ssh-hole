<p align="center">
  <img src="assets/logo.svg" width="120" alt="are-you-an-ssh-hole logo">
</p>
<p align="center"><sub>Asterisk motif inspired by <a href="https://axelhow.com/2013/01/19/vonnegut-asterisk/">Kurt Vonnegut's asterisk</a> in <i>A Man Without a Country</i> — original artwork, not a reproduction.</sub></p>

# are-you-an-ssh-hole

[![ci](https://github.com/Hoffamania/are-you-an-ssh-hole/actions/workflows/ci.yml/badge.svg)](https://github.com/Hoffamania/are-you-an-ssh-hole/actions/workflows/ci.yml)

A **local** detector for *sshole* ([**CVE-2026-123158**](https://nvd.nist.gov/vuln/detail/CVE-2026-123158)),
the OpenSSH authentication bypass on musl-based Linux. On musl libc (Alpine,
OpenWRT, Buildroot, Yocto, many Docker base images), `crypt()` returns the
single character `*` on failure — including when its SHA-256/SHA-512 hash
refuses a password over 256 bytes. An account whose `/etc/shadow` field is
exactly `*` (meant to be unmatchable) then matches that return value, so
non-PAM `sshd` accepts the login. On Alpine this exposes `root` (3.16+).

- **CVE:** CVE-2026-123158 · CVSS 8.1 (High) · CWE-394 · disclosed Nov 2026.
- **Status:** actively exploited in the wild — patch urgently.
- **Fix:** OpenSSH **10.6p2** (and Alpine backports); or `PasswordAuthentication no` as a stopgap.

## The tool lives in [`are-you-an-ssh-hole/`](are-you-an-ssh-hole/)

| file | purpose |
|------|---------|
| [`are-you-an-ssh-hole.sh`](are-you-an-ssh-hole/are-you-an-ssh-hole.sh) | on-host audit; `VULNERABLE` / `NOT_VULNERABLE` / `NEEDS_REVIEW` via exit code |
| [`are-you-an-ssh-hole-fleet.sh`](are-you-an-ssh-hole/are-you-an-ssh-hole-fleet.sh) | runs the audit across hosts you administer, over your own SSH |
| [`test/run-tests.sh`](are-you-an-ssh-hole/test/run-tests.sh) | 40 unit + integration tests |
| [`README.md`](are-you-an-ssh-hole/README.md) | full checks, fixed-version table, usage |

```sh
are-you-an-ssh-hole/are-you-an-ssh-hole.sh          # audit this host
are-you-an-ssh-hole/are-you-an-ssh-hole.sh --json   # machine-readable record
are-you-an-ssh-hole/are-you-an-ssh-hole-fleet.sh --hosts hosts.txt --sudo --json > report.json
```

## Detect, don't exploit

Everything runs **on a host** and inspects its own configuration — **no network
connections and no authentication attempts against anything.** Confirming this
bug by logging in over the network *is* the bypass, so there is deliberately no
remote-probe mode. To cover a fleet, the runner executes the local audit over
SSH access you already hold.

## CI

Every push and pull request runs the test suite and validates the detector
inside real **musl** (`alpine:3.20`) and **glibc** (`debian:bookworm-slim`)
containers: the `crypt()` defect must be present on musl and absent on glibc.

## References

- CVE record: [CVE-2026-123158 (NVD)](https://nvd.nist.gov/vuln/detail/CVE-2026-123158)
- Disclosure (Orca Security): [*sshole* OpenSSH authentication bypass](https://orca.security/resources/research/sshole-openssh-authentication-bypass-gives-attackers-root-on-alpine-linux/)
- Technical write-up: [sshhole.com](https://sshhole.com/)
- OpenSSH patches: [SecurityWeek](https://www.securityweek.com/openssh-rushes-patches-for-sshole-authentication-bypass/)
- In-the-wild exploitation: [The Hacker News](https://thehackernews.com/2026/11/hackers-exploited-openssh-sshole-flaw.html) · [Help Net Security](https://www.helpnetsecurity.com/2026/11/06/openssh-sshole-cve-2026-123158-exploitation/)
- Related root cause: [CVE-2016-6210](https://nvd.nist.gov/vuln/detail/CVE-2016-6210) (username enumeration; its fix introduced the salt-borrowing path)
- Logo inspiration: [Kurt Vonnegut's asterisk](https://axelhow.com/2013/01/19/vonnegut-asterisk/) (*A Man Without a Country*) — the logo is original artwork, not a reproduction
