# are-you-an-ssh-hole

A **local** detector for *sshole, the OpenSSH authentication bypass on
musl-based Linux ([Orca Security disclosure][orca]). On musl libc (Alpine,
OpenWRT, Buildroot, Yocto, many Docker base images), `crypt()` returns the
single character `*` on failure — including for passwords over its 256-byte
limit. An account whose `/etc/shadow` field is `*` (meant to be unmatchable)
then *matches* that return value, and non-PAM `sshd` accepts the login. On
Alpine this exposes `root` (3.16+).

Tracked as [CVE-2026-123158](https://nvd.nist.gov/vuln/detail/CVE-2026-123158)
(CVSS 8.1 High, CWE-394). **Actively exploited in the wild** — root access was
confirmed on an Alpine honeypot within hours of disclosure, so patch urgently.

## What it does — and does not do

Runs **on a host** and inspects that host's own configuration. Makes **no
network connections** and attempts **no authentication** against anything. It
is a configuration/behavior audit, not a scanner that logs into things.

It does not probe remote machines. Confirming this bug by logging in over the
network *is* the bypass; a tool that did that would be an auth-bypass scanner
regardless of intent. To check many machines, run this on each one over access
you already hold (e.g. config management or your own SSH keys).

## Affected when ALL hold (per the disclosure)

- libc is **musl**;
- OpenSSH is **not patched** (see table);
- sshd is built **without PAM**, or runs with `UsePAM no`;
- an account's `/etc/shadow` password field is exactly `*`;
- at least one local account has a **SHA-256 (`$5$`) or SHA-512 (`$6$`)** hash
  (the "donor" salt sshd borrows).

Not affected: glibc/libxcrypt, PAM-enabled sshd, Dropbear, non-Linux.

## Checks

| Signal | How |
|--------|-----|
| libc is musl | `/lib/ld-musl-*.so.1`, `ldd --version` |
| `crypt()` defect present | reproduces `crypt(<300 bytes>, "$6$...") == "*"` in isolation (sha512crypt refusing the over-long password) |
| OpenSSH patched | Alpine: `apk version` vs the per-branch fixed version; else upstream vs `10.6p2` |
| `*` account exposed | `/etc/shadow` fields equal to exactly `*` (not `!`, `!!`, `*0`, a hash) |
| SHA donor account | any `$5$`/`$6$` account in `/etc/shadow` |
| PAM shielding | `UsePAM yes` + a PAM stack present |

A host is `VULNERABLE` only when the musl `crypt()` defect is present, OpenSSH
is confirmed **unpatched**, a `*` account and a SHA donor account both exist,
sshd is installed, and PAM is not shielding the path. Because PAM detection and
some version mappings are heuristic, unresolved cases return `NEEDS_REVIEW`
rather than a false all-clear. The `crypt()` gate matters: `*` accounts exist on
nearly every Unix host, but on glibc `crypt()` never returns `*`.

## Fixed versions

Upstream: **OpenSSH 10.6p2**. Alpine backports:

| branch | fixed `openssh` |
|--------|-----------------|
| edge | `10.6_p2-r0` |
| 3.24 | `10.3_p1-r2` |
| 3.23 | `10.2_p1-r1` |
| 3.22 | `10.0_p1-r11` |
| 3.21 | `9.9_p2-r1` |
| 3.20 | `9.7_p1-r6` |

Restart `sshd` after upgrading — the package upgrade does not replace the
running daemon. If you cannot patch, `PasswordAuthentication no` closes the
hole. Check auth logs for `Accepted password for` on passwordless accounts and
treat any such host as compromised.

## Usage

```sh
./are-you-an-ssh-hole.sh              # full audit (run as root for a definitive shadow read)
./are-you-an-ssh-hole.sh --crypt-probe   # just the isolated crypt() behavior check
```

Exit codes: `0` NOT_VULNERABLE · `1` VULNERABLE · `2` NEEDS_REVIEW.

## Fleet audit

`are-you-an-ssh-hole-fleet.sh` runs the local audit across hosts you already administer. For
each host it opens an SSH session **with your own credentials** (`BatchMode` is
forced on, so it is key-based only and can never fall back to sending a
password), pipes `are-you-an-ssh-hole.sh` in over stdin, runs it there, and aggregates
the verdicts. It does no password probing and no bypass — it only orchestrates
the safe local detector over access you hold.

```sh
./are-you-an-ssh-hole-fleet.sh host1 user@host2
./are-you-an-ssh-hole-fleet.sh --hosts hosts.txt --sudo --jobs 20 --out results/
```

`--sudo` runs the remote audit under `sudo -n` (needs passwordless sudo) for a
definitive `/etc/shadow` read. Exit: `0` all clear · `1` any VULNERABLE · `2`
any NEEDS_REVIEW / UNREACHABLE / ERROR.

This is the intended "scan my network" path: detection runs locally on each
machine via legitimate access, never a blind probe against hosts you cannot
already log into.

## Tests

```sh
sh test/run-tests.sh
```

The verdict logic is a pure function unit-tested against fixtures; the shadow
scanners are tested against synthetic files. No musl host is needed to run the
tests.

[orca]: https://orca.security/resources/research/sshole-openssh-authentication-bypass-gives-attackers-root-on-alpine-linux/
