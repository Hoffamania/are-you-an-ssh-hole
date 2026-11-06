# sshole-detector

A **local** detector for the musl/OpenSSH `*`-password authentication bypass
(the "sshole" issue): on musl libc (Alpine, OpenWRT, Buildroot, Yocto, many
Docker base images), `crypt()` returns the single character `*` when it cannot
produce a hash — including for passwords over its 256-byte limit. Accounts whose
`/etc/shadow` password field is `*` (a value meant to be unmatchable) then
*match* that return value, so `sshd` accepts the login.

## What it does — and does not do

This tool runs **on a host** and inspects that host's own configuration. It
makes **no network connections** and attempts **no authentication** against any
system. It is a configuration/behavior audit, not a scanner that logs into
things.

It does not probe remote machines. Confirming this bug by logging in over the
network *is* the bypass; a tool that did that would be an auth-bypass scanner
regardless of intent. To check many machines, run this on each one over access
you already hold (e.g. via your config-management or your own SSH keys).

## Checks

| Signal | How |
|--------|-----|
| libc is musl | `/lib/ld-musl-*.so.1`, `ldd --version` |
| `crypt()` defect present | reproduces `crypt(<300 bytes>, "*") == "*"` in isolation |
| accounts exposed | `/etc/shadow` fields equal to exactly `*` (not `!`, `!!`, `*0`, or a real hash) |
| sshd present / version | `sshd -V` |
| PAM shielding | `UsePAM yes` + a PAM stack that never calls `crypt()` for `*` |

A host is reported `VULNERABLE` only when the musl `crypt()` defect is actually
present **and** at least one `*` account exists **and** sshd is installed
**and** PAM is not shielding that path. The `crypt()` gate matters:
`*` accounts exist on virtually every Unix system, but on glibc/libxcrypt
`crypt()` does not return `*`, so those hosts are not affected.

## Usage

```sh
./sshole-audit.sh              # full audit (run as root for a definitive shadow read)
./sshole-audit.sh --crypt-probe   # just the isolated crypt() behavior check
```

Exit codes: `0` NOT_VULNERABLE · `1` VULNERABLE · `2` NEEDS_REVIEW.

## Tests

```sh
sh test/run-tests.sh
```

The verdict logic is a pure function unit-tested against fixtures; the
`/etc/shadow` scanner is tested against synthetic files. No musl host is needed
to run the tests.
