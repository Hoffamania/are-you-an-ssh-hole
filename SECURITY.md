# Security Policy

## Scope

This policy covers **this project** — the `are-you-an-ssh-hole` detector and
its tooling. It is not the place to report the underlying OpenSSH/musl
vulnerability it detects ([CVE-2026-123158](https://nvd.nist.gov/vuln/detail/CVE-2026-123158));
report that to the OpenSSH and distribution maintainers.

## What this tool does (and does not) do

The detector runs **locally on a host** and inspects that host's own
configuration. It makes **no network connections** and attempts **no
authentication against any system**. There is deliberately no remote-probe or
exploitation mode. Use it only on systems you are authorized to inspect.

## Supported versions

Security fixes are applied to the `main` branch. There are no separately
maintained release branches.

## Reporting a vulnerability

If you find a security issue **in this tool** (for example, a way it could be
abused, a false "not vulnerable" result that hides a real exposure, or a flaw
in the fleet runner's SSH handling):

1. Prefer GitHub's private reporting: the repository's **Security** tab →
   **Report a vulnerability** (private advisory). This keeps details out of
   public view until a fix is available.
2. If private reporting is unavailable, open an issue **without** sensitive
   exploit details and ask for a private channel.

Please do not include working exploit payloads in public issues or pull
requests. We aim to acknowledge reports within a few days.
