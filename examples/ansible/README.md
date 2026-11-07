# Ansible example

Run the [`are-you-an-ssh-hole`](../../are-you-an-ssh-hole/) audit across an
inventory of hosts. Detection runs **locally on each host** over the SSH access
Ansible already uses — no password probing and no bypass, same as the fleet
runner.

## Usage

```sh
# edit inventory.ini to list your own hosts
ansible-playbook -i inventory.ini sshole-audit.yml
ansible-playbook -i inventory.ini sshole-audit.yml -e sshole_report=/tmp/report.json
```

Each host prints a verdict, and the play **fails for any host that is
`VULNERABLE`** — so a non-zero playbook exit means at least one host needs
patching, which is handy in CI or a cron job.

To just **collect a report without failing** on vulnerable hosts (so the run
completes cleanly across the whole fleet), pass
`-e sshole_fail_on_vulnerable=false`. The report is written either way — the
switch only controls whether the play exits non-zero.

### Aggregated report

The run also writes one JSON report on the control node (default
`sshole-report.json`, override with `-e sshole_report=PATH`) — schema
`are-you-an-ssh-hole-fleet/v1`, the same shape the fleet runner's `--json`
produces: a `summary` with counts and a `hosts` array of per-host records. This
is your fleet-wide "what still needs patching" artifact.

## Notes

- **Root:** a definitive `/etc/shadow` read needs root. The example sets
  `ansible_become=true`; drop it only if you accept `NEEDS_REVIEW` where shadow
  is unreadable.
- **No Python required:** the playbook uses the `script` module, so it works on
  minimal Alpine images that have no Python (most Ansible modules would fail
  there).
- **crypt() helper:** the isolation probe needs `python3` or a C compiler on the
  target. Without one, musl hosts report `NEEDS_REVIEW` instead of a definitive
  verdict. Add `-e sshole_install_crypt_helper=true` to install `python3` first.
- **Exit codes** (per host): `0` NOT_VULNERABLE, `1` VULNERABLE, `2` NEEDS_REVIEW.
- **Unreachable hosts:** a host Ansible can't SSH to appears in the run recap as
  `unreachable` rather than in the JSON report (no task can run on it). The fleet
  runner, by contrast, synthesizes a record for such hosts.
