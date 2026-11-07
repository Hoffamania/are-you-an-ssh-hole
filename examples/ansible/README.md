# Ansible example

Run the [`are-you-an-ssh-hole`](../../are-you-an-ssh-hole/) audit across an
inventory of hosts. Detection runs **locally on each host** over the SSH access
Ansible already uses — no password probing and no bypass, same as the fleet
runner.

## Usage

```sh
# edit inventory.ini to list your own hosts
ansible-playbook -i inventory.ini sshole-audit.yml
```

Each host prints a verdict and the full audit report, and the play **fails for
any host that is `VULNERABLE`** — so a non-zero playbook exit means at least one
host needs patching, which is handy in CI or a cron job.

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
