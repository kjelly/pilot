# vm-target-basics.md -- the disposable KVM lifecycle

What `pilot vm-target --help` does not tell you about cost, failure modes
and the inventory contract. Checked against `cmd/pilot/cmd/vm_target*.go`
and `internal/vmtarget`; re-check `--help` when in doubt. The operator
runbook is [docs/runbooks/vm-target.md](../../../../docs/runbooks/vm-target.md).

## Command map

| Command | What it does | Notes |
|---------|-------------|-------|
| `up` | Provision a VM from a base image, wait for a DHCP lease and SSH | Refuses a name already in state or libvirt. Takes the `clean` checkpoint `reset` returns to |
| `test` | L1 syntax → L3 `--check --diff` → snapshot → L4 apply → L5 verify → L6 idempotency, rollback on failure | Needs a running VM; never provisions |
| `topology up/status/inventory/down` | Bring up, inspect, render or tear down a whole multi-VM scenario | See `multi-vm-networking.md` |
| `topology test` | `test` over a topology; `--ephemeral` provisions fresh nodes and tears them down | See `multi-vm-networking.md` |
| `topology snapshot/rollback/reset` | The single-VM operation on every node, concurrently; `rollback`/`reset` re-wire | |
| `list` | Every VM in pilot state, with live status | Shows other sessions' VMs too |
| `show-inventory` | The SSH inventory `run`/`verify` pass to Ansible | Read-only |
| `run` | `ansible-playbook` against a running VM | Debugging; preflight syntax check |
| `verify` | `pilot verify <spec>` against the VM | Adds `-l <vm>` unless you pass `-l` |
| `exec` / `ssh` / `shell` | One command / an interactive session over SSH | `exec` runs no host shell |
| `wire` | Pin peer VMs' IPs into this VM's `/etc/hosts` | Idempotent marker block |
| `snapshot` / `rollback` | libvirt qcow2 snapshot under a tag / revert to it | `rollback` is destructive |
| `reset` | Revert to the `clean` checkpoint from `up` | Seconds; drops `wire` blocks |
| `resize-disk` | Grow the root disk (`--disk <GiB>`, grow only) | Online if running |
| `down` | Destroy, undefine, delete the per-target directory, clear state | Destructive |

## The inventory contract

`vm-target show-inventory --name <vm>` prints (abridged):

```yaml
all:
  hosts:
    <vm>:
      ansible_connection: ssh
      ansible_host: <dhcp-ip>
      ansible_user: <ssh-user>
      ansible_port: 22
      ansible_ssh_private_key_file: /var/lib/libvirt/images/pilot/<vm>/id_ed25519
      ansible_ssh_args: -o ControlMaster=auto -o ControlPath="/tmp/pilot-vmt-<uid>-<hash>/%C" -o ControlPersist=60s
      ansible_ssh_common_args: -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
      ansible_ssh_pipelining: true
  children:
    <alias>:            # one per --hosts alias given at `up`
      hosts:
        <vm>: {}
```

- The VM is exactly one host, keyed by its name. A `--hosts` alias is a
  group holding that host, so `-l <alias>`, `-e target_group=<alias>` and a
  spec whose targets are that group all select this VM
  ([vm-target.md](../../../../docs/runbooks/vm-target.md) §5.4).
- The private key is per VM and per `up`; cloud-init injects the public half.
- The ControlPath sits in `ansible_ssh_args` (Ansible puts `ssh_args`
  first and OpenSSH keeps the first value), in a per-VM directory under
  `/tmp` (`$PILOT_SSH_CONTROL_BASE` overrides `/tmp`). `show-inventory`
  creates it; `down` removes it. Do not copy these lines into a hand-written
  inventory.
- `run --name <vm>` and `test` add `-l <vm>` unless the extra args set
  `target_group`. `run --group` renders real multi-host groups and adds no
  `-l` (below).
- `--ssh-user` defaults to `root`; cloud-init sets `disable_root: false` and
  writes the key, so root works on the stock images.

## Running Ansible: host or `--sandbox`

`test` and `topology test` always run the host's `ansible-playbook`. Only
`run` has a sandbox mode:

```bash
pilot vm-target run --name <vm> --sandbox --sandbox-image pilot-cli:latest \
  playbooks/apply/<role>-apply.yml -e @~/.vault/<role>-sandbox.yaml
```

- The image comes from `--sandbox-image` or `sandbox.image` in
  `~/.config/pilot/config.yaml`. It must ship `ansible-playbook`, the
  collections and an **ssh client**. Build the repo's control-node image
  once: `docker build -t pilot-cli:latest -f images/Dockerfile.pilot-cli .`.
  `geerlingguy/docker-ubuntu2204-ansible` has no ssh client and cannot
  reach the VM ([freeipa-dns-client.md](../../../../docs/runbooks/freeipa-dns-client.md)).
- `run`'s syntax-check preflight still uses the host `ansible-playbook`;
  pass `--skip-syntax-check` on a host without Ansible.
- The container gets the nearest enclosing `playbooks/` tree (so includes
  across `apply/`, `check/`, `decommission/` resolve), the inventory with
  key paths rewritten, every referenced VM's key (read-only), and each
  `-e @file` (a leading `~` is expanded on the host first).
- `--json` cannot be combined with `--sandbox`; the CLI refuses.

`references/container-in-vmtesting.md` is a different topic: containers the
playbook starts inside the VM.

## `--json`

`pilot vm-target run --name <vm> <playbook> --json` prints one
`<host>: ok=… changed=… failed=… unreachable=… skipped=…` line per host and
keeps the raw JSON in the transcript. Use it for triage, not as evidence.

## Run transcripts

Every `vm-target run` writes `<vm-dir>/<vm>/runs/<UTC>-<playbook>.log` and
prints the path after the run. `down` deletes that directory, so copy a
transcript you need into `.verification/` first. `test` and `topology test`
write no transcript; tee their output (SKILL.md §5). A transcript is raw
output: it belongs in `.verification/`, never in a runbook or spec
(AGENTS.md §1.2).

## `--group`: real groups across several running VMs

```bash
pilot vm-target run --name ipa-ha-client \
  --group freeipa-server=ipa-primary \
  --group freeipa-client=ipa-ha-client \
  --sandbox --sandbox-image pilot-cli:latest \
  playbooks/apply/freeipa-client-apply.yml -e target_group=freeipa-client
```

- Each value is `group=target1,target2`; repeatable; every member must be
  running.
- `--name` only picks whose `runs/` directory gets the transcript and must
  be a member. No `-l` is added: `-e target_group=<group>` or the playbook's
  `hosts:` decides.
- Use the production role-group names the playbook reads (for example
  `groups['freeipa-server']`), not ad-hoc labels; see
  [freeipa-server-replica-ha-drill.md](../../../../docs/runbooks/freeipa-server-replica-ha-drill.md) §1.
- A scenario you will rerun belongs in a topology file instead
  (`multi-vm-networking.md`).

## Disk, memory, timeouts

Defaults: 30 GiB disk, 2048 MiB, 2 vCPUs, network `default`, SSH user
`root`. `--disk` is a sparse qcow2 overlay, so a large value costs little
until written. Raise `--memory` for Java, database and FreeIPA roles. On
`no space left on device`, grow the disk with
`pilot vm-target resize-disk --name <vm> --disk <GiB>`; the guest still has
to grow its partition and filesystem (`--help` shows the commands).

`--boot-timeout` (default 3m) bounds the wait for a DHCP lease;
`--ssh-timeout` (default 2m) bounds the wait for SSH after that. Slow first
boots need more (the FreeIPA topology uses `8m` for both). When either runs
out, `up` tears the VM down unless you passed `--keep-on-failure`.

The first `up` of an image alias downloads it into `<vm-dir>/images/` and
builds a golden copy with `virt-customize` before any VM boots; neither
timeout covers that step.

## The libguestfs / supermin warning

```
▶ customizing ubuntu-24.04 cloud image to create golden image...
▶ running virt-customize to pre-install dependencies...
virt-customize: error: libguestfs error: /usr/bin/supermin exited with error status 1.
warning: virt-customize failed: exit status 1. Falling back to uncustomized image.
```

The optional golden-image customisation failed and pilot fell back to the
plain cloud image, which boots fine. **Do not chase this warning.**

## dnsmasq lease never appears

Symptom: `waiting for IP ... (no active lease for MAC ...)` until the boot
timeout. The libvirt network is usually down:

```bash
sudo virsh net-start default
sudo virsh net-autostart default
```

A short wait for the first lease is normal. Also check that the host
firewall does not block DHCP (dnsmasq, port 67).

## Host-local cache services

See SKILL.md §0.1 for when to use it and
[vm-target.md](../../../../docs/runbooks/vm-target.md) §2.2 for detail.
Cache data lives on the host (`~/.local/share/pilot/cache/` by default),
apart from any VM. `vm-target down` never touches it; `pilot services down`
stops the containers and keeps the data; only `pilot services purge --confirm`
deletes it.

## Clean slate

When you need a truly clean VM of your own (one this session created):

```bash
pilot vm-target down --name <name>    # destroy, undefine, delete /var/lib/libvirt/images/pilot/<name>/
pilot vm-target up   --name <name> ...
```

`down` removes the per-target directory (overlay, seed ISO, SSH key, run
transcripts), the static DHCP reservation, the SSH control directory and the
cached facts, so the next `up` gets a fresh overlay and a new SSH key.
Everything the VM wrote, Docker bind mounts and volumes included, is inside
that overlay: no host directory is shared into the VM. To go back to the
post-`up` state without re-provisioning, `pilot vm-target reset --name <name>`
is faster.

Never `rm -rf` under `/var/lib/libvirt/images/pilot` yourself. Every clone and
session on the host shares that directory (and `images/` holds the base
images); a hand delete can remove another session's running VM disk. A
directory left behind after a successful `down` is a teardown bug to report.

## Fact cache after `reset` or `rollback`

The repo `ansible.cfg` caches facts (`gathering = smart`, jsonfile cache in
`~/.ansible/pilot-factcache`, 3600 s). `up` and `down` drop the VM's
entries; `reset` and `rollback` do not, so a reverted VM can still be
served facts gathered before the revert. If the playbook branches on facts,
delete your VM's `s1_<name>` entry before the next run
([vm-target.md](../../../../docs/runbooks/vm-target.md) §5.4).

## Useful diagnostics

```bash
# is a VM still known to libvirt even if pilot list doesn't show it?
virsh list --all

# what IP did dnsmasq actually assign?
sudo virsh net-dhcp-leases default

# does your VM's per-target dir still exist?
ls -lh /var/lib/libvirt/images/pilot/<name>/
```
