# vm-target-basics.md -- the disposable KVM lifecycle

Everything you need that `pilot vm-target --help` does not tell you
about cost, failure modes, and the inventory contract.

## Lifecycle commands

| Command | What it does | Idempotent? |
|---------|-------------|-------------|
| `up`    | Provision VM from cloud image, wait for SSH | No -- creates new overlay each time |
| `list`  | Print JSON/table of all known targets | Read-only |
| `show-inventory` | Print the SSH inventory vm-target would pass to ansible | Read-only |
| `run`   | Execute an ansible playbook against a running target | Yes (ansible idempotency) |
| `wire`  | Idempotently pin a peer target's IP into this target's `/etc/hosts` | Yes (marker-block replace) |
| `exec`  | Run a single command via SSH on the target | No |
| `verify`| Run `pilot verify` against a spec file | Yes for spec checks |
| `snapshot` | Snapshot the VM's qcow2 under a tag | No (additive) |
| `rollback` | Restore qcow2 to a tagged snapshot | Destructive |
| `reset` | Roll back to the pristine post-`up` snapshot (fast dev/test loop) | Destructive |
| `down`  | Destroy + undefine + delete overlay + clear state | Destructive |

## The inventory contract

`vm-target show-inventory` prints a YAML inventory like:

```yaml
all:
  hosts:
    <target-name>:
      ansible_connection: ssh
      ansible_host: <dhcp-ip>
      ansible_user: <ssh-user>
      ansible_port: 22
      ansible_ssh_private_key_file: /var/lib/libvirt/images/pilot/<name>/id_ed25519
      ansible_ssh_common_args: -o StrictHostKeyChecking=no ... -o ControlMaster=auto ...
      ansible_ssh_pipelining: true
```

Key invariants:
- The **only host key** is the target name itself (no extra groups).
- `ansible_ssh_private_key_file` is per-target, per-up (a new keypair is
  generated and the public half is injected via cloud-init seed).
- `ansible_ssh_common_args` includes `ControlMaster=auto`. Do not copy
  this line into a hand-written inventory -- it will clash with `pilot`'s
  connection multiplexing.
- `pilot vm-target run` automatically adds `-l <target-name>`. This is
  how the playbook's `hosts:` pattern matches: the single host key is
  sufficient to satisfy the group pattern.
- This single-target contract only holds for a plain `run --name <n>`.
  `run --group <name>=<t1>,<t2>` (below) produces a *different* shape —
  real `children:` groups spanning multiple target names — and skips the
  `-l` auto-limit entirely, since there is no longer one obvious host.

## Sandbox mode (`--sandbox`) -- the default way to run playbooks

`pilot vm-target run --sandbox` runs `ansible-playbook` **inside a Docker
container** on the host (via `docker cp` + `docker exec`), instead of
requiring `ansible-playbook`/collections installed directly on the host
running `pilot`. This is the `docker-exec` sandbox mode documented in
`README.md`'s "兩種 sandbox 執行模式" section -- the container must ship
its own `ansible-playbook` on `$PATH`.

**Default to `--sandbox` for every `vm-target run` in a spec test**, so
the host driving `pilot` never needs its own ansible install/collections
kept in sync with whatever the playbook needs:

```bash
pilot vm-target run --name <name> --sandbox \
  --sandbox-image geerlingguy/docker-ubuntu2204-ansible:latest \
  playbooks/apply/<role>-apply.yml -e ...
```

Or set it once in `~/.config/pilot/config.yaml` so `--sandbox-image`
never needs repeating:

```yaml
sandbox:
  image: geerlingguy/docker-ubuntu2204-ansible:latest
```

Caveats:
- `--json` (below) is **not supported together with `--sandbox`** --
  the CLI errors out immediately rather than silently ignoring one.
  Use plain-text mode (drop `--sandbox`, or drop `--json`) when you need
  the structured summary.
- The VM's SSH key(s) are auto-mounted read-only into the container; you
  never need to copy keys around by hand.
- `run --group ... --sandbox` mounts **every** referenced target's own
  key (each vm-target VM gets its own generated keypair), so multi-node
  `--group` runs work the same way under sandbox as single-target runs.

Do not confuse this with `references/container-in-vmtesting.md` --
that file is about containers your *playbook* starts **inside** the VM
under test (e.g. a FreeIPA server container). `--sandbox` is about
where `ansible-playbook` itself runs (on the host, inside a throwaway
container) -- it has nothing to do with what the playbook does once it
connects to the VM over SSH.

## `--json`: structured pass/fail instead of scrollback-parsing

```bash
pilot vm-target run --name <name> playbooks/apply/<role>-apply.yml --json
```

Parses ansible's built-in `json` stdout callback into one line per host:

```
  <host>: ok=6 changed=2 failed=0 unreachable=0 skipped=1
```

Use this when you just need a fast triage signal (did anything fail /
change unexpectedly) rather than the full scrollback. For the evidence
you actually paste into a runbook (AGENTS.md §1.1 actual-run), prefer the
plain-text run's PLAY RECAP or the transcript file below -- `--json`'s
raw document is not meant for a human reader.

## Every run writes a transcript -- use it instead of copy-pasting scrollback

Every `vm-target run` (with or without `--sandbox`/`--json`) writes the
full output to `<vm-dir>/<name>/runs/<timestamp>-<playbook>.log` and
prints the path on stderr after the run. When AGENTS.md §1.1 requires
"the real captured output" in a runbook, `cat` this file instead of
manually re-transcribing terminal scrollback -- it is guaranteed to be
the exact, complete bytes ansible produced, including anything that
scrolled past your terminal's buffer.

## `--group`: real ansible groups across multiple vm-target VMs

`show-inventory`/plain `run --name <n>` only ever produce a single-host
inventory (see "The inventory contract" above). Some playbooks need
real cross-host groups instead -- e.g. a FreeIPA primary+replica apply
playbook with `hosts: "{{ target_group | default('ipa_masters') }}"`
that must resolve a `[ipa_masters]`/`[ipa_replicas]` group spanning two
already-`up` VMs. For that:

```bash
pilot vm-target run \
  --group masters=ipa-primary --group replicas=ipa-replica \
  --sandbox --sandbox-image geerlingguy/docker-ubuntu2204-ansible:latest -- \
  playbooks/apply/freeipa-server-replica-apply.yml -e target_group=masters ...
```

- `--name` becomes optional and, if given, only picks which target's
  directory the run transcript is written under -- it does **not**
  restrict which hosts the play runs against.
- No `-l` limit is auto-added; the playbook's own `hosts:` pattern (via
  `-e target_group=<group>`) decides the subset.
- See `references/multi-vm-networking.md` for pairing `--group` with
  `vm-target wire` when the playbook also needs hostname resolution
  between the nodes.

## Disk sizing

The ubuntu-24.04 cloud image root is **2.4 GiB**. Every `--disk N` adds
a qcow2 overlay with virtual size N GiB (sparse, grows on write). Rule
of thumb:

| Role                        | Minimum disk |
|-----------------------------|-------------|
| Config-only (files, systemd)| 20 GiB      |
| Docker / container heavy    | 30 GiB      |
| Database (postgres, mysql)  | 30 GiB      |
| Java (keycloak, jenkins)    | 40 GiB      |

If you hit `no space left on device` during `apt install` or `docker
pull`, the disk was too small. Bump it, `down`, and `up` again.

## ssh timeout vs boot timeout

`--ssh-timeout` (default 2m): how long to wait after the DHCP lease
appears before declaring the VM unreachable.
`--boot-timeout` (default 3m): how long to wait for *any* DHCP lease
at all.

First-time `up` needs longer on both because the cloud image's
`virt-customize` step (pre-installing python3) can take 4-6 minutes
on a cold cache. Pass `--ssh-timeout 8m --boot-timeout 8m` for the
first up of a new image.

## The libguestfs / supermin warning

```
▶ customizing ubuntu-24.04 cloud image to create golden image...
▶ running virt-customize to pre-install dependencies...
[   0.0] Examining the guest ...
virt-customize: error: libguestfs error: /usr/bin/supermin exited with error status 1.
warning: virt-customize failed: exit status 1. Falling back to uncustomized image.
```

This is the optional image-customisation step failing in a chroot-style
environment. The fallback image boots fine and has python3/sudo already.
**Do not chase this warning.**

## dnsmasq lease never appears

Symptom: `... waiting for IP (elapsed 30s) (no active lease for MAC ...)`
forever. Most likely the `default` libvirt network is down:

```bash
sudo virsh net-start default
sudo virsh net-autostart default
```

Also check the host firewall is not blocking DHCP (dnsmasq on port 67).

## Clean slate

When you need a truly clean VM:

```bash
pilot vm-target down --name <name>                          # destroy + undefine
sudo rm -rf /var/lib/libvirt/images/pilot/<name>            # delete qcow2 + seed + key
```

Deleting the per-target dir ensures the next `up` gets a fresh overlay
and a new SSH key -- necessary when the playbook wrote persistent state
outside the VM's filesystem (e.g. bind-mounted data dirs, docker
volumes on the host).

## Useful diagnostics

```bash
# is a VM still known to libvirt even if pilot list doesn't show it?
virsh list --all

# what IP did dnsmasq actually assign?
sudo virsh net-dhcp-leases default

# does the per-target dir still have the old qcow2?
ls -lh /var/lib/libvirt/images/pilot/<name>/
```
