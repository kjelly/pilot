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
| `topology up/down/inventory/status` | Bring up/tear down/inventory/inspect an entire named multi-VM scenario from one YAML spec | `up` yes (skips already-running nodes) |
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
- `--group` is for combining VMs you already brought up ad hoc. If the
  same named scenario (which nodes, which groups, which wire pairs)
  gets reused across resets or CI runs, declare it once instead as a
  `vm-target topology` spec -- see below.

## `vm-target topology`: one spec file for an entire multi-VM scenario

`up`/`wire`/`--group` compose, but hand-assembling their sequence means
parsing each step's printed IP to build the next command, and
re-deriving the same sequence by hand every time the scenario resets.
`vm-target topology` makes the scenario declarative:

```yaml
# ha-topology.yaml
nodes:
  - name: ipa-primary
    base_image: rocky9
    groups: [ipa_masters]
    wire: [ipa-replica, ipa-ha-client]
  - name: ipa-replica
    base_image: rocky9
    groups: [ipa_replicas]
    wire: ["ipa-primary=ipa1.ipa.pilot.internal"]
```

```bash
pilot vm-target topology up        --topology ha-topology.yaml
pilot vm-target topology status    --topology ha-topology.yaml
pilot vm-target topology inventory --topology ha-topology.yaml
pilot vm-target topology down      --topology ha-topology.yaml
pilot vm-target topology snapshot  --topology ha-topology.yaml --tag pre-drill
pilot vm-target topology rollback  --topology ha-topology.yaml --tag pre-drill
pilot vm-target topology reset     --topology ha-topology.yaml
```

- `up` provisions every not-yet-running node **concurrently** -- one
  `*vmtarget.Manager` per node, all pointed at the same state dir.
  Concurrent `vm-target up` calls used to race and lose a VM's state;
  the 2026-07-06 fix (see the `pilot-vm-target-up-concurrency-race`
  memory, AGENTS.md §5.1) closed that for good -- `Manager.Up` reserves
  its name via `Store.Mutate` (cross-process flock) before touching
  disk/libvirt, so concurrent `Up` for different names is safe
  (`TestUp_ConcurrentDifferentNames_BothPersist`). It's one `Manager`
  per goroutine, not several goroutines sharing one `Manager` --
  `Manager.Up` holds an in-process lock for its entire call (including
  the multi-minute boot/SSH wait), so goroutines on a shared `Manager`
  would just queue instead of overlapping.
- `up` is idempotent at the node level: an already-running node (same
  name) is skipped, so re-running `up` after adding a node to the spec
  only provisions the new one.
- After bring-up, `up` wires every node's declared `wire:` peers
  automatically (same mechanism as `vm-target wire --peer`) -- no
  manual IP copy-paste between steps.
- `inventory` renders the same grouped inventory `run --group` does
  (`RenderGroupedInventory`), from the `groups:` each node declares --
  requires every node to already be `running`.
- `status` prints a name/status/ip/groups/wire table for just this
  spec's nodes, without needing to grep `vm-target list`.
- `snapshot`/`rollback`/`reset` apply the single-VM operation of the same
  name to every node in the spec concurrently -- for checkpointing or
  restoring an entire scenario at once (e.g. "can replica-install rerun
  from a clean cluster?") instead of resetting each VM by hand and
  re-running `wire` yourself. Because the "clean" snapshot `up` captures
  automatically predates wiring, `rollback`/`reset` re-apply every node's
  declared `wire:` peers afterward; `snapshot` doesn't need to, since it
  never touches disk state.

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

## Host-local cache services (`pilot services` + `--services local`)

`vm-target up`/`topology up` default to `--services none` (no cache; each
VM's `apt install`/`docker pull` hits the public internet directly). If
you're bringing the same VM(s) up more than once in a session, start the
host-side cache stack first and reuse it across every `up`:

```bash
pilot services up --profile dev-lite   # long-lived; apt-cacher-ng + Pulp RPM + Harbor on the host
pilot services status                  # confirm running=true / bind_ip before the first `up`
```

Then add `--services local` to `vm-target up`, or a root-level
`services: local` field to a topology YAML (applies to every node in that
spec) -- see `docs/runbooks/vm-target.md` §2.2. From first boot, cloud-init
points the VM's APT/DNF repos and Docker Hub/Harbor proxy config at the
host stack instead of upstream.

Key behaviors:
- **Fail-closed, no silent fallback.** If the stack isn't running,
  unhealthy, or the selected libvirt network's gateway can't be probed,
  `up --services local` errors out before creating the VM -- it never
  substitutes an uncached VM. If you hit this, run `pilot services
  status` and fix/restart the stack; don't work around it by switching to
  `--services none` unless you actually intend an uncached run.
- **Cache data lives on the host**, separate from any VM's qcow2/state
  (`~/.local/share/pilot/cache/` by default). `vm-target down` never
  touches it; `pilot services down` stops the containers but keeps the
  data; only `pilot services purge --confirm` deletes it.
- **Don't churn `services down`/`purge` between iterations** of the same
  testing session -- there's no benefit to stopping/restarting the cache
  stack while you're still using it, and `purge` throws away the warmed
  cache you were trying to avoid re-downloading.
- **Not yet acceptance-tested end-to-end on a disposable VM** (as of
  2026-07-23): host-side lifecycle and the fail-closed `vm-target`
  preflight are implemented and verified, but a VM actually installing a
  package / pulling an image through the cache is still pending real
  evidence -- see `docs/superpowers/specs/2026-07-23-host-local-services-design.md`
  Task 8. Treat `--services local` as a bandwidth-saving default, not yet
  a fully proven path; don't cite it as verified in a spec's Expected
  behavior until that evidence lands.

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
