# multi-vm-networking.md -- cross-VM connectivity in vm-target

When two or more `pilot vm-target` VMs need to talk to each other,
there are a few non-obvious details beyond "they share a libvirt
network."

## The libvirt default network

By default every `vm-target up` uses `--network default`, which is a
libvirt NAT network (`virbr0` bridge, 192.168.123.0/24, dnsmasq DHCP).
All VMs on this network can reach each other directly via their
192.168.123.x addresses.

```bash
# verify after bring-up
go run ./cmd/pilot vm-target exec --name <server> -- ping -c1 <client-ip>
go run ./cmd/pilot vm-target exec --name <client> -- ping -c1 <server-ip>
```

Both must respond. If either does not, the libvirt firewall
(`nwfilter`) or host `iptables` may be blocking. Diagnose:

```bash
sudo iptables -L FORWARD -n -v | grep virbr
sudo virsh net-dumpxml default | grep -A5 filter
```

## Hostname resolution between VMs

The VMs do **not** have a shared DNS. For any service whose TLS cert
or Kerberos principal includes a hostname (e.g. `ipa.pilot.internal`),
**every VM that needs to reach that service** must have the hostname
in its `/etc/hosts`. The server's apply playbook writes the server's own
`/etc/hosts` entry, but the **client needs it too** -- and a vm-target
VM's own inventory has no path to edit a *different* VM's `/etc/hosts`
(`references/vm-target-basics.md`'s "inventory contract": each `run`
only ever sees the one target it was invoked against).

**Recommended: `pilot vm-target wire`** -- no playbook change needed,
works from the CLI, and is idempotent (safe to re-run after a
`vm-target reset` wiped the target's `/etc/hosts`):

```bash
pilot vm-target wire --name <server> --peer <client>
pilot vm-target wire --name <client> --peer <server>
# --peer <other-name>=<alias> if the /etc/hosts entry needs a different
# hostname than the target's own name (e.g. the FQDN a cert expects)
pilot vm-target wire --name ipa-client --peer ipa-primary=ipa.pilot.internal
```

Under the hood this resolves `--peer`'s current IP via vm-target's own
state (never hand-typed / never goes stale across a re-`up`) and writes
a single marked block to `/etc/hosts`, replacing it wholesale on every
call -- so re-running never leaves duplicate lines the way a manual
`>> /etc/hosts` append would.

**Alternative: bake it into the playbook itself**, if you want the
apply to be self-contained even outside of vm-target (e.g. also runs
against real hosts with real DNS already resolving, where `wire` is a
no-op you'd skip):

```yaml
- name: "Pin server FQDN on client"
  ansible.builtin.lineinfile:
    path: /etc/hosts
    regexp: '\s{{ server_fqdn }}(\s|$)'
    line: "{{ server_ip }} {{ server_fqdn }}"
    state: present
  delegate_to: "{{ client_host }}"
```

This requires `client_host` to already be a resolvable inventory host
in the SAME play (i.e. combined via `vm-target run --group`, since a
plain single-target inventory has no other host to `delegate_to`). The
server IP and client host must be passed as `-e` vars (never
hard-coded -- AGENTS.md §4). Prefer `wire` unless the playbook must
also work unchanged against real, already-networked hosts.

## Combining nodes into one inventory (`--group`)

When the playbook's own `hosts:` pattern needs to see more than one
vm-target VM in a single play (not just resolve hostnames, but actually
run tasks against both, e.g. a primary+replica FreeIPA install), a
single-target inventory is not enough. Use
`vm-target run --group <groupname>=<target1>,<target2> ...` -- see
`references/vm-target-basics.md`'s `--group` section for the full
example. Pair it with `wire` above when the playbook also needs
`/etc/hosts` entries rather than just inventory group membership.

## Declarative topology (`vm-target topology`)

`--group` and `wire` above are composable building blocks, but for a
scenario with 3+ named roles (primary/replica/client), assembling the
right sequence of `up`/`wire`/`--group` calls by hand means the agent
has to parse each step's printed IP to build the next command, and
re-derive the same sequence every time the scenario is reset or
extended. `vm-target topology` makes the scenario itself a file:

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
  - name: ipa-ha-client
    base_image: rocky9
    groups: [ipa_clients]
    wire: [ipa-primary, ipa-replica]
```

```bash
pilot vm-target topology up        --topology ha-topology.yaml   # concurrent, idempotent
pilot vm-target topology status    --topology ha-topology.yaml   # name/status/ip/groups/wire table
pilot vm-target topology inventory --topology ha-topology.yaml   # real ansible groups, no target_group=all hack
pilot vm-target topology down      --topology ha-topology.yaml
pilot vm-target topology snapshot  --topology ha-topology.yaml --tag pre-drill
pilot vm-target topology rollback  --topology ha-topology.yaml --tag pre-drill
pilot vm-target topology reset     --topology ha-topology.yaml
```

`up` provisions every not-yet-running node **concurrently** (one
`*vmtarget.Manager` per node, all pointed at the same state dir). This
used to be sequential-only out of caution, but the 2026-07-06 state-race
fix (see `pilot-vm-target-up-concurrency-race` memory and AGENTS.md
§5.1) closed the lost-state-entry bug for good — `Manager.Up` reserves
its name via `Store.Mutate` (cross-process flock) before touching disk
or libvirt, so concurrent `Up` calls for different names are safe
(regression test: `TestUp_ConcurrentDifferentNames_BothPersist`).
Concurrency is per-Manager-instance, not per-goroutine-on-one-Manager:
`Manager.Up` holds an in-process lock for its whole call (including the
multi-minute boot/SSH wait), so goroutines sharing one `Manager` would
just queue — `topology up` gives each node its own `Manager` instead.
An already-running node (same name) is left alone, so re-running `up`
after adding a node to the spec only provisions the new one. Wiring
happens after every node is up (it needs every peer's final IP), so it
still runs as a separate, sequential pass — no IP copy-paste between
steps either way.

`topology inventory`'s `groups:` list feeds the same
`RenderGroupedInventory` machinery as `run --group`, so a playbook
whose `hosts:` pattern matches a real group name (e.g. `ipa_masters`)
needs no `-e target_group=...` workaround — pass
`--inventory $(...) topology inventory --topology ... --out /tmp/inv.yaml)`
or `-e target_group=ipa_masters` against the rendered file.

`snapshot`/`rollback`/`reset` apply the equivalent single-VM operation to
every node in the spec **concurrently**, so a whole multi-VM scenario can
be checkpointed or restored to a known state in one call (e.g. "does
`ipa-replica-install` rerun cleanly from scratch?") instead of resetting
each VM by hand and re-running `wire` yourself for every peer pair.
`rollback`/`reset` re-apply every node's declared `wire:` peers
afterward — the auto-`clean` snapshot `up` takes predates wiring, so a
plain single-VM `reset` would otherwise silently drop `/etc/hosts`
wiring on every node it touches. `snapshot` skips the re-wire step since
it never touches disk state. See
`docs/runbooks/freeipa-server-replica-ha-drill.md` §11 for real captured
output of `topology reset` reverting a node's disk (a planted marker
file disappears) and then automatically restoring its wiring.

Reach for `--group`/`wire` directly for a one-off/ad-hoc combination of
already-up targets; reach for `topology` when the same named scenario
gets brought up, reset, or extended more than once.

## Time sync (Kerberos, TLS, any cert validation)

Kerberos rejects tickets if the clock skew between client and KDC
exceeds 5 minutes. The ubuntu-24.04 cloud image has **no** NTP daemon
installed by default. Install on every VM before applying any
time-sensitive service:

```bash
go run ./cmd/pilot vm-target exec --name <vm> --     sudo apt-get install -y systemd-timesyncd
go run ./cmd/pilot vm-target exec --name <vm> --     sudo timedatectl set-ntp true
```

Or delegate to the `ntp` role if one exists in your playbook suite.

## Port exposure

VMs on `default` are NAT'd behind the host, so services on them are
accessible from the host and from other VMs on the same network, but
**not** from outside the host. No `--port-forward` or bridge setup is
needed for cross-VM communication.

If the spec requires external access (e.g. testing from a laptop),
use `--network <name>` to join a routed or bridged libvirt network
instead of the default NAT network.

## Two-node health check pattern

Before declaring "server is up" in a multi-VM spec, run the same
check from **both nodes**:

```bash
# server-side: ports listening
go run ./cmd/pilot vm-target exec --name <server> --     ss -tlnp | grep -E ':<port> '

# client-side: can reach server's port
go run ./cmd/pilot vm-target exec --name <client> --     curl -fsS -o /dev/null -w '%{http_code}' http://<server-ip>:<port>/
```

The server-side check only confirms the service is bound. The
client-side check confirms the network path is open and the
service answers.
