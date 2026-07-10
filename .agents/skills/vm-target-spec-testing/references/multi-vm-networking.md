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
