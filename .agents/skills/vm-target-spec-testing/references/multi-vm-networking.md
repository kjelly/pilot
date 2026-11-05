# multi-vm-networking.md -- cross-VM connectivity in vm-target

When two or more `pilot vm-target` VMs need to talk to each other, there are
a few non-obvious details beyond "they share a libvirt network". Checked
against `pilot vm-target topology --help`, `cmd/pilot/cmd/vm_target_topology.go`
and `internal/vmtarget/topology.go`.

## The libvirt network

Every `vm-target up` uses `--network default` unless told otherwise: a
libvirt NAT network with dnsmasq DHCP. VMs on it reach each other directly
by IP. The subnet depends on the host (`192.168.122.0/24` on some hosts,
`192.168.123.0/24` on others), and lease order is not guaranteed: read IPs
from `vm-target list` or `topology status`, never hard-code them.

```bash
pilot vm-target exec --name <server> -- ping -c1 <client-ip>
pilot vm-target exec --name <client> -- ping -c1 <server-ip>
```

If either fails, the libvirt firewall (`nwfilter`) or host `iptables` may be
blocking:

```bash
sudo iptables -L FORWARD -n -v | grep virbr
sudo virsh net-dumpxml default | grep -A5 filter
```

Services on the NAT network are reachable from the host and from other VMs
on it, not from outside the host. For outside access, join a routed or
bridged libvirt network with `--network <name>` (topology: `network:`).

## Hostname resolution between VMs

The VMs share no DNS. For a service whose TLS certificate or Kerberos
principal names a host (for example `ipa1.ipa.pilot.internal`), **every VM
that reaches that service** needs the name in its `/etc/hosts`. A server
playbook writes its own entry, but a single-VM inventory has no path to
another VM's `/etc/hosts`.

**Recommended: `wire`.** It resolves each peer's current IP from vm-target
state and replaces one marked block in `/etc/hosts` on every call, so it is
safe to rerun after a `reset` or a peer's re-`up`:

```bash
pilot vm-target wire --name <server> --peer <client>
pilot vm-target wire --name <client> --peer <server>=<fqdn-the-cert-expects>
```

In a topology file the same entries go under `wire:`, and `topology up`,
`topology reset`/`rollback` and `topology test --ephemeral` apply them.

**Alternative: in the playbook**, when it must also run unchanged against
real hosts:

```yaml
- name: "Pin server FQDN on client"
  ansible.builtin.lineinfile:
    path: /etc/hosts
    regexp: '\s{{ server_fqdn }}(\s|$)'
    line: "{{ server_ip }} {{ server_fqdn }}"
    state: present
  delegate_to: "{{ client_host }}"
```

`client_host` must be a host in the same play (a grouped inventory, since a
single-VM inventory has no other host), and `server_ip`/`client_host` come
from `-e` or inventory, never hard-coded (AGENTS.md §4).

## Combining running VMs in one inventory (`run --group`)

When one play must run tasks on several VMs (a primary + replica install),
use `vm-target run --group <group>=<vm1>,<vm2> ...`; see
`vm-target-basics.md`. Pair it with `wire` when the playbook also needs
names to resolve. For a scenario you will bring up, reset or test more than
once, use a topology file instead.

## Topology files (`vm-target topology`)

A topology YAML declares every node once (examples in `docs/topologies/`):

```yaml
services: local                # optional: none, local or a profile path; applies to every node
nodes:
  - name: ipa-primary          # [a-zA-Z0-9_.-]+, unique
    base_image: almalinux-9    # alias or local qcow2 path; default ubuntu-24.04
    memory: 3072
    ssh_timeout: 8m
    boot_timeout: 8m
    groups: [freeipa-server]   # ansible groups for the rendered inventory
    wire: ["ipa-replica=ipa2.ipa.pilot.internal"]   # peer must be a node in this file
  # - name: ipa-replica ...
```

Other node fields: `ssh_user`, `vcpus`, `disk`, `network`, `hosts`,
`keep_on_failure`. Validation rejects an empty node list, duplicate or
invalid names, a `wire` peer that is not a node in the file, a node wiring
itself and unparseable timeouts.

```bash
pilot vm-target topology up        --topology <file>   # concurrent; skips names already in state
pilot vm-target topology status    --topology <file>   # name/status/ip/groups/wire
pilot vm-target topology inventory --topology <file> [--out <path>]
pilot vm-target topology snapshot  --topology <file> --tag <t>
pilot vm-target topology rollback  --topology <file> --tag <t>   # then re-wires
pilot vm-target topology reset     --topology <file>             # clean checkpoint, then re-wires
pilot vm-target topology test      --topology <file> --playbook <pb> --verify <spec>=<limit> [--ephemeral]
pilot vm-target topology down      --topology <file>
```

- `groups:` become real inventory groups, so a playbook's `hosts:` pattern
  and each `--verify <spec>=<group>` match without `-e target_group=all`.
  Use the group names the playbooks and specs actually target (for example
  `docker`, `log-server`, `freeipa-server`); a label nothing reads leaves
  `site.yml` plays with no hosts.
- `topology up` provisions every missing node concurrently, then wires.
  A declared name already in pilot state, whatever its status, is skipped
  and adopted: `topology up` wires it if it declares `wire:`, and `topology down`
  later destroys it with the rest. Check `vm-target list` for name
  collisions with other sessions first. `topology test --ephemeral` refuses
  to start on any collision instead.
- `rollback` and `reset` re-apply every node's `wire:` because the `clean`
  checkpoint predates wiring; a per-VM `vm-target reset` would silently drop
  it. Use `topology reset` to test "does this reinstall from scratch".
  [freeipa-server-replica-ha-drill.md](../../../../docs/runbooks/freeipa-server-replica-ha-drill.md)
  §13 runs it.
- `topology test` behaviour, `--ephemeral` and `--keep-on-failure`:
  SKILL.md §4.

## Time sync (Kerberos, TLS, any certificate validation)

Kerberos rejects tickets when client and KDC clocks differ by more than
five minutes. The HA drill measured VM clocks 54–90 minutes behind after
`up`/`reset`, with `chronyd` active but never synchronised, and the FreeIPA
case study found no time daemon at all on its ubuntu-24.04 VM. Check
`timedatectl` on every VM before applying a time-sensitive service; the
drill's fix (`hwclock -s` on AlmaLinux, `date -s "@<host epoch>"` on Ubuntu)
is in
[freeipa-server-replica-ha-drill.md](../../../../docs/runbooks/freeipa-server-replica-ha-drill.md)
§2 and §15. The repo's NTP role is
`playbooks/apply/core-infra-provider-apply.yml`.

## Two-node health checks

A server-side `ss -tlnp` only proves the service is bound; only a
client-side request proves the path is open and the service answers. While
debugging:

```bash
pilot vm-target exec --name <server> -- sh -c "ss -tlnp | grep -E ':<port> '"
pilot vm-target exec --name <client> -- curl -fsS -o /dev/null -w '%{http_code}' http://<server-ip>:<port>/
```

For evidence, make the client-side request a spec row and verify it against
the client group (SKILL.md §7).
