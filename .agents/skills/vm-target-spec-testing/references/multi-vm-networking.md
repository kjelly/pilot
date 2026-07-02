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
`/etc/hosts` entry, but the **client needs it too**.

**Pattern**: add a task in the server apply playbook (or a separate
client prep playbook) that pushes the server's FQDN to the client's
`/etc/hosts`:

```yaml
- name: "Pin server FQDN on client"
  ansible.builtin.lineinfile:
    path: /etc/hosts
    regexp: '\s{{ server_fqdn }}(\s|$)'
    line: "{{ server_ip }} {{ server_fqdn }}"
    state: present
  delegate_to: "{{ client_host }}"
```

The server IP and client host must be passed as `-e` vars (never
hard-coded -- AGENTS.md §4).

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
