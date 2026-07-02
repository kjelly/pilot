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
| `exec`  | Run a single command via SSH on the target | No |
| `verify`| Run `pilot verify` against a spec file | Yes for spec checks |
| `snapshot` | Snapshot the VM's qcow2 under a tag | No (additive) |
| `rollback` | Restore qcow2 to a tagged snapshot | Destructive |
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
