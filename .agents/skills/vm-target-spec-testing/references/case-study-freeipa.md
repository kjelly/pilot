# case-study-freeipa.md -- the canonical Shape 3 example

This is a worked example of `SKILL.md` Shape 3 (multi-VM). It shows the
exact sequence that was attempted for the freeipa-server spec. Whenever a
new multi-VM spec is written, follow this pattern.

## What was tested

- **Server spec**: `docs/verification/freeipa-server.md` (v0.1 DRAFT)
- **Server apply**: `playbooks/apply/freeipa-server-apply.yml`
- **Client install**: hand-written shell in `freeipa-server.md` §7.3
  (no dedicated `freeipa-client-apply.yml` exists yet)
- **Vault**: `~/.vault/freeipa-sandbox.yaml` (`ipa_admin_password`,
  `ipa_dm_password`, mode 0600)

## Step-by-step (annotated)

### 0. Host prep

```bash
virsh net-list --all | grep -q 'default.*active'
[ -e /dev/kvm ]
mkdir -p ~/.vault && chmod 700 ~/.vault
cat > ~/.vault/freeipa-sandbox.yaml <<'EOF'
---
ipa_admin_password: SandboxAdm1n!Pass
ipa_dm_password:   SandboxDm1n!Pass
EOF
chmod 600 ~/.vault/freeipa-sandbox.yaml
```

### 1. Up two VMs

```bash
# server: 30 GiB disk (FreeIPA container images + install output)
go run ./cmd/pilot vm-target up     --name freeipa-server --ssh-user ubuntu     --vcpus 2 --memory 4096 --disk 30     --ssh-timeout 8m --boot-timeout 8m

# client: 20 GiB (just ipa-client + dependencies)
go run ./cmd/pilot vm-target up     --name freeipa-client --ssh-user ubuntu     --vcpus 2 --memory 2048 --disk 20
```

### 2. Fact snapshot (pasted into the runbook)

```
$ go run ./cmd/pilot vm-target list
NAME            STATUS   IP              VCPU  MEM(MiB)  DISK(GiB)  CREATED
freeipa-client  running  192.168.123.8   2     2048      20         2026-07-02 02:28:51
freeipa-server  running  192.168.123.11  2     4096      30         2026-07-02 03:18:51

$ go run ./cmd/pilot vm-target show-inventory --name freeipa-server
# ... (single host entry, key /var/lib/libvirt/images/pilot/freeipa-server/id_ed25519)

$ yq 'keys' ~/.vault/freeipa-sandbox.yaml
- ipa_admin_password
- ipa_dm_password
```

**Alignment decision**: the spec §1 targets table lists `freeipa-server`
group. The vm-target inventory has the same key as the target name
(`freeipa-server`). `pilot vm-target run` adds `-l freeipa-server`
automatically -> group pattern matches. **No misalignment.** (Option:
neither A nor B needed.)

### 3. Dry-run apply (server)

```bash
go run ./cmd/pilot vm-target run --name freeipa-server     playbooks/apply/freeipa-server-apply.yml     -e ipa_server_ip=192.168.123.11     -e ipa_install_timeout_s=1500     -e @/home/ubuntu/.vault/freeipa-sandbox.yaml     --check --diff
```

Expected: `PLAY RECAP: ... failed=0 skipped=8` (all mutate tasks skip).

### 4. Real apply (server)

```bash
go run ./cmd/pilot vm-target run --name freeipa-server     playbooks/apply/freeipa-server-apply.yml     -e ipa_server_ip=192.168.123.11     -e ipa_install_timeout_s=1500     -e @/home/ubuntu/.vault/freeipa-sandbox.yaml
```

> **Current status (2026-07-02)**: the INSTALL phase produces
> `changed: true` on the `ipa-server-install` container, but the
> SERVICE phase's `ipactl status` returns "IPA is not configured."
> The root cause is still being debugged -- see
> `container-in-vmtesting.md` for the known failure mode. The real
> PLAY RECAP would be pasted here once green.

### 5. Verify (server spec)

```bash
go run ./cmd/pilot vm-target verify --name freeipa-server     docs/verification/freeipa-server.md
```

> Blocked until §4 is green. Expected: 13 rows, all pass (or §5
> exceptions applied).

### 6. Cross-check (client -> server)

> Blocked until server is healthy. Expected sequence:

```bash
# on server: create a test IPA user
go run ./cmd/pilot vm-target exec --name freeipa-server --     sudo docker exec -i pilot-freeipa bash -lc '...'

# on client: install freeipa-client + enroll
go run ./cmd/pilot vm-target exec --name freeipa-client --     sudo apt-get install -y freeipa-client
go run ./cmd/pilot vm-target exec --name freeipa-client --     sudo ipa-client-install --server=ipa.pilot.internal         --domain=ipa.pilot.internal --realm=IPA.PILOT.INTERNAL         --mkhomedir --enable-dns-updates=no --no-ntp --unattended         --principal=admin --password=...

# round-trip check
go run ./cmd/pilot vm-target exec --name freeipa-client --     getent passwd pilot-smoke
```

### 7. Tear down

```bash
go run ./cmd/pilot vm-target down --name freeipa-client
go run ./cmd/pilot vm-target down --name freeipa-server
sudo rm -rf /var/lib/libvirt/images/pilot/freeipa-server
```

## Lessons extracted for future multi-VM specs

1. **Always ping cross-VM before applying any playbook.** The `default`
   libvirt network is NAT, so both VMs can reach each other out of the
   box -- but verifying saves hours of "is the playbook broken or the
   network?"
2. **The server's IP must be resolvable from the client.** The spec's
   §7.3 says "ensure client can resolve ipa.pilot.internal". The server
   apply writes that to its own `/etc/hosts`, but there is no task (yet)
   that pushes it to the client. This is a gap every multi-VM spec should
   address -- either with a `lineinfile` task on the client or a shared
   DNS record.
3. **Time sync matters for Kerberos (and any TLS-cert-based service).**
   The cloud image has no chrony/ntpd. The apply playbook warns but does
   not fail. For a green run, install `systemd-timesyncd` on all VMs
   before any service that checks timestamps.
4. **Two VMs on the same `default` network get sequential DHCP leases**
   but the order is not guaranteed. Always read the IP from `vm-target
   list`, never hard-code `192.168.123.X`.
