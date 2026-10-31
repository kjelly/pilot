# case-study-freeipa.md -- the first multi-VM attempt (2026-07-02)

The sequence first tried for the freeipa-server spec: a server VM plus a
client VM enrolled against it. It shows why the current tooling exists.
Do not copy its commands.

> **Historical record.** This run predates `vm-target test`,
> `vm-target topology test`, `wire` and `run --group`, and the evidence
> rules in AGENTS.md §1.2/§1.5 (it planned to paste output into the
> runbook). The server then ran as a container; `freeipa-server-apply.yml`
> now installs natively on EL9 and its header explains why the container
> path was dropped. For a new multi-VM spec, follow SKILL.md §4 and §5; the
> current FreeIPA drill is
> [freeipa-server-replica-ha-drill.md](../../../../docs/runbooks/freeipa-server-replica-ha-drill.md).
> Lesson 2 below is solved by `wire` (`multi-vm-networking.md`).

## What was tested

- **Server spec**: `docs/verification/freeipa-server.md` (v0.1 DRAFT)
- **Server apply**: `playbooks/apply/freeipa-server-apply.yml`
- **Client install**: hand-written shell in `freeipa-server.md` §7.3
  (no dedicated `freeipa-client-apply.yml` existed yet)
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
ipa_admin_password: <sandbox-admin-password>
ipa_dm_password:   <sandbox-dm-password>
EOF
chmod 600 ~/.vault/freeipa-sandbox.yaml
```

### 1. Up two VMs

```bash
# server: 30 GiB disk (FreeIPA container images + install output)
go run ./cmd/pilot vm-target up --name freeipa-server --ssh-user ubuntu \
    --vcpus 2 --memory 4096 --disk 30 --ssh-timeout 8m --boot-timeout 8m

# client: 20 GiB (just ipa-client + dependencies)
go run ./cmd/pilot vm-target up --name freeipa-client --ssh-user ubuntu \
    --vcpus 2 --memory 2048 --disk 20
```

(`--ssh-user ubuntu` is not needed: the default `root` works on the stock
images.)

### 2. Fact snapshot (read before any Ansible run)

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

**Alignment decision**: the spec §1 targets table lists the `freeipa-server`
group. The vm-target inventory's only host has the same name, and
`pilot vm-target run` adds `-l freeipa-server` automatically, so the group
pattern matches. **No misalignment** (neither A nor B needed).

### 3. Dry-run apply (server)

```bash
go run ./cmd/pilot vm-target run --name freeipa-server \
    playbooks/apply/freeipa-server-apply.yml \
    -e ipa_server_ip=192.168.123.11 -e ipa_install_timeout_s=1500 \
    -e @/home/ubuntu/.vault/freeipa-sandbox.yaml --check --diff
```

Expected at the time: `PLAY RECAP: ... failed=0 skipped=8` (all mutate
tasks skip).

### 4. Real apply (server)

```bash
go run ./cmd/pilot vm-target run --name freeipa-server \
    playbooks/apply/freeipa-server-apply.yml \
    -e ipa_server_ip=192.168.123.11 -e ipa_install_timeout_s=1500 \
    -e @/home/ubuntu/.vault/freeipa-sandbox.yaml
```

> **Status on 2026-07-02**: the INSTALL phase produced `changed: true` on
> the `ipa-server-install` container, but the SERVICE phase's
> `ipactl status` returned "IPA is not configured." The container path
> never went green (see `container-in-vmtesting.md` for the traps it hit)
> and was replaced by the native install.

### 5. Verify (server spec)

```bash
go run ./cmd/pilot vm-target verify --name freeipa-server \
    docs/verification/freeipa-server.md
```

> Blocked until §4 was green.

### 6. Cross-check (client -> server)

> Blocked until the server was healthy. Planned sequence:

```bash
# on server: create a test IPA user
go run ./cmd/pilot vm-target exec --name freeipa-server -- \
    sudo docker exec -i pilot-freeipa bash -lc '...'

# on client: install freeipa-client + enroll
go run ./cmd/pilot vm-target exec --name freeipa-client -- \
    sudo apt-get install -y freeipa-client
go run ./cmd/pilot vm-target exec --name freeipa-client -- \
    sudo ipa-client-install --server=ipa.pilot.internal \
    --domain=ipa.pilot.internal --realm=IPA.PILOT.INTERNAL \
    --mkhomedir --enable-dns-updates=no --no-ntp --unattended \
    --principal=admin --password=...

# round-trip check
go run ./cmd/pilot vm-target exec --name freeipa-client -- \
    getent passwd pilot-smoke
```

### 7. Tear down

```bash
go run ./cmd/pilot vm-target down --name freeipa-client
go run ./cmd/pilot vm-target down --name freeipa-server
```

`down` deletes each VM's directory under `/var/lib/libvirt/images/pilot`;
nothing else needs removing.

## Lessons extracted for future multi-VM specs

1. **Always ping cross-VM before applying any playbook.** The `default`
   libvirt network is NAT, so both VMs can reach each other out of the
   box -- but verifying saves hours of "is the playbook broken or the
   network?"
2. **The server's IP must be resolvable from the client.** The spec's
   §7.3 says "ensure client can resolve ipa.pilot.internal". The server
   apply writes that to its own `/etc/hosts`, but nothing pushed it to the
   client. Now solved by `wire` / topology `wire:`.
3. **Time sync matters for Kerberos (and any TLS-cert-based service).**
   This VM had no chrony/ntpd. The apply playbook warned but did not fail.
   Check the clock on every VM before any service that checks timestamps
   (`multi-vm-networking.md`).
4. **Two VMs on the same `default` network get DHCP leases in no
   guaranteed order.** Always read the IP from `vm-target list`, never
   hard-code `192.168.123.X`.
