---
name: delivery-test
description: |
  Perform delivery verification testing based on DELIVERY.md. Guides the creation
  of a multi-VM test environment (AlmaLinux 9 for FreeIPA server, Ubuntu for main
  services server, and Ubuntu for client verification), configuration of inventory,
  group_vars, vault secrets — entirely through `pilot edit` / `pilot inventory
  generate` / `pilot deploy`, never hand-written inventory.yml or raw
  ansible-playbook/ansible-vault calls — running the site playbook, and
  validating multi-node features (FreeIPA authentication/sudo via both live SSH
  and `ipa hbactest`, FreeIPA native DNS/NTP, the full metric chain Grafana ->
  Thanos Query -> Prometheus, the full log chain Grafana -> Loki <- Promtail,
  restic backups to S3, and Wazuh FIM).
---

# delivery-test

> Recipe for executing a full integration and delivery test of the pilot codebase, using KVM VMs managed by `pilot vm-target`. It validates that all components (FreeIPA, Prometheus/Thanos/Grafana, Loki/Promtail, Restic S3 Backups, and Wazuh FIM) deploy together and interoperate correctly across a multi-node layout.
>
> This skill covers the *scenario* (which nodes, which roles, which checks). For the mechanics of driving `pilot edit`/`pilot deploy`'s interactive wizards and recording them with `trec`, see the sibling `pilot-trec-verification` skill — use both together.

## 0. Hard Preconditions

Read `AGENTS.md` and `DELIVERY.md` before executing.
Make sure your host environment meets the prerequisites for KVM VM provisioning (libvirt, kvm, QEMU, cloud-localds).

**Editing/deployment only goes through `pilot edit` / `pilot inventory generate` /
`pilot deploy`** — never a hand-written `inventory.yml`, never a raw
`ansible-playbook`/`ansible-vault` invocation. Everything in §2/§3 below that
used to be a heredoc or a bare `ansible-playbook -e ...` call is now a wizard
step. This matters for two reasons: (1) it's the same discipline the rest of
the pilot demos hold to, so a delivery test actually exercises the tool the
way a user would; (2) the wizards apply `-e target_group=` scoping and the
`site.yml` safety valve correctly, which a hand-rolled inventory can silently
get wrong (e.g. accidentally wiring a role to a host it shouldn't touch).

---

## 1. Setup the Multi-VM Test Environment

We provision three KVM nodes using `pilot vm-target`:
- **`ipa-1`**: AlmaLinux 9 (`almalinux-9`). Role: FreeIPA identity provider (server).
- **`web-1`**: Ubuntu 24.04 (`ubuntu-24.04`). Role: Central services server. Hosts Prometheus/Thanos sidecar, Thanos Query, Alertmanager, Grafana+Loki dashboard, Wazuh Manager (syslog receiver & FIM controller), SeaweedFS S3 storage.
- **`web-2`**: Ubuntu 24.04 (`ubuntu-24.04`). Role: Client node. Integrates into FreeIPA realm, ships logs (Promtail) and forwards audit logs to `web-1`, backs up config files to SeaweedFS S3 on `web-1`, and runs the Wazuh FIM agent reporting to `web-1`.

Node names are illustrative — reuse whatever `pilot vm-target list` already
shows if VMs are already up rather than tearing down and renaming; the
role/scenario coverage below is what matters, not the literal hostnames.

### 1.1 Provisioning VMs

```bash
# 1. Provision AlmaLinux 9 VM for FreeIPA Server (needs at least 4096 MiB Memory)
pilot vm-target up --name ipa-1 --base-image almalinux-9 --memory 4096 --vcpus 2 --disk 30 --ssh-user root

# 2. Provision Ubuntu 24.04 VM for Central Services Server (needs 8192+ MiB Memory, 4+ vCPUs for Wazuh/Containers)
pilot vm-target up --name web-1 --base-image ubuntu-24.04 --memory 8192 --vcpus 4 --disk 50 --ssh-user root

# 3. Provision Ubuntu 24.04 VM for Client verification
pilot vm-target up --name web-2 --base-image ubuntu-24.04 --memory 2048 --vcpus 2 --disk 30 --ssh-user root
```

If all three are started concurrently, the heaviest VM can miss the default
DHCP-lease window — retry that one alone (optionally with a longer
`--boot-timeout`) rather than assuming a real failure.

### 1.2 Gather IPs and Verify Connectivity

```bash
pilot vm-target list
```

> **IMPORTANT**: Use the **actual IPs** shown by `vm-target list` in every
> step below — never hardcode an IP from a prior run. libvirt DHCP
> reassigns leases on every rebuild.

```bash
pilot vm-target exec --name ipa-1 -- ip -4 a
pilot vm-target exec --name web-1 -- id
pilot vm-target exec --name web-2 -- id
```

Per-VM SSH keys live under `/var/lib/libvirt/images/pilot/<name>/id_ed25519`
— different from your personal `~/.ssh/id_rsa`.

---

## 2. Configure Inventory, Group Vars, and Vault — via the wizards

Do this entirely with `pilot edit --dir <workspace>` and `pilot inventory
generate --dir <workspace>`, driven/recorded the way `pilot-trec-verification`
describes (`SELECT`/`EXPECT`/`ASSERT` against the real menu labels — never a
blind `DOWN <n>` count). Put `<workspace>` under this repo's gitignored
`./tmp/` directory, never inside the tracked project tree, and never reuse a
prior run's IPs.

### 2.1 Hosts and roles (via `pilot edit` -> hosts.yml)

For each VM, add a host with its real `ansible_host` (from §1.2),
`ansible_user: root`, the per-VM SSH key path, and this role set:

| Host | Roles |
|---|---|
| `ipa-1` | `freeipa-server`, `restic-backup`, `audit-log-forwarding`, `wazuh-fim` |
| `web-1` | `docker`, `wazuh-manager`, `seaweedfs-s3`, `restic-backup`, `prometheus`, `thanos-query`, `alertmanager`, `dashboard`, `audit-log-forwarding`, `wazuh-fim` |
| `web-2` | `docker`, `freeipa-client`, `restic-backup`, `audit-log-forwarding`, `wazuh-fim` |

**All three hosts get `wazuh-fim` and `audit-log-forwarding`**, not just the
client node — every node's own `/etc` should be FIM-monitored and every
node's own logs should reach the central Wazuh manager, including the
manager's own host and the FreeIPA server. This is a real scope correction
from an earlier version of this skill that only wired those two roles to the
client VM.

Since `wazuh-manager` is enabled on `web-1`, leave the `log-server` group
empty — Wazuh Manager is the primary syslog receiver, avoiding a port
514/udp collision. Keycloak and PAM-OIDC-SSHD are out of scope for this
delivery test (leave those groups empty too; `site.yml`'s empty-group
auto-skip means you don't need vault entries for them).

Host-level extra vars (via `pilot edit`'s "其他變數" host menu, not `-e` on
the command line, so they persist with the workspace):
- `ipa-1`: none extra beyond the role set.
- `web-2`, `ipa-1` (and `web-1` itself): `siem_forward_host` / `wazuh_manager_host`
  pointed at `web-1`'s IP — or set these once at the group_vars level (§2.2)
  since all three hosts resolve to the same manager.

### 2.2 group_vars (via `pilot edit` -> group_vars/)

After `pilot inventory generate --dir <workspace>` backfills the
`.example.yml` templates for every role you selected, fill in via `pilot
edit`:

- `freeipa.yml`: `freeipa_server_ip` = ipa-1's IP.
- `prometheus.yml`: `prometheus_site_label` (required, unique — e.g.
  `site-test`), `thanos_s3_target_host` = web-1's IP (same host as
  `seaweedfs-s3`).
- `thanos-query.yml`: `thanos_s3_target_host` = web-1's IP (must match
  `prometheus.yml`'s value and bucket).
- `dashboard.yml`: `thanos_query_target_host` = web-1's IP (Grafana's
  datasource points at the central Thanos Query, not straight at
  Prometheus).

  These three (`prometheus_site_label`, `thanos_s3_target_host`,
  `thanos_query_target_host`) genuinely take effect from group_vars now —
  see §3.2 for the play-vars-precedence bug this used to hit and how it
  was fixed at the source.
- `restic-backup.yml`: `restic_s3_target_host` = web-1's IP.
- `wazuh-manager.yml`: `siem_forward_host` (optional; leave empty unless
  you also want the manager's own syslog forwarded elsewhere).
- `wazuh-fim.yml`: `wazuh_manager_host` = web-1's IP (all three hosts share
  this group_vars file, so one edit covers `ipa-1`/`web-1`/`web-2`).

### 2.3 Vault Setup (via `pilot edit` -> `.vault/main.yaml`)

Required scalar secrets (all through the vault editor, no plaintext, no
hand-edited YAML — `pilot deploy` auto-detects whether the file is
`ansible-vault`-encrypted and skips the password prompt if it isn't):

- `ipa_admin_password` (>= 8 chars)
- `grafana_admin_password`
- `restic_aws_access_key_id` / `restic_aws_secret_access_key` / `restic_password`
- `thanos_aws_access_key_id` / `thanos_aws_secret_access_key`

**`thanos_aws_access_key_id`/`secret` must equal `restic_aws_access_key_id`/
`secret` exactly** — the self-hosted SeaweedFS gateway's only identity is
rendered from the `restic_*` pair, and Thanos's sidecar authenticates against
that same identity, not a separate one.

---

## 3. Apply — one-shot `pilot deploy`, not role-by-role

### 3.1 S3 signed-mode identity

`seaweedfs-s3-apply.yml` needs `-e seaweedfs_s3_config_path=/etc/seaweedfs/s3.json`
to render and mount the signed-mode identity file — SeaweedFS's default
anonymous mode rejects restic's and Thanos's always-signed requests. Add
this in `pilot deploy`'s site-wide flow via its final "還有其他 -e 變數要帶嗎？"
prompt (the site-wide flow doesn't have `runSinglePlaybookDeploy`'s dedicated
S3-signed-mode prompt, so it must be passed here explicitly).

SeaweedFS does not auto-create a missing bucket on first `PutObject`, and
treats every retry against a missing bucket as slow backoff rather than a
fast, obvious failure — but `restic-backup-apply.yml`,
`prometheus-apply.yml`, and `thanos-query-apply.yml` all now ensure their
own destination bucket (`pilot-restic-backup`, `pilot-thanos-metrics`)
exists on apply (idempotent `weed shell` check-then-create, delegated to
the `seaweedfs-s3` inventory host), so no manual bucket-creation step is
needed before the first apply.

### 3.2 `prometheus_site_label` / `thanos_s3_target_host` / `thanos_query_target_host` — group_vars now genuinely works

These three used to be silently ignored when set via `pilot edit`'s
group_vars editor: `prometheus-apply.yml`/`thanos-query-apply.yml`/
`dashboard-apply.yml` each declared them as **play-level `vars:`** with a
hardcoded `""` default, and Ansible's precedence puts play `vars:` above
both group_vars and host_vars — so the play's own `""` always won,
forcing every deploy to repeat them as `-e` regardless of what §2.2 told
you to put in group_vars. **Fixed**: all three playbooks no longer
declare these as play vars at all (every task that reads them now does
`| default('', true)` at the point of use instead) — group_vars/host_vars
values set per §2.2 now flow through with no `-e` needed, and `-e` still
overrides on top if you ever want to.

If you're on an older checkout where this isn't fixed yet, the symptom is
`prometheus_site_label is required` even after setting it in
group_vars — see Troubleshooting.

### 3.3 Deploy everything via `pilot deploy`'s "全站部署(site.yml)"

Select "全站部署(site.yml)" **once** — do not loop "單一元件" once per role.
Inventory group membership (§2.1) decides what actually runs; an empty
group is skipped automatically. Pass, at the one "-e 變數" prompt:

```
freeipa_setup_dns=true freeipa_setup_ntp=true freeipa_dns_forwarders=<libvirt-gateway-ip>
seaweedfs_s3_config_path=/etc/seaweedfs/s3.json
```

`freeipa_setup_dns=true`/`freeipa_setup_ntp=true` make `freeipa-server-apply.yml`
use FreeIPA's own native `--setup-dns`/`--setup-ntp` install flags instead of
the generic `core-infra-provider` dns/ntp roles — those are Debian/Ubuntu-only
(`ansible.builtin.apt`, `/etc/systemd/resolved.conf`) and fail outright on the
AlmaLinux FreeIPA host. Do **not** put `dns`/`ntp` in `ipa-1`'s role list in
§2.1; those roles are superseded by FreeIPA's native flags here.
`freeipa_dns_forwarders` (a space-separated string, not a YAML/JSON list —
`-e key=value` does not JSON-decode) is needed so the FreeIPA host's own
`named` can still resolve the public internet for its own package installs;
the libvirt `default` network's gateway (`virsh net-dumpxml default`) is the
usual value.

`site.yml`'s own safety valve forbids a top-level `-e target_group=` — don't
pass one; scope with inventory group membership or `--limit` instead.

### 3.4 Components `site.yml` structurally excludes — separate `pilot deploy` runs

- **`freeipa-identity`**: data-driven day-2 HBAC/sudo roster, needs its own
  vault roster file (`.vault/ipa-identity.yaml` — nested YAML, the one
  tool-endorsed exception to "no hand-edited YAML", since `pilot edit`'s
  vault editor explicitly declines nested structures). Deploy separately
  targeting the FreeIPA server.

`log-shipping` is **not** in this list as of `site.yml` v2.3+: its
`target_group` is a Jinja expression (`log-server` if that group has
hosts, else `wazuh-manager`) instead of a hardcoded, possibly-empty
group name, so the single site-wide `pilot deploy` now installs Promtail
on whichever host actually has real logs to tail — no separate invocation
needed. `log-shipping-apply.yml` itself resolves the real
`siem_log_root` at apply time (a co-located `wazuh-manager` container's
real alerts-log volume via `docker inspect`, else the `log-server`
default). If you're on an older checkout where `site.yml` still hardcodes
`target_group: log-server`, run `log-shipping` as its own single-component
`pilot deploy` with `-e target_group=<host with real logs>` instead.

---

## 4. Post-Deployment Verification

### 4.1 FreeIPA Authentication & Sudo Rules — allow AND deny, both live SSH and FreeIPA's own policy engine

Don't stop at live SSH — cross-check with FreeIPA's own authoritative
evaluator, since a live-SSH-only check can pass for the wrong reason (e.g. a
stale SSSD cache) and a `hbactest`-only check can miss a real SSSD/PAM
misconfiguration:

```bash
# Live: allowed sudo command
ssh alice@<web-2-ip> "echo '<password>' | sudo -S systemctl is-active ssh"
# Live: denied sudo command
ssh alice@<web-2-ip> "echo '<password>' | sudo -S cat /etc/shadow"
# Live: login denied entirely for an out-of-policy user
ssh -o PreferredAuthentications=password bob@<web-2-ip> 'echo should-not-reach-here'

# FreeIPA's own authoritative check (run on ipa-1, after kinit admin)
ipa hbactest --user=alice --host=<web-2-fqdn> --service=sshd   # Access granted: True
ipa hbactest --user=bob   --host=<web-2-fqdn> --service=sshd   # Access granted: False
```

Both layers must agree: `hbactest`'s verdict for alice/bob should match what
the live SSH/sudo test actually did. A mismatch means either the HBAC/sudo
rule data is wrong (fix in `.vault/ipa-identity.yaml`) or the client's own
SSSD/PAM config isn't honoring FreeIPA's policy (see Troubleshooting).

### 4.2 Metric chain: Grafana -> Thanos Query -> Prometheus

Verify the **full** chain, not just Prometheus in isolation — Grafana's
datasource points at the central Thanos Query, and Thanos Query is what
federates every site's Prometheus/sidecar, so a check that only curls
Prometheus directly can pass even if the Thanos Query hop is broken:

```bash
curl -s http://<web-1-ip>:3000/api/health                         # Grafana itself
curl -s "http://<web-1-ip>:10912/api/v1/query?query=up"           # Thanos Query -- same datasource Grafana's panel reads
```

A real `result` array with a live `up{...}` sample means Prometheus's own
`/metrics`, the Thanos sidecar's upload to SeaweedFS (or its direct gRPC
StoreAPI), and Thanos Query's federation are all working end-to-end.

### 4.3 Log chain: Grafana -> Loki <- Promtail (log-shipping)

```bash
curl -s "http://<web-1-ip>:3100/loki/api/v1/label/job/values"
curl -s -G "http://<web-1-ip>:3100/loki/api/v1/query_range" \
  --data-urlencode 'query={job=~".+"}' --data-urlencode 'limit=5'
```

Expect a real `job` label value and at least one real log line from the
client host (e.g. `sssd_sudo.log` entries generated by the §4.1 sudo test
itself is good evidence the pipeline is live, not just configured).

### 4.4 Config Backup to S3 (SeaweedFS via Restic)

```bash
pilot vm-target exec --name web-2 -- restic snapshots
```
Expect at least one snapshot of `/etc`. See Troubleshooting for the
`ciphertext verification failed` / stale-lock failure modes.

### 4.5 Wazuh File Integrity Monitoring (FIM)

```bash
pilot vm-target exec --name web-2 -- touch /etc/wazuh_test_fim_trigger
# wait a few seconds, then on web-1:
pilot vm-target exec --name web-1 -- docker exec single-node-wazuh.manager-1 \
  tail -n 200 /var/ossec/logs/alerts/alerts.log | grep wazuh_test_fim_trigger
```

---

## 5. Cleanup

```bash
pilot vm-target down --name web-2
pilot vm-target down --name web-1
pilot vm-target down --name ipa-1
```

Only tear down VMs you actually brought up for this test — never tear down a
VM you didn't create or that the user didn't explicitly name for deletion.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `restic-backup` fails with `Signed request requires setting up SeaweedFS S3 authentication` | `seaweedfs_s3_config_path` was omitted or SeaweedFS started without the rendered identity config | Pass `seaweedfs_s3_config_path=/etc/seaweedfs/s3.json` at the site-wide deploy's extra-vars prompt |
| `restic-backup` fails with `ciphertext verification failed` | Either the bucket was initialized with a different `restic_password`, or multiple hosts raced to initialize the same fresh repository | Ensure single-host repository initialization, then delete/recreate the test bucket and re-run |
| `preflight` fails with `Permission denied (publickey)` | Wrong SSH key used | Use the pilot VM-specific key: `/var/lib/libvirt/images/pilot/<name>/id_ed25519` |
| `prometheus-apply.yml` fails with `prometheus_site_label is required` even after setting it in `group_vars/prometheus.yml` (should no longer occur — see §3.2) | On an older checkout: `prometheus_site_label`/`thanos_s3_target_host`/`thanos_query_target_host` were declared as play-level `vars:` with a hardcoded `""`, which outranks group_vars/host_vars, silently shadowing what you set | Fixed at the source (see §3.2) — upgrade the checkout. If stuck on an old one, pass it as `-e prometheus_site_label=...` instead as a one-off workaround |
| Thanos Query container fails to start: `Bind for 0.0.0.0:10902 failed: port is already allocated` (should no longer occur by default — see §3.2) | Prometheus's own Thanos sidecar hardcodes host port 10902; the central Thanos Query used to default its own host-published HTTP port to the same 10902, colliding whenever the two are co-located on one host (e.g. `web-1` in this scenario's own role table) | Fixed at the source: `thanos-query-apply.yml`'s `thanos_query_http_port` (and `dashboard-apply.yml`'s matching `thanos_query_port`) now default to **10912**, not 10902 — no override needed for this topology. Only pass `-e thanos_query_http_port=... -e thanos_query_port=...` if you need some other port scheme |
| FreeIPA sudo test fails with `user does not exist` | Wrong shell used to run `sudo runuser` | Use `bash -c "sudo runuser -u <user> -- sudo -n id"` |
| FreeIPA sudo test says `not allowed` when `hbactest` says `Access granted: True` | Client sudo policy cache or SSSD sudo provider did not converge | Confirm `/etc/nsswitch.conf` has `sudoers: files sss`, `/etc/sssd/sssd.conf` has `services = nss, pam, ssh, sudo` and `sudo_provider = ipa`, then `sss_cache -E` / restart SSSD |
| `freeipa-server-apply.yml` fails with `Source /etc/systemd/resolved.conf not found` | `dns`/`ntp` roles (Debian/Ubuntu-only) were assigned to the AlmaLinux FreeIPA host instead of using its native flags | Remove `dns`/`ntp` from that host's role list; use `freeipa_setup_dns=true freeipa_setup_ntp=true` instead (§3.3) |
| Grafana's Thanos Query datasource returns no data even though Prometheus itself has metrics | Checked Prometheus directly instead of through Thanos Query, or `thanos_s3_target_host`/bucket mismatch between `prometheus.yml` and `thanos-query.yml` | Always verify via the Thanos Query port (§4.2), and confirm both group_vars files point at the same S3 host + bucket |
| Loki has no log data | `log-shipping` didn't reach a host with real logs — either `site.yml` still hardcodes `target_group: log-server` (older checkout) and that group is empty, or `wazuh-manager`/`log-server` are both empty in this inventory | On current `site.yml`, check the resolved host with `--list-hosts --tags log-shipping`; on an older checkout, run `log-shipping` as its own `pilot deploy` single-component invocation with `-e target_group=<host with real logs>` |
