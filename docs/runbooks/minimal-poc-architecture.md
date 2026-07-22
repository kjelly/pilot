# Runbook — Minimal PoC Architecture: FreeIPA + Wazuh + Grafana 3-VM Rebuild

> Status: **VERIFIED — IMMUTABLE CANDIDATE**
> Latest completed pass: 2026-07-23 (Asia/Taipei), round 12 / CAND-23
> Evidence: [`2026-07-23-round-12.md`](../evidence/minimal-poc-architecture/2026-07-23-round-12.md)
> Automation: `playbooks/site.yml` plus the day-2
> `playbooks/apply/freeipa-identity-apply.yml` reconciler
> Maintainer: sre

Round 12 was executed from the immutable CAND-23 commit/tree recorded in §7. This runbook keeps
only the current sanitized facts and links; its one-time acceptance recordings are disposable.

## 0. Goal

Rebuild and verify this three-node PoC entirely through sanctioned `pilot` workflows:

| Node | Platform | Purpose |
|---|---|---|
| `freeipa-server` | AlmaLinux 9 | FreeIPA identity, HBAC, sudo policy |
| `nexus` | Ubuntu 24.04 | FreeIPA client and Kerberos NFSv4 server; Docker, Wazuh manager, signed SeaweedFS S3, restic, Prometheus, Thanos, Grafana/Loki |
| `client-vm` | Ubuntu 24.04 | FreeIPA and Kerberos automount NFS client; end-user authorization checks |

Use `pilot edit`, `pilot inventory generate`, `pilot deploy`, and `pilot reconcile`; do not
hand-edit the generated inventory and do not call `ansible-playbook` directly. Inventory group
membership controls which `site.yml` roles run. `freeipa-identity` remains a separate day-2
reconciler because it consumes a roster rather than ordinary role membership.

## 0.5 Current fact summary

| Item | Last verified value |
|---|---|
| Fact timestamp | 2026-07-23T03:25+08:00 |
| Targets | `freeipa-server`, `nexus`, `client-vm` |
| VM sizing | FreeIPA: 2 vCPU/4096 MiB/30 GiB; nexus: 6/12288/80; client: 2/2048/20 |
| Inventory source | Generated from a fresh gitignored workspace by `pilot edit` + `pilot inventory generate` |
| Stage | `sandbox` |
| Alignment | Actual hosts and populated role groups matched the intended topology |
| Manual extra `-e` | Empty; inventory-derived values were accepted through the wizard |
| Tested candidate | commit `4034ccd6cc7290a3dd625ea2e6e15d825c9373a3`; tree `d72c9f9c21bc531d0d3127e3b03c70d20594f6af` |
| Result | Fresh site apply passed; identical second site apply was `changed=0 failed=0` on all three hosts; canonical identity no-op reconcile was `changed=0 failed=0` |

The last run used ephemeral lab IPs. Never copy an address from old evidence; read the current
addresses and generated inventory before each rebuild.

### Required role placement

- `freeipa-server`: `freeipa-server`.
- `nexus` and `client-vm`: `freeipa-client`.
- `nexus`: `freeipa-nfs-server`; `client-vm`: `freeipa-nfs-client`.
- `nexus` and `client-vm`: `docker`.
- `nexus`: `wazuh-manager`, `seaweedfs-s3`, `prometheus`, `thanos-query`, `alertmanager`,
  `dashboard`.
- All hosts that require local audit/FIM/backup coverage: `audit-log-forwarding`, `wazuh-fim`,
  `restic-backup`.
- Keep `dns`, `ntp`, `keycloak`, `keycloak-db`, `linux-servers`, and `log-server` empty in this PoC.
  FreeIPA supplies DNS/NTP; Wazuh manager is the SIEM receiver; Keycloak/PAM-OIDC is out of scope.

After generation, inspect the actual inventory. If it differs from this topology, choose A (fix
the workspace/environment) or B (change the contract), then regenerate and restart the formal run.

When the generated vault supplies the restic/Thanos S3 access key and secret, full-site deployment
automatically renders `/etc/seaweedfs/s3.json` with mode `0600` and starts SeaweedFS with
`-s3.config=/etc/seaweedfs/s3.json`. That is the supported signed S3 path; do not add a manual
`seaweedfs_s3_config_path` override for this topology.

## 1. Aligned acceptance contracts

The component checks live in these specs and are not duplicated here:

- `docs/verification/freeipa-server.md`
- `docs/verification/freeipa-client.md`
- `docs/verification/freeipa-identity.md`
- `docs/verification/docker.md`
- `docs/verification/seaweedfs-s3.md`
- `docs/verification/prometheus.md`
- `docs/verification/thanos-query.md`
- `docs/verification/alertmanager.md`
- `docs/verification/dashboard.md`
- `docs/verification/log-shipping.md`
- `docs/verification/wazuh-manager.md`
- `docs/verification/wazuh-fim.md`
- `docs/verification/audit-log-forwarding.md`
- `docs/verification/restic-backup.md`

This runbook adds only the cross-component checks: live HBAC/sudo allow and deny, Grafana-facing
metric/log queries, shared backup visibility, a Wazuh FIM event, and the FreeIPA identity
remove/restore/drift reconciliation cycle.

## 2. Prerequisites

- `/dev/kvm` access, an active libvirt `default` NAT network, and writable pilot image storage.
- A freshly built `./pilot` binary from the candidate revision.
- A new gitignored workspace under `./tmp`; do not reuse an abandoned or partially repaired one.
- A real TTY for `pilot edit`, `pilot deploy`, and `pilot reconcile`.
- `trec` recording according to the `pilot-trec-verification` and `trec-tui-drive` skills. Driver
  mechanics and recording failures belong in those skills, not this operational runbook.
- Vault values for the keys listed below; never record their values:
  `ipa_admin_password`, `grafana_admin_password`, `restic_aws_access_key_id`,
  `restic_aws_secret_access_key`, `restic_password`, `thanos_aws_access_key_id`,
  `thanos_aws_secret_access_key`, and `alertmanager_config`.
- A canonical FreeIPA identity roster with `schema_version: 1`, the `freeipa` connection/safety
  block, and the required `users`, `groups`, `hosts`, `hbac`, `sudo`, and `nfs` objects.

Use `playbooks/apply/freeipa-identity.roster.example.yaml` as the roster schema. Keep Nexus's
canonical FQDN/IP, NFS service principal, export, ACL, and automount objects in that roster. If
`allow_all` is disabled, the intended HBAC rule must include `sshd`, `sudo`, and `sudo-i` where
sudo access is required.

## 3. Rebuild procedure

### 3.1 Freeze the candidate

Before the formal run, commit the complete execution-affecting candidate locally. Perform the
following steps from a clean isolated checkout of that revision and record its commit ID, tree ID,
relevant file hashes, target image digests, and tool versions in the evidence record.

### 3.2 Create fresh targets

Remove only the three named disposable targets and the exact gitignored PoC workspace after
read-only confirmation. Retain shared base images. Rebuild these targets:

```bash
./pilot vm-target up --name freeipa-server --base-image almalinux-9 --vcpus 2 --memory 4096 --disk 30
./pilot vm-target up --name nexus --base-image ubuntu-24.04 --vcpus 6 --memory 12288 --disk 80
./pilot vm-target up --name client-vm --base-image ubuntu-24.04 --vcpus 2 --memory 2048 --disk 20
./pilot vm-target list
```

Do not assume addresses from a previous run. If pilot state and libvirt disagree, resolve only the
three exact target domains/directories after read-only inspection; never delete shared images or a
broad directory.

### 3.3 Build the inventory workspace

Use one fresh workspace consistently throughout the run:

```bash
./pilot edit --dir tmp/pilot-verify-minimal-poc-r12-formal-cand23
./pilot inventory generate --dir tmp/pilot-verify-minimal-poc-r12-formal-cand23
./pilot edit --dir tmp/pilot-verify-minimal-poc-r12-formal-cand23
```

In the first edit pass, set every host's SSH user, exact generated private-key path, and role
membership. In the second, fill group variables and `.vault/main.yaml`. The nested identity roster
is the tool-documented exception and may be authored from the committed roster example.

Before deployment:

1. Read `pilot vm-target list` and each target's `show-inventory` output.
2. Inspect the generated inventory and confirm the role placement in §0.5.
3. Confirm required group variables contain real values rather than `CHANGE-ME` or empty defaults.
4. Confirm vault **key names only** and compare them with §2.
5. Run the complete deploy preflight; never choose its skip option.

The wizard save confirmation proves a write occurred, not that every intended field is correct;
inspect the generated files before proceeding.

### 3.4 Site-wide deployment

Run the site-wide wizard using the generated inventory:

```bash
./pilot deploy -i tmp/pilot-verify-minimal-poc-r12-formal-cand23/inventory.yml --timeout 90m
```

Select the full-site `site.yml` scope and `sandbox` stage. Accept inventory-derived automatic
values when the wizard presents them. Leave the later manual extra-`-e` field empty. If a required
value cannot be derived and would need manual input there, stop and fix the inventory/group vars;
do not improvise an override during the evidence run.

Run the full preview (`--check --diff`) and continue to real apply only when every host reports
`failed=0`.

### 3.5 Identity reconciliation

Run the separate day-2 reconciler against the same inventory:

```bash
./pilot reconcile -i tmp/pilot-verify-minimal-poc-r12-formal-cand23/inventory.yml --timeout 90m
```

Select `freeipa-identity`, `freeipa-server`, and `sandbox`. Set `freeipa_roster_file` on the managed
host through `pilot edit`; the reconciler loads that canonical roster separately. At the secret
vars-file prompt select `.vault/main.yaml`, which supplies the `ipa_admin_password` referenced by
the roster. Leave manual extra `-e` empty. A clean recap with every reconcile task skipped means the
roster was not loaded and is not a successful identity apply.

## 4. Verification procedure

Run every aligned component spec against the generated inventory, then perform these end-to-end
checks. Capture exact commands, outputs, exit codes, target facts, and retries in the raw evidence
artifact rather than appending them here.

### 4.1 FreeIPA authorization

- Confirm FreeIPA services are active.
- Use `ipa hbactest` for both `sshd` and `sudo` services.
- With real test credentials, prove an allowed user can log in and run the roster-authorized
  `systemctl` command.
- Prove the same user cannot run an unlisted command such as reading `/etc/shadow`.
- Prove the denied user cannot log in. A credential-less BatchMode attempt is not evidence of HBAC
  denial.

If `ipa hbactest` allows sudo but the first live sudo lookup is denied, use the SSSD cache recovery
in §6 and repeat both checks.

### 4.2 Metrics and logs through Grafana dependencies

- Confirm Grafana, Prometheus, Loki, and Thanos Query readiness.
- Query Thanos for `up` and confirm the `site-nexus` series has value `1`.
- Query Loki label values and a recent range; confirm the `pilot-siem` stream contains a real event
  generated during this run.

### 4.3 Backup and Wazuh FIM

- Confirm `restic-backup.timer` is active and enabled on every host assigned the role.
- Trigger a backup and confirm the shared repository contains fresh snapshots for the intended
  hosts.
- Create a unique file under `/etc` on an enrolled agent and confirm Wazuh manager receives the
  corresponding real-time `whodata` file-add alert.

### 4.4 Identity reconciler cycle

1. Remove the allowed user's `sysops` membership from the roster and reconcile.
2. Confirm `ipa hbactest` and live login/authorization both lose the intended grant without
   changing the user's personalized password state.
3. Restore membership and add one new allowed sudo command in the same roster edit; reconcile.
4. Confirm both membership and command drift are corrected in effective state.
5. Reconcile again without changing the roster and record the real changed count.

Do not round residual changes down to zero. Explain every repeatable non-idempotent task in the
evidence record.

## 5. Rollback and teardown

- Failed `pilot deploy`/`reconcile` previews must stop before mutation.
- Apply playbooks retain their own snapshot/rescue boundaries; preserve their failure evidence.
- For a disposable full teardown, confirm the exact three target names, then use `pilot vm-target
  down` for each. Remove only this run's exact gitignored workspace.
- Never use a broad recursive deletion target, unresolved variable, wildcard, repository root, or
  shared image directory.

## 6. Current gotchas

| Symptom | Cause | Current action |
|---|---|---|
| First live sudo is denied although `ipa hbactest --service=sudo` allows it | Stale SSSD sudo cache on the client | Run `sss_cache -E`, restart `sssd`, and repeat the live and authoritative checks. Do **not** add `sudo` to `sssd.conf` `services=`; the sudo responder is socket-activated and that edit breaks its socket. |
| `pilot deploy --dir ...` is rejected | `deploy` takes an inventory with `-i`; `--dir` belongs to authoring commands such as `pilot edit` | Use the §3.4 invocation. |
| Site deploy asks to confirm auto-detected host variables | These are derived from inventory and are distinct from the manual extra-`-e` field | Accept the detected values; keep the manual field empty. If a required value is not derived, stop and fix inputs. |
| Identity reconcile reports `failed=0` but all mutation tasks skip | `.vault/main.yaml` was selected instead of the roster | Select `.vault/ipa-identity.yaml` at the vars-file prompt and rerun preview/apply. |
| Generated files do not contain intended wizard values | Saving the wrong cursor field can still exit successfully | Inspect saved host, role, group-var, and vault-key facts before deployment; keep TUI-driving details in the trec skills. |
| A no-op reconcile still reports changes | Forced test-password handling, HBAC disable behavior, or Dogtag-owned mode correction may be non-idempotent | Identify the exact changed tasks and preserve their real count; do not claim `changed=0`. |
| SeaweedFS anonymous C6–C8 fail while restic credentials are enabled | Full-site correctly selected signed S3 mode; the legacy rows intentionally send unsigned requests | Require the signed config/runtime probes plus `restic-backup` and Thanos verification to pass; do not weaken authentication. |

Detailed component-specific troubleshooting belongs in the aligned spec/runbook for that component,
not in this composition runbook.

## 7. Latest verified evidence

| Field | Round 12 / CAND-23 record |
|---|---|
| Verified at | 2026-07-23T03:25+08:00 |
| Tested revision/tree | `4034ccd6cc7290a3dd625ea2e6e15d825c9373a3` / `d72c9f9c21bc531d0d3127e3b03c70d20594f6af` |
| Targets | Fresh `freeipa-server` (AlmaLinux 9), `nexus` and `client-vm` (Ubuntu 24.04) |
| First site apply | `client-vm ok=101 changed=31 failed=0`; `freeipa-server ok=72 changed=25 failed=0`; `nexus ok=220 changed=87 failed=0`; `localhost ok=1 changed=0 failed=0` |
| Identical second site apply | `client-vm ok=95 changed=0 failed=0`; `freeipa-server ok=67 changed=0 failed=0`; `nexus ok=207 changed=0 failed=0`; `localhost ok=1 changed=0 failed=0` |
| Canonical identity | Initial reconcile `changed=21 failed=0`; final no-op reconcile `changed=0 failed=0` |
| Signed S3/restic | `s3.json` mode `0600`; live `-s3.config` flag present; restic `30/30`; Prometheus `12/12`; Thanos `10/10` |
| Functional verdict | PASS with documented applicability exceptions: unsigned SeaweedFS rows C6–C8; Wazuh manager C11 and log-shipping C3/C6 require an independent `log-server` |
| Evidence integrity | Critical evidence set: 51/51 TREC recordings valid and secret-scan safe |
| Publication | [`2026-07-23-round-12.md`](../evidence/minimal-poc-architecture/2026-07-23-round-12.md); secret values and ephemeral addresses omitted |

The compact evidence record contains the current candidate provenance, result matrix, documented
exceptions, and raw-artifact pointers. Earlier runs remain available in their evidence records and
Git history and are intentionally not duplicated here.
