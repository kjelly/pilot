# Runbook — Minimal PoC Architecture: FreeIPA + Wazuh + Grafana 3-VM Rebuild

> Status: **VERIFIED — LEGACY EVIDENCE**
> Latest completed pass: 2026-07-21, round 11 / v11.0
> Evidence: [`round-11.md`](../evidence/minimal-poc-architecture/2026-07-21-round-11.md)
> Automation: `playbooks/site.yml` plus the day-2
> `playbooks/apply/freeipa-identity-apply.yml` reconciler
> Maintainer: sre

The round-11 run predates the immutable-candidate evidence policy in
[`docs/actual-run-evidence.md`](../actual-run-evidence.md). Its real verdicts are retained, but the
tested tree, raw archive checksum, and durable raw-artifact location were not recorded. This
current-only rewrite changes documentation layout, not the executable procedure. The next
execution-affecting change must be verified from a frozen candidate revision under the new policy.

## 0. Goal

Rebuild and verify this three-node PoC entirely through sanctioned `pilot` workflows:

| Node | Platform | Purpose |
|---|---|---|
| `freeipa-server` | AlmaLinux 9 | FreeIPA identity, HBAC, sudo policy |
| `nexus` | Ubuntu 24.04 | Docker, Wazuh manager, SeaweedFS, Prometheus, Thanos, Grafana/Loki |
| `client-vm` | Ubuntu 24.04 | FreeIPA client and end-user authorization checks |

Use `pilot edit`, `pilot inventory generate`, `pilot deploy`, and `pilot reconcile`; do not
hand-edit the generated inventory and do not call `ansible-playbook` directly. Inventory group
membership controls which `site.yml` roles run. `freeipa-identity` remains a separate day-2
reconciler because it consumes a roster rather than ordinary role membership.

## 0.5 Current fact summary

| Item | Last verified value |
|---|---|
| Fact timestamp | 2026-07-21T17:30Z |
| Targets | `freeipa-server`, `nexus`, `client-vm` |
| VM sizing | FreeIPA: 2 vCPU/4096 MiB/30 GiB; nexus: 6/12288/80; client: 2/2048/20 |
| Inventory source | Generated from a fresh gitignored workspace by `pilot edit` + `pilot inventory generate` |
| Stage | `sandbox` |
| Alignment | Actual hosts and populated role groups matched the intended topology |
| Manual extra `-e` | Empty; inventory-derived values were accepted through the wizard |
| Result | Site apply, identity reconcile, and functional checks completed with `failed=0` |

The last run used ephemeral lab IPs. Never copy an address from old evidence; read the current
addresses and generated inventory before each rebuild.

### Required role placement

- `freeipa-server`: `freeipa-server`.
- `client-vm`: `freeipa-client`.
- `nexus` and `client-vm`: `docker`.
- `nexus`: `wazuh-manager`, `seaweedfs-s3`, `prometheus`, `thanos-query`, `alertmanager`,
  `dashboard`.
- All hosts that require local audit/FIM/backup coverage: `audit-log-forwarding`, `wazuh-fim`,
  `restic-backup`.
- Keep `dns`, `ntp`, `keycloak`, `keycloak-db`, `linux-servers`, and `log-server` empty in this PoC.
  FreeIPA supplies DNS/NTP; Wazuh manager is the SIEM receiver; Keycloak/PAM-OIDC is out of scope.

After generation, inspect the actual inventory. If it differs from this topology, choose A (fix
the workspace/environment) or B (change the contract), then regenerate and restart the formal run.

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
- A FreeIPA identity roster containing `ipa_admin_password`, `ipa_groups`, `ipa_users`,
  `ipa_sudo_rules`, `ipa_hbac_rules`, and `ipa_hbac_disable_allow_all`.

Use `playbooks/apply/freeipa-identity.roster.example.yaml` as the roster schema. User rows use
`name`, `groups`, and `allow_commands`; do not invent aliases. If `allow_all` is disabled, the
intended HBAC rule must include `sshd`, `sudo`, and `sudo-i` where sudo access is required.

## 3. Rebuild procedure

### 3.1 Freeze the candidate

Before the formal run, commit the complete execution-affecting candidate locally. Perform the
following steps from a clean isolated checkout of that revision and record its commit ID, tree ID,
relevant file hashes, target image digests, and tool versions in the evidence record.

### 3.2 Create fresh targets

Remove only the three named disposable targets and the exact gitignored PoC workspace after
read-only confirmation. Retain shared base images. Rebuild these targets:

```bash
./pilot vm-target up --name freeipa-server --base-image almalinux-9 --memory 4096 --vcpus 2 --disk 30 --ssh-user root --boot-timeout 6m --ssh-timeout 3m
./pilot vm-target up --name nexus --base-image ubuntu-24.04 --memory 12288 --vcpus 6 --disk 80 --ssh-user root --boot-timeout 6m --ssh-timeout 3m
./pilot vm-target up --name client-vm --base-image ubuntu-24.04 --memory 2048 --vcpus 2 --disk 20 --ssh-user root --boot-timeout 6m --ssh-timeout 3m
./pilot vm-target list
```

Do not assume addresses from a previous run. If pilot state and libvirt disagree, resolve only the
three exact target domains/directories after read-only inspection; never delete shared images or a
broad directory.

### 3.3 Build the inventory workspace

Use one fresh workspace consistently throughout the run:

```bash
./pilot edit --dir tmp/pilot-verify-minimal-poc-r10/demo
./pilot inventory generate --dir tmp/pilot-verify-minimal-poc-r10/demo
./pilot edit --dir tmp/pilot-verify-minimal-poc-r10/demo
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
./pilot deploy -i tmp/pilot-verify-minimal-poc-r10/demo/inventory.yml --timeout 90m
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
./pilot reconcile -i tmp/pilot-verify-minimal-poc-r10/demo/inventory.yml --timeout 90m
```

Select `freeipa-identity`, `freeipa-server`, and `sandbox`. At the vault vars-file prompt, select the
identity roster rather than `.vault/main.yaml`; the roster already includes
`ipa_admin_password`. Leave manual extra `-e` empty. A clean recap with every reconcile task skipped
means the wrong vars file was selected and is not a successful identity apply.

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

Detailed component-specific troubleshooting belongs in the aligned spec/runbook for that component,
not in this composition runbook.

## 7. Latest verified evidence

| Field | Round 11 legacy record |
|---|---|
| Verified at | 2026-07-21T17:30Z |
| Evidence recorded by | Git commit `04809b551599bc42a3fb833e97c6f2cf04d0c6d8` |
| Tested revision/tree | Not recorded under the pre-v1.16 evidence process |
| Targets | Fresh `freeipa-server`, `nexus`, and `client-vm` VMs |
| Site apply | `client-vm ok=83 changed=41 failed=0`; `freeipa-server ok=35 changed=10 failed=0`; `nexus ok=154 changed=74 failed=0`; `localhost ok=1 changed=0 failed=0` |
| Identity apply | `freeipa-server ok=31 changed=12 failed=0` |
| Functional verdict | PASS: FreeIPA HBAC/sudo, Grafana→Thanos→Prometheus, Grafana→Loki←Promtail, restic, Wazuh FIM |
| Reconciler cycle | Removal and restore/drift correction passed; final rerun `changed=2 failed=0` |
| Raw artifact/checksum | Not durably retained in the legacy record |
| Publication | Sanitized summary; secret values omitted, lab addresses omitted |

The compact evidence record contains the retained round-11 facts and limitations. Historical v2–v10
procedures, transcripts, bug narratives, and changelog entries remain available in Git history and
are intentionally not duplicated in the current runbook.
