# Runbook — Minimal PoC Architecture: FreeIPA + Wazuh + Grafana 3-VM Rebuild

> Status: **VERIFIED**
> Latest completed pass: 2026-07-23 (Asia/Taipei), round 13
> Evidence: [`2026-07-23-round-13.md`](../evidence/minimal-poc-architecture/2026-07-23-round-13.md)
> Automation: `playbooks/site.yml` plus the day-2
> `playbooks/apply/freeipa-identity-apply.yml` reconciler
> Maintainer: sre

Round 13 started from commit `6837e13`/tree `8587262` and is **not** a single immutable commit
end to end: a genuinely fresh clean-room preview/apply surfaced 2 real playbook defects (both
check-mode/fresh-host ordering gaps in the NFS server/client apply playbooks, plus one FreeIPA
DNS-design gap) that had not previously been exercised this way. Both were fixed with user
authorization mid-run; the exact diff is in the round-13 evidence file. This runbook keeps only the
current sanitized facts and links; its one-time acceptance recordings are disposable.

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
| Fact timestamp | 2026-07-23T14:24+08:00 |
| Targets | `freeipa-server`, `nexus`, `client-vm` |
| VM sizing | FreeIPA: 2 vCPU/4096 MiB/30 GiB; nexus: 6/12288/80; client: 2/2048/20 |
| Inventory source | Generated from a fresh gitignored workspace by `pilot edit` + `pilot inventory generate` |
| Stage | `sandbox` |
| Alignment | Actual hosts and populated role groups matched the intended topology |
| Manual extra `-e` | Empty; inventory-derived values were accepted through the wizard |
| Tested candidate | commit `6837e1341e22fee0b8020226bfe27e3a2cf3ed29`; tree `8587262520189d142462d824c1ea9142a3776b71`; plus 2 authorized mid-run playbook fixes (not yet committed — see round-13 evidence) |
| Result | Fresh site apply passed after the mid-run fixes; identical second site apply was `changed=0 failed=0` on all three hosts; canonical identity no-op reconcile was `changed=1 failed=0` (fully explained — see §6) |

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

Set `freeipa_roster_file` as an extra host var (via `pilot edit`'s hosts.yml editor) on **every**
host whose apply playbook reads it — in this topology that is both `freeipa-server`
(`freeipa-identity-apply.yml`) and `nexus` (`freeipa-nfs-server-apply.yml`, which independently
loads the same roster to resolve its own NFS server/share entries). Point it at the same absolute
roster path on both hosts.

A roster group's `category` must match its name's prefix: `team` → `^team-`, `filesystem` →
`^data-`, `access` → `^access-`, `role` → `^role-` (enforced by a validation gate). HBAC rule
`subjects.groups` may only reference `category: access` groups; sudo rule `subjects.groups` may
only reference `category: role` groups — a single group cannot serve both purposes directly, so an
account needing both SSH login and sudo access needs membership in one of each category.

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
./pilot edit --dir tmp/pilot-verify-minimal-poc-r13
./pilot inventory generate --dir tmp/pilot-verify-minimal-poc-r13
./pilot edit --dir tmp/pilot-verify-minimal-poc-r13
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
./pilot deploy -i tmp/pilot-verify-minimal-poc-r13/inventory.yml --timeout 90m
```

Select the full-site `site.yml` scope and `sandbox` stage. Accept inventory-derived automatic
values when the wizard presents them. Leave the later manual extra-`-e` field empty. If a required
value cannot be derived and would need manual input there, stop and fix the inventory/group vars;
do not improvise an override during the evidence run.

Run the full preview (`--check --diff`) and continue to real apply only when every host reports
`failed=0`.

On a genuinely fresh host, if `nexus`'s `freeipa-nfs-server` component fails a real apply with
`chgrp failed: failed to look up group <name>` for a roster-managed NFS share ownership group (e.g.
`data-project-alpha-rw`), that group does not exist yet because §3.5's identity reconciliation has
not run. Run §3.5 now, then re-run this site-wide deploy — every already-applied component reports
`changed=0` and only the NFS share step completes.

### 3.5 Identity reconciliation

Run the separate day-2 reconciler against the same inventory:

```bash
./pilot reconcile -i tmp/pilot-verify-minimal-poc-r13/inventory.yml --timeout 90m
```

Select `freeipa-identity`, `freeipa-server`, and `sandbox`. Set `freeipa_roster_file` on the managed
host through `pilot edit` (see §2 — also required on `nexus`); the reconciler loads that canonical
roster separately via that host var, independent of whatever is selected at the vars-file prompt
below. At the secret vars-file prompt select `.vault/main.yaml`, which supplies the
`ipa_admin_password` referenced by the roster. Leave manual extra `-e` empty. A clean recap with
every reconcile task skipped means the roster was not loaded and is not a successful identity apply.

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

1. Remove the allowed user's access/role-group membership from the roster and reconcile. Per §2's
   category convention this is normally two groups (one `access-*` for HBAC, one `role-*` for
   sudo) — remove both to fully revoke.
2. Confirm `ipa hbactest` and live login/authorization both lose the intended grant without
   changing the user's personalized password state.
3. Restore membership and add one new allowed sudo command in the same roster edit; reconcile.
4. Confirm both membership and command drift are corrected in effective state. A newly-added sudo
   command may need a client-side `sss_cache -E && systemctl restart sssd` before it takes effect
   live (§6) — that is a cache-staleness gotcha, not evidence the reconcile itself failed.
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
| Identity reconcile reports `failed=0` but all mutation tasks skip | `freeipa_roster_file` is not set as a host var on the target (see §2); this is independent of whatever is selected at the vars-file prompt — selecting `.vault/main.yaml` there is fine for a canonical (`schema_version: 1`) roster and does not by itself cause a skip, confirmed live 2026-07-23 (round 13) | Confirm `freeipa_roster_file` is set on the managed host, not just which file was picked at the vars-file prompt. |
| Generated files do not contain intended wizard values | Saving the wrong cursor field can still exit successfully | Inspect saved host, role, group-var, and vault-key facts before deployment; keep TUI-driving details in the trec skills. |
| A no-op reconcile still reports changes | Forced test-password handling, HBAC disable behavior, or Dogtag-owned mode correction may be non-idempotent; also, any roster user who has never actually logged in yet (`krbLastPwdChange == krbPasswordExpiration`) has their bootstrap password legitimately re-applied every run regardless of `force_change`, by design (only a user's own real password change breaks the equality) | Identify the exact changed tasks and preserve their real count; do not claim `changed=0`. |
| A brand-new roster user's first live login/sudo fails with "Password change required but no TTY available", even though the roster sets `force_change: false` | FreeIPA's own `ipa passwd` always arms the forced-change flag on first-ever password assignment, independent of the roster flag — `force_change` only controls whether a *routine rerun* re-arms it for an already-onboarded user | Personalize with a scripted `kinit <user>` (3-line forced-change stdin: old/new/new), confirmed live 2026-07-23 to work over `pilot vm-target exec` piped stdin without needing a PTY (unlike the equivalent SSH+PAM path, which does need one) |
| SeaweedFS anonymous C6–C8 fail while restic credentials are enabled | Full-site correctly selected signed S3 mode; the legacy rows intentionally send unsigned requests | Require the signed config/runtime probes plus `restic-backup` and Thanos verification to pass; do not weaken authentication. |
| `pilot verify docs/verification/restic-backup.md ... --host restic-backup` reports a `C6` timeout | Default per-row timeout (15s) is too short for `restic check --retry-lock 120s` run concurrently across all hosts sharing one repository — confirmed live 2026-07-23 | Pass `--timeout 180` for group verification of this spec, per its own v1.3 changelog note. |

Detailed component-specific troubleshooting belongs in the aligned spec/runbook for that component,
not in this composition runbook.

## 7. Latest verified evidence

| Field | Round 13 record |
|---|---|
| Verified at | 2026-07-23T14:24+08:00 |
| Tested revision/tree | `6837e1341e22fee0b8020226bfe27e3a2cf3ed29` / `8587262520189d142462d824c1ea9142a3776b71`, plus 2 authorized mid-run playbook fixes (diff in the evidence file; not yet committed) |
| Targets | Fresh `freeipa-server` (AlmaLinux 9), `nexus` and `client-vm` (Ubuntu 24.04) |
| First site apply | `client-vm ok=90 changed=27 failed=0`; `freeipa-server ok=71 changed=24 failed=0`; `nexus ok=207 changed=75 failed=0`; `localhost ok=1 changed=0 failed=0` |
| Identical second site apply | `client-vm ok=85 changed=0 failed=0`; `freeipa-server ok=66 changed=0 failed=0`; `nexus ok=197 changed=0 failed=0`; `localhost ok=1 changed=0 failed=0` |
| Canonical identity | Initial reconcile `changed=19 failed=0`; remove-membership reconcile `changed=2 failed=0` (denial confirmed both authoritative and live); restore+drift reconcile `changed=4 failed=0` (restoration and new sudo command confirmed); final no-op reconcile `changed=1 failed=0`, fully explained (§6) |
| Signed S3/restic | restic `30/30`; Prometheus `12/12`; Thanos `10/10` |
| Functional verdict | PASS with documented applicability exceptions: unsigned SeaweedFS rows C6–C8; Wazuh manager C11 and log-shipping C3/C6 require an independent `log-server`; `freeipa-client.md` C5/C8 need the spec's own `pilotuser` fixture account |
| New this round | 2 real playbook defects found+fixed (check-mode/fresh-host ordering in the NFS apply playbooks; `ipa service-add` needed `--force` in this no-DNS topology); 1 documentation gap closed (`freeipa_roster_file` needed on `nexus` too); 1 procedural ordering note added (identity reconcile before a fresh host's NFS share group-ownership step); 1 stale gotcha row corrected (vars-file `main.yaml` selection was never actually the cause of a reconcile skip) |
| Evidence integrity | All produced TREC recordings passed `cast_verify` (safe to share); 2 vault-fill attempts with secret-scan findings were quarantined and never published, per the process note in the evidence file |
| Publication | [`2026-07-23-round-13.md`](../evidence/minimal-poc-architecture/2026-07-23-round-13.md); secret values and ephemeral addresses omitted |

The compact evidence record contains the current candidate provenance, result matrix, documented
exceptions, and raw-artifact pointers. Earlier runs remain available in their evidence records and
Git history and are intentionally not duplicated here.
