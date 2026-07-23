# Runbook — Minimal PoC Architecture: FreeIPA + Wazuh + Grafana 3-VM Rebuild

> Status: **VERIFIED**
> Latest completed pass: 2026-07-23 (Asia/Taipei), round 14
> Evidence: [`2026-07-23-round-14.md`](../evidence/minimal-poc-architecture/2026-07-23-round-14.md)
> Semantic action catalog expansion (local-only, no VM rebuild): [`2026-07-23-semantic-actions-expansion.md`](../evidence/minimal-poc-architecture/2026-07-23-semantic-actions-expansion.md)
> Automation: `playbooks/site.yml` plus the day-2
> `playbooks/apply/freeipa-identity-apply.yml` reconciler
> Maintainer: sre

Round 14 rebuilt the same topology from a clean environment specifically to validate two
capabilities added the same day as round 13: **`pilot actions` semantic TUI automation**
(`pilot edit/deploy/reconcile --actions <scenario.json>` — drives the real screens via synthesized
key events resolved against live labels, not raw keystroke/index counting) and **`pilot services`**
(host-local package/image cache for `vm-target up`, `--services local`). It found and fixed one real
multi-host bug in the new edit automation (authorized; diff in the round-14 evidence file) and one
stale/misleading roster-authoring instruction (documentation-only; corrected in §2/§3.5 below).
Round 13's own findings (2 playbook fixes, both already merged) remain valid and are not
re-litigated here. This runbook keeps only the current sanitized facts and links; its one-time
acceptance recordings are disposable.

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
| Fact timestamp | 2026-07-23T19:05+08:00 |
| Targets | `freeipa-server`, `nexus`, `client-vm` |
| VM sizing | FreeIPA: 2 vCPU/4096 MiB/30 GiB; nexus: 6/12288/80; client: 2/2048/20 |
| VM provisioning | `pilot vm-target up --services local` — host-local cache reused from an already-running `pilot services up --profile dev-lite` session |
| Inventory source | Generated from a fresh gitignored workspace; `hosts.yml` built via `pilot edit --actions` (semantic automation), group_vars/vault via interactive `pilot edit`, then `pilot inventory generate` |
| Stage | `sandbox` |
| Alignment | Actual hosts and populated role groups matched the intended topology |
| Manual extra `-e` | Empty; inventory-derived values were accepted through the wizard/scenario |
| Tested candidate | commit `23786e76dc8366660cbddcbc0ed8e8111cd892dd`; tree `14e4761d438b27dfb80a56db586ae619775028f8`; plus 1 authorized Go-source fix to `pilot edit --actions` (not yet committed — see round-14 evidence) |
| Result | Site-wide deploy via `pilot deploy --actions` passed `failed=0` on all three hosts; `freeipa-identity` reconcile via `pilot reconcile --actions` passed initial apply (`changed=21`), remove-membership (`changed=1`, denial confirmed live+authoritative), restore+drift-correction (`changed=3`, new sudo command live after `sss_cache -E`), and a final no-op reconcile was genuinely `changed=0 failed=0` — no exceptions needed this round |

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
- Optionally, `pilot services up --profile dev-lite` running (`pilot services status` to check) so
  `vm-target up --services local` can reuse a host-local package/image cache across rebuilds instead
  of re-pulling from public upstreams every time; it is fail-closed (errors rather than silently
  falling back) if the stack isn't healthy. This is host-level cache state, not part of the
  disposable candidate — do not tear it down between rounds.
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
sudo access is required, **and** an enabled HBAC rule granting `admin` login (e.g. a
`breakglass-admin-access`-style rule, `hostcat: all`) must already exist in the same roster edit —
`freeipa-identity-apply.yml` refuses to disable `allow_all` without one (confirmed live 2026-07-23,
round 14; the example roster already includes this rule for exactly this reason).

Do **not** add a bare top-level `ipa_admin_password` key to the roster file itself, despite what
`freeipa-identity-apply.yml`'s own top-of-file comment and `contracts/freeipa-identity.yaml`'s
`groupVars` declaration both imply — a canonical (`schema_version: 1`) roster's own top-level-key
gate rejects it (confirmed live 2026-07-23, round 14: preview failed, no mutation). The admin
credential belongs in `freeipa.admin.password` inside the roster; the bare `ipa_admin_password` the
contract-level preflight check wants comes from **selecting `.vault/main.yaml`** at the deploy/
reconcile wizard's own vars-file prompt (§3.5) — that file's copy of the same key satisfies the tool
side without ever appearing in the roster.

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
./pilot vm-target up --name freeipa-server --base-image almalinux-9 --vcpus 2 --memory 4096 --disk 30 --services local
./pilot vm-target up --name nexus --base-image ubuntu-24.04 --vcpus 6 --memory 12288 --disk 80 --services local
./pilot vm-target up --name client-vm --base-image ubuntu-24.04 --vcpus 2 --memory 2048 --disk 20 --services local
./pilot vm-target list
```

`--services local` requires `pilot services up` to already be running (see §2); drop it for an
intentionally uncached run. Bring these up **serially, one at a time** — not concurrently — even
though `pilot vm-target up` itself now tolerates parallel invocations; this runbook's own execution
discipline keeps VM lifecycle operations serialized for auditability.

Do not assume addresses from a previous run. If pilot state and libvirt disagree, resolve only the
three exact target domains/directories after read-only inspection; never delete shared images or a
broad directory.

### 3.3 Build the inventory workspace

Use one fresh workspace consistently throughout the run:

```bash
./pilot edit --dir tmp/pilot-verify-minimal-poc-r14
./pilot inventory generate --dir tmp/pilot-verify-minimal-poc-r14
./pilot edit --dir tmp/pilot-verify-minimal-poc-r14
```

In the first edit pass, set every host's SSH user, exact generated private-key path, and role
membership. In the second, fill group variables and `.vault/main.yaml`. The nested identity roster
is the tool-documented exception and may be authored from the committed roster example.

The entire build — `hosts.yml` (hosts, `ansible_host`/`ansible_user`/SSH-key/`env` fields, role
checklist, role presets, extra host vars), `group_vars/*.yml`, and the plaintext `.vault/*.yaml`
skeleton — can be driven either interactively (`trec drive` or a live `trec mcp` session) or
non-interactively via **`pilot edit --actions <scenario.json> --presentation --trace-out <path>`**
— a versioned JSON scenario of semantic action steps, resolved against the live in-memory screen
model rather than rendered terminal text or a remembered index. Discover the current action
contract fresh from the binary being tested, never from memory: `./pilot actions list` / `./pilot
actions schema` (as of 2026-07-23 this is 25 edit-workflow actions plus the standalone `deploy`/
`reconcile`). It still needs a real PTY (same TTY guard as the interactive path) even though it
takes no live keystrokes, so wrap it in a plain `trec` recorder (no `drive` script needed — the
scenario file drives itself):

```bash
CI=1 trec -o casts/01-edit-hosts.cast --title "pilot edit --actions -- hosts.yml" \
  -- ./pilot edit --dir <workspace> --actions scripts/edit-hosts-scenario.json \
     --presentation --trace-out evidence/edit-hosts-trace.jsonl
```

Every action drives the same real menu a human would (`choose`/`moveCursor` only ever resolve
against labels that genuinely exist on the *current* live screen — there is no shortcut that
mutates `hosts.yml`/group_vars/vault data directly), so a `--presentation` + `trec` recording is
real evidence of menu correspondence, not a claim to take on faith.

Two permanent, deliberate exclusions — not gaps, the wizard has no menu path here for a human
either: the `ansible-vault`-**encrypted** shellout (`pilot edit` suspends its own Program and shells
out to the real `ansible-vault edit` with stdio wired to the terminal — not a screen, can't be
key-driven) and any vault file whose top-level values aren't plain scalars (nested YAML/roster —
`pilot edit`'s own `doc.Editable()` check rejects this for everyone). Fill both by hand via a text
editor or `trec drive`.

Vault/extra-var actions (`add_vault_key`, `set_vault_value`, `add_extra_var`, `edit_extra_var`)
accept a value **or** a `value_env` field naming an environment variable to read the real value
from at run time — mirroring `trec drive`'s `TEXT_ENV`/`--secret-env` convention, so a real secret
never has to sit in the scenario JSON in cleartext. **Never combine `value_env` with
`--presentation`**: `pilot edit` refuses the combination outright, because `--presentation` dumps
the live screen after every step and the vault/extra-var key-list screen renders the saved value in
plain text — there is no per-field redaction hook in `View()`. `--trace-out`'s JSONL never carries
the literal value either way (a `value_env` step's typed keys are recorded as a `«redacted»`
placeholder). Run `value_env` scenarios without `--presentation`; the run is silent (by design —
`--actions` never opens a live `tea.Program`, so nothing renders unless `--presentation` asks for
it) but the file mutation and the trace are still real.

One `save_hosts`/workspace-boundary rule worth knowing before authoring a multi-workspace scenario:
`save_hosts` leaves the router at the top menu (it does **not** quit the session) specifically so a
`group_vars`/`.vault` action can follow it in the same scenario; switching from one already-open
group_vars/vault file to a *different* file (or a different workspace entirely) requires that
file's own `save_*`/`discard_*` action first — the automation will not guess a discard confirm's
answer on your behalf.

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
./pilot deploy -i tmp/pilot-verify-minimal-poc-r14/inventory.yml --timeout 90m
```

Select the full-site `site.yml` scope and `sandbox` stage. Accept inventory-derived automatic
values when the wizard presents them. Leave the later manual extra-`-e` field empty. If a required
value cannot be derived and would need manual input there, stop and fix the inventory/group vars;
do not improvise an override during the evidence run.

Run the full preview (`--check --diff`) and continue to real apply only when every host reports
`failed=0`.

As an alternative to driving the interactive wizard by hand or with `trec drive`, **`pilot deploy
--actions <scenario.json> --presentation --trace-out <path>`** answers the exact same prompt chain
from a single standalone `deploy` action (`inventory` + an `answers` array of `{prompt, select|
text|confirm}` entries, matched by substring against the live prompt text — same discipline as
`trec`'s own `SELECT`: pick a substring unique to that prompt). It still runs the real preflight,
inventory preview, stage gate, `--check --diff` preview, and the apply confirmation — nothing about
the underlying transaction changes. Confirmed live 2026-07-23 (round 14) for this exact topology's
full site-wide deploy, end to end, on the first fully-correct attempt (`failed=0` all hosts).
Two traps found authoring the answers array:

- The apply confirm chain (§ below) asks the *same literal prompt string*
  ("確定要執行以上指令嗎？") twice — once for the preview run, once for the real apply. The scenario
  validator rejects two answers sharing one literal `prompt` value, so give the two answers
  slightly different (but still substring-matching) text, e.g. with and without the trailing `？`.
- It still needs a real PTY (same TTY guard as interactive `pilot deploy`) despite taking no live
  keystrokes — wrap it in a plain `trec` recorder, not `trec drive`.

On a genuinely fresh host, if `nexus`'s `freeipa-nfs-server` component fails a real apply with
`chgrp failed: failed to look up group <name>` for a roster-managed NFS share ownership group (e.g.
`data-project-alpha-rw`), that group does not exist yet because §3.5's identity reconciliation has
not run. Run §3.5 now, then re-run this site-wide deploy — every already-applied component reports
`changed=0` and only the NFS share step completes.

### 3.5 Identity reconciliation

Run the separate day-2 reconciler against the same inventory:

```bash
./pilot reconcile -i tmp/pilot-verify-minimal-poc-r14/inventory.yml --timeout 90m
```

Select `freeipa-identity`, `freeipa-server`, and `sandbox`. Set `freeipa_roster_file` on the managed
host through `pilot edit` (see §2 — also required on `nexus`); the reconciler loads that canonical
roster separately via that host var, independent of whatever is selected at the vars-file prompt
below. At the secret vars-file prompt select `.vault/main.yaml`, which supplies the
`ipa_admin_password` referenced by the roster. Leave manual extra `-e` empty. A clean recap with
every reconcile task skipped means the roster was not loaded and is not a successful identity apply.

`.vault/main.yaml` here satisfies `contracts/freeipa-identity.yaml`'s own required-input preflight
check (it wants a bare `ipa_admin_password`); the roster file's `freeipa.admin.password` is what the
canonical Ansible code path actually reads. Answering **yes** to the main.yaml prompt is correct —
do not redirect this prompt at the roster path itself (see §2's note on why the roster must not
carry a bare top-level `ipa_admin_password`).

`pilot reconcile --actions <scenario.json>` (a standalone scenario with exactly one `reconcile`
action) drives this same prompt chain non-interactively — same mechanics, same two traps, as
§3.4's `pilot deploy --actions` note. Confirmed live 2026-07-23 (round 14) for the full initial
apply / remove-membership / restore+drift-correction / idempotency-rerun cycle in §4.6.

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
  down` for each.
- Never use a broad recursive deletion target, unresolved variable, wildcard, repository root, or
  shared image directory.

**Do not delete the run's workspace, casts, traces, or other evidence files as part of teardown.**
They are gitignored (never committed) precisely so they can be reviewed as one-time proof without
polluting the repo — "gitignored" means "not committed," not "disposable to the agent." Tearing down
the VMs is safe and expected; deleting the evidence the run just produced, before the user has had a
chance to look at it, is not (confirmed the hard way 2026-07-23, round 14: the prior wording here read
"remove only this run's exact gitignored workspace," and following it literally at the end of a run
deleted 15 casts the user still wanted to see). Leave the workspace in place and tell the user its
path; only remove it once the user has reviewed it or explicitly asks for cleanup.

## 6. Current gotchas

| Symptom | Cause | Current action |
|---|---|---|
| First live sudo is denied although `ipa hbactest --service=sudo` allows it | Stale SSSD sudo cache on the client | Run `sss_cache -E`, restart `sssd`, and repeat the live and authoritative checks. Do **not** add `sudo` to `sssd.conf` `services=`; the sudo responder is socket-activated and that edit breaks its socket. |
| `pilot deploy --dir ...` is rejected | `deploy` takes an inventory with `-i`; `--dir` belongs to authoring commands such as `pilot edit` | Use the §3.4 invocation. |
| Site deploy asks to confirm auto-detected host variables | These are derived from inventory and are distinct from the manual extra-`-e` field | Accept the detected values; keep the manual field empty. If a required value is not derived, stop and fix inputs. |
| Identity reconcile reports `failed=0` but all mutation tasks skip | `freeipa_roster_file` is not set as a host var on the target (see §2); this is independent of whatever is selected at the vars-file prompt — selecting `.vault/main.yaml` there is fine for a canonical (`schema_version: 1`) roster and does not by itself cause a skip, confirmed live 2026-07-23 (round 13) | Confirm `freeipa_roster_file` is set on the managed host, not just which file was picked at the vars-file prompt. |
| Identity reconcile preview fails with "Canonical roster contains an unknown freeipa/admin field" | A bare top-level `ipa_admin_password` key was added to the roster file itself, following `freeipa-identity-apply.yml`'s own (stale) top-of-file comment and `contracts/freeipa-identity.yaml`'s required-input declaration — the canonical top-level-key gate rejects it. Confirmed live 2026-07-23 (round 14) | Remove it from the roster; put `freeipa.admin.password` there instead, and satisfy the *contract's* `ipa_admin_password` requirement by selecting `.vault/main.yaml` at the vars-file prompt (§3.5) — not by editing the roster. |
| Identity reconcile preview fails with "Refusing to disable allow_all without an enabled admin break-glass rule" | `hbac.disable_allow_all: true` with no `enabled: true` HBAC rule granting the `admin` user `hostcat: all` login — a deliberate safety gate, not a bug. Confirmed live 2026-07-23 (round 14) | Add a `breakglass-admin-access`-style rule (`subjects.users: [admin]`, `hostcat: all`, `services: [sshd]`, `enabled: true`) in the same roster edit — see `playbooks/apply/freeipa-identity.roster.example.yaml`, which already includes one for exactly this reason. |
| Generated files do not contain intended wizard values | Saving the wrong cursor field can still exit successfully | Inspect saved host, role, group-var, and vault-key facts before deployment; keep TUI-driving details in the trec skills. |
| A no-op reconcile still reports changes | Forced test-password handling, HBAC disable behavior, or Dogtag-owned mode correction may be non-idempotent; also, any roster user who has never actually logged in yet (`krbLastPwdChange == krbPasswordExpiration`) has their bootstrap password legitimately re-applied every run regardless of `force_change`, by design (only a user's own real password change breaks the equality) | Identify the exact changed tasks and preserve their real count; do not claim `changed=0`. |
| A brand-new roster user's first live login/sudo fails with "Password change required but no TTY available", even though the roster sets `force_change: false` | FreeIPA's own `ipa passwd` always arms the forced-change flag on first-ever password assignment, independent of the roster flag — `force_change` only controls whether a *routine rerun* re-arms it for an already-onboarded user | Personalize with a scripted `kinit <user>` (3-line forced-change stdin: old/new/new), confirmed live 2026-07-23 to work over `pilot vm-target exec` piped stdin without needing a PTY (unlike the equivalent SSH+PAM path, which does need one) |
| SeaweedFS anonymous C6–C8 fail while restic credentials are enabled | Full-site correctly selected signed S3 mode; the legacy rows intentionally send unsigned requests | Require the signed config/runtime probes plus `restic-backup` and Thanos verification to pass; do not weaken authentication. |
| `pilot verify docs/verification/restic-backup.md ... --host restic-backup` reports a `C6` timeout | Default per-row timeout (15s) is too short for `restic check --retry-lock 120s` run concurrently across all hosts sharing one repository — confirmed live 2026-07-23 | Pass `--timeout 180` for group verification of this spec, per its own v1.3 changelog note. |

Detailed component-specific troubleshooting belongs in the aligned spec/runbook for that component,
not in this composition runbook.

## 7. Latest verified evidence

| Field | Round 14 record |
|---|---|
| Verified at | 2026-07-23T19:05+08:00 |
| Tested revision/tree | `23786e76dc8366660cbddcbc0ed8e8111cd892dd` / `14e4761d438b27dfb80a56db586ae619775028f8`, plus 1 authorized Go-source fix to `pilot edit --actions` (diff in the evidence file; not yet committed) |
| Targets | Fresh `freeipa-server` (AlmaLinux 9), `nexus` and `client-vm` (Ubuntu 24.04); all provisioned via `vm-target up --services local` |
| Focus | Validating `pilot actions` semantic TUI automation and `pilot services` host-local cache (user-requested), not re-deriving round 13's own findings |
| hosts.yml build | Entire 3-host, 22-role-assignment `hosts.yml` built via `pilot edit --actions` in one non-interactive run (after the fix) |
| Site apply | `pilot deploy --actions` — `client-vm ok=92 changed=41 failed=0`; `freeipa-server ok=78 changed=33 failed=0`; `nexus ok=209 changed=95 failed=0`; `localhost ok=1 changed=0 failed=0` |
| Canonical identity | `pilot reconcile --actions` throughout — initial `changed=21 failed=0`; remove-membership `changed=1 failed=0` (denial confirmed both authoritative and live — live SSH itself was refused, not just sudo); restore+drift `changed=3 failed=0` (membership and a newly-added sudo command both confirmed live after `sss_cache -E`); final no-op reconcile was genuinely `changed=0 failed=0` — no non-idempotent exceptions hit this round |
| §4 verification | FreeIPA hbactest+live allow/deny: PASS. Grafana/Thanos Query (`site-nexus` series=1): PASS. Loki (`pilot-siem` real log lines): PASS. restic-backup: 4 snapshots across all 3 hosts in the shared repo: PASS. Wazuh FIM: real-time whodata alert (rule 554) matched the trigger file: PASS |
| Functional verdict | PASS. Round 13's own documented applicability exceptions (unsigned SeaweedFS C6–C8, Wazuh/log-shipping needing an independent `log-server`, `freeipa-client.md` C5/C8 fixture account) were not re-tested this round and remain as last recorded |
| New this round | 1 real Go bug found+fixed (`pilot edit --actions` couldn't build a multi-host `hosts.yml`, regression test added); 1 stale documentation instruction corrected (roster must not carry a bare top-level `ipa_admin_password`; §2/§3.5/§6); `pilot deploy/reconcile --actions` validated end-to-end against this full topology for the first time, including the duplicate-literal-prompt authoring trap (§3.4) |
| Evidence integrity | All 15 produced TREC recordings passed `cast_verify`: complete, exit 0, 0 secret-scan findings, safe to share. No leaked `trec mcp` sessions |
| Publication | [`2026-07-23-round-14.md`](../evidence/minimal-poc-architecture/2026-07-23-round-14.md); secret values and ephemeral addresses omitted |

The compact evidence record contains the current candidate provenance, result matrix, documented
exceptions, and raw-artifact pointers. Earlier runs remain available in their evidence records and
Git history and are intentionally not duplicated here.
