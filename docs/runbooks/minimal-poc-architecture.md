# Runbook — Minimal PoC Architecture: FreeIPA + Wazuh + Grafana 3-VM Rebuild

> Status: **VERIFIED**
> Latest completed pass: 2026-07-25 (Asia/Taipei), round 16
> Evidence: [`2026-07-25-round-16.md`](../evidence/minimal-poc-architecture/2026-07-25-round-16.md)
> Round 15 (adopted `vm-target topology`): [`2026-07-23-round-15.md`](../evidence/minimal-poc-architecture/2026-07-23-round-15.md)
> Round 14 (deep §4 verification matrix): [`2026-07-23-round-14.md`](../evidence/minimal-poc-architecture/2026-07-23-round-14.md)
> Semantic action catalog expansion (local-only, no VM rebuild): [`2026-07-23-semantic-actions-expansion.md`](../evidence/minimal-poc-architecture/2026-07-23-semantic-actions-expansion.md)
> Reusable `trec drive` scripts (edit-menu-only rebuild): [`scripts/minimal-poc/`](../../scripts/minimal-poc/)
> Automation: `playbooks/site.yml` plus the day-2
> `playbooks/apply/freeipa-identity-apply.yml` reconciler
> Maintainer: sre

Round 16 evaluated whether §3.3's workspace build could go entirely through `pilot edit`'s real
interactive menu — including the host_vars editor, roster manager, and NFS-role-add roster
bootstrap added after round 15 — rather than the `--actions` JSON scenario round 15 used, and
rewrote §3.3 to document exactly what that path can and cannot cover today. It rebuilt the full
three-node topology from zero this way (real `trec` recordings of every wizard invocation, no
`--actions`) and proved out the full chain end to end: site-wide deploy (`failed=0` all hosts,
first real-apply attempt) and `freeipa-identity` reconcile (`changed=15 failed=0`, plus a live
drift-correction re-run) both passed. This round's own verification focus was the edit-menu
coverage and a light §4.1/§4.2 spot-check (HBAC allow/deny + one Thanos metric, both fully passing
after two authoring fixes below), not a re-run of the full §4 matrix — round 14's deep verification
(Grafana/Loki, restic snapshots, Wazuh FIM) remains the last full pass and is not re-litigated here.
Two suspected implementation defects were found and are reported, not silently patched — see §6.
Round 14/15's own findings remain valid. This runbook keeps only the current sanitized facts and
links; its one-time acceptance recordings are disposable, but the `scripts/minimal-poc/*.drive`
files above are checked-in, reusable evidence of the edit-menu path and are not disposable.

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

Before building the workspace, use the companion [Minimal PoC configuration guide](minimal-poc-configuration.md)
for the complete role membership, group vars, host vars, and vault key contract. The semantic-action
recordings under `tmp/` are smoke coverage for the editor API, not a complete walkthrough of these
component-specific values.

## 0.5 Current fact summary

| Item | Last verified value |
|---|---|
| Fact timestamp | 2026-07-25T15:04+08:00 |
| Targets | `freeipa-server`, `nexus`, `client-vm` |
| VM sizing | FreeIPA: 2 vCPU/**4608 MiB**/30 GiB (bumped from 4096 this round — see §6); nexus: 6/12288/80; client: 2/2048/20 |
| VM provisioning | `pilot vm-target topology up --topology docs/topologies/minimal-poc-topology.yaml` (spec's own `services: local` key); see §3.2 |
| Inventory source | Generated from a fresh gitignored workspace; `hosts.yml` (incl. role checklist, `add_extra_var`-equivalent `freeipa_roster_file`), `host_vars/nexus.yml`, and the FreeIPA identity roster's initial NFS/admin block all built through the real interactive `pilot edit` menu — no `--actions` scenario this round, see §3.3; `pilot inventory generate` backfilled group_vars/vault skeletons; remaining vault secrets and the roster's HBAC/sudo/membership sections filled via the edit menu's vault `➕ 新增 key` action and one sanctioned hand-edit of the roster's nested YAML respectively (§3.3) |
| Stage | `sandbox` |
| Alignment | Actual hosts and populated role groups matched the intended topology |
| Manual extra `-e` | Empty; inventory-derived values were accepted through the wizard |
| Tested candidate | commit `228938b` (clean tree at round start); topology memory sizing and `scripts/minimal-poc-section4-spotcheck.sh`'s JSON parsing fixed in-round (documented below, both are config/tooling, not `pilot` Go source or an Ansible playbook); rebuilt `./pilot` binary; no Go source changes this round |
| Result | Site-wide deploy via the interactive `pilot deploy` wizard passed `failed=0` on all three hosts on the **first** real-apply attempt (`client-vm ok=92 changed=41`, `freeipa-server ok=78 changed=33`, `nexus ok=206 changed=95`) — no retry needed this round; `freeipa-identity` reconcile via the interactive `pilot reconcile` wizard passed initial apply (`changed=15 failed=0`) plus a live sudo-command drift-correction re-run (`changed=3 failed=0`); §4.1 HBAC allow (alice)/deny (bob) and §4.2 one Thanos metric (`up{site="site-nexus"}=1`) spot-checked live, all 8/8 checks passing — see round-16 evidence for scope and the two fixes that got there |

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
  `thanos_aws_secret_access_key`, and `alertmanager_config`. `ipa_dm_password` remains genuinely
  optional (falls back to `ipa_admin_password`) — round 16 found and fixed a bug where `pilot
  deploy`'s hard completeness gate demanded it anyway despite `internal/inventory/vault.go` marking
  it `Optional: true`; see §6's now-historical gotcha entry if you're on a checkout older than that
  fix.
- A canonical FreeIPA identity roster with `schema_version: 1`, the `freeipa` connection/safety
  block, and the required `users`, `groups`, `hosts`, `hbac`, `sudo`, and `nfs` objects. A user entry
  with no `ssh_keys` field at all is fine — round 16 found and fixed a crash in
  `freeipa-identity-apply.yml`'s user-normalization task that made this combination (exactly what
  `pilot edit`'s roster manager, §3.3, produces) fail on ansible-core 2.19.x; see §6's now-historical
  gotcha entry if you're on a checkout older than that fix. Add an explicit `ssh_keys:
  {authoritative: true, values: [...]}` block only when a user actually has SSH public keys to
  authorize.

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
roster path on both hosts. The project convention is `.vault/ipa-identity.yaml` under the
workspace; there is **no playbook default path**, so pass its deployment-controller absolute path,
for example `<workspace>/.vault/ipa-identity.yaml` (on the investigated controller:
`/home/ubuntu/ansible/.vault/ipa-identity.yaml`). Do not use `.vault/main.yaml` as the roster path.

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

The three nodes' names, sizing, base images, and required role-group membership are captured once
in [`docs/topologies/minimal-poc-topology.yaml`](../topologies/minimal-poc-topology.yaml) — a
declarative spec `pilot vm-target topology` consumes directly. Prefer it over three hand-typed
`pilot vm-target up` invocations: the sizing/role facts then live in one reviewable file instead of
being re-typed (and potentially drifting) in this prose every round. Remove only the three named
disposable targets and the exact gitignored PoC workspace after read-only confirmation. Retain
shared base images. Rebuild the whole topology in one command:

```bash
./pilot vm-target topology up --topology docs/topologies/minimal-poc-topology.yaml
./pilot vm-target topology status --topology docs/topologies/minimal-poc-topology.yaml
```

The spec's own `services: local` key is the declarative equivalent of `vm-target up --services
local` — it requires `pilot services up` to already be running (see §2); remove that key (or set it
to `none`) for an intentionally uncached run. `topology up` provisions every not-yet-running node
**concurrently** (one goroutine + one `*vmtarget.Manager` per node; an already-running node with a
matching name is left alone, so re-running this after only one node needed a rebuild is idempotent)
and then wires every node's declared `wire:` peers into `/etc/hosts` once all three have an IP. The
previous revision of this runbook deliberately serialized three separate `vm-target up` calls "for
auditability" even after `pilot vm-target up` itself became safe under concurrent invocation
(2026-07-06 cross-process bring-up race fix, `internal/vmtarget`'s `Store.Mutate` flock) — that
caution is no longer buying anything now that bring-up is expressed as one auditable command against
one committed spec file, and round 15's rebuild confirmed concurrent bring-up completes correctly
for all three nodes (see the round-15 evidence link at the top of this file). `topology status`
reports exactly the three spec-declared nodes (name/status/IP/groups/wire), scoped to this topology
rather than every VM `pilot vm-target list` happens to know about; either view reads the same
underlying state, so use whichever is more convenient.

Do not assume addresses from a previous run. If pilot state and libvirt disagree, resolve only the
three exact target domains/directories after read-only inspection; never delete shared images or a
broad directory.

### 3.3 Build the inventory workspace

Use one fresh workspace consistently throughout the run:

```bash
./pilot edit --dir <workspace>
./pilot inventory generate --dir <workspace>
./pilot edit --dir <workspace>
```

In the first edit pass, set every host's SSH user, exact generated private-key path, and role
membership. In the second, fill group variables and `.vault/main.yaml`. The nested identity roster
is a narrower tool-documented exception than it used to be (see below) and may still be authored
from the committed roster example for the parts the wizard doesn't cover.

#### Driving the build entirely through the real interactive menu

As of round 16 (2026-07-25), this is the recommended default path — every step below goes through
`pilot edit`'s genuine live TUI, driven and recorded by `trec drive --script <file>` (label-based
`CHOOSE`/`TOGGLE`, never blind `DOWN <n>` counting — see the `pilot-trec-verification` skill). The
checked-in, reusable scripts in [`scripts/minimal-poc/`](../../scripts/minimal-poc/) reproduce this
exact sequence; read that directory's `README.md` for the required env vars and run order before
using them. In outline:

- **`hosts.yml`**: add each host, set `ansible_host`/`ansible_user`/SSH-key, then the role
  checklist. The moment `freeipa-nfs-server` is newly checked on a host with no
  `freeipa_roster_file` set yet, the wizard auto-derives
  `<workspace>/.vault/ipa-identity.yaml`, sets that host's `freeipa_roster_file` extra var to it,
  and prompts once (masked) for the FreeIPA admin password — writing a *minimal* roster
  (`schema_version: 1`, `freeipa.admin.{principal,password}`, one `nfs.servers` entry for that
  host, `shares: []`) and filling `.vault/main.yaml`'s `ipa_admin_password` from the same value.
  This fires for `freeipa-nfs-server` only, never `freeipa-nfs-client` — set `freeipa_roster_file`
  by hand (host's "其他變數" menu) on any *other* host whose apply playbook also reads the roster
  (in this topology, `freeipa-server` — point it at the same absolute path the bootstrap already
  used on nexus).
- **`host_vars/<host>.yml`**: a per-host menu item, `host_vars/<host>.yml(必填、無安全預設值的設定)`,
  appears automatically once that host has a role with such a key (today just
  `prometheus_site_label` for `prometheus`, gating on `prometheus-apply.yml`'s hard requirement —
  see `docs/verification/prometheus.md` §1.5). Selecting it auto-scaffolds the file and reuses the
  same flat key-editor `group_vars/` uses.
- **`group_vars/*.yml`** and **`.vault/main.yaml`**: unchanged from before — `pilot inventory
  generate` backfills the group_vars skeleton from `.example.yml` files and (only on a workspace
  with no existing vault file) a vault skeleton; fill remaining group_vars values and add any vault
  key `pilot inventory generate` didn't already create via `.vault/`'s `➕ 新增 key` action.
- **`roster` (top-menu item)**: append-only `👤 Users` / `👥 Groups` CRUD against the same canonical
  roster the NFS bootstrap already created. Adding a user writes only `{name, state: present}`;
  adding a group writes only `{name, state: present, category}` (category from a
  team-/data-/access-/role- picker matching §2's prefix rule). Both dry-run against the roster
  validator first and refuse (showing the violation) rather than writing anything invalid.
- **`🔍 檢查設定完整性` (top-menu item)**: an advisory ✅/❌ report sharing its checks with `pilot
  deploy`'s own hard gate (missing/CHANGE-ME vault keys, unfilled host_vars, roster structural
  violations) — run it before deploying; it never blocks a save or exit itself.

What the edit menu still cannot do — hand-edit the roster's nested YAML for these, the same
tool-endorsed exception as before, now narrower in scope:

- HBAC rules, sudo rules, hostgroups, and NFS shares/exports/automount entries.
- Group and user **membership** (the roster manager creates the bare group/user objects only).
- A user's `password`/`ssh_keys` fields — the roster manager's `➕ 新增 User` writes only
  `{name, state}`, so add these by hand when a user needs a password or an authorized SSH key.

Run `./pilot roster lint <roster-file>` after any hand edit — it checks the same rules
`freeipa-identity-apply.yml` enforces at real-apply time, without needing a live target.

The wizard also has an `ansible-vault`-**encrypted** shellout exclusion (`pilot edit` suspends its
own Program and shells out to the real `ansible-vault edit` with stdio wired to the terminal — not
a screen, can't be key-driven); fill that by hand via a text editor or `trec drive` if the workspace
uses an encrypted vault file.

#### Alternative: non-interactive `--actions` scenario

The same `hosts.yml`/`group_vars`/`.vault` build (not the roster manager or host_vars editor, which
postdate the `--actions` action catalog and are not yet covered by it as of 2026-07-25) can also be
driven non-interactively via **`pilot edit --actions <scenario.json>
--presentation --trace-out <path>`** — a versioned JSON scenario of semantic action steps, resolved
against the live in-memory screen model rather than rendered terminal text or a remembered index.
Discover the current action contract fresh from the binary being tested, never from memory:
`./pilot actions list` / `./pilot actions schema`. It still needs a real PTY (same TTY guard as the
interactive path) even though it takes no live keystrokes, so wrap it in a plain `trec` recorder (no
`drive` script needed — the scenario file drives itself):

```bash
CI=1 trec -o casts/01-edit-hosts.cast --title "pilot edit --actions -- hosts.yml" \
  -- ./pilot edit --dir <workspace> --actions scripts/edit-hosts-scenario.json \
     --presentation --trace-out evidence/edit-hosts-trace.jsonl
```

Every action drives the same real menu a human would (`choose`/`moveCursor` only ever resolve
against labels that genuinely exist on the *current* live screen — there is no shortcut that
mutates `hosts.yml`/group_vars/vault data directly), so a `--presentation` + `trec` recording is
real evidence of menu correspondence, not a claim to take on faith.

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

Skipping this fails a real apply (not just a preview) with `prometheus_site_label is required`,
confirmed live 2026-07-23 (round 15) on a genuinely fresh workspace that had never set it.

Before deployment:

1. Read `pilot vm-target topology status --topology docs/topologies/minimal-poc-topology.yaml` (or
   `pilot vm-target list`) and each target's `show-inventory` output.
2. Inspect the generated inventory and confirm the role placement in §0.5.
3. Confirm required group variables contain real values rather than `CHANGE-ME` or empty defaults,
   and that `host_vars/nexus.yml`'s `prometheus_site_label` above is present.
4. Confirm vault **key names only** and compare them with §2.
5. Run the complete deploy preflight; never choose its skip option.

The wizard save confirmation proves a write occurred, not that every intended field is correct;
inspect the generated files before proceeding.

### 3.4 Site-wide deployment

Run the site-wide wizard using the generated inventory:

```bash
./pilot deploy -i <workspace>/inventory.yml --timeout 90m
```

Select the full-site `site.yml` scope and `sandbox` stage. Accept inventory-derived automatic
values when the wizard presents them. Leave the later manual extra-`-e` field empty. If a required
value cannot be derived and would need manual input there, stop and fix the inventory/group vars;
do not improvise an override during the evidence run.

Run the full preview (`--check --diff`) and continue to real apply only when every host reports
`failed=0`. Confirmed live 2026-07-25 (round 16) driving this real interactive wizard directly
(`scripts/minimal-poc/03-deploy-sitewide.drive`) rather than `--actions`: `failed=0` on the first
real-apply attempt, once §2's `ipa_dm_password` and this topology's `freeipa-server` memory sizing
(§6) were both fixed ahead of the run.

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
./pilot reconcile -i <workspace>/inventory.yml --timeout 90m
```

Select `freeipa-identity`, `freeipa-server`, and `sandbox`. Set `freeipa_roster_file` on the managed
host through `pilot edit` (see §2 — also required on `nexus`); the reconciler loads that canonical
roster separately via that host var, independent of whatever is selected at the vars-file prompt
below. At the secret vars-file prompt select `.vault/main.yaml`, which supplies the
`ipa_admin_password` referenced by the roster. Leave manual extra `-e` empty. A clean recap with
every reconcile task skipped means the roster was not loaded and is not a successful identity apply.
Confirmed live 2026-07-25 (round 16) driving this real interactive wizard directly
(`scripts/minimal-poc/04-reconcile-identity.drive`): initial apply `changed=15 failed=0`, plus a
live drift-correction re-run (`changed=3 failed=0`) after fixing an authoring mistake in the
roster's own sudo command (§6) — the `pilot-trec-verification` skill's older `n`-then-roster-path
guidance for this exact prompt chain is now stale; it actively fails a canonical roster with a
Go-side `requires input "ipa_admin_password"` error before this document's own **yes** answer
below was applied. That skill has been corrected; don't resurrect the old sequence from memory.

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

§4.1's HBAC checks and §4.2's Thanos `up` check are pure read-only assertions against an already-
deployed site — there is no wizard, prompt, or mutation to observe, so they are scripted (see
below). §4.3 and §4.4 are deliberately **not** scripted: they mutate state and/or drive `pilot
reconcile`'s wizard, and for those the actual thing under test is the live interactive flow itself
(TREC-driven), not just its end state — a canned script would verify the wrong layer. Round 15
evaluated converting all of §4 to scripts and drew the line here; see
[`2026-07-23-round-15.md`](../evidence/minimal-poc-architecture/2026-07-23-round-15.md) for the
tradeoffs considered.

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

Repeatable form: `ALICE_PASSWORD='...' ./scripts/minimal-poc-section4-spotcheck.sh` (see the
script's own header for the full env var list — `ALICE_SUDO_CMD` in particular must match whatever
the *current* roster's sudo rule actually grants). It resolves `nexus`'s IP live from `pilot
vm-target topology status` rather than assuming one, since libvirt DHCP reservations are not
guaranteed identical across rebuilds. It assumes `hbac.disable_allow_all: true` is set on the active
roster (required by §2/§1) — otherwise `hbactest`'s top-level `Access granted` is always `True`
regardless of the real per-rule result (see `docs/runbooks/freeipa-identity.md`'s note on this).

### 4.2 Metrics and logs through Grafana dependencies

- Confirm Grafana, Prometheus, Loki, and Thanos Query readiness.
- Query Thanos for `up` and confirm the `site-nexus` series has value `1`. (Covered by
  `scripts/minimal-poc-section4-spotcheck.sh` above, `THANOS_SITE_LABEL`/`THANOS_PORT` env vars.)
- Query Loki label values and a recent range; confirm the `pilot-siem` stream contains a real event
  generated during this run. (Not yet scripted — no round has needed to repeat this check often
  enough to justify it; add it to the spot-check script if that changes.)

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
  topology down --topology docs/topologies/minimal-poc-topology.yaml` — it tears down exactly the
  three nodes that spec declares (the same three-name scope this step has always required), driven
  from the same file §3.2 used to bring them up, instead of three separate `pilot vm-target down`
  invocations.
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
| Site-wide deploy's real apply fails `nexus`'s `freeipa-client` component with `Joining realm failed: Operations error: Error checking for attribute uniqueness` | Transient FreeIPA/389-ds LDAP contention when two `freeipa-client` hosts run `ipa-client-install` concurrently against the same server (Ansible's default `ANSIBLE_FORKS=20` runs both in the same play) — confirmed live 2026-07-23 (round 15); the losing host is excluded from every subsequent play in that same `ansible-playbook` run, which cascades into unrelated-looking failures on it (e.g. `wazuh-fim`'s agent-auth failing because `wazuh-manager` never got applied to the excluded host) | Simply re-run `pilot deploy` (site-wide is idempotent — already-applied hosts report `changed=0`); only one host is left to enroll on retry, so it no longer races. Not evidence of a topology/bring-up defect. |
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
| `pilot deploy` aborts before any preview with `delivery transaction failed: component "freeipa-server" host "..." resources cpu=2 ramMiB=<observed> ... are below minimum ... ramMiB=4096` | **Suspected environment/topology gap, not a code defect.** `deploy_facts.go` (added 2026-07-24) now gathers real per-host OS facts before the delivery preflight check runs; before that commit the check always saw "facts unavailable" and silently passed. AlmaLinux 9's actual usable RAM under this topology's KVM/virtio overhead landed ~185 MiB below the nominal 4096 MiB `vm-target up --memory` value — confirmed live 2026-07-25 (round 16), first time this exact gate could ever fire for real. | Give `freeipa-server` headroom above the component's declared minimum — `docs/topologies/minimal-poc-topology.yaml`'s `memory: 4608` (was `4096`) reflects this. If the node was already up, `pilot vm-target down --name freeipa-server` then `topology up` again recreates just that one node (the topology's own idempotent skip leaves the other two alone) — but it gets a **new DHCP-assigned IP**, even with the same MAC; re-set that host's `ansible_host` via `pilot edit` and re-run `pilot inventory generate` before redeploying. |
| `pilot deploy`/`pilot reconcile` refuses to run at all with `inventory 完整性檢查沒過(1 項)： - vault: .vault/main.yaml: ipa_dm_password 未設定` | **Fixed** (round 16, 2026-07-26). `internal/inventory/vault.go`'s `ipa_dm_password` catalog entry is marked `Optional: true` and `docs/verification/freeipa-server.md` documents it as not required (falls back to `ipa_admin_password`), but `checkVaultCompleteness`'s key list (`vaultSection.keyNames()`) never filtered on that flag, so `pilot deploy`'s hard gate (`deploy_completeness.go`) treated it as required anyway. `pilot edit`'s own advisory "🔍 檢查設定完整性" report showed the identical ❌ but — being advisory-only — never blocked on it, which is why this could look like it "used to work." Confirmed live 2026-07-25, round 16; root-caused and fixed live 2026-07-26: `keyNames()` now skips `Optional: true` keys, matching `GenerateVaultSkeleton`'s own comment-out-when-Optional behavior (`internal/inventory/vault_test.go`'s `TestExpectedVaultKeysForRoles_ExcludesOptionalKeys` locks this in); re-verified live against the exact original repro (`.vault/main.yaml` with no `ipa_dm_password`, same workspace) — the gate no longer fires. | Upgrade past this fix; `ipa_dm_password` needs no value unless you actually want a separate Directory Manager password. If you're stuck on an older checkout, add it to `.vault/main.yaml` anyway (any value, e.g. equal to `ipa_admin_password`) as a workaround. |
| A real `freeipa-identity` reconcile fails preview with `Type 'method' is unsupported for variable storage` / `<bound method _AnsibleLazyTemplateDict.values of {}>`, tasks masked by `no_log` | **Fixed** (round 16, 2026-07-26). `freeipa-identity-apply.yml`'s "Normalize canonical users for the compatibility reconciler" task did `(item.ssh_keys \| default({}))['values']`. For a roster user with **no `ssh_keys` field at all** (exactly what `pilot edit`'s roster manager's `➕ 新增 User` produces), this was a bracket lookup on a genuinely empty dict for the key `'values'` — Jinja2's item-then-attribute fallback resolution turned that into the dict's own bound `.values` method instead of raising `Undefined`/`KeyError`, which `set_fact` then refused to store. Every prior round's roster populated `ssh_keys` for every user (copied from the committed example), so this path was never exercised before the roster manager started producing bare `{name, state}` entries. Confirmed live 2026-07-25, round 16, on ansible-core 2.19.2; fixed live 2026-07-26 by switching to `.get('values', none)` — a real dict-method call, not a subscript, so it can't hit the same fallback — mirroring an identical `.get(...)` pattern already used elsewhere in the same file (line ~685). Re-verified live against the exact original repro (roster with `alice`/`bob` having no `ssh_keys` field at all, same workspace): preview now completes cleanly (`failed=0`). | Upgrade past this fix. If you're stuck on an older checkout, give every roster user an explicit `ssh_keys: {authoritative: true, values: [...]}` block (empty `values` is fine) before reconciling. |
| §4.1's roster-authorized sudo command (`ALICE_SUDO_CMD`) fails with `sudo: a password is required` right after a fresh identity reconcile, even though `ipa sudorule-show`/`sudo -n -l` on the client show the rule attached with the `!authenticate` option | Same documented SSSD-sudo-cache-staleness gotcha as the row above ("First live sudo is denied...") — a *newly applied* sudo rule needs the same `sss_cache -E && systemctl restart sssd` on the client the rule targets, not just on the FreeIPA server. Confirmed live 2026-07-25, round 16. | Run `sss_cache -E && systemctl restart sssd` on the **client host being sudo'd into** (not the FreeIPA server) after any sudo-rule change, then retry. |
| §4.1's roster-authorized sudo command fails with `Unit sshd.service could not be found` even though the sudo rule itself is correctly attached | **Authoring mistake, not a tool/playbook defect.** The roster granted `/usr/bin/systemctl status sshd`, but the live target (`nexus`) is Ubuntu 24.04, where the real unit is `ssh.service` — AlmaLinux/RHEL and Debian/Ubuntu use different systemd unit names for the same daemon. Confirmed live 2026-07-25, round 16. | Grant a command that actually exists on the target host's OS family (`systemctl status ssh` on Debian/Ubuntu, `systemctl status sshd` on RHEL/AlmaLinux); re-run `pilot reconcile` to apply the correction (a real, useful exercise of the drift-correction path — see §4.4) and re-fresh the client's SSSD sudo cache (row above) before retrying. |
| `scripts/minimal-poc-section4-spotcheck.sh`'s `4.2-thanos-up` check reports `got ''` even though the same script's own `raw:` output shows a genuine `"value":[...,"1"]` result | **Script bug, fixed this round.** `pilot vm-target exec ... 2>&1` merges the SSH host-key warning ("Warning: Permanently added ... known_hosts") into the same stream as the real JSON response — sometimes before it, sometimes after, depending on SSH/curl buffering — and a plain `json.load()`/`json.loads()` fails closed on either ordering (caught by the script's own `except Exception: pass`). Confirmed live 2026-07-25, round 16, both orderings. Fixed by parsing with `json.JSONDecoder().raw_decode()` from the first `{`, which tolerates trailing garbage the way `json.loads()` does not. | Use an up-to-date checkout of the script; if you still see this on an older one, the fix is in the `4.2-thanos-up` block. |

Detailed component-specific troubleshooting belongs in the aligned spec/runbook for that component,
not in this composition runbook.

## 7. Latest verified evidence

| Field | Round 16 record |
|---|---|
| Verified at | 2026-07-25T15:04+08:00 |
| Tested revision/tree | commit `228938b` (clean at round start); in-round config/tooling fixes only — `docs/topologies/minimal-poc-topology.yaml` memory sizing, `scripts/minimal-poc-section4-spotcheck.sh` JSON parsing; rebuilt `./pilot` binary; no Go source changes this round |
| Targets | Fresh `freeipa-server` (AlmaLinux 9, memory bumped to 4608 MiB mid-round — see §6), `nexus` and `client-vm` (Ubuntu 24.04); all provisioned via **`pilot vm-target topology up --topology docs/topologies/minimal-poc-topology.yaml`** |
| Focus | Building the entire workspace through `pilot edit`'s real interactive menu — including the host_vars editor, roster manager, and NFS-role-add roster bootstrap that landed after round 15 — instead of the `--actions` JSON scenario round 15 used; a light §4.1/§4.2 spot-check, not the full §4 matrix (round 14 remains the last full pass) |
| hosts.yml build | 3-host, 22-role-assignment `hosts.yml` built entirely through the live interactive menu (`scripts/minimal-poc/01-edit-hosts.drive`), including the NFS-role-add bootstrap on `nexus` and a hand-set `freeipa_roster_file` extra var on `freeipa-server` |
| group_vars/vault/roster | group_vars and `host_vars/nexus.yml`'s `prometheus_site_label` filled via the live interactive menu; `.vault/main.yaml`'s remaining secrets added via the vault editor's `➕ 新增 key` action (`scripts/minimal-poc/02-edit-vault-secrets.drive`); roster's `access-poc-ssh`/`role-poc-sudo` groups and `alice`/`bob` users added via the new roster manager; HBAC rules, sudo rule, and per-user `ssh_keys` blocks hand-edited (the roster manager doesn't cover these — see §3.3) |
| Site apply | Interactive `pilot deploy` wizard (`scripts/minimal-poc/03-deploy-sitewide.drive`) — `client-vm ok=92 changed=41 failed=0`; `freeipa-server ok=78 changed=33 failed=0`; `nexus ok=206 changed=95 failed=0`; passed on the **first** real-apply attempt, no retry needed |
| Canonical identity | Interactive `pilot reconcile` wizard (`scripts/minimal-poc/04-reconcile-identity.drive`) — initial apply `changed=15 failed=0`; a live drift-correction re-run after fixing an authoring mistake in the roster's sudo command (§6) — `changed=3 failed=0` |
| §4 spot-check | `scripts/minimal-poc-section4-spotcheck.sh`, 8/8 checks passing: FreeIPA hbactest + live — alice (sshd+sudo) allowed, matched `poc-ssh-access`; bob denied. Live `sudo -n -l` showed exactly the roster-authorized command (`systemctl status ssh`, corrected mid-round for Ubuntu — see §6); an unlisted command (`/etc/shadow`) was refused. Thanos Query `up{site="site-nexus"}` = `1`. Full §4.3/§4.4 (restic snapshots, Wazuh FIM trigger, remove/restore identity cycle) not re-run this round — see round 14 |
| Functional verdict | PASS for this round's scope (edit-menu-only rebuild + spot-check). Round 14's fuller verification and its documented exceptions stand as last recorded |
| New this round | Runbook §2/§3.3/§6 updated for the new edit-menu capabilities (host_vars editor, roster manager, NFS bootstrap) and their remaining gaps; `pilot-trec-verification` skill corrected (its `freeipa-identity` vars-file-prompt guidance had gone stale and now actively fails a canonical roster) and one new trec-driver gotcha added (`TOGGLE docker` label ambiguity on the role checklist); 4 checked-in `scripts/minimal-poc/*.drive` scripts added as reusable, lint-clean (not yet independently re-proven end to end) reproduction of this exact rebuild; 1 verification-script bug found and fixed (`scripts/minimal-poc-section4-spotcheck.sh`'s Thanos JSON parsing, broken by `pilot vm-target exec`'s own SSH warning sharing stdout); 2 suspected `pilot`/playbook implementation defects found, reported, authorized, and **fixed** (2026-07-26) — `internal/inventory/vault.go`'s `keyNames()` now skips `Optional: true` keys (fixing `ipa_dm_password` being wrongly required by `pilot deploy`'s hard completeness gate) and `freeipa-identity-apply.yml`'s user-normalization task now uses `.get('values', none)` instead of a colliding bracket lookup (fixing the ansible-core 2.19.x crash for a roster user with no `ssh_keys` field); both re-verified live against their exact original repro, plus the full Go test suite (988 tests) and an Ansible syntax-check; 1 topology sizing gap found and fixed (`freeipa-server` memory 4096→4608 MiB) after a newly-enabled real-fact resource gate correctly caught it for the first time |
| Evidence integrity | 10 TREC recordings kept as evidence, all passed `cast_verify`: complete, exit 0, 0 secret-scan findings, safe to share. An 11th recording leaked `grafana_admin_password`/`ipa_admin_password` in plaintext (vault key-list screens render saved values in plaintext by design — same limitation prior rounds' evidence documents — and this one was typed without declaring `--secret-file` first) and was deleted rather than kept once caught during final review, not by `cast_verify` (never run on it); the group_vars-fill file changes that recording also covered are real and file-verified but have no surviving recording — see the round-16 evidence's own integrity section |
| Publication | [`2026-07-25-round-16.md`](../evidence/minimal-poc-architecture/2026-07-25-round-16.md); secret values and ephemeral addresses omitted |

The compact evidence record contains the current candidate provenance, result matrix, documented
exceptions, and raw-artifact pointers. Earlier runs remain available in their evidence records and
Git history and are intentionally not duplicated here.
