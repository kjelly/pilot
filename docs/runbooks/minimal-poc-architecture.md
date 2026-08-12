# Runbook — Minimal PoC Architecture: FreeIPA + Wazuh + Grafana 3-VM Rebuild

> Status: **VERIFIED**
> Latest completed pass: 2026-08-11 (Asia/Taipei), round 21
> Evidence: [`2026-08-11-round-21.md`](../evidence/minimal-poc-architecture/2026-08-11-round-21.md)
> Round 20: [`2026-08-07-round-20.md`](../evidence/minimal-poc-architecture/2026-08-07-round-20.md)
> Round 19: [`2026-08-06-round-19.md`](../evidence/minimal-poc-architecture/2026-08-06-round-19.md)
> Round 18: [`2026-07-30-round-18.md`](../evidence/minimal-poc-architecture/2026-07-30-round-18.md)
> Round 17 (unattended-script proof): [`2026-07-27-round-17.md`](../evidence/minimal-poc-architecture/2026-07-27-round-17.md)
> Round 16 (edit-menu-only rebuild): [`2026-07-25-round-16.md`](../evidence/minimal-poc-architecture/2026-07-25-round-16.md)
> Round 15 (adopted `vm-target topology`): [`2026-07-23-round-15.md`](../evidence/minimal-poc-architecture/2026-07-23-round-15.md)
> Round 14 (deep §4 verification matrix): [`2026-07-23-round-14.md`](../evidence/minimal-poc-architecture/2026-07-23-round-14.md)
> Semantic action catalog expansion (local-only, no VM rebuild): [`2026-07-23-semantic-actions-expansion.md`](../evidence/minimal-poc-architecture/2026-07-23-semantic-actions-expansion.md)
> Automation: `playbooks/site.yml` plus the day-2
> `playbooks/apply/freeipa-identity-apply.yml` and
> `playbooks/apply/freeipa-dns-apply.yml` reconcilers
> Maintainer: sre

Round 21 (2026-08-11) authored and deployed the FreeIPA identity roster as **Roster
Schema v2** for the first time in this runbook's history, and is the current verified
pass. **§7 holds its full record** — scope, the roster's actual shape, every
`ok=/changed=/failed=` count, the one real implementation defect found and fixed, and
the environment note — with the precise numbers rather than a prose summary of them.

Earlier rounds, newest first — each round's own evidence record (linked above) holds
the full detail; this runbook keeps only the current sanitized facts:

- **Round 20 (2026-08-07)** — clean-room rebuild scoped to proving the SIEM/Loki
  log-collection chain against a real diagnosed production gap. Rewrote §4.2 from a
  single "does any event exist" smoke check into four targeted checks, which then
  surfaced and fixed **three independent real defects** none of the old check could
  have caught (`audisp-syslog` plugin never activated, an rsyslog self-forwarding
  loop that filled a 77GB disk in under an hour, and a Promtail job scraping
  `alerts.log` instead of `alerts.json`) — all three in §6.2. One process incident:
  a delegated worker autonomously launched a persistent background truncation
  script without authorization; caught by monitoring and killed, no lasting effect,
  noted as a process lesson rather than a product defect.
- **Round 19 (2026-08-06)** — full rebuild plus the **full** §4.1–§4.4 matrix from a
  fresh topology, driven entirely through the sanctioned wizards. Confirmed a
  same-day `audit-log-forwarding` logrotate fix on every OS family in this topology
  and found that fix had been scoped to Debian only — AlmaLinux 9's
  `rsyslog-logrotate` RPM had the identical bug under different paths; fixed the
  same session (v1.4). Component detail lives in
  `docs/runbooks/audit-log-forwarding.md` §5.5.1, not here. Three further findings
  all traced to this round's own roster-authoring choices rather than any
  tool/playbook defect — see §3.3 and §6.1. One suspected defect (`pilot services
  status` reporting a dead Harbor stack as healthy) reported, not fixed.
- **Round 18 (2026-07-30)** — added the `freeipa-dns` day-2 reconciler
  (`docs/specs/freeipa-dns.md` Phase 5) to a full fresh rebuild: site-wide deploy,
  `freeipa-identity` reconcile, then `freeipa-dns` reconcile with 3 A records
  resolved through `target.inventory_host`, drift correction and an idempotent
  rerun. Two real bugs found and fixed — see §6.2.
- **Round 17 (2026-07-27)** — proved the per-run wizard flows as fully **unattended**
  `trec drive --script` runs against a fresh rebuild, and ran the full §4 matrix
  including the complete §4.4 remove/restore/drift-correction/idempotency cycle
  ending in a clean `changed=0` rerun. Three real driver bugs surfaced and were
  fixed; per AGENTS.md v1.15 those live in the trec skills
  (`.agents/skills/pilot-trec-verification/references/known-gotchas.md`), not in
  this runbook. Every recording was verified for replay fidelity, not just exit
  code. Rounds 14/15/16's findings remain valid.

One-time acceptance recordings and per-run wizard drivers are disposable.

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
| Fact timestamp | 2026-08-11T18:00+08:00 |
| Targets | `freeipa-server`, `nexus`, `client-vm` |
| VM sizing | FreeIPA: 2 vCPU/**4608 MiB**/30 GiB; nexus: 6/12288/80; client: 2/2048/20 |
| VM provisioning | `pilot vm-target topology up --topology docs/topologies/minimal-poc-topology.yaml` (spec's own `services: local` key); see §3.2 |
| Inventory source | Generated from a fresh gitignored workspace, built via live `pilot edit`/`pilot inventory generate` driving — `hosts.yml` (3 hosts, all required roles), the hard-required `group_vars` values (prometheus/thanos-query S3 target, dashboard Thanos-Query target, restic S3 target, wazuh-fim manager host, freeipa server IP), `host_vars/nexus.yml`, remaining `.vault/main.yaml` secrets, and the FreeIPA identity roster authored as **`schema_version: 2`** (users/groups/hostgroups incl. one nested/one netgroup/HBAC/sudo/NFS-with-netgroup-export hand-authored into the roster's nested YAML, still the documented exception — see §2/§3.3) |
| Stage | `sandbox` |
| Alignment | Actual hosts and populated role groups matched the intended topology |
| Manual extra `-e` | Empty; inventory-derived values were accepted through the wizard |
| Tested candidate | Working tree at round start (uncommitted Roster Schema v2 implementation, baseline commit `604aef4`); one real gap found+fixed mid-round in `freeipa-nfs-server-apply.yml` (hardcoded `schema_version == 1`, never updated for v2 — see §6) |
| Result | Site-wide deploy `failed=0` on all three hosts after the fix above (`client-vm ok=105 changed=47`, `freeipa-server ok=86 changed=38`, `nexus ok=242 changed=107`); `freeipa-identity` reconcile passed initial apply with a genuine v2 roster (`ok=87 changed=27 failed=0`, netgroup+nested-hostgroup included); `alice`'s forced-change password personalized via scripted `kinit`; full §4.4 remove/restore/drift-correction/idempotency cycle passed, including — for the first time in this runbook's history — live proof that netgroup membership removal and restoration actually take effect; §4.1 passed 8/8 on the first attempt. `freeipa-dns`/§4.2 log chain/§4.3 deliberately deferred (unrelated to the v2 rollout, already proven in prior rounds); see round-21 evidence for full detail |

The last run used ephemeral lab IPs. Never copy an address from old evidence; read the current
addresses and generated inventory before each rebuild.

### Required role placement

- `freeipa-server`: `freeipa-server`.
- `nexus` and `client-vm`: `freeipa-client`.
- `nexus`: `freeipa-nfs-server`; `client-vm`: `freeipa-nfs-client`.
- `nexus` and `client-vm`: `docker`.
- `nexus`: `wazuh-manager`, `log-server`, `seaweedfs-s3`, `prometheus`, `thanos-query`,
  `alertmanager`, `dashboard`.
- All hosts that require local audit/FIM/backup coverage: `audit-log-forwarding`, `wazuh-fim`,
  `restic-backup`.
- Keep `dns`, `ntp`, `keycloak`, `keycloak-db`, and `linux-servers` empty in this PoC. FreeIPA
  supplies DNS/NTP; Keycloak/PAM-OIDC is out of scope.

`nexus` carries `log-server` alongside `wazuh-manager` (added 2026-08-06) — without it,
`audit-log-forwarding`'s local6/auth/authpriv forwarding has nowhere real to land: it auto-resolves
`siem_forward_host` to `log-server` if present, else `wazuh-manager`, but `wazuh-manager`'s own
docker-compose port mapping is never wired into anything that parses that traffic (confirmed via a
real incident — see `docs/runbooks/audit-log-forwarding.md` §5.5.1 and
`docs/verification/log-server.md`'s v1.1/v1.2 changelog). `log-server-apply.yml` runs correctly
co-located with `wazuh-manager` (TCP/514 only since v1.2 — no port conflict). `pilot deploy`'s
topology preview now also warns (advisory, never a hard fail) if `audit-log-forwarding` hosts exist
with neither `log-server` nor `wazuh-manager` present anywhere in inventory, so leaving `log-server`
unassigned in a future topology won't fail silently.

After generation, inspect the actual inventory. If it differs from this topology, choose A (fix
the workspace/environment) or B (change the contract), then regenerate and restart the formal run.

When the generated vault supplies the restic/Thanos S3 access key and secret, full-site deployment
automatically renders `/etc/seaweedfs/s3.json` with mode `0600` and starts SeaweedFS with
`-s3.config=/etc/seaweedfs/s3.json`. That is the supported signed S3 path; do not add a manual
`seaweedfs_s3_config_path` override for this topology.

The standalone [network firewall matrix](../network-firewall-matrix.md) defines the required
inter-node and controlled outbound connections for this topology.

## 1. Aligned acceptance contracts

The component checks live in these specs and are not duplicated here:

- `docs/verification/freeipa-server.md`
- `docs/verification/freeipa-client.md`
- `docs/verification/freeipa-identity.md`
- `docs/verification/freeipa-dns.md`
- `docs/verification/docker.md`
- `docs/verification/seaweedfs-s3.md`
- `docs/verification/prometheus.md`
- `docs/verification/thanos-query.md`
- `docs/verification/alertmanager.md`
- `docs/verification/dashboard.md`
- `docs/verification/log-server.md`
- `docs/verification/log-shipping.md`
- `docs/verification/wazuh-manager.md`
- `docs/verification/wazuh-fim.md`
- `docs/verification/audit-log-forwarding.md`
- `docs/verification/restic-backup.md`

**`freeipa-client.md`, `freeipa-identity.md`, and `freeipa-dns.md` do not fully pass `pilot verify`
against this topology's own roster/manifest — this is expected, not a regression.** All three
specs' Command/Expected columns are pinned to a fixed fixture (a `pilotuser` account for
`freeipa-client.md`'s C5/C8; `fixture-group-a`/`fixture-canonical-user-a`/etc. for
`freeipa-identity.md`; `delete-fixture`/`authoritative-fixture.pilot.internal.`/etc. for
`freeipa-dns.md`), provisioned by each spec's own separate `§7.1` fixtures playbook — never by this
runbook's roster/manifest, which intentionally uses `alice`/`bob` and this PoC's own DNS zone.
Confirmed 2026-08-06 (round 19, the first round to actually run `pilot verify` against these 3
specs): `freeipa-client.md` 16/20 (only the fixture-bound C5/C8 fail), `freeipa-identity.md` 2/18,
`freeipa-dns.md` 0/12 — all failures are fixture-name mismatches, not tool/playbook errors. The real
acceptance test for THIS runbook's own identity/DNS state is §4.1/§4.4 below plus the live checks
already exercised during `freeipa-identity`/`freeipa-dns` reconcile (group membership, HBAC,
hostgroups, sudo rules, and a live `dig` round-trip against the real records) — not these 3 specs.

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
- A canonical FreeIPA identity roster with `schema_version: 2` (current default as of round 21;
  `pilot roster migrate <file>` upgrades an existing `schema_version: 1` roster in place, and
  `pilot edit`/`pilot deploy`/`pilot reconcile` all auto-upgrade one the moment they open it —
  see `.agents/skills/freeipa-roster-authoring/SKILL.md`), the `freeipa` connection/safety
  block, and the required `users`, `groups`, `hosts`, `hbac`, `sudo`, and `nfs` objects. `netgroups`
  is optional and v2-only (feeds NSS/NFS export selectors, not HBAC/sudo) — the roster manager has no
  netgroup screen, so hand-author it into the roster's nested YAML like HBAC/sudo/NFS already are; a
  netgroup name must match `^ng-[a-z0-9][a-z0-9_.-]*$`, must not collide with a hostgroup name, needs
  `membership.authoritative: true`, and every reference must resolve to something declared in the
  same roster (confirmed live round 21: netgroup membership removal and restoration both take effect
  on a real FreeIPA server — the first round to actually exercise that direction). A user entry
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
`groupVars` declaration both imply — a canonical roster's own top-level-key gate rejects it on
either schema version (confirmed live 2026-07-23, round 14 on v1; re-confirmed round 21 on v2:
preview failed, no mutation). The admin
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
`pilot edit`'s genuine live TUI. When automation is needed, generate and validate a fresh per-run
driver from the current UI, inventory, and environment; do not reuse a checked-in driver. In
outline:

- **`hosts.yml`**: add each host, set `ansible_host`/`ansible_user`/SSH-key, then the role
  checklist. The moment `freeipa-nfs-server` is newly checked on a host with no
  `freeipa_roster_file` set yet, the wizard auto-derives
  `<workspace>/.vault/ipa-identity.yaml`, sets that host's `freeipa_roster_file` extra var to it,
  and prompts once (masked) for the FreeIPA admin password — writing a *minimal* roster
  (`schema_version: 2` as of round 21 — the bootstrap now writes v2 directly, with an empty
  `netgroups: []`; older checkouts wrote `schema_version: 1`, auto-upgraded the next time any
  `pilot` command opens it — `freeipa.admin.{principal,password}`, one `nfs.servers` entry for that
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

**Three authoring pitfalls confirmed live 2026-08-06 (round 19) — none caught by `pilot roster
lint` or any wizard gate, because all three are structurally valid rosters that simply don't do
what the author intended:**

- **The HBAC rule's target hostgroup must include every host §4.1's live checks actually test
  against — by default `nexus`, per `scripts/minimal-poc-section4-spotcheck.sh`'s `NEXUS_NODE`
  default and every prior round's roster (see §6's `sshd.service`/`ssh.service` gotcha, which
  already assumes `nexus` as the live target).** A hostgroup that only lists `client-vm` lints
  clean, reconciles clean, and then fails every live SSH/sudo check against `nexus` with a genuine
  (and correct) HBAC denial — `journalctl -u ssh` on the target shows
  `pam_sss(sshd:account): Access denied for user <name>` — that is the roster doing exactly what it
  was told, not a bug.
- **Flip a user's `password.force_change` to `false` immediately after personalizing that user's
  password via a real `kinit` — not just once, ever, but as a standing edit whenever you next touch
  the roster.** `playbooks/apply/freeipa-identity-apply.yml` only skips re-resetting a password when
  EITHER `force_password: false` and the self-change gap (`krbPasswordExpiration >
  krbLastPwdChange`) is detected, OR when left `true` it always wins — leaving `force_change: true`
  on an already-personalized user means the **next reconcile for any unrelated reason** (e.g. a
  hostgroup fix, a new sudo command) silently resets that user's password back to the roster's
  `initial` value and re-arms the forced-change flag, breaking every live check that assumed the
  personalized password until you re-run the `kinit` dance. Confirmed live: a hostgroup-only
  roster edit stomped an already-personalized user's password this way.
- **A sudo rule needs `options: ["!authenticate"]` for any live check that runs `sudo -n` (non-
  interactive).** An empty `options: []` list is a legal, common roster shape — it just means real
  interactive-password sudo, not NOPASSWD. The resulting `sudo: a password is required` looks
  identical to the existing stale-SSSD-sudo-cache gotcha (§6) unless you check `ipa sudorule-show
  <rule>` first: a cache issue shows the rule correctly attached with `!authenticate` already
  present; a missing-option issue shows the rule attached with no options at all.

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
rather than `--actions`: `failed=0` on the first
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

**Corrected 2026-08-12**: this used to describe a hard failure. As of HEAD `88b62db`,
`freeipa-nfs-server-apply.yml` is self-healing instead: on a genuinely fresh host, if a
roster-managed NFS share's ownership group (e.g. `data-ops-share`) does not exist yet because
§3.5's identity reconciliation has not run, the playbook no longer fails the whole component with
`chgrp failed: failed to look up group <name>`. It runs `getent group <name>` per share first
(`changed_when: false`, `failed_when: false`), and for any share whose group doesn't resolve yet,
prints a clear per-share warning (`Share <name>'s ownership group <group> is not yet resolvable via
NSS/SSSD. Deferring this share until a later apply — run \`pilot reconcile\` (freeipa-identity) to
create the roster's groups, then re-run this playbook to pick it up.`) and narrows
`nfs_selected_server.shares` to just the ready ones — every other task in the component still runs
and the overall play still reports `failed=0`. Confirmed live 2026-08-12 (minimal-poc
revalidation): a site-wide deploy against a roster whose `ops-data` share's owning group
(`data-ops-share`) did not exist yet in live FreeIPA reported `nexus failed=0` and emitted exactly
this warning, deferring only that one share. **This means a clean `failed=0` site-wide deploy does
not by itself prove every roster-managed NFS share was actually created** — check the deploy output
for this warning (or just diff the roster's declared shares against a live `exportfs -v`/`ls` on
the target) before assuming §3.5 is unnecessary. The remedy is unchanged: run §3.5, then re-run
either this site-wide deploy or (faster) a single-component `pilot deploy` limited to
`freeipa-nfs-server` — every already-applied component/share reports `changed=0` and only the
deferred share's step completes.

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
initial apply `changed=15 failed=0`, plus a
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

### 3.6 DNS reconciliation (`freeipa-dns`, added round 18)

A second, independent day-2 reconciler (`docs/specs/freeipa-dns.md`) manages FreeIPA-native DNS
zones/records declaratively. Author the manifest first via `pilot edit`'s "freeipa-dns manifest"
top-menu item (zone + A/AAAA/CNAME records, `target.inventory_host` resolved against `hosts.yml` —
then run the same reconcile wizard:

```bash
./pilot reconcile -i <workspace>/inventory.yml --timeout 90m
```

Select `freeipa-dns` (the second, not the first, catalog entry — `freeipa-identity` is always
listed first). Set both `freeipa_dns_manifest_file` and `freeipa_roster_file` as extra host vars on
`freeipa-server` (the same "其他變數" screen used in §3.3). At the secret vars-file prompt select
`.vault/main.yaml` — same convention as §3.5, same `ipa_admin_password` requirement. Leave manual
extra `-e` empty. Confirmed live 2026-07-30 (round 18) driving this real interactive wizard directly
confirmed unattended): initial apply
`changed=2 failed=0` (3 A records — grafana/wazuh/s3 — created, all resolving through `nexus`'s real
IP via `dig`), idempotent rerun `changed=0 failed=0`. One real bug found and fixed getting here (see
§6): `freeipa-dns-apply.yml`'s `ipa_server_fqdn_expected` defaulted to the inventory's short host
alias instead of the FQDN `freeipa-server-apply.yml` actually installed the server as, whenever
`freeipa_server_fqdn` was left unset (the documented, normal case) — every reconcile against a
workspace following that convention failed the manifest-vs-inventory gate until fixed.

## 4. Verification procedure

Run every aligned component spec against the generated inventory, then perform these end-to-end
checks. Capture exact commands, outputs, exit codes, target facts, and retries in the raw evidence
artifact rather than appending them here.

**Round 18 scope note (historical)**: that round's focus was proving `freeipa-dns` end to end
(§3.6) on top of a fresh full rebuild — it did not re-run the full §4.1–§4.4 matrix (round 17 had
already proved that matrix cleanly). `freeipa-dns`'s own end-to-end check — 3 service names
resolving to the right IP via `dig`, surviving a drift-correction cycle, staying idempotent — is
`docs/verification/freeipa-dns.md`'s own checklist (C1–C12), not a §4 row here; see that file and
the round-18 evidence record for the real output. **Round 19 re-ran the full §4.1–§4.4 matrix**
(see §7) — this scope note is kept only as historical context for round 18's own record.

§4.1's HBAC checks and §4.2's Thanos `up` check are pure read-only assertions against an already-
deployed site — there is no wizard, prompt, or mutation to observe, so they are scripted (see
below). §4.3 and §4.4 are deliberately **not** scripted: they mutate state and/or drive `pilot
reconcile`'s wizard, and for those the actual thing under test is the live interactive flow itself
(TREC-driven), not just its end state — a canned script would verify the wrong layer. Round 15
evaluated converting all of §4 to scripts and drew the line here; see
[`2026-07-23-round-15.md`](../evidence/minimal-poc-architecture/2026-07-23-round-15.md) for the
tradeoffs considered.

### 4.1 FreeIPA authorization

**Prerequisite, confirmed live 2026-08-12 — personalize the test users' passwords before running
any check below.** A roster user's `password.initial` value is a one-time bootstrap password with
FreeIPA's forced-change flag already armed (this happens on first-ever password assignment
regardless of the roster's own `force_change` setting — see §6's "brand-new roster user's first
live login" row). A live SSH/sudo/`kinit` attempt using that initial value fails with "Password
change required but no TTY available" (or an SSH session that hangs on an interactive password
prompt it can't answer) — that is a missing prerequisite, not a check failure, and it is easy to
misread as a real HBAC/sudo regression. Personalize each test user (both the allowed user and the
denied user — the denied-user check below needs a *real*, usable credential too, not just a
missing one) with a scripted 3-line forced-change `kinit` (old password, new password, new
password repeat — no more, no less) before doing anything else:

```bash
printf '%s\n%s\n%s\n' "<initial password>" "<new personalized password>" "<new personalized password>" \
  | pilot vm-target exec --name freeipa-server -- kinit alice
```

Use the **personalized** password (never the roster's `initial` value) for every check below and
for the `ALICE_PASSWORD` env var in the repeatable form. Do not flip the roster's own
`password.force_change` to `false` yet — that edit belongs with §4.4 (see its own note on doing it
"whenever you next touch the roster"), not here.

- Confirm FreeIPA services are active.
- Use `ipa hbactest` for both `sshd` and `sudo` services.
- With real test credentials, prove an allowed user can log in and run the roster-authorized
  `systemctl` command.
- Prove the same user cannot run an unlisted command such as reading `/etc/shadow`.
- Prove the denied user cannot log in, using that user's own real (personalized) password — a
  wrong-password or credential-less attempt is not evidence of HBAC denial, only of a failed
  authentication, which would fail identically whether or not HBAC denies the user. Confirm the
  denial is specifically an authorization decision, not an authentication failure, via
  `journalctl -u ssh` on the target: a real HBAC denial shows `pam_sss(sshd:auth): authentication
  success` immediately followed by `pam_sss(sshd:account): Access denied for user <name>`; a
  wrong-password attempt never gets past `pam_sss(sshd:auth): authentication failure` in the first
  place, and only proves the password was wrong.

If `ipa hbactest` allows sudo but the first live sudo lookup is denied, use the SSSD cache recovery
in §6 and repeat both checks.

Repeatable form: `ALICE_PASSWORD='...' ./scripts/minimal-poc-section4-spotcheck.sh` (see the
script's own header for the full env var list — `ALICE_SUDO_CMD` in particular must match whatever
the *current* roster's sudo rule actually grants). It resolves `nexus`'s IP live from `pilot
vm-target topology status` rather than assuming one, since libvirt DHCP reservations are not
guaranteed identical across rebuilds. It assumes `hbac.disable_allow_all: true` is set on the active
roster (required by §2/§1) — otherwise `hbactest`'s top-level `Access granted` is always `True`
regardless of the real per-rule result (see `docs/runbooks/freeipa-identity.md`'s note on this).
**The script's own denied-user check uses a deliberately wrong password, not the denied user's
real one** — it only proves a wrong password fails, which the prerequisite note above already
explains is not HBAC evidence. Treat it as a cheap sanity check only, and additionally run the
`journalctl`-based real-credentialed check above by hand for actual HBAC-denial evidence.

### 4.2 Metrics and logs through Grafana dependencies

- Confirm Grafana, Prometheus, Loki, and Thanos Query readiness.
- Query Thanos for `up` and confirm the `site-nexus` series has value `1`. (Covered by
  `scripts/minimal-poc-section4-spotcheck.sh` above, `THANOS_SITE_LABEL`/`THANOS_PORT` env vars.)

**Log chain — rewritten round 20 (2026-08-07).** The previous version of this section asked only
"query Loki label values and a recent range; confirm the `pilot-siem` stream contains a real event."
That check passed for years while three real collection gaps sat underneath it undetected: raw
auditd/auth traffic was never actually reaching Loki, no check ever proved *which* host a given
event came from, and the Wazuh-alerts job's own host attribution silently never worked. A "some
event exists somewhere in this job" check cannot distinguish "the whole raw-audit pipeline works"
from "one Wazuh alert got through" — do not regress to it. Run all four of the following instead.

**Precondition**: `nexus` must carry both `log-server` and `wazuh-manager` (§0.5) — if `log-server`
was left empty, every check below fails or returns empty, and that is the actual regression, not a
check bug.

**Naming gotcha, confirmed live round 20**: the Loki `host` label (both jobs) is the target's real
OS hostname, not the `hosts.yml` inventory alias. In this topology `nexus`/`client-vm` happen to
match, but `freeipa-server` does not — its real hostname is `ipa1` (from
`ipa1.ipa.pilot.internal`, the FQDN `freeipa-server-apply.yml` installs it as). Querying
`host="freeipa-server"` silently returns empty and looks exactly like a collection gap; use
`host="ipa1"` for that host. Read the actual `%HOSTNAME%` rsyslog resolved for each host
(`pilot vm-target exec --name nexus -- ls /var/log/siem/`) rather than assuming the inventory name.

**C-log-1 (central landing files exist per host, on `nexus`):**

```bash
pilot vm-target exec --name nexus -- ls /var/log/siem/
# expect one subdirectory per host that forwards to nexus, by real hostname —
# this topology: client-vm/ ipa1/ nexus/
pilot vm-target exec --name nexus -- tail -n3 /var/log/siem/client-vm/audit.log /var/log/siem/client-vm/auth.log
```

Both `audit.log` (local6/raw auditd) and `auth.log` (auth/authpriv) must exist and have real,
recent content for every host. `audit.log` missing while `auth.log` exists is exactly the
audisp-syslog-plugin-inactive gap this round found — see §6.

**C-log-2 (per-host marker injection + host-label Loki query):**

```bash
# left = pilot vm-target name (inventory alias); right = the real OS hostname
# that ends up as the Loki `host` label (see the naming gotcha above)
declare -A VM_TO_HOSTLABEL=([freeipa-server]=ipa1 [nexus]=nexus [client-vm]=client-vm)

for vm in "${!VM_TO_HOSTLABEL[@]}"; do
  h="${VM_TO_HOSTLABEL[$vm]}"
  pilot vm-target exec --name "$vm" -- logger -p local6.info "PILOT-DT-${h}-$(date +%s)"
done
sleep 6

# each query must return ONLY that host's own marker, never another host's or empty
for h in "${VM_TO_HOSTLABEL[@]}"; do
  curl -s -G "http://<nexus-ip>:3100/loki/api/v1/query" \
    --data-urlencode "query={job=\"pilot-siem\", host=\"${h}\"}" \
    --data-urlencode "time=$(date +%s)" | grep -o "PILOT-DT-${h}-[0-9]*"
done
```

A wrong or empty result means either the naming gotcha above, or a genuine Promtail pipeline-stage
regex mismatch against the actual file path — check `docker logs pilot-promtail` on `nexus`.

**C-log-3 (coverage query — proves every host is represented, not just whichever is loudest):**

```bash
curl -s -G "http://<nexus-ip>:3100/loki/api/v1/query" \
  --data-urlencode 'query=sum by (host) (count_over_time({job="pilot-siem"}[5m]))' \
  --data-urlencode "time=$(date +%s)"
# expect non-zero counts for ipa1, nexus, AND client-vm
```

**C-log-4 (Wazuh alerts host attribution — and why alerts alone are insufficient):**

```bash
curl -s -G "http://<nexus-ip>:3100/loki/api/v1/query_range" \
  --data-urlencode 'query={job="pilot-siem-wazuh-alerts"}' --data-urlencode 'limit=5'
```

The `host` label here comes from each alert's own `agent.name` JSON field, extracted from
`alerts.json` (never `alerts.log` — that's the plain-text sibling file the same round-20 fix
corrected; see §6). Confirm entries actually carry a `host` label, not just that the job has data —
an empty-`host` series with real content is exactly the round-20 pre-fix state. This job is
intentionally narrowed to `alerts.json` only: raw Wazuh `archives.log`/`archives.json` stay
unscraped by design, since `<logall>`/`<logall_json>` default to `no` and the raw audit trail is
already fully covered by C-log-1 through C-log-3's `siem_log_root` path — do not treat a Wazuh
archive scrape target's permanently-zero read position as evidence of a bug (it is documented, see
`docs/verification/log-shipping.md` §1 note), and do not treat Wazuh alerts alone (parsed,
rule-matched events only) as a substitute for C-log-1 through C-log-3's raw per-host coverage.

**Label-format mismatch between the two jobs, confirmed live 2026-08-12**: `pilot-siem`'s `host`
label is the short real hostname (`nexus`, `ipa1`, `client-vm` — see the naming gotcha above), while
`pilot-siem-wazuh-alerts`'s `host` label is the full FQDN taken verbatim from Wazuh's `agent.name`
(`nexus.ipa.pilot.internal`, etc.). A query or dashboard panel that tries to correlate C-log-3's raw
coverage against C-log-4's alert coverage with a naive `host=` join across both jobs will silently
match nothing — normalize one side's label format (e.g. strip the domain suffix) before joining.

**Legacy smoke check** (cheap first-pass only — insufficient alone, see above):

```bash
curl -s "http://<nexus-ip>:3100/loki/api/v1/label/job/values"
# expect at least: pilot-siem, pilot-siem-wazuh-alerts
```

### 4.3 Backup and Wazuh FIM

- Confirm `restic-backup.timer` is active and enabled on every host assigned the role.
- Trigger a backup and confirm the shared repository contains fresh snapshots for the intended
  hosts.
- Create a unique file under `/etc` on an enrolled agent and confirm Wazuh manager receives the
  corresponding real-time `whodata` file-add alert.

**Naming gotcha, confirmed live 2026-08-12**: `restic snapshots`' `Host` column reflects each VM's
real FQDN (`ipa1.ipa.pilot.internal`, `nexus.ipa.pilot.internal`, `client-vm.ipa.pilot.internal`),
not the inventory/topology alias — the same "real hostname, not the alias" gotcha §4.2 already
documents for Loki's `host` label. Grepping the snapshot list for the literal string
`freeipa-server` to confirm coverage finds nothing; use `ipa1.ipa.pilot.internal` instead.

### 4.4 Identity reconciler cycle

1. Remove the allowed user's access/role-group membership from the roster and reconcile. Per §2's
   category convention this is normally two groups (one `access-*` for HBAC, one `role-*` for
   sudo) — remove both to fully revoke.
2. Confirm `ipa hbactest` and live login/authorization both lose the intended grant without
   changing the user's personalized password state.
3. Restore membership and add one new allowed sudo command in the same roster edit; reconcile.
4. Confirm both membership and command drift are corrected in effective state. A newly-added sudo
   command may need a client-side `sss_cache -E && systemctl restart sssd` before it takes effect
   live (§6) — that is a cache-staleness gotcha, not evidence the reconcile itself failed. **A
   second, easily-confused failure mode, confirmed live 2026-08-12**: the roster grants an
   exact-match (non-wildcarded) command string, and sudoers matches the full command line —
   testing with any extra CLI argument the roster didn't grant (e.g. adding `--no-pager` to a
   granted `systemctl status <unit>`) produces the identical `sudo: a password is required`
   symptom as real cache staleness. Distinguish with `sudo -n -l` (shows the rule as `NOPASSWD`
   regardless of which symptom you're hitting) and by retrying with the exact declared command
   string before concluding the cache needs a flush.
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

Detailed component-specific troubleshooting belongs in the aligned spec/runbook
for that component, not in this composition runbook. §6.2 lists defects already
fixed upstream — on a current checkout you can skip it entirely.

### 6.1 Live on a current checkout

| Symptom | Cause | Current action |
|---|---|---|
| `pilot vm-target topology up` fails with `services: Harbor is unreachable: ... connection refused`, moments after `pilot services status` reported `running=true` | **Suspected implementation defect, reported not fixed (round 19, 2026-08-06).** The dev-lite Harbor containers had actually exited (`Exited (128)` ~28h earlier) but `services status`'s health signal did not reflect it; the first real signal came from `topology up`'s own consumer-side connectivity check. | `./pilot services down && ./pilot services up --profile dev-lite` (full recreate), confirm the Harbor health endpoint returns HTTP 200, then retry. A future round should investigate `services status`'s health-check implementation. |
| Site-wide deploy's real apply fails `nexus`'s `freeipa-client` with `Joining realm failed: Operations error: Error checking for attribute uniqueness` | Transient FreeIPA/389-ds LDAP contention when two `freeipa-client` hosts run `ipa-client-install` concurrently against the same server (default `ANSIBLE_FORKS=20` runs both in one play). The losing host is then excluded from every later play in that run, cascading into unrelated-looking failures on it (e.g. `wazuh-fim` agent-auth failing because `wazuh-manager` never applied). | Re-run `pilot deploy` — site-wide is idempotent, already-applied hosts report `changed=0`, and only one host is left to enroll so it no longer races. Not a topology/bring-up defect. |
| First live sudo is denied although `ipa hbactest --service=sudo` allows it — **or** a *newly applied* sudo rule fails `sudo: a password is required` even though `ipa sudorule-show`/`sudo -n -l` show it attached with `!authenticate` | Stale SSSD sudo cache. Applies both on first enrollment and after every sudo-rule change. | `sss_cache -E && systemctl restart sssd` on the **client host being sudo'd into** (not the FreeIPA server), then repeat the live and authoritative checks. Do **not** add `sudo` to `sssd.conf` `services=` — the sudo responder is socket-activated and that edit breaks its socket. |
| `pilot deploy --dir ...` is rejected | `deploy` takes an inventory with `-i`; `--dir` belongs to authoring commands such as `pilot edit` | Use the §3.4 invocation. |
| Site deploy asks to confirm auto-detected host variables | Derived from inventory; distinct from the manual extra-`-e` field | Accept the detected values; keep the manual field empty. If a required value is not derived, stop and fix inputs. |
| Identity reconcile reports `failed=0` but all mutation tasks skip | `freeipa_roster_file` is not set as a host var on the target (§2). Independent of the vars-file prompt — selecting `.vault/main.yaml` there is correct for a canonical roster on either schema version and does not by itself cause a skip. | Confirm `freeipa_roster_file` is set on the managed host, not just which file was picked at the prompt. |
| Identity reconcile preview fails with "Canonical roster contains an unknown freeipa/admin field" | A bare top-level `ipa_admin_password` key was added to the roster file itself; the canonical top-level-key gate rejects it. | Remove it from the roster; put `freeipa.admin.password` there instead, and satisfy the *contract's* `ipa_admin_password` requirement by selecting `.vault/main.yaml` at the vars-file prompt (§3.5) — not by editing the roster. |
| Identity reconcile preview fails with "Refusing to disable allow_all without an enabled admin break-glass rule" | `hbac.disable_allow_all: true` with no `enabled: true` HBAC rule granting `admin` `hostcat: all` login — a deliberate safety gate, not a bug. | Add a `breakglass-admin-access`-style rule (`subjects.users: [admin]`, `hostcat: all`, `services: [sshd]`, `enabled: true`) in the same roster edit — `playbooks/apply/freeipa-identity.roster.example.yaml` already includes one for exactly this reason. |
| Generated files do not contain intended wizard values | Saving the wrong cursor field can still exit successfully | Inspect saved host, role, group-var and vault-key facts before deployment; keep TUI-driving details in the trec skills. |
| A no-op reconcile still reports changes | Forced test-password handling, HBAC disable behavior and Dogtag-owned mode correction may be non-idempotent. Also, any roster user who has never actually logged in (`krbLastPwdChange == krbPasswordExpiration`) has their bootstrap password legitimately re-applied every run regardless of `force_change`, by design — only a user's own real password change breaks the equality. | Identify the exact changed tasks and preserve their real count; do not claim `changed=0`. |
| A brand-new roster user's first live login/sudo fails with "Password change required but no TTY available", even though the roster sets `force_change: false` | FreeIPA's own `ipa passwd` always arms the forced-change flag on first-ever password assignment, independent of the roster flag — `force_change` only controls whether a *routine rerun* re-arms it for an already-onboarded user. | Personalize with a scripted `kinit <user>` (3-line forced-change stdin: old/new/new). Works over `pilot vm-target exec` piped stdin without needing a PTY, unlike the equivalent SSH+PAM path. |
| A reconcile for one unrelated roster change (e.g. adding a hostgroup member) silently resets an already-personalized user's password, breaking every live check that assumed it | **Acknowledged limitation of the reconciler's password-reset safety design, not a new bug.** The `krbLastPwdChange`/`krbPasswordExpiration` self-change detection only protects the `force_password: false` case; the task's `when:` is `force_password OR needs_reset` (an OR, not a gate), so a roster entry still carrying `force_change: true` from onboarding re-triggers `ipa passwd` on every reconcile. | Flip `password.force_change` to `false` in the roster the same day you personalize a user's password via `kinit` — see §3.3's authoring-pitfalls note. If it already happened, redo the `kinit` forced-change dance once (old = roster's `initial`, new = your choice), then flip the flag. |
| A sudo rule's live `sudo -n <cmd>` fails with `sudo: a password is required` and `ipa sudorule-show <rule>` confirms the rule is attached | **Authoring mistake (missing NOPASSWD)** — `sudo.rules[].options` was `[]`; without `!authenticate`, `sudo -n` correctly refuses since it cannot prompt. Distinguish from the cache-staleness row above via `ipa sudorule-show`'s output: cache issue shows `!authenticate` already present, this shows no options at all. | Add `"!authenticate"` to the rule's `options`, reconcile, then still refresh the target client's SSSD cache (the staleness gotcha applies on top once the option exists). |
| §4.1's roster-authorized sudo command fails with `Unit sshd.service could not be found` even though the rule is correctly attached | **Authoring mistake, not a tool/playbook defect.** The roster granted `/usr/bin/systemctl status sshd`, but the live target is Ubuntu 24.04 where the unit is `ssh.service` — RHEL/AlmaLinux and Debian/Ubuntu name the same daemon differently. | Grant a command that exists on the target's OS family (`systemctl status ssh` on Debian/Ubuntu, `systemctl status sshd` on RHEL/AlmaLinux), re-run `pilot reconcile` to apply the correction (a useful exercise of the drift-correction path, §4.4), then refresh the client's SSSD sudo cache. |
| `pilot reconcile`'s `freeipa-identity` preview crashes with `Error while resolving value for 'identity_hbac_test_host': object of type 'dict' has no attribute 'server'` | **Suspected implementation defect, reported not fixed (round 17, 2026-07-27).** The "Normalize canonical FreeIPA settings" task reads `freeipa_roster.freeipa.server` with no `\| default(...)` fallback, unlike every sibling field in the same `set_fact`. `freeipa.server` is a legal-but-optional roster key that `pilot edit`'s NFS-role-add bootstrap never writes — so this crashes on a roster produced entirely through sanctioned tooling. | Add `freeipa.server: <the freeipa-server host's real FQDN>` (confirm via `hostname -f` on the VM, e.g. `ipa1.<domain>` — don't assume the alias other hosts use) and `freeipa.realm` to the roster by hand (the nested-YAML hand-edit exception, §3.3) until fixed upstream. Proposed fix: give `identity_hbac_test_host` the same `\| default(ipa_server_fqdn \| default(inventory_hostname))` fallback its sibling top-level default already uses. |
| `pilot deploy` aborts before any preview with `delivery transaction failed: component "freeipa-server" ... resources ... are below minimum ... ramMiB=4096` | **Environment/topology gap, not a code defect.** `deploy_facts.go` gathers real per-host OS facts before the delivery preflight; AlmaLinux 9's usable RAM under this topology's KVM/virtio overhead lands ~185 MiB below the nominal `--memory` value. | Give `freeipa-server` headroom above the declared minimum — `docs/topologies/minimal-poc-topology.yaml`'s `memory: 4608` reflects this. If the node was already up, `pilot vm-target down --name freeipa-server` then `topology up` recreates just that node, **but it gets a new DHCP-assigned IP even with the same MAC** — re-set that host's `ansible_host` via `pilot edit` and re-run `pilot inventory generate` before redeploying. |
| `pilot deploy`/`pilot reconcile` fail their completeness gate — or, worse, silently resolve a `group_vars`/`host_vars` value to the wrong thing — even though the workspace's own files are correct | **Environment pollution, not a pilot defect.** `internal/ansible`'s `Runner.Run` never sets `cmd.Dir`, so `ansible-playbook` inherits pilot's process cwd, and Ansible's vars-plugin search path includes cwd-adjacent `group_vars`/`host_vars` alongside the inventory-adjacent ones. Stray files at the repo root — e.g. from an earlier `pilot edit`/`inventory generate` run without `--dir` — silently shadow the real workspace for any same-named key. A read-only `ansible -m debug -a "var=<key>"` from the same cwd reveals the actually-resolved value. | Never invoke `pilot edit`/`pilot inventory generate` without `--dir`. If the repo root already has such stray files and their ownership is unclear, don't move or delete them — run `pilot deploy`/`reconcile` from an isolated directory that symlinks every repo-root entry except `group_vars`/`host_vars`/`.vault`/`tmp`. A future Go-side fix should pin `cmd.Dir` explicitly. |

### 6.2 Fixed upstream — upgrade past these

Listed only so a symptom on an older checkout is recognizable. On a current
checkout none of these can fire.

| Symptom | Fixed | If you are stuck on an older checkout |
|---|---|---|
| `inventory 完整性檢查沒過(1 項)： - vault: .vault/main.yaml: ipa_dm_password 未設定` blocks deploy/reconcile outright | round 16 (2026-07-26) | Add `ipa_dm_password` to `.vault/main.yaml` with any value (e.g. equal to `ipa_admin_password`). It needs no real value unless you want a separate Directory Manager password. |
| `freeipa-identity` preview fails `Type 'method' is unsupported for variable storage` / `<bound method _AnsibleLazyTemplateDict.values of {}>`, tasks masked by `no_log` | round 16 (2026-07-26) | Give every roster user an explicit `ssh_keys: {authoritative: true, values: [...]}` block (empty `values` is fine) before reconciling. Guard comment now lives at the fix site in `freeipa-identity-apply.yml`. |
| `scripts/minimal-poc-section4-spotcheck.sh`'s `4.2-thanos-up` reports `got ''` although its own `raw:` output shows a valid result | round 16 (2026-07-26) | Update the script — SSH host-key warnings were being merged into the JSON stream. |
| `freeipa-identity` preview fails "Canonical roster contains an unknown freeipa/admin field" on `freeipa.domain`/`freeipa.realm` | round 18 (2026-07-30) | No roster-level workaround needed. Guard comment now lives at the fix site. |
| `freeipa-dns` preview fails `manifest freeipa.domain/realm/server must equal this deployment's ...`, showing a bare inventory alias instead of a real FQDN | round 18 (2026-07-30) | No manual `-e freeipa_server_fqdn=...` override needed for the standard naming convention. |
| §4.2's `audit.log` never appears under `/var/log/siem/<host>/` even though receiver and forwarding rule both check out | round 20 (2026-08-07) | See `docs/verification/audit-log-forwarding.md` v1.5 (C21) — the `audisp-syslog` plugin ships inactive, so no local6 traffic was ever generated. |
| `nexus`'s disk fills to 100% within about an hour, one host's `auth.log` reaching multiple GB | round 20 (2026-08-07) | An rsyslog self-forwarding loop. `systemctl stop rsyslog` immediately, truncate the affected files, then upgrade before restarting. Full writeup: `docs/verification/log-server.md` v1.3 (C11). |
| The `pilot-siem-wazuh-alerts` Loki job has real content but every stream's `host` label is empty | round 20 (2026-08-07) | See `docs/verification/log-shipping.md` v1.3 — the Promtail job scraped the plain-text alert file instead of `alerts/alerts.json`. |
| `--check --diff` preview fails on `nexus`'s `freeipa-nfs-server` at "Gate: required roster and stage authorization" although `pilot roster lint` reports the roster clean | round 21 (2026-08-11) | Apply the one-line `\| int in [1, 2]` change locally. Guard comment now lives at the fix site in `freeipa-nfs-server-apply.yml`. |

Two rows previously listed here now live with their component, which is
authoritative for them: SeaweedFS's anonymous `C6`–`C8` rows failing once signed
S3 mode is on (`docs/verification/seaweedfs-s3.md`, expected behavior — do not
weaken authentication), and `restic-backup`'s `C6` verification timeout
(`docs/verification/restic-backup.md`, which now applies the longer timeout
automatically).

## 7. Latest verified evidence

| Field | Round 21 record |
|---|---|
| Verified at | 2026-08-11 (Asia/Taipei) |
| Tested revision/tree | Working tree at round start (uncommitted Roster Schema v2 implementation, baseline commit `604aef4`); one real playbook bug found and fixed mid-round (`freeipa-nfs-server-apply.yml` — see §6) |
| Targets | Fresh `freeipa-server` (AlmaLinux 9, real hostname `ipa1`), `nexus` and `client-vm` (Ubuntu 24.04); all provisioned via **`pilot vm-target topology up --topology docs/topologies/minimal-poc-topology.yaml`** |
| Focus | Author and deploy the FreeIPA identity roster as **Roster Schema v2** for the first time in this runbook's history — the schema, migration engine, and netgroup feature had been implemented but never exercised end-to-end against a real 3-VM rebuild before this round |
| Roster | `schema_version: 2`, hand-authored: users `alice` (granted)/`bob` (withheld, for the deny test), access-/role-/filesystem-category groups, hostgroup `sysops-hosts` (targets `nexus`, matching §3.3's documented gotcha) nested under `production-hosts`, netgroup `ng-nfs-clients` wired into an NFS export via `sysops-hosts`, HBAC (`breakglass-admin-access` + `sysops-access`), sudo (`sysops-sudo-access`, `!authenticate`). `pilot roster lint` clean throughout |
| Site apply | Full `site.yml`, sandbox stage — final clean state after the §6 fix: `client-vm ok=105 changed=47 failed=0`; `freeipa-server ok=86 changed=38 failed=0`; `nexus ok=242 changed=107 failed=0`. A second pass (after the identity reconcile created the NFS share's ownership group) applied the one remaining NFS-share step: `client-vm ok=97 changed=1`, `freeipa-server ok=73 changed=1`, `nexus ok=231 changed=4`, `failed=0` |
| `freeipa-identity` reconcile | Initial apply: `ok=87 changed=27 failed=0` — first real v2 roster ever applied end-to-end (groups/users/nested-hostgroups/netgroup/HBAC/sudo/NFS-automount all created; `allow_all` disabled with break-glass access proven both before and after) |
| §4.1 (live HBAC/sudo allow+deny) | `scripts/minimal-poc-section4-spotcheck.sh`: 8/8 passed on the first attempt (alice granted sshd+sudo via `hbactest` and live SSH/sudo; bob denied both; allowed/denied sudo commands both correct) |
| §4.4 (remove/restore/drift/idempotency) | Full cycle, PASS on every step: removal (`ok=87 changed=3`, including — for the first time in this runbook's history — netgroup membership removal live-confirmed via `ipa netgroup-show`); restore + drift-correction (`ok=86 changed=4`, netgroup membership restored, hostgroup description drift-corrected, both live-confirmed); idempotency rerun (`ok=86 changed=1`, the one change being exactly the documented non-idempotent `force_password: true` item) |
| Bug found + fixed | **1 real implementation defect**: `freeipa-nfs-server-apply.yml:33` still hardcoded `schema_version == 1`, never updated when the rest of the v2 rollout happened — rejected an otherwise-valid v2 roster outright. Fixed with a one-line change (`in [1, 2]`) matching `freeipa-identity-apply.yml:137`'s already-correct convention exactly; user-authorized before applying. No other implementation defect found this round |
| Environment note | A separate, unrelated `pilot edit`/`inventory generate` invocation had left stray `host_vars`/`group_vars`/`.vault` files at the repo root; `pilot deploy`/`reconcile` picked them up via `ansible-playbook`'s inherited cwd (`internal/ansible`'s `Runner.Run` never pins `cmd.Dir`) — not a pilot defect against this round's own workspace, but a real general cwd-sensitivity gap (see §6). Worked around with an isolated symlinked working directory; the ambiguous-ownership files were left untouched |
| Scope narrowed | `freeipa-dns` reconcile, §4.2's log chain, and §4.3 (backup + Wazuh FIM) deliberately deferred — each tests an already-proven-in-a-prior-round feature unrelated to the roster schema rollout this round targets |
| Functional verdict | PASS for the round's actual scope (v2 roster authoring + deploy + identity reconcile + §4.1/§4.4) — 1 real regression found, fixed, and re-verified live the same round |
| Publication | [`2026-08-11-round-21.md`](../evidence/minimal-poc-architecture/2026-08-11-round-21.md); secret values and ephemeral addresses omitted |

Earlier rounds' records remain valid and are not repeated here — see the round links
at the top of this runbook.

The compact evidence record contains the current candidate provenance, result matrix, documented
exceptions, and raw-artifact pointers. Earlier runs remain available in their evidence records and
Git history and are intentionally not duplicated here.
