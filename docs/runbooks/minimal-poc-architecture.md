# Runbook — Minimal PoC Architecture: FreeIPA + Wazuh + Grafana 3-VM Rebuild

> Status: **VERIFIED — the full merged scope (§3.7, §3.8, §4.2's strengthened check, §4.5) was
> executed end-to-end for the first time in round 25, including the `freeipa-nfs-client`
> `nfs_clients[]` Plan B fix. Four real bugs were found and fixed live; see round 25's evidence
> for full detail and the one known, reported-not-fixed limitation (end-to-end Kerberized NFS
> mount between this topology's own hosts, blocked by a separate FreeIPA DNS-registration gap).**
> Latest completed full-matrix pass: 2026-08-31 (Asia/Taipei), round 30 — another full clean-room
> rebuild covering the complete §0.5–§4.5 scope, including all idempotency reruns. Found and fixed,
> with explicit live authorization, 2 real regressions introduced by very recent unrelated work
> landing just before the round started: a fail-closed FreeIPA-client DNS gate with no check-mode
> exemption (broke every `--check` preview of a fresh topology), and an NFS-server roster
> schema-version gate that missed the `schema_version: 3` rollout (rejected every freshly-created
> roster). Both fixed with a regression test each; `failed=0` throughout the rest of the run. One
> known reported-not-fixed bug remains open (`pilot edit`'s internal-endpoint suggester menu item,
> §3.9 — use the CLI form instead). Round 29 (2026-08-25) ran the same full scope on the prior
> candidate, finding and fixing 2 different real bugs (a `dig`-diagnostic-as-stdout misread, and a
> `/etc/hosts` FQDN-in-IP-column bug present at 8 call sites) — both still fixed and reconfirmed
> clean in round 30's own run of the exact same tasks. Round 27 (2026-08-17) ran a full clean-room
> rebuild re-confirming the round-25/26 scope (site-wide deploy, both day-2 reconcilers, all
> three delivery-test-merged single components, `internal-endpoint` reconcile, the full idempotency
> suite, the complete §4.1–§4.5 matrix, and the `internal-endpoint` suggester), no product defects
> found. Round 28 (2026-08-18, its own independent fresh 3-node rebuild — not a topology reuse) then
> narrowly verified three new fixes round 27's candidate predates: FreeIPA DNS
> `allow-recursion`/`allow-query-cache` opened to `any` client (new C20 in
> `docs/verification/freeipa-server.md`), a `cmd/pilot/cmd/deploy.go` roster-autofill regression fix,
> and a `nfs_clients` roster `membership.all` wildcard — all three confirmed live, `failed=0` on a
> clean site-wide deploy, after four earlier attempts blocked on self-inflicted/environment state
> (not product defects — see round 28's evidence). Round 28 did not re-run the broader §4 matrix;
> round 27 remains its reference.
> Round 30 (2 new fixes — DNS preflight fail-closed check-mode gate, NFS-server roster schema v3
> gate; full clean-room rebuild, complete §0.5–§4.5 scope plus idempotency reruns):
> [`2026-08-31-round-30.md`](../evidence/minimal-poc-architecture/2026-08-31-round-30.md)
> Round 29 (2 new fixes — `dig`-diagnostic misread, `/etc/hosts` FQDN-in-IP-column at 8 sites; full
> clean-room rebuild, complete §0.5–§4.5 scope):
> [`2026-08-25-round-29.md`](../evidence/minimal-poc-architecture/2026-08-25-round-29.md)
> Round 28 (three new fixes — DNS recursion wildcard, roster-autofill regression, `nfs_clients`
> `membership.all` wildcard; independent fresh rebuild, narrower scope):
> [`2026-08-18-round-28.md`](../evidence/minimal-poc-architecture/2026-08-18-round-28.md)
> Round 27 (full clean-room re-confirmation of the round-25/26 scope, no defects found):
> [`2026-08-17-round-27.md`](../evidence/minimal-poc-architecture/2026-08-17-round-27.md)
> Round 26 (`internal-endpoint` auto-provision suggester, built on round 25's still-running
> topology — not a fresh rebuild): [`2026-08-15-round-26.md`](../evidence/minimal-poc-architecture/2026-08-15-round-26.md)
> Round 25: [`2026-08-15-round-25.md`](../evidence/minimal-poc-architecture/2026-08-15-round-25.md)
> Round 24 (pre-merge scope only): [`2026-08-14-round-24.md`](../evidence/minimal-poc-architecture/2026-08-14-round-24.md)
> Round 23 (partial pass, continuation of round 22's topology): [`2026-08-13-round-23.md`](../evidence/minimal-poc-architecture/2026-08-13-round-23.md)
> Round 22: [`2026-08-12-round-22.md`](../evidence/minimal-poc-architecture/2026-08-12-round-22.md)
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

Round 28 (2026-08-18) narrowly verified **three new fixes** made the same session, none of which
round 27's candidate (12 commits behind) includes: `freeipa_dns_allow_any_recursion` (opens FreeIPA's
`allow-recursion`/`allow-query-cache` to `any` client — new C20 in `docs/verification/freeipa-server.md`),
a `resolveRosterAutoFillValue` regression fix in `cmd/pilot/cmd/deploy.go` (the roster-autofill safety
valve no longer backs off just because a co-selected component like `freeipa-nfs-server` already
agrees with the candidate value), and a `membership.all` wildcard on a roster hostgroup
(`freeipa-nfs-client-apply.yml`'s `nfs_clients` targeting can now cover every `freeipa-nfs-client`
host via one wildcard entry instead of listing FQDNs individually). Authored the workspace
deliberately to exercise both Go-side fixes: `client-vm`'s `freeipa_roster_file` was left unset (to
force autofill) and its `nfs_clients` coverage came from a `membership.all: true` hostgroup with no
FQDN listed anywhere. All three confirmed live on a genuine fresh 3-node rebuild: the DNS task
`changed` the config on real apply and reported `ok` (idempotent) on a same-day rerun, a real
`dig ... @<freeipa-ip>` from `client-vm` resolved a public domain end-to-end, `pilot verify` scored
FreeIPA-server 20/20 including C20, the autofill informational message fired instead of a
`requires input` error, and the `nfs_clients` gate passed for `client-vm` via the wildcard alone.
Getting to that clean pass took five deploy attempts — the first four were blocked by an
environment/timing hiccup on `ipa-server-install` and three rounds of self-inflicted, accumulated
VM state from partial recovery attempts in between, none of them defects in the three fixes
themselves; full narrative in round 28's own evidence. This round deliberately did **not** re-run
the broader §4.1–§4.4 matrix, the day-2 reconcilers, or the `delivery-test`-merged single
components — round 27 (the day before) remains their reference. Full detail:
[`2026-08-18-round-28.md`](../evidence/minimal-poc-architecture/2026-08-18-round-28.md).

Round 27 (2026-08-17) ran **another full clean-room rebuild re-confirming the entire round-25/26
scope** on a slightly later candidate (12 commits ahead of round 25/26's) — site-wide deploy, both
day-2 reconcilers, all three `delivery-test`-merged single components, the `internal-endpoint`
reconcile, the complete idempotency suite, the full §4.1–§4.5 matrix, and the `internal-endpoint`
auto-provision suggester. **No product defects found.** Every checkpoint passed cleanly with counts
close to round 25's own (site-deploy `client-vm changed=58`, `freeipa-server changed=48`,
`nexus changed=120`; `freeipa-identity` reconcile `changed=21`; `freeipa-dns` reconcile `changed=2`,
2-record shape). One limitation reported, not fixed: after a revoke-then-restore membership cycle,
`ipa hbactest` correctly re-grants access but a credentialed SSH/`kinit` attempt still reports
`Client's credentials have been revoked` — a residual identity-reconciler credential-lifecycle gap,
not something this round's scope covers fixing. This round's evidence sat unpublished until round 28
prompted writing both up together; see
[`2026-08-17-round-27.md`](../evidence/minimal-poc-architecture/2026-08-17-round-27.md) for full
detail.

Round 25 (2026-08-15) ran the **first live test of two things at once**: the
`freeipa-nfs-client` roster-driven `nfs_clients[]` targeting fix ("Plan B"), and the complete
`delivery-test`-merged scope (§3.7, §3.8, §4.2's strengthened check, §4.5) that round 24 had left
as DRAFT. Both are now VERIFIED. Four real bugs were found live and fixed with explicit
authorization at each stop: (1) the new NFS-client fail-closed gate wasn't check-mode-safe on a
fresh, not-yet-enrolled host — fixed with `when: not ansible_check_mode`, mirroring
`freeipa-nfs-server-apply.yml`'s own identical pattern; (2) the new mount-verify task's hard
failure cascaded through Ansible's default "drop a failed host from all later plays" behavior,
silently skipping `host-monitoring`/`wazuh-fim`/`restic-backup`/`audit-log-forwarding` on
`client-vm` — fixed with `ignore_errors: true`; (3) `contracts/freeipa-ca-trust.yaml` declared
`role: freeipa-ca-trust` instead of the literal `all` group it actually targets, which made
`cmd/pilot/cmd/deploy.go`'s dependency resolver treat it as permanently unresolvable — this
completely blocked `internal-endpoint`'s reconcile (which depends on it) with no possible wizard
workaround, fixed by correcting the contract's `role` field; (4) Wazuh dashboard's docker-compose
bundle hard-binds host port 443, colliding with `reverse-proxy`/nginx on `nexus` (both roles
share that host in this topology) — the entire "reach Grafana via a clean internal HTTPS FQDN"
feature was structurally broken until this was fixed by remapping the dashboard to port 8443.
After all four fixes: site-wide deploy `client-vm ok=138 changed=41 failed=0 ignored=1,
freeipa-server ok=106 changed=39 failed=0, nexus ok=271 changed=96 failed=0`; both day-2
reconcilers clean; all three single-component deploys (`freeipa-dns-client`/`freeipa-ca-trust`/
`reverse-proxy`) plus `internal-endpoint`'s reconcile `failed=0`; §4.2's strengthened check found
3/3 `host-monitoring` targets up; §4.5's full matrix (C-ca-1/C-dns-1/C-dns-2/C-endpoint-1) passed
completely, including a real `curl https://grafana.it.pilot.internal/api/health` with a genuine
FreeIPA-issued certificate; 4/4 idempotency reruns landed clean `changed=0`. One finding reported,
not fixed: the Plan B NFS mount itself still cannot complete end-to-end in this topology, because
`freeipa-client-apply.yml` deliberately never registers a client's FQDN in FreeIPA's own DNS
(confirmed via a direct `dig` against the authoritative server: `NXDOMAIN`) — a separate,
pre-existing architectural gap, not a defect in the Plan B mechanism itself (which was proven
correct: the gate resolves hosts via the roster correctly, and the mount-verify tasks correctly
detect and report the non-mounted state). Full detail:
[`2026-08-15-round-25.md`](../evidence/minimal-poc-architecture/2026-08-15-round-25.md).

Round 26 (2026-08-15, same day) added and live-tested a new **`internal-endpoint` auto-provision
suggester** on top of round 25's still-running topology — **not a fresh clean-room rebuild**, a
deliberate reuse to exercise the new capability against an already-established manifest/DNS-zone
state. A new `autoPublish.eligible` contract field lets an endpoint opt in to `pilot internal-endpoint
suggest` (read-only) and a new `pilot edit` checklist menu item, both of which propose ready-to-use
`internal-endpoints.yaml` entries — resolved against real inventory group membership, never guessed
when ambiguous, never writing anything without going through the same `SimulateAddInternalEndpoint`
gate a manual entry already uses. Live-tested by publishing Wazuh's dashboard as
`wazuh-dashboard.it.pilot.internal`: `suggest` correctly proposed it and correctly skipped the
already-published `grafana` endpoint; a first attempt using the default subdomain `wazuh` was
correctly rejected by the DNS-ownership-collision gate (this topology's `freeipa-dns.yaml` already
owns a `wazuh` A record for a different purpose) — corrected, then a real `pilot reconcile` applied
cleanly (`freeipa-server ok=112 changed=10 failed=0`) and `curl https://wazuh-dashboard.it.pilot.internal/`
succeeded from all 3 hosts with a genuine FreeIPA-issued certificate, no regression to the existing
`grafana` endpoint. Full detail:
[`2026-08-15-round-26.md`](../evidence/minimal-poc-architecture/2026-08-15-round-26.md).

Round 24 (2026-08-14) ran the **entire scope in one clean-room pass** — full teardown/rebuild,
site-wide deploy, both day-2 reconcilers (`freeipa-identity` and `freeipa-dns`), and the complete
§4.1–§4.4 matrix — the first round since round 19 to do so without narrowing scope. This superseded
round 23's still-running topology (which round 23 had explicitly left up for continuation) after
confirming with the user that a genuine clean-room rebuild was wanted rather than a continuation,
since the `minimal-poc-update` skill's own contract only sanctions clean-room acceptance evidence for
a runbook update. **No product defect was found.** Every checkpoint passed cleanly, several matching
round 21's/round 18's counts almost exactly (site-deploy `client-vm ok=105 changed=47, freeipa-server
ok=86 changed=38, nexus ok=242 changed=107`; `freeipa-dns` apply `changed=2`), and the §4.4
idempotency rerun landed a genuinely clean `changed=0` — cleaner than round 21's `changed=1`, because
this round's alice/bob had both already completed a real password self-change via §4.1's `kinit`
personalization before the rerun. Two documentation-completeness gaps were found and reported, not
fixed (scope decisions, not defects): `host-monitoring` is a real, current role that this runbook's
§0.5/topology never assigns anywhere, leaving §4.2's plain `up` check satisfied only by Prometheus's
own self-scrape; and a stale code comment in `freeipa-identity-apply.yml` claims a playbook consumes
the roster's `nfs_clients` field when it does not actually load the roster at all. One process lesson
independent of the product: two long-running wizard-apply checkpoints delegated to subagents were
each killed mid-flight by session/process lifetime limits before mutating anything; every long-running
apply from that point on was run directly by the controlling session instead. Full detail:
[`2026-08-14-round-24.md`](../evidence/minimal-poc-architecture/2026-08-14-round-24.md).

Round 23 (2026-08-13) continued round 22's still-running topology and executed exactly what
round 22 had left out at the identity layer: the **full roster build-out**, the
**`freeipa-identity` reconcile**, and **§4.1**. The reconcile applied
`freeipa-server ok=85 changed=27 failed=0` with `✅ 套用完成` — `changed=27` matching round
21's count exactly — and §4.1 then passed **8/8** plus the real-credentialed HBAC-denial
check §4.1 requires on top of the script (`pam_sss(sshd:auth): authentication success`
followed by `pam_sss(sshd:account): Access denied for user bob`, with alice logging in as
the control). No product defect was found. It did find that **this runbook's description of
`pilot edit`'s roster manager was substantially stale**: HBAC rules, sudo rules, hostgroups,
group/user membership, `password.initial` and `ssh_keys` all have real wizard editors now, so
§3.3's "cannot do" list was directing operators to hand-edit files the wizard owns — which
the clean-room contract's Pilot-ownership rule forbids. §3.3's roster bullet and that list
are rewritten from verified source, and the genuinely wizard-impossible remainder is now
enumerated precisely (netgroups, the NFS share model, an HBAC rule's `subjects.users`/
`hostcat` — hence the mandatory `breakglass-admin-access` rule — a sudo rule's `options`,
and deletion). Five further corrections landed in §2, §3.3, §3.5, §4.1 and §6. Full detail:
[`2026-08-13-round-23.md`](../evidence/minimal-poc-architecture/2026-08-13-round-23.md).
`freeipa-dns`, §4.2's log chain, §4.3 and §4.4 were **not executed** — round 21 remains the
reference for §4.4, round 20 for §4.2, round 18 for `freeipa-dns`.

Round 22 (2026-08-12) rebuilt the whole topology clean-room and re-proved the
**workspace-authoring and site-deploy path** end to end: `topology up` → `pilot edit`
→ `inventory generate` → vault/group_vars fill → full `site.yml` deploy, every step
TREC-recorded. Preview and apply both finished `failed=0` on all three hosts
(`client-vm ok=105 changed=47`, `freeipa-server ok=86 changed=38`,
`nexus ok=239 changed=107`, `✅ 套用完成`). It deliberately stopped there: the roster
build-out, both day-2 reconcilers, and §4.1–§4.4 were **not executed**, so round 21
remains the reference for those. The round found **no product defect** but six
documentation defects — four of them in this runbook — all corrected here: §6.1's
isolated-cwd workaround was actively broken, §3.3 claimed the two authoring routes
produce identical files when they do not, and the wizards' automatic prompts were
substantially under-documented (§3.3, §3.4). Full detail:
[`2026-08-12-round-22.md`](../evidence/minimal-poc-architecture/2026-08-12-round-22.md).

Round 21 (2026-08-11) authored and deployed the FreeIPA identity roster as **Roster
Schema v2** for the first time in this runbook's history, and remains the reference
pass for identity, the reconcilers and §4.1/§4.4. **§7 holds its full record** — scope,
the roster's actual shape, every `ok=/changed=/failed=` count, the one real
implementation defect found and fixed, and the environment note.

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
| Fact timestamp | 2026-08-31T09:00+08:00 (round 30; round 29's full-matrix pass was 2026-08-25) |
| Targets | `freeipa-server`, `nexus`, `client-vm` |
| VM sizing | FreeIPA: 2 vCPU/**4608 MiB**/30 GiB; nexus: 6/12288/80; client: 2/2048/20 |
| VM provisioning | `pilot vm-target topology up --topology docs/topologies/minimal-poc-topology.yaml` (spec's own `services: local` key); see §3.2 |
| Inventory source | Generated from a fresh gitignored workspace, built via live `pilot edit`/`pilot inventory generate` driving — `hosts.yml` (3 hosts, all required roles), the hard-required `group_vars` values (prometheus/thanos-query S3 target, dashboard Thanos-Query target, restic S3 target, wazuh-fim manager host, freeipa server IP), `host_vars/nexus.yml`, remaining `.vault/main.yaml` secrets, the FreeIPA identity roster authored as **`schema_version: 3`** (users/groups/hostgroups/HBAC/sudo/NFS export incl. the Plan B `nfs_clients[]` entry/one optional netgroup, hand-authored parts into the roster's nested YAML per §2/§3.3's documented exceptions), a `freeipa-dns` manifest (one zone, 2 A records — `grafana` deliberately excluded, owned by `internal-endpoint` instead, see §3.6), and an `internal-endpoints` manifest (one `reverse_proxy`+`tls.mode: freeipa` endpoint for Grafana) |
| Stage | `sandbox` |
| Alignment | Actual hosts and populated role groups matched the intended topology, including the merged `freeipa-dns-client`/`host-monitoring`/`reverse-proxy` placements — confirmed live for the first time in round 25 (previously DRAFT). `freeipa_roster_file` is now also required on `client-vm` (Plan B — see §2) |
| Manual extra `-e` | Empty; inventory-derived values were accepted through the wizard |
| Tested candidate | Round 29: commits `338bf83`+`131ae5a` (full clean pass after 2 authorized fixes). Round 30: HEAD `0bb39cc` plus that session's own 2 uncommitted fixes (DNS preflight fail-closed gate skips `--check` mode; NFS-server roster schema gate accepts `schema_version: 3`) |
| Result | Round 29 found and fixed 2 real bugs (a `dig`-diagnostic-as-stdout misread, and 8 sites writing an FQDN into `/etc/hosts`'s IP column), then passed clean. Round 30 found and fixed 2 more real bugs — both introduced by very recent unrelated work landing in between: a fail-closed DNS gate (commit `0bb39cc`) with no check-mode exemption, and an NFS-server roster schema gate that missed the `schema_version: 3` rollout. Both fixed with explicit authorization plus a regression test each; site-wide deploy, both day-2 reconcilers, all three single-component deploys, and the complete §4.1–§4.5 matrix then passed clean, `failed=0` throughout. Idempotency reruns (`freeipa-dns`+`internal-endpoint` combined, and `freeipa-dns-client`/`freeipa-ca-trust`/`reverse-proxy` individually) all confirmed `changed=0`; a full site-wide idempotency rerun hit an unrelated environment/disk-sizing gate on `nexus` (see §6.1) rather than a code defect. See [round-29](../evidence/minimal-poc-architecture/2026-08-25-round-29.md) and [round-30](../evidence/minimal-poc-architecture/2026-08-31-round-30.md) evidence for full detail |

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
- **All three hosts: `freeipa-dns-client`, `host-monitoring`** (merged in from the retired
  `delivery-test` skill, 2026-08-14; **verified live end-to-end in round 25** — see §3.7, §4.2, §4.5).
- **`nexus`: `reverse-proxy`** (merged in from the retired `delivery-test` skill — see §3.7, §3.8,
  §4.5). `freeipa-ca-trust` is day-2/opt-in and targets the literal `all` inventory group by
  default, so it has no per-host role-table entry — see §3.7.
- Keep `dns`, `ntp`, `keycloak`, `keycloak-db`, and `linux-servers` empty in this PoC. FreeIPA
  supplies DNS/NTP; Keycloak/PAM-OIDC is out of scope.

**All three hosts point their own OS-level DNS resolver at the FreeIPA server**
(`freeipa-dns-client`) — `freeipa-server` resolves itself first (the shared resolver logic
auto-detects when the current host is itself a DNS provider), `nexus`/`client-vm` resolve against
`freeipa-server`'s IP — **and all three get the FreeIPA integrated CA installed into their OS trust
store** (`freeipa-ca-trust`, run explicitly in §3.7, not left as an incidental side effect of §3.8's
reconcile) **and all three run `host-monitoring`'s node_exporter** so Prometheus has real per-host
scrape targets instead of only ever scraping itself — see §4.2's strengthened metric-chain check.
`nexus` additionally gets `freeipa-client` (already required above for NFS/AAA) plus `reverse-proxy`
specifically so the `internal-endpoint` reconciler can publish Grafana at a stable internal FQDN
(`grafana.it.pilot.internal`, HTTPS via a FreeIPA-issued certificate) instead of
`http://<nexus-ip>:3000` — see §3.7, §3.8, and §4.5 for the closed-loop proof that DNS + CA trust
together are what actually make `curl https://grafana.it.pilot.internal/...` succeed with a
genuinely valid certificate, from every node, not just from `nexus` itself.

This merge was **executed end-to-end against this exact topology in round 25 (2026-08-15)** — see
[round-25 evidence](../evidence/minimal-poc-architecture/2026-08-15-round-25.md) for the full
checkpoint matrix, including the port-443 conflict between `reverse-proxy` and `wazuh-manager`
that round found and fixed (Wazuh dashboard now maps to host port 8443, not 443).

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
- `docs/verification/freeipa-dns-client.md`
- `docs/verification/freeipa-ca-trust.md`
- `docs/verification/reverse-proxy.md`
- `docs/verification/internal-endpoint.md`
- `docs/verification/host-monitoring.md`

The last five were merged in from the retired `delivery-test` skill (2026-08-14) — see §3.7, §3.8,
and §4.5.

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
metric/log queries, shared backup visibility, a Wazuh FIM event, the FreeIPA identity
remove/restore/drift reconciliation cycle, and (merged in from `delivery-test`, 2026-08-14) a
closed-loop proof that FreeIPA CA trust + DNS resolver on every host are what make
`https://grafana.it.pilot.internal/...` succeed with a genuinely valid certificate — see §4.5.

## 2. Prerequisites

- `/dev/kvm` access, an active libvirt `default` NAT network, and writable pilot image storage.
- Optionally, `pilot services up --profile dev-lite` running (`pilot services status` to check) so
  `vm-target up --services local` can reuse a host-local package/image cache across rebuilds instead
  of re-pulling from public upstreams every time; it is fail-closed (errors rather than silently
  falling back) if the stack isn't healthy. This is host-level cache state, not part of the
  disposable candidate — do not tear it down between rounds.
- A freshly built `./pilot` binary from the candidate revision.
- A new gitignored workspace under `./tmp`; do not reuse an abandoned or partially repaired one.
- **Added round 30**: before the first `pilot deploy`/`pilot reconcile` invocation, run
  `git status --porcelain group_vars/ host_vars/ .vault/` from the repo root. Any stray,
  gitignored file sitting there from unrelated prior work silently pollutes `pilot deploy`'s
  `ansible-inventory --list` variable resolution when pilot is (as every invocation in this
  runbook is) run with cwd=repo-root — e.g. a leftover repo-root `group_vars/prometheus.yml` with
  an empty `thanos_s3_target_host` overrides the correct value from the workspace's own
  `group_vars/`, producing a spurious `component "thanos-query" requires input
  "thanos_s3_target_host"` even though the workspace is configured correctly. Not a pilot defect
  (see §6.1); move any stray file aside for the duration of the run rather than deleting it.
- A real TTY for `pilot edit`, `pilot deploy`, and `pilot reconcile`.
- `trec` recording according to the `pilot-trec-verification` and `trec-tui-drive` skills. Driver
  mechanics and recording failures belong in those skills, not this operational runbook.
- Vault values for the eight **required** keys listed below; never record their values:
  `ipa_admin_password`, `grafana_admin_password`, `restic_aws_access_key_id`,
  `restic_aws_secret_access_key`, `restic_password`, `thanos_aws_access_key_id`,
  `thanos_aws_secret_access_key`, and `node_exporter_basic_auth_password`.
  **Corrected round 23**: this list previously ended in `alertmanager_config`, which is
  wrong in both directions. `internal/inventory/vault.go` marks `alertmanager_config`
  `Optional: true` and the generator emits it commented-out; the genuinely required eighth
  key is `node_exporter_basic_auth_password` (shared with `host-monitoring` — both sides
  must hold the same value or Prometheus's scrape is refused with 401), which this list
  never mentioned. `ipa_dm_password` remains genuinely
  optional (falls back to `ipa_admin_password`) — round 16 found and fixed a bug where `pilot
  deploy`'s hard completeness gate demanded it anyway despite `internal/inventory/vault.go` marking
  it `Optional: true`; see §6's now-historical gotcha entry if you're on a checkout older than that
  fix.
- A canonical FreeIPA identity roster with `schema_version: 3` (current default; confirmed round
  30 — `pilot edit`'s NFS-server bootstrap writes a brand-new roster as `schema_version: 3` with
  an empty `grants: []`. `pilot roster migrate <file>` upgrades an existing `schema_version: 1` or
  `2` roster in place, and `pilot edit`/`pilot deploy`/`pilot reconcile` all auto-upgrade one the
  moment they open it — see `.agents/skills/freeipa-roster-authoring/SKILL.md`), the `freeipa` connection/safety
  block, and the required `users`, `groups`, `hosts`, `hbac`, `sudo`, and `nfs` objects. `netgroups`
  is optional and v2-only (feeds NSS/NFS export selectors, not HBAC/sudo) — the roster manager has no
  netgroup screen, so hand-author it into the roster's nested YAML like the NFS shares already are
  (**corrected round 23**: HBAC rules and sudo rules are no longer in that hand-authored set —
  they have wizard editors now, with the narrow exceptions §3.3 lists); a
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
host whose apply playbook reads it — in this topology that is `freeipa-server`
(`freeipa-identity-apply.yml`), `nexus` (`freeipa-nfs-server-apply.yml`, which independently
loads the same roster to resolve its own NFS server/share entries), and, **as of the Plan B fix
(2026-08-14) and confirmed live in round 25**, `client-vm` too
(`freeipa-nfs-client-apply.yml`, which now resolves its own `nfs_clients[]` targeting from the same
roster — see §3.4's roster-authoring note and `docs/verification/freeipa-nfs-client.md` §1.5). Point
it at the same absolute roster path on all three hosts. The project convention is
`.vault/ipa-identity.yaml` under the workspace; there is **no playbook default path**, so pass its
deployment-controller absolute path, for example `<workspace>/.vault/ipa-identity.yaml` (on the
investigated controller: `/home/ubuntu/ansible/.vault/ipa-identity.yaml`). Do not use
`.vault/main.yaml` as the roster path.

**Added 2026-08-18 (round 28)**: `pilot deploy` now auto-fills a missing `freeipa_roster_file` at
preflight time from whatever value another selected component's host already resolves it to (e.g.
`nexus`'s or `freeipa-server`'s), backing off only if some host's own value genuinely disagrees —
confirmed live by deliberately leaving it unset on `client-vm` and observing the auto-fill message
fire instead of a `requires input` error. Setting it explicitly everywhere, as this section
recommends, remains the clearer and still-fully-supported default; the autofill is a safety net for
the case where it was missed, not a replacement for setting it.

A roster group's `category` must match its name's prefix: `team` → `^team-`, `filesystem` →
`^data-`, `access` → `^access-`, `role` → `^role-` (enforced by a validation gate). **Corrected
round 30**: HBAC rule `subjects.groups` may reference `category: team`, `role`, or (legacy)
`access` groups directly — `access-*` is no longer required as a wrapper — confirmed live via
`internal/inventory/group_category.go`'s `IsHBACSubjectGroupCategory` and via `pilot edit`'s own
HBAC rule wizard, which offers a `team-*` group with no `access-*` indirection needed; the
committed `playbooks/apply/freeipa-identity.roster.example.yaml` already documents this exact
relaxation inline. Sudo rule `subjects.groups` still may only reference `category: role` groups
(`IsSudoSubjectGroupCategory`) — an account needing both SSH login and sudo access still needs
membership in a `role-*` group for the sudo half, but its HBAC login rule no longer requires a
separate `access-*` group of its own.

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

**Authoring pitfalls confirmed live in round 22** (each one cost a scripted
attempt; all are wizard behaviour, not defects):

- **Checking `freeipa-nfs-server` fires three chained prompts on checklist
  confirm, not one.** In order: `pushNFSRoleBootstrap`'s masked FreeIPA
  admin-password prompt; then — if that host also has `prometheus` — an inline
  `prometheus_site_label` prompt; then the `host_vars/<host>.yml` key-list
  editor, which you must save explicitly (`💾 存檔並離開`). Saving it returns to
  that **host's own menu**, not the roles menu, so this host never shows the
  `✅ 完成` roles-menu row the other hosts do. Script all three or the run
  stalls on unscripted input.
- **`freeipa_roster_file` is needed on `freeipa-server` too, and nothing sets it
  for you.** The NFS bootstrap only auto-sets it on the host that gained the
  `freeipa-nfs-server` role (here `nexus`). `pilot inventory generate` then
  fail-closes with `host "freeipa-server": roles ... require freeipa_roster_file
  pointing to the canonical FreeIPA roster` until you add it by hand through
  that host's `其他變數` screen. This is correct fail-closed behaviour — expect
  it rather than treating it as a bug.
- **The bootstrap's minimal vault blocks skeleton completion.** Because the NFS
  bootstrap creates `.vault/main.yaml` with exactly one key
  (`ipa_admin_password`) during hosts.yml authoring, `inventory generate`'s
  never-overwrite policy reports "already exists, left untouched" and never adds
  the remaining required keys. Round 22 measured **1 of 8** present. Get the
  authoritative list without touching the workspace:
  ```bash
  ./pilot inventory generate --dir <workspace> --out /dev/null \
    --vault-out /tmp/vault-skeleton.yaml \
    --no-group-vars --no-host-vars --no-nfs-roster
  ```
  then fill every missing key through `pilot edit`'s vault editor.
- **A derailed wizard run is not always side-effect-free.** The ordinary editors
  only write on an explicit save, but the auto-bootstrap paths above write
  immediately — a run that dies before any save can still have created
  `.vault/ipa-identity.yaml`, `.vault/main.yaml` and `host_vars/<host>.yml`.
  Wipe the workspace between scripted attempts to keep them deterministic.
- **A recorded vault fill will fail `trec verify`'s secret scan, and that is
  expected.** The vault key-list screen re-renders `<key> = <value>` for every key
  each time it opens, and the scanner's `inline-secret-assignment` rule fires on
  that *pattern* — it matches the shipped `CHANGE-ME-…` placeholders and even
  redacted or empty values. Round 22's fill was correct (all keys set on disk,
  every declared secret redacted, literal greps clean) yet still scored 33
  findings. Do **not** chase these as leaks and do not weaken `--secret-env`
  coverage to silence them. Treat the vault-fill cast as a diagnostic and let the
  checkpoint's evidence be the on-disk key check — `grep` each key and confirm no
  `CHANGE-ME` remains. Verify first that your own declared secrets really are
  redacted; only the placeholder/pattern findings are benign.
- **Scope that `CHANGE-ME` check to *uncommented* lines (corrected round 23).** A
  correct, fully-filled vault still greps one hit: the generator writes each
  **optional** key commented-out but keeps its `CHANGE-ME-…` placeholder text, so
  `ipa_dm_password` matches forever by design. A bare `grep -c CHANGE-ME` therefore
  reports a finished vault as incomplete. Check the key's active state instead — e.g.
  confirm every required key from §2 appears at column 0 with a non-placeholder value,
  and ignore anything behind a `#`.

> **Alternative entry route.** `pilot edit`'s top menu also offers
> `快速建立最小 workspace`, a guided quick-start that walks hosts → skeleton →
> group_vars → vault → readiness in one pass. It drives the same editors, targets
> the same workspace files, and gates on the same `checkWorkspaceCompleteness`
> contract `pilot deploy` enforces. Either route is acceptable here, and neither
> substitutes for real deployment evidence — §3.4 onward is unchanged.
>
> **They used to not be byte-identical (round 22 finding, closed 2026-08-19).** The
> cross-role host pointers used to differ: `autofillCrossRoleHostVars` ran in only
> two places — the quick path called it explicitly, and `pilot edit`'s group_vars
> picker called it only when creating a file from its example — while `pilot
> inventory generate`'s own backfill (`copyMissingGroupVars`) copied each example
> verbatim with no autofill, leaving seven derivable values
> (`restic_s3_target_host`, `siem_forward_host` (×2), `thanos_query_target_host`,
> `thanos_s3_target_host` (×2), `wazuh_manager_host`) empty for you to type by hand.
> `copyMissingGroupVars` now runs the same autofill too, so both routes fill these
> from the inventory when it resolves unambiguously — this is also why `pilot
> deploy`'s own auto-detect prompt (§3.4) for these same seven vars stopped firing
> on every single run of a workspace built either way.

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
  (`schema_version: 3` as of round 30 — the bootstrap now writes v3 directly, with an empty
  `grants: []` in addition to the empty `netgroups: []` round 21 already documented; older
  checkouts wrote `schema_version: 1` or `2`, auto-upgraded the next time any `pilot` command opens
  it — `freeipa.admin.{principal,password}`, one `nfs.servers` entry for that
  host, `shares: []`) and filling `.vault/main.yaml`'s `ipa_admin_password` from the same value.
  This fires for `freeipa-nfs-server` only, never `freeipa-nfs-client` — set `freeipa_roster_file`
  by hand (host's "其他變數" menu) on any *other* host whose apply playbook also reads the roster
  (in this topology, `freeipa-server` — point it at the same absolute path the bootstrap already
  used on nexus).
- **If you use the roles menu's `📋 套用常用角色範本` shortcut instead of the manual checklist for
  `client-vm`, still check `freeipa-nfs-client` yourself (2026-08-17 change).** The built-in
  `被監控的 Linux 主機(minimal PoC)` preset no longer bundles `freeipa-nfs-client` by default — it
  was removed because not every host built from that preset needs an NFS mount. §1's role table is
  unaffected and still requires it on `client-vm`; the preset shortcut alone will now leave it
  unchecked, so add it via `☑  逐項勾選角色` (or `⚙  管理角色範本` to add it back into a
  workspace-local copy of the preset) before moving on.
- **`host_vars/<host>.yml`**: a per-host menu item, `host_vars/<host>.yml(必填、無安全預設值的設定)`,
  appears automatically once that host has a role with such a key (today just
  `prometheus_site_label` for `prometheus`, gating on `prometheus-apply.yml`'s hard requirement —
  see `docs/verification/prometheus.md` §1.5). Selecting it auto-scaffolds the file and reuses the
  same flat key-editor `group_vars/` uses.
- **`group_vars/*.yml`** and **`.vault/main.yaml`**: unchanged from before — `pilot inventory
  generate` backfills the group_vars skeleton from `.example.yml` files and (only on a workspace
  with no existing vault file) a vault skeleton; fill remaining group_vars values and add any vault
  key `pilot inventory generate` didn't already create via `.vault/`'s `➕ 新增 key` action.
- **`roster` (top-menu item)**: four editors against the same canonical roster the NFS
  bootstrap already created — `👤 Users`, `👥 Groups`, `🔐 Host access`, and
  `🛡️  Sudo commands & rules`. **Substantially wider than this runbook claimed before
  round 23**, which described it as Users/Groups only. Every action dry-runs against the
  roster validator first and refuses — showing the violation — rather than writing
  anything invalid. Writes land immediately; there is no separate save step, so the
  `✅` banner *is* the save confirmation. Verified live in round 23:
  - **Users** — add writes `{name, state: present}`, then per-user field editors for
    `state` (present/disabled), `first`, `last`, `display_name`, `email`, `uid`, `gid`,
    `login_shell`, `home_directory`, `enabled`, **`password.initial`** (masked input,
    never pre-filled), `password.force_change`, `password.preserve_existing`, and
    **`ssh_keys.values`** (add/modify/remove individual public keys).
  - **Groups** — add is a category picker (team-/data-/access-/role-, matching §2's
    prefix rule) then a name, then editors for `type`, `description`, `gid`,
    `membership.authoritative`, and **`membership.users`/`membership.groups`** as
    checklists over what the roster already declares.
  - **Host access** — **`Hostgroups`** (add; `description`; `membership.hosts` as a
    comma-separated FQDN field; `membership.hostgroups` as a nested-hostgroup checklist)
    and **`HBAC rules`** (add walks name → subject-group checklist → hostgroup checklist →
    PAM-service checklist; edit covers `subjects.groups`, `targets.hostgroups`,
    `services`), plus a direct **`hbac.disable_allow_all`** toggle. **Corrected round 30**: the
    subject-group checklist offers `team-`/`role-`/(legacy) `access-` category groups directly —
    not `access-*` only, as previously documented here — matching §2's relaxed HBAC category rule.
  - **Sudo** — **`Command groups`** (name + comma-separated absolute commands) and
    **`Sudo rules`** (add walks name → role-group checklist → command-group checklist →
    extra-commands text; edit covers `subjects.groups`, `allow.command_category`,
    `allow.command_groups`, `allow.commands`).
- **`🔍 檢查設定完整性` (top-menu item)**: an advisory ✅/❌ report sharing its checks with `pilot
  deploy`'s own hard gate (missing/CHANGE-ME vault keys, unfilled host_vars, roster structural
  violations) — run it before deploying; it never blocks a save or exit itself.
- **Noted round 30, not exercised**: the roster manager's top menu now also lists **`🏛️ Access
  governance`** and **`🔒 Identity hardening`** (later v3.x roster features). Both are out of scope
  for this minimal PoC's baseline and were not exercised this round; see
  `internal/inventory/roster_version.go`/`roster_migrate.go` if a future round needs to cover them.

What the edit menu still cannot do — hand-edit the roster's nested YAML for these, the same
tool-endorsed exception as before. **This list was rewritten in round 23**: the previous
version named HBAC rules, sudo rules, hostgroups, membership, passwords and `ssh_keys`, and
every one of those now has a wizard editor (see the `roster` bullet above). Following the
old list meant hand-editing files the wizard owns, which the clean-room contract's
Pilot-ownership rule forbids. Each item below was verified against the current source and
exercised live in round 23:

- **`netgroups`** — no screen anywhere in `pilot edit`. Still fully hand-authored (§2).
- **`nfs.servers[].shares[]`** and **`nfs_clients`** — no screen. The NFS-role bootstrap
  writes one `nfs.servers` entry with `shares: []`; every share, its `ownership`, `acl`,
  `export.clients` and `automount` block is hand work. **`nfs_clients[]` is functionally load-bearing
  since the 2026-08-14 Plan B fix** (previously accepted but never read by any playbook): each entry's
  `hostgroup` must resolve — via direct membership or one level of nesting — to the real FQDN of every
  `freeipa-nfs-client` host, or `freeipa-nfs-client-apply.yml`'s new gate fails closed (see
  `docs/verification/freeipa-nfs-client.md` §1.5). **Confirmed live in round 25**: the gate/targeting
  mechanism itself works correctly, but the actual `verification_mounts` mount can only succeed if the
  NFS server's own FQDN (`nfs.servers[].host`) resolves from the client — which it does not in this
  topology today, since `freeipa-client-apply.yml` never registers a client's FQDN in FreeIPA's own DNS
  (a separate, pre-existing gap, not a Plan B defect — see round-25 evidence and §6).
  **Added 2026-08-18 (round 28)**: a hostgroup's membership may instead be declared
  `membership: {all: true}` — this wildcard covers every `freeipa-nfs-client` host, present and
  future, without listing FQDNs individually. Confirmed live: a `client-vm` whose FQDN appears
  nowhere in any hostgroup's `hosts`/`hostgroups` still passed the targeting gate via a single
  `nfs_clients` entry pointing at an `all: true` hostgroup. Still hand-authored (no wizard screen)
  — same "no screen for this" exception as the rest of this bullet.
- **An HBAC rule's `subjects.users` and `targets.hostcat`** — the HBAC editor only offers
  *access-group* subjects and *hostgroup* targets, and `pushRosterHBACTargets` explicitly
  deletes `hostcat` when you touch targets. The practical consequence: the
  **`breakglass-admin-access` rule §2 requires before `allow_all` can be disabled cannot be
  produced by the wizard at all** (it needs `subjects.users: [admin]` + `hostcat: all`).
  Hand-author it *before* flipping the `hbac.disable_allow_all` toggle, or the apply-time
  safety gate rejects the run.
- **A sudo rule's `options`** — `newRosterSudoRule` hard-codes `options: []` and the rule
  detail screen has no options field, deliberately ("password authentication is the safe
  default"). So `!authenticate`, which §4.1's `sudo -n` checks require, is *always* a hand
  edit. See §6's NOPASSWD row.
- **A sudo rule's `deny`, `run_as`, and `targets`**, and an HBAC/sudo rule's `enabled`
  flag — creation sets `enabled: true`, `run_as.users: [root]`, `hostcat: all` and empty
  deny lists; nothing edits them afterwards.
- **`freeipa.*` beyond `admin.{principal,password}`** — `server`, `realm`, `domain`,
  `defaults`, `safety` have no editor.
- **Deletion.** The user `state` picker deliberately excludes `absent`, and groups are
  read-only on `state`; there is no delete for hostgroups, HBAC rules, sudo rules or
  command groups either. Removing an object is a hand edit — which is what §4.4's
  remove-membership step exercises (membership *itself* is wizard-editable; removing the
  whole object is not).

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

**Round 22 pinned down the exact prompt sequence**, which matters if you script it:

```
Inventory 檔路徑 → 拓樸圖 [Y/n] → 前置檢查(select) → 要佈署什麼(select)
→ 哪個 stage(select) → --limit → --tags → 密碼變數檔 [Y/n]
→ sudo(become) [y/N] → N× auto-detected -e [Y/n] → 還有其他 -e(text)
→ 要先預覽 [Y/n] → 確定要執行預覽指令嗎 [Y/n] → (preview)
→ 要接著套用真正的變更嗎 [y/N] → 確定要執行正式套用指令嗎 [Y/n] → (apply)
```

The `N× auto-detected -e` step is the one that bites: the wizard asks **one `[Y/n]`
confirm per derived host pointer**, and `N` depends on which roles this inventory
places. This topology originally produced **seven** — `siem_forward_host`,
`wazuh_manager_host`, `restic_s3_target_host`, `thanos_s3_target_host`,
`thanos_query_target_host`, `loki_target_host`, `alertmanager_target_host`, every one
resolving to `nexus`. Derive the expected set from `AutoHostVars` in
`cmd/pilot/cmd/deploy_catalog.go` rather than assuming a count; answering the wrong
number sends the next keystroke into the following prompt, and round 22's first
attempt silently answered `n` to `siem_forward_host` that way — declining a derived
value, which the input policy forbids.

**Confirmed round 30: `N` is no longer a fixed number, and the prompt set is not fixed either.**
On a workspace whose group_vars were already correctly autofilled going into deploy (the normal
case after the 2026-08-19 fix below), only `loki_target_host` fired from the original seven — the
other six were already configured and skipped outright. Two *new*, topology-independent prompts
also now fire regardless of whether this inventory selects the component at all:
`detection_metrics_source_host` and `detection_alertmanager_target_host`, belonging to the
`detection-engine` component added by unrelated later work — they ask even on a topology with an
empty `detection-engine` role group. Treat "derive the expected set from `AutoHostVars`, don't
assume a fixed count" as the durable rule; a specific number (seven or otherwise) is a snapshot of
one round's state, not a contract.

**Added 2026-08-19**: `N` shrinks on its own once a var is genuinely configured. Each
of these seven no longer gets asked about at all once its group_vars value is already
active (non-empty, non-`CHANGE-ME`) in every group_vars file that declares it —
`groupVarsKeyAlreadyConfigured` skips straight past it. And answering `y` here now
has a lasting effect: once the deploy actually succeeds, every accepted value is
written back into those group_vars files (`persistAcceptedAutoHostVars`), so the very
next run of this same workspace won't ask again for that var. `pilot inventory
generate`'s own group_vars backfill also now runs the same cross-role autofill
`pilot edit`'s group_vars picker always did (`copyMissingGroupVars` previously copied
each `*.example.yml` verbatim with every cross-role pointer left commented out — the
gap the "quick path" note below already flagged, now closed for the standalone
`pilot inventory generate` path too) — so a brand-new workspace whose topology
already resolves these vars unambiguously may see this prompt only once, or not at
all. Because neither wizard uses an alternate
screen buffer, a guard-matched answer loop can also re-match the previous prompt from
scrollback and type a stray character into the `還有其他 -e` text field; clear that
field (Ctrl-U) before submitting it empty.

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

Select `freeipa-identity`, `freeipa-server`, and `sandbox`. **Round 23 pinned down the exact
prompt chain**, which differs from §3.4's site-wide one in two ways that matter if you script it:

```
Inventory 檔路徑 → 拓樸圖 [Y/n] → 前置檢查(select) → 挑一個要調和的元件(select)
→ target_group(text) → 哪個 stage(select) → --limit → --tags → 密碼變數檔 [Y/n]
→ sudo(become) [y/N] → 還有其他 -e(text) → 要先預覽 [Y/n]
→ 確定要執行預覽指令嗎 [Y/n] → (preview)
→ 要接著套用真正的變更嗎 [y/N] → 確定要執行正式套用指令嗎 [Y/n] → (apply)
```

- **The `freeipa-server` in "select freeipa-identity, freeipa-server, sandbox" is a *text*
  prompt, not a menu**: `要限定只套用到哪個 group/host 嗎？(-e target_group=...；留空 = 用預設
  group "freeipa-server")`, sitting between the component menu and the stage menu. Leaving it
  empty selects that default, which is what this runbook wants. Round 23's first scripted
  attempt expected the stage menu here and stalled — before any mutation.
- **There are no auto-detected `-e` confirms at all.** §3.4's seven `[Y/n]` prompts come from
  the site-wide path's `siteAutoHostVars()` loop; the catalog path used by `reconcile` iterates
  only that component's own `AutoHostVars`, and `freeipa-identity` declares none. Do not budget
  keystrokes for them here.

Set `freeipa_roster_file` on the managed
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
apply / remove-membership / restore+drift-correction / idempotency-rerun cycle in §4.4.

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
`freeipa-server` (the same "其他變數" screen used in §3.3). **Added 2026-08-19**: leaving either
unset is no longer a hard requirement — `pilot deploy`/`pilot reconcile` now auto-fills
`freeipa_dns_manifest_file` at preflight time from the workspace-convention path
(`<workspace>/freeipa-dns.yaml`) as long as no host that needs it already has its own explicit
value; setting it explicitly here remains the clearer default. At the secret vars-file prompt select
`.vault/main.yaml` — same convention as §3.5, same `ipa_admin_password` requirement. Leave manual
extra `-e` empty. Confirmed live 2026-07-30 (round 18) driving this real interactive wizard directly
confirmed unattended): initial apply
`changed=2 failed=0` (3 A records — grafana/wazuh/s3 — created, all resolving through `nexus`'s real
IP via `dig`), idempotent rerun `changed=0 failed=0`. One real bug found and fixed getting here (see
§6): `freeipa-dns-apply.yml`'s `ipa_server_fqdn_expected` defaulted to the inventory's short host
alias instead of the FQDN `freeipa-server-apply.yml` actually installed the server as, whenever
`freeipa_server_fqdn` was left unset (the documented, normal case) — every reconcile against a
workspace following that convention failed the manifest-vs-inventory gate until fixed.

**Record ownership changed 2026-08-14 (merged in from `delivery-test`): `grafana` moves to
`internal-endpoint`.** As of this merge, this manifest should declare only the `wazuh` and `s3` A
records directly (both still `target.inventory_host: nexus`) — **not** `grafana`. §3.8's
`internal-endpoint` reconciler now owns the `grafana` name itself, fronting it with a real
FreeIPA-issued TLS certificate and nginx (§3.7), which this manifest's plain A record never did.
`records_mode: merge` means this manifest only touches the RRsets it explicitly lists, so leaving
`grafana` out here is exactly what lets `internal-endpoint` add it without either side pruning the
other. Round 24's evidence (which predates this merge) reflects the pre-merge 3-record shape
(`grafana`/`wazuh`/`s3` all created directly here) — that record is historically accurate for what
was run then, not a description of the current procedure. **This 2-record shape was executed
against this exact topology in round 25 (2026-08-15)**: `freeipa-dns` reconcile
`ok=31 changed=2 failed=0` with only `wazuh`/`s3` declared, then `internal-endpoint`'s own
reconcile (§3.8) added `grafana` with no ownership collision and no pruning of the other two —
confirmed live via `dig`/`getent hosts` from all three nodes. See
[round-25 evidence](../evidence/minimal-poc-architecture/2026-08-15-round-25.md).

### 3.7 `freeipa-dns-client`/`freeipa-ca-trust`/`reverse-proxy` — day-2/opt-in, single-component

> Merged in from the retired `delivery-test` skill, 2026-08-14. **Executed against this exact
> topology in round 25 (2026-08-15)** — all three single-component deploys passed `failed=0` on
> every targeted host, with a clean idempotent rerun for each. See
> [round-25 evidence](../evidence/minimal-poc-architecture/2026-08-15-round-25.md).

None of these three roles are in `site.yml` (their `deployCatalog` entries have no
`Reconcile: true`, so they run through `pilot deploy`'s "單一元件" flow, not `pilot reconcile`), and
all three must be applied **after** §3.4's site-wide deploy — `freeipa-dns-client` needs
`freeipa-server`'s native DNS already listening (`freeipa_setup_dns` defaults to `true`), and
`freeipa-ca-trust` needs a real CA cert already minted on `freeipa-server` to fetch. Order between
the three calls below doesn't matter to each other, but all three must finish before §3.8's
`internal-endpoint` reconcile (which needs `nexus`'s nginx already installed).

`freeipa-ca-trust` targets the literal `all` inventory group by default (`DefaultGroup: all` — not a
named role you add to §0.5's table, unlike the other two), so it needs no inventory change. Running
it here, on its own, is deliberate rather than redundant: `internal-endpoint`'s own reconcile (§3.8)
*also* re-applies the exact same CA-trust logic fleet-wide as a side effect of its first play, but
that only exercises the shared task file (`tasks/freeipa-ca-trust.yml`), never the standalone
`freeipa-ca-trust-apply.yml` playbook's own stage gates and `pilot deploy` path. Running it
explicitly here means §4.5's later proof that `curl https://grafana.it.pilot.internal/...` gets a
genuinely valid certificate rests on a CA-trust step that was itself independently applied and
verified — not on an incidental side effect of a different component's reconcile that happens to
also do it.

```bash
pilot deploy   # 選「單一元件」→ freeipa-dns-client
# target group already resolves to all 3 hosts from §0.5's role table — no
# -e target_group= override needed.

pilot deploy   # 選「單一元件」→ freeipa-ca-trust
# target group defaults to the literal `all` group (every host in this
# inventory) — no role-table entry, no -e target_group= override needed.

pilot deploy   # 選「單一元件」→ reverse-proxy
# target group already resolves to nexus alone from §0.5's role table.
```

**Corrected round 25**: in a workspace that already has a `.vault/main.yaml` (every workspace
built per §3.3 does), the vars-file prompt is the same auto-detect confirm every other component
uses ("偵測到 .../.vault/main.yaml，這次佈署要用它當密碼變數檔嗎？" `[Y/n]`) — answer `y`. The
"不需要/需要" select this section previously described only appears when no vault file was
auto-detected at all; it never actually fires in this runbook's own workspace convention.

**`freeipa-ca-trust`'s empty-`target_group` default was a real bug, found and fixed live in round
25** (not just this section's prose being wrong): leaving the target-group prompt empty resolved
zero hosts (`component "freeipa-ca-trust" role "freeipa-ca-trust" resolves no hosts`), and — far
more seriously — **any other component depending on it, with no possible prompt-level workaround,
failed the same way** (this is exactly how §3.8's `internal-endpoint` reconcile failed before the
fix). Root cause: `contracts/freeipa-ca-trust.yaml` declared `role: freeipa-ca-trust` instead of
the literal `all` it actually targets; `cmd/pilot/cmd/deploy.go`'s dependency resolver has no
knowledge of `deploy_catalog.go`'s cosmetic `DefaultGroup` field, only a literal
`inventoryGroups[component.Role]` lookup. Fixed by correcting the contract's `role` to `all` — the
empty-`target_group` default (and every dependent component) now resolves correctly. See
[round-25 evidence](../evidence/minimal-poc-architecture/2026-08-15-round-25.md).

**A second real bug found running these three live in round 25**: Wazuh dashboard's official
docker-compose bundle hard-binds host port 443, which collides with `reverse-proxy`/nginx on
`nexus` (this topology co-locates both roles there) — nginx's `bind()` to 443 failed with "Address
already in use", so external HTTPS connections to `nexus` landed on Wazuh's own dashboard cert
instead of any `internal-endpoint` vhost, no matter what nginx's config said. Fixed by remapping
the dashboard to host port 8443 in `wazuh-manager-apply.yml` (`community.docker.docker_compose_v2`
against the official bundle, patched via `ansible.builtin.replace` after unpack, before compose-up)
— re-run `wazuh-manager` once after upgrading past this fix if `nexus` was ever provisioned before
it landed, since a stale nginx worker holding a failed-bind state needs one restart to actually
claim the now-free port (`systemctl restart nginx` on `nexus`; a fresh topology never hits this,
since Wazuh claims 8443 from its very first start).

A rerun of all three must settle to `changed=0` on every host they apply to — confirm this once
before moving on to §3.8, since §3.8's own idempotency claim depends on these three already being
converged, not still catching up on their first apply. Confirmed live in round 25: all three
idempotency reruns landed clean `changed=0`.

### 3.8 `internal-endpoint` reconcile — publish `grafana.it.pilot.internal`

> Merged in from the retired `delivery-test` skill, 2026-08-14. **Executed against this exact
> topology in round 25 (2026-08-15)** — `ok=80 changed=10 failed=0`, `✅ 套用完成`. See
> [round-25 evidence](../evidence/minimal-poc-architecture/2026-08-15-round-25.md).

Must run after §3.7 (nginx installed on `nexus`) and §3.6 (the `it.pilot.internal.` zone exists).
Author the endpoint manifest first via `pilot edit`'s "internal-endpoints manifest" top-menu item —
a `reverse_proxy` route through `nexus` to Grafana's own `:3000` on the same host, fronted by a real
FreeIPA-issued certificate (`tls.mode: freeipa`) so §4.5's check needs no `-k`/`--insecure`. Then run
the same reconcile wizard as §3.5/§3.6:

```bash
./pilot reconcile -i <workspace>/inventory.yml --timeout 90m
```

Select `internal-endpoint`, target `freeipa-server`, `sandbox` stage, vars-file prompt →
`.vault/main.yaml` (same `ipa_admin_password` requirement as §3.5/§3.6). At "還有其他 -e 變數要帶
嗎？", pass both manifest paths together (the reconciler cross-checks the endpoint's `dns.zone`
against the freeipa-dns manifest's own zones, spec.md §11.1-§11.3). **Added 2026-08-19**: leaving
this prompt empty now also works — `pilot reconcile` auto-fills both
`internal_endpoint_manifest_file` (`<workspace>/internal-endpoints.yaml`) and
`freeipa_dns_manifest_file` (`<workspace>/freeipa-dns.yaml`) from these conventional paths at
preflight time when neither is already set elsewhere; typing them explicitly remains the clearer
default and is what the example below still shows:

```
internal_endpoint_manifest_file=<absolute path to workspace>/internal-endpoints.yaml freeipa_dns_manifest_file=<absolute path to workspace>/freeipa-dns.yaml
```

This run's first play also reapplies the FreeIPA CA-trust and DNS-resolver baseline to **every**
managed host (not just `nexus`) — expect `changed=0` there if §3.7 already ran, since both playbooks
share the same underlying task files (`tasks/freeipa-ca-trust.yml` /
`tasks/freeipa-dns-client-resolver.yml`); that overlap is intentional, not a sign either step was
redundant to run on its own. Confirm the preview shows: a new `HTTP/grafana.it.pilot.internal`
service principal + virtual host object (delegated to `nexus`), a certmonger request on `nexus`, a
rendered nginx vhost on `nexus`, and the `grafana` A record in `it.pilot.internal.` pointing at
`nexus`'s IP (never Grafana's own "upstream" identity, since `route.mode` is `reverse_proxy` — the
DNS destination is always the proxy host). Apply, then see §4.5 for the client-side proof.

### 3.9 `internal-endpoint` auto-provision suggester — added and live-tested round 26

> **Round 26 (2026-08-15).** Built on round 25's still-running topology, not a fresh rebuild — see
> [`2026-08-15-round-26.md`](../evidence/minimal-poc-architecture/2026-08-15-round-26.md).

§3.8 above requires hand-authoring one manifest entry per endpoint. A contract endpoint can instead
opt in to auto-suggestion by declaring `autoPublish: {eligible: true, subdomain: <name>}` (see e.g.
`contracts/dashboard.yaml`'s `grafana` entry, `contracts/wazuh-manager.yaml`'s `dashboard` entry).
Eligibility is a real, per-endpoint decision, never inferred from `scheme: http`/`https` alone — every
ineligible endpoint in this project's own contracts (FreeIPA's own web UI, Keycloak's OIDC endpoint,
Prometheus/Alertmanager/Thanos Query) still declares the block with `eligible: false` and a `reason`,
so the exclusion reads as a decision, not an oversight. See round 26's evidence for the reasoning
behind each: FreeIPA's own web UI would be circular (it is the trust root `internal-endpoint` itself
depends on); Keycloak's `KC_HOSTNAME` is hardcoded and would issue OIDC tokens with a mismatched `iss`
claim if fronted under a different name; the metrics-stack components have no auth of their own.

Two ways to use it, neither of which reconciles a live host by itself — every accepted candidate still
goes through the exact same `SimulateAddInternalEndpoint`/`AppendInternalEndpoint` gate a hand-authored
entry uses, then §3.8's own reconcile wizard to actually apply it:

```bash
# read-only — prints candidates, writes nothing
./pilot internal-endpoint suggest \
  --inventory <workspace>/inventory.yml \
  --freeipa-dns-manifest <workspace>/freeipa-dns.yaml \
  --manifest <workspace>/internal-endpoints.yaml   # omit for a fresh/empty manifest
```

or interactively, via `pilot edit`'s internal-endpoints manifest → Endpoints menu → "🔎 從已部署服務建議
endpoint", which presents the same candidates as a checklist.

Both auto-resolve the publishing zone from `freeipa-dns.yaml` (only when it declares exactly one zone)
and the proxy host from the `reverse-proxy` inventory group (only when it has exactly one host) —
anything ambiguous is reported, never guessed; pass `--zone`/`--proxy-host` explicitly in that case.
A candidate whose default subdomain collides with an existing `freeipa-dns.yaml` record (a real case
hit live in round 26 — see §6.1) is rejected by the same DNS-ownership-collision gate §3.8 already
relies on, not silently double-claimed.

**Known bug, found round 30 (reported, not fixed) — prefer the CLI form.** The interactive menu
item ("🔎 從已部署服務建議 endpoint") always reports the `reverse-proxy` host count as 0
regardless of actual role assignments, because `pushInternalEndpointSuggestMenu`
(`cmd/pilot/cmd/edit_tui_internal_endpoints.go`) resolves inventory groups against `hosts.yml`
(pilot's own authoring format, top-level `hosts:` key) via `ansible-inventory`, not the generated
`inventory.yml` — `ansible-inventory -i hosts.yml --list` misreads `hosts:` as a literal group
named "hosts" and every real group resolves empty this way, not just `reverse-proxy`. The
standalone CLI shown above is unaffected in normal use only because its own `--inventory` flag
default is *also* `hosts.yml` (same latent bug) but every documented invocation overrides it
explicitly with the workspace's `inventory.yml`. Until fixed, always pass `--inventory
<workspace>/inventory.yml` explicitly and use the CLI form rather than the interactive menu item.

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
in §6 and repeat both checks. **Expect this on every fresh run, not occasionally** (round 23: the
spotcheck scored 6/8 with both alice-sudo rows failing `sudo: a password is required`, then 8/8
immediately after `sss_cache -E && systemctl restart sssd` on `nexus`, with no roster change in
between). Confirm it is the cache and not the NOPASSWD authoring gap first — `ipa sudorule-show`
showing `Sudo Option: !authenticate` already attached means cache; no options at all means §6's
NOPASSWD row.

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

**Strengthened 2026-08-14 (merged in from `delivery-test`): a plain `up` query is not enough on its
own.** Prometheus always self-scrapes its own `job="prometheus"` target, so the query above returns
a non-empty `result` array even when `host-monitoring` (§0.5) has zero real targets — this is the
same class of vacuous-pass bug this project has hit before (the C1 cobra "unknown"-substring
false-pass, Wazuh's unused 514/udp port). Query the **node** job specifically and count the targets:

```bash
curl -s "http://<nexus-ip>:10912/api/v1/query?query=up%7Bjob%3D%22node%22%7D" | \
  python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]["result"]; print(len(d), [r["metric"].get("instance") for r in d])'
# expect: 3 [<freeipa-ip>:9100, <nexus-ip>:9100, <client-ip>:9100] — one per host-monitoring host, all value=1
```

If this returns `0 []` while the plain `up` query above still "passed," `host-monitoring` (§0.5) is
empty in the inventory, `node_exporter_basic_auth_password` doesn't match between
`host-monitoring`'s and `prometheus`'s vault consumption (§2 — same key, both sides read it), or
Prometheus never picked up the `host-monitoring` group's members at apply time (rerun the site-wide
deploy, §3.4 — `prometheus-apply.yml` re-expands its scrape targets from the current inventory on
every apply, no separate step needed). **Confirmed live in round 25 (2026-08-15)**:
`3 [('192.168.122.2:9100', '1'), ('192.168.122.3:9100', '1'), ('192.168.122.4:9100', '1')]` — one
target per `host-monitoring` host, all `value=1`.

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

1. Remove the allowed user's HBAC/role-group membership from the roster and reconcile. Per §2's
   category rule (**relaxed round 30** — HBAC now accepts `team`/`role`/legacy `access` groups
   directly) this is normally still two groups in practice (one for HBAC login, one `role-*` for
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

### 4.5 FreeIPA CA trust + DNS resolver on every host, and Grafana via `grafana.it.pilot.internal`

> Merged in from the retired `delivery-test` skill, 2026-08-14. **Executed against this exact
> topology in round 25 (2026-08-15) — every check below passed.** See
> [round-25 evidence](../evidence/minimal-poc-architecture/2026-08-15-round-25.md) for the full
> command output.

Three separate things to prove, not one — a host could resolve the internal FQDN by accident (e.g.
a stale `/etc/hosts` entry from earlier debugging) without its resolver genuinely pointing at
FreeIPA, the CA cert could be present on disk but not actually wired into the OS trust store
nginx/curl consult, and the reverse-proxy chain could work by IP even if DNS were broken. Check all
three, and check the resolver/trust checks from **all three** hosts, not just `client-vm`.

**C-ca-1 — the FreeIPA CA is genuinely installed and trusted, on every host** (reuses
`docs/verification/freeipa-ca-trust.md`'s own C1/C3/C4 probes verbatim — this is the property that
actually determines whether C-endpoint-1's `curl` below needs `-k`, so check it directly rather than
inferring it backwards from whether `curl` happened to succeed):

```bash
for h in freeipa-server nexus client-vm; do
  echo "== $h =="
  pilot vm-target exec --name "$h" -- sh -c '
    f=/usr/local/share/ca-certificates/pilot-freeipa-ca.crt
    [ -f "$f" ] || f=/etc/pki/ca-trust/source/anchors/pilot-freeipa-ca.crt
    if [ ! -f "$f" ]; then echo missing; exit 0; fi
    issuer=$(openssl x509 -in "$f" -noout -issuer 2>/dev/null | sed "s/^issuer=//")
    subject=$(openssl x509 -in "$f" -noout -subject 2>/dev/null | sed "s/^subject=//")
    [ "$issuer" = "$subject" ] || { echo not-self-signed; exit 0; }
    openssl verify "$f" 2>&1 | grep -q ": OK$" && echo trusted || echo untrusted'
done
# expect "trusted" for all three
```

**C-dns-1 — every host's resolver is genuinely FreeIPA, not DHCP/distro default** (same probe
`docs/verification/freeipa-dns-client.md` C3 uses — NetworkManager on EL regenerates
`/etc/resolv.conf` on every `nmcli device reapply`, so check the persisted connection profile there
instead of the file):

```bash
for h in freeipa-server nexus client-vm; do
  echo "== $h =="
  pilot vm-target exec --name "$h" -- sh -c '
    if command -v nmcli >/dev/null 2>&1 && [ -n "$(nmcli -t -f NAME connection show --active 2>/dev/null | head -n1)" ]; then
      conn=$(nmcli -t -f NAME connection show --active | head -n1)
      [ "$(nmcli -g ipv4.ignore-auto-dns connection show "$conn" 2>/dev/null)" = yes ] && echo pilot-managed || echo not-managed
    else
      grep -q pilot-freeipa-dns-client /etc/resolv.conf && echo pilot-managed || echo not-managed
    fi'
done
# expect pilot-managed for all three
```

**C-dns-2 — real end-to-end resolution against FreeIPA's own DNS**, not a cached/hardcoded answer:

```bash
for h in freeipa-server nexus client-vm; do
  echo "== $h =="
  pilot vm-target exec --name "$h" -- getent hosts grafana.it.pilot.internal
done
# expect the same IP as `pilot vm-target list`'s nexus entry, from all three
```

**C-endpoint-1 — Grafana reachable by FQDN over HTTPS, real FreeIPA cert, no `-k`**:

```bash
pilot vm-target exec --name client-vm -- curl -sS https://grafana.it.pilot.internal/api/health
# {"database": "ok", ...} with no --insecure/-k needed

pilot vm-target exec --name client-vm -- sh -c \
  "echo | openssl s_client -connect grafana.it.pilot.internal:443 -servername grafana.it.pilot.internal 2>/dev/null | openssl x509 -noout -subject -issuer"
# subject=...CN=grafana.it.pilot.internal, issuer=...CN=Certificate Authority (FreeIPA's own CA, not self-signed)
```

If C-endpoint-1's `curl` needs `-k` to succeed, go back to C-ca-1 on that specific host first, not
nginx — a broken/untrusted cert chain is a trust-store problem on the *client* host running `curl`
(either §3.7's `freeipa-ca-trust` step never reached it, or §3.8's own fleet-wide reapply somehow
diverged from it), unrelated to whether nginx itself is serving correctly. If `getent hosts` in
C-dns-2 fails outright on `freeipa-server` or `nexus` specifically (works fine from `client-vm`),
re-check that §0.5's role table really was applied to all three — §3.7's `freeipa-dns-client` deploy
silently no-ops on a host that never joined the inventory group.

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
| `pilot vm-target topology up` fails with `services: Harbor is unreachable: ... connection refused`, moments after `pilot services status` reported `running=true` | **Suspected implementation defect, reported not fixed (round 19, 2026-08-06).** The dev-lite Harbor containers had actually exited (`Exited (128)` ~28h earlier) but `services status`'s health signal did not reflect it; the first real signal came from `topology up`'s own consumer-side connectivity check. | `./pilot services down && ./pilot services up --profile dev-lite` (full recreate), then retry. To tell a real outage from this reporting gap, check container state directly — `docker ps --format '{{.Names}}\t{{.Status}}' \| grep dev-lite` — and expect every Harbor container plus `pulp` and `apt-cacher-ng` to read `Up ... (healthy)`; the round-19 incident showed `Exited (128)` there while `services status` still said `running=true`. Round 22 confirmed a genuinely healthy stack this way. Don't probe an HTTP health path for this — the earlier wording said to, without naming one, and a guessed path returns 404 on a healthy Harbor. `topology up` with `services: local` is fail-closed, so it is the authoritative test either way. A future round should investigate `services status`'s health-check implementation. |
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
| A sudo rule's live `sudo -n <cmd>` fails with `sudo: a password is required` and `ipa sudorule-show <rule>` confirms the rule is attached | **Missing NOPASSWD — and not really an authoring slip (reclassified round 23).** `sudo.rules[].options` was `[]`; without `!authenticate`, `sudo -n` correctly refuses since it cannot prompt. What the old wording missed: a rule created through `pilot edit`'s sudo wizard **always** starts this way — `newRosterSudoRule` hard-codes `options: []` as its deliberate safe default and no screen edits the field — so every wizard-authored rule needs this hand edit before §4.1 can pass. Distinguish from the cache-staleness row above via `ipa sudorule-show`'s output: cache issue shows `!authenticate` already present, this shows no options at all. | Add `"!authenticate"` to the rule's `options`, reconcile, then still refresh the target client's SSSD cache (the staleness gotcha applies on top once the option exists). |
| §4.1's roster-authorized sudo command fails with `Unit sshd.service could not be found` even though the rule is correctly attached | **Authoring mistake, not a tool/playbook defect.** The roster granted `/usr/bin/systemctl status sshd`, but the live target is Ubuntu 24.04 where the unit is `ssh.service` — RHEL/AlmaLinux and Debian/Ubuntu name the same daemon differently. | Grant a command that exists on the target's OS family (`systemctl status ssh` on Debian/Ubuntu, `systemctl status sshd` on RHEL/AlmaLinux), re-run `pilot reconcile` to apply the correction (a useful exercise of the drift-correction path, §4.4), then refresh the client's SSSD sudo cache. |
| `pilot deploy` aborts before any preview with `delivery transaction failed: component "freeipa-server" ... resources ... are below minimum ... ramMiB=4096` | **Environment/topology gap, not a code defect.** `deploy_facts.go` gathers real per-host OS facts before the delivery preflight; AlmaLinux 9's usable RAM under this topology's KVM/virtio overhead lands ~185 MiB below the nominal `--memory` value. | Give `freeipa-server` headroom above the declared minimum — `docs/topologies/minimal-poc-topology.yaml`'s `memory: 4608` reflects this. If the node was already up, `pilot vm-target down --name freeipa-server` then `topology up` recreates just that node, **but it gets a new DHCP-assigned IP even with the same MAC** — re-set that host's `ansible_host` via `pilot edit` and re-run `pilot inventory generate` before redeploying. |
| `pilot deploy`/`pilot reconcile` fail their completeness gate — or, worse, silently resolve a `group_vars`/`host_vars` value to the wrong thing — even though the workspace's own files are correct | **Environment pollution, not a pilot defect** — but the mechanism stated here for four rounds is wrong, **corrected round 23**. `internal/ansible`'s `Runner.Run` genuinely never sets `cmd.Dir`, so `ansible-playbook` does inherit pilot's process cwd. What does *not* follow is the vars-plugin claim: for `ansible-playbook <playbook>` the `host_group_vars` plugin reads the **inventory** directory and the **playbook's** directory, not the cwd. A controlled probe with inventory, playbook and cwd in three separate directories, each holding a conflicting `group_vars/<group>.yml`, resolved the **inventory-adjacent** value. Do **not** use `ansible -m debug -a "var=<key>"` from the same cwd as the diagnostic (what this row used to say): ad-hoc `ansible` *does* treat cwd as its basedir, so it reports a value the real deploy never uses. Round 23 hit exactly that false positive — the isolated cwd had accumulated six verbatim copies of unfilled `*.example.yml`, `ansible -m debug` reported `thanos_s3_target_host: ""`, and the live host had every derived alias correctly mapped to nexus in `/etc/hosts`, proving the apply had used the real values all along. A real cwd sensitivity may still exist by another route — vars-file paths reach `ansible-playbook` unresolved as `-e @<path>` (`internal/ansible/runner.go:207`), so a *relative* vault path would resolve against cwd — but that was not the thing this row described and has not been re-tested. **Reconfirmed round 30** with a concrete live trigger: a stray, gitignored repo-root `group_vars/prometheus.yml` (leftover from unrelated earlier work) with an empty `thanos_s3_target_host` produced exactly `component "thanos-query" requires input "thanos_s3_target_host"` when `pilot deploy` ran from the repo root, even though the workspace's own `group_vars/` had the correct value — confirmed by reproducing it directly with `ansible-inventory -i <workspace>/inventory.yml --list` from repo-root cwd vs. from the workspace dir. Isolating cwd via `PILOT_ROOT` was tried as a fix and rejected: it broke `ansible-playbook playbooks/preflight.yml`'s own relative-path resolution instead. | Never invoke `pilot edit`/`pilot inventory generate` without `--dir`. If the repo root already has such stray files and their ownership is unclear, don't move or delete them — run from an isolated directory that symlinks every repo-root entry except `host_vars`/`.vault`/`tmp`, **and a `group_vars/` containing symlinks to only the `*.example.yml` templates plus the `dns/` example dir**. Excluding `group_vars/` wholesale (what this row said before round 22) silently breaks `pilot inventory generate`'s backfill: that one directory holds both the stray shadowing `*.yml` and the 13 legitimate templates the generator copies from, so the run produces a workspace with **zero** group_vars files and still exits 0 — see §3.3. A future Go-side fix should pin `cmd.Dir` explicitly. Quick pre-flight check (added round 30): run `git status --porcelain group_vars/ host_vars/ .vault/` from the repo root before the first deploy of a round — any listed file is a candidate; move it aside for the run's duration rather than deleting it. |
| `pilot deploy`/`pilot reconcile` preflight fails a **second, otherwise-clean** site-wide idempotency rerun with `component "wazuh-manager" host "nexus" resources ... diskGiB=<N> are below minimum ... diskGiB=50` | **Environment/topology sizing gap, found round 30, not a code defect.** `docs/topologies/minimal-poc-topology.yaml`'s `nexus` disk (80 GiB) was sized against `wazuh-manager`'s declared 50 GiB minimum assuming a mostly-empty disk; it does not leave headroom for the real data the full component stack accumulates once actually running (Wazuh indexer data, Prometheus/Loki TSDB, Docker images). Confirmed live: `df -h /` on `nexus` showed only 43 GiB free after a real full site-wide deploy, `77G total, 35G used`. | Not a bug to fix in code. Single-component deploys/reconcilers that don't select `wazuh-manager` (`freeipa-dns-client`, `freeipa-ca-trust`, `reverse-proxy`, `freeipa-dns` reconcile, `internal-endpoint` reconcile) are unaffected — verify idempotency through those instead of a full site-wide rerun once the stack has real data. A future round should bump `nexus`'s topology disk allocation (e.g. 80→120 GiB) if a full-site idempotency rerun after real data accumulation needs to stay possible. |

The rows below were merged in from the retired `delivery-test` skill (2026-08-14). **Confirmed
live against this exact topology in round 25 (2026-08-15)** — none of these five actually fired
during that round (all preconditions were already satisfied in the order §3.6→§3.7→§3.8 runs
them), so they remain untested *failure* paths even though the surrounding scope is now verified;
kept as documented troubleshooting guidance.

| Symptom | Cause | Current action |
|---|---|---|
| §3.8's `internal-endpoint` reconcile fails requesting the certificate (`ipa-getcert request` errors, or certmonger has no valid credential) on `nexus` | `nexus` was missing the `freeipa-client` role — a FreeIPA *virtual* host object (created automatically for `grafana.it.pilot.internal` itself) has no keytab of its own; the request is authenticated as `nexus`'s own real host principal via the managedBy delegation (spec.md §18), which requires `nexus` to actually be enrolled. This topology's §0.5 already requires `freeipa-client` on `nexus` for NFS/AAA reasons, so this should not fire here — it is listed for the case where that role gets removed | Confirm `freeipa-client` is still in `nexus`'s role list, rerun the site-wide deploy (§3.4) so `nexus` enrolls, then rerun §3.8 |
| §3.8 fails a precondition/assert about the DNS zone, or the manifest cross-check against `freeipa_dns_manifest_file` | §3.6 (declare the `it.pilot.internal.` zone) wasn't run yet, or its `records_mode` isn't `merge`, or the zone name in `internal-endpoints.yaml`'s `dns.zone` doesn't exactly match `freeipa-dns.yaml`'s zone name (including the trailing dot) | Run §3.6 before §3.8; diff both files' zone name byte-for-byte |
| §3.8's nginx vhost render/reload task fails on `nexus` (`nginx: command not found`, or `nginx -t` fails against a config namespace that doesn't exist) | §3.7's `reverse-proxy` single-component deploy wasn't run yet — `internal-endpoint`'s own reconcile only ever *renders a vhost*, it never installs nginx itself (see `reverse-proxy`'s `planOnly` dependency in `contracts/internal-endpoint.yaml`) | Run §3.7's `reverse-proxy` deploy against `nexus` before §3.8 |
| §3.7's `freeipa-ca-trust` deploy step itself fails or is skipped for a host | `freeipa-ca-trust-apply.yml` needs a real CA certificate already minted on the `freeipa-server` host — the site-wide deploy (§3.4) hasn't finished yet, or `freeipa-server`'s own DNS/CA services aren't up yet | Confirm §3.4's site-wide deploy finished cleanly and `freeipa-server-apply.yml`'s own recap showed the CA/DS services started before retrying §3.7 |
| §4.5's `curl https://grafana.it.pilot.internal/...` needs `-k`, or fails cert verification only from `freeipa-server`/`client-vm` (works fine from `nexus` itself) | The FreeIPA CA-trust baseline hasn't reached that host — either §3.7's standalone `freeipa-ca-trust` deploy was skipped/failed on it, or (less likely, since §3.8's own first play reapplies the identical logic fleet-wide) something diverged between the two runs | Run §4.5's C-ca-1 check on that specific host first to confirm/deny it's a trust-store problem before touching nginx; if C-ca-1 says `untrusted`/`missing`, re-run §3.7's `freeipa-ca-trust` deploy (idempotent) and re-check — don't just re-run §3.8 and hope, since that masks *why* §3.7 didn't already cover it |
| §4.5's `curl https://grafana.it.pilot.internal/...` gets a connection that presents **Wazuh's own dashboard certificate** (`CN=wazuh.dashboard`), not a FreeIPA one, even though nginx's vhost config looks completely correct | **Real bug, found and fixed round 25.** Wazuh dashboard's official docker-compose bundle hard-binds host port 443, colliding with `reverse-proxy`/nginx on any host running both roles (this topology's `nexus`) — whichever binds first wins the socket; `journalctl -u nginx`/`/var/log/nginx/error.log` shows `bind() to 0.0.0.0:443 failed (98: Address already in use)`. | Upgrade past the fix (`wazuh-manager-apply.yml` now remaps the dashboard to host port 8443). If `nexus` was provisioned before the fix landed, one manual `systemctl restart nginx` is needed after re-running `wazuh-manager` — a stale nginx worker holding the old failed-bind state doesn't self-heal on its own. A fresh topology built after the fix never hits this. |
| Plan B's `verification_mounts` check on `client-vm` never shows a real `nfs4`/`sec=krb5` mount, even after `freeipa-identity`/`freeipa-dns-client` have both run | **Separate, pre-existing gap, not a Plan B defect (found round 25).** The NFS server's own FQDN (`nfs.servers[].host`, e.g. `nexus.ipa.pilot.internal`) has no A record in FreeIPA's own DNS at all — confirmed via `dig @<freeipa-ip> nexus.ipa.pilot.internal A` returning `NXDOMAIN` directly from the authoritative server. `freeipa-client-apply.yml` deliberately passes `--no-dns-sshfp` with no `--enable-dns-updates` to `ipa-client-install` (this project's own DNS-is-reconciler-managed design choice), so client hosts are never dynamically registered. | Not yet fixed — would need either enabling dynamic DNS updates during enrollment, or adding an explicit `freeipa-dns` manifest record for every NFS server FQDN a client needs to resolve. The Plan B gate/targeting/verify mechanism itself is confirmed correct independent of this gap (see round-25 evidence). |
| §3.9's `pilot internal-endpoint suggest` (or its `pilot edit` menu item) proposes a candidate that `pilot internal-endpoint validate`/`SimulateAddInternalEndpoint` then rejects with `dns ownership conflict` | **Not a bug — the same gate §3.8 already relies on, working as designed (found round 26).** A contract endpoint's default `autoPublish.subdomain` can collide with a name `freeipa-dns.yaml` already owns for something unrelated — happened live in this exact topology: the dashboard's default `wazuh` collided with an existing direct-access `wazuh` A record for the manager's own agent ports. | Pick a different, non-colliding subdomain for that one candidate (either edit the printed YAML's `fqdn` before pasting it, or the contract's own `autoPublish.subdomain` default if the collision will recur on every fresh run of this same reference topology — `contracts/wazuh-manager.yaml`'s default is already `wazuh-dashboard` for exactly this reason). |

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
| `pilot reconcile`'s `freeipa-identity` preview crashes with `Error while resolving value for 'identity_hbac_test_host': object of type 'dict' has no attribute 'server'` | 2026-07-30, commit `e5c56c4` (i.e. before round 18) | Add `freeipa.server` (the FreeIPA host's real FQDN, e.g. `ipa1.<domain>`) to the roster by hand. **Moved out of §6.1 in round 23**: §6.1 had carried this as a live "reported not fixed (round 17)" row for four rounds, together with a mandatory roster workaround, after the exact fix it proposed had already landed — `freeipa-identity-apply.yml:424` now reads `{{ freeipa_roster.freeipa.server \| default(ipa_server_fqdn \| default(inventory_hostname)) }}`. Round 23 confirmed it live by authoring a roster with **no** `freeipa.server` key — precisely the bootstrap-produced shape the old row said would crash — and reconciling it successfully. |
| `pilot deploy`/`pilot reconcile` reports `component "freeipa-ca-trust" role "freeipa-ca-trust" resolves no hosts` — either leaving its own `target_group` empty, or trying to run `internal-endpoint` (which depends on it) at all, with no possible wizard workaround for the latter | round 25 (2026-08-15) | `contracts/freeipa-ca-trust.yaml` now declares `role: all`, matching what `freeipa-ca-trust-apply.yml` actually targets by default. `cmd/pilot/cmd/deploy.go`'s dependency resolver has no knowledge of `deploy_catalog.go`'s cosmetic `DefaultGroup` field — a component's contract `role` must itself be a real, resolvable inventory group name (or the literal `all`) for both its own empty-`target_group` default and any other component's dependency resolution to work. |
| `freeipa-nfs-client-apply.yml`'s new roster-driven fail-closed gate fails a fresh, not-yet-enrolled host's very first `--check --diff` preview | round 25 (2026-08-15) | Gate now guarded with `when: not ansible_check_mode`, mirroring `freeipa-nfs-server-apply.yml`'s own identical pattern — a fresh host's `hostname --fqdn` only reports its real FQDN after `ipa-client-install` actually runs, never during a preview. |
| Adding the `verification_mounts` mount-check to `freeipa-nfs-client-apply.yml` made the very first real site-wide apply silently skip `host-monitoring`/`wazuh-fim`/`restic-backup`/`audit-log-forwarding` on the NFS client host | round 25 (2026-08-15) | The check now carries `ignore_errors: true` — its own prerequisites (the IPA automount map, created by the separate `freeipa-identity` day-2 reconcile; the NFS server FQDN resolving, needing the separate `freeipa-dns-client` day-2 role) are never guaranteed during a plain `site.yml` pass, and a hard failure there used to cascade through Ansible's default "drop a failed host from every later play" behavior. |
| `pilot vm-target topology up` fails the whole command with `Error: wire "<host>": peer "<other>" has no IP yet; bring it up first`, even though every VM genuinely started booting (fresh qemu processes, fresh overlay disks) | round 28 (2026-08-18) — **not fixed, environment timing, retry works** | The cross-node "wire" step (which pins every node's `wire:` peers into `/etc/hosts` once all three have an IP) appears to check peer IPs once rather than waiting/retrying under concurrent bring-up — one node's DHCP lease can land a few seconds after the check runs. An immediate identical retry of the same `topology up` command succeeds (`already up ... skipping` for the already-booted nodes, then all wire entries succeed) once leases have landed. |
| Recreating only one node (e.g. `pilot vm-target down --name freeipa-server` then `topology up`) to recover from an unrelated issue leaves the other already-enrolled hosts silently unable to reach it (`ipa` CLI / `service-add` etc. fail `[SSL: CERTIFICATE_VERIFY_FAILED] ... self-signed certificate in certificate chain`) | round 28 (2026-08-18) | A fresh `ipa-server-install` mints a **brand-new self-signed root CA** every time — the existing §6.1 note about this scenario only mentions needing to update the recreated host's `ansible_host` IP, but every other already-enrolled host also still trusts the *old*, now-destroyed CA, and `freeipa-client-apply.yml`'s enrollment task is (correctly) idempotent on `/etc/ipa/default.conf` already existing, so it won't detect or fix the mismatch on its own. Run `ipa-client-install --uninstall --unattended` on every other host before redeploying, so enrollment genuinely re-joins against the new CA (the "Unenrolling host failed: Client not found in Kerberos database" line this prints is expected and harmless — the old server is gone). A genuine full clean-room rebuild (all nodes recreated together) never hits this. |
| `--check --diff` (or a real apply's DNS-registration phase) on `freeipa-client-host-dns.yml` treats a genuinely fresh `freeipa-server` that hasn't finished `ipa-server-install` yet as if it already owns a conflicting CNAME/A/AAAA record for the host being registered | round 29 (2026-08-25), commit `131ae5a` | `dig` writes its own "communications error"/"no servers could be reached" diagnostics to **stdout**, not stderr; the CNAME-ownership assert and the A/AAAA current-addresses `set_fact` both read `.stdout` unconditionally, so an unreachable/refused query (`rc != 0`) got misread as "found a real record." Both now guard on `rc == 0` before trusting `.stdout` — see the fix site in `tasks/freeipa-client-host-dns.yml`. |
| A component's apply reports `changed: true` for its "pin `<alias>` → `<target>` in `/etc/hosts`" task, but the alias still doesn't resolve afterward (`Could not resolve hostname`, or a live `dial tcp: ... server misbehaving`) | round 29 (2026-08-25), commit `338bf83` | `/etc/hosts` requires a literal IP in column 1, but every `*_target_host` var these tasks pin is documented as accepting either an IP or an inventory host's own FQDN — an FQDN written unchanged into that column is silently ignored by glibc/systemd-resolved while the task still reports `changed: true`. Hit live in 8 files (`wazuh-fim`, `restic-backup`, `audit-log-forwarding`, `wazuh-manager`, `prometheus` ×2, `thanos-query`, `dashboard`, `log-shipping`); all now `include_tasks: tasks/resolve-hosts-alias-target.yml` first, which resolves via this inventory's own `hostvars` before ever falling back to a live DNS lookup. |
| Site-wide `--check --diff` preview fails on `client-vm`/`nexus` with "Cannot verify the authoritative DNS state ... Refusing DNS registration ... (spec.md §8.2/§8.3, fail-closed)" on any genuinely fresh clean-room topology | round 30 (2026-08-31); not yet committed at time of writing — see `playbooks/apply/tasks/freeipa-client-host-dns.yml`'s "Gate: authoritative DNS queries must return a usable response" | Introduced by the same round's own starting `HEAD` (`0bb39cc`), which added this fail-closed gate with no check-mode exemption. A `--check` preview correctly skips `ipa-server-install` (a real mutation), so FreeIPA's DNS genuinely isn't running yet and the read-only plan-phase `dig` query gets no answer — expected on a fresh topology, not evidence of a broken authority. Fixed by adding `and not ansible_check_mode` to the gate's `when:`; regression test `TestRegression_FreeipaClientHostDNSTask_FailClosedGateSkipsCheckMode` in `internal/spec/freeipa_client_regression_test.go`. |
| `--check --diff` preview or real apply fails on `nexus`'s `freeipa-nfs-server` at "Gate: required roster and stage authorization" even though `pilot roster lint` reports the roster clean, on a roster `pilot edit`'s own NFS-server bootstrap just created | round 30 (2026-08-31); not yet committed at time of writing — see `playbooks/apply/freeipa-nfs-server-apply.yml` line 38 | The gate's `schema_version \| int in [1, 2]` (already fixed once, round 21, for the v1→v2 rollout — see the row above) missed the later v2→v3 rollout: `pilot edit`'s NFS-server bootstrap now writes a brand-new roster as `schema_version: 3` directly, and the sibling `freeipa-identity-apply.yml` gate had already been updated to `[1, 2, 3]` but this one hadn't. Fixed by matching the sibling gate exactly; regression test `TestRegression_FreeIPANFSServerAcceptsCurrentRosterSchema` in `internal/spec/freeipa_nfs_regression_test.go` also asserts both gates' lists stay identical going forward. |

Two rows previously listed here now live with their component, which is
authoritative for them: SeaweedFS's anonymous `C6`–`C8` rows failing once signed
S3 mode is on (`docs/verification/seaweedfs-s3.md`, expected behavior — do not
weaken authentication), and `restic-backup`'s `C6` verification timeout
(`docs/verification/restic-backup.md`, which now applies the longer timeout
automatically).

## 7. Latest verified evidence

| Field | Round 30 record |
|---|---|
| Verified at | 2026-08-31 (Asia/Taipei) |
| Tested revision/tree | HEAD `0bb39cc` plus this session's own 2 uncommitted fixes (DNS preflight fail-closed check-mode gate in `playbooks/apply/tasks/freeipa-client-host-dns.yml`; NFS-server roster schema-version gate in `playbooks/apply/freeipa-nfs-server-apply.yml`), each with a regression test added in `internal/spec/` |
| Targets | Fresh `freeipa-server` (AlmaLinux 9), `nexus` and `client-vm` (Ubuntu 24.04); full `pilot vm-target topology up` clean-room rebuild — first attempt clean, no wire-race retry needed |
| Focus | Full end-to-end re-confirmation of the entire §0.5–§4.5 scope plus a complete idempotency-rerun sweep, from a genuinely fresh topology; this round's value was finding, stopping for, and fixing (with explicit live authorization) 2 real regressions introduced by unrelated work that had landed on `HEAD` roughly an hour before this round started |
| Fix #1 verification | `freeipa-client-host-dns.yml`'s new fail-closed DNS gate (introduced by `0bb39cc`, this round's own starting `HEAD`) had no check-mode exemption, so every `--check --diff` preview of a fresh topology failed it outright — FreeIPA's DNS genuinely isn't running yet during a `--check` preview, since `ipa-server-install` is correctly skipped as a real mutation. Fixed by adding `and not ansible_check_mode` to the gate's `when:`. Re-ran the same preview after the fix: passed cleanly through the DNS gate section for both `client-vm`/`nexus` and reached `✅ 預覽完成，沒有錯誤。`. Regression test: `TestRegression_FreeipaClientHostDNSTask_FailClosedGateSkipsCheckMode` |
| Fix #2 verification | `freeipa-nfs-server-apply.yml` line 38's roster schema-version gate (`schema_version \| int in [1, 2]`) never picked up `schema_version: 3` when it became the current default — `pilot edit`'s own NFS-server bootstrap writes a brand-new roster as `schema_version: 3`, so this gate rejected every freshly-created roster even though `pilot roster lint` reported it clean, and even though the sibling gate in `freeipa-identity-apply.yml` had already been correctly updated to `[1, 2, 3]`. Fixed by matching the sibling gate exactly. Regression test: `TestRegression_FreeIPANFSServerAcceptsCurrentRosterSchema` (also asserts both gates' lists stay identical) |
| Site apply | Full `site.yml`, sandbox stage, clean after both fixes: `client-vm ok=184 changed=60 failed=0 ignored=1`; `freeipa-server ok=133 changed=54 failed=0`; `nexus ok=346 changed=122 failed=0`; `✅ 套用完成` |
| Day-2 reconcilers | `freeipa-identity`: `ok=103 changed=26 failed=0`; `freeipa-dns`: `ok=31 changed=2 failed=0`, 2 A records (`wazuh`/`s3` → nexus) |
| Single-component deploys | `freeipa-dns-client`: `client-vm/nexus ok=20 changed=7`, `freeipa-server ok=18 changed=3`, all `failed=0`; `freeipa-ca-trust`: all 3 hosts `ok=11 changed=2 failed=0`; `reverse-proxy`: `nexus ok=9 changed=5 failed=0`; `internal-endpoint` reconcile: `freeipa-server ok=82 changed=11 failed=0`, `client-vm`/`nexus ok=25 changed=0` |
| Idempotency reruns | `freeipa-dns`+`internal-endpoint` (combined multi-select rerun): `changed=0` on every host for both preview and apply. `freeipa-dns-client`/`freeipa-ca-trust`/`reverse-proxy` (individual reruns): all `changed=0`. A full site-wide idempotency rerun was attempted but blocked at the delivery-transaction preflight gate — `wazuh-manager` on `nexus` had only 43 GiB free against its declared 50 GiB minimum after the real deploy's own data accumulated; environment/topology-sizing gap, not a code defect (see §6.1) |
| §3.9 suggester | CLI spot-check (`pilot internal-endpoint suggest`): correctly skipped the already-published `grafana.it.pilot.internal` and proposed a new candidate, `wazuh-dashboard.it.pilot.internal`, for the undeclared `wazuh-manager` dashboard service, with well-formed YAML output |
| §4.1 HBAC/sudo | 8/8 via `scripts/minimal-poc-section4-spotcheck.sh` (after fixing a genuine roster-authoring gap mid-round — the HBAC rule was missing `sudo`/`sudo-i` services); real-credentialed HBAC denial confirmed via `journalctl -u ssh` on `nexus`: `pam_sss(sshd:auth): authentication success` → `pam_sss(sshd:account): Access denied for user bob: 6 (Permission denied)` |
| §4.2 strengthened check | `up{job="node"}`/Thanos: `up{site="round30-nexus"} == 1`; full C-log-1–4 chain confirmed, incl. the coverage query (`client-vm=201, ipa1=679, nexus=3868`) and real Wazuh-alert host attribution |
| §4.3 backup/FIM | `restic-backup.timer` active+enabled on all 3 hosts; a real triggered backup produced 3 fresh snapshots by real FQDN (`ipa1.ipa.pilot.internal`, `nexus.ipa.pilot.internal`, `client-vm.ipa.pilot.internal`); a real-time Wazuh `whodata` `added` alert (`syscheck_new_entry` decoder) captured end-to-end through Loki for a live-injected `/etc` file on `client-vm` |
| §4.4 identity reconciler cycle | Revoke `changed=1`; live-discovered gap: the HBAC rule needed `sudo`/`sudo-i` services added, fixed via `pilot edit` and reconciled (`changed=2`) — this reconcile also silently reset alice's/bob's password back to the roster `initial` value, a pre-existing, already-documented §6.1 mechanism (`force_change: true` still set from onboarding), not a new bug; flipped `force_change: false` for both, re-personalized alice, reconciled again (`changed=0`, confirming the fix); restore `changed=3`; idempotency rerun `changed=0` on the first try — cleaner than round 29's cycle, which needed one extra pass for bob's own password |
| §4.5 (CA trust/DNS/endpoint matrix) | C-ca-1 `trusted` × 3; C-dns-1 `pilot-managed` × 3; C-dns-2 resolves to nexus's real IP (`192.168.122.2`) × 3; C-endpoint-1 real HTTPS `curl` (no `-k`) + genuine FreeIPA certificate (`issuer=... CN=Certificate Authority`, not self-signed) |
| Bugs found + fixed | (1) `playbooks/apply/tasks/freeipa-client-host-dns.yml`'s new fail-closed DNS gate had no check-mode exemption — fixed with `and not ansible_check_mode`; (2) `playbooks/apply/freeipa-nfs-server-apply.yml`'s roster schema gate missed the `schema_version: 3` rollout — fixed to `[1, 2, 3]`. Both stopped-and-authorized live before editing, per the clean-room contract; both introduced by very recent unrelated work, neither present in round 29's candidate |
| Findings reported, not fixed | `pilot edit`'s internal-endpoint suggester menu item always reports 0 `reverse-proxy` hosts because it resolves inventory groups against `hosts.yml` via `ansible-inventory` instead of the generated `inventory.yml` (`cmd/pilot/cmd/edit_tui_internal_endpoints.go`'s `pushInternalEndpointSuggestMenu`) — use the CLI form instead (§3.9) |
| Findings, environment (not product defects) | A stray, gitignored repo-root `group_vars/prometheus.yml`/`host-monitoring.yml` from unrelated prior work polluted `pilot deploy`'s variable resolution when run from repo-root cwd, reproducing a spurious `requires input "thanos_s3_target_host"` error — worked around by moving the files aside for each invocation (see §6.1); `nexus`'s topology disk (80 GiB) leaves insufficient headroom for a full site-wide idempotency rerun once the stack has accumulated real data (see §6.1) |
| Functional verdict | PASS for the complete §0.5–§4.5 scope plus the idempotency-rerun sweep, on a genuine fresh clean-room rebuild, after 2 real regressions were found and fixed live with explicit authorization at each stop |
| Publication | [`2026-08-31-round-30.md`](../evidence/minimal-poc-architecture/2026-08-31-round-30.md) |

| Field | Round 29 record |
|---|---|
| Verified at | 2026-08-25 (Asia/Taipei) |
| Tested revision/tree | This round's own 2 fixes, committed as `338bf83` (shared `/etc/hosts` alias resolution) and `131ae5a` (CNAME/A/AAAA rc-guard) — landed interleaved with unrelated commits from another concurrently active session on this same branch, so no single clean pre/post SHA pair is recorded here; the fix commits themselves are the authoritative pointer |
| Targets | Fresh `freeipa-server` (AlmaLinux 9), `nexus` and `client-vm` (Ubuntu 24.04); full `pilot vm-target topology up` clean-room rebuild — first attempt clean, no wire-race retry needed this round |
| Focus | Full end-to-end re-confirmation of the entire §0.5–§4.5 scope from a genuinely fresh topology; no new feature under test — this round's value was finding and fixing 2 real implementation bugs the existing matrix had never previously exercised in this exact combination |
| Site apply | Full `site.yml`, sandbox stage, on the **4th** attempt (attempts 1–3 hit and fixed the 2 real bugs below): `client-vm ok=166 changed=16 failed=0 skipped=66 ignored=1`; `freeipa-server ok=113 changed=11 failed=0 skipped=44`; `nexus ok=310 changed=48 failed=0 skipped=127`; `localhost ok=1` |
| Fix #1 verification | `freeipa-client-host-dns.yml`'s CNAME/A/AAAA rc-guard (`131ae5a`) — attempt 1 had false-failed exactly this task against this fresh `freeipa-server`; attempt 4's clean `failed=0` on it is the fix's own live proof |
| Fix #2 verification | Shared `tasks/resolve-hosts-alias-target.yml` (`338bf83`), wired into all 8 call sites — `wazuh-fim`'s manager alias and `restic-backup`'s S3 alias both actually resolved and reached their target live post-fix, where the pre-fix attempts got `Could not resolve hostname`/`dial tcp: ... server misbehaving`. The other 6 sites (`audit-log-forwarding`, `wazuh-manager`, `prometheus` ×2, `thanos-query`, `dashboard`, `log-shipping`) had not yet been exercised live before the sweep found the same shape by inspection — their fix is confirmed by this round's clean `changed=0`/`ok` on that task, not by an independent live failure-then-fix cycle |
| Day-2 reconcilers | `freeipa-identity`: `ok=99 changed=26 failed=0`; `freeipa-dns`: `ok=31 changed=2 failed=0`, 2 A records (`wazuh`/`s3` → nexus) verified live via `dig` |
| Single-component deploys | `freeipa-dns-client`/`freeipa-ca-trust`/`reverse-proxy`: all `failed=0`, idempotency reruns clean `changed=0 failed=0`; `internal-endpoint` reconcile: `changed=11 failed=0` |
| §3.9 suggester | Read-only `suggest` check only this round (no new endpoint published): proposed `wazuh-manager.dashboard` at port 8443, confirming round 25's dashboard-port-collision fix is still in place; correctly skipped the already-published `grafana` endpoint |
| §4.1 HBAC/sudo | 8/8 via `scripts/minimal-poc-section4-spotcheck.sh`; real-credentialed HBAC denial confirmed via `journalctl` for both the allowed and denied user (`pam_sss(sshd:auth): authentication success` → `pam_sss(sshd:account): Access denied for user bob`, and again for `alice` after §4.4's own revoke step) |
| §4.2 strengthened check | `up{job="node"}`: 3/3 targets up; full C-log-1–4 chain confirmed, incl. the coverage query (`client-vm=199, ipa1=1160, nexus=3945`) and real Wazuh-alert FQDN host attribution |
| §4.3 backup/FIM | `restic-backup.timer` active+enabled on all 3 hosts; a real triggered backup produced 3 fresh snapshots (one per host's real FQDN); a real-time Wazuh `whodata` alert captured end-to-end through Loki for a live-injected `/etc` file |
| §4.4 identity reconciler cycle | Revoke `changed=2`; live-discovered the reconcile had also silently reset alice's password — not a new bug, the roster still carried `password.force_change: true` from onboarding (existing §6.1 row); flipped `force_change: false` for alice and bob per the runbook's own documented convention, absorbed the one expected residual reset (`changed=1`) and re-personalized alice; restore + new sudo command `changed=4 failed=0`, no SSSD cache flush needed this time; idempotency rerun `changed=1`, traced to bob's own password never having been re-personalized after the flag flip; confirmed `changed=0` once bob was personalized too |
| §4.5 (CA trust/DNS/endpoint matrix) | C-ca-1 `trusted` × 3; C-dns-1 `pilot-managed` × 3; C-dns-2 resolves to nexus's real IP × 3; C-endpoint-1 real HTTPS `curl` (no `-k`) + genuine FreeIPA certificate (`issuer=CN=Certificate Authority`) |
| Bugs found + fixed | (1) `freeipa-client-host-dns.yml`'s CNAME/A/AAAA gate misread an unreachable `dig` (rc≠0) as an existing record — `131ae5a`; (2) systemic `/etc/hosts` FQDN-in-IP-column bug across 8 apply playbooks — `338bf83`. Both stopped-and-authorized live before editing, per the clean-room contract |
| Findings reported, not fixed | `trec`'s default `--pointer` regex doesn't match this TUI's `┃ ` box-drawing row prefix, blocking `CHOOSE`/`SELECT`/`TOGGLE` until overridden explicitly (belongs with `pilot-trec-verification`'s own gotchas, not here); a harmless duplicate YAML mapping key `register` in `audit-log-forwarding-apply.yml:376` (Ansible warns, uses the last value) |
| Functional verdict | PASS for the complete §0.5–§4.5 scope, after 2 real fixes applied live with explicit authorization at each stop |
| Publication | [`2026-08-25-round-29.md`](../evidence/minimal-poc-architecture/2026-08-25-round-29.md) |

| Field | Round 28 record |
|---|---|
| Verified at | 2026-08-18 (Asia/Taipei) |
| Tested revision/tree | HEAD `bc9d7bb` plus this session's own uncommitted changes (the 3 fixes below) |
| Targets | Fresh `freeipa-server` (AlmaLinux 9), `nexus` and `client-vm` (Ubuntu 24.04); independent fresh `pilot vm-target topology up` rebuild (not a topology reuse) |
| Focus | Narrow verification of **3 new fixes** round 27's candidate (12 commits behind) predates: (1) `freeipa_dns_allow_any_recursion` (new C20); (2) `cmd/pilot/cmd/deploy.go` roster-autofill regression fix; (3) `nfs_clients` roster `membership.all` wildcard |
| Deliberate authoring choices | `client-vm`'s `freeipa_roster_file` left unset (forces autofill); its `nfs_clients` coverage came from a `membership.all: true` hostgroup with no FQDN listed anywhere |
| Site apply | Full `site.yml`, sandbox stage, on the 5th attempt (first 4 blocked on an `ipa-server-install` connection timing hiccup and self-inflicted accumulated VM state from recovering it — not fixes-related, see round 28's evidence): `client-vm ok=143 changed=59 failed=0 ignored=1`; `freeipa-server ok=120 changed=52 failed=0`; `nexus ok=271 changed=121 failed=0` |
| Fix #1 verification | Real apply `changed` the config; `/etc/named/ipa-options-ext.conf` shows `allow-recursion { any; }; allow-query-cache { any; };`; `dig +short archive.ubuntu.com @<freeipa-ip>` from `client-vm` resolved a real public domain end-to-end; `pilot verify docs/verification/freeipa-server.md`: **PASS 20/20** incl. C20; same-day idempotent rerun reported both items `ok` (not `changed`) |
| Fix #2 verification | Real apply log: `ℹ️ freeipa_roster_file 未設定，自動帶入 .../ipa-identity.yaml` fired for `client-vm` (no `freeipa_roster_file` key in its `hosts.yml` entry) — deploy proceeded with no `requires input` error |
| Fix #3 verification | Real apply: `Gate: this host must be declared as a present nfs_clients entry in the roster` → `ok: [client-vm] => {"changed": false, "msg": "All assertions passed"}`, purely via the `membership.all` wildcard hostgroup |
| Not re-run this round | §4.1–§4.4 matrix, day-2 reconcilers, `delivery-test`-merged single components — round 27 remains their reference |
| Findings (both self-inflicted/environment, not product defects — see §6.1) | `topology up`'s wire step can fail once under concurrent bring-up (retry works); recreating a single node invalidates other hosts' CA trust, not just its IP |
| Functional verdict | PASS for all 3 fixes under test, on a genuine fresh clean-room rebuild with `failed=0` |
| Publication | [`2026-08-18-round-28.md`](../evidence/minimal-poc-architecture/2026-08-18-round-28.md) |

| Field | Round 27 record |
|---|---|
| Verified at | 2026-08-17 (Asia/Taipei) |
| Tested revision/tree | Commit `32f68c3` (tree `2e7df67`) — predates round 28's 3 fixes |
| Targets | Fresh `freeipa-server` (AlmaLinux 9), `nexus` and `client-vm` (Ubuntu 24.04); full `pilot vm-target topology up` clean-room rebuild |
| Focus | Full re-confirmation of the entire round-25/26 scope on a slightly later candidate — no new features under test |
| Site apply | Full `site.yml`, sandbox stage: `client-vm ok=140 changed=58 failed=0 ignored=1`; `freeipa-server ok=113 changed=48 failed=0`; `nexus ok=272 changed=120 failed=0` |
| `freeipa-identity` reconcile | `ok=72 changed=21 failed=0` |
| `freeipa-dns` reconcile | Zone `it.pilot.internal.`, 2 A records (`wazuh`/`s3` → nexus): `ok=31 changed=2 failed=0` |
| `freeipa-dns-client`/`freeipa-ca-trust`/`reverse-proxy` (single-component) | All three `failed=0` on every targeted host; idempotency reruns clean `changed=0` |
| `internal-endpoint` reconcile | `ok=81 changed=11 failed=0` on `freeipa-server`; `changed=0` on `nexus`/`client-vm` |
| §4.1 HBAC/sudo | 8/8 via `scripts/minimal-poc-section4-spotcheck.sh`; real-credentialed HBAC denial confirmed via `journalctl` (`pam_sss(sshd:auth): authentication success` → `pam_sss(sshd:account): Access denied for user bob`) |
| §4.2 strengthened check | `up{job="node"}`: 3/3 targets up, all `value=1`; full C-log-1–4 chain confirmed (per-host landing files, unique markers, coverage query, Wazuh alert host attribution) |
| §4.3 backup/FIM | restic timer active on all 3 hosts, snapshots present for all 3 real hostnames; a real `whodata` FIM alert confirmed for a live-injected file |
| §4.4 identity reconciler cycle | Revoke `changed=1`; restore + new sudo command `changed=3`; final rerun `changed=0`; password-stability rerun also `changed=0` |
| §4.5 (CA trust/DNS/endpoint matrix) | C-ca-1 `trusted` × 3; C-dns-1 `pilot-managed` × 3; C-dns-2 resolves × 3; C-endpoint-1 real HTTPS `curl` + genuine FreeIPA certificate |
| `internal-endpoint` suggester (§3.9) | Proposed `wazuh-dashboard.it.pilot.internal`; correctly skipped the already-published `grafana` endpoint |
| Bugs found | **None** — full clean pass |
| Findings reported, not fixed | After a revoke→restore membership cycle, `ipa hbactest` re-grants access correctly but a credentialed SSH/`kinit` attempt still reports `Client's credentials have been revoked` — a residual identity-reconciler credential-lifecycle gap |
| Functional verdict | PASS for the complete documented scope; no product defects found |
| Publication | [`2026-08-17-round-27.md`](../evidence/minimal-poc-architecture/2026-08-17-round-27.md); written up 2026-08-18 alongside round 28 |

**Round 25 (2026-08-15) — first live test of the Plan B `nfs_clients[]` fix and the complete
`delivery-test` merge (kept here as the historical record of that first pass; round 27 re-confirmed
the same scope cleanly two days later):**

| Field | Round 25 record |
|---|---|
| Verified at | 2026-08-15 (Asia/Taipei) |
| Tested revision/tree | HEAD `8ba602c` plus this round's own uncommitted fixes (4 real bugs found and fixed live — see below) |
| Targets | Fresh `freeipa-server` (AlmaLinux 9), `nexus` and `client-vm` (Ubuntu 24.04); all provisioned via **`pilot vm-target topology up --topology docs/topologies/minimal-poc-topology.yaml`** (the merged topology — every host also carries `freeipa-dns-client`/`host-monitoring`; `nexus` also carries `reverse-proxy`) |
| Focus | First live test of **two things at once**: the `freeipa-nfs-client` `nfs_clients[]` Plan B fix, and the complete `delivery-test`-merged scope (§3.7, §3.8, §4.2's strengthened check, §4.5) round 24 had left as DRAFT |
| Roster | `schema_version: 2`, same wizard-uncovered hand-authored exceptions as round 24 (users, category groups, hostgroups, HBAC, sudo, NFS share, one netgroup) plus the new Plan B `nfs_clients: [{hostgroup: nfsclients, verification_mounts: [/sysops]}]` entry. `pilot roster lint` clean throughout |
| Site apply | Full `site.yml`, sandbox stage, after fixes #1/#2 below: `client-vm ok=138 changed=41 failed=0 ignored=1`; `freeipa-server ok=106 changed=39 failed=0`; `nexus ok=271 changed=96 failed=0` |
| `freeipa-identity` reconcile | `ok=72 changed=21 failed=0` |
| `freeipa-dns` reconcile | Zone `it.pilot.internal.`, **2** A records (`wazuh`/`s3` → nexus; `grafana` deliberately excluded, owned by `internal-endpoint` instead — see §3.6): `ok=31 changed=2 failed=0` |
| `freeipa-dns-client`/`freeipa-ca-trust`/`reverse-proxy` (single-component) | All three `failed=0` on every targeted host; 3/3 idempotency reruns clean `changed=0` |
| `internal-endpoint` reconcile | `ok=80 changed=10 failed=0`, after fix #3 below |
| §4.2 strengthened check | `up{job="node"}`: 3/3 `host-monitoring` targets up, all `value=1` |
| §4.5 (CA trust/DNS/endpoint matrix) | C-ca-1 `trusted` × 3 hosts; C-dns-1 `pilot-managed` × 3 hosts; C-dns-2 `grafana.it.pilot.internal` resolves to nexus's real IP × 3 hosts; C-endpoint-1 real HTTPS `curl` + genuine FreeIPA certificate (`CN=grafana.it.pilot.internal`, issuer `IPA.PILOT.INTERNAL`'s CA) — after fix #4 below |
| Bugs found + fixed | (1) NFS-client fail-closed gate not check-mode-safe — `when: not ansible_check_mode`; (2) mount-verify task cascaded a hard failure through the rest of `site.yml` for that host — `ignore_errors: true`; (3) `contracts/freeipa-ca-trust.yaml`'s `role` field didn't match its actual `all`-group target, permanently blocking `internal-endpoint`'s dependency resolution with no wizard workaround — corrected to `role: all`; (4) Wazuh dashboard's docker-compose bundle hard-binds host port 443, colliding with `reverse-proxy`/nginx on `nexus` — dashboard remapped to port 8443 |
| Findings reported, not fixed | The Plan B NFS mount itself still can't complete end-to-end: `nexus.ipa.pilot.internal` has no DNS record in FreeIPA's own DNS at all (confirmed via direct `dig`: `NXDOMAIN`), since `freeipa-client-apply.yml` deliberately never requests dynamic DNS registration during enrollment — a separate, pre-existing architectural gap, not a Plan B defect (the gate/targeting/verify mechanism itself is proven correct); `deploy_catalog.go`'s `Note` field for 3 components still says "Phase-1 placeholder only" though all three have substantial real, already-tested logic |
| Process | Every long-running apply run directly by the controlling session's own backgrounded `Bash` calls, never delegated to a subagent (round 24's process lesson, held to throughout) |
| Functional verdict | PASS for the full documented scope, both Plan B and the merge, after 4 real fixes applied live with explicit authorization at each stop |
| Publication | [`2026-08-15-round-25.md`](../evidence/minimal-poc-architecture/2026-08-15-round-25.md); secret values and ephemeral addresses omitted |

**Round 26 (2026-08-15, same day) — `internal-endpoint` auto-provision suggester, added on top of
round 25's still-running topology (not an independent rebuild):**

| Field | Round 26 record |
|---|---|
| Verified at | 2026-08-15 (Asia/Taipei), same day as round 25 |
| Scope | New `autoPublish` contract field + `SuggestInternalEndpoints` + `pilot internal-endpoint suggest` (read-only) + `pilot edit` checklist menu item (§3.9) |
| Topology | Round 25's own 3 VMs, left running — no teardown/rebuild between rounds |
| Live test | Published `wazuh-dashboard.it.pilot.internal` via `suggest` → validate → real `pilot reconcile`: `freeipa-server ok=112 changed=10 failed=0`; `curl` + genuine FreeIPA cert confirmed from all 3 hosts; pre-existing `grafana.it.pilot.internal` unaffected; idempotency rerun `changed=0` on every host |
| Finding | Default subdomain `wazuh` collided with an existing `freeipa-dns.yaml` A record — caught by the DNS-ownership-collision gate before reaching a live host, not a suggester bug; corrected the contract default to `wazuh-dashboard` (§6.1) |
| Tests | `go build ./...` clean; `go test ./...` 1749 passed, 0 failed |
| Publication | [`2026-08-15-round-26.md`](../evidence/minimal-poc-architecture/2026-08-15-round-26.md) |

**Round 24 remains the reference for the pre-merge scope's own full §4.1–§4.4 matrix**
(HBAC/sudo allow+deny, the full log chain, backup+FIM, and the identity remove/restore/drift/
idempotency cycle) — round 25 did not re-run that matrix, since its own focus was the Plan B fix
and the merge's new sections. See
[`2026-08-14-round-24.md`](../evidence/minimal-poc-architecture/2026-08-14-round-24.md).

**Round 21 remains the historical reference for one narrower detail no later round has
re-exercised**: live proof that **netgroup** membership removal and restoration (as opposed to
ordinary group membership) actually take effect on a real FreeIPA server — see
[`2026-08-11-round-21.md`](../evidence/minimal-poc-architecture/2026-08-11-round-21.md).

Earlier rounds' records remain valid and are not repeated here — see the round links
at the top of this runbook.

The compact evidence record contains the current candidate provenance, result matrix, documented
exceptions, and raw-artifact pointers. Earlier runs remain available in their evidence records and
Git history and are intentionally not duplicated here.
