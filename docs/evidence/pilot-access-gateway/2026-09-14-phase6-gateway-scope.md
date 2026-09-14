# pilot-access-gateway Phase 6 — gateway scope publication evidence — 2026-09-14

- Spec: `docs/superpowers/specs/2026-09-14-pilot-access-gateway-stateless-freeipa-portal-spec.md` §9.6, §57, §60 Phase 6
- Operator: Claude Code (kjelly, jellykao@linkervision.com)
- Target: same `ag-spike-ipa` vm-target (real FreeIPA server) as Phase 0-5
- Files: `playbooks/apply/gateway-scope-apply.yml`, `cmd/pilot/cmd/gateway_scope.go` (+ tests),
  `contracts/pilot-gateway-scope.yaml`, `docs/verification/pilot-gateway-scope.md`

## What was built and why it's shaped this way

`pilot gateway-scope plan/reconcile --scope <scope> --hosts <fqdn,...>`:
a thin CLI wrapper (`internal/ansible.Runner`, same pattern as
`pilot reconcile`) around a new, deliberately small playbook that ensures
FreeIPA hostgroup `pilot-target-<scope>` has **exactly** the desired host
membership — add missing, remove stale, idempotently.

This is **management-plane** tooling (spec.md §3.1: management plane may
use roster/inventory/vault/Ansible) — a completely separate codepath from
pilot-access-gateway's own runtime (`internal/freeipaaccess`/
`internal/accessportal`/`internal/gatewayapi`), which never reads
anything this playbook writes except by querying live FreeIPA itself.

**Deliberately its own playbook, not a new tag on
`freeipa-identity-apply.yml`**, even though that playbook already has a
generic, battle-tested `ipa_hostgroups` reconciler with the exact same
add/remove idempotency idiom (reused here, task-for-task pattern:
`hostgroup-add` → `hostgroup-show`+regex diff → `hostgroup-add-member`/
`hostgroup-remove-member`, including freeipa-identity's own documented
FQDN-vs-short-name normalization gotcha). Reason: gateway-scope
publication is a narrow, single-hostgroup concern with no users/HBAC/
sudo/nested-group scope, and spec.md §61 treats the FreeIPA identity/
roster system as pilot's pre-existing, separate thing this feature sits
alongside rather than grows to depend on.

## A real bug found live: `-e key=[...]` is not reliably a list

First live "plan" invocation passed
`-e gateway_scope_hosts=["test1-host.ipa.pilot.internal"]` and got:

```
"add": ["s", "", "i", "[", "-", "1", "l", "t", "n", "o", "e", "h", "p", "r", "\"", "]", "a"]
```

— Ansible received the value as a **plain string** and Jinja's
`difference()` iterated it character-by-character. Fix: pass the whole
thing as one JSON-object `-e` value instead —
`-e '{"gateway_scope_hosts": ["test1-host.ipa.pilot.internal"]}'` — which
parses correctly every time. `buildGatewayScopeArgs` (the CLI's argv
builder) always uses this form; `TestBuildGatewayScopeArgsPlan` pins it
so this can't regress silently. Consistent with an existing repo-wide
gotcha (`pilot-ansible-extra-vars-space-splitting-gotcha`) about `-e`
values needing careful quoting — this is the list-shaped variant of the
same underlying issue.

## Real, live vm-target verification (not just unit tests)

Against the real FreeIPA server, using a throwaway `test1` scope (cleaned
up afterward — `pilot-target-gpu` with the real `gpu-a`/`gpu-b` fixture
hosts from Phase 0-5 was left untouched throughout):

1. **plan on a scope that doesn't exist yet** → `add: [test1-host],
   hostgroup_exists: false, remove: [], keep: []`; write tasks correctly
   skipped (`gateway_scope_plan_only=true`).
2. **reconcile** → hostgroup created, host added (`changed=2`).
3. **reconcile again, no change** → `changed=0` (idempotent).
4. **reconcile with a different desired host** (`test2-host` instead of
   `test1-host`) → `add: [test2-host], remove: [test1-host], keep: []`;
   both the add and the removal actually applied (`changed=2`),
   `ipa hostgroup-show` confirmed only `test2-host` remained a member.
5. **reconcile again** → `changed=0` (idempotent after removal too).
6. Same 5 steps repeated through the actual `pilot gateway-scope plan/
   reconcile` CLI (not just `vm-target run` directly on the playbook) —
   identical results, confirming the CLI wrapper's argv construction is
   correct end-to-end.
7. Final sanity check against the **real** `gpu` scope (the one Phase
   0-5's fixtures actually use): `plan` correctly reports
   `keep: [gpu-a, gpu-b], add: [], remove: []` — already in the desired
   state, nothing to do.

## An unplanned but necessary detour: repo-wide governance integration

Adding one new file under `playbooks/apply/*-apply.yml` triggered six
separate hardcoded-expectation test failures across the repo — this
repo enforces, mechanically, that **every** apply playbook has a
component contract, a mapped verification spec with tag-aligned rows,
a `deployCatalog` entry, and (per `AGENTS.md` §4.3) a staging/prod
confirm gate with an inventory-group cross-check. None of this was
optional or skippable via a naming trick (deliberately not attempted —
see below). Delivered to satisfy it:

- `contracts/pilot-gateway-scope.yaml` (new, minimal — modeled on
  `freeipa-realm-replacement`'s contract, the closest existing precedent
  for "one-shot management action against the FreeIPA server", not a
  persistent service).
- `docs/verification/pilot-gateway-scope.md` (new, 3 rows — C1 hostgroup
  exists, C2/C3 the two real fixture hosts are members — documenting the
  real `gpu` scenario from the live run above, not the throwaway `test1`
  scope used to prove add/remove).
- `cmd/pilot/cmd/tag_coverage_test.go`'s `specTagMap`, `deploy_catalog.go`
  (new day-2/opt-in entry, `Reconcile: true`), and
  `edit_role_catalog_coverage_test.go`'s exemption list (this is not a
  per-host role — same reasoning already used for `freeipa-identity`/
  `freeipa-realm-replacement`).
- `gateway-scope-apply.yml` gained the same `stage`/`confirm_staging`/
  `confirm_prod` + inventory-group cross-check `pre_tasks` every other
  apply playbook has (copied from `freeipa-realm-replacement-apply.yml`'s
  pattern) — genuinely warranted here too, since this playbook can add or
  remove hosts from a hostgroup that gates real SSH/sudo access.
- Half a dozen hardcoded counts (`34`→`35` playbooks, `35`→`36`
  contracts, two exact-match ID list literals) across
  `internal/contract/*_test.go` and `cmd/pilot/cmd/*_test.go`, plus an
  `AGENTS.md` §4.3 changelog entry — all things this repo's own tests
  catch automatically the moment they drift, which is exactly what
  happened and is why this section exists.

**A path considered and rejected:** the two governance checks both key
off the literal glob `playbooks/apply/*-apply.yml`
(`internal/contract/lint.go`, `cmd/pilot/cmd/tag_coverage_test.go`) —
naming the file something else (e.g. `gateway-scope.yml`, no `-apply`
suffix) would have silently exempted it from all of this. Rejected: the
naming convention exists specifically to guarantee every state-mutating
playbook has a traceable verification story, and this one really does
mutate FreeIPA state with real access-control consequences — dodging the
convention via a filename would be exactly the kind of workaround that
defeats its purpose.

## Verification run

```
ansible-playbook playbooks/apply/gateway-scope-apply.yml --syntax-check → clean
ansible-lint playbooks/apply/gateway-scope-apply.yml                    → 0 failures, 0 warnings (production profile)
go build ./...                                                          → clean
go test ./...                                                           → clean (whole repo, including all newly
                                                                            touched governance tests)
```
