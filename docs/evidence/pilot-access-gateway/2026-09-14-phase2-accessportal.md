# pilot-access-gateway Phase 2 — internal/accessportal evidence — 2026-09-14

- Spec: `docs/superpowers/specs/2026-09-14-pilot-access-gateway-stateless-freeipa-portal-spec.md` §13, §14, §15, §17, §21, §36, §38, §60 Phase 2
- Operator: Claude Code (kjelly, jellykao@linkervision.com)
- Target: same `ag-spike-ipa` vm-target as Phase 0/1 (reused)
- Package: `internal/accessportal` (`model.go`, `resolver.go`, `hbac.go`, `sudo.go`)

## The one finding that reshaped this phase's design

Spec §13/§14 assume Pilot must manually walk group/hostgroup membership
(`group_show`/`hostgroup_show` called recursively, with its own cycle
guard, dedupe, and stable sort — §35/§38 both describe this as
resolver-owned work, and §36's package layout even anticipates a
`graph.go`).

Live testing found this manual walk is unnecessary. FreeIPA's own
`memberof` plugin already computes the **full transitive closure
server-side** and exposes it as a second, separate attribute alongside the
direct one:

- `user_show(username, all=true)`: `memberof_group` (direct) +
  `memberofindirect_group` (every ancestor group, any depth) — confirmed
  with a real 3-level chain (`bob ∈ group-c ⊂ group-b ⊂ group-a`): a single
  `user_show(bob)` call returned `memberof_group: [ipausers, group-c]`,
  `memberofindirect_group: [group-b, group-a]`. No recursive `group_show`
  calls needed at all.
- `hostgroup_show(name, all=true)`: `member_host` (direct) +
  `memberindirect_host` (every host reachable through any depth of nested
  hostgroups) — confirmed with `hg-parent ⊂ hg-child`, `hg-child` holding
  the real host `leaf-host.ipa.pilot.internal`: a single
  `hostgroup_show(hg-parent)` call returned
  `memberindirect_host: [leaf-host.ipa.pilot.internal]`.

**The cycle case, tested deliberately and for real:** `ipa` does **not**
reject a group or hostgroup cycle. `hg-child` was nested under `hg-parent`
and then `hg-parent` was ALSO nested under `hg-child` (real, via
`ipa hostgroup-add-member`, not simulated); same for
`group-a ⊂ group-b ⊂ group-c ⊂ group-a`. FreeIPA's memberof plugin still
terminated and produced a correct answer — the only visible effect is that
a hostgroup/group ends up listed in its own `memberindirect_hostgroup`/
`memberindirect_group` (a self-reference), a field this package never
reads for the host/group *sets* it actually uses (`member_host`/
`memberindirect_host` for hosts, `memberof_group`/`memberofindirect_group`
for a user's effective groups — none of these ever contain a hostgroup/
group name where a host/user name is expected, so the self-reference is
inert for our purposes).

**Consequence:** `internal/accessportal` has no graph-walking code at all
— no `graph.go`, no cycle guard, no max-node limit for group/hostgroup
closures. `ResolveUserContext` and `ResolveGatewayScope` are each exactly
one `Provider` call plus a set union. This is simpler, faster (one RPC
instead of N), and inherits FreeIPA's own (already-correct, if
occasionally self-referential) cycle handling instead of reimplementing
it. §35's "max graph nodes" concern still has a place — as a sanity bound
on how large a single response is allowed to be — but not as a recursion
depth limit, since there is no recursion.

This finding required amending the already-committed Phase 1
(`internal/freeipaaccess`): `User` gained `IndirectGroups`
(`memberofindirect_group`) and `Hostgroup` gained `IndirectMemberHosts`
(`memberindirect_host`), both parsed from the *same* RPC call Phase 1
already made — no new RPC methods, no allowlist changes. New real fixtures
`user_show_nested.json` (bob) and `hostgroup_show_nested.json` (hg-parent,
captured *with* the live cycle in place) were added to
`internal/freeipaaccess/testdata/` and are covered by
`TestParseUserIndirectGroups` / `TestParseHostgroupIndirectMembersUnderCycle`.

## What else was implemented, and how it maps to §21's Query Plan

`Resolver.LoadUserAccess` (§19's top-level per-user, per-gateway result):

1. One `hostgroup_show` for `gateway.target_hostgroup` → `GatewayScope.Hosts`.
2. One `user_show` for the caller → `EffectiveGroups`.
3. One `hbacrule_find` + one `sudorule_find` (every enabled/disabled rule,
   spec.md §15/§17 — corrected to `all=true` only per the Phase 1 evidence
   doc, not `raw=true`).
4. One `hostgroup_show` per **distinct** hostgroup referenced by any rule
   (deduped across all rules) — not per host, matching §21's explicit
   goal ("每個 `GET /v1/access` 不可 N × hosts 查詢"). Same for
   `hbacsvcgroup_show` (distinct service groups referenced) and
   `sudocmdgroup_show` (distinct sudo command groups referenced).
5. Everything else — subject/host/service matching (§15.1-§15.3), sudo
   time-window and command aggregation (§17.1-§17.3), the §17.3 display-
   scope classification — is pure in-memory set logic (`hbac.go`/`sudo.go`),
   no further RPCs.

FQDN canonicalization (spec.md §14: "lowercase, trim trailing dot") is
applied at every point a host name enters a set or gets compared —
verified with a synthetic duplicate/case/trailing-dot variant of the same
real host collapsing to one canonical entry
(`TestResolveGatewayScope_NestedAndCycle`).

## §38 Resolver Test Matrix coverage

| Case | Covered by | Fixture/data source |
|---|---|---|
| direct group / nested group / multi-parent / duplicate / cycle | `TestResolveUserContext_NestedGroupsAndCycle` | real: bob/group-a/b/c |
| direct host / nested hostgroup / duplicate / cycle / trailing-dot canonicalization | `TestResolveGatewayScope_NestedAndCycle` | real: hg-parent/hg-child/leaf-host |
| HBAC: direct user, user group, usercategory all, direct host, hostgroup, hostcategory all, servicecategory all, direct sshd service, HBAC service group, disabled rule | `TestHBACRuleGrants_Matrix` | constructed (this package's own logic, not FreeIPA wire format — see file doc comment) |
| HBAC: nested user group | `TestLoadUserAccess_GPUScenario` (alice ∈ gpu-users, matched via `ViaGroups`) | real: alice/gpu-users/pilot-target-gpu/pilot-grant-login-gpu-test |
| HBAC: unmanaged host excluded | `TestLoadUserAccess_UnmanagedHostExcludedEvenWithHostCategoryAll` | constructed from the real scenario, widened to hostcategory=all to prove scope still wins |
| Sudo: no rule, direct user\*, group, direct host\*, hostgroup, cmdcategory all\*, specific command, command group, deny command, deny command group, notBefore future, notAfter expired, active window, disabled rule | `TestSudoRuleActive_TimeWindow`, `TestSudoDisplayScope`, `TestLoadUserAccess_GPUScenario` | real (gpu scenario + `sudonotbefore`/`sudonotafter`) + constructed for the time-window edge cases |

\* direct-user/direct-host/cmdcategory-all for sudo share the exact same
`subjectMatch`/`hostMatch` code as HBAC (already proven by
`TestHBACRuleGrants_Matrix`); not re-tested with different fixtures to
avoid redundant coverage of identical code paths.

## Verification run

```
go build ./internal/accessportal/...   → clean
go vet ./internal/accessportal/...     → clean
golangci-lint run ./internal/accessportal/... → clean
go test ./internal/accessportal/... -v → 28 passed
go test ./internal/freeipaaccess/...   → 19 passed (2 new: indirect-membership fields)
gofmt -l internal/accessportal/*.go internal/freeipaaccess/*.go → clean
```

## Known gaps carried forward

- `RunAsUsers`/`RunAsGroups`/deny-service (HBAC has no deny concept in
  modern FreeIPA, but a legacy `accessruletype` field exists) are not
  modeled — not exercised by any live capture yet.
- `internal/freeipaaccess.User`'s `memberofindirect_hbacrule`/
  `memberofindirect_sudorule` (also server-computed, seen in the original
  alice fixture) were deliberately NOT used as a shortcut for HBAC/sudo
  rule matching: they only cover group-membership-based rule references,
  not `usercategory=all` rules, and never carry host/service conditions,
  so the full `hbacrule_find`/`sudorule_find` + matching approach above is
  still required for correctness. Noted here so a future optimization
  attempt doesn't have to rediscover this.
- No live vm-target smoke test of the real `Resolver` wired to the real
  `freeipaaccess.Client` was run this phase (Phase 1's smoke test already
  proved the transport end-to-end; this phase is fixture/fake-provider-only
  per its landing gate). Worth doing once Phase 3's Gateway API exists, so
  there is a real end-to-end path to test against.
