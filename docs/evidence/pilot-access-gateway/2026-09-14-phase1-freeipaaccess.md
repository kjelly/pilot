# pilot-access-gateway Phase 1 — internal/freeipaaccess evidence — 2026-09-14

- Spec: `docs/tmp/now/spec.md` §11-§21, §36, §37, §60 Phase 1
- Operator: Claude Code (kjelly, jellykao@linkervision.com)
- Target: same `ag-spike-ipa` vm-target as Phase 0 (reused, not rebuilt)
- Package: `internal/freeipaaccess` (`provider.go`, `jsonrpc.go`, `kerberos.go`,
  `normalize.go`, `testdata/`)

## What was built

A `Provider` interface with one Go method per FreeIPA JSON-RPC read operation
listed in spec §10.3 (ping, user_show, group_show, host_show, hostgroup_show,
hbacrule_find, hbacrule_show is folded into find-then-index, hbacsvcgroup_show,
sudorule_find, sudocmd_show, sudocmdgroup_show, hbactest), plus a `Client`
implementing it with the Phase-0-validated Go SPNEGO transport
(`github.com/jcmturner/gokrb5/v8`).

## Deviations from the written spec, each backed by live evidence

1. **Provider shape (§11).** Spec sketched `Ping/LoadUserContext/
   LoadAccessSnapshot/CheckSSH` — already-resolved, closure-expanded data.
   Implemented instead: one primitive method per raw RPC call, returning
   normalized-but-unresolved structs (`User.DirectGroups` is direct
   membership only, no closure walk). Reason: spec's own §36 package layout
   puts group/hostgroup closure walking and HBAC/sudo intersection in
   `internal/accessportal` (Phase 2), not `internal/freeipaaccess`. Building
   the composite interface here would either duplicate that logic in the
   wrong package or make this package depend on Phase-2 concepts it
   shouldn't need to unit test. `internal/accessportal`'s Phase 2 resolver
   will compose these primitives into the higher-level `UserContext`/
   `Snapshot`/`Decision` types spec §11/§19 describes.

2. **raw=true → non-raw (§15/§17).** Spec required `hbacrule_find(all=true,
   raw=true)` / `sudorule_find(all=true, raw=true)`. A live side-by-side
   capture (both forms, same objects) found raw=true returns member
   attributes as full LDAP DNs (`cn=gpu-users,cn=groups,cn=accounts,...`),
   requiring a DN-container classifier to split each into
   user/group/host/hostgroup/service/service-group — and, worse, sudo
   command references resolve only to an opaque `ipaUniqueID`, not the
   actual command text. Non-raw (`all=true` only) instead returns
   pre-classified, pre-resolved attributes: `memberuser_user`,
   `memberuser_group`, `memberhost_host`, `memberhost_hostgroup`,
   `memberservice_hbacsvc`, `memberservice_hbacsvcgroup`,
   `memberallowcmd_sudocmd` (actual command text),
   `memberallowcmd_sudocmdgroup`, `memberdenycmd_sudocmd`,
   `memberdenycmd_sudocmdgroup`. This eliminates an entire class of DN-
   parsing bugs and is what `internal/freeipaaccess` uses exclusively. See
   fixtures for the exact shapes; a discarded `*_nonraw.json` side-by-side
   capture (not committed) is what surfaced this before it became a
   production bug.

3. **A real API inconsistency, not a bug in this code.** Boolean-shaped
   attributes come back as either a bare JSON scalar (`nsaccountlock:
   false` on `user_show`) or a single-element array (`ipaenabledflag:
   [true]` on `hbacrule_show`/`sudorule_show`) — same conceptual shape,
   different wire encoding depending on the object type. `attrBool`/
   `attrStrings` in `normalize.go` accept both forms uniformly; this was
   only caught because real fixtures were captured for both object kinds
   instead of assuming one shape from spec prose.

4. **FreeIPA ships a default enabled `allow_all` HBAC rule.** A fresh
   `ipa-server-install` (used to build the Phase 0 vm-target) includes an
   enabled `allow_all` HBAC rule (usercategory/hostcategory/servicecategory
   all = "all") that grants every user access to every host/service. The
   first `hbactest` capture showed "Access granted: True" for a
   deliberately-should-be-denied probe (service=ftp) purely because of this
   rule — not because the resolver logic was wrong. Disabled it
   (`ipa hbacrule-disable allow_all`) before recapturing so
   `hbactest_deny.json` is a real negative case. **This matters beyond
   fixture hygiene**: any real deployment's HBAC-correctness verification
   (spec §52 AG14) will trivially "pass" against a fresh FreeIPA install
   with `allow_all` still enabled, regardless of whether the gateway's own
   HBAC∩scope logic is correct. Phase 7/8 delivery playbooks and AG14's
   verification must check `allow_all` is disabled (or explicitly account
   for it), not just that `pilot-target-<scope>` rules exist.

## Fixtures (real captures, `internal/freeipaaccess/testdata/`)

`ping`, `user_show`, `group_show`, `host_show`, `hostgroup_show`,
`hbacrule_find`, `hbacrule_show`, `hbacsvcgroup_show`, `sudorule_find`,
`sudorule_show`, `sudocmd_show`, `sudocmdgroup_show`, `hbactest_allow`,
`hbactest_deny`, `rpc_error` — all captured by a throwaway Go tool (not
committed) run from the vm-target against the live server, using the same
`pilot-access-gateway/ipa1.ipa.pilot.internal` reader principal from Phase 0.
Backing FreeIPA objects: user `alice` (member of group `gpu-users`),
hostgroup `pilot-target-gpu` (hosts `gpu-a`/`gpu-b`), HBAC rule
`pilot-grant-login-gpu-test` (group→hostgroup→sshd), sudo rule
`pilot-grant-sudo-gpu-test` (group→hostgroup, allow command + allow command
group `test-sudocmdgroup` + deny command, `sudoNotBefore`/`sudoNotAfter` set
to a real 2026–2027 window), HBAC service group `test-svc-group`.

## Verification run (fixture-only, per Phase 1 landing gate — no live IPA required)

```
go test ./internal/freeipaaccess/...   → 17 passed
go vet ./internal/freeipaaccess/...    → clean
golangci-lint run ./internal/freeipaaccess/... → clean
gofmt -l internal/freeipaaccess/*.go   → clean
```

## Additional live verification performed (not required by the landing gate, done anyway)

A throwaway `manual_smoke_test.go` (build-tagged `manual`, deleted before
commit — not part of the repo) cross-compiled and run on the vm-target
against the real `Client`, confirming:

- Session establishment failing over past a deliberately unreachable first
  server (`unreachable.invalid.example`) to the real one.
- `Ping`, `UserShow`, `HostgroupShow`, `HBACRuleFind`, `SudoRuleFind`,
  `HBACTest` all return correctly parsed live data.
- A nonexistent user (`UserShow`) correctly surfaces as `*RPCError{Name:
  "NotFound"}` — the allowlist and error-typing work end-to-end, not just
  against static fixtures.

## Known gaps carried forward (not fixture-backed yet, do not assume they work)

- `SudoRule.RunAsUsers/RunAsGroups/Options` from spec §17 are not
  implemented — no real fixture was captured for `ipasudorunas*`
  attributes. Add when a phase actually needs them.
- No nested-group / cycle / multi-parent fixtures yet (spec §38's resolver
  test matrix needs these) — `gpu-users` has no nested group members in
  this environment. These belong to Phase 2 (`internal/accessportal`) and
  will be captured against the same reused vm-target when that phase
  starts.
- Failover was exercised only for "can't establish a session at all"
  (first server entirely unreachable). Mid-session failover (a server that
  was working, then drops mid-call) is not covered by any test yet.
