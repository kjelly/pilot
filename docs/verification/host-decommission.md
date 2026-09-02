---
schemaVersion: 2
compatibility: {minPilotVersion: "0.9"}
intent:
  summary: host decommission lifecycle — resumable saga, zero-active-residue verification, hard host-delete safety boundary
  source: docs/superpowers/specs/2026-09-02-host-decommission-spec.md §3, §6, §32 (HD1-HD28)
  maintainer: sre
targets:
  roles: [freeipa-client]
  hostScope: aggregate
  platforms:
    - {os: almalinux, versions: ["9"]}
inputs: []
traceability: {components: []}
defaults:
  become: false
  timeout: 30s
  action: {mode: readOnly}
evidencePolicy: {captureStdout: true, retention: retain-all}
---

# Verification Spec — host-decommission

This is the Phase 0 acceptance contract for
`docs/superpowers/specs/2026-09-02-host-decommission-spec.md`: a
resumable host decommission lifecycle that replaces the current unsafe
"delete a host, hope nothing pointed at it" TUI action (§1-§2 of that
spec) with a plan → approve → clean → verify → finalize saga (§6 hard
safety invariants INV-1..INV-15). Row IDs and semantics here are exactly
that spec's §32 HD1-HD28 acceptance rows — do not renumber or reword
them independently of that spec; if a row's intended behavior turns out
to be wrong once real code/hosts exist, fix the spec and this file
together with a stated reason (AGENTS.md §0.2 responsibility split), not
just this file alone.

**Status: DRAFT — Phase 0 only.** No mutation implementation exists yet
(spec.md §37 Phase 0 explicitly forbids it). None of the Go test names
referenced by the probes below exist yet either; every row is a real,
intended acceptance check, not a placeholder, and every row is currently
`FAIL` (test not found) by construction. Phase 1 makes HD1, HD3, HD4,
HD6, HD7, HD8, HD15, HD16, HD17, HD26, HD27, HD28 executable (planner is
read-only, no live provider needed). Phase 2 makes HD2, HD5, HD18-HD22,
HD24 executable (finalizer + TUI refactor, still no live provider
required to *unit*-test the boundary). Phase 3 is the first phase that
requires disposable-target evidence per spec.md §35.1 for HD9-HD12;
Phase 4 requires it for HD13/HD14. HD23 and HD25 are pure static/registry
checks and are executable as soon as the relevant code exists, with no
live host.

**Scope split.** Every row below is `scope: aggregate`: it runs Go tests
against `internal/decommission` fixture workspaces (synthetic
`hosts.yml`/roster/manifest trees under `t.TempDir()`), never against a
live host, because the planner itself must never touch a live system
(spec.md §10.1) and HD1-HD28 as written are observable *saga/store/CLI*
behavior, not per-host effective state. This intentionally does **not**
yet satisfy spec.md §35's disposable-target requirement for HD9-HD14/
HD16/HD17/HD19 — those rows get a *second*, host-scoped verification
pass (new row IDs, e.g. `HD9-LIVE`) appended to this file once Phase 3/4
lands real FreeIPA/Wazuh disposable-target evidence (spec.md §36); until
then, "PASS" on HD9-HD14 here means "the Go-level provider contract and
blocker logic behave correctly against fixtures", not "verified against
a real FreeIPA server" — do not read it as the latter.

**Why `go test -run` probes instead of shell/ansible probes.** This
feature's primary observable surface is a Go CLI + SQLite saga store +
TUI, not a system service — the same shape as
`docs/verification/snmp-monitoring-integration.md`. Each probe below
runs one narrowly-scoped Go test and asserts its own `PASS`; the real
assertions live in the Go test bodies (table-driven per spec.md §33),
not in this file's `expect` matcher. This spec intentionally does not
re-derive detailed FreeIPA/Wazuh/internal-endpoint per-host baselines
that `docs/verification/freeipa-client.md`,
`docs/verification/internal-endpoint.md` already own — it only verifies
that decommission *reuses* those paths safely.

## Checks

```yaml
- id: HD1
  category: planner
  check: plan is read-only and leaves workspace/live state unchanged
  probe: |
    go test ./internal/decommission/... -run TestPlanner_PlanIsReadOnly -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD2
  category: tui
  check: TUI no longer directly removes a host from hosts.yml — the delete action enters the decommission planner instead
  probe: |
    go test ./cmd/pilot/cmd/... -run TestEditTUI_HostDelete_EntersDecommissionFlow -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD3
  category: planner
  check: plan contains a deterministic hash and a persisted host snapshot
  probe: |
    go test ./internal/decommission/... -run TestPlanner_PlanHashDeterministicAndSnapshotPersisted -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD4
  category: freshness
  check: stale workspace/contract/reference state invalidates apply
  probe: |
    go test ./internal/decommission/... -run TestFreshness_StaleInputInvalidatesApply -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD5
  category: approval
  check: human approval is required in sandbox/staging/prod, with no autonomous exception
  probe: |
    go test ./internal/decommission/... -run TestApply_RequiresHumanApprovalAllEnvironments -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD6
  category: references
  check: reverse references are discovered and classified (AUTO_REMOVE/REQUIRES_REPLACEMENT/INFORMATIONAL/FOREIGN_UNKNOWN/HARD_BLOCKER) before any mutation
  probe: |
    go test ./internal/decommission/... -run TestReferences_DiscoveredAndClassifiedBeforeMutation -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD7
  category: planner
  check: a selected component with external state and no supported decommission lifecycle blocks planning
  probe: |
    go test ./internal/decommission/... -run TestPlanner_UnsupportedExternalStateBlocks -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD8
  category: dependency
  check: component teardown follows reverse dependency order (consumers before providers); a dependency cycle fails closed
  probe: |
    go test ./internal/decommission/... -run TestDependency_ReverseOrderTeardown -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD9
  category: freeipa-client
  check: a reachable, enrolled host's FreeIPA client local enrollment is planned for removal via the established uninstall mechanism
  probe: |
    go test ./internal/decommission/... -run TestFreeIPAProvider_ClientEnrollmentRemoved -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD10
  category: freeipa-client
  check: FreeIPA host object and Pilot-owned DNS record(s) are planned absent after cleanup, using exact-value/surgical deletion (never a broad DNS cascade)
  probe: |
    go test ./internal/decommission/... -run TestFreeIPAProvider_HostObjectAndDNSAbsent -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD11
  category: freeipa-client
  check: FreeIPA hostgroup/HBAC/sudo/netgroup direct references to the host are pruned
  probe: |
    go test ./internal/decommission/... -run TestFreeIPAProvider_DirectReferencesAbsent -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD12
  category: freeipa-client
  check: an unknown/unproven FreeIPA service principal blocks unsafe host deletion instead of being cascade-deleted
  probe: |
    go test ./internal/decommission/... -run TestFreeIPAProvider_UnknownServicePrincipalBlocks -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD13
  category: internal-endpoint
  check: an internal endpoint referencing the target host as backend is removed/repointed via the existing ledger-aware delete path, or blocks decommission if neither disposition is selected
  probe: |
    go test ./internal/decommission/... -run TestInternalEndpointProvider_RemovedOrRepointedOrBlocks -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD14
  category: wazuh
  check: Wazuh manager-side agent registration is removed by stable recorded identity only, never by hostname substring
  probe: |
    go test ./internal/decommission/... -run TestWazuhProvider_RemovedByStableIdentity -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD15
  category: retention
  check: a stateful component with retention=required blocks planning until an explicit retention disposition is supplied
  probe: |
    go test ./internal/decommission/... -run TestPlanner_StatefulRetentionRequired -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD16
  category: unreachable
  check: a temporarily-unreachable host blocks any component step that requires local cleanup
  probe: |
    go test ./internal/decommission/... -run TestUnreachable_TemporaryBlocksLocalCleanup -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD17
  category: unreachable
  check: a permanently-lost host records local cleanup as local_cleanup_unavailable_attested, never a fake verified_removed
  probe: |
    go test ./internal/decommission/... -run TestUnreachable_PermanentlyLostRecordsUnattested -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD18
  category: resume
  check: a failed step can resume without replaying already-completed destructive work
  probe: |
    go test ./internal/decommission/... -run TestExecutor_ResumeDoesNotReplayCompletedDestructiveStep -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD19
  category: verification
  check: independent zero-residue verification (re-querying live effective state, not just task exit codes) gates finalization
  probe: |
    go test ./internal/decommission/... -run TestVerifier_IndependentZeroResidueGatesFinalization -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD20
  category: finalizer
  check: the target host remains present in hosts.yml until HD19's verification passes
  probe: |
    go test ./internal/decommission/... -run TestFinalizer_HostRemainsUntilVerificationPasses -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD21
  category: finalizer
  check: finalization regenerates inventory.yml via internal/inventory.Generate and validates it
  probe: |
    go test ./internal/decommission/... -run TestFinalizer_RegeneratesAndValidatesInventory -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD22
  category: audit
  check: historical Pilot delivery evidence and Agent Controller records remain available after retirement (not purged)
  probe: |
    go test ./internal/decommission/... -run TestFinalizer_HistoricalEvidenceRetained -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD23
  category: safety
  check: the generic decommission workflow returns a hard blocker for a host with role freeipa-server or freeipa-server-replica, with no bypass flag
  probe: |
    go test ./internal/decommission/... -run TestPlanner_RejectsFreeIPAServerAndReplica -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD24
  category: idempotency
  check: a completed decommission is replay-safe — a repeated apply/finalize request returns already_completed plus the original receipt, and recreates nothing
  probe: |
    go test ./internal/decommission/... -run TestFinalizer_CompletedDecommissionReplaySafe -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD25
  category: safety
  check: no Agent/MCP tool exposes host decommission mutation (plan/apply/resume) in v1
  probe: |
    go test ./cmd/pilot/... -run TestMCP_NoAutonomousDecommissionMutationPath -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD26
  category: secrets
  check: no secret values appear in plan JSON, step JSON, error text, receipts, or approval records
  probe: |
    go test ./internal/decommission/... -run TestStore_NoSecretValuesInPersistedRecords -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD27
  category: approval
  check: plan/apply approval is bound to the exact plan_hash; a changed plan invalidates any prior approval
  probe: |
    go test ./internal/decommission/... -run TestApproval_BoundToExactPlanHash -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: HD28
  category: ownership
  check: foreign/unknown-ownership resources are never automatically deleted and are reported, not silently dropped
  probe: |
    go test ./internal/decommission/... -run TestOwnership_ForeignUnknownNeverAutoDeleted -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
```
