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

**Status: DRAFT — Phase 3 live evidence landed 2026-09-03.** Phase 1 makes
HD1, HD3, HD4, HD6, HD7, HD8, HD15, HD16, HD17, HD26, HD27, HD28
executable (planner is read-only, no live provider needed). Phase 2 makes
HD2, HD5, HD18-HD22, HD24 executable (finalizer + TUI refactor, still no
live provider required to *unit*-test the boundary). Phase 3 wired the
FreeIPA client provider into the CLI (`cmd/pilot/cmd/host_decommission.go`
— Phase 3a had left this unwired) and, per spec.md §35.1, ran a real
disposable 2-VM `pilot vm-target` topology (`hd-ipa1` freeipa-server +
`hd-client1` freeipa-client) through the full plan → apply → verify (×2,
independent passes) → idempotent-replay → stale-plan → partial-failure/
resume → HD12-service-principal-block cycle. **HD9-HD12's real-host
counterpart now exists as `HD9-LIVE`-`HD12-LIVE` below** (`scope:
per-host`, real `ipa`/ssh probes, not `go test` fixture probes); the
five real bugs that live run found and fixed (a bad FQDN-derivation
precedence, an Apply/Finalize freshness-check interaction, ansible
stdout/stderr conflation, two independently-wrong assumptions about real
FreeIPA CLI output shape, and an `ansible.builtin.debug` message-escaping
issue that silently defeated every anchored regex this feature reads)
are recorded in `docs/evidence/host-decommission/2026-09-03-3b4ef4d.md` —
read that note before treating HD9-HD12 (the fixture-only rows above) as
having ever been "verified against a real FreeIPA server" on their own;
they were not, until HD9-LIVE-HD12-LIVE existed. Phase 4 still needs
disposable-target evidence for HD13/HD14 (internal-endpoint/Wazuh,
explicitly out of scope for this round). HD23 and HD25 are pure static/
registry checks and are executable as soon as the relevant code exists,
with no live host.

**Scope split.** Every HD1-HD28 row above is `scope: aggregate`: it runs Go
tests against `internal/decommission` fixture workspaces (synthetic
`hosts.yml`/roster/manifest trees under `t.TempDir()`), never against a
live host, because the planner itself must never touch a live system
(spec.md §10.1) and HD1-HD28 as written are observable *saga/store/CLI*
behavior, not per-host effective state. That intentionally did **not**
satisfy spec.md §35's disposable-target requirement for HD9-HD12 on its
own — "PASS" on HD9-HD12 above means "the Go-level provider contract and
blocker logic behave correctly against fixtures", not "verified against a
real FreeIPA server"; do not read it as the latter. `HD9-LIVE`-`HD12-LIVE`
(scope: per-host, appended below) are that promised second, host-scoped
verification pass for FreeIPA — landed 2026-09-03 against a real 2-VM
`pilot vm-target` topology (see
`docs/evidence/host-decommission/2026-09-03-3b4ef4d.md`). HD13/HD14's
own live-host pass (internal-endpoint/Wazuh) remains Phase 4's job, not
done here.

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

# ── Phase 3 live disposable-target evidence (HD9-HD12's real-host pass) ──
#
# The four rows below are HD9-HD12's promised second, host-scoped
# verification pass (spec.md §35.1/§36), run 2026-09-03 against a real
# 2-VM `pilot vm-target` topology (`hd-ipa1` freeipa-server + `hd-client1`
# freeipa-client, almalinux-9 + ubuntu-24.04) — see
# docs/evidence/host-decommission/2026-09-03-3b4ef4d.md for the full
# session log, tested revision, and the five real bugs this pass found and
# fixed. Unlike HD1-HD28 above, these are `scope: per-host` real shell/
# `ipa`/direct-SSH probes (mirroring docs/verification/internal-endpoint.md's
# per-host rows), not `go test` fixture probes — "PASS" here means
# "independently confirmed against a live FreeIPA server", not "the Go
# contract behaves correctly against a synthetic fixture". The exact
# `ipa`/host commands shown were actually executed against that disposable
# topology this session (torn down afterward, per AGENTS.md's evidence
# conventions) — reproduce with your own equivalently-named `vm-target`
# pair (server-side `kinit admin` via the roster's own admin credential
# first).
- id: HD9-LIVE
  category: freeipa-client
  check: a reachable, enrolled host's FreeIPA client local enrollment is actually removed by `pilot host decommission apply` against a real FreeIPA server
  probe: |
    ssh -i <client-key> ubuntu@<client-ip> 'test -f /etc/ipa/default.conf && echo ENROLLED || echo UNINSTALLED'
  expect: {stdout: {equals: "UNINSTALLED"}}
  scope: per-host
  verifyOnly: true
- id: HD10-LIVE
  category: freeipa-client
  check: the FreeIPA host object and Pilot-owned DNS A record are actually absent on the real server after `pilot host decommission apply`, confirmed on an independent second pass
  probe: |
    ssh -i <server-key> root@<server-ip> \
      "kinit admin <<< '<admin-password>' >/dev/null 2>&1; ipa host-show <client-fqdn> 2>&1; ipa dnsrecord-show <domain> <client-short-name> 2>&1"
  expect: {stdout: {contains: "host not found"}}
  scope: per-host
  action:
    mode: isolatedMutation
    authorization: explicit
    residualRisk: a Kerberos ticket for admin remains cached in the shell's default credential cache until it expires or is destroyed
    cleanup:
      required: true
      probe: |
        ssh -i <server-key> root@<server-ip> kdestroy
      expect: {exitCode: 0}
  verifyOnly: true
- id: HD11-LIVE
  category: freeipa-client
  check: the host's direct hostgroup/netgroup membership is actually pruned on the real server (the containing hostgroup/netgroup object itself survives; only the host's membership is gone)
  probe: |
    ssh -i <server-key> root@<server-ip> \
      "kinit admin <<< '<admin-password>' >/dev/null 2>&1; ipa hostgroup-show <hostgroup-name>"
  expect: {stdout: {notContains: "Member hosts:"}}
  scope: per-host
  action:
    mode: isolatedMutation
    authorization: explicit
    residualRisk: a Kerberos ticket for admin remains cached in the shell's default credential cache until it expires or is destroyed
    cleanup:
      required: true
      probe: |
        ssh -i <server-key> root@<server-ip> kdestroy
      expect: {exitCode: 0}
  verifyOnly: true
- id: HD12-LIVE
  category: freeipa-client
  check: an unknown/unproven service principal on the target host actually hard-blocks `pilot host decommission plan` against a real FreeIPA server, without cascade-deleting the service or the host object
  probe: |
    ssh -i <server-key> root@<server-ip> "kinit admin <<< '<admin-password>' >/dev/null 2>&1; ipa service-add HTTP/<client-fqdn> --force"
    go run ./cmd/pilot host decommission plan --dir "<workspace>" --host "<client-fqdn>"
  expect: {stdout: {contains: "ownership_unknown"}}
  scope: per-host
  action:
    mode: isolatedMutation
    authorization: explicit
    residualRisk: a lingering HTTP/<client-fqdn> service principal object on the FreeIPA server if cleanup fails
    cleanup:
      required: true
      probe: |
        ssh -i <server-key> root@<server-ip> "kinit admin <<< '<admin-password>' >/dev/null 2>&1; ipa service-del HTTP/<client-fqdn>"
      expect: {exitCode: 0}
  verifyOnly: true
```
