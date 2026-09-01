---
schemaVersion: 2
compatibility: {minPilotVersion: "0.9"}
intent:
  summary: SNMP monitoring cross-cutting integration (registry v2, Detection Engine subject generalization, Agent Controller generic subject, read-only diagnosis)
  source: docs/superpowers/specs/2026-09-01-snmp-monitoring-integration-spec.md §7-§10, §17.3 (C1-C15)
  maintainer: sre
targets:
  roles: [monitoring-registry, detection-engine, agent-controller]
  hostScope: aggregate
  platforms:
    - {os: ubuntu, versions: ["22.04", "24.04"]}
inputs: []
traceability: {components: []}
defaults:
  become: false
  timeout: 30s
  action: {mode: readOnly}
evidencePolicy: {captureStdout: true, retention: retain-all}
---

# Verification Spec — snmp-monitoring-integration

This spec does not belong to a single deployable component contract —
it verifies the cross-cutting invariants (spec §4 I1-I12) that hold
across `internal/monitoring`, `internal/detection`, and
`internal/agentcontroller` once the SNMP monitoring feature is wired
together. Row IDs and semantics here are exactly
`docs/superpowers/specs/2026-09-01-snmp-monitoring-integration-spec.md`
§17.2/§17.3's positive/negative lanes — do not renumber or reword them
independently of that spec.

**Status:** DRAFT — Phase 0 only records the intended checks. None of
these rows have actual-run or unit-test evidence yet; the Go schema
types they exercise (`SNMPProfile`, `SubjectKey`,
`DiagnoseMonitoringTargetInput`) exist only as unit-test-skeleton stubs
as of this revision (spec §15 Phase 0 exit gate).

## Checks

```yaml
- id: C1
  category: compatibility
  check: schema v1 direct-Prometheus workspace load/validate/compile golden output is byte-identical to pre-SNMP behavior
  probe: |
    go test ./internal/monitoring/... -run TestCompile -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C2
  category: schema
  check: schema v2 kind=snmp profile/target validate+compile produce the exact file_sd shape in spec §8.1
  probe: |
    go test ./internal/monitoring/... -run Golden -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C3
  category: secret-boundary
  check: strict known-fields decoding rejects a community/username/password/privPassword key anywhere in targets.yml or scrape-profiles.yml
  probe: |
    go test ./internal/monitoring/... -run RejectsSecretKey -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C4
  category: catalog
  check: an unknown module or auth profile reference fails validation
  probe: |
    go test ./internal/monitoring/... -run UnknownReference -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C5
  category: policy
  check: prod stage fails closed for any auth profile with version < 3 or securityLevel != authPriv, without an explicit reviewed break-glass exception
  probe: |
    go test ./internal/monitoring/... -run ProdRejectsV2c -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C6
  category: compile
  check: a target whose site does not match the local prometheus_site_label is excluded from the compiled scrape config
  probe: |
    go test ./internal/monitoring/... -run WrongSiteExcluded -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C7
  category: identity
  check: GroupSamplesByKey classifies SNMP samples under SubjectKey{Kind=network_device} and never assigns pilot_host
  probe: |
    go test ./internal/detection/... -run SubjectKey -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C8
  category: persistence
  check: SQLite migration backfills legacy pilot_host rows into subject_id/subject_kind/site and passes an integrity check inside one transaction
  probe: |
    go test ./internal/detection/... -run Migration -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C9
  category: correctness
  check: multiple unaggregated series for the same (subject, site, feature) in one cycle are classified ambiguous_series, never an arbitrarily picked winner
  probe: |
    go test ./internal/detection/... -run Ambiguous -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C10
  category: identity
  check: Agent Controller normalizes a pilot_target-labeled alert into an IncidentSubject with the subject's own kind and Managed=false, never Managed=true
  probe: |
    go test ./internal/agentcontroller/... -run NormalizeSubject -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C11
  category: repair-boundary
  check: a repair/autonomy request for a subject with Managed=false or Kind != managed_host is rejected before planning/execution
  probe: |
    go test ./internal/repair/... -run ExternalSubjectRejected -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C12
  category: diagnose
  check: pilot_diagnose_monitoring_target accepts only an exact target name (no regex/group/wildcard) and returns bounded structured evidence
  probe: |
    go test ./internal/diagnose/... -run MonitoringTarget -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C13
  category: envelope
  check: FakeDispatcher/HTTPDispatcher receive IncidentEnvelopeV2 with mutation_allowed/raw_command_allowed/workspace_write_allowed/external_subject_mutation_allowed all false
  probe: |
    go test ./internal/agentcontroller/... -run EnvelopeV2 -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C14
  category: model-safety
  check: a transport failure, malformed reply, or exhausted retry from the model provider preserves the local statistical anomaly result and never reports normal
  probe: |
    go test ./internal/detection/... -run ModelFailurePreservesLocal -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C15
  category: cardinality
  check: no per-ifIndex series becomes its own Detection Engine subject — device-level PromQL aggregation is enforced before a sample reaches GroupSamplesByKey
  probe: |
    go test ./internal/detection/... -run DeviceLevelAggregate -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
```

## PASS / FAIL

All C1-C15 rows must pass, plus the disposable-topology positive/negative
lanes in spec §17.2/§17.3, before the SNMP monitoring integration as a
whole reaches VERIFICATION_READY. This file alone never certifies
PRODUCTION_READY — see spec §17.4/§18 (AC23) for the real-device gate.

## Traceability

- C1-C6 exercise `internal/monitoring` (Phase 2 of the spec).
- C7-C9, C14-C15 exercise `internal/detection` (Phase 4/5).
- C10, C13 exercise `internal/agentcontroller` (Phase 3).
- C11 exercises `internal/repair`'s fail-closed guard (Phase 3, spec §10.6).
- C12 exercises `internal/diagnose` (Phase 3).

## Actual-run evidence

None yet. This file will be updated with real `go test` output and
disposable-topology run logs as each phase in
`docs/superpowers/specs/2026-09-01-snmp-monitoring-integration-spec.md`
§15 lands.

## Change record

| Date | Version | Change |
|---|---|---|
| 2026-09-01 | DRAFT | Phase 0 initial authoring per spec §17.2/§17.3's positive/negative lanes, reframed as C1-C15. No actual-run evidence yet. |
