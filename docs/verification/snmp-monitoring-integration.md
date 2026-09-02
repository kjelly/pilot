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
    go test ./internal/detection/... -run DuplicateSeriesIsInvalid -v
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
    go test ./cmd/pilot-agent-controller/... -run RequireManagedIncidentSubject -v
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
- C7-C9 exercise `internal/detection`'s subject/migration generalization (Phase 4). C15 exercises the real `network-device-ifmib-v1` profile's cardinality policy (Phase 5). C14 exercises the model-provider fallback lane (Phase 6, not yet implemented).
- C10, C13 exercise `internal/agentcontroller` (Phase 3).
- C11 exercises the fail-closed guard at `cmd/pilot-agent-controller`'s
  `remediation propose`/`reapply-propose` choke point, the only place a
  repair plan is built from an incident_id (Phase 3, spec §10.6).
- C12 exercises `internal/diagnose` (Phase 3).

## Actual-run evidence

**C1, C2, C6 (Phase 2 — registry v2 schema/compile/site-filtering): DONE.**
See `docs/runbooks/snmp-monitoring-registry.md` for the full disposable
two-VM run: real `go test ./internal/monitoring/...` golden coverage (v1
unchanged, new v2 SNMP golden), plus a real Prometheus + snmp-exporter +
lab SNMPv3 device chain — `promtool check config` PASS,
`up{pilot_protocol="snmp"}=1`, and a wrong-site target confirmed absent
from both the compiled file_sd JSON and Prometheus's live target list.

**C3, C4, C5 (Phase 2 — secret-key rejection / unknown module-auth /
prod version-policy): DONE** via `internal/monitoring`'s own unit tests
(`TestLoadTargets_RejectsSecretKey`, `TestLoadProfiles_RejectsSecretKey`,
`TestValidate_SNMPProfile_UnknownModule`,
`TestValidate_SNMPProfile_UnknownAuthProfile`) — no disposable-topology
run needed, these are pure schema/validate rules.

**C10-C13 (Phase 3 — Agent Controller generic subject, repair
fail-closed guard, read-only diagnose, IncidentEnvelopeV2): DONE.** See
`docs/runbooks/agent-monitoring-snmp-subject.md` — full unit/integration
test evidence for subject normalization precedence, SQLite schemaV5
migration+backfill, the `requireManagedIncidentSubject` repair-boundary
guard, `pilot_diagnose_monitoring_target`'s bounded structured output,
and `IncidentEnvelopeV2` dispatch. That runbook also discloses a scope
trade-off: no fresh disposable-VM run re-proves a full live
Prometheus→Alertmanager→controller chain specifically for an
SNMP-sourced alert in one continuous pass — Phase 1's runbook already
proved the Alertmanager→controller webhook chain, Phase 2's runbook
already proved `SNMPTargetDown` fires for real, and this phase's own
tests prove subject normalization handles that exact alert shape
correctly.

**C7-C9 (Phase 4 — Detection Engine subject/migration generalization):
DONE.** See `docs/runbooks/detection-engine-subject-generalization.md` —
`GroupSamplesByKey` now takes a profile `IdentityProfile` and classifies
SNMP-shaped samples under `SubjectKey{Kind=network_device}` without ever
touching `pilot_host` (C7); a real schemaV2 SQLite migration backfills
legacy `pilot_host` rows into `subject_id`/`subject_kind`/`site` across
BOTH `signal_episodes` and `baseline_samples`, verified via
`PRAGMA integrity_check` (C8); the pre-existing ambiguous-series
classification (unchanged by Phase 4) is re-confirmed still passing, and
C9's probe corrected to the test's real name (C9). C10-C13 remain the
Phase 3 rows (Agent Controller); see
`docs/runbooks/agent-monitoring-snmp-subject.md`.

**C15 (Phase 5 — `network-device-ifmib-v1` cardinality policy): DONE.**
See `docs/runbooks/snmp-adaptive-detection.md` — the real feature profile
(`monitoring/detection/feature-profiles/network-device-ifmib-v1.yaml`)
groups every feature's PromQL by `pilot_target` and never `ifIndex`, and a
real 3-VM disposable-topology run confirmed the Detection Engine's live
Thanos chain actually discovers `pilot_target` (a real snmpd → real
snmp-exporter → real Prometheus → real Thanos Query chain), producing a
`subject_kind=network_device` row with `pilot_host` empty — matching
Phase 4's design. Fixture tests (not a real-device fault) additionally
prove a warm-up + spike sequence produces a correctly-labeled SignalEvent,
and the four normal/stale/missing/ambiguous negative lanes pass using the
profile's own 90s/5s sampling override. One real bug was found+fixed in
the profile's PromQL (an ambiguous `group_left` clause) via a live Thanos
Query 400 response.

**C14 (Phase 6 — model-provider fallback lane): not yet implemented.**
This file stays DRAFT until that phase lands.

## Change record

| Date | Version | Change |
|---|---|---|
| 2026-09-01 | DRAFT | Phase 0 initial authoring per spec §17.2/§17.3's positive/negative lanes, reframed as C1-C15. No actual-run evidence yet. |
| 2026-09-02 | DRAFT | Phase 2 evidence added for C1-C6 (registry v2 schema/validate/compile) — see `docs/runbooks/snmp-monitoring-registry.md`. C7-C15 remain unimplemented; still DRAFT overall. |
| 2026-09-02 | DRAFT | Phase 3 evidence added for C10-C13 (Agent Controller subject/envelope, repair guard, diagnose) — see `docs/runbooks/agent-monitoring-snmp-subject.md`; C11 probe path corrected to `cmd/pilot-agent-controller` (actual guard location) instead of `internal/repair`. C7-C9, C14-C15 remain unimplemented; still DRAFT overall. |
| 2026-09-02 | DRAFT | Phase 4 evidence added for C7-C9 (Detection Engine subject/migration generalization) — see `docs/runbooks/detection-engine-subject-generalization.md`; C9 probe corrected to the real ambiguous-series test name. C14-C15 remain unimplemented (Phase 5/6); still DRAFT overall. |
| 2026-09-02 | DRAFT | Phase 5 evidence added for C15 (`network-device-ifmib-v1` cardinality policy + real disposable-VM discovery) — see `docs/runbooks/snmp-adaptive-detection.md`. C14 (model-provider fallback) remains unimplemented (Phase 6); still DRAFT overall. |
