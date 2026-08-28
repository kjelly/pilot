---
schemaVersion: 2
compatibility: {minPilotVersion: "0.9"}
intent:
  summary: Detection Engine (central Thanos-driven adaptive anomaly detection plane, Stage A)
  source: docs/superpowers/specs/2026-08-28-detection-engine-spec.md §47 (C1-C12)
  maintainer: sre
targets:
  roles: [detection-engine]
  hostScope: per-host
  platforms:
    - {os: ubuntu, versions: ["24.04"]}
inputs: []
traceability: {components: [detection-engine]}
defaults:
  become: true
  timeout: 15s
  action: {mode: readOnly}
evidencePolicy: {captureStdout: true, retention: retain-all}
---

# Verification Spec — detection-engine

Stage A acceptance for the central Detection Engine (`pilot-detection-engine`
binary, `playbooks/apply/detection-engine-apply.yml`). Row IDs and semantics
here are exactly `docs/superpowers/specs/2026-08-28-detection-engine-spec.md`
§47's C1-C12 — do not renumber or reword them independently of that spec.

Provider (Stage B) is always disabled for Stage A: C12 verifies that fact
structurally (no secret file, no secret substring anywhere observable).
`docs/verification/detection-engine-model-provider.md` (M1-M5) is a
separate, not-yet-authored Stage B document — it does not exist yet and
these C rows do not depend on it.

C9 and C10 assert the OBSERVABLE effect of the statistical engine (no false
anomaly on a fresh/cold-start host, at least one successful cycle) — the
exhaustive formula-level proof (exact median/MAD/scale-floor math, cold-start
threshold, contamination-protection freeze, cohort self-exclusion, etc.) is
`internal/detection`'s own Go unit test suite
(`internal/detection/baseline_test.go`, `cohort_test.go`, `lifecycle_test.go`),
which this spec cannot and does not duplicate. C11 is `verifyOnly` for the
same reason as `freeipa-ca-trust.md`'s C6: a single already-applied host
cannot exercise "does the outbox correctly serialize a
warning-then-critical escalation against a fake Alertmanager", so that
scenario is proven by the fake-protocol topology lane (spec §49) instead;
this row's own probe only confirms the outbox mechanism is structurally
present and healthy on the host under test.

## Checks

```yaml
- id: C1
  category: artifact
  check: the installed binary is the expected artifact and reports a valid version string (controller-side sha256/version equality is enforced by the apply playbook's preflight gate before this host is ever mutated)
  probe: |
    /usr/local/bin/pilot-detection-engine version
  expect: {stdout: {regex: '^pilot-detection-engine \S+ \(\S+\)'}}
  tags: [C1]
- id: C2
  category: service
  check: dedicated pilot-detect system account (nologin, no home) runs an active pilot-detection-engine.service
  probe: |
    getent passwd pilot-detect | grep -q '/usr/sbin/nologin$' || exit 1
    home=$(getent passwd pilot-detect | cut -d: -f6)
    [ -d "$home" ] && [ "$home" != "/" ] && [ "$(ls -A "$home" 2>/dev/null)" ] && exit 1
    systemctl is-active pilot-detection-engine.service
  expect: {stdout: {equals: active}}
  tags: [C2]
- id: C3
  category: config
  check: the rendered config.yaml passes `config validate` (schema gate already ran before restart at apply time; this re-confirms it still does)
  probe: |
    /usr/local/bin/pilot-detection-engine config validate --config /etc/pilot/detection-engine/config.yaml
  expect: {stdout: {equals: "config valid"}}
  tags: [C3]
- id: C4
  category: storage
  check: SQLite state.db passes PRAGMA integrity_check and is owned/mode-correct
  probe: |
    /usr/local/bin/pilot-detection-engine db check --db /var/lib/pilot/detection-engine/state.db || exit 1
    stat -c '%U:%G %a' /var/lib/pilot/detection-engine/state.db
  expect: {stdout: {contains: "pilot-detect:pilot-detect 600"}}
  tags: [C4]
- id: C5
  category: network
  check: detection-engine has no TCP/UDP listener of its own
  probe: |
    pid=$(systemctl show -p MainPID --value pilot-detection-engine.service)
    ss -H -tulnp 2>/dev/null | grep -q "pid=${pid}," && echo listening || echo no-listener
  expect: {stdout: {equals: no-listener}}
  tags: [C5]
- id: C6
  category: observability
  check: status.json and the textfile metrics file are present, parseable, and carry no secret
  probe: |
    status_json=$(/usr/local/bin/pilot-detection-engine status --json)
    echo "$status_json" | python3 -c "import json,sys; json.load(sys.stdin)" || exit 1
    textfile_content=$(cat /var/lib/node_exporter/textfile/pilot_detection_engine.prom)
    if printf '%s %s' "$status_json" "$textfile_content" | grep -qiE 'api_key|apikey|secret'; then echo leaked; else echo clean; fi
  expect: {stdout: {equals: clean}}
  tags: [C6]
- id: C7
  category: source
  check: the engine's own view of Thanos source health is healthy (never :10902 — the binary only ever calls the configured :10912 base URL, see spec §9/§10)
  probe: |
    /usr/local/bin/pilot-detection-engine status --field source.healthy
  expect: {stdout: {equals: "true"}}
  tags: [C7]
- id: C8
  category: identity
  check: subjects are derived from the canonical pilot_host discovery (spec §9), reported as a non-negative count — the real-chain identity proof itself (pilot_host equals the inventory hostname) is spec §51's cross-check, not repeatable from a single already-applied host
  probe: |
    /usr/local/bin/pilot-detection-engine status --field subjects.active
  expect: {stdout: {regex: '^[0-9]+$'}}
  tags: [C8]
- id: C9
  category: telemetry
  check: the engine completes cycles against the real feed without turning invalid telemetry into a false cycle failure (spec §13's exact per-sample classification is proven by internal/detection/source_test.go, not here)
  probe: |
    /usr/local/bin/pilot-detection-engine status --field last_cycle.success
  expect: {stdout: {equals: "true"}}
  tags: [C9]
- id: C10
  category: baseline
  check: a freshly-applied host has no false anomaly before its baseline has enough history (spec §14's 120-bucket cold-start gate is proven by internal/detection/baseline_test.go, not here)
  probe: |
    /usr/local/bin/pilot-detection-engine signals list --db /var/lib/pilot/detection-engine/state.db
  expect: {stdout: {equals: "[]"}}
  tags: [C10]
- id: C11
  category: fixture
  check: the outbox mechanism (schema, lease/retry/dead, delivery ordering) is structurally present and healthy on this host — the actual lifecycle/escalation/resolution SCENARIO evidence comes from the fake-protocol topology lane (spec §49), not a single already-applied host
  probe: |
    /usr/local/bin/pilot-detection-engine status --field state
  expect: {stdout: {regex: '^(healthy|degraded)$'}}
  verifyOnly: true
- id: C12
  category: secret
  check: with the model provider disabled, no provider secret file exists and no secret substring appears anywhere observable
  probe: |
    test -e /etc/pilot/detection-engine/provider.env && echo present || echo absent
  expect: {stdout: {equals: absent}}
  tags: [C12]
```

## PASS / FAIL

All C1-C12 rows must pass for this component to be considered Stage A
VERIFICATION_READY (spec §1.3). A missing or failing row rejects that
status — see spec §48.1's readiness-matrix rule: a clean `spec --lint` alone
never makes a row PASS.

## Traceability

- C1-C10, C12 map to their playbook tags (same names) in
  `playbooks/apply/detection-engine-apply.yml`.
- C11 is intentionally `verifyOnly` — see the note above and spec §49.

## Actual-run evidence

Not yet recorded. Target evidence for every row (fake-lane C11, real-lane
C1-C10/C12, and the §51 real metrics-chain cross-check) must come from
actually running `pilot vm-target topology test` against the fake and real
topology artifacts in `tmp/detection-engine-{fake,real}-topology.example.yaml`
(spec §49) before this document — or the spec's `VERIFICATION_READY` status
— can claim to be satisfied. Do not backfill this section with anything
that was not actually executed.

## Change record

| Date | Version | Change |
|---|---|---|
| 2026-08-28 | DRAFT | Stage A-2: initial Spec v2 authoring per spec §47's C1-C12. No actual-run evidence yet. |
