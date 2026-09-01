---
schemaVersion: 2
compatibility: {minPilotVersion: "0.9"}
intent:
  summary: snmp-exporter (site-local Prometheus SNMP exporter for switch/router/UPS/PDU/BMC telemetry)
  source: docs/superpowers/specs/2026-09-01-snmp-monitoring-integration-spec.md §6, §12, §13 (C1-C12)
  maintainer: sre
targets:
  roles: [snmp-exporter]
  hostScope: per-host
  platforms:
    - {os: ubuntu, versions: ["22.04", "24.04"]}
inputs: []
traceability: {components: [snmp-exporter]}
defaults:
  become: true
  timeout: 15s
  action: {mode: readOnly}
evidencePolicy: {captureStdout: true, retention: retain-all}
---

# Verification Spec — snmp-exporter

Phase 1 acceptance for the site-local `snmp_exporter` component
(`pilot-snmp-exporter` container,
`playbooks/apply/snmp-exporter-apply.yml`). Row IDs and semantics here
are exactly
`docs/superpowers/specs/2026-09-01-snmp-monitoring-integration-spec.md`
§6/§12/§13's requirements — do not renumber or reword them
independently of that spec.

This component only polls SNMP devices; it never receives Prometheus
credentials, never holds a Pilot MCP capability, and by default binds
only to loopback so Prometheus is the only caller of `/snmp`. C1-C9
verify the container/filesystem/network boundary; C10-C12 verify the
non-secret catalog and production version-policy guards.

## Checks

```yaml
- id: C1
  category: container
  check: pilot-snmp-exporter container exists and is running
  probe: |
    docker ps --filter name=pilot-snmp-exporter --filter status=running -q | wc -l
  expect: {stdout: {equals: "1"}}
  tags: [C1]
- id: C2
  category: version
  check: container image matches the pinned snmp_exporter_version (floating tag or digest)
  probe: |
    docker ps --filter name=pilot-snmp-exporter --no-trunc | grep -m1 -oE 'quay.io/prometheus/snmp-exporter[:@][^ ]+'
  expect: {stdout: {regex: '^quay\.io/prometheus/snmp-exporter[:@]\S+$'}}
  tags: [C2]
- id: C3
  category: hardening
  check: container runs with no-new-privileges and cap-drop ALL
  # Deliberately plain `docker inspect` (JSON) piped to grep, never
  # `docker inspect --format '{{...}}'` — ansible ad-hoc's -m command/-m
  # shell runs Jinja finalization over the whole command string, and
  # Docker's own Go template braces are indistinguishable from Jinja to
  # that pass (see docs/verification/dcgm-exporter.md's C1/C4/C5 note).
  probe: |
    sh -c 'j=$(docker inspect pilot-snmp-exporter); echo "$j" | grep -q "no-new-privileges" && echo "$j" | grep -A2 "\"CapDrop\"" | grep -q "\"ALL\"" && echo hardened || echo not-hardened'
  expect: {stdout: {equals: hardened}}
  tags: [C3]
- id: C4
  category: isolation
  check: container has no Docker socket bind-mount
  probe: |
    docker inspect pilot-snmp-exporter | grep -qF '/var/run/docker.sock' && echo present || echo absent
  expect: {stdout: {equals: absent}}
  tags: [C4]
- id: C5
  category: isolation
  check: container has no SSH key or Pilot vault file mounted
  probe: |
    docker inspect pilot-snmp-exporter | grep -qE '"Source": "[^"]*(\.ssh|\.vault)' && echo present || echo absent
  expect: {stdout: {equals: absent}}
  tags: [C5]
- id: C6
  category: network
  check: exporter HTTP port binds only to the configured loopback/private address, never 0.0.0.0
  probe: |
    ss -H -tln "sport = :9116" | awk '{print $4}'
  expect: {stdout: {regex: '^(127\.0\.0\.1|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)'}}
  tags: [C6]
- id: C7
  category: filesystem
  check: config directory is 0750 and root-owned
  probe: |
    stat -c '%U:%G %a' /etc/pilot/snmp-exporter
  expect: {stdout: {equals: "root:root 750"}}
  tags: [C7]
- id: C8
  category: filesystem
  check: env file is 0600 and contains resolved credentials only there (never in module files)
  probe: |
    stat -c '%U:%G %a' /etc/pilot/snmp-exporter/snmp-exporter.env
  expect: {stdout: {equals: "root:root 600"}}
  tags: [C8]
- id: C9
  category: secret-boundary
  check: no module or catalog file under the config directory contains a secret-like key
  probe: |
    grep -rilE '(^|[^A-Za-z])(community|username|password|privPassword)[[:space:]]*:' /etc/pilot/snmp-exporter/catalog.yml /etc/pilot/snmp-exporter/modules 2>/dev/null | wc -l
  expect: {stdout: {equals: "0"}}
  tags: [C9]
- id: C10
  category: observability
  check: exporter self metrics endpoint answers on 9116 with valid Prometheus exposition
  probe: |
    curl -fsS http://127.0.0.1:9116/metrics | head -n1
  expect: {stdout: {regex: '^#'}}
  tags: [C10]
- id: C11
  category: idempotency
  check: re-applying the playbook with unchanged inputs reports changed=0
  probe: |
    test -d /etc/pilot/snmp-exporter && echo present || echo absent
  expect: {stdout: {equals: present}}
  verifyOnly: true
- id: C12
  category: policy
  check: prod stage rejects a catalog auth profile with version < 3 or securityLevel != authPriv unless an explicit, expiring break-glass exception is set (scenario evidence, see below)
  probe: |
    test -d /etc/pilot/snmp-exporter && echo present || echo absent
  expect: {stdout: {equals: present}}
  verifyOnly: true
```

## PASS / FAIL

All C1-C12 rows must pass for this component to be considered
VERIFICATION_READY. A missing or failing row rejects that status. Mock
SNMP-agent evidence is sufficient here — real-device production gates
are tracked in
`docs/superpowers/specs/2026-09-01-snmp-monitoring-integration-spec.md`
§17.4/§18 (AC23), not by this file.

## Traceability

- C1-C10 map to their playbook tags (same names) in
  `playbooks/apply/snmp-exporter-apply.yml`.
- C11-C12 are `verifyOnly` — idempotency and the production version-policy
  guard are scenario/apply-run evidence (spec §17.2/§17.3), not a single
  already-applied host's static probe.

## Actual-run evidence

See `docs/runbooks/snmp-exporter.md` for the full disposable two-VM lane:
a real `snmp-exporter` VM applied fresh, cross-scraping a real net-snmp
SNMPv3 authPriv agent (read-only view) on a separate VM. Summary:

- `pilot verify docs/verification/snmp-exporter.md`: **12/12 PASS**
  (`.verification/snmp-exporter-20260901-143741.{ndjson,md}`).
- Fresh apply: `ok=25 changed=6 failed=0`; second apply (idempotency):
  `ok=24 changed=0 failed=0`.
- Real SNMPv3 scrape via the deployed exporter returned genuine
  interface counters (`ifHCInOctets`, `ifAdminStatus`, ...) from the lab
  device — see runbook §4.
- `snmpset` against the lab device rejected with `noAccess` (read-only
  view, spec §13.4) — runbook §5.
- Secret scan clean across `catalog.yml`/`modules/if_mib.yml`/`auths.yml`
  — runbook §6.
- Config negative lanes (missing credentialRef, secret-like key in
  catalog, prod + v2c with no/expired/valid exception) all produced the
  expected `assert` pass/fail — runbook §8.

## Change record

| Date | Version | Change |
|---|---|---|
| 2026-09-01 | DRAFT | Phase 0 initial authoring per spec §6/§12/§13's C1-C12. No actual-run evidence yet; apply playbook is a no-op skeleton. |
| 2026-09-01 | v1.0 | Phase 1: real apply implementation (catalog render, hardened container, self metrics), disposable two-VM actual-run evidence (12/12 PASS, real SNMPv3 scrape, idempotent reapply, secret scan clean, negative lanes verified) — see `docs/runbooks/snmp-exporter.md`. |
