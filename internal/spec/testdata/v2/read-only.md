---
schemaVersion: 2
compatibility: {minPilotVersion: "0.9"}
intent:
  summary: read-only fixture
  source: internal/spec/testdata
  maintainer: sre
targets:
  roles: [fixture]
  hostScope: per-host
  platforms:
    - {os: linux, versions: ["any"]}
  hosts:
    - {hostname: localhost, group: all}
inputs: []
traceability: {components: [fixture]}
defaults:
  become: false
  timeout: 10s
  action: {mode: readOnly}
evidencePolicy: {captureStdout: true, retention: default}
---

# Verification Spec — read-only fixture

## Checks

```yaml
- id: C1
  category: smoke
  check: shell is available
  probe: |
    printf 'ready\n'
  expect: {stdout: {equals: ready}}
```
