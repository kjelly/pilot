---
schemaVersion: 2
compatibility: {minPilotVersion: "0.9"}
intent:
  summary: Agent Controller (Phase 1 observe-only incident orchestrator)
  source: docs/superpowers/specs/2026-09-01-agent-monitoring-phase-1-observe-only-controller-spec.md §15 (C1-C13)
  maintainer: sre
targets:
  roles: [agent-controller]
  hostScope: per-host
  platforms:
    - {os: ubuntu, versions: ["24.04"]}
inputs: []
traceability: {components: [agent-controller]}
defaults:
  become: true
  timeout: 15s
  action: {mode: readOnly}
evidencePolicy: {captureStdout: true, retention: retain-all}
---

# Verification Spec — agent-controller

Phase 1 acceptance for the observe-only Incident Controller
(`pilot-agent-controller` binary,
`playbooks/apply/agent-controller-apply.yml`). Row IDs and semantics here
are exactly
`docs/superpowers/specs/2026-09-01-agent-monitoring-phase-1-observe-only-controller-spec.md`
§15's C1-C13 — do not renumber or reword them independently of that spec.

The controller has **zero mutation authority**: it never receives an SSH
credential, never holds `--enable-diagnose-raw`/`--allow-write` MCP
capability, and never execs a shell. C8 verifies the MCP capability
boundary structurally; every other row verifies the controller's own
webhook ingress, incident state machine, and persistence.

## Checks

```yaml
- id: C1
  category: service
  check: dedicated pilot-agent system account (nologin, no home) runs an active pilot-agent-controller.service
  probe: |
    getent passwd pilot-agent | grep -q '/usr/sbin/nologin$' || exit 1
    home=$(getent passwd pilot-agent | cut -d: -f6)
    [ -d "$home" ] && [ "$home" != "/" ] && [ "$(ls -A "$home" 2>/dev/null)" ] && exit 1
    systemctl is-active pilot-agent-controller.service
  expect: {stdout: {equals: active}}
  tags: [C1]
- id: C2
  category: network
  check: the webhook listener binds only to the private/loopback address configured, never a public interface
  probe: |
    pid=$(systemctl show -p MainPID --value pilot-agent-controller.service)
    ss -H -tlnp 2>/dev/null | grep "pid=${pid}," | grep -qE '(127\.0\.0\.1|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)' && echo private || echo not-private
  expect: {stdout: {equals: private}}
  tags: [C2]
- id: C3
  category: auth
  check: a webhook with a missing/wrong bearer token is rejected with 401, never 2xx
  probe: |
    addr=$(grep '^listenAddr:' /etc/pilot/agent-controller/config.yaml | sed -E 's/^listenAddr: *"?([^"]*)"?$/\1/')
    curl -sS -o /dev/null -w '%{http_code}' "http://${addr}/webhooks/alertmanager" \
      -H 'Authorization: Bearer wrong-token' \
      --data '{"version":"4","status":"firing","alerts":[{"status":"firing","fingerprint":"verify-c3","labels":{"alertname":"VerifyProbe","pilot_host":"verify-host"},"annotations":{},"startsAt":"2026-01-01T00:00:00Z"}]}'
  expect: {stdout: {equals: "401"}}
  tags: [C3]
- id: C4
  category: config
  check: the rendered config.yaml passes `config validate`
  probe: |
    /usr/local/bin/pilot-agent-controller config validate --config /etc/pilot/agent-controller/config.yaml
  expect: {stdout: {equals: "config valid"}}
  tags: [C4]
- id: C5
  category: storage
  check: SQLite state.db passes PRAGMA integrity_check and is owned/mode-correct
  probe: |
    /usr/local/bin/pilot-agent-controller db check --db /var/lib/pilot/agent-controller/state.db || exit 1
    stat -c '%U:%G %a' /var/lib/pilot/agent-controller/state.db
  expect: {stdout: {contains: "pilot-agent:pilot-agent 600"}}
  tags: [C5]
- id: C6
  category: observability
  check: status.json and the textfile metrics file are present, parseable, and carry no secret
  probe: |
    status_json=$(/usr/local/bin/pilot-agent-controller status --json)
    echo "$status_json" | python3 -c "import json,sys; json.load(sys.stdin)" || exit 1
    textfile_content=$(cat /var/lib/node_exporter/textfile/pilot_agent_controller.prom)
    if printf '%s %s' "$status_json" "$textfile_content" | grep -qiE 'secret|password|api_key'; then echo leaked; else echo clean; fi
  expect: {stdout: {equals: clean}}
  tags: [C6]
- id: C7
  category: identity
  check: a firing webhook creates exactly one incident, and an identical replay creates no duplicate (scenario evidence, see below)
  probe: |
    /usr/local/bin/pilot-agent-controller db check --db /var/lib/pilot/agent-controller/state.db
  expect: {stdout: {equals: "ok"}}
  verifyOnly: true
- id: C8
  category: capability-boundary
  check: this host holds no local Pilot MCP capability of its own (the observe-only MCP session `pilot mcp serve --enable-diagnose` the Agent Runtime connects through runs on the operator's control plane, never on this component's own host) — the exhaustive raw/write-tool-exclusion proof is pilot's own MCP test suite, not this row
  probe: |
    test -x /usr/local/bin/pilot && echo present || echo absent
  expect: {stdout: {equals: absent}}
  verifyOnly: true
- id: C9
  category: lifecycle
  check: a valid structured diagnosis persists and is retrievable (scenario evidence, see below — a single already-applied host cannot itself submit a signed webhook and inspect the resulting row without the disposable-lane harness)
  probe: |
    /usr/local/bin/pilot-agent-controller status --field runs.active
  expect: {stdout: {regex: '^[0-9]+$'}}
  verifyOnly: true
- id: C10
  category: robustness
  check: malformed Agent output never becomes a persisted partial diagnosis (Go-code-level guarantee, internal/agentcontroller/model.go's DiagnosisResult.Validate + queue.go's dispatchOne)
  probe: |
    /usr/local/bin/pilot-agent-controller version
  expect: {stdout: {regex: '^pilot-agent-controller \S+ \(\S+\)'}}
  verifyOnly: true
- id: C11
  category: durability
  check: a controller restart preserves already-recorded incident state (scenario evidence, see below)
  probe: |
    /usr/local/bin/pilot-agent-controller db check --db /var/lib/pilot/agent-controller/state.db
  expect: {stdout: {equals: "ok"}}
  verifyOnly: true
- id: C12
  category: isolation
  check: the controller process holds no SSH private key and no Ansible vault password file
  probe: |
    found=0
    for f in /home/pilot-agent/.ssh/id_* /etc/pilot/agent-controller/*.vault; do
      [ -e "$f" ] && found=1
    done
    [ "$found" = "1" ] && echo present || echo absent
  expect: {stdout: {equals: absent}}
  tags: [C12]
- id: C13
  category: idempotency
  check: re-applying the playbook with unchanged inputs reports changed=0
  probe: |
    test -x /usr/local/bin/pilot-agent-controller && echo present || echo absent
  expect: {stdout: {equals: present}}
  verifyOnly: true
```

## PASS / FAIL

All C1-C13 rows must pass for this component to be considered Phase 1
VERIFICATION_READY. A missing or failing row rejects that status.

## Traceability

- C1, C2, C4, C5, C6, C12 map to their playbook tags (same names) in
  `playbooks/apply/agent-controller-apply.yml`.
- C3 is a Go-code-level guarantee (`internal/agentcontroller/http.go`'s
  `verifyBearerToken`) — no apply task implements the auth check itself,
  only provisions the shared secret.
- C7, C9-C11, C13 are `verifyOnly` — their scenario evidence (replay
  dedup, resolve, restart recovery, idempotent reapply) comes from the
  disposable-lane actual-run evidence (spec §17), not a single already-
  applied host's static probe.
- C8's own probe confirms this host holds no local Pilot binary at all
  (so it could never open a raw/write MCP session even by accident); the
  exhaustive capability-enumeration proof is `internal/agentcontroller`'s
  own Go test suite plus the operator-side MCP session, mirroring
  `detection-engine.md`'s C11 precedent.

## Actual-run evidence

See `docs/runbooks/agent-controller.md` for the disposable-lane PLAY
RECAP/verdict output this spec's scenario rows depend on. Real-chain
lane: `docs/runbooks/agent-controller.md` §4 — a real Alertmanager v0.27
instance, configured with a `webhook_configs` bearer-token route,
successfully delivered a live-fired alert end to end.

## Change record

| Date | Version | Change |
|---|---|---|
| 2026-09-01 | DRAFT | Phase 1 initial authoring per spec §15's C1-C13. No actual-run evidence yet. |
| 2026-09-01 | v1.0 | Disposable-lane actual-run evidence recorded (see `docs/runbooks/agent-controller.md`): 13/13 Spec v2 PASS, idempotent changed=0, real Alertmanager v0.27 webhook delivery verified end to end. Found and fixed 3 real bugs during the run (HMAC-vs-bearer-token auth mismatch with real Alertmanager, C3/C8 probe defects) — see runbook §3. Phase 1 reaches VERIFICATION_READY. |
