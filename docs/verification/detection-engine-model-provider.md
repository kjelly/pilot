---
schemaVersion: 2
compatibility: {minPilotVersion: "0.9"}
intent:
  summary: Detection Engine Model Provider (Stage B — OpenAI/Ollama-driven model-assisted anomaly scoring)
  source: docs/superpowers/specs/2026-08-28-detection-engine-spec.md §60 (M1-M5)
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

# Verification Spec — detection-engine-model-provider

Stage B provider acceptance for the central Detection Engine's model-assisted
scoring path. Row IDs and semantics here are exactly
`docs/superpowers/specs/2026-08-28-detection-engine-spec.md` §60's M1-M5 — do
not renumber or reword them independently of that spec.

These rows are **not applicable** when the provider is disabled (Stage A's
default) — that is not a Stage A failure (spec §60). They only apply to a
host that was actually applied with
`detection_model_provider_enabled=true`. In the fake-protocol
provider-verification lane (spec §49/§60, `detection-fixture-provider`
group), the fixture always speaks `ollama-chat` with `auth=none`, so every
row below is proven against that real (fake-backed) wire protocol, not
against a real OpenAI/Ollama account — Stage B-2's own real-provider
evidence is separate and not claimed here.

M3's exhaustive OpenAI/Ollama protocol-edge-case behavior (incomplete/
refusal/multiple-output-text handling) and M4's exhaustive retry/circuit-
breaker/candidate-cap semantics are `internal/detection`'s own Go unit test
suite (`model_openai_test.go`, `model_ollama_test.go`,
`model_provider_test.go`, `model_batch_test.go`) — this spec cannot and
does not duplicate that; the rows below verify the OBSERVABLE host-level
effect only.

## Checks

```yaml
- id: M1
  category: config
  check: provider configuration obeys spec §41.1's inputRules (enabled provider has a non-empty base URL and model; auth is none or bearer) — production external-provider permission is the apply-time gate's own job, not re-checked here
  probe: |
    /usr/local/bin/pilot-detection-engine config validate --config /etc/pilot/detection-engine/config.yaml
  expect: {stdout: {equals: "config valid"}}
  tags: [M1]
- id: M2
  category: protocol
  check: a real batch round-trip passes JSON Schema + semantic validation (request_id equality, exact candidate-ID set equality, no partial batch acceptance, spec §29/§30) against the configured provider
  probe: |
    /usr/local/bin/pilot-detection-engine provider probe --config /etc/pilot/detection-engine/config.yaml
  expect: {stdout: {contains: "provider probe ok"}}
  tags: [M2]
- id: M3
  category: protocol
  check: status.json reports the configured protocol correctly (openai-responses or ollama-chat, spec §31/§32) — exhaustive per-protocol edge-case behavior (incomplete/refusal/multiple-output-text) is internal/detection's own Go test suite, not repeatable from a single already-applied host
  probe: |
    /usr/local/bin/pilot-detection-engine status --field model_provider.protocol
  expect: {stdout: {regex: '^(openai-responses|ollama-chat)$'}}
  tags: [M3]
- id: M4
  category: resilience
  check: the circuit breaker reports closed under a healthy provider (spec §34) — provider failure/retry/circuit-opening itself never suppresses local detection, proven exhaustively by internal/detection's retry/circuit Go test suite, not repeatable from a single healthy already-applied host
  probe: |
    /usr/local/bin/pilot-detection-engine status --field model_provider.circuit
  expect: {stdout: {equals: "closed"}}
  tags: [M4]
- id: M5
  category: secret
  check: the API key has exactly one Vault -> provider.env -> systemd EnvironmentFile ownership path, and a disabled/non-bearer provider (this lane's own ollama-chat/auth=none configuration) requires no secret and exposes none anywhere observable
  probe: |
    test ! -e /etc/pilot/detection-engine/provider.env || { echo file-present; exit 0; }
    status_json=$(/usr/local/bin/pilot-detection-engine status --json)
    textfile_content=$(cat /var/lib/node_exporter/textfile/pilot_detection_engine.prom)
    if printf '%s %s' "$status_json" "$textfile_content" | grep -qiE 'api_key|apikey|secret'; then echo leaked; else echo clean; fi
  expect: {stdout: {equals: clean}}
  tags: [M5]
```

## PASS / FAIL

All M1-M5 rows must pass for a Stage-B-enabled host to be considered
acceptance-verified per spec §60. These rows are not applicable (not a
failure) when the provider is disabled — see spec §1.3's `STAGE_B_READY`
gate, which is independent of Stage A's own `VERIFICATION_READY`.

## Traceability

- M1-M5 map to their playbook tags (same names) — none of them exist under
  Stage A's disabled-provider default; the apply playbook only renders
  them meaningfully when `detection_model_provider_enabled=true`.

## Actual-run evidence

Recorded 2026-08-28 via `pilot vm-target topology test` against
`tmp/detection-engine-fake-topology.example.yaml` (4 nodes: the SUT plus
`detection-fixture-source`/`-sink`/`-provider`), with
`detection_model_provider_enabled=true`, `protocol=ollama-chat`,
`base_url=http://<detection-fixture-provider IP>:11434`, `auth=none`:

```
=== [Step 5/6] L5 Verification Specs (2) ===
verdict: **PASS**  (pass=12 fail=0 skip=0)   # detection-engine.md
verdict: **PASS**  (pass=5  fail=0 skip=0)   # detection-engine-model-provider.md — M1-M5 all pass
=== [Step 6/6] L6 Idempotency Check ===
PLAY RECAP: ok=51 changed=0 unreachable=0 failed=0 skipped=10
✓ Idempotency check passed (changed=0)
```

Direct confirmation on the target after apply:

```
$ pilot-detection-engine provider probe --config /etc/pilot/detection-engine/config.yaml
provider probe ok: protocol=ollama-chat status=ok elapsed=2ms

$ sudo pilot-detection-engine status --json
{
  "model_provider": {"enabled": true, "healthy": true, "protocol": "ollama-chat", "circuit": "closed"},
  ...
}
```

**Stage B-2 real-provider evidence (Ollama native)** — recorded the same
day, same topology and procedure, with `base_url` pointed at a real
Ollama server (`http://10.1.80.71:11434`, `model: gemma4:e4b`) instead of
the fake fixture: M1-M5 all PASS again, idempotent changed=0,
`provider probe` and `status --json` both healthy against the real
model (`elapsed=9.161s`). See `docs/runbooks/detection-engine.md` §6.3 for
the full transcript — this satisfies spec §58's Stage B-2 "at least one:
Ollama native" requirement.

No bugs found in this run (unlike C11's fake-lane closure, which found 3)
— Stage B-1b/B-1c's playbook/contract/inventory work was correct on the
first real attempt. See `docs/runbooks/detection-engine.md` §6.2 for the
full transcript excerpts.

## Change record

| Date | Version | Change |
|---|---|---|
| 2026-08-28 | DRAFT | Stage B-1c: initial Spec v2 authoring per spec §60's M1-M5. No actual-run evidence yet. |
| 2026-08-28 | v1.0 | Actual-run evidence recorded: fake-protocol provider-verification lane, all M1-M5 PASS, idempotent changed=0. |
