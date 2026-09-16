---
schemaVersion: 2
compatibility: {minPilotVersion: "0.9"}
intent:
  summary: outbound state webhook — durable, versioned, sanitized `user_host_access_v1` projection published to external HTTP consumers at deploy/reconcile terminal boundaries
  source: docs/tmp/now/spec.md §4-§50 (INV-1..INV-7, C1-C30) — will move to docs/superpowers/specs/2026-09-15-outbound-state-webhook-spec.md once implementation completes
  maintainer: sre
targets:
  roles: [outbound-webhook]
  hostScope: aggregate
  platforms:
    - {os: almalinux, versions: ["9"]}
    - {os: ubuntu, versions: ["24.04"]}
inputs: []
traceability: {components: []}
defaults:
  become: false
  timeout: 30s
  action: {mode: readOnly}
evidencePolicy: {captureStdout: true, retention: retain-all}
---

# Verification Spec — outbound-webhook

This is the Phase 0 acceptance contract for `docs/tmp/now/spec.md`
("Pilot Outbound State Webhook + State Projection"): a durable outbox
that publishes a sanitized, versioned, deterministic projection of
Pilot's declarative state (`user_host_access_v1`) to external HTTP
consumers at the terminal boundary of `pilot deploy`/`pilot reconcile`
(and the dedicated `pilot gateway-scope`/`pilot access
reconcile`/`pilot access breakglass` frontends), governed by the hard
invariants INV-1..INV-7 in that spec's §4. Row IDs and semantics here
are exactly that spec's §47 C1-C30 acceptance rows — do not renumber
or reword them independently of that spec; if a row's intended
behavior turns out to be wrong once real code exists, fix the spec and
this file together with a stated reason, not just this file alone.

**Status: DRAFT — Phase 0 only records the intended checks.** None of
these rows have unit-test or actual-run evidence yet. The Go types and
packages they exercise (`internal/outbound/*`, `internal/contract`'s
`Effects` field, `internal/store`'s `webhook_outbox` schema) do not
exist as of this revision. This file will be amended in place as each
implementation phase lands, exactly like
`docs/verification/host-decommission.md`'s phase-by-phase history —
each row goes from "not yet executable" to a real PASS as its owning
phase (§48 Phase 1-5 of the design spec) is implemented, and this
status paragraph will name which rows each phase made executable.

**Why `go test -run` probes instead of shell/ansible probes.** This
feature's primary observable surface is a Go CLI + SQLite durable
outbox + HTTP dispatcher, not a system service applied by a playbook —
the same shape as `docs/verification/snmp-monitoring-integration.md`
and `docs/verification/host-decommission.md`. Each probe below runs a
narrowly-scoped Go test and asserts its own `PASS`; the real assertions
live in the Go test bodies (table-driven), not in this file's `expect`
matcher. Only Phase 5's actual-run evidence lanes (L1-L7 in the design
spec's §48.1 — a real HTTPS receiver with a test CA, two independent
Pilot processes sharing one `--data-dir`, and a disposable `vm-target`
`pilot deploy`/`pilot reconcile`) exercise this outside `go test`; that
evidence will be recorded in `docs/evidence/outbound-webhook/` and
linked from this file once it exists — no such evidence exists yet, so
no row below claims it.

**Test-name buckets.** Rows below reference test names that this
project's later phases will create with these exact prefixes, so a
row's probe never has to be renamed once its test exists:

- `internal/outbound/config_test.go` — `TestOutboundConfig_CFG<1-16>` (design spec §46.1)
- `internal/contract/effects_test.go` — `TestContractEffects_E<1-3>` (design spec §46.2, contract-loader-only checks)
- `cmd/pilot/cmd/deploy_catalog_effects_test.go` — `TestDeployCatalogEffects_E<4-7>` (design spec §46.2, cross-layer lint)
- `internal/outbound/effect_match_test.go` — `TestOutboundEffectMatch_*` (design spec §6.2/§31 wildcard matching, not individually numbered upstream)
- `internal/outbound/projection_test.go` / `projection_roster_test.go` — `TestOutboundProjection_P<1-27>` (design spec §46.3)
- `internal/outbound/diff_test.go` — `TestOutboundDiff_D<1-15>` (design spec §46.4)
- `internal/outbound/dispatcher_test.go` / `outbox_test.go` — `TestOutboundDispatcher_H<1-24>` (design spec §46.5)
- `internal/outbound/secrets_test.go` — `TestOutboundSecrets_S<1-5>` (design spec §46.7 secret-sentinel regression)
- `internal/store/webhook_outbox_test.go` — `TestWebhookOutboxSchemaMigration`, `TestWebhookOutboxFilePermissions` (design spec §22, §37)
- `cmd/pilot/cmd/outbound_workflow_test.go` — `TestOutboundWorkflow_W<1-20>` (design spec §46.6)

## Checks

```yaml
- id: C1
  category: config
  check: integrations.yaml strict schema/URL/auth/delivery-bounds validation matches the full CFG1-CFG16 acceptance matrix
  probe: |
    go test ./internal/outbound/... -run '^TestOutboundConfig_CFG' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C2
  category: effects
  check: effect_any subscription matching honors exact effects and trailing-namespace wildcards only, never bare/arbitrary glob
  probe: |
    go test ./internal/outbound/... -run '^TestOutboundEffectMatch_' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C3
  category: workflow
  check: a successful pilot deploy publishes a fresh, operation-terminal-rebuilt snapshot marked basis=pilot_declared and authoritative=true
  probe: |
    go test ./cmd/pilot/cmd/... -run '^TestOutboundWorkflow_W(1|9|19)$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C4
  category: workflow
  check: a failed pilot deploy still publishes a terminal event (payload per subscription), marked authoritative=false
  probe: |
    go test ./cmd/pilot/cmd/... -run '^TestOutboundWorkflow_W(7|10)$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C5
  category: workflow
  check: pilot reconcile success on an identity/access-effect component matches an identity.*/access.* subscription
  probe: |
    go test ./cmd/pilot/cmd/... -run '^TestOutboundWorkflow_W(5|17)$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C6
  category: effects
  check: freeipa-dns's dns.* effects never match an identity.*/access.*-only subscription — zero HTTP calls made
  probe: |
    go test ./cmd/pilot/cmd/... -run '^TestOutboundWorkflow_W6$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C7
  category: projection
  check: the snapshot hash is a deterministic function of semantic state only (excludes generated_at/event_id/workflow_id/delivery outcome)
  probe: |
    go test ./internal/outbound/... -run '^TestOutboundProjection_P14$' -v && go test ./internal/outbound/... -run '^TestOutboundDiff_D7$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C8
  category: diff
  check: diff base is the last authoritative-ACKed publication snapshot, never a local pre/post file comparison, and host diff keys are namespaced ids
  probe: |
    go test ./internal/outbound/... -run '^TestOutboundDiff_D(1|2|3|13|14|15)$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C9
  category: diff
  check: a consumer with no prior cursor gets bootstrap=true with all current entities as upserts, and can re-establish cursor from a later snapshot
  probe: |
    go test ./internal/outbound/... -run '^TestOutboundDiff_D(1|12)$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C10
  category: diff
  check: the publication cursor advances only after 2xx delivery of an authoritative, available, source_complete event
  probe: |
    go test ./internal/outbound/... -run '^TestOutboundDiff_D(8|9)$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C11
  category: dispatcher
  check: retryable HTTP failures (5xx/429/timeout) are durably retried with bounded exponential+jitter backoff honoring Retry-After, without consuming attempts on missing-secret
  probe: |
    go test ./internal/outbound/... -run '^TestOutboundDispatcher_H(4|5|7|19|20)$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C12
  category: dispatcher
  check: same-webhook deliveries are strictly FIFO by sequence, including across a crashed/reclaimed cross-process claim
  probe: |
    go test ./internal/outbound/... -run '^TestOutboundDispatcher_H(9|13|14|15)$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C13
  category: auth
  check: HMAC-SHA256 signature is computed exactly over timestamp.eventID.rawBody and bearer tokens are never logged
  probe: |
    go test ./internal/outbound/... -run '^TestOutboundDispatcher_H(1|2)$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C14
  category: secrets
  check: fixture secret sentinels (password/ssh-key) never appear in webhook body, outbox JSON, cursor JSON, status output, or retry error text
  probe: |
    go test ./internal/outbound/... -run '^TestOutboundSecrets_' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C15
  category: workflow
  check: a multi-component deploy/reconcile (including an auto-added sameHosts dependency) produces exactly one terminal event per webhook
  probe: |
    go test ./cmd/pilot/cmd/... -run '^TestOutboundWorkflow_W(2|3|4)$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C16
  category: workflow
  check: --actions and --force automation drivers publish through the identical terminal workflow path as interactive mode
  probe: |
    go test ./cmd/pilot/cmd/... -run '^TestOutboundWorkflow_W(11|12|16)$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C17
  category: workflow
  check: webhook HTTP failure/success never changes the underlying deploy/reconcile process exit code in either direction
  probe: |
    go test ./internal/outbound/... -run '^TestOutboundDispatcher_H11$' -v && go test ./cmd/pilot/cmd/... -run '^TestOutboundWorkflow_W(9|10)$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C18
  category: projection
  check: an encrypted roster is decrypted in memory using the reused vault-password-file resolution order, with no plaintext temp file
  probe: |
    go test ./internal/outbound/... -run '^TestOutboundProjection_P1[56]$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C19
  category: projection
  check: a projection source that is configured but unreadable/oversized never degrades to an empty authoritative snapshot — it omits payload and blocks cursor advance instead
  probe: |
    go test ./internal/outbound/... -run '^TestOutboundProjection_P(17|24)$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C20
  category: store
  check: the webhook_outbox/webhook_state_cursor schema migrates additively from a real prior-version fixture, and pending rows survive process restart (close+reopen)
  probe: |
    go test ./internal/store/... -run '^TestWebhookOutboxSchemaMigration$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C21
  category: projection
  check: disabled HBAC/sudo rules and disabled/account-expired users are excluded from effective access, while remaining present as entities where applicable
  probe: |
    go test ./internal/outbound/... -run '^TestOutboundProjection_P1[89]$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C22
  category: projection
  check: inventory and FreeIPA-roster hosts use distinct namespaced stable IDs (no heuristic FQDN merge) and every explicit access host reference resolves without a dangling target
  probe: |
    go test ./internal/outbound/... -run '^TestOutboundProjection_P2[012]$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C23
  category: dispatcher
  check: a cross-process claim lease (BEGIN IMMEDIATE + lease expiry) prevents two processes from double-delivering the same sequence and preserves FIFO after a crash/reclaim
  probe: |
    go test ./internal/outbound/... -run '^TestOutboundDispatcher_H(13|14|15|24)$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C24
  category: dispatcher
  check: 3xx redirects are never followed (classified http_redirect, dead-lettered) and TLS uses MinVersion 1.2 with no insecure-skip-verify override
  probe: |
    go test ./internal/outbound/... -run '^TestOutboundDispatcher_H(12|23)$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C25
  category: workflow
  check: site.yml full-site deploy and every dedicated reconcile frontend (gateway-scope reconcile/enable-auto/disable-auto, access reconcile, breakglass activate/deactivate) publish through the same coordinator with exactly one event each
  probe: |
    go test ./cmd/pilot/cmd/... -run '^TestOutboundWorkflow_W1[4678]$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C26
  category: workflow
  check: wire state fields correctly separate publication authority (basis/authoritative) from remote application consistency (confirmed_effects), never overclaiming an unconfirmed domain
  probe: |
    go test ./cmd/pilot/cmd/... -run '^TestOutboundWorkflow_W19$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C27
  category: dispatcher
  check: terminal publication enqueues all matched subscriptions before any HTTP attempt, respects the bounded 30s/4-concurrent-attempt budget, and a local enqueue failure after mutation never reports a pending event
  probe: |
    go test ./internal/outbound/... -run '^TestOutboundDispatcher_H18$' -v && go test ./cmd/pilot/cmd/... -run '^TestOutboundWorkflow_W20$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C28
  category: projection
  check: effective sudo access resolves complete allow/deny command-group unions, run-as users/groups, options, and future/expired/duplicate grant edge cases per the specified inclusion rules
  probe: |
    go test ./internal/outbound/... -run '^TestOutboundProjection_P2[67]$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C29
  category: store
  check: terminal outbox rows compact body/target-snapshot fields atomically, paused rows keep an immutable retry body, and an enabled integration's history.db (+ WAL/SHM) is 0600
  probe: |
    go test ./internal/outbound/... -run '^TestOutboundDispatcher_H21$' -v && go test ./internal/store/... -run '^TestWebhookOutboxFilePermissions$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
- id: C30
  category: store
  check: a shared --data-dir isolates workspace_key rows and a source_id/workspace rebinding conflict fails closed rather than mixing publication lineages
  probe: |
    go test ./internal/outbound/... -run '^TestOutbound(Dispatcher_H24|Config_CFG14)$' -v
  expect: {stdout: {contains: "PASS"}}
  verifyOnly: true
```
