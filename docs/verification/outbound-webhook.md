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

**Status: DRAFT.** This file is amended in place as each implementation
phase lands, exactly like `docs/verification/host-decommission.md`'s
phase-by-phase history — each row goes from "not yet executable" to a
real PASS as its owning phase (§48 Phase 1-5 of the design spec) is
implemented.

- **Phase 0** recorded the intended checks only; no unit-test or
  actual-run evidence existed for any row.
- **Phase 1** landed `contract.Effects` (E1-E3 in
  `internal/contract/effects_test.go`), the §6.4 component/effect-set
  cross-layer lint (E4-E7 in
  `cmd/pilot/cmd/deploy_catalog_effects_test.go`), and the
  `integrations.yaml` parser/validator (`internal/outbound/config.go`,
  CFG1-CFG13 + CFG15-CFG16 in `internal/outbound/config_test.go`). This
  made **C1** (config strict parse) real and passing. CFG14
  (source/name-change/disabled → orphaned/paused semantics) is
  deferred to Phase 3, where `internal/outbound`'s outbox/store exists
  to actually hold the rows being reclassified — C1's probe already
  matches it by prefix (`^TestOutboundConfig_CFG`) so no row edit is
  needed once it lands.
- **Phase 2** (this revision) lands the `user_host_access_v1` projection
  builder (`internal/outbound/projection.go`/`projection_roster.go`,
  P1-P27 in `internal/outbound/projection_test.go`) and the diff engine
  (`internal/outbound/diff.go`, D1-D7 + D15 in
  `internal/outbound/diff_test.go`), plus the `internal/inventory`
  extensions this needed: `EffectiveSudoAccess` gained
  `DeniedCommands`/`RunAsUsers`/`RunAsGroups`/`Options`
  (`roster_effective.go`), `ViewEncryptedRoster`/
  `ReadRosterAsMapWithVault` (`roster_vault.go`, in-memory-only
  decrypt), and a new `external_projection.go` exposing typed
  `ExternalUsers`/`ExternalGroups`/`ExternalHostgroups`/
  `ExternalRosterHosts`/`ExternalEffectiveAccess` so this package never
  has to reach into roster internals. This makes **C2, C5, C6, C7
  (partially — P14 only; D7's own timestamp-independence half is also
  covered), C15 (via P7/P8 shape — the workflow-level exactly-once
  assertion is still Phase 4), C18, C19, C21, C22, C25 (partially —
  projection only), C26 (partially), C28** real for the projection
  layer specifically; their full acceptance still needs Phase 4's
  workflow wiring to be genuinely end-to-end. D8-D14 (cursor/FIFO/
  cross-process claim semantics) and C10/C12/C23/C30 are deferred to
  Phase 3, where the outbox/store exists to hold a cursor at all — pure
  `Diff()` has no notion of "ACKed" or "pending". P24's projection-level
  half (an unavailable result never fabricates an empty snapshot) is
  covered now; its event-envelope half (an unavailable/oversized event
  omits the `snapshot`/`diff` JSON fields entirely) is deferred to
  Phase 3's event.go.
- **Phase 3** (this revision) lands the durable outbox
  (`internal/store/sqlite.go` schema v16: `webhook_outbox`,
  `webhook_state_cursor`, `webhook_workspace_binding`;
  `internal/outbound/outbox.go`'s `SQLiteOutbox` — enqueue with §31
  idempotency-on-conflict, the cross-process claim lease via a
  dedicated `_txlock=immediate` connection — SQLite's own
  single-writer model is the cross-process mutex, so no extra
  optimistic-concurrency guard was needed beyond matching on
  `claim_owner` — mark-delivered/mark-attempt-failed, config
  reconciliation (`ReconcileWebhookConfig`, closing CFG14) and
  workspace/source binding (`CheckWorkspaceBinding`)), HMAC/bearer auth
  (`auth.go`), retry classification and backoff (`retry.go`), the HTTP
  dispatcher and bounded flush loop (`dispatcher.go`), the wire
  envelope builder plus dead-letter base-mismatch chain safety
  (`event.go`), history.db permission securing (`workspace.go`), and
  `pilot webhook lint/status/flush` (`cmd/pilot/cmd/webhook.go`). This
  makes **C10, C11, C12, C13, C14, C20, C23, C24, C29, C30** real and
  passing, and CFG14 (deferred from Phase 1) now has a real test
  (`internal/outbound/outbox_test.go`). **C27** is real at the
  dispatcher/outbox level (`H18`/`H20`'s budget and
  missing-secret-consumes-no-attempt assertions) — its workflow-level
  half (`W20`: a *caller's* local enqueue failure never flips the
  underlying deploy/reconcile exit code) still needs Phase 4, since
  there is no real caller yet. **C25/C26** remain projection-level only
  until Phase 4 wires the dedicated frontends and the real
  `WorkflowResult` aggregation through `event.go`'s
  `OperationMetadata`. C2-C9, C15-C19, C21, C22, C28 are unchanged from
  Phase 2 (still projection-level, pending Phase 4 for end-to-end
  workflow coverage). No `docs/evidence/outbound-webhook/` actual-run
  evidence exists yet — everything above is `go test`-only, exactly as
  designed for Phase 0-4 (see the rationale below); Phase 5 is the only
  phase that touches a real HTTPS receiver, a real disposable
  `vm-target`, or two real separate Pilot processes.
- **Phase 4** (this revision) wires every terminal-publication call
  site design spec §28.2/§41 requires: `cmd/pilot/cmd/outbound_workflow.go`
  is the shared coordinator (`publishTerminalWorkflow`,
  `aggregateDeploymentResult`/`aggregateWorkflowResult` implementing
  §9's precedence table, `webhookReadiness` for the INV-3 pre-mutation
  gate), called from `deploy.go`'s `runSiteDeploy`,
  `runCatalogPlaybookDeployEntry`, and `executeCatalogReconcileBatch`
  (covering `pilot deploy`/`pilot reconcile` interactive, `--force`, and
  `--actions`, which all funnel through the same instrumented
  entrypoints via the shared TUI/prompt-automation layer — there is no
  separate automation code path to miss), and from the dedicated
  frontends `gateway_scope.go` (`reconcile`/`enable-auto`/`disable-auto`),
  `access_cli.go` (`pilot access reconcile`, routing effects pinned to
  the §1 `access.hbac`/`access.sudo`/`access.grants` subset, never the
  full freeipa-identity effect set), and `access_breakglass_cli.go`
  (`activate`/`deactivate`, empty component sets plus
  `operation.subject`). `internal/delivery/transaction.go` gained
  `Result`/`RunResult` (backward-compatible; `Run` is now a thin
  wrapper) so callers get `FailedStep` without parsing an error string,
  and `internal/outbound/outbox.go` gained `EffectiveBase` (the enqueue-
  time §14.7 base resolution `publishTerminalWorkflow` needs). This
  makes **C3, C4, C5, C6, C15, C16, C17 (workflow half), C25, C26, C27
  (workflow half)** real and passing — the full W1-W20 workflow
  regression suite lives in
  `cmd/pilot/cmd/outbound_workflow_integration_test.go` (end-to-end,
  real fake-ansible subprocess + `httptest` HTTP dispatch) plus the
  pure aggregation-logic tests in `cmd/pilot/cmd/outbound_workflow_test.go`.
  W8 (verify failure) and W20 (local enqueue failure) call
  `publishTerminalWorkflow`/`aggregateDeploymentResult` directly with a
  synthetic `ComponentDeliveryResult`/blocked data dir rather than
  driving a real SSH-verify failure or disk-full condition end-to-end —
  documented in-file at each test, not silently narrowed. C2-C14,
  C18-C24, C28-C30 are unchanged from Phase 3 (projection/dispatcher/
  store-level, not workflow-dependent). No `docs/evidence/outbound-webhook/`
  actual-run evidence exists yet — Phase 5 remains the only phase that
  touches a real HTTPS receiver, a real disposable `vm-target`, or two
  real separate Pilot processes. `pilot webhook send-test` (a fourth
  `pilot webhook` subcommand, `cmd/pilot/cmd/webhook.go` +
  `internal/outbound/testsend.go`) was added on top of Phase 4 as an
  operator convenience — an unretried, non-durable one-shot HTTP POST
  of a synthetic event for checking endpoint/auth/TLS connectivity and
  payload shape — but it is out of design spec scope (§34 only defines
  `lint`/`status`/`flush`) and carries no acceptance row here.
- **Phase 5** (2026-09-17 actual-run evidence, tested at candidate
  `f3cb905`, fixed and re-verified at `df31248`) executed design spec
  §48.1's L1-L7 plan for real: L1 (clean checkout build/test/lint/
  fresh-DB), L2 (a local HTTPS receiver with a test CA —
  HMAC/Bearer/429+Retry-After/503/400/redirect-rejection/timeout, all
  real deliveries via `pilot webhook flush`), and L3 (two concurrent
  `pilot webhook flush` processes sharing one `--data-dir` —
  FIFO/claim-lease/crash-reclaim/monotonic-sequence/workspace-isolation)
  are clean, real, and unconditional PASSes. L4-L6 ran against a real
  disposable `vm-target` FreeIPA server: a real full-site deploy, a real
  `freeipa-identity` reconcile proving disabled-user/HBAC exclusion
  against a live server, real `access reconcile`/breakglass
  activate+deactivate/gateway-scope reconcile — each with correct
  effect-routing and exactly-one-event — plus several genuine real
  ansible failures correctly published as failure events with
  `authoritative: false`. This run also found that `gateway-scope
  enable-auto`/`disable-auto` (and `reconcile`, by the same code path)
  never actually detected a failed `ansible-playbook` run — a
  pre-existing bug in `gateway_scope.go` unrelated to this candidate's
  own diff, but directly affecting this feature's `operation.result`
  accuracy for those three commands. It was fixed in `df31248`
  ("fix(gateway-scope): surface ansible-playbook exit code as an
  error") with two new regression tests, independently re-verified at
  the unit level (judged sufficient over a second live VM run — the bug
  is a pure Go-level exit-code-handling defect with no dependency on
  real ansible/FreeIPA behavior; full reasoning in the evidence doc).
  Full evidence, the reproduction, the fix, and the re-verification are
  in
  [`docs/evidence/outbound-webhook/2026-09-17-phase5-actual-run.md`](../evidence/outbound-webhook/2026-09-17-phase5-actual-run.md).
  L1-L6 are now clean actual-run PASSes at `df31248`; L7 remains
  partially unit-level-only (documented in that same evidence file).

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

- `internal/outbound/config_test.go` — `TestOutboundConfig_CFG<1-13,15-16>` (design spec §46.1); `CFG14` is deferred to `internal/outbound/outbox_test.go` in Phase 3 (it needs the outbox/store's identity-reconciliation logic, not just config parsing)
- `internal/contract/effects_test.go` — `TestContractEffects_E<1-3>` (design spec §46.2, contract-loader-only checks)
- `cmd/pilot/cmd/deploy_catalog_effects_test.go` — `TestDeployCatalogEffects_E<4-7>` (design spec §46.2, cross-layer lint)
- `internal/outbound/effect_match_test.go` — `TestOutboundEffectMatch_*` (design spec §6.2/§31 wildcard matching, not individually numbered upstream)
- `internal/outbound/projection_test.go` — `TestOutboundProjection_P<1-27>` (design spec §46.3); P17/P22/P27 each split into lettered sub-tests (e.g. `P22a`/`P22b`) covering distinct scenarios the design spec's single-line description bundles together
- `internal/outbound/diff_test.go` — `TestOutboundDiff_D<1-7,15>` (design spec §46.4); `D8-D14` (cursor advance/FIFO/cross-process claim) are deferred to `internal/outbound/outbox_test.go` in Phase 3 — pure `Diff()` has no cursor/ACK/claim state to test yet
- `internal/outbound/dispatcher_test.go` / `outbox_test.go` — `TestOutboundDispatcher_H<1-24>` (design spec §46.5); `H16` lives in `event_test.go` as `TestOutboundDiff_D11_H16` since it is the same base-mismatch mechanism as D11
- `internal/outbound/secrets_test.go` — `TestOutboundSecrets_S<1-5>` (design spec §46.7 secret-sentinel regression)
- `internal/store/webhook_outbox_test.go` — `TestWebhookOutboxSchemaMigration` (design spec §22). File/WAL/SHM permission securing (design spec §37) turned out to be an `internal/outbound`-level policy (gated on "at least one webhook enabled", not a blanket `internal/store` behavior) — its tests are `TestOutboundWorkspace_WorkspaceKeyDeterministicAndDistinct` / `TestOutboundDispatcher_PermissionsNewFile` / `TestOutboundDispatcher_PermissionsNarrowsExistingFile` in `internal/outbound/workspace_test.go`, not `internal/store`.
- `cmd/pilot/cmd/webhook_test.go` — `TestWebhookCLI_*` (design spec §34's `lint`/`status`/`flush` CLI, real HTTP delivery over `httptest`)
- `cmd/pilot/cmd/outbound_workflow_test.go` / `outbound_workflow_integration_test.go` — `TestOutboundWorkflow_W<1-20>` (design spec §46.6): pure aggregation-logic tests live in the former, end-to-end (real fake-ansible + `httptest` HTTP dispatch) coverage in the latter — Phase 4

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
  check: snapshot hosts come only from hosts.yml, roster host references map to inventory IDs by one exact address match, and every explicit access host reference resolves without a dangling target
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
