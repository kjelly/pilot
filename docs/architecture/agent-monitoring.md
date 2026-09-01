# Agent Monitoring Architecture

> 完整規格（依 phase 分開撰寫）：
> `docs/superpowers/specs/2026-09-01-agent-monitoring-phase-1-observe-only-controller-spec.md`、
> `docs/superpowers/specs/2026-09-01-agent-monitoring-phase-2-structured-diagnostics-spec.md`
> （Phase 3-5 尚在 `docs/tmp/future/agent-monitoring/`，尚未實作 —— 完成一個
> phase 就搬一份進來、在這裡補一段）。這份文件只整理架構全貌，不重複規格的
> normative 細節，這裡衝突時一律以對應 phase 的 spec 為準。

## 1. 資料流（Phase 1）

```
managed hosts
  → node_exporter / logs / security telemetry
  → Prometheus / Loki / Thanos
  → Prometheus deterministic rules ─┐
  → pilot-detection-engine adaptive │
    SignalEvent ──────────────────┼─→ Alertmanager
                                    │      │ webhook (Bearer-token
                                    │      │  authenticated, send_resolved: true)
                                    │      ▼
                                    │  pilot-agent-controller
                                    │      │ IncidentEnvelopeV1
                                    │      ▼
                                    │  external Agent Runtime
                                    │  (Phase 1: none wired in — only
                                    │   FakeDispatcher + a generic
                                    │   HTTPDispatcher adapter exist)
                                    │      │ DiagnosisResult
                                    │      ▼
                                    │  incidents / incident_events /
                                    └─ agent_runs / agent_evidence (SQLite)
```

The Agent Controller is an incident orchestrator and state store. It is
**not** a second anomaly detector — `pilot-detection-engine` remains the
sole owner of adaptive detection — and it holds **zero mutation
authority**: no SSH credential, no `--enable-diagnose-raw`/`--allow-write`
MCP capability, no shell exec.

## 2. 為什麼是這個切法

- **Observe-only first.** Phase 1 proves the incident normalization,
  dedup, and dispatch machinery end-to-end before any remediation
  capability exists — remediation (Phase 3+) is a strictly separate MCP
  tool family (`--enable-repair`) the Agent Runtime never even sees a
  session for.
- **Identity survives what Alertmanager's own fingerprint doesn't.**
  `pilot-detection-engine`'s real Alertmanager payload
  (`internal/detection/engine.go`'s `buildAlertPayload`) includes
  `severity` in its label set, so a warning→critical transition on the
  SAME anomaly produces a DIFFERENT Alertmanager-computed fingerprint.
  `internal/agentcontroller/normalize.go` uses `annotations.signal_id`
  as the episode identity for `source=detection-engine` alerts instead —
  Alertmanager's own fingerprint is only the identity for deterministic
  `prometheus-rule` alerts, which have no such transition.
- **Adapted, not fabricated.** The upstream wire payload carries no
  explicit revision number (only labels/annotations/startsAt/endsAt);
  `incidents.current_revision` is therefore the controller's own
  locally-computed monotonic counter, not a pass-through of an upstream
  field. Documented in `normalize.go`, not silently assumed.
- **Bearer token, not HMAC — found via a real disposable-VM deploy, not
  guessed.** The phase-1 design doc's own words ("HMAC/shared-secret")
  were implemented literally at first (HMAC-SHA256 over the raw body),
  then deployed against a real Alertmanager v0.27 on a fresh vm-target.
  Alertmanager's `webhook_configs` sender has no feature to COMPUTE an
  HMAC over its own outgoing body — it can only attach a static
  credential via `http_config.authorization` (Bearer) or
  `http_config.basic_auth`. `http.go` was rewritten to a constant-time
  Bearer-token comparison before any evidence was recorded, so the
  committed implementation matches what a real Alertmanager can actually
  send — an HMAC scheme would only work with a sender this repo controls
  (a hypothetical future in-house forwarder), never stock Alertmanager.

## 3. 元件邊界

- **Runtime**: `cmd/pilot-agent-controller` — a single static binary
  (`CGO_ENABLED=0`, pure-Go SQLite driver via `modernc.org/sqlite`),
  copied to the target the same way as `pilot-detection-engine` (spec
  §14, `scripts/build-agent-controller.sh`).
- **State**: `internal/agentcontroller` owns the SQLite schema
  (`incidents`, `incident_events`, `agent_runs`, `agent_evidence`),
  webhook ingress + bearer-token auth (`http.go`), the incident state machine
  (`incident.go`), and the dispatch scheduler (`queue.go`).
  `cmd/pilot-agent-controller` is a thin CLI/systemd wrapper —
  `version`/`config validate`/`serve`/`status`/`db check`/`db backup`,
  mirroring `pilot-detection-engine`'s own CLI contract.
- **Dispatcher**: `AgentDispatcher` is the only channel to an external
  Agent Runtime (`dispatcher.go`) — `FakeDispatcher` (deterministic, used
  by tests and the disposable-lane evidence) and `HTTPDispatcher` (a
  generic, vendor-agnostic JSON-over-HTTP adapter) are the only two
  implementations Phase 1 ships. No specific Runtime product is wired in
  yet.
- **Delivery**: `playbooks/apply/agent-controller-apply.yml` — preflight
  gates, binary/config/secret deployment, systemd lifecycle. The listener
  binds to this host's own default-routed address (never `0.0.0.0`) per
  spec §5.2's private/network-scoped requirement.
- **Dependencies** (`contracts/agent-controller.yaml`): none required —
  Phase 1 does not auto-detect or call out to any other Pilot-managed
  role. Alertmanager reaches IN via its own manually-configured
  `webhook_configs` route (there is no code-level binding yet; see §5).

## 4. Incident state machine

```
OPEN → QUEUED → INVESTIGATING → DIAGNOSED
  │                              │
  └──────────→ RESOLVED_EXTERNAL ┘

QUEUED/INVESTIGATING → AGENT_FAILED (retried with exponential backoff,
                                      bounded by MaxDispatchAttempts)
```

A replayed identical firing payload (same source+episode+status+severity+
startsAt) is a no-op — `store.go`'s `ux_incidents_active_identity` and
`identityHash` enforce this at both the DB-constraint and normalization
layers. A controller restart marks any in-flight run `AGENT_FAILED` for
audit and reopens its incident `OPEN` for a fresh dispatch through the
SAME scheduler path every other run takes — there is deliberately no
second "resume a stale run" code path.

## 5. 已知限制 / 未做（Phase 1）

- No real external Agent Runtime is wired in — only the fake/HTTP
  dispatcher adapters exist. Whoever integrates a specific Runtime
  product implements `AgentDispatcher`; `IncidentEnvelopeV1`/
  `DiagnosisResult` never gain a vendor-specific field.
- Alertmanager's `webhook_configs` route to this controller is entirely
  operator-configured (via `alertmanager-apply.yml`'s free-form
  `alertmanager_config` variable) — there is no contract-level
  `bindings`/`AutoHostVars` wiring the way `detection-engine.yaml` wires
  its own Thanos/Alertmanager consumption, because the data flows the
  OPPOSITE direction here (Alertmanager pushes to the controller, not the
  other way around).
- No "postmortem mode" for re-dispatching a resolved incident (spec §13
  mentions it as an explicit opt-in that Phase 1 does not implement).
- No HA/active-active; exactly one controller process (spec §3
  non-goals).
- Phase 3 (human-approved R1 remediation), Phase 4 (policy-gated
  autonomous R1), and Phase 5 (controlled R2 reapply) are not yet
  implemented — see `docs/tmp/future/agent-monitoring/README.md` for the
  full plan-set order and phase-exit-gate discipline.

## 6. Phase 2 — structured diagnostic composites

Four bounded, read-only MCP tools (`internal/diagnose/host_health.go`,
`component.go`, `network_path.go`; `internal/changejournal/` for the
fourth) so the Agent asks Pilot a domain question ("is this host
healthy?") instead of assembling low-level commands. All four register
under the SAME `--enable-diagnose` flag and `addRecoveredTool` choke
point as the narrow `pilot_diagnose_*` tools from Phase 1's design (spec
§11) — there is no new capability flag.

- **`pilot_diagnose_component`** is driven entirely by a new, optional
  `diagnostics:` block in `contracts/*.yaml` (`internal/contract`'s
  `Diagnostics` type) — `runtime.kind: docker|systemd|none`,
  `readiness.endpoint`/`path`, `logs.source`, `verifySpec` — with no
  `command:`/`shell:` field possible even in principle
  (`KnownFields(true)` decoding rejects the key outright). Wired into the
  three components the design doc names as representative:
  `prometheus`, `alertmanager` (both docker), `detection-engine`
  (systemd, no HTTP readiness endpoint — it has none, spec §5 non-goal).
- **`pilot_diagnose_recent_changes`** does NOT introduce a second
  competing change-tracking store. `internal/store`'s existing
  `DeliveryRun`/`ListRuns` (SQLite, one row per `pilot deploy` run) is
  already the unified journal Phase 2 §7 asks to check for before adding
  one — `internal/changejournal.QueryDeployChanges` adapts it directly.
  Only MCP edit-apply mutations had no queryable index (just a
  per-invocation `metadata.json` on disk); `QueryEditApplyChanges` reads
  those same files rather than duplicating `pilot_edit_apply`'s own write
  path. There is still no remediation/repair mutation boundary at all —
  `ChangeKindRemediate` exists in the enum for forward compatibility, but
  no query function produces it until Phase 3's own executor exists.

### Real bug found via live testing (2026-09-01)

Both `pilot_diagnose_network_path`'s transport layer and
`pilot_diagnose_component`'s dependency-reachability check originally
used `timeout 2 bash -c 'cat < /dev/tcp/<host>/<port>'`. Verified against
a real `prom/alertmanager:v0.27.0` container: `cat` blocks waiting for
the SERVER to send data first, which no HTTP-like server ever does
before it receives a request — so this reported `closed`/`unreachable`
against a container that `curl` confirmed was serving `200` on the exact
same port at the exact same moment. Fixed to `exec 3<>/dev/tcp/<host>/
<port>` (open the descriptor read-write, never read from it) — a plain
TCP-handshake check, confirmed correct against both a real open port and
a real closed one before landing. `internal/diagnose/network_path.go`
and `component.go` both carry this fix with the same evidence noted
inline.
