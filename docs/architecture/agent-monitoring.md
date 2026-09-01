# Agent Monitoring Architecture

> 完整規格（依 phase 分開撰寫）：
> `docs/superpowers/specs/2026-09-01-agent-monitoring-phase-1-observe-only-controller-spec.md`、
> `docs/superpowers/specs/2026-09-01-agent-monitoring-phase-2-structured-diagnostics-spec.md`、
> `docs/superpowers/specs/2026-09-01-agent-monitoring-phase-3-human-approved-r1-remediation-spec.md`、
> `docs/superpowers/specs/2026-09-01-agent-monitoring-phase-4-autonomous-r1-policy-spec.md`
> （Phase 5 尚在 `docs/tmp/future/agent-monitoring/`，尚未實作 —— 完成後搬一份
> 進來、在這裡補一段）。這份文件只整理架構全貌，不重複規格的
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
- Phase 5 (controlled R2 reapply) is not yet implemented — see
  `docs/tmp/future/agent-monitoring/README.md` for the full plan-set
  order and phase-exit-gate discipline.

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

## 7. Phase 3 — human-approved R1 remediation

The first live repair capability, hard-restricted to **R1**
(single-host restart/reload of an explicitly opted-in stateless
component) and requiring explicit human approval before every single
execution. Authority separation (design doc §2):

```
Agent -> observe MCP (--enable-diagnose) -> recommendation (advisory only)
Operator/Controller CLI -> pilot_repair_plan -> immutable, hashed Plan
Human -> `pilot-agent-controller remediation approve <id> --plan-hash <hash>`
Operator/Controller CLI -> pilot_repair_apply -> execute + verify
```

`internal/repair` (Pilot side) is the planning/execution/verification
core: `ListCapabilities` (only ever returns R1), `BuildPlan` (resolves
every executable field server-side from `contracts/*.yaml`'s new
`remediation:` block — same `KnownFields(true)`-enforced "no command/
shell field possible" guarantee as Phase 2's `diagnostics:` block),
`Execute` (reuses `internal/diagnose`'s own `Step`/`RunSteps`/
`AdHocRunner` — no second ad-hoc execution path), `VerifyAfterExecution`
(reuses `pilot verify`'s own `tools.VerifySpecTool`, never process exit
code alone). Three new MCP tools —
`pilot_repair_capabilities`/`pilot_repair_plan`/`pilot_repair_apply` —
register under a SEPARATE `--enable-repair` flag, independent of
`--enable-diagnose`/`--enable-diagnose-raw`/`--allow-write`.

`internal/agentcontroller` owns ALL stateful workflow (schema v2:
`remediation_plans`/`approvals`/`remediation_runs`) — the repair MCP
process itself is stateless per call, exactly like every other pilot
MCP tool. `RepairClient` is the controller's own connection to that MCP
family: it spawns a private `pilot mcp serve --enable-repair` subprocess
per call (design doc §3's own recommended topology), rather than
importing `internal/repair`'s execution path in-process — the production
ansible-execution machinery (ControlMaster pooling, log rotation,
timeout handling) lives as unexported internals deep in `cmd/pilot/cmd`,
tightly coupled to that binary's own MCP server lifecycle; spawning
`pilot` itself reuses that already-audited surface instead of
duplicating it into a second binary.

The operator-only CLI (`cmd/pilot-agent-controller/remediation_cli.go`:
`incident show`, `remediation propose/show/approve/reject/execute`) is
never called by `serve`'s own scheduler loop or by the Agent — approval
`--actor` always comes from the human invoking the CLI.

### Two real bugs found via live testing (2026-09-01)

1. **Tampered-plan execution bug.** `VerifyPlanFresh` originally
   returned only an error/nil — the caller then executed against the
   CALLER-SUPPLIED plan object, not a freshly-rebuilt one. A plan whose
   `ExecutorTarget` was tampered WITHOUT recomputing `PlanHash` still
   passed the freshness check (the hash was never derived from the
   tampered copy to begin with), so execution would have silently used
   the attacker-chosen target. Caught by a test written to prove the
   opposite ("tampering should be rejected") — the test itself revealed
   the real gap once it passed for the wrong reason. Fixed: `apply`
   always executes against the plan `VerifyPlanFresh` freshly re-derives
   from the CURRENT contract/inventory, never the caller-supplied one —
   a tampered field is simply never read by anything downstream.
2. **Subprocess working-directory bug.** `RepairClient` spawned `pilot
   mcp serve --dir <workspace>` without setting the child process's OWN
   working directory. `--dir` only controls the edit-workspace root;
   contract loading resolves from `$PILOT_ROOT` or the process's actual
   `cwd` — a DIFFERENT root. The spawned child inherited the CONTROLLER's
   own cwd (wherever it happened to be invoked from) and silently failed
   to find `contracts/` at all. Found via a real spawned-subprocess test
   connecting through the actual MCP stdio transport, not simulated.
   Fixed: `cmd.Dir = c.Dir`.

### Real disposable-VM evidence (2026-09-01)

A single vm-target (`host-monitoring` + `docker` + `alertmanager` — the
`alertmanager` contract's own R1 `docker_restart` action, chosen over
`prometheus`'s because it needs no extra S3/Thanos-sidecar
infrastructure to stand up for this narrow purpose and its own
verification spec is fully self-contained). `docker stop
pilot-alertmanager` simulated a real failure; the FULL CLI chain ran for
real: `remediation propose` (real `pilot_repair_plan` MCP round-trip) →
`remediation approve --plan-hash <real hash>` → `remediation execute`
(real `docker restart` via ansible ad-hoc + real `docs/verification/
alertmanager.md` run via `pilot verify`'s own machinery) →
`APPLIED_VERIFIED`. Independently re-confirmed on the VM afterward:
`docker ps` showed the container `Up 30 seconds` and `/-/healthy`
returned `200`.

Negative evidence, all real (not just unit-tested): an unapproved plan
refuses to execute; an approval bound to the wrong plan hash is
rejected; a second `remediation execute` against an already-terminal
plan is rejected (replay protection). A dedicated spawned-binary test
(`TestMCPServe_Integration_RepairToolsAbsentFromObserveOnlyDiagnoseSession`)
proves the single most important safety invariant directly: an MCP
session started with `--enable-diagnose` alone — exactly what an
external Agent Runtime receives — never lists any `pilot_repair_*` tool.

Not independently re-proven in this pass (both already covered
elsewhere, not silently skipped): "Agent recommends restart" (no real
Agent Runtime is wired into any phase yet — an operator proposed the
plan manually, the same honest scope boundary Phase 1/2 already
documented) and "Alertmanager resolves" (Phase 1's own evidence already
proves the webhook delivery chain end to end; Phase 3 adds nothing new
to that specific mechanism).

## 8. Phase 4 — policy-gated autonomous R1 remediation

Extends Phase 3's human-approved R1 workflow with a second, ADDITIONAL
authorization source — a deterministic policy engine — without adding a
new executor, action kind, or execution path. Design doc §3's
"authorization unification" invariant: human approval and policy
approval both flow into the exact same
`Store.Approve → Store.MarkExecuting → RepairClient.Apply → Store.FinishRun`
sequence Phase 3 already proved end to end; they differ only in the
`actor` string recorded on the approval row
(`agentcontroller.PolicyActor(policyID, decisionID)` vs. an operator's
own identity). There is no `autoRestart()` shortcut anywhere in this
codebase.

```
internal/policy.EvaluatePolicy(cfg, autonomy, PolicyInput, now) -> PolicyDecision
                    ^ pure function — no IO, no database, no network
                    |
internal/agentcontroller.GatherPolicyInput  -- assembles PolicyInput from:
    • Store (cooldown/budgets/breakers/prior-episode-failures, all
      DERIVED from approvals+remediation_plans+remediation_runs —
      no separate ledger table)
    • RepairClient.Plan() re-fetch (plan freshness + the contract's own
      resolved autonomy: {sandbox,staging,prod} block)
    • Incident.Status (alert-still-firing)
                    |
`pilot-agent-controller remediation auto-execute <plan-id> --environment <env>`
    1. evaluate + unconditionally persist the decision (policy_decisions)
    2. mode=disabled|shadow -> stop here, plan stays PROPOSED
    3. mode=enforced AND decision=allow_auto -> Store.Approve(actor=policy:...)
       -> MarkExecuting -> RepairClient.Apply -> FinishRun
    4. any non-APPLIED_VERIFIED outcome -> TripBreaker(component) + TripBreaker(host)
```

### Why the policy config has no YAML file

The design doc sketches a versioned `policy.yaml` with `autonomy_mode`
as one of its fields. This implementation instead makes `autonomy_mode`
**durable database state** (`autonomy_state` singleton row,
schema v3), set only via `pilot-agent-controller autonomy enable/
disable --actor --reason`, and keeps `internal/policy.DefaultConfig()`
(cooldown 30m, host budget 2/6h, component budget 5/1h,
sandbox/staging=allow_r1, prod=human_only — exactly design doc §4/§7's
own defaults) as the CLI's baseline, overridable per invocation via
`--cooldown`/`--host-budget-count`/`--host-budget-window`/
`--component-budget-count`/`--component-budget-window` flags. Rationale:
`autonomy enable/disable` must take effect on the very next evaluation
without an operator hand-editing YAML on the controller host — exactly
the same reasoning Phase 3 already applied to `approvals`/
`remediation_plans` being database rows, not files. A future deployment
that wants a persistent non-default cooldown/budget can wrap the CLI
call with its own fixed flag set; no new subsystem was built for that
now that the flags alone don't already cover.

### Where the 15 mandatory guards live

Every guard in design doc §6 is a single `if` branch in
`internal/policy.EvaluatePolicy`, covered by
`TestEvaluatePolicy_TableCases`'s 20 cases (§15's required table plus
extras) — table-testable with zero IO. Two deliberate deviations from a
literal reading of §6, both because §15's own test-case list is more
specific than §6's guard list and this implementation follows the more
specific requirement:

- **Budget exhaustion denies, not requires-human** (§15: "budget
  exhausted -> deny"; §6 itself is silent on which). An exhausted budget
  is a hard stop — routing it to a human queue would let an operator
  approve MORE repairs than the cap allows, defeating the guard's
  purpose.
- **Kill switches (guards 4/5) are not a separate on/off primitive.**
  `GlobalKillSwitch`/`ComponentKillSwitch` in `PolicyInput` are real,
  independently-testable fields at the pure-evaluator level, but the
  LIVE gatherer wires `GlobalKillSwitch` to the SAME `circuit_breakers`
  state `GlobalBreakerOpen` reads, and always reports
  `ComponentKillSwitch = false`. An operator's manual emergency stop
  (`pilot-agent-controller autonomy kill <scope>`) and an
  automatically-tripped breaker carry the identical contract — "does
  not silently self-clear, reset must be audited" (§8) — so they share
  one mechanism (`TripBreaker`/`ResetBreaker`) per scope rather than
  duplicating it. `MaintenanceMode` is likewise always `false` — no
  maintenance-window concept exists elsewhere in this codebase to source
  it from yet; both are documented, not silent, gaps
  (`internal/agentcontroller/policy_evaluate.go`'s own doc comment).

Budgets/cooldown/prior-episode-failure counts are DERIVED from
`approvals`/`remediation_plans`/`remediation_runs` (design doc §11
suggests a separate `action_budgets` ledger table; this implementation
omits it) rather than a second reservation ledger, because every count
only ever reads rows `Store.Approve`'s own transaction already wrote —
there is no second "reservation" step that could itself crash
independently of the approval it represents, which is a stronger
crash-safety property than a separate ledger would give for the same
amount of code. `RecoverOrphanedExecutingPlans` (mirrors Phase 1's
`RecoverInFlightRuns` reasoning exactly: single controller process, no
lease-timestamp arithmetic — anything still `EXECUTING` at startup was
definitely orphaned) closes out the one crash window that DOES need
explicit reconciliation: a CLI process dying between `MarkExecuting` and
`FinishRun`.

### CLI-triggered, not wired into the `serve` scheduler

`serve`'s scheduler (Phase 1) only ever ingests incidents and dispatches
observe-only diagnosis; it has never called `MarkExecuting`/`FinishRun`
in any phase. Phase 4 keeps that boundary: `remediation auto-execute` is
a separate, explicitly-invoked CLI command (an operator, a cron job, or
a future Agent-adjacent trigger all call it the same way), not a new
code path inside the always-running daemon. This was a deliberate scope
decision to avoid risky changes to already-proven production code for
this phase — wiring automatic dispatch into `serve` itself remains
possible future work, not a gap in what Phase 4 claims to deliver.

### Real sandbox evidence (2026-09-01, disposable vm-target)

Same target shape as Phase 3 (`agentctl4`: `host-monitoring` → `docker`
→ `alertmanager`, no agent-controller service redeployment needed — the
webhook delivery chain was already proven end to end in Phase 1/3), plus
a locally-run `pilot-agent-controller serve` fed real Alertmanager-shaped
webhook JSON over HTTP with real bearer-token auth. Every step below is
a real subprocess (`pilot-agent-controller` CLI) driving real ansible
ad-hoc commands and a real `pilot verify` run — nothing simulated except
the two fault injections (`docker stop`, `docker rename`), which
directly imitate the real failure modes those actions exist to fix:

1. **Trigger**: real webhook POST → real incident (`GetIncident`
   returns `DIAGNOSED`, `host=agentctl4 component=alertmanager
   severity=critical`).
2. **Shadow, zero mutation**: `autonomy enable --mode shadow` then
   `remediation auto-execute` → `policy decision: allow_auto (mode=
   shadow)`, plan stays `PROPOSED`; independently confirmed on the VM
   the container was still `Exited` afterward.
3. **Enforced, exactly one repair**: `autonomy enable --mode enforced`
   then the SAME `remediation auto-execute` call →
   `APPLIED_VERIFIED (execution_ok=true verify_passed=true)`.
4. **Verification PASS + source alert resolves**: `docker ps` on the VM
   independently showed `Up`; `pilot verify docs/verification/
   alertmanager.md` independently re-ran **7/7 PASS**; a real `status:
   resolved` webhook for the SAME fingerprint flipped the incident to
   `RESOLVED_EXTERNAL` — the one thing Phase 3's own evidence write-up
   (§7 above) explicitly left "not independently re-proven"; Phase 4
   closes that gap for real.
5. **Immediate retrigger → cooldown blocks**: a second real webhook
   (new fingerprint, SAME host/component) → a fresh incident → a fresh
   plan → `remediation auto-execute` → `policy decision: require_human
   (mode=enforced) reasons=[cooldown active for this host/component/
   action]`; container independently confirmed untouched.
6. **Forced failure → breaker trips, episode capped**: `docker rename
   pilot-alertmanager pilot-alertmanager-renamed` (so `docker restart
   pilot-alertmanager` genuinely fails), then `remediation auto-execute
   --cooldown 1s` (cooldown legitimately overridden via the new CLI
   flag rather than waiting out 30 real minutes) → `EXECUTION_FAILED`,
   both `component:alertmanager` and `host:agentctl4` breakers tripped
   automatically; `autonomy status` showed both `OPEN` with the failing
   plan ID as reason. A THIRD plan proposed against the SAME incident
   episode, evaluated with breakers reset and host/component budgets
   raised out of the way, was denied specifically for `"incident episode
   already had a prior autonomous repair attempt"` — guard 10 in
   isolation, not just budget/breaker/cooldown masking it.
7. **Kill switch blocks action**: `autonomy kill component:alertmanager
   --reason "..."` then `remediation auto-execute` on a still-PROPOSED
   plan → `policy decision: deny reasons=[component circuit breaker is
   open]` (the documented kill-switch/breaker state-sharing design in
   action) — no execution attempted.
8. **Restart → budgets/breakers persist**: every step above was already
   a genuinely separate OS process re-reading the same SQLite file
   (`state.db`) — `autonomy status` after the forced failure showed both
   tripped breakers from a brand-new process with no in-memory state
   carried over. The narrower "CLI dies mid-execution" crash window is
   covered by `TestRecoverOrphanedExecutingPlans` (real SQLite, not
   mocked): a plan stuck `EXECUTING` is closed to a terminal state on
   the next invocation and can never re-execute.

Negative/safety evidence also proven for real in this same run, not
just unit-tested: `disabled` mode leaves a plan `PROPOSED` untouched
even with a hypothetically-passing decision underneath it (checked
before `EvaluatePolicy` is even consulted, per §9's "policy not used for
execution"); `TestEvaluatePolicy_R2NeverEligible` and
`TestEvaluatePolicy_ProdDefaultIsHuman` lock the two hardest exit-gate
invariants (§18: "no R2/R3/R4 is auto-eligible", "prod default remains
human") at the pure-function level across every risk value and even an
explicit contract opt-in, respectively.

### Real gap found while gathering evidence (2026-09-01)

The first implementation had NO way for an operator to manually engage
a kill switch — `TripBreaker` was only ever called internally by the
auto-execute failure path. Discovered attempting to prove evidence
step 7 above, not by inspection: there was no CLI verb to call. Fixed by
adding `pilot-agent-controller autonomy kill <scope> --reason`
(`cmd/pilot-agent-controller/autonomy_cli.go`), which is exactly
`TripBreaker` on the same scope naming convention the failure path
already used — the missing half of the kill-switch/breaker unification
described above, not a new mechanism.
