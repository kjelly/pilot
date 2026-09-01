# Agent Monitoring Phase 1 — Observe-only Incident Controller


> **Repository:** `kjelly/pilot`  
> **Baseline observed:** `e89b96b649264ad94d3a6002293ec2d4defb134a` (2026-09-01)  
> **Delivery discipline:** requirement → verification contract → implementation → disposable/real target evidence.  
> **Before editing:** coding agent MUST re-read the current worktree. If paths or APIs moved after this baseline, preserve the invariants in this plan and adapt to the current source rather than resurrecting stale structure.

## 1. Goal

Build the first production-safe SRE Agent path while granting **zero mutation authority**. The existing monitoring/detection plane remains authoritative for detecting events:

```text
managed hosts
  -> node_exporter / logs / security telemetry
  -> Prometheus / Loki / Thanos
  -> Prometheus deterministic rules
  -> pilot-detection-engine adaptive SignalEvent
  -> Alertmanager
  -> pilot-agent-controller
  -> external Agent Runtime
  -> Pilot MCP --enable-diagnose
  -> structured diagnosis
  -> durable incident history
```

The Agent Controller is an incident orchestrator and state store. It is not a second anomaly detector and is not an LLM implementation inside `pilot`.

## 2. Current Pilot facts that are normative for this phase

- `pilot-detection-engine` already owns robust-baseline/cohort/model-assisted detection and emits `SignalEvent` to Alertmanager.
- Detection Engine explicitly declares auto-remediation a non-goal. Preserve `SignalEvent -> Alertmanager -> SRE Agent/Human -> optional controlled Pilot action`.
- `pilot mcp serve --enable-diagnose` already provides fixed read-only live diagnostics, including metrics/log/security/DNS/login/sudo and Detection Engine diagnostics.
- `--enable-diagnose-raw` is a separate high-risk command runner. The unattended Agent MUST NOT receive it.
- `--allow-write` / `pilot_edit_apply` mutate the local workspace. They are not needed here and MUST NOT be enabled.
- Alertmanager remains the common routing/dedup layer. The controller must not poll Thanos as its primary incident source.

## 3. Non-goals

- no remediation execution;
- no SSH credential owned by controller/Agent Runtime;
- no arbitrary Ansible module or command;
- no replacement of Alertmanager, Thanos, Loki or Detection Engine;
- no new mathematical anomaly detector;
- no Kafka/NATS requirement for MVP;
- no HA controller;
- no public Internet listener.

## 4. New component

Add a separately deployable Go service:

```text
binary:  pilot-agent-controller
role:    agent-controller
service: pilot-agent-controller.service
state:   /var/lib/pilot/agent-controller/state.db
```

Recommended code split:

```text
cmd/pilot-agent-controller/main.go
internal/agentcontroller/config.go
internal/agentcontroller/http.go
internal/agentcontroller/normalize.go
internal/agentcontroller/store.go
internal/agentcontroller/migrations.go
internal/agentcontroller/state.go
internal/agentcontroller/queue.go
internal/agentcontroller/dispatcher.go
internal/agentcontroller/result.go
```

The controller talks to an **external Agent Runtime** through a typed `AgentDispatcher` interface. Runtime-specific protocol details must stay behind an adapter. A Hufu/Agent-Protocol adapter can be implemented later without changing the incident schema.

## 5. Alertmanager ingress

Add a webhook receiver while preserving human receivers.

Requirements:

1. `send_resolved: true`.
2. Endpoint is private/network-scoped.
3. Authenticate with mTLS or an HMAC/shared-secret mechanism. Unauthenticated webhooks fail closed.
4. Apply a strict body-size limit and bounded annotations.
5. Return 2xx only after durable DB commit.
6. Controller failure must not block Alertmanager's other receivers.
7. Never log the full webhook payload at info level; persist body hash and sanitized normalized fields.

## 6. Canonical event model

Normalize Prometheus rule alerts and Detection Engine alerts into one internal event:

```go
type IncidentEvent struct {
    Source        string            // prometheus-rule | detection-engine
    GroupKey      string
    Fingerprint   string
    Episode       string
    Revision      int64
    Status        string            // firing | resolved
    AlertName     string
    Severity      string
    Host          string            // canonical pilot_host when available
    Site          string
    Component     string
    Category      string
    StartsAt      time.Time
    EndsAt        *time.Time
    Labels        map[string]string
    Annotations   map[string]string
    RawBodySHA256 string
    ReceivedAt    time.Time
}
```

Identity rules:

- Detection Engine: preserve the source fingerprint/episode/revision. Do not recompute anomaly identity.
- Deterministic alerts: use Alertmanager fingerprint + active firing episode.
- Prefer `pilot_host` for managed-host identity; never reverse-DNS an IP to invent an inventory host.
- Missing host is valid for global/service incidents, but host-scoped diagnose tools then cannot be invoked.

## 7. Incident state machine

```text
OPEN -> QUEUED -> INVESTIGATING -> DIAGNOSED
  |                                |
  +-----------> RESOLVED_EXTERNAL -+

QUEUED/INVESTIGATING -> AGENT_FAILED
any nonterminal      -> SUPPRESSED
terminal             -> CLOSED
```

Rules:

- repeated identical firing payloads do not create concurrent Agent runs;
- one active Agent run per incident;
- `resolved` never deletes evidence;
- Agent failure never marks the source alert resolved;
- controller restart must recover leases deterministically.

## 8. SQLite schema

Use SQLite WAL + foreign keys + busy timeout + explicit migrations.

Minimum tables:

```sql
incidents(id, source, source_fingerprint, source_episode, status, severity,
          host, component, opened_at, updated_at, resolved_at, current_revision);
incident_events(id, incident_id, event_kind, source_revision,
                payload_json, payload_sha256, created_at);
agent_runs(id, incident_id, state, attempt, started_at, finished_at,
           input_sha256, output_json, error_class, error_text);
agent_evidence(id, run_id, kind, source_tool, reference, summary, created_at);
```

Constraints:

- ingestion + incident update in one transaction;
- unique replay key prevents duplicate append/dispatch;
- bounded retained raw/sanitized output;
- process-restart tests use a real temp SQLite DB.

## 9. Agent input contract

Create a versioned `IncidentEnvelopeV1`:

```json
{
  "schema_version": 1,
  "incident_id": "...",
  "source": "detection-engine",
  "status": "firing",
  "alert": {
    "name": "AdaptiveHostAnomaly",
    "severity": "critical",
    "host": "web-1",
    "site": "hq",
    "component": "host"
  },
  "diagnostic_policy": {
    "mutation_allowed": false,
    "raw_command_allowed": false,
    "workspace_write_allowed": false
  }
}
```

Do not dump the entire Alertmanager body into the prompt. Keep normalized context small and deterministic.

## 10. Agent output contract

Controller accepts structured output only:

```go
type DiagnosisResult struct {
    SchemaVersion          int
    Verdict                string  // explained|probable|insufficient_evidence|false_positive|agent_error
    Confidence             float64
    Summary                string
    SuspectedCause         string
    Evidence               []DiagnosisEvidence
    RecommendedNextActions []RecommendedAction
}
```

Validation:

- confidence in `[0,1]`;
- evidence names a Pilot diagnose tool or immutable evidence source;
- recommended actions are advisory only;
- malformed output = `AGENT_FAILED`, not a partial diagnosis;
- no prose parser controls incident state.

## 11. Observe-only MCP security gate

Agent Runtime must launch/connect only to an MCP session equivalent to:

```text
pilot mcp serve --dir <workspace> \
  --enable-diagnose \
  --diagnose-inventory <inventory>
```

Forbidden:

```text
--enable-diagnose-raw
--allow-write
```

At runtime startup, enumerate MCP capabilities and fail closed if any raw-command or mutation tool is visible. Add a regression test for this exact property.

## 12. Dispatcher interface

```go
type AgentDispatcher interface {
    Diagnose(ctx context.Context, in IncidentEnvelopeV1) (DiagnosisResult, error)
}
```

Production adapter requirements:

- configured endpoint/transport; incident cannot choose executable/URL;
- fixed timeout;
- explicit environment-variable allowlist;
- no `sh -c` or string command concatenation;
- health probe separate from diagnosis request;
- fake dispatcher for unit/integration tests.

## 13. Scheduling semantics

- global max Agent concurrency configurable and bounded;
- max 1 active run per host in MVP;
- retry transport/runtime failure only;
- do not retry a valid `insufficient_evidence` result automatically;
- exponential backoff with cap;
- resolved incident waiting in queue is skipped unless postmortem mode is explicitly enabled.

## 14. Deployment contract

Create:

```text
contracts/agent-controller.yaml
docs/verification/agent-controller.md
playbooks/apply/agent-controller-apply.yml
group_vars/agent-controller.example.yml
scripts/build-agent-controller.sh
```

Update current catalog/site/network files according to today's repo mechanism. `playbooks/apply/agent-controller-apply.yml` MUST satisfy the tag-coverage ratchet enforced by `cmd/pilot/cmd/tag_coverage_test.go` (every task tag mapped, no orphan tags) — run that test locally before opening a PR, do not discover it only in CI.

Systemd hardening minimum:

```text
User=pilot-agent
Group=pilot-agent
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
CapabilityBoundingSet=
AmbientCapabilities=
```

Controller account must not own SSH keys or Ansible vault password files. State DB must be included in backup policy because it is durable incident history.

## 15. Verification rows to write before implementation

At minimum:

- C1 unprivileged service account and hardening;
- C2 private listener only;
- C3 invalid webhook auth rejected;
- C4 valid firing creates one incident;
- C5 replay creates no duplicate incident/run;
- C6 resolved updates same episode;
- C7 Detection Engine fingerprint/episode/revision preserved;
- C8 Agent MCP exposes no raw/write tools;
- C9 valid diagnosis persisted;
- C10 malformed Agent output -> AGENT_FAILED;
- C11 restart preserves DB state;
- C12 controller outage does not break other Alertmanager receivers;
- C13 idempotent apply changed=0.

## 16. Implementation tasks

### Task 1 — spec/contract/regressions

Write verification spec and component contract first. Add catalog/site/network/persistent-data regression tests before service code.

### Task 2 — ingress + auth

TDD: bad signature, oversized body, invalid timestamps, multiple alerts, firing/resolved mix, missing fingerprint.

### Task 3 — store + lifecycle

Implement migrations, transaction boundaries, dedup constraints, dispatch lease, restart recovery, retention bounds.

### Task 4 — dispatcher adapter

Implement interface + fake. Add the chosen external Agent Runtime adapter without leaking protocol-specific fields into core types.

### Task 5 — queue + retries

Implement bounded scheduler and exact retry semantics.

### Task 6 — status/metrics

Provide `pilot-agent-controller status --json` with DB/queue/runtime health. Export operational metrics through current authenticated/Pilot monitoring convention; never expose diagnosis text as metric labels.

### Task 7 — deployment and backup

Static pinned artifact pattern, SHA256 verification, service account, systemd hardening, state backup.

## 17. Actual-run evidence

Disposable lane:

1. deploy Alertmanager + controller + fake Agent Runtime;
2. invalid auth rejected;
3. firing webhook -> one incident/run;
4. replay 3x -> still one active run;
5. structured diagnosis persists;
6. controller restart -> incident remains;
7. resolved webhook closes same incident;
8. prove observe MCP tool list excludes raw/write;
9. reapply controller -> changed=0.

Real-chain lane:

- use a real deterministic alert and a real Detection Engine SignalEvent when topology is available;
- both must normalize into the same incident framework without losing source identity.

Save sanitized evidence per `AGENTS.md` rules.

## 18. Phase exit gate

Phase 1 is complete only when all verification rows PASS on the same candidate revision/tree, real/fixture event lanes satisfy repository evidence policy, no mutation/raw tool is visible to the Agent, and existing monitoring/detection regressions remain green.

## 19. Rollback

Disable/remove the Alertmanager Agent receiver route. Existing Alertmanager notifications and Detection Engine continue unchanged. No managed-host redeploy is required.
