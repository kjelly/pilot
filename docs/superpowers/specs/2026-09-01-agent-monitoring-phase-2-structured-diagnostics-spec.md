# Agent Monitoring Phase 2 — Structured Diagnostic Abstractions


> **Repository:** `kjelly/pilot`  
> **Baseline observed:** `e89b96b649264ad94d3a6002293ec2d4defb134a` (2026-09-01)  
> **Delivery discipline:** requirement → verification contract → implementation → disposable/real target evidence.  
> **Before editing:** coding agent MUST re-read the current worktree. If paths or APIs moved after this baseline, preserve the invariants in this plan and adapt to the current source rather than resurrecting stale structure.

## 1. Goal

Add four bounded, read-only composite diagnostics so the Agent asks Pilot domain questions rather than assembling low-level commands:

```text
pilot_diagnose_host_health
pilot_diagnose_component
pilot_diagnose_network_path
pilot_diagnose_recent_changes
```

Existing narrow tools remain available for drill-down:

```text
pilot_diagnose_metrics
pilot_diagnose_logs
pilot_diagnose_security_logs
pilot_diagnose_dns
pilot_diagnose_sudo
pilot_diagnose_login
pilot_diagnose_detection
```

No mutation is introduced in Phase 2.

## 2. Security invariants

- host input resolves to exactly one inventory host; `all`, `*`, group patterns fail closed;
- component resolves from current `contracts/*.yaml` and must actually be assigned to the host;
- network destination resolves from typed contract endpoints; caller cannot provide arbitrary `host:port`;
- no composite accepts shell text, arbitrary Ansible module/args, or user-supplied command;
- recent-change output contains metadata/audit references only, never secret values;
- every deterministic finding includes underlying evidence, not prose-only conclusions.
- all four new tools register through `addRecoveredTool` (`cmd/pilot/cmd/mcp_tool_recovery.go`), never raw `mcp.AddTool` — this is the panic-isolation choke point added 2026-08-21 after a handler panic took down the whole MCP transport; every existing `pilot_diagnose_*` tool in `cmd/pilot/cmd/mcp_diagnose_tools.go` already goes through it, follow that exact pattern.

## 3. `pilot_diagnose_host_health`

Input:

```go
type DiagnoseHostHealthInput struct {
    Host     string `json:"host"`
    Lookback string `json:"lookback,omitempty"` // default 30m, bounded
}
```

Fixed evidence set:

- exact host reachability;
- uptime/boot time;
- current load;
- CPU saturation trend from Thanos;
- memory pressure/available memory;
- filesystem free bytes and inode pressure for relevant mounts;
- failed systemd units, bounded list;
- clock sync state;
- interface/link summary;
- node_exporter scrape/up state;
- OOM/kernel error evidence from existing log path when available;
- active Detection Engine signal summary for host when Detection Engine exists.

Output:

```text
healthy | degraded | unreachable | insufficient_evidence
```

Pilot reports deterministic findings; Agent performs higher-level root-cause reasoning.

## 4. `pilot_diagnose_component`

Input:

```go
type DiagnoseComponentInput struct {
    Host      string
    Component string
    Lookback  string
}
```

Introduce optional component diagnostic metadata instead of a forever-growing switch statement:

```yaml
diagnostics:
  runtime:
    kind: docker
    name: pilot-prometheus
  readiness:
    endpoint: prometheus
    path: /-/ready
  logs:
    source: docker
    lookback: 30m
  verifySpec: docs/verification/prometheus.md
```

First supported runtime kinds:

```text
docker
systemd
none
```

Explicitly forbid a `command:` field.

Return:

- runtime present/running state;
- readiness endpoint status;
- bounded recent error summary;
- dependency endpoint reachability;
- verification spec reference;
- raw step evidence.

Start with representative components: `prometheus`, `alertmanager`, `detection-engine` if current contracts support them.

## 5. `pilot_diagnose_network_path`

Input must identify a contract endpoint, not an arbitrary socket:

```go
type DiagnoseNetworkPathInput struct {
    SourceHost string
    Component  string
    Endpoint   string
    Host       string // only where endpoint placement requires destination host
}
```

Fixed layers:

```text
name_resolution
routing
transport
tls
application_readiness
```

From the exact source host:

1. resolve declared destination;
2. inspect route;
3. TCP connect declared contract port;
4. validate TLS where scheme requires it;
5. optional readiness call only to declared HTTP endpoint/path;
6. surface Pilot network/firewall expectation as metadata.

Never silently use `-k`/insecure TLS to turn certificate failure into success.

## 6. `pilot_diagnose_recent_changes`

Purpose: answer "what changed shortly before this incident?"

Input:

```go
type DiagnoseRecentChangesInput struct {
    Host      string
    Component string
    Start     string
    End       string
    Limit     int
}
```

Default controller usage should query `[incident_start-lookback, incident_start]`, not `[now-lookback, now]` after an Agent run has already consumed time.

Sources must be Pilot-owned durable metadata:

- MCP edit plan/apply audit artifacts;
- deploy/reconcile outcomes;
- future remediation outcomes;
- bounded controller-side Ansible/deploy metadata only where safely correlated.

Do **not** label Detection Engine signal revisions as deployment changes.

## 7. Add a Pilot change journal if a unified one does not exist

Suggested record:

```go
type ChangeRecord struct {
    ID                string
    Kind              string // edit_apply|deploy|reconcile|remediate
    StartedAt         time.Time
    FinishedAt        time.Time
    Actor             string
    WorkspaceRevision string
    InventoryRef      string
    Hosts             []string
    Components        []string
    Result            string
    ChangedCount      int
    AuditRef          string
}
```

Properties:

- append-only;
- canonical sorted host/component lists;
- no vault values, passwords, tokens, private keys, or secret env contents;
- record success and failure after final outcome is known;
- concurrency-safe and durable;
- audit persistence failure policy explicitly documented. For live mutation, fail closed if current Pilot audit policy requires it.

Possible files:

```text
internal/changejournal/journal.go
internal/changejournal/query.go
internal/changejournal/*_test.go
```

Instrument current mutation boundaries rather than scraping terminal logs:

```text
MCP edit apply
pilot deploy
pilot reconcile
future repair apply
```

## 8. Proposed source files

```text
internal/diagnose/host_health.go
internal/diagnose/component.go
internal/diagnose/network_path.go
internal/diagnose/recent_changes.go
cmd/pilot/cmd/mcp_diagnose_tools.go
cmd/pilot/cmd/mcp_diagnose_test.go
internal/changejournal/*
```

Likely contract files:

```text
internal/contract/contract.go
internal/contract/lint.go
internal/contract/fixture_schema_test.go
contracts/prometheus.yaml
contracts/alertmanager.yaml
contracts/detection-engine.yaml
```

Use the current schema evolution policy; do not bump versions casually.

## 9. Verification contract

Add rows proving:

- exact host rejection for patterns/groups;
- bounded duration/output;
- component/host assignment enforcement;
- arbitrary port/URL cannot be probed;
- TLS verification is fail-closed;
- missing optional Loki/Detection source returns partial evidence, not panic;
- recent-change journal redacts secrets;
- all composites include raw step evidence;
- tools register only under `--enable-diagnose`;
- `--enable-diagnose-raw` remains independent.

## 10. Implementation tasks

### Task 1 — extract shared safe primitives

Reuse exact-host validation, duration parsing, Ansible read-only runner, central Thanos/Loki resolution, truncation and error taxonomy. Do not expose a generic executor.

### Task 2 — implement host health

TDD cases: healthy, SSH unreachable, node exporter down but SSH works, disk pressure, OOM evidence, Thanos down, Detection Engine absent, output truncation.

### Task 3 — add diagnostic contract metadata

Linter checks:

- runtime kind enum;
- runtime target non-empty and no wildcard;
- endpoint reference exists;
- verification spec belongs to component;
- no command/shell field exists.

### Task 4 — implement component diagnostic

TDD: wrong host, unknown component, stopped runtime, readiness fail, dependency unreachable, missing logs, healthy.

### Task 5 — implement network path

Tests must prove strings containing shell metacharacters or alternate ports cannot alter the derived probe target.

### Task 6 — change journal writer

Instrument edit/deploy/reconcile outcomes. Add restart/concurrency tests and secret-redaction tests.

### Task 7 — recent changes query

Filter by time/host/component, return compact records + immutable audit refs, not full transcripts.

### Task 8 — Agent Controller integration

Preferred diagnostic sequence for host/component incidents:

```text
host_health
recent_changes
component and/or network_path
existing narrow tools as needed
```

This is guidance, not a hard-coded chain for every incident.

## 11. Actual-run evidence

Disposable multi-host topology with monitored host + metrics chain + Alertmanager + controller.

Inject real sandbox failures:

1. stop a declared component;
2. create safe filesystem pressure on disposable mount;
3. break one declared endpoint path;
4. make a real Pilot change immediately before an alert;
5. prove recent_changes reports that change and excludes unrelated records.

For each case keep deterministic tool evidence and Agent diagnosis evidence separately.

## 12. Phase exit gate

Complete only when all four tools have target evidence, no arbitrary command/port/pattern input exists, change journal is secret-safe, and the Phase 1 Agent remains observe-only.

## 13. Rollback

The composite tools are additive. Disable Agent dispatch or deploy the prior Pilot binary. Existing monitoring/detection is unaffected.
