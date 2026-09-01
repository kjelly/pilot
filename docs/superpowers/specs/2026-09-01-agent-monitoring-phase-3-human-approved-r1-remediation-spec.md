# Agent Monitoring Phase 3 — Human-approved R1 Remediation


> **Repository:** `kjelly/pilot`  
> **Baseline observed:** `e89b96b649264ad94d3a6002293ec2d4defb134a` (2026-09-01)  
> **Delivery discipline:** requirement → verification contract → implementation → disposable/real target evidence.  
> **Before editing:** coding agent MUST re-read the current worktree. If paths or APIs moved after this baseline, preserve the invariants in this plan and adapt to the current source rather than resurrecting stale structure.

## 1. Goal

Introduce the first live repair capability, limited to **R1** and requiring explicit human approval for every execution.

Risk model:

```text
R0 = diagnostics/read-only
R1 = single-host restart/reload of explicitly opted-in stateless component
R2 = canonical idempotent component reapply/reconcile
R3 = inventory/DNS/FreeIPA/firewall/security-policy mutation
R4 = destructive delete/decommission/data-loss-capable action
```

Phase 3 implements only R1.

## 2. Authority separation

```text
Agent -> observe MCP -> recommendation
Controller -> Pilot repair plan -> immutable plan
Human -> approves exact plan hash
Controller -> repair MCP -> execute
Pilot -> verify + audit + change journal
```

The Agent never receives repair MCP transport/capabilities.

Do not implement repair using:

```text
pilot_diagnose_run
pilot_edit_apply
generic ansible-playbook API
shell/command passthrough
```

## 3. Separate repair MCP family

Add a distinct flag and tool family:

```text
pilot mcp serve --enable-repair

pilot_repair_capabilities
pilot_repair_plan
pilot_repair_apply
```

`--enable-repair` is independent from `--enable-diagnose`, `--enable-diagnose-raw`, and `--allow-write`.

All three `pilot_repair_*` tools register through `addRecoveredTool` (`cmd/pilot/cmd/mcp_tool_recovery.go`), never raw `mcp.AddTool`, matching the existing `pilot_diagnose_*`/`pilot_edit_*` registrations. A panic inside a repair handler must not take down the MCP transport for concurrent sessions.

Naming caution: this repo already has an unrelated `--repair-managed` flag and `repair_identity_drift` code path for FreeIPA identity-drift reconciliation (`cmd/pilot/cmd/identity_drift_cli.go`). It does not collide with `pilot_repair_*`/`--enable-repair` here, but keep the two "repair" concepts clearly separated in naming/review — this family is remediation execution via the Agent Controller, that one is a standalone identity-drift CLI.

Recommended production topology:

```text
Agent Runtime: observe MCP only
Agent Controller: owns private repair MCP process/session
```

## 4. Component remediation contract

Absence means no repair permission.

Example Docker R1:

```yaml
remediation:
  actions:
    - id: restart
      risk: R1
      executor:
        kind: docker_restart
        target: pilot-prometheus
      maxTargets: 1
      requiresApproval: true
      cooldown: 30m
      verification:
        spec: docs/verification/prometheus.md
```

Systemd example:

```yaml
remediation:
  actions:
    - id: restart
      risk: R1
      executor:
        kind: systemd_restart
        target: pilot-detection-engine.service
      maxTargets: 1
      requiresApproval: true
      verification:
        spec: docs/verification/detection-engine.md
```

Allowed executor kinds in first slice:

```text
docker_restart
systemd_restart
systemd_reload   # only if actual semantics/evidence exist
```

There is intentionally no generic `command`, `args`, `playbook`, `extra_vars`, or `sudo` field.

## 5. Immutable RemediationPlan

```go
type RemediationPlan struct {
    SchemaVersion     int
    ID                string
    IncidentID        string
    Host              string
    Component         string
    Action            string
    Risk              string
    ExecutorKind      string
    ExecutorTarget    string
    VerificationSpec  string
    InventoryRevision string
    ContractHash      string
    PlanHash          string
    CreatedAt         time.Time
    ExpiresAt         time.Time
}
```

Plan rules:

- exact known inventory host;
- component assigned to host;
- action declared in component contract;
- R1 only;
- one target exactly;
- executor target resolved from contract, never Agent input;
- verification spec resolved at plan time;
- hash covers every executable field;
- expired/stale inventory or contract rejects apply;
- no secret values.

## 6. Agent recommendation is not executable

Agent may return:

```json
{
  "kind": "restart_component",
  "host": "web-1",
  "component": "prometheus",
  "reason": "runtime unhealthy after recent deploy"
}
```

Controller asks `pilot_repair_plan` to validate/resolve this. If Pilot rejects it, record the recommendation as unsupported and stop.

## 7. Human approval record

Suggested operator CLI:

```text
pilot-agent-controller incident show <incident-id>
pilot-agent-controller remediation show <plan-id>
pilot-agent-controller remediation approve <plan-id> --reason "..."
pilot-agent-controller remediation reject <plan-id> --reason "..."
```

Approval must bind to `plan_id + plan_hash`:

```go
type ApprovalRecord struct {
    ID        string
    PlanID    string
    PlanHash  string
    Decision  string
    Actor     string
    Reason    string
    CreatedAt time.Time
}
```

Actor identity comes from trusted operator context, never Agent text.

## 8. Execution semantics

Pilot performs one typed action on one exact host.

- Docker restart uses the current deterministic Ansible/Docker path and exact contract container name.
- systemd restart uses `systemd_service` or equivalent typed runner and exact contract unit.
- no wildcard host/unit/container.
- no automatic retry in Phase 3.
- append Phase 2 change journal `kind=remediate`.

## 9. Verification is mandatory

Success criteria are not process exit code.

After action:

1. execute component verification spec via existing Pilot verify machinery;
2. run `pilot_diagnose_component`/readiness checks;
3. observe relevant Alertmanager incident state for bounded period;
4. persist result/evidence.

Result enum:

```text
APPLIED_VERIFIED
APPLIED_ALERT_STILL_FIRING
EXECUTION_FAILED
VERIFICATION_FAILED
VERIFICATION_INCONCLUSIVE
PLAN_STALE
```

A resolved alert with failed verification is still remediation failure.

## 10. Controller persistence additions

```sql
remediation_plans(... plan_hash, incident_id, host, component, action, risk,
                  state, created_at, expires_at ...);
approvals(... plan_id, plan_hash, actor, decision, reason, created_at ...);
remediation_runs(... plan_id, started_at, finished_at, result,
                 audit_ref, verify_ref ...);
```

State machine:

```text
PROPOSED -> APPROVED -> EXECUTING -> APPLIED_VERIFIED
         -> REJECTED
         -> EXPIRED
APPROVED -> STALE
EXECUTING -> EXECUTION_FAILED | VERIFICATION_FAILED | VERIFICATION_INCONCLUSIVE
```

Replay of an already executed approved plan must fail.

## 11. Proposed files

Pilot side:

```text
internal/repair/capabilities.go
internal/repair/plan.go
internal/repair/executor.go
internal/repair/verify.go
cmd/pilot/cmd/mcp_repair_tools.go
cmd/pilot/cmd/mcp_repair_test.go
cmd/pilot/cmd/mcp.go
internal/contract/contract.go
internal/contract/lint.go
```

Controller side:

```text
internal/agentcontroller/remediation.go
internal/agentcontroller/approval.go
internal/agentcontroller/remediation_store.go
```

Opt in only components with actual evidence. Start with one Docker and one systemd component if both are reviewed safe; otherwise narrow scope instead of fabricating coverage.

## 12. Contract/linter tests

- no remediation block -> zero actions;
- duplicate IDs rejected;
- invalid risk/executor enum rejected;
- wildcard/empty executor target rejected;
- `maxTargets != 1` rejected for Phase 3;
- R2/R3/R4 rejected by repair planner;
- verification spec must exist/belong to component;
- command/shell fields cannot be represented by typed schema.

## 13. Implementation tasks

### Task 1 — threat model/spec first

Document privilege path, exact target rules, approval ownership, verification failure behavior and why raw diagnose is not used.

### Task 2 — repair capability discovery

Return only contract-declared actions applicable to current inventory.

### Task 3 — immutable plan

Minimal input: incident id, exact host, component, action. Resolve all execution metadata server-side.

### Task 4 — Controller recommendation ingestion

Convert Agent recommendation into plan request; unsupported recommendation is non-executable evidence only.

### Task 5 — approval UX

Show incident evidence, host/component/action/risk, plan hash/expiry, exact verification contract. Default is no-op/reject.

### Task 6 — executor

Reuse Pilot isolated Ansible runtime. Exact one host. Timeouts and structured step evidence. No shell.

### Task 7 — verify and audit

Write audit artifact + change journal + verification result before closing run.

## 14. Actual-run evidence

Positive lane(s):

1. safely stop a selected Docker/systemd component in disposable sandbox;
2. alert incident created;
3. Agent recommends restart;
4. Pilot produces R1 plan;
5. human approves exact hash;
6. repair executes exactly one host;
7. verification PASS;
8. Alertmanager resolves.

Negative evidence:

- Agent session has no repair tools;
- unapproved plan cannot execute;
- stale/changed plan invalidates approval;
- wildcard host rejected;
- unsupported component/action rejected;
- verification failure is not success;
- same approval cannot replay execution.

## 15. Phase exit gate

Every R1 action remains human-approved; no R2/R3/R4 can be expressed/executed; real target evidence proves typed executor + verification + audit; Phase 1/2 observe-only Agent boundary remains intact.

## 16. Emergency rollback

Disable controller remediation feature and stop private repair MCP. Observe-only incident diagnosis continues.
