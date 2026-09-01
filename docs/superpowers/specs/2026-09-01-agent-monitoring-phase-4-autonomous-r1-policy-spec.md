# Agent Monitoring Phase 4 — Policy-gated Autonomous R1 Remediation


> **Repository:** `kjelly/pilot`  
> **Baseline observed:** `e89b96b649264ad94d3a6002293ec2d4defb134a` (2026-09-01)  
> **Delivery discipline:** requirement → verification contract → implementation → disposable/real target evidence.  
> **Before editing:** coding agent MUST re-read the current worktree. If paths or APIs moved after this baseline, preserve the invariants in this plan and adapt to the current source rather than resurrecting stale structure.

## 1. Goal

Allow a narrowly defined subset of the already-proven Phase 3 R1 actions to execute without human approval using a **deterministic policy engine**.

Phase 4 adds no new executor and no new action kind. It changes only the authorization source.

## 2. Fundamental invariant

```text
Agent recommendation != authorization
```

The policy engine evaluates only trusted structured facts. Agent prose/confidence never grants authority.

## 3. Authorization unification

There must be one execution path:

```text
human approval -----+
                    +-> ExecutionAuthorization -> same repair apply -> verify
policy decision ----+
```

```go
type ExecutionAuthorization struct {
    Kind      string // human|policy
    PlanID    string
    PlanHash  string
    Reference string // approval id or policy decision id
}
```

Do not create a shortcut such as `autoRestart()` that bypasses plan hash, journal, repair MCP, or verification.

## 4. Default environment policy

| Environment | R1 | Default |
|---|---|---|
| sandbox | eligible | auto only when all guards pass |
| staging | eligible after evidence | auto only when all guards pass |
| prod | not autonomous | human required |

Component action must explicitly opt in:

```yaml
remediation:
  actions:
    - id: restart
      risk: R1
      autonomy:
        sandbox: allowed
        staging: allowed
        prod: human
```

Missing autonomy block = human required.

## 5. Policy input/output

```go
type PolicyInput struct {
    Plan                         RemediationPlan
    Environment                  string
    IncidentSeverity             string
    IncidentSource               string
    AlertStillFiring             bool
    PriorActionsHostWindow       int
    PriorActionsComponentWindow  int
    PriorFailuresIncident        int
    LastActionAt                 *time.Time
    MaintenanceMode              bool
    GlobalKillSwitch             bool
    ComponentKillSwitch          bool
}

type PolicyDecision struct {
    Decision      string // allow_auto|require_human|deny
    PolicyID      string
    PolicyVersion string
    Reasons       []string
    EvaluatedAt   time.Time
}
```

Persist the decision before execution.

## 6. Mandatory allow guards

Autonomous execution requires ALL:

1. one exact host;
2. risk exactly R1;
3. action contract allows autonomy in environment;
4. global kill switch off;
5. component kill switch off;
6. no blocking maintenance/suppression condition;
7. cooldown expired;
8. host budget available;
9. component budget available;
10. incident episode has no prior failed autonomous repair;
11. plan hash/inventory/contract still current;
12. source incident still firing immediately before execution;
13. no human rejection exists;
14. audit DB/change journal writable;
15. repair/verification infrastructure healthy.

Unknown state is never allow.

## 7. Cooldowns and budgets

Initial bounded defaults:

```text
same host/component/action cooldown: 30m
max auto R1 per host:               2 / 6h
max auto R1 per component:          5 / 1h
max auto R1 per incident episode:   1
```

Configuration may tighten these. Hard maximums prevent accidental unlimited loops.

## 8. Circuit breakers

Persist at least:

```text
global
component
host
```

Trip on:

- repeated autonomous verification failures;
- repair infrastructure unhealthy;
- DB/audit persistence failure;
- repeated stale-plan churn.

A tripped breaker does not silently self-clear in MVP. Operator reset must be audited.

## 9. Kill switch and modes

Modes:

```text
disabled
shadow
enforced
```

- `disabled`: policy not used for execution;
- `shadow`: evaluate/persist `would_allow_auto`, never mutate;
- `enforced`: allow only when all guards pass.

Operational CLI:

```text
pilot-agent-controller autonomy status
pilot-agent-controller autonomy disable --reason "..."
pilot-agent-controller autonomy enable --reason "..."
pilot-agent-controller autonomy reset-breaker <scope> --reason "..."
```

Persist actor/reason/time.

## 10. Pure deterministic evaluator

Keep the decision core pure:

```go
func EvaluatePolicy(cfg PolicyConfig, in PolicyInput) PolicyDecision
```

IO that gathers history/current alert state is outside this function. This makes every allow path table-testable.

## 11. Durable policy state

Add:

```sql
policy_decisions(id, incident_id, plan_id, plan_hash, decision,
                 policy_id, policy_version, reasons_json, created_at);
circuit_breakers(scope, state, reason, tripped_at, reset_at, reset_actor);
action_budgets(scope_key, window_start, count, lease_state, updated_at);
```

Budget reservation + decision persistence must happen atomically before repair call.

Crash after reservation must not cause blind replay. Recover leases explicitly.

## 12. Pre-execution revalidation

Immediately before mutation:

1. reload incident;
2. re-check alert still firing;
3. revalidate plan hash/inventory/contract;
4. re-evaluate kill switches/breakers;
5. reserve budgets atomically;
6. persist policy decision;
7. call same Phase 3 repair apply.

## 13. Failure feedback

On `APPLIED_VERIFIED`:

- keep cooldown/budget record;
- wait for source alert resolution;
- do not mark incident resolved solely from repair success.

On any failed/inconclusive result:

- disable autonomy for that incident episode;
- increment breaker counters;
- future attempts require human.

## 14. Configuration

Use declarative versioned config, no natural-language policy or dynamic code engine:

```yaml
schema_version: 1
autonomy_mode: disabled
defaults:
  cooldown: 30m
  host_budget_count: 2
  host_budget_window: 6h
  component_budget_count: 5
  component_budget_window: 1h
environments:
  sandbox: allow_r1
  staging: allow_r1
  prod: human_only
```

Validator enforces bounds.

## 15. Tests first

Table cases:

- sandbox eligible -> allow;
- prod -> human;
- no component opt-in -> human;
- cooldown active -> deny/human per spec;
- budget exhausted -> deny;
- prior failed auto repair -> human;
- stale plan -> deny;
- alert resolved -> no-op/deny;
- kill switch -> deny;
- breaker open -> deny;
- unknown environment -> human/deny;
- DB decision cannot persist -> no execution.

## 16. Shadow rollout

Shadow mode is mandatory before enforced mode. Collect:

- would-run count;
- components/hosts affected;
- duplicate/cooldown suppressions;
- false-positive recommendations found by humans;
- number of decisions requiring missing evidence.

Do not turn on staging enforced mode until sandbox shadow/enforced evidence is reviewed.

## 17. Actual-run evidence

Sandbox:

1. trigger R1-remediable incident;
2. shadow -> would_allow, zero mutation;
3. enforced -> exactly one repair;
4. verification PASS + source alert resolves;
5. immediate retrigger -> cooldown blocks;
6. force verification failure -> incident autonomy disabled/breaker updated;
7. kill switch blocks action;
8. restart controller -> budgets/breakers persist.

Staging only after sandbox gate. Prod remains human-only in this phase.

## 18. Phase exit gate

- all allow guards have deterministic tests;
- shadow evidence exists;
- autonomous execution is exactly Phase 3 execution path;
- cooldown/budget/breaker/kill-switch state survives restart;
- real sandbox auto-repair verifies end-to-end;
- no R2/R3/R4 is auto-eligible;
- prod default remains human.

## 19. Rollback

Set `autonomy_mode: disabled`. Human-approved R1 and observe-only diagnosis remain available. No managed-host redeploy required.
