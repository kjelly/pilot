# Agent Monitoring Phase 5 — Controlled R2 Single-host Reapply


> **Repository:** `kjelly/pilot`  
> **Baseline observed:** `e89b96b649264ad94d3a6002293ec2d4defb134a` (2026-09-01)  
> **Delivery discipline:** requirement → verification contract → implementation → disposable/real target evidence.  
> **Before editing:** coding agent MUST re-read the current worktree. If paths or APIs moved after this baseline, preserve the invariants in this plan and adapt to the current source rather than resurrecting stale structure.

## 1. Goal

Add R2 repair: reapply one component's **canonical Pilot apply path** to one exact host. R2 may change packages/files/configuration and restart services, so every R2 action remains **human-approved in all environments** in this phase.

## 2. Agent authority remains minimal

Agent may request only:

```text
reapply component X on host Y
```

Agent cannot provide:

```text
playbook path
inventory path
Ansible module/args
extra vars
tags/skip-tags
limit expression
stage override
vault path
secret value
shell command
```

Pilot resolves canonical execution from component contract + inventory + existing configuration.

## 3. R2 eligibility gate

A component is R2-eligible only if all are proven:

1. explicit contract opt-in;
2. canonical `playbooks.apply` exists;
3. actual idempotency evidence exists;
4. verification spec exists;
5. required non-secret inputs are deterministically resolvable;
6. required secrets have existing Pilot-owned reference paths;
7. exact-host scoping is safe;
8. stage gates remain enforced;
9. normal apply is not destructive/decommission behavior;
10. required dependencies can be health-checked before reapply;
11. no unsafe multi-host transaction is needed.

Unknown = not eligible.

## 4. Initial scope exclusions

Do not start R2 with control-plane/security identity components. Keep out until separate reviewed work:

```text
FreeIPA primary/replica
identity roster changes
DNS authority mutation
firewall/security policy
CA changes
NFS/storage destructive mutation
backup restore
delete/decommission
```

Prefer first candidates among observability/stateless components with strong idempotency evidence, after rereading current contracts.

## 5. Contract declaration

```yaml
remediation:
  actions:
    - id: reapply
      risk: R2
      executor:
        kind: canonical_apply
      maxTargets: 1
      requiresApproval: true
      verification:
        spec: docs/verification/prometheus.md
      preflight:
        requireIdempotencyEvidence: true
        requireDependencyHealth: true
```

`canonical_apply` contains no caller-configurable playbook field. Server resolves contract `playbooks.apply`.

## 6. R2 plan contents

Extend immutable repair plan with resolved metadata:

```go
type ReapplyResolvedInput struct {
    PlaybookPath        string
    PlaybookHash        string
    TargetHost          string
    Stage               string
    ResolvedInputKeys   []string
    SecretReferenceKeys []string
    DependencySnapshot  []DependencyStatus
    PreviewRef          string
}
```

Never store secret values.

Plan hash covers:

- incident/host/component/action;
- inventory revision;
- contract hash;
- playbook path/hash or repository revision;
- stage;
- resolved safe non-secret inputs;
- secret **reference identifiers** only;
- dependency snapshot refs;
- preview ref/hash;
- verification spec.

Any change requires replan/reapproval.

## 7. Secret resolution

Rules:

- Agent output contains no secrets;
- Controller DB contains no plaintext deploy secrets;
- plan output contains no plaintext secrets;
- apply resolves secrets at execution time using existing Pilot vault/value_env mechanisms;
- missing required secret reference blocks planning/preflight;
- audit/preview/change journal redact values;
- never ask the Agent to invent a missing credential.

## 8. Canonical apply executor

Implement typed executor, not generic playbook runner API:

```text
resolve exact host
resolve component contract
resolve playbooks.apply
resolve current host role membership
resolve trusted stage
resolve required inputs and secret refs
validate dependencies
run completeness/preflight gates
run check/diff preview when supported
execute canonical apply with exact host scope
run verification spec
append change journal
return structured result
```

Reuse current Pilot `ansible.Runner`, isolated Ansible runtime, timeouts, stage gates and deploy-completeness logic.

## 9. Preview/check-mode policy

Plan should produce a sanitized preview when component evidence says check mode is supported.

Approval view shows:

```text
would-change summary
warnings
estimated changed count when reliable
unsupported-check-mode reason if explicitly documented
```

Do not silently treat check-mode failure as "skip preview".

## 10. Dependency preflight

Resolve required dependencies from component contract/bindings. Use Phase 2 component/network diagnostics.

Example for Prometheus:

- same-host Docker runtime healthy;
- S3 provider reachable;
- Alertmanager provider reachable;
- host-monitoring target set is optional according to contract.

If a required provider is down, block reapply instead of repeatedly reconfiguring the consumer.

## 11. Result taxonomy

```text
PREVIEW_BLOCKED
PLAN_STALE
APPLY_FAILED_ROLLED_BACK
APPLY_FAILED_PARTIAL
APPLIED_VERIFIED
APPLIED_VERIFICATION_FAILED
APPLIED_ALERT_STILL_FIRING
```

Do not claim rollback unless the component's real transaction restored previous state. If only partial cleanup exists, say partial.

Automatic rollback may be added only for a component with explicit rollback contract + separate acceptance evidence.

## 12. Human approval

All R2 requires human approval, including sandbox.

Approval display must include:

- exact host/component;
- R2 risk;
- canonical playbook + revision/hash;
- stage;
- preview summary;
- dependency health;
- resolved input source categories (no secret values);
- verification spec;
- rollback support status;
- plan hash + expiry.

An R1 approval cannot authorize R2.

## 13. Phase 4 policy hard guard

Add regression invariant:

```text
risk == R2 -> require_human
```

Even if a bad contract accidentally says `autonomy: allowed`, current policy version must refuse R2 auto-execution.

## 14. Proposed files

```text
internal/repair/reapply_plan.go
internal/repair/reapply_executor.go
internal/repair/dependency_preflight.go
internal/repair/reapply_verify.go
internal/repair/*_test.go
cmd/pilot/cmd/mcp_repair_tools.go
internal/contract/contract.go
internal/contract/lint.go
internal/agentcontroller/approval_view.go
internal/agentcontroller/policy.go
```

## 15. Task 1 — evidence-backed eligibility matrix

Before coding executor, select 1–2 candidates and fill:

| Component | Idempotent evidence | Exact-host safe | Inputs resolvable | Secret refs | Dependencies checkable | Verify | Rollback | Eligible |
|---|---|---|---|---|---|---|---|---|

Any unknown means not eligible.

## 16. Task 2 — schema/linter

Tests:

- canonical_apply only valid for R2;
- requires canonical apply playbook;
- maxTargets exactly 1;
- requiresApproval true;
- idempotency evidence requirement enforced;
- R2 autonomy cannot become effective;
- no caller playbook/extra_vars/command fields.

## 17. Task 3 — input resolution

Reuse existing deploy completeness/contract metadata rather than creating a second variable registry.

Classify required input as:

```text
resolved_non_secret
resolved_secret_reference
missing
ambiguous
```

Missing/ambiguous blocks plan.

## 18. Task 4 — dependency snapshot

Generate deterministic snapshot from contract topology + Phase 2 diagnostics. Re-check critical providers immediately before apply.

## 19. Task 5 — sanitized preview

Run current preview/check mechanism against exact target when supported. Persist sanitized diff/summary and hash it into the plan.

Add a hard guard for unexpectedly broad change surface (threshold defined in spec). Operator override, if any, is outside Agent control.

## 20. Task 6 — execute

- acquire per-host repair lock;
- revalidate incident relevance;
- revalidate plan hash/revision;
- dependency preflight;
- resolve secrets at execution time;
- run canonical exact-host apply;
- record true Ansible recap/changed count;
- append journal;
- verify.

No automatic second attempt.

## 21. Verification

After apply:

1. component verification spec;
2. component health diagnosis;
3. required dependency reachability;
4. relevant metrics/log recovery;
5. Alertmanager incident state over bounded window.

If alert remains firing, return `APPLIED_ALERT_STILL_FIRING` and re-diagnose; do not loop another reapply.

## 22. Actual-run evidence

For each eligible candidate:

1. pristine sandbox deploy;
2. introduce a failure that canonical apply should repair;
3. incident created;
4. Agent recommends reapply;
5. Pilot generates R2 plan + preview;
6. human approves exact hash;
7. exact-host apply runs;
8. verification PASS;
9. alert resolves;
10. a second normal component apply proves changed=0.

Negative cases:

- missing vault reference blocks plan;
- provider dependency down blocks plan;
- stale inventory/contract rejects old approval;
- Agent cannot inject playbook/vars;
- Phase 4 policy cannot auto-authorize R2;
- verification failure escalates without retry.

## 23. Phase exit gate

At least one component has real R2 end-to-end evidence; canonical execution is Pilot-resolved; no plaintext secrets enter Agent/controller storage; dependency preflight + preview + exact-host scoping + idempotency + verification are proven; every R2 remains human-approved; R3/R4 remain unsupported.

## 24. After Phase 5

Stop increasing authority by default. R3/R4 require a separate threat model/spec/review. Successful R2 does not justify autonomous FreeIPA, DNS, firewall, account access, CA, storage, delete, restore, or decommission operations.

## 25. Rollback

Disable R2 capability while retaining R1 and observe-only modes. Manual Pilot deploy remains operator fallback.
