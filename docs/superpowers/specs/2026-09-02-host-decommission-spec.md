# Pilot Host Decommission & Zero-Residue Host Removal — Coding Agent Implementation Spec

> Status: **IMPLEMENTATION SPEC**
>
> Repository: `https://github.com/kjelly/pilot`
>
> Baseline revision inspected for this spec: `c39739018a39961d421deb439db8cc8921619a5f`
>
> Baseline date: 2026-09-01
>
> Intended implementation start: 2026-09-02 or later
>
> Primary objective: add a safe, resumable host decommission lifecycle so removing a host from Pilot does not leave active FreeIPA, DNS, Wazuh, internal-endpoint, monitoring, authorization, or other Pilot-managed residue.
>
> **Coding agent must read repository `AGENTS.md` before implementation.** In particular, follow its acceptance-contract-first workflow and actual-run evidence rules. Commands written into `docs/verification/*.md` or `docs/runbooks/*.md` must be validated on the corresponding target environment before being documented as working procedures.

---

## 1. Executive summary

Pilot currently has a workspace-level host delete operation in `pilot edit`, but the existing path only removes the host from the parsed `hosts.yml` data structure and then saves the file. It does not first decommission live state.

Relevant current paths:

- `cmd/pilot/cmd/edit.go`
  - `removeHost(hf, name)` removes the entry from `HostsFile.Hosts`.
- `cmd/pilot/cmd/edit_tui.go`
  - exposes `🗑 刪除這台主機`.
  - confirmation eventually calls `removeHost(...)`.
- `internal/inventory/inventory.go`
  - `Host` contains the connection address, user, SSH key, roles, environment, deployment availability, and `Extra` variables required to perform cleanup.
- `internal/contract/contract.go`
  - component contracts already contain `Playbooks.Decommission *string`.
  - `Lifecycle.Decommission` exists but is currently untyped.
- `cmd/pilot/cmd/deploy.go`
  - already recognizes a component's `playbooks.decommission`.
- Most current contracts still declare `decommission: null`.
- `playbooks/apply/tasks/internal-endpoint-delete.yml`
  - already demonstrates the desired ownership-aware delete pattern: use the ledger, surgically remove only Pilot-owned resources, verify dependent state, and avoid broad cascading deletion.
- `playbooks/apply/freeipa-identity-apply.yml`
  - canonical host schema already accepts `state: absent`, but host deletion is incomplete: present hosts are created and DNS A records are added; there is no equivalent canonical host `state: absent -> host-del` convergence path.
- `playbooks/apply/freeipa-realm-replacement-apply.yml`
  - already exercises `ipa-client-install --uninstall -U` as a client-side enrollment removal primitive.
- `playbooks/apply/wazuh-fim-apply.yml`
  - may register an agent to a central Wazuh manager via `agent-auth`, therefore inventory-only deletion can leave a manager-side registration.
- `internal/store`
  - provides Pilot's general SQLite delivery/evidence store. Baseline `SchemaVersion` is 14.
- `internal/agentcontroller`
  - separately stores incidents/remediation/reapply history. This history is audit data and must not be purged merely because a host is retired.

The new behavior MUST treat host deletion as a **decommission workflow**, not a CRUD edit.

Required lifecycle:

```text
ACTIVE
  -> PLANNED
  -> QUIESCING
  -> LOCAL_CLEANUP
  -> CENTRAL_CLEANUP
  -> VERIFYING
  -> FINALIZING
  -> COMPLETED
```

Failure is resumable:

```text
(any executable state)
  -> FAILED
  -> resume from the first incomplete safe step
```

The fundamental invariant is:

> **A host must remain in `hosts.yml` until active managed residue has been cleaned and independently verified.**

`removeHost()` becomes a finalization primitive only. It MUST NOT remain reachable as a standalone destructive host-removal feature.

---

## 2. Problem statement

Deleting a host from `hosts.yml` first is unsafe for two reasons.

### 2.1 It loses cleanup metadata

The current host object may be the only immediately available source for:

- `ansible_host`
- `ansible_user`
- SSH private key path
- environment
- assigned roles/components
- deployment availability
- host-level `Extra` variables
- FreeIPA roster path
- component-specific configuration references

Removing this source of truth before cleanup makes later cleanup less reliable.

### 2.2 It can leave active central-plane residue

Examples include:

- FreeIPA host object.
- host Kerberos identity.
- hostgroup memberships.
- HBAC direct host references.
- sudo direct host references.
- netgroup host membership.
- DNS A/AAAA/PTR/SSHFP records created or managed by Pilot.
- NFS or HTTP service principals.
- internal endpoint DNS, certmonger tracking, certificates, nginx vhosts, service principals, and endpoint ownership ledger entries.
- Wazuh manager agent registration.
- active monitoring scrape/discovery references.
- backup/storage dependencies that still point to the retiring host.
- repair/autonomy paths that may still attempt actions against the retired host.

Historical metrics, logs, incidents, delivery evidence, approvals, and remediation records are **not** active residue. They should normally be retained for audit/history.

---

## 3. Goals

The implementation MUST provide all of the following.

1. A read-only host decommission planner.
2. A deterministic plan hash and freshness check.
3. Explicit human approval before any mutation in every environment.
4. Reverse-reference discovery across Pilot-managed workspace configuration.
5. Contract-driven component lifecycle resolution.
6. Reverse dependency ordering for component teardown.
7. Resumable saga execution with durable state.
8. FreeIPA client cleanup with zero active identity/DNS/authorization residue.
9. Safe Wazuh manager registration cleanup when Wazuh enrollment was used.
10. Safe reuse of the existing internal-endpoint ownership-aware deletion behavior.
11. Stateful/retention gating.
12. Unreachable-host handling with fail-closed semantics.
13. Independent post-cleanup zero-residue verification.
14. Removal from `hosts.yml` only after verification passes.
15. Regeneration/validation of `inventory.yml` after finalization.
16. Preservation of historical evidence and Agent Controller audit history.
17. A hard block for generic deletion of FreeIPA servers/replicas.
18. No autonomous Agent/MCP path for host decommission.
19. Idempotent re-entry after partial failure.
20. Actual-run evidence on disposable target environments before declaring delivery complete.

---

## 4. Non-goals for v1

The following MUST NOT be silently folded into this feature.

1. Automatically decommissioning a FreeIPA primary server.
2. Automatically decommissioning a FreeIPA replica.
3. Automatically deleting stateful application data.
4. Automatically deleting NFS share data.
5. Automatically wiping disks or destroying VMs.
6. Hypervisor power control.
7. Generic arbitrary-shell cleanup hooks supplied by users or Agents.
8. Autonomous decommission initiated by the SRE Agent.
9. Purging historical Prometheus time series.
10. Purging historical logs.
11. Purging Agent Controller incidents, approvals, remediation plans, or evidence.
12. A broad `--force` option that bypasses unknown ownership, unresolved references, retention requirements, or control-plane safety checks.

Dedicated FreeIPA server/replica decommission workflows may be implemented later under separate acceptance contracts.

---

## 5. Terminology

### 5.1 Host delete

Pure workspace mutation that removes a host entry from `hosts.yml`.

This is NOT a safe public lifecycle operation.

### 5.2 Host decommission

A multi-step operation that:

1. plans;
2. checks dependencies/references;
3. cleans local state when required;
4. cleans central state;
5. verifies zero active residue;
6. finalizes workspace removal.

### 5.3 Active residue

A live resource that can still affect operation/security after the host is intended to be retired.

Examples:

- FreeIPA host object;
- live Wazuh agent registration;
- direct HBAC target;
- active DNS record;
- active monitoring target;
- live service principal;
- live internal endpoint route.

### 5.4 Historical record

Immutable or retained data describing past operation.

Examples:

- deployment evidence;
- historical alerts;
- incidents;
- remediation approvals;
- past metrics;
- logs.

Historical records MUST NOT be counted as cleanup failure unless the feature explicitly defines an active reference in that subsystem.

### 5.5 Foreign resource

A resource whose ownership cannot be proven to belong to Pilot.

Foreign resources MUST NOT be deleted automatically.

### 5.6 Ownership evidence

Evidence sufficient for Pilot to safely claim it owns a resource.

Valid sources in descending confidence:

1. existing Pilot ownership ledger;
2. exact canonical roster declaration plus deterministic resource identity;
3. exact component-managed state written by a Pilot playbook;
4. exact local identity that proves the central object, e.g. a unique stored Wazuh agent ID;
5. legacy discovery that is unique and independently cross-checked.

A name similarity or hostname substring alone is NOT ownership evidence.

---

## 6. Hard safety invariants

These are non-negotiable and require regression tests.

### INV-1 — inventory removal is last

The target host MUST remain present in `hosts.yml` until all required cleanup and verification steps pass.

### INV-2 — plan before mutation

No decommission mutation may execute unless a persisted plan exists.

### INV-3 — stale plans cannot execute

The plan MUST be re-derived immediately before execution. If any plan-bound input changed, execution fails and requires a new plan.

At minimum freshness covers:

- target host snapshot;
- `hosts.yml` hash;
- generated inventory revision/hash;
- affected workspace file hashes;
- referenced FreeIPA roster hash;
- affected internal endpoint manifest hash;
- affected DNS manifest hash;
- component contract hashes;
- component role set;
- dependency graph;
- retention decisions;
- discovered external resource identities.

Follow the same design principle already used by R2 reapply freshness verification: execute against freshly re-derived server-side data, never against caller-supplied executable content.

### INV-4 — human approval always required

Host decommission is destructive and MUST require a human approval in sandbox, staging, and production.

There is no autonomous exception.

### INV-5 — no generic Agent/MCP execution path

Do NOT expose host decommission mutation through the existing Agent diagnosis/repair MCP surface in v1.

A future MCP tool would require a separate threat model and approval design.

### INV-6 — unknown ownership means no deletion

If Pilot cannot prove ownership of a resource, it MUST:

- report it;
- classify it as foreign/unknown;
- leave it untouched;
- block finalization if it remains an active reference to the retiring host.

### INV-7 — external-state components require supported cleanup

If a selected component creates central/external state and its decommission lifecycle is unsupported, planning MUST block.

It is not acceptable to silently remove the host from inventory and leave the external state.

### INV-8 — stateful retention must be explicit

A component whose lifecycle policy requires retention MUST block until an allowed retention disposition is supplied.

### INV-9 — failed cleanup remains resumable

A partial decommission MUST retain enough state to safely continue. It MUST NOT automatically roll the environment backward by recreating identities or re-registering central resources after cleanup has begun.

This is a **forward-recovery saga**, not a pretend distributed transaction.

### INV-10 — verification is independent

Success is not determined from task exit codes alone.

The verifier must re-query live effective state.

### INV-11 — zero active residue before finalization

`FINALIZING` is unreachable while any required verifier returns active residue.

### INV-12 — audit history survives retirement

Historical Pilot delivery evidence and Agent Controller records are retained.

### INV-13 — generic workflow rejects FreeIPA servers

If the target host has role `freeipa-server` or `freeipa-server-replica`, generic host decommission MUST return a hard blocker.

### INV-14 — no broad FreeIPA DNS cascade

Do not use broad host deletion semantics to blindly delete all DNS associated with a FreeIPA host. DNS cleanup must be ownership-aware and surgical.

### INV-15 — completed plan is replay-safe

A completed decommission cannot execute again. A repeated request should return `already_completed` plus the original receipt.

---

## 7. Current code that MUST be refactored

### 7.1 `cmd/pilot/cmd/edit.go`

Current helper:

```go
func removeHost(hf *inventory.HostsFile, name string)
```

Keep this as a pure in-memory helper if useful, but rename or document it as a finalization-only primitive if needed.

It MUST NOT be directly reachable from a normal public "delete host" action without a successful decommission receipt.

Suggested internal name:

```go
removeHostFromWorkspaceFinalization(...)
```

Renaming is optional if tests/comments make the lifecycle boundary unambiguous.

### 7.2 `cmd/pilot/cmd/edit_tui.go`

Current action:

```text
🗑 刪除這台主機
```

Replace with:

```text
🗑 下架 / Decommission 主機
```

The action must enter the decommission planner flow. It must not immediately modify `HostsFile`.

### 7.3 `cmd/pilot/cmd/edit_test.go` and TUI tests

Tests that currently assert direct `removeHost()` behavior may retain pure helper coverage, but end-to-end TUI tests MUST be rewritten to prove that:

- no host disappears during plan;
- blockers prevent apply;
- explicit confirmation is required;
- only a completed decommission finalizes workspace removal.

---

## 8. New package architecture

Add a deterministic core package:

```text
internal/decommission/
    model.go
    planner.go
    freshness.go
    dependency.go
    references.go
    ownership.go
    executor.go
    verifier.go
    finalizer.go
    store.go
    receipt.go
    errors.go
    providers/
        provider.go
        freeipa_client.go
        internal_endpoint.go
        wazuh_agent.go
        agent_controller.go
        generic_component.go
```

Exact file split is flexible. The package boundary is not.

Rules:

- domain logic belongs in `internal/decommission`;
- CLI/TUI is orchestration/presentation only;
- Ansible execution should reuse existing Pilot execution machinery;
- contract lookup must use `internal/contract`;
- inventory parsing/generation must use `internal/inventory`;
- do not reimplement YAML parsers ad hoc in CLI code;
- do not create a giant switch in `cmd/pilot/cmd`.

### 8.1 Provider interface

Use a typed provider abstraction.

Illustrative shape:

```go
type Provider interface {
    ID() string
    Inspect(ctx context.Context, in InspectInput) (Inspection, error)
    Plan(ctx context.Context, in PlanInput) ([]Step, error)
    Verify(ctx context.Context, in VerifyInput) ([]Verification, error)
}
```

The exact API may differ, but it MUST enforce:

- typed inputs;
- server-side target resolution;
- no caller-supplied raw command;
- no shell field in a plan;
- deterministic output;
- explicit ownership classification;
- independent verify phase.

### 8.2 Generic component provider

Components with `playbooks.decommission != null` should be executable through one generic contract-driven provider.

The generic provider:

1. resolves the component contract from the host's role;
2. resolves the decommission playbook path from the contract;
3. resolves required non-secret/secret-reference inputs using the same safe patterns as canonical R2 reapply;
4. never accepts a playbook path from the caller;
5. executes the decommission playbook limited to the target host;
6. runs component-specific verification defined by contract/spec.

Shared control-plane providers such as FreeIPA/Wazuh may add domain-specific inspection and central cleanup where a normal host-limited playbook is insufficient.

---

## 9. Persistent saga state

Do not store decommission workflow state in `internal/agentcontroller`. Host lifecycle is a core Pilot concern and must function without Agent Controller.

Use the existing general `internal/store` SQLite database.

Baseline observation:

```text
internal/store/sqlite.go
SchemaVersion = 14
```

Add the next migration. If main has advanced when implementation begins, add the next actual schema version rather than assuming 15.

### 9.1 Required logical tables

Suggested schema:

```sql
host_decommission_plans (
    id TEXT PRIMARY KEY,
    host TEXT NOT NULL,
    fqdn TEXT,
    environment TEXT,
    status TEXT NOT NULL,
    reason TEXT,
    plan_hash TEXT NOT NULL,
    inventory_revision TEXT NOT NULL,
    workspace_snapshot_hash TEXT NOT NULL,
    host_snapshot_json TEXT NOT NULL,
    roles_json TEXT NOT NULL,
    contract_hashes_json TEXT NOT NULL,
    dependency_snapshot_json TEXT NOT NULL,
    reference_snapshot_json TEXT NOT NULL,
    resource_snapshot_json TEXT NOT NULL,
    retention_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    completed_at TEXT
);

host_decommission_steps (
    id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    seq INTEGER NOT NULL,
    component TEXT,
    provider TEXT NOT NULL,
    phase TEXT NOT NULL,
    action TEXT NOT NULL,
    target_identity TEXT,
    state TEXT NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0,
    started_at TEXT,
    finished_at TEXT,
    error_class TEXT,
    error_text TEXT,
    result_json TEXT,
    UNIQUE(plan_id, seq)
);

host_decommission_approvals (
    id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    plan_hash TEXT NOT NULL,
    actor TEXT NOT NULL,
    decision TEXT NOT NULL,
    reason TEXT,
    created_at TEXT NOT NULL
);

retired_hosts (
    host TEXT PRIMARY KEY,
    fqdn TEXT,
    decommission_id TEXT NOT NULL,
    reason TEXT,
    retired_at TEXT NOT NULL,
    final_inventory_revision TEXT NOT NULL
);
```

If an append-only event model better matches `internal/store`, the coding agent may implement equivalent projections over append-only events. The observable invariants above are more important than the exact schema.

### 9.2 Secrets

Never persist secret values in:

- plan JSON;
- step JSON;
- errors;
- receipts;
- approval records.

Store only secret reference names/paths when necessary.

This should mirror R2 reapply's distinction between resolved non-secret input and secret reference.

### 9.3 Plan expiry

Plans should expire by default after a bounded duration, recommended 30 minutes.

Expiry is not a substitute for freshness hashing. Both checks apply.

---

## 10. CLI contract

Add a `host decommission` command group.

Target interface:

```text
pilot host decommission plan   --dir <workspace> --host <host>
pilot host decommission show   --id <plan-id>
pilot host decommission apply  --id <plan-id>
pilot host decommission resume --id <plan-id>
pilot host decommission verify --id <plan-id>
```

Also support `--json` on read-oriented commands.

Exact Cobra flag spelling may follow existing conventions.

### 10.1 `plan`

MUST be read-only.

It returns:

- plan ID;
- host snapshot;
- FQDN/IP;
- environment;
- roles;
- component teardown order;
- external resources discovered;
- ownership confidence;
- workspace references;
- retention requirements;
- unreachable-host requirements;
- planned mutations;
- planned verification probes;
- hard blockers;
- warnings;
- plan hash;
- expiry.

Exit behavior:

- successful safe plan with no blockers: success;
- valid plan with blockers: non-zero structured blocked result;
- malformed workspace: error.

Planning itself must not:

- edit YAML;
- uninstall packages;
- touch FreeIPA;
- touch Wazuh;
- reload services;
- alter Agent Controller.

### 10.2 `show`

Read-only. Shows persisted plan and latest step states.

### 10.3 `apply`

Requirements:

1. plan exists;
2. plan has no unresolved blocker;
3. plan is not expired;
4. freshness re-derivation succeeds;
5. plan hash still matches;
6. explicit human confirmation is collected;
7. current plan has not already completed.

For non-interactive usage require a confirmation flag tied to the host and plan, for example:

```text
--confirm-host <exact-host-name>
```

Do not implement a generic `--yes` that makes accidental scripting trivial.

TUI can satisfy the same requirement through an exact typed-host confirmation field.

### 10.4 `resume`

Re-derives freshness first.

If external state has changed in a way that invalidates already-completed assumptions, return `stale_resume` and require a new plan or a dedicated recovery decision.

Otherwise continue from the first safe incomplete step.

### 10.5 `verify`

Read-only with respect to managed systems.

It re-runs all final verifiers and reports:

```text
pass
active_residue
unknown_ownership
unreachable_unverified
historical_only
not_applicable
```

It must not silently mutate residue while "verifying".

---

## 11. TUI behavior

Replace direct delete with a decommission flow.

### 11.1 First screen — plan summary

Show:

- host;
- connection state;
- FQDN/IP;
- environment;
- roles;
- component cleanup order;
- external managed resources;
- references to be removed;
- files that would eventually change;
- retention requirements;
- blockers/warnings.

### 11.2 Blocked plan

If blockers exist:

- no destructive confirmation control;
- show blocker detail;
- allow return/edit configuration.

### 11.3 Approval

For executable plans, require typing the exact host name.

Example conceptual prompt:

```text
Type "gpu-a01" to confirm decommission:
```

Default is cancel.

### 11.4 Progress

Show persisted phases/steps rather than only transient Ansible output.

### 11.5 Failure

On failure, show:

- completed steps;
- failed step;
- whether retry is safe;
- plan ID;
- action to resume.

Do not imply rollback recreated removed identities.

---

## 12. Reverse-reference scanner

Planning must compute the impact of deleting the target host from the workspace.

At minimum inspect:

- `hosts.yml`;
- current/generated `inventory.yml`;
- `host_vars/<host>.yml`;
- `group_vars/*.yml` where host aliases/explicit addresses are structurally known;
- canonical FreeIPA roster referenced by workspace;
- `freeipa-dns.yaml` if present;
- `internal-endpoints.yaml` if present;
- role/component contract dependencies and bindings;
- deterministic component configuration that directly names `inventory_host`.

Reuse existing validators where possible, including the same parsing path used by workspace completeness.

Do NOT implement this as unrestricted grep.

### 12.1 Reference classifications

Every reference becomes one of:

```text
AUTO_REMOVE
REQUIRES_REPLACEMENT
INFORMATIONAL
FOREIGN_UNKNOWN
HARD_BLOCKER
```

Examples:

- host in canonical FreeIPA hostgroup membership:
  - `AUTO_REMOVE`.
- internal endpoint whose target is the retiring host:
  - `REQUIRES_REPLACEMENT` unless the endpoint itself is being removed.
- host is the only selected required S3/backend provider:
  - `HARD_BLOCKER`.
- historical evidence mentioning hostname:
  - `INFORMATIONAL`.
- unknown manually-created DNS object:
  - `FOREIGN_UNKNOWN`.

### 12.2 Proposed workspace validation

Planner must construct an in-memory proposed after-state and run relevant validators against it.

The proposed state must include:

- host removed from `hosts.yml`;
- host-specific references pruned where semantically safe;
- host-specific FreeIPA roster references pruned;
- host object set to `state: absent` or otherwise represented according to the canonical roster lifecycle decision;
- internal endpoint entries removed/repointed as selected;
- DNS manifest references removed/repointed as selected.

Do not persist the proposed state during `plan`.

---

## 13. Component dependency teardown order

Build the selected component dependency graph from current contracts.

If component A requires component B:

```text
A -> B
```

decommission in reverse dependency order:

```text
A first
B later
```

This prevents removing shared providers before their consumers have been detached.

If the dependency graph is cyclic, planning fails closed.

If removal of the host violates a component's required host cardinality or leaves a required dependency with no surviving provider, planning fails.

Reuse existing component/dependency resolution code where possible rather than building another independent model.

---

## 14. Contract changes

`internal/contract/contract.go` already has:

```go
type Playbooks struct {
    Apply        string
    Rollback     *string
    Upgrade      *string
    Decommission *string
}
```

Keep this.

Replace the untyped lifecycle decommission value with a typed structure while retaining compatibility with `null`.

Suggested shape:

```go
type Lifecycle struct {
    Backup       *Backup             `yaml:"backup"`
    Upgrade      any                 `yaml:"upgrade"`
    Decommission *DecommissionPolicy `yaml:"decommission"`
}

type DecommissionPolicy struct {
    Class                 string   `yaml:"class"`                  // stateless | stateful | control_plane
    Scope                 string   `yaml:"scope"`                  // local | central | both
    ExternalState         bool     `yaml:"externalState"`
    RequiresReachableHost bool     `yaml:"requiresReachableHost"`
    Retention             string   `yaml:"retention"`              // none | required | operator_choice
    DataPaths             []string `yaml:"dataPaths,omitempty"`
}
```

Field naming may be adjusted, but semantics must remain typed and linted.

### 14.1 Contract linter rules

Add lints:

1. if `ExternalState=true`, either:
   - `playbooks.decommission` is non-null; or
   - a registered central decommission provider exists.
2. stateful lifecycle cannot declare `retention=none` unless the component explicitly has no managed persistent data.
3. `class=control_plane` cannot be generically removed unless explicitly supported.
4. `requiresReachableHost=true` must be honored by the planner.
5. decommission playbook path must be repository-confined and exist.
6. null lifecycle remains valid for legacy components but may block actual host decommission depending on whether residue exists.

Do not introduce raw `command`, `shell`, `args`, or caller-supplied executable fields into the contract.

---

## 15. Generic component decommission playbooks

Create a new directory:

```text
playbooks/decommission/
```

Suggested naming:

```text
playbooks/decommission/<component>-decommission.yml
```

Each playbook MUST:

- be idempotent;
- target one host when invoked by host decommission;
- accept fixed, typed inputs;
- avoid deleting user/application data unless lifecycle/retention explicitly authorizes it;
- have a corresponding verification contract;
- support safe retry after partial completion;
- avoid hidden broad cleanup outside the component's ownership.

Do not create one monolithic `host-decommission.yml` containing every component's product-specific behavior.

---

## 16. FreeIPA client decommission

This is a required v1 provider.

### 16.1 Generic server exclusion

If host roles contain:

```text
freeipa-server
freeipa-server-replica
```

return a hard blocker:

```text
requires_dedicated_freeipa_server_decommission
```

Do not continue into the generic client provider.

### 16.2 Client-side cleanup

When the host is reachable and enrolled:

- remove the FreeIPA client enrollment using the already-established uninstall mechanism;
- verify the local machine is no longer an active IPA client;
- clean only Pilot-managed local pins/config that the FreeIPA client apply path owns;
- do not remove unrelated administrator-managed `/etc/hosts` entries.

Use the actual behavior already exercised by:

```text
playbooks/apply/freeipa-realm-replacement-apply.yml
```

The coding agent must validate the exact target behavior before writing final verification/runbook commands.

### 16.3 Canonical roster host lifecycle completion

`playbooks/apply/freeipa-identity-apply.yml` currently accepts canonical host:

```yaml
state: absent
```

but does not converge it to deletion.

Implement complete host absent semantics.

Required order:

1. remove/prune canonical references to the host from:
   - hostgroups;
   - netgroups;
   - HBAC rules;
   - sudo rules;
   - grant/auth-policy-derived effective references where applicable.
2. clean Pilot-owned service principals associated with that host through their owning component provider.
3. surgically clean Pilot-owned DNS records.
4. verify no unsafe service/reference remains attached.
5. delete the FreeIPA host object.
6. verify the host object is absent.

The implementation MUST NOT interpret `state: absent` as "skip creation only".

### 16.4 Roster mutation helper

Add a typed inventory/roster helper rather than editing YAML using text replacement.

Suggested API concepts:

```go
SimulateRemoveRosterHost(...)
RemoveRosterHostReferences(...)
SetRosterHostAbsent(...)
```

The helper must understand at least:

- `hosts`;
- `hostgroups.membership.hosts`;
- `netgroups.membership.hosts`;
- `hbac.rules[].targets.hosts`;
- `sudo.rules[].targets.hosts`;
- schema-v3 constructs that resolve to explicit host targets.

It must run full roster validation before returning a writable result.

### 16.5 DNS deletion

Do not perform a broad host-level DNS cascade.

Delete only records whose ownership/value is known to Pilot.

For canonical host A records, the expected owned tuple is derived from:

```text
zone
record owner
record type
exact IP value
```

If the current live record contains a foreign value or an ownership ambiguity, do not delete the foreign value.

If Pilot cannot prove which value it owns, block and report the ambiguity.

### 16.6 Service principals

Before deleting the host object, detect service principals managed by or tied to the host.

Known Pilot-owned principals should be cleaned by the owning provider, for example:

- `HTTP/<fqdn>` from internal endpoints;
- `nfs/<fqdn>` from NFS lifecycle.

Unknown service principals are a hard blocker, not a cascade-delete target.

### 16.7 FreeIPA final verification

At minimum verify effective absence of:

- host object;
- Pilot-owned host DNS record(s);
- direct hostgroup membership;
- direct HBAC references;
- direct sudo references;
- netgroup host membership;
- known Pilot-owned service principal references.

Historical CA/audit data that cannot/should not be erased is not active residue.

---

## 17. Internal endpoint provider

Reuse the existing ownership-aware deletion design in:

```text
playbooks/apply/tasks/internal-endpoint-delete.yml
```

Do not duplicate its cleanup logic in Go.

### 17.1 Reverse-reference detection

If an internal endpoint references the target host as:

- `target.inventory_host`;
- route owner;
- certificate owner;
- another host-bound ownership field;

the planner must determine whether:

1. the endpoint is being removed;
2. the endpoint is being repointed;
3. decommission must block.

An endpoint that should continue serving cannot silently retain the deleted host as its backend.

### 17.2 Deletion

For endpoints explicitly being removed, invoke the existing endpoint delete lifecycle through the supported manifest/ledger path.

Preserve the existing safety properties:

- ownership ledger is authoritative;
- exact DNS value deletion;
- nginx validation before reload;
- certmonger stop tracking;
- certificate revocation when identifiable;
- service principal cleanup;
- virtual host object only when unreferenced;
- no broad `--updatedns` cascade.

### 17.3 Verification

Verify:

- endpoint ledger no longer contains the retired endpoint;
- active DNS route is absent/repointed;
- Pilot-owned nginx vhost is absent when removed;
- Pilot-owned certificate tracking is absent;
- owned service principal is absent;
- no endpoint manifest still points to the retiring host.

---

## 18. Wazuh FIM / agent provider

`playbooks/apply/wazuh-fim-apply.yml` can enroll a host to a Wazuh manager.

A host decommission must not leave the central agent registration active.

### 18.1 Stable agent identity

Enhance Wazuh enrollment ownership tracking.

Preferred identity sources:

1. exact agent ID recorded by Pilot after enrollment;
2. exact agent ID parsed from the host's existing Wazuh client identity;
3. legacy manager-side unique lookup plus independent cross-check.

Do not delete based on hostname substring.

### 18.2 Legacy host handling

If:

- host is unreachable;
- no Pilot-recorded agent ID exists;
- no other exact identity can prove the central registration;

the central Wazuh deletion step must block as `ownership_unknown`.

### 18.3 Local cleanup

When reachable:

- stop/disable the Pilot-managed Wazuh agent;
- remove enrollment identity/config according to component decommission policy;
- do not remove unrelated audit data unless the Wazuh component contract owns it.

### 18.4 Central cleanup

Remove the exact manager-side agent registration identified by stable ID.

The coding agent must validate the actual Wazuh command/API in a target environment before documenting or accepting the implementation.

### 18.5 Verification

Re-query manager state and verify the exact agent ID is absent.

Historical alerts/logs referring to the retired host remain historical data.

---

## 19. Monitoring and observability residue

The planner/provider model must distinguish active target configuration from historical telemetry.

### Active residue examples

- Prometheus target still actively scraped;
- service-discovery entry still advertising the host;
- active alert target mapping that attempts to contact the host.

These must be removed/reconciled.

### Historical data examples

- old Prometheus time series;
- archived logs;
- resolved alerts.

These must not block decommission.

If the current Pilot monitoring stack derives active targets directly from inventory, the implementation must provide a supported pre-finalization reconcile path that removes the target without first deleting the actual host source entry.

Acceptable implementation patterns:

- a component-specific decommission playbook;
- a provider that renders/reconciles the proposed after-state;
- a temporary validated inventory projection used only by the decommission component.

Do not mutate the canonical `hosts.yml` early merely to make monitoring converge.

---

## 20. Stateful component and retention policy

Stateful roles require explicit handling.

Examples include:

- NFS server;
- backup/storage provider;
- object storage;
- database-like services.

### 20.1 Required planning behavior

If a component contract declares:

```text
class=stateful
retention=required
```

the plan is blocked until a retention disposition exists.

Supported conceptual dispositions:

```text
exported
migrated
retain_on_disk
destroy_authorized
```

The concrete schema may differ.

### 20.2 NFS

Follow the current `freeipa-nfs-server` design principle:

- do not automatically delete share data;
- do not silently revoke/delete data ownership just because the host is leaving;
- clean NFS service principal and policy only after retention/dependency gates pass.

### 20.3 No implicit data deletion

Removing a component package/container is not authorization to delete its data directory.

---

## 21. Unreachable hosts

Host decommission must support hardware that is already unavailable without weakening safety.

### 21.1 Distinguish temporary vs permanent loss

If transport is unreachable, require an operator disposition:

```text
temporarily_unreachable
permanently_lost
```

`temporarily_unreachable` blocks components that require local cleanup.

`permanently_lost` permits central cleanup only if:

- component policy allows it;
- required ownership identity is available centrally or in durable Pilot state;
- retention is not unresolved;
- cryptographic/security invalidation can be completed centrally.

### 21.2 No fake local success

A skipped local cleanup on a permanently lost machine is recorded as:

```text
local_cleanup_unavailable_attested
```

not `verified_removed`.

### 21.3 Security warning

For permanently lost/reused hardware, the receipt must record that local disk/key material could not be verified wiped unless Pilot actually has a supported wipe mechanism. Pilot must not claim physical credential destruction it did not perform.

---

## 22. Agent Controller retirement behavior

Do not delete Agent Controller history.

If Agent Controller is deployed, add a retirement marker or equivalent read path so the controller can reject new work for a retired host.

Suggested logical data:

```sql
retired_hosts (
    host TEXT PRIMARY KEY,
    decommission_id TEXT NOT NULL,
    retired_at TEXT NOT NULL,
    reason TEXT
);
```

This may live in the Agent Controller database or be synchronized from the core Pilot retirement record.

Required behavior after retirement:

- no new autonomous R1 action;
- no new human R1 action against the retired host;
- no new R2 reapply against the retired host;
- active incident can be closed/suppressed with a retirement reason;
- historical incidents, approvals, runs, and evidence remain queryable.

Do not add an Agent-triggered decommission action.

---

## 23. Workspace finalization

Finalization executes only after all mandatory verifiers pass.

Required order:

1. acquire workspace mutation lock consistent with existing edit/apply behavior;
2. verify plan freshness again;
3. atomically write already-planned non-secret workspace changes;
4. remove target host from `hosts.yml`;
5. remove/archive `host_vars/<host>.yml` if it is exclusively host-owned;
6. regenerate `inventory.yml` using `internal/inventory.Generate`;
7. run inventory lint;
8. run workspace completeness checks relevant to the resulting workspace;
9. write `retired_hosts` record;
10. mark decommission `COMPLETED`;
11. emit immutable receipt/evidence event.

If final workspace generation fails:

- do not mark completed;
- restore the finalization file set using the same managed-file backup discipline already used by `pilot edit`;
- keep central cleanup completed;
- leave the plan resumable at finalization.

Do not recreate deleted central identities as part of finalization rollback.

---

## 24. Workspace backup / atomicity

Reuse the existing `pilot edit` managed-file backup/journal pattern where possible.

The workspace file transaction must cover every file that the decommission plan intends to mutate, potentially including:

- `hosts.yml`;
- `inventory.yml`;
- `host_vars/<host>.yml`;
- canonical FreeIPA roster;
- `internal-endpoints.yaml`;
- `freeipa-dns.yaml`.

The plan must list affected files before apply.

No hidden file mutation outside the planned set is allowed.

---

## 25. Zero-residue verifier

Create a dedicated final verifier in `internal/decommission`.

Each provider returns normalized verification results.

Suggested model:

```go
type Verification struct {
    Provider     string
    Kind         string
    Identity     string
    Status       string
    Detail       string
    Active       bool
    Historical   bool
    Ownership    string
}
```

Final success requires:

```text
all mandatory checks in {pass, not_applicable, historical_only}
AND
active_residue_count == 0
AND
unknown_active_ownership_count == 0
```

### 25.1 Verification must query live state

Examples:

- FreeIPA live object query;
- DNS live record query;
- Wazuh manager live agent query;
- internal endpoint live/ledger query;
- active monitoring target query.

Do not verify only by rereading the YAML that was just edited.

---

## 26. Receipt

On completion create a durable receipt.

Required fields:

```yaml
decommission_id:
host:
fqdn:
environment:
reason:
started_at:
completed_at:
plan_hash:
initial_inventory_revision:
final_inventory_revision:
components:
completed_steps:
retention_disposition:
offline_disposition:
verified:
historical_records_retained:
warnings:
```

Never include secret values.

The receipt should be queryable through CLI:

```text
pilot host decommission show --id ...
```

Optionally add:

```text
pilot host decommission list
```

if it fits existing CLI patterns.

---

## 27. Failure and retry semantics

### 27.1 Step states

Use explicit states:

```text
pending
running
completed
skipped_attested
failed_retryable
failed_terminal
```

### 27.2 Retry

A retryable step is re-inspected before execution.

If it is already converged, mark completed without mutating again.

### 27.3 Failure after central deletion

Do not compensate by recreating FreeIPA/Wazuh identities automatically.

Continue forward.

### 27.4 Failure during finalization

Restore workspace files only. Do not undo successful control-plane cleanup.

---

## 28. Plan freshness algorithm

The plan hash must be computed from canonicalized data, not raw map iteration order.

Hash at least:

```text
host snapshot
roles
environment
affected file hashes
inventory revision
contract hashes
dependency graph
reference decisions
external resource identities
ownership classifications
retention decisions
offline disposition
ordered steps
verification identities
```

At apply/resume:

1. inspect current state;
2. rebuild canonical plan inputs;
3. compare hashes;
4. if mismatch, return a structured stale error.

Do not execute the old plan's executable fields after a mismatch.

---

## 29. Concurrency

Prevent concurrent decommission of the same host.

Also prevent conflicting workspace mutation while finalization is active.

If two plans exist for the same host:

- at most one may become executing;
- older unexecuted plans become superseded/stale.

Do not rely only on in-process mutexes. Enforce the important single-active-plan invariant in persistent state where practical.

---

## 30. Approval model

Persist approval bound to:

```text
plan_id + plan_hash
```

An approval must never carry over to a changed plan.

If freshness produces a different plan hash:

- old approval is invalid;
- a new plan and approval are required.

Actor identity should use the same operator identity conventions as other Pilot audit events.

---

## 31. Security requirements

1. No secret values in persistent decommission state.
2. No caller-controlled executable path.
3. No caller-controlled shell command.
4. No raw arbitrary Ansible extra-vars from an Agent path.
5. Decommission playbook is resolved from contract.
6. Central object IDs are resolved server-side.
7. Destructive operations require exact ownership evidence.
8. Plan/apply actor and hash are auditable.
9. `--json` output must redact secret-derived detail.
10. Error messages must not dump vault contents.
11. No generic `--force` bypass.
12. FreeIPA server/replica block is not bypassable by generic CLI flags.

---

## 32. Required acceptance contract

Before implementing mutation, create:

```text
docs/verification/host-decommission.md
```

Follow repository `AGENTS.md`.

Suggested acceptance rows:

| ID | Acceptance |
|---|---|
| HD1 | `plan` is read-only and leaves workspace/live state unchanged |
| HD2 | TUI no longer directly removes a host from `hosts.yml` |
| HD3 | plan contains deterministic hash and persisted host snapshot |
| HD4 | stale workspace/contract/reference state invalidates apply |
| HD5 | human approval is required in sandbox/staging/prod |
| HD6 | reverse references are discovered and classified before mutation |
| HD7 | unsupported external-state component blocks decommission |
| HD8 | component teardown follows reverse dependency order |
| HD9 | reachable FreeIPA client local enrollment is removed |
| HD10 | FreeIPA host object and Pilot-owned DNS are absent after cleanup |
| HD11 | FreeIPA hostgroup/HBAC/sudo/netgroup direct references are absent |
| HD12 | unknown FreeIPA service principal blocks unsafe host deletion |
| HD13 | internal endpoint referencing the host is removed/repointed or blocks |
| HD14 | Wazuh manager registration is removed by stable identity |
| HD15 | stateful component requires explicit retention disposition |
| HD16 | unreachable temporary host blocks required local cleanup |
| HD17 | permanently lost host records local cleanup as unattested/unavailable, never fake PASS |
| HD18 | failed step can resume without replaying completed destructive work |
| HD19 | independent zero-residue verify gates finalization |
| HD20 | target remains in `hosts.yml` until HD19 passes |
| HD21 | finalization regenerates and validates `inventory.yml` |
| HD22 | historical delivery/Agent Controller evidence remains available |
| HD23 | generic workflow rejects `freeipa-server` and `freeipa-server-replica` |
| HD24 | completed decommission is replay-safe/idempotent |
| HD25 | no Agent/MCP autonomous decommission execution path exists |
| HD26 | no secret values appear in plan/store/receipt output |
| HD27 | plan/apply approval is bound to exact `plan_hash` |
| HD28 | foreign/unknown resources are never automatically deleted |

The coding agent may split rows if that improves observable verification, but it must not weaken these outcomes.

---

## 33. Regression/unit test requirements

Add table-driven Go tests for at least:

### Planner

- deterministic plan hash;
- same semantic YAML with different map ordering yields same canonical hash where applicable;
- missing host;
- host with no roles;
- host with unsupported external-state component;
- FreeIPA server role blocker;
- FreeIPA replica role blocker;
- cycle in component dependencies;
- only surviving provider/cardinality blocker;
- stateful retention blocker;
- unreachable-host policy.

### Reverse references

Fixtures covering:

- FreeIPA hostgroup;
- netgroup;
- HBAC;
- sudo;
- `freeipa-dns.yaml` `inventory_host`;
- internal endpoint `inventory_host`;
- internal endpoint owner;
- host_vars file;
- historical evidence not treated as active reference.

### Freshness

- `hosts.yml` changes after plan;
- roster changes after plan;
- contract changes after plan;
- external resource identity changes after plan;
- retention disposition changes;
- plan expiry.

All must block apply.

### Store

- one active executing plan per host;
- approval binds exact hash;
- resume survives process restart;
- completed plan cannot replay;
- secret values are absent from serialized records.

### Finalizer

- cannot finalize with active residue;
- cannot finalize with unknown active ownership;
- successful finalization removes host;
- generated inventory is fresh;
- workspace write failure restores workspace but does not attempt to recreate central resources.

### TUI

- old direct-delete path removed;
- plan screen appears;
- blocked plan cannot approve;
- exact host confirmation required;
- failure displays resumable plan ID.

---

## 34. FreeIPA regression requirements

Add dedicated regression coverage for the gap in canonical host `state: absent`.

Required tests:

1. validator still accepts present/absent only.
2. present host creation behavior unchanged.
3. absent host does not run host-add.
4. absent host triggers safe reference cleanup.
5. absent host DNS deletion is exact-value/surgical.
6. unknown service references block host deletion.
7. host deletion does not use a broad DNS cascade.
8. idempotent second absent reconcile reports no destructive change.
9. existing user/group/netgroup absent semantics are not regressed.

---

## 35. Disposable target integration tests

Per `AGENTS.md`, unit tests alone are insufficient.

Create actual-run evidence using disposable targets.

### 35.1 FreeIPA topology

Minimum topology:

```text
ipa1       freeipa-server
client1    freeipa-client
```

Before decommission, create observable state:

- enrolled client;
- host object;
- host DNS;
- hostgroup membership;
- HBAC direct or hostgroup-derived relation;
- sudo relation where supported by the fixture;
- netgroup host membership where schema supports it.

Run decommission and independently verify all mandatory active residue is absent.

Then run verification again to prove stable absence.

### 35.2 Partial failure / resume

Inject one controlled central cleanup failure after at least one earlier destructive step succeeds.

Prove:

- plan remains persisted;
- completed step is not blindly repeated;
- resume reaches completion;
- final result is zero active residue.

### 35.3 Stale plan

Create plan, mutate a bound workspace file, attempt apply.

Expected:

```text
stale plan
zero decommission mutation
```

### 35.4 Wazuh topology

Where practical, create manager + agent and prove:

- agent was registered;
- decommission identifies exact agent;
- central registration is removed;
- second verification confirms absence.

If Wazuh disposable evidence cannot be completed in the first delivery batch, its provider must remain disabled/blocking rather than claim support without evidence.

### 35.5 Internal endpoint

Create an endpoint tied to the retiring host.

Prove:

- decommission plan detects it;
- deleting/repointing it follows existing ledger-aware path;
- foreign RR data at the same owner is preserved.

### 35.6 Idempotency

After a completed decommission:

- replay of the completed plan is rejected as already completed;
- verify is stable;
- no resource is recreated.

---

## 36. Evidence requirements

Create sanitized evidence under an appropriate feature directory, for example:

```text
docs/evidence/host-decommission/<date>-<tested-revision>.md
```

Follow `AGENTS.md` and `docs/actual-run-evidence.md`.

Evidence must record:

- tested revision;
- tested tree if required by repo convention;
- target inventory/topology facts;
- plan output summary;
- real apply outcome;
- zero-residue verification results;
- retry/resume result;
- idempotency/replay result;
- any discovered implementation bugs.

Do not put invented PLAY RECAP values in the verification spec.

---

## 37. Delivery phases

Implement in phases. Each phase must keep main buildable and tests green.

### Phase 0 — Acceptance contract

Deliver:

- `docs/verification/host-decommission.md`;
- design decisions aligned with this spec;
- no mutation implementation yet.

### Phase 1 — Core planner and persisted saga

Deliver:

- `internal/decommission`;
- store migration;
- read-only plan/show;
- reverse-reference scanner;
- plan hash/freshness;
- blockers;
- CLI;
- no live delete yet.

Tests must prove planning is read-only.

### Phase 2 — Finalization boundary + TUI refactor

Deliver:

- remove direct TUI delete behavior;
- decommission TUI;
- finalizer;
- workspace backup;
- inventory regeneration;
- hard guarantee that finalizer requires successful verification state.

At this phase, unsupported live providers may still block apply.

### Phase 3 — FreeIPA client provider

Deliver:

- client local uninstall;
- canonical roster host absent completion;
- reference pruning;
- surgical DNS cleanup;
- service-principal blocker;
- zero-residue verifier;
- actual disposable FreeIPA evidence.

This is the minimum phase after which host decommission can be considered materially useful.

### Phase 4 — Internal endpoint + Wazuh providers

Deliver:

- reuse endpoint ledger-aware deletion;
- Wazuh stable agent identity and central delete;
- actual evidence.

### Phase 5 — Generic contract decommission

Deliver:

- typed `Lifecycle.Decommission`;
- contract lint;
- generic `playbooks.decommission` executor;
- initial stateless component decommission playbooks;
- reverse dependency ordering.

### Phase 6 — Stateful retention

Deliver:

- retention dispositions;
- NFS/storage blockers and supported cleanup;
- evidence.

### Future phase — FreeIPA server/replica

Separate spec and threat model. Do not unblock generic deletion in this feature.

---

## 38. Expected file changes

The exact set may vary, but implementation should likely touch/create:

```text
docs/verification/host-decommission.md
docs/evidence/host-decommission/...

internal/decommission/...
internal/store/sqlite.go
internal/store/...decommission tests...

internal/contract/contract.go
internal/contract/lint.go
internal/contract/...tests...

internal/inventory/...roster host mutation helpers...
internal/inventory/...tests...

cmd/pilot/cmd/host_decommission.go
cmd/pilot/cmd/host_decommission_test.go
cmd/pilot/cmd/edit_tui.go
cmd/pilot/cmd/edit_tui_*test.go

playbooks/decommission/...
playbooks/apply/freeipa-identity-apply.yml
playbooks/apply/wazuh-fim-apply.yml
playbooks/apply/tasks/internal-endpoint-delete.yml   # preferably reused, minimal/no duplication

contracts/freeipa-client.yaml
contracts/wazuh-fim.yaml
contracts/...initial supported components...
```

Do not modify unrelated components merely to make every current contract claim decommission support.

Unsupported components should truthfully block until implemented.

---

## 39. Compatibility

### 39.1 Existing workspaces

Existing `hosts.yml` syntax remains valid.

Do not require a new host state field in `hosts.yml` for this feature.

### 39.2 Existing contracts

`lifecycle.decommission: null` remains parseable.

A null policy does not imply safe deletion.

### 39.3 Existing direct `pilot edit`

Editing normal host fields remains unchanged.

Only destructive host deletion semantics change.

### 39.4 Existing FreeIPA rosters

Existing canonical roster versions remain supported.

No new roster schema version should be invented solely for host decommission if the current `hosts[].state: absent` contract is sufficient.

Complete the already-declared absent semantics instead.

---

## 40. Observability and operator output

Every apply/resume should emit concise structured progress:

```text
PLAN       <id> host=<host> hash=<short-hash>
STEP 01    internal-endpoint inspect       PASS
STEP 02    wazuh local cleanup             PASS
STEP 03    wazuh central unregister        PASS
STEP 04    freeipa local unenroll          PASS
STEP 05    freeipa reference reconcile     PASS
STEP 06    freeipa host remove             PASS
VERIFY     active_residue=0 unknown=0      PASS
FINALIZE   hosts.yml/inventory.yml         PASS
COMPLETE   receipt=<id>
```

Do not log secrets.

For JSON mode use a stable machine-readable schema.

---

## 41. Error taxonomy

Use typed/structured errors where practical.

Suggested classes:

```text
host_not_found
plan_blocked
plan_expired
plan_stale
approval_required
approval_hash_mismatch
dependency_cycle
required_provider_loss
retention_required
host_unreachable
ownership_unknown
external_state_unsupported
control_plane_host_requires_dedicated_workflow
cleanup_failed_retryable
cleanup_failed_terminal
active_residue
finalization_failed
already_completed
```

CLI exit behavior should distinguish user-fixable blockers from internal errors.

---

## 42. Definition of done

This feature is NOT done when:

- the CLI command exists;
- `hosts.yml` can be edited;
- FreeIPA `host-del` runs once;
- unit tests pass;
- one happy-path playbook returns exit code 0.

It is done only when all of the following are true:

1. acceptance contract exists;
2. old direct host-delete path cannot bypass decommission;
3. planner is read-only;
4. plan freshness is enforced;
5. approval is hash-bound and human-only;
6. FreeIPA client cleanup has real target evidence;
7. zero-residue verification is independent;
8. partial failure is resumable;
9. host remains in inventory until verification passes;
10. final inventory is valid/fresh;
11. historical evidence remains intact;
12. generic FreeIPA server/replica deletion remains blocked;
13. no Agent/MCP autonomous decommission exists;
14. supported providers have actual-run evidence;
15. idempotent/replay-safe behavior is demonstrated.

---

## 43. Coding-agent execution instructions

1. Read `AGENTS.md`.
2. Re-read the current main branch before editing; this spec is based on baseline `c39739018a39961d421deb439db8cc8921619a5f`.
3. If current main differs materially, preserve the invariants in this spec but adapt file locations/APIs to the new code.
4. First create/update the acceptance contract in `docs/verification/host-decommission.md`.
5. Add tests that fail for the current unsafe direct-delete behavior.
6. Implement Phase 1 core planner/store without live mutation.
7. Refactor TUI so no direct workspace delete bypass remains.
8. Add FreeIPA provider and complete canonical host absent semantics.
9. Gather real disposable-target evidence before documenting commands as verified.
10. Add additional providers only after each has independent verification.
11. Do not weaken blockers merely to make an integration test pass.
12. If a subsystem cannot be safely identified/cleaned, return a hard blocker and leave the host in `hosts.yml`.

---

## 44. Key design rationale

### Why a saga instead of rollback?

FreeIPA, Wazuh, local host state, DNS, nginx, certificates, and workspace YAML do not share a transaction.

After a central identity has been correctly revoked, recreating it automatically because a later unrelated cleanup step failed is often less safe than continuing forward.

Therefore:

```text
durable plan
+ idempotent steps
+ persisted completion
+ independent verify
+ resume
```

is the correct model.

### Why keep the host in `hosts.yml` until the end?

Because the host entry contains cleanup targeting metadata and because its presence makes incomplete retirement visible to Pilot.

Removing it early turns active residue into orphaned state.

### Why contract-driven component decommission?

Pilot already has a component contract model with `playbooks.decommission`. Extending that model avoids a growing hard-coded product switch and makes future components such as SNMP exporter, detection engine, and SRE monitoring agents declare their own lifecycle behavior.

### Why not delete historical Agent Controller data?

Retirement should stop future execution, not erase the audit trail of what happened before retirement.

### Why block unknown ownership?

A false negative residue is undesirable, but deleting a foreign DNS/service/identity object can cause a larger outage. Pilot must fail closed and make ambiguity explicit.

---

## 45. Final required invariant

The coding agent should treat this sentence as the feature's top-level acceptance criterion:

> **After Pilot reports a host decommission as COMPLETED, the host is absent from the canonical Pilot inventory, all supported Pilot-owned active references and external registrations for that host have been independently verified absent, no foreign resource was deleted, and historical audit/evidence data remains available.**

