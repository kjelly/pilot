# Minimal POC subagent delegation policy

This workflow uses the root agent as a serialized controller and custom Luna
agents as bounded workers. Delegation is for context isolation and lower-cost
atomic work, not uncontrolled parallel execution.

## Root controller ownership

The root controller exclusively owns:

- complete interpretation of all required Skills and the runbook;
- the immutable execution contract and checkpoint ordering;
- authorization of destructive operations;
- classification of unexpected results;
- approval or rejection of retries, remediation, alternate paths, and scope
  changes;
- the decision to update documentation in update mode;
- the final PASS, FAIL, or BLOCKED verdict.

Never delegate those decisions.

## Custom agents

### `poc_state_probe`

Use for one bounded read-only question, such as:

- whether named VMs exist;
- whether the disposable workspace or stale generated files exist;
- device, socket, mount, ACL, process, or permission state;
- whether a completed artifact exists and is immutable.

### `poc_step_runner`

Use for exactly one preselected state-changing checkpoint, such as:

- deleting a named set of runbook VMs;
- creating one VM through `pilot vm-target`;
- running one `pilot edit` wizard;
- running one inventory-generation command;
- running one `pilot deploy` wizard;
- running one explicitly authorized reconcile or verification operation.

It must stop after the assigned checkpoint.

### `poc_evidence_auditor`

Use to compare one completed requirement against one immutable evidence bundle.
It may inspect transcripts and persisted files but may not repair or change the
environment.

### `poc_roster_builder`

Use only to create and validate the explicitly permitted new
`freeipa-identity` nested roster at `.vault/ipa-identity.yaml`.

### `poc_bug_investigator`

Use for a bounded, read-only suspected-bug investigation after the root
controller supplies transcript evidence, persisted-state evidence, relevant
code scope, and one hypothesis to test. It must not modify product code.

## Required delegation envelope

Every request to a custom agent must include:

- mode: `update` or `revalidate`;
- checkpoint ID and runbook requirement;
- exact objective;
- current verified preconditions;
- allowed commands or command family;
- allowed read and write paths or resources;
- forbidden actions;
- expected result;
- evidence to capture;
- stop conditions;
- required result format.

Do not delegate vague tasks such as:

> Follow the runbook and finish the remaining deployment. Fix problems as needed.

Prefer:

> Execute checkpoint VM-02 only. Create `freeipa-server` through the exact
> `pilot vm-target` path specified by the runbook. Do not create another VM,
> edit inventory, or start deployment. Stop on any unexpected prompt or path.

## Wait and review gate

After a state-changing worker returns, the root controller must:

1. wait for the worker to finish;
2. review its checkpoint result and evidence paths;
3. use `poc_evidence_auditor` when independent evidence review is needed;
4. classify the checkpoint;
5. select the next checkpoint explicitly.

The root controller must not queue dependent state-changing operations in
parallel.

## Failure handling

A child agent stops at the first unexpected result and returns control.
A child agent must never independently:

- choose or invent a workaround;
- switch VM target or deployment mechanism;
- reuse stale state;
- manually edit generator-owned files;
- suppress an error;
- reinterpret a requirement;
- continue into a later checkpoint;
- spawn another subagent.

The root controller classifies failures as one of:

- retryable execution failure;
- environment or permission blocker;
- implementation defect;
- runbook defect;
- evidence deficiency;
- human policy or input decision required.

## Escalation

Luna is the default for bounded worker tasks. The root controller may keep the
work instead of delegating, or explicitly use a stronger model, when the task
requires open-ended cross-subsystem reasoning, safety judgment, or final
adjudication. Do not escalate merely because an environment permission is
missing.
