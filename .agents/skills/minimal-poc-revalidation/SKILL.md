---
name: minimal-poc-revalidation
description: >
  Perform a clean-room revalidation of
  docs/runbooks/minimal-poc-architecture.md.
  Use only when the user explicitly requests a complete or partial
  minimal-poc architecture revalidation, evidence audit, or rerun.
---

# Minimal POC revalidation

## Scope

This skill applies only to revalidation of:

- `docs/runbooks/minimal-poc-architecture.md`

Do not apply this workflow to ordinary implementation, documentation,
code review, or unrelated infrastructure tasks.

## Required inputs

Before making any change, read completely:

- `docs/runbooks/minimal-poc-architecture.md`
- `.agents/skills/pilot-trec-verification/SKILL.md`
- `$HOME/.agents/skills/trec-mcp/SKILL.md`
- `$HOME/.agents/skills/trec-tui-drive/SKILL.md`

Resolve their requirements into a numbered execution contract.

## Controller responsibilities

The root agent exclusively owns:

- interpretation of the complete runbook;
- ordering of state transitions;
- authorization of destructive operations;
- decisions after unexpected results;
- approval or rejection of alternative paths;
- final evidence assessment;
- the final PASS, FAIL, or BLOCKED verdict.

Do not delegate these responsibilities.

## Delegation policy

Use the following custom agents:

### `poc_state_probe`

Use for one bounded, read-only inspection:

- existing VM state;
- disposable workspace state;
- forbidden stale files;
- device, socket, mount, ACL, or permission state;
- completed evidence inspection.

### `poc_step_runner`

Use for exactly one preselected state-changing step.

The delegated request must specify:

- runbook requirement;
- exact objective;
- allowed commands;
- writable resources;
- expected result;
- evidence to capture;
- stop conditions.

The agent must stop after that step.

### `poc_evidence_auditor`

Use to compare one completed requirement against immutable evidence.

It may not modify the environment or repair failures.

### `poc_roster_builder`

Use only for the explicitly permitted nested FreeIPA identity roster.

It may not create or modify ordinary generated inventory or group variables.

## Serialization

Only one state-changing agent may run at a time.

Never run these concurrently:

- teardown;
- VM creation;
- inventory generation;
- interactive wizard execution;
- deployment;
- FreeIPA mutation;
- NFS configuration;
- idempotency reruns.

Read-only audits may overlap only after their input evidence is complete
and immutable.

## Failure policy

Every delegated agent stops at the first unexpected result.

A delegated agent must never independently:

- select a workaround;
- change target type;
- reuse stale state;
- manually edit generator-owned files;
- suppress errors;
- reinterpret a runbook requirement;
- continue into the next checkpoint.

The root agent must classify the result as:

- retryable execution failure;
- environment blocker;
- implementation defect;
- runbook defect;
- evidence deficiency;
- policy decision required.

## Output contract

Each state-changing step returns:

1. checkpoint identifier;
2. commands executed;
3. exit status;
4. concise relevant output;
5. resources changed;
6. evidence paths;
7. expected versus observed result;
8. PASS, FAIL, or BLOCKED.

Store complete logs as evidence files. Return only focused excerpts to the
root context.
