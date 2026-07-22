---
name: minimal-poc-revalidate
description: Revalidate the existing docs/runbooks/minimal-poc-architecture.md from a completely clean environment using Pilot and TREC, without modifying the runbook or product implementation. Use only when the user explicitly asks to rerun, verify, audit, or prove the current minimal POC runbook; do not use when the user wants the runbook updated.
---

# Revalidate the existing minimal POC runbook

This is a verification-only workflow. The runbook is the subject under test and
must remain unchanged.

## 1. Load the complete contract

Before any destructive action, read completely:

- `docs/runbooks/minimal-poc-architecture.md`;
- `.agents/skills/pilot-trec-verification/SKILL.md`;
- `$HOME/.agents/skills/trec-mcp/SKILL.md`;
- `$HOME/.agents/skills/trec-tui-drive/SKILL.md`;
- `../../workflows/minimal-poc/common-contract.md`;
- `../../workflows/minimal-poc/delegation-policy.md`.

If any required file is unavailable, return BLOCKED.

Translate the existing runbook into an immutable numbered requirement matrix
before changing state. Each row must include acceptance criteria and required
evidence.

## 2. Immutability boundary

Do not modify:

- `docs/runbooks/minimal-poc-architecture.md`;
- Ansible playbooks, roles, or tasks;
- Go source code;
- other product implementation;
- repository instructions merely to make the run pass.

When observed behavior differs from the runbook, record the difference as FAIL
or BLOCKED with evidence. Do not reinterpret documentation drift as success and
do not repair the runbook during this workflow.

The only generated execution inputs permitted are those explicitly allowed by
the common contract, including the new FreeIPA nested roster and narrowly
scoped `pilot reconcile` inputs.

## 3. Execute from zero

Apply the common clean-room contract:

- record and remove every required VM;
- delete the entire disposable workspace;
- prove prohibited stale state is absent;
- create a new workspace;
- rebuild every VM only through `pilot vm-target`;
- create ordinary configuration only through `pilot edit` and
  `pilot inventory generate`;
- generate the new FreeIPA roster from
  `playbooks/apply/freeipa-identity.roster.example.yaml` at the new workspace's
  `.vault/ipa-identity.yaml`;
- run every deployment, including `freeipa-identity`, through `pilot deploy`;
- never invoke `ansible-playbook` directly.

If any required ordinary setting cannot be produced by `pilot edit` or
`pilot inventory generate`, stop immediately and return BLOCKED or FAIL as
appropriate. Do not hand-edit or use a substitute tool.

Follow the shared wizard input policy:

- select `Y` for automatically detected `-e` values;
- leave manually entered additional `-e` empty;
- if any other human-authored value is required, stop the entire workflow.

## 4. TREC and persisted-state gates

Record every wizard process independently with TREC.

After each wizard save:

1. inspect the actual persisted file;
2. compare it with the immutable requirement matrix;
3. store the check as evidence;
4. continue only if the checkpoint permits continuation.

When a suspected bug appears:

1. confirm key placement and focus in the transcript;
2. inspect actual disk content;
3. read relevant code and comments;
4. check intended design;
5. vary exactly one condition per reproduction attempt.

Do not change product code during investigation.

## 5. Delegate bounded work

Use the custom agents defined in the delegation policy:

- `poc_state_probe` for one read-only precondition;
- `poc_step_runner` for one selected atomic state-changing checkpoint;
- `poc_evidence_auditor` for one completed evidence check;
- `poc_roster_builder` only for the new FreeIPA nested roster;
- `poc_bug_investigator` for one bounded read-only suspected-bug hypothesis.

Only one state-changing agent may run at a time. The root controller retains
all ordering, retry, deviation, and final verdict decisions.

## 6. Final verdict

Evaluate every immutable requirement as PASS, FAIL, or BLOCKED according to the
common contract.

The overall result is:

- PASS only when every mandatory requirement passes with current-run evidence;
- FAIL when any mandatory runbook requirement or product behavior violates its
  acceptance criteria;
- BLOCKED when completion is prevented by environment, permissions, missing
  dependency, missing human value, or mandatory unavailable tooling.

Incomplete or missing evidence is never PASS.

## 7. Final output

Return:

- immutable requirement matrix;
- checkpoint results;
- transcript and evidence index;
- expected-versus-observed differences;
- detailed suspected or confirmed problem reports;
- final PASS, FAIL, or BLOCKED verdict;
- explicit confirmation that runbook, playbook, and Go source remained
  unchanged.
