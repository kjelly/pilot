---
name: minimal-poc-update
description: Empirically rebuild and deploy the minimal POC from a clean environment, record every Pilot wizard with TREC, compare observed behavior with docs/runbooks/minimal-poc-architecture.md, and update that runbook from verified evidence. Use only when the user explicitly asks to update, correct, refresh, or regenerate the minimal POC runbook; do not use for a read-only revalidation.
---

# Update the minimal POC runbook from verified execution

This Skill applies only to updating:

- `docs/runbooks/minimal-poc-architecture.md`

The workflow is an empirical documentation update: execute the current process
from a clean environment, collect evidence, then update the runbook. Do not edit
the runbook first to make the deployment appear successful.

## 1. Load the complete contract

Before any destructive action, read completely:

- `docs/runbooks/minimal-poc-architecture.md`;
- `.agents/skills/pilot-trec-verification/SKILL.md`;
- `.agents/skills/delivery-test/SKILL.md`;
- `$HOME/.agents/skills/trec-mcp/SKILL.md`;
- `$HOME/.agents/skills/trec-tui-drive/SKILL.md`;
- `../../workflows/minimal-poc/common-contract.md`;
- `../../workflows/minimal-poc/delegation-policy.md`.

If any required file is unavailable, return BLOCKED.

Create:

1. a numbered execution contract;
2. a checkpoint matrix;
3. an observed-differences ledger;
4. a current-run evidence directory.

Do not modify the runbook at this stage.

## 2. Execute from zero

Apply the common clean-room contract:

- record and remove every runbook VM;
- remove the entire disposable workspace;
- prove prohibited stale state is absent;
- create a new workspace;
- rebuild VMs only through `pilot vm-target`;
- create ordinary settings only through `pilot edit` and
  `pilot inventory generate`;
- create only the explicitly allowed new FreeIPA roster or narrowly scoped
  reconcile input exceptions;
- deploy every role again through `pilot deploy` wizard, including roles that
  appear already satisfied;
- never invoke `ansible-playbook` directly.

Use TREC and persisted-file checks for every wizard exactly as required by the
common contract.

Follow the shared wizard input policy:

- select `Y` for automatically detected `-e` values;
- leave manually entered additional `-e` empty;
- if any other human-authored value is required, stop the entire workflow.

## 3. Delegate bounded work

Use the custom agents defined in the delegation policy:

- `poc_state_probe` for one read-only precondition;
- `poc_step_runner` for one selected atomic state-changing checkpoint;
- `poc_evidence_auditor` for one completed evidence check;
- `poc_roster_builder` only for the new FreeIPA nested roster;
- `poc_bug_investigator` for one bounded read-only suspected-bug hypothesis.

Only one state-changing agent may run at a time. The root controller retains all
ordering, deviation, and final documentation decisions.

## 4. Maintain an observed-differences ledger

For every difference between the current runbook and observed behavior, record:

- requirement or section;
- expected behavior;
- observed behavior;
- transcript and persisted-state evidence;
- whether the difference is documentation-only, environment-specific,
  intentional design, or a suspected product defect;
- whether the workflow can continue safely.

Do not rewrite the runbook while the relevant deployment checkpoint is still in
progress or unstable.

## 5. Stop conditions for implementation changes

If completing or accurately documenting the workflow requires modifying any:

- Ansible playbook, role, or task;
- Go source code;
- product implementation outside the runbook;

then:

1. stop immediately;
2. do not modify the implementation;
3. preserve the current evidence;
4. report the exact file, symbol, behavior, and proposed direction;
5. ask the user for authorization before any implementation change.

A documentation-only correction may proceed when supported by evidence and it
does not conceal a product defect.

## 6. Update the runbook only after evidence stabilizes

After the executable checkpoints have reached stable PASS, FAIL, or BLOCKED
states:

1. map each proposed edit to evidence;
2. update only `docs/runbooks/minimal-poc-architecture.md` and explicitly
   authorized documentation artifacts;
3. preserve clean-room, Pilot ownership, TREC, wizard input, and verification
   requirements;
4. do not document an unexecuted workaround as a verified path;
5. distinguish normative steps from environment-specific notes;
6. verify that commands, paths, prompts, and expected persisted values match the
   current evidence.

After editing, reread the affected sections and compare them against the
observed-differences ledger.

## 7. Final output

Return:

- summary of the clean-room execution;
- checkpoint matrix and verdicts;
- evidence index;
- runbook sections changed and the evidence supporting each change;
- all problems found, with severity and reproduction details;
- unresolved BLOCKED or FAIL items;
- explicit confirmation that no playbook or Go source was modified, unless the
  user separately authorized it.

Do not claim the runbook is fully verified when required checkpoints remain
BLOCKED or lack evidence.
