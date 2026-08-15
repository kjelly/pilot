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

- `docs/runbooks/minimal-poc-architecture.md` — the document under update;
- `.agents/skills/_shared/clean-room-contract.md` — the common clean-room
  contract this workflow executes (modes, Pilot ownership, teardown/rebuild
  sequence, wizard input policy, serialization, stop conditions, output
  contract, cleanup);
- `.agents/skills/pilot-trec-verification/SKILL.md` — the wizard-driving and
  recording contract. Its §4b rules table is complete and normative on its own;
  load a file from its `references/` directory when you reach the screen or
  decision that file covers;
- `$HOME/.agents/skills/trec-tui-drive/SKILL.md` — the `trec drive` DSL.

Read **only if this run actually needs a stateful back-and-forth with a live
screen** (menu discovery, diagnosing a derailed run — see
`pilot-trec-verification/references/mcp-mode.md`):

- `$HOME/.agents/skills/trec-mcp/SKILL.md`.

`.agents/skills/delivery-test/SKILL.md` was retired 2026-08-14 — its scope (internal-endpoint,
reverse-proxy, freeipa-ca-trust, freeipa-dns-client, host-monitoring) is now part of THIS runbook's
own §0.5/§3.7/§3.8/§4.2/§4.5 (marked DRAFT until a live round confirms them). Do not go looking for
a separate delivery-test scenario to reconcile against; there is only one canonical topology now.

If any required file is unavailable, return BLOCKED.

Create:

1. a numbered execution contract;
2. a checkpoint matrix;
3. an observed-differences ledger;
4. a current-run evidence directory.

Do not modify the runbook at this stage.

## 2. Execute from zero

Execute `_shared/clean-room-contract.md` in **clean-room acceptance** mode
(its §1). That file is authoritative for the teardown/rebuild sequence (§4),
Pilot ownership and the permitted hand-edit exceptions (§3), the wizard input
policy (§5), the recording gate (§6), serialization (§7), and cleanup (§10).

Run in **clean-room acceptance** mode, never diagnosis mode: this workflow
updates a committed runbook, so a diagnostic rerun cannot supply its evidence.

Two points from the contract carry extra weight for this workflow specifically:

- **Deploy every role again, including roles that appear already satisfied.**
  A green check-mode preview on an already-applied host proves nothing about a
  genuinely fresh one, and this runbook's value is the fresh path.
- **Persisted-file checks are part of every wizard checkpoint**, not just the
  cast. `grep` each key you intended to set and compare the actual value on
  disk; a cast showing `✅ 已存檔` proves a save happened, not that the right
  fields got the right values.

## 3. Delegate bounded work

Delegate narrow, bounded work to subagents rather than doing everything inline,
using the general-purpose agent for each of these roles:

- one read-only precondition probe at a time;
- one selected atomic state-changing checkpoint at a time;
- one completed evidence check at a time;
- roster authoring for the new FreeIPA nested roster (follow the
  `freeipa-roster-authoring` skill's contract);
- one bounded read-only suspected-bug hypothesis at a time.

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
