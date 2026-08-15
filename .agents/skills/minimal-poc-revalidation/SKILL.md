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
- `.agents/skills/_shared/clean-room-contract.md` — modes, Pilot ownership,
  teardown/rebuild, wizard input policy, serialization, stop conditions,
  output contract, cleanup
- `.agents/skills/pilot-trec-verification/SKILL.md` — its §4b rules table is
  complete and normative on its own; load a `references/` file when you reach
  the screen or decision it covers
- `$HOME/.agents/skills/trec-tui-drive/SKILL.md`

Read only if this run needs a stateful back-and-forth with a live screen
(see `pilot-trec-verification/references/mcp-mode.md`):

- `$HOME/.agents/skills/trec-mcp/SKILL.md`

Resolve their requirements into a numbered execution contract.

This skill is **read-only with respect to the runbook**: revalidate and report,
never edit `minimal-poc-architecture.md`. Use `minimal-poc-update` when the
runbook itself must change.

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

## Serialization, recording gate, failure policy, output contract

These are not restated here — they are shared with `minimal-poc-update`
(`delivery-test` was retired 2026-08-14 and merged into that runbook), and a second copy would
drift. Apply, as written:

| Concern | Authority |
|---|---|
| Serialization of state-changing work | `_shared/clean-room-contract.md` §7 |
| Failure policy and stop conditions | `_shared/clean-room-contract.md` §8 |
| Per-step output contract | `_shared/clean-room-contract.md` §9 |
| Recording/evidence gate, cast directories, manifest | `pilot-trec-verification/SKILL.md` §3a |
| Wizard keyboard-driving rules | `pilot-trec-verification/SKILL.md` §4b |

The delegation policy above is specific to this skill and overrides nothing in
those files; the contract's serialization rule (§7) applies to the custom agents
named here exactly as it does to a general-purpose one.
