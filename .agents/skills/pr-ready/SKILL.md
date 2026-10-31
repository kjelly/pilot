---
name: pr-ready
description: Repair and verify existing GitHub Draft pull requests until merge-ready, then mark them Ready for Review; use when asked to process exactly one Draft PR per invocation after checking out its original head branch, repair CI/review findings, or manage an iterative PR quality gate with independent subagents. Never merge PRs.
---

# PR Ready — multi-agent Draft PR remediation

## Single-item checkout contract (mandatory)

Follow the single-item scope and branch checkout contract,
`.agents/skills/_shared/single-item-checkout.md`, from the repo root (a path, not a
relative link: Claude Code presents this skill as the symlink `.claude/skills/<name>`,
where `../_shared` does not exist). Resolve this skill's directory with `realpath`
before reading shared files or taking the snapshot. Apply it
before analysis, edits, review, tests or delegation. Handle exactly one Issue/PR
per invocation; multiple/all targets require choosing one with the user. Checkout
the selected branch in the current clean checkout; do not create per-item worktrees.
Before each dispatch the contract's role check applies: PASS dispatches, DRIFT (the
target branch carries a different role file) dispatches with the snapshot as the
binding contract and a reported pin difference, STOP is `BLOCKED`. At the end, whatever
the outcome, the contract's restore step switches back to the starting branch when that
is safe, and otherwise stays and reports why.

## Project runtime configuration

This skill is repository-local: use the native `pr-sa`, `pr-coder`, and `pr-reviewer`
definitions shipped beside it; there is no personal installation. Codex invocation:
`$pr-ready`; Claude Code invocation: `/pr-ready`.

- The orchestrator runs on the invoking session's model: the repository pins no
  session model (`.codex/config.toml` sets no `model`, and no shared
  `.claude/settings.json` is versioned), so personal and per-session choices apply.
- Role models and effort live only in the native role definitions under
  `platforms/<platform>/agents/`: Codex roles `gpt-6.1-sol` / `high`; Claude SA
  `claude-opus-5-5` / `xhigh`; Claude Coder and Reviewer `claude-sonnet-5-5` /
  `xhigh`. `cmd/pilot/cmd/agent_skill_consistency_test.go` keeps the three
  platform copies of each role and the installed `.codex/agents` /
  `.claude/agents` files identical.
- Delegate by the configured native role name, with a fresh independent context;
  do not override its model/effort or use a conversation fork that inherits another
  model. Report unavailable roles/models rather than silently substituting them.
- Run packaged scripts and read references from the verified snapshot (`$SNAP`) the
  checkout contract takes, by absolute snapshot paths, never from the branch being
  worked on: it may predate or replace them. `$REPO_ROOT` is the current checkout.
  Do not fall back to `~/.agents/skills`.

You are the **orchestrator**, not the implementer of last resort. Execute the work; do not stop after making a plan. This skill supports Codex, Claude Code, and Antigravity CLI (`agy`). Use each runtime's native subagent mechanism; role contracts are under `references/roles.md` and the platform-native `pr-sa`, `pr-coder`, `pr-reviewer` agent definitions ship beside this skill (`platforms/<platform>/agents/`).

## Pilot: turn review history into a verification plan

Read [shared historical checks and vm-target prompts](../pilot-code-review/references/pilot-history-checks.md)
before SA/Coder dispatch. Resolve the reference to its absolute path inside the
verified snapshot for the children: the checked-out PR branch may predate it.
Read all relevant earlier findings and actual fix commits,
not merely the latest “fixed” comment. Maintain a finding ledger with root-cause
class, trigger, invariant, fix SHA and regression/counterexample. On the second
occurrence of a class, send SA to assess related callers/includes/backends before
another point fix. Verify tests fail for the intended reason when the fix is absent.

SA/Root must record `target_validation = required | not-needed | blocked` with a
reason before implementation; Reviewer must re-evaluate it before PASS. If the
claim depends on native service state, fresh-host ordering, selected tags,
upgrade/rollback or multi-host behavior, use candidate-bound vm-target/topology
validation when current evidence does not cover it. Test relevant failure paths
and recovery separately from the normal chain. Missing required target evidence
keeps the PR Draft. The current Python gate checks JSON/remote facts, not those
semantic assertions: Root must inspect target artifacts and put their paths and
limits into the review report and `assessment.rationale` before `--ready`.
Text-only changes need no unrelated VM run.

## Inputs and preflight

- Accept one PR number/URL. Multiple targets or **all Draft PRs** require asking the user to select one; never process a batch. If no target is supplied, use the current branch's PR when unambiguous; otherwise list Draft PRs and identify the scope before mutation.
- Verify `git`, `gh`, `python3`, an authenticated `gh auth status`, repository identity, a clean checkout, and write permission to the selected PR's head branch. If an action is permission-blocked, request the normal permission grant; **never** bypass sandbox/branch protections.
- Fetch for the selected PR: description/body, diff, base/head SHAs, linked issues, acceptance criteria, review comments and threads, required checks, all CI checks, branch restrictions, dependency edges. Do not assume a comment is resolved simply because it is outdated.
- Skip closed/merged PRs and never revert a non-Draft PR to Draft. If a Draft already meets every gate, do not make unnecessary changes.

## Branch checkout and dependency isolation

- Checkout the existing PR **head branch** in the current clean checkout; confirm branch name and HEAD equal the GitHub PR head before working. Do not create per-PR worktrees. Preserve the original branch and PR; no duplicate PRs, no destructive resets or force-push.
- For fork PRs, confirm head repository and permissions; if updating the original head is impossible, report `DRAFT-BLOCKED` rather than creating a replacement.
- Inspect dependencies as read-only context. An unmet prerequisite blocks this PR; do not start that prerequisite or another PR. Never let two writers touch the same branch/checkout or shared mutable resources at the same time.
- Keep this PR's state/checkpoint and validation receipts under `.pr-ready/<N>/` (N = PR number): one checkout serves different PRs over time, so never reuse another PR's state. Checkpoint after every meaningful step; on resume, revalidate the current remote HEAD and invalidate stale evidence.

## Per-PR execution loop

1. **Analyze first.** Gather GitHub context; derive acceptance criteria and reproduce reported failures. Check whether the PR already passes the entire quality gate.
2. **SA (`pr-sa`)** independently diagnose root cause, architectural impact, design options, and regressions. Produce a concise evidence-backed diagnosis.
3. **Coder (`pr-coder`)** owns implementation *only* in the verified checkout of that PR's head branch. Repair root cause, add or strengthen regressions, run tests, lint, and static analysis as applicable. Never weaken assertions, silence errors, skip meaningful checks, or hardcode expected results. Commit only changes belonging to this PR.
4. **Reviewer (`pr-reviewer`)** must be an independent agent/context, not the Coder relabelled. Review current diff for correctness, architecture, security, concurrency, edge cases, semantic regressions and test adequacy. Use [the shared severity/origin rubric](../issue-to-pr/references/severity.md); return P0/P1/P2 blocking findings with precise file:line evidence and report P3/P4 separately. Origin is relative to the PR base, not the previous review. A fix is not closed until its regression and relevant target evidence are checked; an outdated thread alone is not proof.
5. If blocking findings remain, hand back to Coder; rerun impacted checks and reviewer on the new commit. After **three effective unsuccessful fix rounds**, reassign SA for a fresh diagnosis. If still stuck, record `DRAFT-BLOCKED`, preserve the PR, and end this invocation without starting another item.
6. Before pushing, verify branch identity, uncommitted changes, and remote movement. Push **only the original PR head branch** (no force). After any push, discard all previously successful CI results as evidence for the new HEAD, and re-query GitHub until checks settle or an external blocker prevents completion.
7. Create a HEAD-specific evidence JSON using `references/evidence-schema.md`. Prefer `scripts/run_check.py` for local check receipts. Run `scripts/pr_gate.py` for a **fail-closed** machine-assisted gate; unresolved items remain Draft. `pr_gate.py --ready` is the *only* recommended mutation step to call `gh pr ready` after passing all automated checks and explicit reviewer/acceptance attestations. Never invoke `gh pr ready` on a failing gate.
8. Final report: PR URL/number, `READY` or `DRAFT-BLOCKED`, actual fixes/root cause, independent review result, test/CI results, final HEAD SHA, blockers/next action, the branch the checkout ended on (restored to the starting branch, or why it stayed), and any role DRIFT (role, both hashes, `header_changes`), which also goes into `assessment.rationale`. Do not claim READY if GitHub post-action verification failed.

## Quality / authority rules

- Gate requires all acceptance criteria met, actual root-cause fix, appropriate local validations, no serious design flaws, all required CI successful, no relevant failing CI, no outstanding P0/P1/P2 or major review comments, no conflict/unresolved dependencies, accurate PR description, and verification against **current remote HEAD**.
- **Human approval is not required to change Draft → Ready for Review.** Distinguish pending approval from unresolved technical objections; do not treat `REVIEW_REQUIRED` alone as a blocker.
- Treat LLM assertions as attestations, not GitHub facts. The gate script verifies machine-readable GitHub state and HEAD; it cannot prove semantic correctness without the independent review and test evidence.
- Never merge, enable auto-merge, bypass branch protection, use `--admin`, or change repository settings. No quality compromises due to time/tokens/attempt count. Report blockers rather than fabricate success.
- If subagent tools are genuinely unavailable, **do not claim independent review occurred**. Leave Draft, state the missing prerequisite and retain all work/evidence.

## Context discipline / supporting docs

- Read `references/workflow.md` for checkout, checkpoint, and resumption.
- Read `references/roles.md` before delegating; pass concise task inputs and have agents return structured summaries, not full logs.
- Read `references/evidence-schema.md` and `references/quality-gate.md` before the final gate.
- Run `python3 "$SNAP/.agents/skills/pr-ready/scripts/pr_gate.py" --help` and `python3 "$SNAP/.agents/skills/pr-ready/scripts/run_check.py" --help` to learn flags without loading script sources into context.
- Native agent roles live under Codex `.codex/agents` (copies) and Claude `.claude/agents` (symlinks into this skill); the agy definitions are in `platforms/agy/agents/` (copy into `.agents/agents/` when agy is used, and list `/.agents/agents/` in `$(git rev-parse --git-path info/exclude)`). Delegate using native facilities and these role names, without inventing tool API names.
