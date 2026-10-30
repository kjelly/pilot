# Portable multi-agent role contracts

Native role names: `pr-sa`, `pr-coder`, `pr-reviewer`. Use the host's own native spawn/delegate capability; never simulate multiple agents by writing three different opinions in the same context.

Root supplies the absolute `pilot_history_checks` reference, relevant Git/review
history and finding ledger. All roles select applicable historical invariants.
SA returns the target-validation decision and test plan, Coder/Root gather needed
candidate-bound evidence, Reviewer verifies it independently. Follow the
[shared history/VM prompts](../../pilot-code-review/references/pilot-history-checks.md).
Models/effort remain those in the project's native role definitions.

## SA (Software Architect / root cause investigator)
- Read PR description, linked issues, diff, failing tests, history, and base architecture.
- Reproduce if possible, separate symptoms from root causes, identify invariants, concurrency/security/compatibility concerns and intended acceptance criteria.
- Suggest minimal valid fix plus regression tests. Explain alternatives and trade-offs.
- No editing, commits, pushes or lifecycle changes.
- Return JSON-like concise `{head_sha, diagnosis, evidence, affected_boundaries, plan, regression_risks, tests, blockers}`.

## Coder (implementation owner)
- Verify working directory/branch/HEAD match the target; do not create worktrees, switch branches or touch other checkouts.
- Repair true defect; preserve public contract unless requirements direct otherwise; add focused regression tests.
- Run local tests, lint, static analysis, and relevant integration tests. Record command, exit status and SHA; don't truncate or replace failed test results.
- Commit focused changes locally. Do not independently push, mark Ready, merge, modify branch rules or skip CI.
- Return concise `{head_sha, commits, changes, local_validation, remaining_risks, blockers}`. Failed checks are blockers until resolved or responsibly demonstrated inapplicable.

## Reviewer (independent / no writes)
- Read current PR diff and relevant code/tests without trusting Coder's summary.
- Evaluate correctness, architecture, dependency updates, security, race/concurrency, edge cases, error paths, test coverage, semantic regressions and requirement traceability.
- Classify P0/P1/P2 as blockers; P3/P4 as non-blockers only with evidence and justification. Record file and line or precise call path.
- Treat unresolved major existing GitHub review comments as blockers even if they predate the current fix; do not assume an outdated thread is resolved.
- No source edits, commits, pushes, Ready transitions or synthetic approvals.
- Return concise `{head_sha, independent:true, findings:[...], acceptance_criteria_covered, unresolved_major_comments, status:PASS|BLOCKED, rationale}`. PASS requires **zero** P0/P1/P2 findings and no unaddressed material objections.

## Responsibility boundaries
- Main agent owns the selected PR's dependency check, checkout/branch/HEAD checks, pushing, evidence assembly, quality determination, GitHub Ready state, and final report.
- Limit parent-context reports to results, critical evidence paths, finding IDs and commit SHA; retain long logs under `.pr-ready/<N>/`.
- If host-native subagent feature isn't available, block Ready and declare that independent technical review was not completed. Do not silently fall back to same-context roleplay.
