# Work sequencing and review discipline

1. Inventory (paginated) open Ready PRs via `python3 scripts/list_ready.py --repo OWNER/REPO`; include individual PR targets exactly when specified.
2. Resolve PR DAG (stacked PRs, explicit depends-on text, related Issues, shared touching files, migrations). Cross-PR interactions require a separate dependency review. Do not assume issue references imply hard dependencies.
3. Read the pilot history reference (`../../pilot-code-review/references/pilot-history-checks.md`) and the base branch's `.github/pr-evidence.json`; for each PR note which changed paths need an actual-run record (the manifest's `required_paths` always do) and whether a `docs/evidence/**` record covers its HEAD or tested revision. Pass the absolute reference path and the relevant earlier findings to every reviewer. The gate re-reads the manifest at the PR's base SHA through the GitHub API and checks `target_validation` itself (`evidence-contract.md`); no local checkout is needed.
4. Collect the earlier findings disputed on each PR and the replies disputing them (SKILL.md, "Disputed findings"); they go to that PR's reviewer.
5. Allocate up to two independent PR reviewer subagents. They review the actual diff at a captured Head/Base SHA and may run sandboxed, trusted tests in isolated worktrees without touching PR state. Use capped log artifacts and include only summary/paths in Root context.
6. Save each reviewed PR evidence JSON according to `evidence-contract.md`. If reviewer returned findings without exact location/evidence, ask reviewer for targeted verification before classification.
7. Run read-only gate; WAITING PRs are left unchanged. For confirmed blockers, guarded actor posts findings + converts to Draft. For clean PRs, Root serially runs actor with `--execute`.
8. After each merge, update the dependency ledger and **invalidate/review evidence for PRs whose Base SHA has changed**. GH may automatically update base SHA when merging another PR. Do not reuse a passing review against a prior base.
9. Revisit WAITING PRs only when they can progress; do not loop forever waiting for CI or approval.
10. Final report includes exact state and evidence per PR, including error cases and partial GitHub operations.

# Expected reviewer return (compact)

```
PR: #123 (URL)
HEAD: <40 hex>  BASE: <40 hex>
Verdict: PASS | BLOCK | NEEDS_MORE_EVIDENCE
Coverage: requirements, correctness, architecture, security, concurrency, edge_cases,
          semantic_regression, tests (each explicitly assessed)
Findings: [severity, path:line, concrete evidence, suggested fix, disputed_reply_url + new_evidence when repeating a disputed finding]
Tests: [name, status, evidence URL or artifact path]
Dependencies: resolved? rationale
Target validation: required | not-needed | blocked, reason (30+ chars) with the invariant, docs/evidence artifact + full 40-hex tested revision it names
Risks or unknowns: ...
```

# Workflow separation

`issue-to-pr` creates Ready PRs, `pr-review-merge` reviews the Ready queue and handles merge vs Draft, `pr-ready` fixes Draft PRs and promotes them to Ready. Skills do not automatically invoke each other recursively; Root owns the desired transition and prevents endless cycles. The two gates agree on what is left for the PR to fix: a state `pr-ready` accepts for Ready is never a `DRAFT` here (`tests/test_pr_ready_handoff.py`), and a disputed finding repeated without new evidence goes to a person on both sides.
