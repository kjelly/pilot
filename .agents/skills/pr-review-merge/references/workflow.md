# Work sequencing and review discipline

1. Select exactly one Ready PR. For multiple/all targets, list candidates via `python3 scripts/list_ready.py --repo OWNER/REPO` and ask which one to handle. Follow the checkout contract, `.agents/skills/_shared/single-item-checkout.md` (repo-root path), before review.
2. Resolve PR DAG (stacked PRs, explicit depends-on text, related Issues, shared touching files, migrations). Cross-PR interactions require a separate dependency review. Do not assume issue references imply hard dependencies.
3. Read the pilot history reference (`../../pilot-code-review/references/pilot-history-checks.md`) and the base branch's `.github/pr-evidence.json`; for the selected PR note which changed paths need an actual-run record and whether a `docs/evidence/**` record covers its HEAD or tested revision. Pass the absolute reference path and the relevant earlier findings to every reviewer.
4. After checking out the selected PR head branch, allocate one independent reviewer. It reviews the actual diff at captured Head/Base SHAs and may run sandboxed, trusted tests in that checkout without touching source, branches or PR state. Use capped log artifacts and include only summary/paths in Root context.
5. Save each reviewed PR evidence JSON according to `evidence-contract.md`. If reviewer returned findings without exact location/evidence, ask reviewer for targeted verification before classification.
6. Run read-only gate; a WAITING PR is left unchanged. For confirmed blockers, guarded actor posts findings + converts to Draft. For a clean PR, Root runs the actor with `--execute`.
7. Before acting, **invalidate/review evidence if the selected PR Base SHA has changed**. Do not reuse a passing review against a prior base. After handling this PR, stop; no next-item scheduling.
8. Re-check the selected PR's WAITING reason only if it can progress within this session; do not loop forever waiting for CI or approval. Otherwise report WAITING and stop.
9. Final report includes exact state and evidence for the selected PR, including error cases and partial GitHub operations.

# Expected reviewer return (compact)

```
PR: #123 (URL)
HEAD: <40 hex>  BASE: <40 hex>
Verdict: PASS | BLOCK | NEEDS_MORE_EVIDENCE
Coverage: requirements, correctness, architecture, security, concurrency, edge_cases,
          semantic_regression, tests (each explicitly assessed)
Findings: [severity, path:line, concrete evidence, suggested fix]
Tests: [name, status, evidence URL or artifact path]
Dependencies: resolved? rationale
Target validation: required | not-needed | blocked, invariant, docs/evidence artifact + tested revision
Risks or unknowns: ...
```

# Workflow separation

`issue-to-pr` creates Ready PRs, `pr-review-merge` reviews one selected Ready PR and handles merge vs Draft, `pr-ready` fixes Draft PRs and promotes them to Ready. Skills do not automatically invoke each other recursively; Root owns the desired transition and prevents endless cycles.
