# Work sequencing and review discipline

1. Select exactly one Ready PR. For multiple/all targets, list candidates via `python3 "$SNAP/.agents/skills/pr-review-merge/scripts/list_ready.py" --repo OWNER/REPO` and ask which one to handle. Follow the checkout contract, `.agents/skills/_shared/single-item-checkout.md` (repo-root path), before review.
2. First require the live base branch tip to be an ancestor of PR HEAD and PR Base SHA to equal that tip. A failure confirmed by fresh PR/ref reads is an operational Draft hand-off to `pr-ready`: record HEAD/Base/live-base SHAs, run the actor to comment then convert, and stop this invocation. No completed semantic review is required for this case. If the live ref or ancestry is unavailable, or identities change during confirmation, leave WAITING. Otherwise resolve PR DAG (stacked PRs, explicit depends-on text, related Issues, shared touching files, migrations). Cross-PR interactions require a separate dependency review. Do not assume issue references imply hard dependencies.
3. Read the pilot history reference (`../../pilot-code-review/references/pilot-history-checks.md`) and the base branch's `.github/pr-evidence.json`; for the selected PR note which changed paths need an actual-run record (the manifest's `required_paths` always do) and whether a `docs/evidence/**` record covers its HEAD or tested revision. Pass the absolute reference path and the relevant earlier findings to every reviewer. The gate re-reads the manifest at the PR's base SHA through the GitHub API and checks `target_validation` itself (`evidence-contract.md`); the gate itself needs no local checkout (the reviewer's checkout comes from the contract).
4. Collect the earlier findings disputed on the selected PR and the replies disputing them (SKILL.md, "Disputed findings"); they go to its reviewer.
5. After checking out the selected PR head branch, allocate one independent reviewer. It reviews the actual diff at captured Head/Base SHAs and may run sandboxed, trusted tests in that checkout without touching source, branches or PR state. Use capped log artifacts and include only summary/paths in Root context.
6. Save each reviewed PR evidence JSON according to `evidence-contract.md`. If reviewer returned findings without exact location/evidence, ask reviewer for targeted verification before classification.
7. Run read-only gate; a WAITING PR is left unchanged. Before Draft conversion or merge, complete the shared safe restore and verify the starting branch/SHA. Restore failure leaves the PR unchanged (WAITING). After restoration, rerun the live gate using saved PR HEAD/Base and external evidence, then run the guarded actor with `--execute`. It posts findings before Draft conversion, or merges a clean PR, and verifies remote state. No checkout switch follows the state change.
8. Before acting, **invalidate/review evidence if the selected PR Base SHA has changed**. Do not reuse a passing review against a prior base. Confirmed base ancestry or metadata failures go to Draft for `pr-ready`; stale evidence alone still waits for fresh review. After handling this PR, stop; no next-item scheduling.
9. Re-check the selected PR's WAITING reason only if it can progress within this session; do not loop forever waiting for CI or approval. Otherwise report WAITING and stop.
10. Final report includes exact state and evidence for the selected PR, including error cases and partial GitHub operations. If the contract's role check reported DRIFT for a role, record the role, both hashes and `header_changes` in the evidence `summary` too.
11. Report the restore already completed before the actor; `--safe-sha` is the reviewed HEAD. For outcomes without an actor call, restore before reporting. Do not defer restoration until after changing GitHub PR state.

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

`issue-to-pr` creates Ready PRs, `pr-review-merge` reviews one selected Ready PR and handles merge vs Draft, `pr-ready` fixes Draft PRs and promotes them to Ready. Skills do not automatically invoke each other recursively; Root owns the desired transition and prevents endless cycles. With the same live base tip included in HEAD, states accepted by `pr-ready` stay Ready here (`tests/test_pr_ready_handoff.py`). A newly confirmed base ancestry or metadata failure instead requires Draft and integration/reconciliation before Ready again. A disputed finding repeated without new evidence goes to a person on both sides.
