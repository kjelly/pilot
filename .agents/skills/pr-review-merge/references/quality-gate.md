# Quality gate: classifications and safety

| Signal | Decision | Why |
|---|---|---|
| Independent reviewer finds P0/P1/P2 (a repeated disputed claim only with new evidence), failing unit/regression tests, GH checks `fail` or `cancel` not confirmed unrelated, unresolved review threads, merge conflict | DRAFT | Confirmed defect or blocker; comment with proof and next fix |
| GH checks `pending`, review `REVIEW_REQUIRED`, PR mergeability `UNKNOWN`, unavailable GraphQL threads, base/head mismatch, incomplete reviewer coverage, PR dependency not satisfied | WAITING | Transient or unverified conditions; keep Ready |
| `CHANGES_REQUESTED`; a `fail`/`cancel` check listed in `unrelated_failing_checks`; a disputed finding repeated without `new_evidence` | WAITING | The PR has nothing left to change: a reviewer has to re-review, a check has to be rerun after its cause is fixed, or a person decides between two reviews. A Draft would be undone by `pr-ready` |
| Active rules include `merge_queue` | WAITING | `gh pr merge` may enqueue or enable auto-merge without a final merge; do not trigger automatically |
| Empty CI, no documented rationale or no positive test evidence | WAITING | Absent checks are not an implicit pass |
| Every gate clear, no unresolved threads, base/HEAD unchanged, branch mergeability `MERGEABLE`, merge state `CLEAN`, tests/CI passed | MERGE | Attempt `gh pr merge --merge --match-head-commit SHA` (merge commits are this repository's practice); verify state `MERGED` |
| Repository-mandated actual-run evidence missing for a change that needs it (`.github/pr-evidence.json`, AGENTS.md §1) | DRAFT | Hard repository rule violated; the reviewer files a `P1` at the changed path naming the missing `docs/evidence` record |
| Closed, already merged or Draft | SKIP | Out of scope |

Additional rules:
- Any unexpected CLI/API response or inability to inspect **active branch rules** makes the result WAITING. If branch rules cannot be read, do not auto-merge.
- Both required checks and other displayed checks must pass; skipped checks are permitted only if GitHub treats them as non-failing and reviewer has verified all relevant test areas. An unexpected bucket is WAITING.
- No `--admin`, `--auto`, `--delete-branch`, rebase, force push, or bypass. Respect repo's allowed merge methods; no fallback to a different method without authorization. In this repository the method is `merge` (the project default of `apply_decision.py`); GitHub deletes the head branch itself.
- Only the actor mutates PR state. Before mutation it recomputes the gate live. `MERGE` only authorizes an **attempt**; GitHub still enforces its own rules.
- Never interpret a merge queue enqueue operation as merged. Only PR remote `state == MERGED` constitutes success.
- A reviewer result is evidence, not an unconditional approval. Prefer paths, line ranges, test evidence, and explicit scope.
- For outstanding review comments: because unresolved threads can hide substantive objections, default to Draft for any unresolved thread, including outdated threads, until triaged/resolved. For unknown thread availability, WAITING.
- If a PR includes release-sensitive changes requiring human sign-off beyond configured repository branch rules (production secrets, destructive migrations, irreversible data loss), treat it as WAITING and flag the requirement explicitly; do not extrapolate permissions from CI green alone.
