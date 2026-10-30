# Evidence contract (per PR)

Put reviewer evidence outside the repository checkout, e.g. `~/.cache/pr-review-merge/OWNER/REPO/123/review.json`. **Generate from a real independent review, not from the template without verification.** Replace the example SHAs with current full 40-character hex commit IDs and use real tests/evidence URLs.

```json
{
  "schema_version": 1,
  "repo": "OWNER/REPO",
  "pr": 123,
  "head_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "base_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "reviewer_id": "prm-reviewer",
  "independent": true,
  "verdict": "PASS",
  "summary": "Reviewed actual full diff and affected paths, with no blocking findings.",
  "coverage": {
    "requirements": true,
    "correctness": true,
    "architecture": true,
    "security": true,
    "concurrency": true,
    "edge_cases": true,
    "semantic_regression": true,
    "tests": true
  },
  "findings": [],
  "tests": [
    {"name": "unit + integration", "status": "PASS", "sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "evidence": "https://github.com/OWNER/REPO/actions/runs/123"}
  ],
  "dependencies": {"resolved": true, "evidence": "No upstream PR dependency or shared-resource conflict"},
  "no_ci_rationale": "",
  "unrelated_failing_checks": [],
  "target_validation": {"decision": "not-needed", "reason": "Docs-only change; no playbook, spec, contract, inventory or Go code touched.", "artifact": "", "tested_revision": ""}
}
```

Allowed `verdict`: `PASS`, `BLOCK`, `NEEDS_MORE_EVIDENCE`.
Allowed finding `severity`: `P0`, `P1`, `P2`, `P3`, `P4` ([shared rubric](../../issue-to-pr/references/severity.md)).
Finding shape: `{"severity":"P1","path":"pkg/x.go","line":42,"reason":"...","recommendation":"...","blocking":true}`. Any P0–P2 is blocking regardless of the `blocking` flag.

A blocking finding that repeats a claim already disputed on this PR (usually by `pr-ready`) adds `"disputed_reply_url"`: the reply, a conversation comment (`#issuecomment-`) or inline reply (`#discussion_r`) on this PR. It blocks only with `"new_evidence"` (at least 30 characters) the reply does not answer; without it the gate decides `WAITING` so a person decides, instead of another Draft round. A malformed or foreign `disputed_reply_url` is `WAITING` too. The gate checks the URL's shape, not that the comment exists or what it says; that is the reviewer's and Root's job. For `BLOCK` verdict **at least one concrete finding** (or a failing test) is required before turning Draft; `BLOCK` alone is insufficient.

`tests`: each entry must include the exact `sha` of the current PR HEAD; status `PASS`, `FAIL`, or `SKIPPED`. `SKIPPED` requires a concrete `reason`; an all-skipped test set cannot justify merging if there are no CI checks. `FAIL` blocks merging and results in Draft. CI presence and result are checked live, not just from the evidence file.

`dependencies.resolved` must be `true` with a nonempty, checked explanation. This is an agent-authored assertion; code cannot independently prove an undocumented dependency.

`coverage`: each field must be explicitly `true` for MERGE; an inapplicable category can still be `true` *only after explicit consideration*, e.g. "no concurrent execution touched" in reviewer summary. If any field is missing/false, decision is `WAITING`, not `MERGE`.

`unrelated_failing_checks`: `[{"name": "exact check name", "reason": "evidence it fails the same way without this diff (at least 30 characters)", "reviewer_confirmed": true}]`. A listed `fail`/`cancel` check makes the decision `WAITING` (rerun once the cause is fixed) instead of `DRAFT`; it never allows `MERGE`. Same shape as `pr-ready`'s field, so a PR it marked Ready with that exemption is not returned to Draft.

When there are no check runs, use `no_ci_rationale` only if no CI truly applies and there is positive test evidence (and the branch has no required checks). The runtime rechecks mergeability and rules; it does not pretend that absence of checks is success.

`target_validation` (project-local; the Python gate ignores it, Root requires it before `MERGE`): `{"decision": "required|not-needed|blocked", "reason": "...", "artifact": "docs/evidence/<feature>/<date>-<rev>.md", "tested_revision": "<sha>"}`. A `required` decision must name a committed record that covers the reviewed HEAD, or a tested revision whose delta to HEAD is evidence-only under `.github/pr-evidence.json`; `blocked` never turns into `not-needed`. A `required` decision without such a record is a blocking `P1` finding at the changed path (AGENTS.md §1).

Evidence trust boundary: `independent: true` cannot cryptographically prove agent isolation, and SHA equality alone does not prove code correctness. The Orchestrator must really delegate and verify review evidence, and **must not fabricate fields to satisfy the gate**.
