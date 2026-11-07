# Evidence contract (per PR)

Put reviewer evidence outside the repository checkout, e.g. `~/.cache/pr-review-merge/OWNER/REPO/123/review.json`. **Generate from a real independent review, not from the template without verification.** Replace the example SHAs with current full 40-character hex commit IDs and use real tests/evidence URLs.

Exception: the operational base-alignment gate runs before semantic evidence checks. A HEAD that lacks the live base tip is fine when the merge train can integrate it (clean test merge, no file changed on both sides; `references/merge-train.md`); a conflict or an overlap is confirmed with fresh PR/ref identities and can require Draft without a completed independent review. Save observed SHAs and explicit review limitations in the evidence JSON (an object is still required by the CLI); do not fabricate reviewer findings or PASS fields. The actor records HEAD/Base/live-base SHAs in its comment and rechecks them before writing. This exception never authorizes a merge or stale semantic findings.

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

`target_validation`: `{"decision": "required|not-needed|blocked", "reason": "...", "artifact": "docs/evidence/<feature>/<date>-<rev>.md", "tested_revision": "<40-hex sha>"}`. The gate reads `.github/pr-evidence.json` at the PR's **base SHA** (GitHub contents API, never the head, so a PR cannot weaken its own requirement) and checks this object when the manifest has `required_evidence`; with no manifest, or one without `required_evidence`, it ignores the field. Rules, each failure `WAITING` (never `MERGE`):

- The object is present, `decision` is one of the three values and `reason` has at least 30 characters (the floor issue-to-pr uses for `not-applicable`).
- `blocked` is always `WAITING`; it never turns into `not-needed`.
- `required`: `artifact` is a repository-relative path inside the manifest's `artifact_glob` (`docs/evidence/**/*.md`), committed at HEAD, and naming `tested_revision` (the full SHA or an abbreviation of at least 7 hex digits). `tested_revision` is the full 40-hex SHA of the tested candidate and equals HEAD, or is an ancestor of HEAD whose delta to HEAD is evidence-only (every changed file, both names of a rename, matches `evidence_only_paths` or an `artifact_glob`; GitHub `compare`, which lists at most 300 files, so a larger delta cannot be verified).
- `not-needed` is accepted with its reason, except that the PR may not change a path matching the requirement's `required_paths` (`playbooks/**`, `contracts/**` here). Changes the manifest's prose also covers but no glob can tell apart stay the reviewer's call: specs (`docs/verification/**`; an edit that changes no command, Expected, target or variable contract needs no new run, `docs/actual-run-evidence.md` §4), Go inventory handling and deploy orchestration.
- A manifest the gate cannot read or validate, or one with more than one `required_evidence` item, is `WAITING`.

The manifest schema, globs and the evidence-only delta rule are issue-to-pr's `scripts/repo_evidence.py`, loaded by path. The gate result carries `target_validation` (manifest state, required ids, accepted deltas). A missing or stale record is `WAITING` in the gate; it becomes `DRAFT` only through the reviewer's blocking `P1` finding at the changed path (AGENTS.md §1), like every other Draft.

Secret scan (not reviewer evidence): the gate reads no field for it. With `--worktree` it scans every commit of the PR's `baseRefOid..headRefOid` itself and the result carries a value-free `secret_scan` summary (`status`, `commits_scanned`, `findings`). A finding is `DRAFT`; a scan that could not run (no `--worktree`, a commit not in the clone, a scanner that does not load) is `WAITING`. A reviewer's own secret finding is still a blocking P0 (`.agents/skills/_shared/committed-secrets.md`).

Evidence trust boundary: `independent: true` cannot cryptographically prove agent isolation, and SHA equality alone does not prove code correctness. The Orchestrator must really delegate and verify review evidence, and **must not fabricate fields to satisfy the gate**.

### Target evidence after merging an advanced base

For a base requirement with `kind: target-run`, `target_validation.target_reuse`
may provide the separately reviewed proof described in the
shared target evidence rule at `$SNAP/.agents/skills/_shared/target-evidence-reuse.md` (the verified snapshot). Without
`target_reuse`, the gate also keeps the record when main brought in only the base
manifest's `non_execution_paths` that the record's closure cannot reach; a machine
record whose closure has unresolved or external inputs takes the reviewed path only
when the manifest item declares `rerun_paths`, with `unrelated_runtime_changes`
for each imported runtime file. These are the only alternatives to the evidence-only
candidate delta above. The original `tested_revision` is retained. It does not relax reviewed HEAD/base,
current-HEAD tests or CI; the gate verifies complete trees, scoped modes/blobs
and pure upstream imports using the shared implementation.

### Review after the merge train integrates the base

`head_sha`/`base_sha` name the reviewed HEAD and the base it was reviewed against. The review covers
the current HEAD when it is the same commit, or when every change since is evidence-only or a pure
import from the base (the file is unchanged at the reviewed HEAD since the fork and equals the base
at HEAD): the merge train's integration commit, kjelly/pilot#307. `base_sha` must be on the live base
branch (the PR's Base or an ancestor of the live tip). `tests[].sha` stays the reviewed HEAD; CI on the
current HEAD covers the integration. Any other delta is stale evidence.
