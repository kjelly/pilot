# Evidence contract for issue_gate.py

For each Issue use an external directory (e.g. `~/.cache/issue-to-pr/myorg/myrepo/123/`), not tracked source paths.

1. Commit fix and tests to the Issue branch.
2. Run `scripts/run_check.py --worktree ... --name NAME --out /absolute/path/NAME.json -- COMMAND [ARGS...]` on a **clean** committed HEAD. Capture at least a targeted `regression` check; include other relevant commands.
3. Have the independent Reviewer issue a concrete conclusion for the same HEAD. Root records the finding details; do not self-label code as independent review.
4. Create `evidence.json` and run `issue_gate.py`. If any commit changes, rerun receipts and review.

Example (full SHA values must be actual full git commit hashes; placeholders below are illustrative):

```json
{
  "schema_version": 1,
  "repo": "OWNER/REPO",
  "issue": 123,
  "base_branch": "main",
  "head_branch": "issue/123-fix",
  "head_sha": "<actual full 40-character SHA>",
  "root_cause": "Defective state transition leaves a stale entry",
  "dependencies": {"status": "resolved", "evidence": "No pending prerequisites; compared related issues"},
  "acceptance_criteria": [
    {"criterion": "Previous failure now handled correctly", "met": true, "evidence": "regression test TestStaleEntry"}
  ],
  "checks": [
    {"category": "regression", "receipt": "/absolute/path/regression.json"},
    {"category": "unit", "receipt": "/absolute/path/unit.json"},
    {"category": "lint", "receipt": "/absolute/path/lint.json"}
  ],
  "lint": {"status": "pass", "evidence": "lint receipt above"},
  "static_analysis": {"status": "not-applicable", "reason": "No configured static analyzer; checked build/config"},
  "review": {
    "agent": "issue-reviewer",
    "independent": true,
    "head_sha": "<same actual HEAD SHA>",
    "status": "pass",
    "summary": "Verified the state machine and regression coverage",
    "findings": []
  },
  "issue_resolution": "fixes",
  "disputed_issue_claims": []
}
```

- `checks[].receipt` is an absolute path, or a path **relative to the evidence JSON's directory**. Receipt must have status `pass`, matching `head_sha`, clean-before/after, unchanged HEAD, and successful exit code.
- `checks[].category` allowed: `regression`, `unit`, `integration`, `lint`, `static-analysis`, `security`, `build`, `other`.
- At least **one regression** receipt is required. A passing full-suite receipt (`pytest`, `npm test`, `go test ./...`, ...) can be categorized `regression` if it covers the actual reported defect. Name the actual regression in acceptance evidence.
- For `lint`/`static_analysis`: use `status: pass` with a corresponding passing `lint` / `static-analysis` check receipt, or `status: not-applicable` with nontrivial `reason`. No `skipped`, `fail`, or unexplained N/A accepted.
- `review.independent` represents an independently delegated review; the gate validates declared evidence structurally, not the cognitive independence of an LLM.
- `review.findings` items have `severity` (`P0`/`P1`/`P2`/`P3`), `status` (`resolved`/`open`), `description`, and (when resolved) fix/test evidence. Any `open` P0/P1/P2 blocks. Findings also carry `origin` (`introduced`/`aggravated`/`pre-existing`) and `class` per [severity.md](severity.md); `pre-existing` findings cap at P3.
- `repo_required_evidence` (list) holds one entry per item the repository requires (`id`, `status` `pass`/`not-applicable`, `head_sha`, committed `artifact`, `summary`/`reason`). `checks[]` receipts, `review.head_sha` and these entries may predate HEAD when every file changed since matches the base branch's `evidence_only_paths`. Top-level `head_sha` must equal HEAD. Details: [repo-evidence.md](repo-evidence.md).
- `disputed_issue_claims` (list, optional) holds one entry per Issue claim the PR does not implement ([Issue claims](issue-claims.md)):

  ```json
  {"source_url": "https://github.com/OWNER/REPO/issues/123#issuecomment-6487450538",
   "claim": "The retry loop hides the error and must be removed",
   "disposition": "invalid",
   "counter_evidence": "retry.go:41 re-raises after the last attempt; TestRetrySurfacesError fails without it",
   "reply_url": "https://github.com/OWNER/REPO/issues/123#issuecomment-6487999001",
   "head_sha": "<actual HEAD SHA>",
   "reviewer_confirmed": true}
  ```

  `disposition` is `invalid`, `needs_evidence` or `out_of_scope`. `source_url` is the Issue URL (a claim in the body) or one of its comments. `reply_url` is Root's comment on the Issue, posted after the claim, containing `source_url` when the claim came from a comment. `head_sha` follows the same evidence-only delta rule as `review.head_sha`. Set `reviewer_confirmed` only when the independent reviewer's own verdict agrees. When the list is non-empty the gate reads the Issue's comments to verify each entry.
- `issue_resolution` is `fixes` (default: the PR body must close the Issue with `Fixes #N`) or `partial` (something the Issue asks for stays open; needs at least one disputed claim, and the PR body must reference the Issue with `Refs #N` and no closing keyword).
- GitHub CI on a new Draft PR happens only **after** PR creation; this contract does not spoof post-PR CI success. Draft → Ready additionally requires `CI_PASSED` on the exact HEAD (`mark_ready.py`).

Successful gate output (stdout JSON): `{"status":"GATE-PASS", ...}`. If unverified or blocked: `{"status":"BLOCKED","blockers":[...]}` and exit code 2. Non-gate misuse exits nonzero and must never be interpreted as success.
