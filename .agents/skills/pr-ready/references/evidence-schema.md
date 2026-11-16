# Evidence JSON (v1)

Create one evidence file *per PR per latest HEAD*. A new commit invalidates old review and validation receipts unless the gate accepts the delta as evidence-only (below). This is an example only; replace every value with observed facts. Store in `.pr-ready/<N>/evidence.json`, N = the PR number (gitignored, **not committed**; one checkout serves different PRs over time, so keep a separate directory per PR).

```json
{
  "schema_version": 1,
  "repo": "OWNER/REPO",
  "pr": 123,
  "head_sha": "0123456789abcdef0123456789abcdef01234567",
  "assessment": {
    "acceptance_criteria_passed": true,
    "root_cause_fixed": true,
    "architecture_sound": true,
    "description_matches_code": true,
    "dependencies_resolved": true,
    "major_review_comments_resolved": true,
    "related_ci_failures_resolved": true,
    "rationale": "Describe evidence, AC traceability, and root-cause fix."
  },
  "independent_review": {
    "agent": "pr-reviewer",
    "head_sha": "0123456789abcdef0123456789abcdef01234567",
    "status": "PASS",
    "blocking_findings": [],
    "report": "Path to real review report or factual summary"
  },
  "local_validation": {
    "tests": [{"command": "go test ./internal/inventory/ ./cmd/pilot/cmd/", "exit_code": 0, "head_sha": "0123456789abcdef0123456789abcdef01234567", "log": ".pr-ready/123/logs/tests.log"}],
    "lint": [{"command": "golangci-lint run", "exit_code": 0, "head_sha": "0123456789abcdef0123456789abcdef01234567", "log": ".pr-ready/123/logs/lint.log"}],
    "static_analysis": [{"command": "go vet ./...", "exit_code": 0, "head_sha": "0123456789abcdef0123456789abcdef01234567", "log": ".pr-ready/123/logs/static-analysis.log"}]
  },
  "unrelated_failing_checks": [],
  "disputed_review_comments": [],
  "agent_runs": [
    {"role": "pr-coder", "model": "claude-sonnet-5-5", "effort": "high", "head_sha": "89abcdef0123456789abcdef0123456789abcdef", "round": 1},
    {"role": "pr-reviewer", "model": "claude-sonnet-5-5", "effort": "xhigh", "head_sha": "89abcdef0123456789abcdef0123456789abcdef", "round": 1, "findings": {"P2": 1, "P3": 2}},
    {"role": "pr-reviewer", "model": "claude-sonnet-5-5", "effort": "xhigh", "head_sha": "0123456789abcdef0123456789abcdef01234567", "round": 2, "findings": {}}
  ],
  "target_validation": {"decision": "not-needed", "reason": "Docs and skill-only change; no playbook, spec, contract, inventory or Go code touched.", "artifact": "", "tested_revision": ""}
}
```

`agent_runs` (optional) records which model and effort each dispatched role ran at, so effort levels can be compared across PRs. One entry per role run: `role` is `pr-sa`, `pr-coder` or `pr-reviewer`; `model` and `effort` (`low`, `medium`, `high`, `xhigh`, `max`) are copied from the role's native definition (or the transcript), never guessed; `head_sha` is the HEAD that run worked on or reviewed; `round` counts review rounds from 1; `findings` (reviewer runs only) maps `P0`..`P4` to the number that run reported. Unlike the rest of the evidence it is cumulative: when a new HEAD needs a new evidence file, carry the earlier entries over. The gate does not require it, but rejects a malformed entry (a typo would silently drop the run from the comparison). `scripts/effort_report.py [evidence.json ...]` (default `.pr-ready/*/evidence.json`) prints runs per role/model/effort and PR cohorts by Coder effort with mean reviewer rounds and P0-P2 findings; it lists evidence files that lack the field.

`target_validation` is read only when the base branch's `.github/pr-evidence.json` requires a record (see [Repository-required target evidence](#repository-required-target-evidence)); the gate ignores it otherwise. A `required` decision names the committed `artifact` and the full `tested_revision` SHA instead.

Use a **category object** like `{ "not_applicable": "Project has no linter; examined Makefile, CI and language tooling." }` only if no applicable command exists. This is not a way to excuse a failing command. Where a failing GitHub check is demonstrably unrelated, `unrelated_failing_checks` can list objects `{ "name": "check name", "reason": "specific independently verified reason", "reviewer_confirmed": true }`; required checks are **never exempted**. A pending check is never exempted either: `--wait` keeps waiting until it becomes terminal. The exemption only lets the PR become Ready: `pr-review-merge` never merges with a failing check, and with the same entry in its evidence it waits for a rerun instead of returning the PR to Draft. There is no exemption for review threads: resolve each one after fixing or disputing it (the upstream `unresolved_nonblocking_threads` field is rejected).

A review comment the PR does not act on (see [review comments](review-comments.md)) gets one `disputed_review_comments` entry per disputed claim:

```json
{
  "source_url": "https://github.com/OWNER/REPO/pull/123#issuecomment-6494548870",
  "reply_url": "https://github.com/OWNER/REPO/pull/123#issuecomment-6501033173",
  "disposition": "invalid",
  "claim": "P2: the rescue drops the snapshot when --tags C3 is used",
  "counter_evidence": "Snapshot task is tagged always (apply.yml:88); tag-scoped vm-target run kept it, log .pr-ready/logs/c3.log",
  "head_sha": "0123456789abcdef0123456789abcdef01234567",
  "reviewer_confirmed": true
}
```

`disposition` is `invalid`, `needs_evidence` or `nonblocking`; `nonblocking` also needs `"severity": "P3"` or `"P4"`. `source_url` can be a conversation comment (`#issuecomment-`), a review (`#pullrequestreview-`) or an inline comment (`#discussion_r`). `reply_url` is the reply Root posted: in the same thread for an inline comment, otherwise a conversation comment whose body contains `source_url`. Set `reviewer_confirmed` only when the independent reviewer's own verdict agrees with the disposition on this HEAD.

A `run_check.py` execution prints/writes a receipt with `command`, `exit_code`, `head_sha`, and `log`; the orchestrator can append it to `local_validation.<category>` in the evidence. A receipt, or the independent review, taken at an earlier commit is accepted only when that commit is an ancestor of HEAD and every file changed since matches the base branch's `evidence_only_paths` (`.github/pr-evidence.json`, read from `refs/remotes/<--base-remote>/<base>`; the gate runs `git diff` itself and reports the accepted deltas under `receipt_reuse`). Any other delta needs new receipts. Never change a failed exit code to 0. Receipts cover the packages the diff touches; the whole suite is CI's `Go test` check (SKILL.md, cycle-time rule 1).

Example commands (from the verified checkout of PR 123's head branch; state under `.pr-ready/<N>/`):

```bash
# the packages the diff touches, not ./...: CI runs the whole suite
python3 "$SNAP/.agents/skills/pr-ready/scripts/run_check.py" --category tests --log-dir .pr-ready/123/logs --receipt-dir .pr-ready/123/receipts -- go test -count=1 ./internal/inventory/ ./cmd/pilot/cmd/
python3 "$SNAP/.agents/skills/pr-ready/scripts/run_check.py" --category lint --log-dir .pr-ready/123/logs --receipt-dir .pr-ready/123/receipts -- golangci-lint run
python3 "$SNAP/.agents/skills/pr-ready/scripts/run_check.py" --category static_analysis --log-dir .pr-ready/123/logs --receipt-dir .pr-ready/123/receipts -- go vet ./...
python3 "$SNAP/.agents/skills/pr-ready/scripts/pr_gate.py" --repo OWNER/REPO --pr 123 --evidence .pr-ready/123/evidence.json --worktree .
# Default after push/review/evidence: keep this session active through CI and Ready:
python3 "$SNAP/.agents/skills/pr-ready/scripts/pr_gate.py" --repo OWNER/REPO --pr 123 --evidence .pr-ready/123/evidence.json --worktree . --wait --ready --restore-sha "$START_SHA" --restore-branch="$START_BRANCH"
```

`run_check.py` prints a JSON receipt on stdout and stores it under `--receipt-dir` (default `.pr-ready/receipts`, so pass the per-PR directory) even on failure, returning the command's exit status. Copy the receipt fields into the matching evidence category. `pr_gate.py --worktree` (required) verifies that all referenced logs exist under that checkout directory and scans every commit of the PR (`baseRefOid..headRefOid`) for secrets; `GATE-PASS` and `READY` carry a value-free `secret_scan` summary, and `--secret-file FILE` (outside the repository, one value per line) adds values to look for.

## Repository-required target evidence

The gate reads `.github/pr-evidence.json` at the current base SHA and validates
`target_validation` with the same read-only verifier as `pr-review-merge`, before
Ready and again immediately before mutation. Use the
[merge workflow target schema](../../pr-review-merge/references/evidence-contract.md).
A missing manifest preserves the generic workflow; an unreadable base/manifest
or missing mandated target record blocks Ready. This does not weaken
`local_validation`, which remains current-HEAD-specific (or an evidence-only ancestor).
`independent_review` may also be taken at an ancestor when every change since is
evidence-only or a pure import of the base manifest's `non_execution_paths`
(`receipt_reuse` reports it with `method: non-execution-base-import`).

After integrating an advanced base, a base requirement with `kind: target-run`
may accept `target_validation.target_reuse` (with `unrelated_runtime_changes` for a
machine record whose closure has unresolved or external inputs) under the
shared target evidence rule at `$SNAP/.agents/skills/_shared/target-evidence-reuse.md` (the verified snapshot). A base that
brought in only `non_execution_paths` needs no `target_reuse`. A changed
execution/dependency input still needs a new target run.

In wait mode the helper pins the evidence JSON bytes, referenced local reports/logs/artifacts, PR HEAD/base/branch, fetched base policy ref, title/body and complete review/comment content. Existing evidence-only ancestor receipts/review remain accepted at wait start; no top-level HEAD movement or artifact edit is accepted during the wait. A referenced file the PR head commits (such as the `target_validation.artifact` record or a committed log) is pinned by its Git blob at that head, as `git:<path>` with the blob's mode and object id; it must be a regular file, and while the checkout is at the PR head the worktree copy must equal the blob (this also catches edits hidden with `skip-worktree`). Because the pin and the check read Git objects, they give the same answer after `--restore-sha` has switched to a starting branch that lacks the file or holds other bytes of it. The evidence JSON and files the head does not track, such as the ignored `.pr-ready` reports, logs and receipts, are pinned by path and SHA-256 and are compared byte for byte before and after the restore; a changed pin names the paths. A legacy inline review summary remains supported; path-shaped local report references must exist. `wait-status.json` stores progress and hashes under `.pr-ready/N/`, leaving Root's `checkpoint.json` alone. Do not edit evidence while the helper is waiting; stop, revalidate and start a fresh session.

Wait status also records observed Actions run IDs, workflow IDs, attempts, paths, statuses and conclusions. The helper queries all runs for current HEAD, verifies pagination completeness, and waits for delayed dependent jobs through workflow lifecycle state; green visible checks alone cannot finish the wait. It retains previously active runs/attempts across new runs/reruns. API errors or unknown metadata block; a verified empty run list preserves no-Actions/external-check support. Completed historical failures are settlement facts, not substitutes for the existing current-check/exemption gate.
