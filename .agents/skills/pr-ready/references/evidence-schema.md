# Evidence JSON (v1)

Create one evidence file *per PR per latest HEAD*. A new commit always invalidates old review and validation receipts. This is an example only; replace every value with observed facts. Store in `.pr-ready/<N>/evidence.json`, N = the PR number (gitignored, **not committed**; one checkout serves different PRs over time, so keep a separate directory per PR).

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
    "tests": [{"command": "go test ./...", "exit_code": 0, "head_sha": "0123456789abcdef0123456789abcdef01234567", "log": ".pr-ready/123/logs/tests.log"}],
    "lint": [{"command": "golangci-lint run", "exit_code": 0, "head_sha": "0123456789abcdef0123456789abcdef01234567", "log": ".pr-ready/123/logs/lint.log"}],
    "static_analysis": [{"command": "go vet ./...", "exit_code": 0, "head_sha": "0123456789abcdef0123456789abcdef01234567", "log": ".pr-ready/123/logs/static-analysis.log"}]
  },
  "unresolved_nonblocking_threads": [],
  "unrelated_failing_checks": []
}
```

Use a **category object** like `{ "not_applicable": "Project has no linter; examined Makefile, CI and language tooling." }` only if no applicable command exists. This is not a way to excuse a failing command. Where a failing GitHub check is demonstrably unrelated, `unrelated_failing_checks` can list objects `{ "name": "check name", "reason": "specific independently verified reason", "reviewer_confirmed": true }`; required checks are **never exempted**. Unresolved minor review threads can be listed as `{ "id": "PRRT_...", "severity": "P3", "reason": "...", "reviewer_confirmed": true }`.

A `run_check.py` execution prints/writes a receipt with `command`, `exit_code`, `head_sha`, and `log`; the orchestrator can append it to `local_validation.<category>` in the evidence. Do not carry receipts forward after any commit, and do not change a failed exit code to 0.

Example commands (from the verified checkout of PR 123's head branch; state under `.pr-ready/<N>/`):

```bash
python3 "$SNAP/.agents/skills/pr-ready/scripts/run_check.py" --category tests --log-dir .pr-ready/123/logs --receipt-dir .pr-ready/123/receipts -- go test ./...
python3 "$SNAP/.agents/skills/pr-ready/scripts/run_check.py" --category lint --log-dir .pr-ready/123/logs --receipt-dir .pr-ready/123/receipts -- golangci-lint run
python3 "$SNAP/.agents/skills/pr-ready/scripts/run_check.py" --category static_analysis --log-dir .pr-ready/123/logs --receipt-dir .pr-ready/123/receipts -- go vet ./...
python3 "$SNAP/.agents/skills/pr-ready/scripts/pr_gate.py" --repo OWNER/REPO --pr 123 --evidence .pr-ready/123/evidence.json --worktree .
# After every gate succeeds, and ONLY to change the PR lifecycle:
python3 "$SNAP/.agents/skills/pr-ready/scripts/pr_gate.py" --repo OWNER/REPO --pr 123 --evidence .pr-ready/123/evidence.json --worktree . --ready
```

`run_check.py` prints a JSON receipt on stdout and stores it under `--receipt-dir` (default `.pr-ready/receipts`, so pass the per-PR directory) even on failure, returning the command's exit status. Copy the receipt fields into the matching evidence category. `pr_gate.py --worktree` verifies that all referenced logs exist under that checkout directory.
