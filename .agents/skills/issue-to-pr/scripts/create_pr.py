#!/usr/bin/env python3
"""Guarded, idempotent creation of a GitHub PR for an Issue branch. The PR is created as a
DRAFT: Ready for Review means "merge-quality, nothing left to do", so it is only reached through
mark_ready.py after CI is green on the exact HEAD and all follow-up work is done. ``--ready``
creates a Ready PR directly and is only for an explicit user request.

Before first use inspect the target repo, title and body. Requires GitHub CLI auth.
The pre-PR review gate cannot substitute for a human GitHub approval.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

from issue_gate import (ISSUE_RESOLUTIONS, GateError, closes_issue, command, evaluate, references_issue,
                        resolution_problem)


def execute(args: list[str], cwd: Path) -> str:
    try:
        p = subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=False)
    except OSError as exc:
        raise GateError(f"Cannot run {args[0]}: {exc}") from exc
    if p.returncode:
        raise GateError(f"Command {args[:4]} failed ({p.returncode}): {(p.stderr or p.stdout).strip()[:800]}")
    return p.stdout.strip()


def issue_reference_problem(body: str, repo: str, issue: int, resolution: str) -> str | None:
    """A 'fixes' PR must close the Issue; a 'partial' one must reference it without closing it,
    so merging does not silently close the claims that stay open."""
    if resolution not in ISSUE_RESOLUTIONS:
        # Named first: a typo such as 'Partial' is otherwise reported as a missing 'Fixes #N'.
        return resolution_problem(resolution)
    if resolution == "partial":
        if closes_issue(body, repo, issue):
            return f"issue_resolution is 'partial': the PR body must not close #{issue}; use 'Refs #{issue}'"
        if not references_issue(body, repo, issue):
            return f"PR body must reference #{issue} (e.g. 'Refs #{issue}')"
        return None
    if not re.search(rf"(?i)\b(?:fixes|closes|resolves)\s+(?:(?:[\w.-]+/[\w.-]+)?#){issue}\b", body):
        return f"PR body must contain a genuine 'Fixes #{issue}' or equivalent closing keyword"
    return None


def check_pr(repo: str, branch: str, base: str, sha: str, *, draft: bool, issue: int,
             resolution: str = "fixes") -> dict:
    p = command(["gh", "pr", "view", branch, "-R", repo,
                 "--json", "number,url,state,isDraft,headRefName,headRefOid,baseRefName,body"])
    if not isinstance(p, dict):
        raise GateError("PR view did not return an object")
    if p.get("state") != "OPEN" or p.get("headRefName") != branch or p.get("headRefOid") != sha:
        raise GateError("New PR branch/HEAD/state does not match verified local worktree")
    if p.get("baseRefName") != base or p.get("isDraft") is not draft:
        raise GateError("New PR base/Draft-state mismatch")
    if not isinstance(p.get("number"), int) or not p.get("url"):
        raise GateError("Cannot identify created PR")
    problem = issue_reference_problem(p.get("body") or "", repo, issue, resolution)
    if problem:
        raise GateError(f"New PR body: {problem}")
    return p


def create(*, repo: str, issue: int, worktree: Path, evidence: Path,
           title: str, body_file: Path, remote: str = "origin", draft: bool = True) -> dict:
    worktree = worktree.expanduser().resolve(strict=True)
    body_file = body_file.expanduser().resolve(strict=True)
    if body_file.is_relative_to(worktree):
        raise GateError("PR body file must be outside the worktree to keep source clean")
    body = body_file.read_text(encoding="utf-8")
    evidence_data = json.loads(evidence.expanduser().resolve(strict=True).read_text(encoding="utf-8"))
    resolution = evidence_data.get("issue_resolution", "fixes") if isinstance(evidence_data, dict) else "fixes"
    problem = issue_reference_problem(body, repo, issue, resolution)
    if problem:
        raise GateError(problem)
    if len(title.strip()) < 8 or not title.strip():
        raise GateError("Provide a meaningful PR title")
    if not ("tests" in body.lower() or "測試" in body):
        raise GateError("PR body must summarize validation/test evidence")
    errors, info = evaluate(repo=repo, issue=issue, worktree=worktree, evidence_path=evidence,
                            stage="local", remote=remote)
    if errors:
        return {"status": "BLOCKED", "issue": issue, "blockers": errors}
    branch, sha = info["branch"], info["head_sha"]
    # Base comes from the validated evidence, not the mutable main checkout.
    base_name = evidence_data["base_branch"]
    # Push is intentionally a side effect only after local gate passes. No force-push.
    execute(["git", "push", "--set-upstream", remote, branch], cwd=worktree)
    errors, _ = evaluate(repo=repo, issue=issue, worktree=worktree, evidence_path=evidence,
                         stage="pushed", remote=remote)
    if errors:
        return {"status": "BLOCKED_AFTER_PUSH", "issue": issue, "head_sha": sha, "blockers": errors}
    cmd = ["gh", "pr", "create", "-R", repo, "--base", base_name, "--head", branch,
           "--title", title, "--body-file", str(body_file)]
    if draft:
        cmd.append("--draft")
    try:
        execute(cmd, cwd=worktree)
    except GateError as exc:
        # A timeout/network error may occur AFTER GitHub creates the PR.
        # Do not retry creation blindly. Caller should inspect `gh pr view` first.
        return {"status": "CREATE_UNCERTAIN", "issue": issue, "head_sha": sha,
                "blockers": [str(exc), "Check gh pr view <branch> before attempting to retry"]}
    try:
        pr = check_pr(repo, branch, base_name, sha, draft=draft, issue=issue, resolution=resolution)
    except GateError as exc:
        return {"status": "CREATED_UNVERIFIED", "issue": issue, "head_sha": sha,
                "blockers": [str(exc), "Do not retry creation; inspect the created PR"]}
    return {"status": "DRAFT_PR_CREATED" if draft else "READY_PR_CREATED",
            "issue": issue, "pr": pr["number"], "url": pr["url"],
            "branch": branch, "head_sha": sha, "draft": draft,
            "ci_status": "NOT_YET_VERIFIED"}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--issue", required=True, type=int)
    ap.add_argument("--worktree", required=True, type=Path)
    ap.add_argument("--evidence", required=True, type=Path)
    ap.add_argument("--title", required=True)
    ap.add_argument("--body-file", required=True, type=Path)
    ap.add_argument("--remote", default="origin")
    ap.add_argument("--ready", action="store_true",
                    help="Create a Ready PR directly. Only on an explicit user request; default is DRAFT until mark_ready.py")
    opts = ap.parse_args(argv)
    try:
        result = create(repo=opts.repo, issue=opts.issue, worktree=opts.worktree, evidence=opts.evidence,
                        title=opts.title, body_file=opts.body_file, remote=opts.remote, draft=not opts.ready)
    except (GateError, OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
        result = {"status": "BLOCKED", "issue": opts.issue, "blockers": [str(exc)]}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"].endswith("_PR_CREATED") else 2


if __name__ == "__main__":
    sys.exit(main())
