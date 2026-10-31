#!/usr/bin/env python3
"""Guarded Draft -> Ready transition for an Issue PR.

Ready for Review means "quality is already mergeable; nothing is left to do". This script only runs
`gh pr ready` when, for the exact current HEAD: the PR is an open Draft of the validated branch, the
pre-PR gate still passes (pushed stage, own PR excluded from duplicate screening), the PR body still
agrees with the evidence's `issue_resolution` (`Fixes #N` for `fixes`, `Refs #N` without a closing
keyword for `partial`; the evidence or the body may have changed since create_pr.py), no review requests
changes and no review thread is unresolved, GitHub CI is fully green, the PR has no merge conflicts, and
the caller explicitly confirmed (--confirm-complete) that every other follow-up is finished: final
independent review of the whole head diff, every review comment answered, PR body accurate, evidence/doc
follow-ups done. It never merges and never enables auto-merge.

Review feedback that arrives while the PR is a Draft is pr-ready's job (fix it, or dispute it with
evidence and a reply). This script does not triage it; it only refuses to call such a PR finished.
pr-review-merge returns a PR with an unresolved thread to Draft, so marking it Ready here would bounce.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import pr_ci
from issue_gate import GateError, command, evaluate

from create_pr import execute, issue_reference_problem

# Every review thread of the PR, 100 per page; the first comment's URL names the thread.
THREADS_QUERY = """query($owner:String!,$repo:String!,$number:Int!,$cursor:String){repository(owner:$owner,name:$repo){\
pullRequest(number:$number){reviewThreads(first:100,after:$cursor){nodes{isResolved comments(first:1){nodes{url}}} \
pageInfo{hasNextPage endCursor}}}}}"""


def unresolved_threads(repo: str, pr: int) -> list[str]:
    """The first-comment URL of every unresolved review thread, over all pages. Anything other than
    a complete, well-formed answer is a GateError, so a failed lookup never reads as "no threads"."""
    owner, name = repo.split("/", 1)
    cursor: str | None = None
    found: list[str] = []
    for _ in range(100):
        argv = ["gh", "api", "graphql", "-f", f"query={THREADS_QUERY}", "-f", f"owner={owner}",
                "-f", f"repo={name}", "-F", f"number={pr}"]
        if cursor:
            argv += ["-f", f"cursor={cursor}"]
        payload = command(argv)
        try:
            threads = payload["data"]["repository"]["pullRequest"]["reviewThreads"]
            nodes, page = threads["nodes"], threads["pageInfo"]
            if not isinstance(nodes, list) or not isinstance(page["hasNextPage"], bool):
                raise ValueError("malformed page")
            for node in nodes:
                if not isinstance(node["isResolved"], bool):
                    raise ValueError("isResolved is not a boolean")
                if not node["isResolved"]:
                    comments = node["comments"]["nodes"]
                    found.append(comments[0]["url"] if comments else "(a thread without comments)")
        except (KeyError, IndexError, TypeError, ValueError) as exc:
            raise GateError(f"Cannot read the PR's review threads: {exc!r}") from exc
        if not page["hasNextPage"]:
            return found
        if not page.get("endCursor") or page["endCursor"] == cursor:
            break
        cursor = page["endCursor"]
    raise GateError("The PR's review threads did not page to the end")


def mark_ready(*, repo: str, issue: int, pr: int, worktree: Path, evidence: Path,
               remote: str = "origin", confirm_complete: bool = False) -> dict:
    if not confirm_complete:
        return {"status": "BLOCKED", "issue": issue, "pr": pr,
                "blockers": ["Pass --confirm-complete only after every follow-up is done "
                             "(final independent review of the whole head diff, accurate PR body, evidence/doc follow-ups)"]}
    worktree = worktree.expanduser().resolve(strict=True)
    errors, info = evaluate(repo=repo, issue=issue, worktree=worktree, evidence_path=evidence,
                            stage="pushed", remote=remote, own_pr=pr)
    if errors:
        return {"status": "BLOCKED", "issue": issue, "pr": pr, "blockers": errors}
    branch, sha = info["branch"], info["head_sha"]
    view = command(["gh", "pr", "view", str(pr), "-R", repo,
                    "--json", "number,state,isDraft,headRefName,headRefOid,mergeable,url,body,reviewDecision"])
    if not isinstance(view, dict) or view.get("number") != pr or view.get("state") != "OPEN":
        return {"status": "BLOCKED", "issue": issue, "pr": pr, "blockers": ["PR is not open"]}
    if view.get("headRefName") != branch or view.get("headRefOid") != sha:
        return {"status": "BLOCKED", "issue": issue, "pr": pr,
                "blockers": [f"PR head {view.get('headRefName')}@{view.get('headRefOid')} is not the validated {branch}@{sha}"]}
    if view.get("isDraft") is not True:
        return {"status": "ALREADY_READY", "issue": issue, "pr": pr, "url": view.get("url"), "head_sha": sha}
    # create_pr.py checked the body at creation; the evidence's resolution or the body can change after.
    problem = issue_reference_problem(view.get("body") or "", repo, issue, info["issue_resolution"])
    if problem:
        return {"status": "BLOCKED", "issue": issue, "pr": pr, "blockers": [f"PR body: {problem}"]}
    if view.get("reviewDecision") == "CHANGES_REQUESTED":
        return {"status": "BLOCKED", "issue": issue, "pr": pr,
                "blockers": ["A review requests changes (reviewDecision CHANGES_REQUESTED). mark_ready does not "
                             "triage reviews: handle the PR with pr-ready (fix, or dispute with evidence and a reply)"]}
    threads = unresolved_threads(repo, pr)
    if threads:
        return {"status": "BLOCKED", "issue": issue, "pr": pr,
                "blockers": [f"Unresolved review thread: {url} (fix or dispute it, then resolve it)" for url in threads]}
    if view.get("mergeable") != "MERGEABLE":
        return {"status": "BLOCKED", "issue": issue, "pr": pr,
                "blockers": [f"PR is not cleanly mergeable (mergeable={view.get('mergeable')}); resolve conflicts on the same branch first"]}
    ci = pr_ci.inspect(repo, pr, sha)
    if ci.get("status") != "CI_PASSED":
        return {"status": "BLOCKED", "issue": issue, "pr": pr, "head_sha": sha,
                "blockers": [f"CI is {ci.get('status')} on {sha}; Ready requires CI_PASSED"], "ci": ci}
    execute(["gh", "pr", "ready", str(pr), "-R", repo], cwd=worktree)
    after = command(["gh", "pr", "view", str(pr), "-R", repo, "--json", "isDraft,headRefOid,url"])
    if not isinstance(after, dict) or after.get("isDraft") is not False or after.get("headRefOid") != sha:
        return {"status": "READY_UNVERIFIED", "issue": issue, "pr": pr,
                "blockers": ["PR is not a non-Draft PR at the validated HEAD after `gh pr ready`; inspect it"]}
    return {"status": "READY_FOR_REVIEW", "issue": issue, "pr": pr, "url": after.get("url"),
            "head_sha": sha, "draft": False, "ci_status": "CI_PASSED"}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--issue", required=True, type=int)
    ap.add_argument("--pr", required=True, type=int)
    ap.add_argument("--worktree", required=True, type=Path)
    ap.add_argument("--evidence", required=True, type=Path)
    ap.add_argument("--remote", default="origin")
    ap.add_argument("--confirm-complete", action="store_true",
                    help="Attest that all other follow-up work is finished, every review comment answered (required)")
    o = ap.parse_args(argv)
    try:
        result = mark_ready(repo=o.repo, issue=o.issue, pr=o.pr, worktree=o.worktree, evidence=o.evidence,
                            remote=o.remote, confirm_complete=o.confirm_complete)
    except (GateError, OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
        result = {"status": "BLOCKED", "issue": o.issue, "pr": o.pr, "blockers": [str(exc)]}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] in ("READY_FOR_REVIEW", "ALREADY_READY") else 2


if __name__ == "__main__":
    sys.exit(main())
