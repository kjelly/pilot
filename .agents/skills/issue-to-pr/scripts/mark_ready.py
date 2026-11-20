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

A Ready PR is only actionable for the automation after the Ready signal (a marker comment and a label,
`_shared/scripts/ready_signal.py`) was written for the exact HEAD and for the one Ready transition this script
invoked. This script is a second producer next to pr-ready's gate: it checks the label exists, removes a stale
one from the Draft and records the Draft's Ready/Draft transitions (the baseline) BEFORE `gh pr ready` (BLOCKED),
writes the signal AFTER the post-action check and reads it back (READY_UNVERIFIED when it cannot, among them a PR
that went through Draft and Ready again in between: nothing is signed), and reports a PR that is already Ready
without a valid signal as READY_UNVERIFIED too. A PR created Ready is ignored
by the automation by design: convert it to Draft and run this script.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Any, Sequence

# Running from the skill snapshot must not add __pycache__ there: `skill_snapshot.py verify`
# counts any added file and would STOP every later step. Set before the first sibling import.
sys.dont_write_bytecode = True
import pr_ci
from issue_gate import GateError, command, evaluate

from create_pr import execute, reference_problems

READY_SIGNAL_PATH = Path(__file__).resolve().parents[2] / "_shared" / "scripts" / "ready_signal.py"
GH_RUNTIME_PATH = Path(__file__).resolve().parents[2] / "pr-review-merge" / "scripts" / "gh_runtime.py"


def load_by_path(name: str, path: Path, what: str) -> Any:
    """`path` loaded as module `name` once per process (`sys.modules`), like pr-ready's `load_secret_scan`.

    A module that is missing or does not load is a refusal (GateError), never a traceback and never a
    skipped check. `name` is the module's import name: a later `import` of it in this process gets this module.
    """
    module = sys.modules.get(name)
    if module is not None:
        return module
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None or not path.is_file():
        raise GateError(f"{what} is missing: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # a module that does not load must refuse, whatever the reason
        sys.modules.pop(name, None)
        raise GateError(f"{what} cannot be loaded ({type(exc).__name__})") from None
    return module


def signal_runtime() -> tuple[Any, Any]:
    """(ready_signal, gh_runtime): the shared signal module and the GitHub adapter the merge skill uses."""
    return (load_by_path("ready_signal", READY_SIGNAL_PATH, "the shared ready-signal module"),
            load_by_path("gh_runtime", GH_RUNTIME_PATH, "the GitHub adapter (pr-review-merge gh_runtime.py)"))


def signal_problem(repo: str, pr: int) -> str | None:
    """None when the PR's signal reads as valid at its current HEAD, otherwise a sentence saying why it does not
    (one read, no retry)."""
    signal, client = signal_runtime()
    target = client.Repo.parse(repo)
    try:
        viewer = client.viewer_login(target)
        view = client.pr_view(target, pr)
        result = signal.assess(view.get("headRefOid"), view.get("labels"), client.timeline_events(target, pr), viewer)
    except (client.GitHubError, signal.SignalError) as exc:
        return f"the {signal.LABEL} signal cannot be read: {exc}"
    return None if result.valid else f"the {signal.LABEL} signal is not valid ({result.state}: {result.reason})"


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
               remote: str = "origin", confirm_complete: bool = False,
               secret_files: Sequence[Path] = ()) -> dict:
    if not confirm_complete:
        return {"status": "BLOCKED", "issue": issue, "pr": pr,
                "blockers": ["Pass --confirm-complete only after every follow-up is done "
                             "(final independent review of the whole head diff, accurate PR body, evidence/doc follow-ups)"]}
    worktree = worktree.expanduser().resolve(strict=True)
    errors, info = evaluate(repo=repo, issue=issue, worktree=worktree, evidence_path=evidence,
                            stage="pushed", remote=remote, own_pr=pr, secret_files=secret_files)
    # The advisory similar-defect report (issue_gate.SIMILAR_SCAN_ENFORCED) rides along on every result.
    scan = {"similar_defect_scan": info["similar_defect_scan"]} if "similar_defect_scan" in info else {}
    if errors:
        return {"status": "BLOCKED", "issue": issue, "pr": pr, "blockers": errors, **scan}
    branch, sha = info["branch"], info["head_sha"]
    view = command(["gh", "pr", "view", str(pr), "-R", repo,
                    "--json", "number,state,isDraft,headRefName,headRefOid,mergeable,url,body,reviewDecision"])
    if not isinstance(view, dict) or view.get("number") != pr or view.get("state") != "OPEN":
        return {"status": "BLOCKED", "issue": issue, "pr": pr, "blockers": ["PR is not open"], **scan}
    if view.get("headRefName") != branch or view.get("headRefOid") != sha:
        return {"status": "BLOCKED", "issue": issue, "pr": pr,
                "blockers": [f"PR head {view.get('headRefName')}@{view.get('headRefOid')} is not the validated {branch}@{sha}"], **scan}
    if view.get("isDraft") is not True:
        problem = signal_problem(repo, pr)
        if problem is not None:
            return {"status": "READY_UNVERIFIED", "issue": issue, "pr": pr, "url": view.get("url"), "head_sha": sha,
                    "blockers": [f"The PR is already Ready but {problem}, so the automation ignores it; convert it to "
                                 "Draft and run mark_ready.py again"], **scan}
        return {"status": "ALREADY_READY", "issue": issue, "pr": pr, "url": view.get("url"), "head_sha": sha, **scan}
    # create_pr.py checked the body at creation; the evidence's resolution or the body can change after.
    subs = {s["issue"]: s["issue_resolution"] for s in (info.get("umbrella") or {}).get("sub_issues", [])}
    problems = reference_problems(view.get("body") or "", repo, issue, info["issue_resolution"], subs)
    if problems:
        return {"status": "BLOCKED", "issue": issue, "pr": pr, "blockers": [f"PR body: {p}" for p in problems], **scan}
    if view.get("reviewDecision") == "CHANGES_REQUESTED":
        return {"status": "BLOCKED", "issue": issue, "pr": pr,
                "blockers": ["A review requests changes (reviewDecision CHANGES_REQUESTED). mark_ready does not "
                             "triage reviews: handle the PR with pr-ready (fix, or dispute with evidence and a reply)"], **scan}
    threads = unresolved_threads(repo, pr)
    if threads:
        return {"status": "BLOCKED", "issue": issue, "pr": pr,
                "blockers": [f"Unresolved review thread: {url} (fix or dispute it, then resolve it)" for url in threads], **scan}
    if view.get("mergeable") != "MERGEABLE":
        return {"status": "BLOCKED", "issue": issue, "pr": pr,
                "blockers": [f"PR is not cleanly mergeable (mergeable={view.get('mergeable')}); resolve conflicts on the same branch first"], **scan}
    ci = pr_ci.inspect(repo, pr, sha)
    if ci.get("status") != "CI_PASSED":
        return {"status": "BLOCKED", "issue": issue, "pr": pr, "head_sha": sha,
                "blockers": [f"CI is {ci.get('status')} on {sha}; Ready requires CI_PASSED"], "ci": ci, **scan}
    signal, client = signal_runtime()
    target = client.Repo.parse(repo)
    try:
        baseline = signal.prepare(client, target, pr)
    except (client.GitHubError, signal.SignalError) as exc:
        return {"status": "BLOCKED", "issue": issue, "pr": pr,
                "blockers": [f"The {signal.LABEL} signal could not be prepared (Ready not invoked): {exc}"], **scan}
    execute(["gh", "pr", "ready", str(pr), "-R", repo], cwd=worktree)
    after = command(["gh", "pr", "view", str(pr), "-R", repo, "--json", "isDraft,headRefOid,url"])
    if not isinstance(after, dict) or after.get("isDraft") is not False or after.get("headRefOid") != sha:
        return {"status": "READY_UNVERIFIED", "issue": issue, "pr": pr,
                "blockers": ["PR is not a non-Draft PR at the validated HEAD after `gh pr ready`; inspect it"], **scan}
    try:
        signed = signal.write(client, target, pr, sha, signal.ISSUE_TO_PR, baseline)
    except (client.GitHubError, signal.SignalError) as exc:
        return {"status": "READY_UNVERIFIED", "issue": issue, "pr": pr, "head_sha": sha,
                "blockers": [f"Ready invoked and verified, but the {signal.LABEL} signal was not confirmed: {exc}; the PR "
                             "is Ready without the signal; convert it to Draft and run mark_ready.py again"], **scan}
    return {"status": "READY_FOR_REVIEW", "issue": issue, "pr": pr, "url": after.get("url"),
            "head_sha": sha, "draft": False, "ci_status": "CI_PASSED",
            "ready_signal": {"label": signal.LABEL, "head_sha": signed.marker_head, "producer": signed.producer}, **scan}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--repo", required=True)
    ap.add_argument("--issue", required=True, type=int)
    ap.add_argument("--pr", required=True, type=int)
    ap.add_argument("--worktree", required=True, type=Path)
    ap.add_argument("--evidence", required=True, type=Path)
    ap.add_argument("--remote", default="origin")
    ap.add_argument("--secret-file", action="append", default=[], type=Path, metavar="FILE",
                    help="File OUTSIDE the repository with one secret value per line (8+ bytes each) that must "
                         "appear in no commit of the branch (see issue_gate.py). Repeatable.")
    ap.add_argument("--confirm-complete", action="store_true",
                    help="Attest that all other follow-up work is finished, every review comment answered (required)")
    o = ap.parse_args(argv)
    try:
        result = mark_ready(repo=o.repo, issue=o.issue, pr=o.pr, worktree=o.worktree, evidence=o.evidence,
                            remote=o.remote, confirm_complete=o.confirm_complete, secret_files=o.secret_file)
    except (GateError, OSError, KeyError, ValueError, json.JSONDecodeError) as exc:
        result = {"status": "BLOCKED", "issue": o.issue, "pr": o.pr, "blockers": [str(exc)]}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result["status"] in ("READY_FOR_REVIEW", "ALREADY_READY") else 2


if __name__ == "__main__":
    sys.exit(main())
