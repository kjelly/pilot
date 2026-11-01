#!/usr/bin/env python3
"""Serial, guarded PR actor. --execute is required for mutations."""
from __future__ import annotations
import argparse
import json
import os
import sys
import tempfile
import hashlib
import fcntl
from pathlib import Path
from contextlib import contextmanager
from typing import Any

# Running from the skill snapshot must not add __pycache__ there: `skill_snapshot.py verify`
# counts any added file and would STOP every later step. Set before the first sibling import.
sys.dont_write_bytecode = True
from gh_runtime import GitHubError, Repo, pr_view, run_gh
from review_gate import evaluate, load_evidence, resolve_repo


def comment_text(result: dict[str, Any]) -> str:
    reasons = result.get("reasons", [])
    # Include reviewer links/locations in gate output. Limit size for responsible comments.
    excerpt = "\n".join(f"- {reason[:1200]}" for reason in reasons[:40])
    if len(reasons) > 40:
        excerpt += f"\n- ... {len(reasons)-40} more items in local evidence"
    return ("## Automated PR review: Draft required\n\n"
            f"Reviewed HEAD: `{result['head_sha']}`  \n"
            f"Reviewed Base: `{result['base_sha']}`\n\n"
            "### Blocking issues / verification notes\n\n" + excerpt + "\n\n"
            "**Next steps:** Address blocking findings, rerun affected tests and CI, "
            "and request independent review on the updated HEAD/Base before marking Ready.\n\n"
            "This comment is an automated technical review, not a human approval.\n")


def _write_comment(repo: Repo, number: int, result: dict[str, Any]) -> None:
    filename: str | None = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".md", prefix="prm-", delete=False) as tmp:
            tmp.write(comment_text(result))
            filename = tmp.name
        run_gh(["pr", "comment", str(number), "-R", repo.raw, "--body-file", filename])
    finally:
        if filename:
            try:
                os.unlink(filename)
            except OSError:
                pass


@contextmanager
def repo_mutation_lock(repo: Repo):
    """POSIX exclusive repository-wide lock; concurrent writers fail closed."""
    directory = Path(os.environ.get("PRM_STATE_DIR", "~/.cache/pr-review-merge")).expanduser() / "locks"
    try:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        key = hashlib.sha256(repo.raw.lower().encode("utf-8")).hexdigest()
        with (directory / f"{key}.lock").open("a+", encoding="utf-8") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise GitHubError("Another pr-review-merge actor is modifying this repository") from exc
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)
    except OSError as exc:
        raise GitHubError(f"Cannot acquire GitHub mutation lock: {exc}") from exc


def perform(repo: Repo, number: int, evidence: dict[str, Any], method: str, execute: bool) -> dict[str, Any]:
    if execute:
        with repo_mutation_lock(repo):
            return _perform_locked(repo, number, evidence, method, execute)
    return _perform_locked(repo, number, evidence, method, execute)


def _perform_locked(repo: Repo, number: int, evidence: dict[str, Any], method: str, execute: bool) -> dict[str, Any]:
    # This runs only in Root Agent; one invocation per PR at a time, with serial merges.
    gate = evaluate(repo, number, evidence)
    out = {"repo": repo.raw, "pr": number, "gate": gate, "executed": False,
           "outcome": gate["decision"], "verified_remote_state": None}
    if gate["decision"] not in ("DRAFT", "MERGE") or not execute:
        if gate["decision"] in ("DRAFT", "MERGE") and not execute:
            out["outcome"] = "DRY_RUN_" + gate["decision"]
        return out
    try:
        # Prevent a concurrent actor or last-moment update to the PR state.
        view = pr_view(repo, number)
        if view.get("state") != "OPEN" or view.get("isDraft") is not False or \
           view.get("headRefOid") != gate["head_sha"] or view.get("baseRefOid") != gate["base_sha"]:
            raise GitHubError("PR state/HEAD/Base changed immediately before action")
        if gate["decision"] == "DRAFT":
            # Ensure explanation is available before modifying the PR status.
            _write_comment(repo, number, gate)
            out["comment_posted"] = True
            run_gh(["pr", "ready", str(number), "-R", repo.raw, "--undo"])
            after = pr_view(repo, number)
            out["verified_remote_state"] = after.get("state")
            out["executed"] = True
            if after.get("state") == "OPEN" and after.get("isDraft") is True:
                out["outcome"] = "DRAFT-BLOCKED"
            else:
                out["outcome"] = "ERROR"
                out["error"] = "Draft conversion command returned success but remote Draft state was not confirmed"
        else:
            method_flag = {"squash": "--squash", "merge": "--merge", "rebase": "--rebase"}[method]
            # This method must be allowed by the repository, never fallback blindly.
            run_gh(["pr", "merge", str(number), "-R", repo.raw, method_flag,
                    "--match-head-commit", gate["head_sha"]])
            after = pr_view(repo, number)
            out["executed"] = True
            out["verified_remote_state"] = after.get("state")
            if after.get("state") == "MERGED":
                out["outcome"] = "MERGED"
            else:
                # Usually unexpected merge queue/race: never report success without MERGED.
                out["outcome"] = "WAITING"
                out["error"] = "Merge command finished but PR is not confirmed MERGED. Check queue/auto-merge status immediately."
    except (GitHubError, ValueError) as exc:
        out["outcome"] = "ERROR"
        out["error"] = str(exc)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", help="OWNER/REPO; defaults to current repository")
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--evidence", required=True)
    # Project default: this repository merges with merge commits (upstream default is squash).
    parser.add_argument("--method", choices=["squash", "merge", "rebase"], default="merge")
    parser.add_argument("--execute", action="store_true", help="Actually post comments, convert Draft, or merge")
    args = parser.parse_args()
    try:
        if args.pr <= 0:
            raise ValueError("PR number must be positive")
        result = perform(resolve_repo(args.repo), args.pr, load_evidence(args.evidence), args.method, args.execute)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result["outcome"] in ("MERGED", "DRAFT-BLOCKED", "SKIP", "DRY_RUN_MERGE", "DRY_RUN_DRAFT") else 1
    except (GitHubError, ValueError) as exc:
        print(json.dumps({"outcome": "ERROR", "error": str(exc)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
