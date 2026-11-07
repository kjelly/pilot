#!/usr/bin/env python3
"""Serial, guarded PR actor. --execute is required for mutations.

DRAFT posts the reasons and converts the PR to Draft. MERGE queues the PR for the merge train
(`merge_train.py`, kjelly/pilot#307): the train is the only merger, so a merge never races another
PR's CI on an aligned HEAD.

A write is reported as done only when the PR itself shows it (`gh pr view`), read again a bounded number
of times: GitHub's reads lag its writes by a few seconds, and a PR that was enqueued must not be reported
as an ERROR for that (kjelly/pilot#310). The label is read from the PR, not from the issues listing, which
lags more. The "enqueued" comment is written after the label and is best effort: the label is what the
train reads, so a comment that fails after it is a warning, not an error.
"""
from __future__ import annotations
import argparse
import json
import os
import sys
import tempfile
import hashlib
import fcntl
import time
from pathlib import Path
from contextlib import contextmanager
from typing import Any, Callable, Sequence

# Running from the skill snapshot must not add __pycache__ there: `skill_snapshot.py verify`
# counts any added file and would STOP every later step. Set before the first sibling import.
sys.dont_write_bytecode = True
from gh_runtime import (GitHubError, MutationLockError, MutationLockHeld, MutationLockUnavailable, Repo,
                        branch_head, pr_view, run_gh)
from review_gate import evaluate, load_evidence, resolve_repo

# A write is read back from the PR at most READ_TRIES times, READ_INTERVAL seconds apart: 25 s at most.
# The reads run while the actor holds the repository mutation lock (the train sees it as held and
# waits), so this bound is also how long a lagging GitHub can keep the train waiting.
READ_TRIES = 6
READ_INTERVAL = 5.0


def comment_text(result: dict[str, Any]) -> str:
    reasons = result.get("reasons", [])
    # Include reviewer links/locations in gate output. Limit size for responsible comments.
    excerpt = "\n".join(f"- {reason[:1200]}" for reason in reasons[:40])
    if len(reasons) > 40:
        excerpt += f"\n- ... {len(reasons)-40} more items in local evidence"
    base_blocked = result.get("base_mismatch") or result.get("base_behind")
    identity_label = "Observed" if base_blocked else "Reviewed"
    base_next = (" Use `pr-ready` to reconcile PR metadata and integrate the verified latest base "
                 "so the live base tip is an ancestor of HEAD."
                 if base_blocked else "")
    live_base = f"Live base tip: `{result['live_base_sha']}`\n\n" if base_blocked else ""
    leaked = (result.get("secret_scan") or {}).get("status") == "FOUND"
    # A leaked secret is not something another commit can fix: the earlier commit stays published.
    next_steps = (
        "**Next steps:** **Stop.** Do not push more commits on top of this and do not mark the PR Ready. "
        "The secret is in the commit history of this PR, so a commit that removes it does not clear this "
        "finding. The user decides on revoking or rotating the credential and on how the history is handled; "
        "the finding stays blocking until they have recorded that decision on this PR. "
        "See `.agents/skills/_shared/committed-secrets.md`."
        if leaked else
        "**Next steps:** Address blocking findings, rerun affected tests and CI, "
        "and request independent review on the updated HEAD/Base before marking Ready.")
    return ("## Automated PR review: Draft required\n\n"
            f"{identity_label} HEAD: `{result['head_sha']}`  \n"
            f"{identity_label} Base: `{result['base_sha']}`\n\n"
            + live_base +
            "### Blocking issues / verification notes\n\n" + excerpt + "\n\n"
            + next_steps
            + base_next + "\n\n"
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
    """POSIX exclusive repository-wide lock; concurrent writers fail closed.

    Taking the lock fails in two ways, told apart by type: `MutationLockHeld` (another actor has it) and
    `MutationLockUnavailable` (its directory or file cannot be used). Only the acquisition is translated:
    whatever the body raises, an `OSError` included, reaches the caller as it is (a full disk while the
    body saves a file is not a lock failure, kjelly/pilot#310)."""
    directory = Path(os.environ.get("PRM_STATE_DIR", "~/.cache/pr-review-merge")).expanduser() / "locks"
    key = hashlib.sha256(repo.raw.lower().encode("utf-8")).hexdigest()
    try:
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        handle = (directory / f"{key}.lock").open("a+", encoding="utf-8")
    except OSError as exc:
        raise MutationLockUnavailable(f"Cannot acquire GitHub mutation lock: {exc}") from exc
    with handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise MutationLockHeld("Another pr-review-merge actor is modifying this repository") from exc
        except OSError as exc:
            raise MutationLockUnavailable(f"Cannot acquire GitHub mutation lock: {exc}") from exc
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def _has_label(view: dict[str, Any], label: str) -> bool:
    labels = view.get("labels")
    return isinstance(labels, list) and any(isinstance(item, dict) and item.get("name") == label
                                            for item in labels)


def _read_until(repo: Repo, number: int, confirmed: Callable[[dict[str, Any]], bool], *,
                sleep: Callable[[float], None]) -> tuple[bool, dict[str, Any], GitHubError | None]:
    """Read the PR until `confirmed(view)`, at most READ_TRIES reads READ_INTERVAL seconds apart (GitHub's
    reads lag its writes). Returns (confirmed, the last view read, the error of the last read when it
    failed). A read that fails is read again; only a PR that still does not show the write after the last
    read is "not confirmed"."""
    view: dict[str, Any] = {}
    error: GitHubError | None = None
    for attempt in range(READ_TRIES):
        if attempt:
            sleep(READ_INTERVAL)
        try:
            view, error = pr_view(repo, number), None
        except GitHubError as exc:
            error = exc
            continue
        if confirmed(view):
            return True, view, None
    return False, view, error


def perform(repo: Repo, number: int, evidence: dict[str, Any], method: str, execute: bool, *,
            worktree: Any = None, secret_files: Sequence[Any] = (),
            sleep: Callable[[float], None] = time.sleep) -> dict[str, Any]:
    if execute:
        with repo_mutation_lock(repo):
            return _perform_locked(repo, number, evidence, method, execute,
                                   worktree=worktree, secret_files=secret_files, sleep=sleep)
    return _perform_locked(repo, number, evidence, method, execute, worktree=worktree,
                           secret_files=secret_files, sleep=sleep)


def _perform_locked(repo: Repo, number: int, evidence: dict[str, Any], method: str, execute: bool, *,
                    worktree: Any = None, secret_files: Sequence[Any] = (),
                    sleep: Callable[[float], None] = time.sleep) -> dict[str, Any]:
    # This runs only in Root Agent; one invocation per PR at a time, with serial merges. The gate is
    # re-run here with the same worktree: a MERGE needs the secret scan of every commit to be clean.
    gate = evaluate(repo, number, evidence, worktree=worktree, secret_files=secret_files)
    out = {"repo": repo.raw, "pr": number, "gate": gate, "executed": False,
           "outcome": gate["decision"], "verified_remote_state": None}
    if gate["decision"] not in ("DRAFT", "MERGE") or not execute:
        if gate["decision"] in ("DRAFT", "MERGE") and not execute:
            out["outcome"] = "DRY_RUN_" + gate["decision"]
        return out
    try:
        # A branch name is part of the confirmed identity, even when two tips share a SHA.
        base_name = gate.get("base_name")
        if not isinstance(base_name, str) or not base_name:
            raise GitHubError("Gate base branch identity unavailable")
        # Prevent a concurrent actor or last-moment update to the PR state.
        view = pr_view(repo, number)
        if view.get("state") != "OPEN" or view.get("isDraft") is not False or \
           view.get("headRefOid") != gate["head_sha"] or view.get("baseRefOid") != gate["base_sha"] or \
           view.get("baseRefName") != base_name or \
           branch_head(repo, base_name) != gate["live_base_sha"]:
            raise GitHubError("PR state/HEAD/Base changed immediately before action")
        if gate["decision"] == "DRAFT":
            # Ensure explanation is available before modifying the PR status.
            _write_comment(repo, number, gate)
            out["comment_posted"] = True
            # A repair or base advance while the comment was posted invalidates this Draft action.
            current = pr_view(repo, number)
            if any(current.get(k) != view.get(k) for k in
                   ("state", "isDraft", "headRefOid", "baseRefOid", "baseRefName")) or \
                    branch_head(repo, base_name) != gate["live_base_sha"]:
                raise GitHubError("PR state/HEAD/Base changed after comment; retry live gate")
            run_gh(["pr", "ready", str(number), "-R", repo.raw, "--undo"])
            out["executed"] = True
            drafted, after, error = _read_until(
                repo, number, lambda v: v.get("state") == "OPEN" and v.get("isDraft") is True, sleep=sleep)
            out["verified_remote_state"] = after.get("state")
            if drafted:
                out["outcome"] = "DRAFT-BLOCKED"
            else:
                out["outcome"] = "ERROR"
                out["error"] = ("Draft conversion command returned success but remote Draft state was not "
                                f"confirmed after {READ_TRIES} reads" + (f"; the last read failed: {error}" if error else ""))
        else:
            if method != "merge":
                raise GitHubError("The merge train merges with merge commits; --method squash/rebase is not enqueued")
            import merge_train
            enqueued = merge_train.enqueue(repo, number, evidence, gate)
            out["executed"] = True
            out["enqueued"] = enqueued
            # The PR itself says whether it carries the label (the train trusts the same read); the issues
            # listing lags the write by seconds and is not consulted. Read again before calling it absent.
            labelled, _, error = _read_until(repo, number, lambda v: _has_label(v, merge_train.QUEUE_LABEL),
                                             sleep=sleep)
            out["verified_remote_state"] = "ENQUEUED" if labelled else None
            if labelled:
                out["outcome"] = "ENQUEUED"
                if enqueued.get("comment_error"):
                    out["warnings"] = ["The PR is enqueued, but its \"enqueued\" comment could not be posted: "
                                       f"{enqueued['comment_error']}"]
            else:
                out["outcome"] = "ERROR"
                out["error"] = ("Queue label command returned success but the PR does not show the label after "
                                f"{READ_TRIES} reads" + (f"; the last read failed: {error}" if error else ""))
    except (GitHubError, ValueError) as exc:
        out["outcome"] = "ERROR"
        out["error"] = str(exc)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", help="OWNER/REPO; defaults to current repository")
    parser.add_argument("--pr", type=int, required=True)
    parser.add_argument("--evidence", required=True)
    parser.add_argument("--worktree", type=Path,
                        help="Checkout of this repository that holds the PR's commits: every commit of "
                             "baseRefOid..headRefOid is scanned for secrets (without it the gate WAITs and nothing merges)")
    parser.add_argument("--secret-file", action="append", default=[], type=Path, metavar="FILE",
                        help="File OUTSIDE the repository with one secret value per line (8+ bytes each) that must "
                             "appear in no commit, message or path of the PR. Repeatable. Values are never printed.")
    # Project default: this repository merges with merge commits (upstream default is squash).
    parser.add_argument("--method", choices=["squash", "merge", "rebase"], default="merge")
    parser.add_argument("--execute", action="store_true",
                        help="Actually post comments and convert to Draft, or queue for the merge train")
    args = parser.parse_args()
    try:
        if args.pr <= 0:
            raise ValueError("PR number must be positive")
        result = perform(resolve_repo(args.repo), args.pr, load_evidence(args.evidence), args.method, args.execute,
                         worktree=args.worktree, secret_files=args.secret_file)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result["outcome"] in ("ENQUEUED", "MERGED", "DRAFT-BLOCKED", "SKIP", "DRY_RUN_MERGE",
                                          "DRY_RUN_DRAFT") else 1
    except (GitHubError, MutationLockError, ValueError) as exc:
        print(json.dumps({"outcome": "ERROR", "error": str(exc)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
