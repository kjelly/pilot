#!/usr/bin/env python3
"""Serial, guarded PR actor. --execute is required for mutations.

DRAFT posts the reasons and converts the PR to Draft. MERGE queues the PR for the merge train
(`merge_train.py`, kjelly/pilot#307): the train is the only merger, so a merge never races another
PR's CI on an aligned HEAD. WAITING keeps the PR Ready; one that only a person can resolve
(`wait_kind: person` and `person_handoff: true`: the gate registers those reasons, review_gate.py
`WaitKinds.person`) is commented and labelled `needs-person` (`needs_person.py`). Any other WAITING
(CI or GitHub still settling, or evidence and review gaps the next `pr-review-merge` run can supply)
stays listable, and DRAFT, ENQUEUED and such a WAITING remove a stale label again.

The actor acts only on a PR that reached Ready through a verified Draft -> Ready step: `review_gate.ready_signal_gate`
reads the PR's Ready signal (the label and marker comment pr-ready and mark_ready.py write after their post-Ready
verification) after the gate and again on the view taken right before the action. A PR without a valid signal is
WAITING (`wait_kind: transient`, no hand-off) and NOTHING is written to it: no Draft conversion, no comment, no
`needs-person` label, no queue label. A signal bound to an earlier HEAD still counts when `review_covers` says the
new HEAD covers it: a pure import of the base (the merge train's integration commit, a person merging the base in)
or a delta that touches only the base manifest's `evidence_only_paths`. After a
confirmed Draft the Ready label goes: a PR that is Ready again must be signed again.

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
import gh_runtime
from gh_runtime import (GitHubError, MutationLockHeld, MutationLockUnavailable, Repo, branch_head, edit_label,
                        issue_comments, post_comment, pr_view, run_gh, viewer_login)
from review_gate import evaluate, load_evidence, ready_signal_gate, resolve_repo
import needs_person
import ready_signal  # the shared module: review_gate has put its directory on sys.path

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


def _warn(out: dict[str, Any], message: str) -> None:
    out.setdefault("warnings", []).append(message)


def _release_needs_person(repo: Repo, number: int, view: dict[str, Any], out: dict[str, Any]) -> None:
    """Remove a `needs-person` label left by an earlier run. Housekeeping: a failure is a warning and never
    changes the outcome (the label only keeps the PR out of `list_ready.py`)."""
    if not needs_person.has_label(view):
        return
    try:
        edit_label(repo, number, needs_person.LABEL, add=False)
        out["handoff"] = "released"
    except GitHubError as exc:
        _warn(out, f"The `{needs_person.LABEL}` label from an earlier run could not be removed: {exc}")


def _release_ready_signal(repo: Repo, number: int, view: dict[str, Any], out: dict[str, Any]) -> None:
    """Take the Ready label off a PR this actor just converted to Draft (`view` is the confirmed Draft). The PR
    is Ready again only through pr-ready, which signs it for the HEAD it verifies; a label left behind would
    be an old claim on a PR that is no longer Ready. Housekeeping, so a failure is a warning, never an error and
    never retried here (pr-ready removes a stale label before the next Ready)."""
    if not _has_label(view, ready_signal.LABEL):
        return
    try:
        edit_label(repo, number, ready_signal.LABEL, add=False)
        out["ready_label"] = "released"   # not `ready_signal`: that is what the gate saw (`gate["ready_signal"]`)
    except GitHubError as exc:
        _warn(out, f"The `{ready_signal.LABEL}` label could not be removed after the Draft conversion: {exc}; "
                   "pr-ready removes it before the PR is Ready again")


def _signal_refused(repo: Repo, number: int, gate: dict[str, Any], out: dict[str, Any],
                    view: dict[str, Any] | None = None) -> bool:
    """True when the PR has no valid Ready signal: the result is then WAITING (`transient`) and the caller returns
    it without writing anything. `view` is the PR as the caller just read it (None: read it here)."""
    if ready_signal_gate(gh_runtime, repo, number, gate, view) is None:
        return False
    out["outcome"], out["wait_kind"] = "WAITING", gate["wait_kind"]
    return True


def _waiting_handoff(repo: Repo, number: int, gate: dict[str, Any], out: dict[str, Any], *,
                     sleep: Callable[[float], None]) -> None:
    """A WAITING gate leaves the PR Ready. One that only a person can resolve (`wait_kind: person` and
    `person_handoff: true`) gets a comment with the reasons and the judged HEAD (once per HEAD and set of
    reasons) and the `needs-person` label, so the PR has a visible owner instead of being picked up and
    reviewed again for the same answer. Any other WAITING (it settles by itself, or the next review run can
    supply what is missing: `wait_kind: person` alone is the merge train's catch-all, not a hand-off) gets
    no comment and removes such a label from an earlier run: no person is waited for.

    Nothing here changes the outcome, which stays WAITING: a failure is a warning in `warnings`."""
    try:
        view = pr_view(repo, number)
        if gate.get("wait_kind") != "person" or gate.get("person_handoff") is not True:
            _release_needs_person(repo, number, view, out)
            return
        head, base, live, base_name = (gate.get("head_sha"), gate.get("base_sha"), gate.get("live_base_sha"),
                                       gate.get("base_name"))
        if not all(isinstance(v, str) and v for v in (head, base, live, base_name)):
            _warn(out, "The gate result lacks the PR or live base identity; no needs-person hand-off was made")
            return
        if view.get("state") != "OPEN" or view.get("isDraft") is not False or view.get("headRefOid") != head or \
                view.get("baseRefOid") != base or view.get("baseRefName") != base_name or \
                branch_head(repo, base_name) != live:
            _warn(out, "PR state/HEAD/Base changed after the gate; no needs-person hand-off was made, rerun it")
            return
        marker = needs_person.latest_marker(issue_comments(repo, number), viewer_login(repo))
        if not (marker and marker["head"] == head.lower()
                and marker["reasons"] == needs_person.reasons_digest(gate.get("reasons", []))):
            post_comment(repo, number, needs_person.comment_text(gate))
            out["comment_posted"] = True
        if not needs_person.has_label(view):
            edit_label(repo, number, needs_person.LABEL, add=True)
            labelled, _, error = _read_until(repo, number, needs_person.has_label, sleep=sleep)
            if not labelled:
                _warn(out, f"The `{needs_person.LABEL}` label was added but the PR does not show it after "
                      f"{READ_TRIES} reads" + (f"; the last read failed: {error}" if error else ""))
                return
        out["handoff"] = "needs-person"
    except GitHubError as exc:
        _warn(out, f"needs-person hand-off failed: {exc}")


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
    if gate["decision"] == "WAITING":
        out["wait_kind"] = gate.get("wait_kind")
    # Nothing is written to a PR that did not get to Ready through pr-ready's verification, whatever the gate
    # decided: not the Draft conversion, not the comment, not the hand-off, not the queue. A WAITING gate and a
    # dry run are looked at here; a decision that is about to be acted on is looked at inside the `try` below, once
    # its base identity is known and again on the view taken right before the action.
    acting = gate["decision"] in ("DRAFT", "MERGE") and execute
    if gate["decision"] != "SKIP" and not acting and _signal_refused(repo, number, gate, out):
        return out
    if gate["decision"] not in ("DRAFT", "MERGE") or not execute:
        if gate["decision"] in ("DRAFT", "MERGE") and not execute:
            out["outcome"] = "DRY_RUN_" + gate["decision"]
        elif gate["decision"] == "WAITING" and execute:
            _waiting_handoff(repo, number, gate, out, sleep=sleep)
        return out
    try:
        # A branch name is part of the confirmed identity, even when two tips share a SHA.
        base_name = gate.get("base_name")
        if not isinstance(base_name, str) or not base_name:
            raise GitHubError("Gate base branch identity unavailable")
        if _signal_refused(repo, number, gate, out):
            return out
        # Prevent a concurrent actor or last-moment update to the PR state.
        view = pr_view(repo, number)
        if view.get("state") != "OPEN" or view.get("isDraft") is not False or \
           view.get("headRefOid") != gate["head_sha"] or view.get("baseRefOid") != gate["base_sha"] or \
           view.get("baseRefName") != base_name or \
           branch_head(repo, base_name) != gate["live_base_sha"]:
            raise GitHubError("PR state/HEAD/Base changed immediately before action")
        # The signal is read again on this view: a label removed, or a Draft round made, since the first look
        # leaves the PR alone, like a HEAD that moved.
        if _signal_refused(repo, number, gate, out, view):
            return out
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
                # pr-ready owns the PR now: a `needs-person` mark from an earlier run no longer applies, and
                # neither does the Ready signal of the Ready PR it was.
                _release_needs_person(repo, number, after, out)
                _release_ready_signal(repo, number, after, out)
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
            labelled, after, error = _read_until(repo, number, lambda v: _has_label(v, merge_train.QUEUE_LABEL),
                                                 sleep=sleep)
            out["verified_remote_state"] = "ENQUEUED" if labelled else None
            if labelled:
                out["outcome"] = "ENQUEUED"
                if enqueued.get("comment_error"):
                    out["warnings"] = ["The PR is enqueued, but its \"enqueued\" comment could not be posted: "
                                       f"{enqueued['comment_error']}"]
                # The merge train owns the PR now.
                _release_needs_person(repo, number, after, out)
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
    parser.add_argument("--pr-loop-task", type=Path, help="Optional pr-loop task.json (scripts/pr_loop.py); the terminal outcome is written to result.json beside it")
    args = parser.parse_args()
    task = None
    try:
        if args.pr <= 0:
            raise ValueError("PR number must be positive")
        repo = resolve_repo(args.repo)
        if args.pr_loop_task is not None:
            if not args.execute:
                parser.error("--pr-loop-task requires --execute")
            sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_shared" / "scripts"))
            from pr_loop_result import load_task, publish_gate_result
            task = load_task(args.pr_loop_task, f"{repo.owner}/{repo.name}", args.pr, "ready")
        result = perform(repo, args.pr, load_evidence(args.evidence), args.method, args.execute,
                         worktree=args.worktree, secret_files=args.secret_file)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        if task is not None:
            publish_gate_result(args.pr_loop_task, task, result)
        return 0 if result["outcome"] in ("ENQUEUED", "MERGED", "DRAFT-BLOCKED", "SKIP", "DRY_RUN_MERGE",
                                          "DRY_RUN_DRAFT") else 1
    except Exception as exc:
        # GitHubError, MutationLockError and ValueError are the failures this script expects; anything else
        # (the saved entry cannot be written, a response of an unexpected shape) is the same kind of result:
        # a structured ERROR on stdout and exit code 2, never a traceback with exit code 1, which is what a
        # PR the gate would not let through ends with. `MutationLockError` is no GitHubError on purpose.
        result = {"outcome": "ERROR", "error_kind": type(exc).__name__, "error": str(exc)}
        print(json.dumps(result, ensure_ascii=False))
        if task is not None:
            publish_gate_result(args.pr_loop_task, task, result)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
