#!/usr/bin/env python3
"""Merge train: the single consumer of the `merge-queue` label (kjelly/pilot#307).

Enqueue (`apply_decision.py --execute` on a MERGE gate): the gate-checked review evidence is saved
in the train's state directory and the PR gets the `merge-queue` label.

Process (this script; one consumer per repository and host, from a timer or by hand): take the PR
whose label was added first. When its HEAD lacks the live base tip and GitHub's test merge is clean
with no file changed on both sides, commit the merge of exactly that tip and push it to the PR
branch (never forced). Wait for CI on that HEAD, check that the saved review still covers it (every
change since the reviewed HEAD is a pure import from the base) and that the target record still
covers it, rerun the gate and merge with --match-head-commit.

A conflict, an overlap, a failed check or target evidence that no longer covers HEAD returns the PR
to Draft with the reason (`pr-ready` repairs it); a review that no longer covers HEAD dequeues it
(Ready, for a new `pr-review-merge` run). Transient states (pending mergeability, CI timeout, API
errors, a base that keeps moving) leave it enqueued and stop this run.

The consumer never touches a working tree: it fetches into private refs (`refs/merge-train/*`),
builds the merge commit with `git merge-tree`/`git commit-tree` and pushes the commit object. Use a
dedicated clone (a bare one is enough) as `--worktree`.
"""
from __future__ import annotations

import argparse
import datetime as dt
import fcntl
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

# Running from the skill snapshot must not add __pycache__ there (see apply_decision.py).
sys.dont_write_bytecode = True
import gh_runtime  # noqa: E402
from gh_runtime import GitHubError, Repo  # noqa: E402
import review_gate  # noqa: E402

QUEUE_LABEL = "merge-queue"
SCHEMA = "pilot-merge-train/v1"
SHA_LEN = 40


class TrainError(RuntimeError):
    """A git or state failure that stops this run without touching the PR."""


def _key(repo: Repo) -> str:
    return hashlib.sha256(repo.raw.lower().encode("utf-8")).hexdigest()


def state_root() -> Path:
    return Path(os.environ.get("PRM_STATE_DIR", "~/.cache/pr-review-merge")).expanduser()


def queue_dir(repo: Repo) -> Path:
    return state_root() / "queue" / _key(repo)


def entry_path(repo: Repo, number: int) -> Path:
    return queue_dir(repo) / f"{number}.json"


def save_entry(repo: Repo, number: int, record: dict[str, Any]) -> None:
    directory = queue_dir(repo)
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=f".{number}-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(record, handle, indent=2, ensure_ascii=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, entry_path(repo, number))
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def load_entry(repo: Repo, number: int) -> dict[str, Any] | None:
    try:
        record = json.loads(entry_path(repo, number).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(record, dict) or record.get("schema") != SCHEMA or record.get("pr") != number or \
            not isinstance(record.get("repo"), str) or record["repo"].lower() != repo.raw.lower() or \
            not isinstance(record.get("evidence"), dict) or not _sha(record.get("reviewed_head")):
        return None
    return record


def drop_entry(repo: Repo, number: int) -> None:
    try:
        entry_path(repo, number).unlink()
    except FileNotFoundError:
        pass


def _sha(value: Any) -> bool:
    return isinstance(value, str) and len(value) == SHA_LEN and all(c in "0123456789abcdef" for c in value)


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def enqueue(repo: Repo, number: int, evidence: dict[str, Any], gate: dict[str, Any], *,
            client: Any = gh_runtime) -> dict[str, Any]:
    """Queue a PR the gate decided MERGE. Saves the evidence first, so a labelled PR always has it."""
    if gate.get("decision") != "MERGE" or not _sha(gate.get("head_sha")):
        raise ValueError("Only a MERGE gate decision with a HEAD SHA can be enqueued")
    record = {"schema": SCHEMA, "repo": repo.raw, "pr": number, "queued_at": _now(),
              "reviewed_head": gate["head_sha"], "reviewed_base": gate.get("base_sha"),
              "live_base": gate.get("live_base_sha"), "alignment": gate.get("alignment"),
              "evidence": evidence}
    save_entry(repo, number, record)
    client.edit_label(repo, number, QUEUE_LABEL, add=True)
    client.post_comment(repo, number, (
        "## Merge train: enqueued\n\n"
        f"Reviewed HEAD: `{gate['head_sha']}`  \nLive base: `{gate.get('live_base_sha')}`\n\n"
        + ("The train will merge the live base into this branch first (clean merge, no file changed on "
           "both sides), wait for CI on that HEAD and merge.\n\n" if gate.get("needs_alignment") else
           "The train will wait for CI on this HEAD and merge.\n\n")
        + "Removing the `merge-queue` label takes the PR out of the queue.\n"))
    return {"outcome": "ENQUEUED", "pr": number, "reviewed_head": gate["head_sha"]}


@contextmanager
def consumer_lock(repo: Repo):
    """One consumer per repository on this host; a second one exits BUSY instead of waiting."""
    directory = state_root() / "locks"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (directory / f"{_key(repo)}.train.lock").open("a+", encoding="utf-8") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


@dataclass
class Train:
    repo: Repo
    worktree: Path
    client: Any = gh_runtime
    secret_files: Sequence[Path] = ()
    max_align: int = 3
    ci_timeout: float = 5400.0
    registration_grace: float = 300.0
    poll: float = 30.0
    sleep: Callable[[float], None] = time.sleep
    monotonic: Callable[[], float] = time.monotonic
    mutation_lock: Callable[[Repo], Any] | None = None
    log: list[str] = field(default_factory=list)

    # -- git (objects and private refs only; never the working tree) --------------------------
    def git(self, *args: str, ok: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess[str]:
        proc = subprocess.run(["git", "-C", str(self.worktree), *args], capture_output=True, text=True)
        if proc.returncode not in ok:
            raise TrainError(f"git {' '.join(args[:2])} failed ({proc.returncode}): {proc.stderr.strip()[:300]}")
        return proc

    def _locked(self):
        if self.mutation_lock is not None:
            return self.mutation_lock(self.repo)
        from apply_decision import repo_mutation_lock
        return repo_mutation_lock(self.repo)

    # -- queue ------------------------------------------------------------------------------
    def order(self) -> list[int]:
        numbers = self.client.labeled_open_prs(self.repo, QUEUE_LABEL)
        stamped = []
        for number in numbers:
            added = self.client.label_added_at(self.repo, number, QUEUE_LABEL)
            stamped.append((added or "9999-12-31T23:59:59Z", number))
        return [number for _, number in sorted(stamped)]

    def run(self, *, once: bool = False, only: int | None = None) -> dict[str, Any]:
        """Process the queue in order. `only` (a pr-review-merge invocation, which handles one PR)
        processes that PR alone, and only when it is first in the queue; otherwise NOT_AT_HEAD and
        the timer's consumer takes it in turn."""
        order = self.order()
        if only is not None:
            if not order or order[0] != only:
                return {"status": "NOT_AT_HEAD", "pr": only, "queue": order, "results": []}
            order, once = [only], True
        results: list[dict[str, Any]] = []
        for number in order:
            result = self.process_one(number)
            results.append(result)
            if result["outcome"] in ("WAITING", "ERROR") or once:
                break
        return {"status": "DONE", "results": results}

    # -- one PR -----------------------------------------------------------------------------
    def process_one(self, number: int) -> dict[str, Any]:
        try:
            return self._process(number)
        except (GitHubError, TrainError, ValueError, KeyError) as exc:
            return {"pr": number, "outcome": "ERROR", "reason": str(exc)}

    def _process(self, number: int) -> dict[str, Any]:
        view = self.client.pr_view(self.repo, number)
        if view.get("state") != "OPEN":
            drop_entry(self.repo, number)
            return {"pr": number, "outcome": "SKIP", "reason": f"PR is {view.get('state')}"}
        if view.get("isDraft") is not False:
            return self.dequeue(number, "The PR is a Draft; it left the merge train.", comment=False)
        entry = load_entry(self.repo, number)
        if entry is None:
            return self.dequeue(number, "The merge train has no saved review evidence for this PR on this "
                                "host. Run `pr-review-merge` again to queue it.")
        if view.get("isCrossRepository") is not False or not isinstance(view.get("headRefName"), str):
            return self.dequeue(number, "The merge train pushes only to branches of this repository; "
                                "integrate the base by hand and run `pr-review-merge` again.")
        unknown = 0
        integrations = 0
        while True:
            view = self.client.pr_view(self.repo, number)
            align = review_gate.train_alignment(self.client, self.repo, number, view)
            kind = align["alignment"]
            if kind in ("conflict", "overlap"):
                reason = ("GitHub reports a merge conflict with the live base" if kind == "conflict" else
                          "both sides changed " + ", ".join(align["overlap"][:5]) + " since the merge base")
                return self.to_draft(number, view, align, [
                    f"PR HEAD {view['headRefOid']} does not include live {view['baseRefName']} SHA "
                    f"{align['live_base_sha']}, and {reason}. The merge train cannot integrate it: use "
                    "pr-ready to integrate the verified latest base, then rerun validation/CI and "
                    "independent review before Ready."])
            if kind == "unknown":
                unknown += 1
                if unknown > self.max_align:
                    return self.waiting(number, align.get("alignment_detail", "alignment unknown"))
                self.sleep(self.poll)
                continue
            if kind == "train":
                integrations += 1
                if integrations > self.max_align:
                    return self.waiting(number, f"the base moved {self.max_align} times while this PR "
                                        "was in the train; it stays enqueued")
                outcome = self.integrate(number, view, align)
                if outcome is not None:
                    return outcome
                continue
            # aligned: HEAD contains the live tip.
            state = self.wait_ci(number, view["headRefOid"], view["baseRefName"], align["live_base_sha"])
            if state == "base-moved":
                continue
            if state == "head-moved":
                return self.dequeue(number, "The PR HEAD changed outside the merge train while it was "
                                    "enqueued; run `pr-review-merge` again on the new HEAD.")
            if state == "timeout":
                return self.waiting(number, "CI did not settle in time")
            return self.finish(number, entry, view, align)

    def integrate(self, number: int, view: dict[str, Any], align: dict[str, Any]) -> dict[str, Any] | None:
        head, live = view["headRefOid"], align["live_base_sha"]
        base, branch = view["baseRefName"], view["headRefName"]
        self.git("fetch", "--no-tags", "--quiet", "origin",
                 f"+refs/pull/{number}/head:refs/merge-train/pr/{number}",
                 f"+refs/heads/{base}:refs/merge-train/base/{base}")
        fetched_head = self.git("rev-parse", f"refs/merge-train/pr/{number}").stdout.strip()
        fetched_base = self.git("rev-parse", f"refs/merge-train/base/{base}").stdout.strip()
        if fetched_head != head or fetched_base != live:
            self.log.append(f"#{number}: PR head or base moved during fetch; retrying")
            return None
        merged = self.git("merge-tree", "--write-tree", head, live, ok=(0, 1))
        if merged.returncode == 1:
            return self.to_draft(number, view, align, [
                f"PR HEAD {head} does not include live {base} SHA {live}, and merging it conflicts. "
                "Use pr-ready to integrate the verified latest base, then rerun validation/CI and "
                "independent review before Ready."])
        tree = merged.stdout.splitlines()[0].strip()
        message = (f"Merge {base} ({live[:8]}) into {branch}\n\n"
                   f"Merge train for #{number} (kjelly/pilot#307): integrate the live base before merging.")
        commit = self.git("commit-tree", tree, "-p", head, "-p", live, "-m", message).stdout.strip()
        # Belt and braces: the commit may only bring base content (a pure import).
        changed = [p for p in self.git("diff", "--name-only", "--no-renames", "-z", head, commit).stdout.split("\0") if p]
        for path in changed:
            ours = self.git("ls-tree", commit, "--", path).stdout.split()
            theirs = self.git("ls-tree", live, "--", path).stdout.split()
            if ours[:3] != theirs[:3]:
                return self.to_draft(number, view, align, [
                    f"The merge of live {base} SHA {live} into {head} changes {path} differently from "
                    f"{base}; the merge train only integrates pure base imports. Use pr-ready."])
        with self._locked():
            current = self.client.pr_view(self.repo, number)
            if current.get("headRefOid") != head or current.get("isDraft") is not False or \
                    self.client.branch_head(self.repo, base) != live:
                self.log.append(f"#{number}: PR or base moved before the push; retrying")
                return None
            self.git("push", "--quiet", "origin", f"{commit}:refs/heads/{branch}")
        self.log.append(f"#{number}: pushed {commit[:12]} (merge of {base} {live[:12]})")
        for _ in range(int(max(1, 120 / max(self.poll, 1)))):
            if self.client.pr_view(self.repo, number).get("headRefOid") == commit:
                return None
            self.sleep(min(self.poll, 5))
        return self.waiting(number, f"GitHub has not shown the pushed merge commit {commit[:12]} yet")

    def wait_ci(self, number: int, head: str, base: str, live: str) -> str:
        start = self.monotonic()
        while True:
            view = self.client.pr_view(self.repo, number)
            if view.get("headRefOid") != head:
                return "head-moved"
            if self.client.branch_head(self.repo, base) != live:
                return "base-moved"
            checks = self.client.pr_checks(self.repo, number)
            elapsed = self.monotonic() - start
            pending = any(check.get("bucket") == "pending" for check in checks) or \
                (not checks and elapsed < self.registration_grace)
            if not pending:
                return "settled"
            if elapsed > self.ci_timeout:
                return "timeout"
            self.sleep(self.poll)

    def finish(self, number: int, entry: dict[str, Any], view: dict[str, Any],
               align: dict[str, Any]) -> dict[str, Any]:
        head, base, live = view["headRefOid"], view["baseRefName"], align["live_base_sha"]
        evidence = entry["evidence"]
        reuse, why = review_gate.review_covers(self.client, self.repo, entry["reviewed_head"], head, live, base)
        if reuse is None:
            return self.dequeue(number, f"The saved review (HEAD {entry['reviewed_head'][:12]}) no longer "
                                f"covers HEAD {head[:12]}: {why}. Run `pr-review-merge` again.")
        gaps, _ = review_gate.check_target_validation(self.client, self.repo, head, live, evidence,
                                                      base_name=base, integrated_base=True)
        if gaps:
            return self.to_draft(number, view, align, [
                "After the merge train integrated the live base, the target record no longer covers "
                "HEAD: " + "; ".join(gaps)[:1500] + ". Use pr-ready to run the target chain again (or to "
                "record the reviewer's `unrelated_runtime_changes`)."])
        gate = review_gate.evaluate(self.repo, number, evidence, client=self.client,
                                    worktree=self.worktree, secret_files=self.secret_files)
        if gate["decision"] == "MERGE" and not gate.get("needs_alignment"):
            return self.merge(number, gate)
        if gate["decision"] == "DRAFT":
            return self.to_draft(number, view, align, gate["reasons"], gate=gate)
        return self.waiting(number, "; ".join(gate["reasons"])[:1500])

    # -- actions ----------------------------------------------------------------------------
    def merge(self, number: int, gate: dict[str, Any]) -> dict[str, Any]:
        with self._locked():
            view = self.client.pr_view(self.repo, number)
            if view.get("state") != "OPEN" or view.get("isDraft") is not False or \
                    view.get("headRefOid") != gate["head_sha"] or view.get("baseRefName") != gate["base_name"] or \
                    self.client.branch_head(self.repo, gate["base_name"]) != gate["live_base_sha"]:
                return self.waiting(number, "PR state/HEAD/base changed immediately before the merge")
            self.client.merge_pr(self.repo, number, gate["head_sha"])
            after = self.client.pr_view(self.repo, number)
        if after.get("state") != "MERGED":
            return {"pr": number, "outcome": "ERROR",
                    "reason": "Merge command finished but the PR is not confirmed MERGED"}
        drop_entry(self.repo, number)
        return {"pr": number, "outcome": "MERGED", "head_sha": gate["head_sha"]}

    def to_draft(self, number: int, view: dict[str, Any], align: dict[str, Any], reasons: list[str], *,
                 gate: dict[str, Any] | None = None) -> dict[str, Any]:
        from apply_decision import comment_text
        result = gate or {"reasons": reasons, "head_sha": view["headRefOid"], "base_sha": view.get("baseRefOid"),
                          "base_behind": align.get("base_behind"), "base_mismatch": align.get("base_mismatch"),
                          "live_base_sha": align.get("live_base_sha")}
        with self._locked():
            self.client.post_comment(self.repo, number, comment_text(result))
            self.client.edit_label(self.repo, number, QUEUE_LABEL, add=False)
            self.client.mark_draft(self.repo, number)
            after = self.client.pr_view(self.repo, number)
        drop_entry(self.repo, number)
        if after.get("isDraft") is not True:
            return {"pr": number, "outcome": "ERROR", "reason": "Draft conversion was not confirmed"}
        return {"pr": number, "outcome": "DRAFTED", "reasons": reasons}

    def dequeue(self, number: int, reason: str, *, comment: bool = True) -> dict[str, Any]:
        with self._locked():
            if comment:
                self.client.post_comment(self.repo, number, "## Merge train: left the queue\n\n" + reason + "\n")
            self.client.edit_label(self.repo, number, QUEUE_LABEL, add=False)
        drop_entry(self.repo, number)
        return {"pr": number, "outcome": "DEQUEUED", "reason": reason}

    def waiting(self, number: int, reason: str) -> dict[str, Any]:
        return {"pr": number, "outcome": "WAITING", "reason": reason}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    process = sub.add_parser("process", help="Merge enqueued PRs in order (one consumer per repository and host)")
    process.add_argument("--repo", required=True, help="OWNER/REPO")
    process.add_argument("--worktree", type=Path, required=True,
                         help="Dedicated clone (bare is enough) with an `origin` remote; never checked out")
    process.add_argument("--secret-file", action="append", default=[], type=Path, metavar="FILE")
    process.add_argument("--once", action="store_true", help="Process only the first PR in the queue")
    process.add_argument("--pr", type=int, help="Process only this PR, and only when it is first in the queue "
                         "(what a single-item pr-review-merge invocation may do)")
    process.add_argument("--max-align", type=int, default=3)
    process.add_argument("--ci-timeout", type=float, default=5400.0)
    process.add_argument("--poll", type=float, default=30.0)
    status = sub.add_parser("status", help="Show the queue order")
    status.add_argument("--repo", required=True)
    args = parser.parse_args(argv)
    repo = Repo.parse(args.repo)
    try:
        if args.command == "status":
            train = Train(repo, Path("."))
            order = train.order()
            print(json.dumps({"queue": [{"pr": n, "saved_evidence": load_entry(repo, n) is not None}
                                        for n in order]}, indent=2))
            return 0
        with consumer_lock(repo) as acquired:
            if not acquired:
                print(json.dumps({"status": "BUSY", "message": "another merge-train consumer is running"}))
                return 0
            train = Train(repo, args.worktree, secret_files=args.secret_file, max_align=args.max_align,
                          ci_timeout=args.ci_timeout, poll=args.poll)
            out = train.run(once=args.once, only=args.pr)
            out["log"] = train.log
            print(json.dumps(out, indent=2, ensure_ascii=False))
            return 0 if all(r["outcome"] != "ERROR" for r in out["results"]) else 1
    except (GitHubError, TrainError, ValueError, OSError) as exc:
        print(json.dumps({"status": "ERROR", "error": str(exc)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
