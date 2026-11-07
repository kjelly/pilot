#!/usr/bin/env python3
"""Merge train: the single consumer of the `merge-queue` label (kjelly/pilot#307).

Enqueue (`apply_decision.py --execute` on a MERGE gate): the gate-checked review evidence is saved
in the train's state directory, with the HEAD the review covers (`reviewed_head`), the HEAD the
gate saw (`enqueued_head`) and an `entry_id` that names this enqueue, and the PR gets the
`merge-queue` label.

Process (this script; one consumer per repository and host, from a timer or by hand): take the PR
whose label was added first. The PR's HEAD must be the enqueued HEAD or a commit this train pushed
(`train_commits`); any other HEAD was never gated and leaves the queue. When the HEAD lacks the live
base tip and GitHub's test merge is clean with no file changed on both sides, commit the merge of
exactly that tip and push it to the PR branch (never forced). Wait for CI on that HEAD, check that
the saved review still covers it (every change since the reviewed HEAD is a pure import from the
base, and HEAD carries every change the base made) and that the target record still covers it,
rerun the gate and merge with --match-head-commit. Removing the `merge-queue` label cancels the PR
at every one of those steps.

A conflict, an overlap, a failed check or target evidence that no longer covers HEAD returns the PR
to Draft with the reason (`pr-ready` repairs it). A review that no longer covers HEAD, a HEAD changed
outside the train, and a gate result only a person can change (an unresolved approval, a requested
change, a disputed finding, a failing check the reviewer confirmed unrelated, a merge state that is
not clean for another reason, a comparison GitHub cut) dequeue it: Ready, with the reasons in a
comment, and the run goes on with the next PR. Transient states (CI that is pending, a base that
keeps moving, mergeability GitHub has not computed, an API or infrastructure failure, a secret scan
that could not run) leave it enqueued and stop this run. A PR that ends in ERROR on three runs in a
row leaves the queue with a comment, so one persistent error cannot hold up the others.

Every write (a comment, the label, Draft, the merge, the push, and the saved entry) is made through
`Train._guard`: under the repository mutation lock it reads the saved entry, the PR and the base tip
again and writes only while they are what the decision was derived from. Otherwise it writes nothing
and the run looks at the PR again (`RETRY`). `tests/test_merge_train_guard.py` checks this for every
write in the class.

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
import uuid
from contextlib import ExitStack, contextmanager
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
MAX_ERRORS = 3


class TrainError(RuntimeError):
    """A git or state failure that stops this run without touching the PR."""


class LockBusy(RuntimeError):
    """The repository mutation lock could not be taken: another actor holds it, or its directory is
    unusable (the message says which). Nothing was written; the PR stays enqueued and the failure is
    not counted against it."""


class _Signal:
    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:
        return self.name


# Returned instead of a result by a step whose write was refused because the PR (or the saved entry)
# changed after the decision was made: nothing was written and the run looks at the PR again.
RETRY = _Signal("RETRY")
# Returned by a step that is only one more turn of the loop (not a refusal): look at the PR again.
NEXT = _Signal("NEXT")


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
            not _entry_id(record.get("entry_id")) or \
            not isinstance(record.get("evidence"), dict) or not _sha(record.get("reviewed_head")) or \
            not _sha(record.get("enqueued_head")) or not isinstance(record.get("train_commits"), list) or \
            not all(_sha(c) for c in record["train_commits"]) or type(record.get("errors")) is not int:
        return None
    return record


def drop_entry(repo: Repo, number: int) -> None:
    try:
        entry_path(repo, number).unlink()
    except FileNotFoundError:
        pass


def _sha(value: Any) -> bool:
    return isinstance(value, str) and len(value) == SHA_LEN and all(c in "0123456789abcdef" for c in value)


def _entry_id(value: Any) -> bool:
    return isinstance(value, str) and len(value) == 32 and all(c in "0123456789abcdef" for c in value)


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def enqueue(repo: Repo, number: int, evidence: dict[str, Any], gate: dict[str, Any], *,
            client: Any = gh_runtime) -> dict[str, Any]:
    """Queue a PR the gate decided MERGE. Saves the evidence first, so a labelled PR always has it.

    `reviewed_head` is the HEAD the review evidence names; `enqueued_head` is the HEAD the gate decided
    MERGE for (the two differ when the review covers the HEAD by a pure import or evidence-only delta).
    The train works only on `enqueued_head` and the commits it pushes itself (`train_commits`)."""
    reviewed = evidence.get("head_sha") if isinstance(evidence, dict) else None
    reviewed = reviewed.lower() if isinstance(reviewed, str) else None
    if gate.get("decision") != "MERGE" or not _sha(gate.get("head_sha")) or not _sha(reviewed):
        raise ValueError("Only a MERGE gate decision with a HEAD SHA and review evidence naming a reviewed "
                         "HEAD can be enqueued")
    # `entry_id` names this enqueue: a write the train makes for an entry that was replaced since (the
    # same PR enqueued again) is refused, so the new entry and its evidence are never overwritten.
    record = {"schema": SCHEMA, "repo": repo.raw, "pr": number, "entry_id": uuid.uuid4().hex, "queued_at": _now(),
              "reviewed_head": reviewed, "enqueued_head": gate["head_sha"], "train_commits": [], "errors": 0,
              "reviewed_base": gate.get("base_sha"), "live_base": gate.get("live_base_sha"),
              "alignment": gate.get("alignment"), "evidence": evidence}
    save_entry(repo, number, record)
    client.edit_label(repo, number, QUEUE_LABEL, add=True)
    at_enqueue = "" if reviewed == gate["head_sha"] else f"HEAD when enqueued: `{gate['head_sha']}`  \n"
    client.post_comment(repo, number, (
        "## Merge train: enqueued\n\n"
        f"Reviewed HEAD: `{reviewed}`  \n{at_enqueue}Live base: `{gate.get('live_base_sha')}`\n\n"
        + ("The train will merge the live base into this branch first (clean merge, no file changed on "
           "both sides), wait for CI on that HEAD and merge.\n\n" if gate.get("needs_alignment") else
           "The train will wait for CI on this HEAD and merge.\n\n")
        + "Removing the `merge-queue` label takes the PR out of the queue.\n"))
    return {"outcome": "ENQUEUED", "pr": number, "reviewed_head": reviewed, "enqueued_head": gate["head_sha"]}


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


# What a refused write says about the change (for the log and for the comment that withdraws a Draft).
CHANGED = {
    "entry-replaced": "this PR was enqueued again, so the saved entry is not the one the decision used",
    "closed": "the PR is no longer open",
    "reopened": "the PR was reopened",
    "drafted": "the PR was made a Draft",
    "ready": "the PR was marked ready for review",
    "withdrawn": "the `merge-queue` label was removed",
    "relabelled": "the `merge-queue` label was added again",
    "head-changed": "the PR HEAD changed",
    "base-moved": "the base branch moved or the PR was retargeted",
}


@dataclass(frozen=True)
class Observation:
    """What a decision was derived from; `Train._guard` writes only while all of it still holds.

    `entry_id` is the saved entry the decision used (None: there was none). `state`, `draft` and
    `labelled` are what the PR must still be (None: not compared); the defaults are the state a PR must
    be in for the train to act on it. `head` is compared when given, and with it `bound`: whether the
    reloaded entry binds that HEAD (a HEAD that leaves the queue is observed with `bound=False`).
    `base_name` and `live_base` (the tip of that branch) are compared when given."""
    entry_id: str | None
    head: str | None = None
    base_name: str | None = None
    live_base: str | None = None
    bound: bool = True
    state: str | None = "OPEN"
    draft: bool | None = False
    labelled: bool | None = True


class Held:
    """What `Train._guard` found under the mutation lock: the object is true when the saved entry, the PR
    and the base tip are still what the decision was derived from, else `reason` is a key of `CHANGED`.
    `entry` and `view` are the reads the verdict rests on (after a `recheck()`, the latest)."""

    def __init__(self, train: "Train", number: int, observed: Observation) -> None:
        self.train, self.number, self.observed = train, number, observed
        self.reason = ""
        self.entry: dict[str, Any] | None = None
        self.view: dict[str, Any] = {}

    def __bool__(self) -> bool:
        return not self.reason

    def recheck(self) -> bool:
        """Read the entry, the PR and the base tip again; True when nothing the decision rests on changed.
        The order is the order of the reasons: the entry, the PR's state, then what the train acts on."""
        train, want = self.train, self.observed
        self.entry = load_entry(train.repo, self.number)
        self.view = view = train.client.pr_view(train.repo, self.number)
        self.reason = ""
        if (self.entry["entry_id"] if self.entry is not None else None) != want.entry_id:
            self.reason = "entry-replaced"
        elif want.state is not None and view.get("state") != want.state:
            self.reason = "closed" if want.state == "OPEN" else "reopened"
        elif want.draft is not None and (view.get("isDraft") is not False) != want.draft:
            self.reason = "drafted" if not want.draft else "ready"
        elif want.labelled is not None and train._labelled(view) != want.labelled:
            self.reason = "withdrawn" if want.labelled else "relabelled"
        elif want.head is not None and (view.get("headRefOid") != want.head or (
                self.entry is not None and train._bound(self.entry, want.head) != want.bound)):
            self.reason = "head-changed"
        elif want.base_name is not None and view.get("baseRefName") != want.base_name:
            self.reason = "base-moved"
        elif want.live_base is not None and \
                train.client.branch_head(train.repo, want.base_name or view["baseRefName"]) != want.live_base:
            self.reason = "base-moved"
        return not self.reason


@dataclass
class _Attempt:
    """What one `process_one` call acted on: the entry its errors would be counted against."""
    entry_id: str | None = None


@dataclass
class _Turns:
    """How many times one `_process` call has waited for each thing that may resolve itself."""
    unknown: int = 0
    integrations: int = 0
    fetches: int = 0


@dataclass
class Train:
    repo: Repo
    worktree: Path
    client: Any = gh_runtime
    secret_files: Sequence[Path] = ()
    max_align: int = 3
    max_errors: int = MAX_ERRORS
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

    def fetch(self, number: int, base: str) -> tuple[str, str]:
        """Bring the PR head and the base branch into private refs; (fetched PR head, fetched base tip).
        Every processing attempt does this first: the consumer's long-lived clone holds neither the PR's
        commits (the secret scan needs them) nor the live base (the merge needs it)."""
        self.git("fetch", "--no-tags", "--quiet", "origin",
                 f"+refs/pull/{number}/head:refs/merge-train/pr/{number}",
                 f"+refs/heads/{base}:refs/merge-train/base/{base}")
        return (self.git("rev-parse", f"refs/merge-train/pr/{number}").stdout.strip(),
                self.git("rev-parse", f"refs/merge-train/base/{base}").stdout.strip())

    def _locked(self):
        if self.mutation_lock is not None:
            return self.mutation_lock(self.repo)
        from apply_decision import repo_mutation_lock
        return repo_mutation_lock(self.repo)

    @contextmanager
    def _guard(self, number: int, observed: Observation, action: str):
        """The one way the train writes anything (a comment, the label, Draft, the merge, the push, the
        saved entry): take the repository mutation lock, then read the saved entry, the PR and the base
        tip again. The caller writes only while the yielded `Held` is true, that is, while all of
        `observed` still holds; otherwise it writes nothing and returns RETRY, and the run looks at the PR
        again from the top. A lock that cannot be taken raises `LockBusy` (the PR stays enqueued, nothing
        is counted against it).

        GitHub has no compare-and-swap for a comment, a label or Draft: a change after this read and before
        the write cannot be seen. The merge (`--match-head-commit`) and the push (never forced) are the two
        writes the remote itself refuses when the HEAD moved. The lock is not reentrant: a caller that
        holds the guard calls `held.recheck()`, never another guarded method."""
        held = Held(self, number, observed)
        with ExitStack() as stack:
            try:
                stack.enter_context(self._locked())
            except GitHubError as exc:
                raise LockBusy(str(exc)) from exc
            if not held.recheck():
                self.log.append(f"#{number}: {action} refused, {CHANGED[held.reason]}; nothing was written")
            yield held

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
        the timer's consumer takes it in turn. The run stops at a WAITING or ERROR (transient: the
        PRs behind keep their place); a PR that leaves the queue (MERGED, DRAFTED, DEQUEUED, SKIP)
        does not stop it."""
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
        attempt = _Attempt()
        try:
            result = self._process(number, attempt)
        except LockBusy as exc:
            # Another actor holds the lock: the train wrote nothing, so there is nothing to count.
            self.log.append(f"#{number}: the repository mutation lock is not available: {exc}")
            return self.waiting(number, f"the repository mutation lock is not available ({exc}); nothing was "
                                "written and it stays enqueued")
        except (GitHubError, TrainError, ValueError, KeyError) as exc:
            result = {"pr": number, "outcome": "ERROR", "reason": str(exc)}
        return self._track_errors(number, result, attempt)

    def _track_errors(self, number: int, result: dict[str, Any], attempt: _Attempt) -> dict[str, Any]:
        """Count consecutive ERROR runs in the entry; the `max_errors`-th takes the PR out of the queue,
        so an error nobody fixes cannot stop the PRs behind it for ever. The count belongs to the entry
        the run acted on: an entry enqueued since is not touched."""
        saved = load_entry(self.repo, number)
        if saved is None or saved["entry_id"] != attempt.entry_id:
            return result
        failed = result["outcome"] == "ERROR"
        if not failed and not saved["errors"]:
            return result
        errors = saved["errors"] + 1 if failed else 0
        reason = str(result.get("reason", ""))
        try:
            with self._guard(number, Observation(attempt.entry_id, state=None, draft=None, labelled=None),
                             "error count") as held:
                if held:
                    held.entry["errors"] = errors
                    if failed:
                        held.entry["last_error"] = reason[:500]
                    save_entry(self.repo, number, held.entry)
        except LockBusy:
            return result  # not counted: the lock was busy, not the PR's fault
        if not held or not failed or errors < self.max_errors:
            return result
        try:
            left = self.dequeue(number, f"The merge train failed on this PR in {errors} runs in a row, "
                                f"so it left the queue and the PRs behind it can merge. Last error: "
                                f"{reason[:500]}. Fix the cause and run `pr-review-merge` again.",
                                Observation(attempt.entry_id))
        except (GitHubError, ValueError, KeyError, LockBusy):
            return result  # the comment or label write failed too: it stays enqueued and counted
        return result if left is RETRY else left

    def _labelled(self, view: dict[str, Any]) -> bool:
        labels = view.get("labels")
        if not isinstance(labels, list):
            raise GitHubError("gh pr view did not report the PR's labels")
        return any(isinstance(label, dict) and label.get("name") == QUEUE_LABEL for label in labels)

    def label_gone(self, number: int, entry: dict[str, Any] | None) -> dict[str, Any] | _Signal:
        """Removing the label withdraws the PR: drop the saved entry and touch nothing on GitHub. The
        entry dropped is the one that was read: an entry enqueued since survives."""
        observed = Observation(entry["entry_id"] if entry is not None else None, draft=None, labelled=False)
        with self._guard(number, observed, "withdrawal") as held:
            if held:
                drop_entry(self.repo, number)
        if not held:
            return RETRY
        return {"pr": number, "outcome": "DEQUEUED", "reason": f"the `{QUEUE_LABEL}` label was removed"}

    def _closed(self, number: int, entry: dict[str, Any] | None, state: Any) -> dict[str, Any] | _Signal:
        """A closed or merged PR: drop the saved entry (the one that was read) and write nothing."""
        observed = Observation(entry["entry_id"] if entry is not None else None, state=state, draft=None,
                               labelled=None)
        with self._guard(number, observed, "closed PR") as held:
            if held:
                drop_entry(self.repo, number)
        if not held:
            return RETRY
        return {"pr": number, "outcome": "SKIP", "reason": f"PR is {state}"}

    def _left(self, number: int, entry: dict[str, Any] | None,
              view: dict[str, Any]) -> dict[str, Any] | _Signal | None:
        """The result when the PR is no longer one the train may act on (closed, Draft, label removed),
        RETRY when it changed while that was being written, None when it still is."""
        if view.get("state") != "OPEN":
            return self._closed(number, entry, view.get("state"))
        if view.get("isDraft") is not False:
            return self.dequeue(number, "The PR is a Draft; it left the merge train.",
                                Observation(entry["entry_id"] if entry is not None else None, draft=True),
                                comment=False)
        if not self._labelled(view):
            return self.label_gone(number, entry)
        return None

    @staticmethod
    def _bound(entry: dict[str, Any], head: str) -> bool:
        """HEAD is one the gate decided on or one this train built; anything else was never reviewed
        for a merge, whatever the review evidence says."""
        return head == entry["enqueued_head"] or head in entry["train_commits"]

    def _unbound(self, number: int, entry: dict[str, Any], head: str) -> dict[str, Any] | _Signal:
        return self.dequeue(number, f"The PR HEAD `{head[:12]}` is neither the HEAD this PR was enqueued at "
                            f"(`{entry['enqueued_head'][:12]}`) nor a commit the merge train pushed: the HEAD "
                            "changed since it was enqueued; run `pr-review-merge` again.",
                            Observation(entry["entry_id"], head=head, bound=False))

    def _process(self, number: int, attempt: _Attempt) -> dict[str, Any]:
        """Look at the PR until it has an outcome. Every turn starts from what GitHub and the saved entry
        say now; a write that was refused because they changed (RETRY) starts the next turn, at most
        `max_align` times, then WAITING."""
        turns, refused = _Turns(), 0
        while True:
            out = self._turn(number, attempt, turns)
            if out is NEXT:
                continue
            if out is RETRY:
                refused += 1
                if refused > self.max_align:
                    return self.waiting(number, "the PR or its queue entry kept changing while the train was "
                                        "acting on it; it stays enqueued")
                continue
            return out

    def _turn(self, number: int, attempt: _Attempt, turns: _Turns) -> dict[str, Any] | _Signal:
        entry = load_entry(self.repo, number)
        attempt.entry_id = entry["entry_id"] if entry is not None else None
        view = self.client.pr_view(self.repo, number)
        if (left := self._left(number, entry, view)) is not None:
            return left
        if entry is None:
            return self.dequeue(number, "The merge train has no saved review evidence for this PR on this "
                                "host. Run `pr-review-merge` again to queue it.", Observation(None))
        entry_id = entry["entry_id"]
        if view.get("isCrossRepository") is not False or not isinstance(view.get("headRefName"), str):
            return self.dequeue(number, "The merge train pushes only to branches of this repository; "
                                "integrate the base by hand and run `pr-review-merge` again.",
                                Observation(entry_id))
        head = view["headRefOid"]
        if not self._bound(entry, head):
            return self._unbound(number, entry, head)
        fetched_head, fetched_base = self.fetch(number, view["baseRefName"])
        if fetched_head != head:
            turns.fetches += 1
            if turns.fetches > self.max_align:
                return self.waiting(number, f"GitHub has not updated refs/pull/{number}/head to {head[:12]} yet")
            self.log.append(f"#{number}: refs/pull/{number}/head is {fetched_head[:12]}, PR HEAD is {head[:12]}; retrying")
            self.sleep(self.poll)
            return NEXT
        align = review_gate.train_alignment(self.client, self.repo, number, view)
        kind = align["alignment"]
        if kind in ("conflict", "overlap"):
            reason = ("GitHub reports a merge conflict with the live base" if kind == "conflict" else
                      "both sides changed " + ", ".join(align["overlap"][:5]) + " since the merge base")
            return self.to_draft(number, entry, view, align, [
                f"PR HEAD {view['headRefOid']} does not include live {view['baseRefName']} SHA "
                f"{align['live_base_sha']}, and {reason}. The merge train cannot integrate it: use "
                "pr-ready to integrate the verified latest base, then rerun validation/CI and "
                "independent review before Ready."])
        if kind == "unknown":
            if align.get("unknown_reason") == "needs-person":
                return self.dequeue(number, "The merge train cannot tell what the live base changed: "
                                    f"{align.get('alignment_detail', 'alignment unknown')}. A person must "
                                    "integrate the base (`pr-ready`) and run `pr-review-merge` again.",
                                    Observation(entry_id, head=head, base_name=view["baseRefName"],
                                                live_base=align["live_base_sha"]))
            turns.unknown += 1
            if turns.unknown > self.max_align:
                return self.waiting(number, align.get("alignment_detail", "alignment unknown"))
            self.sleep(self.poll)
            return NEXT
        if kind == "train":
            turns.integrations += 1
            if turns.integrations > self.max_align:
                return self.waiting(number, f"the base moved {self.max_align} times while this PR "
                                    "was in the train; it stays enqueued")
            if fetched_base != align["live_base_sha"]:
                self.log.append(f"#{number}: the base moved during the fetch; retrying")
                return NEXT
            outcome = self.integrate(number, view, align, entry)
            return NEXT if outcome is None else outcome
        # aligned: HEAD contains the live tip.
        state = self.wait_ci(number, view["headRefOid"], view["baseRefName"], align["live_base_sha"])
        if state in ("base-moved", "left"):
            return NEXT
        if state == "head-moved":
            current = self.client.pr_view(self.repo, number)["headRefOid"]
            if self._bound(entry, current):
                return NEXT  # back on a HEAD the train may act on: look again
            return self.dequeue(number, "The PR HEAD changed outside the merge train while it was "
                                "enqueued; run `pr-review-merge` again on the new HEAD.",
                                Observation(entry_id, head=current, bound=False))
        if state == "timeout":
            return self.waiting(number, "CI did not settle in time")
        return self.finish(number, entry, view, align)

    def integrate(self, number: int, view: dict[str, Any], align: dict[str, Any],
                  entry: dict[str, Any]) -> dict[str, Any] | _Signal | None:
        """Push the merge of the live base to the PR branch. None: pushed (or the branch moved first),
        look at the PR again; RETRY: the PR or its entry changed under the lock, nothing was written."""
        head, live = view["headRefOid"], align["live_base_sha"]
        base, branch = view["baseRefName"], view["headRefName"]
        merged = self.git("merge-tree", "--write-tree", head, live, ok=(0, 1))
        if merged.returncode == 1:
            return self.to_draft(number, entry, view, align, [
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
                return self.to_draft(number, entry, view, align, [
                    f"The merge of live {base} SHA {live} into {head} changes {path} differently from "
                    f"{base}; the merge train only integrates pure base imports. Use pr-ready."])
        with self._guard(number, Observation(entry["entry_id"], head=head, base_name=base, live_base=live),
                         "push") as held:
            if held:
                # Record the commit before it exists on the PR branch, so a crash after the push still
                # finds a HEAD the train built; a commit that never lands is harmless in the list. It goes
                # on the entry as the lock found it, never on a copy read before.
                recorded = held.entry
                recorded["train_commits"] = [*recorded["train_commits"], commit]
                save_entry(self.repo, number, recorded)
                try:
                    # Never forced: a PR branch that moved since the re-read above rejects this push.
                    self.git("push", "--quiet", "origin", f"{commit}:refs/heads/{branch}")
                except TrainError:
                    recorded["train_commits"] = [c for c in recorded["train_commits"] if c != commit]
                    save_entry(self.repo, number, recorded)
                    if self.client.pr_view(self.repo, number).get("headRefOid") != head:
                        self.log.append(f"#{number}: the PR branch moved during the push; nothing was overwritten")
                        return None
                    raise
        if not held:
            return RETRY
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
            if view.get("state") != "OPEN" or view.get("isDraft") is not False or not self._labelled(view):
                return "left"
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
               align: dict[str, Any]) -> dict[str, Any] | _Signal:
        head, base, live = view["headRefOid"], view["baseRefName"], align["live_base_sha"]
        entry_id = entry["entry_id"]
        # Read the HEAD afresh: a push since the loop read it must not be merged on the strength of the
        # entry (the gate and the merge re-read it too; this refuses it before any of those runs).
        current = self.client.pr_view(self.repo, number)["headRefOid"]
        if not self._bound(entry, current):
            return self._unbound(number, entry, current)
        evidence = entry["evidence"]
        infra: list[str] = []
        try:
            reuse, why = review_gate.review_covers(self.client, self.repo, entry["reviewed_head"], head, live, base)
            gaps = [] if reuse is None else review_gate.check_target_validation(
                self.client, self.repo, head, live, evidence, base_name=base, integrated_base=True, infra=infra)[0]
        except (GitHubError, ValueError, KeyError) as exc:
            # GitHub failing says nothing about the review or the record: never dequeue or Draft for it.
            return self.waiting(number, f"cannot check that the saved review and target record cover HEAD "
                                f"right now: {exc}")
        if reuse is None:
            return self.dequeue(number, f"The saved review (HEAD {entry['reviewed_head'][:12]}) no longer "
                                f"covers HEAD {head[:12]}: {why}. Run `pr-review-merge` again.",
                                Observation(entry_id, head=head, base_name=base, live_base=live))
        if infra:
            return self.waiting(number, "cannot check the target record right now: " + "; ".join(infra)[:1500])
        if gaps:
            return self.to_draft(number, entry, view, align, [
                "After the merge train integrated the live base, the target record no longer covers "
                "HEAD: " + "; ".join(gaps)[:1500] + ". Use pr-ready to run the target chain again (or to "
                "record the reviewer's `unrelated_runtime_changes`)."])
        gate = review_gate.evaluate(self.repo, number, evidence, client=self.client,
                                    worktree=self.worktree, secret_files=self.secret_files)
        decision = gate["decision"]
        if decision == "MERGE":
            if gate.get("needs_alignment"):
                return self.waiting(number, "the live base moved while the final gate ran; it stays enqueued")
            return self.merge(number, entry, gate)
        if decision == "DRAFT":
            return self.to_draft(number, entry, view, align, gate["reasons"], gate=gate)
        if decision == "SKIP":
            # The gate saw a closed or Draft PR: the next turn finds out which and settles it.
            return RETRY
        reasons = [str(reason) for reason in gate["reasons"]]
        if gate.get("wait_kind") == "transient":
            return self.waiting(number, "; ".join(reasons)[:1500])
        # Nothing the train does changes this: a person must act, and the PRs behind it must not wait.
        listing = "\n".join(f"- {reason[:600]}" for reason in reasons[:20])
        result = self.dequeue(number, "The merge train cannot merge this PR until a person acts, so it left the "
                              "queue and the PRs behind it can merge. The PR stays Ready.\n\n" + listing +
                              "\n\nAfter that is resolved, run `pr-review-merge` again to enqueue it.",
                              Observation(entry_id, head=gate.get("head_sha") or head,
                                          base_name=gate.get("base_name") or base,
                                          live_base=gate.get("live_base_sha") or live))
        if result is not RETRY:
            result["reasons"] = reasons
        return result

    # -- actions ----------------------------------------------------------------------------
    def merge(self, number: int, entry: dict[str, Any], gate: dict[str, Any]) -> dict[str, Any] | _Signal:
        """Merge exactly the HEAD the gate approved, only while it is still bound by the saved entry."""
        observed = Observation(entry["entry_id"], head=gate["head_sha"], base_name=gate["base_name"],
                               live_base=gate["live_base_sha"])
        merged = False
        with self._guard(number, observed, "merge") as held:
            if held:
                self.client.merge_pr(self.repo, number, gate["head_sha"])
                merged = self.client.pr_view(self.repo, number).get("state") == "MERGED"
                if merged:
                    drop_entry(self.repo, number)  # only once MERGED is verified: an unconfirmed merge stays enqueued
        if not held:
            if held.reason == "entry-replaced":
                return RETRY
            if held.reason == "withdrawn":
                return self.label_gone(number, entry)
            if held.reason == "closed":
                return self._closed(number, entry, held.view.get("state"))
            return self.waiting(number, "PR state/HEAD/base changed immediately before the merge "
                                f"({CHANGED[held.reason]})")
        if not merged:
            return {"pr": number, "outcome": "ERROR",
                    "reason": "Merge command finished but the PR is not confirmed MERGED"}
        return {"pr": number, "outcome": "MERGED", "head_sha": gate["head_sha"]}

    def to_draft(self, number: int, entry: dict[str, Any], view: dict[str, Any], align: dict[str, Any],
                 reasons: list[str], *, gate: dict[str, Any] | None = None) -> dict[str, Any] | _Signal:
        """Comment the reasons and convert the PR to Draft, only while it is still the PR (HEAD, base,
        label, Draft state, saved entry) those reasons were derived from. The comment is a write that
        cannot be taken back, so the PR is read again after it: if it changed meanwhile the train does
        not convert it, leaves the label alone and says that its comment is superseded."""
        from apply_decision import comment_text
        seen = gate or {}
        head = seen.get("head_sha") or view["headRefOid"]
        result = gate or {"reasons": reasons, "head_sha": head, "base_sha": view.get("baseRefOid"),
                          "base_behind": align.get("base_behind"), "base_mismatch": align.get("base_mismatch"),
                          "live_base_sha": align.get("live_base_sha")}
        observed = Observation(entry["entry_id"], head=head, base_name=seen.get("base_name") or view["baseRefName"],
                               live_base=seen.get("live_base_sha") or align["live_base_sha"])
        drafted = False
        with self._guard(number, observed, "Draft") as held:
            if held:
                self.client.post_comment(self.repo, number, comment_text(result))
                if held.recheck():
                    self.client.mark_draft(self.repo, number)
                    after = self.client.pr_view(self.repo, number)
                    drafted = after.get("isDraft") is True
                    if after.get("headRefOid") != head:
                        self.log.append(f"#{number}: the PR HEAD moved to {str(after.get('headRefOid'))[:12]} while "
                                        "it was converted to Draft (GitHub cannot refuse that); the Draft stands")
                    if drafted:
                        # Only a confirmed Draft takes the PR out of the queue, and only then the label goes.
                        self.client.edit_label(self.repo, number, QUEUE_LABEL, add=False)
                        drop_entry(self.repo, number)
                else:
                    self.log.append(f"#{number}: the Draft comment for HEAD {head[:12]} was posted, then "
                                    f"{CHANGED[held.reason]}: voided; the PR was not converted")
                    self.client.post_comment(self.repo, number, (
                        "## Merge train: Draft comment superseded\n\n"
                        f"The merge train commented above that this PR must return to Draft, judging HEAD `{head}`. "
                        f"Before it acted, {CHANGED[held.reason]}, so that comment no longer applies. The train did "
                        "not convert the PR to Draft; what happens next is decided from the PR as it is now.\n"))
        if not held:
            return RETRY
        if not drafted:
            return {"pr": number, "outcome": "ERROR", "reason": "Draft conversion was not confirmed"}
        return {"pr": number, "outcome": "DRAFTED", "reasons": reasons}

    def dequeue(self, number: int, reason: str, observed: Observation, *,
                comment: bool = True) -> dict[str, Any] | _Signal:
        """Take the PR out of the queue with a comment (none for a Draft or a withdrawal), only while it
        is still the PR `observed` describes; the label goes before the entry."""
        with self._guard(number, observed, "dequeue") as held:
            if held:
                if comment:
                    self.client.post_comment(self.repo, number, "## Merge train: left the queue\n\n" + reason + "\n")
                self.client.edit_label(self.repo, number, QUEUE_LABEL, add=False)
                drop_entry(self.repo, number)
        if not held:
            return RETRY
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
