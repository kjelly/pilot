"""scripts/pr_loop.py: the runner's gates, state machine, tmux driver and checkout, and the whole program.

Nothing here touches the developer's tmux server, GitHub or an agent: the tests that need `tmux`, `gh` or an agent
executable put the fakes of pr_loop_fakes.py first on PATH (FakeEnv refuses to go on unless `which` finds them),
and every wait runs on a fake clock. The pane screens and PR views are synthetic. git is real: the checkout the
runner is started in is a real clone of a real bare repository (FakeEnv.make_checkout), and every refusal of it is
tried on real git state, with the case that must pass beside the case that must stop.
"""
import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import posixpath
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
import warnings
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "scripts"))
import pr_loop
import ready_signal as rs
import ready_signal_world as rw
from pr_loop_result import load_task, write_result
from pr_loop_fakes import (HELPER_PATHS, LIST_FORMAT, LOGIN, NO_SERVER, NO_SOCKET, SOCKET, UPDATE_ENVIRONMENT, FakeEnv, FakeTime,
                           pr_view_json, ready_view, signal_world)
from test_skill_links import link_targets

HEAD = "a" * 40
NEW = "b" * 40
# What a refusal because of a live pane says it can be listed with (kjelly/pilot#442): the one place the tests spell it.
CLEAN_POINTER = "(python3 scripts/pr_loop.py --clean lists what an earlier run left)"


class PRLoopTests(unittest.TestCase):
    def test_reuses_a_role_within_a_pr_but_restarts_it_for_the_next(self):
        view_states = {7: "ready", 8: "ready"}
        dispatched, started, closed = [], [], []
        head = "a" * 40

        def view(_repo, number, _account=None):
            state = view_states[number]
            if state == "queued":
                view_states[number] = "merged"
            return dict(number=number, state="MERGED" if state == "merged" else "OPEN",
                        url=f"https://github.com/kjelly/pilot/pull/{number}",
                        isDraft=state == "draft", headRefOid=head,
                        labels=[{"name": pr_loop.QUEUE_LABEL}] if state == "queued" else []), state, ""

        class Checkout:
            def __init__(self, *_):
                pass

            def verify(self):
                pass

            def task(self, _repo, _number, _phase, _head):
                return Path(tmp) / "task.json", {}

            def announce(self):
                pass

            def finish(self):
                pass

        class Agent:
            def __init__(self, exe, _checkout, number, phase):
                self.pane = f"%{len(started) + 1}"  # the handoff wait names the pane
                self.identity = (number, phase, exe, len(started))
                started.append(self.identity)

            def status(self):
                return False, False, "agent"

            def wait_for_prompt(self, *_args, **_kwargs):
                return True

            def submit(self, text):
                number, phase, _, _ = self.identity
                prefix = "/pr-ready" if phase == "draft" else "$pr-review-merge"
                if not text.startswith(f"{prefix} {number} --pr-loop-task="):
                    raise AssertionError(text)
                dispatched.append(self.identity)
                if phase == "draft":
                    view_states[number] = "ready"
                elif number == 7 and dispatched.count(self.identity) == 1:
                    view_states[number] = "draft"
                else:
                    view_states[number] = "queued"

            def close(self):
                closed.append(self.identity)

        args = SimpleNamespace(pr=[7, 8], dry_run=False, checkout=None, phase_timeout=10, startup_timeout=1,
                               max_actions=5, poll_interval=0.01, ready_agent="codex", draft_agent="claude",
                               ready_command="$pr-review-merge {pr}", draft_command="/pr-ready {pr}")
        with tempfile.TemporaryDirectory() as tmp, patch.object(pr_loop, "observe", side_effect=view), \
             patch.object(pr_loop, "Agent", Agent), patch.object(pr_loop, "Checkout", Checkout), \
             patch.object(pr_loop, "tell"), patch.object(pr_loop.time, "sleep"):
            pr_loop.Batch(pr_loop.Repo.parse("kjelly/pilot"), args).run()
        self.assertEqual([(7, "ready", "codex", 0), (7, "draft", "claude", 1), (8, "ready", "codex", 2)], started)
        self.assertEqual([started[0], started[1], started[0], started[2]], dispatched)
        self.assertEqual(started, closed)

    def test_receipt_only_blocks_the_current_dispatch_and_head(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "task.json"
            head = "a" * 40
            task = dict(version=1, repo="kjelly/pilot", pr=7, phase="draft", nonce="b" * 32, start_head=head)
            write_result(path, task, outcome="DRAFT-BLOCKED", head=head, reason="fix failed")
            pr_loop.check_result(path, task, "c" * 40)
            with self.assertRaisesRegex(pr_loop.Stop, "DRAFT-BLOCKED.*fix failed"):
                pr_loop.check_result(path, task, head)
            with self.assertRaisesRegex(pr_loop.Stop, "does not belong"):
                pr_loop.check_result(path, dict(task, nonce="d" * 32), head)

    def test_success_receipt_does_not_drive_github_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "task.json"
            head = "a" * 40
            task = dict(version=1, repo="kjelly/pilot", pr=7, phase="ready", nonce="b" * 32, start_head=head)
            write_result(path, task, outcome="ENQUEUED", head=head, reason="enqueued")
            self.assertIsNone(pr_loop.check_result(path, task, head))

    def test_moved_head_is_not_held_by_old_person_marker(self):
        current, new = "a" * 40, "b" * 40
        # A signed Ready PR that waits for a person: its signal and the person marker both name `current`.
        world = signal_world(current)
        original = ready_view(world, labels=world.view_labels() + [{"name": "needs-person"}])
        marker = f"<!-- pr-review-merge:needs-person head={current} live-base={'c' * 40} reasons={'d' * 16} -->"
        repo = pr_loop.Repo.parse("kjelly/pilot")
        for latest in (original, dict(original, headRefOid=new)):
            with patch.object(pr_loop, "pr_view", side_effect=[original, latest]), \
                 patch.object(pr_loop, "viewer_login", return_value=LOGIN), \
                 patch.object(pr_loop, "timeline_events", return_value=world.s["events"]), \
                 patch.object(pr_loop, "issue_comments", return_value=[{"login": LOGIN, "body": marker}]):
                if latest["headRefOid"] == current:
                    with self.assertRaisesRegex(pr_loop.Stop, "needs a person"):
                        pr_loop.observe(repo, 7)
                else:
                    # The fresh read is returned, and judged by its own signal: the one on the PR names the old HEAD.
                    view, phase, detail = pr_loop.observe(repo, 7)
                    self.assertEqual((latest, "unverified"), (view, phase))
                    self.assertRegex(detail, r"^stale: the signal was written for HEAD a{12}, the PR HEAD is b{12}$")


# ---- (A) the pure gates: each one is paired with the case that must pass and the case that must stop ----------

class StateOfTests(unittest.TestCase):
    def test_every_phase_is_recognised(self):
        for phase in ("draft", "ready", "queued", "merged"):
            with self.subTest(phase=phase):
                self.assertEqual(phase, pr_loop.state_of(pr_view_json(phase)))
        # The queue label only matters for a PR that is not a Draft.
        self.assertEqual("draft", pr_loop.state_of(dict(pr_view_json("draft"), labels=[{"name": pr_loop.QUEUE_LABEL}])))
        # A merged PR is merged whatever else its view says.
        self.assertEqual("merged", pr_loop.state_of({"number": 7, "state": "MERGED"}))

    def test_a_pr_that_is_neither_open_nor_merged_stops(self):
        for state in ("CLOSED", "open", "", None):
            with self.subTest(state=state):
                with self.assertRaisesRegex(pr_loop.Stop, r"PR #7 is not open or merged"):
                    pr_loop.state_of(dict(pr_view_json("ready"), state=state))

    def test_a_view_without_a_boolean_draft_state_stops(self):
        view = pr_view_json("ready")
        for value in ("MISSING", None, "false", 0, 1):
            with self.subTest(isDraft=value):
                broken = dict(view)
                if value == "MISSING":
                    del broken["isDraft"]
                else:
                    broken["isDraft"] = value
                with self.assertRaisesRegex(pr_loop.Stop, r"PR #7 has no Draft state"):
                    pr_loop.state_of(broken)


class HasLabelTests(unittest.TestCase):
    def test_a_label_is_found_or_absent(self):
        view = {"number": 7, "labels": [{"name": "a"}, {"name": "b"}]}
        self.assertTrue(pr_loop.has_label(view, "b"))
        self.assertFalse(pr_loop.has_label(view, "c"))
        self.assertFalse(pr_loop.has_label({"number": 7, "labels": []}, "a"))

    def test_labels_that_are_not_a_list_of_objects_stop(self):
        for labels in (None, "a", {"name": "a"}, ["a"], [{"name": "a"}, "b"], [None]):
            with self.subTest(labels=labels):
                with self.assertRaisesRegex(pr_loop.Stop, r"PR #7 returned invalid labels"):
                    pr_loop.has_label({"number": 7, "labels": labels}, "a")
        with self.assertRaisesRegex(pr_loop.Stop, r"PR #7 returned invalid labels"):
            pr_loop.has_label({"number": 7}, "a")


class HeadOfTests(unittest.TestCase):
    def test_a_full_sha_is_returned_in_lower_case(self):
        self.assertEqual(HEAD, pr_loop.head_of({"number": 7, "headRefOid": HEAD}))
        self.assertEqual("abcdef0123" * 4, pr_loop.head_of({"number": 7, "headRefOid": ("ABCDEF0123" * 4)}))

    def test_anything_else_stops(self):
        for head in ("a" * 39, "a" * 41, "g" * 40, "", None, 123, HEAD + "\n", ["a" * 40]):
            with self.subTest(head=head):
                with self.assertRaisesRegex(pr_loop.Stop, r"PR #7 has no valid HEAD SHA"):
                    pr_loop.head_of({"number": 7, "headRefOid": head})
        with self.assertRaisesRegex(pr_loop.Stop, r"PR #7 has no valid HEAD SHA"):
            pr_loop.head_of({"number": 7})


class ObserveTests(unittest.TestCase):
    """`observe` is the one read of a PR: `(view, phase, detail)`. The hand-off to a person applies to a PR whose
    signal is valid. The existing test above covers a moved HEAD."""
    repo = pr_loop.Repo.parse("kjelly/pilot")
    marker = f"<!-- pr-review-merge:needs-person head={HEAD} live-base={'c' * 40} reasons={'d' * 16} -->"

    def setUp(self):
        self.world = signal_world(HEAD)  # a Ready PR signed by the fake gh account

    def labelled(self, **fields):
        """The signed Ready PR, waiting for a person too."""
        return ready_view(self.world, labels=self.world.view_labels() + [{"name": "needs-person"}], **fields)

    def observe(self, views, comments, number=7):
        with patch.object(pr_loop, "pr_view", side_effect=views) as view, \
             patch.object(pr_loop, "viewer_login", return_value=LOGIN), \
             patch.object(pr_loop, "timeline_events", return_value=self.world.s["events"]), \
             patch.object(pr_loop, "issue_comments", return_value=comments):
            try:
                return pr_loop.observe(self.repo, number), view.call_count
            except pr_loop.Stop as exc:
                return exc, view.call_count

    def test_a_marker_of_the_viewer_at_the_current_head_stops(self):
        view = self.labelled()
        result, reads = self.observe([view, view], [{"login": LOGIN, "body": self.marker}])
        self.assertIsInstance(result, pr_loop.Stop)
        self.assertRegex(str(result), rf"PR #7 needs a person at HEAD {HEAD[:12]}; see the PR conversation")
        self.assertEqual(2, reads, "the label is confirmed by a second read before the PR is given up")

    def test_a_marker_by_another_login_is_ignored(self):
        view = self.labelled()
        result, reads = self.observe([view], [{"login": "someone-else", "body": self.marker}])
        self.assertEqual(((view, "ready", ""), 1), (result, reads))

    def test_a_marker_for_another_head_is_ignored(self):
        view = self.labelled()
        old = self.marker.replace(HEAD, NEW)
        result, reads = self.observe([view], [{"login": LOGIN, "body": old}])
        self.assertEqual(((view, "ready", ""), 1), (result, reads))

    def test_no_marker_at_all_is_just_the_view(self):
        view = self.labelled()
        self.assertEqual(((view, "ready", ""), 1), self.observe([view], [{"login": LOGIN, "body": "no marker here"}]))
        self.assertEqual(((view, "ready", ""), 1), self.observe([view], []))

    def test_a_label_that_is_gone_on_the_fresh_read_returns_the_fresh_view(self):
        view = self.labelled()
        fresh = ready_view(self.world)
        result, reads = self.observe([view, fresh], [{"login": LOGIN, "body": self.marker}])
        self.assertEqual(((fresh, "ready", ""), 2), (result, reads))

    def test_a_pr_that_is_not_ready_is_not_held_and_reads_no_signal(self):
        for phase in ("draft", "queued", "merged"):
            with self.subTest(phase=phase):
                view = pr_view_json(phase, head=HEAD, labels=["needs-person"])
                with patch.object(pr_loop, "pr_view", return_value=view), \
                     patch.object(pr_loop, "viewer_login", side_effect=AssertionError("not asked")), \
                     patch.object(pr_loop, "timeline_events", side_effect=AssertionError("not asked")), \
                     patch.object(pr_loop, "issue_comments", side_effect=AssertionError("not asked")):
                    self.assertEqual((view, phase, ""), pr_loop.observe(self.repo, 7))

    def test_an_unverified_pr_is_not_held_for_a_person(self):
        # The check stays on `ready`: a PR without a valid signal is the runner's refusal, not a person's.
        view = pr_view_json("ready", head=HEAD, labels=["needs-person"])
        with patch.object(pr_loop, "pr_view", return_value=view), \
             patch.object(pr_loop, "viewer_login", return_value=LOGIN), \
             patch.object(pr_loop, "timeline_events", side_effect=AssertionError("not asked: no signal label")), \
             patch.object(pr_loop, "issue_comments", side_effect=AssertionError("not asked")):
            self.assertEqual((view, "unverified", f"the PR does not carry the {rs.LABEL} label"),
                             pr_loop.observe(self.repo, 7))

    def test_a_pr_that_cannot_be_driven_stops_in_the_same_read(self):
        result, reads = self.observe([dict(pr_view_json("ready"), state="CLOSED")], [])
        self.assertRegex(str(result), "is not open or merged")


class SignalPhaseTests(unittest.TestCase):
    """What `observe` makes of a Ready PR: `ready` only when `ready_signal.assess` says `valid` at this very HEAD,
    otherwise `unverified` with the reason. The worlds are built by ready_signal_world in the shapes of real captures."""
    repo = pr_loop.Repo.parse("kjelly/pilot")

    def observe(self, view, events):
        """(observation, times the account was asked, times the timeline was read)"""
        with patch.object(pr_loop, "pr_view", return_value=view), \
             patch.object(pr_loop, "viewer_login", return_value=LOGIN) as account, \
             patch.object(pr_loop, "timeline_events", return_value=events) as timeline, \
             patch.object(pr_loop, "issue_comments", return_value=[]):
            return pr_loop.observe(self.repo, 7), account.call_count, timeline.call_count

    def test_a_valid_signal_at_the_head_is_ready(self):
        world = signal_world(HEAD)
        view = ready_view(world)
        self.assertEqual(((view, "ready", ""), 1, 1), self.observe(view, world.s["events"]))

    def test_a_ready_pr_without_the_label_is_unverified_and_its_timeline_is_not_read(self):
        world = signal_world(HEAD, signed=False)
        view = ready_view(world)
        self.assertEqual(((view, "unverified", f"the PR does not carry the {rs.LABEL} label"), 0, 0),
                         self.observe(view, world.s["events"]))

    def test_every_other_state_of_the_signal_is_unverified_with_its_reason(self):
        def absent():  # the label is there, the marker comment is not
            world = signal_world(HEAD, signed=False)
            world.label()
            return world

        def stale_epoch():  # the label was left on the PR while it was a Draft
            world = signal_world(HEAD)
            world.to_draft()
            world.ready()
            return world

        def untrusted():  # the label was added by another account
            world = signal_world(HEAD, signed=False)
            world.comment(rs.marker_comment(HEAD, rs.PR_READY, world.latest_ready()))
            world.label(rw.OTHER)
            return world

        def converted_back():  # Draft again after the Ready transition
            world = signal_world(HEAD)
            world.to_draft()
            return world

        def never_a_draft():  # created Ready: no Draft -> Ready transition
            world = rw.World(head=HEAD, viewer=LOGIN)
            world.signal(ready=rw.REAL_LAST_READY)
            return world

        def earlier_ready():  # the comment and the label are for a Ready transition that is not the last one
            world = signal_world(HEAD, signed=False)
            first = world.latest_ready()
            world.to_draft()
            world.ready()
            world.signal(ready=first)
            return world

        for name, build, reason in (
                ("absent", absent, r"no signal comment by reviewer after the PR's last Ready transition"),
                ("stale-epoch", stale_epoch, r"label was added before the PR's last Ready transition"),
                ("untrusted", untrusted, r"label was added by someone-else, not by the authenticated account reviewer"),
                ("inconsistent", converted_back, r"converted to Draft after its last Ready transition"),
                ("absent", never_a_draft, r"no Ready transition from Draft"),
                ("stale-epoch", earlier_ready, r"signal comment certifies Ready transition \d+, but the PR's last Ready "
                                               r"transition is \d+")):
            with self.subTest(case=build.__name__):
                world = build()
                view = ready_view(world)
                (seen, phase, detail), _, timeline = self.observe(view, world.s["events"])
                self.assertEqual((view, "unverified", 1), (seen, phase, timeline))
                self.assertRegex(detail, rf"^{name}: .*{reason}")

    def test_a_signal_for_an_earlier_head_does_not_count_whatever_changed_since(self):
        # Strict, no carry: the merge-train integration commit moves the HEAD of a PR the runner never sees as Ready.
        world = signal_world(NEW)
        view = ready_view(world, headRefOid=HEAD)
        (seen, phase, detail), _, _ = self.observe(view, world.s["events"])
        self.assertEqual((view, "unverified"), (seen, phase))
        self.assertRegex(detail, rf"^stale: the signal was written for HEAD {NEW[:12]}, the PR HEAD is {HEAD[:12]}$")

    def test_a_timeline_that_cannot_be_read_is_unverified(self):
        world = signal_world(HEAD)
        view = ready_view(world)
        (seen, phase, detail), _, _ = self.observe(view, [{"event": 5}])
        self.assertEqual((view, "unverified"), (seen, phase))
        self.assertEqual("the signal cannot be read: timeline entry 0 is not an event object", detail)

    def test_a_failed_github_read_is_not_a_verdict(self):
        # The retry belongs to Batch.read: observe lets a GitHubError through.
        world = signal_world(HEAD)
        for failing in ("timeline_events", "viewer_login"):
            with self.subTest(failing=failing):
                with patch.object(pr_loop, "pr_view", return_value=ready_view(world)), \
                     patch.object(pr_loop, "viewer_login", return_value=LOGIN), \
                     patch.object(pr_loop, "timeline_events", return_value=world.s["events"]), \
                     patch.object(pr_loop, failing, side_effect=pr_loop.GitHubError("boom")):
                    with self.assertRaisesRegex(pr_loop.GitHubError, "boom"):
                        pr_loop.observe(self.repo, 7)


class BatchAccountTests(unittest.TestCase):
    """The account `gh` runs as is read once per Batch, and only when a Ready PR needs it."""
    repo = pr_loop.Repo.parse("kjelly/pilot")

    def test_the_account_is_read_once_per_batch(self):
        world = signal_world(HEAD)
        view = ready_view(world)
        args = SimpleNamespace(poll_interval=0.01)
        with patch.object(pr_loop, "pr_view", return_value=view), \
             patch.object(pr_loop, "viewer_login", return_value=LOGIN) as account, \
             patch.object(pr_loop, "timeline_events", return_value=world.s["events"]) as timeline:
            batch = pr_loop.Batch(self.repo, args)
            self.assertEqual(["ready"] * 3, [batch.read(7)[1] for _ in range(3)])
            self.assertEqual((1, 3), (account.call_count, timeline.call_count), "the timeline is read every time")
            pr_loop.Batch(self.repo, args).read(7)
            self.assertEqual(2, account.call_count, "another Batch asks again")

    def test_an_account_that_could_not_be_read_is_asked_again(self):
        world = signal_world(HEAD)
        args = SimpleNamespace(poll_interval=0.01)
        with patch.object(pr_loop, "pr_view", return_value=ready_view(world)), \
             patch.object(pr_loop, "viewer_login", side_effect=[pr_loop.GitHubError("boom"), LOGIN]) as account, \
             patch.object(pr_loop, "timeline_events", return_value=world.s["events"]), \
             patch.object(pr_loop, "tell"), patch.object(pr_loop.time, "sleep"):
            self.assertEqual("ready", pr_loop.Batch(self.repo, args).read(7)[1])
        self.assertEqual(2, account.call_count)


class CheckResultTests(unittest.TestCase):
    """The skill's result file: what blocks the dispatch, what is ignored, what is invalid."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "task.json"

    def task(self, phase="draft"):
        return dict(version=1, repo="kjelly/pilot", pr=7, phase=phase, nonce="b" * 32, start_head=HEAD)

    def write(self, task, **fields):
        body = dict(task, head_sha=HEAD, outcome="DRAFT-BLOCKED", reason="fix failed", wait_kind="",
                    person_handoff=False)
        body.update(fields)
        self.path.with_name("result.json").write_text(json.dumps(body), encoding="utf-8")

    def test_no_result_yet_is_nothing(self):
        self.assertIsNone(pr_loop.check_result(self.path, self.task(), HEAD))

    def test_a_result_over_4096_bytes_stops(self):
        task = self.task()
        self.write(task, reason="x" * 5000)
        with self.assertRaisesRegex(pr_loop.Stop, "skill result exceeded the size limit"):
            pr_loop.check_result(self.path, task, HEAD)
        # Control: a result of exactly 4096 bytes is read, and then judged like any other.
        self.write(task)
        body = self.path.with_name("result.json").read_text()
        self.path.with_name("result.json").write_text(body + " " * (4096 - len(body)))
        self.assertEqual(4096, self.path.with_name("result.json").stat().st_size)
        with self.assertRaisesRegex(pr_loop.Stop, "DRAFT-BLOCKED at"):
            pr_loop.check_result(self.path, task, HEAD)

    def test_a_result_of_another_dispatch_stops(self):
        task = self.task()
        for key, value in dict(version=2, repo="other/repo", pr=8, phase="ready", nonce="d" * 32,
                               start_head=NEW).items():
            with self.subTest(key=key):
                self.write(task, **{key: value})
                with self.assertRaisesRegex(pr_loop.Stop, "skill result does not belong to this dispatch"):
                    pr_loop.check_result(self.path, task, HEAD)
        self.path.with_name("result.json").write_text("[]")
        with self.assertRaisesRegex(pr_loop.Stop, "does not belong"):
            pr_loop.check_result(self.path, task, HEAD)

    def test_an_invalid_result_stops(self):
        task = self.task()
        bad = {"head_sha": ["a" * 39, "g" * 40, "", 5, None],
               "outcome": ["", "ENQUEUED", "ready", "draft-blocked", 5, None],  # ENQUEUED is the other phase's word
               "reason": [5, None, "two\nlines", "tab\there", ["r"]]}
        for key, values in bad.items():
            for value in values:
                with self.subTest(key=key, value=value):
                    self.write(task, **{key: value})
                    with self.assertRaisesRegex(pr_loop.Stop, "invalid skill result"):
                        pr_loop.check_result(self.path, task, HEAD)
        # Controls: an empty reason is a valid one, and a result of an old head is only ignored once valid.
        self.write(task, reason="")
        with self.assertRaisesRegex(pr_loop.Stop, r"DRAFT-BLOCKED at \w+: $"):
            pr_loop.check_result(self.path, task, HEAD)

    def test_a_result_that_is_not_json_raises_for_the_caller_to_report(self):
        self.path.with_name("result.json").write_text("{not json")
        with self.assertRaises(ValueError):
            pr_loop.check_result(self.path, self.task(), HEAD)

    def test_a_result_for_an_old_head_is_ignored(self):
        task = self.task()
        self.write(task, head_sha=NEW)
        self.assertIsNone(pr_loop.check_result(self.path, task, HEAD))
        self.write(task, head_sha=NEW.upper())
        self.assertIsNone(pr_loop.check_result(self.path, task, HEAD))

    def test_a_blocking_result_at_the_current_head_stops_with_its_outcome_and_reason(self):
        for phase, outcome, kind, expected in (
                ("draft", "DRAFT-BLOCKED", "", f"PR #7 DRAFT-BLOCKED at {HEAD[:12]}: fix failed"),
                ("draft", "WAIT-INTERRUPTED", "", f"PR #7 WAIT-INTERRUPTED at {HEAD[:12]}: fix failed"),
                ("draft", "ERROR", "", f"PR #7 ERROR at {HEAD[:12]}: fix failed"),
                ("ready", "WAITING", "person", f"PR #7 WAITING (person) at {HEAD[:12]}: fix failed"),
                ("ready", "WAITING", "transient", f"PR #7 WAITING (transient) at {HEAD[:12]}: fix failed"),
                ("ready", "WAITING", "unknown", f"PR #7 WAITING at {HEAD[:12]}: fix failed"),
                ("ready", "SKIP", "", f"PR #7 SKIP at {HEAD[:12]}: fix failed"),
                ("ready", "ERROR", "", f"PR #7 ERROR at {HEAD[:12]}: fix failed")):
            with self.subTest(phase=phase, outcome=outcome, kind=kind):
                task = self.task(phase)
                self.write(task, outcome=outcome, wait_kind=kind)
                with self.assertRaises(pr_loop.Stop) as caught:
                    pr_loop.check_result(self.path, task, HEAD)
                self.assertEqual(expected, str(caught.exception))
        # The judged head is compared in lower case.
        task = self.task()
        self.write(task, head_sha=HEAD.upper())
        with self.assertRaisesRegex(pr_loop.Stop, "DRAFT-BLOCKED"):
            pr_loop.check_result(self.path, task, HEAD)

    def test_a_success_result_at_the_current_head_does_not_stop(self):
        for phase, outcome in (("draft", "READY"), ("ready", "DRAFT"), ("ready", "ENQUEUED"), ("ready", "MERGED")):
            with self.subTest(phase=phase, outcome=outcome):
                task = self.task(phase)
                self.write(task, outcome=outcome)
                self.assertIsNone(pr_loop.check_result(self.path, task, HEAD))


# ---- (B) Batch.run_pr: the state machine, on a fake clock with fake agents and a fake checkout -------------------

class World:
    """What `observe` answers, read by read: `(view, phase, detail)`. An item is a phase (`draft`, `ready`,
    `unverified`, `queued`, `merged`), a (phase, head) pair, an exception to raise, or a callable that runs before
    the next item is read (an agent publishing its result at that moment); once the scripted items are used up the PR
    stays in `phase`. `unverified` is a Ready PR whose signal is not valid. Every read is counted."""

    DETAIL = "synthetic detail"

    def __init__(self, items=(), phase="merged"):
        self.items, self.phase, self.reads = list(items), phase, 0

    def observe(self, _repo, number, _account=None):
        self.reads += 1
        item = self.items.pop(0) if self.items else self.phase
        while callable(item):
            item()
            item = self.items.pop(0) if self.items else self.phase
        if isinstance(item, BaseException):
            raise item
        phase, head, *url = item if isinstance(item, tuple) else (item, HEAD)
        view = pr_view_json("ready" if phase == "unverified" else phase, number=number, head=head,
                            url=url[0] if url else f"https://github.com/acme/demo/pull/{number}")
        return view, phase, self.DETAIL if phase == "unverified" else ""


class Fleet:
    """The fake agents and checkout of one test: everything they were asked to do is recorded."""

    def __init__(self, clock, directory):
        self.clock, self.directory = clock, Path(directory)
        self.agents, self.waits, self.submits, self.closed, self.tasks = [], [], [], [], []
        self.events = []     # "start <PR>-<phase>" and "close <PR>-<phase>", in the order they happened
        self.close_fails = set()  # windows (<PR>-<phase>) whose agent cannot be closed
        self.submit_times = []
        self.checkouts = []
        self.busy = {}      # role -> seconds an agent stays busy after it was given a task
        self.statuses = {}  # role -> the (dead, in_mode, foreground) answers; the last one repeats
        self.on_submit = {}  # role -> callable run right after that role's agent is given a task
        self.on_handoff = {}  # role -> callable run when the runner waits for that role's agent to hand over

    def new_agent(self, executable, _checkout, number, phase):
        return FakeAgent(self, executable, number, phase)

    def new_checkout(self, repo, directory=None, *, dry_run=False):
        checkout = FakeCheckout(self, repo, directory, dry_run)
        self.checkouts.append(checkout)
        return checkout


class FakeAgent:
    def __init__(self, fleet, executable, number, phase):
        self.fleet, self.executable, self.role = fleet, executable, phase
        self.window = f"{number}-{phase}"
        self.pane = f"%{len(fleet.agents) + 1}"
        self.statuses = list(fleet.statuses.get(phase, []))
        self.busy = 0
        fleet.agents.append(self)
        fleet.events.append(f"start {self.window}")

    def status(self):
        if not self.statuses:
            return False, False, "agent"
        return self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]

    def wait_for_prompt(self, timeout, *, allow_exit=False):
        self.fleet.waits.append((self.role, timeout, allow_exit))
        if self.busy:
            if self.busy > timeout:
                raise pr_loop.Stop(f"agent did not return to its input prompt in {self.pane}")
            self.fleet.clock.sleep(self.busy)
            self.busy = 0
        if allow_exit and self.role in self.fleet.on_handoff:
            self.fleet.on_handoff[self.role]()  # what the agent publishes before it returns to its prompt
        return True

    def submit(self, text):
        self.fleet.submits.append((self.role, text))
        self.fleet.submit_times.append(self.fleet.clock.now)
        self.busy = self.fleet.busy.get(self.role, 0)
        if self.role in self.fleet.on_submit:
            self.fleet.on_submit[self.role]()

    def close(self):
        self.fleet.events.append(f"close {self.window}")
        if self.window in self.fleet.close_fails:
            raise pr_loop.Stop(f"tmux kill-pane failed (1): fake tmux: injected failure of kill-pane in {self.pane}")
        self.fleet.closed.append(self.role)


class FakeCheckout:
    def __init__(self, fleet, repo, directory, dry_run):
        self.fleet, self.repo, self.directory, self.dry_run = fleet, repo, directory, dry_run
        self.verified, self.announced, self.finished = 0, 0, False

    def announce(self):
        self.announced += 1

    def verify(self):
        self.verified += 1

    def task(self, repo, number, phase, head):
        index = len(self.fleet.tasks) + 1
        task = dict(version=1, repo=f"{repo.owner}/{repo.name}", pr=number, phase=phase, nonce="b" * 32,
                    start_head=head)
        path = self.fleet.directory / f"task-{index}" / "task.json"   # one directory per dispatch, as in Checkout
        path.parent.mkdir()
        self.fleet.tasks.append(SimpleNamespace(phase=phase, head=head, task=task, path=path))
        return path, task

    def finish(self):
        self.finished = True


class RunPRCase(unittest.TestCase):
    real_checkout = False  # True: the real Checkout, on real git (FakeEnv), instead of the fleet's recording fake
    real_agent = False     # True: the real Agent, driving the fake tmux of FakeEnv, instead of the fleet's recording fake

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.clock = FakeTime()
        self.fleet = Fleet(self.clock, self.temp.name)
        self.told = []
        self.env = FakeEnv(self) if self.real_checkout else None
        patches = [("time", self.clock), ("tell", self.told.append)]
        if not self.real_agent:
            patches.append(("Agent", self.fleet.new_agent))
        if not self.real_checkout:
            patches.append(("Checkout", self.fleet.new_checkout))
        for target, value in patches:
            patcher = patch.object(pr_loop, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def args(self, **overrides):
        values = dict(pr=[7], dry_run=False, checkout=str(self.env.checkout) if self.env else None, phase_timeout=100, startup_timeout=60, max_actions=20,
                      poll_interval=10, ready_agent="codex", draft_agent="claude",
                      ready_command="$pr-review-merge {pr}", draft_command="/pr-ready {pr}")
        values.update(overrides)
        return SimpleNamespace(**values)

    def run_batch(self, items=(), phase="merged", **overrides):
        self.world = World(items, phase)
        with patch.object(pr_loop, "observe", self.world.observe):
            batch = pr_loop.Batch(pr_loop.Repo.parse("acme/demo"), self.args(**overrides))
            if self.real_checkout:  # the lock of the checkout is given back at the end of the test
                self.addCleanup(lambda: batch.checkout and batch.checkout.release())
            batch.run()

    def stops(self, pattern, items=(), phase="merged", **overrides):
        with self.assertRaisesRegex(pr_loop.Stop, pattern) as caught:
            self.run_batch(items, phase, **overrides)
        return str(caught.exception)

    def roles(self):
        return [role for role, _ in self.fleet.submits]


class MergeTrainTests(RunPRCase):
    # Reading the sequences: an ordinary dispatch takes two reads of the phase (the debounce) and a third read
    # that confirms it right before the task is pasted; a phase that is left by an agent's own action needs
    # two reads to be believed; a completed PR ends after two reads of `merged`.

    def test_a_pr_that_leaves_the_merge_train_for_ready_stops(self):
        message = self.stops("left the merge train while still Ready; inspect the PR conversation",
                             ["ready"] * 3 + ["queued"] * 2 + ["ready"] * 2)
        self.assertEqual("PR #7: left the merge train while still Ready; inspect the PR conversation", message)
        self.assertEqual(["ready"], self.roles(), "no second dispatch")

    def test_a_pr_that_is_merged_from_the_train_completes(self):
        # The control of the test above: the same run, ending in `merged`.
        self.run_batch(["ready"] * 3 + ["queued"] * 2 + ["merged"] * 2)
        self.assertEqual(["ready"], self.roles())
        self.assertIn("PR #7: waiting for merge train", self.told)
        self.assertIn("PR #7: merged", self.told)
        self.assertEqual(["ready"], self.fleet.closed, "a merged PR's agent is closed when the run ends, the last one")
        self.assertTrue(self.fleet.checkouts[0].finished, "the run says what it kept")

    def test_one_stale_ready_read_after_queued_is_not_a_return_to_ready(self):
        # GitHub can answer one read from before the label was applied.
        # Two of them, each between reads of `queued`: stale reads do not add up.
        self.run_batch(["ready"] * 3 + ["queued"] * 2 + ["ready", "queued", "ready", "queued"] + ["merged"] * 2)
        self.assertEqual(["ready"], self.roles())
        self.assertEqual(0, len([w for w in self.told if "left the merge train" in w]))


class DebounceTests(RunPRCase):
    def test_a_phase_is_acted_on_only_after_two_reads_in_a_row(self):
        # draft, ready, ready: the draft read is not repeated, so only the ready phase is dispatched.
        self.run_batch(["draft", "ready", "ready", "ready"] + ["merged"] * 2)
        self.assertEqual(["ready"], self.roles())
        self.assertEqual(["ready"], [agent.role for agent in self.fleet.agents], "no draft agent was ever started")
        self.assertTrue(self.submitted_command("ready").startswith("$pr-review-merge 7 --pr-loop-task="))

    def submitted_command(self, role):
        return next(text for r, text in self.fleet.submits if r == role)

    def test_a_phase_that_flips_every_read_is_never_acted_on(self):
        self.stops("timed out in draft", ["draft", "ready"] * 20, phase="draft", phase_timeout=100)
        self.assertEqual([], self.fleet.submits)
        self.assertEqual([], self.fleet.agents)

    def test_the_debounce_is_the_module_constant(self):
        # With three reads required, two reads of `ready` are still not enough.
        with patch.object(pr_loop, "STABLE_POLLS", 3):
            self.run_batch(["ready", "ready", "draft", "draft", "draft", "draft"] + ["merged"] * 3)
        self.assertEqual(["draft"], self.roles())

    def test_the_debounce_holds_back_the_first_dispatch_by_one_poll_interval(self):
        start = self.clock.now
        self.run_batch(["ready"] * 3 + ["merged"] * 2)
        self.assertEqual([start + 10], self.fleet.submit_times, "one poll interval passes before the dispatch")

    def inspected_only(self):
        """A dry run inspects the checkout (read-only, `dry_run=True`) and reports it; it takes no part in the run."""
        (checkout,) = self.fleet.checkouts
        self.assertEqual((True, 0, 1, False), (checkout.dry_run, checkout.verified, checkout.announced,
                                               checkout.finished))

    def test_a_dry_run_reports_after_the_first_read_and_starts_nothing(self):
        self.run_batch(["draft", "ready", "merged"], dry_run=True)
        self.assertEqual(1, self.world.reads)
        self.assertEqual(["PR #7: draft"], self.told)
        self.assertEqual(([], []), (self.fleet.agents, self.clock.sleeps))
        self.inspected_only()

    def test_a_dry_run_names_why_a_ready_pr_is_unverified(self):
        self.run_batch(["unverified", "ready"], dry_run=True)
        self.assertEqual(["PR #7: unverified (synthetic detail)"], self.told)
        self.assertEqual(([], []), (self.fleet.agents, self.clock.sleeps))
        self.inspected_only()

    def test_a_dry_run_reports_every_pr_and_then_the_refusal_of_the_checkout(self):
        refusal = pr_loop.Stop("checkout /x is not clean")
        calls = []

        def refused(repo, directory=None, *, dry_run=False):
            calls.append(dry_run)
            raise refusal
        self.world = World(["draft", "ready"], "merged")
        with patch.object(pr_loop, "Checkout", refused), patch.object(pr_loop, "observe", self.world.observe):
            with self.assertRaises(pr_loop.Stop) as caught:
                pr_loop.Batch(pr_loop.Repo.parse("acme/demo"), self.args(pr=[7, 8], dry_run=True)).run()
        self.assertIs(refusal, caught.exception, "reported as it is, without a PR prefix")
        self.assertEqual(["PR #7: draft", "PR #8: ready"], self.told, "every PR is reported before the refusal")
        self.assertEqual([True], calls)


class MaxActionsTests(RunPRCase):
    def test_a_second_dispatch_over_the_limit_stops(self):
        message = self.stops("maximum agent dispatches reached", ["ready"] * 3 + ["draft"] * 2, max_actions=1)
        self.assertEqual("PR #7: maximum agent dispatches reached", message)
        self.assertEqual(["ready"], self.roles())
        self.assertEqual(1, len(self.fleet.agents), "the refused dispatch started no agent")

    def test_the_same_run_with_a_larger_limit_dispatches_twice(self):
        # (a handoff reads the PR once more, to judge the result, before the next role's confirming read)
        self.run_batch(["ready"] * 3 + ["draft"] * 4 + ["merged"] * 2, max_actions=2)
        self.assertEqual(["ready", "draft"], self.roles())


class DispatchChecksTests(RunPRCase):
    """What runs before EVERY dispatch (not only the first): the PR URL, and the checkout (`verify`)."""

    def test_the_pr_url_is_checked_before_every_dispatch(self):
        wrong = "https://example.com/acme/demo/pull/7"
        items = ["ready"] * 3 + [("draft", HEAD, wrong)] * 4
        message = self.stops("PR #7: GitHub returned an unexpected PR URL", items)
        self.assertEqual("PR #7: GitHub returned an unexpected PR URL", message)
        self.assertEqual(["ready"], self.roles(), "the second dispatch never happened")
        self.assertEqual(["ready"], [agent.role for agent in self.fleet.agents], "and no agent was started for it")
        # The control: the same run with the URL of this PR dispatches both.
        self.setUp()
        self.run_batch(["ready"] * 3 + ["draft"] * 4 + ["merged"] * 2)
        self.assertEqual(["ready", "draft"], self.roles())

    def test_the_pr_url_is_checked_before_the_first_agent_is_started(self):
        self.stops("PR #7: GitHub returned an unexpected PR URL", [("ready", HEAD, "https://github.com/acme/other/pull/7")] * 3)
        self.assertEqual(([], []), (self.fleet.agents, self.fleet.submits))
        self.assertEqual(0, self.fleet.checkouts[0].verified, "the URL comes before the checkout is looked at")

    def test_the_checkout_is_verified_before_every_dispatch(self):
        self.run_batch(["ready"] * 3 + ["draft"] * 4 + ["ready"] * 4 + ["merged"] * 2)
        self.assertEqual(["ready", "draft", "ready"], self.roles())
        (checkout,) = self.fleet.checkouts
        self.assertEqual((1, 3, 1), (len(self.fleet.checkouts), checkout.verified, checkout.announced))

    def test_a_checkout_that_fails_verification_stops_before_the_agent_is_started(self):
        def fail():
            raise pr_loop.Stop("checkout /x is no longer on main")
        with patch.object(FakeCheckout, "verify", side_effect=fail):
            message = self.stops("checkout /x is no longer on main", ["ready"] * 3)
        self.assertEqual("PR #7: checkout /x is no longer on main", message)
        self.assertEqual(([], []), (self.fleet.agents, self.fleet.submits))


class RealCheckoutBatchTests(RunPRCase):
    """The Batch with the real Checkout on real git: what the runner does between dispatches and between PRs."""
    real_checkout = True

    def test_a_checkout_a_skill_left_on_another_branch_stops_the_next_dispatch(self):
        def a_skill_leaves_a_pr_branch():
            self.env.git("switch", "-q", "-c", "pr-branch", cwd=self.env.checkout)
        items = ["ready"] * 3 + [a_skill_leaves_a_pr_branch] + ["draft"] * 4
        message = self.stops(rf"PR #7: checkout {re.escape(str(self.env.checkout))} is no longer on main at "
                             rf"{self.env.remote_head[:12]} \(now pr-branch at {self.env.remote_head[:12]}\): a skill "
                             "did not restore it or something else changed it; nothing was dispatched", items)
        self.assertTrue(message.startswith("PR #7: "))
        self.assertEqual(["ready"], self.roles(), "the second role was never dispatched")
        self.assertEqual(["ready"], [agent.role for agent in self.fleet.agents], "and never started")

    def test_a_stopped_run_leaves_what_a_skill_did_exactly_as_it_is(self):
        # An interrupted or blocked agent may leave the checkout on a PR branch with commits, edits, untracked and ignored
        # files and a stash: the runner stops, says so, and touches none of it (no reset, clean, checkout or stash).
        root = self.env.checkout

        def git(*args):
            return self.env.git(*args, cwd=root)

        def a_skill_works_on_a_pr_branch():
            git("switch", "-q", "-c", "pr-branch")
            (root / "feature.txt").write_text("committed\n")
            git("add", "feature.txt")
            git("commit", "-q", "-m", "work")
            (root / "README.txt").write_text("stashed\n")
            git("stash", "push", "-q")
            (root / "README.txt").write_text("edited\n")
            (root / "untracked.txt").write_text("untracked\n")
            (root / ".pr-ready/7").mkdir(parents=True)
            (root / ".pr-ready/7/evidence.json").write_text("ignored\n")
        self.stops("is no longer on main", ["ready"] * 3 + [a_skill_works_on_a_pr_branch] + ["draft"] * 4)
        self.assertEqual("pr-branch", git("symbolic-ref", "--short", "HEAD"))
        self.assertEqual("work", git("log", "-1", "--format=%s"))
        self.assertEqual(["edited\n", "untracked\n", "ignored\n", "committed\n"],
                         [(root / name).read_text() for name in ("README.txt", "untracked.txt", ".pr-ready/7/evidence.json",
                                                                 "feature.txt")])
        self.assertEqual(1, len(git("stash", "list").splitlines()), "the stash is still there")
        self.assertTrue(any(root.glob(".pr-loop/*/task.json")), "and so is the task file of the dispatch")

    def test_the_same_run_with_the_checkout_restored_dispatches_both_roles(self):
        # The control of the test above.
        self.run_batch(["ready"] * 3 + ["draft"] * 4 + ["merged"] * 2)
        self.assertEqual(["ready", "draft"], self.roles())

    def test_a_skill_that_leaves_work_behind_stops_the_next_dispatch(self):
        def a_skill_leaves_a_file():
            (self.env.checkout / "left-behind.txt").write_text("x")
        self.stops(r"PR #7: checkout .* has uncommitted changes or untracked files \(1 paths, e.g. left-behind.txt\); "
                   "commit or remove them; the runner never stashes or discards work; nothing was dispatched",
                   ["ready"] * 3 + [a_skill_leaves_a_file] + ["draft"] * 4)
        self.assertEqual(["ready"], self.roles())

    def test_origin_moving_during_the_batch_does_not_refuse_the_next_pr(self):
        # The merge train moves origin between PRs: the tip is read at startup only.
        # (each PR: two reads to believe `ready`, the confirming read, two of `merged` and the hand-over's fresh read)
        items = ["ready"] * 3 + ["merged"] * 3 + [self.env.advance_remote] + ["ready"] * 3 + ["merged"] * 3
        self.run_batch(items, pr=[7, 8])
        self.assertEqual(["ready", "ready"], self.roles())
        self.assertNotEqual(self.env.remote_head, self.env.git("rev-parse", "HEAD", cwd=self.env.checkout),
                            "origin did move: the checkout is behind it now")

    def test_a_refused_checkout_reads_no_pr_and_starts_nothing(self):
        (self.env.checkout / "stray.txt").write_text("x")
        self.world = World(["ready"] * 3)
        with patch.object(pr_loop, "observe", self.world.observe):
            with self.assertRaisesRegex(pr_loop.Stop, r"^checkout .* has uncommitted changes or untracked files"):
                pr_loop.Batch(pr_loop.Repo.parse("acme/demo"), self.args()).run()
        self.assertEqual((0, [], []), (self.world.reads, self.fleet.agents, self.clock.sleeps))
        self.assertEqual([], self.env.gh_calls(), "no GitHub call")
        self.assertEqual([], [call for call in self.env.tmux_calls() if call[0] != "list-panes"], "no tmux session")

    def test_the_run_holds_the_lock_of_the_checkout_while_it_works(self):
        lock = self.env.checkout / ".git/pilot-pr-loop.lock"
        self.run_batch(["ready"] * 3 + ["merged"] * 2)
        batch_lock = os.open(lock, os.O_RDWR)
        self.addCleanup(os.close, batch_lock)
        # (the run's own descriptor is still open: the process has not ended)
        with self.assertRaises(OSError):
            pr_loop.fcntl.flock(batch_lock, pr_loop.fcntl.LOCK_EX | pr_loop.fcntl.LOCK_NB)

    def test_ctrl_c_keeps_everything_and_says_where(self):
        def ctrl_c():
            raise KeyboardInterrupt
        self.world = World(["ready"] * 3 + [ctrl_c])
        argv = ["pr_loop.py", "7", "--repo", "acme/demo", "--checkout", str(self.env.checkout), "--poll-interval", "0.01"]
        errors = io.StringIO()
        with patch.object(sys, "argv", argv), patch.object(pr_loop, "observe", self.world.observe), \
             contextlib.redirect_stderr(errors):
            code = pr_loop.main()
        session = pr_loop.session_name(self.env.checkout)
        self.assertEqual((130, f"Interrupted; any agent window still open in tmux session {session} and the task files "
                               f"under {self.env.checkout}/.pr-loop/ were kept.\n"), (code, errors.getvalue()))
        self.assertFalse([line for line in self.told if line.startswith("Kept:")], "an interrupt prints its own message")
        self.assertTrue(any(self.env.checkout.glob(".pr-loop/*/task.json")), "the task file of the dispatch is kept")
        self.assertEqual(self.env.remote_head, self.env.git("rev-parse", "HEAD", cwd=self.env.checkout))

    def test_ctrl_c_before_anything_was_started_says_that_nothing_was_written(self):
        argv = ["pr_loop.py", "7", "--repo", "acme/demo", "--checkout", str(self.env.checkout)]
        errors = io.StringIO()
        with patch.object(sys, "argv", argv), patch.object(pr_loop, "Checkout", side_effect=KeyboardInterrupt), \
             contextlib.redirect_stderr(errors):
            code = pr_loop.main()
        self.assertEqual((130, "Interrupted; nothing was written.\n"), (code, errors.getvalue()))

    def test_a_dry_run_reports_the_pr_and_the_checkout_and_holds_no_lock(self):
        self.run_batch(["draft"], dry_run=True)
        self.assertEqual("PR #7: draft", self.told[0])
        self.assertEqual(f"Checkout: {self.env.checkout} (main at {self.env.remote_head[:12]})", self.told[1])
        self.assertFalse((self.env.checkout / ".git/pilot-pr-loop.lock").exists())
        self.assertEqual([], self.env.tmux_calls())


class PhaseTimeoutTests(RunPRCase):
    def test_a_phase_that_does_not_change_times_out(self):
        start = self.clock.now
        message = self.stops("timed out in draft", phase="draft", phase_timeout=100, poll_interval=10)
        self.assertEqual("PR #7: timed out in draft", message)
        # Confirmed at the second read (t+10); the budget of the phase starts there.
        self.assertEqual(start + 10 + 100, self.clock.now)
        self.assertEqual(["draft"], self.roles())

    def test_a_change_inside_the_timeout_completes(self):
        # The same run, but GitHub confirms the next phase at the last read the budget allows.
        self.run_batch(["draft"] * 11 + ["ready"] * 4 + ["merged"] * 2, phase_timeout=100, poll_interval=10)
        self.assertEqual(["draft", "ready"], self.roles())


class ExitedAgentTests(RunPRCase):
    def test_an_agent_that_is_gone_on_two_polls_in_a_row_stops(self):
        self.fleet.statuses["draft"] = [(True, False, "agent")]
        message = self.stops("draft agent exited before GitHub confirmed a state change", ["draft"] * 3,
                             phase="draft")
        self.assertEqual("PR #7: draft agent exited before GitHub confirmed a state change", message)
        self.assertEqual(5, self.world.reads, "the dispatch (3 reads), then exactly two polls")

    def test_dead_polls_that_are_not_consecutive_never_add_up(self):
        # dead, live, dead, live: the counter starts again after every live poll.
        dead, live = (True, False, "agent"), (False, False, "agent")
        self.fleet.statuses["draft"] = [dead, live, dead, live]
        self.run_batch(["draft"] * 7 + ["merged"] * 2)
        self.assertEqual(["draft"], self.roles())

    def test_an_agent_back_at_a_shell_counts_as_exited(self):
        self.fleet.statuses["draft"] = [(False, False, "bash")]
        self.stops("draft agent exited before GitHub confirmed", ["draft"] * 3, phase="draft")

    def test_a_login_shell_name_counts_as_a_shell(self):
        self.fleet.statuses["draft"] = [(False, False, "nu")]
        self.stops("draft agent exited before GitHub confirmed", ["draft"] * 3, phase="draft")

    def test_a_running_agent_is_not_exited(self):
        # The control of the two tests above: the same run with the agent still in its own process.
        self.fleet.statuses["draft"] = [(False, False, "claude")]
        self.stops("timed out in draft", ["draft"] * 3, phase="draft")


class ConfirmReadTests(RunPRCase):
    def test_a_state_that_changed_while_the_agent_started_stops_before_the_task_is_written(self):
        message = self.stops("GitHub state changed before dispatch; retry against the current PR",
                             ["ready", "ready", "draft"])
        self.assertTrue(message.startswith("PR #7: "))
        self.assertEqual(([], []), (self.fleet.submits, self.fleet.tasks))
        self.assertEqual(["ready"], [agent.role for agent in self.fleet.agents], "the agent had been started")

    def test_the_task_is_bound_to_the_head_of_the_confirming_read(self):
        # The PR was repaired while the agent started: the task carries the HEAD GitHub has now.
        self.run_batch([("ready", HEAD), ("ready", HEAD), ("ready", NEW)] + [("merged", NEW)] * 2)
        self.assertEqual([("ready", NEW)], [(t.phase, t.head) for t in self.fleet.tasks])

    def test_the_prompt_template_and_the_task_path_are_pasted(self):
        self.run_batch(["draft"] * 3 + ["merged"] * 2)
        (role, text), = self.fleet.submits
        path = str(self.fleet.directory / "task-1" / "task.json")
        self.assertEqual(("draft", "/pr-ready 7 --pr-loop-task=" + json.dumps(path)), (role, text))


class ReadRetryTests(RunPRCase):
    def boom(self):
        return pr_loop.GitHubError("boom")

    def test_two_failed_reads_then_a_good_one_are_tolerated(self):
        self.run_batch([self.boom(), self.boom()] + ["ready"] * 3 + ["merged"] * 2)
        self.assertEqual(["ready"], self.roles())
        failures = [line for line in self.told if "GitHub read failed" in line]
        self.assertEqual(["PR #7: GitHub read failed (1/3): boom", "PR #7: GitHub read failed (2/3): boom"], failures)
        self.assertEqual([10, 10], self.clock.sleeps[:2], "a retry waits one poll interval")

    def test_failures_that_are_not_consecutive_are_tolerated_on_every_read(self):
        # The counter restarts with every read: the main reads and the confirming read each fail twice in a row.
        err = self.boom
        self.run_batch([err(), "ready", err(), "ready", err(), err(), "ready"] + ["merged"] * 2)
        self.assertEqual(["ready"], self.roles())

    def test_three_failed_reads_in_a_row_stop_without_sending_anything(self):
        message = self.stops("GitHub read failed 3 consecutive times; no command sent: boom",
                             [self.boom(), self.boom(), self.boom()])
        self.assertEqual("PR #7: GitHub read failed 3 consecutive times; no command sent: boom", message)
        self.assertEqual(([], []), (self.fleet.submits, self.fleet.agents))
        (checkout,) = self.fleet.checkouts  # inspected at the start of the run, before the first read
        self.assertEqual(0, checkout.verified, "and never verified for a dispatch that did not happen")
        self.assertEqual([10, 10], self.clock.sleeps, "no sleep after the last attempt")

    def test_a_failing_confirming_read_stops_before_the_task_is_pasted(self):
        self.stops("GitHub read failed 3 consecutive times", ["ready", "ready", self.boom(), self.boom(), self.boom()])
        self.assertEqual(([], []), (self.fleet.submits, self.fleet.tasks))

    def test_a_failing_read_after_a_dispatch_sends_nothing_further(self):
        self.stops("GitHub read failed 3 consecutive times; no command sent",
                   ["ready"] * 3 + [self.boom(), self.boom(), self.boom()])
        self.assertEqual(["ready"], self.roles())

    def test_the_attempts_are_the_module_constant(self):
        with patch.object(pr_loop, "READ_ATTEMPTS", 2):
            self.stops("GitHub read failed 2 consecutive times", [self.boom(), self.boom(), "ready"])
        self.assertEqual(2, self.world.reads)

    def test_a_pr_that_cannot_be_driven_is_never_retried(self):
        views = {"closed": dict(pr_view_json("ready"), state="CLOSED"),
                 "no draft state": {k: v for k, v in pr_view_json("ready").items() if k != "isDraft"},
                 "invalid labels": dict(pr_view_json("ready"), labels="x")}
        expected = {"closed": "PR #7 is not open or merged", "no draft state": "PR #7 has no Draft state",
                    "invalid labels": "PR #7 returned invalid labels"}
        for case, view in views.items():
            with self.subTest(case=case):
                with patch.object(pr_loop, "pr_view", return_value=view) as pr_view:
                    with self.assertRaises(pr_loop.Stop) as caught:
                        pr_loop.Batch(pr_loop.Repo.parse("acme/demo"), self.args()).run()
                self.assertEqual(f"PR #7: {expected[case]}", str(caught.exception))
                self.assertEqual(1, pr_view.call_count, "a verdict about the PR is not a transient failure")
                self.assertEqual([], self.clock.sleeps)

    def test_a_refused_checkout_reads_no_pr_and_starts_nothing(self):
        # The checkout is inspected before the first PR is read, and a refusal is a verdict: it is not retried.
        self.world = World(["ready"] * 3)
        with patch.object(pr_loop, "Checkout", side_effect=pr_loop.Stop("checkout /x has no origin remote")) as checkout:
            with patch.object(pr_loop, "observe", self.world.observe):
                with self.assertRaises(pr_loop.Stop) as caught:
                    pr_loop.Batch(pr_loop.Repo.parse("acme/demo"), self.args()).run()
        self.assertEqual("checkout /x has no origin remote", str(caught.exception), "no PR prefix: no PR was involved")
        self.assertEqual(1, checkout.call_count)
        self.assertEqual((0, [], [], []), (self.world.reads, self.fleet.agents, self.fleet.submits, self.clock.sleeps))
        self.assertEqual([], self.fleet.checkouts)


class HandoffTests(RunPRCase):
    def waits(self):
        return self.fleet.waits

    def test_the_previous_agent_gets_the_phase_timeout_a_new_one_the_startup_timeout(self):
        self.fleet.busy["ready"] = 90   # longer than --startup-timeout, shorter than --phase-timeout
        self.run_batch(["ready"] * 3 + ["draft"] * 4 + ["merged"] * 2, phase_timeout=3600, startup_timeout=60)
        self.assertEqual(["ready", "draft"], self.roles())
        self.assertEqual([("ready", 60, False),     # the prompt of the agent that was just started
                          ("ready", 3600, True),    # it hands over: it was working
                          ("draft", 60, False),
                          ("draft", 3600, True)],   # and again when the PR is merged
                         self.waits())
        self.assertIn("PR #7: waiting for the ready agent in %1 to return to its prompt", self.told)

    def test_a_previous_agent_that_stays_busy_past_the_phase_timeout_stops(self):
        self.fleet.busy["ready"] = 4000
        message = self.stops("did not return to its input prompt", ["ready"] * 3 + ["draft"] * 2,
                             phase_timeout=3600, startup_timeout=60)
        self.assertTrue(message.startswith("PR #7: "))
        self.assertEqual(["ready"], [agent.role for agent in self.fleet.agents], "no draft agent was started")
        self.assertEqual(["ready"], self.roles())

    def test_the_merged_pr_waits_for_the_last_agent_for_the_phase_timeout_too(self):
        self.fleet.busy["ready"] = 4000
        self.stops("did not return to its input prompt", ["ready"] * 3 + ["merged"] * 2,
                   phase_timeout=3600, startup_timeout=60)
        self.assertEqual([], self.fleet.closed, "a stuck agent is retained for inspection")

    def test_an_agent_that_exited_is_replaced_not_waited_for(self):
        # allow_exit: a previous agent that is gone is closed and forgotten; the dispatch then starts a new one.
        self.fleet.busy["ready"] = 0
        with patch.object(FakeAgent, "wait_for_prompt", autospec=True,
                          side_effect=lambda agent, timeout, *, allow_exit=False: False if allow_exit else True):
            self.run_batch(["ready"] * 3 + ["draft"] * 4 + ["ready"] * 4 + ["merged"] * 2)
        self.assertEqual(["ready", "draft", "ready"], self.roles())
        self.assertEqual(["ready", "draft", "ready"], [agent.role for agent in self.fleet.agents],
                         "the exited ready agent was not reused")
        self.assertEqual(["ready", "draft", "ready"], self.fleet.closed)


class HandoffResultTests(RunPRCase):
    """The runner reads the finished agent's result before it moves on: a blocker stops the run even when GitHub
    already shows the next phase. Results are written by the real producer (pr_loop_result.write_result)."""

    def publish(self, role, outcome, head=HEAD, **fields):
        """What the skill of `role` publishes for the task it was last given."""
        record = [t for t in self.fleet.tasks if t.phase == role][-1]
        write_result(record.path, record.task, outcome=outcome, head=head, reason="synthetic reason", **fields)

    def agent_publishes(self, role, outcome, *, when, head=HEAD, **fields):
        """Make the `role` agent publish `outcome` at `when`: "submit" (right after the task is pasted) or
        "handoff" (only once the runner waits for it to return to its prompt)."""
        hooks = {"submit": self.fleet.on_submit, "handoff": self.fleet.on_handoff}[when]
        hooks[role] = lambda: self.publish(role, outcome, head, **fields)

    # Three reads dispatch the first role (two polls and the confirming read), two more believe the next phase;
    # the surplus reads of that phase are the handoff's own fresh read and the next role's confirming read.
    DRAFT_THEN_READY = ["draft"] * 3 + ["ready"] * 4
    READY_THEN_DRAFT = ["ready"] * 3 + ["draft"] * 4
    READY_THEN_MERGED = ["ready"] * 3 + ["merged"] * 2

    def stops_before_the_next_role(self, outcome, items, role, *, kind=""):
        message = self.stops(re.escape(f"PR #7 {outcome}{kind} at {HEAD[:12]}: synthetic reason"), items)
        self.assertEqual(f"PR #7: PR #7 {outcome}{kind} at {HEAD[:12]}: synthetic reason", message)
        self.assertEqual([role], self.roles(), "the next role was never dispatched")
        self.assertEqual([role], [agent.role for agent in self.fleet.agents], "the next role was never started")
        self.assertEqual([], self.fleet.closed, "the panes are retained for inspection")
        self.assertTrue(self.fleet.checkouts[0].finished, "a stopped run says what it kept")
        self.assertNotIn("PR #7: merged", self.told)

    # -- the reviewer's scenario: GitHub already shows Ready when the Draft gate's blocker arrives -------------

    def test_a_blocker_published_before_the_handoff_stops_before_ready_is_dispatched(self):
        self.agent_publishes("draft", "DRAFT-BLOCKED", when="submit")
        self.stops_before_the_next_role("DRAFT-BLOCKED", self.DRAFT_THEN_READY, "draft")

    def test_a_blocker_that_appears_only_when_the_agent_returns_to_its_prompt_stops(self):
        # The agent publishes just before it returns to its prompt: reading the result before the wait misses it.
        self.agent_publishes("draft", "DRAFT-BLOCKED", when="handoff")
        self.stops_before_the_next_role("DRAFT-BLOCKED", self.DRAFT_THEN_READY, "draft")

    def test_the_handoff_wait_comes_first_and_the_result_is_read_after_a_fresh_read_of_the_pr(self):
        self.agent_publishes("draft", "DRAFT-BLOCKED", when="handoff")
        self.stops_before_the_next_role("DRAFT-BLOCKED", self.DRAFT_THEN_READY, "draft")
        # 2 reads to dispatch + confirm, 2 reads of the next phase, then one fresh read for the result's head.
        self.assertEqual(6, self.world.reads)
        self.assertEqual([("draft", 60, False), ("draft", 100, True)], self.fleet.waits)

    def test_every_handoff_stops_on_a_blocker_at_the_current_head(self):
        cases = (
            ("draft to ready", self.DRAFT_THEN_READY, "draft", "DRAFT-BLOCKED", {}, ""),
            ("draft to ready, interrupted", self.DRAFT_THEN_READY, "draft", "WAIT-INTERRUPTED", {}, ""),
            ("draft to ready, error", self.DRAFT_THEN_READY, "draft", "ERROR", {}, ""),
            ("ready to draft, waiting", self.READY_THEN_DRAFT, "ready", "WAITING", {"wait_kind": "person"}, " (person)"),
            ("ready to draft, skip", self.READY_THEN_DRAFT, "ready", "SKIP", {}, ""),
            ("ready to draft, error", self.READY_THEN_DRAFT, "ready", "ERROR", {}, ""),
            ("ready to merged, error", self.READY_THEN_MERGED, "ready", "ERROR", {}, ""),
            ("ready to merged, waiting", self.READY_THEN_MERGED, "ready", "WAITING", {"wait_kind": "transient"},
             " (transient)"))
        for name, items, role, outcome, fields, kind in cases:
            with self.subTest(name):
                self.setUp()   # a fresh fleet per case
                self.agent_publishes(role, outcome, when="handoff", **fields)
                self.stops_before_the_next_role(outcome, items, role, kind=kind)

    def test_a_blocker_does_not_become_harmless_because_the_pr_is_merged(self):
        self.agent_publishes("ready", "ERROR", when="handoff")
        self.stops_before_the_next_role("ERROR", self.READY_THEN_MERGED, "ready")

    def test_a_blocker_stops_when_the_previous_agent_is_gone(self):
        self.agent_publishes("draft", "DRAFT-BLOCKED", when="submit")
        with patch.object(FakeAgent, "wait_for_prompt", autospec=True,
                          side_effect=lambda agent, timeout, *, allow_exit=False: False if allow_exit else True):
            message = self.stops(f"PR #7 DRAFT-BLOCKED at {HEAD[:12]}", self.DRAFT_THEN_READY)
        self.assertTrue(message.startswith("PR #7: "))
        self.assertEqual(["draft"], self.roles(), "ready was never dispatched")
        self.assertEqual(["draft"], [agent.role for agent in self.fleet.agents])
        self.assertEqual(["draft"], self.fleet.closed, "the gone agent was closed, nothing else was started")

    # -- the head that judges the result is the one of a FRESH read -------------------------------------------

    def test_the_fresh_head_makes_a_result_current(self):
        # The PR was repaired while the previous agent finished: the blocker judges the HEAD GitHub has now.
        self.agent_publishes("draft", "DRAFT-BLOCKED", when="handoff", head=NEW)
        items = ["draft"] * 3 + [("ready", HEAD)] * 2 + [("ready", NEW)] * 2
        message = self.stops(f"PR #7 DRAFT-BLOCKED at {NEW[:12]}: synthetic reason", items)
        self.assertEqual(f"PR #7: PR #7 DRAFT-BLOCKED at {NEW[:12]}: synthetic reason", message)
        self.assertEqual(["draft"], self.roles())

    def test_a_blocker_of_the_head_that_is_gone_is_ignored(self):
        # The control of the test above, mirrored: the result judges the stale HEAD, the fresh read has moved on.
        self.agent_publishes("draft", "DRAFT-BLOCKED", when="handoff", head=HEAD)
        items = ["draft"] * 3 + [("ready", HEAD)] * 2 + [("ready", NEW)] * 2 + [("merged", NEW)] * 2
        self.run_batch(items)
        self.assertEqual(["draft", "ready"], self.roles())

    # -- successes and silence are not blockers ----------------------------------------------------------------

    def test_a_delayed_ready_result_lets_the_run_go_on(self):
        self.agent_publishes("draft", "READY", when="handoff")
        self.run_batch(self.DRAFT_THEN_READY + ["merged"] * 2)
        self.assertEqual(["draft", "ready"], self.roles())
        self.assertIn("PR #7: merged", self.told)

    def test_an_enqueued_result_lets_the_run_go_on(self):
        self.agent_publishes("ready", "ENQUEUED", when="handoff")
        self.run_batch(["ready"] * 3 + ["queued"] * 2 + ["merged"] * 2)
        self.assertEqual(["ready"], self.roles())
        self.assertIn("PR #7: waiting for merge train", self.told)
        self.assertIn("PR #7: merged", self.told)

    def test_a_draft_result_lets_the_run_go_on(self):
        self.agent_publishes("ready", "DRAFT", when="handoff")
        self.run_batch(self.READY_THEN_DRAFT + ["merged"] * 2)
        self.assertEqual(["ready", "draft"], self.roles())

    def test_a_merged_result_lets_the_run_complete(self):
        self.agent_publishes("ready", "MERGED", when="handoff")
        self.run_batch(self.READY_THEN_MERGED)
        self.assertEqual(["ready"], self.roles())
        self.assertIn("PR #7: merged", self.told)
        self.assertEqual(["ready"], self.fleet.closed)

    def test_a_handoff_without_a_result_goes_on_and_still_reads_the_pr_again(self):
        self.run_batch(self.DRAFT_THEN_READY + ["merged"] * 2)
        self.assertEqual(["draft", "ready"], self.roles())
        self.assertEqual(10, self.world.reads, "a fresh read at each of the two handoffs")

    # -- a result that cannot be trusted stops the handoff too ---------------------------------------------------

    def result_file(self, role):
        return [t for t in self.fleet.tasks if t.phase == role][-1].path.with_name("result.json")

    def test_a_result_that_is_not_valid_stops_the_handoff(self):
        task_of = lambda: [t for t in self.fleet.tasks if t.phase == "draft"][-1].task
        cases = (
            ("foreign", "skill result does not belong to this dispatch",
             lambda: dict(task_of(), nonce="d" * 32, head_sha=HEAD, outcome="READY", reason="", wait_kind="",
                          person_handoff=False)),
            ("another phase's outcome", "invalid skill result",
             lambda: dict(task_of(), head_sha=HEAD, outcome="ENQUEUED", reason="", wait_kind="",
                          person_handoff=False)),
            ("no outcome", "invalid skill result",
             lambda: dict(task_of(), head_sha=HEAD, outcome=None, reason="", wait_kind="", person_handoff=False)))
        for name, message, body in cases:
            with self.subTest(name):
                self.setUp()
                self.fleet.on_handoff["draft"] = lambda body=body: self.result_file("draft").write_text(
                    json.dumps(body()), encoding="utf-8")
                self.stops(message, self.DRAFT_THEN_READY)
                self.assertEqual(["draft"], self.roles(), "ready was never dispatched")

    def test_a_result_over_the_size_limit_stops_the_handoff(self):
        self.fleet.on_handoff["draft"] = lambda: self.result_file("draft").write_text("x" * 5000)
        self.stops("skill result exceeded the size limit", self.DRAFT_THEN_READY)
        self.assertEqual(["draft"], self.roles())

    def test_a_fresh_read_that_fails_stops_the_handoff_without_dispatching(self):
        boom = pr_loop.GitHubError("boom")
        self.stops("GitHub read failed 3 consecutive times; no command sent: boom",
                   ["draft"] * 3 + ["ready"] * 2 + [boom, boom, boom])
        self.assertEqual(["draft"], self.roles())
        self.assertEqual(["draft"], [agent.role for agent in self.fleet.agents],
                         "the failed read came before the next role was started, not at its confirming read")


class UnverifiedTests(RunPRCase):
    """A Ready PR without a valid signal at its HEAD (`unverified`) is never acted on: the runner dispatches nothing
    for it and writes nothing to GitHub. While the Draft agent is still working it counts as the Draft phase, because
    the gate marks the PR Ready before it verifies and signs it."""

    def refusal(self, head=HEAD):
        return (f"PR #7 is Ready without a valid {rs.LABEL} signal at HEAD {head[:12]}: synthetic detail; "
                "nothing is dispatched for it: convert it to Draft and run pr-ready on it, then start the runner again")

    def publish(self, role, outcome, **fields):
        """What the skill of `role` publishes for the task it was last given."""
        record = [t for t in self.fleet.tasks if t.phase == role][-1]
        write_result(record.path, record.task, outcome=outcome, head=HEAD, reason="synthetic reason", **fields)

    # -- a PR that starts unverified ---------------------------------------------------------------------------
    def test_a_pr_that_starts_unverified_is_refused_before_anything_is_started(self):
        message = self.stops(re.escape(self.refusal()), ["unverified"] * 2)
        self.assertEqual("PR #7: " + self.refusal(), message)
        self.assertEqual(2, self.world.reads, "the phase is believed after two reads, like any other")
        self.assertEqual(([], [], []), (self.fleet.agents, self.fleet.submits, self.fleet.tasks))
        (checkout,) = self.fleet.checkouts  # inspected at the start of the run, before the first read
        self.assertEqual(0, checkout.verified, "and never verified for a dispatch that did not happen")

    def test_one_unverified_read_between_ready_reads_is_not_acted_on(self):
        # The debounce, with the new phase: the same sequence that is refused above when it is stable.
        self.run_batch(["unverified", "ready", "ready", "ready"] + ["merged"] * 2)
        self.assertEqual(["ready"], self.roles())

    def test_the_debounce_of_the_unverified_phase_is_the_module_constant(self):
        with patch.object(pr_loop, "STABLE_POLLS", 3):
            self.run_batch(["unverified", "unverified", "ready", "ready", "ready", "ready"] + ["merged"] * 3)
        self.assertEqual(["ready"], self.roles())

    def test_a_pr_that_turns_unverified_before_the_dispatch_is_not_dispatched(self):
        self.stops("GitHub state changed before dispatch; retry against the current PR", ["ready", "ready", "unverified"])
        self.assertEqual(([], []), (self.fleet.submits, self.fleet.tasks))

    # -- a PR that leaves the Ready or the queued phase unverified -------------------------------------------------
    def test_a_pr_that_leaves_the_merge_train_unverified_stops_like_one_that_returns_to_ready(self):
        message = self.stops("left the merge train while still Ready; inspect the PR conversation",
                             ["ready"] * 3 + ["queued"] * 2 + ["unverified"] * 2)
        self.assertEqual("PR #7: left the merge train while still Ready; inspect the PR conversation", message)
        self.assertEqual(["ready"], self.roles(), "no second dispatch")

    def test_a_ready_agent_that_leaves_the_pr_unverified_hands_over_and_then_the_run_stops(self):
        message = self.stops(re.escape(self.refusal()), ["ready"] * 3 + ["unverified"] * 4)
        self.assertEqual("PR #7: " + self.refusal(), message)
        self.assertEqual(["ready"], self.roles())
        self.assertEqual([("ready", 60, False), ("ready", 100, True)], self.fleet.waits,
                         "the agent is given the time to publish its own result first")
        self.assertEqual(6, self.world.reads, "two reads to dispatch and confirm, two of the phase, one fresh")
        self.assertEqual([], self.fleet.closed, "the pane is retained for inspection")

    def test_the_result_the_ready_agent_publishes_is_what_the_run_stops_on(self):
        self.fleet.on_handoff["ready"] = lambda: self.publish("ready", "WAITING", wait_kind="transient")
        message = self.stops(re.escape(f"PR #7 WAITING (transient) at {HEAD[:12]}: synthetic reason"),
                             ["ready"] * 3 + ["unverified"] * 4)
        self.assertEqual(f"PR #7: PR #7 WAITING (transient) at {HEAD[:12]}: synthetic reason", message)

    # -- while the Draft agent is working: the PR is still in the Draft phase ------------------------------------------
    def test_a_blocker_that_arrives_while_the_pr_shows_unverified_stops_with_the_gates_reason(self):
        # pr_gate marks the PR Ready, then fails its post-action check and publishes DRAFT-BLOCKED: GitHub shows a
        # Ready PR without a signal when the result is not on disk yet. A runner that took that for the Ready phase
        # handed the PR to the Ready agent (and reported it merged) before the blocker arrived.
        # The result arrives after more reads than the debounce needs, so that a runner that took the PR for the Ready
        # phase has already handed over, read nothing and stopped on its own reason when the blocker is written.
        items = ["draft"] * 3 + ["unverified"] * 4 + [lambda: self.publish("draft", "DRAFT-BLOCKED")] + ["unverified"] * 3
        message = self.stops(re.escape(f"PR #7 DRAFT-BLOCKED at {HEAD[:12]}: synthetic reason"), items)
        self.assertEqual(f"PR #7: PR #7 DRAFT-BLOCKED at {HEAD[:12]}: synthetic reason", message)
        self.assertEqual(["draft"], self.roles(), "the Ready phase was never dispatched")
        self.assertEqual(["draft"], [agent.role for agent in self.fleet.agents])
        self.assertEqual([("draft", 60, False)], self.fleet.waits, "the PR never left the Draft phase: no hand-over")
        self.assertEqual([], self.fleet.closed, "the pane is retained for inspection")
        self.assertNotIn("PR #7: merged", self.told)

    def test_a_pr_that_is_signed_while_the_draft_agent_works_goes_on_to_the_ready_phase(self):
        # The control of the test above: the signal arrives instead of a blocker.
        self.run_batch(["draft"] * 3 + ["unverified"] * 3 + ["ready"] * 4 + ["merged"] * 2)
        self.assertEqual(["draft", "ready"], self.roles())
        self.assertIn("PR #7: merged", self.told)

    def why(self):
        """What a stop of the Draft phase adds when the PR is Ready without a valid signal: the reason."""
        return f" (Ready without a valid {rs.LABEL} signal: synthetic detail)"

    def test_without_a_result_a_draft_agent_that_is_gone_is_the_stop(self):
        self.fleet.statuses["draft"] = [(True, False, "agent")]
        message = self.stops("draft agent exited before GitHub confirmed a state change",
                             ["draft"] * 3 + ["unverified"] * 4)
        self.assertEqual("PR #7: draft agent exited before GitHub confirmed a state change" + self.why(), message)
        self.assertEqual(["draft"], self.roles())

    def test_without_a_result_a_draft_agent_that_is_still_there_runs_into_the_phase_timeout(self):
        message = self.stops("timed out in draft", ["draft"] * 3, phase="unverified")
        self.assertEqual("PR #7: timed out in draft" + self.why(), message,
                         "the reason matters: the signal may have been written by another account")
        self.assertEqual(["draft"], self.roles(), "the Ready phase was never dispatched")


class AgentLifetimeTests(RunPRCase):
    """When an agent is closed (kjelly/pilot#425, decision D1 = B): not at the merge of its PR but right after the NEXT agent
    exists, or when the run ends however it ends, so that the tmux session of the batch lives from the first dispatch to
    the end and a watcher is detached once. A pane that is still working for a PR that did not merge is never closed.
    The agents here are the fleet's recording fakes: the order of start and close is what is under test."""
    PR = ["ready"] * 3 + ["merged"] * 3        # one PR dispatched once and merged: three reads to believe `ready`, three of `merged`
    TWO_ROLES = ["ready"] * 3 + ["draft"] * 4 + ["merged"] * 3

    def test_a_merged_prs_agent_is_closed_after_the_next_prs_first_agent_exists(self):
        self.run_batch(self.PR + self.PR, pr=[7, 8])
        self.assertEqual(["start 7-ready", "start 8-ready", "close 7-ready", "close 8-ready"], self.fleet.events)

    def test_every_agent_of_a_merged_pr_waits_for_the_next_agent(self):
        self.run_batch(self.TWO_ROLES + self.PR, pr=[7, 8])
        self.assertEqual(["start 7-ready", "start 7-draft", "start 8-ready", "close 7-ready", "close 7-draft",
                          "close 8-ready"], self.fleet.events)

    def test_the_last_prs_agents_are_closed_when_the_run_ends_and_before_it_says_what_it_kept(self):
        self.run_batch(self.PR)
        self.assertEqual(["start 7-ready", "close 7-ready"], self.fleet.events)
        self.assertTrue(self.fleet.checkouts[0].finished)
        self.assertEqual([], [line for line in self.told if "could not close" in line])

    def test_a_stop_closes_the_agents_of_the_merged_prs_and_keeps_the_running_one_open(self):
        message = self.stops("PR #8: timed out in ready", self.PR + ["ready"], phase="ready", pr=[7, 8], phase_timeout=100)
        self.assertEqual("PR #8: timed out in ready", message)
        self.assertEqual(["start 7-ready", "start 8-ready", "close 7-ready"], self.fleet.events,
                         "PR #8's agent is still working: it is retained for inspection")

    def test_a_stop_before_the_next_agent_exists_still_closes_the_merged_prs_agents(self):
        self.assertEqual("PR #8: synthetic stop", self.stops("synthetic stop", self.PR + [pr_loop.Stop("synthetic stop")],
                                                          pr=[7, 8]))
        self.assertEqual(["start 7-ready", "close 7-ready"], self.fleet.events)

    def test_ctrl_c_closes_the_agents_of_the_merged_prs_and_is_not_swallowed(self):
        with self.assertRaises(KeyboardInterrupt):
            self.run_batch(self.PR + [KeyboardInterrupt()], pr=[7, 8])
        self.assertEqual(["start 7-ready", "close 7-ready"], self.fleet.events)
        self.assertFalse(self.fleet.checkouts[0].finished, "an interrupt prints its own message, not the Kept line")

    def test_a_pane_that_cannot_be_closed_at_the_end_is_said_and_never_hides_the_stop(self):
        self.fleet.close_fails = {"7-ready"}
        self.assertEqual("PR #8: synthetic stop", self.stops("synthetic stop", self.PR + [pr_loop.Stop("synthetic stop")],
                                                          pr=[7, 8]))
        self.assertEqual(["close 7-ready"], [event for event in self.fleet.events if event.startswith("close")])
        self.assertEqual(["could not close the agent pane %1: tmux kill-pane failed (1): fake tmux: injected failure of "
                          "kill-pane in %1"], [line for line in self.told if "could not close" in line])

    def test_a_pane_that_cannot_be_closed_at_the_end_of_a_good_run_does_not_fail_it(self):
        self.fleet.close_fails = {"7-ready"}
        self.run_batch(self.PR)  # no Stop: the PR is merged
        self.assertEqual(1, len([line for line in self.told if line.startswith("could not close the agent pane %1")]))
        self.assertTrue(self.fleet.checkouts[0].finished, "and the run still says what it kept")

    def test_a_close_that_fails_before_the_next_dispatch_is_a_stop_and_the_rest_is_still_closed(self):
        self.fleet.close_fails = {"7-ready"}
        message = self.stops(r"PR #8: tmux kill-pane failed \(1\)", self.TWO_ROLES + self.PR, pr=[7, 8])
        self.assertTrue(message.startswith("PR #8: "))
        self.assertEqual(["start 7-ready", "start 7-draft", "start 8-ready", "close 7-ready", "close 7-draft"],
                         self.fleet.events, "7-draft is closed by the end of the run, 8-ready (new) is retained")

    def test_a_dead_agent_is_replaced_before_it_is_closed(self):
        # The first Ready agent dies while the Draft agent works; the PR returns to Ready: a new Ready agent is started
        # and only then is the dead one closed (closing a window first could end the session, and detach whoever watches it,
        # when it is the last).
        self.fleet.on_submit["draft"] = lambda: setattr(self.fleet.agents[0], "statuses", [(True, False, "agent")])
        self.run_batch(["ready"] * 3 + ["draft"] * 4 + ["ready"] * 4 + ["merged"] * 3)
        self.assertEqual(["ready", "draft", "ready"], self.roles())
        self.assertEqual(["start 7-ready", "start 7-draft", "start 7-ready", "close 7-ready", "close 7-ready",
                          "close 7-draft"], self.fleet.events)
        self.assertEqual("start 7-ready", self.fleet.events[2], "the new agent exists before anything is closed")

    def test_an_agent_that_exited_at_the_handoff_stays_open_until_the_next_agent_exists(self):
        with patch.object(FakeAgent, "wait_for_prompt", autospec=True,
                          side_effect=lambda agent, timeout, *, allow_exit=False: False if allow_exit else True):
            self.run_batch(self.TWO_ROLES)
        self.assertEqual(["start 7-ready", "start 7-draft", "close 7-ready", "close 7-draft"], self.fleet.events,
                         "closed once 7-draft exists (and 7-draft when the run ends), not when the exit is noticed")


class OneSessionPerBatchTests(RunPRCase):
    """The real Agent and the real Checkout, the fake tmux of FakeEnv with its model of sessions and windows: what a Batch
    does to tmux (kjelly/pilot#425 AC1)."""
    real_checkout = True
    real_agent = True
    PR = AgentLifetimeTests.PR

    def session(self, directory=None):
        return pr_loop.session_name(directory or self.env.checkout)

    def test_two_prs_are_two_windows_of_one_session_created_once(self):
        self.run_batch(self.PR + self.PR, pr=[7, 8])
        session = self.session()
        self.assertEqual([("new-session", session, "7-ready"), ("new-window", session, "8-ready")],
                         [(made["kind"], made["session"], made["window"]) for made in self.env.created()])
        calls = [call for call in self.env.tmux_calls() if call[0] in ("new-session", "new-window", "kill-pane")]
        self.assertEqual(["new-session", "new-session", "new-window", "kill-pane", "kill-pane"], [call[0] for call in calls],
                         "the second agent finds the session; the first PR's pane is closed after the second PR's window "
                         "exists, so the session is never torn down between the PRs")
        self.assertEqual([["kill-pane", "-t", "%1"], ["kill-pane", "-t", "%2"]], calls[3:])
        self.assertEqual({}, self.env.live(), "the last pane took the session with it")

    def test_the_session_is_named_once_and_the_kept_line_names_it(self):
        self.run_batch(self.PR)
        session = self.session()
        announced = [line for line in self.told if line.startswith("Agents run as windows")]
        self.assertEqual([f"Agents run as windows of tmux session {session}; watch them read-only with: tmux attach -r -t "
                          f"{session}"], announced)
        self.assertIn(f"PR #7 ready agent: %1 in window 7-ready of tmux session {session}", self.told)
        kept = [line for line in self.told if line.startswith("Kept:")]
        self.assertEqual([f"Kept: the task files under {self.env.checkout / '.pr-loop'} and any agent window still open in "
                          f"tmux session {session}; close the agents still running in {self.env.checkout} before the next "
                          f"run. Nothing in {self.env.checkout} was deleted or reset."], kept)

    def test_another_checkout_gets_another_session_and_never_a_window_of_the_first(self):
        # The first run stops with its agent still working: its window stays. The second run, in another checkout of the
        # same repository, makes a session of its own.
        self.stops("timed out in ready", phase="ready", phase_timeout=100)
        first = self.session()
        other = self.env.make_checkout("other")
        self.assertNotEqual(first, self.session(other))
        self.run_batch(self.PR, checkout=str(other))
        self.assertEqual([("new-session", first, "7-ready"), ("new-session", self.session(other), "7-ready")],
                         [(made["kind"], made["session"], made["window"]) for made in self.env.created()])
        self.assertEqual({first: ["7-ready"]}, self.env.live(), "the first checkout's agent was not touched")

    def test_the_session_is_made_again_when_the_operator_killed_it_between_two_prs(self):
        # PR #7 is merged and its agent waits to be closed when the operator kills the session, the only one: the tmux server
        # exits with it. PR #8 starts a new server, whose first pane has the ID PR #7's had. Closing PR #7's pane must not
        # touch it: only PR #8's own agent is killed, once, at the end of the run.
        killed = lambda: self.env.kill_session(self.session())
        self.run_batch(self.PR + [killed] + self.PR, pr=[7, 8])
        session = self.session()
        self.assertEqual([("new-session", session, "7-ready", "%1"), ("new-session", session, "8-ready", "%1")],
                         [(made["kind"], made["session"], made["window"], made["pane"]) for made in self.env.created()])
        self.assertEqual([["kill-pane", "-t", "%1"]], self.env.tmux_calls("kill-pane"),
                         "one kill: the end of the run closes PR #8's agent; PR #7's was on another server")
        self.assertEqual({}, self.env.live())

    def test_the_same_when_the_operators_own_session_keeps_the_server_alive(self):
        # The server survives: PR #8's pane is %2, and PR #7's %1 is gone from it. It is closed already, not killed.
        self.env.keeper()
        killed = lambda: self.env.kill_session(self.session())
        self.run_batch(self.PR + [killed] + self.PR, pr=[7, 8])
        session = self.session()
        self.assertEqual([("new-session", session, "7-ready", "%1"), ("new-session", session, "8-ready", "%2")],
                         [(made["kind"], made["session"], made["window"], made["pane"]) for made in self.env.created()])
        self.assertEqual([["kill-pane", "-t", "%2"]], self.env.tmux_calls("kill-pane"))
        self.assertEqual({"operator": ["keeper"]}, self.env.live())

    def test_a_server_that_exited_before_the_end_of_the_run_is_not_a_failure_to_close(self):
        # The operator kills the runner's session, the only one, after the last agent handed over and before the run ends: the
        # tmux server is gone, so the pane is closed already. `could not close` is for a pane that is still there.
        killed = lambda: self.env.kill_session(self.session())
        self.run_batch(["ready"] * 3 + ["merged"] * 2 + [killed] + ["merged"])
        self.assertEqual([], [line for line in self.told if "could not close" in line])
        self.assertEqual([], self.env.tmux_calls("kill-pane"), "nothing was sent to a server that was not there")
        self.assertTrue(self.told[-1].startswith("Kept: "), "and the run ended as any other")

    def test_a_server_that_exits_between_the_check_and_the_kill_is_not_a_failure_to_close_either(self):
        self.env.update_tmux(before={"kill-pane": [{"kill_session": self.session()}]})
        self.run_batch(self.PR)
        self.assertEqual([], [line for line in self.told if "could not close" in line])
        self.assertEqual([["kill-pane", "-t", "%1"]], self.env.tmux_calls("kill-pane"), "sent, and answered with no server")

    def test_two_prs_with_a_draft_and_a_ready_agent_each_are_four_windows_of_one_session_created_once(self):
        # The whole flow: Draft, then Ready, then merged, for each of two PRs, with the real Agent and the fake tmux.
        flow = ["draft"] * 3 + ["ready"] * 4 + ["merged"] * 3
        self.run_batch(flow + flow, pr=[7, 8])
        session = self.session()
        self.assertEqual([("new-session", "7-draft"), ("new-window", "7-ready"), ("new-window", "8-draft"),
                          ("new-window", "8-ready")], [(made["kind"], made["window"]) for made in self.env.created()])
        self.assertEqual({session}, {made["session"] for made in self.env.created()}, "one session for all four")
        order = [call[0] if call[0] == "new-window" else call[2] for call in self.env.tmux_calls()
                 if call[0] in ("new-window", "kill-pane")]
        self.assertEqual(["new-window", "new-window", "%1", "%2", "new-window", "%3", "%4"], order,
                         "PR #7's two panes are closed once PR #8's first agent exists, PR #8's two when the run ends")
        self.assertEqual({}, self.env.live())


class ImportsTests(unittest.TestCase):
    """The runner only reads GitHub: it must not import anything that changes it, and it reads the Ready signal
    without ever writing one."""
    SOURCE = (ROOT / "scripts" / "pr_loop.py").read_text()
    GH_READS = {"GitHubError", "Repo", "issue_comments", "pr_view", "timeline_events", "viewer_login"}
    SIGNAL_READS = {"LABEL", "assess", "SignalError"}  # not prepare, write, marker_comment or marker_line

    @classmethod
    def problems(cls, source):
        """What in `source` could change GitHub: a name other than the read ones taken from gh_runtime, gh_runtime
        itself (imported or used as a module), or a ready_signal name other than the read ones."""
        tree = ast.parse(source)
        imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
                    and node.module == "gh_runtime" for alias in node.names}
        found = [f"imports {name} from gh_runtime" for name in sorted(imported - cls.GH_READS)]
        found += [f"no longer imports {name} from gh_runtime" for name in sorted(cls.GH_READS - imported)]
        plain = [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names]
        found += ["imports the gh_runtime module"] * ("gh_runtime" in plain)
        found += [f"uses gh_runtime.{node.attr}" for node in ast.walk(tree) if isinstance(node, ast.Attribute)
                  and isinstance(node.value, ast.Name) and node.value.id == "gh_runtime"]
        found += [f"imports {alias.name} from ready_signal: use the module's attributes, which are checked here"
                  for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module == "ready_signal"
                  for alias in node.names]
        found += [f"uses ready_signal.{name}" for name in sorted({
            node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name) and node.value.id == "ready_signal"} - cls.SIGNAL_READS)]
        return found

    def test_it_imports_only_the_read_functions_of_gh_runtime_and_of_ready_signal(self):
        self.assertEqual([], self.problems(self.SOURCE))
        plain = [alias.name for node in ast.walk(ast.parse(self.SOURCE)) if isinstance(node, ast.Import)
                 for alias in node.names]
        self.assertIn("ready_signal", plain, "the signal is read through the shared module")

    def test_the_guard_rejects_every_way_to_write(self):
        good = "from gh_runtime import " + ", ".join(sorted(self.GH_READS)) + "\nimport ready_signal\nready_signal.assess\n"
        self.assertEqual([], self.problems(good), "control: the read names pass")
        for case, source, expected in (
                ("a write helper", good.replace("GitHubError", "GitHubError, edit_label"), "imports edit_label from gh_runtime"),
                ("the module itself", good + "import gh_runtime\n", "imports the gh_runtime module"),
                ("an attribute of it", good + "gh_runtime.post_comment\n", "uses gh_runtime.post_comment"),
                ("a read dropped", good.replace(", timeline_events", ""), "no longer imports timeline_events"),
                ("the signal writer", good + "ready_signal.write\n", "uses ready_signal.write"),
                ("the preparer", good + "ready_signal.prepare\n", "uses ready_signal.prepare"),
                ("the marker renderer", good + "ready_signal.marker_comment\n", "uses ready_signal.marker_comment"),
                ("a name from the signal module", good + "from ready_signal import write\n",
                 "imports write from ready_signal")):
            with self.subTest(case=case):
                self.assertIn(expected, "; ".join(self.problems(source)))

    # The runner starts agents in the operator's own checkout and must never create a workspace of its own or destroy
    # anything of the operator's (class `ephemeral-agent-workspace`, kjelly/pilot#423): no temporary directory, no
    # deleting, no clone, no git call that writes, and GitHub only through gh_runtime's reads.
    BANNED_MODULES = {"tempfile"}
    DELETES_ANYWHERE = {"rmtree", "unlink", "rmdir", "removedirs", "truncate", "write_text", "write_bytes"}
    DELETES_ON_OS = {"remove", "rename", "renames", "replace", "ftruncate"}
    READ_ONLY_GIT = {"rev-parse", "symbolic-ref", "cat-file", "merge-base", "config", "check-ignore", "ls-remote",
                     "check-ref-format", "diff-tree", "worktree"}
    SPAWNS = {"command", "run", "Popen", "check_output", "check_call", "call"}

    # The ONE place the runner deletes (kjelly/pilot#442): `--clean --remove-task-dirs --yes` unlinks the two files of a finished task
    # directory and removes the empty directory, each through the descriptor of the directory it is in (`dir_fd`: nothing is
    # looked up by a path that a symlink could redirect), in this one module-level function. Every other way to delete is
    # what it was: a violation.
    REMOVER = "remove_task_directory"
    SANCTIONED = {"unlink", "rmdir"}

    @classmethod
    def sanctioned(cls, tree):
        """The ids of the `os.unlink` and `os.rmdir` attributes that are CALLED WITH `dir_fd` inside the module-level function
        REMOVER: the deletions the guard lets through."""
        found = set()
        for function in tree.body:
            if isinstance(function, ast.FunctionDef) and function.name == cls.REMOVER:
                for node in ast.walk(function):
                    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in cls.SANCTIONED \
                            and isinstance(node.func.value, ast.Name) and node.func.value.id == "os" \
                            and any(keyword.arg == "dir_fd" for keyword in node.keywords):
                        found.add(id(node.func))
        return found

    @classmethod
    def ephemeral(cls, source):
        """What in `source` could create a workspace for the agents or destroy something of the operator's."""
        tree = ast.parse(source)
        allowed = cls.sanctioned(tree)
        found = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                found += [f"imports {alias.name}" for alias in node.names if alias.name in cls.BANNED_MODULES]
            elif isinstance(node, ast.ImportFrom):
                if node.module in cls.BANNED_MODULES:
                    found.append(f"imports from {node.module}")
                elif node.module == "shutil":
                    found += [f"imports {alias.name} from shutil" for alias in node.names if alias.name != "which"]
                elif node.module == "os":
                    found += [f"imports {alias.name} from os" for alias in node.names
                              if alias.name in cls.DELETES_ON_OS | cls.DELETES_ANYWHERE]
            elif isinstance(node, ast.Attribute):
                receiver = node.value.id if isinstance(node.value, ast.Name) else None
                if node.attr in cls.DELETES_ANYWHERE and id(node) not in allowed:
                    found.append(f"uses {node.attr}")
                if receiver == "os" and node.attr in cls.DELETES_ON_OS:
                    found.append(f"uses os.{node.attr}")
                if receiver == "shutil" and node.attr != "which":
                    found.append(f"uses shutil.{node.attr}")
            elif isinstance(node, ast.Name) and node.id in cls.DELETES_ANYWHERE:
                found.append(f"uses {node.id}")
            elif isinstance(node, ast.Call):
                found += cls.call_problems(node)
        return sorted(set(found))

    @classmethod
    def call_problems(cls, call):
        name = call.func.id if isinstance(call.func, ast.Name) else getattr(call.func, "attr", None)
        strings = [arg.value for arg in call.args if isinstance(arg, ast.Constant) and isinstance(arg.value, str)]
        found = []
        if name == "open" or (name and name.endswith("open")):
            modes = strings + [kw.value.value for kw in call.keywords if kw.arg == "mode" and isinstance(kw.value, ast.Constant)]
            found += ["opens a file for writing over it" for mode in modes if isinstance(mode, str) and "w" in mode]
        first = call.args[0] if call.args else None
        if name in cls.SPAWNS and first is not None:
            head = first.elts[0] if isinstance(first, (ast.List, ast.Tuple)) and first.elts else first
            if isinstance(head, ast.Constant) and head.value == "gh":
                found.append("runs gh (reads go through gh_runtime)")
            if isinstance(head, ast.Constant) and head.value == "git" and name == "command":
                found.append("calls git through command() (use git(), which is read-only)")
        if name == "git" and isinstance(call.func, ast.Name):
            sub = call.args[1] if len(call.args) > 1 else None
            if not (isinstance(sub, ast.Constant) and isinstance(sub.value, str)):
                found.append("calls git with a subcommand that is not a literal")
            elif sub.value not in cls.READ_ONLY_GIT:
                found.append(f"calls git {sub.value}")
            elif sub.value == "config" and "--get-all" not in strings:
                found.append("calls git config without --get-all")
            elif sub.value == "worktree" and "list" not in strings:
                found.append("calls git worktree without list")
        return found

    def test_the_runner_makes_no_workspace_and_destroys_nothing(self):
        self.assertEqual([], self.ephemeral(self.SOURCE))

    # The one way the runner changes the checkout: the startup fast-forward (`git fetch` of one commit, `git merge --ff-only`
    # of it) and the switch to origin's default branch (a local, unforced `git fetch .` that moves the branch, `git switch`
    # of it), all through `git_change`, which allows those three and builds their `-c` options itself. Each call site
    # spells the flags that keep the call narrow, and no git command line is spelled anywhere else.
    GIT_CHANGES = {"fetch": {"--no-tags", "--no-recurse-submodules", "--no-auto-maintenance", "--no-prune",
                             "--no-write-fetch-head", "--atomic"},
                   "merge": {"--ff-only", "--no-squash", "--no-overwrite-ignore", "--no-autostash"},
                   "switch": {"--no-guess", "--no-recurse-submodules", "--no-overwrite-ignore", "--"}}
    # What no call of the writer may pass: forcing, discarding or merging a work tree, creating or detaching a branch,
    # tracking, and using a branch another work tree holds.
    NEVER_PASSED = {"--force", "-f", "--discard-changes", "--merge", "-m", "-c", "-C", "-B", "--detach", "--orphan",
                    "--track", "-t", "--ignore-other-worktrees"}
    GIT_SPELLERS = {"git", "git_change"}  # the only functions that may spell a git command line
    CHANGE_OPTIONS = {"core.hooksPath=/dev/null", "maintenance.auto=false", "GIT_TERMINAL_PROMPT", "GIT_NO_LAZY_FETCH"}

    @classmethod
    def writers(cls, source):
        """What in `source` could change a checkout beyond the two allowed git calls, or change it without their flags."""
        tree = ast.parse(source)
        parents = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}

        def inside(node):
            while node in parents:
                node = parents[node]
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    return node.name
            return None
        found, seen = [], set()
        for node in ast.walk(tree):
            if isinstance(node, (ast.List, ast.Tuple)) and node.elts and isinstance(node.elts[0], ast.Constant) \
                    and node.elts[0].value == "git" and inside(node) not in cls.GIT_SPELLERS:
                found.append("spells a git command line outside git() and git_change()")
            if not isinstance(node, ast.Call):
                continue
            name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", None)
            if name in cls.SPAWNS and node.args and isinstance(node.args[0], ast.Constant) \
                    and isinstance(node.args[0].value, str) and node.args[0].value.split(" ")[0] == "git" \
                    and inside(node) not in cls.GIT_SPELLERS:
                found.append("runs a git command line given as a string")
            if name == "git_change" and isinstance(node.func, ast.Name):
                sub = node.args[1] if len(node.args) > 1 else None
                if not (isinstance(sub, ast.Constant) and isinstance(sub.value, str)):
                    found.append("calls git_change with a subcommand that is not a literal")
                    continue
                seen.add(sub.value)
                if sub.value not in cls.GIT_CHANGES:
                    found.append(f"calls git_change {sub.value}")
                    continue
                spelled = {arg.value for arg in node.args[2:] if isinstance(arg, ast.Constant)}
                found += [f"git_change {sub.value} lacks {flag}" for flag in sorted(cls.GIT_CHANGES[sub.value] - spelled)]
                found += [f"git_change {sub.value} passes {flag}" for flag in sorted(spelled & cls.NEVER_PASSED)]
                if sub.value == "fetch":
                    found += cls.fetch_problems(node.args[2:])
            if name == "git" and isinstance(node.func, ast.Name) and len(node.args) > 1 \
                    and isinstance(node.args[1], ast.Constant) and node.args[1].value in cls.GIT_CHANGES:
                found.append(f"calls git {node.args[1].value} through git(), which is read-only")
        for function in (n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == "git_change"):
            strings = {n.value for n in ast.walk(function) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
            strings |= {kw.arg for n in ast.walk(function) if isinstance(n, ast.Call) for kw in n.keywords}
            found += [f"git_change does not set {option}" for option in sorted(cls.CHANGE_OPTIONS - strings)]
        return sorted(set(found)), seen

    @staticmethod
    def fetch_problems(args):
        """What is wrong with the arguments of a `git_change(.., 'fetch', ..)`: it fetches from origin, or from this very
        repository (`.`, to move the default branch), and a refspec into refs/heads/ is not forced (git then checks the
        fast-forward itself)."""
        plain = [a for a in args if not (isinstance(a, ast.Constant) and isinstance(a.value, str) and a.value.startswith("-"))]
        found = []
        if not plain or not (isinstance(plain[0], ast.Constant) and plain[0].value in ("origin", ".")):
            found.append("git_change fetch fetches from something other than origin or .")
        for spec in plain[1:]:
            parts = spec.values if isinstance(spec, ast.JoinedStr) else [spec]
            text = "".join(p.value for p in parts if isinstance(p, ast.Constant) and isinstance(p.value, str))
            if "refs/heads/" in text and isinstance(parts[0], ast.Constant) and str(parts[0].value).startswith("+"):
                found.append("git_change fetch forces a ref in refs/heads/")
        return found

    def test_the_runner_changes_the_checkout_only_by_fetching_fast_forwarding_and_switching_with_the_flags_that_narrow_them(self):
        problems, seen = self.writers(self.SOURCE)
        self.assertEqual([], problems)
        self.assertEqual(set(self.GIT_CHANGES), seen, "all three calls are made, and nothing else")
        for sub, count in (("fetch", 2), ("merge", 1), ("switch", 1)):
            calls = [n for n in ast.walk(ast.parse(self.SOURCE)) if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
                     and n.func.id == "git_change" and n.args[1].value == sub]
            self.assertEqual(count, len(calls), f"the call sites of git_change {sub}")

    def test_the_writer_guard_rejects_every_other_way_to_change_a_checkout(self):
        ok = (f"def git_change(cwd, sub, *args):\n    a = ['git', '-c', 'core.hooksPath=/dev/null', '-c', "
              f"'maintenance.auto=false', sub, *args]\n    e = ('GIT_TERMINAL_PROMPT', 'GIT_NO_LAZY_FETCH')\n"
              "def git(cwd, *args):\n    return run(['git', *args])\n"
              "git_change(p, 'fetch', '--no-tags', '--no-recurse-submodules', '--no-auto-maintenance', '--no-prune', "
              "'--no-write-fetch-head', '--atomic', 'origin', f'+{tip}:refs/remotes/origin/{b}')\n"
              "git_change(p, 'fetch', '--no-tags', '--no-recurse-submodules', '--no-auto-maintenance', '--no-prune', "
              "'--no-write-fetch-head', '--atomic', '.', f'{tip}:refs/heads/{b}')\n"
              "git_change(p, 'merge', '--ff-only', '--no-squash', '--no-overwrite-ignore', '--no-autostash', '-q', tip)\n"
              "git_change(p, 'switch', '--no-guess', '--no-recurse-submodules', '--no-overwrite-ignore', '-q', '--', b)\n")
        self.assertEqual(([], {"fetch", "merge", "switch"}), self.writers(ok), "control: the calls, as the runner makes them")
        for case, extra, expected in (
                ("git pull through the writer", "git_change(p, 'pull', '--ff-only')\n", "calls git_change pull"),
                ("git reset through the writer", "git_change(p, 'reset', '--hard')\n", "calls git_change reset"),
                ("a subcommand that is computed", "git_change(p, verb, '--ff-only')\n",
                 "calls git_change with a subcommand that is not a literal"),
                ("a fetch that may fetch tags", ok.replace("'--no-tags', ", ""), "git_change fetch lacks --no-tags"),
                ("a fetch that may recurse", ok.replace("'--no-recurse-submodules', ", ""),
                 "git_change fetch lacks --no-recurse-submodules"),
                ("a fetch that may run maintenance", ok.replace("'--no-auto-maintenance', ", ""),
                 "git_change fetch lacks --no-auto-maintenance"),
                ("a fetch that writes FETCH_HEAD", ok.replace("'--no-write-fetch-head', ", ""),
                 "git_change fetch lacks --no-write-fetch-head"),
                ("a fetch that is not atomic", ok.replace("'--atomic', ", ""), "git_change fetch lacks --atomic"),
                ("a switch that may create a branch", ok.replace("'--no-guess', ", ""), "git_change switch lacks --no-guess"),
                ("a switch that follows submodules", ok.replace("'--no-recurse-submodules', '--no-overwrite-ignore', '-q'",
                                                              "'--no-overwrite-ignore', '-q'"),
                 "git_change switch lacks --no-recurse-submodules"),
                ("a switch that may overwrite ignored files", ok.replace("'switch', '--no-guess', '--no-recurse-submodules', "
                                                                        "'--no-overwrite-ignore', ", "'switch', '--no-guess', "
                                                                        "'--no-recurse-submodules', "),
                 "git_change switch lacks --no-overwrite-ignore"),
                ("a switch name that could be a path", ok.replace("'-q', '--', b", "'-q', b"), "git_change switch lacks --"),
                ("a forced switch", ok.replace("'-q', '--', b", "'--force', '-q', '--', b"), "git_change switch passes --force"),
                ("a switch that throws changes away", ok.replace("'-q', '--', b", "'--discard-changes', '-q', '--', b"),
                 "git_change switch passes --discard-changes"),
                ("a switch that merges", ok.replace("'-q', '--', b", "'--merge', '-q', '--', b"),
                 "git_change switch passes --merge"),
                ("a switch that resets a branch", ok.replace("'-q', '--', b", "'-C', '-q', '--', b"),
                 "git_change switch passes -C"),
                ("a switch that detaches", ok.replace("'-q', '--', b", "'--detach', '-q', '--', b"),
                 "git_change switch passes --detach"),
                ("a switch that ignores other work trees", ok.replace("'-q', '--', b", "'--ignore-other-worktrees', '-q', '--', b"),
                 "git_change switch passes --ignore-other-worktrees"),
                ("a forced fetch", ok.replace("'--atomic', '.', f'{tip}:refs/heads/{b}'", "'--force', '--atomic', '.', "
                                              "f'{tip}:refs/heads/{b}'"), "git_change fetch passes --force"),
                ("a fetch into refs/heads that forces", ok.replace("f'{tip}:refs/heads/{b}'", "f'+{tip}:refs/heads/{b}'"),
                 "git_change fetch forces a ref in refs/heads/"),
                ("a fetch from another remote", ok.replace("'--atomic', '.', ", "'--atomic', 'upstream', "),
                 "git_change fetch fetches from something other than origin or ."),
                ("git checkout through the writer", "git_change(p, 'checkout', 'main')\n", "calls git_change checkout"),
                ("git update-ref through the writer", "git_change(p, 'update-ref', 'refs/heads/main', tip)\n",
                 "calls git_change update-ref"),
                ("git branch -f through the writer", "git_change(p, 'branch', '-f', 'main', tip)\n", "calls git_change branch"),

                ("a merge that may merge", ok.replace("'--ff-only', ", ""), "git_change merge lacks --ff-only"),
                ("a merge that may squash", ok.replace("'--no-squash', ", ""), "git_change merge lacks --no-squash"),
                ("a merge that may overwrite ignored files", ok.replace("'--no-overwrite-ignore', ", ""),
                 "git_change merge lacks --no-overwrite-ignore"),
                ("a writer that leaves hooks on", ok.replace("'core.hooksPath=/dev/null'", "'x'"),
                 "git_change does not set core.hooksPath=/dev/null"),
                ("a writer that may prompt", ok.replace("'GIT_TERMINAL_PROMPT', ", ""),
                 "git_change does not set GIT_TERMINAL_PROMPT"),
                ("git fetch through git()", "git(cwd, 'fetch', 'origin')\n", "calls git fetch through git(), which is read-only"),
                ("git merge through git()", "git(cwd, 'merge', tip)\n", "calls git merge through git(), which is read-only"),
                ("run with a git list", "run(['git', 'reset'])\n", "spells a git command line outside git() and git_change()"),
                ("a list held in a variable", "argv = ['git', 'clean', '-fdx']\nrun(argv)\n",
                 "spells a git command line outside git() and git_change()"),
                ("Popen with a git tuple", "subprocess.Popen(('git', 'checkout', 'x'))\n",
                 "spells a git command line outside git() and git_change()"),
                ("a shell string", "subprocess.run('git reset --hard', shell=True)\n",
                 "runs a git command line given as a string")):
            with self.subTest(case=case):
                source = extra if extra.startswith("def git_change") else ok + extra
                self.assertIn(expected, "; ".join(self.writers(source)[0]))

    def test_the_guard_rejects_every_way_to_make_a_workspace_or_destroy_one(self):
        good = ("import os, shutil, subprocess\nfrom pathlib import Path\n"
                "shutil.which('claude')\ngit(cwd, 'rev-parse', '--show-toplevel')\n"
                "git(cwd, 'config', '--get-all', '-z', 'remote.origin.url')\ncommand('tmux', 'list-panes')\n"
                "git(cwd, 'worktree', 'list', '--porcelain')\n"
                "exclude.open('a', encoding='utf-8')\npath.open('x', encoding='utf-8')\ntext.replace('a', 'b')\n"
                "def remove_task_directory(base, nonce):\n    os.unlink(name, dir_fd=fd)\n    os.rmdir(nonce, dir_fd=base)\n")
        self.assertEqual([], self.ephemeral(good), "control: what the runner does is accepted")
        elsewhere = lambda body, name="remove_task_directories": f"def {name}(base, nonce):\n    {body}\n"
        for case, extra, expected in (
                ("a temporary directory", "import tempfile\n", "imports tempfile"),
                ("one from the module", "from tempfile import mkdtemp\n", "imports from tempfile"),
                ("rmtree", "shutil.rmtree(path)\n", "uses rmtree"),
                ("rmtree by name", "from shutil import rmtree\n", "imports rmtree from shutil"),
                ("another shutil call", "shutil.move(a, b)\n", "uses shutil.move"),
                ("unlink", "path.unlink()\n", "uses unlink"),
                ("rmdir", "path.rmdir()\n", "uses rmdir"),
                ("os.remove", "os.remove(path)\n", "uses os.remove"),
                ("os.replace", "os.replace(a, b)\n", "uses os.replace"),
                ("a truncating open", "open(path, 'w')\n", "opens a file for writing over it"),
                ("a truncating Path.open", "path.open('w+')\n", "opens a file for writing over it"),
                ("write_text", "path.write_text('x')\n", "uses write_text"),
                ("a clone", "command('gh', 'repo', 'clone', url, path)\n", "runs gh"),
                ("gh through subprocess", "subprocess.run(['gh', 'pr', 'ready'])\n", "runs gh"),
                ("git through command", "command('git', 'status', cwd=path)\n", "calls git through command()"),
                ("git reset", "git(cwd, 'reset', '--hard')\n", "calls git reset"),
                ("git clean", "git(cwd, 'clean', '-fdx')\n", "calls git clean"),
                ("git stash", "git(cwd, 'stash', 'push')\n", "calls git stash"),
                ("git checkout", "git(cwd, 'checkout', 'main')\n", "calls git checkout"),
                ("git status", "git(cwd, 'status')\n", "calls git status"),
                ("git worktree without list", "git(cwd, 'worktree', 'remove', path)\n", "calls git worktree without list"),
                ("git update-ref", "git(cwd, 'update-ref', 'refs/heads/main', tip)\n", "calls git update-ref"),
                ("git branch", "git(cwd, 'branch', '-f', 'main', tip)\n", "calls git branch"),
                ("git restore", "git(cwd, 'restore', '.')\n", "calls git restore"),
                ("git rebase", "git(cwd, 'rebase', tip)\n", "calls git rebase"),
                ("git read-tree", "git(cwd, 'read-tree', '-u', tip)\n", "calls git read-tree"),
                ("git pull", "git(cwd, 'pull')\n", "calls git pull"),
                ("git clone", "git(cwd, 'clone', url)\n", "calls git clone"),
                ("git config that writes", "git(cwd, 'config', 'user.name', 'x')\n", "calls git config without --get-all"),
                ("a subcommand that is computed", "git(cwd, verb)\n", "calls git with a subcommand that is not a literal"),
                # the sanctioned deletion is that and no more (kjelly/pilot#442)
                ("the same unlink in another function", elsewhere("os.unlink(name, dir_fd=fd)"), "uses unlink"),
                ("the same rmdir in another function", elsewhere("os.rmdir(nonce, dir_fd=base)"), "uses rmdir"),
                ("the same unlink at the top of the module", "os.unlink(name, dir_fd=fd)\n", "uses unlink"),
                ("a method of that name", "class C:\n    def remove_task_directory(self):\n        os.unlink(name, dir_fd=fd)\n",
                 "uses unlink"),
                ("an unlink inside it that is not through a descriptor", elsewhere("os.unlink(name)", "remove_task_directory"),
                 "uses unlink"),
                ("an rmdir by path inside it", elsewhere("os.rmdir(path)", "remove_task_directory"), "uses rmdir"),
                ("a Path.unlink inside it", elsewhere("path.unlink()", "remove_task_directory"), "uses unlink"),
                ("a Path.rmdir inside it", elsewhere("path.rmdir()", "remove_task_directory"), "uses rmdir"),
                ("an unlink of another receiver inside it", elsewhere("link.unlink(name, dir_fd=fd)", "remove_task_directory"),
                 "uses unlink"),
                ("an rmtree inside it", elsewhere("shutil.rmtree(path)", "remove_task_directory"), "uses rmtree"),
                ("os.remove inside it", elsewhere("os.remove(name, dir_fd=fd)", "remove_task_directory"), "uses os.remove"),
                ("os.removedirs inside it", elsewhere("os.removedirs(path)", "remove_task_directory"), "uses removedirs"),
                ("a write inside it", elsewhere("path.write_text('x')", "remove_task_directory"), "uses write_text"),
                ("os.rename inside it", elsewhere("os.rename(a, b)", "remove_task_directory"), "uses os.rename")):
            with self.subTest(case=case):
                self.assertIn(expected, "; ".join(self.ephemeral(good + extra)))
        self.assertEqual([], self.ephemeral(good.replace("def remove_task_directory(base, nonce):\n    os.unlink(name, dir_fd=fd)"
                                                         "\n    os.rmdir(nonce, dir_fd=base)\n", "def remove_task_directory(base, "
                                                         "nonce):\n    for name in names:\n        os.unlink(name, dir_fd=fd)\n"
                                                         "    os.rmdir(nonce, dir_fd=base)\n")), "control: in a loop, as the runner does it")

    def test_the_only_deletion_is_the_removal_of_a_task_directory_through_the_descriptors_of_that_directory(self):
        tree = ast.parse(self.SOURCE)
        removers = [node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == self.REMOVER]
        self.assertEqual(1, len(removers), "one function, at the top level of the module")
        allowed = self.sanctioned(tree)
        called = sorted(node.func.attr for node in ast.walk(removers[0])
                        if isinstance(node, ast.Call) and id(node.func) in allowed)
        self.assertEqual(["rmdir", "unlink"], called, "one unlink (of each of the two files) and ONE rmdir, nothing else")
        every = [node for node in ast.walk(tree) if isinstance(node, ast.Attribute) and node.attr in self.DELETES_ANYWHERE]
        self.assertEqual({id(node) for node in every}, allowed, "no unlink and no rmdir anywhere else in the runner")
        self.assertNotIn("rmtree", self.SOURCE)

    # The runner closes only panes it started, one pane at a time, and never kills, renames or reuses a window or a session
    # (kjelly/pilot#425): every tmux subcommand it names is on this list, spelled out, and none of them kills or renames
    # anything but a pane. A new subcommand is a change to this list, and a reviewer reads it.
    TMUX_ALLOWED = {"new-session", "new-window", "set-option", "show-options", "list-panes", "display-message",
                    "capture-pane", "load-buffer", "paste-buffer", "delete-buffer", "send-keys", "kill-pane"}
    TMUX_NEVER = {"kill-session", "kill-window", "kill-server", "rename-session", "rename-window", "respawn-pane",
                  "respawn-window", "move-window", "link-window", "unlink-window", "swap-window", "attach-session",
                  "switch-client", "detach-client", "source-file", "run-shell", "if-shell"}

    @classmethod
    def tmux_calls(cls, source):
        """`(the subcommands the source names in a call of tmux, what is wrong with them)`: a call is `command("tmux", ...)`,
        `run(["tmux", ...])` and the like (`SPAWNS`); a subcommand that is not a literal string, or not on the list, is wrong,
        and so is a string equal to a subcommand that kills or renames, wherever it stands (a variable that holds it)."""
        named, found = set(), []
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Call):
                name = node.func.id if isinstance(node.func, ast.Name) else getattr(node.func, "attr", None)
                first = node.args[0] if node.args else None
                words = first.elts if isinstance(first, (ast.List, ast.Tuple)) else node.args
                if name in cls.SPAWNS and words and isinstance(words[0], ast.Constant) and words[0].value == "tmux":
                    sub = words[1] if len(words) > 1 else None
                    if not (isinstance(sub, ast.Constant) and isinstance(sub.value, str)):
                        found.append("calls tmux with a subcommand that is not a literal")
                    else:
                        named.add(sub.value)
                        if sub.value not in cls.TMUX_ALLOWED:
                            found.append(f"calls tmux {sub.value}")
            elif isinstance(node, ast.Constant) and isinstance(node.value, str) and \
                    (node.value in cls.TMUX_NEVER or node.value.startswith("rename-")):
                found.append(f"names the tmux subcommand {node.value}")
        return named, sorted(set(found))

    def test_the_runner_names_only_the_tmux_subcommands_it_may_and_each_of_them(self):
        named, problems = self.tmux_calls(self.SOURCE)
        self.assertEqual([], problems)
        self.assertEqual(self.TMUX_ALLOWED, named, "the list names exactly what the runner calls: no spare entry, no gap")

    def test_the_tmux_guard_rejects_what_kills_renames_or_cannot_be_read(self):
        good = ("command('tmux', 'kill-pane', '-t', pane)\nrun(['tmux', 'new-window', '-d'])\n"
                "subprocess.run(['tmux', 'list-panes', '-a'])\ntext = 'kill the pane'\n")
        self.assertEqual([], self.tmux_calls(good)[1], "control: what the runner does is accepted")
        self.assertEqual({"kill-pane", "new-window", "list-panes"}, self.tmux_calls(good)[0])
        for case, extra, expected in (
                ("kill-session", "command('tmux', 'kill-session', '-t', s)\n", "calls tmux kill-session"),
                ("kill-window", "command('tmux', 'kill-window', '-t', w)\n", "calls tmux kill-window"),
                ("kill-server", "run(['tmux', 'kill-server'])\n", "calls tmux kill-server"),
                ("rename-session", "command('tmux', 'rename-session', 'x')\n", "calls tmux rename-session"),
                ("rename-window", "run(('tmux', 'rename-window', 'x'))\n", "calls tmux rename-window"),
                ("a rename of any kind", "command('tmux', 'rename-anything', 'x')\n", "calls tmux rename-anything"),
                ("through subprocess", "subprocess.run(['tmux', 'kill-window'])\nPopen(['tmux', 'kill-session'])\n",
                 "calls tmux kill-window"),
                ("a subcommand that is computed", "command('tmux', verb, '-t', pane)\n",
                 "calls tmux with a subcommand that is not a literal"),
                ("a subcommand that is built", "command('tmux', 'kill-' + what)\n",
                 "calls tmux with a subcommand that is not a literal"),
                ("a subcommand that is formatted", "command('tmux', f'kill-{what}')\n",
                 "calls tmux with a subcommand that is not a literal"),
                ("a list that is unpacked", "run(['tmux', *rest])\n", "calls tmux with a subcommand that is not a literal"),
                ("no subcommand", "run(['tmux'])\n", "calls tmux with a subcommand that is not a literal"),
                ("a subcommand that is not on the list", "command('tmux', 'attach-session', '-t', s)\n",
                 "calls tmux attach-session"),
                ("the word held in a variable", "VERB = 'kill-session'\nrun([TMUX, VERB])\n",
                 "names the tmux subcommand kill-session"),
                ("the word in a table", "KILL = {'window': 'kill-window'}\n", "names the tmux subcommand kill-window"),
                ("a rename held in a variable", "VERB = 'rename-window'\n", "names the tmux subcommand rename-window")):
            with self.subTest(case=case):
                self.assertIn(expected, "; ".join(self.tmux_calls(good + extra)[1]))

    def test_the_task_directory_is_named_once_in_the_shared_module(self):
        tree = ast.parse(self.SOURCE)
        imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
                    and node.module == "pr_loop_result" for alias in node.names}
        self.assertIn("TASK_DIR", imported)
        spelled = [node.value for node in ast.walk(tree) if isinstance(node, ast.Constant)
                   and isinstance(node.value, str) and (".pr-loop" in node.value or "tmux-ai" in node.value)]
        self.assertEqual([], spelled, "scripts/pr_loop.py must use pr_loop_result.TASK_DIR, not spell the layout")


class DocumentationTests(unittest.TestCase):
    """What the runner's document (`DOC`), the runner's own docstring and the two skills that name it say is true of a
    runner that starts its agents in the operator's own checkout (class `ephemeral-agent-workspace`, kjelly/pilot#423). The
    words of the design it replaced (a managed clone, a trust dialog the operator answers in the printed session,
    `.git/info/exclude`) must not come back, and the document must say what `--checkout` defaults to and what the runner
    does in a directory the agents do not trust. They must also say where the agents run (kjelly/pilot#425): one tmux
    session per checkout, one window per agent, how to watch it and how to close what a stop keeps, and say it the way the
    code does (the lines the runner prints are read from the code, not copied). Text is compared with its white space
    collapsed: the document is hard-wrapped.

    The document lives under `.agents/skills/` (kjelly/pilot#438), where a change to it takes the `skills` CI profile; the
    root README keeps a pointer to it, and `pointer_problems` keeps that pointer short enough that a runner change never
    needs a README edit (the root README is `full`)."""
    # The runner's document and its H1: the whole file is the text that is pinned to the runner.
    DOC = ".agents/skills/_shared/pr-loop.md"
    DOC_HEADING = "# Process a batch of pull requests"
    # The README keeps a section with this heading, as a pointer to DOC (the heading is an anchor other pages may link to).
    HEADING = "## Process a batch of pull requests"
    # The command the README pointer shows, the runner's entry point.
    POINTER_COMMAND = "python3 scripts/pr_loop.py"
    # The most the README pointer may say, with its white space collapsed: a pointer, not a second copy of DOC.
    POINTER_MAX = 1000
    SKILLS = ("pr-ready", "pr-review-merge")
    EXCLUDE_FILE = "git rev-parse --git-path info/exclude"
    # What the replaced design said, or an over-broad claim about the trust dialog, and no longer holds. The runner DOES
    # recognise a screen whose options are numbered (`CHOICE`) and waits instead of typing into it; it takes a dialog
    # whose options are not numbered (claude's) for the input prompt.
    STALE = ("Managed checkout", "answer it in the printed tmux session", ".git/info/exclude",
             "cannot recognise a trust dialog", "cannot recognize a trust dialog",
             # the session design of before kjelly/pilot#425: one session per agent, a PR's panes closed at its merge
             "closes that PR's agent panes", "prints each pane and its session", "close those panes before the next run",
             "(session `pilot-pr-*`)", "(sessions pilot-pr-*)",
             # the claim of db19ac69, which the runner does not keep: it adds windows to a session an earlier run left
             "reuses a window or a session",
             # the checkout before it was fast-forwarded (kjelly/pilot#425): the runner does update it now, in
             # one way, and a checkout behind origin is no longer something to pull by hand
             "the runner never updates the checkout", "run `git pull --ff-only` yourself: the runner never",
             "The runner never deletes, resets, cleans or stashes anything", "Everything here READS it, except two things",
             "at origin's tip, or the runner refuses",
             # the default of --phase-timeout before it became four hours (a Draft phase that fixes a review finding, runs the
             # checks and waits for CI took about two and a half hours)
             "defaults to 7200 seconds", "(7200 seconds by default)",
             # the checkout on another branch (kjelly/pilot#425): the runner leaves it for the default branch and says how
             # to go back; the old requirement and the old advice about an interrupted agent no longer hold
             "HEAD is on the default branch that `origin` itself reports", "may leave the checkout on a PR branch or with "
             "uncommitted work; the next run refuses it", "not on main, the default branch of origin",
             "must be clean, on the default branch of origin, at origin's tip",
             # what the runner promised before `--clean` (kjelly/pilot#442): it deletes a task directory when asked, and closes
             # panes it did not start in this run, so these sentences are no longer true
             "and it never deletes the task files", "and it closes only panes it started in this run")
    # What DOC must say: the option and its default (the runner's own words), the way to update a stale
    # checkout, where the ignore lines go, and what the runner does in a directory the agents do not trust.
    DOC_SAYS = ("--checkout DIR", pr_loop.CHECKOUT_DEFAULT, "git pull --ff-only", EXCLUDE_FILE,
                "must already trust the checkout", "stops at a trust dialog only when its options are numbered",
                # where the agents run (kjelly/pilot#425): the name rule (the cut is the code's constant), how to watch
                # (from outside tmux, and from inside it, where that fails), how to close what a stop keeps (the `=`
                # matters), the environment the windows get, and the one tmux version this was verified on
                "pilot-pr-<directory name>-<8 hex>", f"at most {pr_loop.SESSION_LABEL_MAX} characters",
                "tmux attach -r -t", "sessions should be nested with care", "tmux switch-client -t", "prefix s",
                "tmux kill-pane -t %N", "tmux kill-session -t =", "update-environment", "verified on tmux 3.8",
                # what the runner does and does not do to windows and sessions, and why it checks a pane before it kills it
                "never kills or renames a window or a session", "still that pane on the same tmux server",
                "adds a window to the session named for the checkout when that exists", "glob pattern",
                # the fast-forward: what it fetches and merges, what it leaves alone, what refuses it, and that it is startup only
                "strictly behind", "fast-forwarded by the runner, at startup only", "by its SHA", "git merge --ff-only",
                "hooks and automatic maintenance switched off", "ORIG_HEAD", "does not move a submodule",
                "write into an ignored path", "is a partial clone", "Apart from the fast-forward at startup",
                # the switch from another branch: when, what it runs, what it never does, what refuses it, how to go back
                "another clean branch that the runner leaves for it", "is switched to the default branch",
                "is not switched back when the run ends", "git fetch . <tip>:refs/heads/<b>", "never forced",
                "git switch --no-guess --no-recurse-submodules --no-overwrite-ignore -- <b>",
                "never created", "also a prunable one", "to go back: git -C <path> switch <x>",
                "leaves for the default branch (the branch and its commits stay)",
                # `--clean` (kjelly/pilot#442): the four flags, what each does and does not, which panes are the runner's, when a
                # pane is idle, what is closed and in what way, what is removed and in what way, and what it cannot know
                "It is not `git clean`", "reads no GitHub (no `gh` call)", "`--yes` is the confirmation: nothing asks again",
                "`--include-busy` and `--remove-task-dirs` without `--yes` are still a listing",
                "`--yes`, `--include-busy` and `--remove-task-dirs` without `--clean` are errors",
                "never builds the checkout the way a run does", "`<PR>-draft` or `<PR>-ready`",
                "its start command is `exec <absolute path>`", "the real paths are equal",
                "at least a second apart", "Busy panes are closed only with `--include-busy`",
                "each with `kill-pane` on its ID and never a window or a session",
                "a pane started again with `respawn-pane` is not closed", "It never closes the pane the command runs in",
                "the lock is held by this run", "never a recursive delete", "do not paste a listing into GitHub or a chat")
    # What DOC says about --phase-timeout: the default the runner has (read from the code and spelled out) and why
    PHASE_TIMEOUT_SAYS = (f"defaults to {pr_loop.PHASE_TIMEOUT} seconds (4 hours)", "defaults to 14400 seconds (4 hours)",
                          "can take more than two hours", f"({pr_loop.PHASE_TIMEOUT} seconds by default)",
                          "(14400 seconds by default)")
    # What the runner's docstring says about the session, which `--help` shows
    DOCSTRING_SAYS = ("pilot-pr-<directory name>-<8 hex>", "tmux attach -r -t", "is fast-forwarded to exactly the tip",
                      "one `git merge --ff-only`", "it switches the checkout to origin's default branch",
                      "never switches it back",
                      "never kills or renames a window or a session",
                      "adds a window to the session named for the checkout when that exists",
                      "still that pane on the same tmux server",
                      "`--clean --yes` takes the checkout's lock and closes the dead and idle panes",
                      "it never closes the pane the command itself runs in", "It never touches the git checkout",
                      "`--remove-task-dirs` removes the task directories of finished runs")

    @staticmethod
    def flat(text):
        return " ".join(text.split())

    @classmethod
    def raw_section(cls, readme):
        """The README's batch section as written, from its heading to the next `## ` heading; None without the heading."""
        found = re.search(rf"^{re.escape(cls.HEADING)}[ \t]*$(.*?)(?=^## |\Z)", readme, re.M | re.S)
        return found.group(1) if found else None

    @classmethod
    def section(cls, readme):
        """The README's batch section (the pointer to DOC), flattened; None without the heading."""
        raw = cls.raw_section(readme)
        return None if raw is None else cls.flat(raw)

    @classmethod
    def doc_body(cls, text):
        """What follows the H1 of the runner's document, to the END of the text (a sub-heading does not end the scan, so
        nothing below one can escape it), flattened; None when the text does not start with the H1."""
        found = re.match(rf"\A{re.escape(cls.DOC_HEADING)}[ \t]*$(.*)\Z", text, re.M | re.S)
        return cls.flat(found.group(1)) if found else None

    def doc_section(self, root=None):
        """The runner's document (`DOC` below `root`, the repository by default): its whole text, flattened. Fails, as a
        test, when the file is missing or no longer starts with its H1: a check that read nothing must not pass."""
        path = (ROOT if root is None else Path(root)) / self.DOC
        self.assertTrue(path.is_file(), f"{self.DOC} is missing: the check scanned nothing")
        body = self.doc_body(path.read_text())
        self.assertIsNotNone(body, f"{self.DOC} does not start with {self.DOC_HEADING!r}: the check scanned nothing")
        return body

    @staticmethod
    def tracked_files():
        """The repository's tracked files, relative to its root (`git ls-files -z`): untracked and ignored files are not."""
        done = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, check=True, timeout=60)
        return {name.decode() for name in done.stdout.split(b"\0") if name}

    @classmethod
    def pointer_problems(cls, readme_text, tracked_files):
        """What is wrong with the README's pointer to DOC: no section with HEADING; no `python3 scripts/pr_loop.py` command
        in a fenced code block; no link to DOC; a link to a file `tracked_files` does not hold (a link in a tracked document
        must resolve to a tracked file); a phrase the tests pin to the runner (DOC_SAYS, PHASE_TIMEOUT_SAYS or a line the
        runner prints) restated, which would make the next runner change a README change again; a section longer than
        POINTER_MAX characters, white space collapsed. [] when the pointer is as it must be."""
        raw = cls.raw_section(readme_text)
        if raw is None:
            return [f"README.md has no section {cls.HEADING!r}"]
        flat, tracked, problems = cls.flat(raw), set(tracked_files), []
        fenced = re.findall(r"^(?:```|~~~)[^\n]*\n(.*?)^(?:```|~~~)[ \t]*$", raw, re.M | re.S)
        if not any(cls.POINTER_COMMAND in block for block in fenced):
            problems.append(f"the section has no {cls.POINTER_COMMAND!r} command in a fenced code block")
        links = list(dict.fromkeys(posixpath.normpath(link) for link in link_targets(raw)))
        if cls.DOC not in links:
            problems.append(f"the section does not link to {cls.DOC}")
        problems += [f"the section links to {link}, which is not a tracked file" for link in links if link not in tracked]
        pinned = [*cls.DOC_SAYS, *cls.PHASE_TIMEOUT_SAYS, *cls.printed_by_the_runner()]
        problems += [f"the section restates {phrase!r}, which the tests pin to the runner" for phrase in pinned
                     if phrase in flat]
        if len(flat) > cls.POINTER_MAX:
            problems.append(f"the section is {len(flat)} characters long, more than the {cls.POINTER_MAX} a pointer may be")
        return problems

    @classmethod
    def stale(cls, text):
        """What in `text` still describes the replaced design: a stale phrase, or any sentence that tells the operator to
        answer a trust dialog within `--startup-timeout` (however it is reworded)."""
        flat = cls.flat(text)
        found = [f"still says {phrase!r}" for phrase in cls.STALE if phrase in flat]
        found += [f"still tells the operator to answer a trust dialog within --startup-timeout: {sentence[:90]!r}"
                  for sentence in re.split(r"(?<=[.!?])\s+", flat)
                  if "--startup-timeout" in sentence and re.search(r"trust|answer", sentence, re.IGNORECASE)]
        return found

    @classmethod
    def missing(cls, section, phrases=None):
        phrases = cls.DOC_SAYS if phrases is None else phrases
        return [f"does not say {phrase!r}" for phrase in phrases if phrase not in cls.flat(section)]

    @staticmethod
    def printed_by_the_runner():
        """What the runner prints about its session, read from the code with placeholders for what varies: the line a real
        run prints at the start, the line a dry run prints, the line of each agent, and the refusal for a live pane."""
        told = []
        with patch.object(pr_loop, "tell", told.append):
            for dry_run in (False, True):
                where = SimpleNamespace(dry_run=dry_run, path=Path("/x/checkout"), branch="refs/heads/<branch>", head="1" * 40,
                                        would_add=[], lock_path="/x/lock", exclude="/x/exclude", session="<session>",
                                        would_forward=("1" * 40, "2" * 40, True), would_switch=None)
                pr_loop.Checkout.announce(where)
            pr_loop.Checkout.say_forwarded("<branch>", "1" * 40, "2" * 40)
            pr_loop.Checkout.announce(SimpleNamespace(dry_run=True, path=Path("/x/checkout"), branch="refs/heads/<x>",
                                                      head="3" * 40, would_add=[], lock_path="/x/lock", exclude="/x/exclude",
                                                      session="<session>", would_forward=None,
                                                      would_switch=("<x>", "3" * 40, "<b>")))
            pr_loop.Checkout.say_switched(Path("/x/checkout"), "<x>", "3" * 40, "<b>")
            wait = subprocess.CompletedProcess([], 0, "%12|4207|1700000091\n", "")
            with patch.object(pr_loop, "run", return_value=wait), patch.object(pr_loop, "command", return_value=""), \
                 patch.object(pr_loop.shutil, "which", return_value="/x/bin/claude"):
                pr_loop.Agent("claude", SimpleNamespace(path=Path("/x/checkout"), session="<session>"), 7, "draft")
        by_word = {word: [line for line in told if word in line]
                   for word in ("Agents run as", "would start", "agent: %", "Fast-forwarded", "would fetch", "would switch",
                                "Switched")}
        agent = by_word["agent: %"][0].replace("PR #7 draft agent: %12 in window 7-draft", "PR #N <phase> agent: %<id> in window "
                                                                                           "<PR>-<phase>")
        with tempfile.TemporaryDirectory() as top:
            row = pr_loop.Pane("%3", "@1", False, False, "4242", ("1", "2"), "<socket>", "pilot-pr-x-0123abcd", "7-draft", top, "",
                               top, "claude")
            with patch.object(pr_loop, "list_panes", return_value=([row], "")):
                try:
                    pr_loop.check_panes(top)
                except pr_loop.Stop as exc:
                    refusal = f"pr-loop: {exc}".replace(top, "<checkout>").replace("pilot-pr-x-0123abcd", "<session>")
                    refusal = refusal.replace("%3", "%N")
        placed = lambda line: line.replace("1" * 12, "<L12>").replace("2" * 12, "<T12>").replace("3" * 12, "<X12>")
        return [by_word["Agents run as"][0], by_word["would start"][0], agent, refusal,
                placed(by_word["Fast-forwarded"][0]), placed(by_word["would fetch"][0]),
                placed(by_word["would switch"][0]).replace("/x/checkout", "<path>"),
                placed(by_word["Switched"][0]).replace("/x/checkout", "<path>").replace("'<x>'", "<x>"),
                *DocumentationTests.cleaned_lines()]

    @staticmethod
    def cleaned_lines():
        """What `--clean` prints (kjelly/pilot#442), read from the code that formats it, with a placeholder for what varies: the
        header, a pane in each state it is told in (dead, idle, busy, one whose closing ends a session), a pane in the way that is
        not the runner's, a task directory that would be removed and one that is kept, and the summary of a listing and of a run
        that acted."""
        pane = pr_loop.Pane("%N", "@N", False, False, "1", ("1", "1"), "<socket>", "<session>", "<PR>-<phase>", "<checkout>", "",
                            "<path>", "<command>")
        task = pr_loop.TaskDir("<nonce>", "PR #<n> <phase>", 0.0, "<OUTCOME>", None, ())
        with patch.object(pr_loop, "age_text", return_value="<age>"):
            return [pr_loop.header_line("<checkout>", "<session>", "<socket>"),
                    pr_loop.pane_line(pane, pr_loop.State("dead", "", ""), "would close", "it is dead"),
                    pr_loop.pane_line(pane, pr_loop.State("idle", "at its prompt", ""), "would close", "it is idle"),
                    pr_loop.pane_line(pane, pr_loop.State("busy", "<reason>", ""), "left open",
                                      "it is busy; busy panes are closed only with --include-busy"),
                    pr_loop.pane_line(pane, pr_loop.State("idle", "at its prompt", ""), "closed", "it is idle",
                                      "window <PR>-<phase> and session <session>; an attached client is detached"),
                    pr_loop.foreign_line(pane._replace(window="<window>")),
                    pr_loop.task_line(task, "would remove", "no pane of the runner is left and it holds only its task and "
                                                           "result"),
                    pr_loop.task_line(task, "kept", "task directories are removed only with --remove-task-dirs"),
                    pr_loop.summary_line(False, "<k>", "<m>", []),
                    pr_loop.summary_line(False, "<k>", "<m>", ["%N"]),
                    pr_loop.summary_line(True, "<k>", "<m>", [])]

    @classmethod
    def skill_lines(cls, name):
        """The lines of a skill's SKILL.md that describe the task file `scripts/pr_loop.py` hands it (there must be one)."""
        text = (ROOT / ".agents" / "skills" / name / "SKILL.md").read_text()
        return [line for line in text.splitlines() if "scripts/pr_loop.py" in line and "--pr-loop-task=" in line]

    def test_the_runner_document_describes_the_checkout_the_agents_start_in(self):
        section = self.doc_section()
        self.assertGreater(len(section), 2000, f"{self.DOC} is there but nearly empty: the check scanned nothing")
        self.assertIn("python3 scripts/pr_loop.py", section, "control: this is the document about the runner")
        self.assertEqual([], self.missing(section) + self.stale(section), self.DOC)

    def test_the_runner_document_states_the_phase_timeout_the_runner_defaults_to_and_no_other(self):
        section = self.doc_section()
        self.assertEqual([], self.missing(section, self.PHASE_TIMEOUT_SAYS), self.DOC)
        self.assertNotIn("7200", section, f"the old default must not be stated anywhere in {self.DOC}")
        self.assertEqual([], [stale for stale in self.stale(section) if "7200" in stale])

    def test_the_check_fails_when_the_runner_document_states_the_old_phase_timeout(self):
        good = "The phase timeout defaults to 14400 seconds (4 hours): a phase can take more than two hours; (14400 seconds by default)."
        self.assertEqual([], self.missing(good, self.PHASE_TIMEOUT_SAYS), "control: a text that says all of it is accepted")
        self.assertEqual(len(self.PHASE_TIMEOUT_SAYS), len(self.missing("", self.PHASE_TIMEOUT_SAYS)))
        for case, text in (("the first sentence", good.replace("14400", "7200", 1)),
                           ("the parenthesis", good.replace("(14400 seconds by default)", "(7200 seconds by default)"))):
            with self.subTest(case=case):
                self.assertTrue(self.missing(text, self.PHASE_TIMEOUT_SAYS), "the new default is no longer stated")
        self.assertIn("still says 'defaults to 7200 seconds'", "; ".join(self.stale("The phase timeout defaults to 7200 seconds.")))
        self.assertIn("still says '(7200 seconds by default)'", "; ".join(self.stale("until `--phase-timeout` (7200 seconds by default).")))

    def test_the_runners_docstring_describes_the_checkout_the_agents_start_in(self):
        self.assertGreater(len(self.flat(pr_loop.__doc__ or "")), 500, "the docstring is missing: nothing was scanned")
        self.assertEqual([], self.stale(pr_loop.__doc__), "the module docstring of scripts/pr_loop.py")

    def test_the_runners_docstring_describes_the_session(self):
        self.assertEqual([], self.missing(pr_loop.__doc__, self.DOCSTRING_SAYS), "the module docstring of scripts/pr_loop.py")

    def test_the_docstrings_of_the_checkout_describe_the_fast_forward(self):
        for name, thing in (("Checkout", pr_loop.Checkout), ("Checkout.check_tip", pr_loop.Checkout.check_tip),
                            ("Checkout.verify", pr_loop.Checkout.verify), ("git_change", pr_loop.git_change),
                            ("Checkout.switch_to_default", pr_loop.Checkout.switch_to_default),
                            ("git", pr_loop.git)):
            with self.subTest(name=name):
                self.assertGreater(len(self.flat(thing.__doc__ or "")), 200, "the docstring is missing")
                self.assertEqual([], self.stale(thing.__doc__), name)
        for name, thing, phrases in (
                ("Checkout", pr_loop.Checkout, ("three things", "strictly behind origin's tip", "fast-forward", "switch",
                                                 "fetch .")),
                ("Checkout.check_tip", pr_loop.Checkout.check_tip, ("strictly behind it", "fast-forwarded", "refused")),
                ("Checkout.verify", pr_loop.Checkout.verify, ("not fast-forwarded again", "not switched back")),
                ("Checkout.switch_to_default", pr_loop.Checkout.switch_to_default,
                 ("before the first write", "git fetch .", "git switch", "never touched")),
                ("git", pr_loop.git, ("READ-ONLY", "git_change"))):
            with self.subTest(says=name):
                self.assertEqual([], self.missing(thing.__doc__, phrases), name)

    def test_the_help_of_checkout_says_the_runner_fast_forwards_it(self):
        done = subprocess.run([sys.executable, "-B", str(ROOT / "scripts" / "pr_loop.py"), "--help"], capture_output=True,
                              text=True, timeout=60)
        text = self.flat(done.stdout).replace("fast- forwards", "fast-forwards")  # (argparse wraps at the hyphen)
        self.assertEqual([], self.missing(text, ("at or strictly behind origin's tip (the runner fast-forwards it)",
                                                 "or on a branch of it (the runner switches to origin's default branch and "
                                                 "fast-forwards it to origin's tip)")))
        self.assertNotIn("at origin's tip, whose origin", text, "the old help said the checkout must be AT the tip")

    def test_the_runner_document_quotes_the_lines_the_runner_prints(self):
        section = self.doc_section()
        lines = self.printed_by_the_runner()
        self.assertEqual(19, len(lines))
        self.assertEqual(["Agents run as windows of tmux session <session>; watch them read-only with: tmux attach -r -t "
                          "<session>", "would start the agents in tmux session <session>",
                          "PR #N <phase> agent: %<id> in window <PR>-<phase> of tmux session <session>",
                          "pr-loop: agent pane %N (session <session>) is still running in <checkout>; inspect and close it "
                          "before starting the runner again (python3 scripts/pr_loop.py --clean lists what an earlier run left)",
                          "Fast-forwarded <branch> from <L12> to <T12>, origin's tip",
                          "would fetch origin's <branch> at <T12> and fast-forward <branch> from <L12> to it",
                          "would switch <path> from <x> (at <X12>) to <b>",
                          "Switched <path> from <x> (at <X12>) to <b>; to go back: git -C <path> switch <x>",
                          # `--clean` (kjelly/pilot#442): the listing, and what a run that acted says in its place
                          "Residue of earlier runs in <checkout> (tmux session <session> on <socket>):",
                          "pane %N window <PR>-<phase>: dead, <command>; would close: it is dead",
                          "pane %N window <PR>-<phase>: alive, idle (at its prompt), <command>; would close: it is idle",
                          "pane %N window <PR>-<phase>: alive, busy (<reason>), <command>; left open: it is busy; busy panes "
                          "are closed only with --include-busy",
                          "pane %N window <PR>-<phase>: alive, idle (at its prompt), <command>; closed: it is idle; closing it "
                          "ends window <PR>-<phase> and session <session>; an attached client is detached",
                          "not the runner's: pane %N (session <session>, window <window>) in <path>: left alone; the next run "
                          "refuses because of it",
                          "task <nonce>: PR #<n> <phase>, <age> old, result <OUTCOME>; would remove: no pane of the runner is "
                          "left and it holds only its task and result",
                          "task <nonce>: PR #<n> <phase>, <age> old, result <OUTCOME>; kept: task directories are removed only "
                          "with --remove-task-dirs",
                          "would close <k> panes and remove <m> task directories; the next run would start",
                          "would close <k> panes and remove <m> task directories; the next run would still be refused (%N)",
                          "closed <k> panes and removed <m> task directories; the next run would start"],
                         lines, "what the code prints, with placeholders")
        self.assertEqual([], self.missing(section, lines), self.DOC)

    def test_the_check_fails_when_the_runner_document_quotes_something_the_runner_does_not_print(self):
        lines = self.printed_by_the_runner()
        section = "The runner prints " + "; ".join(f"`{line}`" for line in lines) + "."
        self.assertEqual([], self.missing(section, lines), "control: a section that quotes every line is accepted")
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual([f"does not say {line!r}"], self.missing(section.replace(line, "..."), lines))
        reworded = section.replace("watch them read-only with", "watch them with")
        self.assertEqual(1, len(self.missing(reworded, lines)), "a line the code no longer prints that way is caught")

    def test_the_check_fails_when_the_docstring_stops_saying_what_it_must(self):
        text = "The runner " + ", ".join(self.DOCSTRING_SAYS) + "."
        self.assertEqual([], self.missing(text, self.DOCSTRING_SAYS), "control: a text that says all of it is accepted")
        for phrase in self.DOCSTRING_SAYS:
            with self.subTest(phrase=phrase):
                self.assertEqual([f"does not say {phrase!r}"],
                                 self.missing(text.replace(phrase, "..."), self.DOCSTRING_SAYS))

    def test_the_two_skills_name_the_checkouts_git_exclude_file(self):
        for name in self.SKILLS:
            with self.subTest(skill=name):
                lines = self.skill_lines(name)
                self.assertEqual(1, len(lines), f".agents/skills/{name}/SKILL.md: the line about the task file of "
                                                f"scripts/pr_loop.py was not found exactly once: nothing was scanned")
                self.assertEqual([], self.stale(lines[0]), f".agents/skills/{name}/SKILL.md")
                self.assertIn(self.EXCLUDE_FILE, self.flat(lines[0]), f".agents/skills/{name}/SKILL.md")

    def test_the_check_fails_on_every_way_the_old_words_come_back(self):
        old_readme = ("The runner hides `/.pr-loop/` and `/.pr-ready/` from `git status` through the checkout's "
                      "`.git/info/exclude` and refuses to start when git does not ignore them. A newly started agent may "
                      "ask whether to trust the new checkout directory; answer it in the printed tmux session within "
                      "`--startup-timeout`.")
        self.assertEqual([], self.stale("The runner keeps `.pr-loop/` out of git status through the checkout's git exclude "
                                        "file (`git rev-parse --git-path info/exclude`). `--startup-timeout` is how long "
                                        "the runner waits for a started agent's prompt."),
                         "control: the new wording, and `--startup-timeout` without a trust sentence, are accepted")
        for case, text, expected in (
                ("the managed checkout line", "Managed checkout: /somewhere/batch-1", "still says 'Managed checkout'"),
                ("the old trust sentence", old_readme, "still says 'answer it in the printed tmux session'"),
                ("the old exclude file", old_readme, "still says '.git/info/exclude'"),
                ("the over-broad trust claim", "The runner cannot recognise a trust dialog: it pastes its command.",
                 "still says 'cannot recognise a trust dialog'"),
                ("the over-broad trust claim, wrapped and in US spelling", "The runner cannot\nrecognize a trust\ndialog.",
                 "still says 'cannot recognize a trust dialog'"),
                ("the old trust sentence, wrapped", "answer it in\nthe printed\ntmux session",
                 "still says 'answer it in the printed tmux session'"),
                ("a reworded trust sentence", "Answer the trust prompt within `--startup-timeout`.",
                 "still tells the operator to answer a trust dialog within --startup-timeout"),
                ("a reworded sentence that names the dialog", "The agent may ask whether you trust the folder, "
                 "so wait for it for up to --startup-timeout seconds.",
                 "still tells the operator to answer a trust dialog within --startup-timeout"),
                ("the old merge sentence", "After GitHub confirms the merge, the runner closes that PR's agent panes and "
                 "starts new processes.", "still says \"closes that PR's agent panes\""),
                ("the old print sentence, wrapped", "The runner prints each pane\nand its session when it starts the agent.",
                 "still says 'prints each pane and its session'"),
                ("the old session wording", "an earlier run (session `pilot-pr-*`) is still alive",
                 "still says '(session `pilot-pr-*`)'"),
                ("the old close advice", "so close those panes before the next run.",
                 "still says 'close those panes before the next run'"),
                ("the claim it never reuses a session", "it never kills, renames or reuses a window or a session it did not "
                 "start in this run", "still says 'reuses a window or a session'"),
                ("the claim it never updates the checkout", "otherwise run `git pull --ff-only` yourself: the runner never "
                 "updates the checkout)", "still says 'the runner never updates the checkout'"),
                ("the claim, wrapped", "the runner never\nupdates the checkout", "still says 'the runner never updates the "
                 "checkout'"),
                ("the old promise of the runner", "The runner never deletes, resets, cleans or stashes anything in it.",
                 "still says 'The runner never deletes, resets, cleans or stashes anything'"),
                ("the old docstring of Checkout", "Everything here READS it, except two things: the lock",
                 "still says 'Everything here READS it, except two things'"),
                ("the old refusal sentence", "on the default branch of origin, at origin's tip, or the runner refuses",
                 "still says \"at origin's tip, or the runner refuses\""),
                ("the old requirement that HEAD is on the default branch", "nothing is uncommitted; HEAD is on the default "
                 "branch that `origin` itself reports (`git ls-remote`); that", "still says 'HEAD is on the default branch "
                 "that `origin` itself reports'"),
                ("the old advice about an interrupted agent", "An agent that was interrupted may leave the checkout on a PR "
                 "branch or with uncommitted work; the next run refuses it until you have put it right.",
                 "still says 'may leave the checkout on a PR branch or with uncommitted work; the next run refuses it'"),
                ("the old docstring requirement", "The checkout must be clean, on the default branch of origin, at origin's "
                 "tip, and its origin", "still says \"must be clean, on the default branch of origin, at origin's tip\"")):
            with self.subTest(case=case):
                self.assertIn(expected, "; ".join(self.stale(text)))

    def test_the_check_fails_when_the_runner_document_stops_saying_what_it_must(self):
        section = "The runner " + ", ".join(self.DOC_SAYS) + "."  # synthetic: this test must not depend on the document
        self.assertEqual([], self.missing(section), "control: a section that says all of it is accepted")
        for phrase in self.DOC_SAYS:
            with self.subTest(phrase=phrase):
                self.assertEqual([f"does not say {phrase!r}"], self.missing(section.replace(phrase, "...")))
        self.assertEqual(len(self.DOC_SAYS), len(self.missing("")), "an empty section says none of it")

    def test_the_check_fails_when_it_would_scan_nothing(self):
        # shaped like the README: a section that ends at the next `## ` heading (what the pointer test reads)
        readme = f"# Title\n\n{self.HEADING}\n\nAnswer it in the printed tmux session.\n\n## Command map\n\nManaged checkout\n"
        self.assertEqual("Answer it in the printed tmux session.", self.section(readme),
                         "control: the section is cut at the next heading")
        self.assertIsNone(self.section(readme.replace(self.HEADING, "## Process batches of pull requests")),
                          "a renamed heading is no section: the pointer test fails instead of passing on an empty scan")
        self.assertEqual("", self.section(f"{self.HEADING}\n\n## Command map\n"), "an empty section is empty, not None")
        self.assertEqual("", self.section(f"{self.HEADING}\n"), "a heading at the end of the file is an empty section")
        # shaped like the document: the whole file after its H1, and a sub-heading cuts nothing
        doc = f"{self.DOC_HEADING}\n\nAnswer it in the printed tmux session.\n\n## A sub-heading\n\nManaged checkout\n"
        self.assertEqual("Answer it in the printed tmux session. ## A sub-heading Managed checkout", self.doc_body(doc),
                         "control: the document is read to the end of the file, a sub-heading does not end it")
        self.assertIn("still says 'Managed checkout'", "; ".join(self.stale(self.doc_body(doc))),
                      "what stands below a sub-heading is scanned too")
        self.assertEqual("", self.doc_body(f"{self.DOC_HEADING}\n"), "a heading at the end of the file is an empty document")
        for case, text in (("a renamed H1", doc.replace(self.DOC_HEADING, "# Process batches of pull requests")),
                           ("an H1 with more on its line", doc.replace(self.DOC_HEADING, self.DOC_HEADING + " (old)")),
                           ("the heading demoted to an H2", doc.replace(self.DOC_HEADING, "#" + self.DOC_HEADING)),
                           ("text before the H1", "Some words.\n" + doc),
                           ("the README's heading", doc.replace(self.DOC_HEADING, self.HEADING)),
                           ("an empty file", "")):
            with self.subTest(case=case):
                self.assertIsNone(self.doc_body(text), "no H1, no document: doc_section fails instead of passing on a scan of nothing")
        with tempfile.TemporaryDirectory() as top:
            with self.assertRaises(AssertionError) as missing:
                self.doc_section(top)
            self.assertIn(f"{self.DOC} is missing: the check scanned nothing", str(missing.exception))
            path = Path(top) / self.DOC
            path.parent.mkdir(parents=True)
            path.write_text(doc.replace(self.DOC_HEADING, "# Process batches of pull requests"))
            with self.assertRaises(AssertionError) as renamed:
                self.doc_section(top)
            self.assertIn(f"{self.DOC} does not start with {self.DOC_HEADING!r}: the check scanned nothing", str(renamed.exception))
            path.write_text(doc)
            self.assertEqual(self.doc_body(doc), self.doc_section(top), "control: a document with its H1 is read")

    # ---- the README keeps a pointer to the document, and nothing the runner's tests pin --------------------------------

    def test_the_readme_points_to_the_runner_document(self):
        readme = (ROOT / "README.md").read_text()
        section = self.section(readme)
        self.assertIsNotNone(section, f"README.md has no section {self.HEADING!r}: the check scanned nothing")
        self.assertGreater(len(section), 100, "the section is there but nearly empty: the check scanned nothing")
        tracked = self.tracked_files()
        self.assertIn("README.md", tracked, "control: the listing of tracked files is not empty")
        self.assertEqual([], self.pointer_problems(readme, tracked), f"the pointer of README.md to {self.DOC}")

    def a_pointer(self, command="python3 scripts/pr_loop.py 371 372 --repo o/r", link=None, extra=""):
        """A README, synthetic, whose batch section is a pointer; `extra` goes at the end of its first sentence. What
        follows the section (a pinned phrase, a missing file, a long text) is not part of it and must not count."""
        link = self.DOC if link is None else link
        return (f"# Title\n\nIntro.\n\n{self.HEADING}\n\n`scripts/pr_loop.py` runs the agents.{extra}\n\n"
                f"```bash\n{command}\n```\n\nRead [the document]({link}) before the first run.\n\n## Command map\n\n"
                f"{self.DOC_SAYS[0]} and python3 scripts/pr_loop.py, see [a missing file](nowhere.md): {'long ' * 400}\n")

    def test_the_check_accepts_a_readme_pointer_that_is_one(self):
        tracked = {self.DOC, "README.md"}
        self.assertEqual([], self.pointer_problems(self.a_pointer(), tracked),
                         "control: a short section with the command and a link to the document is accepted, and what "
                         "follows it (a pinned phrase, a missing file, a long text) is not read")
        for case, text in (("an anchor on the link", self.a_pointer(link=self.DOC + "#top")),
                           ("a ./ in front of the link", self.a_pointer(link="./" + self.DOC)),
                           ("links that name no file", self.a_pointer(extra=" See [the web](https://example.org/x), [here](#top).")),
                           ("a tilde fence", self.a_pointer().replace("```bash", "~~~").replace("```\n\nRead", "~~~\n\nRead"))):
            with self.subTest(case=case):
                self.assertEqual([], self.pointer_problems(text, tracked))

    def test_the_check_fails_when_the_readme_pointer_misses_its_command_or_its_link(self):
        tracked = {self.DOC, "README.md"}
        command = ["the section has no 'python3 scripts/pr_loop.py' command in a fenced code block"]
        link = [f"the section does not link to {self.DOC}"]
        for case, text, files, expected in (
                ("no section", self.a_pointer().replace(self.HEADING, "## Process batches of pull requests"), tracked,
                 [f"README.md has no section {self.HEADING!r}"]),
                ("no command", self.a_pointer(command="scripts/pr_loop.py 371 372"), tracked, command),
                ("an empty block", self.a_pointer(command=""), tracked, command),
                ("the command in the prose only", self.a_pointer(command="", extra=" Run python3 scripts/pr_loop.py 371."),
                 tracked, command),
                ("the link as plain text", self.a_pointer().replace(f"[the document]({self.DOC})", f"the document ({self.DOC})"),
                 tracked, link),
                ("a link to another file only", self.a_pointer(link="README.md"), tracked, link),
                ("a link to a copy in another place", self.a_pointer(link="docs/the-runner.md"),
                 tracked | {"docs/the-runner.md"}, link),
                ("a link to a file that does not exist", self.a_pointer(extra=" See [more](docs/missing.md)."), tracked,
                 ["the section links to docs/missing.md, which is not a tracked file"]),
                ("a link to the document when it is not tracked", self.a_pointer(), tracked - {self.DOC},
                 [f"the section links to {self.DOC}, which is not a tracked file"])):
            with self.subTest(case=case):
                self.assertEqual(expected, self.pointer_problems(text, files))

    def test_the_check_fails_when_the_readme_pointer_restates_what_the_tests_pin(self):
        tracked = {self.DOC, "README.md"}
        pinned = [*self.DOC_SAYS, *self.PHASE_TIMEOUT_SAYS, *self.printed_by_the_runner()]
        self.assertGreater(len(pinned), 50, "the pinned phrases were not collected")
        for phrase in pinned:
            with self.subTest(pinned=phrase):
                problems = self.pointer_problems(self.a_pointer(extra=f" {phrase}"), tracked)
                self.assertIn(f"the section restates {phrase!r}, which the tests pin to the runner", problems)
                self.assertEqual([], [problem for problem in problems if "characters long" in problem], "a short section")

    def test_the_check_fails_when_the_readme_pointer_is_longer_than_a_pointer(self):
        tracked = {self.DOC, "README.md"}
        room = self.POINTER_MAX - len(self.section(self.a_pointer()))
        self.assertGreater(room, 100, "the synthetic pointer leaves no room under the cap")
        at_the_cap = self.a_pointer(extra="x" * room)
        self.assertEqual(self.POINTER_MAX, len(self.section(at_the_cap)))
        self.assertEqual([], self.pointer_problems(at_the_cap, tracked), "control: exactly the cap is accepted")
        too_long = self.a_pointer(extra="x" * (room + 1))
        self.assertEqual([f"the section is {self.POINTER_MAX + 1} characters long, more than the {self.POINTER_MAX} a pointer "
                          f"may be"], self.pointer_problems(too_long, tracked))
        spaced = self.a_pointer(extra=" word" * 400)
        self.assertEqual(1, len(self.pointer_problems(spaced, tracked)), "words that no test pins are one problem: the length")

    def test_the_runner_document_and_its_tests_take_the_skills_ci_profile(self):
        """A runner change that must edit its document or its tests is not `full` for that: the document is below
        `.agents/skills/`, which scripts/ci-impact.py takes as `skills`; the root README is `full`."""
        spec = importlib.util.spec_from_file_location("ci_impact_for_the_runner_document", ROOT / "scripts" / "ci-impact.py")
        impact = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(impact)
        tests = ".agents/skills/_shared/tests/test_pr_loop.py"
        for path in (self.DOC, tests):
            with self.subTest(path=path):
                self.assertEqual("skills", impact.path_kind(path), f"{path} must take the skills profile")
                self.assertEqual("skills", impact.classify([path]), f"a change to {path} alone must take the skills profile")
        self.assertEqual("full", impact.path_kind("README.md"), "control: the root README is why the document moved")
        self.assertEqual(impact.classify(["scripts/pr_loop.py"]), impact.classify(["scripts/pr_loop.py", self.DOC, tests]),
                         "the document and the tests add nothing to what the runner alone takes")


# ---- (C) Agent: the real class driving the fake tmux in a subprocess ----------------------------------------------

class SessionNameTests(unittest.TestCase):
    """The tmux session of a checkout (kjelly/pilot#425). tmux 3.8 keeps `.` and `:` in a session name as typed; a `:` makes
    the session impossible to address (`-t =a:b:` names the session `a`), a `.` breaks some target forms (`=a.b:` works for
    new-window and list-windows, `has-session -t =a.b` does not), a tab is refused and an empty name is accepted: the name is
    made of letters, digits, `_` and `-` only, whatever the directory is called, and it is the same on every run in a
    checkout."""
    NAME = re.compile(r"pilot-pr-[A-Za-z0-9_-]+-[0-9a-f]{8}")

    def test_the_name_is_the_prefix_the_directory_name_and_a_hash_of_the_whole_path(self):
        path = "/work/pilot"
        self.assertEqual("pilot-pr-pilot-" + hashlib.sha256(path.encode()).hexdigest()[:8], pr_loop.session_name(path))
        self.assertTrue(pr_loop.session_name(path).startswith(pr_loop.PANE_SESSION_PREFIX), "check_panes looks for it")

    def test_it_is_the_same_every_time_and_in_every_process(self):
        path = "/work/pilot"
        self.assertEqual(pr_loop.session_name(path), pr_loop.session_name(path))
        self.assertEqual(pr_loop.session_name(Path(path)), pr_loop.session_name(path), "a Path and its string agree")
        done = subprocess.run([sys.executable, "-B", "-c", "import sys; sys.path.insert(0, sys.argv[1]); import pr_loop; "
                               "print(pr_loop.session_name(sys.argv[2]))", str(ROOT / "scripts"), path],
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(pr_loop.session_name(path), done.stdout.strip(), done.stderr)

    def test_two_checkouts_with_the_same_directory_name_get_different_sessions(self):
        first, second = pr_loop.session_name("/one/pilot"), pr_loop.session_name("/two/pilot")
        self.assertNotEqual(first, second)
        self.assertEqual(first.rsplit("-", 1)[0], second.rsplit("-", 1)[0], "the label is the same: only the hash tells")

    def test_the_directory_name_is_cut_down_to_what_tmux_keeps_as_typed(self):
        for basename, label in (("pilot", "pilot"), ("my repo", "my-repo"), ("a:b", "a-b"), ("a.b", "a-b"),
                                ("tab\there", "tab-here"), ("line\nbreak", "line-break"), ("a  :  b", "a-b"),
                                ("quo'te", "quo-te"), ('dq"x', "dq-x"), ("a=b", "a-b"), ("-rf", "rf"), ("=x", "x"),
                                ("under_score-1", "under_score-1"), ("UPPER", "UPPER"), ("%x", "x"), ("a;b&c", "a-b-c"),
                                ("caf\u00e9", "caf"), ("\u65e5\u672c", "checkout"), ("..", "checkout"),
                                ("---", "checkout"), ("x" * 40, "x" * 24), ("a" * 23 + "-b", "a" * 23),
                                ("a" * 22 + ".b", "a" * 22 + "-b")):
            with self.subTest(basename=basename):
                name = pr_loop.session_name(f"/work/{basename}")
                self.assertRegex(name, "^" + self.NAME.pattern + "$")
                self.assertEqual(f"pilot-pr-{label}-" + hashlib.sha256(f"/work/{basename}".encode()).hexdigest()[:8], name)
                self.assertLessEqual(len(name), len("pilot-pr-") + pr_loop.SESSION_LABEL_MAX + 1 + 8)

    def test_a_path_without_a_directory_name_still_has_one(self):
        for path in ("/", ""):
            with self.subTest(path=path):
                self.assertRegex(pr_loop.session_name(path), r"^pilot-pr-checkout-[0-9a-f]{8}$")

    def test_a_path_that_is_not_text_still_gives_a_name(self):
        # A byte of a path that is not valid UTF-8 reaches Python as a surrogate: it is hashed as the bytes it was.
        name = pr_loop.session_name(os.fsdecode(b"/work/caf\xe9"))
        self.assertEqual("pilot-pr-caf-" + hashlib.sha256(b"/work/caf\xe9").hexdigest()[:8], name)


class TmuxCase(unittest.TestCase):
    def setUp(self):
        self.env = FakeEnv(self)
        self.clock = FakeTime()
        self.told = []
        for target, value in (("time", self.clock), ("tell", self.told.append)):
            patcher = patch.object(pr_loop, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.checkout = SimpleNamespace(path=self.env.root, session=pr_loop.session_name(self.env.root))

    def agent(self, number=7, phase="draft"):
        return pr_loop.Agent("claude", self.checkout, number, phase)

    def calls(self, *names):
        return [call for call in self.env.tmux_calls() if not names or call[0] in names]


class AgentStartTests(TmuxCase):
    def test_the_first_agent_creates_the_session_in_a_window_of_its_own_and_keeps_its_pane_when_it_exits(self):
        agent = self.agent()
        self.assertEqual("%1", agent.pane)
        session = self.checkout.session
        self.assertRegex(session, r"^pilot-pr-[A-Za-z0-9_-]+-[0-9a-f]{8}$")
        self.assertEqual([["new-session", "-d", "-s", session, "-n", "7-draft", "-c", str(self.env.root), "-P", "-F",
                           pr_loop.PANE_FORMAT, "--", "exec " + shlex.quote(str(self.env.bin / "claude"))]],
                         self.calls("new-session", "new-window", "show-options"))
        self.assertEqual([["set-option", "-w", "-t", "%1", "remain-on-exit", "on"]], self.calls("set-option"))
        self.assertIn(f"PR #7 draft agent: %1 in window 7-draft of tmux session {session}", self.told)
        self.assertEqual({session: ["7-draft"]}, self.env.live())

    def test_a_pane_id_that_is_not_one_stops_before_anything_else_is_sent(self):
        for answer in ("bogus", "%x", "", "1", "%1 %2"):
            with self.subTest(answer=repr(answer)):
                self.env.update_tmux(pane_ids=[answer], log=[])
                with self.assertRaisesRegex(pr_loop.Stop, "tmux did not return a pane ID"):
                    self.agent()
                self.assertEqual([], self.calls("set-option"))
        self.env.update_tmux(pane_ids=["%12"], log=[])
        self.assertEqual("%12", self.agent().pane, "control: a real pane ID is taken as it is")

    def test_an_executable_that_does_not_exist_stops_before_tmux_is_called(self):
        with self.assertRaisesRegex(pr_loop.Stop, "agent executable not found: no-such-agent"):
            pr_loop.Agent("no-such-agent", self.checkout, 7, "draft")
        self.assertEqual([], self.calls())

    def test_a_failing_new_session_stops_with_the_command_and_status(self):
        self.env.update_tmux(fail={"new-session": 3})
        with self.assertRaisesRegex(pr_loop.Stop, r"tmux new-session failed \(3\): fake tmux: injected failure"):
            self.agent()
        self.assertEqual([], self.calls("new-window", "show-options", "set-option"), "and no other way is tried")

    # ---- the second agent: a window of the session the first one made (kjelly/pilot#425) -----------------------
    def window_argv(self, window, *environment):
        return ["new-window", "-d", "-t", f"={self.checkout.session}:", "-n", window, "-c", str(self.env.root), "-P", "-F",
                pr_loop.PANE_FORMAT, *environment, "--", "exec " + shlex.quote(str(self.env.bin / "claude"))]

    def session_argv(self, window):
        return ["new-session", "-d", "-s", self.checkout.session, "-n", window, "-c", str(self.env.root), "-P", "-F",
                pr_loop.PANE_FORMAT, "--", "exec " + shlex.quote(str(self.env.bin / "claude"))]

    def test_the_second_agent_finds_the_session_and_adds_a_window_to_it_with_an_exact_target(self):
        first = self.agent(7, "draft")
        self.env.update_tmux(log=[])
        second = self.agent(7, "ready")
        self.assertEqual(("%1", "%2"), (first.pane, second.pane))
        self.assertEqual([self.session_argv("7-ready"),           # the session exists: tmux says so
                          ["show-options", "-gv", "update-environment"],
                          self.window_argv("7-ready"),            # `=S:`: the session S itself, never one whose name starts with S
                          ["set-option", "-w", "-t", "%2", "remain-on-exit", "on"]],
                         self.calls("new-session", "new-window", "show-options", "set-option"))
        self.assertEqual({self.checkout.session: ["7-draft", "7-ready"]}, self.env.live())
        self.assertEqual([("new-session", "7-draft"), ("new-window", "7-ready")],
                         [(made["kind"], made["window"]) for made in self.env.created()])
        self.assertIn(f"PR #7 ready agent: %2 in window 7-ready of tmux session {self.checkout.session}", self.told)

    def test_a_new_window_gets_the_runners_value_of_every_update_environment_name_it_has(self):
        # A new window takes the SESSION's value of these names (an earlier run's, or the last client's); the runner passes
        # its own. A name that is not on tmux's list is not passed, and neither is a listed one the runner does not have.
        self.agent(7, "draft")
        self.env.update_tmux(log=[])
        env = {"DISPLAY": ":9", "SSH_AUTH_SOCK": "/synthetic/agent.sock", "NOT_ON_THE_LIST": "x"}
        with patch.dict(os.environ, env):
            self.agent(7, "ready")
        self.assertEqual(self.window_argv("7-ready", "-e", "DISPLAY=:9", "-e", "SSH_AUTH_SOCK=/synthetic/agent.sock"),
                         self.calls("new-window")[0])
        self.assertEqual(["DISPLAY=:9", "SSH_AUTH_SOCK=/synthetic/agent.sock"], self.env.created()[-1]["env"])
        self.env.update_tmux(log=[])
        self.agent(8, "ready")
        self.assertEqual(self.window_argv("8-ready"), self.calls("new-window")[0], "a runner without them passes none")

    def test_an_entry_of_update_environment_is_a_glob_pattern_as_tmux_matches_it(self):
        # tmux 3.8 copies every variable of the client that a pattern of the list matches (`FOO_*` copies `FOO_X`):
        # captured on a private server, `set -g update-environment FOO_*` and a client with FOO_X set gave the session FOO_X.
        self.agent(7, "draft")
        self.env.update_tmux(update_environment=["FOO_*", "DISPLAY", "BAR?", "NOTHING_*"], log=[])
        env = {"FOO_X": "1", "FOO_Y": "2", "FOO": "no", "foo_z": "no", "BARS": "s", "BARSS": "no", "DISPLAY": ":9", "OTHER": "o"}
        with patch.dict(os.environ, env):
            self.agent(7, "ready")
        self.assertEqual(self.window_argv("7-ready", "-e", "FOO_X=1", "-e", "FOO_Y=2", "-e", "DISPLAY=:9", "-e", "BARS=s"),
                         self.calls("new-window")[0], "the pattern's matches, a plain name, `?` for one character; not the "
                                                      "rest (case counts) and nothing for a pattern that matches nothing")

    def test_a_variable_two_entries_match_is_passed_once(self):
        self.agent(7, "draft")
        self.env.update_tmux(update_environment=["FOO_*", "FOO_X"], log=[])
        with patch.dict(os.environ, {"FOO_X": "1"}):
            self.agent(7, "ready")
        self.assertEqual(self.window_argv("7-ready", "-e", "FOO_X=1"), self.calls("new-window")[0])

    def test_the_environment_is_not_read_for_the_first_agent_and_a_failure_to_read_it_is_a_stop(self):
        self.agent()
        self.assertEqual([], self.calls("show-options"), "a new session takes the runner's environment by itself")
        self.env.update_tmux(fail={"show-options": 1}, log=[])
        with self.assertRaisesRegex(pr_loop.Stop, r"tmux show-options failed \(1\)"):
            self.agent(7, "ready")
        self.assertEqual([], self.calls("new-window"), "no window is made without its environment")

    def test_a_pane_id_that_is_not_one_stops_for_a_new_window_too(self):
        self.agent()
        self.env.update_tmux(pane_ids=["bogus"])
        with self.assertRaisesRegex(pr_loop.Stop, "tmux did not return a pane ID"):
            self.agent(7, "ready")

    def test_an_unknown_failure_of_new_session_stops_and_no_window_is_tried(self):
        # tmux answers are compared exactly: another session's name, or the right text with another status, is no
        # `duplicate session: S` and must not be taken for one.
        for case, answer in (("another session", {"rc": 1, "stderr": "duplicate session: another-session"}),
                             ("another status", {"rc": 2, "stderr": f"duplicate session: {self.checkout.session}"}),
                             ("another text", {"rc": 1, "stderr": "no space for new window"})):
            with self.subTest(case=case):
                self.env.update_tmux(answers={"new-session": [answer]}, log=[])
                with self.assertRaisesRegex(pr_loop.Stop, rf"^tmux new-session failed \({answer['rc']}\): "
                                                          f"{re.escape(answer['stderr'])}$"):
                    self.agent()
                self.assertEqual([], self.calls("new-window", "show-options"), "no fallback for what is not a duplicate")
                self.assertEqual(1, len(self.calls("new-session")), "and no second try")

    def test_an_unknown_failure_of_new_window_stops_and_the_session_is_not_made_again(self):
        self.agent(7, "draft")
        for case, answer in (("another session", {"rc": 1, "stderr": "can't find session: another-session"}),
                             ("another status", {"rc": 2, "stderr": f"can't find session: {self.checkout.session}"}),
                             ("another text", {"rc": 1, "stderr": "create window failed: index in use"})):
            with self.subTest(case=case):
                self.env.update_tmux(answers={"new-window": [answer]}, log=[])
                with self.assertRaisesRegex(pr_loop.Stop, rf"^tmux new-window failed \({answer['rc']}\): "
                                                          f"{re.escape(answer['stderr'])}$"):
                    self.agent(7, "ready")
                self.assertEqual(["new-session", "show-options", "new-window"], [call[0] for call in self.calls()],
                                 "no new-session after the window failed")
        self.assertEqual({self.checkout.session: ["7-draft"]}, self.env.live(), "nothing was made")

    def test_a_session_that_is_killed_between_the_two_calls_is_made_again(self):
        # new-session says the session exists; the operator kills it; the window has nowhere to go: the session is made.
        # (The operator has a session of their own, which keeps the tmux server alive: see the tests of a server that exits.)
        self.env.keeper()
        self.agent(7, "draft")
        session = self.checkout.session
        self.env.update_tmux(log=[], before={"new-window": [{"kill_session": session}]})
        second = self.agent(7, "ready")
        self.assertEqual(["new-session", "show-options", "new-window", "new-session", "set-option"],
                         [call[0] for call in self.calls()])
        self.assertEqual("%2", second.pane)
        self.assertEqual({session: ["7-ready"], "operator": ["keeper"]}, self.env.live())
        self.assertEqual(["new-session", "new-session"], [made["kind"] for made in self.env.created()])

    def test_a_session_somebody_made_just_before_the_first_call_gets_the_window(self):
        session = self.checkout.session
        self.env.update_tmux(before={"new-session": [{"create_session": session}]})
        agent = self.agent()
        self.assertEqual(["new-session", "show-options", "new-window", "set-option"], [call[0] for call in self.calls()])
        self.assertEqual({session: ["operator", "7-draft"]}, self.env.live())
        self.assertEqual("%1", agent.pane)

    def test_a_session_that_keeps_appearing_and_disappearing_stops_after_three_rounds(self):
        session = self.checkout.session
        appears = {"create_session": session}
        disappears = {"kill_session": session}
        self.env.keeper()
        self.env.update_tmux(before={"new-session": [appears] * 3, "new-window": [disappears] * 3})
        with self.assertRaisesRegex(pr_loop.Stop, rf"^tmux session {session} kept appearing and disappearing while an "
                                                  "agent was started; nothing was dispatched$"):
            self.agent()
        self.assertEqual(["new-session", "show-options", "new-window", "new-session", "new-window", "new-session",
                          "new-window"], [call[0] for call in self.calls()],
                         "three rounds of new-session, then new-window (the environment is read once), and no fourth")
        self.assertEqual({"operator": ["keeper"]}, self.env.live())
        self.assertEqual([], self.calls("set-option"), "nothing was started")

    def test_two_rounds_of_it_are_tolerated(self):
        # The control of the test above: the third round gets through.
        session = self.checkout.session
        self.env.keeper()
        self.env.update_tmux(before={"new-session": [{"create_session": session}] * 2,
                                     "new-window": [{"kill_session": session}] * 2})
        agent = self.agent()
        self.assertEqual({session: ["7-draft"], "operator": ["keeper"]}, self.env.live())
        self.assertEqual(["new-session", "show-options", "new-window", "new-session", "new-window", "new-session",
                          "set-option"], [call[0] for call in self.calls()])
        self.assertTrue(re.fullmatch(r"%\d+", agent.pane))

    def test_a_surviving_twin_of_a_killed_session_never_gets_the_window(self):
        # The operator's tool keeps a grouped twin (`<name>-eink`) of the session. The session is killed after
        # new-session said it exists, and the twin keeps the windows. An inexact target `S:` would fall back to a
        # session whose name starts with S, which is the twin: the window would land in the OPERATOR's session.
        first = self.agent(7, "draft")
        session = self.checkout.session
        self.env.add_twin(session, session + "-eink")
        self.env.update_tmux(log=[], before={"new-window": [{"kill_session": session}]})
        second = self.agent(7, "ready")
        self.assertEqual({session + "-eink": ["7-draft"], session: ["7-ready"]}, self.env.live(),
                         "the twin keeps its own windows and gets nothing; the new session is not grouped with it")
        self.assertEqual([session, session], [made["session"] for made in self.env.created()])
        self.assertEqual(("%1", "%2"), (first.pane, second.pane))

    def test_a_twin_alone_does_not_stop_the_session_from_being_made(self):
        first = self.agent(7, "draft")
        session = self.checkout.session
        self.env.add_twin(session, session + "-eink")
        self.env.kill_session(session)  # the operator kills the session; the twin lives on
        second = self.agent(7, "ready")
        self.assertEqual([self.session_argv("7-ready")], self.calls("new-session")[-1:])
        self.assertEqual({session + "-eink": ["7-draft"], session: ["7-ready"]}, self.env.live())
        self.assertEqual(["new-session", "new-session"], [made["kind"] for made in self.env.created()])
        self.assertEqual(("%1", "%2"), (first.pane, second.pane))


class AgentStatusTests(TmuxCase):
    def test_a_status_line_is_parsed(self):
        self._agent = self.agent()
        for answer, expected in (("0|0|claude", (False, False, "claude")), ("1|0|claude", (True, False, "claude")),
                                 ("0|1|claude", (False, True, "claude")), ("0|0|-claude", (False, False, "claude")),
                                 ("0|0|", (False, False, ""))):
            with self.subTest(answer=answer):
                self.env.set_pane("%1", status=[answer])
                self.assertEqual(expected, self._agent.status())

    def test_a_status_line_that_is_not_three_fields_of_the_expected_kind_stops(self):
        self._agent = self.agent()
        for answer in ("garbage", "0|0", "0|0|a|b", "2|0|x", "0|2|x", "|0|x", "0||x", ""):
            with self.subTest(answer=answer):
                self.env.set_pane("%1", status=[answer])
                with self.assertRaisesRegex(pr_loop.Stop, "tmux could not read pane %1"):
                    self._agent.status()


class WaitForPromptTests(TmuxCase):
    """Screens are SYNTHETIC: they exercise the PROMPT, CHOICE and BUSY rules, not any real agent's UI."""

    def wait(self, *, status="0|0|claude", screens=("synthetic banner\n\n❯",), timeout=1.0, allow_exit=False):
        agent = self.agent()
        self.env.set_pane(agent.pane, status=[status], screens=list(screens))
        return agent.wait_for_prompt(timeout, allow_exit=allow_exit)

    def never_ready(self, **kwargs):
        with self.assertRaisesRegex(pr_loop.Stop, r"agent did not return to its input prompt in %\d+; inspect window "
                                                  rf"7-draft of tmux session {re.escape(self.checkout.session)}$"):
            self.wait(**kwargs)

    def test_an_agent_at_its_prompt_is_ready_at_once(self):
        self.assertTrue(self.wait())
        self.assertEqual([], self.clock.sleeps)
        for prompt in ("❯", "›", ">", "❯ typed text", "› Ask anything"):
            with self.subTest(prompt=prompt):
                self.assertTrue(self.wait(screens=[f"synthetic\n{prompt}\n"]))

    def test_text_that_is_not_a_prompt_line_is_not_ready(self):
        for screen in ("synthetic: loading", "synthetic $ ", "synthetic\n❯\n" + "line\n" * 6):
            with self.subTest(screen=screen):
                self.never_ready(screens=[screen])

    def test_a_busy_agent_is_not_ready_until_it_stops_being_busy(self):
        busy = "synthetic\n❯\nWorking (12s • esc to interrupt)"
        self.never_ready(screens=[busy])
        self.assertEqual([0.25] * 4, self.clock.sleeps)
        self.setUp()
        self.assertTrue(self.wait(screens=[busy, "synthetic\n❯"]))
        self.assertEqual([0.25], self.clock.sleeps, "control: it is ready as soon as the busy line is gone")
        self.assertEqual(2, len(self.calls("capture-pane")))

    def test_ctrl_c_to_interrupt_is_busy_too(self):
        self.never_ready(screens=["synthetic\n❯\nrunning (ctrl+c to interrupt)"])

    def test_a_trust_prompt_that_looks_like_an_input_prompt_is_not_ready(self):
        trust = "synthetic: Do you trust the files in this folder?\n❯ 1. Yes, proceed\n  2. No, exit"
        self.never_ready(screens=[trust])
        self.setUp()
        self.assertTrue(self.wait(screens=["synthetic: Do you trust the files in this folder?\n❯ yes, proceed"]),
                        "control: the same line without a numbered choice is a prompt")

    def test_a_pane_at_a_shell_is_not_ready_and_its_screen_is_not_read(self):
        for shell in ("bash", "zsh", "nu"):
            with self.subTest(shell=shell):
                self.setUp()
                self.never_ready(status=f"0|0|{shell}")
                self.assertEqual([], self.calls("capture-pane"))

    def test_a_pane_in_copy_mode_is_not_ready_and_its_screen_is_not_read(self):
        self.never_ready(status="0|1|claude")
        self.assertEqual([], self.calls("capture-pane"))

    def test_a_pane_whose_command_is_not_known_yet_is_not_ready(self):
        self.never_ready(status="0|0|")

    def test_a_dead_pane_stops_unless_the_caller_allows_the_exit(self):
        with self.assertRaisesRegex(pr_loop.Stop, "agent exited during startup in %1"):
            self.wait(status="1|0|claude")
        self.setUp()
        self.assertIs(False, self.wait(status="1|0|claude", allow_exit=True))
        self.assertEqual([], self.calls("capture-pane"))


class SubmitTests(TmuxCase):
    TEXT = '/pr-ready 7 --pr-loop-task="/x/.pr-loop/task.json"'

    def submit(self, **pane):
        agent = self.agent()
        if pane:
            self.env.set_pane("%1", **pane)
        agent.submit(self.TEXT)
        return agent

    def names(self):
        return [call[0] for call in self.calls()]

    def test_the_text_is_pasted_as_one_paste_and_then_submitted(self):
        self.submit()
        log = self.env.tmux()["log"]
        (load,) = [c for c in log if c["argv"][0] == "load-buffer"]
        buffer = load["argv"][2]
        self.assertTrue(buffer.startswith("pilot-pr-"))
        self.assertEqual(["load-buffer", "-b", buffer, "-"], load["argv"])
        self.assertEqual(self.TEXT, load["stdin"])
        self.assertEqual([["paste-buffer", "-p", "-d", "-b", buffer, "-t", "%1"]], self.calls("paste-buffer"))
        self.assertEqual(["display-message", "load-buffer", "paste-buffer", "display-message", "send-keys"], self.names()[2:],
                         "the pane is checked before anything is loaded or pasted, and again before Enter")
        self.assertEqual([["send-keys", "-t", "%1", "Enter"]], self.calls("send-keys"))
        self.assertEqual([self.TEXT], self.env.tmux()["panes"]["%1"]["input"])
        self.assertEqual([0.25], self.clock.sleeps, "the paste is given time to land before the pane is checked")

    def test_a_pane_that_changed_while_pasting_gets_no_enter(self):
        for case, pane in (("dead", dict(status=["1|0|claude"])), ("copy mode", dict(status=["0|1|claude"])),
                           ("shell", dict(status=["0|0|bash"])), ("no command", dict(status=["0|0|"])),
                           ("died of the paste", dict(die_on_paste=True))):
            with self.subTest(case=case):
                self.setUp()
                with self.assertRaisesRegex(pr_loop.Stop, "pane %1 changed while pasting; inspect before resuming"):
                    self.submit(**pane)
                self.assertEqual([], self.calls("send-keys"), "nothing may be sent to a pane that changed")
                self.assertEqual(1, len(self.calls("paste-buffer")))

    def test_a_paste_that_fails_removes_its_buffer_and_stops(self):
        self.env.update_tmux(fail={"paste-buffer": 1})
        with self.assertRaisesRegex(pr_loop.Stop, r"tmux paste-buffer failed \(1\): fake tmux: injected failure"):
            self.submit()
        (load,) = [c for c in self.env.tmux()["log"] if c["argv"][0] == "load-buffer"]
        self.assertEqual([["delete-buffer", "-b", load["argv"][2]]], self.calls("delete-buffer"))
        self.assertEqual([], self.calls("send-keys"))
        self.assertEqual(1, len(self.calls("display-message")), "the check before the paste, and none after the failure")

    def test_a_failing_cleanup_does_not_hide_the_paste_failure(self):
        self.env.update_tmux(fail={"paste-buffer": 1, "delete-buffer": 1})
        with self.assertRaisesRegex(pr_loop.Stop, r"tmux paste-buffer failed"):
            self.submit()
        self.assertEqual(1, len(self.calls("delete-buffer")), "the cleanup was attempted")

    def test_a_buffer_that_cannot_be_loaded_is_not_pasted(self):
        self.env.update_tmux(fail={"load-buffer": 1})
        with self.assertRaisesRegex(pr_loop.Stop, r"tmux load-buffer failed \(1\)"):
            self.submit()
        self.assertEqual([], self.calls("paste-buffer", "delete-buffer", "send-keys"))


class CloseTests(TmuxCase):
    def test_close_kills_the_pane(self):
        agent = self.agent()
        agent.close()
        self.assertEqual([["kill-pane", "-t", "%1"]], self.calls("kill-pane"))
        self.assertTrue(self.env.tmux()["panes"]["%1"]["killed"])

    def test_a_pane_that_cannot_be_killed_is_reported(self):
        agent = self.agent()
        self.env.update_tmux(fail={"kill-pane": 1})
        with self.assertRaisesRegex(pr_loop.Stop, r"tmux kill-pane failed \(1\)"):
            agent.close()

    def test_close_removes_the_agents_pane_and_nothing_else_of_the_session(self):
        # The operator split a pane off in the first agent's window, and a second agent has a window of its own: closing
        # the first agent kills its pane only (`kill-pane`, never the window or the session), so the split pane survives.
        first, second = self.agent(7, "draft"), self.agent(7, "ready")
        split = self.env.add_split(first.pane)
        self.env.update_tmux(log=[])
        first.close()
        self.assertEqual([["display-message", "-p", "-t", first.pane, pr_loop.READ_FORMAT], ["kill-pane", "-t", first.pane]],
                         self.env.tmux_calls(), "the pane is checked to be this agent's, then it is killed")
        state = self.env.tmux()
        windows = {window["name"]: window["panes"] for window in state["live"][self.checkout.session]["windows"]}
        self.assertEqual({"7-draft": [split], "7-ready": [second.pane]}, windows)
        self.assertEqual({self.checkout.session: ["7-draft", "7-ready"]}, self.env.live())

    def test_closing_the_last_pane_of_the_session_ends_it_and_its_grouped_twin(self):
        first, second = self.agent(7, "draft"), self.agent(7, "ready")
        self.env.add_twin(self.checkout.session, self.checkout.session + "-eink")
        first.close()
        self.assertEqual(2, len(self.env.live()), "the session and its twin are still there: a window is left")
        second.close()
        self.assertEqual({}, self.env.live())

    def test_a_pane_that_is_already_gone_is_closed(self):
        # The operator closed the window, or killed the session: what close asks for has happened, and nothing is sent.
        agent = self.agent()
        self.env.keeper()  # another session keeps the server alive: the server answers, and has no such pane
        self.env.kill_session(self.checkout.session)
        agent.close()
        self.assertEqual([], self.calls("kill-pane"))
        self.assertEqual(1, len(self.calls("display-message")))

    def test_a_pane_that_vanishes_between_the_check_and_the_kill_is_closed_too(self):
        agent = self.agent()
        self.env.update_tmux(answers={"kill-pane": [{"rc": 1, "stderr": "can't find pane: %1"}]})
        agent.close()
        self.assertEqual([["kill-pane", "-t", "%1"]], self.calls("kill-pane"))
        self.env.update_tmux(answers={"kill-pane": [{"rc": 1, "stderr": NO_SERVER}]})
        agent.close()  # the server went in those milliseconds: the pane is as gone as it can be

    def test_only_a_pane_that_is_gone_counts_as_closed(self):
        agent = self.agent()
        for case, answer in (("another pane", {"rc": 1, "stderr": "can't find pane: %9"}),
                             ("another status", {"rc": 2, "stderr": "can't find pane: %1"}),
                             ("a status that is not 1 with no server", {"rc": 2, "stderr": NO_SERVER}),
                             ("another text", {"rc": 1, "stderr": "no space"})):
            with self.subTest(case=case):
                self.env.update_tmux(answers={"kill-pane": [answer]})
                with self.assertRaisesRegex(pr_loop.Stop, rf"^tmux kill-pane failed \({answer['rc']}\): "
                                                          f"{re.escape(answer['stderr'])}$"):
                    agent.close()


class ServerIdentityTests(TmuxCase):
    """A pane ID is only unique within one tmux server (kjelly/pilot#425, review of db19ac69). A server exits with its last
    session, and the next one numbers its panes again: after the operator killed the runner's session, `%1` can be the pane
    of the runner's NEXT agent, or of a pane the operator made. An agent records which server made its pane (the PID and the
    start time that new-session and new-window print beside the pane ID) and acts on the pane only while the server that
    answers is that one: `close` does not kill what it cannot show is its own pane, and `status` and `submit` stop."""

    def operator_session(self, name="ops"):
        """The operator starts a session of their own, with tmux itself: its first pane; a new server if none runs."""
        done = subprocess.run(["tmux", "new-session", "-d", "-s", name, "-n", "w", "-c", "/", "-P", "-F", pr_loop.PANE_FORMAT,
                               "--", "x"], input="", capture_output=True, text=True, timeout=60)
        self.assertEqual(0, done.returncode, done.stderr)
        return done.stdout.split("|")[0]

    def restarted(self):
        """An agent of a server that has exited: the operator killed the runner's session, the only one."""
        old = self.agent(7, "draft")
        self.env.kill_session(self.checkout.session)
        self.assertIsNone(self.env.server(), "the last session took the server with it")
        self.env.update_tmux(log=[])
        return old

    def stale(self, agent):
        return rf"^agent pane {agent.pane} \(window {agent.window} of tmux session {re.escape(agent.session)}\) is not the pane " \
               "this agent was started in: the tmux server it was started on or the pane itself is gone or was replaced; " \
               "nothing was done to it$"

    def test_an_agent_records_the_server_that_made_its_pane(self):
        agent = self.agent()
        self.assertEqual(tuple(self.env.server().split("|")), agent.server)
        second = self.agent(7, "ready")  # a window of the same server: the same identity
        self.assertEqual(agent.server, second.server)
        self.assertEqual((False, False, "claude"), agent.status())

    def test_the_new_agent_of_a_new_server_has_the_old_agents_pane_id_and_closing_the_old_one_leaves_it_alone(self):
        old = self.restarted()
        new = self.agent(7, "ready")
        self.assertEqual(old.pane, new.pane, "the IDs collide: a new server numbers its panes again")
        self.assertNotEqual(old.server, new.server)
        self.env.update_tmux(log=[])
        old.close()
        self.assertEqual([["display-message", "-p", "-t", old.pane, pr_loop.READ_FORMAT]], self.env.tmux_calls(),
                         "the check found another server: no kill-pane")
        self.assertEqual({self.checkout.session: ["7-ready"]}, self.env.live(), "the new agent's window is there")
        self.assertEqual((False, False, "claude"), new.status(), "and it is still readable")
        new.close()  # the control: the agent that owns the pane kills it
        self.assertEqual([["kill-pane", "-t", new.pane]], self.calls("kill-pane"))
        self.assertEqual({}, self.env.live())

    def test_the_old_agent_does_not_read_or_paste_into_the_pane_that_has_its_id_now(self):
        old = self.restarted()
        new = self.agent(7, "ready")
        self.env.update_tmux(log=[])
        for action in (old.status, lambda: old.wait_for_prompt(1, allow_exit=True), lambda: old.submit("/pr-ready 7")):
            with self.assertRaisesRegex(pr_loop.Stop, self.stale(old)):
                action()
        self.assertEqual([], self.calls("load-buffer", "paste-buffer", "send-keys", "capture-pane"),
                         "nothing was loaded, pasted, typed or read")
        self.assertEqual([], self.env.tmux()["panes"][new.pane]["input"], "the new agent was sent nothing")

    def test_the_old_id_that_is_now_a_pane_of_the_operators_survives_and_is_not_sent_anything(self):
        old = self.restarted()
        ops = self.operator_session()
        self.assertEqual(old.pane, ops, "the operator's first pane has the old agent's ID")
        self.env.update_tmux(log=[])
        old.close()
        self.assertEqual([], self.calls("kill-pane"))
        self.assertEqual({"ops": ["w"]}, self.env.live(), "the operator's pane survives")
        with self.assertRaisesRegex(pr_loop.Stop, self.stale(old)):
            old.submit("/pr-ready 7")
        with self.assertRaisesRegex(pr_loop.Stop, self.stale(old)):
            old.status()
        self.assertEqual([], self.calls("load-buffer", "paste-buffer", "send-keys"))
        self.assertEqual([], self.env.tmux()["panes"][ops]["input"])

    def test_another_pid_or_another_start_time_is_another_server(self):
        # tmux's start time has a resolution of a second and PIDs are reused: both have to match.
        for case, change in (("another pid", lambda pid, start: (str(int(pid) + 1), start)),
                             ("another start time", lambda pid, start: (pid, str(int(start) + 1)))):
            with self.subTest(case=case):
                self.setUp()
                agent = self.agent()
                agent.server = change(*agent.server)
                self.env.update_tmux(log=[])
                agent.close()
                self.assertEqual([], self.calls("kill-pane"))
                with self.assertRaisesRegex(pr_loop.Stop, self.stale(agent)):
                    agent.status()
                agent.server = tuple(self.env.server().split("|"))  # the control: the real identity
                agent.close()
                self.assertEqual(1, len(self.calls("kill-pane")))

    def test_a_server_that_is_gone_means_the_pane_is_closed_and_a_stop_for_an_active_agent(self):
        for case, answer in (("a server that ran (the socket is left behind)", NO_SERVER),
                             ("no server ever ran there", NO_SOCKET)):
            with self.subTest(case=case):
                self.setUp()
                agent = self.agent()
                self.env.update_tmux(answers={"display-message": [{"rc": 1, "stderr": answer}] * 3}, log=[])
                agent.close()  # closed already: no kill-pane
                self.assertEqual([], self.calls("kill-pane"))
                with self.assertRaisesRegex(pr_loop.Stop, self.stale(agent)):
                    agent.status()
                with self.assertRaisesRegex(pr_loop.Stop, self.stale(agent)):
                    agent.submit("x")
                self.assertEqual([], self.calls("load-buffer", "paste-buffer", "send-keys"))

    def test_a_server_the_fake_ended_is_gone_for_close_and_status_alike(self):
        agent = self.agent()
        self.env.kill_server()
        self.env.update_tmux(log=[])
        agent.close()
        self.assertEqual(["display-message"], [call[0] for call in self.calls()], "the check says there is no server")
        with self.assertRaisesRegex(pr_loop.Stop, self.stale(agent)):
            agent.status()

    def test_a_pane_the_same_server_does_not_have_is_closed_and_a_stop_for_an_active_agent(self):
        agent = self.agent()
        self.env.keeper()  # the operator's session keeps this server alive
        self.env.kill_session(self.checkout.session)
        self.env.update_tmux(log=[])
        agent.close()
        self.assertEqual([], self.calls("kill-pane"))
        with self.assertRaisesRegex(pr_loop.Stop, self.stale(agent)):
            agent.status()

    def test_a_failure_of_tmux_that_is_not_a_missing_server_is_a_stop_and_kills_nothing(self):
        agent = self.agent()
        self.env.update_tmux(answers={"display-message": [{"rc": 1, "stderr": "protocol version mismatch"}]}, log=[])
        with self.assertRaisesRegex(pr_loop.Stop, r"^tmux display-message failed \(1\): protocol version mismatch$"):
            agent.close()
        self.assertEqual([], self.calls("kill-pane"))
        self.env.set_pane(agent.pane, status=["garbage"])  # output that cannot be read
        with self.assertRaisesRegex(pr_loop.Stop, rf"^tmux could not read pane {agent.pane}$"):
            agent.close()
        self.assertEqual([], self.calls("kill-pane"))


class FakeTmuxTests(unittest.TestCase):
    """The fake tmux says about sessions, windows, panes and servers what tmux 3.8 said on a private server (kjelly/pilot#425):
    the texts are those captures, and what was not captured is not modelled: the fake refuses a target or a format the runner
    does not use with status 98 and a message that says so. A test that relies on a rule below relies on it being true of the
    fake as it is of tmux."""

    def setUp(self):
        self.env = FakeEnv(self)

    @staticmethod
    def tmux(*args):
        done = subprocess.run(["tmux", *args], input="", capture_output=True, text=True, timeout=60)
        return done.returncode, done.stdout, done.stderr.strip()

    def session(self, name, window="w"):
        return self.tmux("new-session", "-d", "-s", name, "-n", window, "-c", "/", "-P", "-F", pr_loop.PANE_FORMAT, "--", "x")

    def window(self, target, name="v"):
        return self.tmux("new-window", "-d", "-t", target, "-n", name, "-c", "/", "-P", "-F", pr_loop.PANE_FORMAT, "--", "x")

    def read(self, pane):
        return self.tmux("display-message", "-p", "-t", pane, pr_loop.READ_FORMAT)

    def test_a_session_name_in_use_is_a_duplicate_and_a_new_pane_says_which_server_made_it(self):
        rc, out, err = self.session("S")
        self.assertEqual((0, "", f"%1|{self.env.server()}\n"), (rc, err, out))
        self.assertEqual((1, "", "duplicate session: S"), self.session("S"))
        self.assertEqual(0, self.session("S-eink")[0], "another name is another session")

    def test_a_window_needs_a_server_and_a_session_that_exists(self):
        self.assertEqual((1, "", NO_SERVER), self.window("=S:"), "no session, so no server")
        self.session("S")
        self.assertEqual((1, "", "can't find session: gone"), self.window("=gone:"))
        rc, out, _ = self.window("=S:")
        self.assertEqual((0, "%2|" + self.env.server() + "\n"), (rc, out))
        self.assertEqual({"S": ["w", "v"]}, self.env.live())

    def test_a_target_the_runner_does_not_use_is_refused_loudly_and_changes_nothing(self):
        # The runner only sends `=S:`. Colon-less targets and inexact ones resolve in ways that depend on what else the
        # server has (a colon-less `S` is a window name that tmux 3.8 found in S, and in a session `S-eink` when S was
        # gone); the fake does not model any of it, and a runner that sent one would fail its tests here.
        self.session("S")
        self.session("S-eink")
        for target in ("S", "S:", "S-e:", "=S", ":", "=:", "", "=S:w", "=a:b:"):
            with self.subTest(target=target):
                rc, out, err = self.window(target)
                self.assertEqual((98, ""), (rc, out))
                self.assertIn("is not a target the runner uses (only =SESSION:)", err)
        self.assertEqual({"S": ["w"], "S-eink": ["w"]}, self.env.live())

    def test_a_format_the_runner_does_not_use_is_refused_loudly(self):
        rc, _, err = self.tmux("new-session", "-d", "-s", "S", "-P", "-F", "#{pane_id}", "--", "x")
        self.assertEqual(98, rc)
        self.assertIn("is only answered with -P -F", err)
        self.session("S")
        self.assertEqual(98, self.tmux("display-message", "-p", "-t", "%1", "#{pane_dead}")[0])
        self.assertEqual(98, self.tmux("list-panes", "-a", "-F", "#{pane_id}")[0])
        self.assertEqual({"S": ["w"]}, self.env.live())

    def test_a_pane_goes_with_its_window_a_window_with_its_session_and_the_session_with_its_twin(self):
        self.session("S")
        self.window("=S:")
        self.env.add_twin("S", "S-eink")
        self.assertEqual({"S": ["w", "v"], "S-eink": ["w", "v"]}, self.env.live(), "a twin shows the windows of its group")
        self.assertEqual((1, "", "can't find pane: %9"), self.tmux("kill-pane", "-t", "%9"))
        self.assertEqual((0, "", ""), self.tmux("kill-pane", "-t", "%1"))
        self.assertEqual({"S": ["v"], "S-eink": ["v"]}, self.env.live())
        self.assertEqual((0, "", ""), self.tmux("kill-pane", "-t", "%2"))
        self.assertEqual({}, self.env.live())
        self.assertEqual((1, "", NO_SERVER), self.tmux("kill-pane", "-t", "%2"), "the last session took the server with it")

    def test_a_window_survives_while_a_pane_the_operator_split_off_is_in_it(self):
        self.session("S")
        split = self.env.add_split("%1")
        self.assertEqual((0, "", ""), self.tmux("kill-pane", "-t", "%1"))
        self.assertEqual({"S": ["w"]}, self.env.live())
        self.assertEqual((0, "", ""), self.tmux("kill-pane", "-t", split))
        self.assertEqual({}, self.env.live())

    def test_a_killed_session_leaves_its_twin_with_the_windows(self):
        self.session("S")
        self.env.add_twin("S", "S-eink")
        self.env.kill_session("S")
        self.assertEqual({"S-eink": ["w"]}, self.env.live())
        self.assertIsNotNone(self.env.server(), "the twin keeps the server alive")
        self.assertEqual((0, "", ""), self.tmux("kill-pane", "-t", "%1"))
        self.assertEqual({}, self.env.live())

    def test_a_pane_it_does_not_have_is_empty_fields_with_the_servers_identity_and_status_0(self):
        self.session("S")
        identity = self.env.server()
        self.assertEqual((0, f"0|0|claude|{identity}\n", ""), self.read("%1"))
        self.assertEqual((0, f"|||{identity}\n", ""), self.read("%77"),
                         "tmux 3.8 answers a pane it has not got with empty pane fields, exit status 0, server fields filled")

    def test_the_server_goes_with_its_last_session_and_the_next_one_is_another_server_that_numbers_its_panes_again(self):
        self.session("S")
        first = self.env.server()
        self.env.set_pane("%1", enter=["old"])  # something the old pane had
        self.assertEqual((0, "", ""), self.tmux("kill-pane", "-t", "%1"))
        self.assertIsNone(self.env.server())
        self.assertEqual((1, "", NO_SERVER), self.read("%1"), "no server: tmux says so and exits 1")
        self.assertEqual((1, "", NO_SERVER), self.tmux("list-panes", "-a", "-F", pr_loop.LIST_FORMAT))
        rc, out, _ = self.session("S")
        second = self.env.server()
        self.assertNotEqual(first, second, "another PID and start time")
        self.assertEqual((0, f"%1|{second}\n"), (rc, out), "and the pane IDs start again: %1 is another pane")
        self.assertEqual([], self.env.tmux()["panes"]["%1"].get("enter", []), "with nothing of the old pane's")
        self.assertEqual((0, f"0|0|claude|{second}\n", ""), self.read("%1"))

    def test_a_server_that_exits_takes_its_buffers_with_it(self):
        self.session("S")
        self.assertEqual((0, "", ""), self.tmux("load-buffer", "-b", "b", "-"))
        self.assertEqual(["b"], list(self.env.tmux()["buffers"]))
        self.tmux("kill-pane", "-t", "%1")
        self.assertEqual({}, self.env.tmux()["buffers"])

    def test_the_panes_listing_is_derived_from_the_model_the_way_tmux_prints_it(self):
        self.assertEqual(LIST_FORMAT, pr_loop.LIST_FORMAT, "the fake answers the format the runner asks for, and no other")
        self.assertEqual((1, "", NO_SERVER), self.tmux("list-panes", "-a", "-F", LIST_FORMAT), "no session, no server")
        self.session("S")
        self.window("=S:")
        self.env.add_twin("S", "S-eink")
        self.env.set_pane("%2", status=["1|0|sleep"])  # exited, kept by remain-on-exit: no process and no path
        rc, out, err = self.tmux("list-panes", "-a", "-F", LIST_FORMAT)
        self.assertEqual((0, ""), (rc, err))
        identity, pid = self.env.server(), 1000000000 + 1000 * 1 + 10 * 1  # (a synthetic PID: no real process has it)
        self.assertEqual([f"%1|@0|0|0|{pid}|{identity}|{SOCKET}|S|w|/|x|/|claude",
                          f"%2|@1|1|0||{identity}|{SOCKET}|S|v|/|x||sleep",
                          f"%1|@0|0|0|{pid}|{identity}|{SOCKET}|S-eink|w|/|x|/|claude",
                          f"%2|@1|1|0||{identity}|{SOCKET}|S-eink|v|/|x||sleep"], out.splitlines(),
                         "sorted by session name, a twin repeats the rows of its session, a dead pane keeps what it was "
                         "started with and has no process and no path")
        self.env.update_tmux(listing=["x|%1|0|/y"])
        self.assertEqual((0, "x|%1|0|/y\n", ""), self.tmux("list-panes", "-a", "-F", LIST_FORMAT), "a listing a test sets wins")
        self.assertEqual(98, self.tmux("list-panes", "-a", "-F", "#{pane_id}")[0], "and any other format is refused")

    def test_a_listing_row_is_read_back_into_the_pane_it_describes(self):
        self.session("S")
        pane = pr_loop.read_pane(pr_loop.split_listing(self.tmux("list-panes", "-a", "-F", LIST_FORMAT)[1])[0])
        self.assertEqual(("%1", "@0", False, False, tuple(self.env.server().split("|")), SOCKET, "S", "w", "/", "x", "/", "claude"),
                         (pane.pane, pane.window_id, pane.dead, pane.in_mode, pane.server, pane.socket, pane.session, pane.window,
                          pane.start_path, pane.start_command, pane.path, pane.command))

    def test_the_environment_a_new_session_takes_is_tmuxs_default_list(self):
        self.session("S")
        self.assertEqual((0, "".join(name + "\n" for name in UPDATE_ENVIRONMENT), ""),
                         self.tmux("show-options", "-gv", "update-environment"))
        self.assertEqual(13, len(UPDATE_ENVIRONMENT))
        self.assertIn("SSH_AUTH_SOCK", UPDATE_ENVIRONMENT)


# ---- (D) Checkout: real git, a real scratch remote, the fake tmux and gh -------------------------------------------

@contextlib.contextmanager
def working_in(path):
    here = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(here)


def sha256_of(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


class CheckPrUrlTests(unittest.TestCase):
    """The PR a view describes must be this repository's pull request: a pure check, run before every dispatch."""
    repo = pr_loop.Repo.parse("acme/demo")
    BAD = {
        "plain http": "http://github.com/acme/demo/pull/7",
        "ssh": "ssh://github.com/acme/demo/pull/7",
        "another host": "https://example.com/acme/demo/pull/7",
        "another repository": "https://github.com/acme/other/pull/7",
        "another owner": "https://github.com/other/demo/pull/7",
        "another PR": "https://github.com/acme/demo/pull/8",
        "not a pull URL": "https://github.com/acme/demo/issues/7",
        "a longer path": "https://github.com/acme/demo/pull/7/files",
        "a query": "https://github.com/acme/demo/pull/7?x=1",
        "a fragment": "https://github.com/acme/demo/pull/7#issuecomment-1",
        "empty": "",
    }

    def test_a_pr_url_that_is_not_this_pr_is_refused(self):
        for case, url in self.BAD.items():
            with self.subTest(case=case):
                with self.assertRaisesRegex(pr_loop.Stop, "^GitHub returned an unexpected PR URL$"):
                    pr_loop.check_pr_url(pr_view_json("ready", url=url), self.repo)
        view = pr_view_json("ready")
        del view["url"]
        with self.assertRaisesRegex(pr_loop.Stop, "^GitHub returned an unexpected PR URL$"):
            pr_loop.check_pr_url(view, self.repo)
        self.assertIsNone(pr_loop.check_pr_url(pr_view_json("ready"), self.repo), "control: this PR's own URL")

    def test_the_comparison_ignores_case_like_github(self):
        self.assertIsNone(pr_loop.check_pr_url(pr_view_json("ready", url="https://GitHub.com/Acme/Demo/pull/7"), self.repo))

    def test_a_host_qualified_repository_is_checked_against_its_own_host(self):
        repo = pr_loop.Repo.parse("ghe.example.com/acme/demo")
        self.assertIsNone(pr_loop.check_pr_url(
            pr_view_json("ready", url="https://ghe.example.com/acme/demo/pull/7"), repo))
        with self.assertRaisesRegex(pr_loop.Stop, "unexpected PR URL"):
            pr_loop.check_pr_url(pr_view_json("ready"), repo)  # a github.com URL for a ghe.example.com repository


class CheckoutCase(unittest.TestCase):
    """A real clone of a real bare repository (the operator's checkout), the fake tmux and gh, real git."""
    repo = pr_loop.Repo.parse("acme/demo")
    IDENTITY = "github.com/acme/demo"

    def setUp(self):
        self.env = FakeEnv(self)
        self.path = self.env.checkout
        self.told = []
        patcher = patch.object(pr_loop, "tell", self.told.append)
        patcher.start()
        self.addCleanup(patcher.stop)

    def checkout(self, directory="", *, repo=None, dry_run=False):
        """The Checkout of the operator's checkout (`directory`: a path; None, the current directory)."""
        found = pr_loop.Checkout(repo or self.repo, str(self.path) if directory == "" else directory, dry_run=dry_run)
        self.addCleanup(found.release)
        return found

    def refused(self, directory="", **kwargs):
        """The checkout is refused; the Stop it raised (it holds no lock afterwards)."""
        with self.assertRaises(pr_loop.Stop) as caught:
            self.checkout(directory, **kwargs)
        return caught.exception

    def stops(self, message, directory="", **kwargs):
        """The checkout is refused, with exactly `message`."""
        error = self.refused(directory, **kwargs)
        self.assertEqual(message, str(error))
        return error

    def git(self, *args, cwd=None):
        return self.env.git(*args, cwd=cwd or self.path)

    def tip(self, cwd=None):
        return self.git("rev-parse", "HEAD", cwd=cwd)

    def commit(self, name="local.txt", cwd=None):
        (Path(cwd or self.path) / name).write_text("local\n")
        self.git("add", "-A", cwd=cwd)
        self.git("commit", "-q", "-m", "local " + name, cwd=cwd)
        return self.tip(cwd)

    def ignored(self, path, probe):
        done = subprocess.run(["git", "check-ignore", "-q", "--", probe], cwd=path, env=self.env.git_env)
        return done.returncode == 0

    def exclude(self, path=None):
        return Path(path or self.path) / ".git/info/exclude"

    @staticmethod
    def helpers(*, leave_out=(), **more):
        """The files of a default branch the runner accepts (stubs: only the presence of the two helpers is checked)."""
        return {**{path: "x = 1\n" for path in HELPER_PATHS if path not in leave_out}, **more}

    def rebuild(self, files):
        """The scratch remote with these files on `main`, and the operator's checkout of it again."""
        self.env.make_remote(files)
        self.path = self.env.make_checkout()


class CheckoutResolveTests(CheckoutCase):
    """AC1 at the unit level: ONE absolute path, the root of the work tree, for the agents and for every git call."""

    def test_the_default_is_the_root_of_the_work_tree_that_contains_the_current_directory(self):
        below = self.path / "sub" / "dir"
        below.mkdir(parents=True)
        for here in (self.path, below):
            with self.subTest(here=str(here)), working_in(here):
                self.assertEqual(self.path, pr_loop.resolve_checkout(self.repo))
                found = self.checkout(None)
                self.assertEqual(self.path, found.path)
                found.release()

    def test_a_current_directory_outside_a_work_tree_is_refused(self):
        message = ("the current directory is not inside a git work tree; start the runner in a checkout of "
                   f"{self.IDENTITY} or pass --checkout DIR")
        plain = self.env.root / "plain"
        plain.mkdir()
        # (the ceiling keeps git from finding a repository above the scratch directory)
        with patch.dict(os.environ, GIT_CEILING_DIRECTORIES=str(self.env.root)):
            for here in (plain, self.path / ".git"):
                with self.subTest(here=str(here)), working_in(here):
                    self.stops(message, None)

    def test_checkout_must_be_a_directory_that_is_a_work_tree(self):
        plain = self.env.root / "plain"
        plain.mkdir()
        (self.env.root / "file.txt").write_text("x")
        with patch.dict(os.environ, GIT_CEILING_DIRECTORIES=str(self.env.root)):
            for given, message in ((str(self.env.root / "missing"), "is not a directory"),
                                   (str(self.env.root / "file.txt"), "is not a directory"),
                                   (str(plain), "is not a git work tree"),
                                   (str(self.path / ".git"), "is not a git work tree")):
                with self.subTest(given=given):
                    self.stops(f"--checkout {given} {message}", given)

    def test_checkout_must_be_the_root_of_its_work_tree(self):
        below = self.path / "sub"
        below.mkdir()
        self.stops(f"--checkout {below} is not the root of its git work tree {self.path}; pass {self.path}", str(below))
        self.assertEqual(self.path, self.checkout(str(self.path)).path, "control: the root itself")

    def test_the_same_checkout_however_it_is_spelled(self):
        link = self.env.root / "link"
        link.symlink_to(self.path)
        for case, given, cwd in (("a symlink to it", str(link), None), ("a trailing slash", str(self.path) + "/", None),
                                 ("a relative path", "checkout", self.env.root)):
            with self.subTest(case=case), working_in(cwd or os.getcwd()):
                found = self.checkout(given)
                self.assertEqual(self.path, found.path, "one real absolute path")
                found.release()
        with patch.dict(os.environ, HOME=str(self.env.root)):
            found = self.checkout("~/checkout")
            self.assertEqual(self.path, found.path, "~ is expanded")

    def test_a_linked_work_tree_is_a_checkout_of_its_own(self):
        # The main checkout steps aside so that the linked work tree can be on main.
        self.git("switch", "-q", "-c", "side")
        linked = self.env.root / "linked"
        self.git("worktree", "add", "-q", str(linked), "main")
        found = self.checkout(str(linked))
        self.assertEqual(linked, found.path)
        # Its lock is its own; the exclude file is shared by every work tree of the repository.
        self.assertEqual(self.path / ".git/worktrees/linked", found.lock_path.parent)
        self.assertTrue(found.lock_path.is_file())
        self.assertEqual(self.path / ".git/info/exclude", found.exclude)
        self.assertEqual(["/.pr-ready/", "/.pr-loop/"], self.exclude().read_text().splitlines()[-2:])
        # The main work tree, on `side`, is refused because main is checked out in the linked one, which is no checkout
        # of the runner's to take it from.
        self.stops(f"checkout {self.path} is on side, and main, the default branch of origin, is checked out in another work "
                   f"tree ({linked}); the runner does not switch to it: start the runner in that work tree, or check out "
                   "another branch there, and start the runner again")


class CheckoutOriginTests(CheckoutCase):
    """origin must be the repository the runner drives; git reads the raw configuration, never a rewritten URL."""

    def point_at(self, *urls, replace=True):
        """Make these URLs the origin: the first is configured, and all of them are sent to the scratch remote."""
        self.git("remote", "set-url", "origin", urls[0])
        self.env.redirect_origin(self.path, *urls, replace=replace)

    def test_no_origin_at_all_is_refused(self):
        self.git("remote", "remove", "origin")
        self.stops(f"checkout {self.path} has no origin remote")

    def test_another_repository_is_refused_and_the_right_one_passes(self):
        for url, found in (("https://github.com/other/demo.git", "github.com/other/demo"),
                           ("https://github.com/acme/other.git", "github.com/acme/other"),
                           ("https://example.com/acme/demo.git", "example.com/acme/demo"),
                           ("git@gitlab.com:acme/demo.git", "gitlab.com/acme/demo")):
            with self.subTest(url=url):
                self.git("remote", "set-url", "origin", url)
                self.stops(f"origin of {self.path} is {found}, not {self.IDENTITY}")
        self.point_at("https://github.com/acme/demo.git")
        self.checkout()

    def test_an_origin_that_is_not_a_url_of_the_repository_is_refused(self):
        for case, url in (("a local path", str(self.env.remote)), ("a file URL", f"file://{self.env.remote}"),
                          ("git protocol", "git://github.com/acme/demo.git"), ("plain http", "http://github.com/acme/demo"),
                          ("a deeper path", "https://github.com/acme/demo/tree/main"), ("only an owner", "https://github.com/acme"),
                          ("a query", "https://github.com/acme/demo.git?x=1"), ("empty", "")):
            with self.subTest(case=case):
                self.git("remote", "set-url", "origin", url)
                self.stops(f"origin of {self.path} is not a URL of {self.IDENTITY}")

    def test_two_urls_are_refused_even_when_one_is_right(self):
        # git fetches from the first and pushes to all of them: the runner needs exactly one.
        for second in ("https://github.com/acme/other.git", "https://github.com/acme/demo.git"):
            with self.subTest(second=second):
                self.git("config", "--add", "remote.origin.url", second)
                self.stops(f"origin of {self.path} has 2 URLs; the runner needs exactly one, of {self.IDENTITY}")
                self.git("config", "--unset-all", "remote.origin.url")  # back to exactly one
                self.git("config", "remote.origin.url", self.env.ORIGIN)
        self.assertEqual([self.env.ORIGIN], self.git("config", "--get-all", "remote.origin.url").split())
        self.checkout()  # control: one URL

    def test_every_push_url_must_be_the_repository_too(self):
        self.git("config", "remote.origin.pushurl", "https://github.com/other/demo.git")
        self.stops(f"origin of {self.path} pushes to github.com/other/demo, not {self.IDENTITY}")
        self.git("config", "remote.origin.pushurl", str(self.env.remote))
        self.stops(f"a push URL of origin of {self.path} is not a URL of {self.IDENTITY}")
        self.git("config", "remote.origin.pushurl", "git@github.com:acme/demo.git")
        self.git("config", "--add", "remote.origin.pushurl", "https://github.com/acme/other.git")
        self.stops(f"origin of {self.path} pushes to github.com/acme/other, not {self.IDENTITY}")
        self.git("config", "--unset-all", "remote.origin.pushurl")
        self.git("config", "--add", "remote.origin.pushurl", "git@github.com:acme/demo.git")
        self.git("config", "--add", "remote.origin.pushurl", "ssh://git@github.com/ACME/demo")
        self.checkout()  # control: every push URL is the repository, in other spellings

    def test_the_forms_github_hands_out_are_the_repository(self):
        token = "tok" + uuid.uuid4().hex
        # (one of each form through the whole inspection; OriginRepoTests reads every spelling of them)
        for url in ("https://GitHub.com/Acme/Demo/", "ssh://git@github.com:22/acme/demo.git", "git@github.com:acme/demo.git",
                    f"https://x-access-token:{token}@github.com/acme/demo.git"):
            with self.subTest(url=url.replace(token, "<token>")):
                self.point_at(url)
                found = self.checkout()
                found.release()
        self.assertNotIn(token, "\n".join(self.told), "a token in the URL is never printed")

    def test_a_token_in_the_url_is_never_printed(self):
        token = "tok" + uuid.uuid4().hex
        self.git("remote", "set-url", "origin", f"https://x-access-token:{token}@github.com/other/demo.git")
        error = self.stops(f"origin of {self.path} is github.com/other/demo, not {self.IDENTITY}")
        self.assertNotIn(token, str(error))
        self.git("config", "remote.origin.pushurl", f"https://{token}@example.com/acme/demo.git")
        self.git("config", "--unset-all", "remote.origin.url")
        self.git("config", "remote.origin.url", f"https://{token}@github.com/acme/demo.git")
        error = self.stops(f"origin of {self.path} pushes to example.com/acme/demo, not {self.IDENTITY}")
        self.assertNotIn(token, str(error))

    def test_a_host_qualified_repository_is_the_origin_on_its_own_host(self):
        repo = pr_loop.Repo.parse("ghe.example.com/acme/demo")
        self.stops(f"origin of {self.path} is github.com/acme/demo, not ghe.example.com/acme/demo", repo=repo)
        self.point_at("https://ghe.example.com/acme/demo.git")
        self.assertEqual(self.path, self.checkout(repo=repo).path)


class OriginRepoTests(unittest.TestCase):
    """`origin_repo` reads the three URL forms GitHub hands out and nothing else; it never returns userinfo."""

    def test_the_url_forms_of_a_repository(self):
        token = "tok" + uuid.uuid4().hex  # (built at run time: no credential-shaped literal in a committed file)
        for url, expected in {
            "https://github.com/acme/demo": ("github.com", "acme", "demo"),
            "https://github.com/acme/demo.git": ("github.com", "acme", "demo"),
            "https://github.com/acme/demo/": ("github.com", "acme", "demo"),
            "https://github.com/acme/demo.git/": ("github.com", "acme", "demo"),
            f"https://user:{token}@github.com:8443/acme/demo.git": ("github.com", "acme", "demo"),
            "https://GitHub.COM/Acme/Demo": ("github.com", "Acme", "Demo"),
            "ssh://git@github.com/acme/demo.git": ("github.com", "acme", "demo"),
            "ssh://github.com:22/acme/demo": ("github.com", "acme", "demo"),
            "git@github.com:acme/demo.git": ("github.com", "acme", "demo"),
            "github.com:acme/demo": ("github.com", "acme", "demo"),
            "git@GHE.example.com:acme/demo": ("ghe.example.com", "acme", "demo"),
            "https://github.com/acme/my.repo.git": ("github.com", "acme", "my.repo"),
        }.items():
            with self.subTest(url=url):
                self.assertEqual(expected, pr_loop.origin_repo(url))

    def test_anything_else_is_not_a_url_of_a_repository(self):
        for url in ("", "/srv/git/demo.git", "../demo", "file:///srv/git/demo.git", "git://github.com/acme/demo.git",
                    "http://github.com/acme/demo", "https://github.com/acme", "https://github.com/acme/demo/extra",
                    "https://github.com/acme/demo?x=1", "https://github.com/acme/demo#frag", "https://github.com:bad/acme/demo",
                    "https:///acme/demo", "https://[::1]/acme/demo", "git@github.com:acme", "git@github.com:acme/demo/extra",
                    "git@github.com acme/demo", "C:\\\\repos\\\\demo", "https://github.com/acme/de mo", "github.com:acme//demo"):
            with self.subTest(url=url):
                self.assertIsNone(pr_loop.origin_repo(url))

    def test_a_url_that_git_quotes_back_is_redacted(self):  # the function; CheckoutDefaultBranchTests tests its use
        token = "tok" + uuid.uuid4().hex
        url = f"https://x-access-token:{token}@github.com/acme/demo.git"
        for text in (f"fatal: unable to access '{url}': boom", f"fatal: repository '{url}/' not found",
                     f"fatal: unable to access 'https://{token}@other.example/x.git': boom"):
            with self.subTest(text=text.replace(token, "<token>")):
                self.assertNotIn(token, pr_loop.redact(text, [url]))
        self.assertEqual("fatal: nothing to hide here", pr_loop.redact("fatal: nothing to hide here", [url, ""]))


class CheckoutDefaultBranchTests(CheckoutCase):
    """Origin says which branch is its default and where it is NOW; the checkout must be on it, at its tip."""

    def test_an_origin_that_cannot_be_reached_is_refused(self):
        self.env.redirect_origin(self.path, self.env.ORIGIN, remote=self.env.root / "missing.git", replace=True)
        error = str(self.refused())
        self.assertRegex(error, rf"^cannot read the default branch of origin for {re.escape(str(self.path))}: "
                                r"git ls-remote failed \(128\): fatal: .*does not appear to be a git repository")
        self.assertLessEqual(len(error.split("failed (128): ", 1)[1]), 300)
        self.env.redirect_origin(self.path, self.env.ORIGIN, replace=True)
        self.checkout()  # control: the same checkout, origin reachable

    def test_what_git_says_about_origin_never_carries_a_url_with_a_token(self):
        # SYNTHETIC: git quotes the URL back, userinfo and all, in some failures; a failing `git ls-remote` is made to
        # do that here, because a real one would only be as good as the git version that runs the test.
        token = "tok" + uuid.uuid4().hex
        url = f"https://x-access-token:{token}@github.com/acme/demo.git"
        self.git("remote", "set-url", "origin", url)
        real = pr_loop.git

        def quoting(cwd, *args, **kwargs):
            if args[:1] == ("ls-remote",):
                return subprocess.CompletedProcess(args, 128, "", f"fatal: unable to access '{url}/': boom {url}")
            return real(cwd, *args, **kwargs)
        with patch.object(pr_loop, "git", quoting):
            with self.assertRaises(pr_loop.Stop) as caught:
                self.checkout()
        self.assertNotIn(token, str(caught.exception))
        self.assertRegex(str(caught.exception), r"git ls-remote failed \(128\): fatal: unable to access '<origin>/': boom <origin>$")

    def test_a_listing_that_is_not_exactly_the_two_lines_of_a_default_branch_is_refused(self):
        # SYNTHETIC outputs (the real shape: `ref: refs/heads/main<TAB>HEAD` and `<sha><TAB>HEAD`, captured from git 2.53 and
        # served by every other test of this class); each is a way for origin's answer to be something else.
        sha, ref = "a" * 40, "ref: refs/heads/main\tHEAD"
        real = pr_loop.git
        refused = "origin did not report its default branch (git ls-remote --symref origin HEAD)"
        for case, output in (("nothing", ""), ("the sha only", f"{sha}\tHEAD\n"), ("the ref only", f"{ref}\n"),
                             ("a third line", f"{ref}\n{sha}\tHEAD\n{sha}\trefs/heads/other\n"),
                             ("the lines the other way round", f"{sha}\tHEAD\n{ref}\n"), ("a short sha", f"{ref}\n{'a' * 39}\tHEAD\n"),
                             ("a ref that is not a branch", f"ref: refs/tags/v1\tHEAD\n{sha}\tHEAD\n"),
                             ("a branch name git refuses", f"ref: refs/heads/a..b\tHEAD\n{sha}\tHEAD\n"),
                             ("another remote ref than HEAD", f"{ref}\n{sha}\trefs/heads/main\n"),
                             ("no tab", f"ref: refs/heads/main HEAD\n{sha} HEAD\n")):
            with self.subTest(case=case):
                def listing(cwd, *args, _output=output, **kwargs):
                    if args[:1] == ("ls-remote",):
                        return subprocess.CompletedProcess(args, 0, _output, "")
                    return real(cwd, *args, **kwargs)
                with patch.object(pr_loop, "git", listing):
                    self.stops(refused)
        self.checkout()  # control: the real answer

    def test_an_origin_without_a_default_branch_is_refused(self):
        empty = self.env.root / "empty.git"
        self.env.git("init", "-q", "--bare", "-b", "main", str(empty), cwd=self.env.root)
        self.env.redirect_origin(self.path, self.env.ORIGIN, remote=empty, replace=True)
        self.stops("origin did not report its default branch (git ls-remote --symref origin HEAD)")

    def test_the_default_branch_is_what_origin_says_not_the_cached_origin_head(self):
        # origin renamed its default branch to trunk; the checkout's refs/remotes/origin/HEAD still says main.
        self.env.git("branch", "trunk", "main", cwd=self.env.remote)
        self.env.git("symbolic-ref", "HEAD", "refs/heads/trunk", cwd=self.env.remote)
        self.assertEqual("refs/remotes/origin/main", self.git("symbolic-ref", "refs/remotes/origin/HEAD"))
        self.stops(f"checkout {self.path} is on main, and it has no local trunk, the default branch of origin; the runner "
                   "switches only to an existing local branch: create it at origin's tip yourself and start the runner again")
        self.assertEqual("refs/heads/main", self.git("symbolic-ref", "HEAD"))
        self.git("switch", "-q", "-c", "trunk", "main")
        self.assertEqual("refs/heads/trunk", self.checkout().branch, "control: on trunk it passes")

    def test_a_missing_or_wrong_cached_origin_head_changes_nothing(self):
        self.git("remote", "set-head", "origin", "-d")
        self.checkout().release()
        self.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/nonexistent")
        self.checkout().release()

    def test_a_detached_head_is_refused_even_at_the_tip(self):
        self.git("switch", "-q", "--detach")
        self.stops(f"checkout {self.path} has a detached HEAD at {self.env.remote_head[:12]}; check out main, "
                   "the default branch of origin")
        self.git("switch", "-q", "main")
        self.checkout()

    def test_another_branch_at_the_same_commit_is_switched_away_from_not_refused(self):
        # The tip alone would pass: `other` and `main` are the same commit. The runner leaves `other` for main.
        self.git("switch", "-q", "-c", "other")
        self.assertEqual(self.env.remote_head, self.tip())
        found = self.checkout()
        self.assertEqual(("refs/heads/main", self.env.remote_head, ("other", self.env.remote_head)),
                         (self.git("symbolic-ref", "HEAD"), self.tip(), found.switched))
        self.assertEqual(self.env.remote_head, self.git("rev-parse", "refs/heads/other"))

    def test_a_checkout_ahead_of_origin_is_refused(self):
        local = self.commit()
        self.stops(f"local main at {local[:12]} has commits that origin's main ({self.env.remote_head[:12]}) does not "
                   "have; the skills must come from origin's default branch")
        self.git("push", "-q", "origin", "main")
        self.env.remote_head = self.git("rev-parse", "main", cwd=self.env.remote)
        self.checkout()  # control: pushed, equal to origin

    def test_a_checkout_without_a_commit_is_refused(self):
        fresh = self.env.root / "fresh"
        self.env.git("init", "-q", "-b", "main", str(fresh), cwd=self.env.root)
        self.env.git("remote", "add", "origin", self.env.ORIGIN, cwd=fresh)
        self.env.redirect_origin(fresh, self.env.ORIGIN)
        self.stops(f"local main has no commit but origin's main is at {self.env.remote_head[:12]}; run git pull "
                   f"--ff-only in {fresh} and start the runner again", str(fresh))


class FastForwardCase(CheckoutCase):
    """A checkout strictly behind origin's tip is fast-forwarded at startup to exactly that tip (kjelly/pilot#425).
    Real git throughout: a bare origin, a clone of it, a second clone that pushes."""

    def push(self, files=None, remove=(), name="push", stage=True):
        """Another commit on origin's `main` (writing `files`, deleting `remove`); its SHA."""
        work = self.env.root / "work"
        for path, text in (files or {}).items():
            (work / path).parent.mkdir(parents=True, exist_ok=True)
            (work / path).write_text(text)
        for path in remove:
            self.env.git("rm", "-q", path, cwd=work)
        (work / f"{name}.txt").write_text(name + "\n")
        self.env.git("add", "-A" if stage else f"{name}.txt", cwd=work)  # (`-A` would drop a gitlink with no directory)
        self.env.git("commit", "-q", "-m", name, cwd=work)
        self.env.git("push", "-q", str(self.env.remote), "main", cwd=work)
        self.env.remote_head = self.env.git("rev-parse", "main", cwd=self.env.remote)
        return self.env.remote_head

    def push_gitlink(self, path, sha, name="gitlink"):
        work = self.env.root / "work"
        self.env.git("update-index", "--add", "--cacheinfo", f"160000,{sha},{path}", cwd=work)
        return self.push(name=name, stage=False)

    def fresh(self):
        """A new origin and a new clone of it: the state a test sets up starts from the same place every time."""
        self.env.make_remote()
        self.path = self.env.make_checkout()

    def has(self, sha):
        done = subprocess.run(["git", "cat-file", "-e", f"{sha}^{{commit}}"], cwd=self.path, env=self.env.git_env,
                              capture_output=True)
        return done.returncode == 0

    def objects(self, path=None):
        root = Path(path or self.path) / ".git/objects"
        return sorted((str(file.relative_to(root)), file.stat().st_size) for file in root.rglob("*") if file.is_file())

    def tree(self, path=None):
        """Every file of the work tree outside .git, with its content."""
        top = Path(path or self.path)
        return {str(file.relative_to(top)): file.read_bytes() for file in sorted(top.rglob("*"))
                if file.is_file() and ".git" not in file.relative_to(top).parts}

    def written(self):
        git = self.path / ".git"

        def read(name):
            return (git / name).read_bytes() if (git / name).exists() else None
        index = git / "index"
        return dict(refs=self.refs(), head=read("HEAD"), packed=read("packed-refs"), objects=self.objects(),
                    fetch_head=read("FETCH_HEAD"), orig_head=read("ORIG_HEAD"), config=read("config"),
                    index=(sha256_of(index), index.stat().st_mtime_ns), exclude=read("info/exclude"),
                    lock=(git / "pilot-pr-loop.lock").exists(), tasks=(self.path / ".pr-loop").exists(),
                    tmux=self.env.tmux_calls(), tree=self.tree(),
                    logs={str(f.relative_to(git)): f.read_bytes() for f in sorted((git / "logs").rglob("*")) if f.is_file()})

    def test_the_task_files_are_judged_against_the_tree_the_fast_forward_brought(self):
        old = self.tip()
        new = self.push(files={".gitignore": "!/.pr-loop/\n"})
        self.stops(f"{self.path} does not ignore .pr-loop/ and .pr-ready/ even after they were added to {self.exclude()}: "
                   "a tracked .gitignore overrides it, so the task files would count as uncommitted work")
        self.assertEqual((new, self.line("main", old, new)), (self.tip(), self.told[0]),
                         "the .gitignore of the tip is what git reads now, and the run was told the branch moved")
        self.fresh()
        old = self.tip()
        new = self.push(files={".gitignore": "/dist/\n"})
        found = self.checkout()  # control: a tip whose .gitignore is unrelated
        self.assertEqual((new, ["/.pr-ready/", "/.pr-loop/"]),
                         (found.head, [line for line in self.exclude().read_text().splitlines() if line.startswith("/.pr-")]))

    def refs(self, path=None):
        return self.git("for-each-ref", "--format=%(refname) %(objectname)", cwd=path)

    def ignore(self, *lines):
        with self.exclude().open("a") as stream:
            stream.writelines(line + "\n" for line in lines)

    def untouched(self, local, *, objects=None):
        """What a refusal leaves: the branch at `local`, HEAD on it, a clean work tree."""
        self.assertEqual((local, "refs/heads/main"), (self.tip(), self.git("symbolic-ref", "HEAD")))
        self.assertEqual(local, self.git("rev-parse", "refs/heads/main"))
        self.assertEqual("", self.git("status", "--porcelain=v1", "--untracked-files=all"))
        if objects is not None:
            self.assertEqual(objects, self.objects(), "nothing was fetched")

    def line(self, branch, local, tip):
        return f"Fast-forwarded {branch} from {local[:12]} to {tip[:12]}, origin's tip"


class CheckoutFastForwardTests(FastForwardCase):
    """The runner brings a checkout that is strictly behind origin's tip up to exactly that tip, and refuses every
    other state without touching it."""

    def test_a_checkout_behind_origin_is_fast_forwarded_to_the_tip(self):
        old = self.tip()
        new = self.push()
        self.env.git("tag", "release", new, cwd=self.env.remote)
        self.assertFalse(self.has(new), "origin's new commit is not in the checkout yet")
        found = self.checkout()
        self.assertEqual((new, "refs/heads/main"), (self.tip(), self.git("symbolic-ref", "HEAD")))
        self.assertEqual((new, (old, new)), (found.head, found.forwarded))
        self.assertEqual("refs/heads/main", found.branch)
        self.assertEqual(self.line("main", old, new), self.told[0], "said first, before anything else is")
        self.assertEqual("", self.git("status", "--porcelain=v1", "--untracked-files=all"))
        self.assertTrue((self.path / "push.txt").is_file(), "the work tree is the tip's")
        self.assertEqual(new, self.git("rev-parse", "refs/remotes/origin/main"), "the tracking ref moved, as in git pull")
        self.assertFalse((self.path / ".git/FETCH_HEAD").exists(), "no FETCH_HEAD")
        self.assertEqual("", self.git("tag", "--list"), "no tag came with it")
        self.assertEqual(old, self.git("rev-parse", "ORIG_HEAD"), "the commit it was at is easy to find")
        self.assertIn("merge", self.git("reflog", "-1", "--format=%gs", "main"), "and so is the reflog")
        found.verify()  # the run goes on from the new commit

    def test_a_tip_that_is_already_in_the_checkout_is_fast_forwarded_too(self):
        old = self.tip()
        new = self.push()
        self.git("fetch", "-q", "origin")
        fetch_head = (self.path / ".git/FETCH_HEAD").read_bytes()  # the operator's own fetch wrote it
        self.assertTrue(self.has(new))
        self.assertEqual(old, self.tip())
        found = self.checkout()
        self.assertEqual((new, self.line("main", old, new)), (self.tip(), self.told[0]))
        self.assertEqual(new, found.head)
        self.assertEqual(fetch_head, (self.path / ".git/FETCH_HEAD").read_bytes(), "the runner's fetch left it alone")

    def test_what_lands_is_the_commit_origin_reported_even_when_origin_moves_on(self):
        old = self.tip()
        first = self.push()
        real, moved = pr_loop.git, []

        def racing(cwd, *args, **kwargs):
            done = real(cwd, *args, **kwargs)
            if args[:1] == ("ls-remote",) and not moved:
                moved.append(self.env.advance_remote("later.txt"))  # origin moves between the listing and the fetch
            return done
        with patch.object(pr_loop, "git", racing):
            found = self.checkout()
        self.assertEqual(1, len(moved))
        self.assertNotEqual(first, moved[0])
        self.assertEqual((first, first, self.line("main", old, first)), (self.tip(), found.head, self.told[0]))
        self.assertFalse((self.path / "later.txt").exists())
        self.assertEqual(first, self.git("rev-parse", "refs/remotes/origin/main"))

    def test_a_ref_named_like_origins_branch_cannot_divert_it(self):
        old = self.tip()
        new = self.push()
        decoy = self.commit("decoy.txt")
        self.git("branch", "origin/main", decoy)
        self.git("update-ref", f"refs/heads/{new}", decoy)
        self.git("reset", "-q", "--hard", old)
        self.git("update-ref", "refs/heads/main", old)
        self.assertEqual(old, self.tip())
        self.assertEqual(decoy, self.git("rev-parse", "origin/main^{commit}"), "the decoy shadows origin/main")
        found = self.checkout()
        self.assertEqual((new, new), (self.tip(), found.head))
        self.assertFalse((self.path / "decoy.txt").exists())

    def test_a_checkout_ahead_of_origin_is_refused_and_nothing_is_fetched(self):
        new = self.push()
        self.git("pull", "-q", "--ff-only", "origin", "main")
        local = self.commit()
        before, refs = self.objects(), self.refs()
        self.stops(f"local main at {local[:12]} has commits that origin's main ({new[:12]}) does not have; the skills "
                   "must come from origin's default branch")
        self.assertEqual((before, refs), (self.objects(), self.refs()), "no fetch, no ref written")
        self.untouched(local)

    def test_a_diverged_checkout_is_refused_whether_or_not_origins_tip_was_fetched(self):
        local = self.commit()
        new = self.push()
        message = (f"local main at {local[:12]} and origin's main at {new[:12]} have diverged (each has commits the other "
                   "does not have); the runner only fast-forwards: put main at origin's tip yourself and start the runner "
                   "again")
        tree = self.tree()
        for fetched in (False, True):
            with self.subTest(fetched=fetched):
                if fetched:
                    self.git("fetch", "-q", "origin")
                self.assertEqual(fetched, self.has(new))
                self.stops(message)
                self.untouched(local)
                self.assertEqual(tree, self.tree())
        with self.assertRaises(pr_loop.Stop) as dry:
            self.checkout(dry_run=True)
        self.assertEqual(message, str(dry.exception), "a dry run refuses it for the same reason once the tip is known")

    def test_a_checkout_without_a_commit_is_refused_and_fetches_nothing(self):
        fresh = self.env.root / "fresh"
        self.env.git("init", "-q", "-b", "main", str(fresh), cwd=self.env.root)
        self.env.git("remote", "add", "origin", self.env.ORIGIN, cwd=fresh)
        self.env.redirect_origin(fresh, self.env.ORIGIN)
        before = self.objects(fresh)
        self.stops(f"local main has no commit but origin's main is at {self.env.remote_head[:12]}; run git pull --ff-only "
                   f"in {fresh} and start the runner again", str(fresh))
        self.assertEqual(before, self.objects(fresh))
        self.assertEqual("", self.git("for-each-ref", cwd=fresh), "no ref was written")

    def test_a_partial_clone_is_refused_before_anything_is_fetched(self):
        self.env.git("config", "uploadpack.allowFilter", "true", cwd=self.env.remote)
        self.env.git("clone", "-q", "--filter=blob:none", f"file://{self.env.remote}", "partial", cwd=self.env.root)
        partial = self.env.root / "partial"
        self.env.git("remote", "set-url", "origin", self.env.ORIGIN, cwd=partial)
        self.env.redirect_origin(partial, self.env.ORIGIN)
        self.assertEqual("true", self.git("config", "remote.origin.promisor", cwd=partial), "it is a partial clone")
        old = self.git("rev-parse", "HEAD", cwd=partial)
        new = self.push()
        before = self.objects(partial)
        self.stops(f"local main is at {old[:12]} but origin's main is at {new[:12]}; {partial} is a partial clone, which "
                   f"the runner does not fast-forward: run git pull --ff-only in {partial} and start the runner again",
                   str(partial))
        self.assertEqual((old, before), (self.git("rev-parse", "HEAD", cwd=partial), self.objects(partial)))
        with self.assertRaises(pr_loop.Stop):
            self.checkout(str(partial), dry_run=True)
        self.checkout()  # control: the same remote, a full clone, is fast-forwarded
        self.assertEqual(new, self.tip())

    def test_a_tip_without_a_helper_is_refused_and_the_branch_stays(self):
        old = self.tip()
        new = self.push(remove=(HELPER_PATHS[1],))
        message = (f"origin's default branch main at {new[:12]} lacks {HELPER_PATHS[1]}; the skills it hosts could not "
                   "report or sign")
        found = self.checkout(dry_run=True)  # the tip is not in the checkout: a dry run cannot tell, and does not refuse
        self.assertEqual((old, new, False), found.would_forward)
        self.stops(message)
        self.untouched(old)
        self.assertTrue(self.has(new), "the tip was fetched: the helpers are judged on it before the branch moves")
        self.stops(message, dry_run=True)  # now that the tip is in the checkout, a dry run reads it and says the same

    def test_a_tip_that_moves_a_submodule_is_refused(self):
        old = self.tip()
        added = self.push_gitlink("vendor/sub", old)
        message = (f"origin's main at {added[:12]} moves the submodule vendor/sub; the runner does not update submodules: "
                   f"run git pull --ff-only and git submodule update in {self.path} and start the runner again")
        self.stops(message)
        self.untouched(old)
        # a gitlink the checkout already has, moved by the tip
        self.git("pull", "-q", "--ff-only", "origin", "main")
        self.assertEqual(added, self.tip())
        moved = self.push_gitlink("vendor/sub", added, name="move")
        self.stops(message.replace(added[:12], moved[:12]))
        self.untouched(added)

    def test_a_tip_that_would_write_into_ignored_paths_is_refused_and_the_tree_stays_as_it_is(self):
        def nested():
            where = self.path / "vendor/x"
            where.mkdir(parents=True)
            self.env.git("init", "-q", "-b", "main", cwd=where)
            (where / "mine.txt").write_text("the operator's own repository\n")
            self.ignore("vendor/")
            return {"vendor/x/tracked.txt": "from origin\n"}, "vendor/x/tracked.txt"

        def ignored_file():
            (self.path / "notes.log").write_text("ignored, and mine\n")
            self.ignore("*.log")
            return {"notes.log": "from origin\n"}, "notes.log"

        def ignored_directory():
            (self.path / "build").mkdir()
            (self.path / "build/out.txt").write_text("ignored, and mine\n")
            self.ignore("build/")
            return {"build": "a file where a directory stands\n"}, "build"
        for name, setup in (("a nested repository", nested), ("a file", ignored_file), ("a directory", ignored_directory)):
            with self.subTest(case=name):
                self.fresh()
                (self.path / ".git/info/exclude").write_text("")
                old = self.tip()
                files, example = setup()
                new = self.push(files=files, name="tracks-" + name.replace(" ", "-"))
                before = self.tree()
                self.assertEqual("", self.git("status", "--porcelain=v1", "--untracked-files=all"))
                error = str(self.refused())
                self.assertRegex(error, rf"(?s)^fast-forwarding main to {new[:12]} would overwrite, delete or write into "
                                        rf"ignored paths in {re.escape(str(self.path))} \(\d+ paths, e.g. [^)]*"
                                        rf"{re.escape(example.split('/')[0])}[^)]*\); move them out of the way and start the "
                                        "runner again; the runner never deletes them$")
                self.untouched(old)
                self.assertEqual(before, self.tree(), "every file, ignored ones too, is as it was")
                self.assertTrue(self.has(new), "the tip was fetched, which is all that was written")

    def test_git_itself_still_refuses_to_overwrite_an_ignored_file_when_the_check_is_blind(self):
        # The backstop: `--no-overwrite-ignore`. The collision check is replaced by one that finds nothing.
        old = self.tip()
        (self.path / "notes.log").write_text("ignored, and mine\n")
        self.ignore("*.log")
        new = self.push(files={"notes.log": "from origin\n"})
        with patch.object(pr_loop, "check_ignored_collisions", lambda *args: []):
            error = str(self.refused())
        self.assertRegex(error, rf"(?s)^git merge --ff-only {new[:12]} failed \(\d+\): .*notes\.log.*; main is still at "
                                rf"{old[:12]} and clean$")
        self.untouched(old)
        self.assertEqual("ignored, and mine\n", (self.path / "notes.log").read_text())

    def test_a_dry_run_writes_nothing_whether_or_not_the_tip_is_in_the_checkout(self):
        for fetched in (False, True):
            with self.subTest(fetched=fetched):
                self.fresh()
                old = self.tip()
                new = self.push(name=f"dry-{fetched}")
                if fetched:
                    self.git("fetch", "-q", "origin")
                os.utime(self.path / "README.txt", (1, 1))  # a plain `git status` would rewrite the index
                subprocess.run(["git", "status", "--porcelain"], cwd=self.path, env=self.env.git_env, check=True,
                               capture_output=True)
                os.utime(self.path / "README.txt", (2, 2))
                before = self.written()
                found = self.checkout(dry_run=True)
                self.assertEqual(before, self.written())
                self.assertEqual((old, None, (old, new, fetched)), (found.head, found.forwarded, found.would_forward))
                found.announce()
                self.assertEqual(f"would fetch origin's main at {new[:12]} and fast-forward main from {old[:12]} to it",
                                 self.told[1])
                unchecked = "because " + new[:12] + " is not in the checkout and a dry run does not fetch it"
                self.assertEqual(not fetched, unchecked in self.told[-1])
                self.assertEqual(before, self.written(), "announcing writes nothing either")
                self.told.clear()

    def test_a_failed_fetch_leaves_the_checkout_and_its_refs_as_they_were(self):
        old = self.tip()
        self.push()
        real = pr_loop.git
        made_up = "c" * 40

        def listing(cwd, *args, **kwargs):
            if args[:1] == ("ls-remote",):
                return subprocess.CompletedProcess(args, 0, f"ref: refs/heads/main\tHEAD\n{made_up}\tHEAD\n", "")
            return real(cwd, *args, **kwargs)
        before = self.refs()
        with patch.object(pr_loop, "git", listing):
            error = str(self.refused())
        self.assertRegex(error, rf"(?s)^cannot fetch origin's main at {made_up[:12]} into {re.escape(str(self.path))}: git "
                                r"fetch failed \(\d+\): .+; main was not changed$")
        self.untouched(old)
        self.assertEqual(before, self.refs())

    def test_what_a_failed_fetch_says_never_carries_a_url_with_a_token(self):
        # SYNTHETIC: git quotes the URL back, userinfo and all, in some failures.
        token = "tok" + uuid.uuid4().hex
        url = f"https://x-access-token:{token}@github.com/acme/demo.git"
        self.git("remote", "set-url", "origin", url)
        self.env.redirect_origin(self.path, url, replace=True)
        new = self.push()
        quoting = lambda cwd, sub, *args: subprocess.CompletedProcess(args, 128, "", f"fatal: unable to access '{url}/': boom {url}")
        with patch.object(pr_loop, "git_change", quoting):
            error = str(self.refused())
        self.assertNotIn(token, error)
        self.assertEqual(f"cannot fetch origin's main at {new[:12]} into {self.path}: git fetch failed (128): fatal: unable "
                         "to access '<origin>/': boom <origin>; main was not changed", error)

    def test_a_merge_git_refuses_is_reported_with_gits_words_and_the_state_it_left(self):
        old = self.tip()
        new = self.push()
        self.git("config", "merge.verifySignatures", "true")
        error = str(self.refused())
        self.assertRegex(error, rf"(?s)^git merge --ff-only {new[:12]} failed \(\d+\): .+; main is still at {old[:12]} and "
                                "clean$")
        self.untouched(old)
        self.git("config", "--unset", "merge.verifySignatures")
        self.checkout()  # control: without it the same checkout is fast-forwarded
        self.assertEqual(new, self.tip())

    def test_a_merge_that_changed_something_before_it_failed_says_where_the_checkout_is(self):
        old = self.tip()
        new = self.push()
        real = pr_loop.git_change

        def leaves_it_dirty(cwd, sub, *args):
            if sub == "merge":
                (Path(cwd) / "left.txt").write_text("x\n")
                self.git("switch", "-q", "-c", "elsewhere")
                return subprocess.CompletedProcess(args, 1, "", "synthetic failure\n")
            return real(cwd, sub, *args)
        with patch.object(pr_loop, "git_change", leaves_it_dirty):
            error = str(self.refused())
        self.assertEqual(f"git merge --ff-only {new[:12]} failed (1): synthetic failure; the checkout is now on elsewhere at "
                         f"{old[:12]} with uncommitted changes: inspect it before starting the runner again", error)

    def test_a_configured_squash_cannot_turn_the_fast_forward_into_a_squash(self):
        old = self.tip()
        new = self.push()
        self.git("config", "branch.main.mergeOptions", "--squash")
        found = self.checkout()
        self.assertEqual((new, new), (self.tip(), found.head))
        self.assertEqual("", self.git("status", "--porcelain=v1"), "a squash would leave the tree changed, uncommitted")
        self.assertNotEqual(old, self.tip())

    def test_a_merge_that_reports_success_without_moving_the_branch_is_refused(self):
        old = self.tip()
        new = self.push()
        real = pr_loop.git_change
        shim = lambda cwd, sub, *args: subprocess.CompletedProcess(args, 0, "", "") if sub == "merge" else real(cwd, sub, *args)
        with patch.object(pr_loop, "git_change", shim):
            error = str(self.refused())
        self.assertEqual(f"git merge --ff-only {new[:12]} reported success but did not leave main at {new[:12]}, clean, "
                         f"with no git operation in progress; main is still at {old[:12]} and clean", error)
        self.untouched(old)

    def test_hooks_do_not_run_for_the_fetch_or_the_merge(self):
        marker = self.env.root / "hook-ran"
        for hook in ("post-merge", "reference-transaction", "post-checkout", "pre-merge-commit"):
            path = self.path / ".git/hooks" / hook
            path.write_text(f"#!/bin/sh\necho {hook} >> {marker}\n")
            path.chmod(0o755)
        subprocess.run(["git", "hook", "run", "post-merge"], cwd=self.path, env=self.env.git_env, check=True)
        self.assertTrue(marker.is_file(), "control: the hook runs when git is asked to run it")
        marker.unlink()
        new = self.push()
        self.checkout()
        self.assertEqual(new, self.tip())
        self.assertFalse(marker.exists(), marker.read_text() if marker.exists() else "")

    def test_a_refusal_that_comes_first_comes_first_and_nothing_is_fetched(self):
        held = []

        def pane():
            self.env.update_tmux(listing=[self.env.row("pilot-pr-7-draft-0123456789", "%3", path=self.path)])
            return (f"^agent pane %3 \\(session pilot-pr-7-draft-0123456789\\) is still running in "
                    f"{re.escape(str(self.path))}")

        def dirty():
            (self.path / "stray.txt").write_text("x")
            return "^checkout .* has uncommitted changes or untracked files"

        def locked():
            fd = os.open(self.path / ".git/pilot-pr-loop.lock", os.O_RDWR | os.O_CREAT, 0o600)
            held.append(fd)
            pr_loop.fcntl.flock(fd, pr_loop.fcntl.LOCK_EX | pr_loop.fcntl.LOCK_NB)
            return "^another pr_loop runner is using the checkout"
        for name, setup in (("a live agent pane", pane), ("uncommitted work", dirty), ("another runner", locked)):
            with self.subTest(name=name):
                self.fresh()
                self.env.reset_tmux()
                old = self.tip()
                self.push(name=name.replace(" ", "-"))
                before = self.objects()
                pattern = setup()
                self.assertRegex(str(self.refused()), pattern)
                self.assertEqual((before, old), (self.objects(), self.tip()), "nothing was fetched, the branch stayed")
                while held:
                    os.close(held.pop())
        self.fresh()
        self.env.reset_tmux()
        old = self.tip()
        self.push(name="control")
        self.checkout()  # control: with all three out of the way, the same checkout is fast-forwarded
        self.assertNotEqual(old, self.tip())

    def test_the_run_says_what_it_changed_when_it_ends(self):
        old = self.tip()
        new = self.push()
        found = self.checkout()
        self.told.clear()
        found.finish()
        self.assertEqual([f"Kept: the task files under {self.path / '.pr-loop'} and any agent window still open in tmux "
                          f"session {pr_loop.session_name(self.path)}; close the agents still running in {self.path} before "
                          f"the next run. The runner changed {self.path} only by fast-forwarding main from {old[:12]} to "
                          f"{new[:12]} at the start; nothing else in it was deleted or reset."], self.told)

    def test_ctrl_c_during_the_fast_forward_says_what_to_check(self):
        old = self.tip()
        new = self.push()
        real = pr_loop.git_change
        text = (f"Interrupted while fast-forwarding main in {self.path} (from {old[:12]} to {new[:12]}); check it with git "
                "status before the next run.\n")
        for sub in ("fetch", "merge"):
            with self.subTest(interrupted=sub):
                def interrupts(cwd, name, *args, _sub=sub):
                    if name == _sub:
                        raise KeyboardInterrupt
                    return real(cwd, name, *args)
                argv = ["pr_loop.py", "7", "--repo", "acme/demo", "--checkout", str(self.path)]
                errors = io.StringIO()
                with patch.object(sys, "argv", argv), patch.object(pr_loop, "git_change", interrupts), \
                     patch.object(pr_loop.Batch, "drive", side_effect=pr_loop.Stop("no interrupt: the run went on")), \
                     contextlib.redirect_stderr(errors):
                    code = pr_loop.main()
                self.assertEqual((130, text), (code, errors.getvalue()))
                self.untouched(old)
                pr_loop.os.close(pr_loop.lock_checkout(self.path, self.path / ".git/pilot-pr-loop.lock"))  # the lock was given back

    def test_ctrl_c_before_the_fast_forward_began_says_that_nothing_was_written(self):
        self.push()
        argv = ["pr_loop.py", "7", "--repo", "acme/demo", "--checkout", str(self.path)]
        errors = io.StringIO()
        with patch.object(sys, "argv", argv), patch.object(pr_loop, "check_panes", side_effect=KeyboardInterrupt), \
             patch.object(pr_loop.Batch, "drive", side_effect=pr_loop.Stop("no interrupt: the run went on")), \
             contextlib.redirect_stderr(errors):
            self.assertEqual(130, pr_loop.main())
        self.assertEqual("Interrupted; nothing was written.\n", errors.getvalue())


class CheckoutSwitchTests(FastForwardCase):
    """A clean checkout on another branch is switched to origin's default branch at startup (and not switched back): the
    default branch is moved to the tip first when it is strictly behind, by a local fast-forward that git itself checks.
    Every refusal comes before the first write to a ref of the operator's."""

    def on_other(self, name="feature", commit=None):
        """Leave `main` for a new branch `name` (with a commit of its own when `commit` names a file); its commit."""
        self.git("switch", "-q", "-c", name)
        return self.commit(commit) if commit else self.tip()

    def back(self, other):
        return f"git -C {self.path} switch {other}"

    def switched(self, other, at, branch="main"):
        return f"Switched {self.path} from {other} (at {at[:12]}) to {branch}; to go back: {self.back(other)}"

    def still_on(self, other, at, *, main=None):
        """What a refusal leaves: HEAD on `other` at `at`, a clean tree, `main` where it was."""
        self.assertEqual(("refs/heads/" + other, at), (self.git("symbolic-ref", "HEAD"), self.tip()))
        self.assertEqual(at, self.git("rev-parse", f"refs/heads/{other}"))
        self.assertEqual("", self.git("status", "--porcelain=v1", "--untracked-files=all"))
        if main is not None:
            self.assertEqual(main, self.git("rev-parse", "refs/heads/main"), "main was not moved")

    def logs(self):
        root = self.path / ".git/logs"
        return {str(f.relative_to(root)): f.read_bytes() for f in sorted(root.rglob("*")) if f.is_file()} if root.is_dir() else {}

    def test_a_clean_checkout_on_another_branch_is_switched_to_the_default_branch_at_the_tip(self):
        tip = self.env.remote_head
        for tracked in (False, True):
            with self.subTest(tracked=tracked):
                self.fresh()
                self.told.clear()
                tip = self.env.remote_head
                self.git("switch", "-q", "-c", "feature", *(["--track", "origin/main"] if tracked else []))
                objects = self.objects()
                found = self.checkout()
                self.assertEqual(("refs/heads/main", tip), (self.git("symbolic-ref", "HEAD"), self.tip()))
                self.assertEqual(tip, self.git("rev-parse", "refs/heads/feature"), "the branch it left is untouched")
                self.assertEqual("", self.git("status", "--porcelain=v1", "--untracked-files=all"))
                self.assertEqual([self.switched("feature", tip)], self.told[:1], "and said first")
                self.assertEqual(("refs/heads/main", tip, ("feature", tip), None),
                                 (found.branch, found.head, found.switched, found.forwarded))
                self.assertEqual(objects, self.objects(), "the default branch was at the tip: nothing was fetched")
                self.assertFalse((self.path / ".git/FETCH_HEAD").exists())
                found.verify()  # the run goes on from the default branch

    def test_a_branch_with_commits_of_its_own_and_no_upstream_keeps_them(self):
        old = self.tip()
        mine = self.on_other("feature", "mine.txt")
        self.assertNotEqual(old, mine)
        found = self.checkout()
        self.assertEqual(("refs/heads/main", old), (self.git("symbolic-ref", "HEAD"), self.tip()))
        self.assertEqual(mine, self.git("rev-parse", "refs/heads/feature"), "its commit is still where it was")
        self.assertEqual(mine, self.git("rev-parse", "feature"))
        self.assertFalse((self.path / "mine.txt").exists(), "the work tree is main's")
        self.assertEqual(("feature", mine), found.switched)
        self.assertEqual(self.switched("feature", mine), self.told[0])

    def test_a_default_branch_behind_origin_is_fast_forwarded_by_git_and_then_switched_to(self):
        old = self.tip()
        feature = self.on_other()
        new = self.push()
        self.assertFalse(self.has(new))
        found = self.checkout()
        self.assertEqual(("refs/heads/main", new, new), (self.git("symbolic-ref", "HEAD"), self.tip(), found.head))
        self.assertEqual(new, self.git("rev-parse", "refs/heads/main"))
        self.assertEqual(new, self.git("rev-parse", "refs/remotes/origin/main"))
        self.assertEqual(feature, self.git("rev-parse", "refs/heads/feature"))
        self.assertEqual([self.line("main", old, new), self.switched("feature", feature)], self.told[:2])
        self.assertIn("fast-forward", self.git("reflog", "-1", "--format=%gs", "refs/heads/main"))
        self.assertEqual((("feature", feature), (old, new)), (found.switched, found.forwarded))
        self.assertFalse((self.path / ".git/FETCH_HEAD").exists())
        self.assertEqual("", self.git("tag", "--list"))
        self.assertEqual("", self.git("status", "--porcelain=v1", "--untracked-files=all"))

    def test_a_default_branch_with_commits_origin_does_not_have_is_refused_and_nothing_moves(self):
        self.git("switch", "-q", "-c", "feature")
        self.git("switch", "-q", "main")
        local = self.commit("mine.txt")
        feature = self.git("rev-parse", "refs/heads/feature")
        self.git("switch", "-q", "feature")
        tip = self.env.remote_head
        message = (f"local main at {local[:12]} has commits that origin's main ({tip[:12]}) does not have; the skills must "
                   "come from origin's default branch; the checkout was left on feature")
        before = self.objects()
        self.stops(message)
        self.still_on("feature", feature, main=local)
        self.assertEqual(before, self.objects(), "no fetch")
        # diverged, whether or not origin's tip was fetched
        new = self.push()
        diverged = (f"local main at {local[:12]} and origin's main at {new[:12]} have diverged (each has commits the other "
                    "does not have); the runner only fast-forwards: put main at origin's tip yourself and start the runner "
                    "again; the checkout was left on feature")
        for fetched in (False, True):
            with self.subTest(fetched=fetched):
                if fetched:
                    self.git("fetch", "-q", "origin")
                self.stops(diverged)
                self.still_on("feature", feature, main=local)
        with self.assertRaises(pr_loop.Stop) as dry:
            self.checkout(dry_run=True)
        self.assertEqual(diverged, str(dry.exception), "a dry run says the same once the tip is known")

    def test_git_itself_refuses_a_ref_move_that_is_not_a_fast_forward_when_the_classification_is_blind(self):
        # The backstop of the unforced `git fetch .`: a diverged branch that the classification wrongly calls behind.
        self.git("switch", "-q", "-c", "feature")
        self.git("switch", "-q", "main")
        local = self.commit("mine.txt")
        feature = self.git("rev-parse", "refs/heads/feature")
        self.git("switch", "-q", "feature")
        self.push()
        with patch.object(pr_loop.Checkout, "relation", lambda *args: "behind"):
            error = str(self.refused())
        self.assertRegex(error, rf"(?s)^cannot move main to [0-9a-f]{{12}} in {re.escape(str(self.path))}: git fetch \. failed "
                                rf"\(\d+\): .*main was not changed; the checkout is still on feature at {feature[:12]} and "
                                "clean$")
        self.still_on("feature", feature, main=local)

    def test_a_branch_or_a_tag_named_like_origins_default_branch_cannot_divert_the_switch(self):
        old = self.tip()
        between = self.push(name="between")
        new = self.push(name="tip")
        self.git("fetch", "-q", "origin")
        self.git("branch", "origin/main", between)
        self.git("tag", "main", between)
        self.git("update-ref", f"refs/heads/{new}", between)
        self.on_other()
        self.assertEqual(old, self.git("rev-parse", "refs/heads/main"))
        found = self.checkout()
        self.assertEqual(("refs/heads/main", new, new), (self.git("symbolic-ref", "HEAD"), self.tip(), found.head))
        self.assertEqual(new, self.git("rev-parse", "refs/heads/main"))
        self.assertEqual(between, self.git("rev-parse", "refs/heads/origin/main"), "the decoys were left alone")
        self.assertEqual(between, self.git("rev-parse", "refs/tags/main^{commit}"))

    def test_a_tip_that_would_write_into_ignored_paths_is_refused_before_a_ref_moves(self):
        def nested():
            where = self.path / "vendor/x"
            where.mkdir(parents=True)
            self.env.git("init", "-q", "-b", "main", cwd=where)
            (where / "mine.txt").write_text("the operator's own repository\n")
            self.ignore("vendor/")
            return {"vendor/x/tracked.txt": "from origin\n"}, "vendor"

        def ignored_file():
            (self.path / "notes.log").write_text("ignored, and mine\n")
            self.ignore("*.log")
            return {"notes.log": "from origin\n"}, "notes.log"
        for name, setup in (("a nested repository", nested), ("a file", ignored_file)):
            with self.subTest(case=name):
                self.fresh()
                (self.path / ".git/info/exclude").write_text("")
                main = self.tip()
                self.git("switch", "-q", "-c", "feature")
                files, example = setup()
                new = self.push(files=files, name="tracks-" + name.replace(" ", "-"))
                before = self.tree()
                error = str(self.refused())
                self.assertRegex(error, rf"(?s)^switching {re.escape(str(self.path))} to main at {new[:12]} would overwrite, "
                                        rf"delete or write into ignored paths in {re.escape(str(self.path))} \(\d+ paths, "
                                        rf"e\.g\. [^)]*{re.escape(example)}[^)]*\); move them out of the way and start the "
                                        "runner again; the runner never deletes them$")
                self.still_on("feature", main, main=main)
                self.assertEqual(before, self.tree(), "every file, ignored ones too, is as it was")
                self.assertEqual(main, self.git("rev-parse", "refs/heads/main"), "no ref was moved before the checks")

    def test_git_itself_refuses_to_overwrite_an_ignored_file_in_the_switch_when_the_check_is_blind(self):
        # The backstop of `--no-overwrite-ignore`: the collision check is replaced by one that finds nothing.
        feature = self.on_other()
        (self.path / "notes.log").write_text("ignored, and mine\n")
        self.ignore("*.log")
        self.push(files={"notes.log": "from origin\n"})
        with patch.object(pr_loop, "check_ignored_collisions", lambda *args: []):
            error = str(self.refused())
        self.assertRegex(error, rf"(?s)^git switch to main failed \(\d+\): .*notes\.log.*; the checkout is still on feature "
                                rf"at {feature[:12]} and clean; main was fast-forwarded to [0-9a-f]{{12}}$")
        self.assertEqual("ignored, and mine\n", (self.path / "notes.log").read_text())
        self.assertEqual(("refs/heads/feature", feature), (self.git("symbolic-ref", "HEAD"), self.tip()))

    def test_a_checkout_with_no_local_default_branch_is_refused_and_nothing_is_created(self):
        self.on_other()
        self.git("branch", "-q", "-D", "main")
        feature = self.tip()
        self.push()
        message = (f"checkout {self.path} is on feature, and it has no local main, the default branch of origin; the runner "
                   "switches only to an existing local branch: create it at origin's tip yourself and start the runner again")
        before = self.objects()
        for dry_run in (False, True):
            with self.subTest(dry_run=dry_run):
                self.stops(message, dry_run=dry_run)
                self.still_on("feature", feature)
                done = subprocess.run(["git", "rev-parse", "--verify", "--quiet", "refs/heads/main"], cwd=self.path,
                                      env=self.env.git_env, capture_output=True)
                self.assertEqual(1, done.returncode, "refs/heads/main still does not exist")
        self.assertEqual(before, self.objects(), "nothing was fetched")

    def rebase_stops(self, where):
        """Start an interactive rebase in `where` that stops at its first commit: the work tree is mid-rebase."""
        env = dict(self.env.git_env, GIT_SEQUENCE_EDITOR="sed -i '1s/^pick/edit/'")
        subprocess.run(["git", "rebase", "-q", "-i", "--root"], cwd=where, env=env, capture_output=True, text=True)
        self.assertTrue((Path(self.git("rev-parse", "--path-format=absolute", "--git-path", "rebase-merge", cwd=where))).is_dir())

    def test_a_default_branch_another_work_tree_holds_is_refused_and_nothing_moves(self):
        for case in ("a plain work tree", "a prunable work tree", "a work tree in the middle of a rebase"):
            with self.subTest(case=case):
                self.fresh()
                self.git("switch", "-q", "-c", "feature")
                main = self.tip()
                where = self.env.root / "other-tree"
                shutil.rmtree(where, ignore_errors=True)
                self.git("worktree", "prune")
                self.git("worktree", "add", "-q", str(where), "main")
                if case.startswith("a prunable"):
                    shutil.rmtree(where)
                    self.assertIn("prunable", self.git("worktree", "list", "--porcelain"))
                if case.endswith("rebase"):
                    self.rebase_stops(where)
                self.push(name="tip-" + case.split()[1])
                before = self.git("status", "--porcelain=v1", "--untracked-files=all", cwd=where) if where.exists() else None
                error = str(self.refused())
                if case.endswith("rebase"):
                    self.assertRegex(error, rf"^checkout {re.escape(str(self.path))} is on feature, and the work tree "
                                            rf"{re.escape(str(where))} has a git operation in progress \(rebase-merge\); "
                                            "the runner does not move or switch to main while it may hold it: finish or "
                                            "abort it and start the runner again$")
                else:
                    self.assertEqual(f"checkout {self.path} is on feature, and main, the default branch of origin, is checked "
                                     f"out in another work tree ({where}); the runner does not switch to it: start the "
                                     "runner in that work tree, or check out another branch there, and start the runner "
                                     "again", error)
                self.still_on("feature", main, main=main)
                if before is not None:
                    self.assertEqual(before, self.git("status", "--porcelain=v1", "--untracked-files=all", cwd=where),
                                     "the other work tree is as it was")
                if case.endswith("rebase"):
                    self.git("rebase", "--abort", cwd=where)

    def test_git_itself_refuses_to_move_a_branch_another_work_tree_holds_when_the_pre_check_is_blind(self):
        # The backstop of the ref move: `git fetch .` refuses a branch that is checked out elsewhere (`update-ref` would
        # have moved it under that work tree and left it dirty). The pre-check is replaced by one that sees nothing.
        feature = self.on_other()
        main = self.git("rev-parse", "refs/heads/main")
        where = self.env.root / "other-tree"
        self.git("worktree", "add", "-q", str(where), "main")
        self.push()
        before = self.git("status", "--porcelain=v1", cwd=where)
        with patch.object(pr_loop.Checkout, "check_worktrees", lambda *args: None):
            error = str(self.refused())
        self.assertRegex(error, rf"(?s)^cannot move main to [0-9a-f]{{12}} in {re.escape(str(self.path))}: git fetch \. failed "
                                rf"\(\d+\): .*main was not changed; the checkout is still on feature at {feature[:12]} and "
                                "clean$")
        self.still_on("feature", feature, main=main)
        self.assertEqual((main, before), (self.git("rev-parse", "refs/heads/main", cwd=where),
                                          self.git("status", "--porcelain=v1", cwd=where)), "the other work tree is as it was")

    def test_a_switch_never_creates_the_default_branch_from_a_remote_ref_of_that_name(self):
        # The backstop of `--no-guess`: the branch disappears between the checks and the switch, and git must not make it
        # again from refs/remotes/origin/main.
        feature = self.on_other()
        real = pr_loop.git_change

        def branch_goes(cwd, sub, *args):
            if sub == "switch":
                self.git("update-ref", "-d", "refs/heads/main")
            return real(cwd, sub, *args)
        with patch.object(pr_loop, "git_change", branch_goes):
            error = str(self.refused())
        self.assertRegex(error, rf"(?s)^git switch to main failed \(\d+\): .*; the checkout is still on feature at "
                                rf"{feature[:12]} and clean$")
        done = subprocess.run(["git", "rev-parse", "--verify", "--quiet", "refs/heads/main"], cwd=self.path,
                              env=self.env.git_env, capture_output=True)
        self.assertEqual(1, done.returncode, "refs/heads/main was not created")
        self.assertEqual(("refs/heads/feature", feature), (self.git("symbolic-ref", "HEAD"), self.tip()))

    def test_another_work_tree_with_an_operation_in_progress_is_refused_even_when_it_does_not_hold_the_default_branch(self):
        self.on_other("feature", "mine.txt")
        main = self.git("rev-parse", "refs/heads/main")
        where = self.env.root / "side-tree"
        self.git("worktree", "add", "-q", "-b", "side", str(where), "main")
        self.commit("side.txt", cwd=where)
        self.rebase_stops(where)
        self.push()
        message = (f"checkout {self.path} is on feature, and the work tree {where} has a git operation in progress "
                   "(rebase-merge); the runner does not move or switch to main while it may hold it: finish or abort it and "
                   "start the runner again")
        self.stops(message)
        self.assertEqual(main, self.git("rev-parse", "refs/heads/main"))
        self.assertEqual("refs/heads/feature", self.git("symbolic-ref", "HEAD"))
        self.git("rebase", "--abort", cwd=where)
        self.checkout()  # control: with the rebase gone the same checkout is switched
        self.assertEqual("refs/heads/main", self.git("symbolic-ref", "HEAD"))

    def test_hooks_do_not_run_for_the_switch(self):
        marker = self.env.root / "hook-ran"
        for hook in ("post-checkout", "reference-transaction", "post-merge"):
            path = self.path / ".git/hooks" / hook
            path.write_text(f"#!/bin/sh\necho {hook} >> {marker}\n")
            path.chmod(0o755)
        self.on_other()
        marker.unlink(missing_ok=True)
        subprocess.run(["git", "hook", "run", "post-checkout", "--ignore-missing"], cwd=self.path, env=self.env.git_env,
                       check=True)
        self.assertTrue(marker.is_file(), "control: the hook runs when git is asked to run it")
        marker.unlink()
        self.push()
        self.checkout()
        self.assertEqual("refs/heads/main", self.git("symbolic-ref", "HEAD"))
        self.assertFalse(marker.exists(), marker.read_text() if marker.exists() else "")

    def test_a_detached_head_is_refused_with_the_unchanged_text_reachable_or_not(self):
        main = self.tip()
        self.git("switch", "-q", "--detach")
        self.stops(f"checkout {self.path} has a detached HEAD at {main[:12]}; check out main, the default branch of origin")
        lost = self.commit("lost.txt")
        self.assertEqual("", self.git("for-each-ref", "--contains", lost, "--format=%(refname)"))
        self.stops(f"checkout {self.path} has a detached HEAD at {lost[:12]}; check out main, the default branch of origin")
        self.assertEqual(lost, self.tip())
        self.assertEqual(main, self.git("rev-parse", "refs/heads/main"))

    def test_a_current_branch_without_a_commit_is_refused(self):
        self.git("switch", "-q", "--orphan", "fresh")
        self.assertEqual("", self.git("status", "--porcelain=v1", "--untracked-files=all"))
        self.stops(f"checkout {self.path} is on fresh, which has no commit; check out main, the default branch of origin")
        self.assertEqual("refs/heads/fresh", self.git("symbolic-ref", "HEAD"))

    def test_a_dry_run_on_another_branch_writes_nothing_and_says_what_it_would_do(self):
        for state in ("equal", "behind, the tip in the checkout", "behind, the tip not in the checkout"):
            with self.subTest(state=state):
                self.fresh()
                main = self.tip()
                self.git("switch", "-q", "-c", "feature")
                new = None if state == "equal" else self.push(name="dry-" + state.split(",")[0])
                if new and "not" not in state:
                    self.git("fetch", "-q", "origin")
                os.utime(self.path / "README.txt", (1, 1))  # a plain `git status` would rewrite the index
                subprocess.run(["git", "status", "--porcelain"], cwd=self.path, env=self.env.git_env, check=True,
                               capture_output=True)
                os.utime(self.path / "README.txt", (2, 2))
                before = self.written()
                found = self.checkout(dry_run=True)
                self.assertEqual(before, self.written())
                self.assertEqual((main, ("feature", main, "main")), (found.head, found.would_switch))
                self.assertEqual("refs/heads/feature", found.branch)
                found.announce()
                expected = [f"Checkout: {self.path} (feature at {main[:12]})"]
                if new:
                    expected.append(f"would fetch origin's main at {new[:12]} and fast-forward main from {main[:12]} to it")
                expected.append(f"would switch {self.path} from feature (at {main[:12]}) to main")
                self.assertEqual(expected, self.told[:len(expected)])
                unchecked = f"because {(new or '')[:12]} is not in the checkout and a dry run does not fetch it"
                self.assertEqual("not" in state, unchecked in self.told[-1])
                if "not" in state:
                    self.assertIn(f"whether origin's main at {new[:12]} is a fast-forward of main, has the two helpers, moves "
                                  "no submodule and leaves ignored files alone", self.told[-1])
                self.assertEqual(before, self.written(), "announcing writes nothing either")
                self.told.clear()

    def test_a_refusal_that_comes_first_comes_first_when_the_checkout_is_on_another_branch(self):
        held = []

        def pane():
            self.env.update_tmux(listing=[self.env.row("pilot-pr-7-draft-0123456789", "%3", path=self.path)])
            return "^agent pane %3 "

        def dirty():
            (self.path / "stray.txt").write_text("x")
            return "^checkout .* has uncommitted changes or untracked files"

        def locked():
            fd = os.open(self.path / ".git/pilot-pr-loop.lock", os.O_RDWR | os.O_CREAT, 0o600)
            held.append(fd)
            pr_loop.fcntl.flock(fd, pr_loop.fcntl.LOCK_EX | pr_loop.fcntl.LOCK_NB)
            return "^another pr_loop runner is using the checkout"
        for name, setup in (("a live agent pane", pane), ("uncommitted work", dirty), ("another runner", locked)):
            with self.subTest(name=name):
                self.fresh()
                self.env.reset_tmux()
                main = self.tip()
                feature = self.on_other()
                self.push(name=name.replace(" ", "-"))
                before = self.objects()
                pattern = setup()
                self.assertRegex(str(self.refused()), pattern)
                self.assertEqual(before, self.objects(), "nothing was fetched")
                self.assertEqual(("refs/heads/feature", feature, main),
                                 (self.git("symbolic-ref", "HEAD"), self.tip(), self.git("rev-parse", "refs/heads/main")))
                while held:
                    os.close(held.pop())

    def test_a_tip_that_moves_a_submodule_between_the_branch_left_and_the_tip_is_refused_before_any_write(self):
        old = self.tip()
        added = self.push_gitlink("vendor/sub", old)
        self.git("pull", "-q", "--ff-only", "origin", "main")
        self.assertEqual(added, self.git("rev-parse", "refs/heads/main"))
        self.git("switch", "-q", "-c", "feature", old)  # (main is AT the tip; only the branch left differs from it)
        before = self.objects()
        self.stops(f"origin's main at {added[:12]} moves the submodule vendor/sub; the runner does not update submodules: "
                   f"run git pull --ff-only and git submodule update in {self.path} and start the runner again")
        self.still_on("feature", old, main=added)
        self.assertEqual(before, self.objects())

    def test_a_switch_that_fails_after_the_default_branch_moved_says_so_and_leaves_the_checkout_on_its_branch(self):
        feature = self.on_other()
        new = self.push()
        real = pr_loop.git_change

        def lock_the_index(cwd, sub, *args):
            if sub == "switch":
                (Path(cwd) / ".git/index.lock").write_text("")
            return real(cwd, sub, *args)
        with patch.object(pr_loop, "git_change", lock_the_index):
            error = str(self.refused())
        self.assertRegex(error, rf"(?s)^git switch to main failed \(\d+\): .*index\.lock.*; the checkout is still on feature "
                                rf"at {feature[:12]} and clean; main was fast-forwarded to {new[:12]}$")
        (self.path / ".git/index.lock").unlink()
        self.still_on("feature", feature, main=new)
        self.assertEqual(self.line("main", feature, new), self.told[0], "the move of the branch was said when it happened")

    def partial_clone(self, name="partial"):
        """A partial clone of origin (`--filter=blob:none`), origin rewritten as in the other tests, on a new branch
        `feature`: its path."""
        self.env.git("config", "uploadpack.allowFilter", "true", cwd=self.env.remote)
        shutil.rmtree(self.env.root / name, ignore_errors=True)
        self.env.git("clone", "-q", "--filter=blob:none", f"file://{self.env.remote}", name, cwd=self.env.root)
        where = self.env.root / name
        self.env.git("remote", "set-url", "origin", self.env.ORIGIN, cwd=where)
        self.env.redirect_origin(where, self.env.ORIGIN)
        self.assertEqual("true", self.git("config", "remote.origin.promisor", cwd=where), "it is a partial clone")
        self.env.git("switch", "-q", "-c", "feature", cwd=where)
        return where

    def test_a_partial_clone_on_another_branch_is_refused_before_a_ref_or_an_object_is_written(self):
        for behind in (False, True):
            for dry_run in (False, True):
                with self.subTest(behind=behind, dry_run=dry_run):
                    self.fresh()
                    where = self.partial_clone()
                    main = self.git("rev-parse", "refs/heads/main", cwd=where)
                    new = self.push(name="partial-tip") if behind else None
                    state = lambda: (self.git("symbolic-ref", "HEAD", cwd=where), self.tip(where), self.refs(where),
                                     self.objects(where))
                    before = state()
                    if behind:
                        message = (f"local main is at {main[:12]} but origin's main is at {new[:12]}; {where} is a partial "
                                   f"clone, which the runner does not fast-forward: run git pull --ff-only in {where} and "
                                   "start the runner again")
                    else:
                        message = (f"checkout {where} is on feature; {where} is a partial clone, which the runner does not "
                                   "switch: check out main, the default branch of origin, yourself and start the runner "
                                   "again")
                    self.stops(message, str(where), dry_run=dry_run)
                    self.assertEqual(before, state(), "no ref, no object, not even the tracking ref, was written")
                    self.assertEqual("feature", self.git("branch", "--show-current", cwd=where))

    def test_a_dry_run_runs_the_checks_on_the_tip_when_it_is_in_the_checkout_and_refuses_what_the_real_run_refuses(self):
        def helper():
            return self.push(remove=(HELPER_PATHS[0],), name="no-helper"), r"^origin's default branch main at \w+ lacks "

        def submodule():
            return self.push_gitlink("vendor/sub", self.tip()), r"^origin's main at \w+ moves the submodule vendor/sub; "

        def ignored():
            (self.path / "notes.log").write_text("ignored, and mine\n")
            self.ignore("*.log")
            return (self.push(files={"notes.log": "from origin\n"}, name="tracks-notes"),
                    r"^switching .* to main at \w+ would overwrite, delete or write into ignored paths in ")
        for name, setup in (("a helper missing from the tip", helper), ("a submodule moved by the tip", submodule),
                            ("an ignored path the tip tracks", ignored)):
            with self.subTest(case=name):
                self.fresh()
                (self.path / ".git/info/exclude").write_text("")
                feature = self.on_other()
                new, pattern = setup()
                self.git("fetch", "-q", "origin")
                self.assertTrue(self.has(new), "the tip is in the checkout, so a dry run can read it")
                before = self.written()
                dry = str(self.refused(dry_run=True))
                self.assertEqual(before, self.written(), "a dry run writes nothing, even when it refuses")
                self.assertRegex(dry, pattern)
                real = str(self.refused())
                self.assertEqual(real, dry, "the dry run refuses with the real run's words")
                self.still_on("feature", feature)

    def test_a_dry_run_refuses_a_submodule_the_tip_moves_even_when_the_default_branch_is_already_at_the_tip(self):
        old = self.tip()
        added = self.push_gitlink("vendor/sub", old)
        self.git("pull", "-q", "--ff-only", "origin", "main")
        self.git("switch", "-q", "-c", "feature", old)
        message = (f"origin's main at {added[:12]} moves the submodule vendor/sub; the runner does not update submodules: "
                   f"run git pull --ff-only and git submodule update in {self.path} and start the runner again")
        before = self.written()
        self.stops(message, dry_run=True)
        self.assertEqual(before, self.written())
        self.stops(message)

    def test_a_prunable_work_tree_that_does_not_hold_the_default_branch_does_not_stop_the_switch(self):
        feature = self.on_other()
        where = self.env.root / "gone-tree"
        self.git("worktree", "add", "-q", "-b", "side", str(where), "feature")
        shutil.rmtree(where)  # its directory is gone, `git worktree prune` has not run
        self.assertIn("prunable", self.git("worktree", "list", "--porcelain"))
        found = self.checkout()
        self.assertEqual(("refs/heads/main", ("feature", feature)), (self.git("symbolic-ref", "HEAD"), found.switched))
        self.assertIn("prunable", self.git("worktree", "list", "--porcelain"), "the runner did not prune it")

    def test_a_switch_that_git_stops_half_way_says_the_checkout_is_not_clean_and_does_not_claim_it_is_still_on_the_branch(self):
        # A required smudge filter that fails, on a path that differs between the branch left and the tip: git writes part
        # of the work tree and gives up. (`clean=cat` keeps `git status` working with a required filter.)
        feature = self.on_other()
        self.git("config", "filter.bad.required", "true")
        self.git("config", "filter.bad.smudge", "false")
        self.git("config", "filter.bad.clean", "cat")
        (self.path / ".git/info/attributes").write_text("README.txt filter=bad\n")
        new = self.push(files={"README.txt": "changed\n"})
        error = str(self.refused())
        self.assertRegex(error, rf"(?s)^git switch to main failed \(128\): .*smudge filter bad failed; the checkout is now on "
                                rf"feature at {feature[:12]} with uncommitted changes: inspect it before starting the runner "
                                "again$")
        self.assertNotIn("still on", error)
        self.assertNotIn("and clean", error)
        self.assertEqual("D README.txt", self.git("status", "--porcelain=v1"), "it really is not clean")
        self.assertEqual(new, self.git("rev-parse", "refs/heads/main"), "the default branch had been moved")

    def test_a_tip_that_cannot_be_read_after_it_was_fetched_is_refused_with_nothing_changed(self):
        # Defensive: the relation is unknown even after the fetch (patched: the one seam). From the default branch and from
        # another one the run stops, and neither the branch nor HEAD moves.
        for where in ("on the default branch", "on another branch"):
            with self.subTest(case=where):
                self.fresh()
                main = self.tip()
                feature = main if where == "on the default branch" else self.on_other()
                new = self.push(name="unreadable-" + where.split()[-1])
                with patch.object(pr_loop.Checkout, "relation", lambda *args: None):
                    error = str(self.refused())
                self.assertEqual(f"cannot read origin's main at {new[:12]} in {self.path} after fetching it; main was not "
                                 "changed", error)
                self.assertEqual(main, self.git("rev-parse", "refs/heads/main"))
                self.assertEqual(feature, self.tip())
                self.assertEqual("main" if where == "on the default branch" else "feature",
                                 self.git("branch", "--show-current"))

    def test_a_ref_move_that_reports_success_but_did_not_move_the_branch_is_refused(self):
        feature = self.on_other()
        main = self.git("rev-parse", "refs/heads/main")
        new = self.push()
        real = pr_loop.git_change
        shim = lambda cwd, sub, *args: (subprocess.CompletedProcess(args, 0, "", "") if sub == "fetch" and "." in args
                                        else real(cwd, sub, *args))
        with patch.object(pr_loop, "git_change", shim):
            error = str(self.refused())
        self.assertEqual(f"git fetch . reported success but main is not at {new[:12]} in {self.path}; the checkout is still "
                         f"on feature at {feature[:12]} and clean", error)
        self.still_on("feature", feature, main=main)

    def test_a_switch_that_reports_success_without_moving_head_is_refused(self):
        feature = self.on_other()
        real = pr_loop.git_change
        shim = lambda cwd, sub, *args: subprocess.CompletedProcess(args, 0, "", "") if sub == "switch" else real(cwd, sub, *args)
        with patch.object(pr_loop, "git_change", shim):
            error = str(self.refused())
        self.assertEqual("git switch to main reported success but did not leave the checkout on main at "
                         f"{self.env.remote_head[:12]}, clean, with no git operation in progress; the checkout is still on "
                         f"feature at {feature[:12]} and clean", error)

    def test_a_ref_move_that_git_refuses_leaves_everything_as_it_was(self):
        feature = self.on_other()
        main = self.git("rev-parse", "refs/heads/main")
        self.push()
        real = pr_loop.git_change

        def refused(cwd, sub, *args):
            if sub == "fetch" and "." in args:
                return subprocess.CompletedProcess(args, 128, "", "fatal: refusing to fetch into branch\n")
            return real(cwd, sub, *args)
        with patch.object(pr_loop, "git_change", refused):
            error = str(self.refused())
        self.assertRegex(error, rf"^cannot move main to [0-9a-f]{{12}} in {re.escape(str(self.path))}: git fetch \. failed "
                                rf"\(128\): fatal: refusing to fetch into branch; main was not changed; the checkout is still "
                                rf"on feature at {feature[:12]} and clean$")
        self.still_on("feature", feature, main=main)

    def test_the_run_says_how_to_go_back_when_it_ends(self):
        old = self.tip()
        feature = self.on_other()
        found = self.checkout()
        self.told.clear()
        found.finish()
        self.assertEqual([f"Kept: the task files under {self.path / '.pr-loop'} and any agent window still open in tmux "
                          f"session {pr_loop.session_name(self.path)}; close the agents still running in {self.path} before "
                          f"the next run. The runner switched {self.path} from feature (at {feature[:12]}) to main at the "
                          f"start; to go back: {self.back('feature')}; nothing else in it was deleted or reset."], self.told)
        self.assertEqual(("refs/heads/main", old), (self.git("symbolic-ref", "HEAD"), self.tip()), "it does not switch back")
        found.release()
        self.fresh()
        old = self.tip()
        feature = self.on_other()
        new = self.push()
        found = self.checkout()
        self.told.clear()
        found.finish()
        self.assertEqual(f"The runner switched {self.path} from feature (at {feature[:12]}) to main and fast-forwarded main "
                         f"from {old[:12]} to {new[:12]} at the start; to go back: {self.back('feature')}; nothing else in "
                         "it was deleted or reset.", self.told[0].split("before the next run. ")[1])

    def test_a_branch_name_with_awkward_characters_is_quoted_in_the_way_back(self):
        self.git("switch", "-q", "-c", "it's$x")
        self.checkout()
        self.assertEqual(f"git -C {self.path} switch 'it'\"'\"'s$x'", pr_loop.Checkout.way_back(self.path, "it's$x"))
        self.assertIn("'it'\"'\"'s$x'", self.told[0])

    def test_ctrl_c_during_the_switch_or_the_ref_move_says_what_to_check(self):
        feature = self.on_other()
        self.push()
        real = pr_loop.git_change
        text = (f"Interrupted while switching {self.path} from feature to main; check it with git status before the next "
                "run.\n")
        for where in ("the ref move", "the switch"):
            with self.subTest(interrupted=where):
                def interrupts(cwd, name, *args, _where=where):
                    if (_where == "the switch" and name == "switch") or (_where == "the ref move" and name == "fetch"
                                                                         and "." in args):
                        raise KeyboardInterrupt
                    return real(cwd, name, *args)
                argv = ["pr_loop.py", "7", "--repo", "acme/demo", "--checkout", str(self.path)]
                errors = io.StringIO()
                with patch.object(sys, "argv", argv), patch.object(pr_loop, "git_change", interrupts), \
                     patch.object(pr_loop.Batch, "drive", side_effect=pr_loop.Stop("no interrupt: the run went on")), \
                     contextlib.redirect_stderr(errors):
                    code = pr_loop.main()
                self.assertEqual((130, text), (code, errors.getvalue()))
                self.assertEqual(("refs/heads/feature", feature), (self.git("symbolic-ref", "HEAD"), self.tip()))
                pr_loop.os.close(pr_loop.lock_checkout(self.path, self.path / ".git/pilot-pr-loop.lock"))

    def test_ctrl_c_later_in_the_run_says_the_checkout_was_switched_and_how_to_go_back(self):
        feature = self.on_other()
        argv = ["pr_loop.py", "7", "--repo", "acme/demo", "--checkout", str(self.path)]
        errors = io.StringIO()
        with patch.object(sys, "argv", argv), patch.object(pr_loop.Batch, "drive", side_effect=KeyboardInterrupt), \
             contextlib.redirect_stderr(errors):
            code = pr_loop.main()
        session = pr_loop.session_name(self.path)
        self.assertEqual((130, f"Interrupted; any agent window still open in tmux session {session} and the task files under "
                               f"{self.path}/.pr-loop/ were kept. The checkout was switched from feature (at {feature[:12]}) "
                               f"to main at the start; to go back: {self.back('feature')}.\n"), (code, errors.getvalue()))
        self.assertEqual("refs/heads/main", self.git("symbolic-ref", "HEAD"), "it is not switched back")


# A killed process is a zombie (Z) until its parent (init, for an orphan) reaps it, and shows X (dead) for an instant while it is
# reaped: a check that counts X as running reads Z, then X, then nothing, and fails a test whose process was killed (the flake of
# kjelly/pilot#427: the same code failed one run in about twenty on Python 3.12).
DEAD_STATES = ("Z", "X", "x")


def alive(pid):
    """Whether process `pid` runs: a killed process stays a zombie until its parent (init, for an orphan) reaps it."""
    try:
        os.kill(pid, 0)
        with open(f"/proc/{pid}/stat") as stat_file:
            return stat_file.read().rsplit(")", 1)[1].split()[0] not in DEAD_STATES
    except OSError:  # gone between the two calls, or /proc says so
        return False


def group_members(pgid):
    """The pids of the live (not zombie) members of process group `pgid`."""
    found = []
    for name in os.listdir("/proc"):
        if name.isdigit():
            try:
                with open(f"/proc/{name}/stat") as stat_file:
                    state, _, group = stat_file.read().rsplit(")", 1)[1].split()[:3]
            except OSError:
                continue
            if state not in DEAD_STATES and int(group) == pgid:
                found.append(int(name))
    return found


class GitChangeTests(unittest.TestCase):
    """`git_change`, the one call that changes a checkout: what it runs, with what, and how it ends."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pr-loop-git-change-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / "bin").mkdir()
        (self.root / "work").mkdir()
        self.log = self.root / "log"
        self.signal = self.root / "after"
        patcher = patch.dict(os.environ, PATH=f"{self.root / 'bin'}{os.pathsep}{os.environ['PATH']}", GIT_FOO="inherited")
        patcher.start()
        self.addCleanup(patcher.stop)
        # A test run started in the background has SIGINT ignored: the interrupt these tests send would go nowhere.
        before = signal.signal(signal.SIGINT, signal.default_int_handler)
        self.addCleanup(signal.signal, signal.SIGINT, before)
        # Small limits for what the bounded-cleanup tests wait for. Whatever a test starts is killed when it ends, and by a
        # watchdog if it hangs: nothing may outlive the test, also when the code under test is wrong.
        for name, value in (("KILL_AFTER", 0.5), ("DRAIN", 0.5), ("POLL", 0.2)):
            patcher = patch.object(pr_loop, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(self.kill_leftovers)
        watchdog = threading.Timer(12, self.kill_leftovers)
        watchdog.daemon = True
        watchdog.start()
        self.addCleanup(watchdog.cancel)

    def fake_git(self, body):
        path = self.root / "bin/git"
        path.write_text(f"#!/bin/sh\necho $$ > {self.root}/leader\n" + body)
        path.chmod(0o755)

    def script(self, name, text):
        path = self.root / name
        path.write_text(text)
        return f"{shlex.quote(sys.executable)} {path}"

    def pid(self, name):
        return int((self.root / name).read_text())

    def kill_leftovers(self):
        for name in ("leader", "child", "helper"):
            with contextlib.suppress(OSError, ValueError):
                pid = self.pid(name)
                with contextlib.suppress(OSError):
                    os.killpg(os.getpgid(pid), signal.SIGKILL)
                os.kill(pid, signal.SIGKILL)

    def test_it_runs_the_subcommand_with_hooks_off_and_nothing_to_prompt_for(self):
        self.fake_git(f'{{ pwd; echo "$@"; echo "$GIT_TERMINAL_PROMPT $GIT_NO_LAZY_FETCH $LC_ALL $GIT_FOO"; }} > {self.log}\n'
                      "echo out; echo err >&2; exit 3\n")
        done = pr_loop.git_change(self.root / "work", "fetch", "--no-tags", "origin")
        self.assertEqual((3, "out\n", "err\n"), (done.returncode, done.stdout, done.stderr), "the caller judges the status")
        self.assertEqual([str(self.root / "work"),
                          "-c core.hooksPath=/dev/null -c maintenance.auto=false fetch --no-tags origin",
                          "0 1 C inherited"], self.log.read_text().splitlines())

    def test_it_changes_a_checkout_with_fetch_merge_and_switch_only(self):
        self.fake_git(f"echo ran > {self.log}\n")
        for sub in ("pull", "reset", "checkout", "clean", "stash", "config", "update-ref", "branch", "restore", "rebase"):
            with self.subTest(sub=sub):
                with self.assertRaisesRegex(pr_loop.Stop, rf"^git {sub} is not a command this runner changes a checkout with$"):
                    pr_loop.git_change(self.root / "work", sub)
        self.assertFalse(self.log.exists(), "nothing was run")

    def interrupt_soon(self, delay=0.3):
        self.interrupt_at(delay)

    def test_an_interrupted_merge_is_waited_for_and_the_interrupt_raised_afterwards(self):
        self.fake_git(f"sleep 1.2\necho finished > {self.signal}\n")
        self.interrupt_soon()
        with self.assertRaises(KeyboardInterrupt):
            pr_loop.git_change(self.root / "work", "merge", "--ff-only")
        self.assertEqual("finished\n", self.signal.read_text(), "the merge ran to its end before the interrupt left")

    def test_an_interrupted_switch_is_waited_for_like_a_merge(self):
        self.fake_git(f"sleep 1.2\necho finished > {self.signal}\n")
        self.interrupt_soon()
        with self.assertRaises(KeyboardInterrupt):
            pr_loop.git_change(self.root / "work", "switch", "--no-guess")
        self.assertEqual("finished\n", self.signal.read_text(), "the switch ran to its end before the interrupt left")

    def test_a_switch_is_run_with_hooks_off_like_the_other_two(self):
        self.fake_git(f'echo "$@" > {self.log}\n')
        pr_loop.git_change(self.root / "work", "switch", "--no-guess", "--", "main")
        self.assertEqual("-c core.hooksPath=/dev/null -c maintenance.auto=false switch --no-guess -- main",
                         self.log.read_text().strip())

    def test_an_interrupted_fetch_is_ended_first(self):
        self.fake_git(f"sleep 5\necho finished > {self.signal}\n")
        self.interrupt_soon()
        with self.assertRaises(KeyboardInterrupt):
            pr_loop.git_change(self.root / "work", "fetch")
        time.sleep(0.3)
        self.assertFalse(self.signal.exists(), "the fetch was ended, not left running")

    def test_a_command_that_outlives_its_limit_is_ended_even_when_it_ignores_sigterm(self):
        self.fake_git(f"trap '' TERM\nsleep 3\necho finished > {self.signal}\n")
        began = time.monotonic()
        with patch.dict(pr_loop.GIT_CHANGES, {"fetch": 0.3}), patch.object(pr_loop, "KILL_AFTER", 0.3):
            with self.assertRaisesRegex(pr_loop.Stop, r"^git fetch timed out after 0\.3 seconds$"):
                pr_loop.git_change(self.root / "work", "fetch")
        self.assertLess(time.monotonic() - began, 2.5, "it did not wait for the command to end by itself")
        time.sleep(0.5)
        self.assertFalse(self.signal.exists())


    # What `git_change` guarantees however git's descendants behave (class: completion and cleanup keyed on the leader and
    # on pipe EOF, instead of on the process group and one fixed deadline; PR #426 review). Every test names the pids it
    # starts in files, and asserts the outcome (the time it took, the group's live members, the exact text), not a call.
    def ignores_sigterm(self):
        return self.script("ignore.py", "import signal, time\nsignal.signal(signal.SIGTERM, signal.SIG_IGN)\ntime.sleep(30)\n")

    def child_holding_the_pipes(self):
        return f"{self.ignores_sigterm()} &\necho $! > {self.root}/child\n"

    # Git ends on SIGTERM, after reaping its own child: no zombie of its own is left to keep the group "there" until init
    # reaps it (what the descendants of a killed group do, whose reaping is not up to the runner).
    LEADER_ENDS_ON_SIGTERM = "trap 'kill $!; wait $!; exit 143' TERM\nsleep 30 &\nwait\n"

    def assertGone(self, name, within=3.0):
        pid, end = self.pid(name), time.monotonic() + within
        while alive(pid) and time.monotonic() < end:
            time.sleep(0.05)
        self.assertFalse(alive(pid), f"{name} (pid {pid}) is still running")

    def assertGroupGone(self, within=3.0):
        """No live member is left in git's group (killed members are zombies until init reaps them: not live)."""
        pgid, end = self.pid("leader"), time.monotonic() + within
        while group_members(pgid) and time.monotonic() < end:
            time.sleep(0.05)
        self.assertEqual([], group_members(pgid), "a process of git's group is still running")

    def interrupt_at(self, *delays, after="leader"):
        """SIGINT to this process once for each of `delays`, that many seconds after the pid file `after` (`leader`, which the
        fake git writes first, or `child`/`helper`, which it writes once it has started that process) appeared: git is running
        then, and the call under test holds the process it started. A timer started BEFORE the call can fire between the fork
        and the helper's `try:`, where an interrupt leaves the command running (a window the helper documents). The wait is
        bounded: a file that does not appear within 5 s sends nothing and fails the test when it ends. The sender stops when
        the test does."""
        stop, missing = threading.Event(), []

        def send():
            marker, end = self.root / after, time.monotonic() + 5
            while not marker.exists():
                if stop.wait(0.01):
                    return
                if time.monotonic() > end:
                    missing.append(after)
                    return
            began = time.monotonic()
            for delay in delays:
                if stop.wait(max(0.0, began + delay - time.monotonic())):
                    return
                os.kill(os.getpid(), signal.SIGINT)
        sender = threading.Thread(target=send, daemon=True)
        sender.start()

        def finish():
            stop.set()
            sender.join(2)
            if missing:
                raise AssertionError(f"{after} did not appear within 5 s: no SIGINT was sent")
        self.addCleanup(finish)

    def test_a_timeout_ends_what_a_leader_that_ended_on_sigterm_left_holding_its_pipes(self):
        self.fake_git(self.child_holding_the_pipes() + self.LEADER_ENDS_ON_SIGTERM)
        began = time.monotonic()
        with patch.dict(pr_loop.GIT_CHANGES, {"fetch": 0.3}):
            with self.assertRaisesRegex(pr_loop.Stop, r"^git fetch timed out after 0\.3 seconds$"):
                pr_loop.git_change(self.root / "work", "fetch")
        self.assertLess(time.monotonic() - began, 4, "limit + KILL_AFTER + DRAIN, not the child's 30 seconds")
        self.assertGone("child")
        self.assertGroupGone()

    def test_a_member_that_ignores_sigterm_and_holds_no_pipe_is_killed_after_kill_after(self):
        self.fake_git(f"{self.ignores_sigterm()} >/dev/null 2>&1 &\necho $! > {self.root}/child\n"
                      + self.LEADER_ENDS_ON_SIGTERM)
        with patch.dict(pr_loop.GIT_CHANGES, {"fetch": 0.3}):
            with self.assertRaisesRegex(pr_loop.Stop, r"^git fetch timed out after 0\.3 seconds$"):
                pr_loop.git_change(self.root / "work", "fetch")
        self.assertGone("child")
        self.assertGroupGone()

    def test_an_interrupted_fetch_ends_what_a_leader_that_ended_on_sigterm_left_holding_its_pipes(self):
        self.fake_git(self.child_holding_the_pipes() + self.LEADER_ENDS_ON_SIGTERM)
        self.interrupt_at(0.3, after="child")
        began = time.monotonic()
        with self.assertRaises(KeyboardInterrupt):
            pr_loop.git_change(self.root / "work", "fetch")
        self.assertLess(time.monotonic() - began, 4, "KILL_AFTER + DRAIN after the interrupt")
        self.assertGone("child")
        self.assertGroupGone()

    def test_an_interrupted_merge_is_ended_at_its_original_limit_and_the_interrupt_is_raised_not_the_timeout(self):
        self.fake_git(self.LEADER_ENDS_ON_SIGTERM)
        self.interrupt_at(1.5)
        began = time.monotonic()
        with patch.dict(pr_loop.GIT_CHANGES, {"merge": 2.0}):
            with self.assertRaises(KeyboardInterrupt):  # a Stop is a RuntimeError: it would be an error here
                pr_loop.git_change(self.root / "work", "merge", "--ff-only")
        took = time.monotonic() - began
        self.assertGreater(took, 1.9, "an interrupted merge is still waited for, up to its limit")
        self.assertLess(took, 3.0, "the limit counts from the start of the call, not from the interrupt")
        self.assertGroupGone()

    def test_an_interrupted_switch_with_a_lingering_child_is_ended_at_its_limit(self):
        self.fake_git(self.child_holding_the_pipes() + self.LEADER_ENDS_ON_SIGTERM)
        self.interrupt_at(0.3, after="child")
        began = time.monotonic()
        with patch.dict(pr_loop.GIT_CHANGES, {"switch": 1.0}):
            with self.assertRaises(KeyboardInterrupt):
                pr_loop.git_change(self.root / "work", "switch", "--no-guess")
        self.assertLess(time.monotonic() - began, 4)
        self.assertGone("child")
        self.assertGroupGone()

    def test_a_git_that_exited_is_judged_by_its_exit_code_even_when_a_leftover_holds_its_output(self):
        for code in (0, 3):
            with self.subTest(code=code):
                self.fake_git(self.child_holding_the_pipes() + f"echo out\necho err >&2\nexit {code}\n")
                began = time.monotonic()
                with patch.dict(pr_loop.GIT_CHANGES, {"fetch": 30}):
                    done = pr_loop.git_change(self.root / "work", "fetch")
                self.assertEqual((code, "out\n", "err\n"), (done.returncode, done.stdout, done.stderr))
                self.assertLess(time.monotonic() - began, 3, "git's own exit, not the 30 second limit")
                self.assertTrue(alive(self.pid("child")), "what a finished git left behind is not signalled")
                self.kill_leftovers()

    def test_a_process_that_left_the_group_while_holding_the_pipe_cannot_hold_the_runner(self):
        writer = self.script("escaped.py", "import os, signal, sys, time\nos.setsid()\n"
                             "signal.signal(signal.SIGTERM, signal.SIG_IGN)\nfor _ in range(300):\n"
                             "    sys.stderr.write('x\\n')\n    sys.stderr.flush()\n    time.sleep(0.1)\n")
        self.fake_git(f"{writer} &\necho $! > {self.root}/child\n" + self.LEADER_ENDS_ON_SIGTERM)
        calls, real = [], os.killpg

        def recording_killpg(pgid, sig):
            try:
                real(pgid, sig)
            except ProcessLookupError:
                calls.append((sig, "ESRCH"))
                raise
            calls.append((sig, "ok"))
        made = []

        class Recording(subprocess.Popen):  # the test holds git's Popen: only the runner can close its pipes (a collected
            def __init__(self, *args, **kwargs):  # Popen closes them by itself, and would hide a runner that does not)
                super().__init__(*args, **kwargs)
                made.append(self)
        began = time.monotonic()
        with patch.dict(pr_loop.GIT_CHANGES, {"fetch": 0.3}), patch.object(pr_loop.os, "killpg", recording_killpg), \
                patch.object(pr_loop.subprocess, "Popen", Recording):
            with self.assertRaisesRegex(pr_loop.Stop, r"^git fetch timed out after 0\.3 seconds$"):
                pr_loop.git_change(self.root / "work", "fetch")
        self.assertLess(time.monotonic() - began, 4)
        seen_empty = [i for i, (_, result) in enumerate(calls) if result == "ESRCH"]
        self.assertTrue(seen_empty, f"the group was seen empty: {calls}")
        self.assertEqual(seen_empty[0] + 1, len(calls), f"nothing is signalled after the group answered ESRCH: {calls}")
        self.assertTrue(made[0].stdout.closed and made[0].stderr.closed, "the runner closed git's pipes")
        self.assertGone("child", within=3.0)  # its next write meets a closed pipe

    def test_a_second_interrupt_ends_the_group_at_once(self):
        self.fake_git("trap '' TERM\nsleep 30\n")
        self.interrupt_at(0.3, 1.0)
        began = time.monotonic()
        with patch.object(pr_loop, "KILL_AFTER", 20):
            with self.assertRaises(KeyboardInterrupt):
                pr_loop.git_change(self.root / "work", "fetch")
        self.assertLess(time.monotonic() - began, 3, "not KILL_AFTER (20 s)")
        self.assertGroupGone()

    def test_a_group_that_cannot_be_signalled_does_not_turn_the_timeout_into_a_crash(self):
        self.fake_git("trap '' TERM\nsleep 30\n")

        def refused(pgid, sig):
            raise PermissionError(1, "Operation not permitted")
        began = time.monotonic()
        with patch.dict(pr_loop.GIT_CHANGES, {"fetch": 0.3}), patch.object(pr_loop.os, "killpg", refused), \
                warnings.catch_warnings():
            warnings.simplefilter("ignore", ResourceWarning)  # git cannot be ended here, and is collected still running
            with self.assertRaisesRegex(pr_loop.Stop, r"^git fetch timed out after 0\.3 seconds$"):
                pr_loop.git_change(self.root / "work", "fetch")
        self.assertLess(time.monotonic() - began, 4, "the pipes were still drained and closed within the bound")

    # The same, with a real git: `git fetch` of an `ext::` remote runs a helper that ignores SIGTERM and holds git's stderr.
    def real_git_fetch(self, mode):
        if shutil.which("git") is None:
            self.skipTest("git is not installed")
        helper = self.root / "helper.sh"
        helper.write_text(f"#!/bin/sh\necho $$ > {self.root}/helper\ntrap '' TERM\nexec sleep 30\n")
        helper.chmod(0o755)
        probe = self.root / "probe.sh"
        probe.write_text(f"#!/bin/sh\necho ran > {self.root}/probed\n")
        probe.chmod(0o755)
        patcher = patch.dict(os.environ, GIT_CONFIG_COUNT="1", GIT_CONFIG_KEY_0="protocol.ext.allow",
                             GIT_CONFIG_VALUE_0="always")
        patcher.start()
        self.addCleanup(patcher.stop)
        subprocess.run(["git", "init", "-q", str(self.root / "work")], check=True)
        subprocess.run(["git", "ls-remote", f"ext::{probe}"], cwd=self.root / "work", capture_output=True, timeout=30)
        if not (self.root / "probed").exists():
            self.skipTest("this git does not run an ext:: helper here (protocol.ext.allow), so the case cannot be made")
        if mode == "interrupt":
            self.interrupt_at(1.2, after="helper")
        patches = [patch.object(pr_loop, "KILL_AFTER", 1.0), patch.object(pr_loop, "DRAIN", 1.0)]
        if mode == "timeout":
            patches.append(patch.dict(pr_loop.GIT_CHANGES, {"fetch": 1.5}))
        for each in patches:
            each.start()
            self.addCleanup(each.stop)
        began = time.monotonic()
        try:
            pr_loop.git_change(self.root / "work", "fetch", "--no-tags", f"ext::{helper}", "+refs/heads/*:refs/remotes/x/*")
        finally:
            took = time.monotonic() - began
            self.assertTrue((self.root / "helper").exists(), "git started the helper")
            self.assertLess(took, 6, "limit + KILL_AFTER + DRAIN")
            end = time.monotonic() + 3
            while alive(self.pid("helper")) and time.monotonic() < end:
                time.sleep(0.05)
            self.assertFalse(alive(self.pid("helper")), "the helper that ignores SIGTERM was ended")
            self.assertEqual([], sorted(p.name for p in (self.root / "work/.git").rglob("*.lock")),
                             "git removed its own lock files")

    def test_a_real_git_fetch_whose_helper_ignores_sigterm_is_bounded_at_its_limit(self):
        with self.assertRaisesRegex(pr_loop.Stop, r"^git fetch timed out after 1\.5 seconds$"):
            self.real_git_fetch("timeout")

    def test_an_interrupted_real_git_fetch_whose_helper_ignores_sigterm_is_bounded(self):
        with self.assertRaises(KeyboardInterrupt):
            self.real_git_fetch("interrupt")


class RunTests(unittest.TestCase):
    """`run`, the one call of this runner that starts every other command (tmux, gh, git reads): a command that outlives its
    timeout is a Stop and its WHOLE process group ends; one that exited is judged by its exit code, whatever something it
    started does with its output (kjelly/pilot#427). The command is a script named `tool` in front of PATH; the processes
    it starts carry an environment marker, and only those are ever killed by the test."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="pr-loop-run-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        (self.root / "bin").mkdir()
        patcher = patch.dict(os.environ, PATH=f"{self.root / 'bin'}{os.pathsep}{os.environ['PATH']}", BR_TEST_MARKER=str(self.root))
        patcher.start()
        self.addCleanup(patcher.stop)
        for name, value in (("KILL_AFTER", 0.5), ("DRAIN", 0.5), ("POLL", 0.2)):
            patcher = patch.object(pr_loop, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(self.kill_leftovers)
        watchdog = threading.Timer(12, self.kill_leftovers)
        watchdog.daemon = True
        watchdog.start()
        self.addCleanup(watchdog.cancel)

    def tool(self, body):
        path = self.root / "bin/tool"
        path.write_text(f"#!/bin/sh\necho $$ > {self.root}/leader\n" + body)
        path.chmod(0o755)

    def pid(self, name):
        return int((self.root / name).read_text())

    def owned(self, pid):
        try:
            return f"BR_TEST_MARKER={self.root}".encode() in Path(f"/proc/{pid}/environ").read_bytes().split(b"\0")
        except OSError:
            return False

    def kill_leftovers(self):
        for name in ("leader", "child"):
            with contextlib.suppress(OSError, ValueError):
                pid = self.pid(name)
                if alive(pid) and self.owned(pid):
                    group = os.getpgid(pid)
                    if group != os.getpgid(0):  # never the runner's own group (a command that was not given one of its own)
                        with contextlib.suppress(OSError):
                            os.killpg(group, signal.SIGKILL)
                    os.kill(pid, signal.SIGKILL)

    def assertGone(self, name, within=3.0):
        pid, end = self.pid(name), time.monotonic() + within
        while alive(pid) and time.monotonic() < end:
            time.sleep(0.05)
        self.assertFalse(alive(pid), f"{name} (pid {pid}) is still running")

    def test_a_command_that_exited_is_judged_by_its_exit_code_when_a_leftover_holds_its_output(self):
        for code in (0, 3):
            with self.subTest(code=code):
                self.tool(f"sleep 6 &\necho $! > {self.root}/child\necho out\necho err >&2\nexit {code}\n")
                began = time.monotonic()
                done = pr_loop.run(["tool", "sub"], timeout=30)
                self.assertEqual((code, "out\n", "err\n"), (done.returncode, done.stdout, done.stderr))
                self.assertLess(time.monotonic() - began, 3, "the command's own exit, not the 30 second timeout or the leftover's 6")
                self.assertTrue(alive(self.pid("child")), "what a finished command left behind is not signalled")
                self.kill_leftovers()

    def test_a_command_that_outlives_its_timeout_is_a_stop_and_its_whole_group_is_ended(self):
        self.tool(f"trap 'exit 143' TERM\nsleep 30 &\necho $! > {self.root}/child\nwait\n")
        began = time.monotonic()
        with self.assertRaisesRegex(pr_loop.Stop, r"^tool sub timed out after 0\.5 seconds$"):
            pr_loop.run(["tool", "sub", "ignored"], timeout=0.5)
        self.assertLess(time.monotonic() - began, 4)
        self.assertGone("leader")
        self.assertGone("child")  # the leader alone is what `subprocess.run(timeout=)` ends

    def test_a_command_that_ignores_sigterm_is_killed_after_kill_after(self):
        self.tool(f"trap '' TERM\nsleep 30 &\necho $! > {self.root}/child\nwait\n")
        began = time.monotonic()
        with self.assertRaisesRegex(pr_loop.Stop, r"^tool sub timed out after 0\.5 seconds$"):
            pr_loop.run(["tool", "sub"], timeout=0.5)
        self.assertGreaterEqual(time.monotonic() - began, 0.5 + 0.5 - 0.2, "SIGTERM first, SIGKILL KILL_AFTER seconds later")
        self.assertGone("leader")
        self.assertGone("child")

    def test_data_is_the_standard_input_and_without_it_the_input_is_closed(self):
        self.tool("cat\n")
        self.assertEqual("hello", pr_loop.run(["tool", "sub"], data="hello").stdout)
        self.assertEqual("", pr_loop.run(["tool", "sub"]).stdout, "`cat` met end of input at once")


class CheckoutCleanTests(CheckoutCase):
    """The runner never stashes or discards work: a checkout with anything of the operator's in flight is refused."""

    def test_uncommitted_work_is_refused_and_a_clean_checkout_passes(self):
        text = "checkout %s has uncommitted changes or untracked files (%d paths, e.g. %s); commit or remove them; " \
               "the runner never stashes or discards work"
        (self.path / "README.txt").write_text("changed\n")
        self.stops(text % (self.path, 1, "README.txt"))                                    # modified, unstaged
        self.git("checkout", "--", "README.txt")
        (self.path / "staged.txt").write_text("x")
        self.git("add", "staged.txt")
        self.stops(text % (self.path, 1, "staged.txt"))                                    # staged
        self.git("reset", "-q")
        self.stops(text % (self.path, 1, "staged.txt"))                                    # untracked
        (self.path / "staged.txt").unlink()
        self.checkout()                                                                    # control: clean

    def test_the_first_three_paths_are_named_and_all_are_counted(self):
        for name in ("z4", "z3", "z2", "z1"):
            (self.path / name).write_text("x")
        (self.path / "README.txt").write_text("changed\n")
        self.stops(f"checkout {self.path} has uncommitted changes or untracked files (5 paths, e.g. README.txt, z1, z2); "
                   "commit or remove them; the runner never stashes or discards work")

    def test_a_path_that_is_not_printable_cannot_forge_the_message(self):
        (self.path / "bad\nname").write_text("x")
        error = str(self.refused())
        self.assertIn("e.g. bad?name)", error)
        self.assertEqual(1, len(error.splitlines()))

    def test_ignored_files_do_not_count(self):
        with self.exclude().open("a") as stream:
            stream.write("/build/\n/.pr-ready/\n")
        (self.path / "build").mkdir()
        (self.path / "build/out.bin").write_text("x")
        (self.path / ".pr-ready/7").mkdir(parents=True)
        (self.path / ".pr-ready/7/evidence.json").write_text("{}")
        self.checkout()

    def test_a_dirty_submodule_is_refused(self):
        inner = self.env.root / "inner"
        self.env.git("init", "-q", "-b", "main", str(inner), cwd=self.env.root)
        (inner / "lib.txt").write_text("lib\n")
        self.env.git("add", "-A", cwd=inner)
        self.env.git("commit", "-q", "-m", "lib", cwd=inner)
        self.git("-c", "protocol.file.allow=always", "submodule", "add", "-q", str(inner), "sub")
        self.git("commit", "-q", "-m", "add the submodule")
        self.git("push", "-q", "origin", "main")
        self.env.remote_head = self.git("rev-parse", "main", cwd=self.env.remote)
        self.checkout().release()  # control: the submodule is clean
        (self.path / "sub/lib.txt").write_text("edited inside the submodule\n")
        self.stops(f"checkout {self.path} has uncommitted changes or untracked files (1 paths, e.g. sub); "
                   "commit or remove them; the runner never stashes or discards work")

    def test_a_git_operation_in_progress_is_refused(self):
        for name in ("rebase-merge", "rebase-apply", "MERGE_HEAD", "CHERRY_PICK_HEAD", "REVERT_HEAD", "BISECT_LOG",
                     "sequencer"):
            with self.subTest(name=name):
                marker = Path(self.git("rev-parse", "--git-path", name))
                marker = marker if marker.is_absolute() else self.path / marker
                marker.mkdir() if name in ("rebase-merge", "rebase-apply", "sequencer") else marker.write_text("x\n")
                self.stops(f"a git operation is in progress in {self.path} ({name}); finish or abort it")
                shutil.rmtree(marker) if marker.is_dir() else marker.unlink()
        self.checkout()  # control

    def test_every_operation_in_progress_is_named(self):
        for name in ("rebase-merge", "MERGE_HEAD"):
            marker = Path(self.git("rev-parse", "--path-format=absolute", "--git-path", name))
            marker.mkdir() if name == "rebase-merge" else marker.write_text("x\n")
        self.stops(f"a git operation is in progress in {self.path} (MERGE_HEAD, rebase-merge); finish or abort it")

    def test_a_real_merge_in_progress_comes_before_the_dirty_state(self):
        self.git("switch", "-q", "-c", "side")
        self.git("commit", "-q", "--allow-empty", "-m", "nothing changes")
        self.git("switch", "-q", "main")
        self.git("merge", "-q", "--no-ff", "--no-commit", "side")
        self.assertEqual("", self.git("status", "--porcelain=v1"), "a merge that stages nothing: the tree is clean")
        self.stops(f"a git operation is in progress in {self.path} (MERGE_HEAD); finish or abort it")
        (self.path / "stray.txt").write_text("x")
        self.stops(f"a git operation is in progress in {self.path} (MERGE_HEAD); finish or abort it")
        (self.path / "stray.txt").unlink()
        self.git("merge", "--abort")
        self.checkout()


class CheckoutHelpersTests(CheckoutCase):
    """The skills run from the checkout, so the default branch of origin must host both helpers they call."""

    def test_a_default_branch_needs_each_of_the_two_helpers(self):
        # An old default branch has no ready_signal.py: the skills that run from this checkout could not sign a PR
        # and the run would wait for its phase timeout. Each helper is required by itself.
        for missing in HELPER_PATHS:
            with self.subTest(missing=missing):
                self.rebuild(self.helpers(leave_out=(missing,)))
                self.stops(f"origin's default branch main at {self.env.remote_head[:12]} lacks {missing}; "
                           "the skills it hosts could not report or sign")
        self.rebuild(self.helpers())
        self.checkout()  # control: both present

    def test_a_default_branch_with_neither_names_the_first(self):
        self.rebuild({"other.txt": "x\n"})
        self.stops(f"origin's default branch main at {self.env.remote_head[:12]} lacks {HELPER_PATHS[0]}; "
                   "the skills it hosts could not report or sign")


class CheckoutIgnoreTests(CheckoutCase):
    """The task and evidence directories must not count as uncommitted work: ignored by git, or the run is refused."""

    def test_the_task_and_evidence_directories_are_excluded_from_git_status(self):
        checkout = self.checkout()
        exclude = self.exclude().read_text().splitlines()
        self.assertEqual(["/.pr-ready/", "/.pr-loop/"], exclude[-2:])
        self.assertNotIn("tmux-ai", "\n".join(exclude))
        self.assertEqual(f"Added /.pr-ready/, /.pr-loop/ to {self.exclude()}", self.told[0])
        self.assertTrue(self.ignored(self.path, ".pr-loop/" + "0" * 32 + "/task.json"))
        self.assertTrue(self.ignored(self.path, ".pr-ready/anything"))
        self.assertFalse(self.ignored(self.path, "stray.txt"), "control: only those two are ignored")
        self.assertEqual([], checkout.would_add)

    def test_a_checkout_that_already_ignores_them_is_left_alone(self):
        self.checkout().release()
        before = self.exclude().read_bytes()
        self.told.clear()
        self.checkout()
        self.assertEqual(before, self.exclude().read_bytes(), "a second run appends nothing")
        self.assertEqual([], [line for line in self.told if line.startswith("Added")])

    def test_only_what_git_does_not_ignore_yet_is_added(self):
        # An unanchored line of the operator's own ignores .pr-ready/ already: the literal line is not what counts.
        with self.exclude().open("a") as stream:
            stream.write(".pr-ready/\n")
        self.checkout()
        self.assertEqual([".pr-ready/", "/.pr-loop/"], self.exclude().read_text().splitlines()[-2:])
        self.assertEqual(f"Added /.pr-loop/ to {self.exclude()}", self.told[0])

    def test_an_exclude_file_without_a_final_newline_keeps_its_last_line(self):
        self.exclude().write_text("# the operator's\nbuild/")
        self.checkout()
        self.assertEqual("# the operator's\nbuild/\n/.pr-ready/\n/.pr-loop/\n", self.exclude().read_text())

    def test_a_missing_info_directory_is_made(self):
        shutil.rmtree(self.path / ".git/info")
        self.checkout()
        self.assertEqual("/.pr-ready/\n/.pr-loop/\n", self.exclude().read_text())

    def test_a_tracked_gitignore_that_negates_them_is_refused(self):
        # A tracked .gitignore beats the exclude file, so the lines the runner writes can be neutralised.
        for negated in (".pr-loop", ".pr-ready"):
            with self.subTest(negated=negated):
                self.rebuild(self.helpers(**{".gitignore": f"!/{negated}/\n"}))
                self.stops(f"{self.path} does not ignore .pr-loop/ and .pr-ready/ even after they were added to "
                           f"{self.exclude()}: a tracked .gitignore overrides it, so the task files would count as "
                           "uncommitted work")
                self.assertEqual("/.pr-ready/\n/.pr-loop/\n", self.exclude().read_text()[-len("/.pr-ready/\n/.pr-loop/\n"):],
                                 "a line the runner wrote is never taken back")
        self.rebuild(self.helpers(**{".gitignore": "/dist/\n"}))
        self.checkout()  # control: an unrelated tracked .gitignore

    def test_in_a_linked_work_tree_the_lines_go_to_the_exclude_file_of_the_repository(self):
        self.git("switch", "-q", "-c", "side")
        linked = self.env.root / "linked"
        self.git("worktree", "add", "-q", str(linked), "main")
        self.checkout(str(linked))
        self.assertEqual("/.pr-ready/\n/.pr-loop/\n", self.exclude().read_text()[-len("/.pr-ready/\n/.pr-loop/\n"):])
        self.assertTrue(self.ignored(linked, ".pr-loop/x"))
        self.assertFalse((self.path / ".git/worktrees/linked/info").exists())


class CheckoutLockTests(CheckoutCase):
    """One runner per work tree, for the life of the process, and never deleted or inherited."""

    def message(self, found):
        return (f"another pr_loop runner is using the checkout {found.path} (lock {found.lock_path}); "
                "wait for it to finish or stop it")

    def test_a_second_runner_in_the_same_checkout_is_refused_until_the_first_is_done(self):
        first = self.checkout()
        self.assertEqual(self.path / ".git/pilot-pr-loop.lock", first.lock_path)
        self.stops(self.message(first))
        first.release()
        self.checkout()  # control: the lock is free again (in a run, the kernel frees it when the process ends)

    def test_the_lock_file_is_the_owners_and_is_never_deleted(self):
        first = self.checkout()
        self.assertEqual(0o600, stat.S_IMODE(first.lock_path.stat().st_mode))
        first.release()
        self.assertTrue(first.lock_path.is_file(), "releasing the lock leaves the file")

    def test_the_lock_is_not_inheritable_and_a_started_command_does_not_get_it(self):
        found = self.checkout()
        self.assertIs(False, os.get_inheritable(found.lock_fd))
        probe = "import os, sys\ntry:\n    os.fstat(int(sys.argv[1]))\nexcept OSError:\n    print('closed')\nelse:\n    print('open')\n"
        self.assertEqual("closed\n", pr_loop.command(sys.executable, "-c", probe, str(found.lock_fd)))

    def test_a_refusal_gives_the_lock_back(self):
        self.git("remote", "set-url", "origin", "https://github.com/other/demo.git")
        self.stops(f"origin of {self.path} is github.com/other/demo, not {self.IDENTITY}")
        self.git("remote", "set-url", "origin", self.env.ORIGIN)
        self.checkout()  # not "another runner": the refused attempt let go

    def test_a_lock_that_cannot_be_trusted_is_a_refusal(self):
        lock = self.path / ".git/pilot-pr-loop.lock"
        elsewhere = self.env.root / "elsewhere.lock"
        elsewhere.write_text("")
        lock.symlink_to(elsewhere)
        self.stops(f"cannot lock the checkout {self.path} ({lock}): Too many levels of symbolic links")
        lock.unlink()
        lock.mkdir()
        self.stops(f"cannot lock the checkout {self.path} ({lock}): Is a directory")
        lock.rmdir()
        os.mkfifo(lock)
        self.stops(f"cannot lock the checkout {self.path} ({lock}): not a regular file")
        lock.unlink()
        self.checkout()  # control

    def test_a_lock_the_file_system_cannot_give_is_a_refusal_not_a_pass(self):
        # ENOLCK (NFS without a lock manager): an unknown lock is no lock.
        with patch.object(pr_loop.fcntl, "flock", side_effect=OSError(pr_loop.errno.ENOLCK, "No locks available")):
            self.stops(f"cannot lock the checkout {self.path} ({self.path / '.git/pilot-pr-loop.lock'}): "
                       "No locks available")
        self.checkout()

    def test_linked_work_trees_lock_independently(self):
        self.git("switch", "-q", "-c", "side")
        linked = self.env.root / "linked"
        self.git("worktree", "add", "-q", str(linked), "main")
        paths = {}
        for top in (self.path, linked):
            raw = pr_loop.git(top, "rev-parse", "--git-path", pr_loop.LOCK_NAME).stdout.strip()
            paths[top] = Path(raw) if os.path.isabs(raw) else top / raw
        self.assertNotEqual(*paths.values())
        fds = [pr_loop.lock_checkout(top, path) for top, path in paths.items()]
        self.addCleanup(lambda: [os.close(fd) for fd in fds])
        for top, path in paths.items():
            with self.assertRaisesRegex(pr_loop.Stop, "another pr_loop runner is using the checkout"):
                pr_loop.lock_checkout(top, path)


class CheckoutPaneTests(CheckoutCase):
    """A pane an earlier run kept is a second user of the checkout: the lock died with that run, the pane did not."""
    SESSION = "pilot-pr-7-draft-0123456789"

    def listing(self, *rows):
        self.env.update_tmux(listing=list(rows))

    def row(self, session, pane, **more):
        """A row of the listing, as tmux 3.8 prints it: by default a live pane in the checkout (`path` is where it is now)."""
        return self.env.row(session, pane, **more)

    def refusal(self, pane="%3", session=SESSION):
        return (f"agent pane {pane} (session {session}) is still running in {self.path}; "
                f"inspect and close it before starting the runner again {CLEAN_POINTER}")

    def test_a_live_pilot_pane_in_the_checkout_is_refused(self):
        for where in (str(self.path), str(self.path / "sub")):
            with self.subTest(where=where):
                self.listing(self.row(self.SESSION, "%3", path=where))
                self.stops(self.refusal())
        self.listing(self.row("other", "%1", path=self.env.root), self.row(self.SESSION, "%3"))
        self.stops(self.refusal())
        self.assertEqual(["list-panes", "-a", "-F", pr_loop.LIST_FORMAT], self.env.tmux_calls("list-panes")[-1])

    def test_panes_that_are_not_in_the_way_pass(self):
        self.listing(self.row(self.SESSION, "%3", dead=True),                              # dead (tmux reports no path for it)
                     self.row(self.SESSION, "%4", dead=True, path=self.path),              # dead, whatever its path
                     self.row(self.SESSION, "%5", path=self.env.root),                     # live, elsewhere
                     self.row(self.SESSION, "%6", path=f"{self.path}-other"),              # live, a sibling whose name starts the same
                     self.row("mine", "%7"),                                               # the operator's own session in the checkout
                     self.row("pilot-pr", "%8"))                                           # not the runner's prefix
        self.checkout()

    def test_a_pane_that_reaches_the_checkout_through_a_symlink_counts(self):
        link = self.env.root / "link"
        link.symlink_to(self.path)
        self.listing(self.row(self.SESSION, "%3", path=f"{link}/sub"))
        self.stops(self.refusal())

    def test_a_live_pane_is_refused_in_a_session_of_the_new_names_and_of_the_old_ones(self):
        new = pr_loop.session_name(self.path)
        for session in (new, "pilot-pr-7-draft-0123456789", "pilot-pr-" + "x" * 24 + "-0123abcd"):
            with self.subTest(session=session):
                self.listing(self.row(session, "%3"))
                self.stops(self.refusal(session=session))

    def test_a_twin_repeats_the_rows_of_its_session_and_does_not_hide_a_live_pane(self):
        session = pr_loop.session_name(self.path)
        self.listing(self.row(session, "%3"), self.row(f"{session}-eink", "%3"))
        self.stops(self.refusal(session=session))
        self.listing(self.row(f"{session}-eink", "%3"))  # a twin alone is a session of the runner's prefix too
        self.stops(self.refusal(session=f"{session}-eink"))
        self.listing(self.row(session, "%3", dead=True), self.row(f"{session}-eink", "%3", dead=True))
        self.checkout().release()  # control: dead in both

    def test_a_pane_listed_under_a_twin_with_the_runners_prefix_blocks_though_its_first_row_does_not(self):
        # tmux lists the pane once for each session of the group: the row of the session that does not carry the prefix comes first.
        self.listing(self.row("another-session", "%3"), self.row(self.SESSION, "%3"))
        self.stops(self.refusal())

    def test_sessions_that_do_not_carry_the_runners_prefix_are_not_its_business(self):
        self.listing(self.row("pilot-prx-checkout", "%3"), self.row("my-pilot-pr-checkout", "%4"),
                     self.row("pilot", "%5"), self.row("", "%6"))
        self.checkout().release()

    def test_an_agent_the_runner_started_is_seen_in_the_panes_tmux_lists_until_it_is_dead(self):
        first = self.checkout()
        first.release()
        agent = pr_loop.Agent("claude", first, 7, "draft")  # the real Agent, over the fake tmux's sessions and windows
        self.stops(self.refusal(pane=agent.pane, session=first.session))
        self.env.set_pane(agent.pane, status=["1|0|claude"])  # it exited: remain-on-exit keeps the pane, dead, with no path
        (found,) = self.panes_tmux_lists()
        self.assertEqual((first.session, agent.pane, True, "", "", "7-draft", str(self.path)),
                         (found.session, found.pane, found.dead, found.path, found.pid, found.window, found.start_path),
                         "dead: no process and no path, and what it was started with is still there")
        self.assertEqual(str(self.env.bin / "claude"), pr_loop.started_with(found.start_command))
        self.checkout().release()

    @staticmethod
    def panes_tmux_lists():
        done = subprocess.run(["tmux", "list-panes", "-a", "-F", pr_loop.LIST_FORMAT], capture_output=True, text=True)
        return [pr_loop.read_pane(row) for row in pr_loop.split_listing(done.stdout)]

    def test_no_tmux_server_means_no_pane(self):
        for error in (NO_SERVER, NO_SOCKET):
            with self.subTest(error=error):
                self.env.update_tmux(no_server=error)
                self.checkout().release()

    def test_any_other_tmux_failure_is_a_refusal(self):
        self.env.update_tmux(fail={"list-panes": 1})
        self.stops("tmux list-panes failed (1): fake tmux: injected failure of list-panes")
        self.env.update_tmux(fail={}, no_server="error connecting to /tmp/tmux-1000/default (Permission denied)")
        self.stops("tmux list-panes failed (1): error connecting to /tmp/tmux-1000/default (Permission denied)")
        self.env.update_tmux(fail={}, no_server="", listing=["garbage"])
        self.stops("tmux list-panes returned a line that cannot be read")

    def test_the_panes_are_read_after_the_lock_and_before_anything_else_of_the_checkout(self):
        first = self.checkout()
        self.env.update_tmux(log=[], listing=[self.row(self.SESSION, "%3")])
        self.stops(f"another pr_loop runner is using the checkout {first.path} (lock {first.lock_path}); "
                   "wait for it to finish or stop it")
        self.assertEqual([], self.env.tmux_calls(), "the lock refuses first: tmux is not asked")


class GitCallTests(unittest.TestCase):
    """Every git call of the runner reads: no opportunistic index refresh (a plain `git status` rewrites .git/index), no
    credential prompt on a terminal the runner does not own, one locale (the output is parsed)."""

    def test_every_git_call_is_made_read_only_and_never_prompts(self):
        seen = []

        def record(args, **kwargs):
            seen.append(kwargs["env"])
            return subprocess.CompletedProcess(args, 0, "", "")
        with patch.object(pr_loop, "run", record):
            pr_loop.git("/x", "rev-parse", "HEAD")
            pr_loop.git("/x", "cat-file", "-e", "x", env={"GIT_NO_LAZY_FETCH": "1"})
        self.assertEqual(2, len(seen))
        for env in seen:
            self.assertEqual(("0", "0", "C"), tuple(env.get(name) for name in ("GIT_OPTIONAL_LOCKS", "GIT_TERMINAL_PROMPT",
                                                                               "LC_ALL")))
        self.assertEqual("1", seen[1].get("GIT_NO_LAZY_FETCH"), "a caller adds to the environment, it does not replace it")

    def test_a_status_outside_the_accepted_ones_is_a_stop_and_ok_none_is_the_callers_to_judge(self):
        with patch.object(pr_loop, "run", lambda args, **kwargs: subprocess.CompletedProcess(args, 3, "", "boom\n")):
            with self.assertRaisesRegex(pr_loop.Stop, r"^git config failed \(3\): boom$"):
                pr_loop.git("/x", "config", "--get-all", "x")
            self.assertEqual(3, pr_loop.git("/x", "config", "--get-all", "x", ok=(0, 3)).returncode)
            self.assertEqual(3, pr_loop.git("/x", "ls-remote", ok=None).returncode)


class CheckoutDryRunTests(CheckoutCase):
    """A dry run inspects the checkout the way the real run does and writes nothing: no lock, no tmux, no exclude line."""

    def snapshot(self):
        index = self.path / ".git/index"
        return dict(exclude=sha256_of(self.exclude()), index=(sha256_of(index), index.stat().st_mtime_ns),
                    lock=(self.path / ".git/pilot-pr-loop.lock").exists(), tasks=(self.path / ".pr-loop").exists(),
                    tmux=self.env.tmux_calls())

    def stale_index(self):
        """A tracked file whose timestamp changed, so that a plain `git status` would rewrite the index."""
        os.utime(self.path / "README.txt", (1, 1))
        before = sha256_of(self.path / ".git/index")
        probe = subprocess.run(["git", "status", "--porcelain"], cwd=self.path, env=self.env.git_env)
        self.assertEqual(0, probe.returncode)
        self.assertNotEqual(before, sha256_of(self.path / ".git/index"), "the setup must make a plain status write")
        os.utime(self.path / "README.txt", (2, 2))

    def test_a_dry_run_writes_nothing_and_takes_nothing(self):
        self.stale_index()
        before = self.snapshot()
        found = self.checkout(dry_run=True)
        self.assertEqual(before, self.snapshot())
        self.assertIsNone(found.lock_fd)
        self.assertEqual(["/.pr-ready/", "/.pr-loop/"], found.would_add)
        self.assertEqual([], self.told, "nothing is said before the PRs are reported")
        found.announce()
        self.assertEqual([f"Checkout: {self.path} (main at {self.env.remote_head[:12]})",
                          f"would add /.pr-ready/, /.pr-loop/ to {self.exclude()}",
                          f"would start the agents in tmux session {pr_loop.session_name(self.path)}",
                          f"not checked in a dry run: whether another runner holds {self.path / '.git/pilot-pr-loop.lock'}; "
                          f"whether an agent pane kept from an earlier run is still open in {self.path}"], self.told)

    def test_a_dry_run_does_not_mind_the_lock_or_the_panes_a_real_run_refuses(self):
        first = self.checkout()
        self.env.update_tmux(listing=[self.env.row("pilot-pr-7-draft-0123456789", "%3", path=self.path)])
        asked = len(self.env.tmux_calls())
        self.assertEqual(self.path, self.checkout(dry_run=True).path)
        self.assertEqual(asked, len(self.env.tmux_calls()), "a dry run never calls tmux, not even to list the panes")
        first.release()

    def test_a_dry_run_that_has_nothing_to_add_says_so_by_saying_nothing(self):
        self.checkout().release()  # a real run adds the lines
        self.told.clear()
        found = self.checkout(dry_run=True)
        self.assertEqual([], found.would_add)
        found.announce()
        self.assertEqual([f"Checkout: {self.path} (main at {self.env.remote_head[:12]})",
                          f"would start the agents in tmux session {pr_loop.session_name(self.path)}",
                          f"not checked in a dry run: whether another runner holds {self.path / '.git/pilot-pr-loop.lock'}; "
                          f"whether an agent pane kept from an earlier run is still open in {self.path}"], self.told)

    def refusals(self):
        """Each state the real run refuses, as `(name, set up, message)`."""
        top = self.path
        def dirty(): (self.path / "stray.txt").write_text("x")
        def other():
            self.git("switch", "-q", "-c", "other")
            self.git("branch", "-q", "-D", "main")  # (another branch is switched away from; with no local main it is refused)
        def diverged():
            self.commit()
            self.env.advance_remote()
            self.git("fetch", "-q", "origin")  # (a dry run cannot tell, without the tip, that a checkout has diverged)
        def origin(): self.git("remote", "set-url", "origin", "https://github.com/other/demo.git")
        def merging(): Path(self.git("rev-parse", "--path-format=absolute", "--git-path", "MERGE_HEAD")).write_text("x\n")
        return (("dirty", dirty, f"checkout {top} has uncommitted changes or untracked files (1 paths, e.g. stray.txt); "
                                 "commit or remove them; the runner never stashes or discards work"),
                ("another branch and no local default branch", other,
                 f"checkout {top} is on other, and it has no local main, the default branch of origin; the runner switches "
                 "only to an existing local branch: create it at origin's tip yourself and start the runner again"),
                ("diverged", diverged, "local main at <L> and origin's main at <T> have diverged (each has commits the "
                                       "other does not have); the runner only fast-forwards: put main at origin's tip "
                                       "yourself and start the runner again"),
                ("another origin", origin, f"origin of {top} is github.com/other/demo, not {self.IDENTITY}"),
                ("a git operation", merging, f"a git operation is in progress in {top} (MERGE_HEAD); finish or abort it"))

    def test_a_dry_run_refuses_what_the_real_run_refuses_for_the_same_reason(self):
        for name, setup, message in self.refusals():
            with self.subTest(name=name):
                self.env.make_checkout()
                setup()
                message = message.replace("<L>", self.tip()[:12]).replace("<T>", self.env.remote_head[:12])
                with self.assertRaises(pr_loop.Stop) as dry:
                    self.checkout(dry_run=True)
                with self.assertRaises(pr_loop.Stop) as real:
                    self.checkout()
                self.assertEqual((message, message), (str(dry.exception), str(real.exception)))


class CheckoutTaskTests(CheckoutCase):
    def test_the_task_is_laid_out_the_way_the_skills_load_it(self):
        checkout = self.checkout()
        path, task = checkout.task(self.repo, 7, "draft", HEAD)
        self.assertTrue(path.is_absolute())
        self.assertEqual("task.json", path.name)
        self.assertRegex(path.parent.name, r"^[0-9a-f]{32}$")
        self.assertEqual(path.parent.name, task["nonce"], "the directory is named after the nonce")
        self.assertEqual(checkout.path / ".pr-loop", path.parent.parent)
        self.assertEqual(dict(version=1, repo="acme/demo", pr=7, phase="draft", nonce=task["nonce"],
                              start_head=HEAD), task)
        self.assertEqual(task, json.loads(path.read_text()))
        for directory in (path.parent, path.parent.parent):
            self.assertEqual(0o700, stat.S_IMODE(directory.stat().st_mode), directory)
        # The producer and the consumer agree (AGENTS.md 5.7): the skills accept what the runner wrote.
        self.assertEqual(task, load_task(path, "acme/demo", 7, "draft"))
        with self.assertRaisesRegex(ValueError, "does not match this PR invocation"):
            load_task(path, "acme/demo", 7, "ready")

    def test_a_result_the_skill_writes_beside_the_task_is_read_back_by_the_runner(self):
        checkout = self.checkout()
        path, task = checkout.task(self.repo, 7, "draft", HEAD)
        write_result(path, load_task(path, "acme/demo", 7, "draft"), outcome="DRAFT-BLOCKED", head=HEAD,
                     reason="a blocker")
        self.assertEqual(path.parent / "result.json", path.with_name("result.json"))
        with self.assertRaisesRegex(pr_loop.Stop, f"PR #7 DRAFT-BLOCKED at {HEAD[:12]}: a blocker"):
            pr_loop.check_result(path, task, HEAD)

    def test_every_task_gets_its_own_directory_and_an_old_one_is_left_alone(self):
        checkout = self.checkout()
        old = self.path / ".pr-loop/0ld"  # left by an earlier run: ignored by the lines that run appended
        old.mkdir(parents=True)
        (old / "task.json").write_text("{}")
        first, _ = checkout.task(self.repo, 7, "draft", HEAD)
        second, _ = checkout.task(self.repo, 7, "ready", HEAD)
        self.assertNotEqual(first.parent, second.parent)
        self.assertEqual(first.parent.parent, second.parent.parent)
        self.assertEqual("{}", (old / "task.json").read_text())

    def test_a_task_directory_that_exists_is_never_reused(self):
        checkout = self.checkout()
        fixed = SimpleNamespace(uuid4=lambda: SimpleNamespace(hex="1" * 32))
        with patch.object(pr_loop, "uuid", fixed):
            checkout.task(self.repo, 7, "draft", HEAD)
            with self.assertRaises(FileExistsError):
                checkout.task(self.repo, 7, "draft", HEAD)

    def test_the_task_files_do_not_dirty_the_checkout(self):
        checkout = self.checkout()
        path, _ = checkout.task(self.repo, 7, "draft", HEAD)
        path.with_name("result.json").write_text("{}")
        (checkout.path / ".pr-ready" / "7").mkdir(parents=True)
        (checkout.path / ".pr-ready/7/evidence.json").write_text("{}")
        self.assertEqual("", self.git("status", "--porcelain=v1", "--untracked-files=normal"))
        checkout.verify()


class CheckoutVerifyTests(CheckoutCase):
    """Before every dispatch the checkout must be where the run started it: a skill that did not restore it, or
    anything else that changed it, stops the run before an agent is given a task. Origin's tip is not read again."""
    NOTHING = "; nothing was dispatched"

    def test_a_clean_checkout_where_it_started_verifies(self):
        self.checkout().verify()

    def test_work_outside_the_ignored_directories_stops(self):
        checkout = self.checkout()
        text = f"checkout {self.path} has uncommitted changes or untracked files (1 paths, e.g. %s); commit or remove " \
               f"them; the runner never stashes or discards work{self.NOTHING}"
        (self.path / "stray.txt").write_text("x")
        with self.assertRaises(pr_loop.Stop) as caught:
            checkout.verify()
        self.assertEqual(text % "stray.txt", str(caught.exception))
        (self.path / "stray.txt").unlink()
        (self.path / "README.txt").write_text("changed\n")
        with self.assertRaises(pr_loop.Stop) as caught:
            checkout.verify()
        self.assertEqual(text % "README.txt", str(caught.exception))
        self.git("checkout", "--", "README.txt")
        checkout.verify()

    def moved(self, checkout, now, at):
        return (f"checkout {self.path} is no longer on main at {checkout.head[:12]} (now {now} at {at[:12]}): a skill "
                f"did not restore it or something else changed it{self.NOTHING}")

    def test_a_head_that_moved_stops(self):
        checkout = self.checkout()
        new = self.commit("agent.txt")
        with self.assertRaises(pr_loop.Stop) as caught:
            checkout.verify()
        self.assertEqual(self.moved(checkout, "main", new), str(caught.exception))

    def test_another_branch_stops_even_at_the_same_commit(self):
        checkout = self.checkout()
        self.git("switch", "-q", "-c", "other")
        with self.assertRaises(pr_loop.Stop) as caught:
            checkout.verify()
        self.assertEqual(self.moved(checkout, "other", checkout.head), str(caught.exception))
        self.git("switch", "-q", "--detach")
        with self.assertRaises(pr_loop.Stop) as caught:
            checkout.verify()
        self.assertEqual(self.moved(checkout, "detached", checkout.head), str(caught.exception))
        self.git("switch", "-q", "main")
        checkout.verify()  # control: back where it started

    def test_a_git_operation_in_progress_stops_before_anything_else(self):
        checkout = self.checkout()
        (self.path / "stray.txt").write_text("x")
        marker = Path(self.git("rev-parse", "--path-format=absolute", "--git-path", "MERGE_HEAD"))
        marker.write_text("x\n")
        with self.assertRaises(pr_loop.Stop) as caught:
            checkout.verify()
        self.assertEqual(f"a git operation is in progress in {self.path} (MERGE_HEAD); finish or abort it{self.NOTHING}",
                         str(caught.exception))

    def test_the_tip_of_origin_is_not_read_again(self):
        # The merge train moves origin while a batch runs: that must not refuse the next PR.
        checkout = self.checkout()
        self.env.advance_remote()
        checkout.verify()
        self.assertEqual([], [call for call in self.env.tmux_calls() if call[0] != "list-panes"])


class CheckoutFinishTests(CheckoutCase):
    def tree(self):
        return sorted(str(path.relative_to(self.path)) for path in self.path.rglob("*") if ".git/objects" not in str(path))

    def test_finishing_says_where_things_are_and_deletes_nothing(self):
        checkout = self.checkout()
        checkout.task(self.repo, 7, "draft", HEAD)
        before = self.tree()
        self.told.clear()
        checkout.finish()
        self.assertEqual(before, self.tree())
        self.assertEqual([f"Kept: the task files under {self.path / '.pr-loop'} and any agent window still open in tmux "
                          f"session {pr_loop.session_name(self.path)}; close the agents still running in {self.path} before "
                          f"the next run. Nothing in {self.path} was deleted or reset."], self.told)
        self.assertEqual(self.env.remote_head, self.tip())
        self.assertFalse(self.env.state_home.exists())


# ---- (E) the whole program, started as a user starts it, against the fake gh/tmux/agents --------------------------

class ProgramTests(unittest.TestCase):
    """One real `python3 scripts/pr_loop.py` process per test; time is real (small intervals), everything else fake."""
    SCRIPT = ROOT / "scripts" / "pr_loop.py"

    def setUp(self):
        self.env = FakeEnv(self)

    def run_program(self, *extra, cwd=None):
        """The runner, started the way a user starts it: in the operator's checkout unless `cwd` says otherwise."""
        argv = [sys.executable, "-B", str(self.SCRIPT), "7", "--repo", "acme/demo", "--poll-interval", "0.01",
                "--startup-timeout", "2", *extra]
        return subprocess.run(argv, capture_output=True, text=True, timeout=60, cwd=cwd or self.env.checkout)

    def pastes(self):
        """(prompt, task path) of every text pasted into an agent."""
        texts = [call["stdin"] for call in self.env.tmux()["log"] if call["argv"][0] == "load-buffer"]
        found = []
        for text in texts:
            prompt, marker, rest = text.partition(" --pr-loop-task=")
            self.assertEqual(" --pr-loop-task=", marker, text)
            path, end = json.JSONDecoder().raw_decode(rest)
            self.assertEqual(len(rest), end, "the path is the last thing pasted")
            found.append((prompt, Path(path)))
        return found

    def checkout_line(self, proc):
        """The one `Checkout:` line of a real run: it names the operator's own checkout, its branch and commit."""
        lines = [line for line in proc.stdout.splitlines() if line.startswith("Checkout: ")]
        self.assertEqual([f"Checkout: {self.env.checkout} (main at {self.env.remote_head[:12]})"], lines, proc.stdout)
        return self.env.checkout

    def only_listed_panes(self):
        """tmux was asked to list the panes (the retained-pane check) and nothing else: nothing was started."""
        self.assertEqual(["list-panes"], [call[0] for call in self.env.tmux_calls()])

    def gh_kinds(self):
        """What each `gh` call of the runner was, in order. A call that is none of the three reads is reported as its own
        argv, so that any write (`pr ready`, `pr edit`, `pr comment`, `api -X ...`) fails the tests that compare these."""
        kinds = []
        for call in self.env.gh_calls():
            if call[:2] == ["pr", "view"]:
                kinds.append("pr view")
            elif call == ["api", "user"]:
                kinds.append("api user")
            elif call[:1] == ["api"] and "--slurp" in call and call[-1].split("?")[0].endswith("/timeline"):
                kinds.append("api timeline")
            else:
                kinds.append(" ".join(call))
        return kinds

    # ---- the agents start in the checkout the operator chose (AC1) and the runner deletes nothing (AC3) ----------
    def blocked_run(self, *extra, cwd=None):
        """A run that dispatches the Draft agent and stops on its blocker: the shortest run that starts an agent."""
        self.env.set_pane("%1", enter=[{"result": {"outcome": "DRAFT-BLOCKED", "reason": "synthetic blocker"}}])
        proc = self.run_program(*extra, cwd=cwd)
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        self.assertIn("DRAFT-BLOCKED", proc.stderr)
        return proc

    def agent_cwd(self):
        (session,) = self.env.tmux()["sessions"]
        return session["cwd"]

    def test_the_agent_starts_in_the_checkout_the_runner_was_started_in(self):
        # From a directory below the root: the checkout is the root of the work tree (and not the directory the
        # runner was started in, nor a directory of its own: every test of this class runs from the root).
        below = self.env.checkout / "sub" / "dir"
        below.mkdir(parents=True)
        self.blocked_run(cwd=below)
        self.assertEqual(str(self.env.checkout), self.agent_cwd())

    def test_checkout_names_another_directory_whatever_the_current_one_is(self):
        elsewhere = self.env.root / "elsewhere"
        elsewhere.mkdir()
        self.blocked_run("--checkout", str(self.env.checkout), cwd=elsewhere)
        self.assertEqual(str(self.env.checkout), self.agent_cwd(), "not the directory the runner was started in")

    def plant(self):
        """What the operator already has in the checkout and the runner must leave alone: the exclude lines of an
        earlier run, ignored build output, evidence and an old task directory."""
        root = self.env.checkout
        with (root / ".git/info/exclude").open("a") as stream:
            stream.write("/build/\n/.pr-ready/\n/.pr-loop/\n")
        sentinels = {"build/out.bin": "build output\n", ".pr-ready/7/evidence.json": "{}\n",
                     ".pr-loop/0ld/task.json": "{}\n", ".pr-loop/0ld/result.json": "{}\n"}
        for name, text in sentinels.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_text(text)
        # A managed clone an earlier version of the runner left behind: not used any more, and not the runner's to delete.
        old = self.env.state_home / "pilot/pr-loop/batch-0ld"
        old.mkdir(parents=True)
        (old / "README.txt").write_text("an old clone\n")
        self.addCleanup(shutil.rmtree, self.env.state_home, ignore_errors=True)  # (FakeEnv asserts nothing is left)
        return sentinels

    def untouched(self, sentinels, proc, *, tasks):
        """The checkout after a run: where it was, clean, with everything the operator had and the run's own task files."""
        root = self.env.checkout
        self.assertTrue(root.is_dir(), "the checkout was deleted")
        self.assertEqual(self.env.remote_head, self.env.git("rev-parse", "HEAD", cwd=root))
        self.assertEqual("main", self.env.git("symbolic-ref", "--short", "HEAD", cwd=root))
        self.assertEqual("", self.env.git("status", "--porcelain=v1", "--untracked-files=all", cwd=root),
                         "the run left the checkout dirty")
        self.assertEqual((self.env.root / "work" / "README.txt").read_text(), (root / "README.txt").read_text())
        for name, text in sentinels.items():
            self.assertEqual(text, (root / name).read_text(), f"{name} was changed or removed")
        exclude = (root / ".git/info/exclude").read_text().splitlines()
        self.assertTrue({"/build/", "/.pr-ready/", "/.pr-loop/"} <= set(exclude), exclude)
        for _, task in tasks:
            self.assertTrue(task.is_file(), f"{task} was removed")
            self.assertEqual(root / ".pr-loop", task.parent.parent, "task files are under the checkout")
        found = sorted(str(path.relative_to(self.env.state_home)) for path in self.env.state_home.rglob("*"))
        self.assertEqual(["pilot", "pilot/pr-loop", "pilot/pr-loop/batch-0ld", "pilot/pr-loop/batch-0ld/README.txt"], found,
                         "the old clone is left alone and the runner made no state directory of its own")

    def test_a_completed_run_leaves_the_checkout_as_it_found_it(self):
        sentinels = self.plant()
        signed = signal_world()
        ready, queued, merged = ready_view(signed), pr_view_json("queued"), pr_view_json("merged")
        self.env.update_gh(view=pr_view_json("draft"))
        self.env.set_pane("%1", enter=[{"gh": {"set_view": ready, "set_timeline": signed.s["events"]},
                                        "result": {"outcome": "READY", "reason": "gate passed"}}])
        self.env.set_pane("%2", enter=[{"gh": {"set_seq": [{"view": v} for v in (queued, queued, queued, merged)]},
                                        "result": {"outcome": "ENQUEUED", "reason": "queued for the train"}}])
        proc = self.run_program()
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        self.assertIn("PR #7: merged", proc.stdout.splitlines())
        tasks = self.pastes()
        self.assertEqual(2, len(tasks))
        self.untouched(sentinels, proc, tasks=tasks)
        self.assertEqual([str(self.env.checkout)] * 2, [session["cwd"] for session in self.env.tmux()["sessions"]])

    # ---- a run that stopped leaves its window; the next run in the same checkout (kjelly/pilot#425 AC2) ---------------
    def blocked_rerun(self, pane="%2"):
        """The second run of `blocked_run`: the agent of the new run is pane `pane` (`%2` on the server the first run used,
        `%1` again on a new one) and publishes a blocker too."""
        self.env.set_pane(pane, enter=[{"result": {"outcome": "DRAFT-BLOCKED", "reason": "synthetic blocker"}}])
        proc = self.run_program()
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        self.assertIn("DRAFT-BLOCKED", proc.stderr)
        return proc

    def test_a_rerun_is_refused_while_the_kept_agent_lives_and_adds_a_window_once_it_is_dead(self):
        top = self.env.checkout
        session = pr_loop.session_name(top)
        self.blocked_run()
        self.assertEqual({session: ["7-draft"]}, self.env.live())
        # The kept agent still runs in the checkout: a second runner would be a second user of it.
        reads = len(self.env.gh_calls())
        again = self.run_program()
        self.assertEqual((1, "", f"pr-loop: agent pane %1 (session {session}) is still running in {top}; inspect and close "
                                 f"it before starting the runner again {CLEAN_POINTER}\n"),
                         (again.returncode, again.stdout, again.stderr))
        self.assertEqual(reads, len(self.env.gh_calls()), "refused before it read the PR")
        # The agent exited (remain-on-exit keeps the dead pane, with no path): the same start goes through, in a window of the
        # session that is still there, and nothing of the earlier run is closed, renamed or reused.
        self.env.set_pane("%1", status=["1|0|claude"])
        self.env.update_tmux(log=[])
        proc = self.blocked_rerun()
        self.assertIn(f"PR #7 draft agent: %2 in window 7-draft of tmux session {session}", proc.stdout)
        self.assertEqual({session: ["7-draft", "7-draft"]}, self.env.live())
        self.assertEqual(["new-session", "new-window"], [made["kind"] for made in self.env.created()])
        self.assertEqual([], self.env.tmux_calls("kill-pane"), "the dead window of the earlier run stays")
        self.assertEqual([[], []], [[name for name in call if name.startswith("kill-")] for call in self.env.tmux_calls()
                                    if call[0] in ("new-session", "new-window")])

    def test_a_rerun_after_the_operator_killed_the_session_makes_it_again(self):
        top = self.env.checkout
        session = pr_loop.session_name(top)
        self.blocked_run()
        self.env.kill_session(session)  # (and the agent with it: nothing of the earlier run is left in the checkout; the
        self.assertIsNone(self.env.server())  # session was the last one, so the tmux server exited too)
        self.env.update_tmux(log=[])
        proc = self.blocked_rerun("%1")  # a new server numbers its panes again
        self.assertIn(f"PR #7 draft agent: %1 in window 7-draft of tmux session {session}", proc.stdout)
        self.assertEqual({session: ["7-draft"]}, self.env.live())
        self.assertEqual(["new-session", "new-session"], [made["kind"] for made in self.env.created()])
        self.assertEqual(["new-session"], [call[0] for call in self.env.tmux_calls()
                                           if call[0] in ("new-session", "new-window")])

    def test_a_run_in_another_checkout_has_a_session_of_its_own(self):
        other = self.env.make_checkout("other")
        self.blocked_run()
        self.env.set_pane("%2", enter=[{"result": {"outcome": "DRAFT-BLOCKED", "reason": "synthetic blocker"}}])
        proc = self.run_program("--checkout", str(other), cwd=other)
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        first, second = pr_loop.session_name(self.env.checkout), pr_loop.session_name(other)
        self.assertNotEqual(first, second)
        self.assertEqual({first: ["7-draft"], second: ["7-draft"]}, self.env.live())
        self.assertEqual(["new-session", "new-session"], [made["kind"] for made in self.env.created()])

    def test_a_run_that_stops_on_a_blocker_leaves_the_checkout_as_it_found_it(self):
        sentinels = self.plant()
        proc = self.blocked_run()
        self.untouched(sentinels, proc, tasks=self.pastes())

    def test_a_run_that_cannot_read_the_pr_leaves_the_checkout_as_it_found_it(self):
        sentinels = self.plant()
        self.env.update_gh(seq=[{"exit": 1, "stderr": "synthetic outage"}])
        proc = self.run_program()
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        self.assertIn("GitHub read failed 3 consecutive times; no command sent", proc.stderr)
        self.untouched(sentinels, proc, tasks=[])

    def test_a_run_that_times_out_leaves_the_checkout_as_it_found_it(self):
        sentinels = self.plant()
        proc = self.run_program("--phase-timeout", "0.5")
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        self.assertIn("timed out in draft", proc.stderr)
        self.untouched(sentinels, proc, tasks=self.pastes())

    def test_a_pr_goes_from_draft_to_merged(self):
        # The success variant: the gate's Ready is followed by its signal (the marker comment, then the label), which
        # the fake gh serves as the PR's timeline; only then is the Ready phase dispatched.
        signed = signal_world()
        ready, queued, merged = ready_view(signed), pr_view_json("queued"), pr_view_json("merged")
        self.env.write_gh(calls=[], seq=[], view=pr_view_json("draft"), login=LOGIN, comments=[], timeline=[])
        self.env.set_pane("%1", enter=[{"gh": {"set_view": ready, "set_timeline": signed.s["events"]},
                                        "result": {"outcome": "READY", "reason": "gate passed"}}])
        self.env.set_pane("%2", enter=[{"gh": {"set_seq": [{"view": v} for v in (queued, queued, queued, merged)]},
                                        "result": {"outcome": "ENQUEUED", "reason": "queued for the train"}}])
        proc = self.run_program()
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        self.assertEqual("", proc.stderr)
        self.assertIn("PR #7: merged", proc.stdout.splitlines())
        # Two dispatches, each carrying the task path of its own <checkout>/.pr-loop/<nonce>/ directory.
        checkout = self.checkout_line(proc)
        (draft_prompt, draft_task), (ready_prompt, ready_task) = self.pastes()
        self.assertEqual(("/pr-ready 7", "$pr-review-merge 7"), (draft_prompt, ready_prompt))
        for task in (draft_task, ready_task):
            self.assertTrue(task.is_absolute())
            self.assertEqual("task.json", task.name)
            self.assertEqual(checkout / ".pr-loop", task.parent.parent)
            self.assertRegex(task.parent.name, r"^[0-9a-f]{32}$")
        self.assertNotEqual(draft_task, ready_task)
        # The real result CLI accepted both task paths (it exits 2 on a layout it does not know), and the
        # runner read their results without stopping.
        self.assertEqual([0, 0], [done["rc"] for done in self.env.tmux()["cli"]])
        # Both panes are closed, at the end of the run; the checkout and the task files stay, and the run says so.
        self.assertEqual([["kill-pane", "-t", "%1"], ["kill-pane", "-t", "%2"]], self.env.tmux_calls("kill-pane"))
        self.assertTrue(checkout.is_dir())
        self.assertTrue(draft_task.is_file() and ready_task.is_file())
        self.assertIn(f"Kept: the task files under {checkout / '.pr-loop'}", proc.stdout)
        # Two agents, one session: the runner names it once, with the command that watches it, and each agent's line says
        # which window of it the agent is in.
        session = pr_loop.session_name(checkout)
        lines = proc.stdout.splitlines()
        self.assertEqual(1, lines.count(f"Agents run as windows of tmux session {session}; watch them read-only with: "
                                        f"tmux attach -r -t {session}"))
        self.assertIn(f"PR #7 draft agent: %1 in window 7-draft of tmux session {session}", lines)
        self.assertIn(f"PR #7 ready agent: %2 in window 7-ready of tmux session {session}", lines)
        self.assertEqual(["new-session", "new-window"], [made["kind"] for made in self.env.created()])
        self.assertEqual({}, self.env.live(), "both windows are closed: the session ended with the last")
        # The runner only reads GitHub, asked for its account once, and read the signal's timeline.
        kinds = self.gh_kinds()
        self.assertEqual({"pr view", "api user", "api timeline"}, set(kinds))
        self.assertEqual(1, kinds.count("api user"), "the account is read once per run")

    def test_a_blocker_stops_the_run_and_keeps_everything_for_inspection(self):
        self.env.set_pane("%1", enter=[{"result": {"outcome": "DRAFT-BLOCKED", "reason": "go test failed in the synthetic gate"}}])
        proc = self.run_program()
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        self.assertRegex(proc.stderr, rf"^pr-loop: PR #7: PR #7 DRAFT-BLOCKED at {HEAD[:12]}: "
                                      r"go test failed in the synthetic gate\n$")
        self.assertEqual(1, len(self.env.created()), "the Ready phase was never dispatched")
        self.assertEqual([], self.env.tmux_calls("kill-pane"), "the pane is retained")
        checkout = self.checkout_line(proc)
        self.assertTrue(checkout.exists())
        ((_, task),) = self.pastes()
        result = json.loads(task.with_name("result.json").read_text())
        self.assertEqual(("DRAFT-BLOCKED", HEAD, task.parent.name), (result["outcome"], result["head_sha"], result["nonce"]))
        self.assertEqual(0, self.env.tmux()["cli"][0]["rc"])

    def test_a_blocker_that_arrives_as_github_shows_ready_stops_before_the_ready_agent_starts(self):
        # pr_gate marks the PR Ready and then publishes DRAFT-BLOCKED (post-action verification found a newly
        # active workflow): GitHub already shows Ready when the blocker is on disk. A Ready agent that would
        # merge the PR is scripted, so that a runner that ignores the blocker is seen to report success.
        self.env.set_pane("%1", enter=[{"gh": {"set_view": pr_view_json("ready")},
                                        "result": {"outcome": "DRAFT-BLOCKED", "reason": "a workflow became active after Ready"}}])
        self.env.set_pane("%2", enter=[{"gh": {"set_view": pr_view_json("merged")}}])
        proc = self.run_program("--phase-timeout", "5")
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        self.assertRegex(proc.stderr, rf"^pr-loop: PR #7: PR #7 DRAFT-BLOCKED at {HEAD[:12]}: "
                                      r"a workflow became active after Ready\n$")
        self.assertEqual(1, len(self.env.created()), "the Ready phase was never dispatched")
        self.assertEqual(1, len(self.pastes()))
        self.assertNotIn("PR #7: merged", proc.stdout)
        self.assertEqual([], self.env.tmux_calls("kill-pane"), "the pane is retained")
        self.assertTrue(self.checkout_line(proc).exists())
        self.assertEqual(0, self.env.tmux()["cli"][0]["rc"])
        self.assertNotIn("api timeline", self.gh_kinds(), "a Ready PR without the label has no signal to read")

    def test_a_blocker_for_a_signal_the_timeline_does_not_show_yet_stops_before_the_ready_agent_starts(self):
        # The gate wrote the marker comment and the label, could not read the signal back (GitHub lags) and published
        # DRAFT-BLOCKED: the PR view shows the label, the timeline has no `labeled` event yet. The signal is not
        # valid then, so the PR stays in the Draft phase and the blocker is what the run stops on. A Ready agent that
        # would merge the PR is scripted, so that a runner that dispatched it is seen to report success.
        lagging = signal_world(signed=False)
        lagging.comment(rs.marker_comment(HEAD, rs.PR_READY, lagging.latest_ready()))
        shown = ready_view(signal_world())  # the view already lists the label
        self.env.set_pane("%1", enter=[{"gh": {"set_view": shown, "set_timeline": lagging.s["events"]},
                                        "result": {"outcome": "DRAFT-BLOCKED", "reason": "the signal was not confirmed"}}])
        self.env.set_pane("%2", enter=[{"gh": {"set_view": pr_view_json("merged")}}])
        proc = self.run_program("--phase-timeout", "5")
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        self.assertRegex(proc.stderr, rf"^pr-loop: PR #7: PR #7 DRAFT-BLOCKED at {HEAD[:12]}: the signal was not confirmed\n$")
        self.assertEqual(1, len(self.env.created()), "the Ready phase was never dispatched")
        self.assertNotIn("PR #7: merged", proc.stdout)
        self.assertIn("api timeline", self.gh_kinds(), "the label is on the PR: the timeline was read")
        self.assertEqual({"pr view", "api user", "api timeline"}, set(self.gh_kinds()))

    def test_a_ready_pr_without_a_signal_is_refused_and_nothing_is_started(self):
        self.env.update_gh(view=pr_view_json("ready"))
        proc = self.run_program("--phase-timeout", "5")  # a runner that dispatched would wait here, not for 60 s
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        self.assertEqual(f"pr-loop: PR #7: PR #7 is Ready without a valid {rs.LABEL} signal at HEAD {HEAD[:12]}: "
                         f"the PR does not carry the {rs.LABEL} label; nothing is dispatched for it: convert it to "
                         "Draft and run pr-ready on it, then start the runner again\n", proc.stderr)
        self.only_listed_panes()
        self.assertEqual(["pr view", "pr view"], self.gh_kinds(), "two reads, no account, no timeline")

    def test_a_ready_pr_whose_signal_names_an_earlier_head_is_refused_with_the_reason(self):
        signed = signal_world(NEW)
        self.env.update_gh(view=dict(ready_view(signed), headRefOid=HEAD), timeline=signed.s["events"])
        proc = self.run_program("--phase-timeout", "5")
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        self.assertIn(f"at HEAD {HEAD[:12]}: stale: the signal was written for HEAD {NEW[:12]}, the PR HEAD is "
                      f"{HEAD[:12]}; nothing is dispatched for it", proc.stderr)
        self.only_listed_panes()
        self.assertEqual({"pr view", "api user", "api timeline"}, set(self.gh_kinds()))

    # ---- the dry run: the same inspection, read-only (AC5) ------------------------------------------------------
    def dry_report(self, *phases):
        """What a dry run that accepts the checkout prints: the phase of each PR, then the checkout, what it would add
        to the exclude file, and what a dry run does not check."""
        top = self.env.checkout
        return "".join(f"{phase}\n" for phase in phases) + (
            f"Checkout: {top} (main at {self.env.remote_head[:12]})\n"
            f"would add /.pr-ready/, /.pr-loop/ to {top}/.git/info/exclude\n"
            f"would start the agents in tmux session {pr_loop.session_name(top)}\n"
            f"not checked in a dry run: whether another runner holds {top}/.git/pilot-pr-loop.lock; whether an agent "
            f"pane kept from an earlier run is still open in {top}\n")

    def written(self):
        """Everything a dry run must leave as it is: the exclude file, the index (and when it was written), the lock
        file, the task directory, tmux and GitHub."""
        top = self.env.checkout
        index = top / ".git/index"
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        return dict(exclude=digest(top / ".git/info/exclude"), index=(digest(index), index.stat().st_mtime_ns),
                    lock=(top / ".git/pilot-pr-loop.lock").exists(), tasks=(top / ".pr-loop").exists(),
                    tmux=self.env.tmux()["log"], state=self.env.state_home.exists())

    def stale_index(self):
        """A tracked file with another timestamp: a plain `git status` would refresh and rewrite the index."""
        top = self.env.checkout
        os.utime(top / "README.txt", (1, 1))
        before = (top / ".git/index").read_bytes()
        subprocess.run(["git", "status", "--porcelain"], cwd=top, env=self.env.git_env, check=True, capture_output=True)
        self.assertNotEqual(before, (top / ".git/index").read_bytes(), "the setup must make a plain status write")
        os.utime(top / "README.txt", (2, 2))

    def test_a_dry_run_names_why_a_ready_pr_is_unverified(self):
        self.env.update_gh(view=pr_view_json("ready"))
        proc = self.run_program("--dry-run")
        self.assertEqual((0, self.dry_report(f"PR #7: unverified (the PR does not carry the {rs.LABEL} label)"), ""),
                         (proc.returncode, proc.stdout, proc.stderr))
        self.assertEqual([], self.env.tmux()["log"])

    def test_a_dry_run_reports_the_phase_and_the_checkout_and_writes_nothing(self):
        self.stale_index()
        before = self.written()
        proc = self.run_program("--dry-run")
        self.assertEqual((0, self.dry_report("PR #7: draft"), ""), (proc.returncode, proc.stdout, proc.stderr))
        self.assertEqual(before, self.written(), "no lock, no exclude line, no task directory, no index refresh, no tmux")
        self.assertEqual([["pr", "view"]], [call[:2] for call in self.env.gh_calls()])

    def test_a_run_in_a_checkout_behind_origin_fast_forwards_it_and_goes_on_to_read_the_pr(self):
        top, old = self.env.checkout, self.env.remote_head
        new = self.env.advance_remote()
        proc = self.blocked_run()
        self.assertEqual(new, self.env.git("rev-parse", "HEAD", cwd=top), "the checkout is at origin's tip")
        lines = proc.stdout.splitlines()
        self.assertIn(f"Fast-forwarded main from {old[:12]} to {new[:12]}, origin's tip", lines)
        self.assertIn(f"Checkout: {top} (main at {new[:12]})", lines)
        self.assertLess(lines.index(f"Fast-forwarded main from {old[:12]} to {new[:12]}, origin's tip"),
                        lines.index(f"Checkout: {top} (main at {new[:12]})"))
        self.assertTrue(any(line.startswith("Kept:") and f"only by fast-forwarding main from {old[:12]} to {new[:12]}" in line
                            for line in lines), "and the end of the run says what changed")
        self.assertEqual(1, len(self.pastes()), "the agent was dispatched")

    def test_a_dry_run_in_a_checkout_behind_origin_says_what_it_would_do_and_writes_nothing(self):
        top, old = self.env.checkout, self.env.remote_head
        new = self.env.advance_remote()
        self.stale_index()
        git = lambda: (self.env.git("for-each-ref", "--format=%(refname) %(objectname)", cwd=top),
                       self.env.git("count-objects", "-v", cwd=top), (top / ".git/FETCH_HEAD").exists(),
                       (top / ".git/ORIG_HEAD").exists(), self.env.git("rev-parse", "HEAD", cwd=top))
        before, written = git(), self.written()
        proc = self.run_program("--dry-run")
        expected = (f"PR #7: draft\nCheckout: {top} (main at {old[:12]})\n"
                    f"would fetch origin's main at {new[:12]} and fast-forward main from {old[:12]} to it\n"
                    f"would add /.pr-ready/, /.pr-loop/ to {top}/.git/info/exclude\n"
                    f"would start the agents in tmux session {pr_loop.session_name(top)}\n"
                    f"not checked in a dry run: whether another runner holds {top}/.git/pilot-pr-loop.lock; whether an agent "
                    f"pane kept from an earlier run is still open in {top}; whether origin's main at {new[:12]} is a "
                    f"fast-forward of main, has the two helpers and leaves ignored files alone, because {new[:12]} is not in "
                    "the checkout and a dry run does not fetch it\n")
        self.assertEqual((0, expected, ""), (proc.returncode, proc.stdout, proc.stderr))
        self.assertEqual((before, written), (git(), self.written()), "no fetch, no ref, no file, no lock, no tmux")

    def test_a_run_in_a_clean_checkout_on_another_branch_switches_it_and_goes_on_to_read_the_pr(self):
        top = self.env.checkout
        tip = self.env.remote_head
        self.env.git("switch", "-q", "-c", "feature", cwd=top)
        proc = self.blocked_run()
        self.assertEqual("refs/heads/main", self.env.git("symbolic-ref", "HEAD", cwd=top))
        lines = proc.stdout.splitlines()
        switched = (f"Switched {top} from feature (at {tip[:12]}) to main; to go back: git -C {top} switch feature")
        self.assertIn(switched, lines)
        self.assertLess(lines.index(switched), lines.index(f"Checkout: {top} (main at {tip[:12]})"))
        self.assertTrue(any(line.startswith("Kept:") and "The runner switched" in line and "to go back" in line for line in lines))
        self.assertEqual(1, len(self.pastes()), "the agent was dispatched")
        self.assertEqual("refs/heads/main", self.env.git("symbolic-ref", "HEAD", cwd=top), "and the run did not switch back")

    def test_a_dry_run_in_a_clean_checkout_on_another_branch_says_what_it_would_do_and_writes_nothing(self):
        top, tip = self.env.checkout, self.env.remote_head
        self.env.git("switch", "-q", "-c", "feature", cwd=top)
        self.stale_index()
        before = self.written()
        proc = self.run_program("--dry-run")
        expected = (f"PR #7: draft\nCheckout: {top} (feature at {tip[:12]})\n"
                    f"would switch {top} from feature (at {tip[:12]}) to main\n"
                    f"would add /.pr-ready/, /.pr-loop/ to {top}/.git/info/exclude\n"
                    f"would start the agents in tmux session {pr_loop.session_name(top)}\n"
                    f"not checked in a dry run: whether another runner holds {top}/.git/pilot-pr-loop.lock; whether an agent "
                    f"pane kept from an earlier run is still open in {top}\n")
        self.assertEqual((0, expected, ""), (proc.returncode, proc.stdout, proc.stderr))
        self.assertEqual(before, self.written())
        self.assertEqual("refs/heads/feature", self.env.git("symbolic-ref", "HEAD", cwd=top), "a dry run switches nothing")

    def refused_states(self):
        """Each state the real run refuses, as `(name, set up, working directory, a fragment of the reason)`."""
        top, git = self.env.checkout, lambda *args: self.env.git(*args, cwd=self.env.checkout)
        plain = self.env.root / "plain"
        plain.mkdir(exist_ok=True)

        def dirty():
            (top / "stray.txt").write_text("x")

        def diverged():
            (top / "mine.txt").write_text("x\n")
            git("add", "-A")
            git("commit", "-q", "-m", "mine")
            self.env.advance_remote()
            git("fetch", "-q", "origin")

        def without_helper():
            self.env.make_remote({"other.txt": "x\n"})
            self.env.make_checkout()
        return (("not in a work tree", lambda: None, plain, "the current directory is not inside a git work tree"),
                ("dirty", dirty, None, "has uncommitted changes or untracked files (1 paths, e.g. stray.txt)"),
                ("diverged", diverged, None, "have diverged (each has commits the other does not have)"),
                ("another origin", lambda: git("remote", "set-url", "origin", "https://github.com/other/demo.git"), None,
                 "is github.com/other/demo, not github.com/acme/demo"),
                ("a default branch without the helpers", without_helper, None,
                 "lacks .agents/skills/_shared/scripts/pr_loop_result.py"))

    def test_a_dry_run_refuses_what_the_real_run_refuses_for_the_same_reason_and_writes_nothing(self):
        for name, setup, cwd, fragment in self.refused_states():
            with self.subTest(name=name), patch.dict(os.environ, GIT_CEILING_DIRECTORIES=str(self.env.root)):
                self.env.make_checkout()
                setup()
                self.env.reset_tmux()
                self.env.update_gh(calls=[])
                self.stale_index()
                before = self.written()
                dry = self.run_program("--dry-run", cwd=cwd)
                self.assertEqual(1, dry.returncode, dry.stdout + dry.stderr)
                self.assertEqual("PR #7: draft\n", dry.stdout, "the phases are reported; the checkout is not accepted")
                self.assertRegex(dry.stderr, r"^pr-loop: .*" + re.escape(fragment) + r".*\n$")
                self.assertEqual(1, dry.stderr.count("\n"))
                self.assertEqual(before, self.written(), "a dry run writes nothing, even when it refuses")
                real = self.run_program(cwd=cwd)
                self.assertEqual((1, dry.stderr), (real.returncode, real.stderr), "the same reason as the real run")
                self.assertEqual(1, len(self.env.gh_calls()), "the real run refused before it read a PR (the dry run read one)")

    # ---- the lock, the panes and the PR URL (AC for the refusals that need a running process) ---------------------
    def hold_lock(self):
        """Hold the lock of the checkout in this process, as another runner would; `(lock path, release)`."""
        lock = self.env.checkout / ".git/pilot-pr-loop.lock"
        held = [os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)]
        pr_loop.fcntl.flock(held[0], pr_loop.fcntl.LOCK_EX | pr_loop.fcntl.LOCK_NB)

        def release():
            while held:
                os.close(held.pop())
        self.addCleanup(release)
        return lock, release

    def test_a_second_runner_is_refused_before_anything_is_read_or_started(self):
        lock, release = self.hold_lock()
        top = self.env.checkout
        proc = self.run_program()
        self.assertEqual((1, "", f"pr-loop: another pr_loop runner is using the checkout {top} (lock {lock}); "
                                 "wait for it to finish or stop it\n"), (proc.returncode, proc.stdout, proc.stderr))
        self.assertEqual(([], []), (self.env.gh_calls(), self.env.tmux_calls()))
        # Once the other runner is gone the same start goes through (it stops here for an unrelated reason).
        release()
        proc = self.run_with_ready_pr()
        self.assertIn("is Ready without a valid", proc.stderr)
        self.assertNotIn("another pr_loop runner", proc.stderr)

    def test_the_lock_is_held_while_an_agent_is_dispatched_and_free_after_the_run(self):
        lock = self.env.checkout / ".git/pilot-pr-loop.lock"
        self.env.update_tmux(lock_path=str(lock))  # the fake tmux tries to take the lock when a session is made
        self.blocked_run()
        self.assertEqual(["held"], self.env.tmux()["lock_probes"], "the run holds the lock while it works")
        fd = os.open(lock, os.O_RDWR)
        self.addCleanup(os.close, fd)
        pr_loop.fcntl.flock(fd, pr_loop.fcntl.LOCK_EX | pr_loop.fcntl.LOCK_NB)  # free: the process has ended

    def test_a_pane_kept_from_an_earlier_run_in_the_checkout_refuses_the_start(self):
        session = "pilot-pr-7-draft-0123456789"
        self.env.update_tmux(listing=[self.env.row(session, "%3", path=f"{self.env.checkout}/sub")])
        proc = self.run_program()
        self.assertEqual((1, "", f"pr-loop: agent pane %3 (session {session}) is still running in {self.env.checkout}; "
                                 f"inspect and close it before starting the runner again {CLEAN_POINTER}\n"),
                         (proc.returncode, proc.stdout, proc.stderr))
        self.assertEqual([], self.env.gh_calls())
        self.only_listed_panes()
        self.env.update_tmux(listing=[self.env.row(session, "%3", dead=True)], log=[])  # closed (dead): the same start goes through
        self.assertIn("is Ready without", self.run_with_ready_pr().stderr)

    def run_with_ready_pr(self):
        self.env.update_gh(view=pr_view_json("ready"))
        return self.run_program("--phase-timeout", "5")

    def test_a_pr_url_that_is_not_this_pr_stops_before_an_agent_is_started(self):
        self.env.update_gh(view=pr_view_json("draft", url="https://example.com/acme/demo/pull/7"))
        proc = self.run_program()
        self.assertEqual((1, "pr-loop: PR #7: GitHub returned an unexpected PR URL\n"), (proc.returncode, proc.stderr))
        self.only_listed_panes()

    def test_checkout_must_be_the_root_of_a_work_tree(self):
        below = self.env.checkout / "sub"
        below.mkdir()
        proc = self.run_program("--checkout", str(below), cwd=self.env.root)
        top = self.env.checkout
        self.assertEqual((1, f"pr-loop: --checkout {below} is not the root of its git work tree {top}; pass {top}\n"),
                         (proc.returncode, proc.stderr))
        self.assertEqual(([], []), (self.env.gh_calls(), self.env.tmux_calls()))

    def test_the_help_of_checkout_says_what_it_defaults_to(self):
        done = subprocess.run([sys.executable, "-B", str(self.SCRIPT), "--help"], capture_output=True, text=True, timeout=60)
        text = " ".join(done.stdout.split())
        self.assertIn("--checkout DIR", text)
        self.assertIn(f"(default: {pr_loop.CHECKOUT_DEFAULT})", text)

    def parsed_args(self, *extra):
        """What `main()` hands the Batch for this command line, with a Batch that starts nothing."""
        seen = []

        class Capture:
            def __init__(self, repo, args):
                seen.append(args)

            def run(self):
                return None
        argv = ["pr_loop.py", "7", "--repo", "acme/demo", *extra]
        with patch.object(sys, "argv", argv), patch.object(pr_loop, "Batch", Capture):
            self.assertEqual(0, pr_loop.main())
        self.assertEqual(1, len(seen))
        return seen[0]

    def test_the_phase_timeout_defaults_to_four_hours_and_the_flag_overrides_it(self):
        self.assertEqual(14400, self.parsed_args().phase_timeout, "the value the runner would wait per phase")
        self.assertEqual(14400, pr_loop.PHASE_TIMEOUT)
        self.assertEqual(5.0, self.parsed_args("--phase-timeout", "5").phase_timeout)
        self.assertEqual(7200.0, self.parsed_args("--phase-timeout", "7200").phase_timeout, "the old default is still allowed")
        self.assertEqual(14400, self.parsed_args("--poll-interval", "1").phase_timeout, "another flag does not change it")

    def test_the_help_of_phase_timeout_says_its_default(self):
        done = subprocess.run([sys.executable, "-B", str(self.SCRIPT), "--help"], capture_output=True, text=True, timeout=60)
        text = " ".join(done.stdout.split())
        self.assertIn("--phase-timeout PHASE_TIMEOUT seconds waiting per phase (default: 14400)", text)
        self.assertNotIn("(default: 7200)", text)

    def test_a_pr_that_cannot_be_read_stops_without_starting_anything(self):
        self.env.update_gh(seq=[{"exit": 1, "stderr": "synthetic outage"}])
        proc = self.run_program()
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        self.assertIn("GitHub read failed 3 consecutive times; no command sent", proc.stderr)
        self.only_listed_panes()
        self.assertEqual({("pr", "view")}, {tuple(call[:2]) for call in self.env.gh_calls()})
        self.assertIn("GitHub read failed (2/3)", proc.stdout)


# ---- (F) `--clean`: what a stopped or interrupted run left (kjelly/pilot#442) ---------------------------------------

def model(name, *args):
    """A function of the fake tmux's model (the one that is also embedded in the fake), for the pure checks below."""
    from pr_loop_fakes import _model
    return _model[name](*args)


def q34(text):
    """`#{q:text}` as tmux 3.4 prints it (captured on 3.4.1 of Ubuntu 24.04, kjelly/pilot#442): a backslash before the characters
    of `|&;<>()$`\\\"'*?[# =%` and before a backslash, and NOT before `{`, `}` or a newline, which 3.8 quotes (`model("q")`)."""
    return "".join("\\" + char if char in "|&;<>()`\\\"'*?[# =%" else char for char in text)


class ListingParserTests(unittest.TestCase):
    """The rows of `list-panes -a -F LIST_FORMAT` (kjelly/pilot#442). The free text of them (names, directories, commands) comes
    in tmux's `q:` quoting, and no value may end its field or its row early: a name with a `|`, a directory with a newline.
    Everything else about a row is of a fixed shape, and a row that is not is a Stop (fail closed). Read in both quotings that
    the runner meets: tmux 3.8's, which puts a backslash before a newline in a value, and tmux 3.4's, which does not."""
    HOSTILE = ["plain", "a|b", "a\\b", "a\\|b", "two\nlines", "\\\n", "quote'\"s", "$HOME `x` $(y)", "sp ace", "tab\there", "é日本",
               "%#=;&<>()*?[]{}!~^", "", "|", "||", "\\", "x\n", "\n|"]

    def row(self, *free, quote=None, **fixed):
        shape = ["%1", "@1", "0", "0", "4242", "4007", "1700000013"]
        text = list(free) or ["/tmp/tmux-1000/default", "pilot-pr-x-0123abcd", "7-draft", "/work", "exec /bin/claude", "/work",
                              "claude"]
        return "|".join(shape + [(quote or (lambda value: model("q", value)))(value) for value in text]) + "\n"

    def test_a_row_is_read_into_the_pane_it_describes(self):
        (fields,) = pr_loop.split_listing(self.row())
        pane = pr_loop.read_pane(fields)
        self.assertEqual(("%1", "@1", False, False, "4242", ("4007", "1700000013"), "/tmp/tmux-1000/default",
                          "pilot-pr-x-0123abcd", "7-draft", "/work", "exec /bin/claude", "/work", "claude"), tuple(pane))

    def test_quoting_is_undone_for_every_character_tmux_quotes_and_for_a_newline(self):
        for value in self.HOSTILE + [chr(code) for code in range(32, 127)]:
            with self.subTest(value=value):
                self.assertEqual(value, pr_loop.unquote(model("q", value)))

    def test_a_value_that_looks_like_a_separator_stays_in_its_field_and_its_row(self):
        for name, quote in (("tmux 3.8", None), ("tmux 3.4", q34)):
            for value in self.HOSTILE:
                with self.subTest(tmux=name, value=value):
                    rows = pr_loop.split_listing(self.row("/s", value, value, value, value, value, value, quote=quote) * 2)
                    self.assertEqual(2, len(rows), "two rows, whatever the values hold")
                    for fields in rows:
                        pane = pr_loop.read_pane(fields)
                        self.assertEqual([value] * 6, [pane.session, pane.window, pane.start_path, pane.start_command, pane.path,
                                                       pane.command])
                        self.assertEqual(("/s", "%1"), (pane.socket, pane.pane))

    def test_a_newline_that_is_not_quoted_ends_a_row_only_where_a_row_starts(self):
        # tmux 3.4 does not quote a newline in a value. What follows it says whether it ends the row or is in a field.
        two = self.row(quote=q34) + self.row("/s", "S", "w", "/a\nb", "c", "/a\nb", "x", quote=q34)
        rows = pr_loop.split_listing(two)
        self.assertEqual(2, len(rows))
        self.assertEqual("/a\nb", pr_loop.read_pane(rows[1]).start_path)
        forged = self.row("/s", "S", "w", "/a\n%9|@9|0|0|1|4007|1700000013|/s|S|w|/a|exec /x|/a|x", "c", "/a", "x", quote=lambda v: v)
        self.assertEqual(2, len(pr_loop.split_listing(forged)), "(a value made to look like a row is one: 3.8 quotes the newline "
                                                                "in it, 3.4 does not, and nothing can tell the two apart)")
        quoted = self.row("/s", "S", "w", "/a\n%9|@9|0|0|1|4007|1700000013|/s|S|w|/a|exec /x|/a|x", "c", "/a", "x")
        self.assertEqual(1, len(pr_loop.split_listing(quoted)), "while the newline tmux 3.8 quotes is never the end of a row")

    def test_the_unquoted_separators_split_and_nothing_else_does(self):
        first, second = "%1|@1|0|0|4|5|6|a|b", "%2|@2|1|0||5|6|c|d"
        self.assertEqual([first.split("|"), second.split("|")], pr_loop.split_listing(f"{first}\n{second}\n"))
        self.assertEqual([["%1", "@1", "0", "0", "4", "5", "6", "a\\|b"]], pr_loop.split_listing("%1|@1|0|0|4|5|6|a\\|b\n"),
                         "a quoted bar stays")
        self.assertEqual([["%1", "@1", "0", "0", "4", "5", "6", "a\\\nb"]], pr_loop.split_listing("%1|@1|0|0|4|5|6|a\\\nb\n"),
                         "a quoted newline stays")
        self.assertEqual([["%1", "@1", "0", "0", "4", "5", "6", "a\\\\", "b"]],
                         pr_loop.split_listing("%1|@1|0|0|4|5|6|a\\\\|b\n"), "a quoted backslash quotes nothing after it")
        self.assertEqual([], pr_loop.split_listing(""))

    def test_a_listing_that_ends_inside_a_row_or_a_quoting_cannot_be_read(self):
        for text in ("a|b", "a|b\nc", "a\\", "a|b\\", "|"):
            with self.subTest(text=text):
                self.assertIsNone(pr_loop.split_listing(text))

    def test_a_row_of_another_shape_is_a_stop(self):
        good = self.row().rstrip("\n").split("|")
        for case, fields in (("a field short", good[:-1]), ("a field too many", good + ["x"]), ("no fields", []),
                             ("a pane that is not an ID", ["1"] + good[1:]), ("a window that is not an ID", [good[0], "1"] + good[2:]),
                             ("dead that is not 0 or 1", good[:2] + ["2"] + good[3:]),
                             ("in-mode that is not 0 or 1", good[:3] + ["x"] + good[4:]),
                             ("a process that is not a number", good[:4] + ["12x"] + good[5:]),
                             ("a server PID that is empty", good[:5] + [""] + good[6:]),
                             ("a start time that is not a number", good[:6] + ["now"] + good[7:])):
            with self.subTest(case=case), self.assertRaisesRegex(pr_loop.Stop, "^tmux list-panes returned a line that cannot be read$"):
                pr_loop.read_pane(fields)
        self.assertEqual("", pr_loop.read_pane(good[:4] + [""] + good[5:]).pid, "control: a dead pane has no process")

    def test_the_format_quotes_every_free_text_field_and_none_of_the_others(self):
        parts = pr_loop.LIST_FORMAT.split("|")
        self.assertEqual(7 + len(pr_loop.LIST_TEXT), len(parts))
        self.assertEqual([f"#{{q:{name}}}" for name in pr_loop.LIST_TEXT], parts[7:])
        self.assertTrue(all("q:" not in part for part in parts[:7]), "an ID or a number needs no quoting")
        self.assertEqual(len(parts) - 1, len(pr_loop.Pane._fields), "the server's PID and start time are one field of a Pane")


class StartedWithTests(unittest.TestCase):
    """The start command of a pane as tmux shows it: the runner's is `exec <absolute path>`, and only that is the runner's. tmux
    3.8 shows the command in double quotes when it holds a space (a path that needs quoting for a shell is quoted again inside),
    an older one may show it as it was given: both are read, and everything else is not the runner's."""

    def test_the_command_the_runner_starts_an_agent_with_is_read_back_whatever_the_path_is(self):
        for path in ("/usr/bin/claude", "/opt/my tools/agent x", "/o'brien/bin/claude", '/q"uote/agent', "/a$b/c", "/a b#c/d",
                     "/back\\slash/agent", "/new\nline/agent", "/é日本/agent", "/a;b|c&d/agent", "/tab\there/agent"):
            with self.subTest(path=path):
                given = "exec " + shlex.quote(path)
                self.assertEqual(path, pr_loop.started_with(model("start_shown", [given])), "as tmux 3.8 shows it")
                self.assertEqual(path, pr_loop.started_with(given), "as it was given")

    def test_the_forms_tmux_3_8_and_3_4_were_captured_showing_are_read(self):
        # Captured (kjelly/pilot#442) on tmux 3.8 and on tmux 3.4.1 (Ubuntu 24.04) for `new-window -- "exec <quoted path>"`. tmux 3.4
        # writes a `$` in a command between double quotes as `\\$` (a backslash that is not a quoting of the `$`): the shape is
        # still read, the path in it is not the path (`/a\\$b`), which nothing here uses.
        for tmux, shown, path in (("3.8", '"exec /usr/bin/claude"', "/usr/bin/claude"),
                                  ("3.4", '"exec /usr/bin/claude"', "/usr/bin/claude"),
                                  ("3.8", "\"exec '/opt/my tools/agent x'\"", "/opt/my tools/agent x"),
                                  ("3.4", "\"exec '/opt/my tools/agent x'\"", "/opt/my tools/agent x"),
                                  ("3.8", "\"exec '/o'\\\"'\\\"'brien/bin/claude'\"", "/o'brien/bin/claude"),
                                  ("3.4", "\"exec '/o'\\\"'\\\"'brien/bin/claude'\"", "/o'brien/bin/claude"),
                                  ("3.8", "\"exec '/a\\$b/c'\"", "/a$b/c"), ("3.4", "\"exec '/a\\\\$b/c'\"", "/a\\$b/c")):
            with self.subTest(tmux=tmux, shown=shown):
                self.assertEqual(path, pr_loop.started_with(shown))

    def test_anything_that_is_not_that_command_is_not(self):
        for shown in ("", '""', "bash", '"tail -f /dev/null"', "tail -f /dev/null", '"exec"', '"exec "', '"exec bin/claude"',
                      '"exec ./claude"', '"exec /bin/claude --resume"', '"exec /bin/claude;rm"', '"exec /bin/sh -c x"',
                      "exec", "exec /a /b", '"exec \'/unbalanced"', "exec 'x", '"exec /a" "exec /b"', "EXEC /bin/claude",
                      '"exec\\ /bin/claude"', "'exec /bin/claude'", "x exec /bin/claude", "\"exec /bin/claude\" extra"):
            with self.subTest(shown=shown):
                self.assertIsNone(pr_loop.started_with(shown))


class ScreenStateTests(unittest.TestCase):
    """The ONE reader of an agent's screen: `wait_for_prompt` waits for `prompt`, `--clean` reads all four. Screens are
    SYNTHETIC: they exercise the PROMPT, CHOICE and BUSY rules, not any real agent's UI."""

    def test_each_state_is_told_from_the_screen(self):
        for case, screen, state in (("an input prompt", "synthetic banner\n\n❯", "prompt"),
                                    ("a prompt with text typed", "synthetic\n❯ typed", "prompt"),
                                    ("working", "synthetic\n❯\nWorking (12s • esc to interrupt)", "working"),
                                    ("ctrl+c to interrupt", "run (ctrl+c to interrupt)", "working"),
                                    ("a numbered choice", "Do you trust this folder?\n❯ 1. Yes, proceed\n  2. No, exit", "asking"),
                                    ("a loading screen", "synthetic: loading", "unknown"),
                                    ("a shell prompt", "user@host:~$", "unknown"),
                                    ("a prompt too far up", "❯\n" + "line\n" * 6, "unknown"),
                                    ("nothing", "", "unknown"), ("only blank lines", "\n  \n\t\n", "unknown")):
            with self.subTest(case=case):
                self.assertEqual(state, pr_loop.screen_state(screen))
                self.assertEqual(state, pr_loop.screen_state(screen, strict=True))

    def test_strict_also_reads_to_interrupt_wherever_it_stands(self):
        for screen in ("❯\nWorking (12s • esc to interrupt) · 3 background tasks", "❯\nto interrupt, press esc",
                       "❯\nPress ESC TO INTERRUPT now", "❯\nesc to interrupt)  x"):
            with self.subTest(screen=screen):
                self.assertEqual("prompt", pr_loop.screen_state(screen), "the runner's own wait only reads the end of a line")
                self.assertEqual("working", pr_loop.screen_state(screen, strict=True))

    def test_only_the_last_sixteen_non_blank_lines_count(self):
        old = "Working (12s • esc to interrupt)\n" + "\n".join(f"line {n}" for n in range(16)) + "\n❯"
        self.assertEqual("prompt", pr_loop.screen_state(old, strict=True), "the 17th line from the end is out of sight")
        recent = "Working (12s • esc to interrupt)\n" + "\n".join(f"line {n}" for n in range(14)) + "\n❯"
        self.assertEqual("working", pr_loop.screen_state(recent, strict=True), "the 16th line from the end counts")


class RunnersOwnTests(unittest.TestCase):
    """A pane is the runner's only if ALL five conditions hold on one row (kjelly/pilot#442): each is a pass case beside the
    row that fails exactly it."""

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="pr-loop-own-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name).resolve()
        self.top = self.root / "co"
        self.top.mkdir()
        self.session = pr_loop.session_name(self.top)
        self.command = model("start_shown", ["exec /usr/bin/claude"])

    def pane(self, **change):
        pane = pr_loop.Pane("%3", "@1", False, False, "4242", ("4007", "1"), "/s", self.session, "7-draft", str(self.top),
                            self.command, str(self.top), "claude")
        return pane._replace(**change)

    def own(self, **change):
        return pr_loop.runners_own(self.pane(**change), self.top, self.session)

    def test_the_pane_the_runner_started_is_its_own(self):
        self.assertTrue(self.own())
        for window in ("1-draft", "7-ready", "371-draft", "99999-ready"):
            self.assertTrue(self.own(window=window), window)
        self.assertTrue(self.own(dead=True, pid="", path=""), "a dead pane is the runner's too, with no process and no path")

    def test_condition_1_the_session_is_exactly_the_one_named_for_the_checkout(self):
        other = pr_loop.session_name(self.root / "other")
        for session in (other, self.session + "-eink", self.session + "x", self.session[:-1], "x" + self.session,
                        "pilot-pr-7-draft-0123456789", "", self.session.upper()):
            with self.subTest(session=session):
                self.assertFalse(self.own(session=session))

    def test_condition_2_the_window_is_named_for_an_agent(self):
        for window in ("", "draft", "7", "7-", "-draft", "0-draft", "07-draft", "7-drafts", "7-DRAFT", "7-draft ", " 7-draft",
                       "x7-draft", "7-draft\n", "7-merge", "a-draft", "7_draft", "claude", "bash", "7-draft-2", "1.5-ready"):
            with self.subTest(window=window):
                self.assertFalse(self.own(window=window))

    def test_condition_3_it_was_started_in_the_checkout_itself(self):
        (self.root / "co-other").mkdir()
        (self.top / "sub").mkdir()
        link = self.root / "link"
        link.symlink_to(self.top)
        self.assertTrue(self.own(start_path=str(link)), "the same directory through a symlink is the same directory")
        self.assertTrue(self.own(start_path=f"{self.top}/."), "and so is a path that is spelled differently")
        for path in (str(self.root / "co-other"), str(self.top / "sub"), str(self.root), "/", "", str(self.root / "nothing"),
                     "co"):
            with self.subTest(path=path):
                self.assertFalse(self.own(start_path=path))
        self.assertFalse(self.own(start_path="", path=str(self.top)), "where it is NOW is not where it was started")

    def test_condition_4_it_was_started_with_exec_and_an_absolute_path(self):
        # (`exec` and `/bin/claude` as two arguments would show as `exec /bin/claude`, which an older tmux shows for the single
        # argument too: that is a command that cannot run, `exec` being a shell builtin, so it is not a case to tell apart.)
        for command in ("", model("start_shown", ["tail", "-f", "x"]), model("start_shown", ["exec /bin/claude --resume"]),
                        model("start_shown", ["exec claude"]), model("start_shown", ["claude"]),
                        model("start_shown", ["exec  /bin/claude"]), model("start_shown", ["exec '/bin/claude'"]),
                        model("start_shown", ["exec /bin/claude;rm"]), '"exec /a /b"', "exec"):
            with self.subTest(command=command):
                self.assertFalse(self.own(start_command=command))
        self.assertTrue(self.own(start_command="exec /bin/claude"), "as it was given")
        self.assertTrue(self.own(start_command=model("start_shown", ["exec '/a b/claude'"])))

    def test_where_it_is_now_what_runs_in_it_and_its_mode_are_not_conditions(self):
        self.assertTrue(self.own(path="/anywhere", command="bash", pid="1", in_mode=True))


class CleanCase(unittest.TestCase):
    """`--clean` over the fake tmux and a real checkout of a real scratch remote (kjelly/pilot#442). The agents are started
    by the real `Agent`, the way a run starts them, so that the panes are the ones a run leaves; their screens and states are
    scripted and SYNTHETIC. Nothing here can reach the developer's tmux server (FakeEnv refuses to go on unless `which` finds
    the fake) and a test that kills a pane kills it in the fake."""
    repo = pr_loop.Repo.parse("acme/demo")
    WORKING = "synthetic\n❯\nWorking (12s • esc to interrupt)"

    def setUp(self):
        self.env = FakeEnv(self)
        self.clock = FakeTime()
        self.told = []
        for target, value in (("time", self.clock), ("tell", self.told.append)):
            patcher = patch.object(pr_loop, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.top = self.env.checkout
        self.session = pr_loop.session_name(self.top)
        self.where = SimpleNamespace(path=self.top, session=self.session)
        # What an earlier run did to the checkout's exclude file, so that its task directories are not uncommitted work.
        with (self.top / ".git/info/exclude").open("a") as stream:
            stream.write(f"/.pr-ready/\n/{pr_loop.TASK_DIR}/\n")

    def state(self):
        """Everything of the checkout a listing must leave as it is: HEAD, the refs, the index (and when it was written), the exclude
        file, the lock file (it must not be made), every file of the work tree, and what the fake tmux has."""
        git = lambda *args: self.env.git(*args, cwd=self.top)
        index = self.top / ".git/index"
        files = {str(path.relative_to(self.top)): sha256_of(path) if path.is_file() and not path.is_symlink() else str(path.readlink())
                 if path.is_symlink() else "dir" for path in sorted(self.top.rglob("*")) if ".git" not in path.relative_to(self.top).parts[:1]}
        return dict(head=git("rev-parse", "HEAD"), symbolic=git("symbolic-ref", "-q", "HEAD"),
                    refs=git("for-each-ref", "--format=%(refname) %(objectname)"), index=(sha256_of(index), index.stat().st_mtime_ns),
                    exclude=sha256_of(self.top / ".git/info/exclude"), lock=(self.top / ".git" / pr_loop.LOCK_NAME).exists(),
                    fetch_head=(self.top / ".git/FETCH_HEAD").exists(), files=files, live=self.env.live())

    def agent(self, number=7, phase="draft", **pane):
        """An agent the way a run starts it (the real `Agent` over the fake tmux); `pane` scripts its pane."""
        found = pr_loop.Agent("claude", self.where, number, phase)
        self.told.clear()
        if pane:
            self.env.set_pane(found.pane, **pane)
        return found

    def args(self, **flags):
        return SimpleNamespace(**{**dict(clean=True, yes=False, include_busy=False, remove_task_dirs=False, dry_run=False, pr=[],
                                         checkout=str(self.top), repo="acme/demo"), **flags})

    def clean(self, **flags):
        """`--clean` with these flags; `(exit status, the lines it printed)`."""
        del self.told[:]
        code = pr_loop.Clean(self.repo, self.args(**flags)).run()
        return code, list(self.told)

    def kills(self):
        return [call[2] for call in self.env.tmux_calls("kill-pane")]

    def line(self, lines, pane):
        """The one line about `pane` in `lines`."""
        (found,) = [line for line in lines if line.startswith(f"pane {pane} ") or f"pane {pane} (" in line]
        return found

    def task(self, *, pr=7, phase="draft", result=None, age=3 * 3600 + 20 * 60, nonce=None):
        """A task directory the way a run writes it (the runner's own `Checkout.task`), `age` seconds old by the fake clock, with a
        result the real `write_result` writes when `result` names an outcome; its nonce."""
        path, task = pr_loop.Checkout.task(SimpleNamespace(path=self.top), self.repo, pr, phase, HEAD)
        if nonce:
            (path.parent).rename(path.parent.parent / nonce)
            path = path.parent.parent / nonce / "task.json"
            path.write_text(json.dumps(dict(task, nonce=nonce)))
        if result:
            write_result(path, json.loads(path.read_text()), outcome=result, head=HEAD, reason="synthetic")
        stamp = self.clock.time() - age
        for entry in path.parent.iterdir():
            os.utime(entry, (stamp, stamp))
        return path.parent.name

    def task_dir(self, nonce):
        return self.top / pr_loop.TASK_DIR / nonce


class CleanListingTests(CleanCase):
    """The listing (`--clean` without `--yes`): what it says about each pane, and that it changes nothing."""
    SOCKET = SOCKET

    def header(self):
        return f"Residue of earlier runs in {self.top} (tmux session {self.session} on {self.SOCKET}):"

    def test_the_listing_of_one_idle_agent_and_of_nothing(self):
        agent = self.agent()
        code, lines = self.clean()
        self.assertEqual(0, code)
        self.assertEqual([self.header(),
                          f"pane {agent.pane} window 7-draft: alive, idle (at its prompt), claude; would close: it is idle; "
                          f"closing it ends window 7-draft and session {self.session}; an attached client is detached",
                          "  | ❯", "would close 1 panes and remove 0 task directories; the next run would start"], lines)
        self.env.kill_server()
        code, lines = self.clean()
        self.assertEqual((0, [f"Residue of earlier runs in {self.top} (tmux session {self.session}):", NO_SERVER,
                              "would close 0 panes and remove 0 task directories; the next run would start"]), (code, lines))

    def test_a_listing_changes_nothing_and_asks_tmux_only_to_list_and_to_capture(self):
        idle = self.agent(7, "draft")
        self.agent(7, "ready", status=["1|0|claude"])
        self.agent(8, "draft", screens=[self.WORKING])
        self.env.add_split(idle.pane)
        self.task(result="DRAFT-BLOCKED")
        self.env.update_tmux(log=[])
        before = self.state()
        for flags in ({}, {"include_busy": True}, {"remove_task_dirs": True}, {"include_busy": True, "remove_task_dirs": True}):
            with self.subTest(flags=flags):
                code, lines = self.clean(**flags)
                self.assertEqual(0, code)
                self.assertEqual({"list-panes", "capture-pane"}, {call[0] for call in self.env.tmux_calls()},
                                 "tmux is asked to list and to capture, never to change anything")
                self.assertEqual([], self.kills())
                self.assertEqual([], self.env.gh_calls(), "no GitHub")
                self.assertEqual(before, self.state(), "no checkout file, ref, index, lock or task directory, and no pane")
                self.assertTrue(any("would close" in line for line in lines))
                self.assertFalse(any(line.startswith(("closed", "removed")) or ": closed" in line or ": removed" in line
                                     for line in lines))

    def test_each_state_a_pane_can_be_in_is_told_with_its_reason(self):
        asking = "Do you trust this folder?\n❯ 1. Yes, proceed\n  2. No, exit"
        for case, pane, expected in (
                ("dead", dict(status=["1|0|claude"]), ("dead", "dead")),
                ("idle", {}, ("alive, idle (at its prompt)", "idle")),
                ("working", dict(screens=[self.WORKING]), ("alive, busy (working)", "busy")),
                ("working, the words in the middle of a line", dict(screens=["❯\nWorking (12s • esc to interrupt) · 3 tasks"]),
                 ("alive, busy (working)", "busy")),
                ("asking", dict(screens=[asking]), ("alive, busy (asking)", "busy")),
                ("copy mode", dict(status=["0|1|claude"]), ("alive, busy (copy-mode)", "busy")),
                ("a shell in the foreground", dict(status=["0|0|bash"]), ("alive, busy (unknown: no agent in the foreground)", "busy")),
                ("a login shell", dict(status=["0|0|-zsh"]), ("alive, busy (unknown: no agent in the foreground)", "busy")),
                ("nothing in the foreground", dict(status=["0|0|"]), ("alive, busy (unknown: no agent in the foreground)", "busy")),
                ("a screen with no prompt", dict(screens=["synthetic: loading"]),
                 ("alive, busy (unknown: no input prompt on the screen)", "busy")),
                ("a screen that changes", dict(screens=["❯ a", "❯ b"]), ("alive, busy (the screen is still changing)", "busy"))):
            with self.subTest(case=case):
                self.setUp()
                agent = self.agent(**pane)
                what, kind = expected
                command = pane.get("status", ["0|0|claude"])[0].split("|")[2] or "-"
                code, lines = self.clean()
                found = self.line(lines, agent.pane)
                self.assertTrue(found.startswith(f"pane {agent.pane} window 7-draft: {what}, "), found)
                self.assertIn(f", {command}; ", found)
                self.assertIn("would close: it is dead" if kind == "dead" else "would close: it is idle" if kind == "idle" else
                              "left open: it is busy; busy panes are closed only with --include-busy", found)

    def test_busy_panes_would_be_closed_with_include_busy_and_nothing_else_changes(self):
        busy = self.agent(7, "draft", screens=[self.WORKING])
        idle = self.agent(7, "ready")
        lines = self.clean()[1]
        self.assertIn("left open: it is busy; busy panes are closed only with --include-busy", self.line(lines, busy.pane))
        self.assertIn("would close: it is idle", self.line(lines, idle.pane))
        self.assertEqual("would close 1 panes and remove 0 task directories; the next run would still be refused (%1)", lines[-1])
        lines = self.clean(include_busy=True)[1]
        self.assertIn("would close: it is busy, and --include-busy was given", self.line(lines, busy.pane))
        self.assertEqual("would close 2 panes and remove 0 task directories; the next run would start", lines[-1])

    def test_an_idle_pane_is_read_twice_at_least_a_second_apart_and_a_busy_one_once(self):
        busy = self.agent(7, "draft", screens=[self.WORKING])
        idle = self.agent(7, "ready")
        self.env.update_tmux(log=[])
        self.clean()
        captured = [call[-1] for call in self.env.tmux_calls("capture-pane")]
        self.assertEqual([busy.pane, idle.pane, idle.pane], captured, "the busy one needs no second read, the idle one does")
        self.assertEqual([pr_loop.SETTLE], self.clock.sleeps, "one wait for all of them, a second long")
        self.assertGreaterEqual(pr_loop.SETTLE, 1.0)
        self.setUp()
        self.agent(status=["1|0|claude"])
        self.clean()
        self.assertEqual([], self.clock.sleeps, "nothing to wait for when no pane may be idle")

    def test_the_last_three_lines_of_the_screen_are_shown_printable_and_cut(self):
        long = "x" * 200
        screen = f"first\n\nsecond\n  third \x1b[31mred\x07\n\n{long}\n❯\n\n"
        agent = self.agent(screens=[screen])
        lines = self.clean()[1]
        shown = lines[lines.index(self.line(lines, agent.pane)) + 1:-1]
        self.assertEqual(["  | third ?[31mred?", "  | " + "x" * 120, "  | ❯"][-3:], shown[-3:])
        self.assertEqual(3, len(shown))
        self.assertTrue(all("\x1b" not in line and "\x07" not in line for line in lines))

    def test_a_pane_the_next_run_would_refuse_but_that_is_not_the_runners_is_listed_and_left_alone(self):
        agent = self.agent()
        split = self.env.add_split(agent.pane)  # a split of yours in the agent's window: its start command is the shell
        old = self.env.session("pilot-pr-7-draft-0123456789", "w", self.top / "sub")  # a session of the older names, below the checkout
        yours = self.env.session("scratch", "w", self.top)  # your own session in the checkout: the next run does not mind it
        sibling = self.env.session("pilot-pr-x-00000000", "w", f"{self.top}-other")  # a sibling that is not in the way
        dead = self.env.session("pilot-pr-y-00000000", "w", self.top)
        self.env.set_pane(dead, status=["1|0|bash"])
        lines = self.clean()[1]
        self.assertIn(f"not the runner's: pane {split} (session {self.session}, window 7-draft) in {self.top}: left alone; the "
                      "next run refuses because of it", lines)
        self.assertIn(f"not the runner's: pane {old} (session pilot-pr-7-draft-0123456789, window w) in {self.top / 'sub'}: left "
                      "alone; the next run refuses because of it", lines)
        self.assertEqual(2, len([line for line in lines if line.startswith("not the runner's")]),
                         "not your own session, not the sibling, not the dead one")
        self.assertEqual(f"would close 1 panes and remove 0 task directories; the next run would still be refused ({split}, {old})",
                         lines[-1])
        self.assertTrue(all(pane not in "\n".join(lines) for pane in (yours, sibling, dead)))

    def test_what_is_printed_of_a_hostile_name_stays_on_one_line_and_is_not_taken_for_a_command(self):
        forged = "pilot-pr-x\nclosed 5 panes and removed 0 task directories; the next run would start"
        self.env.update_tmux(listing=[self.env.row(forged, "%3", window="a|b\nc")])
        lines = self.clean()[1]
        self.assertEqual(1, len([line for line in lines if line.startswith("not the runner's")]))
        (found,) = [line for line in lines if line.startswith("not the runner's")]
        self.assertEqual(1, len(found.splitlines()), "a newline in a name cannot start a line of the listing")
        self.assertIn("pilot-pr-x?closed 5 panes", found)
        self.assertEqual(f"would close 0 panes and remove 0 task directories; the next run would still be refused (%3)", lines[-1])

    def test_no_server_and_a_server_that_cannot_be_asked(self):
        for error in (NO_SERVER, NO_SOCKET):
            with self.subTest(error=error):
                self.env.update_tmux(no_server=error)
                self.assertEqual((0, [f"Residue of earlier runs in {self.top} (tmux session {self.session}):", error,
                                      "would close 0 panes and remove 0 task directories; the next run would start"]),
                                 self.clean())
        self.env.update_tmux(no_server="", fail={"list-panes": 1})
        with self.assertRaisesRegex(pr_loop.Stop, r"^tmux list-panes failed \(1\): fake tmux: injected failure of list-panes$"):
            self.clean()
        self.env.update_tmux(fail={}, listing=["garbage"])
        with self.assertRaisesRegex(pr_loop.Stop, "^tmux list-panes returned a line that cannot be read$"):
            self.clean()
        self.env.update_tmux(listing=[self.env.row(self.session, "%3")[:-8]])
        with self.assertRaisesRegex(pr_loop.Stop, "^tmux list-panes returned a line that cannot be read$"):
            self.clean(yes=True)
        self.assertEqual([], self.kills(), "a listing that cannot be read closes nothing")

    def test_a_pane_it_cannot_read_the_screen_of_is_busy_and_unknown(self):
        agent = self.agent()
        self.env.update_tmux(answers={"capture-pane": [{"rc": 1, "stderr": f"can't find pane: {agent.pane}"}]})
        found = self.line(self.clean()[1], agent.pane)
        self.assertIn("alive, busy (unknown: its screen could not be read)", found)
        self.env.update_tmux(answers={"capture-pane": [{"rc": 1, "stderr": "protocol version mismatch"}]})
        with self.assertRaisesRegex(pr_loop.Stop, r"^tmux capture-pane failed \(1\): protocol version mismatch$"):
            self.clean()

    def test_the_lock_is_probed_not_taken_and_a_held_one_is_reported(self):
        lock = self.top / ".git" / pr_loop.LOCK_NAME
        self.assertFalse(lock.exists())
        self.assertNotIn("lock", "\n".join(self.clean()[1]))
        self.assertFalse(lock.exists(), "a lock that nobody holds is not created by looking at it")
        held = pr_loop.lock_checkout(self.top, lock)
        try:
            lines = self.clean()[1]
        finally:
            os.close(held)
        self.assertIn(f"lock {lock}: held by a running runner; --clean --yes would be refused", lines)
        self.assertNotIn("lock", "\n".join(self.clean()[1]), "control: nobody holds it now (the file is still there)")
        self.assertTrue(lock.is_file())

    def test_a_lock_that_cannot_be_probed_is_reported_and_not_followed(self):
        lock = self.top / ".git" / pr_loop.LOCK_NAME
        elsewhere = self.env.root / "elsewhere.lock"
        elsewhere.write_text("")
        lock.symlink_to(elsewhere)
        lines = self.clean()[1]
        self.assertTrue(any(line.startswith(f"lock {lock}: cannot be probed (") and line.endswith("); --clean --yes would be refused")
                         for line in lines), lines)
        lock.unlink()
        os.mkfifo(lock)
        self.assertIn(f"lock {lock}: cannot be probed (not a regular file); --clean --yes would be refused", self.clean()[1])

    def test_uncommitted_work_and_a_git_operation_in_progress_are_reported_and_left(self):
        (self.top / "stray.txt").write_text("mine\n")
        (self.top / "README.txt").write_text("changed\n")
        before = self.state()
        lines = self.clean()[1]
        self.assertIn("the checkout has uncommitted changes or untracked files (2 paths, e.g. README.txt, stray.txt): left alone; "
                      "the next run refuses until you commit or remove them", lines)
        self.assertEqual("would close 0 panes and remove 0 task directories; the next run would still be refused (uncommitted work)",
                         lines[-1])
        self.assertEqual(before, self.state())
        marker = Path(self.env.git("rev-parse", "--path-format=absolute", "--git-path", "MERGE_HEAD", cwd=self.top))
        marker.write_text("x\n")
        lines = self.clean()[1]
        self.assertIn("a git operation is in progress in the checkout (MERGE_HEAD): left alone; the next run refuses until you "
                      "finish or abort it", lines)
        self.assertEqual("would close 0 panes and remove 0 task directories; the next run would still be refused "
                         "(a git operation in progress, uncommitted work)", lines[-1])
        self.assertEqual("mine\n", (self.top / "stray.txt").read_text())

    def test_the_clean_path_does_not_build_the_checkout_that_a_run_builds(self):
        # A run's `Checkout` refuses on the very panes `--clean` is for (check_panes), may fast-forward or switch the checkout,
        # and writes the exclude file and the lock: none of that may happen here, however the checkout stands.
        self.agent()
        self.env.advance_remote()
        self.env.git("switch", "-q", "-c", "feature", cwd=self.top)
        before = self.state()
        built = []
        real = pr_loop.Checkout.__init__
        with patch.object(pr_loop.Checkout, "__init__", lambda *a, **k: built.append(a) or real(*a, **k)):
            for flags in ({}, {"yes": True}):
                code, lines = self.clean(**flags)
                self.assertEqual(0, code)
                self.assertTrue(any(line.startswith("pane %1 ") for line in lines))
        self.assertEqual([], built, "no Checkout")
        self.assertEqual({**before, "live": self.env.live(), "lock": True}, self.state(),
                         "HEAD, refs, index, files, exclude file: unchanged (a run that acts makes the lock file, which is in .git)")
        self.assertEqual("refs/heads/feature", self.env.git("symbolic-ref", "HEAD", cwd=self.top))


class CleanClosingTests(CleanCase):
    """`--clean --yes`: which panes it closes, and every rule that keeps it from closing one (kjelly/pilot#442). A rule's trigger
    case is a pane that must NOT be closed although everything else about it says the runner's; its pass case is the pane beside
    it that is."""

    def shown(self, *words):
        """The start command of the agent the runner starts, as tmux shows it (or of `words`)."""
        return model("start_shown", list(words) or ["exec " + shlex.quote(str(self.env.bin / "claude"))])

    def agent_command(self):
        return ["exec " + shlex.quote(str(self.env.bin / "claude"))]

    def test_yes_closes_the_dead_and_the_idle_and_leaves_the_busy_one_open(self):
        idle = self.agent(7, "draft")
        dead = self.agent(7, "ready", status=["1|0|claude"])
        busy = self.agent(8, "draft", screens=[self.WORKING])
        self.env.keeper()
        code, lines = self.clean(yes=True)
        self.assertEqual(0, code)
        self.assertEqual([idle.pane, dead.pane], self.kills())
        self.assertEqual({self.session: ["8-draft"], "operator": ["keeper"]}, self.env.live())
        self.assertIn(f"pane {idle.pane} window 7-draft: alive, idle (at its prompt), claude; closed: it is idle; closing it ends "
                      "window 7-draft", self.line(lines, idle.pane))
        self.assertTrue(self.line(lines, dead.pane).startswith(f"pane {dead.pane} window 7-ready: dead, claude; closed: it is dead"))
        self.assertEqual(f"pane {busy.pane} window 8-draft: alive, busy (working), claude; left open: it is busy; busy panes are "
                         "closed only with --include-busy", self.line(lines, busy.pane))
        self.assertEqual(f"closed 2 panes and removed 0 task directories; the next run would still be refused ({busy.pane})",
                         lines[-1])

    def test_a_pane_is_checked_again_right_before_it_is_closed_and_one_at_a_time(self):
        idle = self.agent(7, "draft")
        self.env.keeper()
        self.env.update_tmux(log=[])
        self.clean(yes=True)
        self.assertEqual(["list-panes", "capture-pane", "capture-pane",           # the listing, and the second read of the screen
                          "list-panes", "capture-pane", "display-message", "kill-pane",   # right before: listed, read, probed, closed
                          "list-panes"], [call[0] for call in self.env.tmux_calls()], "and one list at the end: what is left")
        self.assertEqual([["kill-pane", "-t", idle.pane]], self.env.tmux_calls("kill-pane"), "kill-pane on the pane ID, nothing else")
        self.setUp()
        dead = self.agent(7, "draft", status=["1|0|claude"])
        self.env.keeper()
        self.env.update_tmux(log=[])
        self.clean(yes=True)
        self.assertEqual(["list-panes", "capture-pane", "list-panes", "display-message", "kill-pane", "list-panes"],
                         [call[0] for call in self.env.tmux_calls()], "a dead pane is not read again, only shown")
        self.assertEqual([dead.pane], self.kills())

    def test_include_busy_closes_the_busy_panes_too_and_never_a_window_or_a_session(self):
        panes = [self.agent(7, "draft", screens=[self.WORKING]), self.agent(7, "ready", status=["0|0|bash"]),
                 self.agent(8, "draft", status=["0|1|claude"]), self.agent(8, "ready", screens=["synthetic: loading"]),
                 self.agent(9, "draft", screens=["❯ a", "❯ b"])]
        self.env.keeper()
        code, lines = self.clean(yes=True, include_busy=True)
        self.assertEqual([agent.pane for agent in panes], self.kills())
        self.assertEqual({"operator": ["keeper"]}, self.env.live(), "the last pane took the runner's session with it")
        self.assertTrue(all("closed: it is busy, and --include-busy was given" in self.line(lines, agent.pane) for agent in panes))
        self.assertEqual(["kill-pane"] * 5, [call[0] for call in self.env.tmux_calls() if call[0].startswith("kill")],
                         "no kill-window, no kill-session")
        self.assertEqual("closed 5 panes and removed 0 task directories; the next run would start", lines[-1])

    def test_a_second_run_finds_nothing_more_to_do(self):
        self.agent(7, "draft")
        self.agent(7, "ready", status=["1|0|claude"])
        self.env.keeper()
        self.clean(yes=True)
        self.env.update_tmux(log=[])
        code, lines = self.clean(yes=True)
        self.assertEqual((0, [self.header_line(), "closed 0 panes and removed 0 task directories; the next run would start"]),
                         (code, lines))
        self.assertEqual([], self.env.tmux_calls("kill-pane"))

    def header_line(self):
        return f"Residue of earlier runs in {self.top} (tmux session {self.session} on {SOCKET}):"

    def test_a_kill_that_fails_is_a_stop_and_says_what_was_closed_before_it(self):
        first = self.agent(7, "draft")
        self.agent(7, "ready")
        self.env.keeper()
        self.env.update_tmux(fail={"kill-pane": 1})
        with self.assertRaisesRegex(pr_loop.Stop, r"^tmux kill-pane failed \(1\): fake tmux: injected failure of kill-pane$"):
            self.clean(yes=True)
        self.assertEqual([["kill-pane", "-t", first.pane]], self.env.tmux_calls("kill-pane"), "it stopped at the first failure")

    # ---- rule: the session is the runner's ------------------------------------------------------------------------------
    def test_a_pane_of_another_session_is_never_closed_whatever_else_it_matches(self):
        agent = self.agent()
        command = self.agent_command()
        others = {"the grouped twin's name": self.session + "-eink", "a longer name": self.session + "x",
                  "a shorter name": self.session[:-1], "another checkout's session": pr_loop.session_name(self.env.root / "other"),
                  "a session of the older names": "pilot-pr-7-draft-0123456789", "only the prefix": "pilot-pr-", "yours": "work"}
        panes = {name: self.env.session(session, "7-draft", self.top, command) for name, session in others.items()}
        code, lines = self.clean(yes=True, include_busy=True)
        self.assertEqual([agent.pane], self.kills(), "the one pane that is the runner's, and nothing in any other session")
        after = self.env.live()
        for name, session in others.items():
            with self.subTest(name=name):
                self.assertEqual(["7-draft"], after[session], "every other session is still there, with its window")
                self.assertEqual(session.startswith("pilot-pr-"),
                                 any(line.startswith(f"not the runner's: pane {panes[name]} ") for line in lines),
                                 "the next run would refuse because of the ones in the runner's prefix; they are listed, and left")

    # ---- rule: it was started in the checkout itself ----------------------------------------------------------------------
    def test_a_pane_started_in_another_directory_is_never_closed(self):
        agent = self.agent()
        command = self.agent_command()
        elsewhere = {"a sibling that starts the same": f"{self.top}-other", "a subdirectory": self.top / "sub",
                     "the parent": self.top.parent, "the root": "/", "a directory that is gone": self.top / "gone"}
        (self.top / "sub").mkdir()
        panes = {name: self.env.window(self.session, f"{n}-draft", path, command) for n, (name, path) in enumerate(elsewhere.items(), 8)}
        code, lines = self.clean(yes=True, include_busy=True)
        self.assertEqual([agent.pane], self.kills(), "only the pane started in the checkout itself")
        for name, pane in panes.items():
            with self.subTest(name=name):
                self.assertEqual(name in ("a subdirectory", "a directory that is gone"),
                                 any(line.startswith(f"not the runner's: pane {pane} ") for line in lines),
                                 "a pane below the checkout is in the next run's way and is listed as such; the others are not")
        self.assertEqual([f"{n}-draft" for n in range(8, 8 + len(elsewhere))], self.env.live()[self.session],
                         "the agent's window went, the others are as they were")

    def test_a_pane_that_was_started_through_a_symlink_to_the_checkout_is_the_same_directory(self):
        link = self.env.root / "link"
        link.symlink_to(self.top)
        agent = self.agent()
        pane = self.env.window(self.session, "9-draft", link, self.agent_command())
        self.clean(yes=True)
        self.assertEqual(sorted([pane, agent.pane]), sorted(self.kills()))

    # ---- rule: how it was started and what its window is called --------------------------------------------------------------
    def test_a_pane_you_opened_is_never_closed_in_the_runners_own_session_and_directory(self):
        agent = self.agent()
        command = self.agent_command()
        yours = {"a split with a command": self.env.add_split(agent.pane, ["tail", "-f", "x"], self.top),
                 "a split with the shell": self.env.add_split(agent.pane, None, self.top),
                 "a split that runs exec with a relative path": self.env.add_split(agent.pane, ["exec claude"], self.top),
                 "a window of the shell named like an agent's": self.env.window(self.session, "8-draft", self.top, None),
                 "a window with another name": self.env.window(self.session, "claude", self.top, command),
                 "a window you renamed": self.env.window(self.session, "scratch", self.top, command),
                 "a window named for no PR": self.env.window(self.session, "x-draft", self.top, command),
                 "a window of another phase": self.env.window(self.session, "9-merge", self.top, command),
                 "an agent with arguments": self.env.window(self.session, "10-draft", self.top, ["exec /bin/claude --resume"])}
        code, lines = self.clean(yes=True, include_busy=True)
        self.assertEqual([agent.pane], self.kills())
        for name, pane in yours.items():
            with self.subTest(name=name):
                self.assertTrue(any(line.startswith(f"not the runner's: pane {pane} ") for line in lines),
                                "they are in the next run's way, so they are listed, and left")
        self.assertEqual(f"closed 1 panes and removed 0 task directories; the next run would still be refused "
                         f"({', '.join(sorted(yours.values(), key=lambda name: int(name[1:])))})", lines[-1])

    def test_a_window_the_operator_renamed_after_the_run_is_not_the_runners(self):
        agent = self.agent()
        self.env.rename_window(agent.pane, "mine")
        code, lines = self.clean(yes=True)
        self.assertEqual([], self.kills())
        self.assertTrue(any(line.startswith(f"not the runner's: pane {agent.pane} ") for line in lines))

    # ---- rule: still the pane that was listed, on the server that listed it ----------------------------------------------------
    def second_listing(self, hook):
        """Something happens between the listing and the check right before the kill (the fake's hook of the second `list-panes`)."""
        self.env.update_tmux(before={"list-panes": [None, hook]})

    def test_a_pane_another_server_has_that_id_now_is_not_closed(self):
        agent = self.agent()
        self.env.keeper()
        self.second_listing({"call": "reborn", "args": [self.session, "7-draft", str(self.top), agent.pane, self.shown()]})
        old = self.env.server()
        code, lines = self.clean(yes=True, include_busy=True)
        self.assertNotEqual(old, self.env.server(), "the setup: another server")
        self.assertEqual([], self.kills(), "the ID names another pane now, with the same names, directory and command")
        self.assertIn("left open: another tmux server answers now, and the pane ID may belong to another pane",
                      self.line(lines, agent.pane))
        self.assertEqual({self.session: ["7-draft"]}, self.env.live(), "the new server's pane is alive")
        self.assertEqual(f"closed 0 panes and removed 0 task directories; the next run would still be refused ({agent.pane})",
                         lines[-1])

    def test_a_server_that_is_another_one_between_the_check_and_the_kill_is_not_acted_on_either(self):
        agent = self.agent()
        self.env.keeper()
        self.env.update_tmux(before={"display-message": [{"call": "reborn", "args": [
            self.session, "7-draft", str(self.top), agent.pane, self.shown()]}]})
        code, lines = self.clean(yes=True, include_busy=True)
        self.assertEqual([], self.kills(), "the probe that comes with kill-pane compares the server too")
        self.assertIn("left open: another tmux server answers now", self.line(lines, agent.pane))

    def test_a_pane_that_was_started_again_is_not_closed(self):
        alive = self.agent(7, "draft")
        dead = self.agent(7, "ready", status=["1|0|claude"])
        self.env.keeper()
        self.second_listing({"call": "respawn", "args": [alive.pane]})
        code, lines = self.clean(yes=True, include_busy=True)
        self.assertEqual([dead.pane], self.kills(), "the dead one is closed; the alive one was started again meanwhile")
        self.assertIn("left open: it was started again since it was listed", self.line(lines, alive.pane))
        self.setUp()
        dead = self.agent(7, "draft", status=["1|0|claude"])
        self.env.keeper()
        self.second_listing({"call": "respawn", "args": [dead.pane]})
        code, lines = self.clean(yes=True, include_busy=True)
        self.assertEqual([], self.kills(), "a pane that was dead when it was listed and runs again is not closed")
        self.assertIn("left open: it was dead when it was listed and runs again", self.line(lines, dead.pane))

    def test_a_pane_that_was_renamed_after_it_was_listed_is_left_and_one_that_vanishes_while_it_is_read_counts_as_closed(self):
        alive = self.agent(7, "draft", screens=[self.WORKING])
        self.env.keeper()
        self.second_listing({"call": "rename_window", "args": [alive.pane, "mine"]})
        code, lines = self.clean(yes=True, include_busy=True)
        self.assertEqual([], self.kills())
        self.assertIn("left open: it is not the pane that was listed any more", self.line(lines, alive.pane))
        self.setUp()
        gone = self.agent(7, "draft")
        self.env.keeper()
        self.env.update_tmux(before={"capture-pane": [None, None, {"call": "kill_pane", "args": [gone.pane]}]})
        code, lines = self.clean(yes=True)
        self.assertEqual([], self.kills(), "nothing to close: it is gone")
        self.assertIn("closed: it was already gone", self.line(lines, gone.pane))

    def test_a_pane_or_a_server_that_is_gone_counts_as_closed(self):
        for case, hook, what in (("the pane", None, "it was already gone"),
                                 ("the server", {"call": "kill_server"}, "it was already gone: no tmux server runs any more")):
            with self.subTest(case=case):
                self.setUp()
                agent = self.agent()
                self.env.keeper()
                if hook is None:
                    hook = {"call": "kill_pane", "args": [agent.pane]}
                self.second_listing(hook)
                code, lines = self.clean(yes=True)
                self.assertEqual((0, []), (code, self.kills()))
                self.assertIn(f"closed: {what}", self.line(lines, agent.pane))
                self.assertTrue(lines[-1].startswith("closed 1 panes and removed 0 task directories"))
        self.setUp()
        agent = self.agent()
        self.env.update_tmux(answers={"kill-pane": [{"rc": 1, "stderr": f"can't find pane: {agent.pane}"}]})
        code, lines = self.clean(yes=True)
        self.assertIn("closed: it is idle", self.line(lines, agent.pane), "it vanished between the probe and the kill: closed")

    def test_a_pane_that_became_busy_after_it_was_listed_is_left_open_unless_busy_ones_are_closed(self):
        for flags, closed in (({}, False), ({"include_busy": True}, True)):
            with self.subTest(flags=flags):
                self.setUp()
                agent = self.agent(screens=["❯", "❯", self.WORKING])
                self.env.keeper()
                code, lines = self.clean(yes=True, **flags)
                self.assertEqual([agent.pane] if closed else [], self.kills())
                self.assertIn("alive, busy (working)", self.line(lines, agent.pane))
                self.assertIn("closed: it is busy, and --include-busy was given" if closed else
                              "left open: it is busy; busy panes are closed only with --include-busy", self.line(lines, agent.pane))
        self.setUp()
        agent = self.agent(screens=["❯ a", "❯ a", "❯ b"])
        self.env.keeper()
        code, lines = self.clean(yes=True)
        self.assertEqual([], self.kills(), "a screen that changed since the second read is not at rest")
        self.assertIn("alive, busy (the screen is still changing)", self.line(lines, agent.pane))

    def test_a_pane_that_was_not_at_rest_when_it_was_listed_is_left_open_whatever_the_next_read_says(self):
        agent = self.agent(screens=["❯ a", "❯ b", "❯ b"])  # it changed between the two reads, and is the same in the third
        self.env.keeper()
        code, lines = self.clean(yes=True)
        self.assertEqual([], self.kills())
        self.assertIn("left open: it is busy; busy panes are closed only with --include-busy", self.line(lines, agent.pane))
        self.assertIn("alive, busy (the screen is still changing)", self.line(lines, agent.pane))

    # ---- rule: never the pane the command runs in -----------------------------------------------------------------------------
    def test_it_never_closes_the_pane_the_command_runs_in(self):
        mine = self.agent(7, "draft")
        other = self.agent(7, "ready")
        self.env.keeper()
        server = self.env.server().split("|")[0]
        with patch.dict(os.environ, {"TMUX_PANE": mine.pane, "TMUX": f"{SOCKET},{server},0"}):
            code, lines = self.clean(yes=True, include_busy=True)
        self.assertEqual([other.pane], self.kills())
        self.assertIn("left open: the command runs in this pane", self.line(lines, mine.pane))
        # the same pane ID on another tmux server is not this pane
        with patch.dict(os.environ, {"TMUX_PANE": mine.pane, "TMUX": f"{SOCKET},{int(server) + 1},0"}):
            code, lines = self.clean(yes=True, include_busy=True)
        self.assertEqual([other.pane, mine.pane], self.kills(), "TMUX names another server: control, it is closed")

    def test_a_pane_id_in_the_environment_that_cannot_be_compared_is_not_closed_either(self):
        mine = self.agent()
        self.env.keeper()
        for tmux in (None, "", "garbage", f"{SOCKET},notanumber,0"):
            with self.subTest(tmux=tmux):
                env = {"TMUX_PANE": mine.pane, **({"TMUX": tmux} if tmux is not None else {})}
                with patch.dict(os.environ, env):
                    self.clean(yes=True)
                self.assertEqual([], self.kills())

    def test_it_never_closes_a_pane_whose_process_is_above_the_command(self):
        for case, pid in (("this very process", os.getpid()), ("its parent", os.getppid())):
            with self.subTest(case=case):
                self.setUp()
                above = self.agent(7, "draft", pid=pid)
                beside = self.agent(7, "ready")
                self.env.keeper()
                code, lines = self.clean(yes=True, include_busy=True)
                self.assertEqual([beside.pane], self.kills())
                self.assertIn("left open: the command runs below this pane's process", self.line(lines, above.pane))

    def test_without_proc_only_a_dead_pane_is_closed(self):
        alive = self.agent(7, "draft")
        dead = self.agent(7, "ready", status=["1|0|claude"])
        self.env.keeper()
        with patch.object(pr_loop, "ancestors", return_value=None):
            code, lines = self.clean(yes=True, include_busy=True)
        self.assertEqual([dead.pane], self.kills())
        self.assertIn("left open: /proc cannot be read, so it cannot be told whether the command runs in it",
                      self.line(lines, alive.pane))

    def test_a_pane_whose_process_the_listing_does_not_give_is_left(self):
        self.env.update_tmux(listing=[self.env.row(self.session, "%3", pid="")])
        code, lines = self.clean(yes=True, include_busy=True)
        self.assertIn("left open: its process is unknown, so it cannot be told whether the command runs in it",
                      self.line(lines, "%3"))
        self.assertEqual([], self.kills())

    def test_the_ancestors_are_read_from_proc_and_a_pid_above_is_found(self):
        found = pr_loop.ancestors()
        self.assertIn(os.getpid(), found)
        self.assertIn(os.getppid(), found)
        self.assertNotIn(1000000000, found, "the synthetic PID of the fake's panes is no process")
        with patch.object(pr_loop, "open", side_effect=OSError("no /proc"), create=True):
            self.assertIsNone(pr_loop.ancestors())

    # ---- a grouped twin ---------------------------------------------------------------------------------------------------------
    def test_the_last_pane_of_a_session_with_a_grouped_twin_is_closed_and_the_line_says_what_goes_with_it(self):
        agent = self.agent()
        twin = self.session + "-eink"
        self.env.add_twin(self.session, twin)
        lines = self.clean()[1]
        self.assertEqual(f"pane {agent.pane} window 7-draft: alive, idle (at its prompt), claude; would close: it is idle; closing "
                         f"it ends window 7-draft and session {self.session} and the sessions grouped with it ({twin}); an attached "
                         "client is detached", self.line(lines, agent.pane))
        code, lines = self.clean(yes=True)
        self.assertEqual([agent.pane], self.kills())
        self.assertEqual({}, self.env.live(), "the session and its twin: a group shares its windows, and had none left")
        self.assertIn(f"closed: it is idle; closing it ends window 7-draft and session {self.session} and the sessions grouped "
                      f"with it ({twin}); an attached client is detached", self.line(lines, agent.pane))

    def test_a_twin_that_has_outlived_the_session_is_not_the_runners_and_is_left_alone(self):
        agent = self.agent()
        twin = self.session + "-eink"
        self.env.add_twin(self.session, twin)
        self.env.kill_session(self.session)
        code, lines = self.clean(yes=True, include_busy=True)
        self.assertEqual([], self.kills())
        self.assertEqual({twin: ["7-draft"]}, self.env.live())
        self.assertIn(f"not the runner's: pane {agent.pane} (session {twin}, window 7-draft) in {self.top}: left alone; the next "
                      "run refuses because of it", lines)

    def test_closing_what_is_not_the_last_pane_says_nothing_about_a_window_or_a_session(self):
        first = self.agent(7, "draft")
        second = self.agent(7, "ready")
        self.env.add_split(first.pane)
        lines = self.clean()[1]
        self.assertNotIn("closing it ends", self.line(lines, first.pane), "a pane of yours is left in its window")
        self.assertTrue(self.line(lines, second.pane).endswith("; closing it ends window 7-ready"),
                        "the last pane of a window ends the window, and not the session: the first window is left")


class CleanTaskDirectoryTests(CleanCase):
    """The task directories (`<checkout>/<TASK_DIR>/<nonce>/`): listed with what they say, kept unless `--remove-task-dirs`, and
    removed only when every condition holds. The case that must be removed sits beside each case that must not."""
    KEPT = "kept: task directories are removed only with --remove-task-dirs"

    def task_lines(self, lines):
        return [line for line in lines if line.startswith("task ") and not line.startswith("task directory ")]

    def test_every_task_directory_is_listed_oldest_first_with_what_it_says(self):
        old = self.task(pr=7, phase="draft", result="DRAFT-BLOCKED", age=2 * 86400 + 3 * 3600 + 100)
        mid = self.task(pr=8, phase="ready", age=3 * 3600 + 20 * 60 + 5)
        new = self.task(pr=9, phase="draft", result="READY", age=45)
        lines = self.clean()[1]
        self.assertEqual([f"task {old}: PR #7 draft, 2d 3h old, result DRAFT-BLOCKED; {self.KEPT}",
                          f"task {mid}: PR #8 ready, 3h 20m old, result none; {self.KEPT}",
                          f"task {new}: PR #9 draft, 45s old, result READY; {self.KEPT}"], self.task_lines(lines))
        self.assertEqual("would close 0 panes and remove 0 task directories; the next run would start", lines[-1])
        lines = self.clean(remove_task_dirs=True)[1]
        why = "no pane of the runner is left and it holds only its task and result"
        self.assertEqual([f"task {old}: PR #7 draft, 2d 3h old, result DRAFT-BLOCKED; would remove: {why}",
                          f"task {mid}: PR #8 ready, 3h 20m old, result none; would remove: {why}",
                          f"task {new}: PR #9 draft, 45s old, result READY; would remove: {why}"], self.task_lines(lines))
        self.assertEqual("would close 0 panes and remove 3 task directories; the next run would start", lines[-1])
        self.assertEqual(3, len(list((self.top / pr_loop.TASK_DIR).iterdir())), "a listing removes nothing")

    def test_the_age_is_told_in_the_unit_that_fits_it(self):
        for seconds, text in ((0, "0s"), (59.9, "59s"), (60, "1m"), (3599, "59m"), (3600, "1h 0m"), (86399, "23h 59m"),
                              (86400, "1d 0h"), (10 * 86400 + 7 * 3600 + 59, "10d 7h"), (-5, "0s")):
            with self.subTest(seconds=seconds):
                self.assertEqual(text, pr_loop.age_text(seconds))

    def test_a_task_directory_is_removed_when_the_lock_is_free_and_no_pane_of_the_runner_is_left(self):
        self.agent(7, "draft", status=["1|0|claude"])
        self.env.keeper()
        nonce = self.task(result="DRAFT-BLOCKED")
        self.assertTrue(self.task_dir(nonce).is_dir())
        code, lines = self.clean(yes=True, remove_task_dirs=True)
        self.assertEqual(0, code)
        self.assertFalse(self.task_dir(nonce).exists(), "task.json, result.json and the directory are gone")
        self.assertTrue((self.top / pr_loop.TASK_DIR).is_dir(), "the task directory itself is not")
        self.assertIn(f"task {nonce}: PR #7 draft, 3h 20m old, result DRAFT-BLOCKED; removed: no pane of the runner is left and it "
                      "holds only its task and result", lines)
        self.assertEqual("closed 1 panes and removed 1 task directories; the next run would start", lines[-1])
        code, lines = self.clean(yes=True, remove_task_dirs=True)
        self.assertEqual("closed 0 panes and removed 0 task directories; the next run would start", lines[-1], "and again: nothing")

    def test_without_remove_task_dirs_a_run_that_acts_keeps_them(self):
        self.agent(7, "draft", status=["1|0|claude"])
        nonce = self.task(result="DRAFT-BLOCKED")
        code, lines = self.clean(yes=True)
        self.assertTrue(self.task_dir(nonce).is_dir())
        self.assertIn(f"task {nonce}: PR #7 draft, 3h 20m old, result DRAFT-BLOCKED; {self.KEPT}", lines)

    def test_a_task_directory_of_a_checkout_whose_lock_is_held_is_never_removed(self):
        nonce = self.task(result="DRAFT-BLOCKED")
        self.agent(7, "draft", status=["1|0|claude"])
        lock = self.top / ".git" / pr_loop.LOCK_NAME
        held = pr_loop.lock_checkout(self.top, lock)
        try:
            self.env.update_tmux(log=[])
            with self.assertRaisesRegex(pr_loop.Stop, f"^another pr_loop runner is using the checkout {re.escape(str(self.top))} "
                                                      f"\\(lock {re.escape(str(lock))}\\); wait for it to finish or stop it$"):
                self.clean(yes=True, remove_task_dirs=True)
            self.assertTrue(self.task_dir(nonce).is_dir(), "nothing was removed")
            self.assertEqual([], self.env.tmux_calls(), "and tmux was not even asked: the lock comes first")
            lines = self.clean(remove_task_dirs=True)[1]  # a listing says so, and does not take it
            self.assertIn(f"task {nonce}: PR #7 draft, 3h 20m old, result DRAFT-BLOCKED; kept: the checkout's lock is not free: "
                          "held by a running runner", lines)
        finally:
            os.close(held)
        self.clean(yes=True, remove_task_dirs=True)  # control: free, it is removed
        self.assertFalse(self.task_dir(nonce).exists())

    def test_the_lock_is_held_for_the_whole_run_that_acts_and_given_back_after_it(self):
        lock = self.top / ".git" / pr_loop.LOCK_NAME
        self.agent(7, "draft")
        self.env.update_tmux(lock_path=str(lock))  # the fake tmux tries to take the lock when a pane is made
        seen = []
        real = pr_loop.close_pane
        with patch.object(pr_loop, "close_pane", lambda *a: seen.append(pr_loop.lock_state(lock)) or real(*a)):
            self.clean(yes=True)
        self.assertEqual(["held by a running runner"], seen, "while a pane is closed, another runner would be refused")
        self.assertIsNone(pr_loop.lock_state(lock), "and when it has finished, it is free")
        self.assertEqual(0o600, lock.stat().st_mode & 0o777)

    def test_a_pane_of_the_runner_that_is_left_keeps_every_task_directory(self):
        busy = self.agent(7, "draft", screens=[self.WORKING])
        nonce = self.task()
        lines = self.clean(yes=True, remove_task_dirs=True)[1]
        self.assertTrue(self.task_dir(nonce).is_dir())
        self.assertIn(f"task {nonce}: PR #7 draft, 3h 20m old, result none; kept: a pane of the runner is left ({busy.pane}) and its "
                      "agent may still write there", lines)
        self.assertEqual(f"closed 0 panes and removed 0 task directories; the next run would still be refused ({busy.pane})",
                         lines[-1])
        self.assertIn("kept: a pane of the runner is left", self.clean(remove_task_dirs=True)[1][-2], "a listing says it too")
        code, lines = self.clean(yes=True, remove_task_dirs=True, include_busy=True)
        self.assertFalse(self.task_dir(nonce).exists(), "closed with --include-busy: nothing is left, and it is removed")

    def test_a_pane_that_is_in_the_way_and_not_the_runners_keeps_every_task_directory(self):
        agent = self.agent(7, "draft", status=["1|0|claude"])
        split = self.env.add_split(agent.pane)
        nonce = self.task()
        lines = self.clean(yes=True, remove_task_dirs=True)[1]
        self.assertTrue(self.task_dir(nonce).is_dir())
        self.assertIn(f"kept: a pane of the runner is left ({split}) and its agent may still write there", self.task_lines(lines)[0])

    def test_a_live_pane_of_the_runner_that_moved_out_of_the_checkout_still_keeps_them(self):
        agent = self.agent(7, "draft", screens=[self.WORKING])
        self.env.set_pane(agent.pane, path="/tmp")  # it is not in the checkout now: not in the next run's way, still the runner's
        nonce = self.task()
        lines = self.clean(yes=True, remove_task_dirs=True)[1]
        self.assertTrue(self.task_dir(nonce).is_dir())
        self.assertIn(f"a pane of the runner is left ({agent.pane})", self.task_lines(lines)[0])
        self.assertEqual("closed 0 panes and removed 0 task directories; the next run would start", lines[-1],
                         "though the next run would not be refused because of it")

    def test_a_symlinked_task_directory_is_not_followed(self):
        real = self.env.root / "elsewhere"
        (real / ("0" * 32)).mkdir(parents=True)
        (real / ("0" * 32) / "task.json").write_text(json.dumps(dict(version=1, repo="a/b", pr=7, phase="draft", nonce="0" * 32,
                                                                      start_head=HEAD)))
        shutil.rmtree(self.top / pr_loop.TASK_DIR, ignore_errors=True)
        (self.top / pr_loop.TASK_DIR).symlink_to(real)
        lines = self.clean(yes=True, remove_task_dirs=True)[1]
        self.assertTrue((real / ("0" * 32) / "task.json").is_file(), "what the link points to is untouched")
        (said,) = [line for line in lines if line.startswith("task directory")]
        self.assertRegex(said, rf"^task directory {re.escape(str(self.top / pr_loop.TASK_DIR))}: (Too many levels of symbolic links|"
                               "Not a directory): left alone; nothing in it is listed or removed$")
        self.assertEqual([], self.task_lines(lines))
        self.assertEqual("closed 0 panes and removed 0 task directories; the next run would still be refused (uncommitted work)",
                         lines[-1], "(git does not ignore a link named like the directory the exclude file names)")

    def test_a_task_directory_that_is_a_symlink_is_not_followed_or_removed(self):
        real = self.env.root / "elsewhere"
        real.mkdir()
        (real / "task.json").write_text(json.dumps(dict(version=1, repo="a/b", pr=7, phase="draft", nonce="1" * 32, start_head=HEAD)))
        base = self.top / pr_loop.TASK_DIR
        base.mkdir()
        (base / ("1" * 32)).symlink_to(real)
        lines = self.clean(yes=True, remove_task_dirs=True)[1]
        self.assertTrue((real / "task.json").is_file())
        self.assertTrue((base / ("1" * 32)).is_symlink(), "the link itself stays")
        self.assertEqual(1, len(self.task_lines(lines)))
        self.assertIn("kept: it is not a real directory (", self.task_lines(lines)[0])

    def test_a_task_directory_that_holds_anything_else_is_kept_whole(self):
        for case, make in (("a stray temporary file of an interrupted write", lambda d: (d / "tmpab12cd34").write_text("x")),
                           ("a subdirectory", lambda d: (d / "sub").mkdir()),
                           ("a result that is a symlink", lambda d: (d / "result.json").symlink_to("task.json")),
                           ("a result that is a directory", lambda d: (d / "result.json").mkdir()),
                           ("a hidden file", lambda d: (d / ".x").write_text("x"))):
            with self.subTest(case=case):
                self.setUp()
                nonce = self.task()
                directory = self.task_dir(nonce)
                make(directory)
                before = sorted(path.name for path in directory.iterdir())
                lines = self.clean(yes=True, remove_task_dirs=True)[1]
                self.assertEqual(before, sorted(path.name for path in directory.iterdir()), "not a file of it was removed")
                self.assertRegex(self.task_lines(lines)[0], r"; kept: (it holds other files \(|result\.json is not a regular file)")
                self.assertTrue((directory / "task.json").is_file())

    def test_a_task_directory_whose_task_is_not_its_own_is_kept(self):
        good = dict(version=1, repo="a/b", pr=7, phase="draft", nonce="2" * 32, start_head=HEAD)
        not_its_own = ("task.json is not this directory's task", "its task.json is not this directory's task")
        unreadable = ("task.json unreadable", "its task.json cannot be read (")
        for case, content, (subject, reason) in (
                ("another nonce", json.dumps(dict(good, nonce="3" * 32)), not_its_own), ("a list", "[]", not_its_own),
                ("a PR that is a string", json.dumps(dict(good, pr="7")), not_its_own),
                ("a PR that is a bool", json.dumps(dict(good, pr=True)), not_its_own),
                ("a phase it does not know", json.dumps(dict(good, phase="merge")), not_its_own),
                ("too long", json.dumps(dict(good, reason="x" * 5000)), not_its_own),
                ("not JSON", "{", unreadable), ("empty", "", unreadable)):
            with self.subTest(case=case):
                self.setUp()
                directory = self.top / pr_loop.TASK_DIR / ("2" * 32)
                directory.mkdir(parents=True)
                (directory / "task.json").write_text(content)
                (line,) = self.task_lines(self.clean(yes=True, remove_task_dirs=True)[1])
                self.assertTrue((directory / "task.json").is_file(), "kept")
                self.assertTrue(line.startswith(f"task {'2' * 32}: {subject}, "), line)
                self.assertIn(f"; kept: {reason}", line)
        self.setUp()
        directory = self.top / pr_loop.TASK_DIR / ("2" * 32)
        directory.mkdir(parents=True)
        (line,) = self.task_lines(self.clean(yes=True, remove_task_dirs=True)[1])
        self.assertTrue(directory.is_dir(), "no task.json at all: kept")
        self.assertIn(f"task {'2' * 32}: no task.json, ", line)
        self.assertIn("; kept: it has no task.json", line)
        (directory / "task.json").write_text(json.dumps(good))
        (line,) = self.task_lines(self.clean(yes=True, remove_task_dirs=True)[1])
        self.assertFalse(directory.exists(), "control: its own task, and nothing else in it: removed")
        self.assertIn("; removed:", line)

    def test_a_result_that_cannot_be_read_does_not_keep_the_directory_and_is_reported(self):
        nonce = self.task(result="DRAFT-BLOCKED")
        (self.task_dir(nonce) / "result.json").write_text("{")
        self.assertIn("result unreadable;", self.task_lines(self.clean()[1])[0])
        (self.task_dir(nonce) / "result.json").write_text(json.dumps({"outcome": "NOT-AN-OUTCOME"}))
        self.assertIn("result unreadable;", self.task_lines(self.clean()[1])[0])
        self.clean(yes=True, remove_task_dirs=True)
        self.assertFalse(self.task_dir(nonce).exists())

    def test_a_directory_that_is_not_the_users_is_kept(self):
        nonce = self.task()
        with patch.object(pr_loop.os, "getuid", return_value=os.getuid() + 1):
            lines = self.clean(yes=True, remove_task_dirs=True)[1]
        self.assertTrue(self.task_dir(nonce).is_dir())
        self.assertIn("kept: it is not owned by this user", self.task_lines(lines)[0])

    def test_names_that_are_not_nonces_and_the_evidence_of_the_other_skills_are_never_touched(self):
        base = self.top / pr_loop.TASK_DIR
        sentinels = {"0ld/task.json": "{}\n", "0ld/result.json": "{}\n", "tmux-ai-pr-x/task.json": "{}\n", "README": "x\n",
                     "A" * 32 + "/task.json": "{}\n", "0" * 31 + "/task.json": "{}\n", "0" * 33 + "/task.json": "{}\n"}
        for name, text in sentinels.items():
            (base / name).parent.mkdir(parents=True, exist_ok=True)
            (base / name).write_text(text)
        for name in (".pr-ready/7/evidence.json", ".tmux-ai-pr/tmux-ai-pr-1/task.json"):
            (self.top / name).parent.mkdir(parents=True, exist_ok=True)
            (self.top / name).write_text("{}\n")
        nonce = self.task()
        lines = self.clean(yes=True, remove_task_dirs=True)[1]
        self.assertEqual([nonce], [line.split()[1].rstrip(":") for line in self.task_lines(lines)], "only a nonce is listed")
        for name, text in sentinels.items():
            self.assertEqual(text, (base / name).read_text(), name)
        self.assertTrue((self.top / ".pr-ready/7/evidence.json").is_file())
        self.assertTrue((self.top / ".tmux-ai-pr/tmux-ai-pr-1/task.json").is_file())
        self.assertFalse(self.task_dir(nonce).exists(), "and the one that is, is removed")

    def test_the_removal_is_two_unlinks_through_the_directory_and_one_rmdir_and_never_a_tree(self):
        nonce = self.task(result="DRAFT-BLOCKED")
        calls = []
        real_unlink, real_rmdir = os.unlink, os.rmdir
        with patch.object(pr_loop.os, "unlink", lambda *a, **k: calls.append(("unlink", a[0], sorted(k))) or real_unlink(*a, **k)), \
             patch.object(pr_loop.os, "rmdir", lambda *a, **k: calls.append(("rmdir", a[0], sorted(k))) or real_rmdir(*a, **k)):
            self.clean(yes=True, remove_task_dirs=True)
        self.assertEqual([("unlink", "result.json", ["dir_fd"]), ("unlink", "task.json", ["dir_fd"]), ("rmdir", nonce, ["dir_fd"])],
                         calls, "the result first: an interrupted removal leaves a task that is still a task")

    def test_removing_a_task_directory_does_not_follow_a_symlink(self):
        real = self.env.root / "elsewhere"
        real.mkdir()
        (real / "task.json").write_text(json.dumps(dict(version=1, repo="a/b", pr=7, phase="draft", nonce="1" * 32, start_head=HEAD)))
        base = self.top / pr_loop.TASK_DIR
        base.mkdir()
        (base / ("1" * 32)).symlink_to(real)
        fd = os.open(base, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, fd)
        self.assertRegex(pr_loop.remove_task_directory(fd, "1" * 32), r"^it cannot be opened as a directory \(")
        self.assertTrue((real / "task.json").is_file(), "what the link points to is untouched, though it is a task of its own")
        self.assertTrue((base / ("1" * 32)).is_symlink())

    def test_a_directory_that_changed_since_it_was_listed_is_read_again_before_it_is_removed(self):
        nonce = self.task()
        base = os.open(self.top / pr_loop.TASK_DIR, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, base)
        (self.task_dir(nonce) / "tmpab12").write_text("x")
        self.assertEqual("it holds other files (tmpab12)", pr_loop.remove_task_directory(base, nonce))
        self.assertTrue((self.task_dir(nonce) / "task.json").is_file())
        (self.task_dir(nonce) / "tmpab12").unlink()
        self.assertIsNone(pr_loop.remove_task_directory(base, nonce), "control: nothing else in it")
        self.assertRegex(pr_loop.remove_task_directory(base, nonce), r"^it cannot be opened as a directory \(")


class CleanCheckoutTests(CleanCase):
    """It never changes the git checkout, however the checkout stands: behind origin (a run fast-forwards it), on another branch (a
    run switches it), with uncommitted work or a git operation in progress (a run refuses). All it does is read them out."""

    def residue(self):
        self.agent(7, "draft")
        self.agent(7, "ready", status=["1|0|claude"])
        self.env.keeper()
        self.task(result="DRAFT-BLOCKED")

    def acting_leaves_alone(self, prepare):
        """Run `--clean --yes --remove-task-dirs` on a checkout `prepare` put in some state: HEAD, the refs, the index, the exclude
        file and every file of the work tree are as they were, but for what it is there to do (the lock file it takes, the panes it
        closes, the task directories it removes)."""
        self.residue()
        prepare()
        before = self.state()
        code, lines = self.clean(yes=True, remove_task_dirs=True)
        after = self.state()
        self.assertEqual(0, code)
        for key in ("head", "symbolic", "refs", "index", "exclude", "fetch_head"):
            self.assertEqual(before[key], after[key], key)
        outside = lambda files: {name: sha for name, sha in files.items() if not name.startswith(pr_loop.TASK_DIR)}
        self.assertEqual(outside(before["files"]), outside(after["files"]))
        self.assertEqual({}, {name: sha for name, sha in after["files"].items() if name.startswith(pr_loop.TASK_DIR + "/")},
                         "the task directory was removed: that is the one thing it deletes")
        self.assertTrue(any(line.startswith("pane %1 ") and "closed" in line for line in lines))
        return lines

    def test_a_checkout_behind_origin_is_not_fast_forwarded(self):
        self.acting_leaves_alone(self.env.advance_remote)
        self.assertNotEqual(self.env.remote_head, self.env.git("rev-parse", "HEAD", cwd=self.top), "origin moved on, the checkout did not")
        self.assertNotEqual(self.env.remote_head, self.env.git("rev-parse", "origin/main", cwd=self.top), "and nothing was fetched")

    def test_a_checkout_on_another_branch_is_not_switched(self):
        self.acting_leaves_alone(lambda: self.env.git("switch", "-q", "-c", "feature", cwd=self.top))
        self.assertEqual("refs/heads/feature", self.env.git("symbolic-ref", "HEAD", cwd=self.top))

    def test_a_dirty_checkout_is_neither_stashed_nor_cleaned(self):
        def dirty():
            (self.top / "stray.txt").write_text("mine\n")
            (self.top / "README.txt").write_text("changed\n")
        lines = self.acting_leaves_alone(dirty)
        self.assertEqual("mine\n", (self.top / "stray.txt").read_text())
        self.assertEqual("changed\n", (self.top / "README.txt").read_text())
        self.assertEqual("", self.env.git("stash", "list", cwd=self.top))
        self.assertIn("(uncommitted work)", lines[-1])

    def test_a_git_operation_in_progress_is_left_as_it_is(self):
        marker = Path(self.env.git("rev-parse", "--path-format=absolute", "--git-path", "MERGE_HEAD", cwd=self.top))
        lines = self.acting_leaves_alone(lambda: marker.write_text("x\n"))
        self.assertTrue(marker.is_file())
        self.assertIn("(a git operation in progress)", lines[-1])

    def test_a_checkout_that_is_not_a_clone_of_the_repository_is_not_asked_about_its_origin(self):
        self.env.git("remote", "set-url", "origin", "https://github.com/other/thing.git", cwd=self.top)
        self.agent()
        code, lines = self.clean()
        self.assertEqual(0, code)
        self.assertTrue(any(line.startswith("pane %1 ") for line in lines))


class CleanProgramTests(unittest.TestCase):
    """`python3 scripts/pr_loop.py --clean ...` as a real process (kjelly/pilot#442): the command line, the exit status and what is
    printed, from the entry point to the last line. Time is real (the second read of a screen waits a second); tmux, gh and the
    agents are the fakes."""
    SCRIPT = ROOT / "scripts" / "pr_loop.py"
    CLEAN = "--clean"

    def setUp(self):
        self.env = FakeEnv(self)
        self.top = self.env.checkout
        self.session = pr_loop.session_name(self.top)
        self.where = SimpleNamespace(path=self.top, session=self.session)
        with (self.top / ".git/info/exclude").open("a") as stream:
            stream.write(f"/.pr-ready/\n/{pr_loop.TASK_DIR}/\n")

    def agent(self, number=7, phase="draft", **pane):
        """An agent the way a run starts it, scripted by `pane`; its ID."""
        with patch.object(pr_loop, "tell"):
            found = pr_loop.Agent("claude", self.where, number, phase)
        if pane:
            self.env.set_pane(found.pane, **pane)
        return found.pane

    def run_program(self, *argv, cwd=None, env=None):
        return subprocess.run([sys.executable, "-B", str(self.SCRIPT), *argv], capture_output=True, text=True, timeout=120,
                              cwd=cwd or self.top, env=env)

    def kills(self):
        return [call[2] for call in self.env.tmux_calls("kill-pane")]

    def header(self):
        return f"Residue of earlier runs in {self.top} (tmux session {self.session} on {SOCKET}):"

    def test_the_listing_is_printed_to_stdout_with_status_0_and_nothing_is_changed(self):
        idle = self.agent(7, "draft")
        dead = self.agent(7, "ready", status=["1|0|claude"])
        self.env.keeper()
        self.env.update_tmux(log=[])
        before = (sha256_of(self.top / ".git/index"), self.env.live(), (self.top / ".git" / pr_loop.LOCK_NAME).exists())
        proc = self.run_program(self.CLEAN, "--repo", "acme/demo")
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertEqual("", proc.stderr)
        lines = proc.stdout.splitlines()
        self.assertEqual(self.header(), lines[0])
        self.assertEqual(f"pane {idle} window 7-draft: alive, idle (at its prompt), claude; would close: it is idle; closing it ends "
                         "window 7-draft", lines[1])
        self.assertEqual(f"pane {dead} window 7-ready: dead, claude; would close: it is dead; closing it ends window 7-ready",
                         lines[3])
        self.assertEqual("would close 2 panes and remove 0 task directories; the next run would start", lines[-1])
        self.assertEqual([], self.env.gh_calls(), "no gh call")
        self.assertEqual({"list-panes", "capture-pane"}, {call[0] for call in self.env.tmux_calls()})
        self.assertEqual(before, (sha256_of(self.top / ".git/index"), self.env.live(),
                                  (self.top / ".git" / pr_loop.LOCK_NAME).exists()))

    def test_yes_closes_what_the_listing_said_and_a_second_run_finds_nothing(self):
        idle = self.agent(7, "draft")
        busy = self.agent(7, "ready", screens=["synthetic\n❯\nWorking (3s • esc to interrupt)"])
        self.env.keeper()
        proc = self.run_program(self.CLEAN, "--yes")
        self.assertEqual((0, ""), (proc.returncode, proc.stderr))
        self.assertEqual([idle], self.kills())
        self.assertEqual(f"closed 1 panes and removed 0 task directories; the next run would still be refused ({busy})",
                         proc.stdout.splitlines()[-1])
        proc = self.run_program(self.CLEAN, "--yes", "--include-busy")
        self.assertEqual([idle, busy], self.kills())
        proc = self.run_program(self.CLEAN, "--yes", "--include-busy")
        self.assertEqual((0, [self.header(), "closed 0 panes and removed 0 task directories; the next run would start"]),
                         (proc.returncode, proc.stdout.splitlines()))
        self.assertEqual([idle, busy], self.kills())

    def test_a_wrong_command_line_is_status_2_and_changes_and_asks_nothing(self):
        self.agent()
        self.env.update_tmux(log=[])
        for argv, message in ((["--clean", "7"], "--clean takes no PR numbers and no --dry-run: without --yes it only lists"),
                              (["--clean", "--dry-run"], "--clean takes no PR numbers and no --dry-run: without --yes it only lists"),
                              (["7", "--yes"], "--yes, --include-busy and --remove-task-dirs go with --clean"),
                              (["7", "--include-busy"], "--yes, --include-busy and --remove-task-dirs go with --clean"),
                              (["7", "--remove-task-dirs"], "--yes, --include-busy and --remove-task-dirs go with --clean"),
                              (["--yes"], "the following arguments are required: PR"),
                              ([], "the following arguments are required: PR"),
                              (["--clean", "--yes", "--phase-timeout", "-1"], None)):
            with self.subTest(argv=argv):
                proc = self.run_program(*argv)
                if message is None:
                    self.assertEqual(2, proc.returncode, "an option that is not valid is still checked")
                    continue
                self.assertEqual((2, ""), (proc.returncode, proc.stdout))
                self.assertTrue(proc.stderr.rstrip().endswith(f"pr_loop.py: error: {message}"), proc.stderr)
        self.assertEqual([], self.env.tmux_calls(), "nothing was asked of tmux, and nothing of GitHub")
        self.assertEqual([], self.env.gh_calls())

    def test_the_existing_command_lines_are_still_checked_the_way_they_were(self):
        for argv, message in ((["7", "7"], "PR numbers must be positive and unique, and --max-actions must be positive"),
                              (["0"], "PR numbers must be positive and unique, and --max-actions must be positive"),
                              (["7", "--draft-command", " "], "agent commands must be nonempty single lines")):
            with self.subTest(argv=argv):
                proc = self.run_program(*argv)
                self.assertEqual(2, proc.returncode)
                self.assertTrue(proc.stderr.rstrip().endswith(f"pr_loop.py: error: {message}"), proc.stderr)

    def test_a_directory_that_is_not_a_work_tree_or_not_its_root_is_a_refusal_with_status_1(self):
        plain = self.env.root / "plain"
        plain.mkdir()
        with patch.dict(os.environ, GIT_CEILING_DIRECTORIES=str(self.env.root)):
            proc = self.run_program(self.CLEAN, "--repo", "acme/demo", cwd=plain)
            self.assertEqual((1, ""), (proc.returncode, proc.stdout))
            self.assertEqual("pr-loop: the current directory is not inside a git work tree; start the runner in a checkout of "
                             "github.com/acme/demo or pass --checkout DIR\n", proc.stderr)
            below = self.top / "sub"
            below.mkdir()
            proc = self.run_program(self.CLEAN, "--checkout", str(below), cwd=plain)
            self.assertEqual((1, f"pr-loop: --checkout {below} is not the root of its git work tree {self.top}; pass {self.top}\n"),
                             (proc.returncode, proc.stderr))
            proc = self.run_program(self.CLEAN, "--checkout", str(self.top), cwd=plain)
            self.assertEqual(0, proc.returncode, "control: the checkout named, from another directory")
        self.assertEqual([], self.env.gh_calls())

    def test_a_directory_below_the_root_cleans_the_checkout_it_is_in(self):
        self.agent()
        (self.top / "sub").mkdir()
        proc = self.run_program(self.CLEAN, cwd=self.top / "sub")
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertEqual(self.header(), proc.stdout.splitlines()[0])

    def test_a_held_lock_refuses_the_run_that_acts_and_is_reported_by_the_one_that_lists(self):
        idle = self.agent()
        lock = self.top / ".git" / pr_loop.LOCK_NAME
        held = pr_loop.lock_checkout(self.top, lock)
        try:
            self.env.update_tmux(log=[])
            proc = self.run_program(self.CLEAN, "--yes", "--remove-task-dirs")
            self.assertEqual((1, "", f"pr-loop: another pr_loop runner is using the checkout {self.top} (lock {lock}); wait for it "
                                     "to finish or stop it\n"), (proc.returncode, proc.stdout, proc.stderr))
            self.assertEqual([], self.env.tmux_calls(), "it was refused before tmux was asked anything")
            proc = self.run_program(self.CLEAN)
            self.assertEqual(0, proc.returncode)
            self.assertIn(f"lock {lock}: held by a running runner; --clean --yes would be refused", proc.stdout.splitlines())
            self.assertEqual([], self.kills())
        finally:
            os.close(held)
        proc = self.run_program(self.CLEAN, "--yes")
        self.assertEqual(0, proc.returncode)
        self.assertEqual([idle], self.kills(), "control: the lock is free")

    def test_it_never_closes_the_pane_it_was_started_in_or_one_above_it(self):
        mine = self.agent(7, "draft")
        above = self.agent(7, "ready", pid=os.getpid())  # the process of this pane is above the runner's: this test's own
        other = self.agent(8, "draft")
        self.env.keeper()
        server = self.env.server().split("|")[0]
        env = dict(os.environ, TMUX_PANE=mine, TMUX=f"{SOCKET},{server},0")
        proc = self.run_program(self.CLEAN, "--yes", "--include-busy", env=env)
        self.assertEqual(0, proc.returncode, proc.stderr)
        self.assertEqual([other], self.kills())
        self.assertIn("left open: the command runs in this pane", [line for line in proc.stdout.splitlines()
                                                                  if line.startswith(f"pane {mine} ")][0])
        self.assertIn("left open: the command runs below this pane's process", [line for line in proc.stdout.splitlines()
                                                                                if line.startswith(f"pane {above} ")][0])

    def test_an_interrupt_says_what_was_reported_and_is_status_130(self):
        argv = ["pr_loop.py", self.CLEAN, "--yes", "--checkout", str(self.top)]
        errors = io.StringIO()
        with patch.object(sys, "argv", argv), patch.object(pr_loop.Clean, "run", side_effect=KeyboardInterrupt), \
             contextlib.redirect_stderr(errors):
            self.assertEqual(130, pr_loop.main())
        self.assertEqual("Interrupted; the lines above say what was closed or removed so far.\n", errors.getvalue())

    def test_the_help_names_the_four_flags(self):
        done = subprocess.run([sys.executable, "-B", str(self.SCRIPT), "--help"], capture_output=True, text=True, timeout=60)
        text = " ".join(done.stdout.split())
        for flag in ("--clean", "--yes", "--include-busy", "--remove-task-dirs"):
            self.assertIn(flag, text)
        self.assertIn("[PR ...]", text)
        self.assertIn("changes nothing, reads no GitHub and takes no PR numbers", text)

    # ---- the scenario of kjelly/pilot#442: a stopped run, the refusal, the listing, the cleaning, the next run -------------
    def runner(self, *extra):
        argv = [sys.executable, "-B", str(self.SCRIPT), "7", "--repo", "acme/demo", "--poll-interval", "0.01",
                "--startup-timeout", "2", *extra]
        return subprocess.run(argv, capture_output=True, text=True, timeout=60, cwd=self.top)

    def test_a_stopped_run_is_refused_listed_and_cleaned_and_then_the_runner_starts_again(self):
        self.env.set_pane("%1", enter=[{"result": {"outcome": "DRAFT-BLOCKED", "reason": "synthetic blocker"}}])
        first = self.runner()
        self.assertEqual(1, first.returncode, first.stdout + first.stderr)
        self.assertIn("DRAFT-BLOCKED", first.stderr)
        self.assertEqual({self.session: ["7-draft"]}, self.env.live(), "the run left its agent")
        refusal = (f"pr-loop: agent pane %1 (session {self.session}) is still running in {self.top}; inspect and close it before "
                   f"starting the runner again {CLEAN_POINTER}\n")
        again = self.runner()
        self.assertEqual((1, "", refusal), (again.returncode, again.stdout, again.stderr), "the same command is refused")
        self.env.update_tmux(log=[])
        listing = self.run_program(self.CLEAN)
        self.assertEqual((0, ""), (listing.returncode, listing.stderr))
        lines = listing.stdout.splitlines()
        self.assertEqual(self.header(), lines[0])
        self.assertEqual(f"pane %1 window 7-draft: alive, idle (at its prompt), claude; would close: it is idle; closing it ends "
                         f"window 7-draft and session {self.session}; an attached client is detached", lines[1])
        self.assertRegex(lines[3], r"^task [0-9a-f]{32}: PR #7 draft, [0-9]+s old, result DRAFT-BLOCKED; kept: task directories "
                                   r"are removed only with --remove-task-dirs$")
        self.assertEqual("would close 1 panes and remove 0 task directories; the next run would start", lines[-1])
        self.assertEqual([], self.kills(), "the listing closed nothing")
        done = self.run_program(self.CLEAN, "--yes", "--remove-task-dirs")
        self.assertEqual((0, ""), (done.returncode, done.stderr))
        self.assertEqual([["kill-pane", "-t", "%1"]], self.env.tmux_calls("kill-pane"))
        self.assertEqual({}, self.env.live())
        self.assertEqual([], list((self.top / pr_loop.TASK_DIR).iterdir()), "and the finished run's task directory with it")
        self.assertEqual("closed 1 panes and removed 1 task directories; the next run would start", done.stdout.splitlines()[-1])
        self.env.set_pane("%1", enter=[{"result": {"outcome": "DRAFT-BLOCKED", "reason": "synthetic blocker"}}])
        second = self.runner()
        self.assertEqual(1, second.returncode, second.stdout + second.stderr)
        self.assertIn(f"PR #7 draft agent: %1 in window 7-draft of tmux session {self.session}", second.stdout)
        self.assertIn("DRAFT-BLOCKED", second.stderr, "the runner started again and went as far as the first one")


class CleanAgreesWithTheRefusalTests(CleanCase):
    """ONE predicate says which panes are in the way of the next run (`blocking_panes`): the startup refusal and the listing's
    summary both read it (AGENTS.md section 5.7), so they agree for every row, and a row that one of them thinks is in the way
    and the other does not would be a pane `--clean` reports as fixed that the runner still refuses."""

    def test_they_agree_for_every_kind_of_row(self):
        session, twin = self.session, self.session + "-eink"
        row = self.env.row
        for case, rows, in_the_way in (
                ("a live pane of the runner's", [row(session, "%3")], ["%3"]),
                ("a dead pane of the runner's", [row(session, "%3", dead=True)], []),
                ("a live pane below the checkout", [row(session, "%3", path=self.top / "sub")], ["%3"]),
                ("a live pane in a sibling", [row(session, "%3", path=f"{self.top}-other")], []),
                ("a live pane that moved out", [row(session, "%3", path="/tmp")], []),
                ("a pane of the older names", [row("pilot-pr-7-draft-0123456789", "%3")], ["%3"]),
                ("a pane of another checkout's session", [row(pr_loop.session_name(self.env.root / "other"), "%3")], ["%3"]),
                ("a pane of your own session", [row("work", "%3")], []),
                ("the twin alone", [row(twin, "%3")], ["%3"]),
                ("the pane and its twin", [row(session, "%3"), row(twin, "%3")], ["%3"]),
                ("the pane of a session of yours, and its twin of the runner's prefix", [row("work", "%3"), row(session, "%3")], ["%3"]),
                ("a split of yours in the runner's window", [row(session, "%3"), row(session, "%4", window="7-draft",
                                                                                         start_command="")], ["%3", "%4"]),
                ("two panes, one dead", [row(session, "%3", dead=True), row(session, "%4")], ["%4"]),
                ("no pane", [], [])):
            with self.subTest(case=case):
                self.env.update_tmux(listing=rows)
                try:
                    pr_loop.check_panes(self.top)
                    refusal = None
                except pr_loop.Stop as exc:
                    refusal = str(exc)
                lines = self.clean()[1]
                self.assertEqual(in_the_way, [pane.pane for pane in pr_loop.blocking_panes(self.top, pr_loop.list_panes()[0])])
                self.assertEqual(bool(in_the_way), refusal is not None, refusal)
                if in_the_way:
                    self.assertIn(f"agent pane {in_the_way[0]} ", refusal)
                    self.assertTrue(lines[-1].endswith(f"the next run would still be refused ({', '.join(in_the_way)})"), lines[-1])
                else:
                    self.assertTrue(lines[-1].endswith("the next run would start"), lines[-1])

    def test_the_two_read_the_one_predicate(self):
        source = ast.parse((ROOT / "scripts" / "pr_loop.py").read_text())
        users = {function.name for function in ast.walk(source) if isinstance(function, ast.FunctionDef)
                 and any(isinstance(node, ast.Name) and node.id == "blocking_panes" for node in ast.walk(function))}
        self.assertTrue({"check_panes", "left"} <= users, users)
        spelled = {function.name for function in ast.walk(source) if isinstance(function, ast.FunctionDef)
                   and any(isinstance(node, ast.Name) and node.id == "PANE_SESSION_PREFIX" for node in ast.walk(function))}
        self.assertEqual({"blocking_panes", "session_name"}, spelled,
                         "the prefix is read to decide it in one place, and to build the name of the session in another")
