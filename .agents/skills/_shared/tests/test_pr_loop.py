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
import io
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
import uuid
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
from pr_loop_fakes import (HELPER_PATHS, LOGIN, NO_SERVER, NO_SOCKET, UPDATE_ENVIRONMENT, FakeEnv, FakeTime, pr_view_json,
                           ready_view, signal_world)

HEAD = "a" * 40
NEW = "b" * 40


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
        # PR #7 is merged and its agent waits to be closed when the operator kills the session (and the pane with it). PR #8
        # finds no session: it makes one, and closing PR #7's pane, which is gone, is not a failure.
        killed = lambda: self.env.kill_session(self.session())
        self.run_batch(self.PR + [killed] + self.PR, pr=[7, 8])
        session = self.session()
        self.assertEqual([("new-session", session, "7-ready"), ("new-session", session, "8-ready")],
                         [(made["kind"], made["session"], made["window"]) for made in self.env.created()])
        self.assertEqual([["kill-pane", "-t", "%1"], ["kill-pane", "-t", "%2"]], self.env.tmux_calls("kill-pane"))
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
                     "check-ref-format"}
    SPAWNS = {"command", "run", "Popen", "check_output", "check_call", "call"}

    @classmethod
    def ephemeral(cls, source):
        """What in `source` could create a workspace for the agents or destroy something of the operator's."""
        tree = ast.parse(source)
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
                if node.attr in cls.DELETES_ANYWHERE:
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
        return found

    def test_the_runner_makes_no_workspace_and_destroys_nothing(self):
        self.assertEqual([], self.ephemeral(self.SOURCE))

    def test_the_guard_rejects_every_way_to_make_a_workspace_or_destroy_one(self):
        good = ("import os, shutil, subprocess\nfrom pathlib import Path\n"
                "shutil.which('claude')\ngit(cwd, 'rev-parse', '--show-toplevel')\n"
                "git(cwd, 'config', '--get-all', '-z', 'remote.origin.url')\ncommand('tmux', 'list-panes')\n"
                "exclude.open('a', encoding='utf-8')\npath.open('x', encoding='utf-8')\ntext.replace('a', 'b')\n")
        self.assertEqual([], self.ephemeral(good), "control: what the runner does is accepted")
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
                ("git clone", "git(cwd, 'clone', url)\n", "calls git clone"),
                ("git config that writes", "git(cwd, 'config', 'user.name', 'x')\n", "calls git config without --get-all"),
                ("a subcommand that is computed", "git(cwd, verb)\n", "calls git with a subcommand that is not a literal")):
            with self.subTest(case=case):
                self.assertIn(expected, "; ".join(self.ephemeral(good + extra)))

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
    """What the README, the runner's own docstring and the two skills that name it say is true of a runner that starts
    its agents in the operator's own checkout (class `ephemeral-agent-workspace`, kjelly/pilot#423). The words of the
    design it replaced (a managed clone, a trust dialog the operator answers in the printed session, `.git/info/exclude`)
    must not come back, and the README must say what `--checkout` defaults to and what the runner does in a directory
    the agents do not trust. Text is compared with its white space collapsed: the README is hard-wrapped."""
    HEADING = "## Process a batch of pull requests"
    SKILLS = ("pr-ready", "pr-review-merge")
    EXCLUDE_FILE = "git rev-parse --git-path info/exclude"
    # What the replaced design said, or an over-broad claim about the trust dialog, and no longer holds. The runner DOES
    # recognise a screen whose options are numbered (`CHOICE`) and waits instead of typing into it; it takes a dialog
    # whose options are not numbered (claude's) for the input prompt.
    STALE = ("Managed checkout", "answer it in the printed tmux session", ".git/info/exclude",
             "cannot recognise a trust dialog", "cannot recognize a trust dialog")
    # What the README section must say: the option and its default (the runner's own words), the way to update a stale
    # checkout, where the ignore lines go, and what the runner does in a directory the agents do not trust.
    README_SAYS = ("--checkout DIR", pr_loop.CHECKOUT_DEFAULT, "git pull --ff-only", EXCLUDE_FILE,
                   "must already trust the checkout", "stops at a trust dialog only when its options are numbered")

    @staticmethod
    def flat(text):
        return " ".join(text.split())

    @classmethod
    def section(cls, readme):
        """The README's batch section, from its heading to the next `## ` heading, flattened; None without the heading."""
        found = re.search(rf"^{re.escape(cls.HEADING)}[ \t]*$(.*?)(?=^## |\Z)", readme, re.M | re.S)
        return cls.flat(found.group(1)) if found else None

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
    def missing(cls, section):
        return [f"does not say {phrase!r}" for phrase in cls.README_SAYS if phrase not in section]

    @classmethod
    def skill_lines(cls, name):
        """The lines of a skill's SKILL.md that describe the task file `scripts/pr_loop.py` hands it (there must be one)."""
        text = (ROOT / ".agents" / "skills" / name / "SKILL.md").read_text()
        return [line for line in text.splitlines() if "scripts/pr_loop.py" in line and "--pr-loop-task=" in line]

    def test_the_readme_describes_the_checkout_the_agents_start_in(self):
        section = self.section((ROOT / "README.md").read_text())
        self.assertIsNotNone(section, f"README.md has no section {self.HEADING!r}: the check scanned nothing")
        self.assertGreater(len(section), 2000, "the section is there but nearly empty: the check scanned nothing")
        self.assertIn("python3 scripts/pr_loop.py", section, "control: this is the section about the runner")
        self.assertEqual([], self.missing(section) + self.stale(section),
                         "README.md, section 'Process a batch of pull requests'")

    def test_the_runners_docstring_describes_the_checkout_the_agents_start_in(self):
        self.assertGreater(len(self.flat(pr_loop.__doc__ or "")), 500, "the docstring is missing: nothing was scanned")
        self.assertEqual([], self.stale(pr_loop.__doc__), "the module docstring of scripts/pr_loop.py")

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
                 "still tells the operator to answer a trust dialog within --startup-timeout")):
            with self.subTest(case=case):
                self.assertIn(expected, "; ".join(self.stale(text)))

    def test_the_check_fails_when_the_readme_stops_saying_what_it_must(self):
        section = "The runner " + ", ".join(self.README_SAYS) + "."  # synthetic: this test must not depend on the README
        self.assertEqual([], self.missing(section), "control: a section that says all of it is accepted")
        for phrase in self.README_SAYS:
            with self.subTest(phrase=phrase):
                self.assertEqual([f"does not say {phrase!r}"], self.missing(section.replace(phrase, "...")))
        self.assertEqual(len(self.README_SAYS), len(self.missing("")), "an empty section says none of it")

    def test_the_check_fails_when_it_would_scan_nothing(self):
        readme = f"# Title\n\n{self.HEADING}\n\nAnswer it in the printed tmux session.\n\n## Command map\n\nManaged checkout\n"
        self.assertEqual("Answer it in the printed tmux session.", self.section(readme),
                         "control: the section is cut at the next heading")
        self.assertIsNone(self.section(readme.replace(self.HEADING, "## Process batches of pull requests")),
                          "a renamed heading is no section: the test above fails instead of passing on an empty scan")
        self.assertEqual("", self.section(f"{self.HEADING}\n\n## Command map\n"), "an empty section is empty, not None")
        self.assertEqual("", self.section(f"{self.HEADING}\n"), "a heading at the end of the file is an empty section")


# ---- (C) Agent: the real class driving the fake tmux in a subprocess ----------------------------------------------

class SessionNameTests(unittest.TestCase):
    """The tmux session of a checkout (kjelly/pilot#425). tmux 3.8 keeps `.` and `:` in a session name as typed and then
    cannot address it (`:` makes `-t S:` name the wrong thing), refuses a tab and accepts an empty name: the name is made
    of letters, digits, `_` and `-` only, whatever the directory is called, and it is the same on every run in a checkout."""
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
                           "#{pane_id}", "--", "exec " + shlex.quote(str(self.env.bin / "claude"))]],
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
                "#{pane_id}", *environment, "--", "exec " + shlex.quote(str(self.env.bin / "claude"))]

    def session_argv(self, window):
        return ["new-session", "-d", "-s", self.checkout.session, "-n", window, "-c", str(self.env.root), "-P", "-F",
                "#{pane_id}", "--", "exec " + shlex.quote(str(self.env.bin / "claude"))]

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
        self.agent(7, "draft")
        session = self.checkout.session
        self.env.update_tmux(log=[], before={"new-window": [{"kill_session": session}]})
        second = self.agent(7, "ready")
        self.assertEqual(["new-session", "show-options", "new-window", "new-session", "set-option"],
                         [call[0] for call in self.calls()])
        self.assertEqual("%2", second.pane)
        self.assertEqual({session: ["7-ready"]}, self.env.live())
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
        self.env.update_tmux(before={"new-session": [appears] * 3, "new-window": [disappears] * 3})
        with self.assertRaisesRegex(pr_loop.Stop, rf"^tmux session {session} kept appearing and disappearing while an "
                                                  "agent was started; nothing was dispatched$"):
            self.agent()
        self.assertEqual(["new-session", "show-options", "new-window", "new-session", "new-window", "new-session",
                          "new-window"], [call[0] for call in self.calls()],
                         "three rounds of new-session, then new-window (the environment is read once), and no fourth")
        self.assertEqual({}, self.env.live())
        self.assertEqual([], self.calls("set-option"), "nothing was started")

    def test_two_rounds_of_it_are_tolerated(self):
        # The control of the test above: the third round gets through.
        session = self.checkout.session
        self.env.update_tmux(before={"new-session": [{"create_session": session}] * 2,
                                     "new-window": [{"kill_session": session}] * 2})
        agent = self.agent()
        self.assertEqual({session: ["7-draft"]}, self.env.live())
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
        self.assertEqual(["load-buffer", "paste-buffer", "display-message", "send-keys"], self.names()[2:])
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
        self.assertEqual([], self.calls("send-keys", "display-message"))

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
        self.assertEqual([["kill-pane", "-t", first.pane]], self.env.tmux_calls())
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
        # The operator closed the window, or killed the session: what close asks for has happened.
        agent = self.agent()
        self.env.kill_session(self.checkout.session)
        agent.close()
        self.assertEqual([["kill-pane", "-t", "%1"]], self.calls("kill-pane"))

    def test_only_a_pane_that_is_gone_counts_as_closed(self):
        agent = self.agent()
        for case, answer in (("another pane", {"rc": 1, "stderr": "can't find pane: %9"}),
                             ("another status", {"rc": 2, "stderr": "can't find pane: %1"}),
                             ("no server", {"rc": 1, "stderr": NO_SERVER}),
                             ("another text", {"rc": 1, "stderr": "no space"})):
            with self.subTest(case=case):
                self.env.update_tmux(answers={"kill-pane": [answer]})
                with self.assertRaisesRegex(pr_loop.Stop, rf"^tmux kill-pane failed \({answer['rc']}\): "
                                                          f"{re.escape(answer['stderr'])}$"):
                    agent.close()


class FakeTmuxTests(unittest.TestCase):
    """The fake tmux says about sessions and windows what tmux 3.8 said on a private server (kjelly/pilot#425): the texts
    are those captures, and a test that relies on one of the rules below (the exact `=S:`, the prefix fallback of `S:`)
    relies on it being true of the fake as it is of tmux."""

    def setUp(self):
        self.env = FakeEnv(self)

    @staticmethod
    def tmux(*args):
        done = subprocess.run(["tmux", *args], capture_output=True, text=True, timeout=60)
        return done.returncode, done.stdout, done.stderr.strip()

    def session(self, name, window="w"):
        return self.tmux("new-session", "-d", "-s", name, "-n", window, "-c", "/", "-P", "-F", "#{pane_id}", "--", "x")

    def window(self, target, name="v"):
        return self.tmux("new-window", "-d", "-t", target, "-n", name, "-c", "/", "-P", "-F", "#{pane_id}", "--", "x")

    def test_a_session_name_in_use_is_a_duplicate(self):
        self.assertEqual((0, "%1\n", ""), self.session("S"))
        self.assertEqual((1, "", "duplicate session: S"), self.session("S"))
        self.assertEqual((0, "%2\n", ""), self.session("S-eink"), "another name is another session")

    def test_a_window_needs_a_session_that_exists(self):
        self.assertEqual((1, "", "can't find session: S"), self.window("=S:"))
        self.assertEqual((1, "", "can't find session: S"), self.window("S:"))
        self.session("S")
        self.assertEqual((1, "", "can't find window: S"), self.window("S"), "without a colon the target is a window name")
        self.assertEqual((0, "%2\n", ""), self.window("=S:"))
        self.assertEqual((0, "%3\n", ""), self.window("S:"))
        self.assertEqual({"S": ["w", "v", "v"]}, self.env.live())

    def test_an_inexact_target_falls_back_to_a_session_whose_name_starts_with_it_and_an_exact_one_does_not(self):
        self.session("S-eink")
        self.assertEqual((1, "", "can't find session: S"), self.window("=S:"))
        self.assertEqual({"S-eink": ["w"]}, self.env.live())
        self.assertEqual((0, "%2\n", ""), self.window("S:"), "tmux put the window into S-eink")
        self.assertEqual({"S-eink": ["w", "v"]}, self.env.live())

    def test_an_ambiguous_prefix_is_no_session_and_a_whole_name_wins_over_a_prefix(self):
        self.session("S-a")
        self.session("S-b")
        self.assertEqual((1, "", "can't find session: S"), self.window("S:"))
        self.session("S")
        self.assertEqual((0, "%4\n", ""), self.window("S:"))
        self.assertEqual(["w", "v"], self.env.live()["S"], "the session called S, not one of the longer names")

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
        self.assertEqual((1, "", "can't find pane: %2"), self.tmux("kill-pane", "-t", "%2"), "a second kill finds nothing")

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
        self.assertEqual((0, "", ""), self.tmux("kill-pane", "-t", "%1"))
        self.assertEqual({}, self.env.live())

    def test_the_panes_listing_is_derived_from_the_model_the_way_tmux_prints_it(self):
        format = "#{session_name}|#{pane_id}|#{pane_dead}|#{pane_current_path}"
        self.session("S")
        self.window("=S:")
        self.env.add_twin("S", "S-eink")
        self.env.set_pane("%2", status=["1|0|claude"])  # exited, kept by remain-on-exit: no path
        self.assertEqual((0, "S|%1|0|/\nS|%2|1|\nS-eink|%1|0|/\nS-eink|%2|1|\n", ""), self.tmux("list-panes", "-a", "-F", format),
                         "sorted by session name, a twin repeats the rows of its session")
        self.env.update_tmux(listing=["x|%1|0|/y"])
        self.assertEqual((0, "x|%1|0|/y\n", ""), self.tmux("list-panes", "-a", "-F", format), "a listing a test sets wins")

    def test_the_environment_a_new_session_takes_is_tmuxs_default_list(self):
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
        # The main work tree, on `side`, is refused for being on side, not for the lock the linked one holds.
        self.stops(f"checkout {self.path} is on side, not on main, the default branch of origin")


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
        self.stops(f"checkout {self.path} is on main, not on trunk, the default branch of origin")
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

    def test_another_branch_at_the_same_commit_is_refused(self):
        # The tip alone would pass: `other` and `main` are the same commit.
        self.git("switch", "-q", "-c", "other")
        self.assertEqual(self.env.remote_head, self.tip())
        self.stops(f"checkout {self.path} is on other, not on main, the default branch of origin")
        self.git("switch", "-q", "main")
        self.checkout()

    def test_a_checkout_behind_origin_is_told_to_pull(self):
        behind = (f"local main is at {self.env.remote_head[:12]} but origin's main is at %s; run git pull --ff-only in "
                  f"{self.path} and start the runner again")
        old = self.env.remote_head
        new = self.env.advance_remote()
        # origin's new commit is not in the checkout yet ...
        self.stops(behind % new[:12])
        # ... and once it has been fetched, the checkout is still behind, not ahead.
        self.git("fetch", "-q", "origin")
        self.stops(behind % new[:12])
        self.assertEqual(old, self.tip(), "the runner never updates the checkout")
        self.git("pull", "-q", "--ff-only", "origin", "main")
        self.checkout()  # control: pulled, equal to origin

    def test_a_checkout_ahead_of_origin_is_refused(self):
        local = self.commit()
        self.stops(f"local main at {local[:12]} has commits that origin's main ({self.env.remote_head[:12]}) does not "
                   "have; the skills must come from origin's default branch")
        self.git("push", "-q", "origin", "main")
        self.env.remote_head = self.git("rev-parse", "main", cwd=self.env.remote)
        self.checkout()  # control: pushed, equal to origin

    def test_a_diverged_checkout_is_told_to_pull_too(self):
        local = self.commit()
        new = self.env.advance_remote()
        for fetched in (False, True):
            with self.subTest(fetched=fetched):
                if fetched:
                    self.git("fetch", "-q", "origin")
                self.stops(f"local main is at {local[:12]} but origin's main is at {new[:12]}; run git pull --ff-only in "
                           f"{self.path} and start the runner again")

    def test_a_checkout_without_a_commit_is_refused(self):
        fresh = self.env.root / "fresh"
        self.env.git("init", "-q", "-b", "main", str(fresh), cwd=self.env.root)
        self.env.git("remote", "add", "origin", self.env.ORIGIN, cwd=fresh)
        self.env.redirect_origin(fresh, self.env.ORIGIN)
        self.stops(f"local main has no commit but origin's main is at {self.env.remote_head[:12]}; run git pull "
                   f"--ff-only in {fresh} and start the runner again", str(fresh))


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

    def refusal(self, pane="%3", session=SESSION):
        return (f"agent pane {pane} (session {session}) is still running in {self.path}; "
                "inspect and close it before starting the runner again")

    def test_a_live_pilot_pane_in_the_checkout_is_refused(self):
        for where in (str(self.path), str(self.path / "sub")):
            with self.subTest(where=where):
                self.listing(f"{self.SESSION}|%3|0|{where}")
                self.stops(self.refusal())
        self.listing(f"other|%1|0|{self.env.root}", f"{self.SESSION}|%3|0|{self.path}")
        self.stops(self.refusal())
        self.assertEqual(["list-panes", "-a", "-F", "#{session_name}|#{pane_id}|#{pane_dead}|#{pane_current_path}"],
                         self.env.tmux_calls("list-panes")[-1])

    def test_panes_that_are_not_in_the_way_pass(self):
        self.listing(f"{self.SESSION}|%3|1|",                              # dead (tmux reports no path for it)
                     f"{self.SESSION}|%4|1|{self.path}",                   # dead, whatever its path
                     f"{self.SESSION}|%5|0|{self.env.root}",               # live, elsewhere
                     f"{self.SESSION}|%6|0|{self.path}-other",             # live, a sibling whose name starts the same
                     f"mine|%7|0|{self.path}",                             # the operator's own session in the checkout
                     f"pilot-pr|%8|0|{self.path}")                         # not the runner's prefix
        self.checkout()

    def test_a_pane_that_reaches_the_checkout_through_a_symlink_counts(self):
        link = self.env.root / "link"
        link.symlink_to(self.path)
        self.listing(f"{self.SESSION}|%3|0|{link}/sub")
        self.stops(self.refusal())

    def test_a_live_pane_is_refused_in_a_session_of_the_new_names_and_of_the_old_ones(self):
        new = pr_loop.session_name(self.path)
        for session in (new, "pilot-pr-7-draft-0123456789", "pilot-pr-" + "x" * 24 + "-0123abcd"):
            with self.subTest(session=session):
                self.listing(f"{session}|%3|0|{self.path}")
                self.stops(self.refusal(session=session))

    def test_a_twin_repeats_the_rows_of_its_session_and_does_not_hide_a_live_pane(self):
        session = pr_loop.session_name(self.path)
        self.listing(f"{session}|%3|0|{self.path}", f"{session}-eink|%3|0|{self.path}")
        self.stops(self.refusal(session=session))
        self.listing(f"{session}-eink|%3|0|{self.path}")  # a twin alone is a session of the runner's prefix too
        self.stops(self.refusal(session=f"{session}-eink"))
        self.listing(f"{session}|%3|1|", f"{session}-eink|%3|1|")
        self.checkout().release()  # control: dead in both

    def test_sessions_that_do_not_carry_the_runners_prefix_are_not_its_business(self):
        self.listing(f"pilot-prx-checkout|%3|0|{self.path}", f"my-pilot-pr-checkout|%4|0|{self.path}",
                     f"pilot|%5|0|{self.path}", f"|%6|0|{self.path}")
        self.checkout().release()

    def test_an_agent_the_runner_started_is_seen_in_the_panes_tmux_lists_until_it_is_dead(self):
        first = self.checkout()
        first.release()
        agent = pr_loop.Agent("claude", first, 7, "draft")  # the real Agent, over the fake tmux's sessions and windows
        self.stops(self.refusal(pane=agent.pane, session=first.session))
        self.env.set_pane(agent.pane, status=["1|0|claude"])  # it exited: remain-on-exit keeps the pane, dead, with no path
        self.assertEqual([f"{first.session}|{agent.pane}|1|"], self.panes_tmux_lists())
        self.checkout().release()

    @staticmethod
    def panes_tmux_lists():
        done = subprocess.run(["tmux", "list-panes", "-a", "-F",
                               "#{session_name}|#{pane_id}|#{pane_dead}|#{pane_current_path}"], capture_output=True, text=True)
        return done.stdout.splitlines()

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
        self.env.update_tmux(log=[], listing=[f"{self.SESSION}|%3|0|{self.path}"])
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
        self.env.update_tmux(listing=[f"pilot-pr-7-draft-0123456789|%3|0|{self.path}"])
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
        def other(): self.git("switch", "-q", "-c", "other")
        def behind(): self.env.advance_remote()
        def origin(): self.git("remote", "set-url", "origin", "https://github.com/other/demo.git")
        def merging(): Path(self.git("rev-parse", "--path-format=absolute", "--git-path", "MERGE_HEAD")).write_text("x\n")
        return (("dirty", dirty, f"checkout {top} has uncommitted changes or untracked files (1 paths, e.g. stray.txt); "
                                 "commit or remove them; the runner never stashes or discards work"),
                ("another branch", other, f"checkout {top} is on other, not on main, the default branch of origin"),
                ("behind", behind, f"local main is at {self.env.remote_head[:12]} but origin's main is at "
                                   "%s; run git pull --ff-only in " + f"{top} and start the runner again"),
                ("another origin", origin, f"origin of {top} is github.com/other/demo, not {self.IDENTITY}"),
                ("a git operation", merging, f"a git operation is in progress in {top} (MERGE_HEAD); finish or abort it"))

    def test_a_dry_run_refuses_what_the_real_run_refuses_for_the_same_reason(self):
        for name, setup, message in self.refusals():
            with self.subTest(name=name):
                self.env.make_checkout()
                setup()
                message = message % self.env.remote_head[:12] if "%s" in message else message
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
    def blocked_rerun(self):
        """The second run of `blocked_run`: the agent of the new run is pane `%2` and publishes a blocker too."""
        self.env.set_pane("%2", enter=[{"result": {"outcome": "DRAFT-BLOCKED", "reason": "synthetic blocker"}}])
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
                                 "it before starting the runner again\n"), (again.returncode, again.stdout, again.stderr))
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
        self.env.kill_session(session)  # (and the agent with it: nothing of the earlier run is left in the checkout)
        self.env.update_tmux(log=[])
        proc = self.blocked_rerun()
        self.assertIn(f"PR #7 draft agent: %2 in window 7-draft of tmux session {session}", proc.stdout)
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

    def refused_states(self):
        """Each state the real run refuses, as `(name, set up, working directory, a fragment of the reason)`."""
        top, git = self.env.checkout, lambda *args: self.env.git(*args, cwd=self.env.checkout)
        plain = self.env.root / "plain"
        plain.mkdir(exist_ok=True)

        def dirty():
            (top / "stray.txt").write_text("x")

        def without_helper():
            self.env.make_remote({"other.txt": "x\n"})
            self.env.make_checkout()
        return (("not in a work tree", lambda: None, plain, "the current directory is not inside a git work tree"),
                ("dirty", dirty, None, "has uncommitted changes or untracked files (1 paths, e.g. stray.txt)"),
                ("behind", self.env.advance_remote, None, "run git pull --ff-only in"),
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
        self.env.update_tmux(listing=[f"{session}|%3|0|{self.env.checkout}/sub"])
        proc = self.run_program()
        self.assertEqual((1, "", f"pr-loop: agent pane %3 (session {session}) is still running in {self.env.checkout}; "
                                 "inspect and close it before starting the runner again\n"),
                         (proc.returncode, proc.stdout, proc.stderr))
        self.assertEqual([], self.env.gh_calls())
        self.only_listed_panes()
        self.env.update_tmux(listing=[f"{session}|%3|1|"], log=[])  # closed (dead): the same start goes through
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

    def test_a_pr_that_cannot_be_read_stops_without_starting_anything(self):
        self.env.update_gh(seq=[{"exit": 1, "stderr": "synthetic outage"}])
        proc = self.run_program()
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        self.assertIn("GitHub read failed 3 consecutive times; no command sent", proc.stderr)
        self.only_listed_panes()
        self.assertEqual({("pr", "view")}, {tuple(call[:2]) for call in self.env.gh_calls()})
        self.assertIn("GitHub read failed (2/3)", proc.stdout)
