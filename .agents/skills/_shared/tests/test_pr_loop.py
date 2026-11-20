"""scripts/pr_loop.py: the runner's gates, state machine, tmux driver and checkout, and the whole program.

Nothing here touches the developer's tmux server, GitHub or an agent: the tests that need `tmux`, `gh` or an agent
executable put the fakes of pr_loop_fakes.py first on PATH (FakeEnv refuses to go on unless `which` finds them),
and every wait runs on a fake clock. The pane screens and PR views are synthetic.
"""
import ast
import json
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(ROOT / "scripts"))
import pr_loop
from pr_loop_result import load_task, write_result
from pr_loop_fakes import FakeEnv, FakeTime, pr_view_json

HEAD = "a" * 40
NEW = "b" * 40


class PRLoopTests(unittest.TestCase):
    def test_reuses_a_role_within_a_pr_but_restarts_it_for_the_next(self):
        view_states = {7: "ready", 8: "ready"}
        dispatched, started, closed = [], [], []
        head = "a" * 40

        def view(_repo, number):
            state = view_states[number]
            if state == "queued":
                view_states[number] = "merged"
            return dict(number=number, state="MERGED" if state == "merged" else "OPEN",
                        isDraft=state == "draft", headRefOid=head,
                        labels=[{"name": pr_loop.QUEUE_LABEL}] if state == "queued" else [])

        class Checkout:
            def __init__(self, *_):
                pass

            def verify(self):
                pass

            def task(self, _repo, _number, _phase, _head):
                return Path(tmp) / "task.json", {}

            def clean_up(self):
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

        args = SimpleNamespace(pr=[7, 8], dry_run=False, phase_timeout=10, startup_timeout=1,
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
        original = dict(number=7, state="OPEN", isDraft=False, labels=[{"name": "needs-person"}], headRefOid=current)
        marker = f"<!-- pr-review-merge:needs-person head={current} live-base={'c' * 40} reasons={'d' * 16} -->"
        repo = pr_loop.Repo.parse("kjelly/pilot")
        for latest in (original, dict(original, headRefOid=new)):
            with patch.object(pr_loop, "pr_view", side_effect=[original, latest]), \
                 patch.object(pr_loop, "viewer_login", return_value="reviewer"), \
                 patch.object(pr_loop, "issue_comments", return_value=[{"login": "reviewer", "body": marker}]):
                if latest["headRefOid"] == current:
                    with self.assertRaisesRegex(pr_loop.Stop, "needs a person"):
                        pr_loop.observe(repo, 7)
                else:
                    self.assertEqual(latest, pr_loop.observe(repo, 7))


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
    """`observe` is the one read of a PR. The existing test above covers a moved HEAD."""
    repo = pr_loop.Repo.parse("kjelly/pilot")
    marker = f"<!-- pr-review-merge:needs-person head={HEAD} live-base={'c' * 40} reasons={'d' * 16} -->"

    def labelled(self, **fields):
        return dict(pr_view_json("ready", head=HEAD, labels=["needs-person"]), **fields)

    def observe(self, views, comments, number=7):
        with patch.object(pr_loop, "pr_view", side_effect=views) as view, \
             patch.object(pr_loop, "viewer_login", return_value="reviewer"), \
             patch.object(pr_loop, "issue_comments", return_value=comments):
            try:
                return pr_loop.observe(self.repo, number), view.call_count
            except pr_loop.Stop as exc:
                return exc, view.call_count

    def test_a_marker_of_the_viewer_at_the_current_head_stops(self):
        view = self.labelled()
        result, reads = self.observe([view, view], [{"login": "reviewer", "body": self.marker}])
        self.assertIsInstance(result, pr_loop.Stop)
        self.assertRegex(str(result), rf"PR #7 needs a person at HEAD {HEAD[:12]}; see the PR conversation")
        self.assertEqual(2, reads, "the label is confirmed by a second read before the PR is given up")

    def test_a_marker_by_another_login_is_ignored(self):
        view = self.labelled()
        result, reads = self.observe([view], [{"login": "someone-else", "body": self.marker}])
        self.assertEqual((view, 1), (result, reads))

    def test_a_marker_for_another_head_is_ignored(self):
        view = self.labelled()
        old = self.marker.replace(HEAD, NEW)
        result, reads = self.observe([view], [{"login": "reviewer", "body": old}])
        self.assertEqual((view, 1), (result, reads))

    def test_no_marker_at_all_is_just_the_view(self):
        view = self.labelled()
        self.assertEqual((view, 1), self.observe([view], [{"login": "reviewer", "body": "no marker here"}]))
        self.assertEqual((view, 1), self.observe([view], []))

    def test_a_label_that_is_gone_on_the_fresh_read_returns_the_fresh_view(self):
        view = self.labelled()
        fresh = pr_view_json("ready", head=HEAD)
        result, reads = self.observe([view, fresh], [{"login": "reviewer", "body": self.marker}])
        self.assertEqual((fresh, 2), (result, reads))

    def test_the_hand_off_only_applies_to_a_ready_pr(self):
        for phase in ("draft", "queued"):
            with self.subTest(phase=phase):
                view = pr_view_json(phase, head=HEAD, labels=["needs-person"])
                with patch.object(pr_loop, "pr_view", return_value=view), \
                     patch.object(pr_loop, "viewer_login", side_effect=AssertionError("not asked")), \
                     patch.object(pr_loop, "issue_comments", side_effect=AssertionError("not asked")):
                    self.assertEqual(view, pr_loop.observe(self.repo, 7))

    def test_a_pr_that_cannot_be_driven_stops_in_the_same_read(self):
        result, reads = self.observe([dict(pr_view_json("ready"), state="CLOSED")], [])
        self.assertRegex(str(result), "is not open or merged")


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
    """What GitHub answers, read by read. An item is a phase, a (phase, head) pair or an exception to raise; once
    the scripted items are used up the PR stays in `phase`. Every read is counted."""

    def __init__(self, items=(), phase="merged"):
        self.items, self.phase, self.reads = list(items), phase, 0

    def observe(self, _repo, number):
        self.reads += 1
        item = self.items.pop(0) if self.items else self.phase
        if isinstance(item, BaseException):
            raise item
        phase, head = item if isinstance(item, tuple) else (item, HEAD)
        return pr_view_json(phase, number=number, head=head)


class Fleet:
    """The fake agents and checkout of one test: everything they were asked to do is recorded."""

    def __init__(self, clock, directory):
        self.clock, self.directory = clock, Path(directory)
        self.agents, self.waits, self.submits, self.closed, self.tasks = [], [], [], [], []
        self.submit_times = []
        self.checkouts = []
        self.busy = {}      # role -> seconds an agent stays busy after it was given a task
        self.statuses = {}  # role -> the (dead, in_mode, foreground) answers; the last one repeats
        self.on_submit = {}  # role -> callable run right after that role's agent is given a task
        self.on_handoff = {}  # role -> callable run when the runner waits for that role's agent to hand over

    def new_agent(self, executable, _checkout, number, phase):
        return FakeAgent(self, executable, number, phase)

    def new_checkout(self, view, repo):
        checkout = FakeCheckout(self, view, repo)
        self.checkouts.append(checkout)
        return checkout


class FakeAgent:
    def __init__(self, fleet, executable, number, phase):
        self.fleet, self.executable, self.role = fleet, executable, phase
        self.pane = f"%{len(fleet.agents) + 1}"
        self.statuses = list(fleet.statuses.get(phase, []))
        self.busy = 0
        fleet.agents.append(self)

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
        self.fleet.closed.append(self.role)


class FakeCheckout:
    def __init__(self, fleet, view, repo):
        self.fleet, self.view, self.verified, self.cleaned = fleet, view, 0, False

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

    def clean_up(self):
        self.cleaned = True


class RunPRCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.clock = FakeTime()
        self.fleet = Fleet(self.clock, self.temp.name)
        self.told = []
        for target, value in (("time", self.clock), ("tell", self.told.append), ("Agent", self.fleet.new_agent),
                              ("Checkout", self.fleet.new_checkout)):
            patcher = patch.object(pr_loop, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def args(self, **overrides):
        values = dict(pr=[7], dry_run=False, phase_timeout=100, startup_timeout=60, max_actions=20,
                      poll_interval=10, ready_agent="codex", draft_agent="claude",
                      ready_command="$pr-review-merge {pr}", draft_command="/pr-ready {pr}")
        values.update(overrides)
        return SimpleNamespace(**values)

    def run_batch(self, items=(), phase="merged", **overrides):
        self.world = World(items, phase)
        with patch.object(pr_loop, "observe", self.world.observe):
            pr_loop.Batch(pr_loop.Repo.parse("acme/demo"), self.args(**overrides)).run()

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
        self.assertEqual(["ready"], self.fleet.closed, "the panes are closed once GitHub confirms the merge")
        self.assertTrue(self.fleet.checkouts[0].cleaned)

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

    def test_a_dry_run_reports_after_the_first_read_and_starts_nothing(self):
        self.run_batch(["draft", "ready", "merged"], dry_run=True)
        self.assertEqual(1, self.world.reads)
        self.assertEqual(["PR #7: draft"], self.told)
        self.assertEqual(([], [], []), (self.fleet.agents, self.fleet.checkouts, self.clock.sleeps))


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
        self.assertEqual(([], [], []), (self.fleet.submits, self.fleet.agents, self.fleet.checkouts))
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

    def test_a_failed_clone_is_not_retried(self):
        # Reads are retried; a command that changes something never is.
        with patch.object(pr_loop, "Checkout", side_effect=pr_loop.Stop("gh repo failed (1): clone")) as checkout:
            with self.assertRaisesRegex(pr_loop.Stop, "gh repo failed"):
                self.run_batch(["ready"] * 3)
        self.assertEqual(1, checkout.call_count)


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
        self.assertFalse(self.fleet.checkouts[0].cleaned)
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


class ImportsTests(unittest.TestCase):
    """The runner only reads GitHub: it must not import anything that changes it."""
    SOURCE = (ROOT / "scripts" / "pr_loop.py").read_text()

    def test_it_imports_only_the_read_functions_of_gh_runtime(self):
        tree = ast.parse(self.SOURCE)
        imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
                    and node.module == "gh_runtime" for alias in node.names}
        self.assertEqual({"GitHubError", "Repo", "issue_comments", "pr_view", "viewer_login"}, imported)
        plain = [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names]
        self.assertNotIn("gh_runtime", plain)
        mentioned = {node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
                     and isinstance(node.value, ast.Name) and node.value.id == "gh_runtime"}
        self.assertEqual(set(), mentioned)

    def test_the_task_directory_is_named_once_in_the_shared_module(self):
        tree = ast.parse(self.SOURCE)
        imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)
                    and node.module == "pr_loop_result" for alias in node.names}
        self.assertIn("TASK_DIR", imported)
        spelled = [node.value for node in ast.walk(tree) if isinstance(node, ast.Constant)
                   and isinstance(node.value, str) and (".pr-loop" in node.value or "tmux-ai" in node.value)]
        self.assertEqual([], spelled, "scripts/pr_loop.py must use pr_loop_result.TASK_DIR, not spell the layout")


# ---- (C) Agent: the real class driving the fake tmux in a subprocess ----------------------------------------------

class TmuxCase(unittest.TestCase):
    def setUp(self):
        self.env = FakeEnv(self)
        self.clock = FakeTime()
        self.told = []
        for target, value in (("time", self.clock), ("tell", self.told.append)):
            patcher = patch.object(pr_loop, target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.checkout = SimpleNamespace(path=self.env.root)

    def agent(self):
        return pr_loop.Agent("claude", self.checkout, 7, "draft")

    def calls(self, *names):
        return [call for call in self.env.tmux_calls() if not names or call[0] in names]


class AgentStartTests(TmuxCase):
    def test_a_new_agent_runs_in_its_own_detached_session_and_keeps_its_pane_when_it_exits(self):
        agent = self.agent()
        self.assertEqual("%1", agent.pane)
        (new,) = self.calls("new-session")
        session = new[new.index("-s") + 1]
        self.assertRegex(session, r"^pilot-pr-7-draft-[0-9a-f]{10}$")
        self.assertEqual(["new-session", "-d", "-P", "-F", "#{pane_id}", "-s", session, "-c", str(self.env.root),
                          "--", "exec " + shlex.quote(str(self.env.bin / "claude"))], new)
        self.assertEqual([["set-option", "-w", "-t", "%1", "remain-on-exit", "on"]], self.calls("set-option"))
        self.assertIn(f"PR #7 draft agent: %1 in session {session}", self.told)

    def test_a_pane_id_that_is_not_one_stops_before_anything_else_is_sent(self):
        for answer in ("bogus", "%x", "", "1", "%1 %2"):
            with self.subTest(answer=repr(answer)):
                self.env.update_tmux(new_session=[answer], log=[])
                with self.assertRaisesRegex(pr_loop.Stop, "tmux did not return a pane ID"):
                    self.agent()
                self.assertEqual([], self.calls("set-option"))
        self.env.update_tmux(new_session=["%12"], log=[])
        self.assertEqual("%12", self.agent().pane, "control: a real pane ID is taken as it is")

    def test_an_executable_that_does_not_exist_stops_before_tmux_is_called(self):
        with self.assertRaisesRegex(pr_loop.Stop, "agent executable not found: no-such-agent"):
            pr_loop.Agent("no-such-agent", self.checkout, 7, "draft")
        self.assertEqual([], self.calls())

    def test_a_failing_new_session_stops_with_the_command_and_status(self):
        self.env.update_tmux(fail={"new-session": 3})
        with self.assertRaisesRegex(pr_loop.Stop, r"tmux new-session failed \(3\): fake tmux: injected failure"):
            self.agent()


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
        with self.assertRaisesRegex(pr_loop.Stop, r"agent did not return to its input prompt in %\d+; "
                                                  r"inspect session pilot-pr-7-draft-"):
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


# ---- (D) Checkout: the fake gh clones a scratch bare repository, git is real -------------------------------------

class CheckoutCase(unittest.TestCase):
    repo = pr_loop.Repo.parse("acme/demo")

    def setUp(self):
        self.env = FakeEnv(self)
        self.told = []
        patcher = patch.object(pr_loop, "tell", self.told.append)
        patcher.start()
        self.addCleanup(patcher.stop)

    def checkout(self, view=None, repo=None):
        return pr_loop.Checkout(view or pr_view_json("ready"), repo or self.repo)

    def git(self, checkout, *args):
        return self.env.git(*args, cwd=checkout.path)

    def ignored(self, checkout, path):
        done = subprocess.run(["git", "check-ignore", "-q", "--", path], cwd=checkout.path, env=self.env.git_env)
        return done.returncode == 0


class CheckoutUrlTests(CheckoutCase):
    def test_a_pr_url_that_is_not_this_pr_is_refused_before_anything_is_cloned(self):
        for case, url in {
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
        }.items():
            with self.subTest(case=case):
                with self.assertRaisesRegex(pr_loop.Stop, "GitHub returned an unexpected PR URL"):
                    self.checkout(pr_view_json("ready", url=url))
                self.assertEqual([], self.env.gh_calls(), "nothing was cloned")
                self.assertFalse(self.env.state_home.exists(), "no checkout directory was made")
        with self.assertRaisesRegex(pr_loop.Stop, "unexpected PR URL"):
            view = pr_view_json("ready")
            del view["url"]
            self.checkout(view)

    def test_the_expected_url_is_cloned_over_https_into_the_managed_directory(self):
        checkout = self.checkout()
        self.assertEqual([["repo", "clone", "https://github.com/acme/demo", str(checkout.path)]],
                         self.env.gh_calls())
        root = self.env.state_home / "pilot" / "pr-loop"
        self.assertEqual(root, checkout.path.parent)
        self.assertTrue(checkout.path.name.startswith("batch-"))
        self.assertEqual(0o700, stat.S_IMODE(root.stat().st_mode))
        self.assertIn(f"Managed checkout: {checkout.path}", self.told)
        self.assertEqual("refs/heads/main", checkout.branch)
        self.assertEqual(self.env.remote_head, checkout.head)

    def test_the_comparison_ignores_case_like_github(self):
        self.checkout(pr_view_json("ready", url="https://GitHub.com/Acme/Demo/pull/7"))

    def test_a_host_qualified_repository_is_cloned_from_its_own_host(self):
        repo = pr_loop.Repo.parse("ghe.example.com/acme/demo")
        checkout = self.checkout(pr_view_json("ready", url="https://ghe.example.com/acme/demo/pull/7"), repo)
        self.assertEqual("https://ghe.example.com/acme/demo", self.env.gh_calls()[0][2])
        with self.assertRaisesRegex(pr_loop.Stop, "unexpected PR URL"):
            self.checkout(pr_view_json("ready"), repo)  # a github.com URL for a ghe.example.com repository
        self.assertTrue(checkout.path.exists())

    def test_a_clone_that_fails_stops(self):
        self.env.update_gh(clone_exit=5)
        with self.assertRaisesRegex(pr_loop.Stop, r"gh repo failed \(5\): fake gh: injected clone failure"):
            self.checkout()
        self.assertEqual(1, len(self.env.gh_calls()), "a clone is not retried")


class CheckoutIgnoreTests(CheckoutCase):
    def test_the_task_and_evidence_directories_are_excluded_from_git_status(self):
        checkout = self.checkout()
        exclude = (checkout.path / ".git/info/exclude").read_text().splitlines()
        self.assertIn("/.pr-ready/", exclude)
        self.assertIn("/.pr-loop/", exclude)
        self.assertNotIn("tmux-ai", "\n".join(exclude))
        self.assertTrue(self.ignored(checkout, ".pr-loop/" + "0" * 32 + "/task.json"))
        self.assertTrue(self.ignored(checkout, ".pr-ready/anything"))
        self.assertFalse(self.ignored(checkout, "stray.txt"), "control: only those two are ignored")

    def test_a_checkout_that_does_not_ignore_the_task_directory_is_refused(self):
        # A tracked .gitignore beats .git/info/exclude, so the exclude written by the runner can be neutralised.
        self.env.make_remote({".agents/skills/_shared/scripts/pr_loop_result.py": "x = 1\n", ".gitignore": "!/.pr-loop/\n"})
        with self.assertRaisesRegex(pr_loop.Stop, r"managed checkout does not ignore \.pr-loop/ and \.pr-ready/"):
            self.checkout()

    def test_a_checkout_that_does_not_ignore_the_evidence_directory_is_refused(self):
        # Each directory is probed by itself: ignoring only one of them is not enough.
        self.env.make_remote({".agents/skills/_shared/scripts/pr_loop_result.py": "x = 1\n", ".gitignore": "!/.pr-ready/\n"})
        with self.assertRaisesRegex(pr_loop.Stop, r"managed checkout does not ignore \.pr-loop/ and \.pr-ready/"):
            self.checkout()

    def test_a_default_branch_without_the_result_helper_is_refused(self):
        self.env.make_remote({"other.txt": "x\n"})
        with self.assertRaisesRegex(pr_loop.Stop, r"git cat-file failed"):
            self.checkout()


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

    def test_every_task_gets_its_own_directory(self):
        checkout = self.checkout()
        first, _ = checkout.task(self.repo, 7, "draft", HEAD)
        second, _ = checkout.task(self.repo, 7, "ready", HEAD)
        self.assertNotEqual(first.parent, second.parent)
        self.assertEqual(first.parent.parent, second.parent.parent)

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
        self.assertEqual("", self.git(checkout, "status", "--porcelain=v1", "--untracked-files=normal"))
        checkout.verify()


class CheckoutVerifyTests(CheckoutCase):
    def test_a_clean_checkout_at_the_default_branch_verifies(self):
        self.checkout().verify()

    def test_work_outside_the_ignored_directories_stops(self):
        checkout = self.checkout()
        (checkout.path / "stray.txt").write_text("x")
        with self.assertRaisesRegex(pr_loop.Stop, rf"managed checkout contains uncommitted work: {checkout.path}"):
            checkout.verify()
        (checkout.path / "stray.txt").unlink()
        (checkout.path / "README.txt").write_text("changed\n")
        with self.assertRaisesRegex(pr_loop.Stop, "uncommitted work"):
            checkout.verify()

    def test_a_head_that_moved_stops(self):
        checkout = self.checkout()
        self.git(checkout, "commit", "-q", "--allow-empty", "-m", "an agent committed here")
        with self.assertRaisesRegex(pr_loop.Stop, rf"skill did not restore the checked default branch at {checkout.head}"):
            checkout.verify()

    def test_another_branch_stops(self):
        checkout = self.checkout()
        self.git(checkout, "checkout", "-q", "-b", "other")
        with self.assertRaisesRegex(pr_loop.Stop, "skill did not restore the checked default branch"):
            checkout.verify()


class CheckoutCleanUpTests(CheckoutCase):
    def retained(self, checkout):
        return checkout.path.exists() and f"Retained checkout and evidence: {checkout.path}" in self.told

    def test_a_checkout_with_nothing_to_keep_is_deleted(self):
        checkout = self.checkout()
        checkout.task(self.repo, 7, "draft", HEAD)  # ignored files do not count
        checkout.clean_up()
        self.assertFalse(checkout.path.exists())
        self.assertNotIn(f"Retained checkout and evidence: {checkout.path}", self.told)

    def test_evidence_is_kept(self):
        checkout = self.checkout()
        (checkout.path / ".pr-ready").mkdir()
        checkout.clean_up()
        self.assertTrue(self.retained(checkout))

    def test_uncommitted_work_is_kept(self):
        checkout = self.checkout()
        (checkout.path / "stray.txt").write_text("x")
        checkout.clean_up()
        self.assertTrue(self.retained(checkout))

    def test_a_commit_that_is_not_on_the_remote_is_kept(self):
        checkout = self.checkout()
        self.git(checkout, "commit", "-q", "--allow-empty", "-m", "unpushed")
        checkout.clean_up()
        self.assertTrue(self.retained(checkout))

    def test_a_stash_is_kept(self):
        checkout = self.checkout()
        (checkout.path / "README.txt").write_text("changed\n")
        self.git(checkout, "stash", "push", "-q")
        self.assertEqual("", self.git(checkout, "status", "--porcelain=v1"))
        checkout.clean_up()
        self.assertTrue(self.retained(checkout))


# ---- (E) the whole program, started as a user starts it, against the fake gh/tmux/agents --------------------------

class ProgramTests(unittest.TestCase):
    """One real `python3 scripts/pr_loop.py` process per test; time is real (small intervals), everything else fake."""
    SCRIPT = ROOT / "scripts" / "pr_loop.py"

    def setUp(self):
        self.env = FakeEnv(self)

    def run_program(self, *extra):
        argv = [sys.executable, "-B", str(self.SCRIPT), "7", "--repo", "acme/demo", "--poll-interval", "0.01",
                "--startup-timeout", "2", *extra]
        return subprocess.run(argv, capture_output=True, text=True, timeout=60, cwd=self.env.root)

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

    def managed_checkout(self, proc):
        lines = [line for line in proc.stdout.splitlines() if line.startswith("Managed checkout: ")]
        self.assertEqual(1, len(lines), proc.stdout)
        return Path(lines[0][len("Managed checkout: "):])

    def test_a_pr_goes_from_draft_to_merged(self):
        ready, queued, merged = pr_view_json("ready"), pr_view_json("queued"), pr_view_json("merged")
        self.env.write_gh(calls=[], seq=[], view=pr_view_json("draft"), login="reviewer", comments=[], clone_exit=0)
        self.env.set_pane("%1", enter=[{"gh": {"set_view": ready}, "result": {"outcome": "READY", "reason": "gate passed"}}])
        self.env.set_pane("%2", enter=[{"gh": {"set_seq": [{"view": v} for v in (queued, queued, queued, merged)]},
                                        "result": {"outcome": "ENQUEUED", "reason": "queued for the train"}}])
        proc = self.run_program()
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        self.assertEqual("", proc.stderr)
        self.assertIn("PR #7: merged", proc.stdout.splitlines())
        # Two dispatches, each carrying the task path of its own <checkout>/.pr-loop/<nonce>/ directory.
        checkout = self.managed_checkout(proc)
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
        # Both panes are closed and a clean checkout is deleted.
        self.assertEqual([["kill-pane", "-t", "%1"], ["kill-pane", "-t", "%2"]], self.env.tmux_calls("kill-pane"))
        self.assertFalse(checkout.exists())
        # The runner only reads GitHub.
        self.assertEqual({("pr", "view"), ("repo", "clone")}, {tuple(call[:2]) for call in self.env.gh_calls()})

    def test_a_blocker_stops_the_run_and_keeps_everything_for_inspection(self):
        self.env.set_pane("%1", enter=[{"result": {"outcome": "DRAFT-BLOCKED", "reason": "go test failed in the synthetic gate"}}])
        proc = self.run_program()
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        self.assertRegex(proc.stderr, rf"^pr-loop: PR #7: PR #7 DRAFT-BLOCKED at {HEAD[:12]}: "
                                      r"go test failed in the synthetic gate\n$")
        self.assertEqual(1, len(self.env.tmux_calls("new-session")), "the Ready phase was never dispatched")
        self.assertEqual([], self.env.tmux_calls("kill-pane"), "the pane is retained")
        checkout = self.managed_checkout(proc)
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
        self.assertEqual(1, len(self.env.tmux_calls("new-session")), "the Ready phase was never dispatched")
        self.assertEqual(1, len(self.pastes()))
        self.assertNotIn("PR #7: merged", proc.stdout)
        self.assertEqual([], self.env.tmux_calls("kill-pane"), "the pane is retained")
        self.assertTrue(self.managed_checkout(proc).exists())
        self.assertEqual(0, self.env.tmux()["cli"][0]["rc"])

    def test_a_dry_run_reports_the_phase_and_touches_neither_tmux_nor_the_clone(self):
        proc = self.run_program("--dry-run")
        self.assertEqual((0, "PR #7: draft\n", ""), (proc.returncode, proc.stdout, proc.stderr))
        self.assertEqual([], self.env.tmux()["log"], "tmux was never called")
        self.assertEqual([["pr", "view"]], [call[:2] for call in self.env.gh_calls()])

    def test_a_pr_that_cannot_be_read_stops_without_starting_anything(self):
        self.env.update_gh(seq=[{"exit": 1, "stderr": "synthetic outage"}])
        proc = self.run_program()
        self.assertEqual(1, proc.returncode, proc.stdout + proc.stderr)
        self.assertIn("GitHub read failed 3 consecutive times; no command sent", proc.stderr)
        self.assertEqual([], self.env.tmux()["log"])
        self.assertEqual({("pr", "view")}, {tuple(call[:2]) for call in self.env.gh_calls()})
        self.assertIn("GitHub read failed (2/3)", proc.stdout)
