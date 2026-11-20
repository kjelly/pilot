"""Offline Draft -> Ready transition tests. gh and the gate are faked."""
from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "_shared" / "tests"))
import mark_ready  # noqa: E402
import issue_gate  # noqa: E402
import ready_signal_world as rw  # noqa: E402  (the shared model of the signal's GitHub state; puts ready_signal on sys.path)

ready_signal = rw.ready_signal
SHA = "a" * 40
OLD = "b" * 40
INFO = {"branch": "issue/1-fix", "head_sha": SHA, "issue_resolution": "fixes"}
AFTER = {"isDraft": False, "headRefOid": SHA, "url": "u"}  # what `gh pr view` says after `gh pr ready`
REAL_SIGNAL_RUNTIME = mark_ready.signal_runtime  # the loader itself; MarkReadyTest.setUp replaces it with a refusal


def view(**kw):
    base = {"number": 9, "state": "OPEN", "isDraft": True, "headRefName": "issue/1-fix",
            "headRefOid": SHA, "mergeable": "MERGEABLE", "url": "https://github.com/O/R/pull/9",
            "body": "Fixes #1\n\nTests pass"}
    base.update(kw)
    return base


class MarkReadyTest(unittest.TestCase):
    def setUp(self):
        # Nothing in this class may reach GitHub: a test that gets as far as the signal says which world it runs in.
        refuse = patch.object(mark_ready, "signal_runtime", side_effect=AssertionError("unexpected signal access"))
        refuse.start()
        self.addCleanup(refuse.stop)

    def signal_patch(self, world):
        """The shared signal module and the shared model of GitHub's state, as `mark_ready.signal_runtime` returns them."""
        return patch.object(mark_ready, "signal_runtime", side_effect=None,
                            return_value=(ready_signal, rw.Client(world)))

    def run_mark(self, *, errors=(), views=(), ci="CI_PASSED", confirm=True, resolution="fixes", threads=(), world=None):
        """mark_ready() over faked gate, `gh pr view` answers (`views`) and `gh pr ready`, with the signal's GitHub
        state in `self.world` (a signed-ready PR when the answer is already Ready, an unsigned Draft otherwise).
        Every call that matters is in `self.world.calls()` in order: `command` is a `gh pr view`, `ready` is
        `gh pr ready`, the rest are the signal's reads and writes."""
        calls = []
        self.world = world = world or rw.World(head=SHA)
        answers = list(views)

        def view_answer(argv, **kw):
            world.log("command")
            return answers.pop(0)

        def pr_ready(argv, cwd):
            calls.append(argv)
            world.log("ready")
            world.ready()
            return ""

        with patch.object(mark_ready, "evaluate",
                          return_value=(list(errors), {**INFO, "issue_resolution": resolution})) as ev, \
             patch.object(mark_ready, "command", side_effect=view_answer), \
             patch.object(mark_ready, "unresolved_threads", return_value=list(threads)), \
             patch.object(mark_ready.pr_ci, "inspect", return_value={"status": ci}), \
             patch.object(mark_ready, "execute", side_effect=pr_ready), \
             self.signal_patch(world), rw.read_back_sleeps() as sleeps:
            result = mark_ready.mark_ready(repo="O/R", issue=1, pr=9, worktree=Path("/tmp"), evidence=Path("/tmp/e.json"),
                                           confirm_complete=confirm)
        self.sleeps = sleeps
        return result, calls, ev

    def signed_ready_world(self, **kw):
        world = rw.World(head=SHA, **kw)
        world.signed_ready(producer=ready_signal.ISSUE_TO_PR)
        return world

    def test_requires_explicit_completion_confirmation(self):
        result, calls, ev = self.run_mark(confirm=False)
        self.assertEqual("BLOCKED", result["status"])
        self.assertEqual([], calls)
        ev.assert_not_called()

    def test_ci_must_be_green_on_the_exact_head(self):
        for ci in ("CI_PENDING", "CI_FAILED", "NO_CI_OBSERVED", "STALE_HEAD", "CI_UNKNOWN"):
            result, calls, _ = self.run_mark(views=[view()], ci=ci)
            self.assertEqual("BLOCKED", result["status"], ci)
            self.assertEqual([], calls, ci)

    def test_gate_failure_blocks_and_excludes_own_pr(self):
        result, calls, ev = self.run_mark(errors=["P2 open"])
        self.assertEqual("BLOCKED", result["status"])
        self.assertEqual([], calls)
        self.assertEqual(9, ev.call_args.kwargs["own_pr"])

    def test_head_mismatch_blocks(self):
        result, calls, _ = self.run_mark(views=[view(headRefOid="b" * 40)])
        self.assertEqual("BLOCKED", result["status"])
        self.assertEqual([], calls)

    def test_conflicts_block(self):
        result, calls, _ = self.run_mark(views=[view(mergeable="CONFLICTING")])
        self.assertEqual("BLOCKED", result["status"])
        self.assertEqual([], calls)

    def test_already_ready_is_a_noop(self):
        # A Ready PR that carries a valid signal: nothing is run or written (only the reads of the check).
        for producer in ready_signal.PRODUCERS:
            with self.subTest(producer):
                world = rw.World(head=SHA)
                world.signed_ready(producer=producer)
                result, calls, _ = self.run_mark(views=[view(isDraft=False)], world=world)
                self.assertEqual("ALREADY_READY", result["status"])
                self.assertEqual([], calls)
                self.assertEqual(["command", "user", "pr-view", "timeline"], world.calls())

    def test_body_must_agree_with_the_evidence_resolution(self):
        # The evidence (or the body) can change after create_pr.py checked it: re-check before `gh pr ready`.
        cases = (("partial", "Fixes #1\n\nTests pass", "must not close #1"),
                 ("partial", "Closes O/R#1", "must not close #1"),
                 ("partial", "Partial fix, tests pass", "must reference #1"),
                 ("fixes", "Refs #1\n\nTests pass", "closing keyword"),
                 ("fixes", "", "closing keyword"))
        for resolution, body, needle in cases:
            with self.subTest(resolution=resolution, body=body):
                result, calls, _ = self.run_mark(views=[view(body=body)], resolution=resolution)
                self.assertEqual("BLOCKED", result["status"])
                self.assertTrue(any("PR body" in b and needle in b for b in result["blockers"]), result)
                self.assertEqual([], calls)

    def test_body_that_agrees_with_the_resolution_marks_ready(self):
        for resolution, body in (("partial", "Refs #1\n\nTests pass"), ("fixes", "Fixes #1\n\nTests pass")):
            with self.subTest(resolution=resolution):
                result, calls, _ = self.run_mark(views=[view(body=body), AFTER], resolution=resolution)
                self.assertEqual("READY_FOR_REVIEW", result["status"])
                self.assertEqual([["gh", "pr", "ready", "9", "-R", "O/R"]], calls)

    def test_unresolved_review_thread_blocks(self):
        # pr-review-merge returns a PR with an unresolved thread to Draft; Ready here would bounce.
        thread = "https://github.com/O/R/pull/9#discussion_r1"
        result, calls, _ = self.run_mark(views=[view()], threads=[thread])
        self.assertEqual("BLOCKED", result["status"])
        self.assertTrue(any(thread in b and "resolve it" in b for b in result["blockers"]), result)
        self.assertEqual([], calls)

    def test_changes_requested_blocks_and_points_at_pr_ready(self):
        result, calls, _ = self.run_mark(views=[view(reviewDecision="CHANGES_REQUESTED")])
        self.assertEqual("BLOCKED", result["status"])
        self.assertTrue(any("CHANGES_REQUESTED" in b and "pr-ready" in b for b in result["blockers"]), result)
        self.assertEqual([], calls)

    def test_other_review_decisions_do_not_block(self):
        # gh prints "" when the repository requires no review (kjelly/pilot#201, gh 2.103.3).
        for decision in ("", "REVIEW_REQUIRED", "APPROVED", None):
            with self.subTest(decision=decision):
                result, calls, _ = self.run_mark(views=[view(reviewDecision=decision), AFTER])
                self.assertEqual("READY_FOR_REVIEW", result["status"])
                self.assertEqual([["gh", "pr", "ready", "9", "-R", "O/R"]], calls)

    def test_pr_view_asks_for_the_body(self):
        with patch.object(mark_ready, "evaluate", return_value=([], INFO)), \
             patch.object(mark_ready, "signal_problem", return_value=None), \
             patch.object(mark_ready, "command", return_value=view(isDraft=False)) as command:
            mark_ready.mark_ready(repo="O/R", issue=1, pr=9, worktree=Path("/tmp"), evidence=Path("/tmp/e.json"),
                                  confirm_complete=True)
        argv = command.call_args_list[0].args[0]
        self.assertIn("body", argv[argv.index("--json") + 1].split(","))
        self.assertIn("reviewDecision", argv[argv.index("--json") + 1].split(","))


    def test_similar_scan_report_rides_along(self):
        scan = {"enforced": False, "status": "warn", "problems": ["similar_defect_scan is absent"]}
        for errors, views, status in (((), [view(), AFTER], "READY_FOR_REVIEW"),
                                      (("gate blocker",), [], "BLOCKED")):
            world = rw.World(head=SHA)
            with self.subTest(status=status), \
                 patch.object(mark_ready, "evaluate", return_value=(list(errors), {**INFO, "similar_defect_scan": scan})), \
                 patch.object(mark_ready, "command", side_effect=list(views)), \
                 patch.object(mark_ready, "unresolved_threads", return_value=[]), \
                 patch.object(mark_ready.pr_ci, "inspect", return_value={"status": "CI_PASSED"}), \
                 patch.object(mark_ready, "execute", side_effect=lambda a, cwd: world.ready() and ""), \
                 self.signal_patch(world):
                result = mark_ready.mark_ready(repo="O/R", issue=1, pr=9, worktree=Path("/tmp"),
                                               evidence=Path("/tmp/e.json"), confirm_complete=True)
            self.assertEqual(status, result["status"])
            self.assertEqual(scan, result["similar_defect_scan"])

    def test_success_marks_ready_and_verifies(self):
        result, calls, _ = self.run_mark(views=[view(), AFTER])
        self.assertEqual("READY_FOR_REVIEW", result["status"])
        self.assertEqual([["gh", "pr", "ready", "9", "-R", "O/R"]], calls)
        self.assertFalse(any("merge" in " ".join(c) for c in calls))

    def test_still_draft_after_ready_is_unverified(self):
        result, _, _ = self.run_mark(views=[view(), {"isDraft": True, "headRefOid": SHA, "url": "u"}])
        self.assertEqual("READY_UNVERIFIED", result["status"])
        # Ready was not confirmed: no signal is written for it.
        self.assertEqual(["command", "label-exists", "user", "pr-view", "ready", "command"], self.world.calls())

    # ---- the pr-ready-verified signal: prepared before `gh pr ready`, written and read back after it ----

    def test_ready_for_review_writes_signal(self):
        result, calls, _ = self.run_mark(views=[view(), AFTER])
        self.assertEqual("READY_FOR_REVIEW", result["status"])
        self.assertEqual({"label": rw.LABEL, "head_sha": SHA, "producer": "issue-to-pr"}, result["ready_signal"])
        # prepare (label, viewer, stale-label check) < gh pr ready < post-action view < comment < label < read-back
        self.assertEqual(["command", "label-exists", "user", "pr-view", "ready", "command",
                          "comment", "add-label", "pr-view", "timeline"], self.world.calls())
        events = self.world.s["events"]
        self.assertEqual(["ready_for_review", "commented", "labeled"], [e["event"] for e in events])
        self.assertEqual(ready_signal.marker_comment(SHA, "issue-to-pr"), events[1]["body"])
        # What every consumer will say about the PR the script left behind.
        result_state = ready_signal.assess(SHA, self.world.view_labels(), events, rw.VIEWER)
        self.assertEqual(("valid", SHA, "issue-to-pr"), (result_state.state, result_state.marker_head, result_state.producer))

    def test_a_missing_label_blocks_before_gh_pr_ready(self):
        result, calls, _ = self.run_mark(views=[view()], world=rw.World(head=SHA).label_state("missing"))
        self.assertEqual("BLOCKED", result["status"])
        self.assertEqual([], calls, "gh pr ready must not run")
        self.assertEqual(["command", "label-exists"], self.world.calls())
        (blocker,) = result["blockers"]
        self.assertIn("(Ready not invoked)", blocker)
        self.assertIn(f"the repository has no {rw.LABEL} label", blocker)
        self.assertIn("a maintainer must create it once", blocker)

    def test_a_failing_label_check_blocks_before_gh_pr_ready(self):
        # A server error is not "the label exists" and not "the label is missing": nothing is invoked.
        client_error = rw.Client(rw.World()).GitHubError
        world = rw.World(head=SHA).label_state("error")
        with self.assertRaises(client_error):  # prepare does not swallow it; mark_ready turns it into BLOCKED
            ready_signal.prepare(rw.Client(world), rw.Client(world).Repo.parse("O/R"), 9)
        result, calls, _ = self.run_mark(views=[view()], world=rw.World(head=SHA).label_state("error"))
        self.assertEqual("BLOCKED", result["status"])
        self.assertEqual([], calls)
        self.assertIn("injected failure of label-exists", result["blockers"][0])

    def test_a_stale_label_is_removed_from_the_draft_before_gh_pr_ready(self):
        world = self.signed_ready_world()
        world.to_draft()  # the label from the earlier Ready epoch stays on the Draft
        result, calls, _ = self.run_mark(views=[view(), AFTER], world=world)
        self.assertEqual("READY_FOR_REVIEW", result["status"])
        log = world.calls()
        self.assertLess(log.index("remove-label"), log.index("ready"))
        self.assertEqual(["command", "label-exists", "user", "pr-view", "remove-label", "pr-view", "ready", "command",
                          "comment", "add-label", "pr-view", "timeline"], log)
        # The label the script added after Ready is a new event, after the new Ready transition: not stale-epoch.
        self.assertEqual("valid", ready_signal.assess(SHA, world.view_labels(), world.s["events"], rw.VIEWER).state)

    def test_a_stale_label_that_cannot_be_removed_blocks_before_gh_pr_ready(self):
        world = self.signed_ready_world().fail("remove-label")
        world.to_draft()
        result, calls, _ = self.run_mark(views=[view()], world=world)
        self.assertEqual("BLOCKED", result["status"])
        self.assertEqual([], calls)
        self.assertNotIn("ready", world.calls())
        self.assertIn("could not be prepared (Ready not invoked)", result["blockers"][0])

    def test_a_signal_that_cannot_be_written_leaves_ready_unverified(self):
        for failing in ("comment", "add-label"):
            with self.subTest(failing):
                result, calls, _ = self.run_mark(views=[view(), AFTER], world=rw.World(head=SHA).fail(failing))
                self.assertEqual("READY_UNVERIFIED", result["status"])
                self.assertEqual([["gh", "pr", "ready", "9", "-R", "O/R"]], calls, "Ready was invoked")
                self.assertNotIn("ready_signal", result)
                (blocker,) = result["blockers"]
                self.assertIn(f"Ready invoked and verified, but the {rw.LABEL} signal was not confirmed", blocker)
                self.assertIn(f"injected failure of {failing}", blocker)
                self.assertIn("the PR is Ready without the signal; convert it to Draft and run mark_ready.py again", blocker)
                self.assertEqual([], self.world.label_names(), "no label without the whole signal")

    def test_a_signal_that_never_reads_back_leaves_ready_unverified_after_the_bound(self):
        world = rw.World(head=SHA)
        world.s["flags"]["lag"] = ready_signal.READ_TRIES
        result, _, _ = self.run_mark(views=[view(), AFTER], world=world)
        self.assertEqual("READY_UNVERIFIED", result["status"])
        self.assertIn(f"does not read back as valid after {ready_signal.READ_TRIES} reads", result["blockers"][0])
        self.assertEqual(ready_signal.READ_TRIES, world.calls().count("timeline"))
        self.assertEqual([ready_signal.READ_INTERVAL] * (ready_signal.READ_TRIES - 1), self.sleeps)

    def test_already_ready_without_a_valid_signal_is_ready_unverified(self):
        def unsigned_created_ready():
            world = rw.World(head=SHA)
            world.signal()  # a label and a marker, but the PR never went Draft -> Ready
            return world

        def stale():
            world = rw.World(head=OLD)
            world.signed_ready(producer="issue-to-pr")
            world.s["head"] = SHA  # pushed after the signal
            return world

        def by_someone_else():
            world = rw.World(head=SHA)
            world.ready()
            world.comment(ready_signal.marker_comment(SHA, "issue-to-pr"))
            world.label(actor=rw.OTHER)
            return world

        def marker_by_someone_else():
            world = rw.World(head=SHA)
            world.ready()
            world.comment(ready_signal.marker_comment(SHA, "issue-to-pr"), actor=rw.OTHER)
            world.label()
            return world

        def draft_epoch_leftover():
            world = self.signed_ready_world()
            world.to_draft()
            world.ready()  # made Ready again by hand: the label is from the earlier epoch
            return world

        def converted_to_draft_after_ready():
            world = self.signed_ready_world()
            world.to_draft()  # the timeline ends in a Draft conversion while the view already says Ready: read lag
            return world

        def label_removed():
            world = self.signed_ready_world()
            world.label(add=False)
            return world

        def timeline_down():
            return self.signed_ready_world().fail("timeline")

        cases = {
            "never signed": (lambda: (lambda w: (w.ready(), w)[1])(rw.World(head=SHA)), "absent", "does not carry"),
            "created Ready": (unsigned_created_ready, "absent", "no Ready transition from Draft"),
            "pushed after the signal": (stale, "stale", f"written for HEAD {OLD[:12]}, the PR HEAD is {SHA[:12]}"),
            "label by another account": (by_someone_else, "untrusted", f"added by {rw.OTHER}"),
            "marker by another account": (marker_by_someone_else, "absent", f"no signal comment by {rw.VIEWER}"),
            "label from an earlier epoch": (draft_epoch_leftover, "stale-epoch", "before the PR's last Ready transition"),
            "label removed": (label_removed, "absent", "does not carry"),
            "converted to Draft after the Ready transition": (converted_to_draft_after_ready, "inconsistent",
                                                              "converted to Draft after its last Ready transition"),
            "timeline unreadable": (timeline_down, "cannot be read", "injected failure of timeline"),
        }
        for name, (build, state, why) in cases.items():
            with self.subTest(name):
                world = build()
                result, calls, _ = self.run_mark(views=[view(isDraft=False)], world=world)
                self.assertEqual("READY_UNVERIFIED", result["status"])
                self.assertEqual([], calls, "nothing is invoked")
                (blocker,) = result["blockers"]
                self.assertIn(state, blocker)
                self.assertIn(why, blocker)
                self.assertIn("The PR is already Ready but", blocker)
                self.assertIn("convert it to Draft and run mark_ready.py again", blocker)
                for write in ("comment", "add-label", "remove-label", "ready"):
                    self.assertNotIn(write, world.calls(), "a PR that is already Ready is never written to")

    def run_main(self, world, views):
        out = io.StringIO()
        with patch.object(mark_ready, "evaluate", return_value=([], INFO)), \
             patch.object(mark_ready, "command", side_effect=list(views)), \
             patch.object(mark_ready, "unresolved_threads", return_value=[]), \
             patch.object(mark_ready.pr_ci, "inspect", return_value={"status": "CI_PASSED"}), \
             patch.object(mark_ready, "execute", side_effect=lambda a, cwd: world.ready() and ""), \
             self.signal_patch(world), patch("time.sleep"), contextlib.redirect_stdout(out):
            code = mark_ready.main(["--repo", "O/R", "--issue", "1", "--pr", "9", "--worktree", "/tmp",
                                    "--evidence", "/tmp/e.json", "--confirm-complete"])
        return code, json.loads(out.getvalue())

    def test_the_exit_code_follows_the_signal(self):
        code, result = self.run_main(rw.World(head=SHA), [view(), AFTER])
        self.assertEqual((0, "READY_FOR_REVIEW"), (code, result["status"]))
        code, result = self.run_main(self.signed_ready_world(), [view(isDraft=False)])
        self.assertEqual((0, "ALREADY_READY"), (code, result["status"]))
        code, result = self.run_main(rw.World(head=SHA).fail("add-label"), [view(), AFTER])
        self.assertEqual((2, "READY_UNVERIFIED"), (code, result["status"]))
        unsigned = rw.World(head=SHA)
        unsigned.ready()
        code, result = self.run_main(unsigned, [view(isDraft=False)])
        self.assertEqual((2, "READY_UNVERIFIED"), (code, result["status"]))
        code, result = self.run_main(rw.World(head=SHA).label_state("missing"), [view()])
        self.assertEqual((2, "BLOCKED"), (code, result["status"]))

    def test_the_signal_modules_load_by_path_and_a_failed_load_is_a_blocker_not_a_traceback(self):
        sources = (mark_ready.READY_SIGNAL_PATH, mark_ready.GH_RUNTIME_PATH)
        # The real loader finds both modules where the skill bundle keeps them.
        with patch.dict(sys.modules), patch.object(mark_ready, "signal_runtime", REAL_SIGNAL_RUNTIME):
            for name in ("ready_signal", "gh_runtime"):
                sys.modules.pop(name, None)
            signal, client = mark_ready.signal_runtime()
            self.assertEqual((sources[0], sources[1]), (Path(signal.__file__), Path(client.__file__)))
            self.assertEqual(rw.LABEL, signal.LABEL)
        # A module that is missing, or does not load, refuses.
        with tempfile.TemporaryDirectory() as tmp:
            broken = Path(tmp) / "broken.py"
            broken.write_text("raise RuntimeError('boom')\n")
            for name, path, needle in (("missing", Path(tmp) / "nowhere.py", "is missing"),
                                       ("raises on import", broken, "cannot be loaded (RuntimeError)")):
                with self.subTest(name), patch.dict(sys.modules), patch.object(mark_ready, "READY_SIGNAL_PATH", path), \
                     patch.object(mark_ready, "signal_runtime", REAL_SIGNAL_RUNTIME):
                    sys.modules.pop("ready_signal", None)
                    with self.assertRaises(issue_gate.GateError) as raised:
                        mark_ready.signal_runtime()
                    self.assertIn(needle, str(raised.exception))
                    self.assertNotIn("boom", str(raised.exception))
                    self.assertNotIn("ready_signal", sys.modules)

    def test_a_signal_module_that_cannot_load_blocks_before_gh_pr_ready(self):
        calls = []
        out = io.StringIO()
        with patch.object(mark_ready, "evaluate", return_value=([], INFO)), \
             patch.object(mark_ready, "command", side_effect=[view()]), \
             patch.object(mark_ready, "unresolved_threads", return_value=[]), \
             patch.object(mark_ready.pr_ci, "inspect", return_value={"status": "CI_PASSED"}), \
             patch.object(mark_ready, "execute", side_effect=lambda a, cwd: calls.append(a) or ""), \
             patch.object(mark_ready, "signal_runtime", side_effect=issue_gate.GateError("the shared ready-signal module is missing")), \
             contextlib.redirect_stdout(out):
            code = mark_ready.main(["--repo", "O/R", "--issue", "1", "--pr", "9", "--worktree", "/tmp",
                                    "--evidence", "/tmp/e.json", "--confirm-complete"])
        self.assertEqual(2, code)
        self.assertEqual("BLOCKED", json.loads(out.getvalue())["status"])
        self.assertIn("ready-signal module is missing", json.loads(out.getvalue())["blockers"][0])
        self.assertEqual([], calls)


# Real `gh api graphql` answers (gh 2.103.3, 2026-10-31) to mark_ready.THREADS_QUERY.
CLI_13013 = ('{"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":['
             '{"isResolved":true,"comments":{"nodes":[{"url":"https://github.com/cli/cli/pull/13013#discussion_r2978871405"}]}},'
             '{"isResolved":false,"comments":{"nodes":[{"url":"https://github.com/cli/cli/pull/13013#discussion_r2978871421"}]}},'
             '{"isResolved":true,"comments":{"nodes":[{"url":"https://github.com/cli/cli/pull/13013#discussion_r2978871432"}]}}],'
             '"pageInfo":{"hasNextPage":false,"endCursor":"Y3Vyc29yOnYyOpK0MjAyNi0wMy0yNFQwNDowOToyOFrOdk2Aiw=="}}}}}}')
PILOT_201 = '{"data":{"repository":{"pullRequest":{"reviewThreads":{"nodes":[],"pageInfo":{"hasNextPage":false,"endCursor":null}}}}}}'
# The query those answers belong to; a changed query needs new captures.
CAPTURED_QUERY = ("query($owner:String!,$repo:String!,$number:Int!,$cursor:String){repository(owner:$owner,name:$repo){"
                  "pullRequest(number:$number){reviewThreads(first:100,after:$cursor){nodes{isResolved comments(first:1)"
                  "{nodes{url}}} pageInfo{hasNextPage endCursor}}}}}")


def page(nodes, *, more=False, cursor=None):
    return {"data": {"repository": {"pullRequest": {"reviewThreads": {
        "nodes": nodes, "pageInfo": {"hasNextPage": more, "endCursor": cursor}}}}}}


def thread(resolved, url="https://github.com/O/R/pull/9#discussion_r1"):
    return {"isResolved": resolved, "comments": {"nodes": [{"url": url}]}}


class UnresolvedThreadsTest(unittest.TestCase):
    def lookup(self, *answers):
        with patch.object(mark_ready, "command", side_effect=list(answers)) as command:
            return mark_ready.unresolved_threads("O/R", 9), [c.args[0] for c in command.call_args_list]

    def test_captures_belong_to_this_query(self):
        self.assertEqual(CAPTURED_QUERY, mark_ready.THREADS_QUERY)

    def test_real_answers(self):
        self.assertEqual([], self.lookup(json.loads(PILOT_201))[0])
        found, argv = self.lookup(json.loads(CLI_13013))
        self.assertEqual(["https://github.com/cli/cli/pull/13013#discussion_r2978871421"], found)
        self.assertEqual(["gh", "api", "graphql", "-f", f"query={CAPTURED_QUERY}", "-f", "owner=O", "-f", "repo=R",
                          "-F", "number=9"], argv[0])

    def test_every_page_is_read(self):
        found, argv = self.lookup(page([thread(True)], more=True, cursor="c1"),
                                  page([thread(False, "https://github.com/O/R/pull/9#discussion_r2")]))
        self.assertEqual(["https://github.com/O/R/pull/9#discussion_r2"], found)
        self.assertEqual(["-f", "cursor=c1"], argv[1][-2:])

    def test_a_thread_without_comments_still_counts(self):
        found, _ = self.lookup(page([{"isResolved": False, "comments": {"nodes": []}}]))
        self.assertEqual(["(a thread without comments)"], found)

    def test_anything_short_of_a_complete_answer_fails_closed(self):
        for answers in ([page([], more=True, cursor="c1"), page([], more=True, cursor="c1")],  # cursor stuck
                        [page([], more=True, cursor=None)],
                        [page([{"isResolved": "false", "comments": {"nodes": []}}])],
                        [page([{"comments": {"nodes": []}}])],
                        [{"data": {"repository": {"pullRequest": None}}}],
                        [{"errors": [{"type": "NOT_FOUND"}]}],
                        [[]]):
            with self.subTest(answers=answers):
                with self.assertRaises(issue_gate.GateError):
                    self.lookup(*answers)

    def test_a_failed_lookup_blocks_the_cli(self):
        # The real gh answer for a missing PR is exit 1 (command raises); main reports BLOCKED, exit 2.
        with patch.object(mark_ready, "evaluate", return_value=([], INFO)), \
             patch.object(mark_ready, "command", side_effect=[
                 view(), issue_gate.GateError("gh: Could not resolve to a PullRequest with the number of 9.")]), \
             patch.object(mark_ready, "execute") as execute, \
             patch("sys.stdout"):
            rc = mark_ready.main(["--repo", "O/R", "--issue", "1", "--pr", "9", "--worktree", "/tmp",
                                  "--evidence", "/tmp/e.json", "--confirm-complete"])
        self.assertEqual(2, rc)
        execute.assert_not_called()


class OwnPrDuplicateTest(unittest.TestCase):
    def gh(self, own):
        def fake(cmd, **kw):
            if cmd[:3] == ["gh", "issue", "view"]:
                return {"number": 1, "state": "OPEN", "url": "u", "closedByPullRequestsReferences": [{"number": 9, "url": "p9"}]}
            if "--head" in cmd:
                return [{"number": 9, "url": "p9"}]
            return [{"number": 9, "url": "p9", "headRefName": "issue/1-fix", "body": "Fixes #1",
                     "closingIssuesReferences": [{"number": 1}]}]
        return patch.object(issue_gate, "command", side_effect=fake)

    def test_own_pr_is_not_a_duplicate(self):
        with self.gh(9):
            self.assertEqual([], issue_gate.gh_issue_and_duplicates("O/R", 1, "issue/1-fix", own_pr=9))

    def test_other_pr_is_still_a_duplicate(self):
        with self.gh(9):
            errors = issue_gate.gh_issue_and_duplicates("O/R", 1, "issue/1-fix", own_pr=10)
        self.assertTrue(any("duplicate" in e.lower() or "linked closing" in e for e in errors))
        self.assertTrue(any("issue branch" in e for e in errors))

    def test_without_own_pr_nothing_changes(self):
        with self.gh(9):
            self.assertTrue(issue_gate.gh_issue_and_duplicates("O/R", 1, "issue/1-fix"))


if __name__ == "__main__":
    unittest.main()
