"""Offline Draft -> Ready transition tests. gh and the gate are faked."""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import mark_ready  # noqa: E402
import issue_gate  # noqa: E402

SHA = "a" * 40
INFO = {"branch": "issue/1-fix", "head_sha": SHA, "issue_resolution": "fixes"}


def view(**kw):
    base = {"number": 9, "state": "OPEN", "isDraft": True, "headRefName": "issue/1-fix",
            "headRefOid": SHA, "mergeable": "MERGEABLE", "url": "https://github.com/O/R/pull/9",
            "body": "Fixes #1\n\nTests pass"}
    base.update(kw)
    return base


class MarkReadyTest(unittest.TestCase):
    def run_mark(self, *, errors=(), views=(), ci="CI_PASSED", confirm=True, resolution="fixes", threads=()):
        calls = []
        with patch.object(mark_ready, "evaluate",
                          return_value=(list(errors), {**INFO, "issue_resolution": resolution})) as ev, \
             patch.object(mark_ready, "command", side_effect=list(views)), \
             patch.object(mark_ready, "unresolved_threads", return_value=list(threads)), \
             patch.object(mark_ready.pr_ci, "inspect", return_value={"status": ci}), \
             patch.object(mark_ready, "execute", side_effect=lambda a, cwd: calls.append(a) or ""):
            result = mark_ready.mark_ready(repo="O/R", issue=1, pr=9, worktree=Path("/tmp"), evidence=Path("/tmp/e.json"),
                                           confirm_complete=confirm)
        return result, calls, ev

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
        result, calls, _ = self.run_mark(views=[view(isDraft=False)])
        self.assertEqual("ALREADY_READY", result["status"])
        self.assertEqual([], calls)

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
                result, calls, _ = self.run_mark(
                    views=[view(body=body), {"isDraft": False, "headRefOid": SHA, "url": "u"}], resolution=resolution)
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
                result, calls, _ = self.run_mark(
                    views=[view(reviewDecision=decision), {"isDraft": False, "headRefOid": SHA, "url": "u"}])
                self.assertEqual("READY_FOR_REVIEW", result["status"])
                self.assertEqual([["gh", "pr", "ready", "9", "-R", "O/R"]], calls)

    def test_pr_view_asks_for_the_body(self):
        with patch.object(mark_ready, "evaluate", return_value=([], INFO)), \
             patch.object(mark_ready, "command", return_value=view(isDraft=False)) as command:
            mark_ready.mark_ready(repo="O/R", issue=1, pr=9, worktree=Path("/tmp"), evidence=Path("/tmp/e.json"),
                                  confirm_complete=True)
        argv = command.call_args_list[0].args[0]
        self.assertIn("body", argv[argv.index("--json") + 1].split(","))
        self.assertIn("reviewDecision", argv[argv.index("--json") + 1].split(","))


    def test_success_marks_ready_and_verifies(self):
        result, calls, _ = self.run_mark(views=[view(), {"isDraft": False, "headRefOid": SHA, "url": "u"}])
        self.assertEqual("READY_FOR_REVIEW", result["status"])
        self.assertEqual([["gh", "pr", "ready", "9", "-R", "O/R"]], calls)
        self.assertFalse(any("merge" in " ".join(c) for c in calls))

    def test_still_draft_after_ready_is_unverified(self):
        result, _, _ = self.run_mark(views=[view(), {"isDraft": True, "headRefOid": SHA, "url": "u"}])
        self.assertEqual("READY_UNVERIFIED", result["status"])


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
