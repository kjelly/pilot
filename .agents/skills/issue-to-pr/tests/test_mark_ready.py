"""Offline Draft -> Ready transition tests. gh and the gate are faked."""
from __future__ import annotations

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
    def run_mark(self, *, errors=(), views=(), ci="CI_PASSED", confirm=True, resolution="fixes"):
        calls = []
        with patch.object(mark_ready, "evaluate",
                          return_value=(list(errors), {**INFO, "issue_resolution": resolution})) as ev, \
             patch.object(mark_ready, "command", side_effect=list(views)), \
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

    def test_pr_view_asks_for_the_body(self):
        with patch.object(mark_ready, "evaluate", return_value=([], INFO)), \
             patch.object(mark_ready, "command", return_value=view(isDraft=False)) as command:
            mark_ready.mark_ready(repo="O/R", issue=1, pr=9, worktree=Path("/tmp"), evidence=Path("/tmp/e.json"),
                                  confirm_complete=True)
        argv = command.call_args_list[0].args[0]
        self.assertIn("body", argv[argv.index("--json") + 1].split(","))

    def test_success_marks_ready_and_verifies(self):
        result, calls, _ = self.run_mark(views=[view(), {"isDraft": False, "headRefOid": SHA, "url": "u"}])
        self.assertEqual("READY_FOR_REVIEW", result["status"])
        self.assertEqual([["gh", "pr", "ready", "9", "-R", "O/R"]], calls)
        self.assertFalse(any("merge" in " ".join(c) for c in calls))

    def test_still_draft_after_ready_is_unverified(self):
        result, _, _ = self.run_mark(views=[view(), {"isDraft": True, "headRefOid": SHA, "url": "u"}])
        self.assertEqual("READY_UNVERIFIED", result["status"])


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
