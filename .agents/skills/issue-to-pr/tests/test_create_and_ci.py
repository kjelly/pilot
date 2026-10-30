"""Offline Draft-first PR lifecycle tests. The fake gh never contacts GitHub."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import create_pr  # noqa: E402
import pr_ci      # noqa: E402


class CreatePRTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.worktree = self.root / "wt"
        self.worktree.mkdir()
        self.state = self.root / "state"
        self.state.mkdir()
        self.evidence = self.state / "evidence.json"
        self.evidence.write_text(json.dumps({"base_branch": "main"}))
        self.body = self.state / "body.md"
        self.body.write_text("Fixes #123\n\n## Tests\n- regression passed\n")
        self.sha = "a" * 40
        self.info = {"branch": "issue/123-fix", "head_sha": self.sha}

    def invoke(self, *, draft: bool = True):
        return create_pr.create(repo="OWNER/REPO", issue=123,
                                worktree=self.worktree, evidence=self.evidence,
                                title="fix: issue 123 proper fix", body_file=self.body,
                                draft=draft)

    def test_default_is_draft(self):
        emitted = []
        def fake_exec(args, cwd):
            emitted.append(args)
            return "https://github.com/OWNER/REPO/pull/9"
        with patch.object(create_pr, "evaluate", return_value=([], self.info)), \
             patch.object(create_pr, "execute", side_effect=fake_exec), \
             patch.object(create_pr, "check_pr", return_value={"number": 9, "url": "https://github.com/OWNER/REPO/pull/9"}):
            result = self.invoke()
        self.assertEqual("DRAFT_PR_CREATED", result["status"])
        self.assertEqual(True, result["draft"])
        self.assertTrue(any(a[:2] == ["gh", "pr"] and a[2] == "create" for a in emitted))
        self.assertTrue(any("--draft" in a for a in emitted))
        self.assertTrue(any(a[:2] == ["git", "push"] for a in emitted))

    def test_ready_is_explicit_opt_in(self):
        emitted = []
        with patch.object(create_pr, "evaluate", return_value=([], self.info)), \
             patch.object(create_pr, "execute", side_effect=lambda a, cwd: emitted.append(a) or ""), \
             patch.object(create_pr, "check_pr", return_value={"number": 9, "url": "https://github.com/OWNER/REPO/pull/9"}):
            result = self.invoke(draft=False)
        self.assertEqual("READY_PR_CREATED", result["status"])
        self.assertFalse(any("--draft" in a for a in emitted))

    def test_cli_flag_ready_maps_to_non_draft(self):
        with patch.object(create_pr, "create", return_value={"status": "READY_PR_CREATED"}) as create:
            create_pr.main(["--repo", "O/R", "--issue", "1", "--worktree", "/w", "--evidence", "/e",
                            "--title", "t" * 10, "--body-file", "/b", "--ready"])
        self.assertIs(create.call_args.kwargs["draft"], False)
        with patch.object(create_pr, "create", return_value={"status": "DRAFT_PR_CREATED"}) as create:
            create_pr.main(["--repo", "O/R", "--issue", "1", "--worktree", "/w", "--evidence", "/e",
                            "--title", "t" * 10, "--body-file", "/b"])
        self.assertIs(create.call_args.kwargs["draft"], True)

    def test_gate_failure_never_pushes(self):
        with patch.object(create_pr, "evaluate", return_value=(["P2 blocker"], self.info)), \
             patch.object(create_pr, "execute") as execute:
            result = self.invoke()
        self.assertEqual("BLOCKED", result["status"])
        execute.assert_not_called()

    def test_post_push_gate_failure_never_creates_pr(self):
        actions = []
        with patch.object(create_pr, "evaluate", side_effect=[([], self.info), (["remote SHA mismatch"], self.info)]), \
             patch.object(create_pr, "execute", side_effect=lambda a, cwd: actions.append(a) or ""):
            result = self.invoke()
        self.assertEqual("BLOCKED_AFTER_PUSH", result["status"])
        self.assertEqual(1, len(actions))
        self.assertEqual("git", actions[0][0])

    def test_api_failure_after_attempt_is_uncertain(self):
        with patch.object(create_pr, "evaluate", return_value=([], self.info)), \
             patch.object(create_pr, "execute", side_effect=["", create_pr.GateError("API timeout")]):
            result = self.invoke()
        self.assertEqual("CREATE_UNCERTAIN", result["status"])

    def test_verify_state_must_match_requested_draft_flag(self):
        pr = {"number": 9, "state": "OPEN", "url": "https://github.com/OWNER/REPO/pull/9",
              "isDraft": False, "headRefName": "issue/123-fix", "headRefOid": self.sha,
              "baseRefName": "main", "body": "Fixes #123"}
        with patch.object(create_pr, "command", return_value=pr):
            with self.assertRaisesRegex(create_pr.GateError, "Draft-state"):
                create_pr.check_pr("OWNER/REPO", "issue/123-fix", "main", self.sha,
                                   draft=True, issue=123)

    def partial(self, body: str):
        self.evidence.write_text(json.dumps({"base_branch": "main", "issue_resolution": "partial"}))
        self.body.write_text(body + "\n\n## Tests\n- regression passed\n")

    def test_partial_resolution_must_not_close_the_issue(self):
        for body in ("Fixes #123", "closes OWNER/REPO#123", "Resolved: https://github.com/OWNER/REPO/issues/123"):
            with self.subTest(body=body), patch.object(create_pr, "execute") as execute:
                self.partial(body)
                with self.assertRaisesRegex(create_pr.GateError, "must not close"):
                    self.invoke()
                execute.assert_not_called()

    def test_partial_resolution_must_reference_the_issue(self):
        for body in ("Partial fix.", "Refs #1234", "Refs `#123`", "Refs foo#123"):
            with self.subTest(body=body):
                self.partial(body)
                with self.assertRaisesRegex(create_pr.GateError, "must reference #123"):
                    self.invoke()

    def test_partial_resolution_with_reference_creates_and_verifies(self):
        self.partial("Refs #123: the retry claim is disputed on the Issue. Do not write `Fixes #123` here.")
        with patch.object(create_pr, "evaluate", return_value=([], self.info)), \
             patch.object(create_pr, "execute", return_value=""), \
             patch.object(create_pr, "check_pr", return_value={"number": 9, "url": "u"}) as check:
            result = self.invoke()
        self.assertEqual("DRAFT_PR_CREATED", result["status"])
        self.assertEqual("partial", check.call_args.kwargs["resolution"])

    def test_default_resolution_still_requires_a_closing_keyword(self):
        self.body.write_text("Refs #123\n\n## Tests\n- regression passed\n")
        with self.assertRaisesRegex(create_pr.GateError, "closing keyword"):
            self.invoke()

    def test_created_partial_pr_that_closes_the_issue_is_rejected(self):
        pr = {"number": 9, "state": "OPEN", "url": "https://github.com/OWNER/REPO/pull/9",
              "isDraft": True, "headRefName": "issue/123-fix", "headRefOid": self.sha,
              "baseRefName": "main", "body": "Closes #123"}
        with patch.object(create_pr, "command", return_value=pr):
            with self.assertRaisesRegex(create_pr.GateError, "must not close"):
                create_pr.check_pr("OWNER/REPO", "issue/123-fix", "main", self.sha,
                                   draft=True, issue=123, resolution="partial")
            pr["body"] = "Refs OWNER/REPO#123"
            self.assertEqual(9, create_pr.check_pr("OWNER/REPO", "issue/123-fix", "main", self.sha,
                                                   draft=True, issue=123, resolution="partial")["number"])


class CiTest(unittest.TestCase):
    def test_all_pass(self):
        self.assertEqual("PASS", pr_ci.classify([{"bucket": "pass", "state": "SUCCESS"}]))

    def test_fail_blocks(self):
        self.assertEqual("FAIL", pr_ci.classify([{"bucket": "fail", "state": "FAILURE"}]))

    def test_pending_blocks(self):
        self.assertEqual("PENDING_OR_SKIPPED", pr_ci.classify([{"bucket": "pending", "state": "IN_PROGRESS"}]))

    def test_skipping_not_treated_as_success(self):
        self.assertEqual("PENDING_OR_SKIPPED", pr_ci.classify([{"bucket": "skipping", "state": "SKIPPED"}]))

    def test_skipped_job_does_not_block_when_something_really_passed(self):
        self.assertEqual("PASS", pr_ci.classify([{"bucket": "pass", "state": "SUCCESS"},
                                                 {"bucket": "skipping", "state": "SKIPPED"}]))

    def test_skipped_job_never_hides_failure_or_pending(self):
        self.assertEqual("FAIL", pr_ci.classify([{"bucket": "fail", "state": "FAILURE"},
                                                 {"bucket": "skipping", "state": "SKIPPED"}]))
        self.assertEqual("PENDING_OR_SKIPPED", pr_ci.classify([{"bucket": "pass", "state": "SUCCESS"},
                                                               {"bucket": "pending", "state": "IN_PROGRESS"},
                                                               {"bucket": "skipping", "state": "SKIPPED"}]))

    def test_all_skipped_is_not_verification(self):
        self.assertEqual("PENDING_OR_SKIPPED", pr_ci.classify([{"bucket": "skipping", "state": "SKIPPED"},
                                                               {"bucket": "skipping", "state": "SKIPPED"}]))

    def test_pr_ci_head_bound_success(self):
        sha = "a" * 40
        view = {"number": 9, "state": "OPEN", "isDraft": False,
                "headRefOid": sha, "url": "https://github.com/OWNER/REPO/pull/9"}
        with patch.object(pr_ci, "command", return_value=view), \
             patch.object(pr_ci, "checks", side_effect=[[{"name": "ci", "bucket": "pass"}],
                                                        [{"name": "ci", "bucket": "pass"}]]):
            self.assertEqual("CI_PASSED", pr_ci.inspect("OWNER/REPO", 9, sha)["status"])

    def test_pr_ci_checks_a_draft_pr(self):
        sha = "a" * 40
        view = {"number": 9, "state": "OPEN", "isDraft": True,
                "headRefOid": sha, "url": "https://github.com/OWNER/REPO/pull/9"}
        with patch.object(pr_ci, "command", return_value=view), \
             patch.object(pr_ci, "checks", side_effect=[[{"name": "ci", "bucket": "pending"}],
                                                        [{"name": "ci", "bucket": "pending"}]]):
            result = pr_ci.inspect("OWNER/REPO", 9, sha)
        self.assertEqual("CI_PENDING", result["status"])
        self.assertIs(result["draft"], True)

    def test_pr_ci_head_mismatch_does_not_check_ci(self):
        with patch.object(pr_ci, "command", return_value={"number": 9, "state": "OPEN", "isDraft": False,
                                                      "headRefOid": "b" * 40}), \
             patch.object(pr_ci, "checks") as checks:
            self.assertEqual("STALE_HEAD", pr_ci.inspect("OWNER/REPO", 9, "a" * 40)["status"])
        checks.assert_not_called()

    def test_no_ci_not_reported_as_pass(self):
        with patch.object(pr_ci, "command", return_value={"number": 9, "state": "OPEN", "isDraft": False,
                                                      "headRefOid": "a" * 40}), \
             patch.object(pr_ci, "checks", side_effect=[[], []]):
            self.assertEqual("NO_CI_OBSERVED", pr_ci.inspect("OWNER/REPO", 9, "a" * 40)["status"])


FAKE_GH = """#!/usr/bin/env python3
import os, sys
sys.stdout.write(os.environ.get("FAKE_OUT", ""))
sys.stderr.write(os.environ.get("FAKE_ERR", ""))
sys.exit(int(os.environ.get("FAKE_RC", "0")))
"""


# gh 2.103.3 on a branch without required checks, `gh pr checks <n> --required --json ...`:
# exit 1, nothing on stdout, exactly this line on stderr (real capture, branch name as printed).
REAL_NO_REQUIRED = "no required checks reported on the 'chore/pr-ready-dispute-review-comments' branch\n"
PHRASE_NAME = "Build (no required checks reported)"
PHRASE_FAILURE = json.dumps([{"name": PHRASE_NAME, "state": "FAILURE", "bucket": "fail", "link": "https://x"}])


class RequiredChecksQueryTest(unittest.TestCase):
    """`gh pr checks --required` prints plain text, not JSON, without branch protection; that one
    failure means "no required checks". Nothing else may be read that way."""

    def run_checks(self, *, required, rc, out="", err=""):
        with tempfile.TemporaryDirectory() as tmp:
            gh = Path(tmp) / "gh"
            gh.write_text(FAKE_GH)
            gh.chmod(0o755)
            env = {"PATH": f"{tmp}{os.pathsep}{os.environ['PATH']}",
                   "FAKE_RC": str(rc), "FAKE_OUT": out, "FAKE_ERR": err}
            with patch.dict(os.environ, env):
                return pr_ci.checks("OWNER/REPO", 9, required)

    def test_no_required_checks_reported_means_empty(self):
        self.assertEqual([], self.run_checks(required=True, rc=1, err=REAL_NO_REQUIRED))
        self.assertEqual([], self.run_checks(required=True, rc=1, out="\n", err=REAL_NO_REQUIRED))

    def test_message_only_tolerated_for_required_query(self):
        with self.assertRaises(pr_ci.GateError):
            self.run_checks(required=False, rc=1, err=REAL_NO_REQUIRED)

    def test_other_failures_still_fail_closed(self):
        with self.assertRaises(pr_ci.GateError):
            self.run_checks(required=True, rc=1, err="HTTP 502: Bad Gateway\n")

    def test_failing_checks_json_still_parsed(self):
        out = '[{"name": "ci", "bucket": "fail", "state": "FAILURE"}]'
        self.assertEqual("FAIL", pr_ci.classify(self.run_checks(required=True, rc=1, out=out)))

    def test_a_failing_required_check_named_like_the_message_stays_a_failure(self):
        found = self.run_checks(required=True, rc=1, out=PHRASE_FAILURE)
        self.assertEqual([PHRASE_NAME], [c["name"] for c in found])
        self.assertEqual("FAIL", pr_ci.classify(found))

    def test_json_on_stdout_wins_over_the_message_on_stderr(self):
        found = self.run_checks(required=True, rc=1, out=PHRASE_FAILURE, err=REAL_NO_REQUIRED)
        self.assertEqual("FAIL", pr_ci.classify(found))

    def test_the_message_inside_other_output_is_not_the_message(self):
        for err in ("warning: retrying\n" + REAL_NO_REQUIRED, "HTTP 502: " + REAL_NO_REQUIRED,
                    REAL_NO_REQUIRED + "extra line\n", REAL_NO_REQUIRED.upper(),
                    "no required checks reported\n", "No required checks reported on the 'x' branch\n",
                    "no required checks reported on the '' branch\n"):
            with self.subTest(err=err), self.assertRaises(pr_ci.GateError):
                self.run_checks(required=True, rc=1, err=err)

    def test_other_exit_statuses_do_not_use_the_fallback(self):
        for rc in (0, 2, 8):
            with self.subTest(rc=rc), self.assertRaises(pr_ci.GateError):
                self.run_checks(required=True, rc=rc, err=REAL_NO_REQUIRED)

    def test_unparseable_stdout_does_not_use_the_fallback(self):
        with self.assertRaises(pr_ci.GateError):
            self.run_checks(required=True, rc=1, out="something went wrong", err=REAL_NO_REQUIRED)

    def test_inspect_reports_a_failing_required_check_named_like_the_message(self):
        sha = "a" * 40
        view = {"number": 9, "state": "OPEN", "isDraft": True, "headRefOid": sha, "url": "u"}
        gh_command = pr_ci.command
        with tempfile.TemporaryDirectory() as tmp:
            gh = Path(tmp) / "gh"
            gh.write_text(FAKE_GH)
            gh.chmod(0o755)
            env = {"PATH": f"{tmp}{os.pathsep}{os.environ['PATH']}", "FAKE_RC": "1", "FAKE_OUT": PHRASE_FAILURE}
            with patch.dict(os.environ, env), patch.object(
                    pr_ci, "command",
                    side_effect=lambda argv, **kw: view if argv[:3] == ["gh", "pr", "view"] else gh_command(argv, **kw)):
                result = pr_ci.inspect("OWNER/REPO", 9, sha)
        self.assertEqual("CI_FAILED", result["status"])
        self.assertEqual([PHRASE_NAME], [c["name"] for c in result["required_checks"]])


if __name__ == "__main__":
    unittest.main()
