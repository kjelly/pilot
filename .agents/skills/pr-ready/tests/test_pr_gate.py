import contextlib
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pr_gate", ROOT / "scripts" / "pr_gate.py")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
SHA = "0123456789abcdef0123456789abcdef01234567"


def good():
    pr = {"number": 7, "url": "https://github.com/acme/repo/pull/7",
          "headRefOid": SHA, "headRefName": "fix-one", "state": "OPEN",
          "isDraft": True, "mergeable": "MERGEABLE", "reviewDecision": "REVIEW_REQUIRED"}
    checks = [{"name": "go test", "bucket": "pass", "state": "SUCCESS"},
              {"name": "lint", "bucket": "pass", "state": "SUCCESS"}]
    snapshot = module.Snapshot(pr, checks, [checks[0]], [{"id": "T1", "isResolved": True}])
    assessment = {k: True for k in (
        "acceptance_criteria_passed", "root_cause_fixed", "architecture_sound",
        "description_matches_code", "dependencies_resolved", "major_review_comments_resolved",
        "related_ci_failures_resolved")}
    assessment["rationale"] = "AC traced to test cases, issue root cause is fixed and diff matches description."
    evidence = {"schema_version": 1, "repo": "acme/repo", "pr": 7, "head_sha": SHA,
                "assessment": assessment,
                "independent_review": {"agent": "pr-reviewer", "head_sha": SHA, "status": "PASS",
                                       "blocking_findings": [], "report": "Evidence-backed separate reviewer response"},
                "local_validation": {key: [{"command": f"run {key}", "exit_code": 0,
                                           "head_sha": SHA, "log": f".pr-ready/logs/{key}.log"}]
                                     for key in ("tests", "lint", "static_analysis")},
                "unrelated_failing_checks": []}
    return snapshot, evidence


class GateTests(unittest.TestCase):
    def check(self, snapshot, evidence, local=(SHA, "fix-one", [])):
        return module.evaluate(snapshot, evidence, repo="acme/repo", number=7, local=local)

    def test_good_with_review_required(self):
        s, e = good()
        self.assertEqual([], self.check(s, e))

    def test_evidence_sha_stale(self):
        s, e = good()
        e["head_sha"] = "f" * 40
        self.assertTrue(any("Evidence SHA" in x for x in self.check(s, e)))

    def test_review_sha_stale(self):
        s, e = good()
        e["independent_review"]["head_sha"] = "f" * 40
        self.assertTrue(any("reviewer" in x for x in self.check(s, e)))

    def test_required_check_failed_cannot_exempt(self):
        s, e = good()
        s.required_checks[0]["bucket"] = "fail"
        e["unrelated_failing_checks"] = [{"name": "go test", "reason": "Long specific reason about unrelated failure",
                                          "reviewer_confirmed": True}]
        self.assertTrue(any("Required" in x for x in self.check(s, e)))

    def test_no_checks_fails_closed(self):
        s, e = good()
        s.checks = []
        s.required_checks = []
        self.assertTrue(any("No CI checks" in x for x in self.check(s, e)))

    def test_unresolved_review_thread(self):
        s, e = good()
        s.threads[0]["isResolved"] = False
        self.assertTrue(any("Unresolved" in x for x in self.check(s, e)))

    def test_minor_thread_must_be_resolved_too(self):
        # pr-review-merge drafts a PR with any unresolved thread, so P3/P4 ones are not exempt.
        s, e = good()
        s.threads[0]["isResolved"] = False
        e["unresolved_nonblocking_threads"] = [
            {"id": "T1", "severity": "P3", "reason": "Stylistic suggestion unrelated to acceptance criteria",
             "reviewer_confirmed": True}]
        errors = self.check(s, e)
        self.assertTrue(any("Unresolved GitHub review thread: T1" in x for x in errors))
        self.assertTrue(any("no longer accepted" in x for x in errors))
        s.threads[0]["isResolved"] = True
        self.assertTrue(any("no longer accepted" in x for x in self.check(s, e)))
        e["unresolved_nonblocking_threads"] = []
        self.assertEqual([], self.check(s, e))

    def test_pending_check_fails_closed(self):
        s, e = good()
        s.checks[1]["bucket"] = "pending"
        self.assertTrue(any("Nonpassing" in x for x in self.check(s, e)))

    def test_unrelated_nonrequired_check(self):
        s, e = good()
        s.checks[1]["bucket"] = "fail"
        e["unrelated_failing_checks"] = [{"name": "lint", "reason": "Unrelated external-only failure confirmed by CI trace",
                                          "reviewer_confirmed": True}]
        self.assertEqual([], self.check(s, e))

    def test_changes_requested_not_human_reapproval_gate(self):
        s, e = good()
        s.pr["reviewDecision"] = "CHANGES_REQUESTED"
        self.assertEqual([], self.check(s, e))
        e["assessment"]["major_review_comments_resolved"] = False
        self.assertTrue(any("major_review_comments_resolved" in x for x in self.check(s, e)))

    def test_mergeability_unknown_blocks(self):
        s, e = good()
        s.pr["mergeable"] = "UNKNOWN"
        self.assertTrue(any("Mergeability" in x for x in self.check(s, e)))

    def test_local_dirty_or_wrong_branch_blocks(self):
        s, e = good()
        errs = self.check(s, e, (SHA, "something-else", ["?? hello.go"]))
        self.assertTrue(any("branch" in x for x in errs))
        self.assertTrue(any("uncommitted" in x for x in errs))

    def test_no_lint_requires_justification(self):
        s, e = good()
        e["local_validation"]["lint"] = {"not_applicable": "No linter"}
        self.assertTrue(any("not-applicable" in x for x in self.check(s, e)))
        e["local_validation"]["lint"] = {"not_applicable": "This project has no lint entry in its Makefile or CI workflow."}
        self.assertEqual([], self.check(s, e))

    def test_malformed_receipt_or_bool_rejected(self):
        s, e = good()
        e["assessment"]["root_cause_fixed"] = "true"
        e["local_validation"]["tests"][0]["exit_code"] = True
        errs = self.check(s, e)
        self.assertTrue(any("root_cause_fixed" in x for x in errs))
        self.assertTrue(any("did not pass" in x for x in errs))

    def test_run_check_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cmds = [["git", "init", "--quiet"], ["git", "config", "user.name", "test"],
                    ["git", "config", "user.email", "test@example.org"]]
            for argv in cmds:
                subprocess.run(argv, cwd=root, check=True, stdout=subprocess.DEVNULL)
            (root / "hello").write_text("hello")
            subprocess.run(["git", "add", "hello"], cwd=root, check=True)
            subprocess.run(["git", "commit", "--quiet", "-m", "initial"], cwd=root, check=True)
            p = subprocess.run([sys.executable, str(ROOT / "scripts/run_check.py"), "--category", "tests",
                                "--", sys.executable, "-c", "print('pass')"], cwd=root,
                               capture_output=True, text=True)
            self.assertEqual(0, p.returncode, p.stderr)
            receipt = json.loads(p.stdout)
            self.assertEqual(0, receipt["exit_code"])
            self.assertTrue((root / receipt["log"]).is_file())


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


@contextlib.contextmanager
def fake_gh(rc, out="", err=""):
    """Put a `gh` on PATH that exits `rc` with the given stdout/stderr, whatever it is asked."""
    with tempfile.TemporaryDirectory() as tmp:
        gh = Path(tmp) / "gh"
        gh.write_text(FAKE_GH)
        gh.chmod(0o755)
        env = {"PATH": f"{tmp}{os.pathsep}{os.environ['PATH']}", "FAKE_RC": str(rc), "FAKE_OUT": out, "FAKE_ERR": err}
        with patch.dict(os.environ, env):
            yield


class RequiredChecksQueryTests(unittest.TestCase):
    """`gh pr checks --required` fails with plain text, not JSON, on a branch without required checks;
    that one failure means "no required checks". Nothing else may be read that way."""

    def required(self, rc, out="", err=""):
        with fake_gh(rc, out, err):
            return module.gh_checks("acme/repo", 7, required=True)

    def test_exact_gh_message_on_an_empty_stdout_means_no_required_checks(self):
        self.assertEqual([], self.required(1, err=REAL_NO_REQUIRED))
        self.assertEqual([], self.required(1, out="\n", err=REAL_NO_REQUIRED))

    def test_a_failing_required_check_named_like_the_message_stays_a_failure(self):
        found = self.required(1, out=PHRASE_FAILURE)
        self.assertEqual([PHRASE_NAME], [c["name"] for c in found])
        self.assertEqual("fail", found[0]["bucket"])

    def test_json_on_stdout_wins_over_the_message_on_stderr(self):
        found = self.required(1, out=PHRASE_FAILURE, err=REAL_NO_REQUIRED)
        self.assertEqual([PHRASE_NAME], [c["name"] for c in found])

    def test_the_message_inside_other_output_is_not_the_message(self):
        for err in ("warning: retrying\n" + REAL_NO_REQUIRED, "HTTP 502: " + REAL_NO_REQUIRED,
                    REAL_NO_REQUIRED + "extra line\n", REAL_NO_REQUIRED.upper(),
                    "no required checks reported\n", "No required checks reported on the 'x' branch\n",
                    "no required checks reported on the '' branch\n"):
            with self.subTest(err=err), self.assertRaises(module.GateError):
                self.required(1, err=err)

    def test_other_exit_statuses_do_not_use_the_fallback(self):
        for rc in (0, 2, 8):
            with self.subTest(rc=rc), self.assertRaises(module.GateError):
                self.required(rc, err=REAL_NO_REQUIRED)

    def test_unparseable_stdout_does_not_use_the_fallback(self):
        with self.assertRaises(module.GateError):
            self.required(1, out="something went wrong", err=REAL_NO_REQUIRED)

    def test_the_full_query_never_falls_back(self):
        with fake_gh(1, err=REAL_NO_REQUIRED), self.assertRaises(module.GateError):
            module.gh_checks("acme/repo", 7, required=False)

    def test_other_failures_still_fail_closed(self):
        with self.assertRaises(module.GateError):
            self.required(1, err="HTTP 502: Bad Gateway\n")

    def test_exemption_cannot_hide_a_required_check_named_like_the_message(self):
        s, e = good()
        required = self.required(1, out=PHRASE_FAILURE)
        s.checks, s.required_checks = [*s.checks, *required], required
        e["unrelated_failing_checks"] = [{"name": PHRASE_NAME, "reviewer_confirmed": True,
                                          "reason": "Unrelated failure, same on main at the base SHA"}]
        errors = module.evaluate(s, e, repo="acme/repo", number=7, local=(SHA, "fix-one", []))
        self.assertIn(f"Required GitHub check not passing: {PHRASE_NAME} (FAILURE, fail)", errors)


# URL and timestamp shapes copied from real GraphQL output (kjelly/pilot#190,
# kjelly/pilot#92 and cli/cli#14796), with the PR number changed to 7.
REVIEW = "https://github.com/acme/repo/pull/7#issuecomment-6494548870"
REBUTTAL = "https://github.com/acme/repo/pull/7#issuecomment-6501033173"
REVIEW_BODY = "https://github.com/acme/repo/pull/7#pullrequestreview-5526281476"
INLINE = "https://github.com/acme/repo/pull/7#discussion_r4358213254"
INLINE_REPLY = "https://github.com/acme/repo/pull/7#discussion_r4358333969"


def disputed():
    """A PR whose review comment Root disputed with a linked rebuttal."""
    s, e = good()
    s.comments = [
        {"url": REVIEW, "createdAt": "2026-10-29T10:44:27Z",
         "body": "## Automated PR review: Draft required\n\n**[P2]** gate accepts an empty list"},
        {"url": REBUTTAL, "createdAt": "2026-10-29T15:32:36Z",
         "body": f"Re {REVIEW}: the P2 does not hold; `pr_gate.py:180` rejects empty lists, see test_empty."},
    ]
    s.reviews = [{"url": REVIEW_BODY, "createdAt": "2026-10-29T11:00:00Z"}]
    s.threads = [{"id": "PRRT_kwDODKw3uc6vjTgB", "isResolved": True, "isOutdated": False,
                  "comments": {"nodes": [
                      {"url": INLINE, "createdAt": "2026-10-23T09:44:41Z"},
                      {"url": INLINE_REPLY, "createdAt": "2026-10-23T09:59:24Z"}],
                      "pageInfo": {"hasNextPage": False}}}]
    e["disputed_review_comments"] = [{
        "source_url": REVIEW, "reply_url": REBUTTAL, "disposition": "invalid",
        "claim": "P2: the gate accepts an empty local_validation list",
        "counter_evidence": "pr_gate.py:180 appends an error for an empty list; test_empty fails when it is removed",
        "head_sha": SHA, "reviewer_confirmed": True}]
    return s, e


class DisputedReviewCommentTests(unittest.TestCase):
    def check(self, snapshot, evidence):
        return module.evaluate(snapshot, evidence, repo="acme/repo", number=7, local=(SHA, "fix-one", []))

    def errors_for(self, mutate):
        s, e = disputed()
        mutate(s, e, e["disputed_review_comments"][0])
        return self.check(s, e)

    def assertBlocked(self, needle, mutate):
        errs = self.errors_for(mutate)
        self.assertTrue(any(needle in x for x in errs), errs)

    def test_rebutted_conversation_comment_passes(self):
        s, e = disputed()
        self.assertEqual([], self.check(s, e))

    def test_rebutted_inline_comment_passes(self):
        def inline(s, e, d):
            d.update(source_url=INLINE, reply_url=INLINE_REPLY)
        self.assertEqual([], self.errors_for(inline))

    def test_review_body_rebutted_in_conversation_passes(self):
        def review(s, e, d):
            d["source_url"] = REVIEW_BODY
            s.comments[1]["body"] = f"Re {REVIEW_BODY}: does not reproduce on HEAD."
        self.assertEqual([], self.errors_for(review))

    def test_nonblocking_needs_p3_or_p4(self):
        def no_severity(s, e, d):
            d["disposition"] = "nonblocking"
        self.assertBlocked("severity P3 or P4", no_severity)

        def p3(s, e, d):
            d.update(disposition="nonblocking", severity="P3")
        self.assertEqual([], self.errors_for(p3))

    def test_unknown_disposition_blocks(self):
        self.assertBlocked("disposition", lambda s, e, d: d.update(disposition="wontfix"))

    def test_reviewer_must_confirm(self):
        self.assertBlocked("independent reviewer", lambda s, e, d: d.update(reviewer_confirmed="true"))

    def test_stale_sha_blocks(self):
        self.assertBlocked("stale/missing SHA", lambda s, e, d: d.update(head_sha="f" * 40))

    def test_vague_counter_evidence_blocks(self):
        self.assertBlocked("counter_evidence", lambda s, e, d: d.update(counter_evidence="reviewer is wrong"))

    def test_source_must_be_on_this_pr(self):
        def other_pr(s, e, d):
            d["source_url"] = "https://github.com/acme/repo/pull/8#issuecomment-1"
        self.assertBlocked("source_url is not a review comment", other_pr)

    def test_reply_must_exist(self):
        def missing(s, e, d):
            s.comments.pop()
        self.assertBlocked("reply_url is not a comment", missing)

    def test_reply_must_follow_the_comment(self):
        def earlier(s, e, d):
            s.comments[1]["createdAt"] = "2026-10-29T09:00:00Z"
        self.assertBlocked("not posted after", earlier)

    def test_conversation_reply_must_link_the_comment(self):
        def unlinked(s, e, d):
            s.comments[1]["body"] = "The P2 does not hold; pr_gate.py:180 rejects empty lists."
        self.assertBlocked("does not link", unlinked)

    def test_review_body_reply_must_be_a_conversation_comment(self):
        def in_thread(s, e, d):
            d.update(source_url=REVIEW_BODY, reply_url=INLINE_REPLY)
            s.reviews[0]["createdAt"] = "2026-10-23T09:00:00Z"
        self.assertBlocked("must be a PR conversation comment", in_thread)

    def test_inline_reply_must_be_in_the_same_thread(self):
        def conversation(s, e, d):
            d.update(source_url=INLINE, reply_url=REBUTTAL)
        self.assertBlocked("disputed comment's review thread", conversation)

    def test_inline_comment_after_reply_blocks(self):
        def pushback(s, e, d):
            d.update(source_url=INLINE, reply_url=INLINE_REPLY)
            s.threads[0]["comments"]["nodes"].append(
                {"url": "https://github.com/acme/repo/pull/7#discussion_r4358400000",
                 "createdAt": "2026-10-23T10:30:00Z"})
        self.assertBlocked("comments after the reply", pushback)

    def test_incomplete_thread_blocks(self):
        def truncated(s, e, d):
            d.update(source_url=INLINE, reply_url=INLINE_REPLY)
            s.threads[0]["comments"]["pageInfo"]["hasNextPage"] = True
        self.assertBlocked("incomplete", truncated)

    def test_dispute_does_not_exempt_an_unresolved_thread(self):
        def reopened(s, e, d):
            d.update(source_url=INLINE, reply_url=INLINE_REPLY)
            s.threads[0]["isResolved"] = False
        self.assertBlocked("Unresolved GitHub review thread", reopened)

    def test_conversation_not_fetched_fails_closed(self):
        def unfetched(s, e, d):
            s.comments = None
        self.assertBlocked("not fetched", unfetched)

    def test_malformed_list_blocks(self):
        s, e = disputed()
        e["disputed_review_comments"] = {"source_url": REVIEW}
        self.assertTrue(any("malformed" in x for x in self.check(s, e)))


if __name__ == "__main__":
    unittest.main()
