"""Offline unit + real git worktree quality gate tests (no GitHub operations)."""
from __future__ import annotations

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import issue_gate  # noqa: E402
import run_check   # noqa: E402


def git(path: Path, *args: str) -> str:
    p = subprocess.run(["git", "-C", str(path), *args], text=True, capture_output=True, check=True)
    return p.stdout.strip()


class LocalGitFixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.repo = self.root / "repo"
        self.worktree = self.root / "wt"
        self.state = self.root / "state"
        self.state.mkdir()
        self.repo.mkdir()
        git(self.repo, "init", "-b", "main")
        git(self.repo, "config", "user.email", "test@example.com")
        git(self.repo, "config", "user.name", "Tester")
        (self.repo / "main.txt").write_text("main\n", encoding="utf-8")
        git(self.repo, "add", "main.txt")
        git(self.repo, "commit", "-m", "base")
        git(self.repo, "remote", "add", "origin", "https://github.com/OWNER/REPO.git")
        git(self.repo, "update-ref", "refs/remotes/origin/main", git(self.repo, "rev-parse", "HEAD"))
        git(self.repo, "worktree", "add", "-b", "issue/123-fix", str(self.worktree), "main")
        (self.worktree / "regression.txt").write_text("root-cause fixed\n", encoding="utf-8")
        git(self.worktree, "add", "regression.txt")
        git(self.worktree, "commit", "-m", "fix: issue 123")
        self.sha = git(self.worktree, "rev-parse", "HEAD")
        self.receipt = self.state / "regression.json"
        run_check.run_check(self.worktree, "regression", self.receipt,
                            [sys.executable, "-c", "assert open('regression.txt').read().strip() == 'root-cause fixed'"], 30)
        self.lint = self.state / "lint.json"
        run_check.run_check(self.worktree, "lint", self.lint, [sys.executable, "-c", "print('lint ok')"], 30)
        self.evidence = {
            "schema_version": 1, "repo": "OWNER/REPO", "issue": 123,
            "base_branch": "main", "head_branch": "issue/123-fix", "head_sha": self.sha,
            "root_cause": "Stale entries violated internal state transition invariants.",
            "dependencies": {"status": "resolved", "evidence": "Checked linked issues and found no unmerged prerequisites."},
            "acceptance_criteria": [{"criterion": "The stale state is handled correctly", "met": True,
                                     "evidence": "Regression test verifies the stale state is rejected."}],
            "checks": [{"category": "regression", "receipt": str(self.receipt)},
                       {"category": "lint", "receipt": str(self.lint)}],
            "lint": {"status": "pass", "evidence": "Python-based lint smoke check passed."},
            "static_analysis": {"status": "not-applicable", "reason": "Repository has no configured static analyzer at this stage."},
            "review": {"agent": "issue-reviewer", "independent": True, "head_sha": self.sha,
                       "status": "pass", "summary": "Inspected state transition correctness and tests.", "findings": []}
        }
        self.path = self.state / "evidence.json"
        self.save()

    def save(self):
        self.path.write_text(json.dumps(self.evidence), encoding="utf-8")

    def test_clean_sha_bound_receipt(self):
        data = json.loads(self.receipt.read_text(encoding="utf-8"))
        self.assertEqual("pass", data["status"])
        self.assertEqual(self.sha, data["head_sha"])
        self.assertTrue(data["clean_before"] and data["clean_after"])
        self.assertTrue(Path(data["log"]).exists())
        self.assertFalse(Path(data["log"]).is_relative_to(self.worktree))

    def test_dirty_tree_disallows_check(self):
        (self.worktree / "untracked.tmp").write_text("dirty")
        with self.assertRaises(RuntimeError):
            run_check.run_check(self.worktree, "dirty", self.state / "dirty.json",
                                [sys.executable, "-c", "pass"], 5)

    def test_failing_check_receipt(self):
        result = run_check.run_check(self.worktree, "fail", self.state / "fail.json",
                                     [sys.executable, "-c", "raise SystemExit(1)"], 5)
        self.assertEqual("fail", result["status"])
        self.assertEqual(1, result["exit_code"])

    def test_dirty_after_command_fails_check(self):
        result = run_check.run_check(self.worktree, "write", self.state / "write.json",
                                     [sys.executable, "-c", "open('new.txt', 'w').write('not committed')"], 5)
        self.assertEqual("fail", result["status"])
        self.assertFalse(result["clean_after"])

    def eval_local(self):
        with patch.object(issue_gate, "gh_issue_and_duplicates", return_value=[]):
            return issue_gate.evaluate(repo="OWNER/REPO", issue=123,
                                       worktree=self.worktree, evidence_path=self.path)

    def test_gate_pass(self):
        errors, info = self.eval_local()
        self.assertEqual([], errors)
        self.assertEqual(self.sha, info["head_sha"])
        self.assertEqual("issue/123-fix", info["branch"])

    def test_modified_review_sha_blocks(self):
        self.evidence["review"]["head_sha"] = "0" * 40
        self.save()
        self.assertTrue(any("Reviewer" in e for e in self.eval_local()[0]))

    def test_unresolved_p2_blocks(self):
        self.evidence["review"]["findings"] = [{"severity": "P2", "status": "open", "description": "missing atomicity"}]
        self.save()
        self.assertTrue(any("blocking review" in e for e in self.eval_local()[0]))

    def test_pre_existing_p2_is_rejected_by_rubric(self):
        self.evidence["review"]["findings"] = [{"severity": "P2", "origin": "pre-existing", "status": "open", "description": "already on base"}]
        self.save()
        self.assertTrue(any("capped at P3" in e for e in self.eval_local()[0]))

    def test_pre_existing_p3_open_is_non_blocking(self):
        self.evidence["review"]["findings"] = [{"severity": "P3", "origin": "pre-existing", "status": "open", "description": "already on base"}]
        self.save()
        self.assertEqual([], self.eval_local()[0])

    def test_invalid_origin_is_rejected(self):
        self.evidence["review"]["findings"] = [{"severity": "P3", "origin": "whatever", "status": "open", "description": "x"}]
        self.save()
        self.assertTrue(any("invalid origin" in e for e in self.eval_local()[0]))

    def test_p3_unresolved_non_blocking(self):
        self.evidence["review"]["findings"] = [{"severity": "P3", "status": "open", "description": "nice-to-have refactor"}]
        self.save()
        self.assertEqual([], self.eval_local()[0])

    def test_missing_regression_check_blocks(self):
        self.evidence["checks"] = [self.evidence["checks"][1]]
        self.save()
        self.assertTrue(any("Regression" in e for e in self.eval_local()[0]))

    def test_stale_receipt_blocks(self):
        data = json.loads(self.receipt.read_text())
        data["head_sha"] = "f" * 40
        self.receipt.write_text(json.dumps(data))
        self.assertTrue(any("stale" in e for e in self.eval_local()[0]))

    def test_receipt_path_outside_evidence_root_blocks(self):
        elsewhere = self.root / "elsewhere.json"
        elsewhere.write_text(self.receipt.read_text())
        self.evidence["checks"][0]["receipt"] = str(elsewhere)
        self.save()
        self.assertTrue(any("regular file under" in e for e in self.eval_local()[0]))

    def test_modified_worktree_blocks(self):
        (self.worktree / "main.txt").write_text("changed")
        self.assertTrue(any("Dirty" in e for e in self.eval_local()[0]))

    def test_unexplained_static_na_blocks(self):
        self.evidence["static_analysis"] = {"status": "not-applicable", "reason": "not needed"}
        self.save()
        self.assertTrue(any("static_analysis" in e for e in self.eval_local()[0]))

    def test_wrong_remote_blocks(self):
        git(self.worktree, "remote", "set-url", "origin", "https://github.com/different/repo.git")
        self.assertTrue(any("does not identify" in e for e in self.eval_local()[0]))

    def test_remote_commit_mismatch_blocks(self):
        with patch.object(issue_gate, "gh_issue_and_duplicates", return_value=[]), \
             patch.object(issue_gate, "remote_head", return_value="a" * 40):
            errors, _ = issue_gate.evaluate(repo="OWNER/REPO", issue=123, worktree=self.worktree,
                                            evidence_path=self.path, stage="pushed")
        self.assertTrue(any("differs" in e for e in errors))

    def test_duplicate_issue_branch_blocks(self):
        def fake_gh(argv, **kwargs):
            if argv[1:3] == ["issue", "view"]:
                return {"number": 123, "state": "OPEN", "closedByPullRequestsReferences": []}
            if "--head" in argv:
                return [{"url": "https://github.com/OWNER/REPO/pull/77"}]
            return []
        with patch.object(issue_gate, "command", side_effect=fake_gh):
            errors = issue_gate.gh_issue_and_duplicates("OWNER/REPO", 123, "issue/123-fix")
        self.assertTrue(any("Existing PR" in e for e in errors))

    def test_duplicate_issue_in_pr_body_blocks(self):
        def fake_gh(argv, **kwargs):
            if argv[1:3] == ["issue", "view"]:
                return {"number": 123, "state": "OPEN", "closedByPullRequestsReferences": []}
            if "--head" in argv:
                return []
            return [{"url": "https://github.com/OWNER/REPO/pull/66", "body": "Fixes #123"}]
        with patch.object(issue_gate, "command", side_effect=fake_gh):
            errors = issue_gate.gh_issue_and_duplicates("OWNER/REPO", 123, "issue/123-fix")
        self.assertTrue(any("duplicate" in e.lower() for e in errors))

    def _dups_for_body(self, body):
        def fake_gh(argv, **kwargs):
            if argv[1:3] == ["issue", "view"]:
                return {"number": 123, "state": "OPEN", "closedByPullRequestsReferences": []}
            if "--head" in argv:
                return []
            return [{"url": "https://github.com/OWNER/REPO/pull/66", "body": body,
                     "closingIssuesReferences": []}]
        with patch.object(issue_gate, "command", side_effect=fake_gh):
            return issue_gate.gh_issue_and_duplicates("OWNER/REPO", 123, "issue/123-fix")

    def test_closing_keyword_forms_in_pr_body_block(self):
        for body in ("Fixes #123", "closes: #123", "Resolved #123", "fixes OWNER/REPO#123",
                     "Closes https://github.com/OWNER/REPO/issues/123", "intro\n\nFixes #123\n",
                     "see `code` then Fixes #123", "```\nx\n```\nFixes #123"):
            with self.subTest(body=body):
                self.assertTrue(any("duplicate" in e.lower() for e in self._dups_for_body(body)))

    def test_plain_cross_reference_in_pr_body_does_not_block(self):
        # A PR that fixes another Issue and only mentions this one is not a competing fix.
        for body in ("Related: #123", "see #123 and PR #181", "(#123, PR #181)",
                     "Fixes #177\n\nRelated: #172, #123, #167", "Fixes #1234", "Fixes #12",
                     "Fixes 123", "prefixes #123",
                     "the heuristic matched #181, which is `Fixes #123` and only mentions #177",
                     "```\nFixes #123\n```", "<!-- Fixes #123 -->", "``Fixes #123``"):
            with self.subTest(body=body):
                self.assertEqual([], self._dups_for_body(body))


DELTA_ONLY = {"schema_version": 1, "evidence_only_paths": ["qa/evidence/**"]}
MANIFEST = {"schema_version": 1, "evidence_only_paths": ["qa/evidence/**"],
            "required_evidence": [{"id": "e2e-run", "source": "CONTRIBUTING.md#verification", "artifact_glob": "qa/runs/**"}]}


class RepoEvidenceGateTests(LocalGitFixture):
    """Receipts survive an evidence-only commit; repository-required evidence is enforced."""

    def declare_manifest(self, manifest=MANIFEST):
        (self.repo / ".github").mkdir(exist_ok=True)
        (self.repo / ".github" / "pr-evidence.json").write_text(json.dumps(manifest), encoding="utf-8")
        git(self.repo, "add", ".github/pr-evidence.json")
        git(self.repo, "commit", "-m", "declare evidence rules")
        git(self.repo, "update-ref", "refs/remotes/origin/main", git(self.repo, "rev-parse", "main"))

    def commit_in_worktree(self, name, text="evidence\n"):
        path = self.worktree / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        git(self.worktree, "add", name)
        git(self.worktree, "commit", "-m", name)
        self.evidence["head_sha"] = git(self.worktree, "rev-parse", "HEAD")
        self.save()

    def test_receipts_and_review_survive_evidence_only_commit(self):
        self.declare_manifest(DELTA_ONLY)
        self.commit_in_worktree("qa/evidence/run.md")
        errors, info = self.eval_local()
        self.assertEqual([], errors)
        labels = {x["label"] for x in info["repo_evidence"]["delta_accepted"]}
        self.assertEqual({"checks[0]", "checks[1]", "review"}, labels)

    def test_without_declared_rules_the_same_commit_invalidates_receipts(self):
        self.commit_in_worktree("qa/evidence/run.md")
        errors, info = self.eval_local()
        self.assertTrue(any("stale or malformed receipt" in e for e in errors))
        self.assertTrue(any("another HEAD" in e for e in errors))
        self.assertIn("NOT machine-checked", " ".join(info["repo_evidence"]["warnings"]))

    def test_code_change_after_the_receipts_still_invalidates_them(self):
        self.declare_manifest(DELTA_ONLY)
        self.commit_in_worktree("qa/evidence/run.md")
        self.commit_in_worktree("regression.txt", "changed after the checks ran\n")
        self.assertTrue(any("stale or malformed receipt" in e for e in self.eval_local()[0]))

    def test_pr_cannot_declare_its_own_exemption(self):
        self.commit_in_worktree(".github/pr-evidence.json", json.dumps(MANIFEST))
        self.commit_in_worktree("qa/evidence/run.md")
        self.assertTrue(any("stale or malformed receipt" in e for e in self.eval_local()[0]))

    def test_required_evidence_must_be_listed_committed_and_current(self):
        self.declare_manifest()
        self.assertTrue(any("'e2e-run' missing" in e for e in self.eval_local()[0]))
        self.commit_in_worktree("qa/runs/2026-10-28.md", "ran on staging\n")
        self.evidence["repo_required_evidence"] = [{
            "id": "e2e-run", "status": "pass", "head_sha": self.sha, "artifact": "qa/runs/2026-10-28.md",
            "summary": "Base fails, candidate passes on staging."}]
        self.save()
        self.assertEqual([], self.eval_local()[0])
        self.commit_in_worktree("regression.txt", "code changed after the live run\n")
        self.assertTrue(any("e2e-run" in e and "not HEAD" in e for e in self.eval_local()[0]))

    def test_invalid_manifest_on_base_blocks(self):
        self.declare_manifest({"schema_version": 1, "evidence_only_paths": ["**"]})
        self.assertTrue(any("defeat SHA binding" in e for e in self.eval_local()[0]))



# Shapes copied from real `gh issue view --json number,url,createdAt,comments` output
# (kjelly/pilot#177), with the repository and Issue number changed.
ISSUE_URL = "https://github.com/OWNER/REPO/issues/123"
REPORTER_COMMENT = ISSUE_URL + "#issuecomment-6487450538"
REPLY = ISSUE_URL + "#issuecomment-6487999001"


class DisputedIssueClaimTests(LocalGitFixture):
    """An Issue claim the PR does not act on must be answered on the Issue."""

    def setUp(self):
        super().setUp()
        self.thread = {"number": 123, "url": ISSUE_URL, "createdAt": "2026-10-29T02:57:42Z", "comments": [
            {"url": REPORTER_COMMENT, "createdAt": "2026-10-29T03:54:16Z", "viewerDidAuthor": False,
             "author": {"login": "reporter"}, "body": "Also: the retry loop must be removed, it hides the error."},
            {"url": REPLY, "createdAt": "2026-10-29T05:10:00Z", "viewerDidAuthor": True,
             "author": {"login": "pilot"},
             "body": f"Re {REPORTER_COMMENT}: the retry loop does not hide the error; see the test below."},
        ]}
        self.dispute = {"source_url": REPORTER_COMMENT, "reply_url": REPLY, "disposition": "invalid",
                        "claim": "The retry loop hides the error and must be removed",
                        "counter_evidence": "retry.go:41 re-raises after the last attempt; TestRetrySurfacesError fails without it",
                        "head_sha": self.sha, "reviewer_confirmed": True}
        self.evidence["disputed_issue_claims"] = [self.dispute]
        self.save()

    def eval_with_thread(self, error=None):
        if error:
            fetch = patch.object(issue_gate, "gh_issue_thread", side_effect=error)
        else:
            fetch = patch.object(issue_gate, "gh_issue_thread", return_value=self.thread)
        with patch.object(issue_gate, "gh_issue_and_duplicates", return_value=[]), fetch as mocked:
            errors, info = issue_gate.evaluate(repo="OWNER/REPO", issue=123,
                                               worktree=self.worktree, evidence_path=self.path)
        return errors, info, mocked

    def eval_local(self):
        # The inherited gate tests also run with an answered dispute present.
        return self.eval_with_thread()[:2]

    def blocked(self, needle, mutate):
        mutate(self.dispute, self.thread)
        self.save()
        errors = self.eval_with_thread()[0]
        self.assertTrue(any(needle in e for e in errors), errors)

    def test_answered_comment_claim_passes(self):
        self.assertEqual([], self.eval_with_thread()[0])

    def test_answered_issue_body_claim_passes_without_a_link(self):
        def body_claim(d, t):
            d["source_url"] = ISSUE_URL
            t["comments"][1]["body"] = "The described crash does not reproduce on main; see the trace below."
        body_claim(self.dispute, self.thread)
        self.save()
        self.assertEqual([], self.eval_with_thread()[0])

    def test_no_disputes_never_fetches_comments(self):
        self.evidence.pop("disputed_issue_claims")
        self.save()
        errors, _, mocked = self.eval_with_thread()
        self.assertEqual([], errors)
        mocked.assert_not_called()

    def test_reply_must_link_the_disputed_comment(self):
        self.blocked("does not link", lambda d, t: t["comments"][1].update(body="The retry loop is fine."))

    def test_reply_must_follow_the_claim(self):
        self.blocked("not posted after", lambda d, t: t["comments"][1].update(createdAt="2026-10-29T03:00:00Z"))

    def test_source_must_belong_to_this_issue(self):
        self.blocked("not this Issue", lambda d, t: d.update(
            source_url="https://github.com/OWNER/REPO/issues/124#issuecomment-1"))

    def test_reply_must_be_a_comment(self):
        self.blocked("reply_url is not a comment", lambda d, t: d.update(reply_url=ISSUE_URL))

    def test_reviewer_must_confirm(self):
        self.blocked("independent reviewer", lambda d, t: d.update(reviewer_confirmed="yes"))

    def test_other_head_blocks(self):
        self.blocked("another HEAD", lambda d, t: d.update(head_sha="0" * 40))

    def test_unknown_disposition_blocks(self):
        self.blocked("disposition", lambda d, t: d.update(disposition="wontfix"))

    def test_vague_counter_evidence_blocks(self):
        self.blocked("counter_evidence", lambda d, t: d.update(counter_evidence="issue is wrong"))

    def test_unavailable_comments_fail_closed(self):
        errors = self.eval_with_thread(error=issue_gate.GateError("gh: rate limited"))[0]
        self.assertTrue(any("comments unavailable" in e for e in errors), errors)

    def test_malformed_list_blocks(self):
        self.evidence["disputed_issue_claims"] = {"source_url": ISSUE_URL}
        self.save()
        self.assertTrue(any("malformed" in e for e in self.eval_with_thread()[0]))

    def test_partial_resolution_needs_a_dispute(self):
        self.evidence["issue_resolution"] = "partial"
        self.save()
        self.assertEqual([], self.eval_with_thread()[0])
        self.evidence.pop("disputed_issue_claims")
        self.save()
        self.assertTrue(any("'partial' needs" in e for e in self.eval_with_thread()[0]))

    def test_unknown_resolution_blocks(self):
        self.evidence["issue_resolution"] = "mostly"
        self.save()
        self.assertTrue(any("issue_resolution must be" in e for e in self.eval_with_thread()[0]))


if __name__ == "__main__":
    unittest.main()
