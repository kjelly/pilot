"""Umbrella mode in the gate, create_pr.py and mark_ready.py (V5-V12). The real git worktree fixture of
test_issue_gate runs underneath; GitHub reads are faked from the captured `gh issue view` shapes. The
inherited gate tests also run here, in umbrella mode."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_issue_gate as base  # noqa: E402
from test_issue_gate import create_pr, issue_gate, mark_ready, rw  # noqa: E402
from test_umbrella import BATCH, body as umbrella_body, child_view, umbrella_view  # noqa: E402

REPO = "OWNER/REPO"
U = 354
SUB_URL = "https://github.com/OWNER/REPO/issues/216"
SUB_SOURCE = SUB_URL + "#issuecomment-7000000001"
SUB_REPLY = SUB_URL + "#issuecomment-7000000002"


def entry(n: int, resolution: str = "fixes", **extra) -> dict:
    return {"issue": n, "issue_resolution": resolution,
            "acceptance_criteria": [{"criterion": f"Symptom of #{n} no longer occurs", "met": True,
                                     "evidence": f"Regression TestIssue{n} fails on base and passes here"}],
            "disputed_issue_claims": [], "reviewer_confirmed": True, **extra}


class UmbrellaGateTests(base.LocalGitFixture):
    def setUp(self):
        super().setUp()
        self.evidence["issue"] = U
        self.evidence["umbrella"] = {"batch_id": BATCH, "sub_issues": [entry(142), entry(216)]}
        self.save()
        self.views = {U: umbrella_view(), 142: child_view(142), 216: child_view(216)}
        self.dups: dict[int, list[str]] = {}
        self.dup_calls: list[tuple[int, int | None]] = []
        self.thread = {"number": 216, "url": SUB_URL, "createdAt": "2026-11-01T00:00:00Z", "comments": [
            {"url": SUB_SOURCE, "createdAt": "2026-11-02T00:00:00Z", "body": "The cache must be removed entirely."},
            {"url": SUB_REPLY, "createdAt": "2026-11-03T00:00:00Z",
             "body": f"Re {SUB_SOURCE}: removing the cache is a separate decision; this PR keeps it."}]}
        self.thread_calls: list[int] = []

    # -- fakes -----------------------------------------------------------------------------------

    def view(self, repo, n):
        if n not in self.views:
            raise issue_gate.GateError(f"['gh', 'issue', 'view', '{n}'] failed: not found")
        return copy.deepcopy(self.views[n])

    def dup(self, repo, n, branch, own_pr=None):
        self.dup_calls.append((n, own_pr))
        return list(self.dups.get(n, []))

    def thread_for(self, repo, n):
        self.thread_calls.append(n)
        return self.thread if n == 216 else {"number": n, "url": f"https://github.com/{repo}/issues/{n}",
                                               "createdAt": "2026-11-01T00:00:00Z", "comments": []}

    def fakes(self):
        return (patch.object(issue_gate, "gh_umbrella_view", side_effect=self.view),
                patch.object(issue_gate, "gh_issue_and_duplicates", side_effect=self.dup),
                patch.object(issue_gate, "gh_issue_thread", side_effect=self.thread_for))

    def eval_local(self, issue=U, own_pr=None):
        a, b, c = self.fakes()
        with a, b, c:
            return issue_gate.evaluate(repo=REPO, issue=issue, worktree=self.worktree, evidence_path=self.path,
                                       own_pr=own_pr)

    def blocked(self, needle, issue=U):
        errors = self.eval_local(issue)[0]
        self.assertTrue(any(needle in e for e in errors), errors)
        return errors

    def sub(self, n):
        return next(s for s in self.evidence["umbrella"]["sub_issues"] if s["issue"] == n)

    def dispute_216(self, disposition="out_of_scope", **extra):
        return {"source_url": SUB_SOURCE, "reply_url": SUB_REPLY, "disposition": disposition,
                "claim": "The cache must be removed entirely, not fixed", "head_sha": self.sha,
                "counter_evidence": "Removing the cache changes every login path; it needs a separate decision",
                "reviewer_confirmed": True, **extra}

    # -- gate ------------------------------------------------------------------------------------

    def test_umbrella_gate_passes_and_reports_each_sub_issue(self):
        errors, info = self.eval_local(own_pr=9)
        self.assertEqual([], errors)
        self.assertEqual({"umbrella": U, "sub_issues": [{"issue": 142, "issue_resolution": "fixes"},
                                                        {"issue": 216, "issue_resolution": "fixes"}]},
                         info["umbrella"])
        self.assertEqual([(142, 9), (216, 9), (U, 9)], sorted(self.dup_calls), "own PR excluded for every Issue")

    def test_v5_sub_issues_must_equal_the_open_sub_issues_on_github(self):
        self.evidence["umbrella"]["sub_issues"] = [entry(142)]
        self.save()
        self.blocked("are not #354's open sub-issues [142, 216]")
        self.evidence["umbrella"]["sub_issues"] = [entry(142), entry(216), entry(300)]
        self.save()
        self.blocked("are not #354's open sub-issues")
        self.evidence["umbrella"]["sub_issues"] = [entry(142), entry(216)]
        self.evidence["umbrella"]["batch_id"] = "a" * 12
        self.save()
        self.blocked("is not #354's batch 29b14e9b200a")
        self.evidence["umbrella"]["batch_id"] = BATCH
        self.save()
        self.views[U] = umbrella_view(subs=((142, "CLOSED"), (216, "OPEN")))
        self.blocked("are not #354's open sub-issues [216]")
        self.evidence["umbrella"]["sub_issues"] = [entry(216)]
        self.save()
        self.assertEqual([], self.eval_local()[0], "a closed sub-issue is not part of the work")

    def test_v5_the_umbrella_must_resolve_to_itself(self):
        self.views[U] = umbrella_view(text="An ordinary tracking Issue.")
        self.blocked("#354 is not a planner umbrella")
        self.views[U] = umbrella_view()
        self.evidence["issue"] = 142
        self.save()
        self.blocked("run the gate with the umbrella's number", issue=142)
        self.evidence["issue"] = U
        self.save()
        self.views[U] = umbrella_view(subs=((142, "OPEN"),))
        self.blocked("umbrella: umbrella #354's sub-issues [142] are not its members")
        del self.views[U]
        self.blocked("not found")

    def test_v6_a_sub_issue_with_another_closing_pr_blocks(self):
        self.dups[216] = ["Potential duplicate PR already references Issue #216: https://github.com/OWNER/REPO/pull/77"]
        self.blocked("sub-issue #216: Potential duplicate PR")
        self.dups[216] = ["GitHub issue not OPEN/identity mismatch"]
        self.blocked("sub-issue #216: GitHub issue not OPEN")

    def test_v6_a_sub_issue_whose_validation_cannot_be_read_blocks(self):
        """gh_issue_and_duplicates RAISING (not returning errors) for one sub-issue fails closed, naming it."""
        def dup(repo, n, branch, own_pr=None):
            if n == 216:
                raise issue_gate.GateError("gh timed out")
            return []

        a, _, c = self.fakes()
        with a, c, patch.object(issue_gate, "gh_issue_and_duplicates", side_effect=dup):
            errors = issue_gate.evaluate(repo=REPO, issue=U, worktree=self.worktree, evidence_path=self.path)[0]
        self.assertIn("sub-issue #216: GitHub duplicate/issue validation unavailable: gh timed out", errors)
        self.assertFalse([e for e in errors if "#142" in e], errors)
        self.assertEqual([], self.eval_local()[0], "the same evidence passes when the read works")

    def test_v6_a_sub_issues_follow_up_issue_is_verified(self):
        """An out_of_scope claim of a sub-issue may close it only with a follow-up Issue that exists
        (single mode's check_follow_ups, run per sub-issue)."""
        follow_up = "https://github.com/OWNER/REPO/issues/400"
        self.thread["comments"][1]["body"] = f"Re {SUB_SOURCE}: a separate defect, tracked in {follow_up}."
        self.sub(216)["disputed_issue_claims"] = [self.dispute_216(follow_up_issue_url=follow_up)]
        self.save()
        a, b, c = self.fakes()
        with patch.object(issue_gate, "gh_follow_up_issue", side_effect=issue_gate.GateError("not found")) as gone:
            with a, b, c:
                errors = issue_gate.evaluate(repo=REPO, issue=U, worktree=self.worktree, evidence_path=self.path)[0]
        gone.assert_called_once_with(REPO, 400)
        self.assertIn("sub-issue #216: disputed_issue_claims[0].follow_up_issue_url cannot be verified: not found",
                      errors)
        a, b, c = self.fakes()
        with patch.object(issue_gate, "gh_follow_up_issue", return_value=None) as found:
            with a, b, c:
                errors = issue_gate.evaluate(repo=REPO, issue=U, worktree=self.worktree, evidence_path=self.path)[0]
        found.assert_called_once_with(REPO, 400)
        self.assertEqual([], errors)

    def test_v7_a_sub_issue_listed_twice_or_the_umbrella_itself_is_refused(self):
        for name, subs in (("listed twice", [entry(142), entry(216), entry(216)]),
                           ("the umbrella itself", [entry(142), entry(216), entry(U)])):
            with self.subTest(name):
                self.evidence["umbrella"]["sub_issues"] = subs
                self.save()
                errors = self.blocked("is listed twice or is the umbrella itself")
                self.assertEqual(1, len([e for e in errors if "listed twice or is the umbrella itself" in e]), errors)
        self.evidence["umbrella"]["sub_issues"] = [entry(142), entry(216)]
        self.save()
        self.assertEqual([], self.eval_local()[0])

    def test_v7_each_sub_issue_needs_acceptance_and_the_reviewer(self):
        for name, mutate, needle in (
                ("no criteria", lambda s: s.pop("acceptance_criteria"), "#216.acceptance_criteria: acceptance criteria absent"),
                ("empty criteria", lambda s: s.update(acceptance_criteria=[]), "acceptance criteria absent"),
                ("unmet criterion", lambda s: s["acceptance_criteria"][0].update(met=False), "lacks PASS"),
                ("not confirmed", lambda s: s.update(reviewer_confirmed=False), "#216 not confirmed by the independent reviewer")):
            with self.subTest(name):
                self.evidence["umbrella"]["sub_issues"] = [entry(142), entry(216)]
                mutate(self.sub(216))
                self.save()
                self.blocked(needle)

    def test_v8_the_umbrella_resolution_follows_its_sub_issues(self):
        partial_216 = entry(216, "partial", acceptance_criteria=[], disputed_issue_claims=[self.dispute_216("needs_evidence")])
        for name, top, subs, top_disputes, needle in (
                ("all fixes, top partial", "partial", [entry(142), entry(216)], [], "must be 'fixes'"),
                ("a partial sub-issue, top fixes", "fixes", [entry(142), partial_216], [], "must be 'partial'"),
                ("top-level disputes", "partial", [entry(142), partial_216], [self.dispute_216()], "the umbrella's own list must be empty"),
                ("partial without disputes", "partial", [entry(142), entry(216, "partial")], [], "#216: issue_resolution 'partial' needs"),
                ("fixes with an open claim", "fixes", [entry(142), entry(216, disputed_issue_claims=[self.dispute_216("needs_evidence")])],
                 [], "#216: issue_resolution is 'fixes'"),
                ("a bad resolution", "fixes", [entry(142), entry(216, "Partial")], [], "#216: issue_resolution must be")):
            with self.subTest(name):
                self.evidence.update(issue_resolution=top, disputed_issue_claims=top_disputes)
                self.evidence["umbrella"]["sub_issues"] = subs
                self.save()
                self.blocked(needle)
        with self.subTest("consistent partial passes without top-level disputes"):
            self.evidence.update(issue_resolution="partial", disputed_issue_claims=[])
            self.evidence["umbrella"]["sub_issues"] = [entry(142), partial_216]
            self.save()
            self.assertEqual([], self.eval_local()[0])
            self.assertIn(216, self.thread_calls, "the sub-issue's own thread was read")

    def test_v9_disputes_are_checked_on_the_sub_issues_own_thread(self):
        self.evidence["issue_resolution"] = "partial"
        dispute = self.dispute_216("needs_evidence")
        self.evidence["umbrella"]["sub_issues"] = [entry(142), entry(216, "partial", disputed_issue_claims=[dispute])]
        self.save()
        self.assertEqual([], self.eval_local()[0])
        dispute["reply_url"] = "https://github.com/OWNER/REPO/issues/354#issuecomment-1"
        self.save()
        self.blocked("sub-issue #216: disputed_issue_claims[0].reply_url is not a comment on this Issue")
        dispute.update(reply_url=SUB_REPLY, source_url="https://github.com/OWNER/REPO/issues/142#issuecomment-5")
        self.save()
        self.blocked("sub-issue #216: disputed_issue_claims[0].source_url is not this Issue")

    def test_v12_every_umbrella_field_of_the_wrong_type_is_a_blocker_not_a_crash(self):
        wrong = ({}, [], [{}], "x", 0, -1, 1.5, True, None)
        paths = [("umbrella",), ("umbrella", "batch_id"), ("umbrella", "sub_issues"), ("umbrella", "sub_issues", 1),
                 ("umbrella", "sub_issues", 1, "issue"), ("umbrella", "sub_issues", 1, "issue_resolution"),
                 ("umbrella", "sub_issues", 1, "acceptance_criteria"),
                 ("umbrella", "sub_issues", 1, "acceptance_criteria", 0),
                 ("umbrella", "sub_issues", 1, "disputed_issue_claims"),
                 ("umbrella", "sub_issues", 1, "reviewer_confirmed"), ("issue_resolution",)]
        good = copy.deepcopy(self.evidence)
        ran = 0
        for path in paths:
            for value in wrong:
                with self.subTest(path=path, value=value):
                    self.evidence = copy.deepcopy(good)
                    target = self.evidence
                    for key in path[:-1]:
                        target = target[key]
                    target[path[-1]] = value
                    self.save()
                    errors = self.eval_local()[0]
                    ran += 1
                    valid = {"reviewer_confirmed": True, "disputed_issue_claims": []}
                    if not (path[-1] in valid and value == valid[path[-1]] and type(value) is type(valid[path[-1]])):
                        self.assertNotEqual([], errors)
        self.assertGreater(ran, 90)

    # -- create_pr.py / mark_ready.py --------------------------------------------------------------

    def create(self, text):
        body_file = self.state / "body.md"
        body_file.write_text(text + "\n\n## Tests\n- regressions passed\n")
        a, b, c = self.fakes()
        with a, b, c, patch.object(issue_gate, "remote_head", return_value=self.sha), \
                patch.object(create_pr, "check_pr", return_value={"number": 9, "url": "u"}) as check, \
                patch.object(create_pr, "execute", return_value="") as execute:
            result = create_pr.create(repo=REPO, issue=U, worktree=self.worktree, evidence=self.path,
                                      title="fix: umbrella 354 root cause", body_file=body_file)
        return result, execute, check

    def test_v10_create_pr_needs_each_fixes_and_refs(self):
        for name, text, needle in (
                ("a sub-issue not closed", "Fixes #354\nFixes #142\nRefs #216", "sub-issue #216: PR body must contain a genuine 'Fixes #216'"),
                ("one keyword for two Issues", "Fixes #354\nFixes #142, #216", "sub-issue #216"),
                ("the umbrella not closed", "Refs #354\nFixes #142\nFixes #216", "genuine 'Fixes #354'")):
            with self.subTest(name):
                with self.assertRaisesRegex(issue_gate.GateError, needle):
                    self.create(text)
        result, execute, check = self.create("Fixes #354\nFixes #142\nFixes #216")
        self.assertEqual("DRAFT_PR_CREATED", result["status"], result)
        self.assertEqual({142: "fixes", 216: "fixes"}, check.call_args.kwargs["sub_issues"])

    def test_v10_a_partial_sub_issue_and_umbrella_use_refs(self):
        self.evidence["issue_resolution"] = "partial"
        self.evidence["umbrella"]["sub_issues"] = [
            entry(142), entry(216, "partial", disputed_issue_claims=[self.dispute_216("needs_evidence")])]
        self.save()
        for name, text, needle in (
                ("a partial sub-issue closed", "Refs #354\nFixes #142\nFixes #216", "must not close #216"),
                ("the umbrella closed", "Fixes #354\nFixes #142\nRefs #216", "must not close #354")):
            with self.subTest(name):
                with self.assertRaisesRegex(issue_gate.GateError, needle):
                    self.create(text)
        result, _, _ = self.create("Refs #354\nFixes #142\nRefs #216")
        self.assertEqual("DRAFT_PR_CREATED", result["status"], result)

    def test_v10_check_pr_reads_the_created_body_per_sub_issue(self):
        pr = {"number": 9, "url": "u", "state": "OPEN", "isDraft": True, "headRefName": "issue/123-fix",
              "headRefOid": self.sha, "baseRefName": "main", "body": "Fixes #354\nFixes #142"}
        with patch.object(create_pr, "command", return_value=pr):
            with self.assertRaisesRegex(issue_gate.GateError, "sub-issue #216"):
                create_pr.check_pr(REPO, "issue/123-fix", "main", self.sha, draft=True, issue=U,
                                   sub_issues={142: "fixes", 216: "fixes"})
            pr["body"] += "\nFixes #216"
            self.assertEqual(9, create_pr.check_pr(REPO, "issue/123-fix", "main", self.sha, draft=True, issue=U,
                                                   sub_issues={142: "fixes", 216: "fixes"})["number"])

    def mark(self, body):
        pr = {"number": 9, "state": "OPEN", "isDraft": True, "headRefName": "issue/123-fix",
              "headRefOid": self.sha, "mergeable": "MERGEABLE", "url": "u", "body": body}
        calls = []
        world = rw.World(head=self.sha)  # the Ready signal's GitHub state
        a, b, c = self.fakes()
        with a, b, c, patch.object(issue_gate, "remote_head", return_value=self.sha), \
                patch.object(mark_ready, "command", side_effect=[pr, base.NO_REVIEW_THREADS,
                                                                 {"isDraft": False, "headRefOid": self.sha, "url": "u"}]), \
                patch.object(mark_ready.pr_ci, "inspect", return_value={"status": "CI_PASSED"}), \
                patch.object(mark_ready, "execute", side_effect=rw.pr_ready_executor(world, calls)), \
                rw.mark_ready_signal(mark_ready, world):
            result = mark_ready.mark_ready(repo=REPO, issue=U, pr=9, worktree=self.worktree,
                                           evidence=self.path, confirm_complete=True)
        return result, calls

    def test_v11_mark_ready_rechecks_every_reference(self):
        result, calls = self.mark("Fixes #354\nFixes #142\nRefs #216")
        self.assertEqual("BLOCKED", result["status"], result)
        self.assertTrue(any("sub-issue #216" in b for b in result["blockers"]), result)
        self.assertEqual([], calls)
        result, calls = self.mark("Fixes #354\nFixes #142\nFixes #216")
        self.assertEqual("READY_FOR_REVIEW", result["status"], result)
        self.assertEqual([["gh", "pr", "ready", "9", "-R", REPO]], calls)


class SingleModeIsUnchangedTests(base.LocalGitFixture):
    """V12: without `umbrella` the gate never reads an umbrella and reports no `umbrella` key."""

    def test_v12_no_umbrella_reads(self):
        with patch.object(issue_gate, "gh_issue_and_duplicates", return_value=[]), \
             patch.object(issue_gate, "gh_umbrella_view", side_effect=AssertionError("read")):
            errors, info = issue_gate.evaluate(repo=REPO, issue=123, worktree=self.worktree, evidence_path=self.path)
        self.assertEqual([], errors)
        self.assertNotIn("umbrella", info)
        self.assertEqual([], create_pr.reference_problems("Fixes #123", REPO, 123, "fixes", {}))
        self.assertEqual(["PR body must contain a genuine 'Fixes #123' or equivalent closing keyword"],
                         create_pr.reference_problems("Refs #123", REPO, 123, "fixes", None))


if __name__ == "__main__":
    unittest.main()
