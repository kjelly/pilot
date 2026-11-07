"""Reuse against the base HEAD already contains, and review reuse across any pure base import
(kjelly/pilot#307). Real Git graphs; the strict default is unchanged for issue-to-pr.
"""
import unittest

import test_target_reuse as ttr  # imported as a module so its TestCases are not collected twice
from test_repo_evidence import commit, git, re_
from test_non_execution_reuse import MANIFEST


class IntegratedBaseTests(ttr.ReuseHelpers):
    manifest = MANIFEST
    build = ttr.TargetReuseGuardTests.build

    def setUp(self):
        super().setUp()
        self.root = git(self.wt, "rev-parse", "main")

    def ctx(self, integrated=False):
        return re_.Context.load(self.wt, git(self.wt, "rev-parse", "HEAD"), "refs/remotes/origin/main",
                                integrated_base=integrated)

    def move_main_on(self, path="docs/later.md"):
        """Main advances after the PR integrated it; HEAD now lacks the live tip."""
        integrated = self.base
        git(self.wt, "checkout", "-q", "main")
        self.base = commit(self.wt, path, "later\n")
        git(self.wt, "update-ref", "refs/remotes/origin/main", self.base)
        git(self.wt, "checkout", "-q", "fix/1-x")
        return integrated

    def test_reuse_base_is_the_newest_base_commit_head_contains(self):
        self.build(main={".agents/skills/x/SKILL.md": "rule\n"})
        integrated = self.move_main_on()
        strict, relaxed = self.ctx(), self.ctx(integrated=True)
        self.assertEqual(self.base, strict.reuse_base())
        self.assertEqual(integrated, relaxed.reuse_base())
        # Strict: HEAD must contain the live tip. Integrated: the import from the base HEAD has is proven.
        self.assertFalse(strict.accepts_target(self.candidate, "actual-run", None, None, "e2e-run"))
        self.assertIn("current base has not been integrated into HEAD", strict.target_stale_reason(self.candidate))
        self.assertTrue(relaxed.accepts_target(self.candidate, "actual-run", None, None, "e2e-run"),
                        relaxed.target_stale_reason(self.candidate))
        self.assertEqual(integrated, relaxed.report()["delta_accepted"][-1]["base"])

    def test_attestation_names_the_integrated_base_in_integrated_mode(self):
        self.build()  # main brings src/unrelated.go
        integrated = self.move_main_on()
        ctx = self.ctx(integrated=True)
        self.assertTrue(ctx.accepts_target(self.candidate, "actual-run", self.reuse(base_sha=integrated)),
                        ctx.target_stale_reason(self.candidate))
        ctx = self.ctx(integrated=True)
        self.assertFalse(ctx.accepts_target(self.candidate, "actual-run", self.reuse(base_sha=self.base)))
        self.assertIn("target reuse base SHA does not match current base", ctx.target_stale_reason(self.candidate))

    def test_review_carries_across_a_pure_import_of_any_file_but_receipts_do_not(self):
        self.build()  # main brings src/unrelated.go, a runtime file
        ctx = self.ctx(integrated=True)
        self.assertFalse(ctx.accepts(self.candidate, "checks[0]"))
        self.assertFalse(ctx.accepts_review(self.candidate, "independent_review"))  # non-execution only
        self.assertTrue(ctx.accepts_pure_import(self.candidate, "review"), ctx.review_stale_reason(self.candidate))
        accepted = ctx.report()["delta_accepted"][-1]
        self.assertEqual(("pure-base-import", ["src/unrelated.go"]), (accepted["method"], accepted["changed"]))

    def test_a_pr_side_edit_or_blend_is_not_a_pure_import(self):
        self.build(post={"src/local.go": "package local\n"})
        ctx = self.ctx(integrated=True)
        self.assertFalse(ctx.accepts_pure_import(self.candidate, "review"))
        self.assertIn("base-import reuse: change is neither evidence-only nor a pure base import: src/local.go",
                      ctx.review_stale_reason(self.candidate))
        self.build(fork={"src/shared.go": "1\n2\n3\n4\n5\n6\n"},
                   candidate={"src/app.go": "package app\n", "src/shared.go": "one\n2\n3\n4\n5\n6\n"},
                   main={"src/shared.go": "1\n2\n3\n4\n5\nsix\n"})
        ctx = self.ctx(integrated=True)
        self.assertFalse(ctx.accepts_pure_import(self.candidate, "review"))
        self.assertIn("pure base import: src/shared.go", ctx.review_stale_reason(self.candidate))

    def assertBaseChangeDropped(self, path, *, target=False):
        """No review entry point takes the candidate in either mode, and each says why with this path (the
        base-side guard is the only one that can: the reviewed tree and HEAD hold the same bytes there).
        `target`: the non-execution target reuse refuses it too (it needs a non-evidence delta to get there)."""
        reason = "base change not carried into HEAD: " + path
        for integrated in (False, True):
            with self.subTest(integrated=integrated):
                ctx = self.ctx(integrated)
                self.assertFalse(ctx.accepts_pure_import(self.candidate, "review"))
                self.assertIn(reason, ctx.review_stale_reason(self.candidate))
                ctx = self.ctx(integrated)
                self.assertFalse(ctx.accepts_review(self.candidate, "independent_review"))
                self.assertIn(reason, ctx.review_stale_reason(self.candidate))
                if target:
                    ctx = self.ctx(integrated)
                    self.assertFalse(ctx.accepts_target(self.candidate, "actual-run", None, None, "e2e-run"))
                    self.assertIn("non-execution reuse: " + reason, ctx.target_stale_reason(self.candidate))

    def test_a_merge_that_keeps_the_pr_bytes_of_a_file_main_changed_is_not_a_pure_import(self):
        # `-s ours`: HEAD differs from the reviewed tree only by the evidence record, yet main's change
        # is gone. The loop over reviewed-vs-HEAD differences sees nothing; the base-side loop does.
        for path in ("src/unrelated.go", "docs/note.md"):  # a runtime file and a declared non-execution one
            with self.subTest(path=path):
                self.build(main={path: "main's change\n"}, merge=("merge", "-q", "-s", "ours", "main", "-m", "keep ours"))
                ctx = self.ctx(integrated=True)
                self.assertIn(path, ctx.tree_entries(self.base))
                self.assertNotIn(path, ctx.tree_entries("HEAD"))
                self.assertBaseChangeDropped(path)
                # Target evidence is about the bytes that were tested, and HEAD holds them: an evidence-only
                # delta still carries it (a receipt-like proof; the revert is the review's to refuse).
                self.assertTrue(self.ctx(integrated=True).accepts_target(
                    self.candidate, "actual-run", None, None, "e2e-run"))

    def test_a_conflict_resolved_with_the_pr_side_is_not_a_pure_import(self):
        # Both sides edit line 1 of src/shared.go; `-X ours` keeps the PR's line and still imports
        # main's docs/note.md, so the only visible import is a clean one.
        self.build(fork={"src/shared.go": "1\n2\n3\n"},
                   candidate={"src/app.go": "package app\n", "src/shared.go": "one\n2\n3\n"},
                   main={"src/shared.go": "uno\n2\n3\n", "docs/note.md": "note\n"},
                   merge=("merge", "-q", "-X", "ours", "main", "-m", "resolve with ours"))
        ctx = self.ctx(integrated=True)
        self.assertEqual("one\n2\n3", git(self.wt, "show", "HEAD:src/shared.go"))
        self.assertEqual(ctx.tree_entries(self.candidate)["src/shared.go"], ctx.tree_entries("HEAD")["src/shared.go"])
        self.assertBaseChangeDropped("src/shared.go", target=True)

    def test_a_deletion_main_made_must_reach_head_too(self):
        git(self.wt, "checkout", "-q", "-B", "main", self.root)
        self.fork = ttr.commit_files(self.wt, {"src/dependency.go": "package dependency\n", "src/old.go": "package old\n"}, "fork")
        git(self.wt, "checkout", "-q", "-B", "fix/1-x", self.fork)
        self.candidate = ttr.commit_files(self.wt, {"src/app.go": "package app\n"}, "candidate")
        git(self.wt, "checkout", "-q", "main")
        git(self.wt, "rm", "-q", "src/old.go")
        git(self.wt, "commit", "-q", "-m", "main drops old.go")
        self.base = git(self.wt, "rev-parse", "HEAD")
        git(self.wt, "update-ref", "refs/remotes/origin/main", self.base)
        git(self.wt, "checkout", "-q", "fix/1-x")
        git(self.wt, "merge", "-q", "-s", "ours", "main", "-m", "keep old.go")
        commit(self.wt, "qa/runs/2026/run.md", "Tested " + self.candidate)
        self.assertBaseChangeDropped("src/old.go")
        # The same graph merged normally takes the deletion and is a pure import again.
        git(self.wt, "reset", "-q", "--hard", self.candidate)
        git(self.wt, "merge", "-q", "main", "-m", "integrate main")
        commit(self.wt, "qa/runs/2026/run.md", "Tested " + self.candidate)
        self.assertTrue(self.ctx(integrated=True).accepts_pure_import(self.candidate, "review"))

    def test_a_base_change_both_sides_made_the_same_way_or_in_an_evidence_path_is_carried(self):
        # The PR made the identical edit main made (reviewed bytes == base bytes == HEAD bytes), and both
        # edited an evidence-only file, where the merge keeps the PR's side: neither is a revert.
        self.build(fork={"qa/evidence/log.md": "fork\n"},
                   candidate={"src/app.go": "package app\n", "src/same.go": "package same\n",
                              "qa/evidence/log.md": "pr\n"},
                   main={"src/same.go": "package same\n", "src/unrelated.go": "package unrelated\n",
                         "qa/evidence/log.md": "main\n"},
                   merge=("merge", "-q", "-X", "ours", "main", "-m", "integrate main"))
        ctx = self.ctx(integrated=True)
        self.assertEqual(ctx.tree_entries(self.candidate)["qa/evidence/log.md"], ctx.tree_entries("HEAD")["qa/evidence/log.md"])
        self.assertTrue(ctx.accepts_pure_import(self.candidate, "review"), ctx.review_stale_reason(self.candidate))
        self.assertEqual(["src/unrelated.go"], ctx.report()["delta_accepted"][-1]["changed"])


if __name__ == "__main__":
    unittest.main()
