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


if __name__ == "__main__":
    unittest.main()
