"""Candidate-bound target reuse after main advances. Real Git, no mocked provenance.

Every documented guard of the reuse rule (.agents/skills/_shared/target-evidence-reuse.md) has a
counterexample here in which it is the ONLY guard that rejects, and the test asserts that guard's own
reason text: a rejection for some other reason cannot stand in for the guard under test.
"""
import os
import subprocess
import unittest

from test_repo_evidence import Base, commit, git


class Link(str):
    """File content that is a symlink to this target."""


def commit_files(wt, files, message):
    """One commit that writes `files` (path -> text, or Link); no files, no commit."""
    for path, content in files.items():
        f = wt / path
        f.parent.mkdir(parents=True, exist_ok=True)
        if f.is_symlink() or f.exists():
            f.unlink()
        if isinstance(content, Link):
            os.symlink(str(content), f)
        else:
            f.write_text(content)
        git(wt, "add", path)
    if files:
        git(wt, "commit", "-q", "-m", message)
    return git(wt, "rev-parse", "HEAD")


AUDIT_REASON = "Only latest evidence link and prose changed; no command, expected value or variable contract changed."
PROSE = "docs/verification/x.md"


class ReuseHelpers(Base):
    from test_repo_evidence import MANIFEST
    manifest = {**MANIFEST, "required_evidence": [
        {**MANIFEST["required_evidence"][0], "kind": "target-run"}]}

    def reuse(self, **kw):
        return dict({"head_sha": git(self.wt, "rev-parse", "HEAD"), "base_sha": self.base,
                     "reviewer_confirmed": True,
                     "dependency_review": "Reviewed every execution input and its dependencies; unrelated.go is outside the target invocation and cannot affect its outcome.",
                     "execution_paths": ["src/app.go", "src/dependency.go"],
                     "non_execution_changes": []}, **kw)

    def accepts(self, reuse=None, candidate=None):
        ctx = self.ctx()
        result = ctx.accepts_target(candidate or self.candidate, "actual-run",
                                    self.reuse() if reuse is None else reuse)
        return result, ctx

    def assertRejected(self, reuse, reason, candidate=None):
        """Refused, and for `reason`: another guard rejecting first would leave this one unproven."""
        ok, ctx = self.accepts(reuse, candidate)
        self.assertFalse(ok, "accepted, expected: " + reason)
        self.assertIn(reason, ctx.target_stale_reason(candidate or self.candidate))

    def audit(self, path=PROSE, reason=AUDIT_REASON):
        return [{"path": path, "reason": reason}]


class TargetReuseTests(ReuseHelpers):
    def setUp(self):
        super().setUp()
        # A dependency already exists on both branches when the candidate is frozen.
        git(self.wt, "checkout", "-q", "main")
        self.fork = commit(self.wt, "src/dependency.go", "package dependency\n")
        git(self.wt, "checkout", "-q", "fix/1-x")
        git(self.wt, "merge", "-q", "main", "-m", "prerequisite")
        self.candidate = git(self.wt, "rev-parse", "HEAD")
        git(self.wt, "checkout", "-q", "main")
        self.base = commit(self.wt, "src/unrelated.go", "package unrelated\n")
        git(self.wt, "update-ref", "refs/remotes/origin/main", self.base)
        git(self.wt, "checkout", "-q", "fix/1-x")
        git(self.wt, "merge", "-q", "main", "-m", "integrate main")
        commit(self.wt, "qa/runs/2026/run.md", "Tested " + self.candidate)

    def test_reviewed_pure_base_import_accepts_only_target(self):
        ok, ctx = self.accepts()
        self.assertTrue(ok, ctx.target_stale_reason(self.candidate))
        self.assertEqual("reviewed-base-integration", ctx.report()["delta_accepted"][0]["method"])
        # General check receipts AND reviews still reject the identical candidate.
        for label in ("checks[0]", "review", "disputed_issue_claims[0]"):
            self.assertFalse(ctx.accepts(self.candidate, label))

    def test_required_record_uses_shared_target_policy(self):
        entry = {"id": "e2e-run", "status": "pass", "head_sha": self.candidate,
                 "artifact": "qa/runs/2026/run.md", "summary": "VM target chain and failure paths passed.",
                 "target_reuse": self.reuse()}
        self.assertEqual([], self.ctx().check_required([entry]))
        del entry["target_reuse"]
        self.assertTrue(self.ctx().check_required([entry]))

    def test_required_ci_url_receipt_cannot_opt_itself_into_target_reuse(self):
        ctx = self.ctx()
        ctx.required["coverage"] = {"id": "coverage", "source": "CI policy"}
        entry = {"id": "coverage", "status": "pass", "head_sha": self.candidate,
                 "url": "https://ci.example.org/runs/123", "summary": "Coverage and native test checks passed on the old candidate.",
                 "target_reuse": self.reuse()}
        errors = ctx._check_entry("coverage", entry, None)
        self.assertTrue(any("requires kind: target-run" in e for e in errors))

    def test_unknown_manifest_kind_is_rejected(self):
        import repo_evidence
        manifest = {"schema_version": 1, "required_evidence": [
            {"id": "coverage", "source": "CI policy", "kind": "anything"}]}
        self.assertTrue(any("kind must be target-run" in e for e in repo_evidence.validate_manifest(manifest)))

    def test_no_implicit_reuse_and_no_stale_confirmation(self):
        # Without an attestation the strict evidence-only rule applies: the imported main file is not.
        ctx = self.ctx()
        self.assertFalse(ctx.accepts_target(self.candidate, "actual-run"))
        self.assertIn("files outside evidence_only_paths changed: src/unrelated.go",
                      ctx.target_stale_reason(self.candidate))
        for kw, reason in (({"head_sha": self.candidate}, "independent reviewer confirmation at current HEAD"),
                           ({"base_sha": self.fork}, "base SHA does not match current base"),
                           ({"reviewer_confirmed": False}, "independent reviewer confirmation at current HEAD"),
                           ({"dependency_review": "unchanged"}, "dependency review (60+ characters)")):
            with self.subTest(kw=kw):
                self.assertRejected(self.reuse(**kw), reason)

    def test_changed_shared_dependency_is_rejected_even_when_imported_from_main(self):
        git(self.wt, "checkout", "-q", "main")
        self.base = commit(self.wt, "src/dependency.go", "package dependency // new semantics\n")
        git(self.wt, "update-ref", "refs/remotes/origin/main", self.base)
        git(self.wt, "checkout", "-q", "fix/1-x")
        git(self.wt, "merge", "-q", "main", "-m", "dependency changed")
        self.assertRejected(self.reuse(), "execution input changed, missing or not a regular file: src/dependency.go")

    def test_local_runtime_edit_cannot_be_declared_unrelated(self):
        commit(self.wt, "src/other.go", "package other\n")
        self.assertRejected(self.reuse(), "neither a pure base import nor an audited non-execution change: src/other.go")
        # It cannot be hidden behind the non-execution audit either: the path is not eligible.
        self.assertRejected(self.reuse(non_execution_changes=self.audit(
            "src/other.go", "This is unrelated to the particular target execution.")),
            "each non-execution change needs an eligible exact path")

    def test_conflict_resolution_in_a_scoped_file_is_rejected(self):
        git(self.wt, "checkout", "-q", "main")
        self.base = commit(self.wt, "src/app.go", "package app // base conflict\n")
        git(self.wt, "update-ref", "refs/remotes/origin/main", self.base)
        git(self.wt, "checkout", "-q", "fix/1-x")
        p = subprocess.run(["git", "-C", str(self.wt), "merge", "main"], capture_output=True)
        self.assertNotEqual(0, p.returncode)
        commit(self.wt, "src/app.go", "package app // resolved differently\n")
        self.assertRejected(self.reuse(), "execution input changed, missing or not a regular file: src/app.go")

    def test_runtime_blend_outside_declared_scope_still_rejected(self):
        # Even a reviewer omitting app.go cannot authorize a locally changed runtime file.
        commit(self.wt, "src/app.go", "package app // blend\n")
        self.assertRejected(self.reuse(execution_paths=["src/dependency.go"]),
                            "neither a pure base import nor an audited non-execution change: src/app.go")

    def test_audited_prose_change_accepts_but_unreviewed_does_not(self):
        commit(self.wt, PROSE, "Latest link and prose, checklist unchanged\n")
        self.assertRejected(self.reuse(), "neither a pure base import nor an audited non-execution change: " + PROSE)
        self.assertTrue(self.accepts(self.reuse(non_execution_changes=self.audit()))[0])

    def test_deletion_mode_change_and_rename_of_execution_input_reject(self):
        for kind in ("delete", "mode", "rename"):
            with self.subTest(kind=kind):
                git(self.wt, "reset", "--hard", "HEAD")
                prior = git(self.wt, "rev-parse", "HEAD")
                if kind == "delete":
                    git(self.wt, "rm", "src/dependency.go")
                elif kind == "mode":
                    git(self.wt, "update-index", "--chmod=+x", "src/dependency.go")
                else:
                    git(self.wt, "mv", "src/dependency.go", "qa/runs/dependency.go")
                git(self.wt, "commit", "-q", "-m", kind)
                self.assertRejected(self.reuse(),
                                    "execution input changed, missing or not a regular file: src/dependency.go")
                git(self.wt, "reset", "--hard", prior)

    def test_scope_paths_must_be_exact_regular_files(self):
        shape = "execution_paths must list unique exact files"
        for scope in ([], ["src/**"], ["../x"], ["/tmp/x"], ["src/app.go", "src/app.go"], [None], "src/app.go"):
            with self.subTest(scope=scope):
                self.assertRejected(self.reuse(execution_paths=scope), shape)
        # Well-formed paths that name no regular file at the candidate: a directory, a missing file.
        for scope in (["src"], ["missing.go"]):
            with self.subTest(scope=scope):
                self.assertRejected(self.reuse(execution_paths=scope),
                                    "execution input changed, missing or not a regular file: " + scope[0])

    def test_non_execution_audit_cannot_hide_runtime_or_locks(self):
        for path in ("playbooks/apply/a.yml", "go.sum", "inventory.yml", "src/a.py"):
            with self.subTest(path=path):
                commit(self.wt, path, "changed\n")
                self.assertRejected(self.reuse(non_execution_changes=self.audit(
                    path, "This change was reviewed and described as not affecting target execution.")),
                    "each non-execution change needs an eligible exact path")

    def test_symlink_cannot_masquerade_as_prose(self):
        (self.wt / "docs").mkdir(exist_ok=True)
        os.symlink("../src/app.go", self.wt / "docs/x.md")
        git(self.wt, "add", "docs/x.md")
        git(self.wt, "commit", "-q", "-m", "symlink")
        self.assertRejected(self.reuse(non_execution_changes=self.audit(
            "docs/x.md", "A purported documentation edit which actually aliases runtime code.")),
            "non-execution audit cannot exempt a symlink or submodule: docs/x.md")

    def test_unintegrated_base_rejects(self):
        git(self.wt, "checkout", "-q", "main")
        self.base = commit(self.wt, "another.go", "package another\n")
        git(self.wt, "update-ref", "refs/remotes/origin/main", self.base)
        git(self.wt, "checkout", "-q", "fix/1-x")
        self.assertRejected(self.reuse(), "current base has not been integrated into HEAD")

    def test_missing_tree_and_unrelated_candidate_fail_closed(self):
        ctx = self.ctx()
        ctx.tree_entries = lambda revision: None
        self.assertFalse(ctx.accepts_target(self.candidate, "actual-run", self.reuse()))
        self.assertIn("complete Git trees unavailable", ctx.target_stale_reason(self.candidate))
        git(self.wt, "checkout", "-q", "-b", "unrelated", self.fork)
        other = commit(self.wt, "qa/runs/other.md", "unrelated")
        git(self.wt, "checkout", "-q", "fix/1-x")
        self.assertRejected(self.reuse(), "tested candidate is not an ancestor of HEAD", candidate=other)

    def test_attestation_fields_are_checked_at_their_exact_boundaries(self):
        floor = "dependency review (60+ characters)"
        self.assertRejected(self.reuse(dependency_review="a" * 59 + "   "), floor)
        self.assertTrue(self.accepts(self.reuse(dependency_review="a" * 60))[0])
        self.assertRejected("x", "target reuse must be an object")
        self.assertRejected(self.reuse(), "target reuse needs a full tested candidate SHA", candidate=self.candidate[:12])
        for base in (None, self.base[:12], self.base.upper()):
            with self.subTest(base_sha=base):
                self.assertRejected(self.reuse(base_sha=base), "target reuse needs the current full base SHA")
        for value in (None, "x", {}):
            with self.subTest(non_execution_changes=value):
                self.assertRejected(self.reuse(non_execution_changes=value), "non_execution_changes must be a list")
        # An audit needs a 30+ character explanation (29 refused, 30 accepted).
        commit(self.wt, PROSE, "Latest link and prose, checklist unchanged\n")
        self.assertRejected(self.reuse(non_execution_changes=self.audit(reason="r" * 29 + "  ")),
                            "each non-execution change needs an eligible exact path and a 30+ character explanation")
        self.assertTrue(self.accepts(self.reuse(non_execution_changes=self.audit(reason="r" * 30)))[0])
        for item in (None, {"path": PROSE}, {"reason": AUDIT_REASON}, {"path": None, "reason": AUDIT_REASON}):
            with self.subTest(item=item):
                self.assertRejected(self.reuse(non_execution_changes=[item]),
                                    "each non-execution change needs an eligible exact path")

    def test_audit_must_name_one_changed_path_that_is_not_an_execution_input(self):
        commit(self.wt, PROSE, "Latest link and prose, checklist unchanged\n")
        twice = self.audit() + self.audit()
        self.assertRejected(self.reuse(non_execution_changes=twice), "duplicate or overlapping non-execution change: " + PROSE)
        self.assertRejected(self.reuse(non_execution_changes=self.audit(
            "docs/verification/untouched.md", AUDIT_REASON)),
            "non-execution audit names an unchanged path: docs/verification/untouched.md")
        self.assertTrue(self.accepts(self.reuse(non_execution_changes=self.audit()))[0])


class TargetReuseGuardTests(ReuseHelpers):
    """One counterexample per guard of the reuse rule, on topologies built to isolate it."""

    def setUp(self):
        super().setUp()
        self.root = git(self.wt, "rev-parse", "main")

    def build(self, *, fork=None, candidate=None, main=None, post=None,
              merge=("merge", "-q", "main", "-m", "integrate main")):
        """The shared rule's topology, rebuilt from the root commit on every call.

        main reaches the fork F; the PR branch forks from F and freezes the candidate C
        (`candidate` files; none means C is F); main advances to the base B (`main` files;
        none means B is F, an unadvanced base); `merge` integrates B into the PR branch;
        `post` files are committed after the run, then the evidence-only run record.
        """
        wt = self.wt
        git(wt, "checkout", "-q", "-B", "main", self.root)
        self.fork = commit_files(wt, {"src/dependency.go": "package dependency\n", **(fork or {})}, "fork")
        git(wt, "checkout", "-q", "-B", "fix/1-x", self.fork)
        self.candidate = commit_files(
            wt, {"src/app.go": "package app\n"} if candidate is None else candidate, "candidate")
        git(wt, "checkout", "-q", "main")
        self.base = commit_files(
            wt, {"src/unrelated.go": "package unrelated\n"} if main is None else main, "advance main")
        git(wt, "update-ref", "refs/remotes/origin/main", self.base)
        git(wt, "checkout", "-q", "fix/1-x")
        git(wt, *merge)
        commit_files(wt, post or {}, "after the run")
        commit(wt, "qa/runs/2026/run.md", "Tested " + self.candidate)

    def test_symlinked_scoped_input_requires_new_run(self):
        reason = "execution input changed, missing or not a regular file: playbooks/x.yml"
        scope = ["src/app.go", "src/dependency.go"]
        link = {"src/app.go": "package app\n", "playbooks/x.yml": Link("../lib/real.yml")}
        # The link is byte-identical at the candidate and at HEAD, but main changed the file it names.
        self.build(fork={"lib/real.yml": "v: 1\n"}, candidate=link, main={"lib/real.yml": "v: 2\n"})
        self.assertRejected(self.reuse(execution_paths=scope + ["playbooks/x.yml"]), reason)
        # Naming the regular file the link resolves to is how a reviewer covers it, and then the change shows.
        self.assertRejected(self.reuse(execution_paths=scope + ["lib/real.yml"]),
                            "execution input changed, missing or not a regular file: lib/real.yml")
        # Control: main leaves the file alone, so the regular file is accepted and the link still is not.
        self.build(fork={"lib/real.yml": "v: 1\n"}, candidate=link)
        self.assertTrue(self.accepts(self.reuse(execution_paths=scope + ["lib/real.yml"]))[0])
        self.assertRejected(self.reuse(execution_paths=scope + ["playbooks/x.yml"]), reason)

    def test_candidate_edit_replaced_by_base_version_is_not_a_pure_import(self):
        core = "internal/core.go"
        # The candidate edited an unscoped file and so did main; `-X theirs` keeps main's version, so
        # HEAD's bytes equal main's and look like an import although the run used the candidate's edit.
        self.build(fork={core: "package core // fork\n"},
                   candidate={"src/app.go": "package app\n", core: "package core // candidate\n"},
                   main={core: "package core // main\n"},
                   merge=("merge", "-q", "-X", "theirs", "main", "-m", "integrate main"))
        self.assertEqual(git(self.wt, "rev-parse", "HEAD:" + core), git(self.wt, "rev-parse", self.base + ":" + core))
        self.assertRejected(self.reuse(),
                            "neither a pure base import nor an audited non-execution change: " + core)
        # Control: the same file imported from main when the candidate never touched it is a pure import.
        self.build(fork={core: "package core // fork\n"}, main={core: "package core // main\n"})
        self.assertTrue(self.accepts()[0])

    def test_rebased_candidate_with_identical_scope_is_rejected(self):
        # The PR branch was rebased onto main: every scoped file is byte-identical, but the tested
        # commit is no longer in HEAD's history, so nothing ties the run to what HEAD descends from.
        self.build(merge=("rebase", "-q", "main"))
        rc = subprocess.run(["git", "-C", str(self.wt), "merge-base", "--is-ancestor", self.candidate, "HEAD"]).returncode
        self.assertEqual(1, rc, "precondition: the candidate must not be an ancestor of HEAD")
        for path in ("src/app.go", "src/dependency.go"):
            self.assertEqual(git(self.wt, "rev-parse", self.candidate + ":" + path), git(self.wt, "rev-parse", "HEAD:" + path))
        self.assertRejected(self.reuse(), "tested candidate is not an ancestor of HEAD")
        # Control: the same change integrated by merge keeps the candidate in history.
        self.build()
        self.assertTrue(self.accepts()[0])

    def test_main_commit_cannot_stand_in_for_a_candidate(self):
        # No candidate branch exists: the "candidate" is the commit main had at the fork, and the
        # PR carries only an audited spec-prose edit. Nothing was ever run on a PR candidate.
        self.build(candidate={}, post={PROSE: "prose\n"})
        self.candidate = self.fork
        scoped = self.reuse(execution_paths=["src/dependency.go"], non_execution_changes=self.audit())
        self.assertRejected(scoped, "target reuse requires a candidate branch and an advanced base")
        # Control: the same audit is accepted for a real candidate branch.
        self.build(post={PROSE: "prose\n"})
        self.assertTrue(self.accepts(self.reuse(non_execution_changes=self.audit()))[0])

    def test_unadvanced_base_is_not_an_audit_waiver(self):
        for advanced in (False, True):
            with self.subTest(advanced=advanced):
                self.build(main=None if advanced else {}, post={PROSE: "prose\n"})
                reuse = self.reuse(non_execution_changes=self.audit())
                if advanced:
                    self.assertTrue(self.accepts(reuse)[0])
                else:
                    self.assertEqual(self.fork, self.base, "precondition: main did not advance")
                    self.assertRejected(reuse, "target reuse requires a candidate branch and an advanced base")

    def test_criss_cross_merge_bases_fail_closed(self):
        wt = self.wt
        git(wt, "checkout", "-q", "-B", "main", self.root)
        self.fork = commit(wt, "src/dependency.go", "package dependency\n")
        git(wt, "checkout", "-q", "-B", "fix/1-x", self.fork)
        c1 = commit(wt, "src/app.go", "package app\n")
        git(wt, "checkout", "-q", "main")
        m1 = commit(wt, "src/unrelated.go", "package unrelated\n")
        # Each side merges the other's tip: two commits with identical trees and two merge bases.
        git(wt, "checkout", "-q", "fix/1-x")
        git(wt, "merge", "-q", "--no-ff", "-m", "main into the candidate", m1)
        self.candidate = git(wt, "rev-parse", "HEAD")
        git(wt, "checkout", "-q", "main")
        git(wt, "merge", "-q", "--no-ff", "-m", "the candidate into main", c1)
        self.base = git(wt, "rev-parse", "HEAD")
        git(wt, "update-ref", "refs/remotes/origin/main", self.base)
        git(wt, "checkout", "-q", "fix/1-x")
        git(wt, "merge", "-q", "-m", "integrate main", "main")
        commit(wt, "qa/runs/2026/run.md", "Tested " + self.candidate)
        bases = git(wt, "merge-base", "--all", self.candidate, self.base).splitlines()
        self.assertEqual(sorted([c1, m1]), sorted(bases), "precondition: a criss-cross with two merge bases")
        self.assertEqual(git(wt, "rev-parse", self.candidate + "^{tree}"), git(wt, "rev-parse", self.base + "^{tree}"))
        self.assertRejected(self.reuse(), "target reuse requires a candidate branch and an advanced base")

    def test_attestation_of_older_integrated_base_is_stale(self):
        self.build()
        integrated = self.base
        git(self.wt, "checkout", "-q", "main")
        self.base = commit(self.wt, "src/later.go", "package later\n")
        git(self.wt, "update-ref", "refs/remotes/origin/main", self.base)
        git(self.wt, "checkout", "-q", "fix/1-x")
        # `integrated` is an ancestor of HEAD and a valid advanced base, but main has moved on.
        self.assertRejected(self.reuse(base_sha=integrated), "target reuse base SHA does not match current base")
        self.assertRejected(self.reuse(), "current base has not been integrated into HEAD")
        # Control: integrating the new main and attesting it is accepted.
        git(self.wt, "merge", "-q", "main", "-m", "integrate the new main")
        self.assertTrue(self.accepts()[0])

    def test_audit_cannot_overlap_an_execution_input(self):
        # docs/verification/x.md is an execution input here (an unchanged scoped file) AND audited.
        self.build(candidate={"src/app.go": "package app\n", PROSE: "checklist\n"})
        reuse = self.reuse(execution_paths=["src/app.go", "src/dependency.go", PROSE],
                           non_execution_changes=self.audit())
        self.assertRejected(reuse, "duplicate or overlapping non-execution change: " + PROSE)
        reuse["non_execution_changes"] = []
        self.assertTrue(self.accepts(reuse)[0])


if __name__ == "__main__":
    unittest.main()
