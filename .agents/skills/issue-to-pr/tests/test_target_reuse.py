"""Candidate-bound target reuse after main advances. Real Git, no mocked provenance."""
import unittest

from test_repo_evidence import Base, commit, git


class TargetReuseTests(Base):
    from test_repo_evidence import MANIFEST
    manifest = {**MANIFEST, "required_evidence": [
        {**MANIFEST["required_evidence"][0], "kind": "target-run"}]}
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

    def reuse(self, **kw):
        return dict({"head_sha": git(self.wt, "rev-parse", "HEAD"), "base_sha": self.base,
                     "reviewer_confirmed": True,
                     "dependency_review": "Reviewed every execution input and its dependencies; unrelated.go is outside the target invocation and cannot affect its outcome.",
                     "execution_paths": ["src/app.go", "src/dependency.go"],
                     "non_execution_changes": []}, **kw)

    def accepts(self, reuse=None):
        ctx = self.ctx()
        result = ctx.accepts_target(self.candidate, "actual-run", self.reuse() if reuse is None else reuse)
        return result, ctx

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
        self.assertFalse(self.ctx().accepts_target(self.candidate, "actual-run"))
        for kw in ({"head_sha": self.candidate}, {"base_sha": self.fork},
                   {"reviewer_confirmed": False}, {"dependency_review": "unchanged"}):
            with self.subTest(kw=kw):
                self.assertFalse(self.accepts(self.reuse(**kw))[0])

    def test_changed_shared_dependency_is_rejected_even_when_imported_from_main(self):
        git(self.wt, "checkout", "-q", "main")
        self.base = commit(self.wt, "src/dependency.go", "package dependency // new semantics\n")
        git(self.wt, "update-ref", "refs/remotes/origin/main", self.base)
        git(self.wt, "checkout", "-q", "fix/1-x")
        git(self.wt, "merge", "-q", "main", "-m", "dependency changed")
        ok, ctx = self.accepts()
        self.assertFalse(ok)
        self.assertIn("execution input changed", ctx.target_stale_reason(self.candidate))

    def test_local_runtime_edit_cannot_be_declared_unrelated(self):
        commit(self.wt, "src/other.go", "package other\n")
        ok, ctx = self.accepts()
        self.assertFalse(ok)
        self.assertIn("neither a pure base import", ctx.target_stale_reason(self.candidate))
        # It cannot be hidden behind the non-execution audit either.
        r = self.reuse(non_execution_changes=[{"path": "src/other.go", "reason": "This is unrelated to the particular target execution."}])
        self.assertFalse(self.accepts(r)[0])

    def test_conflict_resolution_changes_execution_and_is_rejected(self):
        git(self.wt, "checkout", "-q", "main")
        self.base = commit(self.wt, "src/app.go", "package app // base conflict\n")
        git(self.wt, "update-ref", "refs/remotes/origin/main", self.base)
        git(self.wt, "checkout", "-q", "fix/1-x")
        import subprocess
        p = subprocess.run(["git", "-C", str(self.wt), "merge", "main"], capture_output=True)
        self.assertNotEqual(0, p.returncode)
        commit(self.wt, "src/app.go", "package app // resolved differently\n")
        self.assertFalse(self.accepts()[0])

    def test_runtime_blend_outside_declared_scope_still_rejected(self):
        # Even a reviewer omitting app.go cannot authorize a locally changed runtime file.
        commit(self.wt, "src/app.go", "package app // blend\n")
        self.assertFalse(self.accepts(self.reuse(execution_paths=["src/dependency.go"]))[0])

    def test_audited_prose_change_accepts_but_unreviewed_does_not(self):
        commit(self.wt, "docs/verification/x.md", "Latest link and prose, checklist unchanged\n")
        self.assertFalse(self.accepts()[0])
        audit = [{"path": "docs/verification/x.md", "reason": "Only latest evidence link and prose changed; no command, expected value or variable contract changed."}]
        self.assertTrue(self.accepts(self.reuse(non_execution_changes=audit))[0])

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
                self.assertFalse(self.accepts()[0])
                git(self.wt, "reset", "--hard", prior)

    def test_scope_paths_must_be_exact_regular_files(self):
        for scope in ([], ["src/**"], ["../x"], ["/tmp/x"], ["src"],
                      ["src/app.go", "src/app.go"], ["missing.go"], [None]):
            with self.subTest(scope=scope):
                self.assertFalse(self.accepts(self.reuse(execution_paths=scope))[0])

    def test_non_execution_audit_cannot_hide_runtime_or_locks(self):
        for path in ("playbooks/apply/a.yml", "go.sum", "inventory.yml", "src/a.py"):
            with self.subTest(path=path):
                commit(self.wt, path, "changed\n")
                self.assertFalse(self.accepts(self.reuse(non_execution_changes=[
                    {"path": path, "reason": "This change was reviewed and described as not affecting target execution."}]))[0])

    def test_symlink_cannot_masquerade_as_prose(self):
        import os
        (self.wt / "docs").mkdir(exist_ok=True)
        os.symlink("../src/app.go", self.wt / "docs/x.md")
        git(self.wt, "add", "docs/x.md")
        git(self.wt, "commit", "-q", "-m", "symlink")
        self.assertFalse(self.accepts(self.reuse(non_execution_changes=[
            {"path": "docs/x.md", "reason": "A purported documentation edit which actually aliases runtime code."}]))[0])

    def test_unintegrated_base_rejects(self):
        git(self.wt, "checkout", "-q", "main")
        self.base = commit(self.wt, "another.go", "package another\n")
        git(self.wt, "update-ref", "refs/remotes/origin/main", self.base)
        git(self.wt, "checkout", "-q", "fix/1-x")
        self.assertFalse(self.accepts()[0])

    def test_missing_tree_and_unrelated_candidate_fail_closed(self):
        ctx = self.ctx()
        ctx.tree_entries = lambda revision: None
        self.assertFalse(ctx.accepts_target(self.candidate, "actual-run", self.reuse()))
        git(self.wt, "checkout", "-q", "-b", "unrelated", self.fork)
        other = commit(self.wt, "qa/runs/other.md", "unrelated")
        git(self.wt, "checkout", "-q", "fix/1-x")
        self.assertFalse(self.ctx().accepts_target(other, "actual-run", self.reuse()))


if __name__ == "__main__":
    unittest.main()
