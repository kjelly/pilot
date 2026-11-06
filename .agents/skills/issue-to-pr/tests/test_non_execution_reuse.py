"""Target and review reuse after main advances, by declared non-execution paths (kjelly/pilot#304).

Phase 1: a pure base import of files the manifest declares a target run never reads keeps the
target record (no reviewer attestation) and the independent review; never a check receipt.
Phase 3: a machine record whose closure has unresolved or external inputs survives a reviewed
import of runtime files outside that closure, never one it can reach or one in `rerun_paths`.

Real Git graphs. As in test_target_reuse, every guard has a counterexample in which it is the ONLY
guard that rejects, and the test asserts that guard's own reason text.
"""
import json
import unittest

import test_target_reuse as ttr  # imported as a module so its TestCases are not collected twice
from test_repo_evidence import commit, git, re_
from test_target_reuse import Link

ART = "qa/runs/2026/run.md"
REASON = "Another component's playbook: no include, lookup, template or spec of this run names it."
MANIFEST = {
    "schema_version": 1,
    "evidence_only_paths": ["qa/evidence/**"],
    "non_execution_paths": [".agents/**", "*.md", "docs/**/*.md", "**/*_test.go", ".github/**"],
    "non_execution_exclude": ["docs/verification/**"],
    "required_evidence": [{"id": "e2e-run", "source": "CONTRIBUTING.md#verification", "kind": "target-run",
                           "artifact_glob": "qa/runs/**/*.md", "required_paths": ["playbooks/**"],
                           "rerun_paths": ["internal/**", "**/*.go", "go.mod", "images/**"]}]}
# What a default (ambient-controller) record of this repository carries: never a complete closure.
UNRESOLVED = [
    {"from": "environment", "ref": "ambient Ansible plugin discovery",
     "reason": "external plugin, collection and Python discovery paths are not fingerprinted"},
    {"from": "src/app.go", "ref": "unsupported task dispatch",
     "reason": "automatic reuse supports only literal copy and debug.msg actions"},
    {"from": "src/app.go", "ref": "{{ freeipa_roster_file }}",
     "reason": "reference is a variable; the file it names is an input of the run, not of the tree"},
    {"from": "src/app.go", "ref": "files/{{ name }}.md", "reason": "dynamic path is a conservative glob"},
]
EXTERNAL = ["/home/operator/.vault/sandbox.yaml"]


class NonExecutionBase(ttr.ReuseHelpers):
    manifest = MANIFEST
    build = ttr.TargetReuseGuardTests.build

    def setUp(self):
        super().setUp()
        self.root = git(self.wt, "rev-parse", "main")

    def record(self, *, unresolved=None, external=None, patterns=("src/dependency*.go",),
               files=("src/app.go", "src/dependency.go"), **top):
        """A pilot-evidence-record for the candidate, committed as the evidence-only artifact."""
        ctx = self.ctx()
        tree = ctx.tree_entries(self.candidate)
        record = {"schema": "pilot-evidence-record/v1", "outcome": "success",
                  "candidate": {"commit": self.candidate, "tree": ctx.commit_tree(self.candidate), "source": "git"},
                  "closure": {"resolution_version": 10, "frozen": True,
                              "files": [{"path": p, "mode": tree[p][0], "blob": tree[p][1]} for p in files],
                              "patterns": list(patterns),
                              "unresolved": UNRESOLVED if unresolved is None else unresolved,
                              "external": EXTERNAL if external is None else external}}
        record.update(top)
        commit(self.wt, ART, "<!-- pilot-evidence-record v1 -->\n```json\n" + json.dumps(record) + "\n```\n")
        return record

    def auto(self, artifact=ART, rid="e2e-run"):
        """Target reuse with NO reviewer attestation."""
        ctx = self.ctx()
        return ctx.accepts_target(self.candidate, "actual-run", None, artifact, rid), ctx

    def assertAutoRejected(self, reason, **kw):
        ok, ctx = self.auto(**kw)
        self.assertFalse(ok, "accepted, expected: " + reason)
        self.assertIn(reason, ctx.target_stale_reason(self.candidate))

    def reviewed(self, **kw):
        reuse = self.reuse(**kw)
        del reuse["execution_paths"]  # a machine record supplies the scope
        ctx = self.ctx()
        return ctx.accepts_target(self.candidate, "actual-run", reuse, ART, "e2e-run"), ctx

    def assertReviewedRejected(self, reason, **kw):
        ok, ctx = self.reviewed(**kw)
        self.assertFalse(ok, "accepted, expected: " + reason)
        self.assertIn(reason, ctx.target_stale_reason(self.candidate))

    def unrelated(self, path, reason=REASON):
        return [{"path": path, "reason": reason}]


PROSE_IMPORT = {".agents/skills/x/SKILL.md": "rule\n", ".agents/skills/x/scripts/gate.py": "print()\n",
                "AGENTS.md": "rules\n", "docs/runbooks/x.md": "steps\n",
                "internal/spec/lint_test.go": "package spec\n", ".github/workflows/ci.yml": "on: push\n"}


class Phase1NonExecutionImportTests(NonExecutionBase):
    def test_pr_259_shape_keeps_the_record_without_attestation(self):
        """Main brings only skills, prose, a Go test and CI configuration: no new run."""
        self.build(main=PROSE_IMPORT)
        self.record()
        ok, ctx = self.auto()
        self.assertTrue(ok, ctx.target_stale_reason(self.candidate))
        accepted = ctx.report()["delta_accepted"][-1]
        self.assertEqual("non-execution-base-import", accepted["method"])
        self.assertEqual(sorted(PROSE_IMPORT), accepted["changed"])
        self.assertEqual(self.base, accepted["base"])
        # A hand-written (legacy) record takes the same import.
        commit(self.wt, ART, "Tested " + self.candidate)
        self.assertTrue(self.auto()[0])

    def test_check_receipts_never_carry_and_reviews_do(self):
        self.build(main=PROSE_IMPORT)
        ctx = self.ctx()
        # The imported Go test must run against the PR's code: receipts stay on evidence-only deltas.
        self.assertFalse(ctx.accepts(self.candidate, "checks[0]"))
        self.assertTrue(ctx.accepts_review(self.candidate, "independent_review"))
        self.assertEqual("non-execution-base-import", ctx.report()["delta_accepted"][-1]["method"])

    def test_review_refuses_a_runtime_import_with_both_reasons(self):
        self.build(main={"src/unrelated.go": "package unrelated\n"})
        ctx = self.ctx()
        self.assertFalse(ctx.accepts_review(self.candidate, "independent_review"))
        reason = ctx.review_stale_reason(self.candidate)
        self.assertIn("files outside evidence_only_paths changed: src/unrelated.go", reason)
        self.assertIn("non-execution reuse: base import is not a declared non-execution path: src/unrelated.go", reason)

    def test_runtime_and_excluded_imports_are_not_non_execution(self):
        for path in ("src/unrelated.go", "docs/verification/other.md", "playbooks/apply/other.yml", "Makefile"):
            with self.subTest(path=path):
                self.build(main={path: "changed\n"})
                self.record()
                self.assertAutoRejected("base import is not a declared non-execution path: " + path)

    def test_required_paths_and_excludes_override_a_matching_glob(self):
        ctx = self.ctx()
        for path in (".agents/x.md", "README.md", "docs/a/b.md", "pkg/a_test.go", ".github/x.json"):
            self.assertTrue(ctx.non_execution_path(path), path)
        for path in ("docs/verification/x.md", "pkg/a.go", "playbooks/README.md", "README.txt", "../x.md"):
            self.assertFalse(ctx.non_execution_path(path), path)
        ctx = re_.Context(self.wt, "0" * 40, {**MANIFEST, "required_evidence": [
            {**MANIFEST["required_evidence"][0], "required_paths": [".agents/hooks/**"]}]}, [], [])
        self.assertFalse(ctx.non_execution_path(".agents/hooks/x.md"))
        self.assertTrue(ctx.non_execution_path(".agents/skills/x.md"))

    def test_local_edit_and_conflict_blend_are_not_base_imports(self):
        self.build(main=PROSE_IMPORT, post={"docs/runbooks/local.md": "PR-side edit\n"})
        self.record()
        self.assertAutoRejected("change is neither evidence-only nor a pure base import: docs/runbooks/local.md")
        # Both sides edit the same skill file; Git merges the two edits into a blend of both.
        self.build(fork={".agents/x.md": "1\n2\n3\n4\n5\n6\n"},
                   candidate={"src/app.go": "package app\n", ".agents/x.md": "one\n2\n3\n4\n5\n6\n"},
                   main={".agents/x.md": "1\n2\n3\n4\n5\nsix\n"})
        self.assertEqual("one\n2\n3\n4\n5\nsix\n", (self.wt / ".agents/x.md").read_text(), "precondition: a blend")
        self.record()
        self.assertAutoRejected("change is neither evidence-only nor a pure base import: .agents/x.md")

    def test_symlink_import_is_refused(self):
        self.build(main={".agents/link.md": Link("../src/app.go")})
        self.record()
        self.assertAutoRejected("non-execution import must be a regular file: .agents/link.md")

    def test_closure_reach_refuses_even_a_declared_path(self):
        # A closure file: a run that read docs/runbooks/x.md (a lookup) has it hashed.
        self.build(fork={"docs/runbooks/x.md": "v1\n"}, main={"docs/runbooks/x.md": "v2\n"})
        self.record(files=("src/app.go", "src/dependency.go", "docs/runbooks/x.md"))
        self.assertAutoRejected("reachable from the recorded closure (a closure file): docs/runbooks/x.md")
        # A search pattern (an existing member changed, so membership itself is unchanged).
        self.build(fork={".agents/hooks/a.md": "v1\n"}, main={".agents/hooks/a.md": "v2\n"})
        self.record(patterns=("src/dependency*.go", ".agents/hooks/*.md"))
        self.assertAutoRejected("(closure search pattern .agents/hooks/*.md): .agents/hooks/a.md")
        # An unresolved templated reference: files/{{ name }}.md can name a new file under files/.
        self.build(main={".agents/files/new.md": "x\n"})
        self.record()
        self.assertAutoRejected("(unresolved reference files/{{ name }}.md): .agents/files/new.md")
        # The file holding unresolved references is itself an input.
        self.build(fork={"docs/x.md": "v1\n"}, main={"docs/x.md": "v2\n"})
        self.record(unresolved=[{"from": "docs/x.md", "ref": "lookup/query expression", "reason": "lookup"}])
        self.assertAutoRejected("(a file with unresolved references): docs/x.md")

    def test_record_identity_is_still_checked(self):
        self.build(main=PROSE_IMPORT)
        self.record(outcome="failed")
        self.assertAutoRejected("target chain did not succeed")
        self.record(closure={"resolution_version": 9, "frozen": True, "files": [], "patterns": []})
        self.assertAutoRejected("current resolution version")

    def test_unintegrated_or_unadvanced_base_is_refused(self):
        self.build(main=PROSE_IMPORT)
        self.record()
        git(self.wt, "checkout", "-q", "main")
        self.base = commit(self.wt, "AGENTS.md", "newer rules\n")
        git(self.wt, "update-ref", "refs/remotes/origin/main", self.base)
        git(self.wt, "checkout", "-q", "fix/1-x")
        self.assertAutoRejected("current base has not been integrated into HEAD")
        self.build(main={}, post={"docs/runbooks/x.md": "local\n"})
        self.assertAutoRejected("target reuse requires a candidate branch and an advanced base")

    def test_only_a_target_run_item_with_a_declared_policy_qualifies(self):
        self.build(main=PROSE_IMPORT)
        self.record()
        ctx = self.ctx()
        ctx.required["coverage"] = {"id": "coverage", "source": "CI policy"}
        self.assertFalse(ctx.accepts_target(self.candidate, "coverage", None, ART, "coverage"))
        self.assertEqual("files outside evidence_only_paths changed: " + ", ".join(sorted(PROSE_IMPORT)[:5]),
                         ctx.target_stale_reason(self.candidate))
        no_policy = {k: v for k, v in MANIFEST.items() if k not in ("non_execution_paths", "non_execution_exclude")}
        ctx = re_.Context(self.wt, git(self.wt, "rev-parse", "HEAD"), no_policy, [], [], "refs/remotes/origin/main")
        self.assertFalse(ctx.accepts_target(self.candidate, "actual-run", None, ART, "e2e-run"))
        self.assertFalse(ctx.accepts_review(self.candidate, "independent_review"))

    def test_required_record_entry_uses_the_shared_policy(self):
        self.build(main=PROSE_IMPORT)
        self.record()
        entry = {"id": "e2e-run", "status": "pass", "head_sha": self.candidate, "artifact": ART,
                 "summary": "VM target chain and failure paths passed on the candidate."}
        self.assertEqual([], self.ctx().check_required([entry]))

    def test_manifest_validation(self):
        bad = {**MANIFEST, "non_execution_paths": ["**"]}
        self.assertTrue(any("non_execution_paths[0]" in e for e in re_.validate_manifest(bad)))
        bad = {**MANIFEST, "non_execution_exclude": ["/abs"]}
        self.assertIn("non_execution_exclude must be a list of repository-relative globs", re_.validate_manifest(bad))
        item = {"id": "coverage", "source": "CI", "rerun_paths": ["x/**"]}
        self.assertIn("required_evidence[0].rerun_paths requires kind: target-run",
                      re_.validate_manifest({"schema_version": 1, "required_evidence": [item]}))
        self.assertEqual([], re_.validate_manifest(MANIFEST))


class Phase3ReviewedIncompleteClosureTests(NonExecutionBase):
    def test_reviewed_runtime_import_outside_the_closure_is_accepted(self):
        self.build(main={"playbooks/apply/other.yml": "- hosts: other\n", **PROSE_IMPORT})
        self.record()
        ok, ctx = self.reviewed(unrelated_runtime_changes=self.unrelated("playbooks/apply/other.yml"))
        self.assertTrue(ok, ctx.target_stale_reason(self.candidate))
        accepted = ctx.report()["delta_accepted"][-1]
        self.assertEqual("reviewed-base-integration", accepted["method"])
        self.assertIs(False, accepted["closure_complete"])
        self.assertEqual(["playbooks/apply/other.yml"], [u["path"] for u in accepted["unrelated_runtime_changes"]])
        # Declared non-execution imports need no entry; the runtime one does.
        self.assertReviewedRejected("closure has unresolved or external inputs; base import outside the closure "
                                    "needs a reviewed unrelated_runtime_changes entry: playbooks/apply/other.yml")

    def test_rerun_paths_cannot_be_waived(self):
        for path in ("internal/x/y.go", "src/unrelated.go", "go.mod", "images/Dockerfile"):
            with self.subTest(path=path):
                self.build(main={path: "changed\n"})
                self.record()
                self.assertReviewedRejected("always needs a new run (rerun_paths): " + path,
                                            unrelated_runtime_changes=self.unrelated(path))

    def test_closure_reach_cannot_be_waived(self):
        self.build(fork={"playbooks/apply/tasks/shared.yml": "v1\n"}, main={"playbooks/apply/tasks/shared.yml": "v2\n"})
        self.record(patterns=("src/dependency*.go", "playbooks/apply/tasks/*.yml"))
        self.assertReviewedRejected("(closure search pattern playbooks/apply/tasks/*.yml): playbooks/apply/tasks/shared.yml",
                                    unrelated_runtime_changes=self.unrelated("playbooks/apply/tasks/shared.yml"))
        self.build(main={"playbooks/apply/files/new.md": "x\n"})
        self.record()
        self.assertReviewedRejected("(unresolved reference files/{{ name }}.md): playbooks/apply/files/new.md",
                                    unrelated_runtime_changes=self.unrelated("playbooks/apply/files/new.md"))

    def test_local_runtime_edit_cannot_be_declared_unrelated(self):
        self.build(post={"playbooks/apply/other.yml": "local\n"})
        self.record()
        self.assertReviewedRejected("neither a pure base import nor an audited non-execution change: playbooks/apply/other.yml",
                                    unrelated_runtime_changes=self.unrelated("playbooks/apply/other.yml"))

    def test_symlink_import_outside_the_closure_is_refused(self):
        self.build(main={"playbooks/apply/other.yml": Link("../../src/app.go")})
        self.record()
        self.assertReviewedRejected("base import outside the closure must be a regular file: playbooks/apply/other.yml",
                                    unrelated_runtime_changes=self.unrelated("playbooks/apply/other.yml"))

    def test_entries_are_checked(self):
        self.build(main={"playbooks/apply/other.yml": "x\n"})
        self.record()
        self.assertReviewedRejected("30+ character explanation",
                                    unrelated_runtime_changes=self.unrelated("playbooks/apply/other.yml", "r" * 29 + " "))
        self.assertTrue(self.reviewed(unrelated_runtime_changes=self.unrelated("playbooks/apply/other.yml", "r" * 30))[0])
        self.assertReviewedRejected("names an unchanged path: playbooks/apply/untouched.yml",
                                    unrelated_runtime_changes=self.unrelated("playbooks/apply/other.yml")
                                    + self.unrelated("playbooks/apply/untouched.yml"))
        self.assertReviewedRejected("duplicate or overlapping unrelated runtime change: src/app.go",
                                    unrelated_runtime_changes=self.unrelated("src/app.go"))
        self.assertReviewedRejected("duplicate or overlapping unrelated runtime change: playbooks/apply/other.yml",
                                    unrelated_runtime_changes=self.unrelated("playbooks/apply/other.yml") * 2)
        for value in ("x", {}, None):
            with self.subTest(value=value):
                self.assertReviewedRejected("unrelated_runtime_changes must be a list", unrelated_runtime_changes=value)
        for entry in ({"path": "../x", "reason": REASON}, {"path": "playbooks/apply/other.yml"}, "x"):
            with self.subTest(entry=entry):
                self.assertReviewedRejected("each unrelated runtime change needs an exact path",
                                            unrelated_runtime_changes=[entry])

    def test_entries_only_apply_to_an_incomplete_machine_closure(self):
        self.build(main={"playbooks/apply/other.yml": "x\n"})  # build() commits a hand-written record
        reuse = self.reuse(unrelated_runtime_changes=self.unrelated("playbooks/apply/other.yml"))
        self.assertRejected(reuse, "applies only to a machine record whose closure has unresolved or external inputs")

    def test_without_rerun_paths_an_incomplete_closure_still_fails_closed(self):
        item = {k: v for k, v in MANIFEST["required_evidence"][0].items() if k != "rerun_paths"}
        self.manifest = {**MANIFEST, "required_evidence": [item]}
        git(self.wt, "checkout", "-q", "-B", "main", self.root)
        commit(self.wt, ".github/pr-evidence.json", json.dumps(self.manifest))
        self.root = git(self.wt, "rev-parse", "HEAD")
        self.build(main={"playbooks/apply/other.yml": "x\n"})
        self.record()
        self.assertReviewedRejected("machine record: closure has unresolved or external inputs",
                                    unrelated_runtime_changes=self.unrelated("playbooks/apply/other.yml"))
        # Phase 1 is independent of rerun_paths: a non-execution import still keeps the record.
        self.build(main=PROSE_IMPORT)
        self.record()
        self.assertTrue(self.auto()[0])

    def test_reference_regex(self):
        rx = re_.reference_regex
        for ref in ("ambient Ansible plugin discovery", "{{ roster }}", "{{ a }}/{{ b }}", "/abs/x.yml", "", None, 3):
            self.assertIsNone(rx(ref), ref)
        self.assertTrue(rx("files/{{ name }}.sh").match("playbooks/apply/files/x.sh"))
        self.assertFalse(rx("files/{{ name }}.sh").match("playbooks/apply/files/x.py"))
        self.assertTrue(rx("ansible.cfg").match("ansible.cfg"))
        self.assertTrue(rx("../tasks/x.yml").match("playbooks/apply/tasks/x.yml"))
        self.assertTrue(rx("{{ d }}.pilot-backup").match("playbooks/apply/a.pilot-backup"))


if __name__ == "__main__":
    unittest.main()
