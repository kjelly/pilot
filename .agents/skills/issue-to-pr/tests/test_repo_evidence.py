"""repo_evidence: evidence-only deltas and repository-required evidence. Offline, real git."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import repo_evidence as re_  # noqa: E402

MANIFEST = {"schema_version": 1,
            "evidence_only_paths": ["qa/evidence/**"],
            "required_evidence": [{"id": "e2e-run", "source": "CONTRIBUTING.md#verification",
                                   "artifact_glob": "qa/runs/**/*.md"}]}


def git(path, *args):
    return subprocess.run(["git", "-C", str(path), *args], text=True, capture_output=True, check=True).stdout.strip()


def commit(path, name, text="x\n", msg=None):
    f = Path(path) / name
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(text)
    git(path, "add", name)
    git(path, "commit", "-q", "-m", msg or name)
    return git(path, "rev-parse", "HEAD")


class Base(unittest.TestCase):
    manifest = MANIFEST

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.wt = Path(tmp.name)
        git(self.wt, "init", "-q", "-b", "main")
        git(self.wt, "config", "user.email", "t@example.org")
        git(self.wt, "config", "user.name", "t")
        if self.manifest is not None:
            commit(self.wt, ".github/pr-evidence.json", json.dumps(self.manifest))
        else:
            commit(self.wt, "README", "r")
        git(self.wt, "update-ref", "refs/remotes/origin/main", "HEAD")
        git(self.wt, "checkout", "-q", "-b", "fix/1-x")
        self.code = commit(self.wt, "src/app.go", "package app\n")

    def ctx(self):
        return re_.Context.load(self.wt, git(self.wt, "rev-parse", "HEAD"), "refs/remotes/origin/main")


class DeltaTests(Base):
    def test_same_sha_is_always_accepted(self):
        self.assertTrue(self.ctx().accepts(self.code, "r"))

    def test_evidence_only_delta_is_accepted_and_reported(self):
        commit(self.wt, "qa/evidence/run.md", "ok\n")
        ctx = self.ctx()
        self.assertTrue(ctx.accepts(self.code, "checks[0]"))
        self.assertEqual(["qa/evidence/run.md"], ctx.report()["delta_accepted"][0]["changed"])

    def test_code_in_the_delta_is_rejected(self):
        commit(self.wt, "qa/evidence/run.md", "ok\n")
        commit(self.wt, "src/app.go", "package app // changed\n")
        ctx = self.ctx()
        self.assertFalse(ctx.accepts(self.code, "r"))
        self.assertIn("src/app.go", ctx.stale_reason(self.code))

    def test_non_ancestor_and_garbage_are_rejected(self):
        git(self.wt, "checkout", "-q", "-b", "other", "main")
        other = commit(self.wt, "qa/evidence/o.md")
        git(self.wt, "checkout", "-q", "fix/1-x")
        ctx = self.ctx()
        self.assertFalse(ctx.accepts(other, "r"))
        self.assertFalse(ctx.accepts("nonsense", "r"))
        self.assertFalse(ctx.accepts(None, "r"))

    def test_required_artifact_glob_counts_as_evidence_only(self):
        commit(self.wt, "qa/runs/2026/run.md", "ok\n")
        self.assertTrue(self.ctx().accepts(self.code, "r"))

    def test_deleting_or_renaming_code_is_a_code_change(self):
        (self.wt / "qa/evidence").mkdir(parents=True)
        git(self.wt, "mv", "src/app.go", "qa/evidence/app.go")
        git(self.wt, "commit", "-q", "-m", "move")
        self.assertFalse(self.ctx().accepts(self.code, "r"))


class ManifestSourceTests(Base):
    manifest = None

    def test_without_manifest_delta_is_strict_and_warns(self):
        commit(self.wt, "qa/evidence/run.md")
        ctx = self.ctx()
        self.assertFalse(ctx.accepts(self.code, "r"))
        self.assertIn("NOT machine-checked", " ".join(ctx.warnings))

    def test_pr_cannot_grant_itself_an_allowlist(self):
        commit(self.wt, ".github/pr-evidence.json", json.dumps(MANIFEST))
        commit(self.wt, "qa/evidence/run.md")
        self.assertFalse(self.ctx().accepts(self.code, "r"))

    def test_missing_base_ref_warns_and_stays_strict(self):
        ctx = re_.Context.load(self.wt, self.code, "refs/remotes/origin/nope")
        self.assertIn("not found locally", " ".join(ctx.warnings))
        self.assertFalse(ctx.accepts("a" * 40, "r"))


class ManifestValidationTests(unittest.TestCase):
    def test_whole_tree_globs_rejected(self):
        for glob in ("**", "*", "**/*", "**/*.go"):
            errs = re_.validate_manifest({"schema_version": 1, "evidence_only_paths": [glob]})
            self.assertTrue(errs, glob)
        self.assertEqual([], re_.validate_manifest({"schema_version": 1, "evidence_only_paths": ["qa/evidence/**", "*.md"]}))

    def test_escaping_and_absolute_globs_rejected(self):
        for glob in ("/etc/**", "../x/**"):
            self.assertTrue(re_.validate_manifest({"schema_version": 1, "evidence_only_paths": [glob]}), glob)

    def test_required_items_need_id_and_source(self):
        self.assertTrue(re_.validate_manifest({"schema_version": 1, "required_evidence": [{"id": "Bad Id", "source": "x"}]}))
        self.assertTrue(re_.validate_manifest({"schema_version": 1, "required_evidence": [{"id": "ok"}]}))
        dup = [{"id": "a", "source": "s"}, {"id": "a", "source": "s"}]
        self.assertTrue(re_.validate_manifest({"schema_version": 1, "required_evidence": dup}))

    def test_glob_semantics(self):
        rx = re_.glob_regex("qa/evidence/**")
        self.assertTrue(rx.match("qa/evidence/a/b.md"))
        self.assertFalse(rx.match("docs/evidence"))
        self.assertFalse(re_.glob_regex("docs/*.md").match("docs/a/b.md"))
        self.assertTrue(re_.glob_regex("docs/**/*.md").match("docs/b.md"))


class RequiredEvidenceTests(Base):
    def entry(self, **kw):
        base = {"id": "e2e-run", "status": "pass", "head_sha": self.code,
                "artifact": "qa/runs/2026/run.md", "summary": "Staging run: base fails the smoke suite, candidate passes."}
        return {**base, **kw}

    def with_artifact(self):
        commit(self.wt, "qa/runs/2026/run.md", "evidence\n")

    def test_missing_required_entry_blocks(self):
        errs = self.ctx().check_required([])
        self.assertTrue(any("e2e-run" in e and "missing" in e for e in errs))
        self.assertTrue(any("missing" in e for e in self.ctx().check_required(None)))

    def test_valid_entry_with_committed_artifact_after_evidence_only_delta(self):
        self.with_artifact()
        self.assertEqual([], self.ctx().check_required([self.entry()]))

    def test_artifact_must_be_committed_at_head(self):
        errs = self.ctx().check_required([self.entry()])
        self.assertTrue(any("not committed at HEAD" in e for e in errs))

    def test_artifact_must_live_in_declared_location(self):
        commit(self.wt, "qa/evidence/run.md")
        errs = self.ctx().check_required([self.entry(artifact="qa/evidence/run.md")])
        self.assertTrue(any("outside the required location" in e for e in errs))

    def test_run_before_a_code_change_is_stale(self):
        self.with_artifact()
        commit(self.wt, "src/app.go", "package app // later\n")
        errs = self.ctx().check_required([self.entry()])
        self.assertTrue(any("not HEAD" in e and "src/app.go" in e for e in errs))

    def test_bad_artifact_paths_and_thin_summary(self):
        self.with_artifact()
        for art in ("/etc/passwd", "../x", ""):
            self.assertTrue(self.ctx().check_required([self.entry(artifact=art)]), art)
        self.assertTrue(any("summary" in e for e in self.ctx().check_required([self.entry(summary="ok")])))

    def test_not_applicable_needs_reason_and_reviewer(self):
        na = {"id": "e2e-run", "status": "not-applicable"}
        self.assertTrue(self.ctx().check_required([na]))
        na.update(reason="Docs-only change; no runtime behaviour touched at all.", reviewer_confirmed=True)
        self.assertEqual([], self.ctx().check_required([na]))

    def required_paths(self, paths=("deploy/**",)):
        """Base manifest whose e2e-run also lists required_paths; HEAD is still the fix branch."""
        head = git(self.wt, "rev-parse", "HEAD")
        git(self.wt, "checkout", "-q", "main")
        manifest = json.loads(json.dumps(MANIFEST))
        manifest["required_evidence"][0]["required_paths"] = list(paths)
        commit(self.wt, ".github/pr-evidence.json", json.dumps(manifest))
        git(self.wt, "update-ref", "refs/remotes/origin/main", "HEAD")
        git(self.wt, "checkout", "-q", "fix/1-x")
        self.assertEqual(head, git(self.wt, "rev-parse", "HEAD"))

    NA = {"id": "e2e-run", "status": "not-applicable", "reviewer_confirmed": True,
          "reason": "Docs-only change; no runtime behaviour touched at all."}

    def test_not_applicable_is_refused_for_required_paths(self):
        # pr-review-merge refuses not-needed for these paths; refusing here keeps an issue-to-pr PR from
        # reaching Ready only to wait at the merge gate.
        self.required_paths()
        self.assertEqual([], self.ctx().check_required([self.NA]))  # src/app.go is not covered
        commit(self.wt, "deploy/site.yml", "- hosts: all\n")
        errs = self.ctx().check_required([self.NA])
        self.assertTrue(any("not-applicable is refused" in e and "deploy/site.yml" in e for e in errs), errs)

    def test_required_paths_see_both_names_of_a_rename(self):
        self.required_paths()
        # The file is on the base branch already; the change only moves it out of deploy/.
        git(self.wt, "checkout", "-q", "main")
        commit(self.wt, "deploy/old.yml", "- hosts: all\n")
        git(self.wt, "update-ref", "refs/remotes/origin/main", "HEAD")
        git(self.wt, "checkout", "-q", "fix/1-x")
        git(self.wt, "merge", "-q", "--no-edit", "main")
        self.assertEqual([], self.ctx().check_required([self.NA]))
        git(self.wt, "mv", "deploy/old.yml", "old.yml")
        git(self.wt, "commit", "-q", "-m", "move it out")
        errs = self.ctx().check_required([self.NA])
        self.assertTrue(any("deploy/old.yml" in e for e in errs), errs)

    def test_changes_on_the_base_branch_alone_do_not_count(self):
        # Only the change itself (from the merge base) counts, not what the base branch did since.
        self.required_paths()
        git(self.wt, "checkout", "-q", "main")
        commit(self.wt, "deploy/later.yml", "- hosts: all\n")
        git(self.wt, "update-ref", "refs/remotes/origin/main", "HEAD")
        git(self.wt, "checkout", "-q", "fix/1-x")
        self.assertEqual([], self.ctx().check_required([self.NA]))

    def test_required_paths_need_a_listable_change(self):
        self.required_paths()
        ctx = self.ctx()
        ctx.base_ref = "refs/remotes/origin/no-such-branch"
        self.assertTrue(any("cannot be listed" in e for e in ctx.check_required([self.NA])))

    def test_required_paths_must_be_relative_globs(self):
        base = json.loads(json.dumps(MANIFEST))
        for paths in ("deploy/**", ["/etc/**"], ["../x"], [""], [1], ["a\\b"]):
            with self.subTest(paths=paths):
                base["required_evidence"][0]["required_paths"] = paths
                self.assertTrue(any("required_paths must be" in e for e in re_.validate_manifest(base)))
        base["required_evidence"][0]["required_paths"] = ["**"]  # broad is stricter, so allowed
        self.assertEqual([], re_.validate_manifest(base))

    def test_unknown_status_duplicates_and_extra_entries_are_validated(self):
        self.with_artifact()
        self.assertTrue(self.ctx().check_required([self.entry(status="done")]))
        self.assertTrue(any("more than once" in e for e in self.ctx().check_required([self.entry(), self.entry()])))
        extra = {"id": "agents-md-extra", "status": "pass", "head_sha": "a" * 40,
                 "artifact": "qa/runs/2026/run.md", "summary": "Listed from AGENTS.md by the agent."}
        self.assertTrue(any("agents-md-extra" in e for e in self.ctx().check_required([self.entry(), extra])))

    def test_invalid_manifest_blocks_everything(self):
        commit(self.wt, "x")
        git(self.wt, "checkout", "-q", "main")
        commit(self.wt, ".github/pr-evidence.json", '{"schema_version": 1, "evidence_only_paths": ["**"]}')
        git(self.wt, "update-ref", "refs/remotes/origin/main", "HEAD")
        git(self.wt, "checkout", "-q", "fix/1-x")
        errs = self.ctx().check_required([])
        self.assertTrue(any("defeat SHA binding" in e for e in errs))


class OtherLayoutTests(unittest.TestCase):
    """Nothing is tied to one repository layout or language: any globs, any evidence location."""

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.wt = Path(tmp.name)
        git(self.wt, "init", "-q", "-b", "trunk")
        git(self.wt, "config", "user.email", "t@example.org")
        git(self.wt, "config", "user.name", "t")
        manifest = {"schema_version": 1, "evidence_only_paths": ["test-reports/**"],
                    "required_evidence": [{"id": "compat-matrix", "source": "CONTRIBUTING.md#testing"},
                                          {"id": "staging-e2e", "source": "docs/release.md",
                                           "artifact_glob": "test-reports/staging/**"}]}
        commit(self.wt, ".github/pr-evidence.json", json.dumps(manifest))
        git(self.wt, "update-ref", "refs/remotes/origin/trunk", "HEAD")
        git(self.wt, "checkout", "-q", "-b", "feature")
        self.tested = commit(self.wt, "pkg/core.py", "x = 1\n")

    def ctx(self):
        return re_.Context.load(self.wt, git(self.wt, "rev-parse", "HEAD"), "refs/remotes/origin/trunk")

    def entries(self, **url_kw):
        return [{"id": "compat-matrix", "status": "pass", "head_sha": self.tested,
                 "url": "https://ci.example.org/runs/123", "summary": "py3.9-3.12 matrix green on the candidate."},
                {"id": "staging-e2e", "status": "pass", "head_sha": self.tested,
                 "artifact": "test-reports/staging/run-1.html", "summary": "Playwright suite green on staging."}]

    def test_external_url_and_committed_report_in_a_python_repo(self):
        commit(self.wt, "test-reports/staging/run-1.html", "<html/>")
        self.assertEqual([], self.ctx().check_required(self.entries()))

    def test_url_not_allowed_when_manifest_demands_a_committed_artifact(self):
        commit(self.wt, "test-reports/staging/run-1.html", "<html/>")
        entries = self.entries()
        entries[1] = {k: v for k, v in entries[1].items() if k != "artifact"}
        entries[1]["url"] = "https://ci.example.org/runs/9"
        self.assertTrue(any("staging-e2e" in e and "repository-relative" in e for e in self.ctx().check_required(entries)))

    def test_url_must_be_https(self):
        commit(self.wt, "test-reports/staging/run-1.html", "<html/>")
        entries = self.entries()
        entries[0]["url"] = "http://ci.example.org/runs/123"
        self.assertTrue(any("https://" in e for e in self.ctx().check_required(entries)))

    def test_external_evidence_still_goes_stale_after_a_code_change(self):
        commit(self.wt, "test-reports/staging/run-1.html", "<html/>")
        commit(self.wt, "pkg/core.py", "x = 2\n")
        errs = self.ctx().check_required(self.entries())
        self.assertTrue(any("compat-matrix" in e and "not HEAD" in e for e in errs))


if __name__ == "__main__":
    unittest.main()
