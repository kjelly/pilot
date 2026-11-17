"""Impact selection over real Git merges, and fail-closed job result checks."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "ci-impact.py"
spec = importlib.util.spec_from_file_location("impact", SCRIPT)
impact = importlib.util.module_from_spec(spec)
spec.loader.exec_module(impact)


class SelectionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.env = {**os.environ, "GIT_AUTHOR_NAME": "CI test", "GIT_COMMITTER_NAME": "CI test",
                    "GIT_AUTHOR_EMAIL": "test@example.org", "GIT_COMMITTER_EMAIL": "test@example.org"}
        self.git("init", "-q")
        self.write("runtime.go")
        self.write(".agents/skills/a/SKILL.md")
        self.write("docs/superpowers/plans/design.md")
        self.base = self.commit()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, env=self.env,
                                       stderr=subprocess.DEVNULL).decode().strip()

    def write(self, path, body="original"):
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(body)

    def commit(self):
        self.git("add", ".")
        self.git("commit", "-qm", "fixture", "--allow-empty")
        return self.git("rev-parse", "HEAD")

    def cli(self, *args, env=None):
        return subprocess.run([sys.executable, str(SCRIPT), *args], cwd=self.root,
                              env={**self.env, **(env or {})}, capture_output=True, text=True, timeout=30)

    def context(self):
        head = self.git("rev-parse", "HEAD")
        self.git("checkout", "--detach", self.base)
        self.git("merge", "--no-ff", "-qm", "frozen merge", head)
        merge = self.git("rev-parse", "HEAD")
        event = {"pull_request": {"number": 1,
                 "head": {"sha": head, "repo": {"full_name": "acme/pilot"}},
                 "base": {"sha": self.base, "repo": {"full_name": "acme/pilot"}}}}
        event_path = self.root / ".git/event.json"
        event_path.write_text(json.dumps(event))
        return {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": str(event_path),
                "GITHUB_REPOSITORY": "acme/pilot", "GITHUB_SHA": merge}, event

    def test_skill_change_and_design_document_select_skills(self):
        self.write(".agents/skills/a/script.py", "print('test')")
        self.write("docs/superpowers/plans/design.md", "updated")
        self.commit()
        env, _ = self.context()
        summary = self.root / ".git/summary.md"
        result = self.cli(env={**env, "GITHUB_STEP_SUMMARY": str(summary)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "profile=skills\n")
        self.assertIn("**skills**", summary.read_text())

    def test_design_docs_select_docs(self):
        self.write("docs/superpowers/plans/design.md", "updated")
        self.commit()
        env, _ = self.context()
        self.assertEqual(self.cli(env=env).stdout, "profile=docs\n")

    def test_runtime_moved_into_allowlist_still_selects_full(self):
        self.git("mv", "runtime.go", ".agents/skills/a/runtime.go")
        self.commit()
        env, _ = self.context()
        self.assertEqual(self.cli(env=env).stdout, "profile=full\n")

    def test_deleted_skill_is_classified_and_odd_filename_is_not_split(self):
        self.git("rm", ".agents/skills/a/SKILL.md")
        self.write(".agents/skills/a/space and\nnewline.md")
        self.commit()
        env, _ = self.context()
        self.assertEqual(self.cli(env=env).stdout, "profile=skills\n")

    def test_fork_non_pr_bad_event_missing_history_and_wrong_checkout_run_full(self):
        self.write(".agents/skills/a/script.py")
        self.commit()
        env, event = self.context()
        for override in ({"GITHUB_EVENT_NAME": "push"}, {"GITHUB_EVENT_NAME": "workflow_dispatch"},
                         {"GITHUB_SHA": "0" * 40}, {"GITHUB_EVENT_PATH": "/does/not/exist"}):
            with self.subTest(override=override):
                self.assertEqual(self.cli(env={**env, **override}).stdout, "profile=full\n")
        event["pull_request"]["head"]["repo"]["full_name"] = "fork/pilot"
        Path(env["GITHUB_EVENT_PATH"]).write_text(json.dumps(event))
        self.assertEqual(self.cli(env=env).stdout, "profile=full\n")
        Path(env["GITHUB_EVENT_PATH"]).write_text("not JSON")
        self.assertEqual(self.cli(env=env).stdout, "profile=full\n")

    def test_empty_change_is_full(self):
        self.commit()
        env, _ = self.context()
        self.assertEqual(self.cli(env=env).stdout, "profile=full\n")

    def test_mixed_shared_and_unknown_paths_are_full(self):
        paths = ["go.mod", "go.sum", "Makefile", ".github/workflows/ci.yml", "scripts/ci-impact.py",
                 "internal/spec/example_test.go", "cmd/pilot/cmd/example_test.go",
                 "playbooks/apply/wazuh-manager-apply.yml", "playbooks/apply/tasks/shared.yml",
                 "docs/verification/wazuh-fim.md", "docs/runbooks/example.md", "README.md",
                 "group_vars/example.yml", "contracts/example.yml", "new-folder/input",
                 ".agents/config.toml", ".claude/settings.json", "docs/superpowers/plans/input.yaml"]
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual(impact.classify([".agents/skills/a/SKILL.md", path]), "full")

    def test_base_advance_uses_actual_tested_parent_not_stale_event_base(self):
        # The actual tested base has advanced. Compare the tested merge against
        # its first parent rather than assuming the PR event describes that base.
        self.write("runtime.go", "new base")
        actual_base = self.commit()
        self.git("checkout", "--detach", self.base)
        self.write(".agents/skills/a/SKILL.md", "changed skill")
        head = self.commit()
        self.git("checkout", "--detach", actual_base)
        self.git("merge", "--no-ff", "-qm", "merge", head)
        merge = self.git("rev-parse", "HEAD")
        event = {"pull_request": {"number": 1,
                 "head": {"sha": head, "repo": {"full_name": "acme/pilot"}},
                 "base": {"sha": self.base, "repo": {"full_name": "acme/pilot"}}}}
        path = self.root / ".git/event.json"
        path.write_text(json.dumps(event))
        env = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": str(path),
               "GITHUB_REPOSITORY": "acme/pilot", "GITHUB_SHA": merge}
        self.assertEqual(self.cli(env=env).stdout, "profile=skills\n")


class ResultTests(unittest.TestCase):
    def results(self, profile="full", evidence="false", receipt=True):
        full = profile == "full" and evidence == "false"
        return {name: {"result": "success" if (name in {"changes", "skills"} or
                (full and (name != "ci-receipt" or receipt))) else "skipped"}
                for name in impact.RESULT_JOBS}

    def test_full_narrow_and_reused_results(self):
        for profile in ("full", "skills", "docs"):
            for evidence in ("true", "false"):
                for receipt in (True, False):
                    impact.check_results(self.results(profile, evidence, receipt), profile, evidence, receipt)

    def test_every_unexpected_failure_cancellation_or_skip_blocks(self):
        for profile in ("full", "skills", "docs"):
            for name in impact.RESULT_JOBS:
                good = self.results(profile)
                expected = good[name]["result"]
                for result in {"success", "failure", "cancelled", "skipped", "pending"} - {expected}:
                    with self.subTest(profile=profile, name=name, result=result), self.assertRaises(ValueError):
                        bad = copy.deepcopy(good)
                        bad[name]["result"] = result
                        impact.check_results(bad, profile, "false", True)

    def test_missing_outputs_or_result_jobs_block(self):
        for profile, evidence in (("", "false"), ("typo", "false"), ("full", "")):
            with self.assertRaises(ValueError):
                impact.check_results(self.results(), profile, evidence, True)
        for name in impact.RESULT_JOBS:
            bad = self.results()
            del bad[name]
            with self.assertRaises(ValueError):
                impact.check_results(bad, "full", "false", True)
        with self.assertRaises(ValueError):
            impact.check_results({**self.results(), "unknown": {"result": "success"}}, "full", "false", True)

    def test_cli_gate_rejects_failed_and_malformed_results(self):
        env = {**os.environ, "CI_PROFILE": "skills", "EVIDENCE_ONLY": "false", "RECEIPT_REQUIRED": "true"}
        for needs, rc in ((self.results("skills"), 0), (self.results(), 1), ({}, 1), (None, 1)):
            run = subprocess.run([sys.executable, str(SCRIPT), "--check-results"],
                                 env={**env, "NEEDS_JSON": json.dumps(needs)}, capture_output=True, timeout=10)
            self.assertEqual(run.returncode, rc, run.stderr)

    def test_cli_gate_rejects_missing_or_invalid_receipt_requirement(self):
        for value in ("", "unknown"):
            env = {**os.environ, "CI_PROFILE": "full", "EVIDENCE_ONLY": "false",
                   "RECEIPT_REQUIRED": value, "NEEDS_JSON": json.dumps(self.results())}
            result = subprocess.run([sys.executable, str(SCRIPT), "--check-results"],
                                    env=env, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
