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
        self.write("scripts/pr_loop.py")
        self.write("scripts/other.py")
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

    def profile_of(self, change):
        """The CLI's profile for `change` applied to the base commit, over a real merge."""
        self.git("checkout", "-q", "--detach", self.base)
        self.git("reset", "-q", "--hard")
        change()
        self.commit()
        env, _ = self.context()
        result = self.cli(env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(result.stdout.startswith("profile="), result.stdout)
        return result.stdout.removeprefix("profile=").strip()

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

    def test_pr_loop_runner_alone_or_with_skill_or_design_document_selects_skills(self):
        # The runner is read only by the skills job's tests. A design document next to it
        # must not downgrade the result to docs: skill-test still has to run.
        cases = {
            "runner alone": lambda: self.write("scripts/pr_loop.py", "changed"),
            "runner and a skill file": lambda: (self.write("scripts/pr_loop.py", "changed"),
                                                self.write(".agents/skills/a/script.py", "x")),
            "runner and a design document": lambda: (self.write("scripts/pr_loop.py", "changed"),
                                                     self.write("docs/superpowers/plans/design.md", "updated")),
        }
        for name, change in cases.items():
            with self.subTest(name):
                self.assertEqual(self.profile_of(change), "skills")

    def test_runner_next_to_any_other_input_is_full(self):
        others = {
            "README.md": lambda: self.write("README.md", "docs"),
            "Go source": lambda: self.write("runtime.go", "changed"),
            "Go test": lambda: self.write("cmd/pilot/cmd/x_test.go", "package cmd"),
            "this script": lambda: self.write("scripts/ci-impact.py", "changed"),
            "another script": lambda: self.write("scripts/other.py", "changed"),
            "script test": lambda: self.write("scripts/tests/x.py", "changed"),
            "workflow": lambda: self.write(".github/workflows/ci.yml", "changed"),
            "Makefile": lambda: self.write("Makefile", "changed"),
        }
        for name, other in others.items():
            with self.subTest(name):
                self.assertEqual(self.profile_of(lambda: (self.write("scripts/pr_loop.py", "changed"), other())), "full")

    def test_only_the_exact_runner_path_is_a_skills_path(self):
        # A prefix match would turn scripts/pr_loop.py/x.go (a Go package directory) into a
        # skipped change.
        lookalikes = ["scripts/pr_loop.py.bak", "scripts/pr_loop.pyc", "scripts/pr_loop.py/x",
                      "scripts/pr_loop.py/x.go", "scripts/pr_loop.py~", "scripts/pr_loop.py/",
                      "scripts/pr_loop", "scripts/pr_loop_result.py", "x/scripts/pr_loop.py",
                      "Scripts/pr_loop.py", "scripts/Pr_loop.py", "./scripts/pr_loop.py",
                      "scripts//pr_loop.py", "/scripts/pr_loop.py", "scripts/../scripts/pr_loop.py",
                      " scripts/pr_loop.py", "scripts/pr_loop.py\n", "scripts", "scripts/", ""]
        self.assertEqual(impact.path_kind("scripts/pr_loop.py"), "skills")
        for path in lookalikes:
            with self.subTest(path=path):
                self.assertEqual(impact.path_kind(path), "full")
                self.assertEqual(impact.classify([".agents/skills/a/SKILL.md", path]), "full")
                self.assertEqual(impact.classify(["scripts/pr_loop.py", path]), "full")

    def test_the_declared_constants_are_what_path_kind_uses(self):
        # cmd/pilot/cmd reads these constants, so path_kind must not carry a list of its own.
        for prefix in impact.SKILL_PREFIXES:
            self.assertEqual(impact.path_kind(prefix + "x/y"), "skills", prefix)
        for name in impact.SKILL_FILES:
            self.assertEqual(impact.path_kind(name), "skills", name)
        for prefix in impact.DOC_PREFIXES:
            self.assertEqual(impact.path_kind(prefix + "x.md"), "docs", prefix)
            self.assertEqual(impact.path_kind(prefix + "x.yaml"), "full", prefix)
        self.assertEqual(impact.SKILL_FILES, frozenset({"scripts/pr_loop.py"}))
        self.assertEqual(impact.path_kind("README.md"), "full")

    def test_removing_the_runner_is_a_skills_change(self):
        self.assertEqual(self.profile_of(lambda: self.git("rm", "-q", "scripts/pr_loop.py")), "skills")

    def test_mode_only_change_of_the_runner_is_a_skills_change(self):
        # Only the mode differs: the content is the fixture's, and commit() stages the real file mode.
        self.assertEqual(self.profile_of(lambda: os.chmod(self.root / "scripts/pr_loop.py", 0o755)), "skills")

    def test_moving_the_runner_is_judged_by_both_paths(self):
        # The selection lists the removed and the added path (--no-renames).
        moves = {
            "next to it": ("scripts/pr_loop2.py", "full"),
            "beside another script": ("scripts/other2.py", "full"),
            "into skills": (".agents/skills/_shared/scripts/pr_loop.py", "skills"),
        }
        for name, (target, want) in moves.items():
            with self.subTest(name):
                def move(target=target):
                    (self.root / target).parent.mkdir(parents=True, exist_ok=True)
                    self.git("mv", "scripts/pr_loop.py", target)
                self.assertEqual(self.profile_of(move), want)

    def test_runtime_file_moved_onto_the_runner_path_is_full(self):
        self.assertEqual(self.profile_of(lambda: self.git("mv", "-f", "runtime.go", "scripts/pr_loop.py")), "full")

    def test_runner_replaced_by_a_directory_is_full(self):
        def replace():
            self.git("rm", "-q", "scripts/pr_loop.py")
            self.write("scripts/pr_loop.py/x.go", "package x")
        self.assertEqual(self.profile_of(replace), "full")

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
