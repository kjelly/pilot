import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pr_gate", ROOT / "scripts" / "pr_gate.py")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
SHA = "0123456789abcdef0123456789abcdef01234567"


def good():
    pr = {"number": 7, "url": "https://github.com/acme/repo/pull/7",
          "headRefOid": SHA, "headRefName": "fix-one", "state": "OPEN",
          "isDraft": True, "mergeable": "MERGEABLE", "reviewDecision": "REVIEW_REQUIRED"}
    checks = [{"name": "go test", "bucket": "pass", "state": "SUCCESS"},
              {"name": "lint", "bucket": "pass", "state": "SUCCESS"}]
    snapshot = module.Snapshot(pr, checks, [checks[0]], [{"id": "T1", "isResolved": True}])
    assessment = {k: True for k in (
        "acceptance_criteria_passed", "root_cause_fixed", "architecture_sound",
        "description_matches_code", "dependencies_resolved", "major_review_comments_resolved",
        "related_ci_failures_resolved")}
    assessment["rationale"] = "AC traced to test cases, issue root cause is fixed and diff matches description."
    evidence = {"schema_version": 1, "repo": "acme/repo", "pr": 7, "head_sha": SHA,
                "assessment": assessment,
                "independent_review": {"agent": "pr-reviewer", "head_sha": SHA, "status": "PASS",
                                       "blocking_findings": [], "report": "Evidence-backed separate reviewer response"},
                "local_validation": {key: [{"command": f"run {key}", "exit_code": 0,
                                           "head_sha": SHA, "log": f".pr-ready/logs/{key}.log"}]
                                     for key in ("tests", "lint", "static_analysis")},
                "unresolved_nonblocking_threads": [], "unrelated_failing_checks": []}
    return snapshot, evidence


class GateTests(unittest.TestCase):
    def check(self, snapshot, evidence, local=(SHA, "fix-one", [])):
        return module.evaluate(snapshot, evidence, repo="acme/repo", number=7, local=local)

    def test_good_with_review_required(self):
        s, e = good()
        self.assertEqual([], self.check(s, e))

    def test_evidence_sha_stale(self):
        s, e = good()
        e["head_sha"] = "f" * 40
        self.assertTrue(any("Evidence SHA" in x for x in self.check(s, e)))

    def test_review_sha_stale(self):
        s, e = good()
        e["independent_review"]["head_sha"] = "f" * 40
        self.assertTrue(any("reviewer" in x for x in self.check(s, e)))

    def test_required_check_failed_cannot_exempt(self):
        s, e = good()
        s.required_checks[0]["bucket"] = "fail"
        e["unrelated_failing_checks"] = [{"name": "go test", "reason": "Long specific reason about unrelated failure",
                                          "reviewer_confirmed": True}]
        self.assertTrue(any("Required" in x for x in self.check(s, e)))

    def test_no_checks_fails_closed(self):
        s, e = good()
        s.checks = []
        s.required_checks = []
        self.assertTrue(any("No CI checks" in x for x in self.check(s, e)))

    def test_unresolved_review_thread(self):
        s, e = good()
        s.threads[0]["isResolved"] = False
        self.assertTrue(any("Unresolved" in x for x in self.check(s, e)))

    def test_minor_thread_with_explicit_exemption(self):
        s, e = good()
        s.threads[0]["isResolved"] = False
        e["unresolved_nonblocking_threads"] = [
            {"id": "T1", "severity": "P3", "reason": "Stylistic suggestion unrelated to acceptance criteria",
             "reviewer_confirmed": True}]
        self.assertEqual([], self.check(s, e))

    def test_pending_check_fails_closed(self):
        s, e = good()
        s.checks[1]["bucket"] = "pending"
        self.assertTrue(any("Nonpassing" in x for x in self.check(s, e)))

    def test_unrelated_nonrequired_check(self):
        s, e = good()
        s.checks[1]["bucket"] = "fail"
        e["unrelated_failing_checks"] = [{"name": "lint", "reason": "Unrelated external-only failure confirmed by CI trace",
                                          "reviewer_confirmed": True}]
        self.assertEqual([], self.check(s, e))

    def test_changes_requested_not_human_reapproval_gate(self):
        s, e = good()
        s.pr["reviewDecision"] = "CHANGES_REQUESTED"
        self.assertEqual([], self.check(s, e))
        e["assessment"]["major_review_comments_resolved"] = False
        self.assertTrue(any("major_review_comments_resolved" in x for x in self.check(s, e)))

    def test_mergeability_unknown_blocks(self):
        s, e = good()
        s.pr["mergeable"] = "UNKNOWN"
        self.assertTrue(any("Mergeability" in x for x in self.check(s, e)))

    def test_local_dirty_or_wrong_branch_blocks(self):
        s, e = good()
        errs = self.check(s, e, (SHA, "something-else", ["?? hello.go"]))
        self.assertTrue(any("branch" in x for x in errs))
        self.assertTrue(any("uncommitted" in x for x in errs))

    def test_no_lint_requires_justification(self):
        s, e = good()
        e["local_validation"]["lint"] = {"not_applicable": "No linter"}
        self.assertTrue(any("not-applicable" in x for x in self.check(s, e)))
        e["local_validation"]["lint"] = {"not_applicable": "This project has no lint entry in its Makefile or CI workflow."}
        self.assertEqual([], self.check(s, e))

    def test_malformed_receipt_or_bool_rejected(self):
        s, e = good()
        e["assessment"]["root_cause_fixed"] = "true"
        e["local_validation"]["tests"][0]["exit_code"] = True
        errs = self.check(s, e)
        self.assertTrue(any("root_cause_fixed" in x for x in errs))
        self.assertTrue(any("did not pass" in x for x in errs))

    def test_install_global_smoke(self):
        # No real $HOME changes: installs into a temporary path only.
        with tempfile.TemporaryDirectory() as tmp:
            env = __import__("os").environ.copy()
            env["HOME"] = tmp
            installer = ROOT / "scripts" / "install.sh"
            for attempt in range(2):
                p = subprocess.run(["bash", str(installer), "--global"], capture_output=True,
                                   text=True, env=env)
                self.assertEqual(0, p.returncode, p.stderr)
            home = Path(tmp)
            self.assertTrue((home / ".agents/skills/pr-ready/SKILL.md").is_file())
            self.assertTrue((home / ".claude/skills/pr-ready/SKILL.md").is_file())
            self.assertTrue((home / ".gemini/antigravity-cli/skills/pr-ready/SKILL.md").is_file())
            self.assertTrue((home / ".codex/agents/pr-sa.toml").is_file())
            self.assertTrue((home / ".claude/agents/pr-reviewer.md").is_file())
            self.assertTrue((home / ".gemini/config/agents/pr-coder.md").is_file())

    def test_install_project_smoke(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = subprocess.run(["git", "init", "--quiet", tmp], capture_output=True, text=True)
            self.assertEqual(0, p.returncode, p.stderr)
            p = subprocess.run(["bash", str(ROOT / "scripts/install.sh"), "--project", tmp],
                               capture_output=True, text=True)
            self.assertEqual(0, p.returncode, p.stderr)
            project = Path(tmp)
            self.assertTrue((project / ".agents/skills/pr-ready/SKILL.md").is_file())
            self.assertTrue((project / ".claude/skills/pr-ready/SKILL.md").is_file())
            self.assertTrue((project / ".agents/agents/pr-sa.md").is_file())
            self.assertTrue((project / ".codex/agents/pr-reviewer.toml").is_file())

    def test_run_check_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cmds = [["git", "init", "--quiet"], ["git", "config", "user.name", "test"],
                    ["git", "config", "user.email", "test@example.org"]]
            for argv in cmds:
                subprocess.run(argv, cwd=root, check=True, stdout=subprocess.DEVNULL)
            (root / "hello").write_text("hello")
            subprocess.run(["git", "add", "hello"], cwd=root, check=True)
            subprocess.run(["git", "commit", "--quiet", "-m", "initial"], cwd=root, check=True)
            p = subprocess.run([sys.executable, str(ROOT / "scripts/run_check.py"), "--category", "tests",
                                "--", sys.executable, "-c", "print('pass')"], cwd=root,
                               capture_output=True, text=True)
            self.assertEqual(0, p.returncode, p.stderr)
            receipt = json.loads(p.stdout)
            self.assertEqual(0, receipt["exit_code"])
            self.assertTrue((root / receipt["log"]).is_file())


if __name__ == "__main__":
    unittest.main()
