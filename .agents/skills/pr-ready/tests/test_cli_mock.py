"""Isolated end-to-end smoke tests; never call real GitHub."""
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("pr_gate", ROOT / "scripts" / "pr_gate.py")
gate = importlib.util.module_from_spec(spec)
sys.modules["pr_gate"] = gate
spec.loader.exec_module(gate)

MOCK_GH = '''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
state = pathlib.Path(os.environ["FAKE_GH_STATE"])
sha = os.environ["FAKE_GH_SHA"]
checks = [{"name": "go test", "bucket": "pass", "state": "SUCCESS"},
          {"name": "lint", "bucket": "pass", "state": "SUCCESS"}]
if (state / "fail").exists():
    checks[0]["bucket"] = "fail"
if args[:2] == ["pr", "view"]:
    print(json.dumps({"number": 7, "url": "https://github.com/acme/repo/pull/7",
        "headRefOid": sha, "headRefName": "fix-one", "state": "OPEN",
        "isDraft": not (state / "ready").exists(), "mergeable": "MERGEABLE", "reviewDecision": "REVIEW_REQUIRED"}))
elif args[:2] == ["pr", "checks"]:
    print(json.dumps(checks[:1] if "--required" in args else checks))
elif args[:2] == ["api", "graphql"]:
    print(json.dumps({"data": {"repository": {"pullRequest": {
        "reviewThreads": {"nodes": [], "pageInfo": {"hasNextPage": False, "endCursor": None}}
    }}}}))
elif args[:2] == ["pr", "ready"]:
    (state / "ready").write_text("yes")
else:
    print(f"unsupported mock args {args}", file=sys.stderr)
    sys.exit(1)
'''


class CLIMockTests(unittest.TestCase):
    def test_ready_only_after_checks_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo = t / "repo"
            repo.mkdir()
            for args in (["git", "init", "--quiet", "-b", "fix-one"],
                         ["git", "config", "user.name", "tester"],
                         ["git", "config", "user.email", "test@example.org"]):
                subprocess.run(args, cwd=repo, check=True, capture_output=True)
            (repo / "file").write_text("something", encoding="utf-8")
            subprocess.run(["git", "add", "file"], cwd=repo, check=True)
            subprocess.run(["git", "commit", "--quiet", "-m", "init"], cwd=repo, check=True)
            sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            validations = {}
            for category in ("tests", "lint", "static_analysis"):
                log = repo / ".pr-ready" / "logs" / (category + ".log")
                log.parent.mkdir(parents=True, exist_ok=True)
                log.write_text("pass", encoding="utf-8")
                validations[category] = [{"command": "command " + category, "exit_code": 0,
                                          "head_sha": sha, "log": str(log.relative_to(repo))}]
            evidence = {"schema_version": 1, "repo": "acme/repo", "pr": 7, "head_sha": sha,
                        "assessment": {**{key: True for key in (
                            "acceptance_criteria_passed", "root_cause_fixed", "architecture_sound",
                            "description_matches_code", "dependencies_resolved", "major_review_comments_resolved",
                            "related_ci_failures_resolved")},
                            "rationale": "Issue and acceptance criteria independently checked against the actual PR diff."},
                        "independent_review": {"agent": "pr-reviewer", "head_sha": sha,
                                               "status": "PASS", "blocking_findings": [],
                                               "report": "Independent review completed on current HEAD."},
                        "local_validation": validations}
            evidence_file = repo / ".pr-ready/evidence.json"
            evidence_file.write_text(json.dumps(evidence), encoding="utf-8")
            bin_dir = t / "bin"
            bin_dir.mkdir()
            gh = bin_dir / "gh"
            gh.write_text(MOCK_GH, encoding="utf-8")
            gh.chmod(0o755)
            env = os.environ.copy()
            env.update(PATH=f"{bin_dir}{os.pathsep}{env['PATH']}", FAKE_GH_STATE=str(t), FAKE_GH_SHA=sha)
            cli = [sys.executable, str(ROOT / "scripts/pr_gate.py"), "--repo", "acme/repo", "--pr", "7",
                   "--worktree", str(repo), "--evidence", str(evidence_file), "--ready"]
            (t / "fail").touch()
            blocked = subprocess.run(cli, env=env, capture_output=True, text=True)
            self.assertEqual(2, blocked.returncode, blocked.stderr)
            self.assertEqual("DRAFT-BLOCKED", json.loads(blocked.stdout)["status"])
            self.assertFalse((t / "ready").exists())
            (t / "fail").unlink()
            ready = subprocess.run(cli, env=env, capture_output=True, text=True)
            self.assertEqual(0, ready.returncode, ready.stderr or ready.stdout)
            self.assertEqual("READY", json.loads(ready.stdout)["status"])
            self.assertTrue((t / "ready").exists())


if __name__ == '__main__':
    unittest.main()
