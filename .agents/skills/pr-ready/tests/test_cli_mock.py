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

MOCK_GH = r'''#!/usr/bin/env python3
import json, os, pathlib, re, sys
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
    query = next(a[len("query="):] for a in args if a.startswith("query="))
    field = re.search(r"pullRequest\(number:\$number\)\s*\{\s*(\w+)", query).group(1)
    with (state / "graphql.log").open("a") as log:
        log.write(field + "\n")
    nodes_file = state / (field + ".json")
    nodes = json.loads(nodes_file.read_text()) if nodes_file.exists() else []
    print(json.dumps({"data": {"repository": {"pullRequest": {
        field: {"nodes": nodes, "pageInfo": {"hasNextPage": False, "endCursor": None}}
    }}}}))
elif args[:2] == ["pr", "ready"]:
    (state / "ready").write_text("yes")
else:
    print(f"unsupported mock args {args}", file=sys.stderr)
    sys.exit(1)
'''


class CLIMockTests(unittest.TestCase):
    def make_pr(self, t):
        """Create a committed PR worktree, passing evidence and a fake-gh environment."""
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
        bin_dir = t / "bin"
        bin_dir.mkdir()
        gh = bin_dir / "gh"
        gh.write_text(MOCK_GH, encoding="utf-8")
        gh.chmod(0o755)
        env = os.environ.copy()
        env.update(PATH=f"{bin_dir}{os.pathsep}{env['PATH']}", FAKE_GH_STATE=str(t), FAKE_GH_SHA=sha)
        return repo, sha, evidence, env

    def gate(self, repo, evidence, env, *extra):
        evidence_file = repo / ".pr-ready/evidence.json"
        evidence_file.write_text(json.dumps(evidence), encoding="utf-8")
        cli = [sys.executable, str(ROOT / "scripts/pr_gate.py"), "--repo", "acme/repo", "--pr", "7",
               "--worktree", str(repo), "--evidence", str(evidence_file), *extra]
        return subprocess.run(cli, env=env, capture_output=True, text=True)

    def test_ready_only_after_checks_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, _, evidence, env = self.make_pr(t)
            (t / "fail").touch()
            blocked = self.gate(repo, evidence, env, "--ready")
            self.assertEqual(2, blocked.returncode, blocked.stderr)
            self.assertEqual("DRAFT-BLOCKED", json.loads(blocked.stdout)["status"])
            self.assertFalse((t / "ready").exists())
            (t / "fail").unlink()
            ready = self.gate(repo, evidence, env, "--ready")
            self.assertEqual(0, ready.returncode, ready.stderr or ready.stdout)
            self.assertEqual("READY", json.loads(ready.stdout)["status"])
            self.assertTrue((t / "ready").exists())
            # Without disputes the gate never reads conversation comments or reviews.
            self.assertNotIn("comments", (t / "graphql.log").read_text().split())

    def test_disputed_comment_is_checked_against_github(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, sha, evidence, env = self.make_pr(t)
            review = "https://github.com/acme/repo/pull/7#issuecomment-6494548870"
            reply = "https://github.com/acme/repo/pull/7#issuecomment-6501033173"
            comments = [{"url": review, "createdAt": "2026-10-29T10:44:27Z", "body": "[P2] gate accepts []"},
                        {"url": reply, "createdAt": "2026-10-29T15:32:36Z",
                         "body": f"Re {review}: does not hold, pr_gate.py rejects an empty list."}]
            (t / "comments.json").write_text(json.dumps(comments), encoding="utf-8")
            evidence["disputed_review_comments"] = [{
                "source_url": review, "reply_url": reply, "disposition": "invalid",
                "claim": "P2: the gate accepts an empty local_validation list",
                "counter_evidence": "pr_gate.py rejects an empty list; the unit test fails without that branch",
                "head_sha": sha, "reviewer_confirmed": True}]
            passed = self.gate(repo, evidence, env)
            self.assertEqual(0, passed.returncode, passed.stdout)
            self.assertEqual("GATE-PASS", json.loads(passed.stdout)["status"])
            self.assertEqual({"reviewThreads", "comments", "reviews"},
                             set((t / "graphql.log").read_text().split()))
            comments[1]["body"] = "Does not hold, pr_gate.py rejects an empty list."
            (t / "comments.json").write_text(json.dumps(comments), encoding="utf-8")
            blocked = self.gate(repo, evidence, env, "--ready")
            self.assertEqual(2, blocked.returncode, blocked.stdout)
            self.assertTrue(any("does not link" in x for x in json.loads(blocked.stdout)["errors"]))
            self.assertFalse((t / "ready").exists())


if __name__ == '__main__':
    unittest.main()
