"""Isolated end-to-end smoke tests; never call real GitHub."""
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

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
if (state / "phrase_check").exists():
    checks[0].update(name="Build (no required checks reported)", state="FAILURE", bucket="fail")
if args[:2] == ["pr", "view"]:
    # Every `pr view` is logged. state/bases.json (a list) gives baseRefOid by call index, the last
    # entry repeating, so a test can move the base between the gate's reads.
    with (state / "views.log").open("a") as log:
        log.write("view\n")
    call = len((state / "views.log").read_text().split()) - 1
    bases = json.loads((state / "bases.json").read_text()) if (state / "bases.json").exists() else [sha]
    print(json.dumps({"number": 7, "url": "https://github.com/acme/repo/pull/7",
        "headRefOid": sha, "headRefName": "fix-one", "baseRefOid": bases[min(call, len(bases) - 1)],
        "baseRefName": "main", "state": "OPEN",
        "isDraft": not (state / "ready").exists(), "mergeable": "MERGEABLE", "reviewDecision": "REVIEW_REQUIRED"}))
elif args[:2] == ["pr", "checks"] and "--required" in args and (state / "checks_error").exists():
    print("HTTP 502: Bad Gateway", file=sys.stderr)
    sys.exit(1)
elif args[:2] == ["pr", "checks"] and "--required" in args and (state / "no_required").exists():
    # Real gh 2.103.3 on a branch without required checks: exit 1, no stdout, this stderr line.
    print("no required checks reported on the 'fix-one' branch", file=sys.stderr)
    sys.exit(1)
elif args[:2] == ["pr", "checks"]:
    print(json.dumps(checks[:1] if "--required" in args else checks))
    # Real gh exits 1 when a check failed, with the JSON still on stdout.
    sys.exit(1 if checks[0]["bucket"] == "fail" else 0)
elif args[0] == "api" and (state / "api.json").exists() and any(
        k in args[-1] for k in json.loads((state / "api.json").read_text())):
    # state/api.json maps a substring of the endpoint (contents, compare, git/trees, branches) to the
    # JSON body gh would print; the first matching key answers.
    table = json.loads((state / "api.json").read_text())
    print(json.dumps(next(table[k] for k in table if k in args[-1])))
elif args[0] == "api" and "/contents/" in args[-1]:
    manifest = state / "manifest.json"
    if manifest.exists():
        import base64
        print(json.dumps({"type": "file", "path": ".github/pr-evidence.json", "encoding": "base64",
                          "content": base64.b64encode(manifest.read_bytes()).decode()}))
    else:
        print(json.dumps({"message": "Not Found", "status": "404"}))
        print("gh: Not Found (HTTP 404)", file=sys.stderr)
        sys.exit(1)
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


FORK, CANDIDATE, BASE, BASE2 = "a" * 40, "c" * 40, "b" * 40, "d" * 40
APP, DEP, OTHER = "playbooks/apply/x.yml", "internal/shared/helper.go", "internal/unrelated/service.go"
ART = "docs/evidence/feature/2026-10-31-ccccccc.md"
MANIFEST_PATH = ".github/pr-evidence.json"
TARGET_MANIFEST = {"schema_version": 1, "evidence_only_paths": ["docs/evidence/**"],
                   "required_evidence": [{"id": "actual-run", "kind": "target-run",
                                          "source": "AGENTS.md actual-run rule",
                                          "artifact_glob": "docs/evidence/**/*.md"}]}


def contents(path, data):
    return {"type": "file", "path": path, "encoding": "base64", "content": base64.b64encode(data).decode()}


def compare(status, behind, merge_base, files):
    return {"status": status, "behind_by": behind, "merge_base_commit": {"sha": merge_base},
            "files": [{"filename": f} for f in files]}


def tree(*paths):
    """A complete Git tree; a path has the same object id in every tree that lists it."""
    return {"truncated": False, "tree": [{"path": f, "mode": "100644", "type": "blob",
                                          "sha": hashlib.sha1(f.encode()).hexdigest()} for f in paths]}


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

    def test_ready_without_required_checks(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, _, evidence, env = self.make_pr(t)
            (t / "no_required").touch()
            (t / "fail").touch()
            blocked = self.gate(repo, evidence, env, "--ready")
            self.assertEqual(2, blocked.returncode, blocked.stdout)
            self.assertEqual(["Nonpassing GitHub check: go test (SUCCESS, fail)"],
                             json.loads(blocked.stdout)["errors"])
            self.assertFalse((t / "ready").exists())
            (t / "fail").unlink()
            ready = self.gate(repo, evidence, env, "--ready")
            self.assertEqual(0, ready.returncode, ready.stdout)
            self.assertEqual("READY", json.loads(ready.stdout)["status"])

    def test_base_required_target_evidence_cannot_be_omitted_at_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, _, evidence, env = self.make_pr(t)
            (t / "manifest.json").write_text(json.dumps({"schema_version": 1,
                "required_evidence": [{"id": "actual-run", "source": "AGENTS.md actual-run rule",
                                       "artifact_glob": "docs/evidence/**/*.md"}]}))
            blocked = self.gate(repo, evidence, env, "--ready")
            self.assertEqual(2, blocked.returncode, blocked.stdout)
            self.assertIn("target_validation is missing", " ".join(json.loads(blocked.stdout)["errors"]))
            self.assertFalse((t / "ready").exists())

    def target_api(self, t, head, live=BASE):
        """GitHub's answers for a reviewed reuse of the run at CANDIDATE after main advanced to BASE."""
        (t / "manifest.json").write_text(json.dumps(TARGET_MANIFEST))
        api = {f"contents/{ART}?ref={head}": contents(ART, b"| Tested candidate | `ccccccc` |\n"),
               "branches/main": {"commit": {"sha": live}},
               f"compare/{CANDIDATE}...{head}": compare("ahead", 0, CANDIDATE, [ART, OTHER]),
               f"compare/{BASE}...{head}": compare("ahead", 0, BASE, [ART, APP]),
               f"compare/{CANDIDATE}...{BASE}": compare("diverged", 1, FORK, [OTHER]),
               f"git/trees/{FORK}?recursive=1": tree(DEP),
               f"git/trees/{CANDIDATE}?recursive=1": tree(APP, DEP),
               f"git/trees/{BASE}?recursive=1": tree(DEP, OTHER),
               f"git/trees/{head}?recursive=1": tree(APP, DEP, OTHER, ART)}
        (t / "api.json").write_text(json.dumps(api))
        (t / "bases.json").write_text(json.dumps([BASE]))

    def reuse_record(self, head):
        return {"decision": "required", "artifact": ART, "tested_revision": CANDIDATE,
                "reason": "Native target chain passed on the candidate; its execution content was independently reviewed.",
                "target_reuse": {"head_sha": head, "base_sha": BASE, "reviewer_confirmed": True,
                                 "execution_paths": [APP, DEP], "non_execution_changes": [],
                                 "dependency_review": "Reviewed the complete dependency closure of the target run; the unrelated service is not called by it."}}

    def test_gate_pass_without_ready_still_requires_target_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, _, evidence, env = self.make_pr(t)
            (t / "manifest.json").write_text(json.dumps(TARGET_MANIFEST))
            blocked = self.gate(repo, evidence, env)
            self.assertEqual(2, blocked.returncode, blocked.stdout)
            out = json.loads(blocked.stdout)
            self.assertEqual("DRAFT-BLOCKED", out["status"])
            self.assertIn("target_validation is missing", " ".join(out["errors"]))
            self.assertFalse((t / "ready").exists())
            # Control: the same gate passes once the mandated record exists.
            evidence["target_validation"] = {"decision": "not-needed",
                                             "reason": "Skill-only change: no playbook, spec or contract path is touched."}
            passed = self.gate(repo, evidence, env)
            self.assertEqual(0, passed.returncode, passed.stdout)
            self.assertEqual("GATE-PASS", json.loads(passed.stdout)["status"])

    def test_target_evidence_is_rechecked_after_base_advances(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, _, evidence, env = self.make_pr(t)
            # The first read sees base BASE, which carries no manifest; main then moves to BASE2, which
            # does. Only a second check immediately before the mutation can notice.
            (t / "bases.json").write_text(json.dumps([BASE, BASE2]))
            (t / "api.json").write_text(json.dumps({
                f"contents/{MANIFEST_PATH}?ref={BASE2}": contents(MANIFEST_PATH, json.dumps(TARGET_MANIFEST).encode())}))
            blocked = self.gate(repo, evidence, env, "--ready")
            self.assertEqual(2, blocked.returncode, blocked.stdout)
            out = json.loads(blocked.stdout)
            self.assertIn("target_validation is missing", " ".join(out["errors"]))
            # The pre-mutation block carries no PR url: the first check did not stop it.
            self.assertNotIn("pr", out)
            self.assertGreaterEqual(len((t / "views.log").read_text().split()), 2)
            self.assertFalse((t / "ready").exists())

    def test_reviewed_target_reuse_passes_gate_and_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, sha, evidence, env = self.make_pr(t)
            self.target_api(t, sha)
            evidence["target_validation"] = self.reuse_record(sha)
            passed = self.gate(repo, evidence, env)
            self.assertEqual(0, passed.returncode, passed.stdout)
            self.assertEqual("GATE-PASS", json.loads(passed.stdout)["status"])
            ready = self.gate(repo, evidence, env, "--ready")
            self.assertEqual(0, ready.returncode, ready.stdout)
            self.assertEqual("READY", json.loads(ready.stdout)["status"])
            self.assertTrue((t / "ready").exists())
            # Without the attestation the same run no longer covers HEAD (strict evidence-only delta).
            del evidence["target_validation"]["target_reuse"]
            (t / "ready").unlink()
            blocked = self.gate(repo, evidence, env, "--ready")
            self.assertEqual(2, blocked.returncode, blocked.stdout)
            self.assertIn("files outside evidence_only_paths changed", " ".join(json.loads(blocked.stdout)["errors"]))
            self.assertFalse((t / "ready").exists())

    def test_stale_live_base_blocks_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, sha, evidence, env = self.make_pr(t)
            # `pr view` still says BASE while the branch already moved on: the attestation is not about live main.
            self.target_api(t, sha, live=BASE2)
            evidence["target_validation"] = self.reuse_record(sha)
            blocked = self.gate(repo, evidence, env, "--ready")
            self.assertEqual(2, blocked.returncode, blocked.stdout)
            self.assertIn("PR base metadata is stale", " ".join(json.loads(blocked.stdout)["errors"]))
            self.assertFalse((t / "ready").exists())

    def test_missing_base_sha_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, _, evidence, env = self.make_pr(t)
            (t / "bases.json").write_text(json.dumps(["not-a-sha"]))
            blocked = self.gate(repo, evidence, env, "--ready")
            self.assertEqual(2, blocked.returncode, blocked.stdout)
            self.assertIn("Current HEAD/base SHA unavailable for target evidence validation",
                          json.loads(blocked.stdout)["errors"])
            self.assertFalse((t / "ready").exists())

    def test_missing_verifier_fails_closed(self):
        pr = {"headRefOid": "1" * 40, "baseRefOid": "2" * 40, "baseRefName": "main"}
        with mock.patch.dict(sys.modules), \
                mock.patch.object(gate.importlib.util, "spec_from_file_location", return_value=None):
            sys.modules.pop("pr_ready_target_gate", None)
            errors = gate.target_evidence_errors(pr, {}, "acme/repo")
        self.assertEqual(["Target evidence validation unavailable: target evidence verifier unavailable"], errors)

    def test_failing_required_check_named_like_the_no_required_message_still_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, _, evidence, env = self.make_pr(t)
            (t / "phrase_check").touch()
            name = "Build (no required checks reported)"
            evidence["unrelated_failing_checks"] = [{
                "name": name, "reviewer_confirmed": True,
                "reason": "Unrelated failure, same on main at the base SHA (CI run 40802511042)"}]
            blocked = self.gate(repo, evidence, env, "--ready")
            self.assertEqual(2, blocked.returncode, blocked.stdout)
            errors = json.loads(blocked.stdout)["errors"]
            self.assertIn(f"Required GitHub check not passing: {name} (FAILURE, fail)", errors)
            self.assertFalse((t / "ready").exists())

    def test_required_checks_lookup_failure_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, _, evidence, env = self.make_pr(t)
            (t / "checks_error").touch()
            blocked = self.gate(repo, evidence, env, "--ready")
            self.assertEqual(2, blocked.returncode, blocked.stdout)
            self.assertIn("HTTP 502", json.loads(blocked.stdout)["errors"][0])
            self.assertFalse((t / "ready").exists())

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
