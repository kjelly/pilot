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
sys.path.insert(0, str(ROOT.parent / "_shared" / "tests"))
import secret_fixtures as fx  # noqa: E402
spec = importlib.util.spec_from_file_location("pr_gate", ROOT / "scripts" / "pr_gate.py")
gate = importlib.util.module_from_spec(spec)
sys.modules["pr_gate"] = gate
spec.loader.exec_module(gate)

MOCK_GH = r'''#!/usr/bin/env python3
import json, os, pathlib, re, sys
args = sys.argv[1:]
state = pathlib.Path(os.environ["FAKE_GH_STATE"])
sha = os.environ["FAKE_GH_SHA"]
default_bases = [os.environ.get("FAKE_GH_BASE", sha)]
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
    bases = json.loads((state / "bases.json").read_text()) if (state / "bases.json").exists() else default_bases
    print(json.dumps({"number": 7, "url": "https://github.com/acme/repo/pull/7",
        "headRefOid": sha, "headRefName": "fix-one", "baseRefOid": bases[min(call, len(bases) - 1)],
        "baseRefName": "main", "state": "OPEN",
        "isDraft": not (state / "ready").exists(),
        "mergeable": "CONFLICTING" if (state / "conflict").exists() else "MERGEABLE",
        "reviewDecision": "REVIEW_REQUIRED"}))
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
    # state/api.json maps a substring of the endpoint (contents, compare, git/trees, git/ref) to the
    # JSON body gh would print; the first matching key answers.
    table = json.loads((state / "api.json").read_text())
    print(json.dumps(next(table[k] for k in table if k in args[-1])))
elif args[0] == "api" and "/git/ref/heads/" in args[-1]:
    if (state / "ref_error").exists():
        print("ref unavailable", file=sys.stderr); sys.exit(1)
    bases = json.loads((state / "bases.json").read_text()) if (state / "bases.json").exists() else default_bases
    call = len((state / "views.log").read_text().split()) - 1
    print(json.dumps({"object": {"type": "commit", "sha": bases[min(call, len(bases) - 1)]}}))
elif args[0] == "api" and "/compare/" in args[-1]:
    if (state / "ancestry_error").exists():
        print("comparison unavailable", file=sys.stderr); sys.exit(1)
    base, head = args[-1].split("/compare/")[1].split("...")
    result = {"status": "identical" if base == head else "ahead", "behind_by": 0,
              "merge_base_commit": {"sha": base}}
    if (state / "ancestry.json").exists():
        result = json.loads((state / "ancestry.json").read_text())
    print(json.dumps(result))
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


FORK, CANDIDATE = "a" * 40, "c" * 40
# The PR base (self.base_sha) and a later main tip (self.base2_sha) are real commits of the test
# repository, made by make_pr: the gate scans baseRefOid..headRefOid, and a base it cannot read is a refusal.
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
        def git(*args):
            return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()

        (repo / "base-file").write_text("the base", encoding="utf-8")
        git("add", "base-file")
        git("commit", "--quiet", "-m", "the PR base")
        self.base_sha = git("rev-parse", "HEAD")
        git("switch", "--quiet", "-c", "main-moved")
        (repo / "moved-file").write_text("main moved on", encoding="utf-8")
        git("add", "moved-file")
        git("commit", "--quiet", "-m", "main moved")
        self.base2_sha = git("rev-parse", "HEAD")
        git("switch", "--quiet", "fix-one")
        (repo / "file").write_text("something", encoding="utf-8")
        git("add", "file")
        git("commit", "--quiet", "-m", "init")
        sha = git("rev-parse", "HEAD")
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
        env.update(PATH=f"{bin_dir}{os.pathsep}{env['PATH']}", FAKE_GH_STATE=str(t), FAKE_GH_SHA=sha,
                   FAKE_GH_BASE=self.base_sha)
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

    def test_behind_the_live_base_is_ready_only_when_the_train_can_integrate_it(self):
        # kjelly/pilot#307: Ready needs a clean test merge and no file changed on both sides, not ancestry.
        for case, base_files, conflict, needle in (("overlap", ["pkg/a.go"], False, "both sides changed pkg/a.go"),
                                                   ("conflict", ["docs/x.md"], True, "merge conflict"),
                                                   ("train", ["docs/x.md"], False, None)):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                t = Path(tmp)
                repo, sha, evidence, env = self.make_pr(t)
                live = self.base_sha
                (t / "api.json").write_text(json.dumps({
                    f"compare/{live}...{sha}": compare("diverged", 1, FORK, ["pkg/a.go"]),
                    f"compare/{sha}...{live}": compare("diverged", 1, FORK, base_files)}))
                if conflict:
                    (t / "conflict").touch()
                proc = self.gate(repo, evidence, env, "--ready")
                if needle is None:
                    self.assertEqual(0, proc.returncode, proc.stdout)
                    self.assertTrue((t / "ready").exists())
                    continue
                self.assertEqual(2, proc.returncode, proc.stdout)
                self.assertIn(needle, " ".join(json.loads(proc.stdout)["errors"]))
                self.assertIn("does not include live main", " ".join(json.loads(proc.stdout)["errors"]))
                self.assertFalse((t / "ready").exists())

    def test_unavailable_base_or_ancestry_keeps_draft(self):
        for flag in ("ref_error", "ancestry_error"):
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as tmp:
                t = Path(tmp)
                repo, _, evidence, env = self.make_pr(t)
                (t / flag).touch()
                blocked = self.gate(repo, evidence, env, "--ready")
                self.assertEqual(2, blocked.returncode, blocked.stdout)
                self.assertIn("Base alignment verification unavailable", " ".join(json.loads(blocked.stdout)["errors"]))
                self.assertFalse((t / "ready").exists())

    def target_api(self, t, head, live=None):
        """GitHub's answers for a reviewed reuse of the run at CANDIDATE after main advanced to the PR base."""
        BASE, live = self.base_sha, live or self.base_sha
        (t / "manifest.json").write_text(json.dumps(TARGET_MANIFEST))
        api = {f"contents/{ART}?ref={head}": contents(ART, b"| Tested candidate | `ccccccc` |\n"),
               "git/ref/heads/main": {"object": {"type": "commit", "sha": live}},
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
                "target_reuse": {"head_sha": head, "base_sha": self.base_sha, "reviewer_confirmed": True,
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
            # The first read sees the PR base, which carries no manifest; main then moves to base2, which
            # does. Only a second check immediately before the mutation can notice.
            (t / "bases.json").write_text(json.dumps([self.base_sha, self.base2_sha]))
            (t / "api.json").write_text(json.dumps({
                f"contents/{MANIFEST_PATH}?ref={self.base2_sha}": contents(MANIFEST_PATH, json.dumps(TARGET_MANIFEST).encode())}))
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

    def evidence_only_pr(self, t):
        """make_pr, then: `main` (fetched as origin/main) carries the manifest; the PR branch adds an
        evidence-only commit on top of the commit the receipts and review were taken at."""
        repo, candidate, evidence, env = self.make_pr(t)

        def git(*args):
            return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()

        git("branch", "main")
        git("checkout", "--quiet", "main")
        (repo / ".github").mkdir()
        (repo / ".github" / "pr-evidence.json").write_text(json.dumps(TARGET_MANIFEST), encoding="utf-8")
        git("add", ".github")
        git("commit", "--quiet", "-m", "manifest")
        git("update-ref", "refs/remotes/origin/main", "main")
        git("checkout", "--quiet", "fix-one")
        record = repo / ART
        record.parent.mkdir(parents=True)
        record.write_text("# tested " + candidate, encoding="utf-8")
        git("add", ART)
        git("commit", "--quiet", "-m", "evidence")
        head = git("rev-parse", "HEAD")
        evidence["head_sha"] = head
        env["FAKE_GH_SHA"] = head
        return repo, candidate, head, evidence, env

    def test_receipts_and_review_carry_over_an_evidence_only_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, candidate, head, evidence, env = self.evidence_only_pr(t)
            passed = self.gate(repo, evidence, env)
            self.assertEqual(0, passed.returncode, passed.stdout + passed.stderr)
            out = json.loads(passed.stdout)
            self.assertEqual("GATE-PASS", out["status"])
            self.assertEqual({"from": candidate, "head": head, "changed": [ART]},
                             {k: out["receipt_reuse"][0][k] for k in ("from", "head", "changed")})
            self.assertEqual({"independent_review", "local_validation.tests[0]", "local_validation.lint[0]",
                              "local_validation.static_analysis[0]"}, {r["label"] for r in out["receipt_reuse"]})
            ready = self.gate(repo, evidence, env, "--ready")
            self.assertEqual(0, ready.returncode, ready.stdout + ready.stderr)
            self.assertEqual("READY", json.loads(ready.stdout)["status"])
            self.assertTrue((t / "ready").exists())

    def test_a_code_commit_after_the_receipts_still_needs_new_receipts(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, candidate, head, evidence, env = self.evidence_only_pr(t)
            (repo / "file").write_text("changed", encoding="utf-8")
            subprocess.run(["git", "commit", "--quiet", "-am", "code"], cwd=repo, check=True)
            head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            evidence["head_sha"] = head
            env["FAKE_GH_SHA"] = head
            blocked = self.gate(repo, evidence, env)
            self.assertEqual(2, blocked.returncode, blocked.stdout)
            errors = " ".join(json.loads(blocked.stdout)["errors"])
            self.assertIn("local_validation.tests[0] stale/missing SHA (files outside evidence_only_paths changed: file)", errors)
            self.assertIn("Independent reviewer result stale for current HEAD (files outside evidence_only_paths changed: file)", errors)

    def test_without_the_fetched_base_the_strict_rule_applies(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, candidate, head, evidence, env = self.evidence_only_pr(t)
            subprocess.run(["git", "update-ref", "-d", "refs/remotes/origin/main"], cwd=repo, check=True)
            blocked = self.gate(repo, evidence, env)
            self.assertEqual(2, blocked.returncode, blocked.stdout)
            errors = " ".join(json.loads(blocked.stdout)["errors"])
            self.assertIn("stale/missing SHA (no evidence_only_paths declared on the base branch)", errors)
            self.assertFalse((t / "ready").exists())

    def test_stale_live_base_blocks_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, sha, evidence, env = self.make_pr(t)
            # `pr view` still says the old base while the branch already moved on: the attestation is not about live main.
            self.target_api(t, sha, live=self.base2_sha)
            evidence["target_validation"] = self.reuse_record(sha)
            blocked = self.gate(repo, evidence, env, "--ready")
            self.assertEqual(2, blocked.returncode, blocked.stdout)
            # The attestation names the PR's old base; HEAD's integrated base is the live tip.
            self.assertIn("does not match current base", " ".join(json.loads(blocked.stdout)["errors"]))
            self.assertFalse((t / "ready").exists())

    def test_missing_base_sha_blocks(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, _, evidence, env = self.make_pr(t)
            (t / "bases.json").write_text(json.dumps(["not-a-sha"]))
            blocked = self.gate(repo, evidence, env, "--ready")
            self.assertEqual(2, blocked.returncode, blocked.stdout)
            self.assertIn("Base alignment verification unavailable", " ".join(json.loads(blocked.stdout)["errors"]))
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


def advance(repo, evidence, env, *commits):
    """Add commits (path, text, message) on top of the PR head and re-bind the evidence and fake gh to the new head."""
    def git(*args):
        return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()

    for path, text, message in commits:
        target = repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        git("add", path)
        git("commit", "--quiet", "-m", message)
    head = git("rev-parse", "HEAD")
    evidence["head_sha"] = evidence["independent_review"]["head_sha"] = head
    for checks in evidence["local_validation"].values():
        for check in checks:
            check["head_sha"] = head
    env["FAKE_GH_SHA"] = head
    return head


def b1(repo, evidence, env):
    """Commit 1 adds a real-shaped NT-hash fixture, commit 2 replaces it with the placeholder."""
    value = fx.random_b64()
    leak = advance(repo, evidence, env, ("testdata/user.json", fx.attribute_document(fx.NT_HASH, value), "test: add a captured user"))
    advance(repo, evidence, env, ("testdata/user.json", fx.attribute_document(fx.NT_HASH, fx.PLACEHOLDER), "test: use the placeholder"))
    return value, leak


def b2(repo, evidence, env):
    """The same final tree as b1() from one commit that adds only the placeholder."""
    advance(repo, evidence, env, ("testdata/user.json", fx.attribute_document(fx.NT_HASH, fx.PLACEHOLDER), "test: add a captured user"))


class SecretScanTests(unittest.TestCase):
    """Ready requires every commit of baseRefOid..headRefOid to be free of secrets."""

    make_pr = CLIMockTests.make_pr
    evidence_only_pr = CLIMockTests.evidence_only_pr
    gate = CLIMockTests.gate

    def tree(self, repo):
        return subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=repo, text=True).strip()

    def test_a_value_replaced_in_a_later_commit_blocks_ready_and_the_one_commit_control_passes(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, _, evidence, env = self.make_pr(t)
            value, leak = b1(repo, evidence, env)
            tree_b1 = self.tree(repo)
            blocked = self.gate(repo, evidence, env, "--ready")
            self.assertEqual(2, blocked.returncode, blocked.stdout + blocked.stderr)
            out = json.loads(blocked.stdout)
            self.assertEqual("DRAFT-BLOCKED", out["status"])
            text = " ".join(out["errors"])
            self.assertIn("freeipa-secret-attribute", text)
            self.assertIn("testdata/user.json", text)
            self.assertIn(leak[:12], text)
            self.assertIn("scrubs the value does not clear this finding", text)
            self.assertFalse((t / "ready").exists())
            for channel in (blocked.stdout, blocked.stderr):
                for part in (value, value[:10], value[-10:]):
                    self.assertNotIn(part, channel)
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, _, evidence, env = self.make_pr(t)
            b2(repo, evidence, env)
            self.assertEqual(tree_b1, self.tree(repo), "premise: the same final tree")
            passed = self.gate(repo, evidence, env, "--ready")
            self.assertEqual(0, passed.returncode, passed.stdout + passed.stderr)
            out = json.loads(passed.stdout)
            self.assertEqual("READY", out["status"])
            self.assertEqual("CLEAN", out["secret_scan"]["status"])
            self.assertEqual(2, out["secret_scan"]["commits_scanned"])
            self.assertTrue((t / "ready").exists())

    def test_the_scan_names_the_pr_shas_not_the_checkout(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, _, evidence, env = self.make_pr(t)
            b1(repo, evidence, env)
            head = env["FAKE_GH_SHA"]
            pr = {"baseRefOid": self.base_sha, "headRefOid": head}
            subprocess.run(["git", "switch", "--quiet", "-c", "elsewhere", self.base_sha], cwd=repo, check=True)
            errors, summary = gate.secret_scan_errors(repo, pr)
            self.assertEqual("FOUND", summary["status"], "HEAD is another branch: only the explicit SHAs name the range")
            self.assertIn("freeipa-secret-attribute", " ".join(errors))
            errors, summary = gate.secret_scan_errors(repo, {**pr, "headRefOid": self.base_sha})
            self.assertEqual(([], "CLEAN"), (errors, summary["status"]), "control: an empty range is clean")
            for bad in ({"baseRefOid": "not-a-sha", "headRefOid": head}, {"baseRefOid": self.base_sha}, {}):
                errors, summary = gate.secret_scan_errors(repo, bad)
                self.assertEqual("ERROR", summary["status"])
                self.assertIn("Secret scan unavailable", " ".join(errors))

    def test_one_scan_per_base_and_head(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, sha, _, _ = self.make_pr(t)
            scanner = gate.load_secret_scan()
            cache = {}
            pr = {"baseRefOid": self.base_sha, "headRefOid": sha}
            with mock.patch.object(scanner, "scan_range", wraps=scanner.scan_range) as scan:
                for _ in range(3):
                    errors, summary = gate.secret_scan_errors(repo, pr, (), cache)
                    self.assertEqual(([], "CLEAN"), (errors, summary["status"]))
                self.assertEqual(1, scan.call_count)
                gate.secret_scan_errors(repo, {**pr, "baseRefOid": self.base2_sha}, (), cache)
                self.assertEqual(2, scan.call_count, "a different base is scanned again")
                # The head is part of the key too: a PR that gained a commit while --wait polled is a new range.
                gate.secret_scan_errors(repo, {**pr, "headRefOid": self.base2_sha}, (), cache)
                self.assertEqual(3, scan.call_count, "a different head is scanned again")
                for key in (pr, {**pr, "baseRefOid": self.base2_sha}, {**pr, "headRefOid": self.base2_sha}):
                    gate.secret_scan_errors(repo, key, (), cache)
                self.assertEqual(3, scan.call_count, "every (base, head) pair is scanned once")

    def test_a_base_that_is_not_in_the_clone_blocks_with_a_fetch_hint(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, _, evidence, env = self.make_pr(t)
            (t / "bases.json").write_text(json.dumps(["b" * 40]))
            (t / "api.json").write_text(json.dumps({"git/ref/heads/main": {"object": {"type": "commit", "sha": "b" * 40}}}))
            blocked = self.gate(repo, evidence, env, "--ready")
            self.assertEqual(2, blocked.returncode, blocked.stdout)
            self.assertRegex(" ".join(json.loads(blocked.stdout)["errors"]), r"Secret scan could not be completed.*fetch")
            self.assertFalse((t / "ready").exists())

    def test_a_scanner_that_cannot_be_loaded_refuses_instead_of_skipping(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, sha, _, _ = self.make_pr(t)
            broken = t / "secret_scan.py"
            broken.write_text("def (:\n", encoding="utf-8")
            pr = {"baseRefOid": self.base_sha, "headRefOid": sha}
            for path in (broken, t / "absent.py"):
                with self.subTest(path=path.name), mock.patch.dict(sys.modules), \
                        mock.patch.object(gate, "SECRET_SCAN_PATH", path):
                    sys.modules.pop("pilot_secret_scan", None)
                    errors, summary = gate.secret_scan_errors(repo, pr)
                    self.assertEqual("ERROR", summary["status"])
                    self.assertTrue(errors[0].startswith("Secret scan unavailable"), errors)
            self.assertEqual("CLEAN", gate.secret_scan_errors(repo, pr)[1]["status"], "control: the real scanner loads")

    def test_worktree_is_mandatory(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, _, evidence, env = self.make_pr(t)
            evidence_file = repo / ".pr-ready/evidence.json"
            evidence_file.write_text(json.dumps(evidence), encoding="utf-8")
            cli = [sys.executable, str(ROOT / "scripts/pr_gate.py"), "--repo", "acme/repo", "--pr", "7",
                   "--evidence", str(evidence_file)]
            refused = subprocess.run(cli, env=env, capture_output=True, text=True)
            self.assertEqual(2, refused.returncode)
            self.assertIn("--worktree", refused.stderr)
            self.assertFalse((t / "views.log").exists(), "nothing was queried without a worktree to scan")

    def test_a_secret_file_blocks_a_known_value_and_an_unusable_one_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, _, evidence, env = self.make_pr(t)
            value = fx.mixed(18)
            advance(repo, evidence, env, ("notes.txt", f"scratch {value}\n", "notes"), ("notes.txt", "scrubbed\n", "scrub"))
            secrets_file = t / "known.txt"
            secrets_file.write_text(f"\n{value}\n", encoding="utf-8")
            clean = self.gate(repo, evidence, env)
            self.assertEqual(0, clean.returncode, "control: without the secret file the branch is clean")
            blocked = self.gate(repo, evidence, env, "--secret-file", str(secrets_file))
            self.assertEqual(2, blocked.returncode)
            self.assertIn("known-value", blocked.stdout)
            self.assertNotIn(value, blocked.stdout + blocked.stderr)
            short = t / "short.txt"
            short.write_text(f"{fx.mixed(14)}\n{fx.mixed(5)}\n", encoding="utf-8")
            refused = self.gate(repo, evidence, env, "--secret-file", str(short))
            self.assertEqual(2, refused.returncode)
            self.assertIn("line 2", refused.stdout)
            inside = repo / "inside.txt"
            inside.write_text(f"{value}\n", encoding="utf-8")
            refused = self.gate(repo, evidence, env, "--secret-file", str(inside))
            self.assertIn("inside the repository", refused.stdout)
            self.assertNotIn(value, refused.stdout + refused.stderr)

    def test_receipts_carry_over_an_evidence_only_commit_but_the_scan_does_not(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, candidate, head, evidence, env = self.evidence_only_pr(t)
            self.assertEqual(0, self.gate(repo, evidence, env).returncode, "control: the evidence-only commit passes")
            token = fx.mixed(40)
            advance(repo, evidence, env, (ART, f"# tested {candidate}\n\ncurl -H 'Authorization: Bearer {token}' https://example.invalid/\n",
                                          "evidence: add the transcript"))
            for checks in evidence["local_validation"].values():
                for check in checks:
                    check["head_sha"] = candidate  # the receipts were taken before the evidence-only commits
            evidence["independent_review"]["head_sha"] = candidate
            blocked = self.gate(repo, evidence, env)
            self.assertEqual(2, blocked.returncode, blocked.stdout)
            errors = json.loads(blocked.stdout)["errors"]
            self.assertEqual([], [e for e in errors if "stale" in e], "premise: receipts and review carry over")
            self.assertIn("authorization-header", " ".join(errors))
            self.assertIn(ART, " ".join(errors))
            self.assertNotIn(token, blocked.stdout + blocked.stderr)


if __name__ == '__main__':
    unittest.main()
