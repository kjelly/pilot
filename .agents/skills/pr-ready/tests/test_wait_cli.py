"""Native CLI wait/Ready contract: real Git, fake gh, no GitHub mutation."""
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

import test_cli_mock as cli_mock

ROOT = cli_mock.ROOT


PASS = {"name": "go test", "bucket": "pass", "state": "SUCCESS"}
PENDING = {"name": "go test", "bucket": "pending", "state": "IN_PROGRESS"}
FAIL = {"name": "go test", "bucket": "fail", "state": "FAILURE"}
LINT = {"name": "lint", "bucket": "pass", "state": "SUCCESS"}

WAIT_GH = r'''#!/usr/bin/env python3
import base64, json, os, pathlib, re, subprocess, sys
args = sys.argv[1:]
root = pathlib.Path(os.environ["FAKE_GH_STATE"])
sha = os.environ["FAKE_GH_SHA"]
views = root / "views.log"
count = len(views.read_text().splitlines()) if views.exists() else 0
index = count if args[:2] == ["pr", "view"] else max(0, count - 1)
plans = json.loads((root / "scenario.json").read_text())
plan = plans[min(index, len(plans) - 1)]
if args[:2] == ["pr", "view"]:
    with views.open("a") as out:
        out.write("view\n")
    hook = root / ("hook-" + str(index) + ".py")
    if hook.exists():
        subprocess.run([sys.executable, str(hook)], check=True)
    pr = {"number": 7, "url": "https://github.com/acme/repo/pull/7", "title": "Fix feature",
          "body": "Reviewed feature change", "headRefOid": sha, "headRefName": "fix-one",
          "baseRefOid": sha, "baseRefName": "main", "state": "OPEN", "mergeable": "MERGEABLE",
          "isDraft": not (root / "ready").exists(), "reviewDecision": "REVIEW_REQUIRED"}
    pr.update(plan.get("pr", {}))
    print(json.dumps(pr))
elif args[:2] == ["pr", "checks"]:
    if plan.get("api_error"):
        print("HTTP 502: Bad Gateway", file=sys.stderr)
        sys.exit(1)
    if plan.get("api_exit"):
        print(json.dumps(plan["checks"]))
        sys.exit(plan["api_exit"])
    checks = plan.get("required", plan["checks"][:1]) if "--required" in args else plan["checks"]
    print(json.dumps(checks))
    sys.exit(8 if any(c.get("bucket") == "pending" for c in checks if isinstance(c, dict)) else 0)
elif args[:2] == ["api", "graphql"]:
    query = next(a[6:] for a in args if a.startswith("query="))
    field = re.search(r"pullRequest\(number:\$number\)\s*\{\s*(\w+)", query).group(1)
    with (root / "graphql.log").open("a") as out:
        out.write(field + "\n")
    print(json.dumps({"data": {"repository": {"pullRequest": {
        field: {"nodes": plan.get(field, []), "pageInfo": {"hasNextPage": False, "endCursor": None}}
    }}}}))
elif args[0] == "api" and "/contents/" in args[-1]:
    if "manifest" in plan:
        print(json.dumps({"type": "file", "path": ".github/pr-evidence.json", "encoding": "base64",
                          "content": base64.b64encode(json.dumps(plan["manifest"]).encode()).decode()}))
        sys.exit(0)
    print(json.dumps({"message": "Not Found", "status": "404"}))
    print("gh: Not Found (HTTP 404)", file=sys.stderr)
    sys.exit(1)
elif args[:2] == ["pr", "ready"]:
    with (root / "ready.log").open("a") as out:
        out.write(str(index) + "\n")
    (root / "ready").write_text("yes")
else:
    print("unsupported mock args " + repr(args), file=sys.stderr)
    sys.exit(1)
'''


def plan(*checks, **kwargs):
    return {"checks": list(checks), **kwargs}


def comment(body="Reviewed feedback"):
    return {"url": "https://github.com/acme/repo/pull/7#issuecomment-1",
            "createdAt": "2026-11-02T01:00:00Z", "updatedAt": "2026-11-02T01:00:00Z", "body": body}


class WaitCLITests(unittest.TestCase):
    make_pr = cli_mock.CLIMockTests.make_pr
    evidence_only_pr = cli_mock.CLIMockTests.evidence_only_pr

    def prepare(self, t, plans, *, ancestor=False):
        if ancestor:
            repo, _, _, evidence, env = self.evidence_only_pr(t)
        else:
            repo, _, evidence, env = self.make_pr(t)
        (t / "bin/gh").write_text(WAIT_GH)
        (t / "scenario.json").write_text(json.dumps(plans))
        env["WAIT_REPO"] = str(repo)
        report = repo / ".pr-ready/review.md"
        report.write_text("Independent review PASS on this candidate.")
        evidence["independent_review"]["report"] = ".pr-ready/review.md"
        (repo / ".pr-ready/evidence.json").write_text(json.dumps(evidence))
        checkpoint = repo / ".pr-ready/7/checkpoint.json"
        checkpoint.parent.mkdir(exist_ok=True)
        checkpoint.write_text('{"root_owned":true}\n')
        cli = [sys.executable, str(ROOT / "scripts/pr_gate.py"), "--repo", "acme/repo", "--pr", "7",
               "--worktree", str(repo), "--evidence", str(repo / ".pr-ready/evidence.json"),
               "--wait", "--ready", "--compact", "--poll-interval", "0.01"]
        return repo, evidence, env, cli

    def run_gate(self, t, plans, *, hook=None, ancestor=False, extra=()):
        repo, evidence, env, cli = self.prepare(t, plans, ancestor=ancestor)
        if hook:
            (t / "hook-1.py").write_text("import os, pathlib, subprocess\nr=pathlib.Path(os.environ['WAIT_REPO'])\n" + hook)
        proc = subprocess.run(cli + list(extra), env=env, capture_output=True, text=True, timeout=20)
        events = [json.loads(line) for line in proc.stdout.splitlines()]
        self.assertTrue(events, proc.stderr)
        status = json.loads((repo / ".pr-ready/7/wait-status.json").read_text())
        self.assertEqual(events[-1], status)
        self.assertEqual('{"root_owned":true}\n', (repo / ".pr-ready/7/checkpoint.json").read_text())
        return proc, events, repo

    def assert_blocked(self, t, plans, needle, **kwargs):
        proc, events, _ = self.run_gate(t, plans, **kwargs)
        self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
        self.assertEqual("DRAFT-BLOCKED", events[-1]["status"])
        self.assertIn(needle, " ".join(events[-1]["errors"]))
        self.assertFalse((t / "ready").exists())
        return events

    def test_pending_to_pass_runs_ready_exactly_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            proc, events, _ = self.run_gate(t, [plan(PENDING), plan(PASS)])
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual(["WAITING-CI", "READY"], [e["status"] for e in events])
            self.assertEqual(["2"], (t / "ready.log").read_text().splitlines())
            self.assertEqual({"reviewThreads", "comments", "reviews"}, set((t / "graphql.log").read_text().split()))

    def test_wait_without_ready_returns_gate_pass_without_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            _, _, env, cli = self.prepare(t, [plan(PENDING), plan(PASS)])
            cli.remove("--ready")
            proc = subprocess.run(cli, env=env, capture_output=True, text=True, timeout=20)
            events = [json.loads(line) for line in proc.stdout.splitlines()]
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual(["WAITING-CI", "GATE-PASS"], [e["status"] for e in events])
            self.assertFalse((t / "ready").exists())

    def test_evidence_only_ancestor_receipts_and_review_survive_wait(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc, events, _ = self.run_gate(Path(tmp), [plan(PENDING), plan(PASS)], ancestor=True)
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual(4, len(events[-1]["receipt_reuse"]))

    def test_pending_exemption_still_waits(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, evidence, env, cli = self.prepare(t, [plan(PASS, {**PENDING, "name": "lint"}),
                plan(PASS, {**PENDING, "name": "lint"}), plan(PASS, LINT)])
            evidence["unrelated_failing_checks"] = [{"name": "lint", "reviewer_confirmed": True,
                "reason": "Confirmed unrelated external check must still finish before Ready."}]
            (repo / ".pr-ready/evidence.json").write_text(json.dumps(evidence))
            proc = subprocess.run(cli, env=env, capture_output=True, text=True, timeout=20)
            events = [json.loads(line) for line in proc.stdout.splitlines()]
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual(["3"], (t / "ready.log").read_text().splitlines(),
                             "Ready must wait until the pending exemption becomes terminal")
            self.assertEqual(["WAITING-CI", "WAITING-CI", "READY"], [e["status"] for e in events])

    def test_pending_with_other_blocker_stops_immediately(self):
        cases = [(plan(PENDING, {**FAIL, "name": "lint"}), "Nonpassing GitHub check: lint"),
                 (plan(PENDING, **{"pr": {"mergeable": "CONFLICTING"}}), "Mergeability"),
                 (plan(PENDING, reviewThreads=[{"id": "T1", "isResolved": False,
                    "comments": {"nodes": [], "pageInfo": {"hasNextPage": False}}}]), "Unresolved")]
        for first, needle in cases:
            with self.subTest(needle=needle), tempfile.TemporaryDirectory() as tmp:
                events = self.assert_blocked(Path(tmp), [first, plan(PASS)], needle)
                self.assertEqual(1, len(events))

    def test_pending_does_not_bypass_attestations_or_receipts(self):
        for key in ("review", "tests", "assessment"):
            with self.subTest(key=key), tempfile.TemporaryDirectory() as tmp:
                t = Path(tmp)
                repo, evidence, env, cli = self.prepare(t, [plan(PENDING), plan(PASS)])
                if key == "review":
                    evidence["independent_review"]["head_sha"] = "f" * 40
                    needle = "reviewer result stale"
                elif key == "tests":
                    evidence["local_validation"]["tests"][0]["exit_code"] = 1
                    needle = "did not pass"
                else:
                    evidence["assessment"]["acceptance_criteria_passed"] = False
                    needle = "acceptance_criteria_passed"
                (repo / ".pr-ready/evidence.json").write_text(json.dumps(evidence))
                proc = subprocess.run(cli, env=env, capture_output=True, text=True, timeout=20)
                self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
                self.assertIn(needle, proc.stdout)
                self.assertNotIn("WAITING-CI", proc.stdout)
                self.assertFalse((t / "ready").exists())

    def test_pending_does_not_bypass_required_target_evidence(self):
        manifest = {"schema_version": 1, "required_evidence": [{"id": "actual-run",
                    "source": "AGENTS.md actual-run", "artifact_glob": "docs/evidence/**/*.md"}]}
        with tempfile.TemporaryDirectory() as tmp:
            events = self.assert_blocked(Path(tmp), [plan(PENDING, manifest=manifest), plan(PASS)],
                                        "target_validation is missing")
            self.assertEqual(1, len(events))

    def test_required_failure_cannot_be_exempted(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, evidence, env, cli = self.prepare(t, [plan(FAIL, {**PENDING, "name": "lint"})])
            evidence["unrelated_failing_checks"] = [{"name": "go test", "reviewer_confirmed": True,
                "reason": "Confirmed unrelated failure, but this is still a required check."}]
            (repo / ".pr-ready/evidence.json").write_text(json.dumps(evidence))
            proc = subprocess.run(cli, env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(2, proc.returncode, proc.stdout)
            self.assertIn("Required GitHub check not passing", proc.stdout)
            self.assertNotIn("WAITING-CI", proc.stdout)
            self.assertFalse((t / "ready").exists())

    def test_nonrequired_terminal_exemption_keeps_existing_policy(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, evidence, env, cli = self.prepare(t, [plan(PASS, {**FAIL, "name": "lint"})])
            evidence["unrelated_failing_checks"] = [{"name": "lint", "reviewer_confirmed": True,
                "reason": "Independent reviewer confirmed failure is unchanged on current base."}]
            (repo / ".pr-ready/evidence.json").write_text(json.dumps(evidence))
            proc = subprocess.run(cli, env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual("READY", json.loads(proc.stdout)["status"])

    def test_missing_unknown_malformed_or_failed_ci_query_stops(self):
        cases = [(plan(), "No CI checks"), (plan({**PASS, "bucket": "unknown"}), "metadata"),
                 (plan({**PASS, "state": "BOGUS"}), "metadata"),
                 (plan({"name": "go test", "bucket": "pass"}), "metadata"),
                 (plan({**PASS, "state": []}), "metadata"),
                 (plan(PASS, required=[{**PASS, "bucket": "unknown"}]), "metadata"),
                 (plan(PENDING, api_error=True), "Invalid/missing JSON"),
                 (plan(PASS, api_exit=2), "exit 2"),
                 (plan(PASS, required=[{**PASS, "name": "missing"}]), "missing from full")]
        for first, needle in cases:
            with self.subTest(first=first), tempfile.TemporaryDirectory() as tmp:
                self.assert_blocked(Path(tmp), [first, plan(PASS)], needle)

    def test_changed_remote_identity_or_description_blocks(self):
        cases = [("headRefOid", "f" * 40), ("headRefName", "other"), ("baseRefOid", "b" * 40),
                 ("baseRefName", "other"), ("body", "Edited description"), ("title", "Edited title"),
                 ("state", "CLOSED"), ("isDraft", False)]
        for key, value in cases:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as tmp:
                self.assert_blocked(Path(tmp), [plan(PENDING), plan(PASS, pr={key: value})],
                                    "PR" if key in ("state", "isDraft") else key)

    def test_changed_local_identity_dirty_tree_or_policy_blocks(self):
        cases = [("subprocess.run(['git','-C',str(r),'commit','--allow-empty','-qm','new'],check=True)", "HEAD differs"),
                 ("subprocess.run(['git','-C',str(r),'checkout','-qb','other'],check=True)", "original PR branch"),
                 ("(r/'file').write_text('dirty')", "uncommitted"),
                 ("subprocess.run(['git','-C',str(r),'update-ref','refs/remotes/origin/main','HEAD'],check=True)", "base policy ref")]
        for hook, needle in cases:
            with self.subTest(needle=needle), tempfile.TemporaryDirectory() as tmp:
                self.assert_blocked(Path(tmp), [plan(PENDING), plan(PASS)], needle, hook=hook)

    def test_evidence_report_and_log_edits_or_deletion_block(self):
        for path in (".pr-ready/evidence.json", ".pr-ready/review.md", ".pr-ready/logs/tests.log"):
            for operation in ("write_text('changed')", "unlink()"):
                with self.subTest(path=path, operation=operation), tempfile.TemporaryDirectory() as tmp:
                    self.assert_blocked(Path(tmp), [plan(PENDING), plan(PASS)],
                                        "artifact" if operation.startswith("write") else "No such file",
                                        hook=f"(r/{path!r}).{operation}")

    def test_new_or_edited_review_comment_requires_triage(self):
        old = comment()
        edited = {**old, "body": "New objection", "updatedAt": "2026-11-02T02:00:00Z"}
        for field in ("comments", "reviews", "reviewThreads"):
            for existing in (False, True):
                def nodes(item):
                    if field == "reviewThreads":
                        return [{"id": "T1", "isResolved": True, "comments": {
                            "nodes": [item], "pageInfo": {"hasNextPage": False}}}]
                    return [item]
                with self.subTest(field=field, existing=existing), tempfile.TemporaryDirectory() as tmp:
                    self.assert_blocked(Path(tmp), [plan(PENDING, **{field: nodes(old) if existing else []}),
                        plan(PASS, **{field: nodes(edited)})], "review/comment content")

    def test_incomplete_review_metadata_blocks(self):
        for field in ("comments", "reviews", "reviewThreads"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as tmp:
                self.assert_blocked(Path(tmp), [plan(PENDING, **{field: [{}]})], "requires complete")

    def test_final_preflight_pending_returns_to_wait(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            proc, events, _ = self.run_gate(t, [plan(PENDING), plan(PASS), plan(PENDING), plan(PASS)])
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual(["WAITING-CI", "WAITING-CI", "READY"], [e["status"] for e in events])
            self.assertEqual(["4"], (t / "ready.log").read_text().splitlines())

    def test_final_preflight_rechecks_all_pins(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assert_blocked(Path(tmp), [plan(PASS), plan(PASS, pr={"baseRefOid": "b" * 40})], "baseRefOid")

    def test_post_action_race_never_reports_validated_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            proc, events, _ = self.run_gate(t, [plan(PASS), plan(PASS), plan(PASS, pr={"headRefOid": "f" * 40})])
            self.assertEqual(2, proc.returncode, proc.stdout)
            self.assertTrue(events[-1]["ready_invoked"])
            self.assertIn("requires reevaluation", " ".join(events[-1]["errors"]))
            self.assertEqual(["1"], (t / "ready.log").read_text().splitlines())

    def test_explicit_timeout_checkpoints_without_mutation(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            proc, events, _ = self.run_gate(t, [plan(PENDING)], extra=("--wait-timeout", "0.5"))
            self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual("WAIT-INTERRUPTED", events[-1]["status"])
            self.assertIn("timeout", " ".join(events[-1]["errors"]))
            self.assertFalse((t / "ready").exists())

    def test_signals_checkpoint_without_mutation(self):
        for sig in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(signal=sig), tempfile.TemporaryDirectory() as tmp:
                t = Path(tmp)
                repo, _, env, cli = self.prepare(t, [plan(PENDING)])
                cli[-1] = "0.05"
                proc = subprocess.Popen(cli, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                try:
                    deadline = time.monotonic() + 10
                    status = repo / ".pr-ready/7/wait-status.json"
                    while not status.exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
                    self.assertTrue(status.exists())
                    proc.send_signal(sig)
                    stdout, stderr = proc.communicate(timeout=10)
                    self.assertEqual(2, proc.returncode, stdout + stderr)
                    self.assertEqual("WAIT-INTERRUPTED", json.loads(status.read_text())["status"])
                    self.assertIn(sig.name, stdout)
                    self.assertFalse((t / "ready").exists())
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.communicate()

    def test_wait_requires_worktree_and_bounded_poll_interval(self):
        for extra in (("--wait",), ("--wait", "--worktree", ".", "--poll-interval", "61"),
                      ("--wait", "--worktree", ".", "--poll-interval", "nan"),
                      ("--wait", "--worktree", ".", "--wait-timeout", "0")):
            proc = subprocess.run([sys.executable, str(ROOT / "scripts/pr_gate.py"), "--repo", "acme/repo",
                "--pr", "7", "--evidence", "unused.json", *extra], capture_output=True, text=True)
            self.assertEqual(2, proc.returncode)
            self.assertIn("error:", proc.stderr)


if __name__ == "__main__":
    unittest.main()
