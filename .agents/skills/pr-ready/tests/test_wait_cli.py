"""Native CLI wait/Ready contract: real Git, fake gh, no GitHub mutation."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import test_cli_mock as cli_mock

ROOT = cli_mock.ROOT
signal_world = cli_mock.signal_world  # the fake gh's model of the pr-ready-verified signal (_shared/tests)
# ready.log holds the fake gh's PR-view count at the moment of `gh pr ready`. The signal's prepare reads the PR once
# more (its labels) right before Ready, so that count is the gate's own reads plus this one.
PREPARE_READ = 1


PASS = {"name": "go test", "bucket": "pass", "state": "SUCCESS"}
PENDING = {"name": "go test", "bucket": "pending", "state": "IN_PROGRESS"}
FAIL = {"name": "go test", "bucket": "fail", "state": "FAILURE"}
LINT = {"name": "lint", "bucket": "pass", "state": "SUCCESS"}

WAIT_GH = r'''#!/usr/bin/env python3
import base64, json, os, pathlib, re, subprocess, sys
args = sys.argv[1:]
root = pathlib.Path(os.environ["FAKE_GH_STATE"])
sha = os.environ["FAKE_GH_SHA"]
base = os.environ.get("FAKE_GH_BASE", sha)
# The pr-ready-verified signal's calls (label, user, timeline, comment, edit) are answered by the shared model, and
# so are the labels of `pr view` and `pr ready`'s bookkeeping. Every `gh` call is a new process that pays for what it
# imports: only those calls import the model.
def signal_world():
    sys.path.insert(0, os.environ["FAKE_GH_SIGNAL_DIR"])
    import ready_signal_world
    return ready_signal_world
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
          "baseRefOid": base, "baseRefName": "main", "state": "OPEN", "mergeable": "MERGEABLE",
          "isDraft": not (root / "ready").exists(), "reviewDecision": "REVIEW_REQUIRED",
          "labels": signal_world().view_labels(root)}
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
elif args[0] == "api" and "/actions/runs" in args[1]:
    endpoint = args[1]
    with (root / "workflow-queries.log").open("a") as out:
        out.write(endpoint + "\n")
    if plan.get("workflow_error"):
        print("HTTP 502: Bad Gateway", file=sys.stderr)
        sys.exit(1)
    if "/attempts/" in endpoint:
        key = endpoint.split("/actions/runs/", 1)[1]
        payload = plan.get("attempts", {}).get(key)
        if payload is None:
            print("missing attempt", file=sys.stderr)
            sys.exit(1)
    else:
        assert "--paginate" in args and "--slurp" in args
        assert "head_sha=" + plan.get("pr", {}).get("headRefOid", sha) in endpoint
        runs = plan.get("runs", [])
        payload = plan.get("workflow_pages", [{"total_count": len(runs), "workflow_runs": runs}])
    def bind(value):
        if isinstance(value, dict):
            return {k: plan.get("pr", {}).get("headRefOid", sha) if k == "head_sha" and v == "HEAD" else bind(v)
                    for k,v in value.items()}
        if isinstance(value, list):
            return [bind(v) for v in value]
        return value
    print(json.dumps(bind(payload)))
elif args[:2] == ["api", "graphql"]:
    query = next(a[6:] for a in args if a.startswith("query="))
    field = re.search(r"pullRequest\(number:\$number\)\s*\{\s*(\w+)", query).group(1)
    with (root / "graphql.log").open("a") as out:
        out.write(field + "\n")
    print(json.dumps({"data": {"repository": {"pullRequest": {
        field: {"nodes": plan.get(field, []), "pageInfo": {"hasNextPage": False, "endCursor": None}}
    }}}}))
elif args[0] == "api" and "/git/ref/heads/" in args[-1]:
    print(json.dumps({"object": {"type": "commit", "sha": plan.get("live_base", plan.get("pr", {}).get("baseRefOid", base))}}))
elif args[0] == "api" and "/compare/" in args[-1]:
    base, head = args[-1].split("/compare/")[1].split("...")
    # plan["compares"] answers per side: "LIVE...HEAD" (the PR side) and "HEAD...LIVE" (the base side).
    live = plan.get("live_base", plan.get("pr", {}).get("baseRefOid", os.environ.get("FAKE_GH_BASE", sha)))
    head_sha = plan.get("pr", {}).get("headRefOid", sha)
    key = base.replace(live, "LIVE").replace(head_sha, "HEAD") + "..." + head.replace(live, "LIVE").replace(head_sha, "HEAD")
    if key in plan.get("compares", {}):
        print(json.dumps(plan["compares"][key]))
        sys.exit(0)
    print(json.dumps(plan.get("ancestry", {"status": "identical" if base == head else "ahead",
        "behind_by": 0, "merge_base_commit": {"sha": base}})))
elif args[0] == "api" and "/contents/" in args[-1]:
    path = args[-1].split("/contents/", 1)[1].split("?", 1)[0]
    if path in plan.get("files", {}):
        print(json.dumps({"type": "file", "path": path, "encoding": "base64",
                          "content": base64.b64encode(plan["files"][path].encode()).decode()}))
        sys.exit(0)
    if "manifest" in plan:
        print(json.dumps({"type": "file", "path": ".github/pr-evidence.json", "encoding": "base64",
                          "content": base64.b64encode(json.dumps(plan["manifest"]).encode()).decode()}))
        sys.exit(0)
    print(json.dumps({"message": "Not Found", "status": "404"}))
    print("gh: Not Found (HTTP 404)", file=sys.stderr)
    sys.exit(1)
elif args[:2] == ["pr", "ready"]:
    signal_world().note_ready(root)
    branch = subprocess.check_output(["git", "-C", os.environ["WAIT_REPO"],
                                      "rev-parse", "--abbrev-ref", "HEAD"], text=True).strip()
    (root / "ready-branch").write_text(branch)
    with (root / "ready.log").open("a") as out:
        out.write(str(index) + "\n")
    (root / "ready").write_text("yes")
else:
    # None of the calls above is one the model answers, so the signal's own come here.
    signal_rc = signal_world().handle(args, root)
    if signal_rc is None:
        print("unsupported mock args " + repr(args), file=sys.stderr)
        sys.exit(1)
    sys.exit(signal_rc)
'''


def plan(*checks, **kwargs):
    return {"checks": list(checks), **kwargs}


def git(repo, *args):
    return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()


def comment(body="Reviewed feedback"):
    return {"url": "https://github.com/acme/repo/pull/7#issuecomment-1",
            "createdAt": "2026-11-02T01:00:00Z", "updatedAt": "2026-11-02T01:00:00Z", "body": body}


def workflow(run_id=11, attempt=1, status="in_progress", conclusion=None, **overrides):
    return {"id": run_id, "workflow_id": 101, "head_sha": "HEAD", "head_branch": "fix-one",
            "event": "pull_request", "path": ".github/workflows/ci.yml", "run_number": run_id,
            "run_attempt": attempt, "status": status, "conclusion": conclusion,
            "created_at": "2026-11-02T01:00:00Z", "updated_at": "2026-11-02T02:00:00Z",
            "check_suite_id": run_id + 1000, **overrides}


class WaitCLITests(unittest.TestCase):
    make_pr = cli_mock.CLIMockTests.make_pr
    evidence_only_pr = cli_mock.CLIMockTests.evidence_only_pr

    def prepare(self, t, plans, *, ancestor=False, adjust=None):
        if ancestor:
            repo, _, _, evidence, env = self.evidence_only_pr(t)
        else:
            repo, _, evidence, env = self.make_pr(t)
        if adjust is not None:
            adjust(repo, evidence, env)
        # Match the skill's checkpoint contract; the safe restore helper checks
        # actual Git cleanliness rather than the gate's evidence-path exception.
        with (repo / ".git/info/exclude").open("a") as out:
            out.write("\n/.pr-ready/\n")
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

    def run_gate(self, t, plans, *, hook=None, ancestor=False, extra=(), adjust=None, env_extra=None):
        repo, evidence, env, cli = self.prepare(t, plans, ancestor=ancestor, adjust=adjust)
        env.update(env_extra or {})
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

    BEHIND = {"status": "diverged", "behind_by": 1, "merge_base_commit": {"sha": "e" * 40}}

    def behind(self, pr_files, base_files, **kwargs):
        side = lambda files: dict(self.BEHIND, files=[{"filename": f} for f in files])
        return plan(PASS, LINT, live_base='d' * 40, ancestry=self.BEHIND,
                    compares={"LIVE...HEAD": side(pr_files), "HEAD...LIVE": side(base_files)}, **kwargs)

    def test_main_advancing_during_the_wait_does_not_block_ready(self):
        # kjelly/pilot#307: the merge train integrates the live base; Ready only needs it to be able to.
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            proc, events, _ = self.run_gate(t, [plan(PENDING, LINT), self.behind(["pkg/a.go"], ["docs/x.md"])])
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual(["WAITING-CI", "READY"], [e["status"] for e in events])

    def test_main_advancing_into_a_conflict_or_overlap_blocks_ready(self):
        for case, extra, needle in (
                ("overlap", {}, "both sides changed pkg/a.go"),
                ("conflict", {"pr": {"mergeable": "CONFLICTING"}}, "merge conflict")):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                t = Path(tmp)
                self.assert_blocked(t, [plan(PASS, LINT), self.behind(["pkg/a.go"], ["pkg/a.go"], **extra)], needle)

    def test_unknown_mergeability_waits_instead_of_blocking(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            proc, events, _ = self.run_gate(t, [plan(PASS, LINT, pr={"mergeable": "UNKNOWN"}), plan(PASS, LINT)])
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual(["WAITING-CI", "READY"], [e["status"] for e in events])
            self.assertIn("mergeability not computed yet", " ".join(events[0]["pending_checks"]))

    def test_pr_loop_task_result_is_written_for_a_blocker_after_pending_ci(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            task = t / (".pr-loop/" + "1" * 32) / "task.json"

            def write_task(_repo, evidence, _env):
                task.parent.mkdir(parents=True)
                task.write_text(json.dumps(dict(version=1, repo="acme/repo", pr=7, phase="draft",
                                                nonce="1" * 32, start_head=evidence["head_sha"])))

            proc, events, _ = self.run_gate(
                t, [plan(PENDING, LINT), plan(FAIL, LINT)], adjust=write_task,
                extra=("--pr-loop-task", str(task)))
            self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual(["WAITING-CI", "DRAFT-BLOCKED"], [e["status"] for e in events])
            result = json.loads(task.with_name("result.json").read_text())
            self.assertEqual("1" * 32, result["nonce"])
            self.assertEqual(events[-1]["head_sha"], result["head_sha"])
            self.assertEqual("DRAFT-BLOCKED", result["outcome"])
            self.assertFalse((t / "ready").exists())

    # ---- pr-loop `--pr-loop-task`: bound before any gh read, one result, no change to the gate ----

    LOOP_PARENT = ".pr-loop/" + "1" * 32  # the directory is named after the task's nonce
    LOOP_START = "c" * 40  # differs from the PR head: a result must carry the head the gate judged

    def loop_task(self, t, **overrides):
        """(task path, adjust): adjust writes the task for prepare()/run_gate() with the PR head known."""
        task = t / self.LOOP_PARENT / "task.json"

        def adjust(_repo, evidence, _env):
            body = dict(version=1, repo="acme/repo", pr=7, phase="draft", nonce="1" * 32,
                        start_head=self.LOOP_START)
            body.update(overrides)
            task.parent.mkdir(parents=True, exist_ok=True)
            task.write_text(json.dumps(body))
            self.pr_head = evidence["head_sha"]

        return task, adjust

    def log_gh_calls(self, t):
        """Every gh call, in order, in <state>/calls.log (the fake gh only logs `pr view` and a few more)."""
        gh = t / "bin/gh"
        source = gh.read_text()
        anchor = "args = sys.argv[1:]\n"
        self.assertEqual(1, source.count(anchor))
        gh.write_text(source.replace(anchor, anchor + (
            "with open(os.path.join(os.environ['FAKE_GH_STATE'], 'calls.log'), 'a') as _log:\n"
            "    _log.write(json.dumps(args) + '\\n')\n"), 1))

    def gh_calls(self, t):
        log = t / "calls.log"
        calls = [json.loads(line) for line in log.read_text().splitlines()] if log.exists() else []
        # `gh pr comment --body-file` names a fresh temporary file on every run (the signal's marker comment).
        return [["<body file>" if i and call[i - 1] == "--body-file" else arg for i, arg in enumerate(call)]
                for call in calls]

    def run_loop_cli(self, t, plans, extra, *, remove=(), **kwargs):
        repo, evidence, env, cli = self.prepare(t, plans, **kwargs)
        self.log_gh_calls(t)
        for flag in remove:
            cli.remove(flag)
        proc = subprocess.run(cli + list(extra), env=env, capture_output=True, text=True, timeout=20)
        return proc, repo, env

    def test_pr_loop_task_invalid_task_stops_before_any_gh_call_or_gate_event(self):
        refused = {
            "another repository": (dict(repo="acme/other"), "does not match this PR invocation"),
            "another PR": (dict(pr=8), "does not match this PR invocation"),
            "the ready phase": (dict(phase="ready"), "does not match this PR invocation"),
            "a short nonce": (dict(nonce="1" * 31), "does not match this PR invocation"),
            "a valid nonce that is not the directory's": (dict(nonce="3" * 32), "nonce does not match its directory"),
        }
        for case, (overrides, reason) in refused.items():
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                t = Path(tmp)
                task, adjust = self.loop_task(t, **overrides)
                proc, repo, _ = self.run_loop_cli(t, [plan(PASS, LINT)], ("--pr-loop-task", str(task)), adjust=adjust)
                self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
                self.assertEqual("", proc.stdout, "no gate event: nothing was judged")
                self.assertIn("error: pr-loop task " + reason, proc.stderr)
                self.assertEqual([], self.gh_calls(t), "the task is bound before the first gh read")
                for log in ("views.log", "graphql.log", "workflow-queries.log", "ready.log", "ready"):
                    self.assertFalse((t / log).exists(), log)
                self.assertFalse((repo / ".pr-ready/7/wait-status.json").exists())
                self.assertFalse(task.with_name("result.json").exists())

    def move_loop_task(self, task):
        """The same valid task, in a directory that is not <checkout>/.pr-loop/."""
        target = task.parents[2] / "elsewhere" / task.parent.name
        target.parent.mkdir()
        task.parent.rename(target)

    def test_pr_loop_task_at_a_wrong_path_or_that_is_unreadable_stops_before_any_gh_call(self):
        for case, setup, reason in (
                ("wrong file name", lambda task: task.rename(task.with_name("job.json")),
                 "expected the absolute path of <checkout>/.pr-loop/<nonce>/task.json"),
                ("wrong directory", lambda task: self.move_loop_task(task),
                 "expected the absolute path of <checkout>/.pr-loop/<nonce>/task.json"),
                ("not json", lambda task: task.write_text("{not json"), "Expecting property name"),
                ("missing file", lambda task: task.unlink(), "No such file or directory")):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as tmp:
                t = Path(tmp)
                task, adjust = self.loop_task(t)
                repo, evidence, env, cli = self.prepare(t, [plan(PASS, LINT)], adjust=adjust)
                self.log_gh_calls(t)
                setup(task)
                shown = {"wrong file name": task.with_name("job.json"),
                         "wrong directory": t / "elsewhere" / task.parent.name / "task.json"}.get(case, task)
                proc = subprocess.run(cli + ["--pr-loop-task", str(shown)], env=env,
                                      capture_output=True, text=True, timeout=20)
                self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
                self.assertEqual("", proc.stdout)
                self.assertIn("error: ", proc.stderr)
                self.assertIn(reason, proc.stderr)
                self.assertEqual([], self.gh_calls(t))
                self.assertFalse((t / "ready").exists())

    def test_pr_loop_task_a_valid_task_lets_the_same_scenario_run(self):
        # The control of the two tests above: the same call with a matching task reads GitHub.
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            task, adjust = self.loop_task(t)
            proc, _, _ = self.run_loop_cli(t, [plan(PASS, LINT)], ("--pr-loop-task", str(task)), adjust=adjust)
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            self.assertIn(["pr", "view"], [call[:2] for call in self.gh_calls(t)])
            self.assertTrue((t / "ready").exists())

    def test_pr_loop_task_loop_task_requires_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            task, adjust = self.loop_task(t)
            proc, repo, _ = self.run_loop_cli(t, [plan(PASS, LINT)], ("--pr-loop-task", str(task)),
                                              remove=("--ready",), adjust=adjust)
            self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual("", proc.stdout)
            self.assertIn("error: --pr-loop-task requires --ready", proc.stderr)
            self.assertEqual([], self.gh_calls(t))
            self.assertFalse(task.with_name("result.json").exists())

    def test_pr_loop_task_ready_publishes_the_ready_outcome_with_the_judged_head(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            task, adjust = self.loop_task(t)
            proc, events, _ = self.run_gate(t, [plan(PENDING, LINT), plan(PASS, LINT)], adjust=adjust,
                                            extra=("--pr-loop-task", str(task)))
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual(["WAITING-CI", "READY"], [e["status"] for e in events])
            self.assertEqual("", proc.stderr, "a pending-CI poll is progress: nothing is published or reported for it")
            result = json.loads(task.with_name("result.json").read_text())
            self.assertEqual("READY", result["outcome"])
            self.assertEqual(self.pr_head, result["head_sha"])
            self.assertEqual(events[-1]["head_sha"], result["head_sha"])
            self.assertEqual(self.LOOP_START, result["start_head"])
            self.assertNotEqual(result["start_head"], result["head_sha"])
            self.assertEqual(("draft", "1" * 32, 7, "acme/repo"),
                             (result["phase"], result["nonce"], result["pr"], result["repo"]))
            self.assertEqual(("", False), (result["wait_kind"], result["person_handoff"]))
            self.assertEqual(events[-1]["message"], result["reason"])
            self.assertEqual([str(2 + PREPARE_READ)], (t / "ready.log").read_text().splitlines())

    def test_pr_loop_task_a_blocker_publishes_draft_blocked_with_the_gate_reason_and_judged_head(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            task, adjust = self.loop_task(t)
            proc, events, _ = self.run_gate(t, [plan(FAIL, LINT)], adjust=adjust,
                                            extra=("--pr-loop-task", str(task)))
            self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
            result = json.loads(task.with_name("result.json").read_text())
            self.assertEqual("DRAFT-BLOCKED", result["outcome"])
            self.assertEqual(self.pr_head, result["head_sha"])
            self.assertEqual(events[-1]["errors"][0][:600], result["reason"])
            self.assertIn("go test", result["reason"])
            self.assertFalse((t / "ready").exists())

    def test_pr_loop_task_wait_timeout_publishes_wait_interrupted(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            task, adjust = self.loop_task(t)
            proc, events, _ = self.run_gate(t, [plan(PENDING)], adjust=adjust,
                                            extra=("--wait-timeout", "1.0", "--pr-loop-task", str(task)))
            self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual("WAIT-INTERRUPTED", events[-1]["status"])
            result = json.loads(task.with_name("result.json").read_text())
            self.assertEqual("WAIT-INTERRUPTED", result["outcome"])
            self.assertIn("timeout", result["reason"])
            self.assertEqual(events[-1]["head_sha"], result["head_sha"])
            self.assertEqual(self.pr_head, result["head_sha"])
            self.assertFalse((t / "ready").exists())

    def reset_fake_gh(self, t, repo):
        for name in ("ready", "ready-branch", "ready.log", "views.log", "graphql.log", "workflow-queries.log",
                     "calls.log", signal_world.STATE_FILE):
            (t / name).unlink(missing_ok=True)
        (repo / ".pr-ready/7/wait-status.json").unlink(missing_ok=True)

    def observe(self, t, repo, env, cli, volatile):
        proc = subprocess.run(cli, env=env, capture_output=True, text=True, timeout=20)
        events = [json.loads(line) for line in proc.stdout.splitlines()]
        for event in events:
            for key in volatile:
                event.pop(key, None)
        return {"returncode": proc.returncode, "events": events, "gh": self.gh_calls(t),
                "ready": (t / "ready").exists()}, proc

    def test_pr_loop_task_flag_changes_neither_stdout_nor_exit_code_nor_gh_calls(self):
        # Same repository, same scenario, the fake gh state reset in between: the only difference is the flag.
        # elapsed_seconds is the one per-run field (a wall clock); everything else is compared as printed.
        scenarios = {
            "READY": ([plan(PENDING, LINT), plan(PASS, LINT)], (), 0, ("elapsed_seconds",)),
            "DRAFT-BLOCKED": ([plan(PENDING, LINT), plan(FAIL, LINT)], (), 2, ("elapsed_seconds",)),
            # The number of polls inside a wall-clock timeout varies from run to run.
            "WAIT-INTERRUPTED": ([plan(PENDING)], ("--wait-timeout", "1.0"), 2, ("elapsed_seconds", "polls")),
        }
        for status, (plans, extra, code, volatile) in scenarios.items():
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                t = Path(tmp)
                task, adjust = self.loop_task(t)
                repo, evidence, env, cli = self.prepare(t, plans, adjust=adjust)
                self.log_gh_calls(t)
                without, proc = self.observe(t, repo, env, cli + list(extra), volatile)
                self.assertEqual(code, proc.returncode, proc.stdout + proc.stderr)
                self.assertEqual(status, without["events"][-1]["status"])
                self.assertFalse(task.with_name("result.json").exists(), "no flag, no result")
                self.reset_fake_gh(t, repo)
                with_flag, proc = self.observe(t, repo, env, cli + list(extra) + ["--pr-loop-task", str(task)], volatile)
                self.assertEqual("", proc.stderr)
                self.assertTrue(task.with_name("result.json").exists())
                if status == "WAIT-INTERRUPTED":
                    # How many WAITING-CI events and gh calls fit in a wall-clock timeout varies from run to
                    # run: compare the final report, the exit code and whether Ready ran.
                    self.assertEqual(without["events"][-1], with_flag["events"][-1])
                    self.assertEqual((without["returncode"], without["ready"]),
                                     (with_flag["returncode"], with_flag["ready"]))
                else:
                    self.assertEqual(without, with_flag)

    def test_pr_loop_task_a_result_that_cannot_be_published_does_not_change_the_gate(self):
        # The task already has a different result: publishing is refused. The gate's mutation, report and
        # exit code are exactly those of a run without the flag; only stderr says what was not published.
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            task, adjust = self.loop_task(t)
            repo, evidence, env, cli = self.prepare(t, [plan(PASS, LINT)], adjust=adjust)
            self.log_gh_calls(t)
            without, _ = self.observe(t, repo, env, cli, ("elapsed_seconds",))
            self.reset_fake_gh(t, repo)
            earlier = task.with_name("result.json")
            earlier.write_text("an earlier invocation's result\n")
            with_flag, proc = self.observe(t, repo, env, cli + ["--pr-loop-task", str(task)], ("elapsed_seconds",))
            self.assertEqual(without, with_flag)
            self.assertEqual(0, proc.returncode)
            self.assertEqual("pr-loop result could not be published: "
                             "this pr-loop task already has a different result\n", proc.stderr)
            self.assertEqual("an earlier invocation's result\n", earlier.read_text())

    def test_pending_to_pass_runs_ready_exactly_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            proc, events, _ = self.run_gate(t, [plan(PENDING), plan(PASS)])
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual(["WAITING-CI", "READY"], [e["status"] for e in events])
            self.assertEqual([str(2 + PREPARE_READ)], (t / "ready.log").read_text().splitlines())
            self.assertEqual({"reviewThreads", "comments", "reviews"}, set((t / "graphql.log").read_text().split()))

    def test_restore_precedes_ready_and_no_switch_follows(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, _, env, cli = self.prepare(t, [plan(PENDING), plan(PASS)])
            sha = env["FAKE_GH_SHA"]
            subprocess.run(["git", "branch", "main", sha], cwd=repo, check=True)
            subprocess.run(["git", "switch", "--quiet", "main"], cwd=repo, check=True)
            (repo / "file").write_text("starting branch has different source")
            subprocess.run(["git", "commit", "--quiet", "-am", "starting branch source"], cwd=repo, check=True)
            start_sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()
            subprocess.run(["git", "switch", "--quiet", "fix-one"], cwd=repo, check=True)
            proc = subprocess.run(cli + ["--restore-sha", start_sha, "--restore-branch=main"],
                                  env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual("main", (t / "ready-branch").read_text())
            self.assertEqual("main", subprocess.check_output(
                ["git", "branch", "--show-current"], cwd=repo, text=True).strip())
            self.assertEqual(1, len((t / "ready.log").read_text().splitlines()))

    def test_detached_start_is_restored_before_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, _, env, cli = self.prepare(t, [plan(PASS)])
            proc = subprocess.run(cli + ["--restore-sha", env["FAKE_GH_SHA"]],
                                  env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual("HEAD", (t / "ready-branch").read_text())

    def test_restore_failure_prevents_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, _, env, cli = self.prepare(t, [plan(PASS)])
            proc = subprocess.run(cli + ["--restore-sha", env["FAKE_GH_SHA"],
                                         "--restore-branch=missing-start"],
                                  env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
            self.assertIn("Checkout restoration failed", proc.stdout)
            self.assertFalse((t / "ready").exists())
            self.assertEqual("fix-one", subprocess.check_output(
                ["git", "branch", "--show-current"], cwd=repo, text=True).strip())

    def test_remote_change_after_restore_prevents_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, _, env, cli = self.prepare(t, [plan(PASS), plan(PASS),
                plan(PASS, pr={"headRefOid": "d" * 40})])
            sha = env["FAKE_GH_SHA"]
            subprocess.run(["git", "branch", "main", sha], cwd=repo, check=True)
            proc = subprocess.run(cli + ["--restore-sha", sha, "--restore-branch=main"],
                                  env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
            self.assertIn("Post-restore preflight blocked Ready", proc.stdout)
            self.assertFalse((t / "ready").exists())
            self.assertEqual("main", subprocess.check_output(
                ["git", "branch", "--show-current"], cwd=repo, text=True).strip())

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
            self.assertEqual([str(3 + PREPARE_READ)], (t / "ready.log").read_text().splitlines(),
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
        # baseRefOid is not pinned (kjelly/pilot#307): GitHub moves it when main advances.
        cases = [("headRefOid", "f" * 40), ("headRefName", "other"),
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
            self.assertEqual([str(4 + PREPARE_READ)], (t / "ready.log").read_text().splitlines())

    def test_final_preflight_rechecks_all_pins(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assert_blocked(Path(tmp), [plan(PASS), plan(PASS, pr={"headRefName": "other"})], "headRefName")

    def test_post_action_race_never_reports_validated_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            proc, events, _ = self.run_gate(t, [plan(PASS), plan(PASS), plan(PASS, pr={"headRefOid": "f" * 40})])
            self.assertEqual(2, proc.returncode, proc.stdout)
            self.assertTrue(events[-1]["ready_invoked"])
            self.assertIn("requires reevaluation", " ".join(events[-1]["errors"]))
            self.assertEqual([str(1 + PREPARE_READ)], (t / "ready.log").read_text().splitlines())
            self.assert_nothing_signed(t)

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

    def test_green_prerequisites_wait_for_workflow_and_delayed_dependent_jobs(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            # Multiple all-green snapshots can precede dependent check registration,
            # including both final preflight and post-action reads of a broken gate.
            scenarios = [plan(PASS, runs=[workflow()]), plan(PASS, runs=[workflow()]),
                         plan(PASS, runs=[workflow()]),
                         plan(PASS, {**PENDING, "name": "image"}, runs=[workflow()]),
                         plan(PASS, {**PASS, "name": "image"},
                              runs=[workflow(status="completed", conclusion="success")])]
            proc, events, _ = self.run_gate(t, scenarios)
            self.assertEqual([str(5 + PREPARE_READ)], (t / "ready.log").read_text().splitlines(),
                             "Ready must wait for workflow completion and delayed dependent jobs")
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual(["WAITING-CI"] * 4 + ["READY"], [e["status"] for e in events])
            self.assertTrue(all("Active GitHub workflow run" in " ".join(e["pending_checks"])
                                for e in events[:-1]))
            self.assertTrue((t / "workflow-queries.log").exists())

    def test_workflow_active_in_final_preflight_returns_to_wait(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            done = workflow(status="completed", conclusion="success")
            proc, events, _ = self.run_gate(t, [plan(PASS, runs=[]), plan(PASS, runs=[workflow()]),
                                               plan(PASS, runs=[done])])
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual(["WAITING-CI", "READY"], [e["status"] for e in events])
            self.assertEqual([str(3 + PREPARE_READ)], (t / "ready.log").read_text().splitlines())

    def test_new_workflow_run_cannot_hide_an_earlier_active_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            old = workflow()
            done = workflow(status="completed", conclusion="success")
            new_done = workflow(run_id=12, status="completed", conclusion="success")
            proc, events, _ = self.run_gate(t, [plan(PASS, runs=[old]),
                plan(PASS, runs=[new_done, old]), plan(PASS, runs=[new_done, done])])
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual([str(3 + PREPARE_READ)], (t / "ready.log").read_text().splitlines())
            self.assertEqual(["WAITING-CI", "WAITING-CI", "READY"], [e["status"] for e in events])

    def test_rerun_cannot_hide_an_earlier_active_attempt(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            rerun_done = workflow(attempt=2, status="completed", conclusion="success")
            old_done = workflow(status="completed", conclusion="failure")
            proc, events, _ = self.run_gate(t, [plan(PASS, runs=[workflow()]),
                plan(PASS, runs=[rerun_done], attempts={"11/attempts/1": workflow()}),
                plan(PASS, runs=[rerun_done], attempts={"11/attempts/1": old_done})])
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual([str(3 + PREPARE_READ)], (t / "ready.log").read_text().splitlines())
            self.assertEqual(["WAITING-CI", "WAITING-CI", "READY"], [e["status"] for e in events])
            self.assertIn("11/attempts/1", (t / "workflow-queries.log").read_text())

    def test_historical_terminal_failure_does_not_replace_current_check_quality(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            old = workflow(status="completed", conclusion="failure")
            new = workflow(run_id=12, status="completed", conclusion="success")
            proc, events, _ = self.run_gate(t, [plan(PASS, runs=[old, new])])
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual("READY", events[-1]["status"])

    def test_all_known_active_workflow_states_wait(self):
        for status in ("queued", "in_progress", "waiting", "pending", "requested"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as tmp:
                t = Path(tmp)
                proc, events, _ = self.run_gate(t, [plan(PASS, runs=[workflow(status=status)]),
                    plan(PASS, runs=[workflow(status="completed", conclusion="success")])])
                self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
                self.assertEqual(["WAITING-CI", "READY"], [e["status"] for e in events])

    def test_workflow_unavailable_missing_unknown_or_malformed_blocks(self):
        bad_runs = [None, {}, workflow(status="mystery"), workflow(status="completed"),
                    workflow(status="completed", conclusion="unknown"), workflow(status=[]),
                    workflow(conclusion="success"), workflow(head_sha="f" * 40),
                    workflow(run_attempt=True), workflow(created_at="invalid")]
        missing = workflow()
        del missing["conclusion"]
        bad_runs.append(missing)
        cases = [plan(PASS, workflow_error=True), plan(PASS, workflow_pages=[]),
                 plan(PASS, workflow_pages=[{}]), plan(PASS, workflow_pages=[{"total_count": True, "workflow_runs": []}]),
                 plan(PASS, workflow_pages=[{"total_count": 2, "workflow_runs": [workflow()]}]),
                 plan(PASS, runs=[workflow(), workflow()])]
        cases.extend(plan(PASS, runs=[run]) for run in bad_runs)
        for first in cases:
            with self.subTest(first=first), tempfile.TemporaryDirectory() as tmp:
                proc, events, _ = self.run_gate(Path(tmp), [first])
                self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
                self.assertEqual("DRAFT-BLOCKED", events[-1]["status"])
                self.assertFalse((Path(tmp) / "ready").exists())

    def test_paginated_workflow_runs_are_complete_and_all_observed(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            done = workflow(status="completed", conclusion="success")
            active = workflow(run_id=12)
            pages = [{"total_count": 2, "workflow_runs": [done]},
                     {"total_count": 2, "workflow_runs": [active]}]
            proc, events, _ = self.run_gate(t, [plan(PASS, workflow_pages=pages),
                plan(PASS, runs=[done, workflow(run_id=12, status="completed", conclusion="success")])])
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual(["WAITING-CI", "READY"], [e["status"] for e in events])
            self.assertEqual(2, len(events[-1]["workflow_runs"]))
        with tempfile.TemporaryDirectory() as tmp:
            self.assert_blocked(Path(tmp), [plan(PASS, workflow_pages=[
                {"total_count": 1, "workflow_runs": [workflow()]},
                {"total_count": 2, "workflow_runs": []}])], "pagination changed")

    def test_workflow_disappearance_identity_drift_attempt_regression_blocks(self):
        cases = [([], "disappeared"), ([workflow(workflow_id=102)], "identity/metadata"),
                 ([workflow(attempt=1)], "attempt regressed")]
        for runs, needle in cases:
            with self.subTest(needle=needle), tempfile.TemporaryDirectory() as tmp:
                self.assert_blocked(Path(tmp), [plan(PASS, runs=[workflow(attempt=2)]),
                    plan(PASS, runs=runs)], needle)

    def test_unverifiable_superseded_active_attempt_blocks(self):
        for previous in (None, workflow(run_id=12), workflow(attempt=2), workflow(status="unknown")):
            with self.subTest(previous=previous), tempfile.TemporaryDirectory() as tmp:
                second = plan(PASS, runs=[workflow(attempt=2, status="completed", conclusion="success")])
                if previous is not None:
                    second["attempts"] = {"11/attempts/1": previous}
                proc, events, _ = self.run_gate(Path(tmp), [plan(PASS, runs=[workflow()]), second])
                self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
                self.assertEqual("DRAFT-BLOCKED", events[-1]["status"])
                self.assertFalse((Path(tmp) / "ready").exists())

    def test_post_action_new_active_workflow_never_claims_validated_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            proc, events, _ = self.run_gate(t, [plan(PASS), plan(PASS), plan(PASS, runs=[workflow()])])
            self.assertEqual(2, proc.returncode, proc.stdout)
            self.assertTrue(events[-1]["ready_invoked"])
            self.assertIn("post-action verification failed", " ".join(events[-1]["errors"]))
            self.assertEqual([str(1 + PREPARE_READ)], (t / "ready.log").read_text().splitlines())
            self.assert_nothing_signed(t)

    def test_wait_requires_worktree_and_bounded_poll_interval(self):
        for extra in (("--wait",), ("--wait", "--worktree", ".", "--poll-interval", "61"),
                      ("--wait", "--worktree", ".", "--poll-interval", "nan"),
                      ("--wait", "--worktree", ".", "--wait-timeout", "0")):
            proc = subprocess.run([sys.executable, str(ROOT / "scripts/pr_gate.py"), "--repo", "acme/repo",
                "--pr", "7", "--evidence", "unused.json", *extra], capture_output=True, text=True)
            self.assertEqual(2, proc.returncode)
            self.assertIn("error:", proc.stderr)

    # ---- the pr-ready-verified signal around `gh pr ready` (--wait): see also test_cli_mock.ReadySignalTests ----

    LABEL = signal_world.LABEL

    def signal_calls(self, t):
        return signal_world.calls(t)

    def assert_nothing_signed(self, t):
        """No comment and no label write was made: a Ready that failed its post-action verification is never signed."""
        log = self.signal_calls(t)
        for write in ("comment", "add-label"):
            self.assertNotIn(write, log)
        world = signal_world.World.load(t)
        self.assertEqual([], [e for e in world.s["events"] if e["event"] in ("commented", "labeled")])

    def run_in_process(self, t, plans, *, adjust=None, extra=()):
        """The wait CLI run by this process, so that the sleeps of the signal's read-back can be counted and are not slept."""
        repo, evidence, env, cli = self.prepare(t, plans, adjust=adjust)
        out = io.StringIO()
        with mock.patch.dict(os.environ, env), mock.patch.object(sys, "argv", cli[1:] + list(extra)), \
                contextlib.redirect_stdout(out), mock.patch("time.sleep") as sleep:
            code = cli_mock.gate.main()
        events = [json.loads(line) for line in out.getvalue().splitlines()]
        status = json.loads((repo / ".pr-ready/7/wait-status.json").read_text())
        self.assertEqual(events[-1], status)
        return code, events, [c.args[0] for c in sleep.call_args_list]

    def test_missing_label_blocks_at_the_first_poll_without_waiting_for_ci(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            signal_world.World().label_state("missing").save(t)
            task, adjust = self.loop_task(t)
            proc, events, repo = self.run_gate(t, [plan(PENDING, LINT), plan(PASS, LINT)], adjust=adjust,
                                               extra=("--pr-loop-task", str(task)))
            self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual(["DRAFT-BLOCKED"], [e["status"] for e in events], "no WAITING-CI: CI is not awaited")
            self.assertEqual((False, 0), (events[-1]["ready_invoked"], events[-1]["polls"]))
            (reason,) = events[-1]["errors"]
            self.assertIn(f"The repository has no {self.LABEL} label", reason)
            self.assertIn("Ready not invoked", reason)
            for name in ("views.log", "graphql.log", "workflow-queries.log", "ready.log", "ready"):
                self.assertFalse((t / name).exists(), name)
            self.assertEqual(["label-exists"], self.signal_calls(t))
            result = json.loads(task.with_name("result.json").read_text())
            self.assertEqual("DRAFT-BLOCKED", result["outcome"])
            self.assertIn(f"The repository has no {self.LABEL} label", result["reason"])

    def test_the_label_present_is_the_control_of_the_missing_label_test(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            proc, events, _ = self.run_gate(t, [plan(PENDING, LINT), plan(PASS, LINT)])
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual(["WAITING-CI", "READY"], [e["status"] for e in events])

    def test_a_label_lookup_that_fails_is_a_pr_loop_blocker_not_a_traceback(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            signal_world.World().label_state("error").save(t)
            task, adjust = self.loop_task(t)
            proc, events, _ = self.run_gate(t, [plan(PASS, LINT)], adjust=adjust, extra=("--pr-loop-task", str(task)))
            self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
            self.assertNotIn("Traceback", proc.stderr)
            self.assertEqual("DRAFT-BLOCKED", events[-1]["status"])
            self.assertIn("(Ready not invoked)", events[-1]["errors"][0])
            self.assertEqual("DRAFT-BLOCKED", json.loads(task.with_name("result.json").read_text())["outcome"])
            self.assertFalse((t / "ready").exists())

    def test_missing_label_blocks_before_ready_when_it_disappears_during_the_wait(self):
        # The first poll sees the label; it is deleted before the final preflight. Only the check right before
        # `gh pr ready` can notice (the check that matters most is the one nearest to the mutation).
        hook = ("import json\nf = pathlib.Path(os.environ['FAKE_GH_STATE']) / " + repr(signal_world.STATE_FILE) + "\n"
                "w = json.loads(f.read_text())\nw['flags']['label'] = 'missing'\nf.write_text(json.dumps(w))\n")
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            signal_world.World().save(t)
            proc, events, _ = self.run_gate(t, [plan(PASS, LINT)], hook=hook)
            self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual("DRAFT-BLOCKED", events[-1]["status"])
            self.assertFalse(events[-1]["ready_invoked"])
            self.assertIn(f"The {self.LABEL} signal could not be prepared (Ready not invoked)", events[-1]["errors"][0])
            self.assertIn(f"the repository has no {self.LABEL} label", events[-1]["errors"][0])
            self.assertFalse((t / "ready").exists(), "gh pr ready must not run")
            self.assertEqual(2, self.signal_calls(t).count("label-exists"), "once at the start, once before Ready")
            self.assert_nothing_signed(t)

    def test_a_stale_label_is_removed_before_ready_and_a_failed_removal_blocks(self):
        for removal_fails in (False, True):
            with self.subTest(removal_fails=removal_fails), tempfile.TemporaryDirectory() as tmp:
                t = Path(tmp)
                world = signal_world.World()
                world.signed_ready()
                world.to_draft()  # the label from the earlier Ready epoch stays on the Draft
                if removal_fails:
                    world.fail("remove-label")
                world.save(t)
                proc, events, _ = self.run_gate(t, [plan(PASS, LINT)])
                log = self.signal_calls(t)
                if not removal_fails:
                    self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
                    self.assertLess(log.index("remove-label"), log.index("ready"))
                    self.assertEqual("READY", events[-1]["status"])
                    final = signal_world.World.load(t)
                    self.assertEqual(["labeled", "unlabeled", "labeled"],
                                     [e["event"] for e in final.s["events"] if e["event"] in ("labeled", "unlabeled")])
                    continue
                self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
                self.assertEqual("DRAFT-BLOCKED", events[-1]["status"])
                self.assertFalse(events[-1]["ready_invoked"])
                self.assertIn(f"The {self.LABEL} signal could not be prepared (Ready not invoked)", events[-1]["errors"][0])
                self.assertNotIn("ready", log)
                self.assertFalse((t / "ready").exists())

    def test_ready_writes_the_signal_in_order_and_only_then_reports_ready(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            proc, events, repo = self.run_gate(t, [plan(PASS, LINT)])
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            (ready,) = events
            self.assertEqual("READY", ready["status"])
            self.assertTrue(ready["ready_invoked"])
            sha = ready["head_sha"]
            self.assertEqual({"label": self.LABEL, "head_sha": sha, "producer": "pr-ready"}, ready["ready_signal"])
            log = self.signal_calls(t)
            self.assertEqual("label-exists", log[0], "the label is checked before any poll")
            self.assertEqual(["label-exists", "user", "pr-view"], log[log.index("ready") - 3:log.index("ready")])
            # gh pr ready < the post-action read < the comment < the label < the read-back; READY comes last.
            self.assertEqual(["ready", "pr-view", "comment", "add-label", "pr-view", "timeline"], log[log.index("ready"):])
            world = signal_world.World.load(t)
            read = signal_world.ready_signal.assess(sha, world.view_labels(), world.s["events"], signal_world.VIEWER)
            self.assertEqual(("valid", "pr-ready"), (read.state, read.producer))
            status = json.loads((repo / ".pr-ready/7/wait-status.json").read_text())
            self.assertEqual(ready["ready_signal"], status["ready_signal"])

    def test_a_signal_that_cannot_be_written_is_draft_blocked_with_ready_invoked(self):
        # label_write_failure_is_draft_blocked: GitHub accepts Ready and then refuses the comment or the label.
        for failing in ("add-label", "comment"):
            with self.subTest(failing), tempfile.TemporaryDirectory() as tmp:
                t = Path(tmp)
                signal_world.World().fail(failing).save(t)
                task, adjust = self.loop_task(t)
                proc, events, _ = self.run_gate(t, [plan(PASS, LINT)], adjust=adjust,
                                                extra=("--pr-loop-task", str(task)))
                self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
                self.assertEqual(["DRAFT-BLOCKED"], [e["status"] for e in events], "READY is never reported")
                self.assertTrue(events[-1]["ready_invoked"])
                (reason,) = events[-1]["errors"]
                self.assertIn(f"Ready invoked and verified, but the {self.LABEL} signal was not confirmed", reason)
                self.assertIn("HTTP 502", reason)
                self.assertTrue(reason.endswith("the PR is Ready without the signal; convert it to Draft and run pr-ready "
                                                "again."), reason)
                self.assertEqual([str(1 + PREPARE_READ)], (t / "ready.log").read_text().splitlines())
                self.assertEqual([], signal_world.World.load(t).label_names())
                self.assertEqual(failing == "add-label", "add-label" in self.signal_calls(t))
                result = json.loads(task.with_name("result.json").read_text())
                self.assertEqual("DRAFT-BLOCKED", result["outcome"])
                self.assertEqual(self.pr_head, result["head_sha"])
                self.assertEqual(reason[:600], result["reason"])

    def test_a_signal_that_never_reads_back_is_draft_blocked_after_the_bound(self):
        interval, tries = signal_world.ready_signal.READ_INTERVAL, signal_world.ready_signal.READ_TRIES
        for lag, ok in ((tries - 1, True), (tries, False)):
            with self.subTest(lag=lag), tempfile.TemporaryDirectory() as tmp:
                t = Path(tmp)
                world = signal_world.World()
                world.s["flags"]["lag"] = lag
                world.save(t)
                task, adjust = self.loop_task(t)
                code, events, sleeps = self.run_in_process(t, [plan(PASS, LINT)], adjust=adjust,
                                                           extra=("--pr-loop-task", str(task)))
                self.assertEqual([interval] * (tries - 1), sleeps)
                self.assertEqual(tries, self.signal_calls(t).count("timeline"))
                if ok:
                    self.assertEqual((0, ["READY"]), (code, [e["status"] for e in events]))
                    self.assertEqual("READY", json.loads(task.with_name("result.json").read_text())["outcome"])
                    continue
                self.assertEqual((2, ["DRAFT-BLOCKED"]), (code, [e["status"] for e in events]), "READY is never reported")
                self.assertTrue(events[-1]["ready_invoked"])
                self.assertIn(f"does not read back as valid after {tries} reads", events[-1]["errors"][0])
                self.assertTrue((t / "ready").exists())
                result = json.loads(task.with_name("result.json").read_text())
                self.assertEqual(("DRAFT-BLOCKED", events[-1]["errors"][0][:600]), (result["outcome"], result["reason"]))


RECORD = "docs/evidence/x/y.md"
RUN_LOG = "docs/evidence/x/run.log"
HOOK_HEADER = "import os, pathlib, subprocess\nr=pathlib.Path(os.environ['WAIT_REPO'])\n"


class TrackedArtifactPinTests(unittest.TestCase):
    """Evidence the PR commits keeps verifying after the checkout is restored to a starting branch.

    The PR commits a target-validation record and a test log. `main` (the starting branch) lacks
    them, or holds other bytes of the record, so any check that reads the worktree after the
    restore sees the wrong file. Real Git, fake gh.
    """
    prepare = WaitCLITests.prepare
    make_pr = cli_mock.CLIMockTests.make_pr
    evidence_only_pr = cli_mock.CLIMockTests.evidence_only_pr

    @staticmethod
    def write(repo, files):
        for rel, text in files.items():
            (repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (repo / rel).write_text(text)

    def pr_with_committed_files(self, t, plans, *, extra_files=None, links=None, start_files=None,
                                target=True, report=None):
        """prepare(), then commit RECORD, RUN_LOG, `extra_files` and symlinks `links` on fix-one.

        `main`, the starting branch, is the initial commit C plus `start_files`. C is also the PR
        base and the tested revision. The PR head, FAKE_GH_SHA and every head_sha in the evidence
        move to the new commit; with `target` the record is the base manifest's required
        target_validation artifact. Returns (repo, env, cli, start_sha, head).
        """
        repo, evidence, env, cli = self.prepare(t, plans)
        base = env["FAKE_GH_SHA"]
        git(repo, "branch", "main")
        if start_files:
            git(repo, "switch", "--quiet", "main")
            self.write(repo, start_files)
            git(repo, "add", "-A")
            git(repo, "commit", "--quiet", "-m", "starting branch")
            git(repo, "switch", "--quiet", "fix-one")
        record = f"# tested {base}\n"
        self.write(repo, {RECORD: record, RUN_LOG: "pass\n", **(extra_files or {})})
        for rel, destination in (links or {}).items():
            os.symlink(destination, repo / rel)
        git(repo, "add", "-A")
        git(repo, "commit", "--quiet", "-m", "evidence")
        head = git(repo, "rev-parse", "HEAD")
        env["FAKE_GH_SHA"] = head
        evidence["head_sha"] = evidence["independent_review"]["head_sha"] = head
        for category in ("tests", "lint", "static_analysis"):
            evidence["local_validation"][category][0]["head_sha"] = head
        evidence["local_validation"]["tests"][0]["log"] = RUN_LOG
        if report:
            evidence["independent_review"]["report"] = report
        changed = git(repo, "diff", "--name-only", base, head).splitlines()
        scenario = json.loads((t / "scenario.json").read_text())
        for item in scenario:
            item["pr"] = {**item.get("pr", {}), "baseRefOid": base}
            if target:
                item.update(manifest=cli_mock.TARGET_MANIFEST, files={RECORD: record},
                            ancestry=cli_mock.compare("ahead", 0, base, changed))
        if target:
            evidence["target_validation"] = {
                "decision": "required", "tested_revision": base, "artifact": RECORD,
                "reason": "Record committed in the PR names the tested base revision."}
        (t / "scenario.json").write_text(json.dumps(scenario))
        (repo / ".pr-ready/evidence.json").write_text(json.dumps(evidence))
        return repo, env, cli, git(repo, "rev-parse", "refs/heads/main"), head

    @staticmethod
    def restore(start_sha):
        return ["--restore-sha", start_sha, "--restore-branch=main"]

    def run_cli(self, cli, env, *extra):
        proc = subprocess.run(cli + list(extra), env=env, capture_output=True, text=True, timeout=30)
        events = [json.loads(line) for line in proc.stdout.splitlines()]
        self.assertTrue(events, proc.stderr)
        return proc, events

    def assert_ready_on_main(self, t, repo, proc, events):
        self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
        self.assertEqual("READY", events[-1]["status"], events[-1])
        self.assertEqual("main", (t / "ready-branch").read_text())
        self.assertEqual(1, len((t / "ready.log").read_text().splitlines()))
        self.assertEqual("main", git(repo, "branch", "--show-current"))

    def assert_blocked_on_pr_branch(self, t, repo, proc, events, *needles):
        self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
        self.assertEqual("DRAFT-BLOCKED", events[-1]["status"])
        message = " ".join(events[-1]["errors"])
        for needle in needles:
            self.assertIn(needle, message)
        self.assertFalse((t / "ready").exists())
        self.assertEqual("fix-one", git(repo, "branch", "--show-current"))

    def test_committed_record_and_log_survive_the_restore(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, env, cli, start, head = self.pr_with_committed_files(t, [plan(PENDING), plan(PASS)])
            self.assertNotEqual(git(repo, "rev-parse", "HEAD"), start)
            self.assertFalse(git(repo, "ls-tree", start, "--", "docs"), "main must not have the record")
            proc, events = self.run_cli(cli, env, *self.restore(start))
            self.assert_ready_on_main(t, repo, proc, events)
            self.assertEqual(["WAITING-CI", "READY"], [e["status"] for e in events])
            pins = json.loads((repo / ".pr-ready/7/wait-status.json").read_text())["pinned_artifacts"]
            for rel in (RECORD, RUN_LOG):
                blob = git(repo, "rev-parse", f"{head}:{rel}")
                self.assertEqual([f"git:{rel}", f"100644 {blob}"], pins[str(repo / rel)])
            # Files Git does not track keep the path + SHA-256 pin.
            report = repo / ".pr-ready/review.md"
            self.assertEqual([str(report), hashlib.sha256(report.read_bytes()).hexdigest()], pins[str(report)])

    def test_record_with_other_bytes_on_the_starting_branch_is_not_a_changed_pin(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, env, cli, start, head = self.pr_with_committed_files(
                t, [plan(PASS)], start_files={RECORD: "the starting branch has other bytes\n", RUN_LOG: "pass\n"})
            self.assertEqual(git(repo, "rev-parse", f"{start}:{RUN_LOG}"), git(repo, "rev-parse", f"{head}:{RUN_LOG}"))
            self.assertNotEqual(git(repo, "rev-parse", f"{start}:{RECORD}"), git(repo, "rev-parse", f"{head}:{RECORD}"))
            proc, events = self.run_cli(cli, env, *self.restore(start))
            self.assert_ready_on_main(t, repo, proc, events)

    def test_restore_without_wait_pins_committed_files_too(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, env, cli, start, _ = self.pr_with_committed_files(t, [plan(PASS)])
            cli.remove("--wait")
            proc, events = self.run_cli(cli, env, *self.restore(start))
            self.assert_ready_on_main(t, repo, proc, events)

    def test_bare_tracked_report_is_pinned_whatever_is_checked_out(self):
        # A name without a directory or a known suffix is path-shaped only because it is a file:
        # the classification must be the same on the PR branch and on the starting branch.
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            repo, env, cli, start, head = self.pr_with_committed_files(
                t, [plan(PASS)], extra_files={"REVIEW-REPORT": "Independent review PASS.\n"},
                report="REVIEW-REPORT", target=False)
            proc, events = self.run_cli(cli, env, *self.restore(start))
            self.assert_ready_on_main(t, repo, proc, events)
            pins = json.loads((repo / ".pr-ready/7/wait-status.json").read_text())["pinned_artifacts"]
            self.assertEqual("git:REVIEW-REPORT", pins[str(repo / "REVIEW-REPORT")][0])

    def test_untracked_report_changed_after_restore_still_blocks(self):
        # Negative control: after the restore the ignored reports and logs are still compared
        # byte for byte, so the restore did not simply switch pin verification off.
        for operation, needle in (("write_text('changed after the restore')", "artifact bytes or paths"),
                                  ("unlink()", "missing/unreadable")):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as tmp:
                t = Path(tmp)
                repo, env, cli, start, _ = self.pr_with_committed_files(
                    t, [plan(PASS)], start_files={"file": "starting branch source"})
                # View 0 and 1 are the PR-branch preflights; view 2 is the first read after the restore.
                (t / "hook-2.py").write_text(
                    HOOK_HEADER + "(r.parent/'hook-branch').write_text(subprocess.check_output("
                    "['git','-C',str(r),'branch','--show-current'],text=True).strip())\n"
                    "(r/'.pr-ready/review.md')." + operation + "\n")
                proc, events = self.run_cli(cli, env, *self.restore(start))
                self.assertEqual("main", (t / "hook-branch").read_text(), "the edit must follow the restore")
                self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
                message = " ".join(events[-1]["errors"])
                for expected in ("Post-restore preflight blocked Ready", ".pr-ready/review.md", needle):
                    self.assertIn(expected, message)
                self.assertFalse((t / "ready").exists())
                self.assertEqual("main", git(repo, "branch", "--show-current"))

    def test_tracked_artifact_edited_behind_git_status_blocks(self):
        # skip-worktree hides the edit from `git status`; the blob at the PR head still decides.
        for restore in (False, True):
            with self.subTest(restore=restore), tempfile.TemporaryDirectory() as tmp:
                t = Path(tmp)
                repo, env, cli, start, _ = self.pr_with_committed_files(t, [plan(PASS)])
                git(repo, "update-index", "--skip-worktree", RECORD)
                (repo / RECORD).write_text("edited after the receipts were taken\n")
                self.assertEqual("", git(repo, "status", "--porcelain"))
                proc, events = self.run_cli(cli, env, *(self.restore(start) if restore else ()))
                self.assert_blocked_on_pr_branch(t, repo, proc, events, "differs from PR head", RECORD)

    def test_tracked_artifact_that_is_not_a_regular_file_is_refused(self):
        cases = {"symlink": ({"docs/evidence/latest.md": "x/y.md"}, "docs/evidence/latest.md"),
                 "directory": (None, "docs/evidence/x")}
        for name, (links, report) in cases.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                t = Path(tmp)
                repo, env, cli, start, _ = self.pr_with_committed_files(
                    t, [plan(PASS)], links=links, report=report, target=False)
                proc, events = self.run_cli(cli, env, *self.restore(start))
                self.assert_blocked_on_pr_branch(t, repo, proc, events, "not a regular file", report)


class RestoreGuardTests(unittest.TestCase):
    """The checks between the restore and `gh pr ready`, and the one after it, must fire.

    Each case changes the checkout or the CI state inside the first `pr view` after the restore
    (hook-2) or after Ready (hook-3). `main`, the starting branch, has another tree, so the
    restore really switches. Real Git, fake gh.
    """
    prepare = WaitCLITests.prepare
    make_pr = cli_mock.CLIMockTests.make_pr
    evidence_only_pr = cli_mock.CLIMockTests.evidence_only_pr

    def restoring_pr(self, t, plans):
        """prepare() plus a starting branch `main` with another tree; returns (repo, env, cli)."""
        repo, _, env, cli = self.prepare(t, plans)
        git(repo, "branch", "main", env["FAKE_GH_SHA"])
        git(repo, "switch", "--quiet", "main")
        (repo / "file").write_text("starting branch has different source")
        git(repo, "commit", "--quiet", "-am", "starting branch source")
        start = git(repo, "rev-parse", "HEAD")
        git(repo, "switch", "--quiet", "fix-one")
        return repo, env, cli + ["--restore-sha", start, "--restore-branch=main"]

    @staticmethod
    def hook(t, index, body):
        """Run `body` inside view `index`; hook-branch records where the checkout was before it."""
        (t / f"hook-{index}.py").write_text(
            HOOK_HEADER + "(r.parent/'hook-branch').write_text(subprocess.check_output("
            "['git','-C',str(r),'branch','--show-current'],text=True).strip())\n" + body + "\n")

    def run_cli(self, cli, env):
        proc = subprocess.run(cli, env=env, capture_output=True, text=True, timeout=30)
        events = [json.loads(line) for line in proc.stdout.splitlines()]
        self.assertTrue(events, proc.stderr)
        return proc, events

    MOVES = (("untracked file", "(r/'stray.txt').write_text('left by something else')", "main"),
             ("detached HEAD", "subprocess.run(['git','-C',str(r),'switch','--quiet','--detach'],check=True)", ""),
             ("new commit", "subprocess.run(['git','-C',str(r),'commit','--allow-empty','-qm','moved'],check=True)", "main"))

    def test_checkout_moved_after_the_restore_blocks_ready(self):
        for name, move, branch_after in self.MOVES:
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                t = Path(tmp)
                repo, env, cli = self.restoring_pr(t, [plan(PASS)])
                self.hook(t, 2, move)  # views 0 and 1 are the PR-branch preflights
                proc, events = self.run_cli(cli, env)
                self.assertEqual("main", (t / "hook-branch").read_text(), "the move must follow the restore")
                self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
                self.assertEqual("DRAFT-BLOCKED", events[-1]["status"])
                self.assertFalse(events[-1]["ready_invoked"], "gh pr ready ran: " + proc.stdout)
                message = " ".join(events[-1]["errors"])
                self.assertIn("Post-restore preflight blocked Ready", message)
                self.assertIn("Restored checkout changed before Ready transition", message)
                self.assertFalse((t / "ready.log").exists(), "gh pr ready must not run")
                self.assertFalse((t / "ready").exists())
                self.assertEqual(branch_after, git(repo, "branch", "--show-current"))

    def test_ci_pending_only_after_the_restore_blocks_ready(self):
        # Pending is not an error in wait mode, so only the explicit `errors or pending` check
        # stops Ready here; without it gh pr ready runs while CI is still running.
        pending = {"check": plan(PASS, {**PENDING, "name": "lint"}),
                   "workflow": plan(PASS, runs=[workflow()])}
        for name, third in pending.items():
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                t = Path(tmp)
                repo, env, cli = self.restoring_pr(t, [plan(PASS), plan(PASS), third])
                proc, events = self.run_cli(cli, env)
                self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
                self.assertEqual("DRAFT-BLOCKED", events[-1]["status"])
                self.assertFalse(events[-1]["ready_invoked"], "gh pr ready ran: " + proc.stdout)
                message = " ".join(events[-1]["errors"])
                self.assertIn("Post-restore preflight blocked Ready", message)
                self.assertIn("pending" if name == "check" else "Active GitHub workflow run", message)
                self.assertFalse((t / "ready.log").exists(), "gh pr ready must not run while CI is pending")
                self.assertFalse((t / "ready").exists())
                self.assertEqual("main", git(repo, "branch", "--show-current"))

    def test_checkout_moved_after_ready_is_never_reported_ready(self):
        moves = (("untracked file", "(r/'stray.txt').write_text('after Ready')", "main"),
                 ("switched back to the PR branch",
                  "subprocess.run(['git','-C',str(r),'switch','--quiet','fix-one'],check=True)", "fix-one"),
                 self.MOVES[1], self.MOVES[2])
        for name, move, branch_after in moves:
            with self.subTest(name), tempfile.TemporaryDirectory() as tmp:
                t = Path(tmp)
                repo, env, cli = self.restoring_pr(t, [plan(PASS)])
                self.hook(t, 3 + PREPARE_READ, move)  # view 3 is the signal's prepare read, view 4 the post-Ready read
                proc, events = self.run_cli(cli, env)
                self.assertEqual("main", (t / "hook-branch").read_text(), "the move must follow Ready")
                self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
                self.assertEqual("DRAFT-BLOCKED", events[-1]["status"])
                self.assertTrue(events[-1]["ready_invoked"])
                message = " ".join(events[-1]["errors"])
                self.assertIn("Ready invoked but post-action verification failed", message)
                self.assertIn("Local worktree changed during Ready transition", message)
                self.assertEqual(1, len((t / "ready.log").read_text().splitlines()))
                self.assertEqual("main", (t / "ready-branch").read_text(), "Ready ran on the restored branch")
                self.assertEqual(branch_after, git(repo, "branch", "--show-current"))
                self.assertNotIn("comment", signal_world.calls(t), "an unverified Ready is never signed")
                self.assertNotIn("add-label", signal_world.calls(t), "an unverified Ready is never signed")


class SecretScanWaitTests(unittest.TestCase):
    """--wait scans the PR's commits once, and what it writes to wait-status.json holds no value."""

    make_pr = cli_mock.CLIMockTests.make_pr
    evidence_only_pr = cli_mock.CLIMockTests.evidence_only_pr
    prepare = WaitCLITests.prepare
    run_gate = WaitCLITests.run_gate

    def test_a_leak_blocks_the_wait_and_no_artifact_holds_the_value(self):
        value = []

        def leak(repo, evidence, env):
            value.append(cli_mock.b1(repo, evidence, env)[0])

        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            proc, events, repo = self.run_gate(t, [plan(PASS, LINT)], adjust=leak)
            self.assertEqual(2, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual("DRAFT-BLOCKED", events[-1]["status"])
            self.assertIn("freeipa-secret-attribute", " ".join(events[-1]["errors"]))
            self.assertFalse((t / "ready").exists())
            status = (repo / ".pr-ready/7/wait-status.json").read_text()
            for part in (value[0], value[0][:10], value[0][-10:]):
                for channel in (proc.stdout, proc.stderr, status):
                    self.assertNotIn(part, channel)

    def test_the_same_base_and_head_are_scanned_once_across_polls(self):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            trace = t / "git-trace.log"
            proc, events, _ = self.run_gate(t, [plan(PENDING), plan(PENDING), plan(PENDING), plan(PASS)],
                                            env_extra={"GIT_TRACE": str(trace)})
            self.assertEqual(0, proc.returncode, proc.stdout + proc.stderr)
            self.assertEqual(["WAITING-CI", "WAITING-CI", "WAITING-CI", "READY"], [e["status"] for e in events])
            walks = [line for line in trace.read_text().splitlines() if "dense-combined" in line]
            self.assertEqual(1, len(walks), "one commit walk for the whole wait, not one per poll")
            self.assertEqual("CLEAN", events[-1]["secret_scan"]["status"])
            self.assertEqual(1, events[-1]["secret_scan"]["commits_scanned"], "the PR commit is the one commit in base..head")


class FakeGhCostTests(unittest.TestCase):
    """A fake `gh` is a new interpreter per call, and a call that needs no signal state must not import the model: the
    imports it brought made a call take 60 ms instead of 23 and the suite twice as long. A stand-in model that records
    its import shows which calls import it."""

    MODEL = ("import os, pathlib\n"
             "pathlib.Path(os.environ['FAKE_GH_STATE'], 'model-imported').write_text('yes')\n"
             "def view_labels(state): return []\n"
             "def handle(args, state): return None\n"
             "def note_ready(state): pass\n")
    CHECKS = ["pr", "checks", "7"]
    REF = ["api", "repos/acme/repo/git/ref/heads/main"]
    CASES = (  # (the call, whether it needs the model)
        (CHECKS, False), (REF, False),
        (["pr", "view", "7", "--json", "number"], True),  # the labels it prints
        (["api", "user"], True),                           # one of the signal's own calls
    )

    def imports_the_model(self, script, args):
        with tempfile.TemporaryDirectory() as tmp:
            t = Path(tmp)
            (t / "gh").write_text(script)
            (t / "model").mkdir()
            (t / "model" / "ready_signal_world.py").write_text(self.MODEL)
            (t / "scenario.json").write_text(json.dumps([plan(PASS, LINT)]))
            env = dict(os.environ, FAKE_GH_STATE=str(t), FAKE_GH_SHA="a" * 40, FAKE_GH_SIGNAL_DIR=str(t / "model"))
            subprocess.run([sys.executable, "-B", str(t / "gh"), *args], env=env, capture_output=True, text=True, timeout=20)
            return (t / "model-imported").exists()

    def test_only_the_calls_that_need_signal_state_import_the_model(self):
        for name, script in (("wait", WAIT_GH), ("smoke", cli_mock.MOCK_GH)):
            for args, needs in self.CASES:
                with self.subTest(fake=name, call=" ".join(args[:3])):
                    self.assertEqual(needs, self.imports_the_model(script, args))


if __name__ == "__main__":
    unittest.main()
