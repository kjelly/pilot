"""file_umbrella.py: the planner's only writer (F1-F18). The fake GitHub builds every view from the
captured `gh issue view` shapes and refuses any command outside file_umbrella's own allowlist."""
from __future__ import annotations

import argparse
import ast
import copy
import fcntl
import io
import json
import subprocess
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from planner_fixtures import CAPTURED, planner, synthetic

import file_umbrella as fu  # noqa: E402  (scripts/ is on sys.path via planner_fixtures)

SAMPLES = json.loads((CAPTURED / "gh_issue_view.json").read_text(encoding="utf-8"))
REPO = "OWNER/REPO"
BATCH = planner.batch_id("error-swallowed", [11, 12, 13])


def node(n: int, repo: str = REPO) -> dict:
    out = copy.deepcopy(SAMPLES["with_parent_and_sub_issues"]["parent"])
    out.update(number=n, state="OPEN", url=f"https://github.com/{repo}/issues/{n}")
    return out


def issue_view(n: int, *, state="OPEN", body="Plain Issue body.", parent=None, subs=(), labels=("bug",),
               closed_by=()) -> dict:
    v = copy.deepcopy(SAMPLES["with_parent_and_sub_issues"])
    v.update(number=n, state=state, body=body, url=f"https://github.com/{REPO}/issues/{n}")
    v["parent"] = parent
    v["subIssues"] = {"nodes": [node(s) for s in subs], "totalCount": len(subs)}
    label = SAMPLES["with_parent_and_sub_issues"]["labels"][0]
    v["labels"] = [dict(label, name=name) for name in labels]
    ref = SAMPLES["closed_by_pr"]["closedByPullRequestsReferences"][0]
    v["closedByPullRequestsReferences"] = [dict(copy.deepcopy(ref), number=num, url=url) for num, url in closed_by]
    return v


class FakeGitHub:
    def __init__(self):
        self.issues = {n: issue_view(n) for n in (11, 12, 13)}
        self.open_prs: set[int] = set()
        self.calls: list[list[str]] = []
        self.create_result: planner.Result | None = None
        self.fail_edit_on: set[int] = set()
        self.drop_edits = False
        self.next_number = 900
        self.lose_create_response = False  # the Issue is created, but create_issue.py reports exit 2
        self.search_lag = False            # the search index has not caught up: every search returns []
        self.stored_body = None            # how GitHub stores a body (None: as given)

    @property
    def writes(self):
        return [c for c in self.calls if c[0] != "gh" or c[1:3] == ["issue", "edit"]]

    def __call__(self, argv, *, timeout=120):
        problem = fu._command_problem(argv)
        if problem:
            raise AssertionError(f"file_umbrella asked for a refused command {argv[:4]}: {problem}")
        self.calls.append(list(argv))
        R = planner.Result
        if argv[0] == sys.executable:
            if self.create_result is not None:
                return self.create_result
            n = self.next_number
            self.next_number += 1
            labels = [argv[i + 1] for i, a in enumerate(argv) if a == "--label"]
            body = Path(argv[argv.index("--body-file") + 1]).read_text()
            self.issues[n] = issue_view(n, body=self.stored_body(body) if self.stored_body else body, labels=labels)
            if self.lose_create_response:
                return R(2, "", "UNCERTAIN creation; inspect repository before retrying: timed out")
            return R(0, f"https://github.com/{REPO}/issues/{n}\n", "")
        sub = argv[1:3]
        if sub == ["issue", "view"]:
            n = int(argv[3])
            return R(0, json.dumps(self.issues[n]), "") if n in self.issues else R(1, "", "not found")
        if sub == ["issue", "list"]:
            hits = [{"number": n, "url": v["url"], "body": v["body"]} for n, v in sorted(self.issues.items())
                    if BATCH in v["body"] and not self.search_lag]
            return R(0, json.dumps(hits), "")
        if sub == ["pr", "list"]:
            return R(0, json.dumps([{"number": n} for n in sorted(self.open_prs)]), "")
        if sub == ["issue", "edit"]:
            umbrella, child = int(argv[3]), int(argv[7])
            if child in self.fail_edit_on:
                return R(1, "", "HTTP 502")
            if not self.drop_edits:
                self.issues[child]["parent"] = node(umbrella)
                subs = self.issues[umbrella]["subIssues"]
                subs["nodes"].append(node(child))
                subs["totalCount"] += 1
            return R(0, "", "")
        raise AssertionError(argv)


def not_a_work_tree(argv, *, timeout=300):
    assert planner._readonly_problem(argv) is None, argv
    return planner.Result(128, "", "")


def as_subprocess(gh, *, times_out=lambda argv: False):
    """A subprocess.run stand-in, so the real run_command runs: the command reaches the fake GitHub (so
    any write happens), then `times_out(argv)` decides whether the caller sees TimeoutExpired."""
    def run(argv, *, capture_output, text, timeout, check):
        r = gh(argv, timeout=timeout)
        if times_out(argv):
            raise subprocess.TimeoutExpired(argv, timeout)
        return subprocess.CompletedProcess(argv, r.returncode, r.stdout, r.stderr)
    return run


class FileUmbrellaTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.state = self.dir / "state"
        self.gh = FakeGitHub()
        self.write_report()

    def write_report(self, mutate_props=None, mutate_report=None):
        snap, props = synthetic("snapshot"), synthetic("proposals")
        if mutate_props:
            mutate_props(props)
        report = planner.build_report(snap, planner.shortlist(snap), props)
        if mutate_report:
            mutate_report(report)
        (self.dir / "report.json").write_text(planner.dumps(report))

    def approval(self, labels=("bug",), batch=BATCH):
        """What the user approved: the dry run's approval_sha256 for the current report and labels."""
        try:
            report, b = fu.load_batch(self.dir / "report.json", batch)
        except fu.Refused:
            return "0" * 64
        return fu.approval_sha256(REPO, batch, fu.build_title(b), list(labels), fu.build_body(report, b))

    def run_fu(self, *, execute=True, labels=("bug",), batch=BATCH, approval=None, runner=None, subprocess_run=None):
        """approval: None = the current dry run's value, False = leave --approval-sha256 out. subprocess_run:
        run the real run_command with this subprocess.run; otherwise `runner` (default: the fake) replaces it."""
        argv = ["--repo", REPO, "--report", str(self.dir / "report.json"), "--batch", batch,
                "--state-dir", str(self.state)] + [x for label in labels for x in ("--label", label)]
        if execute:
            argv.append("--execute")
            if approval is not False:
                argv += ["--approval-sha256", approval or self.approval(labels, batch)]
        out = io.StringIO()
        seam = patch.object(fu.subprocess, "run", side_effect=subprocess_run) if subprocess_run else \
            patch.object(fu, "run_command", side_effect=runner or self.gh)
        with seam, patch.object(planner, "run_readonly", side_effect=not_a_work_tree), redirect_stdout(out):
            code = fu.main(argv)
        return code, json.loads(out.getvalue())

    def creates(self):
        return [c for c in self.gh.calls if c[0] == sys.executable]

    def state_json(self):
        return json.loads((self.state / f"{BATCH}.json").read_text())

    def test_captured_view_shapes_parse(self):
        for name, sample in SAMPLES.items():
            with self.subTest(sample=name), \
                 patch.object(fu, "run_command", return_value=planner.Result(0, json.dumps(sample), "")):
                self.assertEqual(sample["number"], fu.view(REPO, sample["number"])["number"])

    def test_real_umbrella_shapes_after_execute(self):
        """The views captured right after the first real --execute: the child's parent finds the umbrella,
        and the read-back of the umbrella's sub-issues and labels parses."""
        umbrella = copy.deepcopy(SAMPLES["umbrella_after_execute"])
        child = copy.deepcopy(SAMPLES["child_after_execute"])
        umbrella["body"] = f"Captured body replaced.\n{fu.marker(BATCH)}\n"
        views = {umbrella["number"]: umbrella, child["number"]: child}
        with patch.object(fu, "view", side_effect=lambda repo, n: views[n]):
            found, pending = fu.find_existing(REPO, BATCH, {child["number"]: child}, self.dir / "absent.json")
        self.assertEqual(umbrella["number"], found)
        self.assertIsNone(pending)
        self.assertEqual(umbrella["number"], child["parent"]["number"])
        self.assertEqual({142, 216}, {n["number"] for n in umbrella["subIssues"]["nodes"]})
        self.assertEqual(2, umbrella["subIssues"]["totalCount"])
        self.assertTrue({"bug", "security", "area:freeipa", "P1"} <= {x["name"] for x in umbrella["labels"]})

    def test_f1_dry_run_writes_nothing_to_github(self):
        code, out = self.run_fu(execute=False)
        self.assertEqual(0, code, out)
        self.assertEqual("DRY_RUN", out["status"])
        self.assertTrue(out["would_create"])
        self.assertEqual([11, 12, 13], out["sub_issues_to_add"])
        self.assertEqual([], self.gh.writes)
        body = Path(out["body_file"]).read_text()
        self.assertIn(fu.marker(BATCH), body.splitlines())
        self.assertIn("run it on the primary Issue #11", body)
        self.assertEqual(self.approval(), out["approval_sha256"])
        self.assertFalse((self.state / f"{BATCH}.json").exists(), "a dry run records no state")

    def test_f1_execute_files_and_links(self):
        code, out = self.run_fu()
        self.assertEqual(0, code, out)
        self.assertEqual("FILED", out["status"])
        self.assertEqual([11, 12, 13], out["sub_issues"])
        self.assertEqual(1, len(self.creates()))
        self.assertEqual(900, self.state_json()["number"])
        self.assertEqual(Path(out["body_file"]).read_text(), self.gh.issues[900]["body"])

    def test_f2_only_reviewed_merge_candidates(self):
        cases = (
            (dict(mutate_report=lambda r: r.update(status="HEURISTIC_ONLY")), "not REVIEWED"),
            (dict(mutate_report=lambda r: r["batches"][0].update(invariant="changed after hashing")), "altered report"),
            (dict(mutate_props=lambda p: p["batches"][0].update(classification="RELATED_SEPARATE")), "not MERGE_CANDIDATE"),
        )
        for kwargs, needle in cases:
            with self.subTest(needle=needle):
                self.write_report(**kwargs)
                code, out = self.run_fu()
                self.assertEqual(2, code)
                self.assertIn(needle, out["error"])
                self.assertEqual([], self.gh.writes)
        self.write_report()
        code, out = self.run_fu(batch="0" * 12)
        self.assertEqual(2, code)
        self.assertIn("is not in the report", out["error"])
        code, out = self.run_fu(labels=())
        self.assertEqual(2, code)

    def test_f3_children_are_rechecked(self):
        other = f"https://github.com/{REPO}/pull/90"
        cases = (
            (lambda g: g.issues[12].update(state="CLOSED"), "is CLOSED"),
            (lambda g: (g.issues[12].update(closedByPullRequestsReferences=issue_view(
                12, closed_by=[(90, other)])["closedByPullRequestsReferences"]), g.open_prs.add(90)), "closing PR"),
            (lambda g: g.issues[12].update(closedByPullRequestsReferences=issue_view(
                12, closed_by=[(5, "https://github.com/other/repo/pull/5")])["closedByPullRequestsReferences"]), "closing PR"),
            (lambda g: (g.issues.update({700: issue_view(700, body="Someone else's umbrella")}),
                        g.issues[13].update(parent=node(700))), "another parent #700"),
            (lambda g: g.issues[13].update(parent=node(7, "other/repo")), "another repository"),
        )
        for mutate, needle in cases:
            with self.subTest(needle=needle):
                self.gh = FakeGitHub()
                mutate(self.gh)
                code, out = self.run_fu()
                self.assertEqual(2, code, out)
                self.assertIn(needle, out["error"])
                self.assertEqual([], self.gh.writes)
        self.gh = FakeGitHub()
        self.gh.issues[12]["closedByPullRequestsReferences"] = issue_view(
            12, closed_by=[(91, f"https://github.com/{REPO}/pull/91")])["closedByPullRequestsReferences"]
        self.assertEqual(0, self.run_fu()[0], "a closed same-repository PR does not block")

    def test_f4_existing_umbrella_through_a_childs_parent(self):
        self.gh.issues[800] = issue_view(800, body=f"Tracking.\n{fu.marker(BATCH)}\n", subs=(11,))
        self.gh.issues[11]["parent"] = node(800)
        code, out = self.run_fu()
        self.assertEqual(0, code, out)
        self.assertEqual("COMPLETED_EXISTING", out["status"])
        self.assertEqual([], self.creates())
        self.assertEqual([["12"], ["13"]], [[c[7]] for c in self.gh.calls if c[1:3] == ["issue", "edit"]])

    def test_f5_state_file_points_at_the_umbrella(self):
        self.gh.issues[800] = issue_view(800, body=f"x\n{fu.marker(BATCH)}")
        self.state.mkdir()
        (self.state / f"{BATCH}.json").write_text(json.dumps({"number": 800}))
        code, out = self.run_fu()
        self.assertEqual(0, code, out)
        self.assertEqual([], self.creates())
        self.assertEqual(800, out["umbrella"])

    def test_f6_search_needs_the_exact_marker_line(self):
        self.gh.issues[801] = issue_view(801, body=f"mentions {BATCH} in prose only")
        code, out = self.run_fu()
        self.assertEqual(0, code, out)
        self.assertEqual(1, len(self.creates()), "a body without the exact marker line is not the umbrella")
        self.gh = FakeGitHub()
        self.gh.issues[802] = issue_view(802, body=f"Tracking\n{fu.marker(BATCH)}")
        self.state = self.dir / "state2"
        code, out = self.run_fu()
        self.assertEqual(0, code, out)
        self.assertEqual([], self.creates())
        self.assertEqual(802, out["umbrella"])

    def test_f7_failed_link_then_rerun_continues(self):
        self.gh.fail_edit_on = {12}
        code, out = self.run_fu()
        self.assertEqual(3, code)
        self.assertEqual("PARTIAL", out["status"])
        self.assertEqual(900, json.loads((self.state / f"{BATCH}.json").read_text())["number"])
        self.gh.fail_edit_on = set()
        code, out = self.run_fu()
        self.assertEqual(0, code, out)
        self.assertEqual(1, len(self.creates()), "no second umbrella")
        self.assertEqual([11, 12, 13], out["sub_issues"])

    def test_f8_create_issue_exit_codes(self):
        """Only create_issue.py's own "BLOCKED before creation" proves nothing was created; every other
        failure leaves the pending record that blocks a second creation."""
        R = planner.Result
        traceback = "Traceback (most recent call last):\n  ...\nFileNotFoundError: gh"
        for name, result, code, state in (
                ("blocked", R(1, "", "BLOCKED before creation: unknown labels: nope\n"), 2, None),
                ("exit 1 without BLOCKED", R(1, "", traceback), 3, "pending_creation"),
                ("uncertain", R(2, "", "UNCERTAIN creation; inspect repository before retrying: timeout"), 3,
                 "pending_creation"),
                ("exit 0 without URL", R(0, "", ""), 3, "pending_creation"),
                ("labels unverified", R(3, "", f"CREATED but verification failed: https://github.com/{REPO}/issues/950; "
                                               "intended ['bug']"), 3, "number")):
            with self.subTest(name):
                self.gh = FakeGitHub()
                self.gh.create_result = result
                self.state = self.dir / name.replace(" ", "-")
                got, out = self.run_fu()
                self.assertEqual(code, got, out)
                self.assertEqual(1, len(self.creates()), "never retried automatically")
                if state is None:
                    self.assertFalse((self.state / f"{BATCH}.json").exists())
                else:
                    self.assertIn(state, self.state_json())
                if state == "pending_creation":
                    self.assertEqual("create", out["phase"])
                    self.assertIn("delete", out["guidance"])

    def test_f9_secret_or_mention_refused_before_any_call(self):
        for text, needle in (("Authorization: " + "Bearer " + "abcDEF123ghiJKL456mnoPQR", "authorization-header"),
                             ("ping @someone about it", "@mention")):
            with self.subTest(needle=needle):
                self.gh = FakeGitHub()
                self.write_report(mutate_props=lambda p, t=text: p["batches"][0].update(invariant=t))
                code, out = self.run_fu()
                self.assertEqual(2, code)
                self.assertIn(needle, out["error"])
                self.assertNotIn("abcDEF123", out["error"])
                self.assertEqual([], self.gh.calls)

    def test_f10_read_back_mismatch_is_partial(self):
        self.gh.drop_edits = True
        code, out = self.run_fu()
        self.assertEqual(3, code)
        self.assertIn("read-back differs", out["error"])

    def test_f11_lock_held(self):
        self.state.mkdir()
        with open(self.state / f"{BATCH}.lock", "a+") as held:
            fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for execute in (False, True):
                code, out = self.run_fu(execute=execute)
                self.assertEqual(2, code)
                self.assertIn("lock", out["error"])
        self.assertEqual([], self.gh.calls)
        self.assertEqual(["report.json", "state"], sorted(p.name for p in self.dir.iterdir()))
        self.assertEqual([f"{BATCH}.lock"], [p.name for p in self.state.iterdir()],
                         "a run refused by the lock writes no body or state file")

    def test_f13_a_run_refused_by_the_lock_cannot_change_what_the_holder_publishes(self):
        """Run A holds the lock and is about to create. Run B, with a newer valid report and its own
        approval, and a dry run of it, are refused by the lock before writing anything. A publishes exactly
        the body it was approved for (review R1)."""
        report_a = json.loads((self.dir / "report.json").read_text())
        body_a = fu.build_body(report_a, report_a["batches"][0])
        args_a = argparse.Namespace(repo=REPO, report=self.dir / "report.json", batch=BATCH, label=["bug"],
                                    state_dir=self.state, execute=True, approval_sha256=self.approval())
        report_b = copy.deepcopy(report_a)
        report_b["batches"][0]["invariant"] = "A different invariant from a newer report"
        report_b["content_sha256"] = planner.report_content_sha256(report_b)
        (self.dir / "report-b.json").write_text(planner.dumps(report_b))
        body_b = fu.build_body(report_b, report_b["batches"][0])
        approval_b = fu.approval_sha256(REPO, BATCH, fu.build_title(report_b["batches"][0]), ["bug"], body_b)
        args_b = argparse.Namespace(**{**vars(args_a), "report": self.dir / "report-b.json",
                                       "approval_sha256": approval_b})
        at_create, release, result = threading.Event(), threading.Event(), {}

        def runner(argv, **kwargs):
            if argv[0] == sys.executable:
                at_create.set()
                if not release.wait(10):
                    raise AssertionError("interleaving timed out")
            return self.gh(argv, **kwargs)

        def run_a():
            try:
                result["a"] = fu.file_umbrella(args_a)
            except Exception as exc:  # noqa: BLE001 - reported to the main thread
                result["a"] = exc

        with patch.object(fu, "run_command", side_effect=runner), \
             patch.object(planner, "run_readonly", side_effect=not_a_work_tree):
            worker = threading.Thread(target=run_a)
            worker.start()
            try:
                self.assertTrue(at_create.wait(10))
                calls = len(self.gh.calls)
                for execute in (True, False):
                    with self.subTest(execute=execute), self.assertRaisesRegex(fu.Refused, "lock"):
                        fu.file_umbrella(argparse.Namespace(**{**vars(args_b), "execute": execute}))
                self.assertEqual(calls, len(self.gh.calls), "B reached GitHub")
                self.assertEqual(body_a, (self.state / f"{BATCH}.body.md").read_text())
            finally:
                release.set()
                worker.join(10)
        self.assertIsInstance(result["a"], dict, result["a"])
        self.assertEqual("FILED", result["a"]["status"])
        self.assertEqual(body_a, self.gh.issues[900]["body"])
        self.assertNotEqual(body_a, body_b)

    def test_f14_execute_publishes_only_what_the_dry_run_showed(self):
        code, dry = self.run_fu(execute=False)
        self.assertEqual(0, code, dry)
        shown = Path(dry["body_file"]).read_text()
        with self.subTest("no approval"):
            code, out = self.run_fu(approval=False)
            self.assertEqual(2, code)
            self.assertIn("--approval-sha256", out["error"])
        with self.subTest("labels changed after approval"):
            code, out = self.run_fu(labels=("bug", "P3"), approval=dry["approval_sha256"])
            self.assertEqual(2, code)
            self.assertIn("approval_sha256 differs", out["error"])
        with self.subTest("report changed after approval"):
            self.write_report(mutate_props=lambda p: p["batches"][0].update(invariant="Changed after the approval"))
            code, out = self.run_fu(approval=dry["approval_sha256"])
            self.assertEqual(2, code)
            self.assertIn("approval_sha256 differs", out["error"])
            self.assertEqual(shown, Path(dry["body_file"]).read_text(), "a refused run rewrote the shown body")
        self.assertEqual([], self.gh.writes)
        self.write_report()
        code, out = self.run_fu(approval=dry["approval_sha256"])
        self.assertEqual(0, code, out)
        self.assertEqual(shown, self.gh.issues[900]["body"])

    def test_f15_read_back_body_must_be_the_approved_body(self):
        """Real capture: GitHub stores the body file byte for byte (#354, see the captured README), so any
        difference means something else was published."""
        self.gh.stored_body = lambda body: body.replace("Shared root cause", "Edited root cause")
        code, out = self.run_fu()
        self.assertEqual(3, code, out)
        self.assertIn("not the approved body", out["error"])
        self.assertEqual(900, out["umbrella"])

    def test_f16_an_uncertain_creation_is_never_repeated(self):
        """The creation succeeded but its response was lost, and search has not caught up: re-runs must not
        create a second umbrella; once the umbrella is visible it is adopted (review R2)."""
        self.gh.lose_create_response = True
        self.gh.search_lag = True
        code, out = self.run_fu()
        self.assertEqual(3, code, out)
        pending = self.state_json()["pending_creation"]
        self.assertEqual(self.approval(), pending["approval_sha256"])
        for execute in (True, False):
            with self.subTest(execute=execute):
                code, out = self.run_fu(execute=execute)
                self.assertEqual(3, code, out)
                self.assertIn("did not report its result", out["error"])
                self.assertEqual(pending, out["pending_creation"])
        self.assertEqual(1, len(self.creates()))
        self.assertEqual([], [c for c in self.gh.calls if c[1:3] == ["issue", "edit"]])
        self.gh.search_lag = False
        code, out = self.run_fu()
        self.assertEqual(0, code, out)
        self.assertEqual("COMPLETED_EXISTING", out["status"])
        self.assertEqual((900, [11, 12, 13]), (out["umbrella"], out["sub_issues"]))
        self.assertEqual(pending, out["resolved_pending_creation"])
        self.assertEqual(900, self.state_json()["number"])
        self.assertEqual(1, len(self.creates()), "no second umbrella")

    def test_f17_the_pending_record_exists_before_the_creator_runs(self):
        """A run killed while create_issue.py runs leaves the pending record behind."""
        seen = {}

        def killed_during_create(argv, **kwargs):
            if argv[0] == sys.executable:
                seen.update(self.state_json())
                raise KeyboardInterrupt
            return self.gh(argv, **kwargs)

        with self.assertRaises(KeyboardInterrupt):
            self.run_fu(runner=killed_during_create)
        self.assertIn("pending_creation", seen)
        self.assertIn("pending_creation", self.state_json())
        code, out = self.run_fu()
        self.assertEqual(3, code, out)
        self.assertEqual([], self.creates(), "blocked until the earlier attempt is resolved")

    def test_f18_errors_after_a_write_started_are_partial(self):
        """Timeouts and failed or malformed reads after a write started are exit 3 with what is known, never
        exit 2 "nothing written" (review R3). The re-run completes without a second umbrella."""
        is_create = lambda argv: argv[0] == sys.executable  # noqa: E731
        is_link_12 = lambda argv: argv[1:3] == ["issue", "edit"] and argv[-1] == "12"  # noqa: E731
        for name, times_out, phase, umbrella in (("create times out", is_create, "create", None),
                                                 ("link times out", is_link_12, "link", 900)):
            with self.subTest(name):
                self.gh, self.state = FakeGitHub(), self.dir / name.replace(" ", "-")
                code, out = self.run_fu(subprocess_run=as_subprocess(self.gh, times_out=times_out))
                self.assertEqual(3, code, out)
                self.assertEqual((phase, umbrella), (out["phase"], out["umbrella"]))
                self.assertIn("did not finish", out["error"])
                code, out = self.run_fu(subprocess_run=as_subprocess(self.gh))
                self.assertEqual(0, code, out)
                self.assertEqual((900, [11, 12, 13]), (out["umbrella"], out["sub_issues"]))
                self.assertEqual(1, len(self.creates()))
        for name, response in (("read-back fails", planner.Result(1, "", "HTTP 502")),
                               ("read-back is not JSON", planner.Result(0, "<html>", "")),
                               ("read-back has another shape", planner.Result(0, json.dumps({"number": 900}), ""))):
            with self.subTest(name):
                self.gh, self.state = FakeGitHub(), self.dir / name.replace(" ", "-")
                gh = self.gh

                def runner(argv, **kwargs):
                    return response if argv[1:4] == ["issue", "view", "900"] else gh(argv, **kwargs)

                code, out = self.run_fu(runner=runner)
                self.assertEqual(3, code, out)
                self.assertEqual(("read-back", 900), (out["phase"], out["umbrella"]))
                self.assertEqual([900, 900, 900], [gh.issues[n]["parent"]["number"] for n in (11, 12, 13)])


class AllowlistTest(unittest.TestCase):
    ALLOWED = [
        [sys.executable, str(fu.CREATE_ISSUE), "--repo", REPO, "--title", "umbrella(x): y", "--body-file", "/s/b.md",
         "--label", "bug", "--label", "P3"],
        ["gh", "issue", "view", "12", "-R", REPO, "--json", fu.VIEW_FIELDS],
        ["gh", "issue", "list", "-R", REPO, "--state", "all", "--search", f"{BATCH} in:body", "--limit", "20",
         "--json", "number,url,body"],
        ["gh", "pr", "list", "-R", REPO, "--state", "open", "--limit", "1000", "--json", "number"],
        ["gh", "issue", "edit", "900", "-R", REPO, "--add-sub-issue", "12"],
    ]
    REFUSED = [
        ["gh", "issue", "close", "12", "-R", REPO],
        ["gh", "issue", "comment", "12", "-R", REPO, "--body", "x"],
        ["gh", "issue", "edit", "900", "-R", REPO, "--add-label", "bug"],
        ["gh", "issue", "edit", "900", "-R", REPO, "--remove-sub-issue", "12"],
        ["gh", "api", "repos/OWNER/REPO/issues"],
        ["gh", "issue", "list", "-R", REPO, "--state", "all", "--search", "anything at all", "--limit", "20",
         "--json", "number,url,body"],
        [sys.executable, "/tmp/other.py", "--repo", REPO],
        [sys.executable, str(fu.CREATE_ISSUE), "--repo", REPO, "--title", "t", "--body-file", "b", "--label", "a\nb"],
        ["sh", "-c", "gh issue close 12"],
    ]

    def test_f12_allowlist(self):
        for argv in self.ALLOWED:
            with self.subTest(argv=argv[:4]):
                self.assertIsNone(fu._command_problem(argv))
        for argv in self.REFUSED:
            with self.subTest(argv=argv[:4]), patch.object(fu.subprocess, "run", side_effect=AssertionError("ran")):
                self.assertIsNotNone(fu._command_problem(argv))
                with self.assertRaises(fu.Refused):
                    fu.run_command(argv)

    def test_f18_a_write_that_times_out_is_partial(self):
        """A timed-out write may still happen (the killed creator's `gh` can outlive it); a timed-out read
        changed nothing."""
        with patch.object(fu.subprocess, "run", side_effect=subprocess.TimeoutExpired("cmd", 120)):
            for argv in self.ALLOWED:
                with self.subTest(argv=argv[:4]):
                    write = argv[0] == sys.executable or argv[1:3] == ["issue", "edit"]
                    with self.assertRaises(fu.Partial if write else fu.Refused) as caught:
                        fu.run_command(argv)
                    self.assertNotIsInstance(caught.exception, fu.Partial if not write else fu.Refused)

    def test_f12_subprocess_only_in_run_command(self):
        tree = ast.parse(Path(fu.__file__).read_text(encoding="utf-8"))
        uses = []
        for fn in ast.walk(tree):
            if isinstance(fn, ast.FunctionDef):
                for n in ast.walk(fn):
                    if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "subprocess":
                        uses.append(fn.name)
        self.assertEqual({"run_command"}, set(uses))


if __name__ == "__main__":
    unittest.main()
