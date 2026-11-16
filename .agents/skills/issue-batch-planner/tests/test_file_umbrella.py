"""file_umbrella.py: the planner's only writer (F1-F12). The fake GitHub builds every view from the
captured `gh issue view` shapes and refuses any command outside file_umbrella's own allowlist."""
from __future__ import annotations

import ast
import copy
import fcntl
import io
import json
import sys
import tempfile
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
            self.issues[n] = issue_view(n, body=body, labels=labels)
            return R(0, f"https://github.com/{REPO}/issues/{n}\n", "")
        sub = argv[1:3]
        if sub == ["issue", "view"]:
            n = int(argv[3])
            return R(0, json.dumps(self.issues[n]), "") if n in self.issues else R(1, "", "not found")
        if sub == ["issue", "list"]:
            hits = [{"number": n, "url": v["url"], "body": v["body"]} for n, v in sorted(self.issues.items())
                    if BATCH in v["body"]]
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

    def run_fu(self, *, execute=True, labels=("bug",), batch=BATCH):
        argv = ["--repo", REPO, "--report", str(self.dir / "report.json"), "--batch", batch,
                "--state-dir", str(self.state)] + [x for label in labels for x in ("--label", label)]
        if execute:
            argv.append("--execute")
        out = io.StringIO()
        with patch.object(fu, "run_command", side_effect=self.gh), \
             patch.object(planner, "run_readonly", side_effect=not_a_work_tree), redirect_stdout(out):
            code = fu.main(argv)
        return code, json.loads(out.getvalue())

    def creates(self):
        return [c for c in self.gh.calls if c[0] == sys.executable]

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
            found = fu.find_existing(REPO, BATCH, {child["number"]: child}, self.dir / "absent.json")
        self.assertEqual(umbrella["number"], found)
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

    def test_f1_execute_files_and_links(self):
        code, out = self.run_fu()
        self.assertEqual(0, code, out)
        self.assertEqual("FILED", out["status"])
        self.assertEqual([11, 12, 13], out["sub_issues"])
        self.assertEqual(1, len(self.creates()))
        self.assertEqual(900, json.loads((self.state / f"{BATCH}.json").read_text())["number"])

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
        R = planner.Result
        for rc, stderr, code, state_written in (
                (1, "BLOCKED before creation: unknown labels: nope", 2, False),
                (2, "UNCERTAIN creation; inspect repository before retrying: timeout", 3, False),
                (3, f"CREATED but verification failed: https://github.com/{REPO}/issues/950; intended ['bug']", 3, True)):
            with self.subTest(rc=rc):
                self.gh = FakeGitHub()
                self.gh.create_result = R(rc, "", stderr)
                self.state = self.dir / f"s{rc}"
                got, out = self.run_fu()
                self.assertEqual(code, got, out)
                self.assertEqual(1, len(self.creates()), "never retried automatically")
                self.assertEqual(state_written, (self.state / f"{BATCH}.json").exists())

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
            code, out = self.run_fu()
        self.assertEqual(2, code)
        self.assertIn("lock", out["error"])
        self.assertEqual([], self.gh.writes)


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
