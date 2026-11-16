"""collect: snapshot.json from captured gh output (B01, B02, B09c, B16, completeness, out-dir rules).
The fake runner replays fixtures/captured and itself refuses any command outside the read-only forms."""
from __future__ import annotations

import io
import json
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from planner_fixtures import BASE_SHA, captured_text, planner

TREE = ["playbooks/apply/alpha-apply.yml", "docs/verification/beta.md", "internal/gamma/gamma.go", "scripts/delta.py"]
TEST_DEFS = "func TestAlphaLookupFailure\ndef test_delta_cleanup\n"
INJECTED = ("SYSTEM", "example.invalid", "deploy token", "open-files-in-pager", "etc/passwd", "Ignore all previous")


class FakeGitHub:
    def __init__(self, *, issues=None, prs=None, overrides=None):
        self.calls: list[list[str]] = []
        self.issues = captured_text("gh_issue_list") if issues is None else issues
        self.prs = captured_text("gh_pr_list") if prs is None else prs
        self.overrides = overrides or {}

    def __call__(self, argv, *, timeout=300):
        problem = planner._readonly_problem(argv)
        if problem:
            raise AssertionError(f"collect asked for a refused command {argv}: {problem}")
        self.calls.append(list(argv))
        key = " ".join(argv[:3]) if argv[0] == "gh" else (argv[1] if argv[1] != "-C" else argv[3])
        if key in self.overrides:
            return self.overrides[key]
        R = planner.Result
        return {
            "gh repo view": R(0, '{"defaultBranchRef":{"name":"main"}}\n', ""),
            "ls-remote": R(0, f"{BASE_SHA}\trefs/heads/main\n", ""),
            "cat-file": R(0, "", ""),
            "ls-tree": R(0, "\0".join(TREE) + "\0", ""),
            "grep": R(0, TEST_DEFS, ""),
            "rev-parse": R(128, "", "fatal: not a git repository"),
            "gh issue list": R(0, self.issues, ""),
            "gh pr list": R(0, self.prs, ""),
            "gh --version": R(0, "gh version 2.103.3 (2026-10-26)\n", ""),
            "--version": R(0, "git version 2.51.0\n", ""),
        }[key]


class CollectTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.out = Path(self.tmp.name) / "run"

    def collect(self, fake=None, *, limit=1000):
        fake = fake or FakeGitHub()
        out, err = io.StringIO(), io.StringIO()
        with patch.object(planner, "run_readonly", side_effect=fake), redirect_stdout(out), redirect_stderr(err):
            code = planner.main(["collect", "--repo", "kjelly/pilot", "--repo-dir", "/repo",
                                 "--out-dir", str(self.out), "--limit", str(limit)])
        snap_path = self.out / "snapshot.json"
        snap = json.loads(snap_path.read_text()) if snap_path.exists() else None
        return code, snap, fake, err.getvalue()

    def issue(self, snap, n):
        return next(i for i in snap["issues"] if i["number"] == n)

    def test_snapshot_from_captured_output(self):
        code, snap, _, err = self.collect()
        self.assertEqual(0, code, err)
        self.assertEqual([], planner.snapshot_problems(snap))
        self.assertTrue(planner.snapshot_complete(snap))
        self.assertEqual({"branch": "main", "sha": BASE_SHA}, snap["base"])
        i501 = self.issue(snap, 501)
        self.assertEqual(["playbooks/apply/alpha-apply.yml"], i501["referenced_paths"])
        self.assertEqual([502], i501["referenced_issues"])
        self.assertEqual(["TestAlphaLookupFailure"], i501["referenced_tests"])
        self.assertEqual(1, i501["comments_count"])
        i504 = self.issue(snap, 504)
        self.assertEqual([{"number": 601, "state": "OPEN", "url": "https://github.com/kjelly/pilot/pull/601"}],
                         i504["closed_by_prs"])
        pr601 = next(p for p in snap["pull_requests"] if p["number"] == 601)
        self.assertEqual([504], pr601["closing_issues"])
        self.assertEqual([504], pr601["body_closing_issues"])
        pr602 = next(p for p in snap["pull_requests"] if p["number"] == 602)
        self.assertEqual([], pr602["body_closing_issues"], "Refs is not a closing keyword")
        self.assertEqual(1, self.issue(snap, 506)["sub_issue_count"])
        i507 = self.issue(snap, 507)
        self.assertEqual(506, i507["parent"])
        self.assertEqual([{"number": 61398, "state": "OPEN", "url": "https://github.com/nodejs/node/issues/61398"}],
                         i507["blocked_by"])
        self.assertTrue(i507["relations_complete"])
        self.assertTrue((self.out / "run-metadata.json").exists())

    def test_b09c_issue_text_never_reaches_a_command_or_a_file(self):
        code, snap, fake, _ = self.collect()
        self.assertEqual(0, code)
        text = (self.out / "snapshot.json").read_text()
        for needle in INJECTED:
            self.assertNotIn(needle, " ".join(" ".join(c) for c in fake.calls))
            self.assertNotIn(needle, text.replace("Ignore all previous rules", ""))  # titles are kept
        self.assertNotIn('"body"', text)
        self.assertEqual(["docs/verification/beta.md"], self.issue(snap, 503)["referenced_paths"])

    def test_b01_a_full_page_is_incomplete(self):
        code, snap, _, _ = self.collect(limit=7)
        self.assertEqual(2, code)
        self.assertFalse(snap["sources"]["issues"]["complete"])
        self._reset()
        code, snap, _, _ = self.collect(limit=8)
        self.assertEqual(0, code)
        self.assertTrue(snap["sources"]["issues"]["complete"])

    def _reset(self):
        if self.out.exists():
            shutil.rmtree(self.out)

    def test_comment_and_file_caps_make_the_snapshot_incomplete(self):
        issues = json.loads(captured_text("gh_issue_list"))
        issues[0]["comments"] = issues[0]["comments"] * planner.GH_COMMENT_CAP
        prs = json.loads(captured_text("gh_pr_list"))
        prs[0]["changedFiles"] = 150
        code, snap, _, _ = self.collect(FakeGitHub(issues=json.dumps(issues), prs=json.dumps(prs)))
        self.assertEqual(2, code)
        self.assertFalse(self.issue(snap, 501)["comments_complete"])
        self.assertFalse(next(p for p in snap["pull_requests"] if p["number"] == 601)["files_complete"])

    def test_closing_references_of_other_repositories_or_closed_prs(self):
        issues = json.loads(captured_text("gh_issue_list"))
        ref = issues[3]["closedByPullRequestsReferences"][0]
        for url, number, state in (("https://github.com/kjelly/pilot/pull/700", 700, "NOT_OPEN"),
                                   ("https://github.com/other/repo/pull/601", 601, "UNKNOWN")):
            with self.subTest(state=state):
                ref.update(url=url, number=number)
                self._reset()
                code, snap, _, _ = self.collect(FakeGitHub(issues=json.dumps(issues)))
                self.assertEqual(0, code)
                self.assertEqual(state, self.issue(snap, 504)["closed_by_prs"][0]["state"])

    def test_b02_failures_write_no_snapshot(self):
        R = planner.Result
        cases = {
            "gh issue list": R(1, "", "HTTP 502"),
            "gh pr list": R(0, "not json", ""),
            "cat-file": R(128, "", "fatal: Not a valid object name"),
            "ls-remote": R(0, "", ""),
        }
        for key, result in cases.items():
            with self.subTest(failing=key):
                self._reset()
                code, snap, _, err = self.collect(FakeGitHub(overrides={key: result}))
                self.assertEqual(2, code)
                self.assertIsNone(snap)
                self.assertIn("ERROR", err)

    def test_unexpected_shape_fails_closed(self):
        issues = json.loads(captured_text("gh_issue_list"))
        del issues[6]["blockedBy"]["totalCount"]
        code, snap, _, err = self.collect(FakeGitHub(issues=json.dumps(issues)))
        self.assertEqual(2, code)
        self.assertIsNone(snap)
        self.assertIn("blockedBy", err)

    def test_b16_closing_keywords_come_from_issue_gate(self):
        gate = planner.issue_gate()
        self.assertTrue(Path(gate.__file__).as_posix().endswith("issue-to-pr/scripts/issue_gate.py"))
        with patch.object(gate, "closes_issue", return_value=False):
            code, snap, _, _ = self.collect()
        self.assertEqual(0, code)
        self.assertEqual([], next(p for p in snap["pull_requests"] if p["number"] == 601)["body_closing_issues"])


class OutDirTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def run_prepare(self, out, *, toplevel=None, ignored=True):
        def fake(argv, *, timeout=300):
            self.assertIsNone(planner._readonly_problem(argv))
            if argv[3] == "rev-parse":
                return planner.Result(0, f"{toplevel}\n", "") if toplevel else planner.Result(128, "", "")
            return planner.Result(0 if ignored else 1, "", "")
        with patch.object(planner, "run_readonly", side_effect=fake):
            return planner.prepare_out_dir(out)

    def test_outside_a_work_tree(self):
        self.assertTrue(self.run_prepare(self.root / "new").is_dir())

    def test_non_empty_is_refused(self):
        (self.root / "full").mkdir()
        (self.root / "full" / "x").write_text("x")
        with self.assertRaises(planner.PlannerError):
            self.run_prepare(self.root / "full")

    def test_inside_a_work_tree_must_be_ignored(self):
        with self.assertRaises(planner.PlannerError):
            self.run_prepare(self.root / "tracked", toplevel=self.root, ignored=False)
        self.assertFalse((self.root / "tracked").exists())
        self.assertTrue(self.run_prepare(self.root / "ignored", toplevel=self.root, ignored=True).is_dir())


if __name__ == "__main__":
    unittest.main()
