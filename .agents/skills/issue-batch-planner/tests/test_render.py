"""render: report.json / report.md (B12, B09r, B14, B10r, B15) and its refusals."""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from planner_fixtures import BASE_TREE, planner, snapshot_bytes, synthetic


def not_a_work_tree(argv, *, timeout=300):
    assert planner._readonly_problem(argv) is None, argv
    return planner.Result(128, "", "fatal: not a git repository")


class RenderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.snapshot = synthetic("snapshot")
        self.proposals = synthetic("proposals")

    def write_inputs(self, *, proposals=True):
        (self.dir / "snapshot.json").write_bytes(snapshot_bytes(self.snapshot))
        (self.dir / "candidates.json").write_text(planner.dumps(planner.shortlist(self.snapshot)))
        if proposals:
            self.proposals["snapshot_sha256"] = planner.sha256_bytes(snapshot_bytes(self.snapshot))
            (self.dir / "proposals.json").write_text(json.dumps(self.proposals))

    def render(self, out="out", *, proposals=True, extra=()):
        argv = ["render", "--snapshot", str(self.dir / "snapshot.json"), "--candidates", str(self.dir / "candidates.json"),
                "--out-dir", str(self.dir / out), *extra]
        if proposals:
            argv += ["--proposals", str(self.dir / "proposals.json"), "--repo-dir", "/repo"]
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(planner, "run_readonly", side_effect=not_a_work_tree), \
             patch.object(planner, "base_tree_paths", return_value=set(BASE_TREE)), \
             redirect_stdout(stdout), redirect_stderr(stderr):
            code = planner.main(argv)
        return code, self.dir / out, stdout.getvalue() + stderr.getvalue()

    def test_reviewed_report(self):
        self.write_inputs()
        code, out, log = self.render()
        self.assertEqual(0, code, log)
        report = json.loads((out / "report.json").read_text())
        self.assertEqual("REVIEWED", report["status"])
        batch = report["batches"][0]
        self.assertEqual(planner.batch_id("error-swallowed", [11, 12, 13]), batch["batch_id"])
        self.assertFalse(batch["all_fully_addressable"], "#13 is partial_only")
        self.assertTrue(batch["human_approval_required"])
        md = (out / "report.md").read_text()
        self.assertIn("Primary: #11", md)
        self.assertIn("`Refs` only", md)
        self.assertIn("keep the others open", md)
        self.assertIn("#14", md.split("## Already covered by an open PR")[1])

    def test_b12_without_proposals_is_heuristic_only(self):
        self.write_inputs(proposals=False)
        code, out, log = self.render(proposals=False)
        self.assertEqual(0, code, log)
        report = json.loads((out / "report.json").read_text())
        self.assertEqual("HEURISTIC_ONLY", report["status"])
        self.assertEqual([], report["batches"])
        md = (out / "report.md").read_text()
        self.assertIn(planner.HEURISTIC_WARNING, md.split("## Suggested batches")[0])
        self.assertNotIn("REVIEWED", md)

    def test_b14_every_open_issue_exactly_once(self):
        self.write_inputs()
        code, out, _ = self.render()
        self.assertEqual(0, code)
        numbers = [i["number"] for i in json.loads((out / "report.json").read_text())["issues"]]
        self.assertEqual(sorted(i["number"] for i in self.snapshot["issues"]), numbers)
        broken = json.loads(json.dumps(self.proposals))
        broken["issue_statuses"].pop()
        with self.assertRaises(planner.PlannerError):
            planner.build_report(self.snapshot, planner.shortlist(self.snapshot), broken)

    def test_b09r_secret_shaped_text_blocks_the_report(self):
        self.proposals["batches"][0]["invariant"] = "Authorization: " + "Bearer " + "abcDEF123ghiJKL456mnoPQR"
        self.write_inputs()
        code, out, log = self.render()
        self.assertEqual(2, code)
        self.assertFalse((out / "report.json").exists())
        self.assertFalse((out / "report.md").exists())
        diag = (out / "render-diagnostics.json").read_text()
        self.assertIn("authorization-header", diag)
        self.assertNotIn("abcDEF123", diag + log)

    def test_invalid_proposals_block_the_report(self):
        self.write_inputs()
        self.proposals["base_sha"] = "b" * 40
        (self.dir / "proposals.json").write_text(json.dumps(self.proposals))
        code, out, _ = self.render()
        self.assertEqual(2, code)
        self.assertFalse((out / "report.md").exists())
        self.assertIn("base_sha", (out / "render-diagnostics.json").read_text())

    def test_b10r_same_input_same_report(self):
        self.write_inputs()
        first = (self.render("a")[1] / "report.json").read_bytes()
        second = (self.render("b")[1] / "report.json").read_bytes()
        self.assertEqual(first, second)
        report = json.loads(first)
        self.assertEqual(planner.report_content_sha256(report), report["content_sha256"])

    def test_candidates_must_belong_to_the_snapshot(self):
        self.write_inputs()
        other = synthetic("snapshot")
        other["issues"].pop()
        other["sources"]["issues"]["count"] -= 1
        (self.dir / "candidates.json").write_text(planner.dumps(planner.shortlist(other)))
        code, _, log = self.render()
        self.assertEqual(2, code)
        self.assertIn("does not belong to this snapshot", log)

    def test_incomplete_snapshot_report_says_so_and_exits_2(self):
        self.snapshot["sources"]["pull_requests"]["complete"] = False
        self.write_inputs(proposals=False)
        code, out, _ = self.render(proposals=False)
        self.assertEqual(2, code)
        report = json.loads((out / "report.json").read_text())
        self.assertEqual("INCOMPLETE", report["status"])
        self.assertIn("incomplete", (out / "report.md").read_text())

    def test_b15_never_overwrites_a_report(self):
        self.write_inputs()
        self.assertEqual(0, self.render()[0])
        code, _, log = self.render()
        self.assertEqual(2, code)
        self.assertIn("already exists", log)

    def test_proposals_need_repo_dir(self):
        self.write_inputs()
        argv = ["render", "--snapshot", str(self.dir / "snapshot.json"), "--candidates", str(self.dir / "candidates.json"),
                "--proposals", str(self.dir / "proposals.json"), "--out-dir", str(self.dir / "o")]
        with patch.object(planner, "run_readonly", side_effect=not_a_work_tree), redirect_stderr(io.StringIO()) as err:
            self.assertEqual(2, planner.main(argv))
        self.assertIn("--repo-dir", err.getvalue())


if __name__ == "__main__":
    unittest.main()
