"""shortlist: hard statuses and non-transitive heuristic groups (B03-B07, B10)."""
from __future__ import annotations

import json
import os
import random
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from planner_fixtures import make_issue, make_snapshot, planner, synthetic

SCRIPT = Path(planner.__file__)
A = "playbooks/apply/a.yml"
B = "playbooks/apply/b.yml"


def groups(snapshot):
    return [g["issue_numbers"] for g in planner.shortlist(snapshot)["groups"]]


class ShortlistTest(unittest.TestCase):
    def test_b03_title_or_label_alone_is_not_a_candidate(self):
        snap = make_snapshot([
            make_issue(1, title="Lookup failure read as absent host", labels=["area:freeipa"]),
            make_issue(2, title="Lookup failure read as absent host", labels=["area:freeipa"]),
            make_issue(3, title="Alpha retry", paths=[A]), make_issue(4, title="Beta timeout", paths=[A]),  # 25 < 30
        ])
        result = planner.shortlist(snap)
        self.assertEqual([], result["groups"])
        self.assertEqual([[3, 4]], [p["issues"] for p in result["pairs"]], "weak-only pairs are not listed")
        self.assertFalse(result["pairs"][0]["candidate"])

    def test_b04_shared_path_and_cross_reference_form_a_group(self):
        snap = make_snapshot([make_issue(1, paths=[A], refs=[2]), make_issue(2, paths=[A]), make_issue(3)])
        result = planner.shortlist(snap)
        self.assertEqual([[1, 2]], [g["issue_numbers"] for g in result["groups"]])
        self.assertEqual("HEURISTIC_CANDIDATE", result["groups"][0]["classification"])
        self.assertEqual(planner.batch_id("heuristic", [1, 2]), result["groups"][0]["batch_id"])
        self.assertEqual([3], result["unassigned"])

    def test_b05_existing_pr_is_never_grouped(self):
        pr = {"number": 90, "url": "https://github.com/OWNER/REPO/pull/90", "is_draft": False, "closing_issues": [2],
              "body_closing_issues": [], "files": [], "files_complete": True}
        snap = make_snapshot([make_issue(1, paths=[A], refs=[2]), make_issue(2, paths=[A])], [pr])
        result = planner.shortlist(snap)
        self.assertEqual([], result["groups"])
        status = {s["number"]: s for s in result["issue_statuses"]}
        self.assertEqual("EXISTING_PR", status[2]["status"])
        self.assertEqual([90], status[2]["open_prs"])
        self.assertEqual("ELIGIBLE", status[1]["status"])

    def test_b06_grouping_is_not_transitive(self):
        snap = make_snapshot([
            make_issue(1, paths=[A], refs=[2]),
            make_issue(2, paths=[A, B], tests=["TestB"]),
            make_issue(3, paths=[B], tests=["TestB"]),
        ])
        found = groups(snap)
        self.assertNotIn([1, 2, 3], found)
        self.assertEqual([[2, 3]], found, "the higher-scoring pair wins; 1 is not linked to 3")

    def test_b07_hard_statuses(self):
        snap = make_snapshot([
            make_issue(1, labels=["needs-decision"]), make_issue(2, blocked=[99]),
            make_issue(3, labels=["likely-resolved"]), make_issue(4, sub_issue_count=2),
            make_issue(5, closed_by=[77]),
        ])
        status = {s["number"]: s["status"] for s in planner.shortlist(snap)["issue_statuses"]}
        self.assertEqual({1: "NEEDS_DECISION", 2: "BLOCKED_BY", 3: "ALREADY_RESOLVED_REVIEW", 4: "UNASSIGNED",
                          5: "EXISTING_PR"}, status)

    def test_unknown_and_closed_references(self):
        snap = make_snapshot([make_issue(1, closed_by=[77]), make_issue(2, blocked=[99])])
        snap["issues"][0]["closed_by_prs"][0].update(state="NOT_OPEN")
        snap["issues"][1]["blocked_by"][0].update(state="CLOSED")
        self.assertEqual({"ELIGIBLE"}, {s["status"] for s in planner.shortlist(snap)["issue_statuses"]})
        snap["issues"][0]["closed_by_prs"][0].update(state="UNKNOWN", url="https://github.com/other/repo/pull/77")
        status = {s["number"]: s for s in planner.shortlist(snap)["issue_statuses"]}
        self.assertEqual("EXISTING_PR", status[1]["status"])
        self.assertIn("https://github.com/other/repo/pull/77", status[1]["reason"])

    def test_groups_hold_at_most_four(self):
        snap = make_snapshot([make_issue(n, paths=[A], tests=["TestA"]) for n in range(1, 6)])
        found = groups(snap)
        self.assertEqual([[1, 2, 3, 4]], found)
        self.assertEqual([5], planner.shortlist(snap)["unassigned"])

    def test_overlapping_open_pr_is_reported(self):
        snap = synthetic("snapshot")
        status = {s["number"]: s for s in planner.shortlist(snap)["issue_statuses"]}
        self.assertEqual([91], status[17]["overlapping_prs"])


class DeterminismTest(unittest.TestCase):
    def test_b10_same_content_same_bytes(self):
        snap = synthetic("snapshot")
        shuffled = json.loads(json.dumps(snap))
        random.Random(7).shuffle(shuffled["issues"])
        random.Random(8).shuffle(shuffled["pull_requests"])
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            outputs = []
            for i, (data, locale, cwd) in enumerate(((snap, "C", tmp), (shuffled, "C.UTF-8", Path("/")))):
                (tmp / f"s{i}.json").write_text(json.dumps(data))
                env = {**os.environ, "LC_ALL": locale, "PYTHONDONTWRITEBYTECODE": "1"}
                r = subprocess.run([sys.executable, "-B", str(SCRIPT), "shortlist", "--snapshot", str(tmp / f"s{i}.json"),
                                    "--out", str(tmp / f"c{i}.json")], cwd=cwd, env=env, capture_output=True, text=True)
                self.assertEqual(0, r.returncode, r.stderr)
                outputs.append((tmp / f"c{i}.json").read_bytes())
            self.assertEqual(outputs[0], outputs[1])

    def test_existing_output_is_not_overwritten(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "s.json").write_text(json.dumps(synthetic("snapshot")))
            (tmp / "c.json").write_text("keep")
            r = subprocess.run([sys.executable, "-B", str(SCRIPT), "shortlist", "--snapshot", str(tmp / "s.json"),
                                "--out", str(tmp / "c.json")], capture_output=True, text=True)
            self.assertEqual(2, r.returncode)
            self.assertEqual("keep", (tmp / "c.json").read_text())


if __name__ == "__main__":
    unittest.main()
