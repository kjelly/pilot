"""diff: comparing two reports (B11, B11n)."""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from planner_fixtures import planner, synthetic


def report(snapshot, proposals):
    return planner.build_report(snapshot, planner.shortlist(snapshot), proposals)


class DiffTest(unittest.TestCase):
    def setUp(self):
        self.old_snap, self.old_props = synthetic("snapshot"), synthetic("proposals")
        self.previous = report(self.old_snap, self.old_props)

    def current(self):
        snap, props = synthetic("snapshot"), synthetic("proposals")
        # #17 was closed; #13 is now closed by an open PR; the batch shrinks to #11 and #12.
        snap["issues"] = [i for i in snap["issues"] if i["number"] != 17]
        snap["sources"]["issues"]["count"] -= 1
        snap["issues"][2]["closed_by_prs"] = [{"number": 92, "state": "OPEN", "url": "https://github.com/OWNER/REPO/pull/92"}]
        b = props["batches"][0]
        b["issue_numbers"] = [11, 12]
        b["pair_compatibility"] = b["pair_compatibility"][:1]
        b["acceptance_by_issue"] = b["acceptance_by_issue"][:2]
        props["issue_statuses"] = [s for s in props["issue_statuses"] if s["number"] != 17]
        props["issue_statuses"].append({"number": 13, "status": "EXISTING_PR", "reason": "open PR #92 closes it"})
        return report(snap, props)

    def test_b11_changes_between_reports(self):
        diff = planner.diff_reports(self.previous, self.current())
        old_id = planner.batch_id("error-swallowed", [11, 12, 13])
        new_id = planner.batch_id("error-swallowed", [11, 12])
        self.assertEqual("COMPARED", diff["status"])
        self.assertEqual([{"batch_id": new_id, "issue_numbers": [11, 12], "supersedes": old_id}], diff["new_batches"])
        self.assertEqual([{"batch_id": old_id, "issue_numbers": [11, 12, 13]}], diff["retired_batches"])
        self.assertEqual([13], diff["newly_blocked"])
        self.assertEqual([17], diff["issues_closed"])
        self.assertEqual([], diff["changed_classification"])

    def test_changed_classification_keeps_the_batch_id(self):
        props = synthetic("proposals")
        props["batches"][0]["classification"] = "RELATED_SEPARATE"
        diff = planner.diff_reports(self.previous, report(synthetic("snapshot"), props))
        self.assertEqual([{"batch_id": planner.batch_id("error-swallowed", [11, 12, 13]),
                           "from": "MERGE_CANDIDATE", "to": "RELATED_SEPARATE"}], diff["changed_classification"])
        self.assertEqual([], diff["new_batches"])

    def test_identical_reports_have_no_changes(self):
        diff = planner.diff_reports(self.previous, report(synthetic("snapshot"), synthetic("proposals")))
        for key in ("new_batches", "retired_batches", "changed_classification", "newly_blocked", "issues_closed"):
            self.assertEqual([], diff[key], key)

    def test_b11n_no_baseline(self):
        current = self.current()
        incomplete = json.loads(json.dumps(self.previous))
        incomplete["status"] = "INCOMPLETE"
        altered = json.loads(json.dumps(self.previous))
        altered["issues"].pop()
        for previous in (None, incomplete, altered, {"schema_version": 1}):
            with self.subTest(previous=str(previous)[:40]):
                self.assertEqual("NO_BASELINE", planner.diff_reports(previous, current)["status"])

    def test_current_must_be_usable(self):
        broken = json.loads(json.dumps(self.previous))
        broken["status"] = "BLOCKED"
        with self.assertRaises(planner.PlannerError):
            planner.diff_reports(self.previous, broken)

    def test_cli_missing_previous_is_no_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "cur.json").write_text(planner.dumps(self.current()))
            with redirect_stdout(io.StringIO()):
                code = planner.main(["diff", "--previous", str(tmp / "missing.json"), "--current", str(tmp / "cur.json"),
                                     "--out", str(tmp / "diff.json")])
            self.assertEqual(0, code)
            self.assertEqual("NO_BASELINE", json.loads((tmp / "diff.json").read_text())["status"])


if __name__ == "__main__":
    unittest.main()
