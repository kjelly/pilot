"""validate: agent-written proposals checked against the snapshot (B06v, B07v, B08, B14v).
Every rejected case has the valid synthetic proposals as its passing counterpart."""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from planner_fixtures import BASE_SHA, BASE_TREE, planner, snapshot_bytes, synthetic


class ValidateTest(unittest.TestCase):
    def setUp(self):
        self.snapshot = synthetic("snapshot")
        self.digest = planner.sha256_bytes(snapshot_bytes(self.snapshot))
        self.proposals = synthetic("proposals")
        self.proposals["snapshot_sha256"] = self.digest

    def problems(self, mutate=None, *, snapshot_mutate=None):
        props = json.loads(json.dumps(self.proposals))
        snap = json.loads(json.dumps(self.snapshot))
        if snapshot_mutate:
            snapshot_mutate(snap)
        if mutate:
            mutate(props)
        return planner.proposals_problems(snap, self.digest, props, set(BASE_TREE))

    def rejected(self, mutate, needle, **kw):
        problems = self.problems(mutate, **kw)
        self.assertTrue(any(needle in p for p in problems), problems)

    def test_valid_proposals_pass(self):
        self.assertEqual([], self.problems())

    def test_b08_binding_to_the_snapshot(self):
        self.rejected(lambda p: p.update(snapshot_sha256="1" * 64), "snapshot_sha256 does not match")
        self.rejected(lambda p: p.update(base_sha="b" * 40), "base_sha does not match")

    def test_b08_unknown_issue(self):
        self.rejected(lambda p: p["batches"][0]["issue_numbers"].append(99), "#99 is not an open Issue")

    def test_b08_batch_size(self):
        def one(p):
            b = p["batches"][0]
            b["issue_numbers"] = [11]
        self.rejected(one, "a batch has 2 to 4 Issues")

        def five(p):
            p["batches"][0]["issue_numbers"] = [11, 12, 13, 17, 15]
        self.rejected(five, "a batch has 2 to 4 Issues")

    def test_b08_primary_must_be_a_member(self):
        self.rejected(lambda p: p["batches"][0].update(primary_issue=17), "primary_issue must be one of")

    def test_b08_evidence(self):
        self.rejected(lambda p: p["batches"][0].update(evidence=[]), "evidence is empty")
        self.rejected(lambda p: p["batches"][0]["evidence"][1].update(path="playbooks/apply/missing.yml"),
                      "not a file in the base tree")
        self.rejected(lambda p: p["batches"][0]["evidence"][1].update(ref_sha="c" * 40), "at the base SHA")
        self.rejected(lambda p: p["batches"][0]["evidence"][0].update(url=None), "needs a url")

    def test_b08_acceptance_per_issue(self):
        self.rejected(lambda p: p["batches"][0]["acceptance_by_issue"].pop(), "acceptance_by_issue must cover")

    def test_b08_human_approval_and_class(self):
        self.rejected(lambda p: p["batches"][0].update(human_approval_required=False), "human_approval_required")
        self.rejected(lambda p: p["batches"][0].update(root_cause_class="Error Swallowed"), "kebab-case")

    def test_b06v_every_pair_needs_compatibility(self):
        self.rejected(lambda p: p["batches"][0]["pair_compatibility"].pop(), "lacks #12 and #13")

    def test_b07v_blocked_issues_never_join_a_batch(self):
        for n, status in ((14, "EXISTING_PR"), (15, "BLOCKED_BY"), (16, "NEEDS_DECISION")):
            def add(p, n=n):
                p["issue_statuses"] = [s for s in p["issue_statuses"] if s["number"] != n]
                b = p["batches"][0]
                b["issue_numbers"].append(n)
                b["acceptance_by_issue"].append({"issue": n, "coverage": "undecided", "validation": "n/a here"})
                b["pair_compatibility"] += [{"issues": [m, n], "evidence": "added"} for m in (11, 12, 13)]
            with self.subTest(status=status):
                self.rejected(add, f"#{n} is {status}")

    def test_b07v_overlapping_open_pr_must_be_listed(self):
        def add17(p, prs=()):
            p["issue_statuses"] = [s for s in p["issue_statuses"] if s["number"] != 17]
            b = p["batches"][0]
            b["issue_numbers"].append(17)
            b["acceptance_by_issue"].append({"issue": 17, "coverage": "undecided", "validation": "y.go path"})
            b["pair_compatibility"] += [{"issues": [m, 17], "evidence": "same helper"} for m in (11, 12, 13)]
            b["existing_prs"] = list(prs)
        self.rejected(add17, "overlaps open PR(s) [91]")
        self.assertEqual([], self.problems(lambda p: add17(p, prs=[91])))

    def test_b07v_hard_status_is_reported_as_it_is(self):
        self.rejected(lambda p: p["issue_statuses"][0].update(status="UNASSIGNED"), "#14 is EXISTING_PR")

    def test_umbrella_and_likely_resolved_are_hard_statuses(self):
        snap = synthetic("snapshot")
        snap["issues"][6]["sub_issue_count"] = 1
        snap["issues"][5]["labels"] = ["likely-resolved"]
        facts = planner.issue_facts(snap)
        self.assertEqual("UNASSIGNED", facts[17]["status"])
        self.assertEqual("ALREADY_RESOLVED_REVIEW", facts[16]["status"])
        self.assertIsNone(facts[11]["status"])
        self.digest = planner.sha256_bytes(snapshot_bytes(snap))
        self.proposals["snapshot_sha256"] = self.digest
        self.snapshot = snap
        relabel = lambda p: p["issue_statuses"][2].update(status="ALREADY_RESOLVED_REVIEW")  # noqa: E731
        self.assertEqual([], self.problems(relabel))
        self.rejected(lambda p: (relabel(p), p["issue_statuses"][3].update(status="INSUFFICIENT_EVIDENCE")),
                      "#17 is UNASSIGNED")
        self.rejected(None, "#16 is ALREADY_RESOLVED_REVIEW")

    def test_b14v_every_issue_exactly_once(self):
        self.rejected(lambda p: p["issue_statuses"].pop(), "#17 appears 0 times")
        self.rejected(lambda p: p["issue_statuses"].append(
            {"number": 11, "status": "UNASSIGNED", "reason": "listed twice"}), "#11 appears 2 times")

    def test_issue_in_two_merge_candidates(self):
        def twice(p):
            b = json.loads(json.dumps(p["batches"][0]))
            b["issue_numbers"] = [11, 12]
            b["pair_compatibility"] = [{"issues": [11, 12], "evidence": "again"}]
            b["acceptance_by_issue"] = b["acceptance_by_issue"][:2]
            p["batches"].append(b)
        self.rejected(twice, "#11 is in 2 MERGE_CANDIDATE batches")

    def test_incomplete_snapshot_cannot_be_reviewed(self):
        self.rejected(None, "snapshot is incomplete",
                      snapshot_mutate=lambda s: s["sources"]["issues"].update(complete=False))
        self.rejected(None, "snapshot is incomplete",
                      snapshot_mutate=lambda s: s["issues"][0].update(comments_complete=False))


class ValidateCliTest(unittest.TestCase):
    def test_cli_valid_and_invalid(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            snap = synthetic("snapshot")
            (tmp / "s.json").write_bytes(snapshot_bytes(snap))
            props = synthetic("proposals")
            props["snapshot_sha256"] = planner.sha256_bytes(snapshot_bytes(snap))
            for mutate, code, status in ((lambda p: None, 0, "VALID"),
                                         (lambda p: p.update(base_sha="b" * 40), 2, "INVALID")):
                mutate(props)
                (tmp / "p.json").write_text(json.dumps(props))
                out = io.StringIO()
                with patch.object(planner, "base_tree_paths", return_value=set(BASE_TREE)) as tree, \
                     redirect_stdout(out):
                    self.assertEqual(code, planner.main(["validate", "--snapshot", str(tmp / "s.json"),
                                                         "--proposals", str(tmp / "p.json"), "--repo-dir", "."]))
                self.assertEqual(status, json.loads(out.getvalue())["status"])
                self.assertEqual(BASE_SHA, tree.call_args.args[1])


if __name__ == "__main__":
    unittest.main()
