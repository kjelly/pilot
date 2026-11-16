"""snapshot.json and proposals.json shapes (S1): malformed input exits 2, never half-read."""
from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from planner_fixtures import BASE_TREE, planner, snapshot_bytes, synthetic


class SnapshotShapeTest(unittest.TestCase):
    def test_synthetic_snapshot_is_valid(self):
        self.assertEqual([], planner.snapshot_problems(synthetic("snapshot")))

    def check(self, mutate, needle):
        snap = synthetic("snapshot")
        mutate(snap)
        problems = planner.snapshot_problems(snap)
        self.assertTrue(any(needle in p for p in problems), problems)

    def test_unknown_field(self):
        self.check(lambda s: s["issues"][0].update(body="raw text"), "issues[0].body: unknown field")

    def test_missing_sha(self):
        self.check(lambda s: s["base"].pop("sha"), "snapshot.base.sha: missing")

    def test_short_or_uppercase_sha(self):
        self.check(lambda s: s["base"].update(sha="A" * 40), "40-hex")
        self.check(lambda s: s["base"].update(sha="abc"), "40-hex")

    def test_wrong_types(self):
        self.check(lambda s: s["issues"][0].update(number="11"), "positive integer")
        self.check(lambda s: s["issues"][0].update(number=True), "positive integer")
        self.check(lambda s: s["issues"][0].update(labels="bug"), "expected a list")
        self.check(lambda s: s["issues"][0]["blocked_by"].append(
            {"number": 1, "state": "open", "url": "https://github.com/OWNER/REPO/issues/1"}), "one of OPEN")

    def test_duplicates_and_counts(self):
        self.check(lambda s: s["issues"].append(dict(s["issues"][0])) or s["sources"]["issues"].update(count=8),
                   "duplicate numbers")
        self.check(lambda s: s["sources"]["issues"].update(count=99), "does not match")

    def test_schema_version(self):
        self.check(lambda s: s.update(schema_version=2), "schema_version 1")


class LoaderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def write(self, name, data: bytes) -> Path:
        path = self.dir / name
        path.write_bytes(data)
        return path

    def test_load_returns_digest_of_the_bytes(self):
        data = snapshot_bytes(synthetic("snapshot"))
        snap, digest = planner.load_snapshot(self.write("s.json", data))
        self.assertEqual(planner.sha256_bytes(data), digest)
        self.assertEqual(7, len(snap["issues"]))

    def test_malformed_json_is_refused(self):
        with self.assertRaises(planner.PlannerError):
            planner.load_snapshot(self.write("s.json", b"{not json"))

    def test_invalid_snapshot_is_refused(self):
        snap = synthetic("snapshot")
        snap["issues"][0]["title"] = None
        with self.assertRaises(planner.PlannerError):
            planner.load_snapshot(self.write("s.json", snapshot_bytes(snap)))

    def test_validate_cli_exits_2_on_malformed_proposals(self):
        snap = self.write("s.json", snapshot_bytes(synthetic("snapshot")))
        prop = self.write("p.json", b"[]")
        out, err = io.StringIO(), io.StringIO()
        with patch.object(planner, "base_tree_paths", return_value=set(BASE_TREE)), \
             redirect_stdout(out), redirect_stderr(err):
            code = planner.main(["validate", "--snapshot", str(snap), "--proposals", str(prop), "--repo-dir", "."])
        self.assertEqual(2, code)
        self.assertEqual("INVALID", json.loads(out.getvalue())["status"])

    def test_unimplemented_subcommands_exit_2(self):
        for name in ("render", "diff"):
            with self.subTest(name=name), redirect_stderr(io.StringIO()):
                self.assertEqual(2, planner.main([name]))


if __name__ == "__main__":
    unittest.main()
