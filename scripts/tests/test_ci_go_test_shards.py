"""Fast evidence validation tests; no Go installation required."""
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "ci-go-test-shards.py"
spec = importlib.util.spec_from_file_location("go_shards", SCRIPT)
shards = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shards)


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.events = [
            {"Action": "start", "Package": "example/spec"},
            {"Action": "run", "Package": "example/spec", "Test": "TestA"},
            {"Action": "pass", "Package": "example/spec", "Test": "TestA", "Elapsed": 1.25},
            {"Action": "run", "Package": "example/spec", "Test": "TestSkip"},
            {"Action": "output", "Package": "example/spec", "Test": "TestSkip", "Output": "requires isolated topology"},
            {"Action": "skip", "Package": "example/spec", "Test": "TestSkip", "Elapsed": 0},
            {"Action": "pass", "Package": "example/spec", "Elapsed": 1.3},
        ]

    def stream(self, events=None):
        path = self.root / "events.jsonl"
        path.write_text("".join(json.dumps(e) + "\n" for e in (self.events if events is None else events)))
        return path

    def report(self):
        return {"schema_version": 1, "mode": "baseline", "group": "spec", "exit_code": 0,
                "success": True, "wall_seconds": 1.4,
                "identity": {"revision": "a" * 40, "tree": "b" * 40, "dirty": False},
                **shards.events_report(self.stream())}

    def test_skips_and_subtests(self):
        events = self.events[:2] + [
            {"Action": "run", "Package": "example/spec", "Test": "TestA/child"},
            {"Action": "pass", "Package": "example/spec", "Test": "TestA/child", "Elapsed": 0.1},
        ] + self.events[2:]
        report = shards.events_report(self.stream(events))
        self.assertEqual(len(report["tests"]), 3)
        self.assertEqual(report["tests"][-1]["skip_reason"], "requires isolated topology")

    def test_no_test_files(self):
        report = shards.events_report(self.stream([
            {"Action": "start", "Package": "example/cmd"},
            {"Action": "skip", "Package": "example/cmd"},
        ]))
        self.assertEqual(report["tests"], [])

    def test_bad_lifecycles_are_rejected(self):
        bad = [[], self.events[:-1], self.events[:2] + self.events[1:],
               self.events[:2] + self.events[3:], self.events + [self.events[-1]],
               [{**e, "Action": "fail"} if e.get("Test") == "TestA" and e["Action"] == "pass" else e for e in self.events],
               [{**e, "Elapsed": -1} if e["Action"] == "pass" else e for e in self.events],
               [{**e, "Action": "typo"} if e["Action"] == "start" else e for e in self.events]]
        for events in bad:
            with self.subTest(events=events), self.assertRaises(ValueError):
                shards.events_report(self.stream(events))

    def test_broken_json(self):
        for text in ('{}', '{"Action":"start","Action":"skip"}\n', 'null\n', '{"x":NaN}\n'):
            with self.subTest(text=text), self.assertRaises(ValueError):
                path = self.stream()
                path.write_text(text)
                shards.events_report(path)

    def test_verification_rechecks_stream(self):
        path = self.root / "report.json"
        report = self.report()
        shards.write_json(path, report)
        self.assertEqual(shards.verified_reports([path]), [report])
        report["tests"][0]["elapsed_seconds"] = 0
        shards.write_json(path, report)
        with self.assertRaisesRegex(ValueError, "actual events"):
            shards.verified_reports([path])

    def test_weights_are_measured_and_skip_is_nonzero(self):
        report = self.report()
        values = shards.weights([report])["weights"]["example/spec"]
        self.assertEqual(values, {"TestA": 1250, "TestSkip": 1})
        second = copy.deepcopy(report)
        second["tests"][0]["elapsed_seconds"] = 2.75
        self.assertEqual(shards.weights([report, second])["weights"]["example/spec"]["TestA"], 2000)
        report["identity"]["dirty"] = True
        with self.assertRaisesRegex(ValueError, "clean"):
            shards.weights([report])

    def test_summary_counts_top_level_only(self):
        report = self.report()
        summary = shards.summarize([report])["samples"][0]
        self.assertEqual(summary["top_level_count"], 2)
        self.assertEqual(summary["skips"][0]["name"], "TestSkip")

    def test_failed_child_is_not_hidden_by_report_error(self):
        directory = self.root / "failed"
        with patch.object(shards, "identity", return_value={}), \
                patch.object(shards.subprocess, "run") as run:
            run.return_value.returncode = 7
            code = shards.record(["go", "test", "-race", "-count=1", "-json"], directory, "spec")
        self.assertEqual(code, 7)
        report = shards.read_json(directory / "report.json")
        self.assertFalse(report["success"])
        self.assertEqual(report["exit_code"], 7)

    def test_successful_child_with_missing_events_is_rejected(self):
        with patch.object(shards, "identity", return_value={}), \
                patch.object(shards.subprocess, "run") as run:
            run.return_value.returncode = 0
            code = shards.record(["go", "test", "-race", "-count=1", "-json"], self.root / "empty", "spec")
        self.assertEqual(code, 2)

    def test_baseline_cannot_be_filtered_or_lose_race(self):
        for extra in (["-run=TestA"], ["-skip", "TestA"], ["-short"], ["-list=."]):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                shards.record(["go", "test", "-race", "-count=1", "-json", *extra], self.root / "invalid", "spec")
        with patch.dict(shards.os.environ, GOFLAGS="-skip=TestA"), self.assertRaises(ValueError):
            shards.record(["go", "test", "-race", "-count=1", "-json"], self.root / "invalid", "spec")
        with self.assertRaises(ValueError):
            shards.record(["go", "test", "-count=1", "-json"], self.root / "invalid", "spec")


if __name__ == "__main__":
    unittest.main()
