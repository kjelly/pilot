"""Fast evidence validation tests; no Go installation required."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import shutil
import subprocess
import sys
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


class PartitionTests(unittest.TestCase):
    def test_lpt_complete_deterministic_and_new_tests(self):
        names = ["TestA", "TestB", "TestC", "ExampleAnswer", "FuzzTiny"]
        measured = {"TestA": 10000, "TestB": 9000, "TestC": 8000, "OldTest": 1}
        plan = shards.partition(names, 2, measured)
        self.assertEqual(plan, shards.partition(list(reversed(names)), 2, measured))
        self.assertEqual(plan["unknown"], ["ExampleAnswer", "FuzzTiny"])
        self.assertEqual(plan["obsolete_weights"], ["OldTest"])
        flat = sum(plan["shards"], [])
        self.assertEqual(sorted(flat), sorted(names))
        self.assertEqual(len(flat), len(set(flat)))
        self.assertEqual(plan["shards"][0], ["ExampleAnswer", "FuzzTiny", "TestA"])
        newer = shards.partition([*names, "TestNew"], 2, measured)
        self.assertIn("TestNew", sum(newer["shards"], []))
        regex = shards.selector(["TestA", "TestAB", "ExampleAnswer", "FuzzTiny"])
        self.assertTrue(shards.re.fullmatch(regex, "TestAB"))
        self.assertIsNone(shards.re.fullmatch(regex, "TestABC"))

    def test_bad_partitions_fail(self):
        for names, count, measured in [([], 1, {}), (["TestA"], 2, {}), (["TestA", "TestA"], 1, {}),
                                       (["TestA"], 0, {}), (["TestMain"], 1, {}), (["TestA/child"], 1, {}),
                                       (["TestA"], 1, {"TestA": 0}), (["TestA"], 1, {"TestA": True}),
                                       (["TestA"], 1, {"TestA": float("nan")})]:
            with self.subTest(names=names, count=count), self.assertRaises(ValueError):
                shards.partition(names, count, measured)

    def test_config_and_generated_matrix_have_one_source(self):
        cfg = shards.load_config()
        entries = shards.matrix(cfg)["include"]
        self.assertEqual(len(entries), sum(g["shards"] for g in cfg["groups"].values()))
        self.assertEqual(len({e["shard"] for e in entries}), len(entries))
        self.assertEqual([e["index"] for e in entries if e["group"] == "spec"], list(range(cfg["groups"]["spec"]["shards"])))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            for group, key, value in [("rest", "shards", 2), ("spec", "shards", True),
                                      ("cmd", "package", "example/wrong")]:
                bad = copy.deepcopy(cfg)
                bad["groups"][group][key] = value
                shards.write_json(path, bad)
                with self.assertRaises(ValueError):
                    shards.load_config(path)


class RunGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        self.config = self.root / "config.json"
        configuration = shards.load_config()
        for group in ("spec", "cmd"):
            configuration["groups"][group]["shards"] = 2
        shards.write_json(self.config, configuration)
        self.weights = self.root / "weights.json"
        self.measured = {shards.PACKAGES["spec"]: {"TestA": 20, "TestB": 10},
                         shards.PACKAGES["cmd"]: {"TestC": 20, "TestD": 10}}
        self.identity = {"revision": "a" * 40, "tree": "b" * 40, "dirty": False, "run_id": "7", "run_attempt": "1",
                         "go_version": "go-test", "platform": "fixture"}
        shards.write_json(self.weights, {"schema_version": 1, "unit": "milliseconds", "sources": [self.identity], "weights": self.measured})
        self.inventory = {"spec": [shards.PACKAGES["spec"]], "cmd": [shards.PACKAGES["cmd"]],
                          "rest": ["example/other"]}
        self.inventory_patch = patch.object(shards, "package_inventory", return_value=self.inventory)
        self.inventory_patch.start()
        self.addCleanup(self.inventory_patch.stop)
        self.entries = shards.matrix(shards.load_config(self.config))["include"]
        for entry in self.entries:
            group = entry["group"]
            directory = self.artifacts / entry["shard"]
            directory.mkdir()
            package = self.inventory[group][0]
            manifest = {"schema_version": 1, "group": group, "packages": [package],
                        "config_hash": shards.file_hash(self.config),
                        "weights_hash": shards.file_hash(self.weights) if group != "rest" else None}
            if group == "rest":
                manifest["shards"] = [None]
                names = []
            else:
                manifest.update(shards.partition(list(self.measured[package]), 2, self.measured[package]))
                names = manifest["shards"][entry["index"]]
                listed = [{"Action": "start", "Package": package}]
                listed += [{"Action": "output", "Package": package, "Output": name + "\n"} for name in manifest["discovered"]]
                listed += [{"Action": "pass", "Package": package, "Elapsed": 0}]
                self.stream(directory / "discovery.jsonl", listed)
            events = [{"Action": "start", "Package": package}]
            for name in names:
                events += [{"Action": "run", "Package": package, "Test": name},
                           {"Action": "pass", "Package": package, "Test": name, "Elapsed": 0.01}]
            events += [{"Action": "pass", "Package": package, "Elapsed": 0.1}]
            self.stream(directory / "events.jsonl", events)
            shards.write_json(directory / "manifest.json", manifest)
            shards.write_json(directory / "report.json", {"schema_version": 1, "mode": "shard", "group": group,
                "shard": entry, "identity": self.identity, "exit_code": 0, "success": True, "wall_seconds": 0.2,
                "manifest_digest": shards.digest(manifest), **shards.events_report(directory / "events.jsonl")})

    def stream(self, path, events):
        path.write_text("".join(json.dumps(e) + "\n" for e in events))

    def verify(self):
        return shards.verify_run(self.artifacts, self.config, self.weights, self.identity)

    def mutate(self, filename, change):
        path = self.artifacts / self.entries[0]["shard"] / filename
        value = shards.read_json(path)
        change(value)
        shards.write_json(path, value)

    def test_all_actual_streams_verify(self):
        self.assertEqual(len(self.verify()["samples"]), 5)

    def test_missing_extra_and_failed_artifact(self):
        shutil.rmtree(self.artifacts / "rest")
        with self.assertRaisesRegex(ValueError, "directory set"):
            self.verify()

    def test_extra_artifact(self):
        (self.artifacts / "unexpected").mkdir()
        with self.assertRaisesRegex(ValueError, "directory set"):
            self.verify()

    def test_github_artifact_prefix(self):
        for entry in self.entries:
            source = self.artifacts / entry["shard"]
            source.rename(self.artifacts / ("go-shard-1-" + entry["shard"]))
        self.assertEqual(len(shards.verify_run(self.artifacts, self.config, self.weights, self.identity, "go-shard-1-")["samples"]), 5)

    def test_new_attempt_cannot_reuse_old_artifacts(self):
        with self.assertRaisesRegex(ValueError, "directory set"):
            shards.verify_run(self.artifacts, self.config, self.weights, self.identity, "go-shard-2-")

    def test_incomplete_weights_source(self):
        value = shards.read_json(self.weights)
        value["sources"][0].pop("tree")
        shards.write_json(self.weights, value)
        with self.assertRaisesRegex(ValueError, "candidate"):
            shards.load_weights(self.weights)

    def test_run_attempt_mixing(self):
        self.mutate("report.json", lambda r: r["identity"].update(run_attempt="2"))
        with self.assertRaisesRegex(ValueError, "identity"):
            self.verify()

    def test_failure_cannot_be_labeled_success(self):
        self.mutate("report.json", lambda r: r.update(exit_code=1))
        with self.assertRaisesRegex(ValueError, "unsuccessful"):
            self.verify()

    def test_selector_mismatch(self):
        self.mutate("manifest.json", lambda m: m["shards"][0].append("TestMissing"))
        path = self.artifacts / self.entries[0]["shard"]
        report = shards.read_json(path / "report.json")
        report["manifest_digest"] = shards.digest(shards.read_json(path / "manifest.json"))
        shards.write_json(path / "report.json", report)
        with self.assertRaisesRegex(ValueError, "selected shard"):
            self.verify()

    def test_discovery_is_independently_rechecked(self):
        path = self.artifacts / self.entries[0]["shard"] / "discovery.jsonl"
        path.write_text(path.read_text().replace("TestB", "TestOther"))
        with self.assertRaisesRegex(ValueError, "actual discovery"):
            self.verify()

    def test_new_module_package_cannot_be_omitted(self):
        self.inventory["rest"].append("example/new")
        with self.assertRaisesRegex(ValueError, "module inventory"):
            self.verify()

    def test_weights_cannot_drift(self):
        value = shards.read_json(self.weights)
        value["weights"][shards.PACKAGES["spec"]]["TestA"] = 1000
        shards.write_json(self.weights, value)
        with self.assertRaisesRegex(ValueError, "weights"):
            self.verify()

    def controls(self):
        paths = []
        for group in ("spec", "cmd"):
            directory = self.root / ("control-" + group)
            directory.mkdir()
            package = shards.PACKAGES[group]
            events = [{"Action": "start", "Package": package}]
            for name in sorted(self.measured[package]):
                events.extend([{"Action": "run", "Package": package, "Test": name},
                               {"Action": "pass", "Package": package, "Test": name, "Elapsed": 0.1}])
            events.append({"Action": "pass", "Package": package, "Elapsed": 0.3})
            self.stream(directory / "events.jsonl", events)
            path = directory / "report.json"
            shards.write_json(path, {"schema_version": 1, "mode": "baseline", "group": group,
                "identity": self.identity, "exit_code": 0, "success": True, "wall_seconds": 0.4,
                **shards.events_report(directory / "events.jsonl")})
            paths.append(path)
        return paths

    def test_same_candidate_full_comparison(self):
        result = shards.compare(self.artifacts, self.controls(), self.config, self.weights, self.identity)
        self.assertEqual({row["group"] for row in result["comparisons"]}, {"cmd", "spec"})
        self.assertEqual(result["comparisons"][0]["speedup"], 2)

    def test_comparison_rejects_old_candidate(self):
        paths = self.controls()
        value = shards.read_json(paths[0])
        value["identity"]["tree"] = "c" * 40
        shards.write_json(paths[0], value)
        with self.assertRaisesRegex(ValueError, "another candidate"):
            shards.compare(self.artifacts, paths, self.config, self.weights, self.identity)

    def test_comparison_rejects_missing_test_even_with_matching_summary(self):
        paths = self.controls()
        stream = paths[0].parent / "events.jsonl"
        events = [json.loads(line) for line in stream.read_text().splitlines()]
        events = [event for event in events if event.get("Test") != "TestB"]
        self.stream(stream, events)
        value = shards.read_json(paths[0])
        value.update(shards.events_report(stream))
        shards.write_json(paths[0], value)
        with self.assertRaisesRegex(ValueError, "verdict or skip mismatch"):
            shards.compare(self.artifacts, paths, self.config, self.weights, self.identity)


class MakeSelectorTests(unittest.TestCase):
    def test_selector_is_literal_and_empty_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            stub = root / "go"
            stub.write_text(f"#!{sys.executable}\nimport os,sys,json\nopen(os.environ['ARGUMENTS'], 'w').write(json.dumps(sys.argv[1:]))\n")
            stub.chmod(0o700)
            env = {k: v for k, v in os.environ.items() if k not in {
                "GO_TEST_RUN_REGEX", "CI_SHARD_INDEX", "MAKEFLAGS", "MFLAGS", "GO_TEST_REPORT_DIR", "GO_TEST_JSON"}}
            env.update(PATH=str(root) + os.pathsep + env["PATH"], ARGUMENTS=str(root / "args"))
            for regex in (None, "^(TestA|TestAB)$", ""):
                with self.subTest(regex=regex):
                    (root / "args").unlink(missing_ok=True)
                    test_env = {**env, **({"GO_TEST_RUN_REGEX": regex} if regex is not None else {})}
                    done = subprocess.run(["make", "--no-print-directory", "test-race", "GO_TEST_PACKAGES=./internal/spec"],
                                          cwd=shards.ROOT, env=test_env, capture_output=True, text=True)
                    if regex == "":
                        self.assertNotEqual(done.returncode, 0)
                        self.assertFalse((root / "args").exists())
                    else:
                        self.assertEqual(done.returncode, 0, done.stderr)
                        args = json.loads((root / "args").read_text())
                        self.assertEqual(args[:5], ["test", "-race", "-count=1", "-timeout", "45m"])
                        self.assertEqual(args[-1], "-run=" + regex if regex else "./internal/spec")


class TimingTests(unittest.TestCase):
    def setUp(self):
        self.run = {"id": 7, "run_attempt": 1, "status": "completed", "event": "pull_request", "conclusion": "success",
                    "created_at": "2026-11-02T00:00:00Z", "updated_at": "2026-11-02T00:10:00Z"}
        self.job = {"id": 10, "run_id": 7, "name": "Go test (spec)", "status": "completed", "conclusion": "success",
                    "created_at": "2026-11-02T00:00:01Z", "started_at": "2026-11-02T00:00:05Z",
                    "completed_at": "2026-11-02T00:08:05Z", "steps": [
                        {"name": "go build", "started_at": "2026-11-02T00:00:20Z", "completed_at": "2026-11-02T00:00:30Z"},
                        {"name": "go test", "started_at": "2026-11-02T00:01:05Z", "completed_at": "2026-11-02T00:08:00Z"}]}

    def test_distinguishes_job_and_step_clocks(self):
        result = shards.job_timings({"jobs": [self.job]}, self.run)
        row = result["jobs"][0]
        self.assertEqual(row["queue_seconds"], 4)
        self.assertEqual(row["before_test_seconds"], 60)
        self.assertEqual(row["build_step_seconds"], 10)
        self.assertEqual(row["test_step_seconds"], 415)
        self.assertEqual(row["after_test_seconds"], 5)
        self.assertEqual(result["workflow_wall_seconds"], 600)
        self.assertEqual(result["known_runner_minutes"], 8)
        self.assertTrue(result["runner_cost_complete"])

    def test_missing_is_not_zero_and_failure_remains_visible(self):
        self.job.update(created_at=None, status="in_progress", completed_at=None, conclusion=None)
        self.run.update(status="in_progress", conclusion=None)
        result = shards.job_timings({"jobs": [self.job]}, self.run)
        self.assertIsNone(result["jobs"][0]["queue_seconds"])
        self.assertIsNone(result["workflow_wall_seconds"])
        self.assertFalse(result["runner_cost_complete"])
        self.assertEqual(result["missing_execution_durations"], [10])
        self.job.update(status="completed", conclusion="failure", completed_at="2026-11-02T00:08:05Z")
        self.assertEqual(shards.job_timings({"jobs": [self.job]}, self.run)["jobs"][0]["conclusion"], "failure")

    def test_invalid_intervals_duplicate_jobs_and_run_mixing(self):
        for jobs in ([self.job, self.job], [{**self.job, "run_id": 8}],
                     [{**self.job, "completed_at": "2025-01-01T00:00:00Z"}], []):
            with self.subTest(jobs=jobs), self.assertRaises(ValueError):
                shards.job_timings({"jobs": jobs}, self.run)
        with self.assertRaisesRegex(ValueError, "pagination"):
            shards.job_timings({"total_count": 2, "jobs": [self.job]}, self.run)

    def test_unallocated_skipped_job_is_not_a_negative_or_zero_duration(self):
        self.job.update(conclusion="skipped", completed_at="2026-11-02T00:00:04Z", steps=[])
        result = shards.job_timings({"jobs": [self.job]}, self.run)
        self.assertIsNone(result["jobs"][0]["execution_seconds"])
        self.assertIsNone(result["jobs"][0]["queue_seconds"])
        self.assertTrue(result["runner_cost_complete"])


if __name__ == "__main__":
    unittest.main()
