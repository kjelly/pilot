"""Exercise evidence capture against a real Go race binary in a small module."""
import importlib.util
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "ci-go-test-shards.py"
spec = importlib.util.spec_from_file_location("go_shards_runtime", SCRIPT)
shards = importlib.util.module_from_spec(spec)
spec.loader.exec_module(shards)


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        if not shutil.which("go"):
            self.fail("Go is required for CI evidence runtime tests")
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.old = Path.cwd()
        os.chdir(self.root)
        self.addCleanup(os.chdir, self.old)
        (self.root / "go.mod").write_text("module github.com/kjelly/pilot\n\ngo 1.25\n")
        (self.root / "fixture.go").write_text("package fixture\n")
        specdir = self.root / "internal/spec"
        specdir.mkdir(parents=True)
        cmddir = self.root / "cmd/pilot/cmd"
        cmddir.mkdir(parents=True)
        (cmddir / "fixture_test.go").write_text("package cmd\nimport \"testing\"\nfunc TestOne(t *testing.T) {}\nfunc TestTwo(t *testing.T) {}\n")
        (specdir / "fixture_test.go").write_text('''package fixture
import ("fmt"; "os"; "testing")
func TestPass(t *testing.T) { t.Run("child", func(t *testing.T) {}) }
func TestSkip(t *testing.T) { t.Skip("missing optional topology") }
func TestFailure(t *testing.T) { if os.Getenv("FAIL_FIXTURE") == "1" { t.Fatal("intentional failure") } }
func Answer() int { return 42 }
func ExampleAnswer() { fmt.Println(Answer())
// Output: 42
}
func FuzzTiny(f *testing.F) { f.Add("seed"); f.Fuzz(func(t *testing.T, s string) {}) }
''')
        self.identity = patch.object(shards, "identity", return_value={
            "revision": "a" * 40, "tree": "b" * 40, "dirty": False,
            "run_id": "fixture", "run_attempt": "1", "go_version": "fixture", "platform": "fixture"})
        self.identity.start()
        self.addCleanup(self.identity.stop)

    def test_actual_events_examples_seeds_skips_and_weights(self):
        directory = self.root / "success"
        code = shards.record(self.command("spec"), directory, "spec")
        self.assertEqual(code, 0)
        reports = shards.verified_reports([directory / "report.json"])
        rows = {r["name"]: r for r in reports[0]["tests"]}
        self.assertEqual(rows["TestSkip"]["verdict"], "skip")
        self.assertIn("missing optional topology", rows["TestSkip"]["skip_reason"])
        self.assertIn("ExampleAnswer", rows)
        self.assertIn("FuzzTiny/seed#0", rows)
        values = shards.weights(reports)["weights"][shards.PACKAGES["spec"]]
        self.assertEqual(set(values), {"TestPass", "TestSkip", "TestFailure", "ExampleAnswer", "FuzzTiny"})

    def test_actual_failure_retains_exit_and_evidence(self):
        directory = self.root / "failure"
        with patch.dict(os.environ, FAIL_FIXTURE="1"):
            code = shards.record(self.command("spec"), directory, "spec")
        self.assertEqual(code, 1)
        report = shards.read_json(directory / "report.json")
        self.assertEqual(report["exit_code"], 1)
        self.assertFalse(report["success"])
        with self.assertRaises(ValueError):
            shards.verified_reports([directory / "report.json"])

    def command(self, group):
        package = {"spec": "./internal/spec", "cmd": "./cmd/pilot/cmd", "rest": "."}[group]
        packages = shards.package_inventory()["rest"] if group == "rest" else [package]
        return ["go", "test", "-race", "-count=1", "-timeout", "30s", "-json", *packages]

    def test_real_shards_and_result_gate(self):
        extra = self.root / "internal/newpkg"
        extra.mkdir()
        (extra / "new.go").write_text("package newpkg\n")
        race = self.root / "internal/racepkg"
        race.mkdir()
        (race / "race.go").write_text("//go:build race\n\npackage racepkg\n")
        config = self.root / "config.json"
        configuration = shards.load_config()
        for group in ("spec", "cmd"):
            configuration["groups"][group]["shards"] = 2
        shards.write_json(config, configuration)
        baseline = []
        for group in ("spec", "cmd"):
            target = self.root / ("baseline-" + group)
            self.assertEqual(shards.record(self.command(group), target, group), 0)
            baseline.append(target / "report.json")
        weight_path = self.root / "weights.json"
        shards.write_json(weight_path, shards.weights(shards.verified_reports(baseline)))
        artifacts = self.root / "artifacts"
        artifacts.mkdir()
        names = []
        for entry in shards.matrix(shards.load_config(config))["include"]:
            target = artifacts / entry["shard"]
            self.assertEqual(shards.record(self.command(entry["group"]), target, entry["group"],
                                          entry["index"], config, weight_path), 0)
            report = shards.read_json(target / "report.json")
            if entry["group"] == "spec":
                names.extend(t["name"] for t in report["tests"] if "/" not in t["name"])
            if entry["group"] == "rest":
                self.assertIn("github.com/kjelly/pilot/internal/newpkg", report["packages"])
                self.assertIn("github.com/kjelly/pilot/internal/racepkg", report["packages"])
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(set(names), {"TestPass", "TestSkip", "TestFailure", "ExampleAnswer", "FuzzTiny"})
        self.assertEqual(len(shards.verify_run(artifacts, config, weight_path)["samples"]), 5)
        comparisons = shards.compare(artifacts, baseline, config, weight_path)
        self.assertEqual({r["group"] for r in comparisons["comparisons"]}, {"spec", "cmd"})
        # Corrupting actual observations must fail even when cached summaries remain green.
        path = artifacts / "spec-1-of-2" / "events.jsonl"
        path.write_text(path.read_text().replace('"Action":"pass"', '"Action":"fail"').replace('"Action": "pass"', '"Action": "fail"'))
        with self.assertRaises(ValueError):
            shards.verify_run(artifacts, config, weight_path)

    def test_one_shard_without_weights_and_race_only_test(self):
        (self.root / "internal/spec/race_test.go").write_text(
            "//go:build race\n\npackage fixture\nimport \"testing\"\nfunc TestRaceOnly(t *testing.T) {}\n")
        config = self.root / "config.json"
        value = shards.load_config()
        value["groups"]["spec"]["shards"] = 1
        shards.write_json(config, value)
        target = self.root / "one"
        self.assertEqual(shards.record(self.command("spec"), target, "spec", 0, config, self.root / "absent-weights"), 0)
        manifest = shards.read_json(target / "manifest.json")
        self.assertIn("TestRaceOnly", manifest["discovered"])
        self.assertIsNone(manifest["weights_hash"])
        report = shards.read_json(target / "report.json")
        self.assertFalse(any(arg.startswith("-run") for arg in report["command"]))


if __name__ == "__main__":
    unittest.main()
