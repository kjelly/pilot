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
        (self.root / "go.mod").write_text("module example/fixture\n\ngo 1.25\n")
        (self.root / "fixture_test.go").write_text('''package fixture
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
        code = shards.record(["go", "test", "-race", "-count=1", "-timeout", "30s", "-json", "."], directory, "spec")
        self.assertEqual(code, 0)
        reports = shards.verified_reports([directory / "report.json"])
        rows = {r["name"]: r for r in reports[0]["tests"]}
        self.assertEqual(rows["TestSkip"]["verdict"], "skip")
        self.assertIn("missing optional topology", rows["TestSkip"]["skip_reason"])
        self.assertIn("ExampleAnswer", rows)
        self.assertIn("FuzzTiny/seed#0", rows)
        values = shards.weights(reports)["weights"]["example/fixture"]
        self.assertEqual(set(values), {"TestPass", "TestSkip", "TestFailure", "ExampleAnswer", "FuzzTiny"})

    def test_actual_failure_retains_exit_and_evidence(self):
        directory = self.root / "failure"
        with patch.dict(os.environ, FAIL_FIXTURE="1"):
            code = shards.record(["go", "test", "-race", "-count=1", "-timeout", "30s", "-json", "."], directory, "cmd")
        self.assertEqual(code, 1)
        report = shards.read_json(directory / "report.json")
        self.assertEqual(report["exit_code"], 1)
        self.assertFalse(report["success"])
        with self.assertRaises(ValueError):
            shards.verified_reports([directory / "report.json"])


if __name__ == "__main__":
    unittest.main()
