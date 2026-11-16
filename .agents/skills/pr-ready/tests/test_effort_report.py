import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "effort_report.py"
spec = importlib.util.spec_from_file_location("pr_gate_for_agent_runs", ROOT / "scripts" / "pr_gate.py")
gate = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = gate
spec.loader.exec_module(gate)
sys.path.insert(0, str(ROOT / "tests"))
from test_pr_gate import SHA, good, module  # noqa: E402

MODEL = "claude-sonnet-5-5"


def run(role, effort, rnd=1, findings=None, model=MODEL):
    r = {"role": role, "model": model, "effort": effort, "head_sha": SHA, "round": rnd}
    if findings is not None:
        r["findings"] = findings
    return r


class AgentRunShapeTests(unittest.TestCase):
    """The shape check must pass real records and trigger on every malformed field (AGENTS.md 5.12)."""

    def errors(self, *runs):
        return gate.agent_run_errors(list(runs))

    def test_absent_and_valid_records_pass(self):
        self.assertEqual([], gate.agent_run_errors(None))
        self.assertEqual([], self.errors(run("pr-coder", "high"), run("pr-reviewer", "xhigh", 2, {"P2": 1, "P3": 0})))

    def test_each_bad_field_is_reported(self):
        cases = {
            "role": {**run("pr-coder", "high"), "role": "coder"},
            "model": {**run("pr-coder", "high"), "model": " "},
            "effort": run("pr-coder", "extreme"),
            "head_sha": {**run("pr-coder", "high"), "head_sha": "abc"},
            "round": run("pr-coder", "high", rnd=0),
            "findings": run("pr-reviewer", "high", findings={"P5": 1}),
        }
        for field, bad in cases.items():
            with self.subTest(field):
                self.assertTrue(any(f".{field}" in e for e in self.errors(bad)), self.errors(bad))

    def test_findings_rules(self):
        self.assertTrue(self.errors(run("pr-coder", "high", findings={"P1": 1})))
        self.assertTrue(self.errors(run("pr-reviewer", "high", findings={"P1": -1})))
        self.assertTrue(self.errors(run("pr-reviewer", "high", findings={"P1": True})))

    def test_wrong_container_types(self):
        self.assertEqual(["agent_runs must be a list"], gate.agent_run_errors({"role": "pr-coder"}))
        self.assertEqual(["agent_runs[0] is not an object"], gate.agent_run_errors(["pr-coder"]))

    def test_gate_evaluate_applies_it(self):
        s, e = good()
        e["agent_runs"] = [run("pr-reviewer", "xhigh", findings={"P0": 0})]
        self.assertEqual([], module.evaluate(s, e, repo="acme/repo", number=7, local=(SHA, "fix-one", [])))
        e["agent_runs"][0]["effort"] = "turbo"
        errs = module.evaluate(s, e, repo="acme/repo", number=7, local=(SHA, "fix-one", []))
        self.assertTrue(any("agent_runs[0].effort" in x for x in errs), errs)


class ReportTests(unittest.TestCase):
    def write(self, d, name, runs):
        p = Path(d) / name
        p.write_text(json.dumps({"agent_runs": runs} if runs is not None else {}))
        return str(p)

    def test_cohorts_group_prs_by_coder_effort(self):
        with tempfile.TemporaryDirectory() as d:
            paths = [
                self.write(d, "a.json", [run("pr-coder", "high"), run("pr-reviewer", "xhigh", 1, {"P1": 2}),
                                         run("pr-reviewer", "xhigh", 2, {"P3": 4})]),
                self.write(d, "b.json", [run("pr-coder", "high"), run("pr-reviewer", "xhigh", 1, {})]),
                self.write(d, "c.json", [run("pr-coder", "xhigh"), run("pr-reviewer", "xhigh", 1, {"P2": 1})]),
                self.write(d, "d.json", [run("pr-coder", "high"), run("pr-coder", "xhigh"), run("pr-reviewer", "xhigh")]),
            ]
            out = subprocess.run([sys.executable, str(SCRIPT), *paths], capture_output=True, text=True, check=True)
        data = json.loads(out.stdout)
        cohorts = {c["coder_effort"]: c for c in data["pr_cohorts"]}
        self.assertEqual({"high", "xhigh", "mixed"}, set(cohorts))
        self.assertEqual((2, 1.5, 1.0), (cohorts["high"]["prs"], cohorts["high"]["mean_reviewer_rounds"],
                                         cohorts["high"]["mean_blocking_findings"]))
        self.assertEqual(1, cohorts["xhigh"]["prs"])
        self.assertEqual(1, cohorts["mixed"]["prs"])
        reviewer = next(r for r in data["by_role"] if (r["role"], r["effort"]) == ("pr-reviewer", "xhigh"))
        self.assertEqual((5, 4, 3), (reviewer["runs"], reviewer["prs"], reviewer["reviewer_blocking_findings"]))

    def test_missing_and_invalid_are_listed_and_fail_the_exit_code(self):
        with tempfile.TemporaryDirectory() as d:
            ok = self.write(d, "ok.json", [run("pr-coder", "high")])
            missing = self.write(d, "missing.json", None)
            bad = self.write(d, "bad.json", [run("pr-coder", "nope")])
            broken = Path(d) / "broken.json"
            broken.write_text("{")
            res = subprocess.run([sys.executable, str(SCRIPT), ok, missing, bad, str(broken)],
                                 capture_output=True, text=True)
        self.assertEqual(2, res.returncode)
        data = json.loads(res.stdout)
        self.assertEqual([missing], data["missing_agent_runs"])
        self.assertEqual({bad, str(broken)}, {i["file"] for i in data["invalid"]})
        self.assertEqual(1, data["by_role"][0]["runs"])

    def test_no_files_is_an_error(self):
        with tempfile.TemporaryDirectory() as d:
            res = subprocess.run([sys.executable, str(SCRIPT)], capture_output=True, text=True, cwd=d)
        self.assertEqual(1, res.returncode)


if __name__ == "__main__":
    unittest.main()
