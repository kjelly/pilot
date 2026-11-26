"""Scope planning and static/runtime readiness must remain distinct."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from gitrepo import Repo  # noqa: E402


def load(name):
    spec = importlib.util.spec_from_file_location(name, SCRIPTS / (name + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


planner = load("local_test_plan")
roles = load("role_preflight")
CMD = "github.com/kjelly/pilot/cmd/pilot/cmd"
SPEC = "github.com/kjelly/pilot/internal/spec"
PACKAGES = [{"name": "shared", "dir": "internal/shared", "imports": []},
            {"name": "mid", "dir": "internal/mid", "imports": ["shared"]},
            {"name": CMD, "dir": "cmd/pilot/cmd", "imports": ["mid"]},
            {"name": SPEC, "dir": "internal/spec", "imports": []},
            {"name": "unrelated", "dir": "internal/unrelated", "imports": []}]


class LocalPlanTests(unittest.TestCase):
    def test_test_only_changes_do_not_expand_to_importers(self):
        result = planner.plan(["internal/shared/a_test.go"], PACKAGES, {})
        self.assertEqual(["shared"], result["packages"])

    def test_shared_helper_selects_transitive_importers_not_unrelated_packages(self):
        result = planner.plan(["internal/shared/a.go"], PACKAGES, {CMD: "TestAffected"})
        self.assertEqual(sorted(["shared", "mid", CMD]), result["packages"])
        self.assertEqual("PLANNED", result["status"])
        self.assertNotIn("./...", str(result["commands"]))

    def test_large_package_requires_selector_instead_of_full_package_run(self):
        result = planner.plan(["internal/spec/a_test.go"], PACKAGES, {})
        self.assertEqual("NEEDS_SELECTION", result["status"])
        self.assertEqual([SPEC], result["missing_regression_selectors"])
        self.assertEqual([], result["commands"])

    def test_ci_edits_select_command_consistency_checks(self):
        result = planner.plan([".github/workflows/ci.yml"], PACKAGES, {CMD: "TestCI"})
        self.assertEqual([CMD], result["packages"])
        self.assertIn("TestCI", result["commands"][0])

    def test_lock_changes_expand_to_every_package_and_skill_changes_add_skill_suite(self):
        result = planner.plan(["go.sum", ".agents/skills/pr-ready/SKILL.md"], PACKAGES,
                              {CMD: "TestAffected", SPEC: "TestAffected"})
        self.assertEqual(sorted(p["name"] for p in PACKAGES), result["packages"])
        self.assertIn(["make", "skill-test"], result["commands"])

    def test_evidence_only_has_no_local_test_commands(self):
        self.assertEqual([], planner.plan(["docs/evidence/x.md"], PACKAGES, {})["commands"])


def selection(*suites, reason=None):
    """What skill_suites.select returns: the chosen suites (or "all") with a reason each."""
    chosen = "all" if suites == ("all",) else sorted(suites)
    return {"selection": chosen, "reasons": {s: [f"{s} reads the change"] for s in suites if s != "all"}, "reason": reason,
            "universe": ["README.md"]}


class SkillSelectionPlanTests(unittest.TestCase):
    """A change that reaches skill tests plans `make skill-test` for the suites it can reach (kjelly/pilot#430)."""

    def commands(self, paths, skills):
        return planner.plan(paths, PACKAGES, {}, skills)["commands"]

    def test_a_selection_narrows_the_command_to_the_suites_it_names_and_prints_the_reasons(self):
        result = planner.plan(["scripts/pr_loop.py"], PACKAGES, {}, selection("pr-ready", "_shared"))
        self.assertEqual([["make", "skill-test", "SKILL_SUITES=_shared pr-ready"]], result["commands"])
        self.assertEqual({"_shared": ["_shared reads the change"], "pr-ready": ["pr-ready reads the change"]},
                         result["skill_suites"]["reasons"])
        self.assertEqual(["_shared", "pr-ready"], result["skill_suites"]["selection"])

    def test_every_suite_when_the_mapping_is_unknown_is_the_plain_command_with_the_reason(self):
        result = planner.plan([".claude/zzz"], PACKAGES, {}, selection("all", reason=".claude/zzz is read by no suite the derivation knows of (an unknown path)"))
        self.assertEqual([["make", "skill-test"]], result["commands"])
        self.assertEqual(".claude/zzz is read by no suite the derivation knows of (an unknown path)", result["skill_suites"]["reason"])

    def test_an_empty_selection_plans_no_skill_command(self):
        # `skill_suites.select` returns an empty selection only for an empty diff (a change is never "reached by no suite")
        self.assertEqual([], self.commands([], selection()))
        # control: the same paths with a suite reached do plan it
        self.assertEqual([["make", "skill-test", "SKILL_SUITES=issue-filing"]],
                         self.commands(["AGENTS.md"], selection("issue-filing")))

    def test_the_go_plan_is_the_same_whatever_the_skill_selection_is(self):
        paths = ["internal/shared/a.go", ".agents/skills/pr-ready/SKILL.md"]
        plain = planner.plan(paths, PACKAGES, {CMD: "TestAgent"})
        narrow = planner.plan(paths, PACKAGES, {CMD: "TestAgent"}, selection("pr-ready"))
        self.assertEqual(plain["packages"], narrow["packages"])
        self.assertEqual(plain["commands"][:-1], narrow["commands"][:-1])
        self.assertEqual(["make", "skill-test"], plain["commands"][-1])
        self.assertEqual(["make", "skill-test", "SKILL_SUITES=pr-ready"], narrow["commands"][-1])

    def test_a_change_with_no_selection_derived_keeps_the_whole_suite(self):
        self.assertEqual([["make", "skill-test"]], self.commands([".agents/skills/pr-ready/SKILL.md"], None))
        # the legacy rule of before the selection (`main` never takes it: it always derives): .agents/.codex/.claude only
        self.assertEqual([], self.commands(["cmd/pilot/main.go"], None))


class PlannerEntryPointTests(unittest.TestCase):
    """`local_test_plan.py --repo DIR --base B --head H` on a real scratch repository: git diff -> selection -> JSON."""

    SUITE_A = ("import unittest\nfrom pathlib import Path\nROOT = Path(__file__).resolve().parents[4]\n"
               "class T(unittest.TestCase):\n    def test_x(self):\n        (ROOT / 'README.md').read_text()\n")
    SUITE_B = "import unittest\nclass T(unittest.TestCase):\n    def test_x(self):\n        pass\n"

    def repo(self):
        r = Repo(self)
        r.write(".agents/skills/a/tests/test_a.py", self.SUITE_A)
        r.write(".agents/skills/b/tests/test_b.py", self.SUITE_B)
        r.write("README.md", "one\n")
        r.write("internal/x/x.go", "package x\n")
        return r, r.commit("base")

    def plan(self, r, base):
        real = subprocess.check_output

        def check_output(argv, **kwargs):
            return b"" if argv[0] == "go" else real(argv, **kwargs)       # no Go toolchain is needed for these diffs
        out = io.StringIO()
        with patch.object(planner.subprocess, "check_output", side_effect=check_output), \
                patch.object(sys, "argv", ["local_test_plan.py", "--repo", str(r.path), "--base", base]), \
                contextlib.redirect_stdout(out):
            code = planner.main()
        return code, json.loads(out.getvalue())

    def test_a_modified_file_a_suite_reads_plans_that_suite_only(self):
        r, base = self.repo()
        r.write("README.md", "two\n")
        head = r.commit("edit the readme")
        code, result = self.plan(r, base)
        self.assertEqual((0, [["make", "skill-test", "SKILL_SUITES=a"]]), (code, result["commands"]))
        self.assertEqual(["a"], result["skill_suites"]["selection"])
        self.assertEqual((base, head), (result["skill_suites"]["base_sha"], result["skill_suites"]["head_sha"]))
        self.assertIn("README.md", result["skill_suites"]["reasons"]["a"][0])
        self.assertEqual((base, head), (result["base_sha"], result["head_sha"]))

    def test_a_deleted_file_a_suite_reads_plans_every_suite(self):
        r, base = self.repo()
        r.git("rm", "-q", "README.md")
        r.commit("remove the readme")
        code, result = self.plan(r, base)
        self.assertEqual((0, [["make", "skill-test"]]), (code, result["commands"]))
        self.assertEqual("all", result["skill_suites"]["selection"])
        self.assertIn("README.md has status D", result["skill_suites"]["reason"])

    def skill_commands(self, result):
        return [c for c in result["commands"] if c[:2] == ["make", "skill-test"]]

    def test_a_go_only_change_plans_every_suite_because_no_suite_reads_it(self):
        # Issue 430 / #432: an unknown path selects the full suite. The base planned none for a Go-only change; that cost is
        # accepted, and the reason names the path
        r, base = self.repo()
        r.write("internal/x/x.go", "package x\n\nvar V = 1\n")
        r.commit("a go change")
        code, result = self.plan(r, base)
        self.assertEqual(0, code)
        self.assertEqual([["make", "skill-test"]], self.skill_commands(result))
        self.assertEqual("all", result["skill_suites"]["selection"])
        self.assertIn("internal/x/x.go", result["skill_suites"]["reason"])

    def test_an_unknown_added_file_at_the_root_plans_every_suite(self):
        r, base = self.repo()
        r.write("unknown-review-input-441.dat", "x\n")
        r.commit("an unknown file")
        code, result = self.plan(r, base)
        self.assertEqual([["make", "skill-test"]], self.skill_commands(result))
        self.assertIn("unknown-review-input-441.dat", result["skill_suites"]["reason"])

    def test_a_deleted_and_an_added_go_file_outside_every_suite_plan_every_suite(self):
        r, base = self.repo()
        r.git("rm", "-q", "internal/x/x.go")
        r.write("internal/x/y.go", "package x\n")
        r.commit("delete one go file, add another")
        code, result = self.plan(r, base)
        self.assertEqual([["make", "skill-test"]], self.skill_commands(result))
        self.assertEqual("all", result["skill_suites"]["selection"])

    def test_a_git_mv_plans_every_suite(self):
        r, base = self.repo()
        r.git("mv", "internal/x/x.go", "internal/x/z.go")
        r.commit("rename a go file")
        code, result = self.plan(r, base)
        self.assertEqual([["make", "skill-test"]], self.skill_commands(result))
        self.assertIn("internal/x/x.go has status D", result["skill_suites"]["reason"])   # a rename arrives as D + A

    def test_a_docs_only_change_plans_every_suite_and_names_the_path(self):
        r, base = self.repo()
        r.write("docs/evidence/x.md", "evidence\n")
        r.commit("an evidence record")
        code, result = self.plan(r, base)
        self.assertEqual([["make", "skill-test"]], self.skill_commands(result))
        self.assertIn("docs/evidence/x.md", result["skill_suites"]["reason"])

    def test_an_empty_diff_plans_no_skill_command(self):
        r, base = self.repo()
        code, result = self.plan(r, base)                       # base == head
        self.assertEqual(0, code)
        self.assertEqual([], self.skill_commands(result))
        self.assertEqual([], result["skill_suites"]["selection"])
        self.assertIsNone(result["skill_suites"]["reason"])

    def test_a_change_inside_a_suite_plans_that_suite(self):
        r, base = self.repo()
        r.write(".agents/skills/b/tests/test_b.py", self.SUITE_B + "\n")
        r.commit("touch the suite b")
        code, result = self.plan(r, base)
        self.assertEqual([["make", "skill-test", "SKILL_SUITES=b"]], result["commands"])

    def test_a_suite_that_does_not_parse_plans_every_suite_even_for_a_go_change(self):
        r, base = self.repo()
        r.write(".agents/skills/b/tests/test_b.py", "def broken(:\n")
        r.write("internal/x/x.go", "package x\n\nvar V = 2\n")
        r.commit("a go change and a broken suite")
        code, result = self.plan(r, base)
        self.assertEqual([["make", "skill-test"]], result["commands"])
        self.assertIn("cannot parse", result["skill_suites"]["reason"])


class RoleStartupTests(unittest.TestCase):
    def test_static_pass_never_claims_runtime_launch_success(self):
        with patch.object(roles.skill_snapshot, "verify_role", return_value={"checkout_role": "/missing", "role": "x"}) as check:
            result = roles.preflight(Path("/snapshot"), Path("/repo"), "codex", "pr-ready")
        self.assertEqual(3, check.call_count)
        self.assertEqual("LAUNCH_REQUIRED", result["status"])
        self.assertFalse(result["runtime_verified"])

    def test_missing_role_stops_before_work(self):
        with patch.object(roles.skill_snapshot, "verify_role", side_effect=roles.skill_snapshot.Stop("missing")):
            with self.assertRaises(roles.skill_snapshot.Stop):
                roles.preflight(Path("/snapshot"), Path("/repo"), "codex", "issue-to-pr")

    def test_dependency_probe_is_optional(self):
        with patch.object(roles.skill_snapshot, "verify_role", return_value={"checkout_role": "/missing"}) as check:
            roles.preflight(Path("/snapshot"), Path("/repo"), "claude", "pr-review-merge")
            self.assertEqual(1, check.call_count)
            check.reset_mock()
            roles.preflight(Path("/snapshot"), Path("/repo"), "claude", "pr-review-merge", True)
            self.assertEqual(2, check.call_count)

    def test_codex_symlink_is_diagnosed_even_when_bytes_can_be_read(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "source").write_text("valid")
            (path / "role").symlink_to(path / "source")
            with patch.object(roles.skill_snapshot, "verify_role", return_value={"checkout_role": str(path / "role")}):
                result = roles.preflight(path, path, "codex", "pr-ready")
                self.assertEqual("LAUNCH_REQUIRED", result["status"])
                self.assertIn("symlink", result["warnings"][0])
                self.assertFalse(result["runtime_verified"])


if __name__ == "__main__":
    unittest.main()
