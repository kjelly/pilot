"""Scope planning and static/runtime readiness must remain distinct."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))


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
