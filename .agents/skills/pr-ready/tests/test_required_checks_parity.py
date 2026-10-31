"""pr-ready and issue-to-pr read `gh pr checks --required` the same way.

Both skills keep their own copy of the tolerated failure (a branch without required checks makes
gh exit 1 with plain text instead of JSON): pr-ready in pr_gate.py, issue-to-pr in issue_gate.py's
command() as called by pr_ci.py. A gate that swallows a failing required check in one skill but not
the other is the drift this test exists for, so one matrix goes through both helpers and every case
must have the same, stated outcome.
"""
import importlib.util
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_pr_gate import (PHRASE_FAILURE, PHRASE_NAME, REAL_NO_REQUIRED, fake_gh, module as pr_gate)

SKILLS = Path(__file__).resolve().parents[2]


def load_issue_to_pr():
    """issue-to-pr's issue_gate and pr_ci, loaded by path; sys.path is left as it was found."""
    scripts = SKILLS / "issue-to-pr" / "scripts"
    path = list(sys.path)
    try:
        loaded = {}
        for name in ("issue_gate", "pr_ci"):
            spec = importlib.util.spec_from_file_location(name, scripts / f"{name}.py")
            loaded[name] = importlib.util.module_from_spec(spec)
            sys.modules[name] = loaded[name]
            spec.loader.exec_module(loaded[name])
        return loaded["pr_ci"]
    finally:
        sys.path[:] = path


pr_ci = load_issue_to_pr()
FAILED_CHECK = '[{"name": "ci", "state": "FAILURE", "bucket": "fail"}]'
OK_CHECK = '[{"name": "ci", "state": "SUCCESS", "bucket": "pass"}]'
ERROR = "error"

# (label, required query?, exit status, stdout, stderr, expected: a list of check names or ERROR)
MATRIX = (
    ("the exact gh message, nothing on stdout", True, 1, "", REAL_NO_REQUIRED, []),
    ("the same without the trailing newline", True, 1, "", REAL_NO_REQUIRED.rstrip("\n"), []),
    ("blank stdout", True, 1, "\n", REAL_NO_REQUIRED, []),
    ("a failing check named like the message", True, 1, PHRASE_FAILURE, "", [PHRASE_NAME]),
    ("the same, message also on stderr", True, 1, PHRASE_FAILURE, REAL_NO_REQUIRED, [PHRASE_NAME]),
    ("failing JSON, no message", True, 1, FAILED_CHECK, "", ["ci"]),
    ("pending JSON (exit 8)", True, 8, OK_CHECK, "", ["ci"]),
    ("passing JSON", True, 0, OK_CHECK, "", ["ci"]),
    ("message inside other stderr text", True, 1, "", "warning: retrying\n" + REAL_NO_REQUIRED, ERROR),
    ("message with a trailing line", True, 1, "", REAL_NO_REQUIRED + "more\n", ERROR),
    ("message in another case", True, 1, "", REAL_NO_REQUIRED.upper(), ERROR),
    ("message without the branch part", True, 1, "", "no required checks reported\n", ERROR),
    ("message after an HTTP error", True, 1, "", "HTTP 502: " + REAL_NO_REQUIRED, ERROR),
    ("message with exit 8", True, 8, "", REAL_NO_REQUIRED, ERROR),
    ("message with exit 2", True, 2, "", REAL_NO_REQUIRED, ERROR),
    ("message with exit 0", True, 0, "", REAL_NO_REQUIRED, ERROR),
    ("message with unparseable stdout", True, 1, "oops", REAL_NO_REQUIRED, ERROR),
    ("unrelated failure", True, 1, "", "HTTP 502: Bad Gateway\n", ERROR),
    ("the full query never falls back", False, 1, "", REAL_NO_REQUIRED, ERROR),
)


def names(found):
    return [c["name"] for c in found]


def outcome(call):
    try:
        return names(call())
    except (pr_gate.GateError, pr_ci.GateError):
        return ERROR


class RequiredChecksParityTests(unittest.TestCase):
    def test_both_skills_agree_on_every_case_and_on_the_stated_outcome(self):
        for label, required, rc, out, err, expected in MATRIX:
            with self.subTest(label), fake_gh(rc, out, err):
                ready = outcome(lambda: pr_gate.gh_checks("acme/repo", 7, required=required))
                issue = outcome(lambda: pr_ci.checks("acme/repo", 7, required))
                self.assertEqual(expected, ready, "pr-ready")
                self.assertEqual(expected, issue, "issue-to-pr")

    def test_the_two_constants_are_the_same_pattern(self):
        self.assertEqual(pr_gate.NO_REQUIRED_CHECKS.pattern, pr_ci.NO_REQUIRED_CHECKS.pattern)
        self.assertEqual(pr_gate.NO_REQUIRED_CHECKS.flags, pr_ci.NO_REQUIRED_CHECKS.flags)

    def test_the_helpers_are_not_the_same_code_by_accident_of_one_import(self):
        # The matrix above is only a parity proof if the two skills really are separate modules.
        self.assertNotEqual(pr_gate.__file__, pr_ci.__file__)
        self.assertTrue(Path(pr_ci.__file__).is_relative_to(SKILLS / "issue-to-pr"))
        self.assertTrue(Path(pr_gate.__file__).is_relative_to(SKILLS / "pr-ready"))


if __name__ == "__main__":
    unittest.main()
