"""Project-local defaults that an upstream upgrade must not silently revert."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"


class ProjectDefaultsTest(unittest.TestCase):
    def test_apply_decision_merges_with_merge_commits(self):
        # The pilot repository merges PRs with merge commits; upstream defaults to squash.
        source = (SCRIPTS / "apply_decision.py").read_text(encoding="utf-8")
        match = re.search(r'add_argument\("--method",[^\n]*default="(\w+)"', source)
        self.assertIsNotNone(match, "--method argument not found")
        self.assertEqual("merge", match.group(1))


if __name__ == "__main__":
    unittest.main()
