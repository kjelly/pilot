"""Ancestry decisions from captured GitHub compare responses, without file-list limits."""
import copy
import json
import subprocess
import unittest
from unittest import mock

from test_target_validation import API, REPO
import gh_runtime


class BaseAncestryTests(unittest.TestCase):
    def test_recorded_comparisons(self):
        for name, expected in (("ahead_evidence_only", True), ("identical", True),
                               ("behind", False), ("diverged", False), ("over_300_files", True)):
            entry = API["compare"][name]
            cp = subprocess.CompletedProcess(["gh"], entry["rc"], entry["stdout"], entry["stderr"])
            with self.subTest(name=name), mock.patch.object(gh_runtime, "run_gh", return_value=cp) as run:
                self.assertIs(expected, gh_runtime.is_ancestor(REPO, *entry["args"]))
                self.assertIn("/compare/" + "...".join(entry["args"]), run.call_args.args[0][-1])

    def test_invalid_or_inconsistent_comparisons_are_unknown(self):
        entry = API["compare"]["ahead_evidence_only"]
        valid = json.loads(entry["stdout"])
        for patch in ({"status": "unknown"}, {"behind_by": True}, {"behind_by": -1},
                      {"behind_by": 1}, {"merge_base_commit": {"sha": "bad"}},
                      {"merge_base_commit": {"sha": "0" * 40}}):
            body = copy.deepcopy(valid)
            body.update(patch)
            cp = subprocess.CompletedProcess(["gh"], 0, json.dumps(body), "")
            with self.subTest(patch=patch), mock.patch.object(gh_runtime, "run_gh", return_value=cp):
                with self.assertRaises(gh_runtime.GitHubError):
                    gh_runtime.is_ancestor(REPO, *entry["args"])

    def test_unavailable_comparison_raises(self):
        with mock.patch.object(gh_runtime, "run_gh", side_effect=gh_runtime.GitHubError("HTTP 404")):
            with self.assertRaises(gh_runtime.GitHubError):
                gh_runtime.is_ancestor(REPO, "a" * 40, "b" * 40)
