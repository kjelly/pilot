"""Remote gate's target reuse policy: same machine rules as local issue-to-pr."""
import copy
import json
import unittest
from unittest import mock

from test_gate import Fake, sample, B, H
from test_target_validation import R, ART, RECORD, MANIFEST, REPO, repo_manifest
import gh_runtime
from review_gate import evaluate

A = "d" * 40
APP = "playbooks/apply/x.yml"
DEP = "internal/shared/helper.go"
OTHER = "internal/unrelated/service.go"


def blob(n, mode="100644"):
    return (mode, str(n) * 40)


class TargetReuseRemoteTests(unittest.TestCase):
    def fixture(self):
        gh = Fake()
        manifest = json.loads(repo_manifest())
        manifest["required_evidence"][0]["kind"] = "target-run"
        gh.files[(MANIFEST, B)] = json.dumps(manifest).encode()
        gh.files[(ART, H)] = RECORD
        gh.compares[(R, H)] = {"ancestor": True, "merge_base": R, "files": [ART, OTHER]}
        gh.compares[(B, H)] = {"ancestor": True, "merge_base": B, "files": [ART, APP]}
        gh.compares[(R, B)] = {"ancestor": False, "merge_base": A, "files": [OTHER]}
        trees = {A: {DEP: blob(1)}, R: {APP: blob(2), DEP: blob(1)},
                 B: {DEP: blob(1), OTHER: blob(3)},
                 H: {APP: blob(2), DEP: blob(1), OTHER: blob(3), ART: blob(4)}}
        gh.tree_entries = lambda repo, revision: trees[revision]
        gh.branch_head = lambda repo, name: B
        e = sample()
        e["target_validation"] = {"decision": "required", "reason": "Native target chain passed; execution content and dependencies independently reviewed.",
                                  "artifact": ART, "tested_revision": R,
                                  "target_reuse": {"head_sha": H, "base_sha": B, "reviewer_confirmed": True,
                                      "execution_paths": [APP, DEP], "non_execution_changes": [],
                                      "dependency_review": "Reviewed complete target dependency closure; the unrelated service is not called by this target or its shared helpers."}}
        return gh, e, trees

    def test_remote_gate_accepts_reviewed_main_import(self):
        gh, e, _ = self.fixture()
        r = evaluate(REPO, 42, e, client=gh)
        self.assertEqual("MERGE", r["decision"], r["reasons"])
        self.assertEqual("reviewed-base-integration", r["target_validation"]["delta_accepted"][0]["method"])

    def test_execution_dependency_mode_or_content_change_waits(self):
        for changed in (blob(9), blob(1, "100755"), None):
            gh, e, trees = self.fixture()
            if changed is None:
                del trees[H][DEP]
            else:
                trees[H][DEP] = changed
            r = evaluate(REPO, 42, e, client=gh)
            self.assertEqual("WAITING", r["decision"], r)
            self.assertIn("execution input changed", " ".join(r["reasons"]))

    def test_runtime_conflict_outside_scope_is_not_a_pure_import(self):
        gh, e, trees = self.fixture()
        trees[H][OTHER] = blob(8)
        r = evaluate(REPO, 42, e, client=gh)
        self.assertEqual("WAITING", r["decision"])
        self.assertIn("neither a pure base import", " ".join(r["reasons"]))

    def test_audited_docs_conflict_can_be_accepted(self):
        gh, e, trees = self.fixture()
        path = "docs/verification/x.md"
        trees[R][path], trees[H][path] = blob(5), blob(6)
        self.assertEqual("WAITING", evaluate(REPO, 42, e, client=gh)["decision"])
        e["target_validation"]["target_reuse"]["non_execution_changes"] = [
            {"path": path, "reason": "Changelog conflict resolution only; checklist commands and expected values are byte-identical."}]
        self.assertEqual("MERGE", evaluate(REPO, 42, e, client=gh)["decision"])

    def test_missing_stale_or_unconfirmed_attestation_waits(self):
        for kw in ({"reviewer_confirmed": False}, {"base_sha": A}, {"head_sha": R}):
            gh, e, _ = self.fixture()
            e["target_validation"]["target_reuse"].update(kw)
            self.assertEqual("WAITING", evaluate(REPO, 42, e, client=gh)["decision"])
        gh, e, _ = self.fixture()
        del e["target_validation"]["target_reuse"]
        self.assertEqual("WAITING", evaluate(REPO, 42, e, client=gh)["decision"])

    def test_stale_pr_base_metadata_does_not_prove_live_base(self):
        gh, e, _ = self.fixture()
        gh.branch_head = lambda repo, name: A
        r = evaluate(REPO, 42, e, client=gh)
        self.assertEqual("WAITING", r["decision"])
        self.assertIn("PR base metadata is stale", " ".join(r["reasons"]))

    def test_fresh_target_attestation_cannot_hide_stale_overall_review_base(self):
        gh, e, trees = self.fixture()
        current = "e" * 40
        trees[current] = trees[B].copy()
        gh.branch_head = lambda repo, name: current
        gh.compares[(current, H)] = {"ancestor": True, "merge_base": current, "files": [ART, APP]}
        gh.compares[(R, current)] = {"ancestor": False, "merge_base": A, "files": [OTHER]}
        e["target_validation"]["target_reuse"]["base_sha"] = current
        r = evaluate(REPO, 42, e, client=gh)
        self.assertEqual("WAITING", r["decision"])
        self.assertIn("independent review base must match live base", " ".join(r["reasons"]))

    def test_untyped_base_manifest_cannot_be_weakened_from_pr(self):
        gh, e, _ = self.fixture()
        manifest = json.loads(gh.files[(MANIFEST, B)])
        del manifest["required_evidence"][0]["kind"]
        gh.files[(MANIFEST, B)] = json.dumps(manifest).encode()
        gh.files[(MANIFEST, H)] = repo_manifest()
        r = evaluate(REPO, 42, e, client=gh)
        self.assertEqual("WAITING", r["decision"])
        self.assertIn("requires kind: target-run", " ".join(r["reasons"]))

    def test_stale_independent_review_and_test_receipts_remain_rejected(self):
        gh, e, _ = self.fixture()
        stale = copy.deepcopy(e)
        stale["head_sha"] = R
        self.assertEqual("WAITING", evaluate(REPO, 42, stale, client=gh)["decision"])
        e["tests"][0]["sha"] = R
        self.assertEqual("WAITING", evaluate(REPO, 42, e, client=gh)["decision"])

    def test_missing_or_truncated_tree_waits(self):
        gh, e, _ = self.fixture()
        def fail(*args):
            raise gh_runtime.GitHubError("Complete Git tree unavailable (truncated)")
        gh.tree_entries = fail
        r = evaluate(REPO, 42, e, client=gh)
        self.assertEqual("WAITING", r["decision"])
        self.assertIn("truncated", " ".join(r["reasons"]))


class GitTreeAdapterTests(unittest.TestCase):
    def test_live_branch_head_is_resolved_and_malformed_answers_fail_closed(self):
        with mock.patch.object(gh_runtime, "gh_json", return_value={"commit": {"sha": B}}) as call:
            self.assertEqual(B, gh_runtime.branch_head(REPO, "release/main"))
            self.assertIn("release%2Fmain", call.call_args.args[0][-1])
        for data in ({}, {"commit": []}, {"commit": {"sha": "main"}}, []):
            with self.subTest(data=data), mock.patch.object(gh_runtime, "gh_json", return_value=data):
                with self.assertRaises(gh_runtime.GitHubError):
                    gh_runtime.branch_head(REPO, "main")

    def test_blob_modes_symlinks_and_submodules_are_preserved_without_following(self):
        rows = [{"path": p, "mode": mode, "type": typ, "sha": str(n)*40}
                for p, mode, typ, n in (("x", "100644", "blob", 1), ("exe", "100755", "blob", 2),
                                        ("link", "120000", "blob", 3), ("sub", "160000", "commit", 4))]
        data = {"truncated": False, "tree": rows}
        with mock.patch.object(gh_runtime, "gh_json", return_value=data) as call:
            got = gh_runtime.tree_entries(REPO, H)
            self.assertEqual(("120000", "3"*40), got["link"])
            self.assertEqual(("160000", "4"*40), got["sub"])
            self.assertIn(H+"?recursive=1", call.call_args.args[0][-1])

    def test_truncated_malformed_duplicate_and_unknown_mode_trees_fail_closed(self):
        row = {"path": "a", "mode": "100644", "type": "blob", "sha": "1"*40}
        cases = [{"truncated": True, "tree": []}, {"tree": []},
                 {"truncated": False, "tree": [row, row]},
                 {"truncated": False, "tree": [dict(row, mode="040000")]},
                 {"truncated": False, "tree": [dict(row, sha="bad")]},
                 {"truncated": False, "tree": [dict(row, type="commit")]}]
        for data in cases:
            with self.subTest(data=data), mock.patch.object(gh_runtime, "gh_json", return_value=data):
                with self.assertRaises(gh_runtime.GitHubError):
                    gh_runtime.tree_entries(REPO, H)


if __name__ == "__main__":
    unittest.main()
