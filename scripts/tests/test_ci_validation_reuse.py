"""Real Git history plus mocked GitHub artifact/API boundary tests."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

SCRIPT = Path(__file__).resolve().parents[1] / "ci-validation-reuse.py"
spec = importlib.util.spec_from_file_location("reuse", SCRIPT)
reuse = importlib.util.module_from_spec(spec)
spec.loader.exec_module(reuse)


class ReuseTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.old = Path.cwd()
        os.chdir(self.tmp.name)
        self.addCleanup(os.chdir, self.old)
        self.env = patch.dict(os.environ, GIT_AUTHOR_NAME="Test", GIT_COMMITTER_NAME="Test",
                              GIT_AUTHOR_EMAIL="test@example.org", GIT_COMMITTER_EMAIL="test@example.org")
        self.env.start()
        self.addCleanup(self.env.stop)
        self.git("init", "-q")
        self.base = self.commit("README.md")
        # The PR event base can stay at B while Actions tests B0 + PR head.
        self.actual_base = self.commit("dependency.txt", "compatible")
        self.git("checkout", "--detach", self.base)
        self.candidate = self.commit("runtime.go")
        self.head = self.commit("docs/evidence/a space\nand newline.md")
        self.candidate_merge = self.merge(self.actual_base, self.candidate)
        self.current_merge = self.merge(self.actual_base, self.head)
        self.git("checkout", "--detach", self.head)
        self.ctx = {"schema_version": 2, "repository": "acme/repo", "pr_number": 7,
                    **reuse.tested_inputs(self.current_merge, self.head), "validation": "full"}
        self.run = {"id": 11, "run_attempt": 1, "workflow_id": 22, "status": "completed",
                    "created_at": (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat(),
                    "conclusion": "success", "event": "pull_request", "head_sha": self.candidate,
                    "head_repository": {"full_name": "acme/repo"}}
        self.current_run = {**self.run, "id": 100, "head_sha": self.head, "status": "in_progress"}
        self.receipt = {**self.ctx, **reuse.tested_inputs(self.candidate_merge, self.candidate), "run_id": 11,
                        "run_attempt": 1, "workflow_id": 22}
        self.artifact = {"name": "ci-validation-1", "expired": False, "id": 99, "size_in_bytes": 1000}
        self.event = {"pull_request": {"number": 7,
                      "head": {"sha": self.head, "repo": {"full_name": "acme/repo"}},
                      "base": {"sha": self.base, "repo": {"full_name": "acme/repo"}}}}
        self.actions_env = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_REPOSITORY": "acme/repo",
                            "GITHUB_SHA": self.current_merge, "GITHUB_RUN_ID": "100", "GITHUB_RUN_ATTEMPT": "1"}

    def git(self, *args):
        return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL).decode().strip()

    def commit(self, path, content="record"):
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        self.git("add", ".")
        self.git("commit", "-qm", "change")
        return self.git("rev-parse", "HEAD")

    def merge(self, base, head):
        self.git("checkout", "--detach", base)
        self.git("merge", "--no-ff", "-qm", "tested merge", head)
        return self.git("rev-parse", "HEAD")

    def cli(self, *args, api=None):
        event_path = Path(".git/event.json").resolve()
        event_path.write_text(json.dumps(self.event))
        with patch.dict(os.environ, {**self.actions_env, "GITHUB_EVENT_PATH": str(event_path)}), \
                patch.object(sys, "argv", [str(SCRIPT), *args]), \
                patch.object(reuse, "api", api or self.api), \
                patch("sys.stdout", new_callable=io.StringIO) as out, \
                patch("sys.stderr", new_callable=io.StringIO) as err:
            result = reuse.main()
            return result, out.getvalue(), err.getvalue()

    def api(self, path, binary=False):
        if path.endswith("/runs/100"):
            return self.current_run
        if "/workflows/22/runs?" in path:
            return {"workflow_runs": [self.run]}
        if path.endswith("/runs/11"):
            return self.run
        if "/artifacts?" in path:
            return {"artifacts": [self.artifact]}
        if path.endswith("/artifacts/99/zip"):
            raw = io.BytesIO()
            with zipfile.ZipFile(raw, "w") as archive:
                archive.writestr("ci-validation.json", json.dumps(self.receipt))
            return raw.getvalue()
        raise AssertionError(path)

    def find(self):
        with patch.object(reuse, "api", self.api):
            return reuse.find_candidate(self.ctx, 100)

    def test_full_success_can_be_reused_after_evidence_only_commit(self):
        self.assertEqual(11, self.find()["id"])
        # The PR itself includes runtime.go; comparing PR base would reject it.
        self.assertFalse(reuse.evidence_delta(self.base, self.head))
        # Synthetic merges are siblings: only raw PR commits need ancestry.
        self.assertEqual(1, subprocess.run(["git", "merge-base", "--is-ancestor",
                                          self.candidate_merge, self.current_merge]).returncode)

    def test_advanced_actual_base_with_same_event_base_never_reuses(self):
        self.git("checkout", "--detach", self.actual_base)
        advanced = self.commit("dependency.txt", "incompatible")
        self.current_merge = self.merge(advanced, self.head)
        self.actions_env["GITHUB_SHA"] = self.current_merge
        ctx = reuse.context(self.event, self.actions_env)
        self.assertEqual(self.base, self.event["pull_request"]["base"]["sha"])
        self.assertEqual(advanced, ctx["base_sha"])
        self.assertTrue(reuse.evidence_delta(self.candidate, self.head))
        self.assertFalse(reuse.evidence_paths_only(self.candidate_merge, self.current_merge))
        self.ctx = ctx
        self.assertIsNone(self.find())
        result, out, _ = self.cli()
        self.assertEqual(0, result)
        self.assertIn("evidence_only=false", out)

    def test_same_base_but_non_evidence_merged_input_never_reuses(self):
        self.git("checkout", "--detach", self.current_merge)
        altered = self.commit("dependency.txt", "changed merge resolution")
        # Real two-parent commit, with an execution-affecting merge resolution.
        tree = self.git("rev-parse", altered + "^{tree}")
        merge = self.git("commit-tree", tree, "-p", self.actual_base, "-p", self.head, "-m", "resolution")
        self.ctx.update(reuse.tested_inputs(merge, self.head))
        self.assertTrue(reuse.evidence_delta(self.candidate, self.head))
        self.assertIsNone(self.find())

    def test_unchanged_merged_tree_after_raw_evidence_change_can_reuse(self):
        self.ctx.update(reuse.tested_inputs(self.git(
            "commit-tree", self.receipt["tested_merge_tree"], "-p", self.actual_base,
            "-p", self.head, "-m", "same merged inputs"), self.head))
        self.assertEqual(11, self.find()["id"])

    def test_changed_identity_or_non_full_receipt_never_reuses(self):
        for key, value in [("base_sha", "a" * 40), ("pr_number", 8), ("repository", "fork/repo"),
                           ("run_attempt", 2), ("head_sha", self.base), ("validation", "reused"),
                           ("workflow_id", 23), ("schema_version", 1), ("run_id", 12),
                           ("tested_merge_sha", self.current_merge), ("tested_merge_tree", "a" * 40)]:
            with self.subTest(key=key):
                saved = copy.deepcopy(self.receipt)
                self.receipt[key] = value
                self.assertIsNone(self.find())
                self.receipt = saved

    def test_legacy_or_incomplete_merge_receipts_do_not_reuse(self):
        for remove in [("tested_merge_sha",), ("tested_merge_tree",),
                       ("tested_merge_sha", "tested_merge_tree")]:
            with self.subTest(remove=remove):
                saved = copy.deepcopy(self.receipt)
                for key in remove:
                    del self.receipt[key]
                self.assertIsNone(self.find())
                self.receipt = saved
        self.receipt["schema_version"] = 1
        del self.receipt["tested_merge_sha"], self.receipt["tested_merge_tree"]
        self.assertIsNone(self.find())

    def test_unavailable_merge_cannot_reuse_and_fetch_is_bounded_to_sha(self):
        for sha in ["f" * 40, "refs/pull/7/merge", "--upload-pack=bad", None]:
            with self.subTest(sha=sha):
                self.receipt["tested_merge_sha"] = sha
                with patch.object(reuse.subprocess, "run", wraps=subprocess.run) as run:
                    self.assertIsNone(self.find())
                    fetches = [c for c in run.call_args_list if c.args[0][:2] == ["git", "fetch"]]
                    self.assertEqual(1 if sha == "f" * 40 else 0, len(fetches))
                    if fetches:
                        self.assertEqual(["git", "fetch", "--no-tags", "--no-write-fetch-head",
                                          "--recurse-submodules=no", "--depth=1", "origin", sha], fetches[0].args[0])
                        self.assertEqual(45, fetches[0].kwargs["timeout"])

    def test_historical_merge_can_be_retrieved_without_moving_checkout(self):
        origin_tmp = tempfile.TemporaryDirectory()
        self.addCleanup(origin_tmp.cleanup)
        self.git("update-ref", "refs/heads/old-merge", self.candidate_merge)
        self.git("clone", "--bare", ".", origin_tmp.name)
        self.git("remote", "add", "origin", origin_tmp.name)
        self.git("update-ref", "-d", "refs/heads/old-merge")
        Path(".git/objects", self.candidate_merge[:2], self.candidate_merge[2:]).unlink()
        before = self.git("rev-parse", "HEAD")
        self.assertEqual(11, self.find()["id"])
        self.assertEqual(before, self.git("rev-parse", "HEAD"))
        self.assertFalse(Path(".git/FETCH_HEAD").exists())

    def test_unverified_current_tree_or_base_cannot_reuse(self):
        for key in ["base_sha", "tested_merge_tree"]:
            with self.subTest(key=key):
                saved = self.ctx[key]
                self.ctx[key] = "f" * 40
                self.assertIsNone(self.find())
                self.ctx[key] = saved

    def test_producer_records_frozen_merge_and_actual_parents(self):
        self.git("checkout", "--detach", self.current_merge)
        path = ".git/receipt.json"
        result, _, err = self.cli("--record", path)
        self.assertEqual(0, result, err)
        receipt = json.loads(Path(path).read_text())
        self.assertEqual({**self.ctx, "run_id": 100, "run_attempt": 1, "workflow_id": 22}, receipt)
        self.assertNotEqual(self.event["pull_request"]["base"]["sha"], receipt["base_sha"])

    def test_cli_reuses_receipt_produced_from_prior_frozen_merge(self):
        self.git("checkout", "--detach", self.candidate_merge)
        self.actions_env.update(GITHUB_SHA=self.candidate_merge, GITHUB_RUN_ID="11")
        self.event["pull_request"]["head"]["sha"] = self.candidate
        result, _, err = self.cli("--record", ".git/full-receipt.json")
        self.assertEqual(0, result, err)
        self.receipt = json.loads(Path(".git/full-receipt.json").read_text())
        self.git("checkout", "--detach", self.current_merge)
        self.actions_env.update(GITHUB_SHA=self.current_merge, GITHUB_RUN_ID="100")
        self.event["pull_request"]["head"]["sha"] = self.head
        result, out, err = self.cli()
        self.assertEqual(0, result, err)
        self.assertIn("evidence_only=true\nreused_run_id=11", out)

    def test_wrong_checkout_or_missing_merge_prevents_producer_and_reuse(self):
        for sha in [self.current_merge, "f" * 40]:
            with self.subTest(sha=sha):
                self.actions_env["GITHUB_SHA"] = sha
                # The raw PR head checkout cannot attest the tested merge.
                result, out, _ = self.cli()
                self.assertEqual(0, result)
                self.assertIn("evidence_only=false", out)
                result, _, err = self.cli("--record", ".git/receipt.json")
                self.assertEqual(1, result)
                self.assertIn("cannot record validation", err)
                self.assertFalse(Path(".git/receipt.json").exists())

    def test_non_merge_wrong_second_parent_and_extra_parent_rejected(self):
        tree = self.git("rev-parse", self.current_merge + "^{tree}")
        wrong = self.git("commit-tree", tree, "-p", self.actual_base, "-p", self.base, "-m", "wrong head")
        extra = self.git("commit-tree", tree, "-p", self.actual_base, "-p", self.head,
                         "-p", self.base, "-m", "extra parent")
        for merge in [self.head, wrong, extra]:
            with self.subTest(merge=merge):
                self.git("checkout", "--detach", merge)
                self.actions_env["GITHUB_SHA"] = merge
                with self.assertRaisesRegex(ValueError, "two parents"):
                    reuse.context(self.event, self.actions_env)
                result, out, _ = self.cli()
                self.assertEqual(0, result)
                self.assertIn("evidence_only=false", out)
                self.assertEqual(1, self.cli("--record", ".git/receipt.json")[0])
                self.assertFalse(Path(".git/receipt.json").exists())

    def test_stale_producer_run_metadata_never_mints_receipt(self):
        self.git("checkout", "--detach", self.current_merge)
        for key, value in [("run_attempt", 2), ("head_sha", self.candidate), ("id", 99),
                           ("event", "push"), ("head_repository", {"full_name": "fork/repo"}),
                           ("workflow_id", None), ("workflow_id", 0)]:
            with self.subTest(key=key):
                saved = copy.deepcopy(self.current_run)
                self.current_run[key] = value
                self.assertEqual(1, self.cli("--record", ".git/receipt.json")[0])
                self.assertFalse(Path(".git/receipt.json").exists())
                self.current_run = saved

    def test_non_pr_or_fork_context_requires_full_validation(self):
        self.git("checkout", "--detach", self.current_merge)
        for side in ["head", "base"]:
            with self.subTest(side=side):
                self.event["pull_request"][side]["repo"]["full_name"] = "fork/repo"
                self.assertIn("evidence_only=false", self.cli()[1])
                self.assertEqual(1, self.cli("--record", ".git/receipt.json")[0])
                self.event["pull_request"][side]["repo"]["full_name"] = "acme/repo"
        self.actions_env["GITHUB_EVENT_NAME"] = "push"
        self.assertIn("evidence_only=false", self.cli()[1])

    def test_api_error_requires_full_validation(self):
        self.git("checkout", "--detach", self.current_merge)
        with patch.object(self, "api", side_effect=subprocess.TimeoutExpired("gh", 45)):
            result, out, _ = self.cli()
            self.assertEqual(0, result)
            self.assertIn("evidence_only=false", out)
            self.assertEqual(1, self.cli("--record", ".git/receipt.json")[0])

    def test_pending_failed_cancelled_other_workflow_or_fork_never_reuses(self):
        for key, value in [("status", "in_progress"), ("conclusion", "failure"),
                           ("conclusion", "cancelled"), ("event", "push"), ("workflow_id", 23),
                           ("head_repository", {"full_name": "fork/repo"})]:
            with self.subTest(key=key):
                saved = copy.deepcopy(self.run)
                self.run[key] = value
                self.assertIsNone(self.find())
                self.run = saved

    def test_expired_or_other_attempt_artifact_does_not_reuse(self):
        self.artifact["expired"] = True
        self.assertIsNone(self.find())
        self.artifact["expired"] = False
        self.artifact["name"] = "ci-validation-2"
        self.assertIsNone(self.find())

    def test_archive_and_artifact_guards_select_full_validation(self):
        self.git("checkout", "--detach", self.current_merge)
        for case in ["missing", "duplicate", "oversized artifact", "nested archive", "extra entry",
                     "oversized entry", "invalid zip", "invalid json", "non object receipt"]:
            with self.subTest(case=case):
                def api(path, binary=False):
                    result = self.api(path, binary)
                    if "/artifacts?" in path:
                        if case == "missing":
                            return {"artifacts": []}
                        if case == "duplicate":
                            return {"artifacts": [self.artifact, self.artifact]}
                        if case == "oversized artifact":
                            return {"artifacts": [{**self.artifact, "size_in_bytes": 65537}]}
                    if path.endswith("/artifacts/99/zip"):
                        if case == "invalid zip":
                            return b"not a zip"
                        raw = io.BytesIO()
                        with zipfile.ZipFile(raw, "w") as archive:
                            name = "nested/ci-validation.json" if case == "nested archive" else "ci-validation.json"
                            content = json.dumps(self.receipt)
                            if case == "oversized entry":
                                content = " " * 16385
                            elif case == "invalid json":
                                content = "{"
                            elif case == "non object receipt":
                                content = "[]"
                            archive.writestr(name, content)
                            if case == "extra entry":
                                archive.writestr("another.json", "{}")
                        return raw.getvalue()
                    return result
                result, out, _ = self.cli(api=api)
                self.assertEqual(0, result)
                self.assertIn("evidence_only=false", out)

    def test_old_validation_is_not_reused(self):
        self.run["created_at"] = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
        self.assertIsNone(self.find())
        self.run["created_at"] = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        self.assertIsNone(self.find())

    def test_rerun_during_artifact_download_does_not_reuse(self):
        count = 0
        def api(path, binary=False):
            nonlocal count
            result = copy.deepcopy(self.api(path, binary))
            if path.endswith("/runs/11"):
                count += 1
                if count > 1:
                    result.update(run_attempt=2, status="queued")
            return result
        with patch.object(reuse, "api", api):
            self.assertIsNone(reuse.find_candidate(self.ctx, 100))

    def test_code_lock_workflow_and_mode_changes_require_full_run(self):
        for path in ["runtime.go", "go.sum", ".github/workflows/ci.yml", ".agents/skills/x/SKILL.md"]:
            with self.subTest(path=path):
                self.git("reset", "--hard", self.head)
                changed = self.commit(path, "changed")
                self.assertFalse(reuse.evidence_delta(self.candidate, changed))
        self.git("reset", "--hard", self.head)
        Path("runtime.go").chmod(0o755)
        self.git("add", ".")
        self.git("commit", "-qm", "mode")
        self.assertFalse(reuse.evidence_delta(self.candidate, self.git("rev-parse", "HEAD")))

    def test_non_ancestor_empty_missing_and_rename_do_not_reuse(self):
        self.assertFalse(reuse.evidence_delta(self.head, self.head))
        self.assertFalse(reuse.evidence_delta("f" * 40, self.head))
        self.git("mv", "runtime.go", "docs/evidence/runtime.md")
        self.git("commit", "-qm", "move")
        self.assertFalse(reuse.evidence_delta(self.head, self.git("rev-parse", "HEAD")))
        self.git("checkout", "--detach", self.base)
        other = self.commit("docs/evidence/other.md")
        self.assertFalse(reuse.evidence_delta(self.candidate, other))

    def test_evidence_deletion_is_an_evidence_delta(self):
        self.git("rm", "-r", "docs")
        self.git("commit", "-qm", "delete")
        self.assertTrue(reuse.evidence_delta(self.head, self.git("rev-parse", "HEAD")))

    def test_cli_without_actions_context_falls_back_to_full_validation(self):
        result = subprocess.run(["python3", str(SCRIPT)], capture_output=True, text=True,
                                env={"PATH": os.environ["PATH"]})
        self.assertEqual(0, result.returncode)
        self.assertIn("evidence_only=false", result.stdout)


if __name__ == "__main__":
    unittest.main()
