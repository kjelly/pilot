"""Real Git history plus mocked GitHub artifact/API boundary tests."""
import copy
from datetime import datetime, timedelta, timezone
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
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
        self.candidate = self.commit("runtime.go")
        self.head = self.commit("docs/evidence/a space\nand newline.md")
        self.ctx = {"schema_version": 1, "repository": "acme/repo", "pr_number": 7,
                    "base_sha": self.base, "head_sha": self.head, "validation": "full"}
        self.run = {"id": 11, "run_attempt": 1, "workflow_id": 22, "status": "completed",
                    "created_at": (datetime.now(timezone.utc) - timedelta(minutes=30)).isoformat(),
                    "conclusion": "success", "event": "pull_request", "head_sha": self.candidate,
                    "head_repository": {"full_name": "acme/repo"}}
        self.receipt = {**self.ctx, "head_sha": self.candidate, "run_id": 11,
                        "run_attempt": 1, "workflow_id": 22}
        self.artifact = {"name": "ci-validation-1", "expired": False, "id": 99, "size_in_bytes": 1000}

    def git(self, *args):
        return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL).decode().strip()

    def commit(self, path, content="record"):
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)
        self.git("add", ".")
        self.git("commit", "-qm", "change")
        return self.git("rev-parse", "HEAD")

    def api(self, path, binary=False):
        if path.endswith("/runs/100"):
            return {"workflow_id": 22}
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

    def test_changed_identity_or_non_full_receipt_never_reuses(self):
        for key, value in [("base_sha", "a" * 40), ("pr_number", 8), ("repository", "fork/repo"),
                           ("run_attempt", 2), ("head_sha", self.base), ("validation", "reused"),
                           ("workflow_id", 23), ("schema_version", 2), ("run_id", 12)]:
            with self.subTest(key=key):
                saved = copy.deepcopy(self.receipt)
                self.receipt[key] = value
                self.assertIsNone(self.find())
                self.receipt = saved

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

    def test_old_validation_is_not_reused(self):
        self.run["created_at"] = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
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
