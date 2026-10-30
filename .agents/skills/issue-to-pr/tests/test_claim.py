"""claim.py: cross-session claims, branch scans and expiry. Never contacts GitHub."""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

CLAIM = Path(__file__).resolve().parents[1] / "scripts" / "claim.py"
REPO = "acme/demo"


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


class ClaimTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.env = {**os.environ, "GH_WORKFLOW_CLAIM_DIR": str(self.root / "claims")}
        origin, self.clone = self.root / "origin.git", self.root / "clone"
        git(self.root, "init", "--bare", "-q", "-b", "main", str(origin))
        git(self.root, "clone", "-q", str(origin), str(self.clone))
        for k, v in (("user.name", "t"), ("user.email", "t@example.org")):
            git(self.clone, "config", k, v)
        (self.clone / "f").write_text("x")
        git(self.clone, "add", "f")
        git(self.clone, "commit", "-q", "-m", "init")
        git(self.clone, "push", "-q", "origin", "main")

    def claim(self, *args, expect=0):
        p = subprocess.run([sys.executable, str(CLAIM), *args], cwd=self.clone, env=self.env,
                           capture_output=True, text=True)
        self.assertEqual(expect, p.returncode, p.stdout + p.stderr)
        return json.loads(p.stdout)

    def target(self, n=157, kind="--issue"):
        return ["--repo", REPO, kind, str(n)]

    def push_branch(self, name):
        git(self.clone, "push", "-q", "origin", f"HEAD:refs/heads/{name}")

    def test_second_session_is_refused_until_release(self):
        first = self.claim("acquire", *self.target(), "--skill", "issue-to-pr", "--label", "session-a")
        self.assertEqual("CLAIMED", first["status"])
        other = self.claim("acquire", *self.target(), "--skill", "issue-to-pr", "--label", "session-b", expect=3)
        self.assertEqual("CONFLICT", other["status"])
        self.assertEqual("session-a", other["claim"]["owner"]["label"])
        self.assertNotIn("token_sha256", other["claim"])
        self.assertEqual("NOT_OWNER", self.claim("release", *self.target(), "--token", "nope", expect=3)["status"])
        self.assertEqual("RELEASED", self.claim("release", *self.target(), "--token", first["token"])["status"])
        self.assertEqual("CLAIMED", self.claim("acquire", *self.target(), "--skill", "issue-to-pr")["status"])

    def test_resume_with_token_renews_and_keeps_token(self):
        first = self.claim("acquire", *self.target(), "--skill", "issue-to-pr")
        again = self.claim("acquire", *self.target(), "--skill", "issue-to-pr", "--token", first["token"])
        self.assertEqual("RENEWED", again["status"])
        self.assertEqual(first["token"], again["token"])

    def test_renew_detects_lost_or_foreign_claim(self):
        self.assertEqual("CLAIM_LOST", self.claim("renew", *self.target(), "--token", "x", expect=3)["status"])
        first = self.claim("acquire", *self.target(), "--skill", "issue-to-pr")
        self.assertEqual("NOT_OWNER", self.claim("renew", *self.target(), "--token", "wrong", expect=3)["status"])
        self.assertEqual("RENEWED", self.claim("renew", *self.target(), "--token", first["token"])["status"])

    def test_expired_claim_can_be_replaced(self):
        self.claim("acquire", *self.target(), "--skill", "issue-to-pr")
        f = self.root / "claims" / "acme__demo" / "issue-157.json"
        data = json.loads(f.read_text())
        data["expires_at"] = time.time() - 5
        f.write_text(json.dumps(data))
        again = self.claim("acquire", *self.target(), "--skill", "issue-to-pr")
        self.assertEqual("CLAIMED_AFTER_EXPIRY", again["status"])
        self.assertFalse(again["previous"]["active"])

    def test_takeover_is_explicit(self):
        self.claim("acquire", *self.target(), "--skill", "pr-ready")
        took = self.claim("acquire", *self.target(), "--skill", "pr-ready", "--takeover")
        self.assertEqual("TAKEN_OVER", took["status"])

    def test_remote_branch_for_issue_blocks_unless_it_is_yours(self):
        self.push_branch("fix/157-widget-pool")
        blocked = self.claim("acquire", *self.target(), "--skill", "issue-to-pr", expect=3)
        self.assertEqual("REMOTE_BRANCH", blocked["conflicts"][0]["type"])
        self.assertEqual([], list((self.root / "claims").glob("*/issue-157.json")))
        ok = self.claim("acquire", *self.target(), "--skill", "issue-to-pr", "--branch", "fix/157-widget-pool")
        self.assertEqual("CLAIMED", ok["status"])

    def test_branch_scan_matches_whole_numbers_only(self):
        for name in ("fix/1570-other", "release/2.157.1", "fix/9157"):
            self.push_branch(name)
        self.assertEqual("CLAIMED", self.claim("acquire", *self.target(), "--skill", "issue-to-pr")["status"])

    def test_worktree_on_same_pr_branch_conflicts(self):
        git(self.clone, "branch", "fix/146-config-sync")
        other = self.root / "other-wt"
        git(self.clone, "worktree", "add", "-q", str(other), "fix/146-config-sync")
        args = ("acquire", *self.target(148, "--pr"), "--skill", "pr-ready", "--branch", "fix/146-config-sync", "--no-gh")
        blocked = self.claim(*args, expect=3)
        self.assertEqual("LOCAL_WORKTREE", blocked["conflicts"][0]["type"])
        ok = self.claim(*args, "--worktree", str(other))
        self.assertEqual("CLAIMED", ok["status"])

    def test_check_and_list_do_not_leak_tokens(self):
        first = self.claim("acquire", *self.target(), "--skill", "issue-to-pr")
        self.assertEqual("FREE", self.claim("check", *self.target(999))["status"])
        self.assertEqual("CLAIMED_BY_OTHER", self.claim("check", *self.target(), expect=3)["status"])
        self.assertEqual("MINE", self.claim("check", *self.target(), "--token", first["token"])["status"])
        listing = self.claim("list", "--repo", REPO)
        self.assertEqual(1, len(listing["claims"]))
        self.assertNotIn(first["token"], json.dumps(listing))
        self.assertNotIn("token_sha256", listing["claims"][0])

    def test_bad_input_exits_2(self):
        self.claim("acquire", "--repo", "nope", "--issue", "1", "--skill", "pr-ready", expect=2)
        self.claim("acquire", "--repo", REPO, "--skill", "pr-ready", expect=2)


if __name__ == "__main__":
    unittest.main()
