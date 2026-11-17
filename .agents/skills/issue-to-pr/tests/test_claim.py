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
        for members in (("354",), ("142", "142"), ("0",)):
            with self.subTest(members=members):
                args = [x for m in members for x in ("--member", m)]
                self.claim("acquire", *self.target(354), "--skill", "issue-to-pr", *args, expect=2)
        self.claim("acquire", *self.target(148, "--pr"), "--skill", "pr-ready", "--no-gh", "--member", "1", expect=2)

    # ------------------------------------------------------------------ umbrella mode (V3, V4)

    def claim_files(self):
        return sorted(p.name for p in (self.root / "claims").glob("*/*.json"))

    def group(self, *extra, expect=0, umbrella=354, members=(142, 216)):
        args = [x for m in members for x in ("--member", str(m))]
        return self.claim("acquire", *self.target(umbrella), "--skill", "issue-to-pr", *args, *extra, expect=expect)

    def test_v3_a_group_claim_is_one_file(self):
        got = self.group()
        self.assertEqual("CLAIMED", got["status"])
        self.assertEqual([142, 216], got["claim"]["members"])
        self.assertEqual(["issue-354.json"], self.claim_files())

    def test_v3_any_held_member_refuses_the_whole_group(self):
        for name, setup, number in (
                ("a member claimed alone", lambda: self.claim("acquire", *self.target(216), "--skill", "issue-to-pr"), 216),
                ("a member in another umbrella", lambda: self.group(umbrella=400, members=(142,)), 142),
                ("the umbrella is a member elsewhere", lambda: self.group(umbrella=401, members=(354,)), 354)):
            with self.subTest(name):
                for f in (self.root / "claims").glob("*/*.json"):
                    f.unlink()
                setup()
                before = self.claim_files()
                blocked = self.group(expect=3)
                self.assertEqual(("CONFLICT", number), (blocked["status"], blocked["number"]))
                self.assertEqual(before, self.claim_files(), "nothing was written")
                taken = self.group("--takeover", expect=3)
                self.assertEqual("CONFLICT", taken["status"], "--takeover never covers another claim's members")

    def test_v3_a_member_branch_refuses_the_group(self):
        self.push_branch("fix/216-other-session")
        blocked = self.group(expect=3)
        self.assertEqual(("REMOTE_BRANCH", 216), (blocked["conflicts"][0]["type"], blocked["conflicts"][0]["number"]))
        self.assertEqual([], self.claim_files())
        self.push_branch("issue/354-142-216-umbrella")
        ok = self.group("--branch", "issue/354-142-216-umbrella", "--allow-branch", "fix/216-other-session")
        self.assertEqual("CLAIMED", ok["status"])

    def test_v3_a_single_acquire_of_a_member_conflicts(self):
        first = self.group()
        blocked = self.claim("acquire", *self.target(142), "--skill", "issue-to-pr", expect=3)
        self.assertEqual(("CONFLICT", 142), (blocked["status"], blocked["number"]))
        self.assertEqual(354, blocked["claim"]["number"])
        self.assertEqual(["issue-354.json"], self.claim_files())
        self.assertEqual("RELEASED", self.claim("release", *self.target(354), "--token", first["token"])["status"])
        self.assertEqual("CLAIMED", self.claim("acquire", *self.target(142), "--skill", "issue-to-pr")["status"])

    def test_v3_the_umbrella_branch_names_its_members(self):
        """Once the claim expires, the branch issue/<U>-<members>-<slug> still stops a session on a member."""
        self.push_branch("issue/354-142-216-umbrella")
        blocked = self.claim("acquire", *self.target(216), "--skill", "issue-to-pr", expect=3)
        self.assertEqual("REMOTE_BRANCH", blocked["conflicts"][0]["type"])

    def test_v3_a_failed_write_leaves_no_claim(self):
        directory = self.root / "claims" / "acme__demo"
        directory.mkdir(parents=True)
        (directory / ".lock").touch()  # the lock still opens: the claim write itself fails
        directory.chmod(0o500)
        self.addCleanup(directory.chmod, 0o700)
        if os.access(directory, os.W_OK):
            self.skipTest("running as a user who can write a read-only directory")
        failed = self.group(expect=2)
        self.assertEqual("ERROR", failed["status"])
        self.assertIn("nothing was claimed", failed["error"])
        directory.chmod(0o700)
        self.assertEqual([], [p.name for p in directory.iterdir() if p.name != ".lock"])
        (directory / ".lock").unlink()
        directory.chmod(0o500)  # now the lock itself cannot be opened
        self.assertEqual("ERROR", self.group(expect=2)["status"], "an unusable claim directory is no traceback")

    def test_v4_renew_release_and_check_cover_the_whole_group(self):
        first = self.group()
        token = first["token"]
        for n in (354, 142, 216):
            with self.subTest(n=n):
                other = self.claim("check", *self.target(n), expect=3)
                self.assertEqual(("CLAIMED_BY_OTHER", 354), (other["status"], other["claim"]["number"]))
                self.assertEqual("MINE", self.claim("check", *self.target(n), "--token", token)["status"])
        self.assertEqual("RENEWED", self.claim("renew", *self.target(354), "--token", token)["status"])
        again = self.group("--token", token)
        self.assertEqual(("RENEWED", token), (again["status"], again["token"]))
        self.assertEqual("RELEASED", self.claim("release", *self.target(354), "--token", token)["status"])
        for n in (354, 142, 216):
            self.assertEqual("FREE", self.claim("check", *self.target(n))["status"])

    def test_v4_an_expired_group_claim_frees_its_members(self):
        self.group()
        f = self.root / "claims" / "acme__demo" / "issue-354.json"
        data = json.loads(f.read_text())
        data["expires_at"] = time.time() - 5
        f.write_text(json.dumps(data))
        self.assertEqual("FREE", self.claim("check", *self.target(142))["status"])
        self.assertEqual("CLAIMED", self.claim("acquire", *self.target(142), "--skill", "issue-to-pr")["status"])


if __name__ == "__main__":
    unittest.main()
