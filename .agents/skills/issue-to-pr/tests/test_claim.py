"""claim.py: cross-session claims, branch scans and expiry. Never contacts GitHub."""
import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

CLAIM = Path(__file__).resolve().parents[1] / "scripts" / "claim.py"
REPO = "acme/demo"


def git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True)


def claim_write_violations(source):
    """Every way `source` can write a claim file without going through commit_claim under the lock."""
    tree = ast.parse(source)
    problems = []
    if not any(isinstance(n, ast.FunctionDef) and n.name == "commit_claim" for n in ast.walk(tree)):
        problems.append("there is no commit_claim")

    def called(node):
        f = node.func
        return f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None

    def visit(node, fn, locks):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            fn, locks = getattr(node, "name", "<lambda>"), 0  # a nested function runs later, outside the with
        if isinstance(node, ast.With):
            for item in node.items:
                visit(item, fn, locks)
            held = any(isinstance(i.context_expr, ast.Call) and called(i.context_expr) == "locked"
                       for i in node.items)
            for stmt in node.body:
                visit(stmt, fn, locks + held)
            return
        if isinstance(node, ast.Call) and called(node) == "commit_claim" and not locks:
            problems.append(f"line {node.lineno}: commit_claim is called outside `with locked(...)`")
        if (isinstance(node, ast.Name) and node.id == "write_claim" and fn != "commit_claim") or (
                isinstance(node, ast.Attribute) and node.attr == "write_claim"):
            problems.append(f"line {node.lineno}: write_claim is used in {fn}, not in commit_claim")
        for child in ast.iter_child_nodes(node):
            visit(child, fn, locks)

    visit(tree, "<module>", 0)
    return problems


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

    # ------------------------------------------------------------------ one live claim per number (PR #366 merge review)

    def claims_dir(self):
        return self.root / "claims" / "acme__demo"

    def snapshot(self):
        return {p.name: p.read_bytes() for p in self.claims_dir().glob("*.json")}

    def expire(self, name):
        f = self.claims_dir() / name
        data = json.loads(f.read_text())
        data["expires_at"] = time.time() - 5
        f.write_text(json.dumps(data))

    def hand(self, number, token, *, members=None, expires=None, kind="issue"):
        """A claim file written by hand, as an older version or another tool might have left it."""
        self.claims_dir().mkdir(parents=True, exist_ok=True)
        now = time.time()
        data = {"schema_version": 1, "repo": REPO, "kind": kind, "number": number, "skill": "issue-to-pr",
                "branch": None, "worktree": None, "owner": {"label": f"hand-{number}"}, "claimed_at": now,
                "renewed_at": now, "expires_at": expires if expires is not None else now + 3600,
                "token_sha256": hashlib.sha256(token.encode()).hexdigest()}
        if members is not None:
            data["members"] = members
        (self.claims_dir() / f"{kind}-{number}.json").write_text(json.dumps(data))

    def live_holders(self, n):
        """The invariant, read straight from the files: which live claims cover Issue n."""
        now, found = time.time(), []
        for f in self.claims_dir().glob("issue-*.json"):
            c = json.loads(f.read_text())
            if c["expires_at"] > now and n in {c["number"], *c.get("members", [])}:
                found.append(f.name)
        return found

    def assert_one_live_claim_per_number(self):
        for n in (142, 216, 354):
            self.assertLessEqual(len(self.live_holders(n)), 1, f"#{n}: {self.live_holders(n)}")

    def test_renew_of_an_expired_group_does_not_revive_a_reclaimed_member(self):
        first = self.group()
        self.expire("issue-354.json")
        taken = self.claim("acquire", *self.target(142), "--skill", "issue-to-pr", "--label", "session-b")
        self.assertEqual("CLAIMED", taken["status"])
        before = self.snapshot()
        got = self.claim("renew", *self.target(354), "--token", first["token"], expect=3)
        self.assertEqual("EXPIRED", got["status"])
        self.assertEqual(before, self.snapshot(), "nothing was written")
        self.assert_one_live_claim_per_number()
        self.assertEqual(["issue-142.json"], self.live_holders(142))

    def test_renew_of_an_expired_single_does_not_revive_under_a_group(self):
        first = self.claim("acquire", *self.target(142), "--skill", "issue-to-pr")
        self.expire("issue-142.json")
        self.assertEqual("CLAIMED", self.group()["status"])
        before = self.snapshot()
        got = self.claim("renew", *self.target(142), "--token", first["token"], expect=3)
        self.assertEqual("EXPIRED", got["status"])
        self.assertEqual(before, self.snapshot())
        self.assert_one_live_claim_per_number()

    def test_renew_after_a_takeover_of_a_member_while_the_group_was_expired(self):
        first = self.group()
        self.expire("issue-354.json")
        self.claim("acquire", *self.target(142), "--skill", "issue-to-pr", "--label", "session-b")
        took = self.claim("acquire", *self.target(142), "--skill", "issue-to-pr", "--label", "session-c", "--takeover")
        self.assertEqual("TAKEN_OVER", took["status"])
        before = self.snapshot()
        self.assertEqual("EXPIRED", self.claim("renew", *self.target(354), "--token", first["token"], expect=3)["status"])
        self.assertEqual(before, self.snapshot())
        self.assert_one_live_claim_per_number()

    def test_renew_after_a_member_was_acquired_and_released_in_between(self):
        """Negative control for an overlap-only check: nothing overlaps at renew time, yet the claim lapsed."""
        first = self.group()
        self.expire("issue-354.json")
        other = self.claim("acquire", *self.target(142), "--skill", "issue-to-pr")
        self.assertEqual("RELEASED", self.claim("release", *self.target(142), "--token", other["token"])["status"])
        before = self.snapshot()
        got = self.claim("renew", *self.target(354), "--token", first["token"], expect=3)
        self.assertEqual("EXPIRED", got["status"])
        self.assertEqual(before, self.snapshot())
        self.assertEqual("FREE", self.claim("check", *self.target(142))["status"], "the lapsed group is still lapsed")
        self.assertEqual("CLAIMED", self.claim("acquire", *self.target(142), "--skill", "issue-to-pr")["status"])

    def test_a_live_renew_refuses_a_number_another_live_claim_covers(self):
        """Only a hand-written (or older) overlap can reach this: the refusal is the second line of defence."""
        self.hand(142, "A")
        self.hand(354, "B", members=[142, 216])
        before = self.snapshot()
        for number, token in ((142, "A"), (354, "B")):
            got = self.claim("renew", *self.target(number), "--token", token, expect=3)
            self.assertEqual(("CONFLICT", 142), (got["status"], got["number"]))
            self.assertNotIn("token_sha256", got["claim"])
            self.assertEqual(before, self.snapshot())

    def test_check_reports_a_live_overlap_to_everyone(self):
        self.hand(142, "A")
        self.hand(354, "B", members=[142, 216])
        for token in (None, "A", "B"):
            args = ["--token", token] if token else []
            got = self.claim("check", *self.target(142), *args, expect=3)
            self.assertEqual("OVERLAP", got["status"])
            self.assertEqual([142, 354], sorted(c["number"] for c in got["claims"]))
            self.assertNotIn("token_sha256", json.dumps(got))
        self.assertEqual("MINE", self.claim("check", *self.target(216), "--token", "B")["status"])

    def test_acquire_with_a_token_on_an_expired_issue_claim_is_a_new_claim(self):
        first = self.group()
        self.expire("issue-354.json")
        again = self.group("--token", first["token"])
        self.assertEqual("CLAIMED_AFTER_EXPIRY", again["status"])
        self.assertNotEqual(first["token"], again["token"])
        self.assertFalse(again["previous"]["active"])
        self.assertEqual("NOT_OWNER", self.claim("renew", *self.target(354), "--token", first["token"], expect=3)["status"])
        self.assertEqual("RENEWED", self.claim("renew", *self.target(354), "--token", again["token"])["status"])

    def test_acquire_with_a_token_on_an_expired_claim_scans_branches_again(self):
        for members, number in (((142, 216), 354), ((), 157)):
            with self.subTest(number=number):
                for f in self.claims_dir().glob("*.json") if self.claims_dir().is_dir() else []:
                    f.unlink()
                first = self.group(umbrella=number, members=members)
                self.expire(f"issue-{number}.json")
                self.push_branch(f"fix/{(members or (number,))[0]}-someone-else")
                before = self.snapshot()
                blocked = self.group("--token", first["token"], expect=3, umbrella=number, members=members)
                self.assertEqual("CONFLICT", blocked["status"])
                self.assertEqual("REMOTE_BRANCH", blocked["conflicts"][0]["type"])
                self.assertEqual(before, self.snapshot())

    def test_resume_with_a_token_keeps_the_members(self):
        first = self.group()
        resumed = self.claim("acquire", *self.target(354), "--skill", "issue-to-pr", "--token", first["token"])
        self.assertEqual(("RENEWED", first["token"], [142, 216]),
                         (resumed["status"], resumed["token"], resumed["claim"]["members"]))
        blocked = self.claim("acquire", *self.target(142), "--skill", "issue-to-pr", expect=3)
        self.assertEqual(("CONFLICT", 142), (blocked["status"], blocked["number"]))
        self.assertEqual("RENEWED", self.group("--token", first["token"])["status"], "the same set is accepted")

    def test_resume_with_a_different_member_set_is_refused(self):
        first = self.group()
        before = self.snapshot()
        for members in ((142,), (142, 216, 300), (142, 300)):
            with self.subTest(members=members):
                got = self.group("--token", first["token"], expect=2, members=members)
                self.assertEqual("ERROR", got["status"])
                self.assertIn("Release the claim and acquire again", got["error"])
                self.assertEqual(before, self.snapshot())
        single = self.claim("acquire", *self.target(157), "--skill", "issue-to-pr")
        before = self.snapshot()
        self.assertEqual("ERROR", self.group("--token", single["token"], expect=2, umbrella=157, members=(142,))["status"])
        self.assertEqual(before, self.snapshot())

    def test_an_own_token_on_another_file_is_no_exemption(self):
        mine = self.claim("acquire", *self.target(142), "--skill", "issue-to-pr")
        before = self.snapshot()
        got = self.group("--token", mine["token"], expect=3)
        self.assertEqual(("CONFLICT", 142), (got["status"], got["number"]))
        self.assertIn("your own claim", got["hint"])
        self.assertEqual(before, self.snapshot())
        for f in self.claims_dir().glob("*.json"):
            f.unlink()
        grouped = self.group()
        before = self.snapshot()
        got = self.claim("acquire", *self.target(142), "--skill", "issue-to-pr", "--token", grouped["token"], expect=3)
        self.assertEqual(("CONFLICT", 142), (got["status"], got["number"]))
        self.assertEqual(before, self.snapshot())
        self.assert_one_live_claim_per_number()

    def test_takeover_replaces_only_its_own_number(self):
        first = self.claim("acquire", *self.target(157), "--skill", "issue-to-pr")
        took = self.claim("acquire", *self.target(157), "--skill", "issue-to-pr", "--takeover")
        self.assertEqual("TAKEN_OVER", took["status"])
        self.assertEqual("NOT_OWNER", self.claim("renew", *self.target(157), "--token", first["token"], expect=3)["status"])
        self.assertEqual("RENEWED", self.claim("renew", *self.target(157), "--token", took["token"])["status"])
        # a member that another claim holds is never covered by a takeover, whichever claim holds it
        held = self.claim("acquire", *self.target(216), "--skill", "issue-to-pr")
        before = self.snapshot()
        got = self.claim("acquire", *self.target(157), "--skill", "issue-to-pr", "--takeover", "--member", "216", expect=3)
        self.assertEqual(("CONFLICT", 216), (got["status"], got["number"]))
        self.assertEqual(before, self.snapshot())
        self.assertEqual("RENEWED", self.claim("renew", *self.target(216), "--token", held["token"])["status"])
        # ... and a token of yours on that other claim does not make it yours to cover
        before = self.snapshot()
        got = self.claim("acquire", *self.target(157), "--skill", "issue-to-pr", "--takeover", "--member", "216",
                         "--token", held["token"], expect=3)
        self.assertEqual(("CONFLICT", 216), (got["status"], got["number"]))
        self.assertEqual(before, self.snapshot())

    def test_malformed_members_fail_closed(self):
        for members in (["142"], [0], [-1], [142, 142], [354], "142", 142, [True], [1.5]):
            with self.subTest(members=members):
                for f in self.claims_dir().glob("*.json") if self.claims_dir().is_dir() else []:
                    f.unlink()
                self.hand(354, "A", members=members)
                for argv in (("check", *self.target(354)), ("check", *self.target(142)),
                             ("renew", *self.target(354), "--token", "A"),
                             ("acquire", *self.target(142), "--skill", "issue-to-pr")):
                    got = self.claim(*argv, expect=2)
                    self.assertEqual("ERROR", got["status"])
                    self.assertIn("members", got["error"])
        (self.claims_dir() / "issue-354.json").write_text("{not json")
        self.assertEqual("ERROR", self.claim("check", *self.target(142), expect=2)["status"])

    def test_a_pr_claim_still_revives_after_expiry(self):
        """PR claims keep their base behaviour (pr-ready relies on it): no members, one file per number."""
        args = (*self.target(148, "--pr"), "--skill", "pr-ready", "--no-gh")
        first = self.claim("acquire", *args)
        self.expire("pr-148.json")
        self.assertEqual("RENEWED", self.claim("renew", *self.target(148, "--pr"), "--token", first["token"])["status"])
        self.expire("pr-148.json")
        again = self.claim("acquire", *args, "--token", first["token"])
        self.assertEqual(("RENEWED", first["token"]), (again["status"], again["token"]))
        self.assertTrue(again["claim"]["active"])

    def test_expiry_boundary_is_expired(self):
        """expires_at == now is expired. In-process, with a frozen clock, so the boundary is exact."""
        spec = importlib.util.spec_from_file_location("claim_under_test", CLAIM)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        def run(clock, *argv):
            out = io.StringIO()
            with mock.patch.dict(os.environ, self.env), mock.patch("time.time", return_value=clock), \
                    contextlib.redirect_stdout(out):
                code = mod.main([*argv, "--repo", REPO, "--issue", "157"])
            return code, json.loads(out.getvalue())

        t0 = 1_900_000_000.0
        code, got = run(t0, "acquire", "--skill", "issue-to-pr", "--ttl-minutes", "1", "--git-dir", str(self.clone))
        self.assertEqual((0, "CLAIMED"), (code, got["status"]))
        token, expires = got["token"], t0 + 60
        git_dir = ["--git-dir", str(self.clone)]
        code, got = run(expires, "renew", "--token", token)
        self.assertEqual((3, "EXPIRED"), (code, got["status"]))
        self.assertEqual("EXPIRED", run(expires, "check", *git_dir, "--token", token)[1]["status"])
        self.assertEqual("MINE", run(expires - 0.001, "check", *git_dir, "--token", token)[1]["status"])
        code, got = run(expires - 0.001, "renew", "--token", token)
        self.assertEqual((0, "RENEWED"), (code, got["status"]))

    def test_claim_files_are_written_only_by_commit_claim_under_the_lock(self):
        source = CLAIM.read_text()
        self.assertEqual([], claim_write_violations(source))
        renew = source.index("def cmd_renew")
        for label, mutant in (
                ("renew writes directly", source[:renew] + source[renew:].replace(
                    "refused = commit_claim(directory, path, claim, now)", "refused = write_claim(path, claim)", 1)),
                ("acquire writes directly", source.replace(
                    "refused = commit_claim(directory, path, claim, now)", "refused = write_claim(path, claim)", 1)),
                ("write_claim is handed around", source.replace("refused = commit_claim(", "refused = (write_claim, commit_claim)[1](", 1)),
                ("commit_claim outside the lock", "def locked(d):\n    pass\n\ndef commit_claim(d, p, c, n):\n"
                 "    write_claim(p, c)\n\ndef cmd(d, p, c, n):\n    commit_claim(d, p, c, n)\n"),
                ("commit_claim in a function nested in the lock", "def commit_claim(d, p, c, n):\n    write_claim(p, c)\n\n"
                 "def cmd(d, p, c, n):\n    with locked(d):\n        def later():\n            commit_claim(d, p, c, n)\n")):
            with self.subTest(label):
                self.assertNotEqual([], claim_write_violations(mutant), "the lint must fire")
        self.assertEqual([], claim_write_violations(
            "def commit_claim(d, p, c, n):\n    write_claim(p, c)\n\n"
            "def cmd(d, p, c, n):\n    with locked(d):\n        commit_claim(d, p, c, n)\n"))


if __name__ == "__main__":
    unittest.main()
