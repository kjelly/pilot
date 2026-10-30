"""checkout_preflight.py: every silent-loss case stops, the controls pass.

Every test drives the real command line against a scratch git repository. A
STOP test also asserts the premise: what plain `git switch` would have done to
the file the preflight protects, so a passing test proves the refusal is for
the intended reason and not for some unrelated check.
"""
import json
import subprocess
import sys
import unittest
from pathlib import Path

from gitrepo import Repo

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "checkout_preflight.py"


def preflight(repo, target, branch=None, cwd=None):
    cmd = [sys.executable, "-I", str(SCRIPT), "--repo", str(cwd or repo.path),
           "--target-ref", target]
    if branch:
        cmd += ["--branch", branch]
    p = subprocess.run(cmd, capture_output=True, text=True, env=repo.env)
    return p.returncode, json.loads(p.stdout) if p.stdout.strip() else None


def checks(report):
    return sorted(p["check"] for p in report["problems"])


class IgnoredFileCollisions(unittest.TestCase):
    def ignored_local_cfg(self):
        """main ignores local.cfg; branch `pr` force-tracks it; the user has their own."""
        r = Repo(self)
        r.write(".gitignore", "local.cfg\nbuild/\n")
        r.write("a.txt")
        r.commit("init")
        r.branch_from_main("pr")
        r.write("local.cfg", "tracked by pr\n")
        r.commit("force-track", "-f", "local.cfg")
        r.git("switch", "-q", "main")
        mine = r.write("local.cfg", "MY LOCAL SETTINGS\n")
        self.assertEqual("", r.out("status", "--porcelain"), "ignored file must not show")
        return r, mine

    def test_premise_plain_git_switch_silently_destroys_ignored_files(self):
        r, mine = self.ignored_local_cfg()
        r.git("switch", "-q", "pr")  # no error, no warning
        self.assertEqual("tracked by pr\n", mine.read_text())
        r.git("switch", "-q", "main")
        self.assertFalse(mine.exists(), "switching back deletes the user's file for good")

    def test_ignored_file_tracked_by_target_stops(self):
        r, mine = self.ignored_local_cfg()
        head = r.out("rev-parse", "HEAD")
        rc, report = preflight(r, "pr", "pr")
        self.assertEqual(1, rc)
        self.assertEqual("STOP", report["status"])
        self.assertEqual(["ignored_collision"], checks(report))
        self.assertEqual(["local.cfg"], report["problems"][0]["paths"])
        self.assertEqual("MY LOCAL SETTINGS\n", mine.read_text(), "preflight is read-only")
        self.assertEqual(head, r.out("rev-parse", "HEAD"))

    def test_ignored_file_where_target_tracks_a_directory_stops(self):
        r = Repo(self)
        r.write(".gitignore", "a\n")
        r.write("keep.txt")
        r.commit("init")
        r.branch_from_main("pr")
        r.write("a/b", "tracked\n")
        r.commit("dir a", "-f", "a/b")
        r.git("switch", "-q", "main")
        mine = r.write("a", "MY FILE\n")
        self.assertEqual("", r.out("status", "--porcelain"))
        rc, report = preflight(r, "pr", "pr")
        self.assertEqual(1, rc)
        self.assertEqual(["ignored_collision"], checks(report))
        self.assertEqual(["a"], report["problems"][0]["paths"])
        self.assertIn("below that path", report["problems"][0]["detail"])
        self.assertTrue(mine.is_file(), "preflight is read-only")
        # premise: plain git removes the ignored file to make room for the directory
        r.git("switch", "-q", "pr")
        self.assertTrue((r.path / "a").is_dir(), "the ignored file was replaced by the directory")

    def test_ignored_directory_where_target_tracks_a_file_stops(self):
        r = Repo(self)
        r.write(".gitignore", "a/\n")
        r.write("keep.txt")
        r.commit("init")
        r.branch_from_main("pr")
        r.write("a", "now a file\n")
        r.commit("file a")
        r.git("switch", "-q", "main")
        inner = r.write("a/b", "MY NOTES\n")
        self.assertEqual("", r.out("status", "--porcelain"))
        rc, report = preflight(r, "pr", "pr")
        self.assertEqual(1, rc)
        self.assertEqual(["ignored_collision"], checks(report))
        self.assertEqual(["a"], report["problems"][0]["paths"])
        self.assertIn("below this path", report["problems"][0]["detail"])
        self.assertTrue(inner.is_file(), "preflight is read-only")
        # premise: plain git deletes the ignored directory's files
        r.git("switch", "-q", "pr")
        self.assertFalse(inner.exists())

    def test_unrelated_ignored_files_pass(self):
        """Control: ignored files the target branch does not touch are fine."""
        r = Repo(self)
        r.write(".gitignore", "build/\n*.log\n")
        r.write("a.txt")
        r.commit("init")
        r.branch_from_main("pr")
        r.write("feature.txt")
        r.write("docs/a/b.md")
        r.commit("feature")
        r.git("switch", "-q", "main")
        r.write("build/out.o")
        r.write("run.log")
        r.write("docs/scratch.log")  # ignored file inside a directory the target adds
        r.write(".git/info/exclude", ".pr-ready/\n")
        r.write(".pr-ready/123/evidence.json", "{}\n")
        self.assertEqual("", r.out("status", "--porcelain"))
        rc, report = preflight(r, "pr", "pr")
        self.assertEqual((0, "PASS", []), (rc, report["status"], report["problems"]))

    def test_same_path_collision_is_found_among_many_ignored_files(self):
        r = Repo(self)
        r.write(".gitignore", "build/\n")
        r.write("a.txt")
        r.commit("init")
        r.branch_from_main("pr")
        r.write("build/gen/target.h", "tracked\n")
        r.commit("force-track generated header", "-f", "build/gen/target.h")
        r.git("switch", "-q", "main")
        for i in range(30):
            r.write(f"build/obj/{i}.o")
        r.write("build/gen/target.h", "MINE\n")
        rc, report = preflight(r, "pr", "pr")
        self.assertEqual(1, rc)
        self.assertEqual(["build/gen/target.h"], report["problems"][0]["paths"])


class OtherSilentLosses(unittest.TestCase):
    def two_branches(self):
        r = Repo(self)
        r.write("a.txt")
        r.commit("init")
        r.branch_from_main("pr")
        r.write("b.txt")
        r.commit("pr work")
        r.git("switch", "-q", "main")
        return r

    def test_clean_checkout_passes(self):
        r = self.two_branches()
        rc, report = preflight(r, "pr", "pr")
        self.assertEqual((0, "PASS"), (rc, report["status"]))
        self.assertEqual(r.out("rev-parse", "pr"), report["target"])
        self.assertEqual("main", report["current_branch"])

    def test_tracked_modification_and_untracked_file_stop(self):
        for setup in (lambda r: r.write("a.txt", "edited\n"),
                      lambda r: r.write("new-user-file.txt")):
            with self.subTest():
                r = self.two_branches()
                setup(r)
                rc, report = preflight(r, "pr", "pr")
                self.assertEqual((1, ["dirty"]), (rc, checks(report)))

    def test_branch_checked_out_in_another_worktree_stops(self):
        r = self.two_branches()
        other = r.base / "other"
        r.git("worktree", "add", "-q", str(other), "pr")  # scratch repo only
        rc, report = preflight(r, "pr", "pr")
        self.assertEqual((1, ["checked_out_elsewhere"]), (rc, checks(report)))
        self.assertEqual([str(other)], report["problems"][0]["paths"])
        # git refuses too; the preflight names the other checkout before anything runs
        self.assertNotEqual(0, r.git("switch", "-q", "pr", check=False).returncode)

    def test_branch_already_checked_out_here_passes(self):
        r = self.two_branches()
        r.git("switch", "-q", "pr")
        rc, report = preflight(r, "pr", "pr")
        self.assertEqual((0, "PASS"), (rc, report["status"]))
        # another worktree on a different branch is not a conflict
        r.git("worktree", "add", "-q", str(r.base / "other"), "-b", "unrelated", "main")
        rc, report = preflight(r, "pr", "pr")
        self.assertEqual((0, "PASS"), (rc, report["status"]))

    def test_unresolvable_target_stops(self):
        r = self.two_branches()
        rc, report = preflight(r, "refs/remotes/origin/not-fetched", "pr")
        self.assertEqual((1, ["unresolvable_target"]), (rc, checks(report)))

    def test_detached_head_on_an_orphaned_commit_stops(self):
        r = self.two_branches()
        r.git("switch", "-q", "--detach", "main")
        r.write("scratch.txt", "work\n")
        r.commit("detached work")
        rc, report = preflight(r, "pr", "pr")
        self.assertEqual((1, ["detached_head_unreachable"]), (rc, checks(report)))
        # premise: git only prints a warning after the fact
        self.assertEqual(0, r.git("switch", "-q", "pr").returncode)

    def test_detached_head_that_a_branch_contains_passes(self):
        r = self.two_branches()
        r.git("switch", "-q", "--detach", "main")
        rc, report = preflight(r, "pr", "pr")
        self.assertEqual((0, "PASS"), (rc, report["status"]))

    def test_rebase_in_progress_stops(self):
        r = self.two_branches()
        r.git("switch", "-q", "pr")
        r.write("c.txt")
        r.commit("second pr commit")
        env = dict(r.env, GIT_SEQUENCE_EDITOR="sed -i 's/^pick/edit/'")
        stopped = subprocess.run(["git", "-C", str(r.path), "rebase", "-i", "main"],
                                 capture_output=True, text=True, env=env)
        self.assertEqual(0, stopped.returncode, stopped.stderr)
        self.assertEqual("", r.out("status", "--porcelain"), "clean tree, rebase stopped at edit")
        rc, report = preflight(r, "main", "main")
        self.assertEqual((1, ["operation_in_progress"]), (rc, checks(report)))

    def test_not_a_repository_fails_closed(self):
        r = self.two_branches()
        outside = r.base / "not-a-repo"
        outside.mkdir()
        rc, report = preflight(r, "pr", "pr", cwd=outside)
        self.assertEqual((1, ["unverifiable"]), (rc, checks(report)))

    def test_missing_target_argument_is_not_a_pass(self):
        p = subprocess.run([sys.executable, "-I", str(SCRIPT)], capture_output=True, text=True)
        self.assertNotEqual(0, p.returncode)


if __name__ == "__main__":
    unittest.main()
