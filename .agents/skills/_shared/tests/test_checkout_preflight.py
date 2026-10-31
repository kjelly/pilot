"""checkout_preflight.py: every silent-loss case stops, the controls pass, landing is exact.

Every test drives the real command line against a scratch git repository. A STOP test also
asserts the premise: what the plain git command would have done to the file the script
protects, so a passing test proves the refusal is for the intended reason.
"""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from gitrepo import Repo, load_module

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "checkout_preflight.py"
PR_GATE = Path(__file__).resolve().parents[2] / "pr-ready" / "scripts" / "pr_gate.py"
ORIGIN = ("--remote", "origin", "--merge", "refs/heads/pr")


def stale_world(case):
    """origin/pr was P1 (it tracks local.cfg) when `work` cloned it, and is P2 (the PR head,
    which does not) now: work's origin/pr is stale. The user's ignored local.cfg is on main."""
    seed = Repo(case, "seed")
    seed.write(".gitignore", "local.cfg\n")
    seed.write("README", "base\n")
    a = seed.commit("A")
    origin = seed.add_origin()
    seed.branch_from_main("pr")
    seed.write("local.cfg", "TRACKED-BY-STALE-TIP\n")
    seed.write("p", "p1\n")
    p1 = seed.commit("P1", "-f", "local.cfg", "p")
    seed.git("push", "-q", "origin", "pr")
    work = Repo(case, "work", clone_of=origin)
    seed.git("rm", "-q", "--cached", "local.cfg")
    (seed.path / "local.cfg").unlink()
    seed.write("p", "p2\n")
    p2 = seed.commit("P2")
    seed.git("push", "-q", "origin", "pr")
    subprocess.run(["git", "--git-dir", str(origin), "update-ref", "refs/pull/1/head", p2], check=True,
                   env=seed.env)
    work.git("fetch", "-q", "origin", "refs/pull/1/head")
    assert work.out("rev-parse", "FETCH_HEAD") == p2 and work.out("rev-parse", "origin/pr") == p1
    mine = work.write("local.cfg", "USER-SECRET\n")
    return SimpleNamespace(seed=seed, work=work, origin=origin, a=a, p1=p1, p2=p2, mine=mine)


def sha(repo, ref):
    return ref if len(ref) == 40 else repo.out("rev-parse", ref + "^{commit}")


def preflight(repo, target, branch=None, cwd=None, *extra):
    """Dry run for `target` (a ref name or a full SHA); extra arguments go to the command line."""
    cmd = [sys.executable, "-I", str(SCRIPT), "--repo", str(cwd or repo.path), "--target", sha(repo, target)]
    cmd += [f"--branch={branch}"] if branch is not None else []
    p = subprocess.run(cmd + list(extra), capture_output=True, text=True, env=repo.env)
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

    def test_already_on_the_branch_at_the_target_needs_no_switch(self):
        r = self.two_branches()
        r.git("switch", "-q", "pr")
        rc, report = preflight(r, "pr", "pr")
        self.assertEqual((0, "PASS", "none", []), (rc, report["status"], report["action"], report["commands"]))

    def test_another_worktree_on_a_different_branch_is_not_a_conflict(self):
        r = self.two_branches()
        r.git("worktree", "add", "-q", str(r.base / "other"), "-b", "unrelated", "main")
        rc, report = preflight(r, "pr", "pr")
        self.assertEqual((0, "PASS"), (rc, report["status"]))

    def test_unresolvable_target_stops(self):
        r = self.two_branches()
        rc, report = preflight(r, "0" * 40, "pr")
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

    def test_only_a_full_sha_is_accepted_as_the_target(self):
        """A name or abbreviation would be re-resolved by git at run time: an argument error."""
        r = self.two_branches()
        full = r.out("rev-parse", "pr")
        for bad in ("pr", "refs/heads/pr", full[:12], full.upper(), ""):
            p = subprocess.run([sys.executable, "-I", str(SCRIPT), "--repo", str(r.path), "--target", bad],
                               capture_output=True, text=True, env=r.env)
            self.assertEqual(2, p.returncode, bad)
        p = subprocess.run([sys.executable, "-I", str(SCRIPT), "--repo", str(r.path)],
                           capture_output=True, text=True, env=r.env)
        self.assertEqual(2, p.returncode)


class NestedRepositories(unittest.TestCase):
    """`git ls-files -o -i` lists an ignored nested repository as one `dir/` entry."""

    def nested_vendor(self):
        """main ignores vendor/x/ (a nested repo with its own file); branch pr force-tracks vendor/x/file."""
        r = Repo(self)
        r.write(".gitignore", "vendor/x/\nbuild/\n")
        r.write("a.txt")
        r.commit("init")
        r.branch_from_main("pr")
        r.write("vendor/x/file", "tracked by pr\n")
        r.commit("track vendor/x/file", "-f", "vendor/x/file")
        r.git("switch", "-q", "main")
        r.nested("vendor/x", file="MY NESTED REPO FILE\n")
        self.assertEqual("", r.out("status", "--porcelain"), "the nested repo is ignored")
        listed = r.out("ls-files", "--others", "--ignored", "--exclude-standard")
        self.assertEqual("vendor/x/", listed, "the premise: one directory-shaped entry")
        return r

    def test_target_tracking_a_path_inside_an_ignored_nested_repo_stops(self):
        r = self.nested_vendor()
        rc, report = preflight(r, "pr", "pr")
        self.assertEqual((1, ["ignored_collision"]), (rc, checks(report)))
        self.assertEqual(["vendor/x/file"], report["problems"][0]["paths"])
        self.assertIn("nested repository", report["problems"][0]["detail"])
        self.assertEqual("MY NESTED REPO FILE\n", (r.path / "vendor/x/file").read_text())
        # premise: plain git writes into the nested repo and replaces the user's file
        r.git("switch", "-q", "pr")
        self.assertEqual("tracked by pr\n", (r.path / "vendor/x/file").read_text())

    def test_nested_repo_elsewhere_is_not_a_collision(self):
        """Control: the same ignored nested repo, but the target tracks nothing below it."""
        r = self.nested_vendor()
        r.git("switch", "-q", "pr")
        r.git("rm", "-q", "--cached", "vendor/x/file")  # pr's tracked file moves elsewhere
        r.write("vendor/y/file", "elsewhere\n")
        r.commit("move it", "-f", "vendor/y/file")
        r.git("switch", "-q", "main")
        rc, report = preflight(r, "pr", "pr")
        self.assertEqual((0, "PASS", []), (rc, report["status"], report["problems"]))

    def test_nested_repo_inside_an_ignored_directory_stops(self):
        r = Repo(self)
        r.write(".gitignore", "build/\n")
        r.write("a.txt")
        r.commit("init")
        r.branch_from_main("pr")
        r.write("build/dep/g", "tracked\n")
        r.commit("force-track", "-f", "build/dep/g")
        r.git("switch", "-q", "main")
        r.nested("build/dep", g="MINE\n")
        r.write("build/obj/1.o")
        self.assertEqual(["build/dep/", "build/obj/1.o"],
                         r.out("ls-files", "--others", "--ignored", "--exclude-standard").split("\n"))
        rc, report = preflight(r, "pr", "pr")
        self.assertEqual((1, ["ignored_collision"]), (rc, checks(report)))
        self.assertEqual(["build/dep/g"], report["problems"][0]["paths"])

    def test_target_file_where_an_ignored_nested_repo_stands_stops(self):
        """The reverse direction: the target tracks a file at the nested repo's path or above it."""
        for tracked in ("vendor/x", "vendor"):
            with self.subTest(tracked=tracked):
                r = Repo(self)
                r.write(".gitignore", "vendor/\n")
                r.write("a.txt")
                r.commit("init")
                r.branch_from_main("pr")
                r.write(tracked, "a file now\n")
                r.commit("file where the nested repo will be", "-f", tracked)
                r.git("switch", "-q", "main")
                r.nested("vendor/x", file="MINE\n")
                rc, report = preflight(r, "pr", "pr")
                self.assertEqual((1, ["ignored_collision"]), (rc, checks(report)))
                self.assertEqual([tracked], report["problems"][0]["paths"])
                self.assertTrue((r.path / "vendor/x/file").is_file(), "preflight is read-only")


class OddPathsAndSubmodules(unittest.TestCase):
    ODD = ("with space.cfg", "new\nline.cfg", "設定.cfg", "dir with space/inner file.cfg",
           "tab\there.cfg")

    def test_collisions_on_paths_with_spaces_newlines_and_unicode(self):
        r = Repo(self)
        r.write(".gitignore", "*.cfg\n")
        r.write("a.txt")
        r.commit("init")
        r.branch_from_main("pr")
        for name in self.ODD:
            r.write(name, "tracked\n")
        r.git("add", "-f", "--", *self.ODD)
        r.git("commit", "-q", "-m", "odd names")
        r.git("switch", "-q", "main")
        for name in self.ODD:
            r.write(name, "MINE\n")
        self.assertEqual("", r.out("status", "--porcelain"))
        rc, report = preflight(r, "pr", "pr")
        self.assertEqual((1, ["ignored_collision"]), (rc, checks(report)))
        self.assertEqual(sorted(self.ODD), report["problems"][0]["paths"])
        self.assertEqual(len(self.ODD), report["problems"][0]["count"])

    def test_odd_named_ignored_files_the_target_does_not_track_pass(self):
        """Control: the same odd names, ignored, with nothing tracked at them."""
        r = Repo(self)
        r.write(".gitignore", "*.cfg\n")
        r.write("a.txt")
        r.commit("init")
        r.branch_from_main("pr")
        r.write("feature.txt")
        r.commit("feature")
        r.git("switch", "-q", "main")
        for name in self.ODD:
            r.write(name, "MINE\n")
        rc, report = preflight(r, "pr", "pr")
        self.assertEqual((0, "PASS"), (rc, report["status"]))

    def submodule_repo(self):
        sub = Repo(self, "sub")
        sub.write("f", "1\n")
        sub.commit("sub init")
        r = Repo(self, "par")
        r.write("a.txt")
        r.commit("init")
        r.git("-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub.path), "sub")
        r.commit("add submodule")
        r.branch_from_main("pr")
        r.write("b.txt")
        r.commit("pr work")
        r.git("switch", "-q", "main")
        return r

    def test_dirty_submodule_is_not_hidden_by_ignore_configuration(self):
        for hide in (("config", "diff.ignoreSubmodules", "all"),
                     ("config", "-f", ".gitmodules", "submodule.sub.ignore", "all")):
            with self.subTest(hide=hide[1:]):
                r = self.submodule_repo()
                rc, clean = preflight(r, "pr", "pr")
                self.assertEqual((0, "PASS"), (rc, clean["status"]), "control: clean submodule")
                (r.path / "sub" / "f").write_text("edited inside the submodule\n")
                r.git(*hide)
                if hide[1] == "-f":
                    r.git("add", ".gitmodules")  # keep only the submodule edit unstaged
                    r.git("commit", "-q", "-m", "hide")
                    (r.path / "sub" / "f").write_text("edited inside the submodule\n")
                self.assertEqual("", r.out("status", "--porcelain"), "the setting hides it from status")
                rc, report = preflight(r, "pr", "pr")
                self.assertEqual((1, ["dirty"]), (rc, checks(report)))


class Land(unittest.TestCase):
    """The landing commands re-resolve names at run time; --execute lands on exactly one SHA."""

    def land(self, w, target, branch, *extra):
        return preflight(w.work, target, branch, None, *extra, "--execute")

    def test_lands_on_the_verified_sha_not_on_the_stale_remote_tracking_ref(self):
        w = stale_world(self)
        rc, dry = preflight(w.work, w.p2, "pr", None, *ORIGIN)
        self.assertEqual((0, "create"), (rc, dry["action"]))
        self.assertEqual(("main", "USER-SECRET\n"), (w.work.out("branch", "--show-current"), w.mine.read_text()),
                         "the dry run changes nothing")
        rc, done = self.land(w, w.p2, "pr", *ORIGIN)
        self.assertEqual((0, "PASS", w.p2, "pr"), (rc, done["status"], done["head"], done["current_branch"]))
        self.assertEqual("USER-SECRET\n", w.mine.read_text())
        self.assertEqual(w.p2, w.work.out("rev-parse", "pr"))
        self.assertEqual(("origin", "refs/heads/pr"), (w.work.out("config", "branch.pr.remote"),
                                                       w.work.out("config", "branch.pr.merge")))
        self.assertEqual("", w.work.out("status", "--porcelain"))

    def test_the_old_landing_loses_the_file_and_a_target_tracking_it_still_stops(self):
        w = stale_world(self)  # premise: `git switch pr` creates pr from the stale origin/pr
        w.work.git("switch", "-q", "pr")
        self.assertEqual("TRACKED-BY-STALE-TIP\n", w.mine.read_text())
        w = stale_world(self)  # control: the same script refuses when the SHA itself tracks it
        rc, report = self.land(w, w.p1, "pr", *ORIGIN)
        self.assertEqual((1, ["ignored_collision"]), (rc, checks(report)))
        self.assertEqual(("main", "USER-SECRET\n"), (w.work.out("branch", "--show-current"), w.mine.read_text()))
        self.assertEqual("", w.work.out("branch", "--list", "pr"))

    def test_a_stale_local_branch_with_the_same_upstream_is_fast_forwarded_by_cas(self):
        w = stale_world(self)
        w.work.git("branch", "--track", "pr", "origin/pr")  # local pr at P1, upstream origin refs/heads/pr
        rc, done = self.land(w, w.p2, "pr", *ORIGIN)
        self.assertEqual((0, "ff", w.p2, "pr"), (rc, done["action"], done["head"], done["current_branch"]))
        self.assertEqual((w.p2, "USER-SECRET\n"), (w.work.out("rev-parse", "pr"), w.mine.read_text()))

    def test_a_diverged_or_foreign_local_branch_is_a_clash_and_nothing_moves(self):
        for label, tamper in (("diverged", lambda w: w.work.git(
                "branch", "-f", "pr", w.work.out("commit-tree", w.p1 + "^{tree}", "-p", w.p1, "-m", "local only"))),
                              ("other upstream", lambda w: w.work.git("config", "branch.pr.remote", "elsewhere"))):
            with self.subTest(label):
                w = stale_world(self)
                w.work.git("branch", "--track", "pr", "origin/pr")
                tamper(w)
                tip = w.work.out("rev-parse", "pr")
                rc, report = self.land(w, w.p2, "pr", *ORIGIN)
                self.assertEqual((1, ["branch_clash"]), (rc, checks(report)))
                self.assertEqual((tip, "main", "USER-SECRET\n"), (w.work.out("rev-parse", "pr"),
                                                                    w.work.out("branch", "--show-current"), w.mine.read_text()))

    def test_the_fast_forward_is_a_compare_and_swap(self):
        """The branch moves between the plan and the run: update-ref refuses, the branch is untouched."""
        w = stale_world(self)
        w.work.git("branch", "--track", "pr", "origin/pr")
        script = load_module(SCRIPT)
        with mock.patch.dict(os.environ, w.work.env, clear=True):
            report = script.plan(w.work.path, w.p2, "pr", "origin", ["refs/heads/pr"], False, [])
            self.assertEqual(("PASS", "ff"), (report["status"], report["action"]))
            moved = w.work.out("commit-tree", w.p1 + "^{tree}", "-p", w.p1, "-m", "raced")
            w.work.git("branch", "-f", "pr", moved)
            report = script.execute(report)
        self.assertEqual("STOP", report["status"])
        self.assertEqual(moved, w.work.out("rev-parse", "pr"), "the raced branch was not overwritten")
        self.assertEqual("USER-SECRET\n", w.mine.read_text())

    def test_fork_head_named_like_the_users_main_is_a_clash_and_a_clean_name_is_created(self):
        w = stale_world(self)
        fork = w.work.base / "fork.git"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(fork)], check=True, env=w.work.env)
        head = w.work.out("commit-tree", w.a + "^{tree}", "-p", w.a, "-m", "fork head")
        w.work.git("push", "-q", str(fork), f"{head}:refs/heads/main", f"{head}:refs/heads/feature")
        main = w.work.out("rev-parse", "main")
        ident = ("--remote", str(fork), "--merge", "refs/pull/1/head")
        rc, report = self.land(w, head, "main", *ident, "--merge", "refs/heads/main")
        self.assertEqual((1, ["branch_clash"]), (rc, checks(report)))
        self.assertEqual((main, "main"), (w.work.out("rev-parse", "main"), w.work.out("branch", "--show-current")))
        rc, done = self.land(w, head, "feature", *ident, "--merge", "refs/heads/feature")
        self.assertEqual((0, "feature"), (rc, done["current_branch"]))
        self.assertEqual((str(fork), "refs/pull/1/head"), (w.work.out("config", "branch.feature.remote"),
                                                           w.work.out("config", "branch.feature.merge")))
        # pr_gate compares the local branch with the PR's headRefName: it holds by construction
        self.assertEqual((head, "feature", []), tuple(load_module(PR_GATE).check_local(w.work.path)))

    def test_issue_resume_after_the_stale_remote_tracking_ref_moved_back(self):
        w = stale_world(self)
        w.work.git("fetch", "-q", "origin", "refs/heads/pr")
        w.work.git("update-ref", "refs/remotes/origin/pr", w.p1)  # the race: origin/pr is stale when we land
        rc, done = self.land(w, w.p2, "pr", *ORIGIN)
        self.assertEqual((0, w.p2, "USER-SECRET\n"), (rc, done["head"], w.mine.read_text()))
        w.work.git("switch", "-q", "main")  # control: the local branch is already at the verified tip
        rc, done = self.land(w, w.p2, "pr", *ORIGIN)
        self.assertEqual((0, "attach", w.p2), (rc, done["action"], done["head"]))

    def test_a_new_issue_branch_must_not_exist_and_tracks_nothing(self):
        w = stale_world(self)
        rc, done = self.land(w, w.a, "issue/7-fix", "--new")
        self.assertEqual((0, "issue/7-fix", w.a), (rc, done["current_branch"], done["head"]))
        self.assertEqual("", w.work.git("config", "--get", "branch.issue/7-fix.merge", check=False).stdout)
        w.work.git("switch", "-q", "main")
        rc, report = self.land(w, w.a, "issue/7-fix", "--new")
        self.assertEqual((1, ["branch_clash"]), (rc, checks(report)))

    def test_a_ref_named_like_the_sha_cannot_redirect_the_landing(self):
        w = stale_world(self)
        w.work.git("branch", w.p2, w.p1)  # a decoy branch named by the PR head's SHA, pointing at P1
        rc, done = self.land(w, w.p2, "pr", *ORIGIN)
        self.assertEqual((0, w.p2, "USER-SECRET\n"), (rc, done["head"], w.mine.read_text()))
        w = stale_world(self)  # premise: plain `git switch --detach <sha>` takes the decoy
        w.work.git("branch", w.p2, w.p1)
        w.work.git("switch", "-q", "--detach", w.p2)
        self.assertEqual((w.p1, "TRACKED-BY-STALE-TIP\n"), (w.work.out("rev-parse", "HEAD"), w.mine.read_text()))

    def test_invalid_branch_names_stop_before_any_switch(self):
        w = stale_world(self)
        w.work.git("switch", "-q", "-c", "previous")  # so that `@{-1}` names a real branch ("previous")
        w.work.git("switch", "-q", "main")
        head = w.work.out("rev-parse", "HEAD")
        for bad in ("-x", "a..b", "@{-1}", "HEAD", "", "a b", "x.lock"):
            with self.subTest(bad):
                rc, report = self.land(w, w.p2, bad, *ORIGIN)
                self.assertEqual((1, ["invalid_branch_name"]), (rc, checks(report)))
                self.assertEqual((head, "main"), (w.work.out("rev-parse", "HEAD"), w.work.out("branch", "--show-current")))

    def landed(self):
        w = stale_world(self)
        self.assertEqual(0, self.land(w, w.p2, "pr", *ORIGIN)[0])
        w.main = w.work.out("rev-parse", "main")
        return w

    def test_restore_returns_to_the_start_only_from_a_safe_head(self):
        w = self.landed()
        rc, done = self.land(w, w.main, "main", "--safe-sha", w.p2)
        self.assertEqual((0, w.main, "main", "USER-SECRET\n"), (rc, done["head"], done["current_branch"], w.mine.read_text()))
        w = self.landed()  # HEAD ahead of everything verified: its commits would be stranded
        w.work.write("c", "local work\n")
        ahead = w.work.commit("pushed to a fork, not to origin")
        rc, report = self.land(w, w.main, "main", "--safe-sha", w.p2)
        self.assertEqual((1, ["unpushed_commits"]), (rc, checks(report)))
        self.assertEqual("pr", w.work.out("branch", "--show-current"))
        rc, done = self.land(w, w.main, "main", "--safe-sha", w.p2, "--safe-sha", ahead)  # verified after the push
        self.assertEqual((0, "main"), (rc, done["current_branch"]))

    def test_restore_never_recreates_a_deleted_start_branch_from_origin(self):
        w = self.landed()
        w.work.git("branch", "-q", "-D", "main")
        rc, report = self.land(w, w.main, "main", "--safe-sha", w.p2)
        self.assertEqual((1, ["start_branch_missing"]), (rc, checks(report)))
        self.assertEqual(("pr", ""), (w.work.out("branch", "--show-current"), w.work.out("branch", "--list", "main")))

    def test_restore_to_a_detached_start_only_detaches(self):
        w = self.landed()
        rc, done = preflight(w.work, w.main, None, None, "--safe-sha", w.p2, "--execute")
        self.assertEqual((0, w.main, None), (rc, done["head"], done["current_branch"]))


if __name__ == "__main__":
    unittest.main()
