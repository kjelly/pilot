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
    """`target` is one ref or a list of refs (each becomes its own --target-ref)."""
    cmd = [sys.executable, "-I", str(SCRIPT), "--repo", str(cwd or repo.path)]
    for ref in ([target] if isinstance(target, str) else target):
        cmd += ["--target-ref", ref]
    if branch:
        cmd += ["--branch", branch]
    p = subprocess.run(cmd, capture_output=True, text=True, env=repo.env)
    return p.returncode, json.loads(p.stdout) if p.stdout.strip() else None


def restore(repo, start_sha, start_branch=None, checked_out_sha=None, cwd=None):
    cmd = [sys.executable, "-I", str(SCRIPT), "--repo", str(cwd or repo.path), "--restore-check",
           "--start-sha", start_sha]
    if start_branch:
        cmd += ["--start-branch", start_branch]
    if checked_out_sha:
        cmd += ["--checked-out-sha", checked_out_sha]
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


class StaleLocalBranch(unittest.TestCase):
    """`git switch BRANCH` / `gh pr checkout` land on the local tip first, not on the fetched SHA."""

    def stale_pr(self):
        """Local `pr` is stale and tracks local.cfg; the fetched new head `new` does not."""
        r = Repo(self)
        r.write(".gitignore", "local.cfg\n")
        r.write("a.txt")
        r.commit("init")
        r.branch_from_main("pr")
        r.write("local.cfg", "stale tip content\n")
        r.commit("stale tip tracks local.cfg", "-f", "local.cfg")
        r.git("switch", "-q", "main")
        r.git("switch", "-q", "-c", "new", "main")
        r.write("feature.txt")
        new = r.commit("fetched head: no local.cfg")
        r.git("switch", "-q", "main")
        mine = r.write("local.cfg", "MY LOCAL SETTINGS\n")
        self.assertEqual("", r.out("status", "--porcelain"))
        return r, new, mine

    def test_stale_local_branch_tip_is_checked_even_when_the_target_is_clean(self):
        r, new, mine = self.stale_pr()
        # the target commit alone is harmless...
        rc, alone = preflight(r, new)
        self.assertEqual((0, "PASS"), (rc, alone["status"]))
        # ...but with the branch named, the local tip it would land on first is checked too
        rc, report = preflight(r, new, "pr")
        self.assertEqual((1, ["ignored_collision"]), (rc, checks(report)))
        self.assertEqual(["local.cfg"], report["problems"][0]["paths"])
        self.assertEqual("refs/heads/pr", report["problems"][0]["target"])
        self.assertEqual({new, r.out("rev-parse", "pr")}, {t["sha"] for t in report["targets"]})
        self.assertEqual("MY LOCAL SETTINGS\n", mine.read_text())
        # premise: the switch to the stale local tip is what destroys the file
        r.git("switch", "-q", "pr")
        self.assertEqual("stale tip content\n", mine.read_text())

    def test_every_repeated_target_ref_is_checked(self):
        r, new, mine = self.stale_pr()
        rc, report = preflight(r, [new, "refs/heads/pr"])
        self.assertEqual((1, ["ignored_collision"]), (rc, checks(report)))
        self.assertEqual("refs/heads/pr", report["problems"][0]["target"])

    def test_local_tip_equal_to_the_target_or_absent_passes(self):
        r, new, mine = self.stale_pr()
        r.git("branch", "-f", "pr", new)  # the local branch already equals the fetched head
        rc, report = preflight(r, new, "pr")
        self.assertEqual((0, "PASS", 1), (rc, report["status"], len(report["targets"])))
        rc, report = preflight(r, new, "not-yet-created")  # new branch: no local tip to check
        self.assertEqual((0, "PASS", 1), (rc, report["status"], len(report["targets"])))

    def test_fast_forwardable_stale_tip_without_the_tracked_path_passes(self):
        """Control: a stale local tip that does not track the user's ignored file is fine."""
        r, new, mine = self.stale_pr()
        r.git("branch", "-f", "pr", "main")  # tip = main: tracks nothing the user has ignored
        rc, report = preflight(r, new, "pr")
        self.assertEqual((0, "PASS"), (rc, report["status"]))


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


class RestoreCheck(unittest.TestCase):
    """At the end of an invocation: may the checkout go back to where it started?"""

    def on_selected_branch(self):
        """Started on main; the selected branch `pr` is pushed (upstream set) and checked out."""
        r = Repo(self)
        r.write(".gitignore", "local.cfg\n")
        r.write("a.txt")
        start = r.commit("init")
        r.add_origin()
        r.branch_from_main("pr")
        r.write("b.txt")
        r.commit("pr work")
        r.git("push", "-q", "-u", "origin", "pr")
        return r, start

    def test_clean_pushed_branch_may_return_and_the_command_works(self):
        r, start = self.on_selected_branch()
        before = r.out("rev-parse", "HEAD")
        rc, report = restore(r, start, "main")
        self.assertEqual((0, "PASS", True), (rc, report["status"], report["restore_needed"]), report)
        self.assertEqual(["git", "switch", "main"], report["switch_command"])
        self.assertEqual("pr", r.out("branch", "--show-current"), "the check never switches")
        self.assertEqual(before, r.out("rev-parse", "HEAD"))
        r.git(*report["switch_command"][1:])
        self.assertEqual(("main", start), (r.out("branch", "--show-current"), r.out("rev-parse", "HEAD")))

    def test_unpushed_commits_keep_the_checkout_on_the_selected_branch(self):
        r, start = self.on_selected_branch()
        r.write("c.txt")
        unpushed = r.commit("not pushed yet")
        rc, report = restore(r, start, "main")
        self.assertEqual((1, ["unpushed_commits"]), (rc, checks(report)), report)
        self.assertEqual([unpushed], report["problems"][0]["paths"])
        self.assertIn("pr", report["problems"][0]["detail"])
        self.assertIsNone(report["switch_command"])
        self.assertEqual([unpushed], report["unpushed"])

    def test_a_branch_without_an_upstream_cannot_be_shown_pushed(self):
        r, start = self.on_selected_branch()
        r.git("switch", "-q", "-c", "local-only", "main")
        r.write("d.txt")
        r.commit("local work")
        rc, report = restore(r, start, "main")
        self.assertEqual((1, ["no_upstream"]), (rc, checks(report)), report)

    def test_nothing_written_locally_needs_no_upstream_even_after_the_remote_branch_is_deleted(self):
        """pr-review-merge: HEAD is still the reviewed commit; GitHub deleted the merged branch."""
        r, start = self.on_selected_branch()
        reviewed = r.out("rev-parse", "HEAD")
        r.git("push", "-q", "origin", "--delete", "pr")  # deleteBranchOnMerge
        r.git("fetch", "-q", "--prune", "origin")
        rc, report = restore(r, start, "main")
        self.assertEqual((1, ["no_upstream"]), (rc, checks(report)), "without the checked-out SHA")
        rc, report = restore(r, start, "main", checked_out_sha=reviewed)
        self.assertEqual((0, "PASS"), (rc, report["status"]), report)
        r.write("e.txt")
        r.commit("something was written locally after all")
        rc, report = restore(r, start, "main", checked_out_sha=reviewed)
        self.assertEqual((1, ["head_moved"]), (rc, checks(report)), report)

    def test_a_detached_current_head_cannot_be_shown_pushed(self):
        r, start = self.on_selected_branch()
        tip = r.out("rev-parse", "HEAD")
        r.git("switch", "-q", "--detach", "pr")
        rc, report = restore(r, start, "main")
        self.assertEqual((1, ["no_upstream"]), (rc, checks(report)), report)
        self.assertIn("detached", report["problems"][0]["detail"])
        rc, report = restore(r, start, "main", checked_out_sha=tip)  # nothing written: fine
        self.assertEqual((0, "PASS"), (rc, report["status"]), report)

    def test_dirty_checkout_stays(self):
        r, start = self.on_selected_branch()
        r.write("b.txt", "edited\n")
        rc, report = restore(r, start, "main")
        self.assertEqual((1, ["dirty"]), (rc, checks(report)), report)

    def test_ignored_file_that_the_start_branch_tracks_stops_the_way_back(self):
        """The ignored-file guard also covers the return trip."""
        r = Repo(self)
        r.write(".gitignore", "local.cfg\n")
        r.write("local.cfg", "tracked on main\n")
        start = r.commit("main force-tracks local.cfg", "-f", ".gitignore", "local.cfg")
        r.add_origin()
        r.branch_from_main("pr")
        r.git("rm", "-q", "local.cfg")
        r.commit("pr stops tracking it")
        r.git("push", "-q", "-u", "origin", "pr")
        mine = r.write("local.cfg", "MY LOCAL SETTINGS\n")
        self.assertEqual("", r.out("status", "--porcelain"))
        rc, report = restore(r, start, "main")
        self.assertEqual((1, ["ignored_collision"]), (rc, checks(report)), report)
        self.assertEqual(["local.cfg"], report["problems"][0]["paths"])
        self.assertIsNone(report["switch_command"])
        self.assertEqual("MY LOCAL SETTINGS\n", mine.read_text())
        # premise: the plain `git switch main` would have replaced it
        r.git("switch", "-q", "main")
        self.assertEqual("tracked on main\n", mine.read_text())

    def test_a_moved_start_branch_tip_is_checked_too(self):
        r, start = self.on_selected_branch()
        r.git("switch", "-q", "main")
        r.write("local.cfg", "tracked later\n")
        r.commit("main moved on and tracks local.cfg", "-f", "local.cfg")
        r.git("switch", "-q", "pr")
        r.write("local.cfg", "MINE\n")
        rc, report = restore(r, start, "main")  # start SHA alone is harmless; main's tip is not
        self.assertEqual((1, ["ignored_collision"]), (rc, checks(report)), report)
        self.assertEqual("refs/heads/main", report["problems"][0]["target"])
        self.assertTrue(report["tip_moved"])

    def test_a_detached_start_returns_to_the_sha(self):
        r, start = self.on_selected_branch()
        rc, report = restore(r, start)  # no --start-branch: HEAD started detached
        self.assertEqual((0, "PASS"), (rc, report["status"]), report)
        self.assertEqual(["git", "switch", "--detach", start], report["switch_command"])
        r.git(*report["switch_command"][1:])
        self.assertEqual("", r.out("branch", "--show-current"))
        self.assertEqual(start, r.out("rev-parse", "HEAD"))

    def test_already_on_the_start_branch_needs_no_switch(self):
        r = Repo(self)
        r.write("a.txt")
        start = r.commit("init")
        rc, report = restore(r, start, "main")
        self.assertEqual((0, "PASS", False, None), (rc, report["status"], report["restore_needed"],
                                                    report["switch_command"]))

    def test_start_branch_deleted_or_checked_out_elsewhere_stays(self):
        r, start = self.on_selected_branch()
        r.git("worktree", "add", "-q", str(r.base / "other"), "main")  # scratch repo only
        rc, report = restore(r, start, "main")
        self.assertEqual((1, ["checked_out_elsewhere"]), (rc, checks(report)), report)
        r2, start2 = self.on_selected_branch()
        r2.git("branch", "-q", "-D", "main")
        rc, report = restore(r2, start2, "main")
        self.assertEqual(1, rc)
        self.assertIn("start_branch_missing", checks(report))

    def test_unresolvable_start_and_bad_arguments_are_not_a_pass(self):
        r, start = self.on_selected_branch()
        rc, report = restore(r, "0" * 40, "main")
        self.assertEqual(1, rc)
        self.assertIn("unresolvable_target", checks(report))
        for argv in (["--restore-check"], ["--restore-check", "--start-sha", start, "--target-ref", "main"],
                     ["--start-sha", start, "--target-ref", "main"]):
            p = subprocess.run([sys.executable, "-I", str(SCRIPT), "--repo", str(r.path), *argv],
                               capture_output=True, text=True, env=r.env)
            self.assertNotEqual(0, p.returncode, argv)


if __name__ == "__main__":
    unittest.main()
