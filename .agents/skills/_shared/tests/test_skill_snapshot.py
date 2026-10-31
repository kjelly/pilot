"""skill_snapshot.py: the bundle survives a branch switch, a changed role is reported.

The invocation starts on a branch with the skills, switches to an older/newer PR branch that
changes or deletes them, and must still run the verified copies. verify-role has three outcomes:
PASS (identical), DRIFT (the checkout's role file differs: dispatch with the snapshot as the
binding contract, exit 3) and STOP (nothing can be dispatched).
"""
import hashlib
import importlib.util
import json
import os
import py_compile
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

from gitrepo import Repo, load_module

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "skill_snapshot.py"
PREFLIGHT = SCRIPT.with_name("checkout_preflight.py")
PR_GATE = Path(__file__).resolve().parents[2] / "pr-ready" / "scripts" / "pr_gate.py"
REPO = Path(__file__).resolve().parents[4]
BUNDLE = load_module(SCRIPT).BUNDLE_PATHS
ROLE = ".agents/skills/issue-to-pr/platforms/claude/agents/issue-coder.md"
TOML = ".agents/skills/issue-to-pr/platforms/codex/agents/issue-coder.toml"
AGY_SRC = ".agents/skills/issue-to-pr/platforms/agy/agents/issue-coder.md"
AGY_COPY = ".agents/agents/issue-coder.md"  # what agy loads: a copy made when agy is used
TEXTS = {  # platform -> (file edited on a branch, file the runtime loads, content)
    "claude": (ROLE, ".claude/agents/issue-coder.md",
               "---\nname: issue-coder\nmodel: claude-sonnet-5-5\neffort: xhigh\ntools: Read, Grep\n---\n\nUse the checkout.\n"),
    "codex": (TOML, ".codex/agents/issue-coder.toml",
              'name = "issue-coder"\nmodel = "gpt-6.1-sol"\nmodel_reasoning_effort = "high"\n'
              'sandbox_mode = "read-only"\ndeveloper_instructions = """\nUse the checkout.\n"""\n'),
    "agy": (AGY_COPY, AGY_COPY, "---\nname: issue-coder\nmodel: inherit\ntools:\n- Read\n---\n\nUse the checkout.\n"),
}
BASE_ROLES = Path(__file__).resolve().parent / "fixtures" / "base-roles"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def snap(repo, *args):
    p = subprocess.run([sys.executable, "-I", str(SCRIPT), *args], capture_output=True,
                       text=True, env=repo.env)
    return p.returncode, json.loads(p.stdout)


def skill_repo(case, exclude_agy=True):
    """A repo with the whole bundle committed; the agy copy is untracked, as it is in real use."""
    r = Repo(case)
    for path in BUNDLE:
        r.write(f"{path}/README.md", f"{path}\n")
    r.write(ROLE, TEXTS["claude"][2])
    r.write(TOML, TEXTS["codex"][2])
    r.write(AGY_SRC, TEXTS["agy"][2])
    for link, target in ((".claude/agents/issue-coder.md", ROLE), (".codex/agents/issue-coder.toml", TOML)):
        (r.path / link).parent.mkdir(parents=True, exist_ok=True)
        os.symlink("../../" + target, r.path / link)
    r.commit("bundle")
    r.write(AGY_COPY, TEXTS["agy"][2])  # not committed
    if exclude_agy:
        r.write(".git/info/exclude", "/.agents/agents/\n")
    return r


def create(r):
    rc, out = snap(r, "create", "--repo", str(r.path), "--out-parent", str(r.base))
    return rc, out


class Snapshot(unittest.TestCase):
    def snapshot(self, r):
        rc, out = create(r)
        self.assertEqual((0, "PASS"), (rc, out["status"]), out)
        return Path(out["snapshot_dir"]), out

    def test_create_records_the_committed_revision_outside_the_checkout(self):
        r = skill_repo(self)
        r.write(ROLE, "second revision\n")
        head = r.commit("second revision of the role")
        snapshot, out = self.snapshot(r)
        self.assertEqual((head, r.out("rev-parse", "HEAD^{tree}")), (out["head"], out["tree_id"]))
        self.assertNotIn(r.path, [snapshot, *snapshot.parents])
        self.assertEqual("second revision\n", (snapshot / ROLE).read_text())
        link = snapshot / ".claude/agents/issue-coder.md"
        self.assertTrue(link.is_symlink() and str(link.resolve()).startswith(str(snapshot)), "links stay inside")
        manifest = json.loads(Path(out["manifest"]).read_text())
        self.assertEqual((out["tree_id"], True), (manifest["source_tree"], ROLE in manifest["files"]))
        rc, verified = snap(r, "verify", "--snapshot", str(snapshot))
        self.assertEqual((0, "PASS"), (rc, verified["status"]))

    def test_only_the_bundle_has_to_be_clean(self):
        """A snapshot copies the committed bundle: files elsewhere, even untracked, do not matter."""
        for rel in ("notes.txt", ".agents/agents/other.md", ".agents/workflows/x.md"):
            r = skill_repo(self)
            r.write(rel, "untracked, outside the bundle\n")
            self.assertEqual("PASS", create(r)[1]["status"], rel)
        for rel in (f"{BUNDLE[1]}/new.txt", ROLE):  # inside the bundle: untracked, or edited
            r = skill_repo(self)
            r.write(rel, "uncommitted\n")
            rc, out = create(r)
            self.assertEqual((1, "STOP"), (rc, out["status"]), rel)
            self.assertIn("uncommitted or untracked", out["error"])
            self.assertEqual([], [p.name for p in r.base.iterdir() if p.name.startswith("single-item-skills")])

    def test_snapshot_inside_the_checkout_or_without_the_bundle_is_refused(self):
        r = skill_repo(self)
        rc, out = snap(r, "create", "--repo", str(r.path), "--out-parent", str(r.path))
        self.assertEqual(1, rc)
        self.assertIn("outside the checkout", out["error"])
        empty = Repo(self)
        empty.write("README.md")
        empty.commit("no skills")
        rc, out = create(empty)
        self.assertEqual(1, rc)
        self.assertIn("skill bundle", out["error"])

    def test_snapshot_survives_a_switch_to_a_branch_without_the_skills(self):
        r = skill_repo(self)
        snapshot, _ = self.snapshot(r)
        r.branch_from_main("old-pr")
        r.git("rm", "-rq", ".agents", ".claude", ".codex")
        r.commit("old branch predates the skills")
        self.assertFalse((r.path / ROLE).exists())
        self.assertTrue((snapshot / ROLE).is_file())
        self.assertEqual("PASS", snap(r, "verify", "--snapshot", str(snapshot))[1]["status"])

    def test_a_modified_snapshot_fails_verification(self):
        for tamper in ("change", "add", "remove", "retarget a symlink"):
            with self.subTest(tamper):
                r = skill_repo(self)
                snapshot, _ = self.snapshot(r)
                link = snapshot / ".claude/agents/issue-coder.md"
                if tamper == "change":
                    (snapshot / ROLE).write_text("tampered\n")
                elif tamper == "add":
                    (snapshot / BUNDLE[0] / "extra.md").write_text("new\n")
                elif tamper == "remove":
                    (snapshot / BUNDLE[0] / "README.md").unlink()
                else:  # still a valid in-snapshot target: only the recorded link target gives it away
                    link.unlink()
                    os.symlink("../../" + TOML, link)
                rc, out = snap(r, "verify", "--snapshot", str(snapshot))
                self.assertEqual((1, "STOP"), (rc, out["status"]))
                self.assertIn("differs from its manifest", out["error"])


class RunFromTheSnapshot(unittest.TestCase):
    """Every documented script runs from $SNAP, and the snapshot still verifies afterwards.

    `verify` counts any added file. CPython writes `__pycache__/*.pyc` next to a module a script
    imports, so a bundle script that imports a sibling used to make every later verify and
    verify-role STOP. `scan` stays strict (a `.pyc` is code CPython loads), so the scripts must
    not write bytecode. The scripts run as `python -E` with every PYTHON* variable removed:
    the Makefile's PYTHONDONTWRITEBYTECODE=1 must not be what keeps the snapshot clean. (Not
    `-I`: it drops the script's own directory, and the sibling imports are the point.)
    """

    LIST_READY = ".agents/skills/pr-review-merge/scripts/list_ready.py"
    GH_RUNTIME = ".agents/skills/pr-review-merge/scripts/gh_runtime.py"

    def real_snapshot(self):
        """(repo, snapshot): the real bundle committed in a scratch repository and snapshotted."""
        r = Repo(self)
        for path in BUNDLE:
            shutil.copytree(REPO / path, r.path / path, symlinks=True,
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        r.commit("the real bundle")
        rc, out = create(r)
        self.assertEqual((0, "PASS"), (rc, out["status"]), out)
        return r, Path(out["snapshot_dir"])

    def run_script(self, r, snapshot, rel, *args):
        env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
        return subprocess.run([sys.executable, "-E", str(snapshot / rel), *args], capture_output=True,
                              text=True, env=env, cwd=r.base)

    def plant(self, r, source, cfile, mode=py_compile.PycInvalidationMode.UNCHECKED_HASH):
        """Compile `source` (kept outside the snapshot) to the bytecode file `cfile`."""
        src = r.base / "planted-source.py"
        src.write_text(source)
        Path(cfile).parent.mkdir(parents=True, exist_ok=True)
        py_compile.compile(str(src), cfile=str(cfile), doraise=True, invalidation_mode=mode)

    def bytecode_dirs(self, snapshot):
        return sorted(p.relative_to(snapshot).as_posix() for p in snapshot.rglob("__pycache__"))

    def test_every_bundle_script_runs_from_the_snapshot_and_the_snapshot_still_verifies(self):
        r, snapshot = self.real_snapshot()
        scripts = sorted(snapshot.glob(".agents/skills/*/scripts/*.py"))
        self.assertGreaterEqual(len(scripts), 13, [p.name for p in scripts])
        self.assertLessEqual({"list_ready.py", "issue_gate.py", "review_gate.py", "create_pr.py"},
                             {p.name for p in scripts})
        wrote = {}  # script -> the __pycache__ directories its run left in the snapshot
        for script in scripts:
            rel = script.relative_to(snapshot).as_posix()
            with self.subTest(script=rel):
                before = self.bytecode_dirs(snapshot)
                p = self.run_script(r, snapshot, rel, "--help")
                self.assertEqual(0, p.returncode, p.stderr)
                if "__main__" in script.read_text():  # gh_runtime.py is a library: nothing to print
                    self.assertIn("usage:", p.stdout, rel)
                after = self.bytecode_dirs(snapshot)
                if after != before:
                    wrote[rel] = sorted(set(after) - set(before))
        rc, out = snap(r, "verify", "--snapshot", str(snapshot))
        self.assertEqual((0, "PASS"), (rc, out["status"]), (out, wrote))
        rc, out = snap(r, "verify-role", "--snapshot", str(snapshot), "--repo", str(r.path),
                       "--platform", "claude", "--role=issue-coder")
        self.assertEqual((0, "PASS"), (rc, out["status"]), (out, wrote))
        self.assertEqual({}, wrote, "these scripts wrote bytecode into the snapshot")  # diagnostic: names them
        self.assertEqual([], self.bytecode_dirs(snapshot))

    def test_a_planted_bytecode_cache_is_loaded_and_counted_as_added(self):
        """The reason scan() must not skip __pycache__: CPython runs an unchecked-hash .pyc
        without looking at the source, so a planted one replaces the verified module."""
        r, snapshot = self.real_snapshot()
        cfile = importlib.util.cache_from_source(str(snapshot / self.GH_RUNTIME))
        self.plant(r, "print('PLANTED-GH-RUNTIME-LOADED')\n"
                      "class GitHubError(Exception): pass\n"
                      "class Repo: pass\n"
                      "def current_repo(): pass\n"
                      "def list_open_prs(repo): pass\n", cfile)
        p = self.run_script(r, snapshot, self.LIST_READY, "--help")
        self.assertEqual(0, p.returncode, p.stderr)
        self.assertIn("PLANTED-GH-RUNTIME-LOADED", p.stdout, "premise: the planted bytecode is what ran")
        rc, out = snap(r, "verify", "--snapshot", str(snapshot))
        planted = Path(cfile).relative_to(snapshot).as_posix()
        self.assertEqual((1, "STOP"), (rc, out["status"]))
        self.assertIn(f"added=['{planted}']", out["error"])
        self.assertIn("run any other Python from the snapshot with -B", out["error"])
        rc, out = snap(r, "verify-role", "--snapshot", str(snapshot), "--repo", str(r.path),
                       "--platform", "claude", "--role=issue-coder")
        self.assertEqual((1, "STOP"), (rc, out["status"]))
        self.assertIn(planted, out["error"])

    def test_a_sourceless_module_beside_a_script_shadows_the_standard_library(self):
        r, snapshot = self.real_snapshot()
        shadow = snapshot / ".agents/skills/pr-review-merge/scripts/json.pyc"
        self.plant(r, "print('PLANTED-JSON-LOADED')\nraise SystemExit(0)\n", shadow)
        p = self.run_script(r, snapshot, self.LIST_READY, "--help")
        self.assertEqual((0, True), (p.returncode, "PLANTED-JSON-LOADED" in p.stdout), (p.stdout, p.stderr))
        rc, out = snap(r, "verify", "--snapshot", str(snapshot))
        self.assertEqual((1, "STOP"), (rc, out["status"]))
        self.assertIn(f"added=['{shadow.relative_to(snapshot).as_posix()}']", out["error"])
        self.assertNotIn("__pycache__", out["error"], "no bytecode-cache hint for a plain added file")


class RoleVerification(unittest.TestCase):
    def verify(self, r, snapshot, platform="claude", role="issue-coder"):
        return snap(r, "verify-role", "--snapshot", str(snapshot), "--repo", str(r.path),
                    "--platform", platform, f"--role={role}")

    def setUp(self):
        self.r = skill_repo(self)
        self.snapshot = Path(create(self.r)[1]["snapshot_dir"])

    def edit(self, platform, transform):
        """The branch (or the user, for the agy copy) changes the role file this platform loads."""
        self.setUp()
        edited, _loaded, text = TEXTS[platform]
        self.r.branch_from_main("pr")
        self.r.write(edited, transform(text))
        if platform != "agy":
            self.r.commit(f"pr changes the {platform} role")

    def test_identical_roles_pass_on_every_platform(self):
        for platform in TEXTS:
            rc, out = self.verify(self.r, self.snapshot, platform)
            self.assertEqual((0, "PASS", out["snapshot_sha256"]), (rc, out["status"], out["checkout_sha256"]), platform)

    def test_a_changed_role_is_drift_and_header_changes_say_what(self):
        """Report-only: DRIFT never blocks. header_changes lists every top-level header key that
        differs, so a tools/sandbox change is visible, and pins_differ is derived from it."""
        cases = (("claude", "Use the checkout.", "Old prompt: create a worktree.", [], False),
                 ("claude", "tools: Read, Grep", "tools: Read, Grep, Bash, Write", ["tools"], False),
                 ("claude", "model: claude-sonnet-5-5", "model: claude-haiku-5", ["model"], True),
                 ("claude", "effort: xhigh", "effort: low", ["effort"], True),
                 ("codex", 'sandbox_mode = "read-only"', 'sandbox_mode = "danger-full-access"', ["sandbox_mode"], False),
                 ("codex", 'model = "gpt-6.1-sol"', 'model = "gpt-7"', ["model"], True),
                 ("codex", 'model_reasoning_effort = "high"', 'model_reasoning_effort = "low"',
                  ["model_reasoning_effort"], True),
                 ("agy", "- Read", "- Read\n- Bash", ["tools"], False),
                 ("agy", "model: inherit", "model: some-model", ["model"], True))
        for platform, old, new, changes, pins in cases:
            with self.subTest(platform=platform, change=changes or "prompt"):
                self.edit(platform, lambda t: t.replace(old, new))
                rc, out = self.verify(self.r, self.snapshot, platform)
                self.assertEqual((3, "DRIFT", changes, pins), (rc, out["status"], out["header_changes"], out["pins_differ"]))
                snapshot_role, loaded = Path(out["snapshot_role"]), self.r.path / TEXTS[platform][1]
                self.assertTrue(self.snapshot in snapshot_role.parents)
                self.assertEqual((digest(snapshot_role), digest(loaded), str(loaded)),
                                 (out["snapshot_sha256"], out["checkout_sha256"], out["checkout_role"]))
                self.assertNotEqual(out["snapshot_sha256"], out["checkout_sha256"])
                self.assertIn(f"Read `{snapshot_role}` now and follow it as your role contract", out["binding_statement"])
                self.assertEqual(0, self.verify(self.r, self.snapshot, "claude" if platform != "claude" else "codex")[0])

    def test_pin_lookalikes_in_the_prompt_are_not_header_keys(self):
        for platform, line, drop in (("claude", "model: zzz", "model:"), ("codex", 'model = "zzz"', "model ="),
                                     ("agy", "model: zzz", "model:")):
            def edit(text, drop=None):
                if drop:
                    text = "\n".join(l for l in text.split("\n") if not l.startswith(drop))
                return text[:-4] + line + '\n"""\n' if text.endswith('"""\n') else text + line + "\n"
            for label, dropped, expected in (("kept", None, ([], False)), ("removed", drop, (["model"], True))):
                with self.subTest(platform=platform, pin=label):
                    self.edit(platform, lambda t: edit(t, dropped))
                    rc, out = self.verify(self.r, self.snapshot, platform)
                    self.assertEqual((3, *expected), (rc, out["header_changes"], out["pins_differ"]))

    def test_roles_that_cannot_be_dispatched_are_stop(self):
        outside = self.r.base / "elsewhere.md"
        outside.write_text("x\n")

        def relink():
            os.unlink(self.r.path / ".claude/agents/issue-coder.md")
            os.symlink(str(outside), self.r.path / ".claude/agents/issue-coder.md")
        scenarios = (  # (label, what happens to the checkout, platform, role, error)
            ("agy copy never installed", lambda: (self.r.path / AGY_COPY).unlink(), "agy", "issue-coder", "missing"),
            ("role file missing", lambda: self.r.git("rm", "-q", ".claude/agents/issue-coder.md"), "claude", "issue-coder", "missing"),
            ("dangling link", lambda: self.r.git("rm", "-q", ROLE), "claude", "issue-coder", "missing"),
            ("resolves outside the checkout", relink, "claude", "issue-coder", "outside the checkout"),
            ("broken snapshot", lambda: (self.snapshot / ROLE).write_text("tampered\n"), "claude", "issue-coder",
             "differs from its manifest"),
            *((f"invalid role {bad!r}", lambda: None, "claude", bad, "invalid role name")
              for bad in ("", "..", "../outside", "a/b", "/etc/passwd", ".hidden", "-flag", "issue..coder")))
        for label, happen, platform, role, error in scenarios:
            with self.subTest(label):
                self.setUp()
                happen()
                rc, out = self.verify(self.r, self.snapshot, platform, role)
                self.assertEqual((1, "STOP"), (rc, out["status"]))
                self.assertIn(error, out["error"])

    def test_a_snapshot_with_two_agy_copies_of_a_role_is_stop(self):
        self.r.write(".agents/skills/pr-ready/platforms/agy/agents/issue-coder.md", TEXTS["agy"][2])
        self.r.commit("a second agy definition of the same role")
        snapshot = Path(create(self.r)[1]["snapshot_dir"])
        rc, out = self.verify(self.r, snapshot, "agy")
        self.assertEqual((1, True), (rc, "expected one" in out["error"]))


class AgyCopy(unittest.TestCase):
    """agy loads an untracked copy in .agents/agents/: it must not break the other commands."""

    def test_an_excluded_copy_is_invisible_and_an_unexcluded_one_stops_the_landing(self):
        r = skill_repo(self)
        r.branch_from_main("pr")
        r.write("feature.txt")
        target = r.commit("feature")
        r.git("switch", "-q", "main")
        land = lambda t, branch="pr": subprocess.run([sys.executable, "-I", str(PREFLIGHT), "--repo", str(r.path),
                                                      "--target", t, f"--branch={branch}"], capture_output=True,
                                                     text=True, env=r.env)
        self.assertEqual("PASS", create(r)[1]["status"])
        self.assertEqual(0, land(target).returncode)
        self.assertEqual(0, snap(r, "verify-role", "--snapshot", create(r)[1]["snapshot_dir"], "--repo", str(r.path),
                                 "--platform", "agy", "--role=issue-coder")[0])
        self.assertEqual((r.out("rev-parse", "HEAD"), "main", []), tuple(load_module(PR_GATE).check_local(r.path)))
        # a branch that tracks the same path would overwrite the user's copy: ignored_collision
        clash = r.side_commit("tracks-copy", AGY_COPY, "tracked on a branch\n")
        out = json.loads(land(clash, "tracks-copy").stdout)
        self.assertEqual(["ignored_collision"], [p["check"] for p in out["problems"]])
        self.assertEqual(AGY_COPY, out["problems"][0]["paths"][0])
        # without the exclude entry the copy is an untracked file: the landing stops, the snapshot does not
        (r.path / ".git/info/exclude").write_text("")
        self.assertEqual(["dirty"], [p["check"] for p in json.loads(land(target).stdout)["problems"]])
        self.assertEqual("PASS", create(r)[1]["status"])


class RealRoleDefinitions(unittest.TestCase):
    """Real files: the header format the parser reads, and the roles an older PR branch carries."""

    def test_every_real_role_definition_has_its_pins_in_the_header(self):
        header = load_module(SCRIPT).role_header
        for platform, pattern, model, effort in (("claude", ".claude/agents/*.md", "claude-", "effort"),
                                                 ("codex", ".codex/agents/*.toml", "gpt-", "model_reasoning_effort"),
                                                 ("agy", ".agents/skills/*/platforms/agy/agents/*.md", "inherit", None)):
            roles = [p for p in sorted(REPO.glob(pattern)) if p.name.split("-")[0] in ("issue", "pr", "prm")]
            self.assertEqual(8, len(roles), platform)
            for path in roles:
                found = header(path, platform)
                self.assertTrue(found.get("model", "").startswith(model), (path.name, found))
                self.assertTrue(effort is None or found.get(effort), (path.name, found))
                self.assertNotIn("developer_instructions", found)

    def test_an_older_branchs_real_role_files_are_drift_not_blocked(self):
        """pr-coder and prm-reviewer as fdb6f03e (before #205) shipped them, claude and codex."""
        for role, skill, platform, ext in (("pr-coder", "pr-ready", "claude", "md"), ("pr-coder", "pr-ready", "codex", "toml"),
                                           ("prm-reviewer", "pr-review-merge", "claude", "md"),
                                           ("prm-reviewer", "pr-review-merge", "codex", "toml")):
            with self.subTest(role=role, platform=platform):
                path = f".agents/skills/{skill}/platforms/{platform}/agents/{role}.{ext}"
                r = Repo(self)
                for bundle in BUNDLE:
                    r.write(f"{bundle}/README.md", "x\n")
                r.write(path, (REPO / path).read_bytes().decode())
                r.write(".claude/agents/.keep", "")
                r.write(".codex/agents/.keep", "")
                os.symlink("../../" + path, r.path / f".{platform}/agents/{role}.{ext}")
                r.commit("the bundle with this workflow's role")
                snapshot = create(r)[1]["snapshot_dir"]
                r.branch_from_main("older-pr")
                older = BASE_ROLES / f"{role}.{platform}.{ext}.base"
                r.write(path, older.read_bytes().decode())
                r.commit("a PR branch cut before this workflow")
                rc, out = snap(r, "verify-role", "--snapshot", snapshot, "--repo", str(r.path),
                               "--platform", platform, f"--role={role}")
                self.assertEqual((3, "DRIFT", digest(older), digest(REPO / path), False),
                                 (rc, out["status"], out["checkout_sha256"], out["snapshot_sha256"], out["pins_differ"]))
                self.assertTrue(all(out["pins"]["checkout"].values()), "the model and effort pins parse")


if __name__ == "__main__":
    unittest.main()
