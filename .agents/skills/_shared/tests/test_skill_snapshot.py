"""skill_snapshot.py: the bundle survives a branch switch, a changed role is reported.

The scenario is the one the snapshot exists for: the invocation starts on a
branch with the skills, switches to an older/newer PR branch that changes or
deletes them, and must still run the verified copies. verify-role has three
outcomes: PASS (identical), DRIFT (the checkout's role file differs: dispatch
with the snapshot as the binding contract, exit 3) and STOP (nothing can be
dispatched: missing, invalid name, broken snapshot, resolves outside).
"""
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from gitrepo import Repo

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "skill_snapshot.py"
REPO = Path(__file__).resolve().parents[4]
ROLE = ".agents/skills/issue-to-pr/platforms/claude/agents/issue-coder.md"
TOML = ".agents/skills/issue-to-pr/platforms/codex/agents/issue-coder.toml"
AGY_SRC = ".agents/skills/issue-to-pr/platforms/agy/agents/issue-coder.md"
AGY_COPY = ".agents/agents/issue-coder.md"  # what agy loads: a copy made when agy is used
ROLE_TEXT = "---\nname: issue-coder\nmodel: claude-sonnet-5-5\neffort: xhigh\n---\n\nUse the verified checkout.\n"
TOML_TEXT = ('name = "issue-coder"\nmodel = "gpt-6.1-sol"\nmodel_reasoning_effort = "high"\n'
             'developer_instructions = """\nUse the verified checkout.\n"""\n')
AGY_TEXT = "---\nname: issue-coder\nmodel: inherit\n---\n\nUse the verified checkout.\n"
BASE_ROLES = Path(__file__).resolve().parent / "fixtures" / "base-roles"
BINDING = ("Your native role definition on disk comes from the checked-out target branch and differs "
           "from the invoking workflow. Read `{path}` now and follow it as your role contract; "
           "where they conflict, the snapshot wins.")


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_script():
    spec = importlib.util.spec_from_file_location("skill_snapshot_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def snap(repo, *args):
    p = subprocess.run([sys.executable, "-I", str(SCRIPT), *args], capture_output=True,
                       text=True, env=repo.env)
    return p.returncode, json.loads(p.stdout)


def skill_repo(case):
    r = Repo(case)
    for name in ("_shared", "pilot-code-review", "issue-to-pr", "pr-ready", "pr-review-merge"):
        r.write(f".agents/skills/{name}/README.md", f"{name}\n")
    r.write(".agents/skills/_shared/scripts/tool.py", "#!/usr/bin/env python3\n")
    os.chmod(r.path / ".agents/skills/_shared/scripts/tool.py", 0o755)
    r.write(ROLE, ROLE_TEXT)
    r.write(TOML, TOML_TEXT)
    r.write(AGY_SRC, AGY_TEXT)
    r.write(AGY_COPY, AGY_TEXT)
    (r.path / ".claude/agents").mkdir(parents=True)
    (r.path / ".codex/agents").mkdir(parents=True)
    os.symlink("../../" + ROLE, r.path / ".claude/agents/issue-coder.md")
    os.symlink("../../" + TOML, r.path / ".codex/agents/issue-coder.toml")
    r.commit("bundle")
    return r


class Snapshot(unittest.TestCase):
    def create(self, r):
        rc, out = snap(r, "create", "--repo", str(r.path), "--out-parent", str(r.base))
        self.assertEqual((0, "PASS"), (rc, out["status"]), out)
        return Path(out["snapshot_dir"]), out

    def test_create_records_source_revision_and_a_verifiable_manifest(self):
        r = skill_repo(self)
        snapshot, out = self.create(r)
        self.assertEqual(r.out("rev-parse", "HEAD"), out["head"])
        self.assertEqual(r.out("rev-parse", "HEAD^{tree}"), out["tree_id"])
        self.assertNotIn(r.path, [snapshot, *snapshot.parents], "outside the checkout")
        self.assertTrue((snapshot / ".agents/skills/_shared/scripts/tool.py").is_file())
        self.assertTrue(os.access(snapshot / ".agents/skills/_shared/scripts/tool.py", os.X_OK))
        link = snapshot / ".claude/agents/issue-coder.md"
        self.assertTrue(link.is_symlink())
        self.assertTrue(str(link.resolve()).startswith(str(snapshot)), "links stay inside")
        manifest = json.loads(Path(out["manifest"]).read_text())
        self.assertEqual(out["tree_id"], manifest["source_tree"])
        self.assertIn(ROLE, manifest["files"])
        rc, verified = snap(r, "verify", "--snapshot", str(snapshot))
        self.assertEqual((0, "PASS"), (rc, verified["status"]))

    def test_snapshot_holds_the_committed_head_content(self):
        r = skill_repo(self)
        r.write(ROLE, "---\nname: issue-coder\n---\n\nSecond revision.\n")
        head = r.commit("second revision of the role")
        snapshot, out = self.create(r)
        self.assertEqual(head, out["head"])
        self.assertEqual((r.path / ROLE).read_text(), (snapshot / ROLE).read_text())
        self.assertIn("Second revision.", (snapshot / ROLE).read_text())

    def test_snapshot_is_refused_for_a_dirty_checkout(self):
        for dirty in (lambda r: r.write(ROLE, "edited\n"), lambda r: r.write("untracked.txt")):
            r = skill_repo(self)
            dirty(r)
            rc, out = snap(r, "create", "--repo", str(r.path), "--out-parent", str(r.base))
            self.assertEqual((1, "STOP"), (rc, out["status"]))
            self.assertIn("not clean", out["error"])
            self.assertEqual([], [p.name for p in r.base.iterdir() if p.name.startswith("single-item-skills")])

    def test_snapshot_inside_the_checkout_is_refused(self):
        r = skill_repo(self)
        rc, out = snap(r, "create", "--repo", str(r.path), "--out-parent", str(r.path))
        self.assertEqual((1, "STOP"), (rc, out["status"]))
        self.assertIn("outside the checkout", out["error"])

    def test_missing_bundle_path_is_refused(self):
        r = Repo(self)
        r.write("README.md")
        r.commit("no skills")
        rc, out = snap(r, "create", "--repo", str(r.path), "--out-parent", str(r.base))
        self.assertEqual((1, "STOP"), (rc, out["status"]))
        self.assertIn("skill bundle", out["error"])

    def test_snapshot_survives_a_switch_to_a_branch_without_the_skills(self):
        r = skill_repo(self)
        snapshot, _ = self.create(r)
        r.branch_from_main("old-pr")
        r.git("rm", "-rq", ".agents", ".claude", ".codex")
        r.write("old.txt")
        r.commit("old branch predates the skills")
        self.assertFalse((r.path / ".agents").exists())
        self.assertTrue((snapshot / ROLE).is_file())
        self.assertEqual("PASS", snap(r, "verify", "--snapshot", str(snapshot))[1]["status"])

    def test_tampered_snapshot_fails_verification(self):
        for tamper in ("change", "add", "remove"):
            with self.subTest(tamper=tamper):
                r = skill_repo(self)
                snapshot, _ = self.create(r)
                if tamper == "change":
                    (snapshot / ROLE).write_text("tampered\n")
                elif tamper == "add":
                    (snapshot / ".agents/skills/_shared/extra.md").write_text("new\n")
                else:
                    (snapshot / ".agents/skills/_shared/README.md").unlink()
                rc, out = snap(r, "verify", "--snapshot", str(snapshot))
                self.assertEqual((1, "STOP"), (rc, out["status"]))
                self.assertIn("differs from its manifest", out["error"])


    def test_retargeted_symlink_inside_the_snapshot_fails_verification(self):
        r = skill_repo(self)
        snapshot, _ = self.create(r)
        link = snapshot / ".claude/agents/issue-coder.md"
        self.assertTrue(link.is_symlink())
        link.unlink()
        # still a valid, in-snapshot target, so only the recorded link target gives it away
        os.symlink("../../" + TOML, link)
        self.assertTrue(link.exists())
        rc, out = snap(r, "verify", "--snapshot", str(snapshot))
        self.assertEqual((1, "STOP"), (rc, out["status"]))
        self.assertIn("differs from its manifest", out["error"])
        self.assertIn(".claude/agents/issue-coder.md", out["error"])

    def test_dirty_submodule_hidden_by_ignore_configuration_refuses_the_snapshot(self):
        sub = Repo(self, "sub")
        sub.write("f", "1\n")
        sub.commit("sub init")
        r = skill_repo(self)
        r.git("-c", "protocol.file.allow=always", "submodule", "add", "-q", str(sub.path), "sub")
        r.commit("add submodule")
        self.create(r)  # control: a clean submodule is fine
        (r.path / "sub" / "f").write_text("edited inside the submodule\n")
        r.git("config", "diff.ignoreSubmodules", "all")
        self.assertEqual("", r.out("status", "--porcelain"), "the setting hides it from status")
        rc, out = snap(r, "create", "--repo", str(r.path), "--out-parent", str(r.base))
        self.assertEqual((1, "STOP"), (rc, out["status"]))
        self.assertIn("not clean", out["error"])


class RoleVerification(unittest.TestCase):
    PLATFORMS = {"claude": (ROLE, ".claude/agents/issue-coder.md", ROLE_TEXT),
                 "codex": (TOML, ".codex/agents/issue-coder.toml", TOML_TEXT),
                 "agy": (AGY_COPY, AGY_COPY, AGY_TEXT)}

    def verify(self, r, snapshot, platform="claude", role="issue-coder"):
        return snap(r, "verify-role", "--snapshot", str(snapshot), "--repo", str(r.path),
                    "--platform", platform, "--role", role)

    def setUp(self):
        self.r = skill_repo(self)
        rc, out = snap(self.r, "create", "--repo", str(self.r.path), "--out-parent",
                       str(self.r.base))
        self.snapshot = Path(out["snapshot_dir"])

    def edit_on_a_branch(self, platform, transform):
        """The target branch changes the role file this platform loads."""
        edited, _loaded, text = self.PLATFORMS[platform]
        self.r.branch_from_main("pr")
        self.r.write(edited, transform(text))
        self.r.commit(f"pr changes the {platform} role")

    def test_identical_roles_pass_on_every_platform(self):
        for platform in self.PLATFORMS:
            with self.subTest(platform=platform):
                rc, out = self.verify(self.r, self.snapshot, platform)
                self.assertEqual((0, "PASS"), (rc, out["status"]), out)
                self.assertEqual(out["snapshot_sha256"], out["checkout_sha256"])
                self.assertNotIn("binding_statement", out)

    def test_a_changed_role_is_drift_with_the_snapshot_as_binding_contract(self):
        for platform, (edited, loaded, text) in self.PLATFORMS.items():
            with self.subTest(platform=platform):
                self.setUp()
                self.edit_on_a_branch(platform, lambda t: t.replace("Use the verified checkout.",
                                                                    "Old prompt: create a worktree."))
                rc, out = self.verify(self.r, self.snapshot, platform)
                self.assertEqual((3, "DRIFT"), (rc, out["status"]), out)
                snapshot_role = Path(out["snapshot_role"])
                self.assertTrue(snapshot_role.is_absolute() and self.snapshot in snapshot_role.parents)
                self.assertTrue(str(snapshot_role).endswith(
                    AGY_SRC if platform == "agy" else edited))
                self.assertEqual(self.r.path / loaded, Path(out["checkout_role"]))
                self.assertEqual(digest(snapshot_role), out["snapshot_sha256"])
                self.assertEqual(digest(self.r.path / loaded), out["checkout_sha256"])
                self.assertNotEqual(out["snapshot_sha256"], out["checkout_sha256"])
                self.assertFalse(out["pins_differ"], "only the prompt text changed")
                self.assertEqual(out["pins"]["snapshot"], out["pins"]["checkout"])
                self.assertEqual(BINDING.format(path=snapshot_role), out["binding_statement"])
                self.assertIn("the snapshot wins", out["binding_statement"])
                # the other platforms' role files are untouched: still PASS (control)
                for other in set(self.PLATFORMS) - {platform}:
                    self.assertEqual(0, self.verify(self.r, self.snapshot, other)[0])

    def test_a_changed_model_or_effort_pin_is_reported(self):
        cases = (("claude", "model: claude-sonnet-5-5", "model: claude-haiku-5",
                  {"model": "claude-sonnet-5-5", "effort": "xhigh"}, {"model": "claude-haiku-5", "effort": "xhigh"}),
                 ("claude", "effort: xhigh", "effort: low",
                  {"model": "claude-sonnet-5-5", "effort": "xhigh"}, {"model": "claude-sonnet-5-5", "effort": "low"}),
                 ("codex", 'model = "gpt-6.1-sol"', 'model = "gpt-7"',
                  {"model": "gpt-6.1-sol", "effort": "high"}, {"model": "gpt-7", "effort": "high"}),
                 ("codex", 'model_reasoning_effort = "high"', 'model_reasoning_effort = "low"',
                  {"model": "gpt-6.1-sol", "effort": "high"}, {"model": "gpt-6.1-sol", "effort": "low"}),
                 ("agy", "model: inherit", "model: some-model",
                  {"model": "inherit", "effort": None}, {"model": "some-model", "effort": None}))
        for platform, old, new, was, now in cases:
            with self.subTest(platform=platform, change=new):
                self.setUp()
                self.edit_on_a_branch(platform, lambda t: t.replace(old, new))
                rc, out = self.verify(self.r, self.snapshot, platform)
                self.assertEqual((3, "DRIFT", True), (rc, out["status"], out["pins_differ"]), out)
                self.assertEqual({"snapshot": was, "checkout": now}, out["pins"])

    def test_pin_lookalikes_in_the_prompt_are_not_pins(self):
        """`model = ...` or `model: ...` inside the prompt text is not the role's pin."""
        def append_to_prompt(line, drop=None):
            def edit(text):
                if drop:
                    text = "\n".join(l for l in text.split("\n") if not l.startswith(drop))
                if text.endswith('"""\n'):  # TOML: inside developer_instructions
                    return text[:-len('"""\n')] + line + '\n"""\n'
                return text + line + "\n"
            return edit
        for platform, line, pin in (("claude", "model: zzz\neffort: zzz", "model:"),
                                    ("codex", 'model = "zzz"', "model ="),
                                    ("agy", "model: zzz", "model:")):
            with self.subTest(platform=platform, pin="kept"):
                self.setUp()
                self.edit_on_a_branch(platform, append_to_prompt(line))
                rc, out = self.verify(self.r, self.snapshot, platform)
                self.assertEqual((3, "DRIFT", False), (rc, out["status"], out["pins_differ"]), out)
            with self.subTest(platform=platform, pin="removed"):
                # the real model pin is gone and a lookalike sits in the prompt: still no model pin
                self.setUp()
                self.edit_on_a_branch(platform, append_to_prompt(line, drop=pin))
                rc, out = self.verify(self.r, self.snapshot, platform)
                self.assertEqual((3, "DRIFT", True), (rc, out["status"], out["pins_differ"]), out)
                self.assertIsNone(out["pins"]["checkout"]["model"])
                self.assertIsNotNone(out["pins"]["snapshot"]["model"])

    def test_role_missing_on_the_checked_out_branch_is_stop(self):
        for platform, rel in (("claude", ".claude/agents/issue-coder.md"), ("agy", AGY_COPY)):
            with self.subTest(platform=platform):
                self.setUp()
                self.r.branch_from_main("pr")
                self.r.git("rm", "-q", rel)
                self.r.commit("pr drops the role file")
                rc, out = self.verify(self.r, self.snapshot, platform)
                self.assertEqual((1, "STOP"), (rc, out["status"]))
                self.assertIn("missing", out["error"])

    def test_dangling_role_link_is_stop(self):
        r = self.r
        r.branch_from_main("pr")
        r.git("rm", "-q", ROLE)
        r.commit("pr deletes the role target; the .claude link now dangles")
        rc, out = self.verify(r, self.snapshot)
        self.assertEqual((1, "STOP"), (rc, out["status"]))
        self.assertIn("missing", out["error"])

    def test_role_link_pointing_outside_the_checkout_is_stop(self):
        r = self.r
        outside = r.base / "elsewhere.md"
        outside.write_text((r.path / ROLE).read_text())
        link = r.path / ".claude/agents/issue-coder.md"
        link.unlink()
        os.symlink(str(outside), link)
        r.commit("link role outside the checkout")
        rc, out = self.verify(r, self.snapshot)
        self.assertEqual((1, "STOP"), (rc, out["status"]))
        self.assertIn("outside the checkout", out["error"])

    def test_invalid_role_names_are_stop_before_any_path_is_built(self):
        """A role is a plain file name: no separators, no `..`, not empty."""
        outside = self.r.base / "outside.md"
        outside.write_text("---\nname: x\n---\n\nsecret\n")
        for bad in ("", "..", "../outside", "a/b", "/etc/passwd", "..\\x", ".hidden", "-flag",
                    "issue-coder/../issue-coder", "issue..coder"):
            with self.subTest(role=bad):
                rc, out = snap(self.r, "verify-role", "--snapshot", str(self.snapshot), "--repo",
                               str(self.r.path), "--platform", "claude", f"--role={bad}")
                self.assertEqual((1, "STOP"), (rc, out["status"]))
                self.assertIn("invalid role name", out["error"])
        rc, out = self.verify(self.r, self.snapshot)  # control: the real role still verifies
        self.assertEqual((0, "PASS"), (rc, out["status"]))

    def test_a_broken_snapshot_is_stop_even_when_the_role_is_identical(self):
        (self.snapshot / ROLE).write_text("tampered\n")
        rc, out = self.verify(self.r, self.snapshot)
        self.assertEqual((1, "STOP"), (rc, out["status"]))
        self.assertIn("differs from its manifest", out["error"])

    def test_a_snapshot_with_two_agy_copies_of_a_role_is_stop(self):
        """agy: the snapshot copy must be unambiguous (not a DRIFT against a guess)."""
        twin = self.r.path / ".agents/skills/pr-ready/platforms/agy/agents/issue-coder.md"
        self.r.write(".agents/skills/pr-ready/platforms/agy/agents/issue-coder.md", AGY_TEXT)
        self.r.commit("a second agy definition of the same role")
        rc, out = snap(self.r, "create", "--repo", str(self.r.path), "--out-parent", str(self.r.base))
        rc, out = self.verify(self.r, out["snapshot_dir"], "agy")
        self.assertEqual((1, "STOP"), (rc, out["status"]))
        self.assertIn("expected one", out["error"])
        self.assertTrue(twin.exists())


class RealRoleDefinitions(unittest.TestCase):
    """Real files: the format the pin parser reads, and the roles an older PR branch carries."""

    def test_pins_parse_from_every_real_role_definition(self):
        module = load_script()
        shapes = (("claude", ".claude/agents/*.md", "claude-", {"xhigh"}),
                  ("codex", ".codex/agents/*.toml", "gpt-", {"high"}),
                  ("agy", ".agents/skills/*/platforms/agy/agents/*.md", "inherit", {None}))
        for platform, pattern, model_prefix, efforts in shapes:
            roles = [p for p in sorted(REPO.glob(pattern))
                     if p.name.split("-")[0] in ("issue", "pr", "prm")]
            self.assertEqual(8, len(roles), f"{platform}: expected the 8 project roles")
            for path in roles:
                with self.subTest(role=f"{platform}/{path.name}"):
                    pins = module.role_pins(path, platform)
                    self.assertTrue(str(pins["model"]).startswith(model_prefix), pins)
                    self.assertIn(pins["effort"], efforts, pins)

    def test_an_older_branchs_real_role_files_are_drift_not_blocked(self):
        """pr-coder and prm-reviewer as fdb6f03e (before #205) shipped them, claude and codex."""
        cases = (("pr-coder", "pr-ready", "claude", "md"), ("pr-coder", "pr-ready", "codex", "toml"),
                 ("prm-reviewer", "pr-review-merge", "claude", "md"),
                 ("prm-reviewer", "pr-review-merge", "codex", "toml"))
        for role, skill, platform, ext in cases:
            with self.subTest(role=role, platform=platform):
                path = f".agents/skills/{skill}/platforms/{platform}/agents/{role}.{ext}"
                loaded = f".{platform}/agents/{role}.{ext}"
                current = (REPO / path).read_bytes().decode()
                r = Repo(self)
                for name in ("_shared", "pilot-code-review", "issue-to-pr", "pr-ready", "pr-review-merge"):
                    r.write(f".agents/skills/{name}/README.md", f"{name}\n")
                r.write(path, current)
                r.write(".claude/agents/.keep", "")  # the bundle needs both agent directories
                r.write(".codex/agents/.keep", "")
                os.symlink("../../" + path, r.path / loaded)
                r.commit("the bundle with this workflow's role")
                rc, out = snap(r, "create", "--repo", str(r.path), "--out-parent", str(r.base))
                self.assertEqual(0, rc, out)
                r.branch_from_main("older-pr")
                older = BASE_ROLES / f"{role}.{platform}.{ext}.base"
                r.write(path, older.read_bytes().decode())
                r.commit("a PR branch cut before this workflow")
                rc, out = snap(r, "verify-role", "--snapshot", out["snapshot_dir"], "--repo",
                               str(r.path), "--platform", platform, "--role", role)
                self.assertEqual((3, "DRIFT"), (rc, out["status"]), out)
                self.assertEqual(digest(older), out["checkout_sha256"])
                self.assertEqual(digest(REPO / path), out["snapshot_sha256"])
                self.assertFalse(out["pins_differ"], "the model/effort pins did not change")
                self.assertIsNotNone(out["pins"]["checkout"]["model"])
                self.assertIsNotNone(out["pins"]["checkout"]["effort"])
                self.assertIn("the snapshot wins", out["binding_statement"])


if __name__ == "__main__":
    unittest.main()
