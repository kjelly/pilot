"""skill_snapshot.py: the bundle survives a branch switch, a changed role is caught.

The scenario is the one the snapshot exists for: the invocation starts on a
branch with the skills, switches to an older/newer PR branch that changes or
deletes them, and must still run the verified copies.
"""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from gitrepo import Repo

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "skill_snapshot.py"
ROLE = ".agents/skills/issue-to-pr/platforms/claude/agents/issue-coder.md"
TOML = ".agents/skills/issue-to-pr/platforms/codex/agents/issue-coder.toml"


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
    r.write(ROLE, "---\nname: issue-coder\n---\n\nUse the verified checkout.\n")
    r.write(TOML, 'name = "issue-coder"\ndeveloper_instructions = """\nUse the verified checkout.\n"""\n')
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
    def verify(self, r, snapshot, platform="claude"):
        return snap(r, "verify-role", "--snapshot", str(snapshot), "--repo", str(r.path),
                    "--platform", platform, "--role", "issue-coder")

    def setUp(self):
        self.r = skill_repo(self)
        rc, out = snap(self.r, "create", "--repo", str(self.r.path), "--out-parent",
                       str(self.r.base))
        self.snapshot = Path(out["snapshot_dir"])

    def test_unchanged_roles_pass_on_both_platforms(self):
        for platform in ("claude", "codex"):
            rc, out = self.verify(self.r, self.snapshot, platform)
            self.assertEqual((0, "PASS"), (rc, out["status"]), out)

    def test_role_changed_by_the_checked_out_branch_blocks(self):
        r = self.r
        r.branch_from_main("pr")
        r.write(ROLE, "---\nname: issue-coder\n---\n\nOld prompt: create a worktree.\n")
        r.commit("pr changes the role")
        rc, out = self.verify(r, self.snapshot)
        self.assertEqual((1, "STOP"), (rc, out["status"]))
        self.assertIn("differs from the verified snapshot", out["error"])
        # the other platform's role file was not touched: still verified (control)
        rc, other = self.verify(r, self.snapshot, "codex")
        self.assertEqual((0, "PASS"), (rc, other["status"]))

    def test_role_missing_on_the_checked_out_branch_blocks(self):
        r = self.r
        r.branch_from_main("pr")
        r.git("rm", "-q", ".claude/agents/issue-coder.md")
        r.commit("pr drops the claude role link")
        rc, out = self.verify(r, self.snapshot)
        self.assertEqual((1, "STOP"), (rc, out["status"]))
        self.assertIn("missing", out["error"])

    def test_dangling_role_link_blocks(self):
        r = self.r
        r.branch_from_main("pr")
        r.git("rm", "-q", ROLE)
        r.commit("pr deletes the role target; the .claude link now dangles")
        rc, out = self.verify(r, self.snapshot)
        self.assertEqual((1, "STOP"), (rc, out["status"]))
        self.assertIn("missing", out["error"])

    def test_role_link_pointing_outside_the_checkout_blocks(self):
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

    def test_invalid_role_names_are_blocked_before_any_path_is_built(self):
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

    def test_tampered_snapshot_blocks_role_verification(self):
        (self.snapshot / ROLE).write_text("tampered\n")
        rc, out = self.verify(self.r, self.snapshot)
        self.assertEqual((1, "STOP"), (rc, out["status"]))
        self.assertIn("differs from its manifest", out["error"])


if __name__ == "__main__":
    unittest.main()
