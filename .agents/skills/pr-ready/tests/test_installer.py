"""Installer smoke tests create only temporary HOME/project paths.

--force must back up what it replaces (the usage text promises it); the
installer used to `rm -rf` the existing skill or agent file instead.
"""
from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "install.sh"


class InstallerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.env = dict(os.environ, HOME=str(self.home))

    def run_install(self, *args):
        return subprocess.run(["bash", str(SCRIPT), *args], env=self.env,
                              text=True, capture_output=True, check=False)

    def test_global_install_and_idempotency(self):
        one = self.run_install("--global")
        self.assertEqual(0, one.returncode, one.stderr)
        canonical = self.home / ".agents/skills/pr-ready"
        self.assertTrue((canonical / "SKILL.md").is_file())
        self.assertTrue((self.home / ".claude/skills/pr-ready").is_symlink())
        self.assertTrue((self.home / ".gemini/antigravity-cli/skills/pr-ready").is_symlink())
        self.assertTrue((self.home / ".codex/agents/pr-reviewer.toml").is_file())
        self.assertTrue((self.home / ".gemini/config/agents/pr-reviewer.md").is_file())
        two = self.run_install("--global")
        self.assertEqual(0, two.returncode, two.stderr)
        self.assertIn("KEEP", two.stdout)
        self.assertNotIn("BACKUP", two.stdout)

    def test_project_install(self):
        repo = self.root / "repo"
        repo.mkdir()
        subprocess.run(["git", "-C", str(repo), "init"], capture_output=True, check=True)
        result = self.run_install("--project", str(repo))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue((repo / ".agents/skills/pr-ready/SKILL.md").is_file())
        self.assertTrue((repo / ".claude/skills/pr-ready").is_symlink())
        self.assertTrue((repo / ".codex/agents/pr-sa.toml").is_file())
        self.assertTrue((repo / ".claude/agents/pr-coder.md").is_file())
        self.assertTrue((repo / ".agents/agents/pr-reviewer.md").is_file())

    def test_skill_conflict_requires_force_and_backs_up(self):
        canonical = self.home / ".agents/skills/pr-ready"
        canonical.mkdir(parents=True)
        (canonical / "SKILL.md").write_text("another skill")
        result = self.run_install("--global")
        self.assertEqual(3, result.returncode)
        self.assertEqual("another skill", (canonical / "SKILL.md").read_text())
        again = self.run_install("--global", "--force")
        self.assertEqual(0, again.returncode, again.stderr)
        self.assertNotEqual("another skill", (canonical / "SKILL.md").read_text())
        backups = list(canonical.parent.glob("pr-ready.backup-*"))
        self.assertEqual(1, len(backups), backups)
        self.assertEqual("another skill", (backups[0] / "SKILL.md").read_text())

    def test_agent_conflict_requires_force_and_backs_up(self):
        agents = self.home / ".codex/agents"
        agents.mkdir(parents=True)
        (agents / "pr-sa.toml").write_text("name = \"pr-sa\"\n# hand-edited\n")
        result = self.run_install("--global")
        self.assertEqual(3, result.returncode)
        self.assertIn("hand-edited", (agents / "pr-sa.toml").read_text())
        again = self.run_install("--global", "--force")
        self.assertEqual(0, again.returncode, again.stderr)
        self.assertNotIn("hand-edited", (agents / "pr-sa.toml").read_text())
        backups = list(agents.glob("pr-sa.toml.backup-*"))
        self.assertEqual(1, len(backups), backups)
        self.assertIn("hand-edited", backups[0].read_text())


if __name__ == "__main__":
    unittest.main()
