"""Installer smoke tests create only temporary HOME/project paths."""
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
        canonical = self.home / ".agents/skills/issue-to-pr"
        claude = self.home / ".claude/skills/issue-to-pr"
        agy = self.home / ".gemini/antigravity-cli/skills/issue-to-pr"
        self.assertTrue((canonical / "SKILL.md").is_file())
        self.assertTrue(claude.is_symlink())
        self.assertTrue(agy.is_symlink())
        self.assertTrue((self.home / ".codex/agents/issue-reviewer.toml").is_file())
        self.assertTrue((self.home / ".gemini/config/agents/issue-reviewer.md").is_file())
        two = self.run_install("--global")
        self.assertEqual(0, two.returncode, two.stderr)
        self.assertIn("KEEP:", two.stdout)

    def test_project_install(self):
        repo = self.root / "repo"
        repo.mkdir()
        subprocess.run(["git", "-C", str(repo), "init"], capture_output=True, check=True)
        result = self.run_install("--project", str(repo))
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertTrue((repo / ".agents/skills/issue-to-pr/SKILL.md").is_file())
        self.assertTrue((repo / ".claude/skills/issue-to-pr").is_symlink())
        self.assertTrue((repo / ".codex/agents/issue-sa.toml").is_file())
        self.assertTrue((repo / ".claude/agents/issue-coder.md").is_file())
        self.assertTrue((repo / ".agents/agents/issue-reviewer.md").is_file())

    def test_conflict_requires_force_and_backs_up(self):
        canonical = self.home / ".agents/skills/issue-to-pr"
        canonical.mkdir(parents=True)
        (canonical / "SKILL.md").write_text("another skill")
        result = self.run_install("--global")
        self.assertEqual(3, result.returncode)
        again = self.run_install("--global", "--force")
        self.assertEqual(0, again.returncode, again.stderr)
        self.assertNotEqual("another skill", (canonical / "SKILL.md").read_text())
        self.assertTrue(list(canonical.parent.glob("issue-to-pr.backup-*")))


if __name__ == "__main__":
    unittest.main()
