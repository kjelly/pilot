"""Guard the three entry points against batch/worktree scheduling drift."""
import re
import unittest
from pathlib import Path


SKILLS = Path(__file__).resolve().parents[2]
NAMES = ("issue-to-pr", "pr-ready", "pr-review-merge")
FORBIDDEN = (
    r"git worktree add",
    r"at most two concurrent",
    r"two independent PRs concurrently",
    r"up to.*2 independent.*simultaneously",
    r"Cap active PR workflows at 2",
    r"at most two simultaneous",
    r"Allocate up to two",
    r"continue with other independent work",
    r"Proceed with other independent Issues",
    r"move on to independent PRs",
    r"最多\s*2\s*個獨立 Reviewer Subagents 並行",
    r"#42 #43 #44",
)


def batch_rules(text):
    return [pattern for pattern in FORBIDDEN if re.search(pattern, text, re.I)]


class SingleItemContractTests(unittest.TestCase):
    def test_entry_points_share_checkout_contract(self):
        for name in NAMES:
            with self.subTest(skill=name):
                skill = (SKILLS / name / "SKILL.md").read_text()
                self.assertIn("../_shared/single-item-checkout.md", skill)
                self.assertIn("exactly one Issue/PR", skill)
                self.assertIn("before analysis, edits, review, tests or delegation", skill)
                for path in ("SKILL.md", "README.md", "references/workflow.md"):
                    text = (SKILLS / name / path).read_text()
                    self.assertEqual([], batch_rules(text), f"{name}/{path}")

    def test_contract_preserves_safe_branch_identity(self):
        text = (SKILLS / "_shared/single-item-checkout.md").read_text()
        for required in ("git status --porcelain", "git branch --show-current",
                         "git rev-parse HEAD", "head repository", "head SHA",
                         "checked out elsewhere", "Never stash", "detached HEAD",
                         "git switch -c", "never creates a replacement",
                         "Never start another item", "acquire the Issue claim first",
                         "outside the checkout", "source repository/revision",
                         "absolute snapshot paths"):
            self.assertIn(required, text)

    def test_guard_rejects_previous_batch_rules(self):
        for old_rule in ("git worktree add -b issue/123 ../repo origin/main",
                         "Run at most two concurrent modifying Issue workstreams",
                         "Cap active PR workflows at 2",
                         "Allocate up to two independent PR reviewer subagents",
                         "Proceed with other independent Issues"):
            with self.subTest(rule=old_rule):
                self.assertTrue(batch_rules(old_rule))


if __name__ == "__main__":
    unittest.main()
