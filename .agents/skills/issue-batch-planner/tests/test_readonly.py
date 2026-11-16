"""B13: the planner can only run the read-only command forms; nothing else starts a process."""
from __future__ import annotations

import ast
import unittest
from pathlib import Path
from unittest.mock import patch

from planner_fixtures import planner

SHA = "a" * 40
ALLOWED = [
    ["gh", "--version"], ["git", "--version"],
    ["gh", "repo", "view", "OWNER/REPO", "--json", "defaultBranchRef"],
    ["gh", "issue", "list", "-R", "OWNER/REPO", "--state", "open", "--limit", "1000", "--json", planner.ISSUE_FIELDS],
    ["gh", "pr", "list", "-R", "OWNER/REPO", "--state", "open", "--limit", "1000", "--json", planner.PR_FIELDS],
    ["git", "ls-remote", "https://github.com/OWNER/REPO", "refs/heads/main"],
    ["git", "-C", "/repo", "cat-file", "-e", f"{SHA}^{{commit}}"],
    ["git", "-C", "/repo", "ls-tree", "-r", "-z", "--name-only", SHA],
    ["git", "-C", "/repo", "grep", "-h", "-o", "-E", planner.TEST_DEF_PATTERN, SHA, "--", "*.go", "*.py"],
    ["git", "-C", "/repo", "rev-parse", "--show-toplevel"],
    ["git", "-C", "/repo", "check-ignore", "-q", "--", "/repo/.verification/x"],
]
REFUSED = [
    ["gh", "issue", "edit", "1", "-R", "OWNER/REPO", "--add-label", "bug"],
    ["gh", "issue", "comment", "1", "-R", "OWNER/REPO", "--body", "x"],
    ["gh", "issue", "close", "1", "-R", "OWNER/REPO"],
    ["gh", "pr", "create", "-R", "OWNER/REPO"],
    ["gh", "api", "repos/OWNER/REPO/issues"],
    ["gh", "issue", "list", "-R", "OWNER/REPO", "--state", "open", "--limit", "1000", "--json", "number,body,assignees"],
    ["gh", "issue", "list", "-R", "OWNER/REPO", "--state", "all", "--limit", "1000", "--json", planner.ISSUE_FIELDS],
    ["git", "push", "origin", "HEAD"],
    ["git", "fetch", "origin"],
    ["git", "-C", "/repo", "checkout", SHA],
    ["git", "-C", "/repo", "fetch", "origin"],
    ["git", "-C", "/repo", "grep", "-h", "-o", "-E", "--open-files-in-pager=sh", SHA, "--", "*.go", "*.py"],
    ["git", "-C", "/repo", "grep", "-l", "-F", "-w", "TestFromAnIssueBody", SHA, "--"],
    ["git", "ls-remote", "https://github.com/OWNER/REPO", "refs/heads/../x"],
    ["sh", "-c", "gh issue list"],
    [], "gh issue list", ["gh", 1],
]


class ReadonlyRunnerTest(unittest.TestCase):
    def test_allowed_forms(self):
        for argv in ALLOWED:
            with self.subTest(argv=argv[:4]):
                self.assertIsNone(planner._readonly_problem(argv))

    def test_refused_forms_never_start_a_process(self):
        for argv in REFUSED:
            with self.subTest(argv=argv if isinstance(argv, str) else argv[:4]), \
                 patch.object(planner.subprocess, "run", side_effect=AssertionError("must not run")):
                self.assertIsNotNone(planner._readonly_problem(argv))
                with self.assertRaises(planner.PlannerError):
                    planner.run_readonly(argv)

    def test_subprocess_is_used_only_inside_run_readonly(self):
        tree = ast.parse(Path(planner.__file__).read_text(encoding="utf-8"))
        uses = []

        class Visitor(ast.NodeVisitor):
            stack: list[str] = []

            def visit_FunctionDef(self, node):
                self.stack.append(node.name)
                self.generic_visit(node)
                self.stack.pop()

            def visit_Attribute(self, node):
                if isinstance(node.value, ast.Name) and node.value.id == "subprocess":
                    uses.append((self.stack[-1] if self.stack else "<module>", node.attr))
                self.generic_visit(node)

            def visit_ImportFrom(self, node):
                if node.module == "subprocess":
                    uses.append(("<import-from>", ",".join(a.name for a in node.names)))

        Visitor().visit(tree)
        self.assertTrue(uses, "the AST check must see run_readonly's subprocess.run")
        self.assertEqual({"run_readonly"}, {fn for fn, _ in uses}, uses)
        for banned in ("os.system", "os.popen", "os.exec", "pty.spawn"):
            self.assertNotIn(banned, Path(planner.__file__).read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
