"""umbrella.py resolve (V1, V2). Every view is built from issue-batch-planner's captured `gh issue view`
shapes (kjelly/pilot #354 and #142 right after the first file_umbrella.py --execute, AGENTS.md §5.6)."""
from __future__ import annotations

import copy
import io
import json
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
import umbrella  # noqa: E402

CAPTURED = Path(__file__).resolve().parents[2] / "issue-batch-planner" / "tests" / "fixtures" / "captured"
SAMPLES = json.loads((CAPTURED / "gh_issue_view.json").read_text(encoding="utf-8"))
REPO = "OWNER/REPO"
BATCH = "29b14e9b200a"


def body(*, members="142 216", batch=BATCH, extra=()) -> str:
    lines = ["Tracking body.", ""] + list(extra)
    if members is not None:
        lines.append(f"issue-batch-planner issues: {members}")
    if batch is not None:
        lines.append(f"issue-batch-planner batch: {batch}")
    return "\n".join(lines) + "\n"


def sub_node(n: int, state: str = "OPEN", repo: str = REPO) -> dict:
    out = copy.deepcopy(SAMPLES["umbrella_after_execute"]["subIssues"]["nodes"][0])
    out.update(number=n, state=state, url=f"https://github.com/{repo}/issues/{n}")
    return out


def umbrella_view(n: int = 354, *, subs=((142, "OPEN"), (216, "OPEN")), state="OPEN", text=None, total=None):
    v = copy.deepcopy(SAMPLES["umbrella_after_execute"])
    nodes = [sub_node(s, st) for s, st in subs]
    v.update(number=n, state=state, url=f"https://github.com/{REPO}/issues/{n}", body=body() if text is None else text,
             subIssues={"nodes": nodes, "totalCount": len(nodes) if total is None else total})
    return v


def child_view(n: int, parent: int | None = 354, parent_repo: str = REPO, text: str = "A bug report.") -> dict:
    v = copy.deepcopy(SAMPLES["child_after_execute"] if parent else SAMPLES["plain"])
    v.update(number=n, body=text, url=f"https://github.com/{REPO}/issues/{n}")
    if parent:
        v["parent"] = dict(v["parent"], number=parent, url=f"https://github.com/{parent_repo}/issues/{parent}")
    return v


class ResolveTest(unittest.TestCase):
    def setUp(self):
        self.views = {354: umbrella_view(), 142: child_view(142), 216: child_view(216), 77: child_view(77, None)}
        self.calls: list[int] = []

    def fetch(self, n):
        self.calls.append(n)
        if n not in self.views:
            raise umbrella.UmbrellaRefused(f"gh issue view {n} failed: not found")
        return copy.deepcopy(self.views[n])

    def resolve(self, n):
        return umbrella.resolve(REPO, n, self.fetch)

    def assertRefused(self, n, needle):
        with self.assertRaises(umbrella.UmbrellaRefused) as caught:
            self.resolve(n)
        self.assertIn(needle, str(caught.exception))

    def test_captured_shapes_resolve(self):
        """The real #354/#142 views, with the body replaced by the new template's two lines."""
        self.views[354] = copy.deepcopy(SAMPLES["umbrella_after_execute"])
        self.views[354]["body"] = body()
        self.views[142] = copy.deepcopy(SAMPLES["child_after_execute"])
        self.assertEqual([142, 216], self.resolve(142)["sub_issues"])

    def test_v1_umbrella_or_sub_issue_resolve_to_the_same_umbrella(self):
        for n, redirected in ((354, False), (216, True), (142, True)):
            with self.subTest(n=n):
                got = self.resolve(n)
                self.assertEqual({"mode": "umbrella", "issue": n, "redirected": redirected, "umbrella": 354,
                                  "umbrella_url": f"https://github.com/{REPO}/issues/354", "batch_id": BATCH,
                                  "sub_issues": [142, 216], "closed_sub_issues": []}, got)

    def test_v1_ordinary_parents_and_no_parent_are_single_mode(self):
        self.views[500] = umbrella_view(500, text="An ordinary tracking Issue, not filed by the planner.")
        self.views[143] = child_view(143, 500)
        self.views[144] = child_view(144, 600, parent_repo="other/repo")
        for n in (77, 143, 144):
            with self.subTest(n=n):
                self.assertEqual({"mode": "single", "issue": n}, self.resolve(n))
        self.assertNotIn(600, self.calls, "a parent in another repository is never read")

    def test_v1_closed_sub_issues_are_listed_not_worked(self):
        self.views[354] = umbrella_view(subs=((142, "CLOSED"), (216, "OPEN")))
        got = self.resolve(216)
        self.assertEqual(([216], [142]), (got["sub_issues"], got["closed_sub_issues"]))

    def test_v2_refusals(self):
        five = tuple((n, "OPEN") for n in (1, 2, 3, 4, 5))
        cases = (
            ("closed umbrella", dict(state="CLOSED"), "is CLOSED"),
            ("incomplete list", dict(total=3), "the list is incomplete"),
            ("no open sub-issue", dict(subs=((142, "CLOSED"), (216, "CLOSED"))), "0 open sub-issues"),
            ("five open sub-issues", dict(subs=five, text=body(members="1 2 3 4 5")), "5 open sub-issues"),
            ("two batch lines", dict(text=body(extra=[f"issue-batch-planner batch: {'a' * 12}"])), "found 2"),
            ("malformed batch line", dict(text=body(batch="XYZ")), "exactly one well-formed"),
            ("no member line", dict(text=body(members=None)), "--update-body"),
            ("two member lines", dict(text=body(extra=["issue-batch-planner issues: 142 216"])), "found 2"),
            ("member listed twice", dict(text=body(members="142 142 216")), "twice"),
            ("linking stopped part-way", dict(subs=((142, "OPEN"),)), "stopped part-way"),
            ("a sub-issue added by hand", dict(subs=((142, "OPEN"), (216, "OPEN"), (300, "OPEN"))), "stopped part-way"),
        )
        for name, kwargs, needle in cases:
            with self.subTest(name):
                self.views[354] = umbrella_view(**kwargs)
                self.assertRefused(354, needle)
        self.views[354] = umbrella_view()
        self.views[354]["subIssues"]["nodes"][1] = sub_node(216, repo="other/repo")
        self.assertRefused(216, "another repository")

    def test_v2_member_line_must_name_the_selected_sub_issue(self):
        self.views[354] = umbrella_view(subs=((142, "OPEN"), (216, "OPEN")))
        self.views[999] = child_view(999)
        self.assertRefused(999, "is not a member")

    def test_v2_malformed_or_failed_reads_are_refused(self):
        for name, value in (("not an object", []), ("wrong number", dict(umbrella_view(), number=1)),
                            ("subIssues without totalCount", dict(umbrella_view(), subIssues={"nodes": []})),
                            ("body is a list", dict(umbrella_view(), body=["x"]))):
            with self.subTest(name):
                self.views[354] = value
                self.assertRefused(354, "unexpected gh issue view shape")
        self.views[354] = umbrella_view()
        del self.views[354]
        self.assertRefused(142, "not found")


class CliTest(unittest.TestCase):
    def run_cli(self, completed):
        out = io.StringIO()
        with patch.object(umbrella.subprocess, "run", return_value=completed) as run, redirect_stdout(out):
            code = umbrella.main(["resolve", "--repo", REPO, "--issue", "77"])
        return code, json.loads(out.getvalue()), run

    def test_cli_single_and_refusal_exit_codes(self):
        plain = json.dumps(child_view(77, None))
        code, out, run = self.run_cli(subprocess.CompletedProcess([], 0, plain, ""))
        self.assertEqual((0, "single"), (code, out["mode"]))
        self.assertEqual(["gh", "issue", "view", "77", "-R", REPO, "--json", umbrella.VIEW_FIELDS],
                         run.call_args.args[0])
        for name, completed in (("gh fails", subprocess.CompletedProcess([], 1, "", "HTTP 502")),
                                ("not JSON", subprocess.CompletedProcess([], 0, "<html>", ""))):
            with self.subTest(name):
                code, out, _ = self.run_cli(completed)
                self.assertEqual((2, "REFUSED"), (code, out["status"]))

    def test_cli_only_reads(self):
        """The only process umbrella.py starts is `gh issue view`."""
        import ast
        tree = ast.parse((SCRIPTS / "umbrella.py").read_text(encoding="utf-8"))
        calls = [n for n in ast.walk(tree) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
                 and n.value.id == "subprocess" and n.attr not in ("TimeoutExpired",)]
        self.assertEqual(["run"], [n.attr for n in calls])


if __name__ == "__main__":
    unittest.main()
