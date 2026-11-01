"""Relative Markdown links in the single-item skills resolve the way Claude Code reads them.

Claude Code presents a skill's base directory as the symlink path
`.claude/skills/<name>`, and its Read tool resolves `../x` against that path
*lexically*: `../_shared/f.md` becomes `.claude/skills/_shared/f.md`, which does
not exist (`_shared` is not a skill, so it cannot be linked there; the layout
test in cmd/pilot/cmd rejects non-skill entries). Codex and agy read the real
`.agents/skills/<name>` path. A link has to resolve in both views.
"""
import os
import posixpath
import re
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
NAMES = ("issue-to-pr", "pr-ready", "pr-review-merge", "_shared")

FENCE = re.compile(r"^(```|~~~).*?^\1[^\n]*$", re.S | re.M)
INLINE_CODE = re.compile(r"`[^`\n]*`")
INLINE_LINK = re.compile(r"\]\(\s*<?([^)\s>]+)>?(?:\s+[\"'][^)]*[\"'])?\s*\)")
REF_LINK = re.compile(r"^ {0,3}\[[^\]\n]+\]:\s*<?(\S+?)>?(?:\s|$)", re.M)
EXTERNAL = re.compile(r"^(?:[a-zA-Z][a-zA-Z0-9+.-]*:|//)")


def link_targets(text):
    """Relative link targets of a Markdown document, code blocks and spans excluded."""
    text = INLINE_CODE.sub("", FENCE.sub("", text))
    found = INLINE_LINK.findall(text) + REF_LINK.findall(text)
    out = []
    for target in found:
        if not target or target.startswith("#") or EXTERNAL.match(target):
            continue
        out.append(re.split(r"[#?]", target, maxsplit=1)[0])
    return [t for t in out if t]


def unresolved_links(root, names=NAMES):
    """(file, link, why) for every link that does not resolve in both views."""
    root = Path(root)
    problems = []
    for name in names:
        base = root / ".agents" / "skills" / name
        for md in sorted(base.rglob("*.md")):
            sub = md.parent.relative_to(base).as_posix()
            for link in link_targets(md.read_text(encoding="utf-8")):
                rel = md.relative_to(root).as_posix()
                if link.startswith("/"):
                    problems.append((rel, link, "absolute path, not repository-relative"))
                    continue
                real = posixpath.normpath(posixpath.join(md.parent.as_posix(), link))
                if not os.path.exists(real):
                    problems.append((rel, link, f"missing at {real}"))
                    continue
                if name == "_shared":
                    continue  # only ever read by its real path
                seen = posixpath.normpath(posixpath.join(
                    (root / ".claude" / "skills" / name).as_posix(), sub, link))
                if not os.path.exists(seen):
                    problems.append((rel, link, f"does not resolve from the Claude path: {seen}"))
    return problems


def make_tree(root):
    def write(rel, text=""):
        path = Path(root) / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
    write(".agents/skills/_shared/contract.md", "contract\n")
    write(".agents/skills/b/references/ref.md", "ref\n")
    write(".agents/skills/a/references/own.md", "own\n")
    write(".agents/skills/a/SKILL.md", "\n".join([
        "[sibling skill](../b/references/ref.md)",        # resolves in both views
        "[own reference](references/own.md#anchor)",      # inside the skill
        "[shared, one level](../_shared/contract.md)",    # broken from .claude/skills/a
        "[web](https://example.com/x) [mail](mailto:a@b.c) [top](#top)",
        "```text",
        "[example in a fence](../nowhere/fence.md)",
        "```",
        "`[inline code](../nowhere/code.md)`",
        "[absent](references/absent.md)",
        "[title](references/own.md \"a title\")",
        "[ref-style][r]",
        "",
        "[r]: ../_shared/contract.md",
        ""]))
    write(".agents/skills/a/references/w.md", "[shared, two levels](../../_shared/contract.md)\n")
    write(".agents/skills/_shared/inner.md", "[sibling](contract.md) [absent](missing.md)\n")
    for name in ("a", "b"):
        link = Path(root) / ".claude" / "skills" / name
        link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(f"../../.agents/skills/{name}", link)


class LinkResolution(unittest.TestCase):
    def test_links_must_resolve_from_the_claude_path_too(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_tree(tmp)
            problems = {(f, l) for f, l, _ in unresolved_links(tmp, ("a", "b", "_shared"))}
        self.assertEqual({
            (".agents/skills/a/SKILL.md", "../_shared/contract.md"),       # inline and ref-style
            (".agents/skills/a/SKILL.md", "references/absent.md"),
            (".agents/skills/a/references/w.md", "../../_shared/contract.md"),
            (".agents/skills/_shared/inner.md", "missing.md"),
        }, problems)

    def test_each_view_is_reported_for_its_own_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            make_tree(tmp)
            why = {(f, l): w for f, l, w in unresolved_links(tmp, ("a",))}
        self.assertIn("Claude path", why[(".agents/skills/a/SKILL.md", "../_shared/contract.md")])
        self.assertIn("missing at", why[(".agents/skills/a/SKILL.md", "references/absent.md")])

    def test_the_old_shared_links_are_caught_and_the_existing_cross_skill_links_pass(self):
        """Control pair on the real layout: `../_shared/...` fails, `../pilot-code-review/...` passes."""
        broken = "[contract](../_shared/single-item-checkout.md)"
        ok = "[history](../pilot-code-review/references/pilot-history-checks.md) [sev](../issue-to-pr/references/severity.md)"
        with tempfile.TemporaryDirectory() as tmp:
            for rel in (".agents/skills/_shared/single-item-checkout.md",
                        ".agents/skills/pilot-code-review/references/pilot-history-checks.md",
                        ".agents/skills/issue-to-pr/references/severity.md"):
                path = Path(tmp) / rel
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("x\n")
            skill = Path(tmp) / ".agents/skills/pr-ready/SKILL.md"
            skill.parent.mkdir(parents=True)
            for name in ("pr-ready", "pilot-code-review", "issue-to-pr"):
                link = Path(tmp) / ".claude/skills" / name
                link.parent.mkdir(parents=True, exist_ok=True)
                os.symlink(f"../../.agents/skills/{name}", link)
            skill.write_text(ok + "\n")
            self.assertEqual([], unresolved_links(tmp, ("pr-ready",)))
            skill.write_text(broken + "\n")
            found = unresolved_links(tmp, ("pr-ready",))
            self.assertEqual([".agents/skills/pr-ready/SKILL.md"], [f for f, _, _ in found])
            self.assertEqual(["../_shared/single-item-checkout.md"], [l for _, l, _ in found])


class RepositoryLinks(unittest.TestCase):
    def test_every_relative_link_resolves_in_the_codex_and_claude_views(self):
        problems = unresolved_links(REPO)
        self.assertEqual([], problems, "\n".join(f"{f}: ({l}) {w}" for f, l, w in problems))

    def test_the_scan_sees_the_links_it_is_meant_to_check(self):
        """Guard the guard: the real skills still contain cross-skill links to scan."""
        text = (REPO / ".agents/skills/pr-ready/SKILL.md").read_text()
        self.assertIn("../pilot-code-review/references/pilot-history-checks.md", link_targets(text))


if __name__ == "__main__":
    unittest.main()
