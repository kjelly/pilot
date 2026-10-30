"""Guard the three entry points against batch / per-item-worktree scheduling drift.

The rules are structural (a worktree or checkout owned per item, concurrency or
count limits on items, "continue with the next item", queue draining, "all
PRs", a prescribed separate clone) and apply to every Markdown and TOML file of
the three skills, the shared contract and the native role definitions, in
English and Chinese. A *negatable* rule only fires when the sentence does not
forbid the thing ("Do not create per-item worktrees" is the contract itself).

Both directions are tested (AGENTS.md 5.12): MUTATIONS must each be flagged
(including lines that were in the previous batch version of these files), and
CONTROLS, the legitimate wording of the contract, must not be.
"""
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
SKILLS = REPO / ".agents" / "skills"
NAMES = ("issue-to-pr", "pr-ready", "pr-review-merge")
SHARED = ".agents/skills/_shared/single-item-checkout.md"

# A strong negation anywhere earlier in the sentence exempts a negatable rule ("Do not create ...");
# a weak one only directly before the match ("no per-item worktree"), so "If no sound
# alternative, ... move on to independent PRs" is not mistaken for a prohibition.
NEG = re.compile(
    r"\b(do not|don't|does not|doesn't|did not|never|not|cannot|can't|nor|avoid|"
    r"refuse\w*|forbid\w*|reject\w*)\b|不|禁止|勿|無需|不要", re.I)
WEAK_NEG = re.compile(r"\b(no|without|instead of|rather than)\W+(?:\w+\W+){0,3}$", re.I)
CHOOSE = re.compile(r"\b(ask\w*|select\w*|choos\w*|candidates)\b|請使用者|請.{0,6}選|選一個", re.I)

ITEM = r"(?:issues?|prs?|pull requests?|items?)"
COUNT = r"(?:\d+|one|two|three|four|兩|二|三|[一二兩三四]個)"
# (id, regex, negatable, also-exempt-when-the-sentence-asks-the-user-to-choose)
RULES = (
    ("item-owned-worktree", rf"\b{ITEM}['’]?s?\s+(?:git\s+)?worktrees?\b", True, False),
    ("plural-worktrees", r"\bworktrees\b", True, False),
    ("worktree-lifecycle", r"\bworktree\s+(?:lifecycle|isolation)\b|\bworktree and dependency isolation\b",
     False, False),
    ("worktree-names", r"\bissue-(?:\d+-)?worktree\b|\brepo-issue-\d+\b|\bWORKTREE_READY\b|\bQUEUED\b",
     False, False),
    ("worktree-in-return", r"\{[^}]*?\bworktree\s*,", False, False),
    ("another-worktree", r"\b(?:operating|working|running)\s+in\s+(?:another|the other)\s+worktrees?\b",
     False, False),
    ("isolated-worktree",
     r"\b(?:isolated|dedicated|separate|own|new|fresh|exclusive)\b[^.;\n]{0,30}\bworktrees?\b", True, False),
    ("assigned-worktree",
     rf"\b(?:assigned|designated|committed|its|their|that|this)\s+(?:git\s+)?worktrees?\b",
     True, False),
    ("child-worktree", r"\bchild\s+worktrees?\b", False, False),
    ("one-worktree", r"\b(?:one|single|exactly one)\s+(?:dedicated\s+|git\s+)?worktrees?\b", True, False),
    ("worktree-path", r"\bworktree[_ ]path\b", False, False),
    ("worktree-add", r"\bgit\s+worktree\s+add\b", True, False),
    ("separate-clone",
     r"\b(?:separate|fresh|new|clean|dedicated|another)\s+(?:git\s+)?clones?\b|\bin a clone\b", True, False),
    ("worktree-per-item-zh",
     r"隔離\s*(?:的\s*)?(?:git\s*)?worktrees?|獨立\s*(?:的\s*)?(?:git\s*)?worktrees?|"
     r"每個\s*(?:PR|Issue|項目)[^。\n]{0,12}worktree", True, False),
    ("shared-workspace", r"\bshared\s+workspaces?\b", False, False),
    ("gh-pr-checkout-forbidden",
     r"\b(?:do not|don't|never|avoid)\b[^.;\n]{0,40}\bgh pr checkout\b", False, False),
    ("concurrency-limit",
     rf"\b(?:at most|up to|no more than|max(?:imum)?(?: of)?|cap(?:ped)?(?: \w+){{0,3}}(?: at)?)\s+{COUNT}\b"
     r"[^.;\n]{0,70}\b(?:concurrent\w*|parallel\w*|simultaneous\w*|at once|at the same time)\b|"
     rf"\bcap(?:ped)?\b[^.;\n]{{0,40}}\b(?:at|to)\s+{COUNT}\b", False, False),
    ("concurrent-items",
     rf"\b{COUNT}\b[^.;\n]{{0,40}}\b{ITEM}\b[^.;\n]{{0,40}}\b(?:concurrently|in parallel|simultaneously)\b|"
     rf"\b(?:concurrent(?:ly)?|parallel|simultaneous(?:ly)?)\b[^.;\n]{{0,25}}\b{ITEM}\b", True, False),
    ("allocate-up-to", rf"\ballocate\s+up\s+to\s+{COUNT}\b", False, False),
    ("count-limit-zh",
     r"(?:最多|至多|上限)[^。\n]{0,10}[0-9一二兩三四]\s*個?[^。\n]{0,24}(?:並行|同時|平行)|"
     r"(?:並行|平行)\s*(?:處理|修復|審查|執行)", False, False),
    ("continue-with-other-items",
     rf"\b(?:continue|proceed|move on|go on)\b[^.;\n]{{0,25}}\b(?:to|with)\b[^.;\n]{{0,40}}"
     rf"\b(?:other|next|remaining|another|independent)\b[^.;\n]{{0,30}}\b(?:{ITEM}|work)\b", True, False),
    ("next-item", rf"\b(?:next|remaining)\s+(?:independent\s+)?{ITEM}\b|\bnext one\b", True, False),
    ("start-other-item",
     rf"\b(?:start|begin|process|handle|review|work on|take|pick up|move to)\s+(?:the\s+)?"
     rf"(?:another|other|remaining|next)\s+(?:independent\s+)?{ITEM}\b", True, False),
    ("queue", r"\b(?:ready|pr|issue|work|review|draft)\s+queue\b|\bdrain\w*\b", True, False),
    ("serialize", r"\bserializ\w*\b", True, False),
    ("after-each", r"\bafter each (?:merge|pr|issue)\b", False, False),
    ("parallel-agents", r"\bparallel\s+(?:independent\s+)?(?:review\w*|sub-?agents?|analysis)\b", False, False),
    ("multi-target-list",
     rf"\bone or more\b[^.;\n]{{0,30}}\b{ITEM}\b|\bmultiple\s+{ITEM}\b[^.;\n]{{0,20}}\bseparated\b", False, False),
    ("fan-out-batch", r"\bfan[- ]?out\b|\bbatch(?:es)?\b|\bone[- ]by[- ]one\b|\bserially\b", True, False),
    ("serial-merges", r"\bserial\s+merges?\b", False, False),
    ("revisit-waiting", rf"\brevisit\w*\s+(?:the\s+)?(?:waiting|{ITEM})\b", True, False),
    ("sequential-review", r"\breview\w*\s+sequentially\b", False, False),
    ("all-items", rf"\ball\s+(?:(?:open|ready|draft|non-draft|enumerated|pending)\s+)*{ITEM}\b", True, True),
    ("enumerate-items",
     rf"\b(?:enumerat\w*|inventor\w*)\b[^.;\n]{{0,40}}\b(?:open|ready|draft|non-draft)\b[^.;\n]{{0,25}}\b{ITEM}\b",
     True, False),
    ("all-items-zh", r"(?:所有|全部)\s*(?:非\s*)?(?:Draft\s*|Ready\s*)?(?:PR|Issue)", True, True),
    ("each-item", rf"\b(?:each|every|for each)\s+(?:(?:selected|specified|target)\s+)?{ITEM}\b", True, False),
    ("multi-item-example",
     r"(?:/(?:issues|pull)/\d+|#\d+)\s*(?:[,、]\s*|和\s*|及\s*|and\s+)?#\d+", False, False),
)
COMPILED = tuple((rid, re.compile(rx, re.I), neg, ask) for rid, rx, neg, ask in RULES)


def sentences(text):
    text = text.replace("`", "").replace("*", "")
    for block in re.split(r"\n\s*\n", text):
        for line in re.split(r"\n(?=\s*(?:[-+] |\d+\. |\||#))", block):
            flat = re.sub(r"\s*\n\s*", " ", line)
            for s in re.split(r"(?<=[.!?;。；])\s+|(?<=[。；])", flat):
                if s.strip():
                    yield s.strip()


def violations(text, label="text"):
    """(label, rule, sentence) for every rule that fires in `text`."""
    found = []
    for sentence in sentences(text):
        for rid, rx, negatable, asks in COMPILED:
            for m in rx.finditer(sentence):
                before = sentence[max(0, m.start() - 90):m.start()]
                if negatable and (NEG.search(before) or WEAK_NEG.search(before[-24:])):
                    continue
                if asks and CHOOSE.search(sentence):
                    continue
                found.append((label, rid, sentence[:140]))
                break
    return found


def scanned_files():
    """Every Markdown/TOML file of the three skills and the single-item contract, plus the roles."""
    files = {}
    for name in NAMES:
        for path in (SKILLS / name).rglob("*"):
            if path.suffix in (".md", ".toml") and path.is_file():
                files[path.resolve()] = path
    files[(REPO / SHARED).resolve()] = REPO / SHARED  # not _shared/clean-room-contract.md: another skill's
    for pattern in (".codex/agents/*.toml", ".claude/agents/*.md"):
        for path in REPO.glob(pattern):
            if path.name.split("-")[0] in ("issue", "pr", "prm"):
                files.setdefault(path.resolve(), path)
    return sorted(files.values())


# Each line must be flagged. "base:" ones are wording the earlier batch version used.
MUTATIONS = (
    ("each issue gets an isolated worktree", "Each Issue gets an isolated Git worktree."),
    ("per-issue worktree", "Create a per-Issue worktree for the fix."),
    ("per-pr worktrees", "Use per-PR worktrees."),
    ("pr worktree", "Create the PR worktree first."),
    ("issue worktree", "Each fix lives in its Issue worktree."),
    ("exactly one worktree", "The coder gets exactly one worktree."),
    ("next pr listed", "Afterwards the next PR in the list is handled."),
    ("process another", "Then process another PR."),
    ("worktree add in a role file", "Create it with git worktree add -b issue/123 ../repo origin/main."),
    ("two at once", "Run at most 2 concurrently."),
    ("cap of two", "Cap active PR workflows at 2."),
    ("allocate two", "Allocate up to two independent PR reviewer subagents."),
    ("two prs in parallel", "Review two independent PRs in parallel."),
    ("separate clone paraphrase",
     "Do not run gh pr checkout in the user's active worktree; use a separate clone."),
    ("gh pr checkout ban", "Do not run `gh pr checkout` blindly in the user's active worktree."),
    ("continue to others", "Continue with other independent work."),
    ("proceed to issues", "Proceed with other independent Issues."),
    ("move on", "After a blocker, move on to independent PRs."),
    ("next item", "When this PR is done, start the next PR."),
    ("drain queue", "Drain the Ready queue."),
    ("serial merges", "Root serially runs the actor with --execute."),
    ("fan out", "Fan out one reviewer per PR."),
    ("batch", "Process them in a batch."),
    ("one by one", "Handle them one by one."),
    ("all draft prs", "Process all Draft PRs, at most two at a time."),
    ("all prs zh", "處理所有 Draft PR，最多同時兩個。"),
    ("isolated worktrees zh", "每個 PR 使用隔離 worktrees。"),
    ("dedicated worktree zh", "每個 Issue 使用獨立 worktree 修復。"),
    ("multi item example", "Run /pr-review-merge #42 #43 #44."),
    ("multi item zh", "$issue-to-pr 處理 https://github.com/OWNER/REPO/issues/123 和 #124"),
    ("plural worktrees residue", "worktrees may not contain these project-local skills yet."),
    ("tracked worktrees", "Root writes one JSON evidence file per PR outside tracked worktrees."),
    ("worktree heading", "## Worktree lifecycle"),
    ("worktree heading 2", "## Worktree and dependency isolation"),
    ("state tokens", "DISCOVERED -> ANALYZED -> QUEUED -> WORKTREE_READY -> IMPLEMENTING"),
    ("example path", "WT=\"/path/to/issue-123-worktree\""),
    ("return key", "Return compact {issue, worktree, branch, head_sha, commits}."),
    ("another worktree", "Resolve packaged scripts relative to this SKILL.md, including when operating in another worktree."),
    ("serialized", "Independent Issues editing shared core files should be serialized."),
    ("enumerate prs", "If the user requests all Drafts, enumerate open PRs and select only isDraft=true."),
    ("all non-draft zh", "/pr-review-merge 審查 kjelly/pilot 所有非 Draft PR；合格則 merge。"),
    ("all open non-draft", "enumerate all open non-Draft PRs."),
    ("next one", "arrange a new independent review before acting on the next one."),
    ("each specified issue", "create one independent PR for each specified Issue."),
    ("every target issue", "For every target Issue, report the result."),
    ("one or more", "use when asked to process one or more Draft PRs."),
    ("parallel subagents", "Review open PRs with independent parallel subagents."),
    ("after each merge", "After each merge, update the dependency ledger."),
    ("weak negation is not a prohibition", "If no sound alternative, mark Draft-blocked and move on to independent PRs."),
    ("zh parallel reviewers", "最多 2 個獨立 Reviewer Subagents 並行。"),
    ("base pr-ready README", "只處理 Draft PR，最多同時兩個，並以隔離 worktrees 保存狀態。"),
    ("base issue-coder", "Act only in the assigned Issue's worktree/branch, never in other Issue worktrees."),
    ("base pr-coder", "You are PR Coder. Act only on the one PR's assigned isolated worktree and original head branch."),
    ("base pr-coder shared", "Verify the branch/worktree/head_sha and current changes before editing; do not modify shared workspaces."),
    ("base issue-coder description",
     "Implement an Issue root-cause fix with targeted regression tests within exactly one dedicated Git worktree."),
    ("base prm-reviewer", "Use safe read-only commands and trusted test commands in an isolated worktree, scoped to the packages."),
    ("base prm-dependency", "Read-only dependency analysis across the enumerated open Ready PRs."),
    ("base pr-ready coder", "Coder owns implementation only in that PR's worktree."),
    ("base issue-reviewer", "Only PASS if zero unresolved P0/P1/P2, and reviewer HEAD SHA matches committed worktree."),
    ("base pr-reviewer", "Verify the assigned PR or local branch, base/head SHAs and actual diff in the assigned worktree."),
    ("base pr-sa", "Verify the repository, PR number when applicable, assigned branch, worktree path and base/HEAD SHAs from the task envelope."),
    ("base issue platforms", "issue-coder: one Issue, one worktree, implementation + tests (writes allowed only in designated worktree)."),
    ("base issue platforms child", "do not assume a child worktree contains it: pass the absolute path."),
    ("base prm platforms", "if no genuine isolated context exists, review sequentially and disclose the limitation."),
    ("base PROJECT-CHANGES", "no per-item worktree/batch scheduling, history reference, cost, serial merges."),
    ("envelope key", "Task envelope: {repo, pr, url, base_sha, head_sha, worktree_path, role}."),
    ("base pr-ready clone", "Start from a clean clone of the correct repository."),
    ("base issue claim", "Claim each Issue before any worktree, branch or analysis."),
    ("base pr-ready permission", "Verify write permission to each PR head branch."),
    ("base review queue", "pr-review-merge reviews the Ready queue and handles merge vs Draft."),
    ("base revisit", "Revisit WAITING PRs only when they can progress."),
)

# Legitimate wording of the contract and of unchanged script/flag names: never flagged.
CONTROLS = (
    "Do not create per-item worktrees as a workaround.",
    "Checkout the selected branch in the current clean checkout; do not create per-item worktrees.",
    "In existing script flags and evidence schemas, `worktree` means this checkout directory; it does not require `git worktree add`.",
    "Never start another item after success, failure, or a blocker.",
    "For multiple items or “all”, list candidates and ask which one to handle; do not silently choose, fan out, or drain a queue.",
    "Multiple targets or **all Draft PRs** require asking the user to select one; never process a batch.",
    "python3 scripts/run_check.py --worktree \"$REPO_ROOT\" --name lint",
    "git worktree list --porcelain",
    "The merge queue refuses `gh pr merge` without a final merge.",
    "Do not stash, discard, or create a worktree for it.",
    "不建立 per-PR worktrees。",
    "多個或全部項目先列候選並請使用者選一個，不自動處理下一個。",
    "Use the current checkout, not a new per-Issue worktree.",
    "gh pr checkout N --repo OWNER/REPO, without force, or a verified git switch BRANCH.",
    "Read-only dependency analysis for the one selected Ready PR; other PRs are context to read, never work items.",
    "The Issue claim is `claim.py acquire`: a branch/worktree for it already exists on the remote or in this clone.",
    "SA, Coder and Reviewer remain separate roles for this Issue, not parallel Issue workers.",
    "Do not continue to another PR after completion.",
    "Reviewer reads artifacts and independently revisits the decision before PASS.",
    "Verify the branch/head_sha and current changes in the assigned checkout before editing; do not modify other checkouts.",
    "Do not create worktrees, switch branches or touch another Issue.",
    "Never let two subagents write to the checkout at the same time.",
    "A read-only scratch copy outside the checkout is allowed for revert or mutation negative controls.",
)


class SingleItemContractTests(unittest.TestCase):
    def test_entry_points_share_checkout_contract(self):
        for name in NAMES:
            with self.subTest(skill=name):
                skill = (SKILLS / name / "SKILL.md").read_text()
                self.assertIn(SHARED, skill)
                self.assertIn("realpath", skill)
                self.assertIn("exactly one Issue/PR", skill)
                self.assertIn("before analysis, edits, review, tests or delegation", skill)
                self.assertIn("$SNAP", skill)
        self.assertTrue((REPO / SHARED).is_file())

    def test_no_skill_text_links_to_shared_relatively(self):
        """A relative `_shared` link cannot resolve from Claude's .claude/skills/<name> path."""
        link = re.compile(r"\]\([^)]*_shared/|\]:\s*\S*_shared/")
        for path in scanned_files():
            if path.suffix == ".md":
                with self.subTest(path=str(path.relative_to(REPO))):
                    self.assertIsNone(link.search(path.read_text()))

    def test_contract_preserves_safe_branch_identity(self):
        text = " ".join((REPO / SHARED).read_text().split())
        for required in ("git status --porcelain", "git branch --show-current",
                         "git rev-parse HEAD", "head repository", "head SHA",
                         "checked out elsewhere", "Never stash", "detached HEAD",
                         "git switch --no-track -c", "never creates a replacement",
                         "Never start another item", "acquire the Issue claim first",
                         "outside the checkout", "source repository/revision",
                         "absolute snapshot paths", "checkout_preflight.py", "skill_snapshot.py",
                         "ignored", "verify-role", "BLOCKED", "realpath", "Known limitation",
                         "Read-only scratch copies", "candidate checkout"):
            self.assertIn(required, text)
        order = [text.index(marker) for marker in
                 ("checkout_preflight.py", "skill_snapshot.py\" create", "gh pr checkout N")]
        self.assertEqual(sorted(order), order, "preflight, then snapshot, then checkout")

    def test_project_changes_name_the_contract_scripts_and_tests(self):
        """Each skill's PROJECT-CHANGES row lists the shared contract, helper scripts and guards."""
        for name in NAMES:
            text = " ".join((SKILLS / name / "PROJECT-CHANGES.md").read_text().split())
            for required in ("single-item-checkout.md", "checkout_preflight.py", "skill_snapshot.py",
                             "test_single_item_contract.py", "test_checkout_preflight.py",
                             "test_skill_snapshot.py", "test_skill_links.py"):
                with self.subTest(skill=name, needs=required):
                    self.assertIn(required, text)

    def test_the_real_files_are_in_the_scan(self):
        names = {p.name for p in scanned_files()}
        for expected in ("SKILL.md", "README.md", "workflow.md", "single-item-checkout.md",
                         "PROJECT-CHANGES.md", "issue-coder.toml", "pr-coder.toml", "prm-dependency.toml",
                         "prm-reviewer.md", "issue-reviewer.md", "pr-sa.md", "roles.md",
                         "evidence-schema.md", "platforms.md"):
            self.assertIn(expected, names)

    def test_no_batch_or_per_item_worktree_wording_remains(self):
        found = []
        for path in scanned_files():
            found += violations(path.read_text(encoding="utf-8"), str(path.relative_to(REPO)))
        self.assertEqual([], found, "\n".join(f"{f}: [{r}] {s}" for f, r, s in found))

    def test_guard_flags_every_mutation(self):
        for label, text in MUTATIONS:
            with self.subTest(mutation=label):
                self.assertTrue(violations(text), f"not flagged: {text}")

    def test_guard_flags_a_mutation_added_to_each_kind_of_file(self):
        """Appending a banned sentence to any scanned file is caught, whatever the file type."""
        for path in scanned_files():
            text = path.read_text(encoding="utf-8") + "\nEach Issue gets an isolated Git worktree.\n"
            with self.subTest(path=str(path.relative_to(REPO))):
                self.assertTrue(violations(text, str(path.relative_to(REPO))))

    def test_guard_does_not_flag_the_contract_wording(self):
        for text in CONTROLS:
            with self.subTest(control=text[:60]):
                self.assertEqual([], violations(text), text)


if __name__ == "__main__":
    unittest.main()
