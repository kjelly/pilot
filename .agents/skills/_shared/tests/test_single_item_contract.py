"""Guard the single-item skills and their shared contract against scheduling drift.

This lives in _shared/tests because it covers all three skills (issue-to-pr,
pr-ready, pr-review-merge), the contract, the history reference they hand to
every child, and the native role definitions.

Three kinds of checks:

* Wording rules (RULES). Each one matches a specific phrasing or token of the
  earlier batch / per-item-worktree design ("each PR gets an isolated
  worktree", "at most 2 concurrently", "continue with other independent work",
  "all Draft PRs", "serial merges", a prescribed separate clone, ...), in
  English and Chinese, in every Markdown and TOML file of the scan set. A
  *negatable* rule does not fire when the sentence forbids the thing ("Do not
  create per-item worktrees" is the contract itself). Rules that name tokens
  with no legitimate use are not negatable, so a stray "never" elsewhere in the
  sentence cannot hide them.
* Both directions (AGENTS.md 5.12): MUTATIONS must each be flagged, including
  lines from the previous version of these files and paraphrases; CONTROLS must
  not be, including innocent prose that merely shares a word ("Read each PR
  comment", "Batch the GraphQL queries"). Every rule must be needed by at least
  one mutation, so no rule is dead weight.
* Structure of the contract: the preflight stop conditions are tied to the
  checkout_preflight.py check ids, the helper scripts are invoked through
  `$REPO_ROOT`/`$SNAP` paths, and no skill document shows a bare
  `python3 scripts/...` or `/path/to/...` invocation.
"""
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[4]
SKILLS = REPO / ".agents" / "skills"
NAMES = ("issue-to-pr", "pr-ready", "pr-review-merge")
SHARED = ".agents/skills/_shared/single-item-checkout.md"
HISTORY = ".agents/skills/pilot-code-review/references/pilot-history-checks.md"
PREFLIGHT = SKILLS / "_shared" / "scripts" / "checkout_preflight.py"

# A strong negation earlier in the sentence exempts a negatable rule ("Do not create ...");
# a weak one only directly before the match ("no per-item worktree"), so "If no sound
# alternative, ... move on to independent PRs" is not mistaken for a prohibition.
NEG = re.compile(
    r"\b(do not|don't|does not|doesn't|did not|never|not|cannot|can't|nor|avoid|"
    r"refuse\w*|forbid\w*|reject\w*)\b|不|禁止|勿|無需|不要", re.I)
CLAUSE_BREAK = re.compile(r",\s+(?:and|then|but|so|while|whereas)\s+", re.I)
WEAK_NEG = re.compile(r"\b(no|without|instead of|rather than)\W+(?:\w+\W+){0,3}$", re.I)
CHOOSE = re.compile(r"\b(ask\w*|select\w*|choos\w*|candidates)\b|請使用者|請.{0,6}選|選一個", re.I)

# Nouns that make "PR"/"Issue" a modifier ("each PR comment", "every PR check"), not the work item.
PART = (r"comments?|checks?|threads?|reviews?|commits?|files?|labels?|jobs?|status\w*|diffs?|hunks?|"
        r"descriptions?|bod(?:y|ies)|titles?|states?|numbers?|urls?|authors?|metadata|statuses")
ITEM = r"(?:issues?|prs?|pull requests?|items?)"                 # an explicit item noun
ITEM_PL = r"(?:issues|prs|pull requests|items)"
ITEM_NP = rf"{ITEM}(?!\s+(?:{PART})\b)(?![-'’\w])"                # the item itself, not its part
COUNT = r"(?:\d+|one|two|three|four|兩|二|三|[一二兩三四]個)"
# (id, regex, negatable, also-exempt-when-the-sentence-asks-the-user-to-choose)
RULES = (
    # --- a worktree or checkout owned per item
    ("item-owned-worktree", rf"\b{ITEM}['’]?s?\s+(?:git\s+)?worktrees?(?![-\w])", True, False),
    ("creating-worktrees",
     r"\b(?:create|add|make|use|allocate|reuse|provision|spawn)\w*\s+(?:(?:its|their|a|the|new|more|"
     r"several|per[- ]\w+)\s+){0,2}(?:\w+\s+)?worktrees\b|"
     r"\b(?:outside|inside|within|across)\s+(?:tracked\s+|the\s+|other\s+)*worktrees\b|"
     r"\bworktrees\s+(?:may|might|can|should|must)\b", True, False),
    ("isolated-worktree",
     r"\b(?:isolated|dedicated|separate|exclusive|fresh|new|own)\s+(?:(?:git|per-\w+|\w+-specific)\s+)?"
     r"worktrees?(?![-\w])", True, False),
    ("assigned-worktree",
     r"\b(?:assigned|designated|committed|its|their|that|this)\s+(?:git\s+)?worktrees?(?![-\w])",
     True, False),
    ("one-worktree", r"\b(?:one|single|exactly one)\s+(?:dedicated\s+|git\s+)?worktrees?(?![-\w])", True, False),
    ("child-worktree", r"\bchild\s+worktrees?\b", False, False),
    ("worktree-lifecycle", r"\bworktree\s+(?:lifecycle|isolation)\b|\bworktree and dependency isolation\b",
     False, False),
    ("worktree-names", r"\bissue-(?:\d+-)?worktree\b|\brepo-issue-\d+\b|\bWORKTREE_READY\b|\bQUEUED\b",
     False, False),
    ("worktree-in-return", r"\{[^}]*?\bworktree\s*,", False, False),
    ("worktree-path", r"\bworktree[_ ]path\b", False, False),
    ("another-worktree", r"\b(?:operating|working|running)\s+in\s+(?:another|the other)\s+worktrees?\b",
     False, False),
    ("worktree-add", r"\bgit\s+worktree\s+add\b", True, False),
    ("shared-workspace", r"\bshared\s+workspaces?\b", False, False),
    ("separate-clone",
     r"\b(?:use|start from|work in|create|make|run in|clone into)\b[^.;\n]{0,15}\b"
     r"(?:separate|fresh|new|clean|dedicated|another)\s+(?:git\s+)?clones?\b", True, False),
    ("gh-pr-checkout-forbidden",
     r"\b(?:do not|don't|never|avoid)\b[^.;\n]{0,40}\bgh pr checkout\b", False, False),
    ("worktree-per-item-zh",
     r"隔離\s*(?:的\s*)?(?:git\s*)?worktrees?|獨立\s*(?:的\s*)?(?:git\s*)?worktrees?|"
     r"每個\s*(?:PR|Issue|項目)[^。\n]{0,12}worktree", True, False),
    ("assigned-worktree-zh", r"指派\s*(?:的\s*)?worktree", False, False),
    ("isolated-checkout-zh", r"隔離\s*(?:的\s*)?(?:candidate\s*)?(?:checkout|clone)", False, False),
    # --- concurrency, counts, "the next item", queues
    ("concurrency-limit",
     rf"\b(?:at most|up to|no more than|max(?:imum)?(?: of)?)\s+{COUNT}\s+(?:(?:independent|active|modifying)\s+){{0,2}}"
     r"(?:concurrent\w*|parallel\w*|simultaneous\w*|at once)\b|"
     rf"\bcap(?:ped)?\s+(?:\w+\s+){{0,3}}(?:workflows?|workers?|workstreams?|prs?|issues?)\b[^.;\n]{{0,15}}"
     rf"\b(?:at|to)\s+{COUNT}\b", False, False),
    ("concurrent-items",
     rf"\b{COUNT}\b[^.;\n]{{0,30}}\b{ITEM_PL}\b[^.;\n]{{0,40}}\b(?:concurrently|in parallel|simultaneously)\b|"
     rf"\b(?:concurrent|parallel|simultaneous)\w*\s+(?:independent\s+)?{ITEM}\s+(?:workers?|workstreams?|workflows?|"
     r"reviews?|fixes)\b", True, False),
    ("allocate-up-to",
     rf"\ballocate\s+up\s+to\s+{COUNT}\s+(?:\w+\s+){{0,3}}(?:subagents?|reviewers?|workers?|agents?|prs?|issues?)\b",
     False, False),
    ("count-limit-zh",
     r"(?:最多|至多|上限)[^。\n]{0,10}[0-9一二兩三四]\s*個?[^。\n]{0,24}(?:並行|同時|平行)|"
     r"(?:並行|平行)\s*(?:處理|修復|審查)", False, False),
    ("continue-with-other-items",
     rf"\b(?:continue|proceed|move on|go on)\b[^.;\n]{{0,25}}\b(?:to|with)\b[^.;\n]{{0,40}}"
     rf"\b(?:other|next|remaining|another|independent)\b[^.;\n]{{0,30}}\b(?:{ITEM_NP}|work)\b", True, False),
    ("next-item", rf"\b(?:next|remaining)\s+(?:independent\s+)?{ITEM_NP}|"
     r"\b(?:acting|moving|proceeding)\s+(?:on|to)\s+the\s+next\s+one\b", True, False),
    ("start-other-item",
     rf"\b(?:start|begin|process|handle|review|work on|take|pick up|move to)\s+(?:the\s+)?"
     rf"(?:another|other|remaining|next)\s+(?:independent\s+)?{ITEM_NP}", True, False),
    ("queue",
     r"\b(?:ready|draft|pr|issue)\s+queue\b|\bdrain\w*\s+(?:the\s+|a\s+|an\s+)?(?:\w+\s+)?(?:queue|backlog)\b|"
     r"\bqueue\s+(?:up|the rest|them)\b", True, False),
    ("batch-or-fan-out",
     r"\bbatch(?:es)?\s+(?:schedul\w*|process\w*|mode)\b|\b(?:in|as)\s+(?:a\s+)?batch(?:es)?\b|"
     r"\bprocess\w*\s+(?:a\s+)?batch(?:es)?\b|"
     rf"\b{ITEM}\b[^.;\n]{{0,30}}\bone[- ]by[- ]one\b|\bone[- ]by[- ]one\b[^.;\n]{{0,25}}\b{ITEM}\b|"
     rf"\bfan[- ]?out\b[^.;\n]{{0,40}}\b(?:{ITEM}|reviewers?|subagents?|workers?)\b", True, False),
    ("serialize-items", rf"\b{ITEM_PL}\b[^.;\n]{{0,50}}\bserializ\w*\b|\bserializ\w*\s+(?:the\s+)?{ITEM_PL}\b",
     False, False),
    ("serial-merges", r"\bserial\s+merges?\b|\bserially\s+(?:run\w*|merg\w*|handl\w*|process\w*|review\w*|execut\w*)\b",
     False, False),
    ("sequential-review", r"\breview\w*\s+sequentially\b", False, False),
    ("revisit-waiting", rf"\brevisit\w*\s+(?:the\s+)?(?:waiting|{ITEM})\b", False, False),
    ("after-each", r"\bafter each (?:merge|pr|issue)\b", False, False),
    ("parallel-agents", r"\bparallel\s+(?:independent\s+)?(?:review\w*|sub-?agents?|analysis)\b", False, False),
    # --- "all / every / each PR" and multi-item invocations
    ("all-items", rf"\ball\s+(?:(?:open|ready|draft|non-draft|enumerated|pending)\s+)*{ITEM_PL}\b(?!['’])", True, True),
    ("enumerate-items",
     rf"\b(?:enumerat\w*|inventor\w*)\b[^.;\n]{{0,40}}\b(?:open|ready|draft|non-draft)\b[^.;\n]{{0,25}}\b{ITEM_PL}\b",
     True, False),
    ("all-items-zh",
     r"(?:所有|全部)\s*(?:非\s*)?(?:Draft\s*|Ready\s*)?(?:PR|Issue)"
     r"(?!\s*(?:的\s*)?(?:comments?|checks?|reviews?|commits?|threads?|評論|留言|檢查|審查意見|檔案|變更))",
     True, True),
    ("each-item",
     rf"\b(?:claim|process|handle|fix|repair|resolve|analy[sz]e|dispatch)\w*\s+(?:each|every)\s+"
     rf"(?:(?:selected|specified|target)\s+)?{ITEM_NP}|"
     rf"\bfor\s+(?:each|every)\s+(?:(?:selected|specified|target)\s+)?{ITEM_NP}|"
     r"\b(?:each|every)\s+(?:(?:selected|specified|target)\s+)?(?:issue|pr)\s+"
     r"(?:gets|owns|has\s+its\s+own|is\s+handled|runs|receives)\b|"
     r"\bevery\s+target\s+(?:issue|pr)\b|\b(?:each|every)\s+pr\s+head\s+branch\b", False, False),
    ("multi-item-example",
     r"(?:/(?:issues|pull)/\d+|#\d+)\s*(?:[,、]\s*|和\s*|及\s*|and\s+)?#\d+", False, False),
    ("multi-target-list",
     rf"\bone or more\b[^.;\n]{{0,30}}\b{ITEM_PL}\b|\bmultiple\s+{ITEM_PL}\b[^.;\n]{{0,20}}\bseparated\b",
     False, False),
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


def violations(text, label="text", rules=COMPILED):
    """(label, rule, sentence) for every rule that fires in `text`."""
    found = []
    for sentence in sentences(text):
        for rid, rx, negatable, asks in rules:
            for m in rx.finditer(sentence):
                before = sentence[max(0, m.start() - 70):m.start()]
                before = CLAUSE_BREAK.split(before)[-1]  # a negation does not carry past ", and ..."
                if negatable and (NEG.search(before) or WEAK_NEG.search(before[-24:])):
                    continue
                if asks and CHOOSE.search(sentence):
                    continue
                found.append((label, rid, sentence[:140]))
                break
    return found


def scanned_files():
    """The three skills' Markdown/TOML, the contract, the history reference and the role files."""
    files = {}
    for name in NAMES:
        for path in (SKILLS / name).rglob("*"):
            if path.suffix in (".md", ".toml") and path.is_file():
                files[path.resolve()] = path
    for extra in (SHARED, HISTORY):  # not _shared/clean-room-contract.md: another skill's
        files[(REPO / extra).resolve()] = REPO / extra
    for pattern in (".codex/agents/*.toml", ".claude/agents/*.md"):
        for path in REPO.glob(pattern):
            if path.name.split("-")[0] in ("issue", "pr", "prm"):
                files.setdefault(path.resolve(), path)
    return sorted(files.values())


def flat(text):
    """Text with Markdown emphasis and code marks removed and whitespace collapsed."""
    return " ".join(text.replace("`", "").replace("*", "").split())


# Each line must be flagged. "base" ones are wording the earlier batch version used.
MUTATIONS = (
    # per-item worktrees / checkouts / clones
    ("each issue gets an isolated worktree", "Each Issue gets an isolated Git worktree."),
    ("per-issue worktree", "Create a per-Issue worktree for the fix."),
    ("per-pr worktrees", "Use per-PR worktrees."),
    ("pr worktree", "Create the PR worktree first."),
    ("issue worktree", "Each fix lives in its Issue worktree."),
    ("exactly one worktree", "The coder gets exactly one worktree."),
    ("worktree add in a role file", "Create it with git worktree add -b issue/123 ../repo origin/main."),
    ("creating worktrees", "Allocate new worktrees for the reviewers."),
    ("separate clone paraphrase",
     "Do not run gh pr checkout in the user's active worktree; use a separate clone."),
    ("gh pr checkout ban", "Do not run `gh pr checkout` blindly in the user's active worktree."),
    ("isolated worktrees zh", "每個 PR 使用隔離 worktrees。"),
    ("dedicated worktree zh", "每個 Issue 使用獨立 worktree 修復。"),
    ("plural worktrees residue", "worktrees may not contain these project-local skills yet."),
    ("tracked worktrees", "Root writes one JSON evidence file per PR outside tracked worktrees."),
    ("worktree heading", "## Worktree lifecycle"),
    ("worktree heading 2", "## Worktree and dependency isolation"),
    ("state tokens", "DISCOVERED -> ANALYZED -> QUEUED -> WORKTREE_READY -> IMPLEMENTING"),
    ("example path", "WT=\"/path/to/issue-123-worktree\""),
    ("return key", "Return compact {issue, worktree, branch, head_sha, commits}."),
    ("envelope key", "Task envelope: {repo, pr, url, base_sha, head_sha, worktree_path, role}."),
    ("another worktree", "Resolve packaged scripts relative to this SKILL.md, including when operating in another worktree."),
    # concurrency, counts, next item, queues
    ("two at once", "Run at most 2 concurrently."),
    ("two concurrent streams", "Run at most two concurrent modifying Issue workstreams."),
    ("cap of two", "Cap active PR workflows at 2."),
    ("allocate two", "Allocate up to two independent PR reviewer subagents."),
    ("two prs in parallel", "Review two independent PRs in parallel."),
    ("parallel issue workers", "Use parallel Issue workers for the fixes."),
    ("zh parallel reviewers", "最多 2 個獨立 Reviewer Subagents 並行。"),
    ("continue to others", "Continue with other independent work."),
    ("proceed to issues", "Proceed with other independent Issues."),
    ("move on", "After a blocker, move on to independent PRs."),
    ("weak negation is not a prohibition", "If no sound alternative, mark Draft-blocked and move on to independent PRs."),
    ("next item", "When this PR is done, start the next PR."),
    ("next pr listed", "Afterwards the next PR in the list is handled."),
    ("process another", "Then process another PR."),
    ("next one", "arrange a new independent review before acting on the next one."),
    ("drain queue", "Drain the Ready queue."),
    ("fan out", "Fan out one reviewer per PR."),
    ("batch", "Process them in a batch."),
    ("batch scheduling", "Use batch scheduling for the PRs."),
    ("one by one", "Handle the PRs one by one."),
    ("serial merges", "Root serially runs the actor with --execute."),
    ("serialized", "Independent Issues editing shared core files should be serialized."),
    ("after each merge", "After each merge, update the dependency ledger."),
    ("parallel subagents", "Review open PRs with independent parallel subagents."),
    # all / each / every, multi-item invocations
    ("all draft prs", "Process all Draft PRs, at most two at a time."),
    ("all non-draft zh", "/pr-review-merge 審查 kjelly/pilot 所有非 Draft PR；合格則 merge。"),
    ("all prs zh", "處理所有 Draft PR，最多同時兩個。"),
    ("all open non-draft", "enumerate all open non-Draft PRs."),
    ("enumerate prs", "If the user requests all Drafts, enumerate open PRs and select only isDraft=true."),
    ("each specified issue", "create one independent PR for each specified Issue."),
    ("every target issue", "For every target Issue, report the result."),
    ("claim each", "Claim each Issue before any branch checkout."),
    ("each pr owns", "Each PR owns its own state."),
    ("each pr head branch", "Verify write permission to each PR head branch."),
    ("one or more", "use when asked to process one or more Draft PRs."),
    ("multi item example", "Run /pr-review-merge #42 #43 #44."),
    ("multi item zh", "$issue-to-pr 處理 https://github.com/OWNER/REPO/issues/123 和 #124"),
    ("multiple separated", "Multiple Issues separated by commas are accepted."),
    ("revisit waiting", "Revisit WAITING PRs only when they can progress."),
    ("base review queue", "pr-review-merge reviews the Ready queue and handles merge vs Draft."),
    ("base prm platforms", "if no genuine isolated context exists, review sequentially and disclose the limitation."),
    # lines of the previous (batch) version of the skill files, verbatim
    ("base pr-ready README", "$pr-ready 處理目前 repo 所有 Draft PR，最多同時兩個"),
    ("base pr-ready README 2", "主 Agent 讀取 PR/CI/Issue/review，建立依賴 DAG，隔離 worktrees。"),
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
    ("base PROJECT-CHANGES", "no per-item worktree/batch scheduling, history reference, cost, serial merges."),
    ("base pr-ready clone", "Start from a clean clone of the correct repository."),
    ("base issue claim", "Claim each Issue before any worktree, branch or analysis."),
    ("base history assigned worktree", "只使用指派 worktree；你不是唯一工作者，不回退別人的改動。"),
    ("base history isolated candidate", "從乾淨隔離的 candidate checkout 執行，記 commit/tree、執行檔案 hashes、"),
)

# Must not be flagged: the contract's own wording, unchanged flag/script names, and innocent
# prose that shares a word with a banned phrase.
CONTROLS = (
    # the contract and the skills
    "Do not create per-item worktrees as a workaround.",
    "Checkout the selected branch in the current clean checkout; do not create per-item worktrees.",
    "In existing script flags and evidence schemas, `worktree` means this checkout directory; it does not require `git worktree add`.",
    "Never start another item after success, failure, or a blocker.",
    "For multiple items or “all”, list candidates and ask which one to handle; do not silently choose, fan out, or drain a queue.",
    "Multiple targets or **all Draft PRs** require asking the user to select one; never process a batch.",
    "python3 \"$SNAP/.agents/skills/issue-to-pr/scripts/run_check.py\" --worktree \"$REPO_ROOT\" --name lint",
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
    "只使用 Root 指派且已驗證的 checkout（不建立 worktree、不切換 branch）；你不是唯一工作者。",
    "從乾淨的 candidate checkout 執行（凍結 candidate commit 後的乾淨目前 checkout，或該 SHA 的唯讀 git archive scratch 複本）。",
    "Neither is an item workspace: do not give a candidate its own writer worktree or branch.",
    # innocent prose sharing a word with a banned phrase
    "Read each PR comment and every review thread before answering.",
    "Verify every PR check passes before merging.",
    "Review each PR comment, then resolve the remaining PR review threads.",
    "For each PR comment, record the reply.",
    "Fetch all PR review comments and all PR checks.",
    "Fetch all PRs' review comments before the next PR check.",
    "Batch the GraphQL queries to stay under the rate limit.",
    "Use a worktree-free scratch directory for the controls.",
    "Use an isolated worktree-free scratch directory for the controls.",
    "Run up to 4 test shards in parallel.",
    "Wait for concurrent PR checks to settle.",
    "Review the other PR's comments for overlap.",
    "git worktree list shows all worktrees, including the main one.",
    "Actor reruns the live gate immediately before action, never trusts a saved decision, serializes writes, and uses --match-head-commit.",
    "The queue of CI jobs is not ours to manage.",
    "處理所有 PR 評論後再回覆。",
    "Edit the files one by one and run the tests.",
)

# The checkout_preflight.py check ids and the contract wording that must state each stop condition.
STOP_CONDITIONS = {
    "dirty": "dirty or has untracked files",
    "operation_in_progress": "a git operation is in progress",
    "detached_head_unreachable": "a detached HEAD would be orphaned",
    "checked_out_elsewhere": "BRANCH is checked out in another worktree",
    "ignored_collision": "an ignored path collides with a path the target tracks",
    "unresolvable_target": "a target cannot be resolved",
    "unverifiable": "a check cannot be run",
}


def preflight_step(contract):
    """The contract paragraph that runs the preflight (numbered step 3)."""
    return contract[contract.index("3. Preflight"):contract.index("4. Snapshot")]


class WordingTests(unittest.TestCase):
    def test_no_batch_or_per_item_worktree_wording_remains(self):
        found = []
        for path in scanned_files():
            found += violations(path.read_text(encoding="utf-8"), str(path.relative_to(REPO)))
        self.assertEqual([], found, "\n".join(f"{f}: [{r}] {s}" for f, r, s in found))

    def test_the_real_files_are_in_the_scan(self):
        names = {p.name for p in scanned_files()}
        for expected in ("SKILL.md", "README.md", "workflow.md", "single-item-checkout.md",
                         "PROJECT-CHANGES.md", "issue-coder.toml", "pr-coder.toml", "prm-dependency.toml",
                         "prm-reviewer.md", "issue-reviewer.md", "pr-sa.md", "roles.md",
                         "evidence-schema.md", "platforms.md", "pilot-history-checks.md"):
            self.assertIn(expected, names)

    def test_guard_flags_every_mutation(self):
        for label, text in MUTATIONS:
            with self.subTest(mutation=label):
                self.assertTrue(violations(text), f"not flagged: {text}")

    def test_every_rule_is_needed_by_a_mutation(self):
        """Dropping any one rule leaves some mutation unflagged: no rule is dead weight."""
        for i, (rid, *_rest) in enumerate(COMPILED):
            reduced = COMPILED[:i] + COMPILED[i + 1:]
            missed = [label for label, text in MUTATIONS if not violations(text, rules=reduced)]
            with self.subTest(rule=rid):
                self.assertTrue(missed, f"no mutation depends on rule {rid}")

    def test_guard_does_not_flag_the_contract_wording_or_innocent_prose(self):
        for text in CONTROLS:
            with self.subTest(control=text[:70]):
                self.assertEqual([], violations(text), text)

    def test_guard_flags_a_mutation_added_to_each_kind_of_file(self):
        """Appending a banned sentence to any scanned file is caught, whatever the file type."""
        for path in scanned_files():
            text = path.read_text(encoding="utf-8") + "\nEach Issue gets an isolated Git worktree.\n"
            with self.subTest(path=str(path.relative_to(REPO))):
                self.assertTrue(violations(text, str(path.relative_to(REPO))))

    def test_a_stray_negation_does_not_hide_a_hit(self):
        """`never` in an earlier clause must not exempt unrelated batch vocabulary."""
        for text in ("Never trust stale state, then re-run it serially merging the PRs.",
                     "The actor never trusts a saved decision, and Independent Issues should be serialized.",
                     "Never skip the gate, and handle the PRs one by one."):
            with self.subTest(text=text[:50]):
                self.assertTrue(violations(text), text)


class ContractStructureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract = flat((REPO / SHARED).read_text())

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
        text = self.contract
        for required in ("git status --porcelain", "git branch --show-current",
                         "git rev-parse HEAD", "head repository", "head SHA",
                         "checked out elsewhere", "Never stash", "detached HEAD",
                         "git switch --no-track -c", "never creates a replacement",
                         "Never start another item", "acquire the Issue claim first",
                         "outside the checkout", "source repository/revision",
                         "absolute snapshot paths", "BLOCKED", "realpath", "Known limitation",
                         "Read-only scratch copies", "candidate checkout"):
            self.assertIn(required, text)
        order = [text.index(marker) for marker in
                 ("checkout_preflight.py", "skill_snapshot.py\" create", "gh pr checkout N")]
        self.assertEqual(sorted(order), order, "preflight, then snapshot, then checkout")

    def test_preflight_stop_conditions_match_the_script_check_ids(self):
        """Every check id the script can report is stated as a stop condition, and nothing else is."""
        ids = set(re.findall(r'problem\(\s*"([a-z_]+)"', PREFLIGHT.read_text()))
        self.assertEqual(set(STOP_CONDITIONS), ids,
                         "a check was added or removed in checkout_preflight.py: update the contract")
        step = preflight_step(self.contract)
        for check, phrase in STOP_CONDITIONS.items():
            with self.subTest(check=check):
                self.assertIn(phrase, step)

    def test_preflight_step_locks_collisions_and_every_checked_commit(self):
        step = preflight_step(self.contract)
        for required in ('python3 "$REPO_ROOT/.agents/skills/_shared/scripts/checkout_preflight.py"',
                         "--target-ref TARGET_SHA --branch BRANCH",
                         "the same path", "a file/directory prefix of it in either direction",
                         "any path below an ignored nested git repository",
                         "Every commit that can land in the working tree is checked",
                         "--target-ref is repeatable",
                         "BRANCH's existing local tip is checked as well as TARGET_SHA",
                         "diff.ignoreSubmodules", "On any non-zero exit stop and ask",
                         "Never stash, discard, reset, force-checkout, or overwrite user work"):
            with self.subTest(required=required):
                self.assertIn(required, step)

    def test_helper_scripts_are_always_invoked_through_a_snapshot_or_repo_root_path(self):
        for m in re.finditer(r"skill_snapshot\.py", self.contract):
            before = self.contract[max(0, m.start() - 70):m.start()]
            self.assertRegex(before, r'"\$(?:REPO_ROOT|SNAP)/\.agents/skills/_shared/scripts/$',
                             f"bare skill_snapshot.py at {m.start()}")
        for verb in ("create", "verify", "verify-role"):
            with self.subTest(verb=verb):
                self.assertRegex(self.contract, rf'skill_snapshot\.py" {verb}\b')
        # create runs before the snapshot exists, verify/verify-role run from it
        self.assertRegex(self.contract, r'"\$REPO_ROOT/\.agents/skills/_shared/scripts/skill_snapshot\.py" create')
        self.assertRegex(self.contract, r'"\$SNAP/\.agents/skills/_shared/scripts/skill_snapshot\.py" verify\b')
        self.assertRegex(self.contract, r'"\$SNAP/\.agents/skills/_shared/scripts/skill_snapshot\.py" verify-role')

    def test_no_skill_document_shows_a_bare_script_invocation(self):
        """Scripts run from the verified snapshot: `python3 scripts/x.py` and `/path/to/` do not."""
        bare = re.compile(r"python3\s+(?:/path/to/|scripts/|<skill-dir>/)")
        for name in NAMES:
            for path in (SKILLS / name).rglob("*.md"):
                with self.subTest(path=str(path.relative_to(REPO))):
                    self.assertIsNone(bare.search(path.read_text()))

    def test_fork_pr_branch_name_and_scratch_copy_wording_are_stated(self):
        self.assertIn("may create a local branch named differently", self.contract)
        self.assertIn("verify it together with the SHA instead of assuming BRANCH", self.contract)
        self.assertIn("a read-only scratch copy of that same SHA is an equally valid one", self.contract)
        self.assertNotIn("do not build another one", self.contract)

    def test_project_changes_name_the_contract_scripts_and_tests(self):
        """Each skill's PROJECT-CHANGES row lists the shared contract, helper scripts and guards."""
        for name in NAMES:
            text = " ".join((SKILLS / name / "PROJECT-CHANGES.md").read_text().split())
            for required in ("single-item-checkout.md", "checkout_preflight.py", "skill_snapshot.py",
                             "_shared/tests/test_single_item_contract.py", "test_checkout_preflight.py",
                             "test_skill_snapshot.py", "test_skill_links.py"):
                with self.subTest(skill=name, needs=required):
                    self.assertIn(required, text)
            self.assertNotIn("pr-review-merge/tests/test_single_item_contract.py", text)

    def test_the_history_reference_matches_the_contract(self):
        text = flat((REPO / HISTORY).read_text())
        self.assertIn("只使用 Root 指派且已驗證的 checkout", text)
        self.assertIn("git archive", text)
        self.assertNotIn("指派 worktree", text)
        self.assertNotIn("乾淨隔離的 candidate checkout", text)


if __name__ == "__main__":
    unittest.main()
