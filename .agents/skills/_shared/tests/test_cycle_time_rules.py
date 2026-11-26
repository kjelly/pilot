"""Consistency and stale-sentence guard for the cycle-time instructions (kjelly/pilot#432, items 2, 1 and 6).

One fact lives in several files: the Coder runs the tests of what it changed and the planned `make skill-test` (the suites
the change can reach, kjelly/pilot#430; CI runs the full one) runs once, as the receipt on the committed HEAD (item 2); a commit that was read and scanned is pushed before its review, so CI
runs beside it, and the first push of issue-to-pr stays after GATE-PASS (item 1); one Coder dispatch carries every
request known for the PR (item 6). AGENTS.md section 5.7: two copies of one fact need a consistency test that has been
seen to fail. SAYS lists, per file, the phrases of each sentence that carries the fact; STALE lists the sentences this
change replaced, all of them on the base, so this module fails there. Both directions are exercised (section 5.12):
dropping a phrase is reported, and putting a replaced sentence back is reported.

This is a consistency and stale-sentence guard only. It does not show that an agent follows the text (a wording test is
no proof of behaviour, issue-to-pr/references/quality-gate.md): the behaviour scenarios of the change are answered
separately. Text is compared with Markdown emphasis, code marks and line breaks removed, so the phrases carry no
backticks.
"""
import re
import unittest
from pathlib import Path

SKILLS = Path(__file__).resolve().parents[4] / ".agents" / "skills"
RULES_HEADING = "## Pilot: cycle-time rules"

# The validation item of the Coder's dispatch envelope: one fact in three files (F2 of the review of 986bf7d9).
ENVELOPE = ("the tests of what it changed; not the planned make skill-test (Root runs that once, as the receipt)")

# file (relative to .agents/skills) -> the phrases it must contain
SAYS = {
    "pr-ready/SKILL.md": (
        # rule 1 (item 2), rule 2 (order), step 3, step 4, step 6
        "once per candidate HEAD, as the receipt on the committed HEAD; while it works the Coder runs only the tests of "
        "the skills it changed: .agents/skills/_shared/local-validation.md",
        "every non-empty change plans it; a path no suite is known to read, such as a Go-only, playbook-only or docs-only "
        "change, selects every suite; otherwise the plan narrows it to the suites the change can reach and prints the "
        "reason for each; CI runs the full make skill-test;",
        "freeze the code and push it (rule 9), review it,",
        "for a skill change, that skill's tests (the planned make skill-test, for the suites the change can reach or for "
        "every suite when a changed path is unknown, deleted or renamed, runs once, as the receipt; CI runs the full make "
        "skill-test)",
        "Dispatch it on a commit that is already pushed, except one that adds real captures, which is reviewed first "
        "(cycle-time rule 9)",
        "Push each commit as soon as it has been read and scanned for secrets, before its review and receipts "
        "(cycle-time rule 9, with its exception for real captures)",
        # rule 9 (item 1)
        "Push a commit before its review, so CI runs beside it (kjelly/pilot#432)",
        "Root reads every line it adds and runs secret_scan.py over the commits to push",
        "anything but exit 0 stops the push",
        "and only then dispatches the reviewer and runs the receipts, while CI runs on that HEAD",
        "The PR stays a Draft, so pr-review-merge and the merge train do not act on it",
        "Start pr_gate.py --wait --ready once the review and the receipts are in the evidence (step 7), whether or not "
        "CI has finished",
        "CI on the earlier commit is not evidence for it (step 6), and its run time is the accepted cost",
        "A commit that adds real captures or other output copied from a live service (AGENTS.md section 5.6) is pushed "
        "after its review, as before: a push is publication",
        "A docs/evidence record commit is pushed after Root's read and scan, like any other evidence-only delta "
        "(rule 2)",
        "No gate is weaker: the secret scan still comes before every push, and the gate still requires the independent "
        "review, the receipts and CI on the final HEAD",
        # rule 10 (item 6)
        "One round for the requests a PR has (kjelly/pilot#432)",
        "give one Coder dispatch everything known that this PR must change",
        "one that arrives while the review runs joins the next round instead of starting its own; that round is "
        "started when the review has no blocker, and pr_gate.py --wait --ready is not started while a known request "
        "is outstanding",
        "(a design question, a class-level fix SA plans instead of point fixes) goes first and the others wait for it",
        "the user asks for a separate round",
        "P3/P4 remarks still do not start or join a round (rule 3), and nothing is added that no one asked for",
        "No gate is weaker: the round's review covers its whole delta (rule 4), and each request is still fixed and "
        "verified, or disputed, like a single one",
    ),
    "pr-ready/references/workflow.md": (
        "The Coder's envelope carries a validation item (every non-empty change plans make skill-test, narrowed or whole, "
        "so it is always there): \"" + ENVELOPE + "\"",
        "Parent owns GitHub mutations: the push of each scanned commit (SKILL.md, cycle-time rule 9) and Ready after "
        "the final gate.",
        "A round starts with one Coder dispatch that carries everything known that this PR must change",
        "joins the next round, which is started when the review has no blocker; --wait --ready is not started with a "
        "known request outstanding (SKILL.md, cycle-time rule 10, with its two exceptions)",
    ),
    "pr-ready/references/roles.md": (
        "for a skill change, the tests of the skills it changed: the one planned make skill-test, for the suites the "
        "change can reach (every suite when a changed path is unknown, deleted or renamed), is the receipt on the "
        "committed HEAD, and CI runs the full make skill-test (.agents/skills/_shared/local-validation.md)",
    ),
    "pr-ready/README.md": (
        "plan 把 make skill-test 縮到變更碰得到的 suites 並印出每個的理由（沒有任何 suite 讀的路徑、刪除、改名、類型變更或 "
        "derivation 失敗則選全部，所以只動 Go、playbook 或文件的變更也計畫完整的 make skill-test；只有空 diff 沒有），"
        "那個 planned make skill-test 只在 committed HEAD 上以 receipt 跑一次（CI 仍跑完整的 make skill-test）",
        "再派 Reviewer 並跑 receipts，讓 CI 與它們同時進行（Draft 不會被 pr-review-merge 與 merge train 處理；",
        "真實擷取的輸出等審查後才 push",
        "一輪交給一個 Coder（rule 10）",
    ),
    "pr-ready/PROJECT-CHANGES.md": ("kjelly/pilot#432 items 2, 1 and 6", "2026-11-23, kjelly/pilot#430"),
    "issue-to-pr/SKILL.md": (
        "Only GATE-PASS for the currently checked-out HEAD authorizes the next stage: it authorizes the first push and "
        "the PR; a repair commit on an existing Draft is pushed after Root's read and scan (section 4)",
        "also, because every non-empty change plans make skill-test (narrowed or whole), a validation item: \"" + ENVELOPE + "\"",
        "Once the Draft exists, each repair commit is pushed first, as section 4 says, whatever its reason (a CI "
        "failure or a review finding); the first push stays after GATE-PASS",
        "the Coder runs that skill's tests while it works and the planned make skill-test (the suites the change can "
        "reach, with the reason for each, or every suite when a changed path is unknown, deleted or renamed; CI runs "
        "the full make skill-test) runs once, as the receipt on the committed HEAD "
        "(.agents/skills/_shared/local-validation.md)",
        "Give the Coder every blocker of the review, with any other request known for this Issue, in one dispatch; a "
        "request whose answer changes another goes first",
        "The first push stays after GATE-PASS: create_pr.py pushes only once issue_gate.py passes (review and receipts "
        "at HEAD), and a branch with no PR gets no automatic CI; only repairs after the Draft exists push before their review "
        "(kjelly/pilot#433 asks whether the first one may)",
        "repair on the same branch: commit, read the added lines, run the secret scan and push, then run the renewed "
        "tests and the independent review while CI runs on the new HEAD, and re-check (CI on the earlier commit is not "
        "evidence for it)",
        "A commit that adds real captures or other output copied from a live service is pushed after its review, as "
        "pr-ready does",
        "fix on the same Issue branch: push the scanned commit, then rerun affected tests and an independent review "
        "while its CI runs; never create a second PR",
    ),
    "issue-to-pr/references/workflow.md": (
        "It authorizes the first push and the PR; once the Draft exists, a repair commit goes COMMITTED -> PUSHED after "
        "Root's read and scan, and CHECKED and REVIEWED on the new SHA run while its CI runs (SKILL.md, section 4)",
        "Root invalidates old evidence, reads the added lines, runs the secret scan and pushes; checks and review on "
        "the new SHA run while its CI runs",
    ),
    "issue-to-pr/README.md": (
        "the planned make skill-test (the suites the change can reach, with the reason for each, or every suite when a "
        "changed path is unknown, deleted or renamed; CI runs the full make skill-test) runs once, as the receipt on the "
        "committed HEAD",
        "one Coder dispatch carries every blocker, with any other request known for the Issue",
        "The first push stays after the gate (a branch with no PR gets no automatic CI; kjelly/pilot#433)",
        "push the scanned commit, repeat test/review while its CI runs and re-check CI on it",
    ),
    "issue-to-pr/PROJECT-CHANGES.md": (
        "kjelly/pilot#432 items 2, 1 and 6",
        "2026-11-23, kjelly/pilot#430",
        "../_shared/tests/test_cycle_time_rules.py (new, shared with pr-ready)",
        "a branch with no PR gets no automatic CI",
    ),
    "_shared/local-validation.md": (
        "Every non-empty change adds make skill-test (once, as the receipt: below), narrowed to the suites the change can "
        "reach; a path no suite is known to read selects every suite, so a Go-only, playbook-only or docs-only change "
        "plans the plain make skill-test too.",
        "The plan's make skill-test runs once per candidate HEAD, as the run_check.py receipt on the committed HEAD "
        "(Root's, or the Coder's when it takes the receipt; never both)",
        "Root takes the receipt unless the dispatch envelope tells the Coder to; the Coder's envelope carries the "
        "validation item \"" + ENVELOPE + "\"",
        "The plan narrows make skill-test to the suites the change can reach and prints the reason for each",
        "Run the planned command exactly: a narrower command is not the receipt",
        "A path no suite is known to read (anywhere in the repository: a Go-only, playbook-only or docs-only change has "
        "one, and so plans the plain make skill-test",
        "a deleted, renamed or type-changed path, a path that is not canonical, and any error while deriving the suites, "
        "select all of them (the plain make skill-test); only an empty diff plans no skill command",
        "Keep the plan JSON next to the receipt, for the reviewers",
        "CI's Skill and repository contracts job still runs the full make skill-test, and Ready requires it",
        "A CI failure in a suite the plan left out is a defect of the selection: repair the selection and the suite, and "
        "never list it as an unrelated_failing_checks entry",
        "pr-review-merge ignores the selection: it runs the full suite on its own candidate",
        "the make skill-test that pr-review-merge runs (its SKILL.md) is a separate gate on a separate candidate",
    ),
}

# What this change replaced. Each is on the base; none may come back, in any file of the two skills or in _shared.
STALE = (
    "Parent owns Github mutations (push/Ready) after verification",        # pr-ready workflow.md: push after verification
    "rerun affected tests and an independent review, then push",           # issue-to-pr Draft-first: review, then push
    "with renewed tests and independent review, push, and re-check",       # issue-to-pr section 4: review, then push
    "checks/review on new SHA; push;",                                     # issue-to-pr workflow.md: review, then push
    "Skill changes add make skill-test.",                                  # local-validation.md: the suite, no "once"
    "A narrower selection of suites is kjelly/pilot#430; until it changes this text the receipt is the whole suite",
    "No gate is weaker: that receipt still runs every suite on the exact HEAD the gate checks",
    "A deleted, renamed or unattributed path, and any error while deriving the suites, select all of them",
    "Skill changes add make skill-test (once, as the receipt: below).",
    "When the diff touches .agents/skills, the Coder's envelope carries a validation item",
    "when the diff touches .agents/skills, also a validation item",
    "make skill-test for .agents/skills changes",
    "plans all of them when a path is deleted, renamed or unattributed",
    "all of them when the mapping is unknown or a path is deleted or renamed",
)

# The numbers other files cite ("cycle-time rule 3", "rule 9"): appended, never renumbered.
RULE_TITLES = {
    1: "Local receipts cover what the diff touches.",
    2: "Receipts and the review survive an evidence-only delta.",
    3: "P3/P4 close the round; they do not start another.",
    4: "One reviewer per round over the whole diff",
    5: "Do not chase main; the merge train integrates it (kjelly/pilot#307).",
    6: "A bounced PR gets the merge reviewer's rubric before Ready.",
    7: "Do not block on a question that has a conservative answer.",
    8: "Mind the machine.",
    9: "Push a commit before its review, so CI runs beside it",
    10: "One round for the requests a PR has",
}


def flat(text):
    """Text with Markdown emphasis and code marks removed and white space collapsed."""
    return " ".join(text.replace("`", "").replace("*", "").split())


def read(rel):
    return (SKILLS / rel).read_text(encoding="utf-8")


def stale_scan_files():
    """Every Markdown file of the two skills and of _shared (not its tests, not another skill)."""
    found = []
    for base in ("pr-ready", "issue-to-pr"):
        found += sorted((SKILLS / base).rglob("*.md"))
    return [p.relative_to(SKILLS).as_posix() for p in found + sorted((SKILLS / "_shared").glob("*.md"))]


def reference_scan_files():
    return stale_scan_files() + [p.relative_to(SKILLS).as_posix() for p in sorted((SKILLS / "pr-review-merge").rglob("*.md"))]


def missing(texts, says=SAYS):
    """texts: file -> flat text. One entry per phrase a file does not contain."""
    return [f"{rel}: does not say {phrase!r}" for rel, phrases in says.items() for phrase in phrases
            if phrase not in texts.get(rel, "")]


def stale(texts, phrases=STALE):
    return [f"{rel}: still says {phrase!r}" for rel, text in texts.items() for phrase in phrases if phrase in text]


def rule_titles(skill_text):
    """number -> title of the numbered, bold-titled rules under the cycle-time heading of pr-ready/SKILL.md."""
    start = skill_text.index(RULES_HEADING)
    end = skill_text.find("\n## ", start + 1)
    section = skill_text[start:end if end != -1 else None]
    return {int(n): title for n, title in re.findall(r"^(\d+)\. \*\*(.+?)\*\*", section, re.M)}


def title_problems(skill_text):
    found = rule_titles(skill_text)
    return [f"rule {n}: {found.get(n)!r}, expected {title!r}" for n, title in RULE_TITLES.items()
            if found.get(n) != title] + [f"unexpected rule {n}" for n in found if n not in RULE_TITLES]


def bad_references(texts, numbers=frozenset(RULE_TITLES)):
    """Every `cycle-time rule N` (or `rules N and M`) citation whose N is not a rule of pr-ready/SKILL.md."""
    found = []
    for rel, text in texts.items():
        for group in re.findall(r"cycle-time rules? ((?:\d+(?:, and |, | and )?)+)", text):
            found += [f"{rel}: cycle-time rule {n}" for n in re.findall(r"\d+", group) if int(n) not in numbers]
    return found


class CycleTimeInstructionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.says = {rel: flat(read(rel)) for rel in SAYS}
        cls.scan = {rel: flat(read(rel)) for rel in stale_scan_files()}
        cls.cited = {rel: flat(read(rel)) for rel in reference_scan_files()}

    def test_the_real_files_state_every_sentence(self):
        self.assertEqual([], missing(self.says))

    def test_no_replaced_sentence_remains(self):
        self.assertEqual([], stale(self.scan))

    def test_dropping_any_phrase_is_reported(self):
        for rel, phrases in SAYS.items():
            for phrase in phrases:
                with self.subTest(file=rel, phrase=phrase[:60]):
                    self.assertIn(phrase, self.says[rel])
                    dropped = dict(self.says, **{rel: self.says[rel].replace(phrase, "")})
                    self.assertIn(f"{rel}: does not say {phrase!r}", missing(dropped))

    def test_every_replaced_sentence_is_reported_when_it_comes_back(self):
        for phrase in STALE:
            for rel in ("pr-ready/SKILL.md", "issue-to-pr/SKILL.md", "_shared/local-validation.md"):
                with self.subTest(file=rel, phrase=phrase[:50]):
                    back = dict(self.scan, **{rel: self.scan[rel] + " " + phrase})
                    self.assertIn(f"{rel}: still says {phrase!r}", stale(back))

    def test_the_rules_keep_their_numbers(self):
        self.assertEqual([], title_problems(read("pr-ready/SKILL.md")))

    def test_a_renumbered_or_added_rule_is_reported(self):
        text = read("pr-ready/SKILL.md")
        self.assertIn("\n3. **P3/P4 close", text)
        for label, mutated in (("renumbered", text.replace("\n3. **P3/P4 close", "\n13. **P3/P4 close", 1)),
                               ("added", text.replace("\n## Inputs and preflight", "11. **Another rule.** x\n\n"
                                                      "## Inputs and preflight", 1))):
            with self.subTest(case=label):
                self.assertTrue(title_problems(mutated))

    def test_every_cited_rule_exists(self):
        self.assertEqual([], bad_references(self.cited))
        self.assertTrue(any("cycle-time rule 9" in text for text in self.cited.values()), "the scan sees the citations")

    def test_a_citation_of_a_missing_rule_is_reported(self):
        for text in ("see cycle-time rule 11", "cycle-time rules 2 and 12", "cycle-time rules 1, 9 and 0"):
            with self.subTest(text=text):
                self.assertTrue(bad_references({"x.md": text}))
        self.assertEqual([], bad_references({"x.md": "cycle-time rules 2 and 5, and cycle-time rule 10"}))


if __name__ == "__main__":
    unittest.main()
