"""Guard startup ordering and consistent permission boundaries in Codex skills.

This text guard does not prove agent/host behaviour. A real retained-terminal
startup is separate evidence. BASE and mutation controls must fail for this
instruction invariant rather than unavailable tools or filesystem permissions.
Discover callers so new Codex entrypoints join the guard.
"""
from pathlib import Path
import re
import unittest

SKILLS = Path(__file__).resolve().parents[2]
ENTRIES = {f"{name}/SKILL.md" for name in
           ("issue-to-pr", "pr-ready", "pr-review-merge")}
POLICY = "_shared/codex-terminal-permissions.md"
POLICY_PATH = ".agents/skills/" + POLICY
DISPATCH = "_shared/codex-role-dispatch.md"
HEADING = "## Codex terminal permissions (before the first process)"
CHECKOUT = "## Single-item checkout contract (mandatory)"

# Three copies carry one startup rule. Changes to its meaning need all three.
ENTRY_FACTS = (
    "For Codex, before the first shell/process execution, including realpath, git, gh or snapshot/checkout helpers, apply this startup rule",
    "The retained audited terminal needs GitHub network access and the .git writes required by this workflow",
    "If the current grants are insufficient, request the normal, narrowly justified permission grant when starting that terminal",
    "Do not start it under insufficient permissions and wait for a later git fetch or gh failure",
    "Adequate existing grants need no repeat approval",
    "A rejected or unavailable required grant stops under the workflow's existing blocked-outcome protocol",
    "Keep sandbox, branch protections and terminal auditing intact",
    POLICY_PATH,
    "through a non-process reader when available, or in that approved recorded terminal before the single-item checkout contract below",
    "This inline rule is sufficient to establish the terminal when file reading itself needs a process",
)
POLICY_FACTS = (
    "Apply the self-contained inline startup rule",
    "File reading that needs a process must not create a circular prerequisite",
    "live process tool declaration from the available host context before launching a shell",
    "writes to the actual Git metadata directory",
    "Existing grants that cover the required operations are sufficient",
    "request the normal permission grant at startup of the retained terminal, before its first process runs",
    'sandbox_permissions="require_escalated" with a justification when the live process tool exposes it',
    "Keep the request limited to that workflow and checkout",
    "A grant to launch the shell does not authorize unrelated commands or GitHub state changes",
    "Start the retained shell under the required terminal recorder in that approved process invocation",
    "Keep subsequent git, gh, helpers and tests in the same recorded shell",
    "Use only exposed capabilities",
    "does not promise that a process tool supports escalation",
    "Never disable the sandbox, change personal configuration, or bypass branch protections",
    "issue-to-pr reports BLOCKED, pr-ready reports DRAFT-BLOCKED, and pr-review-merge reports WAITING with its existing wait_kind and handoff rules",
    "Do not invent a universal status or send WAITING to the draft-phase task-result writer",
    "Do not blindly retry, switch to a different tool to evade the denial",
    "When they are insufficient, stop sending workflow commands",
    "Do not assume a later approval upgrades that live process",
    "finish/close it safely under the recorder's rules",
    "If safe replacement or the necessary grant is unavailable, stop with that workflow-specific blocked outcome",
    "Disclose any interrupted or incomplete recording",
    "revalidate checkout identity and remote facts before resuming",
    "Preserve all deterministic gates, single-writer ownership, secret scanning, safe checkout/restoration, independent review and GitHub action authorization",
)


def flat(text):
    return " ".join(text.replace("`", "").replace("*", "").split())


def read_contract(skills=SKILLS):
    texts = {p.relative_to(skills).as_posix(): p.read_text(encoding="utf-8")
             for p in skills.glob("*/SKILL.md")}
    for name in (POLICY, DISPATCH):
        path = skills / name
        texts[name] = path.read_text(encoding="utf-8") if path.exists() else ""
    return texts


def problems(texts):
    callers = ENTRIES | {name for name, text in texts.items()
                         if name.endswith("/SKILL.md") and
                         ".agents/skills/_shared/codex-role-dispatch.md" in text}
    errors = []
    for name in sorted(callers):
        text = texts.get(name, "")
        start = text.find(HEADING)
        following = text.find("\n## ", start + len(HEADING)) if start >= 0 else -1
        block = text[start:following if following >= 0 else len(text)] if start >= 0 else ""
        checkout = text.find(CHECKOUT)
        # A fenced command can be executed when encountered. Bootstrap comes first.
        fence = re.search(r"(?m)^\s*(?:```|~~~)", text)
        if (start < 0 or checkout < 0 or start >= checkout or
                (fence is not None and start >= fence.start())):
            errors.append(f"{name}: permission startup must precede checkout and command fences")
        for fact in ENTRY_FACTS:
            if fact not in flat(block):
                errors.append(f"{name}: missing early permission fact: {fact}")
    for fact in POLICY_FACTS:
        if fact not in flat(texts.get(POLICY, "")):
            errors.append(f"{POLICY}: missing permission boundary: {fact}")
    dispatch = texts.get(DISPATCH, "")
    if POLICY_PATH not in dispatch or "before the first process" not in flat(dispatch):
        errors.append(f"{DISPATCH}: missing earlier startup cross-reference")
    return errors


class CodexTerminalPermissionTests(unittest.TestCase):
    def test_all_codex_entrypoints_establish_permissions_before_checkout(self):
        self.assertEqual([], problems(read_contract()))

    def test_removal_rewording_and_late_placement_are_rejected_for_each_entry(self):
        original = read_contract()
        for name in sorted(ENTRIES):
            text = original[name]
            begin = text.index(HEADING)
            end = text.index(CHECKOUT, begin)
            block = text[begin:end]
            mutations = {
                "removed": text[:begin] + text[end:],
                "reworded": text.replace("before the first shell/process", "after the first shell/process", 1),
                "late": text[:begin] + text[end:] + "\n" + block,
                "command-first": text[:begin] + "```bash\ngit fetch origin\n```\n" + text[begin:],
            }
            for mutation, changed in mutations.items():
                with self.subTest(entry=name, mutation=mutation):
                    errors = problems(dict(original, **{name: changed}))
                    self.assertTrue(any(error.startswith(name + ":") for error in errors), errors)

    def test_new_codex_caller_joins_the_guard(self):
        texts = read_contract()
        name = "future-workflow/SKILL.md"
        texts[name] = texts["pr-ready/SKILL.md"].replace(HEADING, "## Later permissions", 1)
        self.assertTrue(any(error.startswith(name + ":") for error in problems(texts)))

    def test_each_shared_boundary_is_required(self):
        original = read_contract()
        for fact in POLICY_FACTS:
            with self.subTest(boundary=fact):
                texts = dict(original)
                texts[POLICY] = flat(texts[POLICY]).replace(fact, "omitted boundary", 1)
                self.assertTrue(any(error.startswith(POLICY + ":") for error in problems(texts)))


if __name__ == "__main__":
    unittest.main()
