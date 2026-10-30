# Project-local changes to the packaged pr-ready skill

Upstream bundle: pr-ready (unversioned archive; record the archive name and date here when
upgrading). This copy is the canonical one for the pilot repository: `.claude/skills/pr-ready`
is a symlink to it and `.codex/agents/pr-*.toml` are byte copies of `platforms/codex/agents/`
(`cmd/pilot/cmd/agent_skill_consistency_test.go` checks both, and that the claude, codex and
agy prompt bodies of each role are identical). Keep this list current so an upstream upgrade
is a three-way merge: `diff -r <upstream> .agents/skills/pr-ready`, re-apply the rows below,
then run `make skill-test` and `go test ./cmd/pilot/cmd -run TestAgentSkillLayout`.

| File | Project-specific change |
|---|---|
| `SKILL.md`, `README.md`, `references/{workflow,roles,evidence-schema}.md`, `platforms/{claude,codex,agy}/agents/pr-{coder,reviewer,sa}.*` | Single PR per invocation; checkout the original head branch in the current clean checkout before work, no per-PR worktree/batch scheduling; per-PR state under `.pr-ready/<N>/`. Shared contract `.agents/skills/_shared/single-item-checkout.md` (cited by repo-root path, not a relative link: Claude Code reads the skill through `.claude/skills/pr-ready`, where `../_shared` does not resolve); helper scripts `_shared/scripts/checkout_preflight.py` (dirty, ignored-file collision, checked-out-elsewhere preflight) and `_shared/scripts/skill_snapshot.py` (bundle snapshot outside the checkout, role verification before dispatch). Guards: `_shared/tests/test_checkout_preflight.py`, `_shared/tests/test_skill_snapshot.py`, `_shared/tests/test_skill_links.py` (links resolve from the Claude path) and `pr-review-merge/tests/test_single_item_contract.py` (scheduling-drift wording across every skill file and role prompt). |
| `SKILL.md` | "Project runtime configuration" (orchestrator keeps the session model; role models live only in the native role definitions) and "Pilot: turn review history into a verification plan" sections |
| `platforms/{claude,codex,agy}/agents/pr-{sa,coder,reviewer}.*` | pilot lines: read the Root-supplied `pilot_history_checks`, finding ledger and target-validation plan; vm-target evidence rules; unavailable required validation keeps the PR Draft |
| `references/roles.md`, `references/workflow.md` | `pilot_history_checks` hand-off paragraphs (reference lives in `../pilot-code-review/references/pilot-history-checks.md`) |
| `references/quality-gate.md` | item 8, "Pilot target evidence (Root/Reviewer check)" |
| `scripts/install.sh`, `tests/test_installer.py`, the two `test_install_*_smoke` cases in `tests/test_pr_gate.py` | removed: the skill is repository-local, nothing installs it elsewhere |
| `README.md` | install sections replaced by the repository layout (symlinks, `.codex/agents` copies, consistency test) |

Repository-side pieces the skill relies on: `.github/pr-evidence.json`, `make skill-test`
(wired into CI's Go test job) and the consistency test above. Files not listed here are
believed unchanged from upstream; verify against the upstream archive when upgrading.
