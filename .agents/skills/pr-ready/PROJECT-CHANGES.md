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
| `SKILL.md`, `README.md`, `references/{workflow,roles,evidence-schema}.md`, `platforms/{claude,codex,agy}/agents/pr-{coder,reviewer,sa}.*` | Single PR per invocation; per-PR state under `.pr-ready/<N>/`. The branch lands by exact SHA (`checkout_preflight.py --execute`, never by name), the skill bundle is snapshotted first (`skill_snapshot.py`) and role files are checked before dispatch (a differing role is DRIFT: dispatch under the snapshot, report the header changes; a missing one is BLOCKED), and the starting branch is restored at the end. Contract `.agents/skills/_shared/single-item-checkout.md`, cited by repo-root path because Claude Code reads the skill through `.claude/skills/pr-ready`; guards in `_shared/tests/`. |
| `../pilot-code-review/references/pilot-history-checks.md` (shared with the other skills, not part of this bundle) | Hands children the assigned verified checkout (no worktree creation, no branch switching) and defines a candidate as the clean committed checkout or a read-only `git archive` scratch copy; included in the guard scan. |
| `SKILL.md` | "Project runtime configuration" (orchestrator keeps the session model; role models live only in the native role definitions) and "Pilot: turn review history into a verification plan" sections |
| `platforms/{claude,codex,agy}/agents/pr-{sa,coder,reviewer}.*` | pilot lines: read the Root-supplied `pilot_history_checks`, finding ledger and target-validation plan; vm-target evidence rules; unavailable required validation keeps the PR Draft |
| `references/roles.md`, `references/workflow.md` | `pilot_history_checks` hand-off paragraphs (reference lives in `../pilot-code-review/references/pilot-history-checks.md`) |
| `references/quality-gate.md` | item 8, "Pilot target evidence (Root/Reviewer check)" |
| `scripts/install.sh`, `tests/test_installer.py`, the two `test_install_*_smoke` cases in `tests/test_pr_gate.py` | removed: the skill is repository-local, nothing installs it elsewhere |
| `README.md` | install sections replaced by the repository layout (symlinks, `.codex/agents` copies, consistency test) |

Repository-side pieces the skill relies on: `.github/pr-evidence.json`, `make skill-test`
(wired into CI's Go test job) and the consistency test above. Files not listed here are
believed unchanged from upstream; verify against the upstream archive when upgrading.
