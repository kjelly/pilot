# Project-local changes to the packaged issue-to-pr skill

Upstream bundle: issue-to-pr 1.2.0 (`VERSION`; Apache-2.0, `LICENSE`). This copy is the
canonical one for the pilot repository: `.claude/skills/issue-to-pr` is a symlink to it and
`.codex/agents/issue-*.toml` are byte copies of `platforms/codex/agents/`
(`cmd/pilot/cmd/agent_skill_consistency_test.go` checks both, and that the claude, codex and
agy prompt bodies of each role are identical). Keep this list current so an upstream upgrade
is a three-way merge instead of guesswork: `diff -r <upstream> .agents/skills/issue-to-pr`,
re-apply the rows below, then run `make skill-test` and
`go test ./cmd/pilot/cmd -run TestAgentSkillLayout`.

| File | Project-specific change |
|---|---|
| `SKILL.md`, `README.md`, `references/{workflow,platforms,quality-gate,evidence-contract,repo-evidence}.md`, `platforms/{claude,codex,agy}/agents/issue-{coder,reviewer}.*` | Single Issue per invocation. The branch lands by exact SHA (`checkout_preflight.py --execute`, never by name), the skill bundle is snapshotted first (`skill_snapshot.py`) and role files are checked before dispatch (a differing role is DRIFT: dispatch under the snapshot, report the header changes; a missing one is BLOCKED), and the starting branch is restored at the end. Contract `.agents/skills/_shared/single-item-checkout.md`, cited by repo-root path because Claude Code reads the skill through `.claude/skills/issue-to-pr`; guards in `_shared/tests/`. |
| `../pilot-code-review/references/pilot-history-checks.md` (shared with the other skills, not part of this bundle) | Hands children the assigned verified checkout (no worktree creation, no branch switching) and defines a candidate as the clean committed checkout or a read-only `git archive` scratch copy; included in the guard scan. |
| `SKILL.md` | "Project runtime configuration" (orchestrator keeps the session model; role models live only in the native role definitions) and "Pilot: history and actual-run decision before implementation" sections |
| `platforms/{claude,codex,agy}/agents/issue-{sa,coder,reviewer}.*` | pilot lines: read the Root-supplied `pilot_history_checks`, finding ledger and target-validation plan; vm-target evidence rules; unavailable required validation is blocked, not PASS |
| `references/platforms.md` | role model pins paragraph; `pilot_history_checks` hand-off paragraph (reference lives in `../pilot-code-review/references/pilot-history-checks.md`) |
| `references/severity.md` | note that the project-local workflows share the rubric |
| `scripts/install.sh`, `tests/test_installer.py` | removed: the skill is repository-local, nothing installs it elsewhere |
| `README.md`, `references/platforms.md` | install sections replaced by the repository layout (symlinks, `.codex/agents` copies, consistency test) |

Repository-side pieces the skill relies on: `.github/pr-evidence.json` (evidence manifest the
gate reads from the base branch), `make skill-test` (runs `tests/`, wired into CI's Go test
job) and the consistency test above. Files not listed here are believed unchanged from
upstream 1.2.0; verify against the upstream archive when upgrading.
