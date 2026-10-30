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
| `SKILL.md` | "Project runtime configuration" (orchestrator keeps the session model; role models live only in the native role definitions) and "Pilot: history and actual-run decision before implementation" sections |
| `platforms/{claude,codex,agy}/agents/issue-{sa,coder,reviewer}.*` | pilot lines: read the Root-supplied `pilot_history_checks`, finding ledger and target-validation plan; vm-target evidence rules; unavailable required validation is blocked, not PASS |
| `references/platforms.md` | role model pins paragraph; `pilot_history_checks` hand-off paragraph (reference lives in `../pilot-code-review/references/pilot-history-checks.md`) |
| `references/severity.md` | note that the project-local `issue-to-pr`, `pr-ready` and `pilot-code-review` workflows share the rubric |

Repository-side pieces the skill relies on: `.github/pr-evidence.json` (evidence manifest the
gate reads from the base branch), `make skill-test` (runs `tests/`, wired into CI's Go test
job) and the consistency test above. Files not listed here are believed unchanged from
upstream 1.2.0; verify against the upstream archive when upgrading.
