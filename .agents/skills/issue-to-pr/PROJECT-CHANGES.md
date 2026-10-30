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
| `references/severity.md` | note that the project-local workflows share the rubric |
| `scripts/install.sh`, `tests/test_installer.py` | removed: the skill is repository-local, nothing installs it elsewhere |
| `README.md`, `references/platforms.md` | install sections replaced by the repository layout (symlinks, `.codex/agents` copies, consistency test) |
| `references/issue-claims.md` (new), `SKILL.md` (§0 Issue fetch with `comments` and claims rule, §1 SA claims and `CLOSED`/`INVALID`/`NEEDS_DECISION` classification, §2.5 reviewer, §4 `Refs #N`, §5 statuses), `references/{workflow,evidence-contract,quality-gate}.md`, `README.md` | Issue claims are hypotheses: triage into `valid`/`invalid`/`needs_evidence`/`out_of_scope`, the reviewer judges disputed claims without SA's conclusion, Root answers them on the Issue and records `disputed_issue_claims`; `issue_resolution: partial` for Issues that stay open; a claim raised again without new evidence is `NEEDS_DECISION` |
| `scripts/issue_gate.py` (`gh_issue_thread`, `check_disputed_claims`, `issue_resolution`, shared `closes_issue`/`references_issue`), `scripts/create_pr.py` (`issue_reference_problem`), `tests/test_issue_gate.py` (`DisputedIssueClaimTests`), `tests/test_create_and_ci.py` (partial-resolution cases) | the gate verifies each disputed claim's reply against the Issue's comments (fetched only when there are disputes); a `partial` PR must reference the Issue without closing it |
| `scripts/issue_gate.py` (`leaves_issue_open`, `follow_up_number`, `check_follow_ups`, `gh_follow_up_issue`, `issue_resolution` in the gate's info), `scripts/mark_ready.py` (PR `body` re-checked with `issue_reference_problem` before `gh pr ready`), `tests/test_issue_gate.py` (`DisputedIssueClaimTests`), `tests/test_mark_ready.py`, `references/{issue-claims,evidence-contract,quality-gate}.md` | the converse of "partial needs a dispute": `fixes` (also the default) is refused while a `needs_evidence` claim, or an `out_of_scope` claim without a verified follow-up, stays open. The optional `out_of_scope` field `follow_up_issue_url` must be an Issue of the same repository other than this one, linked in the entry's reply, and found by a read-only `gh issue view` (a PR number or any lookup failure blocks; open or closed). Ready re-checks the PR body against the evidence's resolution, because either can change after create |
| `platforms/{claude,codex,agy}/agents/issue-{sa,coder,reviewer}.*` | Issue claims are hypotheses (SA, Coder); the reviewer returns `disputed_claim_verdicts` and checks every stated acceptance criterion is met or disputed |

Repository-side pieces the skill relies on: `.github/pr-evidence.json` (evidence manifest the
gate reads from the base branch), `make skill-test` (runs `tests/`, wired into CI's Go test
job) and the consistency test above. Files not listed here are believed unchanged from
upstream 1.2.0; verify against the upstream archive when upgrading.
