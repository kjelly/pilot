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
| `SKILL.md` | "Project runtime configuration" (orchestrator keeps the session model; role models live only in the native role definitions) and "Pilot: turn review history into a verification plan" sections |
| `platforms/{claude,codex,agy}/agents/pr-{sa,coder,reviewer}.*` | pilot lines: read the Root-supplied `pilot_history_checks`, finding ledger and target-validation plan; vm-target evidence rules; unavailable required validation keeps the PR Draft |
| `references/roles.md`, `references/workflow.md` | `pilot_history_checks` hand-off paragraphs (reference lives in `../pilot-code-review/references/pilot-history-checks.md`) |
| `references/quality-gate.md` | item 8, "Pilot target evidence (Root/Reviewer check)" |
| `scripts/install.sh`, `tests/test_installer.py`, the two `test_install_*_smoke` cases in `tests/test_pr_gate.py` | removed: the skill is repository-local, nothing installs it elsewhere |
| `README.md` | install sections replaced by the repository layout (symlinks, `.codex/agents` copies, consistency test) |
| `references/review-comments.md` (new), `SKILL.md` (step 1, step 4, quality rules, context list), `references/{roles,workflow,quality-gate,evidence-schema}.md`, `README.md` flow | review comments are claims to verify: triage into `valid`/`invalid`/`needs_evidence`/`nonblocking`, the reviewer judges disputed comments without Root's conclusion, Root replies on GitHub and records `disputed_review_comments`; a claim raised again without new evidence goes to a person |
| `scripts/pr_gate.py` (`gh_connection`, `check_disputes`, `fetch_snapshot(conversation=)`), `tests/test_pr_gate.py` (`DisputedReviewCommentTests`), `tests/test_cli_mock.py` (fake `gh` answers per GraphQL connection; dispute end-to-end case) | the gate verifies each disputed comment's reply against GitHub; conversation comments and reviews are fetched only when the evidence has disputes |
| `platforms/{claude,codex,agy}/agents/pr-{sa,coder,reviewer}.*` | review comments are claims (SA, Coder); the reviewer returns `disputed_comment_verdicts` |
| `scripts/pr_gate.py` (`cmd(empty_if=)`, `NO_REQUIRED_CHECKS`), `tests/test_pr_gate.py` (`RequiredChecksQueryTests`), `tests/test_cli_mock.py` (fake `gh` reproduces gh 2.103.3's no-required-checks exit; three end-to-end cases), `tests/test_required_checks_parity.py`, `references/quality-gate.md`, `README.md` | a branch without required checks no longer makes the gate fail on missing JSON, but only for gh's exact message: exit 1, empty stdout, stderr fullmatching `no required checks reported on the '<branch>' branch` (gh 2.103.3, case-sensitive). Valid JSON on stdout always wins, so a failing required check whose name contains that text stays a failure; any other `--required` failure still fails closed. issue-to-pr's `pr_ci.py` has the same rule and a parity test locks the two together |
| `scripts/pr_gate.py` (thread check), `tests/test_pr_gate.py` (`test_minor_thread_must_be_resolved_too`), `references/{quality-gate,evidence-schema,review-comments}.md`, `README.md` | every review thread must be resolved before Ready; the upstream `unresolved_nonblocking_threads` exemption is rejected, because `pr-review-merge` drafts any PR with an unresolved thread. The two gates' hand-off is locked by `../pr-review-merge/tests/test_pr_ready_handoff.py` |

Repository-side pieces the skill relies on: `.github/pr-evidence.json`, `make skill-test`
(wired into CI's Go test job) and the consistency test above. Files not listed here are
believed unchanged from upstream; verify against the upstream archive when upgrading.
