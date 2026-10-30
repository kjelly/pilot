# issue-to-pr — Cross-platform GitHub Issue → PR Skill (Draft first, Ready only when mergeable)

Use the same [Agent Skills](https://agentskills.io/) workflow with **Codex CLI**, **Claude Code**, and **Antigravity CLI (`agy`) / App / IDE**. By default, fixes each specified Issue in an isolated branch/worktree and opens **one PR per Issue** after independent review and local checks. The PR is a **Draft** until everything is done and CI is green on its exact HEAD; only then is it marked **Ready for Review** (meaning: quality is already mergeable, nothing left to do). **Does not auto-merge**.

## Requirements

- Bash on Linux/macOS/WSL, `python3` **3.10+**, `git`, GitHub CLI `gh` (`gh auth login`).
- GitHub repository write permission and ability to push dedicated branches.
- Native subagent feature must be available/enabled for true independent SA, Coder, Reviewer roles; the repository layout does not enable unsupported features.
- For automated PR creation, `origin` must point to the **same GitHub `OWNER/REPO`** being targeted. The deterministic helper intentionally rejects fork-only remotes; adapt manually for forks after reviewing the trust boundary.

## Repository-local layout (no installer)

This skill is repository-local to pilot; nothing installs it elsewhere. The canonical copy is `.agents/skills/issue-to-pr/` (Codex and agy read it directly). Claude Code reads the same files through the `.claude/skills/issue-to-pr` and `.claude/agents/issue-*.md` symlinks; Codex reads the role definitions as byte copies in `.codex/agents/issue-*.toml`. `cmd/pilot/cmd/agent_skill_consistency_test.go` keeps the three platform copies of each role, the `.codex/agents` copies and the `.claude` symlinks in step, and `make skill-test` runs `tests/`. Model pins live only in the role definitions; the orchestrator keeps the invoking session's model.

| Platform | Skill | Native subagents |
| --- | --- | --- |
| Codex | `.agents/skills/issue-to-pr` | `.codex/agents/issue-{sa,coder,reviewer}.toml` (copies) |
| Claude Code | `.claude/skills/issue-to-pr` (symlink) | `.claude/agents/issue-{sa,coder,reviewer}.md` (symlinks) |
| agy CLI / App / IDE | `.agents/skills/issue-to-pr` | `platforms/agy/agents/` (copy into `.agents/agents/` if agy is used here) |

## Invoke

```text
# Codex CLI
$issue-to-pr 修正 OWNER/REPO#43，完成驗證後建立 PR（草稿；全部做完且 CI 全綠才轉 Ready）
$issue-to-pr 處理 https://github.com/OWNER/REPO/issues/123 和 #124

# Claude Code and agy CLI
/issue-to-pr 修正 OWNER/REPO#123 #124，每個 Issue 各建一個 PR（草稿 → 全部完成才 Ready）
```

For multiple repos, supply full URLs or qualified `OWNER/REPO#N` IDs. **An empty `Issues:` list is not treated as permission to process all open Issues.**

## Execution protocol

1. SA independently analyzes root cause, acceptance criteria, dependencies and impacted areas, and checks each claim in the Issue (symptom, stated cause, proposed fix, stated acceptance criteria): Issue claims are hypotheses, not a specification. A claim that does not hold is not implemented: after the independent reviewer agrees without seeing SA's conclusion, Root answers it on the Issue with evidence and records it in `disputed_issue_claims` (see `references/issue-claims.md`). Root coordinates a DAG and **at most two simultaneous source-writing Issue streams**; avoid shared-resource conflicts.
2. Each Issue gets an isolated Git worktree and dedicated branch. Coder fixes real root cause, adds regression tests and commits.
3. `repo_evidence.py` loads the repository's `.github/pr-evidence.json` from the base branch (evidence-only paths and mandated evidence such as a live run); the gate then accepts receipts across an evidence-only commit and requires `repo_required_evidence`. See `references/repo-evidence.md`.
4. `claim.py` takes a per-Issue claim before any work so a second session or clone cannot start the same Issue; `run_check.py` records clean-HEAD, SHA-bound test/lint/static-check receipts in a state folder *outside the worktree*.
5. Fresh independent `issue-reviewer` reviews the committed HEAD. P0–P2 findings require changes and repeat verification.
6. `issue_gate.py` enforces the local pre-PR gate and duplicate-PR lookup; with disputed claims it also reads the Issue's comments to confirm each one was answered. `create_pr.py` repeats the gate, pushes to the verified remote, verifies remote SHA, and opens a **Draft PR by default**, closing the Issue (`Fixes #N`) only when `issue_resolution` is `fixes`; a `partial` resolution uses `Refs #N`.
7. `pr_ci.py` inspects GitHub checks of the Draft PR for the exact head SHA. Pending CI does not mean success. A branch without required checks (`gh pr checks --required` exits 1 with nothing on stdout and exactly `no required checks reported on the '<branch>' branch` on stderr) counts as zero required checks; valid JSON on stdout is always read, and any other failure is `CI_UNKNOWN`. If CI fails, repair on the same branch, repeat test/review, push and re-check CI; never open a second PR. Finish every other follow-up (final independent review of the whole head diff, accurate PR body, evidence/doc follow-ups) while it is still a Draft. Keep the Issue claim (`claim.py renew`) the whole time.
   `mark_ready.py` converts Draft → Ready **only** when the PR is an open Draft of the validated branch at the validated HEAD, the pre-PR gate still passes, CI is `CI_PASSED` on that HEAD, there are no merge conflicts, and `--confirm-complete` attests that nothing else is left. **Ready means merge-quality; a PR with anything outstanding stays Draft.**
8. An Issue whose claims are all refuted is reported `INVALID`, and one that needs the reporter's evidence or a person's decision `NEEDS_DECISION`; both get a reply on the Issue and no PR, and the Issue is left open for a person. If blocked before PR creation, no PR is created. If CI or review is unresolved, the PR stays Draft and is reported `DRAFT_CI_BLOCKED` / `DRAFT_PENDING` with evidence. No auto-merge, no branch-protection bypass.

## Quality helper CLI

The agent should choose *real* repo-specific commands, never invent them. Example below is illustrative for a Go repository:

```bash
STATE="$HOME/.cache/issue-to-pr/OWNER/REPO/123"
WT="/path/to/issue-123-worktree"
mkdir -p "$STATE"

# run after git commit and verify git status is clean:
python3 scripts/run_check.py --worktree "$WT" --name regression \
  --out "$STATE/regression.json" -- go test ./...
python3 scripts/run_check.py --worktree "$WT" --name lint \
  --out "$STATE/lint.json" -- golangci-lint run

# Root Agent collects test receipts + Reviewer evidence into $STATE/evidence.json
python3 scripts/issue_gate.py --repo OWNER/REPO --issue 123 \
  --worktree "$WT" --evidence "$STATE/evidence.json"

# After gate passes: create the PR as a DRAFT (the default)
python3 scripts/create_pr.py --repo OWNER/REPO --issue 123 \
  --worktree "$WT" --evidence "$STATE/evidence.json" \
  --title "fix: correct issue 123 root cause" --body-file "$STATE/pr_body.md"

# After PR creation; use the returned PR number and current SHA:
python3 scripts/pr_ci.py --repo OWNER/REPO --pr 99 --head-sha FULL_SHA --watch --timeout 900

# Only when CI is green on that SHA and ALL other follow-up work is finished:
python3 scripts/mark_ready.py --repo OWNER/REPO --issue 123 --pr 99 \
  --worktree "$WT" --evidence "$STATE/evidence.json" --confirm-complete
```

If the user **explicitly** asks for a Ready PR from the start, `create_pr.py --ready` is available; it is never used by default. The `create_pr.py` helper protects its own side effects, but is not a fully automatic coding engine; it is invoked by a native agent after genuinely completing code changes and review.

Evidence JSON and Check schema: [references/evidence-contract.md](references/evidence-contract.md). Full orchestration: [references/workflow.md](references/workflow.md). Quality gates: [references/quality-gate.md](references/quality-gate.md).

## Self-tests and current limits

```bash
python3 -m unittest discover -s tests -v
python3 -m py_compile scripts/*.py
```

Tests use local temporary Git repositories and mock GitHub CLI responses. They do **not** verify your real GitHub credentials, CLI version, repository-specific tests, provider sandbox policy, or live PR creation. The gate mechanically checks evidence **shape and commit binding**, not whether a language model's semantic claims are true. Subagents and the Root must be genuinely independent and inspect evidence, not simply fill in JSON fields.

## References

- [Codex skills](https://learn.chatgpt.com/docs/build-skills), [Codex subagents](https://learn.chatgpt.com/docs/agent-configuration/subagents)
- [Claude Code skills](https://code.claude.com/docs/en/skills), [Claude Code subagents](https://code.claude.com/docs/en/sub-agents)
- [Antigravity skills](https://antigravity.google/docs/skills), [Antigravity subagents](https://antigravity.google/docs/subagents)
- [GitHub CLI](https://cli.github.com/manual/)

## License

Apache License 2.0. See [LICENSE](LICENSE).
