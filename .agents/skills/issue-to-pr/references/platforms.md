# Platform portability

The shared `SKILL.md` follows the Agent Skills YAML frontmatter contract; the same workflow instructions serve all three platforms, with native role definitions adapted to each agent host. This skill is repository-local to pilot: there is no installer and no personal installation. Models are pinned only inside the native role definitions (Codex roles `gpt-6.1-sol` / `high`, Claude SA `claude-opus-5-5` / `xhigh`, other Claude roles `claude-sonnet-5-5` / `xhigh`); the orchestrator keeps the invoking session's model, and `cmd/pilot/cmd/agent_skill_consistency_test.go` keeps the platform copies, the `.codex/agents` copies and the `.claude` symlinks identical.

| Platform | Skill directory | Role definitions |
| --- | --- | --- |
| Codex CLI | `.agents/skills/issue-to-pr` | `.codex/agents/issue-*.toml` (byte copies of `platforms/codex/agents/`) |
| Claude Code | `.claude/skills/issue-to-pr` (symlink) | `.claude/agents/issue-*.md` (symlinks to `platforms/claude/agents/`) |
| Antigravity CLI / App / IDE (`agy`) | `.agents/skills/issue-to-pr` | `platforms/agy/agents/` (copy into `.agents/agents/` if agy is used here) |

Call syntax: Codex `$issue-to-pr ...`; Claude Code `/issue-to-pr ...`; agy `/issue-to-pr ...`.

Subagent dispatch is a **host feature**. This skill tells the Root how to delegate but cannot enable disabled subagent capabilities, override permissions, force a fixed amount of true parallelism, or install the CLIs. If no native subagent machinery is available, **do not pretend an independent review happened**; stop before the gate or use an actually independent review process and document its evidence.

Root passes an absolute `pilot_history_checks` reference path, applicable past
fix/review links, finding ledger and target-validation plan to native roles.
The reference lives in the project `pilot-code-review` skill; do not assume a child worktree
contains it: pass the absolute path. SA proposes the plan,
Coder/Root executes authorized target tests, and Reviewer evaluates actual
artifacts and any missing evidence before PASS.

Recommended subagent roles:

- `issue-sa`: independent analysis (no source writes).
- `issue-coder`: one Issue, one worktree, implementation + tests (writes allowed only in designated worktree).
- `issue-reviewer`: independent reviewer in clean context (no source writes).

Unlike Codex/Claude, agy uses vendor-specific allowed tool names. The included agy definitions declare only supported documented tools. Do not specify a `tools:` list unless the installed host supports those exact tool IDs. Verify on your installed version if subagent invocation fails.

## References

- Codex skills: https://learn.chatgpt.com/docs/build-skills
- Codex subagents: https://learn.chatgpt.com/docs/agent-configuration/subagents
- Claude skills: https://code.claude.com/docs/en/skills
- Claude subagents: https://code.claude.com/docs/en/sub-agents
- Antigravity skills: https://www.antigravity.google/docs/skills
- Antigravity custom subagents: https://www.antigravity.google/docs/subagents
