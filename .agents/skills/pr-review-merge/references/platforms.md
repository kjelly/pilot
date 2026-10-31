# Platforms and repository layout

This skill is repository-local to pilot; there is no global installation and no installer.
The portable Agent Skills `SKILL.md` format is shared by every platform; the native role
declarations live beside it and are wired into each tool's discovery path by the repository:

| Platform | Skill directory | Native agents | Invocation |
|---|---|---|---|
| OpenAI Codex | `.agents/skills/pr-review-merge` | `.codex/agents/prm-*.toml` (byte copies of `platforms/codex/agents/`) | `$pr-review-merge` |
| Claude Code | `.claude/skills/pr-review-merge` (symlink) | `.claude/agents/prm-*.md` (symlinks to `platforms/claude/agents/`) | `/pr-review-merge` |
| Antigravity CLI / IDE (`agy`) | `.agents/skills/pr-review-merge` | `platforms/agy/agents/` (copy into `.agents/agents/` if agy is used here, and list `/.agents/agents/` in `$(git rev-parse --git-path info/exclude)`: the checkout contract explains why) | `/pr-review-merge` |

Model pins live only in the role definitions (Codex `gpt-6.1-sol` / `high`, Claude
`claude-sonnet-5-5` / `xhigh`); the orchestrator keeps the invoking session's model.
`cmd/pilot/cmd/agent_skill_consistency_test.go` keeps the three platform copies of each
role, the `.codex/agents` copies and the `.claude` symlinks in step; `make skill-test`
runs `tests/`.

The subagent declarations are platform-specific, but business rules, review evidence
schema, GitHub action scripts and Quality Gate are shared. If platform invocation fails,
fall back to a built-in isolated review subagent with the same role instructions; if no
genuine isolated context exists, report `WAITING` rather than simulating an independent
review in one context.

Dependencies: `bash`, `python3 >= 3.10`, `gh`, `git` for repository review, and
`gh auth login`/permissions. No Python PyPI dependencies.
