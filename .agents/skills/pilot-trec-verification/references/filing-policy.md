# Where trec-driver findings belong

> Reference for the `pilot-trec-verification` skill.
> Read when you have a finding to file and need to decide whether it is a
> trec-driver issue, a pilot bug, a playbook bug, or a spec bug.

---

This skill and its sibling tool-driver skills
(`~/.agents/skills/trec-mcp/SKILL.md`,
`~/.agents/skills/trec-tui-drive/SKILL.md`) are the canonical home for any issue found
while driving an interactive wizard via `trec`. AGENTS.md v1.15 codifies the rule:
**trec-related issues never go in operational runbooks.**

## Counts as trec-related — file it here

- `EXPECT` / `SELECT` / `TOGGLE` / `CHOOSE` / `CHECKLIST_DOWN` / `DOWN` opcodes
  misbehaving on a particular screen (cursor reset, label ambiguity, off-by-one).
- Bubble Tea / promptui text-input pre-fill surprising a script (cursor at start
  rather than end; pre-fill eating the typed character).
- MCP-vs-CLI recording fallbacks diverging (`trec mcp` healthy at the CLI level but
  no callable tools; an agent loop able to hold a PTY but unable to deliver a real
  carriage-return byte through the MCP text channel).
- `PILOT_DEBUG_MENU=1` interacting badly with `SELECT` (its stderr dump line
  confuses the direction heuristic).
- `EXPECT_QUIET` misused as a child-exit signal — it's a quiet-output check, not a
  child-process completion test.
- A component's prompt chain turning out to need the `vars 檔路徑` slot rather than
  the `extra -e` slot, or vice versa.
- Host-key churn during `ssh` recording — one `ssh` call hung 70 minutes on an
  unanswerable interactive host-key prompt; add
  `-o StrictHostKeyChecking=accept-new` to every raw `ssh` call.
- The `BACKSPACE <n>`-then-`TEXT` pre-fill rule (the field's cursor doesn't always
  start at the end).
- The `vault`/`main.yaml` auto-detect + `否`/`需要` second-stage menu path for
  non-default vault files.

## Does NOT count — file it at the source, classified as **bug**

| Kind of defect | Where it goes |
|---|---|
| Bug in `pilot` itself (Go source) | `cmd/pilot/cmd/...` / `internal/...`, with its own regression test |
| Bug in a playbook (Ansible/YAML) | `playbooks/apply/*.yml` |
| Bug in a spec row (e.g. the v6.0 / v18.0 Real bugs about row-dedup collapse) | the relevant spec file + `pilot spec --lint` |
| Bug in a group's topology / group_vars wiring | the group_vars / inventory editor |

When a `trec` session uncovers something that turns out to be a bug in `pilot`, a
playbook, or a spec, file it in the right place **but classify the entry as bug,
not as trec-driver finding**. The `trec` session is the *how you found it*, not the
*what you found*.

## Runbooks document the run, not the driver

Operational runbooks (`docs/runbooks/*.md`) may include the
`trec drive --script` command that was used, the `Y` keys that were pressed, and
the real output that resulted — but **not** the driver issues encountered. Those
go here.
