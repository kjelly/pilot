# Codex retained terminal permissions

Apply the self-contained inline startup rule in `issue-to-pr`, `pr-ready` and
`pr-review-merge` before the first shell/process execution. Read this detailed
contract through a non-process reader when available, or in the approved
recorded terminal before path discovery, auth checks, snapshot helpers and the
single-item checkout contract. File reading that needs a process must not create
a circular prerequisite to establishing that terminal. Child role dispatch is
later and follows `.agents/skills/_shared/codex-role-dispatch.md`. A permission
failure is not an unavailable-agent-type error.

## Establish the retained audited terminal

1. Inspect the current session grants and the live process tool declaration
   from the available host context before launching a shell. These workflows
   need GitHub network access for
   `git fetch` and `gh`, and writes to the actual Git metadata directory for
   fetch/checkout, branch tracking and safe restoration. A read-only PR review
   still fetches and checks out locally. GitHub mutation authorization is a
   separate workflow gate. Existing grants that cover the required operations
   are sufficient: start or reuse the retained audited terminal without a
   redundant approval request.
2. If those permissions are absent, request the normal permission grant at
   startup of the retained terminal, before its first process runs. Use the
   host's supported escalation/approval mechanism, such as
   `sandbox_permissions="require_escalated"` with a justification when the live
   process tool exposes it. Explain that this one retained audited shell needs
   GitHub network access and the required `.git` writes for the selected item.
   Keep the request limited to that workflow and checkout. A grant to launch
   the shell does not authorize unrelated commands or GitHub state changes.
3. Start the retained shell under the required terminal recorder in that
   approved process invocation. Keep subsequent `git`, `gh`, helpers and tests
   in the same recorded shell. Preserve the recorder's normal redaction,
   completion and verification rules. Do not perform bootstrap commands in an
   unrecorded shell or move later commands to an unapproved replacement process.

Permission APIs and approval choices vary by host. Use only exposed capabilities.
This contract does not promise that a process tool supports escalation, that a
request will be granted, or that approval changes an already-running process.
Never disable the sandbox, change personal configuration, or bypass branch
protections to obtain access.

## A rejected grant or an insufficient running session

- A rejected or unavailable required grant stops the workflow. Record the
  permission blocker and preserve the existing outcome protocol: `issue-to-pr`
  reports `BLOCKED`, `pr-ready` reports `DRAFT-BLOCKED`, and `pr-review-merge`
  reports `WAITING` with its existing `wait_kind` and handoff rules. Do not invent
  a universal status or send `WAITING` to the draft-phase task-result writer.
  Use the workflow's existing checkpoint/handoff path when available. If it cannot be written under the available permissions,
  report that limitation and the next action. Do not blindly retry, switch to a
  different tool to evade the denial, or claim the checkout or workflow completed.
- If a retained terminal already exists, check its grants before running the
  workflow. When they are insufficient, stop sending workflow commands. Do not
  assume a later approval upgrades that live process. Preserve its audit and
  any work, finish/close it safely under the recorder's rules, and request a
  properly authorized recorded terminal only through the normal approval path.
  If safe replacement or the necessary grant is unavailable, stop with that
  workflow-specific blocked outcome.
  Disclose any interrupted or incomplete recording. Never claim an intact audit
  for a lost session. After an approved replacement, revalidate checkout identity
  and remote facts before resuming the single-item checkout contract.
- Preserve all deterministic gates, single-writer ownership, secret scanning,
  safe checkout/restoration, independent review and GitHub action authorization.
  Terminal permission approval does not relax any of them.
