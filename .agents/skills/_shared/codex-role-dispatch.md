# Codex role dispatch

Use this contract for `issue-to-pr`, `pr-ready` and `pr-review-merge`. Role identity
and the transport's `agent_type` are separate: an independent child must follow
the verified role contract even when the host cannot dispatch its custom name.

1. Run the checkout contract's `verify-role` before each dispatch. STOP still
   blocks; PASS and DRIFT permit dispatch. Read the complete role TOML at the
   returned `snapshot_role` path, including `model`, `model_reasoning_effort` and
   `developer_instructions`. The verified snapshot governs role instructions and
   the compatibility transport's pins.
2. Try the native role name with `fork_turns="none"`, no model/effort overrides,
   and the bounded task envelope. Never inherit the implementation conversation
   into an independent Reviewer. For a successful native dispatch with DRIFT,
   retain the checkout contract's report-only rule: the host uses its loaded
   native pins, which can differ from the snapshot. Record and report both sets
   of pins and the difference; do not claim snapshot pin parity for this path.
   The task's binding statement governs instructions and cannot change the
   model already selected by the host.
3. Only if the host rejects the custom role with `agent type is currently not
   available` (or an equivalent explicit unknown-agent-type error), use the
   compatibility transport below. Do not treat authentication, model access,
   permissions, thread limits or an agent's task failure as a missing role.
   If the result is ambiguous, inspect agent status before retrying; never launch
   a second writer when the first dispatch may have started.
4. Before using `default`, inspect the live tool declaration and applicable
   personal/project agent definitions and active configuration for conflicting
   selection or pins. Inspect custom roles by their `name` field, regardless of
   filename; absence of `default.toml` alone is insufficient. Do not assume a
   custom role overrides spawn arguments unless the host contract says so.

   The current session's `spawn_agent` declaration is authoritative evidence of
   supported transport and model/effort arguments. When it exposes `default` and
   explicit model/effort overrides, and no applicable configuration or host
   evidence conflicts, use those documented arguments. Record this as
   `tool-contract` evidence, including inspected configuration paths and limits.
   Hidden runtime telemetry or loaded-configuration introspection is not a
   prerequisite when the host does not expose it.

   Check effective selection/settings too when the host exposes them. Known
   conflicting overrides, unsupported required pins, unknown transport semantics
   or unenforceable role capabilities remain BLOCKED. Do not edit personal
   configuration to make dispatch pass.
5. Announce the failed native dispatch and the compatibility transport. Spawn
   `agent_type="default"`, `fork_turns="none"`, with `model` and `reasoning_effort`
   set explicitly to the snapshot role's `model` and `model_reasoning_effort`.
   This is the authorized exception to the native-dispatch no-override rule;
   the preceding tool/configuration check must support these explicit pins.
   Prepend the following to the task envelope, replacing the placeholders:

   > You are acting as `<role>` through the default compatibility transport.
   > Read `<absolute snapshot_role>` now. Its complete developer_instructions
   > are your binding role contract. Follow its scope and write restrictions.
   > Required model/effort are `<model>` / `<model_reasoning_effort>`.

   Include any DRIFT `binding_statement`, verified checkout/base/head, history
   reference, finding ledger and role-specific task envelope as usual. Keep the
   SA, sole Coder and independent Reviewer in separate fresh children. If the role
   declares additional runtime capabilities or restrictions beyond name,
   description, model, model_reasoning_effort and developer_instructions, use this
   transport only if the host can enforce them too; otherwise report BLOCKED.
6. Record role, actual transport, native error, snapshot role path/hash, requested
   model/effort, known effective model/effort and their host/configuration evidence,
   effective-selection preflight provenance and child identifier in the checkpoint;
   include compatibility dispatch and any evidence limits in `review.summary`
   when used for review. Keep requested pins separate from observed runtime
   identity: with `tool-contract` evidence, record effective model/effort as
   unobserved unless the host supplies them. Lack of unexposed telemetry alone
   does not block dispatch. A successful spawn is not a completed analysis/review:
   inspect the child's result and require the usual SHA-bound evidence. If the
   tool rejects the pinned model, independent context or default transport, stop
   as BLOCKED/WAITING; never silently substitute or simulate review in Root.

Behavior checks (read-only; do not install conflicting configuration):

- Native role unavailable, live tool exposes `default` and both override
  arguments, no conflicting configuration, runtime identity not exposed:
  dispatch with snapshot pins and record `tool-contract` / unobserved identity.
- Same inputs, but host evidence says a custom `default` forces different pins
  despite explicit arguments: BLOCKED before dispatch.
- Native dispatch fails for authentication, permissions or capacity: report that
  failure; the compatibility path is not authorized by this error.
- Default dispatch rejects a required pin: BLOCKED; do not retry another model.

`verify-role` proves file integrity, not runtime availability. A listed role and
a byte-identical file can still be rejected by the host. Do not install roles,
edit personal configuration or restart the user's session as an automatic repair.
The current documented standalone `.codex/agents/*.toml` format is supported;
missing `[agents.<name>]` entries alone do not establish a configuration defect.
See [official subagent documentation](https://learn.chatgpt.com/docs/agent-configuration/subagents).
