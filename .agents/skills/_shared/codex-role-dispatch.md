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
4. Before using `default`, verify its effective selection from the live host
   catalog and active configuration. A custom agent named `default` shadows the
   built-in, and its model/effort settings override explicit spawn values. Inspect
   the applicable personal/project role definitions by their `name` field (any
   filename), plus active configuration/profile/override sources; absence of a
   `default.toml` file alone is insufficient. Record host/version, catalog evidence
   and configuration provenance (paths/hashes or confirmed absence), including how
   they establish the host's loaded selection rather than merely files on disk.
   Proceed only if the selected transport is the built-in and the host honors the
   explicit pins below, or authoritative host evidence establishes that the
   selected custom transport enforces the exact required pins, role contract and
   runtime capabilities/restrictions. Unknown selection, conflicting instructions,
   overridden pins or unenforceable capabilities are BLOCKED; do not edit personal
   configuration to make this gate pass.
5. Announce the failed native dispatch and the compatibility transport. Spawn
   `agent_type="default"`, `fork_turns="none"`, with `model` and `reasoning_effort`
   set explicitly to the snapshot role's `model` and `model_reasoning_effort`.
   This is the authorized exception to the native-dispatch no-override rule;
   the preceding effective-selection check must establish that these pins apply.
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
   when used for review. Requested arguments, a successful spawn, the task envelope
   and child self-report do not prove effective model identity. If host evidence
   cannot establish the required effective settings, report BLOCKED rather than
   recording requested pins as effective. A successful spawn is not a completed
   analysis/review: inspect the child's result and require the usual SHA-bound
   evidence. If default dispatch, pinned model or a genuine independent context
   is unavailable, stop as BLOCKED/WAITING; never substitute another model or
   simulate the review in Root.

Negative control: with a personal role file (even `custom.toml`) declaring
`name = "default"`, `model = "gpt-6-luna"`, `model_reasoning_effort = "low"` and
valid description/instructions, an unavailable native role followed by explicit
`gpt-6.1-sol` / `high` spawn arguments must be BLOCKED before compatibility
dispatch. The custom file wins despite those arguments. A verified built-in
`default` that honors both explicit arguments remains eligible. Evaluate this
scenario from configuration/host evidence without installing it in user config.

`verify-role` proves file integrity, not runtime availability. A listed role and
a byte-identical file can still be rejected by the host. Do not install roles,
edit personal configuration or restart the user's session as an automatic repair.
The current documented standalone `.codex/agents/*.toml` format is supported;
missing `[agents.<name>]` entries alone do not establish a configuration defect.
See [official subagent documentation](https://learn.chatgpt.com/docs/agent-configuration/subagents).
