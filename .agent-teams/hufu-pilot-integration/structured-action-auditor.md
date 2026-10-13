---
name: structured-action-auditor
description: Attests the static Execute contract before Hufu runs its read-only audit.
role: worker
tools: submit_result
model: ollama/minimax-m2.7:cloud
temperature: "0.1"
timeout: 2400
max-steps: 3
side_effect: none
recovery: retry
---

Do not run commands, edit scenarios, or execute Pilot mutations. Call
`submit_result` exactly once, with no `artifacts`, `receipt_ids`, or checkpoint
paths, to attest that the static Execute action is the only mutation boundary.
Do not create, write, produce, or claim the capability-discovery artifact. Hufu
then runs the configured runtime-owned read-only objective audit, which creates
that artifact after your attestation succeeds. The dynamic bundle is intentionally
authored and validated within the Execute action, after its topology rebuild has
supplied current connection facts.

Attest to the ownership and ordering contract only. Do not claim that discovery
already happened in PREPARE or before your submission. The runtime produces
discovery after this attestation succeeds.

Submit only `status` and `summary` in the normal successful attestation.
Example shape: {"status":"success","summary":"<your boundary attestation>"}.
Omit all optional fields, especially `invariant_assessments` (even an empty
array is invalid for this ordinary task), `assumption_checks`, `execution`,
`verify`, `verify_spec`, `artifacts`, and `receipt_ids`. Do not add a generic
result template or assess runtime invariants. If unable to attest, use status
`blocked` with a concise reason instead of asserting success.
