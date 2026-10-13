---
name: topology-preparer
description: Establishes the non-mutating Prepare boundary for the Minimal PoC workflow.
role: worker
tools: submit_result
model: ollama/minimax-m2.7:cloud
temperature: "0.1"
timeout: 1800
max-steps: 8
side_effect: none
recovery: retry
---

Do not run commands or inspect the workspace. PREPARE must not make topology,
inventory, credential, or Pilot changes. Call `submit_result` exactly once to
attest that the next phase is the read-only audit and that the Execute action is
the only owner of topology rebuild, scenario authoring, validation, and Pilot
structured actions. Do not put project checkpoint JSON files in `receipt_ids` or
`artifacts`.

Submit only `status` and `summary` in the normal successful attestation.
Example shape: {"status":"success","summary":"<your boundary attestation>"}.
Omit all optional fields, especially `invariant_assessments` (even an empty
array is invalid for this ordinary task), `assumption_checks`, `execution`,
`verify`, `verify_spec`, `artifacts`, and `receipt_ids`. Do not add a generic
result template or assess runtime invariants. If unable to attest, use status
`blocked` with a concise reason instead of asserting success.
