# Minimal POC common execution contract

This contract applies to both `minimal-poc-update` and
`minimal-poc-revalidate`. A mode-specific Skill may make the workflow more
restrictive, but must not weaken these rules.

## 1. Required source material

Before any destructive action, read completely:

- `docs/runbooks/minimal-poc-architecture.md`
- `.agents/skills/pilot-trec-verification/SKILL.md`
- `$HOME/.agents/skills/trec-mcp/SKILL.md`
- `$HOME/.agents/skills/trec-tui-drive/SKILL.md`
- this contract;
- `.agents/workflows/minimal-poc/delegation-policy.md`.

The update mode must additionally read:

- `.agents/skills/delivery-test/SKILL.md`.

If a required file cannot be found or read, classify the workflow as BLOCKED.
Do not reconstruct missing instructions from memory.

Resolve the requirements into a numbered execution contract and checkpoint
matrix before changing VM, workspace, inventory, configuration, or service
state.

## 2. Clean-room boundary

The run must start from a new disposable environment.

Required actions:

1. Record the pre-cleanup state of every runbook VM and relevant workspace.
2. Delete each VM required by the runbook through the authorized lifecycle path.
3. Delete the entire disposable workspace.
4. Confirm that no old VM or prohibited generated state remains.
5. Create a new disposable workspace only after the cleanup check passes.

Never reuse:

- an old VM;
- `hosts.yml`;
- `inventory.yml`;
- `group_vars`;
- `.vault` content;
- an old FreeIPA identity roster;
- generated Pilot state;
- a prior run's copied configuration or evidence as an execution input.

Previous evidence may be read only for historical comparison and must never be
presented as evidence for the current run.

## 3. Tool ownership matrix

Use the following tool paths as hard ownership boundaries:

| Resource or operation | Required path |
|---|---|
| VM creation or recreation | `pilot vm-target` |
| Ordinary host and role configuration | `pilot edit` wizard |
| Inventory generation | `pilot inventory generate` |
| Every deployment, including `freeipa-identity` | `pilot deploy` wizard |
| Interactive recording | `trec mcp server` according to the TREC skills |

Forbidden:

- direct `ansible-playbook` invocation;
- manually creating or editing ordinary files owned by `pilot edit` or
  `pilot inventory generate`;
- replacing a required Pilot operation with shell scripts, templates, ad hoc
  Ansible, or a different target type;
- silently copying generated files from another workspace.

### FreeIPA roster exception

The only ordinary-generation exception is the nested `freeipa-identity` roster,
including sections such as:

- `ipa_users`;
- `ipa_groups`;
- `ipa_sudo_rules`;
- `ipa_hbac_rules`.

When required:

1. Read the actual schema from
   `playbooks/apply/freeipa-identity.roster.example.yaml`.
2. Generate a new roster using that schema.
3. Store it only at the new workspace path `.vault/ipa-identity.yaml`.
4. Do not reuse or copy an old roster.
5. Preserve a redacted structural validation result as evidence.
6. Never print secrets in transcript excerpts or reports.

### `pilot reconcile` input exception

A configuration file that is an explicit input required only by
`pilot reconcile` may be generated safely when the active mode permits it.
The exception is narrow:

- create it only inside the new disposable workspace;
- derive its schema and fields from the current command, documentation, or
  repository implementation;
- do not use it to replace files owned by `pilot edit` or
  `pilot inventory generate`;
- do not reuse a prior file;
- do not invent secrets or unknown environment-specific values;
- capture the generated path and a redacted content check as evidence.

If the exception's scope is uncertain, stop and ask the root controller to
classify it. A worker must not broaden the exception.

## 4. Wizard input policy

For every Pilot wizard:

- Accept an automatically detected `-e` value by selecting `Y`.
- Leave the manually entered additional `-e` field empty.
- Never infer, invent, or autofill a manually supplied value.
- If any other prompt requires a human-authored value, stop the entire
  workflow immediately.

When stopping for manual input, report:

- checkpoint ID;
- exact prompt text;
- transcript path and relevant location;
- persisted state at the time of stopping;
- expected source or owner of the missing value.

Do not exit the wizard and continue through an alternative path.

## 5. TREC recording and persisted-state verification

Every interactive wizard process must have its own TREC recording.

For each wizard invocation:

1. Start recording before launching the wizard.
2. Capture the complete key sequence, focus movement, output, and process exit.
3. Save the transcript under the current run's evidence directory.
4. After every wizard save action, inspect the actual persisted file.
5. Compare persisted values against the checkpoint's expected values.
6. Continue only when the persisted-state check passes.

A successful UI message or zero process exit status is not sufficient evidence
when the workflow requires persisted configuration or behavioral proof.

Use targeted `grep`, structured parsers, or bounded file reads. Do not print
entire secret-bearing files into the main agent context.

## 6. Long-running operations

Deployment may be long-running. Do not infer failure from elapsed time alone.
Use process state, command status, logs, service state, and the applicable
Skill timeout policy as evidence.

Do not restart a long-running, destructive, or non-idempotent operation merely
because output is temporarily quiet.

## 7. Suspected bug protocol

A suspected bug is not confirmed until all of the following are checked:

1. The TREC transcript confirms the actual key sequence, focus target, and
   timing.
2. The actual persisted files are inspected.
3. Relevant implementation code and comments are read.
4. Documented intended behavior is checked.
5. Reproduction changes exactly one variable at a time.

Do not modify implementation while investigating. Distinguish:

- user input error;
- environment or permission blocker;
- intentional design;
- runbook defect;
- implementation defect;
- insufficient evidence.

## 8. Serialization and state ownership

Only one state-changing child agent may operate at a time.

Never run these concurrently:

- VM deletion or creation;
- workspace deletion or initialization;
- `pilot vm-target`;
- `pilot edit`;
- inventory generation;
- deployment;
- FreeIPA mutation;
- NFS configuration;
- reconcile mutation;
- idempotency reruns;
- teardown.

Read-only evidence checks may overlap only when their input artifacts are
complete, immutable, and independent. Sequential execution is the default.

## 9. Checkpoint result contract

Every state-changing checkpoint must return:

1. checkpoint ID;
2. requirement being tested;
3. commands actually executed;
4. exit status for each command;
5. concise relevant stdout or stderr excerpts;
6. resources created, modified, or deleted;
7. transcript and evidence paths;
8. expected result;
9. observed result;
10. `PASS`, `FAIL`, or `BLOCKED`.

Complete logs belong in evidence files. Return only focused excerpts to the root
controller.

## 10. Verdict definitions

- `PASS`: the requirement was executed from the new clean-room environment and
  has complete, consistent evidence.
- `FAIL`: the runbook requirement or product behavior does not meet the stated
  acceptance condition.
- `BLOCKED`: environment, permission, dependency, missing human input, or a
  mandatory unavailable tool prevents completion.

Missing evidence is never PASS. A worker's result is provisional until the root
controller reviews it.
