# Phase 2 — FreeIPA host access policy projection: vm-target evidence (2026-09-23)

Scope: `docs/superpowers/specs/2026-09-23-pilot-access-gateway-per-host-session-recording-spec.md`
§7/§8 (Phase 2). The new `playbooks/apply/tasks/freeipa-host-access-policy.yml`
is included from `freeipa-client-apply.yml` and projects `pilot_ssh_recording`
onto the FreeIPA userClass value `pilot.policy.ssh-recording=<mode>`. The same
change fixes the annotations include's missing `apply: tags`.

## Tested revision

- Candidate commit `cf09cbb`, tree `f213a3274e7ab65cd09d5e6afd647dc0800bf707`.
- These were development runs from the working tree, not a clean isolated
  checkout. The formal clean-checkout candidate test is Phase 8 (spec §35).
  None of the execution-affecting files changed between the runs and the
  commit. Their committed blobs:

| File | Blob |
|---|---|
| `playbooks/apply/freeipa-client-apply.yml` | `f6984758967e1228a3a40a8b6671aa029157c4ee` |
| `playbooks/apply/tasks/freeipa-host-access-policy.yml` | `01f5c1ee0a62ce2858ed7d700e52edf5f015e3d5` |
| `playbooks/apply/tasks/freeipa-host-annotations.yml` | `0700439e7c6b63959ad94665bcd02070fadd6cba` (unchanged) |

## Target

This is the Phase 0 topology (see `2026-09-23-phase0-userclass-capture.md`).
The FreeIPA server is `phr-ipa` (AlmaLinux 9, `ipa-server-4.13.1-3.el9_8.2`).
The clients are `phr-gw`, `phr-ta`, `phr-tb` and `phr-store` (Ubuntu 24.04).
Each run used a grouped inventory: `freeipa-server=phr-ipa` and
`freeipa-client=<host>`, applied with `pilot vm-target run --sandbox`
(`pilot-cli:latest`). The vault was a disposable test file; no real vault was
used.

## Results

In the userClass column, "unchanged" means a read-back with
`ipa host-show --all --raw` matched the state before the run.

| # | Scenario | Result | userClass afterwards |
|---|---|---|---|
| fresh | `--check --diff` on a never-enrolled host (`phr-tb`) | `ok=75 failed=0`; access policy shows `BLOCKED (not yet enrolled)`, no kinit, no mutation | — |
| enroll | real `freeipa-client-apply.yml` on all 4 clients, no `pilot_ssh_recording` | each host `ok=161 changed=17 failed=0`; plan `NOOP` (inherit); `command`+`stdin` kinit works | none |
| L2 | `--tags host-access-policy -e pilot_ssh_recording=terminal_output` | `changed=1`, `ADD ['pilot.policy.ssh-recording=terminal_output']` | `[=terminal_output]` |
| L17a | same, again (tag-scoped) | `changed=0`, `NOOP: True` | unchanged |
| L6 | `-e pilot_ssh_recording=off` | `changed=2`, `DELETE [=terminal_output]` then `ADD [=off]` | `[=off]` |
| L11 | add foreign `external-provisioning` and `pilot.annotation.owner=qa`, then `terminal_output` | `changed=2`; post-write gates pass | foreign and annotation both kept |
| L7 | no `pilot_ssh_recording` (inherit) | `changed=1`, `DELETE [=terminal_output]` | foreign values only |
| L9 | two managed values (`=off`, `=terminal_output`) | `failed=1 changed=0`, `CONFLICT_DUPLICATE_SSH_RECORDING_POLICY` | unchanged |
| L10 | only `Pilot.Policy.SSH-Recording=terminal_output` | `failed=1 changed=0`, `CONFLICT_MALFORMED_SSH_RECORDING_POLICY` | unchanged |
| L16 (reconcile half) | live `pilot.policy.ssh-recording=terminal_io` | `failed=1 changed=0`, `CONFLICT_UNKNOWN_SSH_RECORDING_POLICY` | unchanged |
| bool | `-e '{"pilot_ssh_recording": false}'` | `failed=1` at Phase A, before any FreeIPA read | unchanged |
| check | enrolled host, `--check --diff` with a pending ADD | `changed=0`; plan prints `ADD` | unchanged |
| L17b | full, untagged `freeipa-client-apply.yml` twice with `terminal_output` | run 1 `ok=156 changed=2 failed=0` (annotations reconciler prunes the test annotation; policy ADD); run 2 `ok=145 changed=0 failed=0` | `[external-provisioning, =terminal_output]` |

Every tag-scoped run executed the included task file's tasks, so
`apply: tags` works in practice. Before this fix,
`--tags host-annotations` skipped every task inside the include.

The connect-deny halves of L9 and L10 depend on the gateway (Phase 5) and are
checked in Phase 8.

## Static checks

For candidate `cf09cbb`:

- `ansible-lint playbooks/apply/tasks/freeipa-host-access-policy.yml` passed
  under the `production` profile with 0 failures.
- `make playbook-lint` exit 0.
- `python3 scripts/check-yaml-duplicate-keys.py` (212 files) passed.
- These tests are green: `go test -race ./internal/spec/ ./internal/contract/...`,
  `TestSpecPlaybookTagAlignment` and
  `TestRegression_AlwaysTaggedTasksHaveAllPrerequisitesAlways`.
- `pilot spec docs/verification/freeipa-client.md --lint`: 0 errors.
- `pilot contract lint`: 39 components.

## State left behind

Raw run outputs stay in the gitignored `.verification/phase2/`. The topology
stays up for later phases. The target hosts are left as follows:

- `phr-tb` keeps `external-provisioning` and
  `pilot.policy.ssh-recording=terminal_output`. It is the recorded
  "Target B".
- `phr-ta` has no userClass values. It is the default "Target A".
