# spec-promotion-checklist.md -- DRAFT -> v1.0 for any spec

AGENTS.md §1.1 and §3 require that any spec promoted out of DRAFT
state must be backed by a real actual-run. This file is the
concrete checklist for promoting **any** `docs/verification/<spec>.md`
out of DRAFT.

## A. The run itself

- [ ] A runbook exists under `docs/runbooks/<spec>.md` (or a sibling
      runbook for the role) that opens with a one-line goal, includes
      the §0.5 fact snapshot, and every shell block in §3+ has a real
      PLAY RECAP / check output excerpt captured from a vm-target or
      real-host run.
- [ ] The runbook reaches the end with `pilot verify
      docs/verification/<spec>.md -i <inventory>` returning the
      expected PASS row count (or the spec's known-deviations section
      properly applied).
- [ ] If multi-VM, the cross-check (e.g. `getent passwd`, `curl`,
      `sudo -l`) returns the real round-trip result, captured in the
      runbook.

## B. Lint and syntax gates (AGENTS.md §3)

- [ ] `go run ./cmd/pilot spec docs/verification/<spec>.md --lint`
      exits 0 with zero errors.
- [ ] `go test -count=1 -run TestShellSyntax ./internal/spec/`
      passes. (The shell syntax test scans every fenced bash block
      in every spec for `bash -n`-style parse errors.)

## C. Regression test (AGENTS.md §3)

- [ ] `internal/spec/<feature>_regression_test.go` exists and locks,
      at minimum:
      - row IDs are contiguous (C1..Cn), no gaps, no vague `expected`
        column.
      - cross-row invariants relevant to the spec (e.g. realm suffix,
        domain name, port numbers that must appear in multiple rows).
      - **spec-vs-inventory agreement**: if the spec has a §1 Targets
        table with group names, a test that runs `show-inventory` (or
        `ansible-inventory --graph` for real hosts) and asserts the
        spec's group set equals the inventory's host set. Use
        `TestRegression_SpecAndInventoryAgree` in
        `internal/spec/core_infra_provider_db_regression_test.go` as
        the template.

## D. Spec content updates to flip DRAFT

- [ ] The §0 "status" block is removed or rewritten to point at the
      runbook.
- [ ] The evidence-collection block (usually §3) replaces the DRAFT
      hand-written examples with the real
      `.verification/<spec>-<UTC>.ndjson` row output from the
      actual-run.
- [ ] The changelog (usually the last section) gets a new row dated
      the day of promotion, version bumped to v1.0.
- [ ] The playbook-mapping table (usually §6) is updated to match
      the current state of the apply playbook (task names, module
      choices, entrypoint overrides, block/rescue structure).

## E. What this does NOT require

- Promoting the server spec does **not** require also writing the
  corresponding client spec or client apply playbook. The client is a
  separate spec.
- Promotion does **not** require hardening (e.g. replacing
  `privileged: true` with a cap set). Hardening can land in a
  follow-up PR.
