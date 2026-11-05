# spec-promotion-checklist.md -- DRAFT -> v1.0 for any spec

AGENTS.md §1 and §3 require a real actual-run before any
`docs/verification/<spec>.md` leaves DRAFT. This list points at the rules;
when it and [AGENTS.md](../../../../AGENTS.md) disagree, AGENTS.md wins.

## A. The run itself (AGENTS.md §1.2, §1.4, §1.5)

- [ ] A formal run (SKILL.md §5) passed on a frozen candidate from a clean,
      isolated checkout: `vm-target test`, or `vm-target topology test`
      (with `--ephemeral` when fresh hosts or cross-playbook ordering
      matter, AGENTS.md §4.0). L3 `--check --diff` was not skipped, or the
      spec/runbook states why the playbook cannot run in check mode.
- [ ] A sanitized record exists at
      `docs/evidence/<feature>/<date>-<tested-revision>.md` with the fields in
      [docs/actual-run-evidence.md](../../../../docs/actual-run-evidence.md)
      §3: tested commit and tree, target and inventory summary, real
      dry-run/apply/verify/idempotency verdicts.
- [ ] Nothing that affects execution changed after that run
      (actual-run-evidence.md §4); otherwise there is a new candidate and a
      new run.
- [ ] If multi-VM, the client-side round trip (`getent passwd`, `curl`,
      `sudo -l`) is a spec row that passed against the client group.

## B. Lint and syntax gates (AGENTS.md §3, §4.0)

- [ ] `go run ./cmd/pilot spec docs/verification/<spec>.md --lint` exits 0.
- [ ] `go test -count=1 -run TestShellSyntax ./internal/spec/` passes
      (`bash -n` over every row command).
- [ ] `go test -count=1 -run TestSpecPlaybookTagAlignment ./cmd/pilot/cmd/`
      passes: every row has a tagged task in the apply playbook, or an
      exemption with a reason.

## C. Regression test (AGENTS.md §3)

- [ ] `internal/spec/<feature>_regression_test.go` exists and locks at least
      contiguous row IDs, no vague Expected values, and the cross-row
      invariants that would catch this spec's likely mistakes.
- [ ] Spec-vs-inventory agreement follows AGENTS.md §1.3/§2.1: no test can
      check it (the reference inventory needs a running VM), so read the
      inventory before the run and record the A/B decision in the fact
      snapshot. For a single-host `target_group` spec, document the exception
      in the regression test (template:
      `internal/spec/freeipa_client_regression_test.go`).

## D. Spec content updates to flip DRAFT

- [ ] The §0 status block is removed or rewritten to point at the runbook.
- [ ] The evidence section keeps only the latest tested revision and tree,
      the real verdict and a link to the `docs/evidence/` record
      (`docs/verification-spec-template.md` §3). No pasted transcripts or
      NDJSON rows, and no link to `.verification/` (AGENTS.md §7).
- [ ] The runbook's fact snapshot (AGENTS.md §2) and last-verified summary
      point at the same record.
- [ ] The changelog gets a row dated the day of promotion, version v1.0.
- [ ] The playbook-mapping table (if the spec has one) matches the current
      apply playbook (task names, tags, block/rescue structure).

## E. What this does NOT require

- Promoting a server spec does **not** require also writing the client spec
  or client apply playbook. The client is a separate spec.
- Promotion does **not** require hardening (e.g. replacing
  `privileged: true` with a cap set). Hardening can land in a follow-up PR.
