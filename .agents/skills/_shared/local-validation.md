# Local validation and role startup

Applies to issue-to-pr, pr-ready and pr-review-merge. Use this reference from the
verified workflow snapshot, preserving the checkout, role and evidence contracts.

## Check runtime readiness before expensive work

After landing in the verified checkout, run the snapshot's
`.agents/skills/_shared/scripts/role_preflight.py` with `--snapshot`, `--repo`,
`--platform codex|claude|agy` and `--workflow issue-to-pr|pr-ready|pr-review-merge`.
It checks the whole required role set, including drift and missing definitions,
and warns about Codex symlink installation hazards. It never repairs configuration automatically.
For pr-review-merge add `--dependency` only when overlap needs the dependency role.

`LAUNCH_REQUIRED` is a static result, not proof of runtime readiness. Before
implementation or expensive tests, use the host's real subagent tool to launch
each required role in a fresh read-only context with a bounded acknowledgement
task. Apply the existing snapshot binding statement on DRIFT. Record the session,
logical role, actual agent, role hash, model/effort and success/failure in the
item checkpoint. Existing successful launches in the same session with the same
role hash and configuration can satisfy this check; do not add duplicate probes.
Recheck after configuration changes or in a new session. Reuse successful probes
for actual bounded analysis when the runtime supports a fresh task context.

If startup fails, inspect the concrete runtime error once and follow the existing
platform dispatch contract. Do not report file validation as a successful launch,
silently substitute a role, or repeatedly run tests hoping startup will recover.
This reference does not replace the dispatch compatibility rules.

## Select local tests once per candidate

Use the snapshot's `.agents/skills/_shared/scripts/local_test_plan.py --repo DIR
--base BASE_SHA --head HEAD_SHA` on the committed candidate. It reports changed
Go packages and their transitive importers, including test imports; go.mod/go.sum
changes expand scope to all packages. Workflow/build/skill changes also select
the command package's repository consistency tests. Every non-empty change adds
`make skill-test` (once, as the receipt: below), narrowed to the suites the change can reach; a
path no suite is known to read selects every suite, so a Go-only, playbook-only or docs-only
change plans the plain `make skill-test` too.
Test-only Go changes select their own package without expanding to importers.

The large `cmd/pilot/cmd` and `internal/spec` packages require explicit
`--regression PACKAGE=REGEX` selectors. `NEEDS_SELECTION` means the plan is
incomplete, not permission to omit that package. Select the changed tests and
tests of the affected behavior; include shared invariants and real runtime
controls where relevant. CI/workflow edits normally include `TestCI` checks
and `TestAnsible` when toolchain installation or job boundaries change;
role changes include `TestAgentSkill`. Document why the selected tests cover the
diff. The planner is advisory: generated files, non-Go dependencies, deleted
packages and dynamic runtime dependencies still need human/Reviewer assessment.
Add their checks explicitly to the plan and acceptance evidence.

Do not run entire cmd/spec packages merely because one regression lives there.
Full normal/race suites belong to CI unless explicitly requested or CI is
unavailable. Record an explicit reason for any local expansion. Reviewers audit
the plan and receipts and independently run counterexamples or missing checks;
unchanged source, environment and test-contract receipts need not be repeated
just to create a new copy. Existing gate rules decide whether receipts can be
reused across evidence-only changes. Startup acknowledgements are not independent
code reviews, and source changes still invalidate affected checks.

## While the Coder works, and the one receipt (kjelly/pilot#432, kjelly/pilot#430)

While the Coder works it runs the tests of what it changed (the selected Go tests; for a
skill, that skill's `tests/` or the changed test modules). The plan's `make skill-test` runs
once per candidate HEAD, as the `run_check.py` receipt on the committed HEAD (Root's, or the
Coder's when it takes the receipt; never both). Root takes the receipt unless the dispatch
envelope tells the Coder to; the Coder's envelope carries the validation item "the tests of
what it changed; not the planned `make skill-test` (Root runs that once, as the receipt)".

The plan narrows `make skill-test` to the suites the change can reach and prints the reason
for each (`skill_suites` in its JSON: which changed path reaches which suite, through which
import, load or read), as `make skill-test SKILL_SUITES="a b"`. Run the planned command
exactly: a narrower command is not the receipt. A path no suite is known to read (anywhere in the repository: a Go-only,
playbook-only or docs-only change has one, and so plans the plain `make skill-test`, where the plan
before the selection planned none for it), a deleted, renamed or type-changed path, a path that is not canonical, and
any error while deriving the suites, select all of them (the plain `make skill-test`); only an
empty diff plans no skill command. CI's own `docs` profile, which skips the suites for such a change, is not consulted. Keep
the plan JSON next to the receipt, for the reviewers. Each suite's last test module (`test_zzz_suite_reads_<suite>.py`) checks
that every tracked file or directory the suite's own run read is a source the derivation names (a read from a test
body, `setUp` or `setUpClass` included); it does not see descendant processes, existence probes, branches that
did not run or data beyond that run. CI's `Skill and repository contracts`
job skips `make skill-test` for a change in its `docs` profile and otherwise runs the full `make skill-test`; Ready
requires the job's result. A CI failure in a suite the
plan left out is a defect of the selection: repair the selection and the suite, and never
list it as an `unrelated_failing_checks` entry. `pr-review-merge` ignores the selection: it
runs the full suite on its own candidate. This section governs the Coder and the receipt of
`issue-to-pr` and `pr-ready`; the `make skill-test` that `pr-review-merge` runs (its
SKILL.md) is a separate gate on a separate candidate, and this section does not change it.
