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
the command package's repository consistency tests. Skill changes add
`make skill-test`.

The large `cmd/pilot/cmd` and `internal/spec` packages require explicit
`--regression PACKAGE=REGEX` selectors. `NEEDS_SELECTION` means the plan is
incomplete, not permission to omit that package. Select the changed tests and
tests of the affected behavior; include shared invariants and real runtime
controls where relevant. CI/workflow edits normally include `TestCI` checks;
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
