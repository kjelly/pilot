---
name: spec-driven-feature-workflow
description: |
  End-to-end recipe for turning a vague or newly-requested capability into a
  committed, evidence-backed pilot feature: (1) evaluate the requirement and
  pick a concrete technical design before writing anything, (2) write the
  verification spec, (3) write the apply playbook, (4) write the regression
  test, (5) run the whole thing for real on a vm-target (or docker-target /
  real host) and fix whatever the real environment breaks, (6) write the
  runbook with the real evidence AND the pitfalls found in step 5. Use this
  when the task starts from a feature description or requirement list
  rather than an existing spec — e.g. "we need X capability, evaluate a
  design and implement it" or "add support for Y and update spec/playbook".
  Not for mechanical spec/playbook edits to something that already exists —
  use `vm-target-spec-testing` directly for that (this skill wraps it as
  step 5).
---

# spec-driven-feature-workflow

> The log-server + audit-log-forwarding feature (2026-07-06) is the first
> case study; see `references/case-study-log-server.md` for the worked
> example this recipe was extracted from.

## 0. When this applies

The user hands you a **capability**, not a spec: "we need setuid/setgid
auditing that forwards to a central log server" — no existing
`docs/verification/*.md` to edit, no existing `playbooks/apply/*.yml` to
extend. You have to invent the design before you can write anything.
If a spec/playbook pair already exists and you're just testing or fixing
it, skip straight to `vm-target-spec-testing` (step 5 below).

## 1. Evaluate — pick the design before writing a single file

A feature request often bundles an implicit technology choice ("log
server", "message queue", "cache") that has more than one reasonable
answer. Resolve this **first**, out loud, before touching `docs/` or
`playbooks/`:

1. **List 2–4 real candidates**, not a strawman + your favorite. For
   log-server this was rsyslog / syslog-ng / Loki+Promtail+Grafana.
2. **Score against what's already true of this repo**, not abstract
   merit: does it match the protocol the other side of the integration
   already speaks (client forwarding was pinned to classic rsyslog
   `@@host:port` syntax — that alone ruled out anything without a native
   syslog listener)? Does it fit the existing "one VM, one systemd
   service, ansible-managed files" shape, or does it drag in a multi-container
   stack for a need that's actually just "receive + retain + prove
   receipt"? Grep for prior art (`grep -rln <keyword>` across
   `docs/verification`, `playbooks/apply`, `AGENTS.md`) before assuming
   there's none.
3. **State the recommendation with the main tradeoff in a few sentences**,
   not an essay — this is the "exploratory question" register: give a
   clear pick and the one thing you'd reconsider it for, then let the
   user redirect. Don't start writing files until they've confirmed the
   direction, even under an auto-mode bias toward action — an evaluation
   request ("評估...是否可以") is explicitly asking for the assessment
   step, not silent implementation.
4. Sketch the **concrete shape** in the same turn you get sign-off: draft
   checklist row categories, the variable contract (§1.5 of
   `verification-spec-template.md`), and which existing playbook you'll
   mirror structurally. This turns "we agreed on rsyslog" into something
   you can immediately start writing against.

## 2. Write the spec

Follow `docs/verification-spec-template.md` literally — copy it, don't
improvise the section headers. Two things bite new specs specifically:

- **Checks with no native rc semantics** (e.g. "is this port listening",
  "did this log line land somewhere") need the
  `sh -c '<check> && echo 0 || echo 1'` idiom so the ad-hoc wrapper never
  sees a non-zero process exit on the unhealthy path (see trap 1 in the
  template). For `~contains` checks where a legitimate miss would leave a
  failing grep's rc on the command, neutralize it (`; true` or
  `&& echo 0 || echo 1`) so a real FAIL renders as a clean mismatch
  instead of a corrupted ansible FAILED-wrapper output.
- **Commands containing a literal `|`** must keep it inside a quoted
  region the parser respects (`'...'`/`"..."`) — e.g. wrap the whole
  thing in `sh -c '...'`. A `\|`-escaped pipe is NOT unescaped by the
  parser; it survives as a literal backslash in the command string and
  silently breaks the shell semantics at verify time. Confirm row count
  and IDs parse correctly (`pilot spec <file> --lint`) immediately after
  writing multi-pipe rows — a silent column-split bug looks like "lint
  passed" but the wrong number of rows or garbled command text.

If the feature is a client/server pair (like log-server +
audit-log-forwarding), design the client spec's site-specific value
(the server's IP) as a **fixed alias pinned into `/etc/hosts` by the
apply playbook**, and have the spec check for the alias literal, not the
IP. Spec Command/Expected columns are static text authored once; they
can't be templated per deployment.

## 3. Write the apply playbook

Mirror the closest existing playbook's skeleton (`pam-oidc-sshd-apply.yml`
for config-file-heavy services, `freeipa-client-apply.yml` for
enroll-then-verify shapes) rather than inventing structure. Non-negotiables
from `AGENTS.md` §4 apply in full: `block/rescue`, every spec-row task
tagged with its row ID, no hard-coded host-specific values.

The one idempotency trap worth calling out by name: **`ansible.builtin.systemd:
state: restarted` is never idempotent** — it restarts every single run,
which fails AGENTS.md §1.4's L6 idempotency check even when nothing
actually changed. Split it: `state: started` (idempotent) plus a second
task `state: restarted` gated on `when: <config_render_task> is changed`.

## 4. Write the regression test

Per `AGENTS.md` §3: row IDs contiguous, lint-clean, generated playbook
covers every row, plus whatever cross-row invariant would have caught the
mistakes you're most likely to make for this feature (matcher traps, a
required substring, a rule-ordering constraint). If step 5 finds a real
bug, add a regression assertion for it here — a bug worth fixing on a live
VM is worth locking so it can't silently regress (see
`log_server_regression_test.go`'s `sh -c '... && echo 0 || echo 1'`
assertions and `audit_log_forwarding_regression_test.go`'s rule-order
check on `audit.rules.j2` for concrete examples).

## 5. Run it for real — budget for the environment to win the first round

Delegate the mechanics to `vm-target-spec-testing` (up → apply → verify →
idempotency → cross-check → down). The meta-lesson for THIS skill: **a
spec and playbook that lint clean and parse correctly will still break on
first contact with a real target**, in ways no amount of re-reading the
YAML would have caught. From the log-server/audit-log-forwarding case
study alone: a directory owned by the wrong user for the service's actual
runtime uid, a restart task that broke idempotency, a kernel audit
filterlist that silently shadows a specific rule behind a broader one
listed first, and a query tool (`ausearch`) whose own parser choked on a
real log line despite the data being correct. None of these were
guessable from the playbook source; all of them took one real apply +
verify cycle to surface. Don't treat a lint-clean spec or a syntax-checked
playbook as evidence of correctness — only a real run is.

When you hit one of these, the discipline is: **fix the playbook/spec and
re-run from the top of the affected step**, not "note it as a known
deviation and move on" — deviations are for genuine environment
differences (EL vs Debian, dev vs prod), not for bugs. See
`references/case-study-log-server.md` for how each of the four bugs above
was root-caused (not just patched) before moving on.

One more thing worth budgeting for: **a check that has only ever run
against a true-positive state can't prove it's a real check.** If every
apply you've tested happened to leave the target in the expected state,
you've never actually exercised the FAIL path — and a broken matcher/tool
that always reports PASS looks identical to a working one until something
is actually wrong. When a feature has an on/off or present/absent
dimension (an optional variable, a conditional task), deliberately run the
"off" apply+verify cycle too, not just the "on" one. That's exactly how a
real bug in `pilot verify`'s own ad-hoc rc-extraction was found in this
case study (§"Bug 5" in the reference doc) — numeric checks using this
template's own recommended `cmd; echo $?` idiom silently always passed
under ad-hoc/inventory verify, and it took testing a genuine negative
state to notice.

## 6. Write the runbook — the pitfalls section is not optional

Follow `docs/runbooks/*.md` convention: §0.5 fact snapshot (AGENTS.md §2),
real apply output, real verify output, real idempotency-rerun output,
real cross-check output for multi-host features. Then add a "踩過的雷"
(pitfalls hit) section for every bug found in step 5, each with: the
symptom as observed, the root cause (not just the fix), and the fix. Per
`docs/README.md`'s own framing, this section is *why* a runbook is worth
more than a clean example — it's where the next reader avoids repeating
your debugging session. See `docs/runbooks/log-server.md` §5 and
`docs/runbooks/audit-log-forwarding.md` §5 for the format.

## 7. Wire it into the index

Add one line to `docs/README.md`'s 入口地圖 table pointing at the new
runbook. If the feature composes with an existing one (client/server,
supplier pattern), cross-link both runbooks' pitfalls sections rather
than duplicating the explanation.

## 8. Reference index

1. `references/case-study-log-server.md` — the worked example this recipe
   was extracted from: the rsyslog-vs-Loki evaluation, the four real bugs
   found during vm-target testing, and how each was root-caused.
2. `vm-target-spec-testing` skill — the mechanics referenced by step 5
   (VM lifecycle, fact snapshot, dry-run, apply, verify, cross-check,
   teardown). This skill does not duplicate that content.
