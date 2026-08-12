# The common clean-room contract

> Shared normative contract for any task that rebuilds a pilot topology from
> zero and produces evidence from it. Referenced by
> `.agents/skills/minimal-poc-update`, `.agents/skills/minimal-poc-revalidation`,
> and `.agents/skills/delivery-test`.
>
> This file is the authority for **how** a clean-room run is conducted. It says
> nothing about **which** hosts, roles, or checks a given run covers — that
> comes from the runbook or scenario under test.

Read this instead of reading a sibling scenario skill in full. A scenario skill
defines a *different* topology; loading one for its clean-room rules imports a
competing host/role list with it.

---

## 1. Execution modes

Use exactly one mode per run, and name it in the final report.

- **Clean-room acceptance** — the required gate. Start from a clean checkout
  and a freshly provisioned, test-owned topology; run the complete scenario,
  the cross-host checks, and the idempotency proof.
- **Failed-topology diagnosis** — a short-lived debugging mode, entered only
  after a clean-room failure. Keep the failed topology and workspace long
  enough to reproduce the failing chain and identify the smallest fix.

A diagnosis run must never produce an acceptance PASS, update committed
evidence, or stand in for a fresh run. After an execution-affecting fix, create
a new candidate and return to a fresh clean-room acceptance.

Role-level fast tests are useful preflight feedback but do not replace this
gate: the defects it targets arise only from cross-host topology, role
ordering, generated inventory, shared group vars, or shared vault inputs.

---

## 2. Hard preconditions

- Read the runbook/spec under test **in full** first — it defines the host
  topology, roles, and vars. Read `AGENTS.md` and `DELIVERY.md`.
- Confirm the host meets the KVM provisioning prerequisites (libvirt, kvm,
  QEMU, cloud-localds).
- Confirm the `pilot` binary in `$PATH` is freshly built
  (`go build -o ./pilot ./cmd/pilot`). A stale binary silently missing a
  feature looks exactly like a wizard bug and wastes a debugging cycle.
- Confirm `trec` is installed (`which trec`, `trec drive --help` for the
  current flag set — don't assume flags from memory).
- Test artifacts (disposable workspace, `trec` scripts, `.cast` recordings) go
  under the repo's gitignored `./tmp/`, never loose in the tracked tree.

Optional bandwidth optimization: `pilot services up --profile dev-lite` once
per host session, then add `--services local` to each `vm-target up`. It is
fail-closed — if the stack isn't healthy, `up` errors rather than silently
falling back to upstreams; run `pilot services status` to diagnose rather than
dropping the flag.

---

## 3. Pilot ownership — the only sanctioned surfaces

Editing, generation, deployment, and reconciliation go **only** through
`pilot edit` / `pilot inventory generate` / `pilot deploy` / `pilot reconcile`
/ `pilot vm-target`. Never a hand-written `hosts.yml`/`inventory.yml`/
`group_vars`, never a raw `ansible-playbook` or `ansible-vault` invocation.

This holds even when the task's own instructions don't restate it. Two reasons
it is not merely stylistic:

1. it is the discipline the rest of the pilot demos hold to, so the run
   actually exercises the tool the way a user would;
2. the wizards apply `-e target_group=` scoping and the `site.yml` safety valve
   correctly, which a hand-rolled inventory can silently get wrong — e.g.
   wiring a role to a host it shouldn't touch.

**The only permitted hand-edit exceptions** are files the tool itself declines
to edit — `pilot edit`'s vault editor explicitly refuses nested-structure YAML
(roster / list / nested map) and tells you to use a text editor. That refusal
is the exception; everything the wizard *will* edit must still go through it.
`pilot roster lint <file>` validates a hand-edited roster against the same
rules the apply playbook enforces. See
`../pilot-trec-verification/references/pilot-edit-wizard.md` for the current
boundary, which narrows as the wizard gains editors.

If completing the run appears to require editing a playbook, role, task, or Go
source, that is a **stop condition** — see §8.

---

## 4. Clean-room teardown and rebuild

In order, and recorded:

1. Record the existing VM inventory, then remove every VM belonging to the
   runbook under test.
2. Remove the entire disposable workspace.
3. **Prove prohibited stale state is absent** — don't assume removal worked.
   Check for surviving VMs, workspace directories, generated inventory, vault
   files, and stale fact caches.
4. Create a new workspace under `./tmp/<slug>`.
5. Rebuild VMs only through `pilot vm-target`.
6. Create ordinary settings only through `pilot edit` and
   `pilot inventory generate`.
7. Create only the explicitly allowed roster / narrowly scoped reconcile-input
   exceptions of §3.
8. Deploy every role again through the `pilot deploy` wizard — **including
   roles that appear already satisfied**. A check-mode preview that runs on an
   already-applied host can look green for the wrong reason.

### Naming, IP, and reuse discipline

- Reserve fresh, test-owned names for the run. Do not reuse an
  already-provisioned VM, workspace, IP, inventory, or vault from a prior
  candidate. If an example name is already in use, choose a new run-scoped name
  and substitute it consistently.
- **Do not tear down an existing target unless the user explicitly identified
  it as disposable for this run.**
- Use the **actual IPs** from `pilot vm-target list` in every step. Never
  hardcode an IP from a prior run — libvirt DHCP reassigns leases on every
  rebuild.
- Per-VM SSH keys live at `/var/lib/libvirt/images/pilot/<name>/id_ed25519`,
  not `~/.ssh/id_rsa`.
- If several VMs are started concurrently, the heaviest can miss the default
  DHCP-lease window. Retry that one alone (optionally with a longer
  `--boot-timeout`) rather than assuming a real failure.

---

## 5. Wizard input policy

- Answer `Y` for automatically detected `-e` values.
- Leave manually entered additional `-e` empty.
- If any other human-authored value is required, **stop the entire workflow**
  and ask. Inventing a value silently changes what the run proves.

Drive and record every wizard per
`../pilot-trec-verification/SKILL.md` — its §4b rules table is the complete
normative checklist for keyboard-driving `pilot edit`/`pilot deploy`.

---

## 6. Evidence and the recording gate

The recording lifecycle, the three-directory cast contract
(`exploration/` / `failed/` / `evidence/`), the per-checkpoint verification
gate, and the `recording-manifest.md` index are defined once in
`../pilot-trec-verification/SKILL.md` §3a. Follow it as written; do not
restate or relax it here.

Two consequences worth stating in contract terms:

- A checkpoint may not advance until its own final cast passes verification
  (`status=success`, `exit_code=0`, one final successful `SESSION_END`,
  matching integrity, clean secret scan).
- Exploration casts, action-mode casts, and any failed/aborted cast are
  diagnostics only. They may never support a PASS or appear in a walkthrough.

---

## 7. Serialization

Only one state-changing agent or step may run at a time. Never run these
concurrently:

- teardown; VM creation; inventory generation; interactive wizard execution;
  deployment; FreeIPA mutation; NFS configuration; idempotency reruns.

Read-only audits may overlap only after their input evidence is complete and
immutable.

---

## 8. Failure policy and stop conditions

Every delegated step stops at the first unexpected result. A delegated agent
must never independently: select a workaround; change target type; reuse stale
state; hand-edit a generator-owned file; suppress an error; reinterpret a
requirement; or continue into the next checkpoint.

The controller classifies each result as one of: retryable execution failure;
environment blocker; implementation defect; runbook defect; evidence
deficiency; policy decision required.

**Implementation stop condition.** If completing or accurately documenting the
run requires modifying any Ansible playbook, role, or task; any Go source; or
any product implementation, then: stop immediately; do not modify the
implementation; preserve the current evidence; report the exact file, symbol,
behavior, and proposed direction; and ask the user for authorization first.

A documentation-only correction may proceed when it is supported by evidence
and does not conceal a product defect.

---

## 9. Per-step output contract

Each state-changing step returns:

1. checkpoint identifier;
2. commands executed;
3. exit status;
4. concise relevant output;
5. resources changed;
6. evidence paths;
7. per-cast verification and secret-scan verdict;
8. expected versus observed result;
9. PASS, FAIL, or BLOCKED.

Store complete logs as evidence files. Return only focused excerpts to the
root context.

---

## 10. Cleanup and what may be committed

Tear down only the targets you created for this run — **never** a VM you did
not create or that the user did not explicitly name for deletion. In diagnosis
mode, retain the failed topology only while isolating the defect.

Raw casts and transcripts are one-time development diagnostics. Commit only a
sanitized candidate/tree, topology, recap, and verdict summary. Do not commit
or link raw recording paths, cast names, inventories, or other gitignored
artifacts.
