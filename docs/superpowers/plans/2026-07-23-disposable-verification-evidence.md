# Disposable Verification Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make one-time `.verification/` recordings disposable while retaining truthful, Git-committed verification summaries and preventing agents from routinely reading full Ansible transcripts.

**Architecture:** The repository rules distinguish short-lived raw recordings from durable sanitized summaries. `AGENTS.md` defines the operating rule; `docs/actual-run-evidence.md` gives the retention and reading policy; the current minimal-PoC runbook and evidence summary remove raw-artifact paths.

**Tech Stack:** Markdown, Git ignore rules, TREC/Ansible evidence conventions.

## Global Constraints

- `.verification/` is Git-ignored and holds only short-lived raw evidence.
- Do not commit cast names, paths, recording inventories, secrets, or raw transcript output.
- Committed evidence remains truthful: candidate/tree, target summary, real verdicts, and sanitized recap remain available.
- Agents read summary/result/recap first and inspect raw evidence only for a failure, audit, baseline comparison, or explicit user request.

---

### Task 1: Define disposable raw-evidence and summary-first rules

**Files:**

- Modify: `AGENTS.md`
- Modify: `docs/actual-run-evidence.md`

**Interfaces:**

- Consumes: Git-ignored `.verification/` and existing candidate-first evidence flow.
- Produces: One repository-wide rule set for raw retention, cleanup, and agent transcript access.

- [x] **Step 1: Replace durable-archive wording with one-time acceptance retention**

State that raw cast/stdout/stderr remains available only during acceptance and diagnosis; after a sanitized accepted summary exists, successful raw artifacts may be deleted. Superseded failed artifacts may be deleted after their fix is verified.

- [x] **Step 2: Add the summary-first reading contract**

Require agents to inspect exit code, duration, recap, verdict counts, and a small generated summary before opening raw output. On failure, use targeted search for `FAILED!`, `fatal:`, `unreachable`, and `PLAY RECAP`, then inspect only the relevant task context.

- [x] **Step 3: Preserve Git and secrecy boundaries**

State that raw recording paths and inventories do not enter committed documentation; committed evidence contains only sanitized facts and does not depend on a durable raw archive identifier.

- [x] **Step 4: Validate policy consistency**

Run `rg -n "archive ID|封存 raw|retention policy|raw artifact.*checksum" AGENTS.md docs/actual-run-evidence.md`.

Expected: no requirement that one-time `.verification/` recordings be archived before accepting a candidate.

### Task 2: Remove raw-artifact references from the current minimal-PoC publication

**Files:**

- Modify: `docs/runbooks/minimal-poc-architecture.md`
- Modify: `docs/evidence/minimal-poc-architecture/2026-07-23-round-12.md`

**Interfaces:**

- Consumes: Round-12 sanitized facts already committed in the evidence record.
- Produces: A public/current document set that is valid after local `.verification/` cleanup.

- [x] **Step 1: Replace the runbook raw-archive statement**

Keep the statement that Round 12 was tested from immutable CAND-23, but remove the assertion that a raw TREC archive remains available.

- [x] **Step 2: Remove raw cast paths from the evidence record**

Replace provenance and raw-recording location references with the recorded candidate/tree, image digests, file hashes, verdicts, and critical evidence integrity result. Do not add a replacement local path.

- [x] **Step 3: Validate no committed minimal-PoC document depends on `.verification/`**

Run `rg -n "\\.verification/|\\.cast\\b|raw TREC archive" docs/runbooks/minimal-poc-architecture.md docs/evidence/minimal-poc-architecture/2026-07-23-round-12.md`.

Expected: no matches.

### Task 3: Review and commit the policy change

**Files:**

- Review: `AGENTS.md`
- Review: `docs/actual-run-evidence.md`
- Review: `docs/runbooks/minimal-poc-architecture.md`
- Review: `docs/evidence/minimal-poc-architecture/2026-07-23-round-12.md`

- [x] **Step 1: Check the diff and Markdown policy language**

Run `git diff --check` and review only the four policy/publication documents.

Expected: no whitespace errors; no unrelated changes included.

- [x] **Step 2: Commit only policy and publication changes**

Commit the four policy/publication documents and this plan with message `clarify disposable verification evidence`. Existing user-owned changes remain untouched.
