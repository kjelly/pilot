# Issue claims are hypotheses to verify

An Issue says what someone observed and usually also why they think it happens,
how to fix it and what "done" looks like. Fix what the reporter needs, but treat
each of those statements as a claim to verify, not a specification: reporters
(people, bots, earlier automated reviews) misread code, describe one symptom of a
different defect, propose a workaround, or ask for behaviour the repository's own
contracts forbid. `AGENTS.md` §0.2 applies: assumptions and unknowns are listed,
and an Expected/acceptance criterion is never relaxed silently.

Read the Issue's comments as well as its body
(`gh issue view N --json ...,comments`): later comments often correct the report,
add a reproduction, or record a maintainer's decision.

## 1. Triage (SA, then Root)

SA splits the Issue into claims (symptom, stated cause, proposed fix, each stated
acceptance criterion) and returns, per claim, whether it holds, with a
reproduction or counter-evidence on the base commit. Root classifies:

| Disposition | When | Action |
|---|---|---|
| `valid` | Reproduces or traces as claimed | Implement and test it. |
| `invalid` | Counter-evidence shows the claim does not hold (the code does not behave that way, or the requested behaviour contradicts a repository contract) | Do not implement it. Dispute it (§2–§4). |
| `needs_evidence` | No reproduction or concrete trace, and none can be found | Do not implement it. Dispute it and ask for the missing reproduction (§2–§4). |
| `out_of_scope` | The claim may hold but is a different defect or request | Do not fold it into this PR. Dispute it (§2–§4) with a link to a follow-up Issue, or ask whether one is wanted. |

A proposed fix that differs from the root-cause fix is normal, not a dispute:
explain in the PR body why the actual root cause needs a different change. A
**stated acceptance criterion or expected behaviour** that you do not deliver is a
dispute and must be answered on the Issue; dropping it from
`acceptance_criteria` without a `disputed_issue_claims` entry is the silent
relaxation `AGENTS.md` forbids.

### Whole-Issue outcomes

- Every claim is `invalid`: no branch, no PR. After §2 and §3, report `INVALID`
  with the reply URL and the reviewer's verdict. Do not close the Issue; a person
  decides.
- The core claim is `needs_evidence`, or Root and the reviewer disagree after a
  fresh SA diagnosis: no PR. After §3, report `NEEDS_DECISION`.
- Some claims are `valid`: open the PR for those. If anything the Issue asks for
  stays open after merge (`needs_evidence` waiting on the reporter, `out_of_scope`
  without a follow-up Issue), set `issue_resolution: "partial"` and reference the
  Issue with `Refs #N` instead of `Fixes #N`. An `invalid` claim answered with
  evidence does not by itself keep the Issue open.

## 2. Independent confirmation (issue-reviewer)

Give the reviewer the claim, its source URL and the code (the PR HEAD, or the
base commit when there is no PR), **not** SA's or Root's conclusion. It returns,
per claim, `holds`, `does_not_hold` or `undetermined` with its own evidence.

The dispute stands only when the reviewer agrees: `does_not_hold` for `invalid`,
`undetermined` for `needs_evidence`, and agreement that it is a separate defect or
request for `out_of_scope`. Otherwise the claim is `valid` (fail closed). The
reviewer also checks that every acceptance criterion the Issue states is either
met in `acceptance_criteria` or listed in `disputed_issue_claims`.

## 3. Reply on the Issue (Root)

Post a comment on the Issue. State the claim as understood, the disposition, the
evidence (commands and results, `file:line`, the commit), and what would change
the conclusion. When the claim came from a comment, include that comment's URL
(the gate checks the link). Never paste secrets or raw logs.

```bash
gh api repos/OWNER/REPO/issues/N/comments -F body=@reply.md --jq .html_url
```

Take the URL from that JSON output; output filters can rewrite what
`gh issue comment` prints.

## 4. Record it in the evidence

Add one `disputed_issue_claims` entry per disputed claim and set
`issue_resolution` ([evidence contract](evidence-contract.md)). When the evidence
has disputes, `issue_gate.py` reads the Issue's comments and fails closed unless:

- `source_url` is the Issue itself or one of its comments;
- `reply_url` is a comment on the Issue posted after the claim and, when the claim
  came from a comment, contains that comment's URL;
- `disposition` is `invalid`, `needs_evidence` or `out_of_scope`, `claim` and
  `counter_evidence` are specific, `head_sha` covers the current HEAD and
  `reviewer_confirmed` is `true`.

`issue_resolution: "partial"` needs at least one dispute. `create_pr.py` then
requires the PR body to reference the Issue (`Refs #N`) without a closing keyword;
with `fixes` (the default) it requires `Fixes #N` as before. The gate cannot judge
whether a dispute is right; §2 is what makes it credible.

## 5. When the claim comes back

A reporter's reply after yours, or the same claim raised again elsewhere, means
triage again:

- **New evidence** (a reproduction, a path you missed): triage it as a new claim;
  it may well be `valid`.
- **The same claim, no new evidence**, after a reviewer-confirmed dispute: do not
  implement it and do not start another reply round. Report `NEEDS_DECISION` with
  both comment URLs so a person decides.
