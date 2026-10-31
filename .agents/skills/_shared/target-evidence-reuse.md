# Target evidence after integrating the base branch

This rule applies to every PR in this repository, through `issue-to-pr`, `pr-ready`
and `pr-review-merge`. It is a conditional reuse of a **target-run record**, not a
waiver for merging main. The manifest on the current base must declare
`required_evidence[].kind: target-run`; untyped required records, including CI or
coverage URLs, retain the existing strict comparison.

The default remains exact candidate/HEAD equality or an evidence-only delta. For
an advanced base merged into the candidate branch, a fresh independent reviewer
may add `target_reuse` to the required target record. `issue-to-pr` puts it on the
`repo_required_evidence[]` entry; the other workflows put it inside
`target_validation`. The original tested revision and artifact are retained.

```json
{
  "head_sha": "<current full HEAD SHA>",
  "base_sha": "<current full base SHA>",
  "reviewer_confirmed": true,
  "dependency_review": "Explain the target entry points, complete execution/dependency closure, and why every imported base change outside it cannot affect this run.",
  "execution_paths": ["playbooks/apply/example.yml", "internal/example/runtime.go", "go.mod", "go.sum"],
  "non_execution_changes": [
    {"path": "docs/verification/example.md", "reason": "Only the latest evidence link changed; commands, expected values, target and variable contract are unchanged."}
  ]
}
```

The paths above are illustrative, not a complete dependency list. The reviewer
must inventory **both** candidate and HEAD: entry points, all relevant shared Go
code, initialization, parser/inventory/runner code, Ansible includes/templates,
fixtures, spec commands and expectations, locks and other execution inputs. New
files in a compiled package or include directory must not be omitted. If the
closure cannot be established, keep WAITING and obtain a new target run.

The shared verifier checks:

1. The reviewer attestation has `reviewer_confirmed: true`, a `dependency_review` of
   at least 60 characters (after trimming), and names the current full HEAD and base
   SHAs. The candidate and current base are ancestors of HEAD, with a common fork
   predating both: a candidate that is itself on the base, or a base that never advanced
   past the candidate's fork, is refused. The remote verifier resolves the live base
   branch too; stale PR `baseRefOid` metadata is not accepted as proof of the current
   base. The local verifier also refuses a candidate and base with more than one merge
   base (criss-cross merges); GitHub's compare API reports a single merge base, so the
   remote verifier cannot see that case and the rejection is enforced locally only.
2. `execution_paths` lists unique exact regular files, including dependencies.
   Every scoped file has identical Git blob **and mode** at candidate and HEAD.
   A changed, added, deleted, renamed or symlinked scoped input requires a new run.
3. Complete Git trees are compared. Every other changed path must be either an
   evidence-only path, an individually audited non-execution edit, or a pure base
   import: candidate equals the common fork and HEAD equals the current base.
   Runtime blends/conflict resolutions and local runtime edits fail this proof.
4. Non-execution audits name exact paths with specific explanations (30+ characters).
   Eligible files are Markdown under `docs/` or `.agents/`, Go/Python test files,
   CI workflow YAML and `Makefile`. Eligibility alone grants no exemption. A spec
   command/Expected/target/variable change is execution-affecting. For CI/Makefile,
   the reviewer must prove the changed commands were outside the recorded target
   invocation. Symlinks and submodules cannot be waived as text edits.
5. The base manifest still requires the original committed artifact. Missing,
   stale or incomplete proof fails closed. Truncated GitHub trees/comparisons are
   not accepted.

Git proves content identity and import provenance, not the semantic completeness
of `execution_paths` or the truth of a non-execution explanation. Those require
an independent substantive review of this HEAD/base. A short list containing only
PR-changed files is not sufficient dependency analysis.

`Context.accepts()` is unchanged: review judgments, disputed claims, local check
receipts and CI do not use this target-only exception. The final merge review
must still match current HEAD/base, and current-HEAD CI must pass. An actual-run
record is not a current-HEAD CI receipt. Do not change its tested SHA to HEAD.

The shared local implementation lives in `issue-to-pr/scripts/repo_evidence.py`.
The remote verifier in `pr-review-merge/scripts/review_gate.py` supplies complete
GitHub trees to the same algorithm; `pr-ready` calls that same read-only target
validator before Ready, and checks it again immediately before mutation.
