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

## Machine-generated records

When the committed artifact has the `pilot-evidence-record` marker, all three
workflows read its JSON directly. The reviewer omits `execution_paths`; supplied
paths cannot narrow the machine closure. The gate binds candidate commit/tree,
clean status, successful outcome and every recorded mode/blob to the candidate,
then compares those files with HEAD. Search patterns also bind membership, so a
new include glob match, copied directory member or earlier search-path match
requires a new run even when all old files are unchanged.

Unresolved references, external inputs, malformed records and older machine
records without `closure.patterns`, `closure.resolution_version: 8`, or
`closure.frozen: true` fail closed. Run again with resolved inputs
instead of overriding the machine result with a manual list. Legacy hand-written
records retain the full manual dependency review above. The independent reviewer
still confirms the current HEAD/base and audits non-execution changes; runtime
changes outside the closure must pass the pure-base-import proof. A changed spec
in the closure cannot be waived as prose. New records keep LATEST outside specs,
so retests do not change their blobs.

Resolver version 8 additionally refuses backslash-bearing key=value payloads (the
Ansible escape grammar is not evaluated); JSON/YAML mappings use their parser.
Version 7 and older records are not eligible for automatic reuse.

Resolver version 8 proves the task dispatch subset only for direct copy with
proved literal argument mappings and debug with a literal scalar `msg` (optional
literal integer verbosity). Templates, implicit/free-form expressions, other
actions and unproved metadata remain unresolved even when known source files
are hashed. Default ambient records retain unresolved plugin/collection/Python discovery;
exact-candidate evidence remains usable. The opt-in `--evidence-controller=pinned`
profile builds the committed digest-pinned recipe, resolves its immutable image ID,
and actually routes all L1/L3/L4/L6 Ansible subprocesses and the whole L5 pilot child
through that image. Fresh private HOME/tmp, read-only mounts, fixed config and a
scrubbed environment isolate each subprocess. The fixed image account and supported host UID/GID1000 avoid host NSS database mounts; actual NSS and non-connecting OpenSSH probes must succeed. Native pre/post probes must agree on
effective origins, config and search paths. The shared local/remote gate validates
the typed profile hashes against candidate closure blobs, image/binary/inventory
identities, native probe fingerprint, all required routed stages and successful
recorded verdicts. A selection flag or boolean alone never clears ambient refusal.

Eligible controlled records also bind the actual static pilot binary BuildInfo to
Go1.26.8/linux/amd64/v1/CGO=0, -trimpath and -buildvcs=false and the pinned OCI toolchain. Offline readonly module
verification and complete `go list` output must match actual binary dependency
versions/sums. A reproducible pinned-Go rebuild must match the entire actual executed binary SHA-256; source/settings/module identity alone cannot certify a stale executable. The controller/v2 proof includes that rebuilt identity and source graph fingerprint. Scope includes transitive repository package sources, package source
membership, embed subtrees, go.mod/go.sum and workspace/vendor absence. Replacements,
workspace/cgo/custom build contexts and partial listings remain unresolved. A new
unimported package remains outside the execution graph. Initial eligibility is
limited to V1 verification and proved pilot-rendered SSH inventory; actual matched
host/group/ancestor vars candidates and missing memberships are tracked.

The zero-unresolved/external gate stays mandatory. Synthetic typed proof fixtures
exercise adapter mechanics only; real OCI constructor/source-graph tests and actual
generated target records separately demonstrate the supported positive path.
