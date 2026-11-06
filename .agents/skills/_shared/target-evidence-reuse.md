# Target evidence after integrating the base branch

This rule applies to every PR in this repository, through `issue-to-pr`, `pr-ready`
and `pr-review-merge`. It is a conditional reuse of a **target-run record**, not a
waiver for merging main. The manifest on the current base must declare
`required_evidence[].kind: target-run`; untyped required records, including CI or
coverage URLs, retain the existing strict comparison.

The default remains exact candidate/HEAD equality or an evidence-only delta. Two
more ways keep the record after an advanced base is merged into the candidate
branch:

- **Declared non-execution import (no attestation).** When every file main brought
  in is one the base manifest declares a target run never reads, the gate keeps the
  record by itself (see "Declared non-execution imports" below).
- **Reviewed import.** Otherwise a fresh independent reviewer may add `target_reuse`
  to the required target record. `issue-to-pr` puts it on the
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
   base. The Ready and merge gates (`pr-ready`, `pr-review-merge`) use the **integrated
   base**: the newest base commit HEAD contains (merge base of HEAD and the live tip), since
   the merge train integrates the live tip before merging (kjelly/pilot#307); at the train's
   final gate HEAD contains the live tip, so the two coincide. They read the manifest at the
   live tip. `issue-to-pr` keeps the live base, which HEAD must contain. The local verifier also refuses a candidate and base with more than one merge
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
receipts and CI do not use the reviewed exception. The one exception for reviews is
the declared non-execution import below (`Context.accepts_review`, used by
`pr-ready`'s gate for `independent_review` only). The final merge review
must still match current HEAD/base, and current-HEAD CI must pass. An actual-run
record is not a current-HEAD CI receipt. Do not change its tested SHA to HEAD.

The shared local implementation lives in `issue-to-pr/scripts/repo_evidence.py`.
The remote verifier in `pr-review-merge/scripts/review_gate.py` supplies complete
GitHub trees to the same algorithm; `pr-ready` calls that same read-only target
validator before Ready, and checks it again immediately before mutation.

## Declared non-execution imports

The base manifest may declare, at top level, `non_execution_paths` (globs of files a
target run never reads) and `non_execution_exclude` (globs that never count, even
when a `non_execution_paths` glob matches). A path matching a `required_paths` glob of
any required record is never non-execution either. This repository declares agent
skills (`.agents/**`), top-level and `docs/` Markdown except specs
(`docs/verification/**`), Go test files and `.github/**`: the pilot binary is built
without `*_test.go`, and no playbook, spec, contract or inventory reads the others.

For a `kind: target-run` record, with no `target_reuse` at all, the gate accepts the
original candidate when:

1. the candidate and the current base are ancestors of HEAD, from a single common fork
   that predates both (the same topology as check 1 above);
2. every path changed from the candidate to HEAD is evidence-only, or a pure base
   import (candidate equals the fork, HEAD equals the current base) of a regular file
   that is a declared non-execution path. A PR-side edit, a merged blend of both sides,
   a symlink or a submodule is not;
3. for a machine record, the record itself still holds (candidate commit/tree, clean,
   successful, `resolution_version: 10`, frozen, recorded blobs and search membership),
   and nothing in its closure can reach an imported path: not a closure file, not a
   search pattern, not the `from` of an unresolved entry, and not an unresolved or
   external reference read as a suffix glob (a Jinja expression becomes `*`; labels,
   absolute paths and references that are only a variable name match nothing). The
   closure may have unresolved or external inputs: the question is only whether an
   imported file can be an input, and the same record is accepted at its exact
   candidate. A hand-written record has no closure to consult and relies on the
   declaration.

`pr-ready`'s gate applies the same proof to `independent_review`: the PR's own content
is byte-identical to what was reviewed. Local check receipts never use it: an imported
Go test must run against the PR's code, so receipts are rerun for the packages the
import touches, and current-HEAD CI is required as before. Accepted imports are
reported under `delta_accepted` with `method: non-execution-base-import`.

## Machine-generated records

When the committed artifact has the `pilot-evidence-record` marker, all three
workflows read its JSON directly. The reviewer omits `execution_paths`; supplied
paths cannot narrow the machine closure. The gate binds candidate commit/tree,
clean status, successful outcome and every recorded mode/blob to the candidate,
then compares those files with HEAD. Search patterns also bind membership, so a
new include glob match, copied directory member or earlier search-path match
requires a new run even when all old files are unchanged.

Malformed records and older machine records without `closure.patterns`,
`closure.resolution_version: 10`, or `closure.frozen: true` fail closed. Unresolved
references and external inputs fail the reviewed path closed unless the record's
manifest item declares `rerun_paths` (see "Reviewed imports outside an incomplete
closure" below). Run again with resolved inputs
instead of overriding the machine result with a manual list. Legacy hand-written
records retain the full manual dependency review above. The independent reviewer
still confirms the current HEAD/base and audits non-execution changes; runtime
changes outside the closure must pass the pure-base-import proof. A changed spec
in the closure cannot be waived as prose. New records keep LATEST outside specs,
so retests do not change their blobs.

Resolver version 10 additionally refuses backslash-bearing key=value payloads (the
Ansible escape grammar is not evaluated); JSON/YAML mappings use their parser.
Version 9 and older records are not eligible for automatic reuse.

Resolver version 10 proves the task dispatch subset only for direct copy with
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
versions/sums. The actual ELF must have no interpreter, dynamic segment or dynamic section; CGO=0 alone does not exclude native loader dependencies. A reproducible pinned-Go rebuild must match the entire actual executed binary SHA-256; source/settings/module identity alone cannot certify a stale executable. The controller/v3 proof includes that rebuilt identity and source graph fingerprint. Scope includes transitive repository package sources, package source
membership (all direct names), ignored Go/native-source bytes (including build-tag activation), embed subtrees, go.mod/go.sum and workspace/vendor absence. Replacements,
workspace/cgo/custom build contexts and partial listings remain unresolved.
Candidate-selected assembly and system objects are unsupported, with no accepted
partial Go proof. Verified module assembly is admitted only after the profile's
native audit proves every raw `#` is a whole-line literal basename include,
without package/CWD, renamed HFiles or generated-header shadows. Module HFiles,
SysoFiles, other preprocessor syntax and a non-closed pinned SDK header tree
remain unresolved. Standard-library assembly stays within the pinned SDK trust
boundary. Resolver 9 records omitted consumed assembly headers and cannot be reused. A new
unimported package remains outside the execution graph. Initial eligibility is
limited to V1 verification and proved pilot-rendered SSH inventory; actual matched
host/group/ancestor vars candidates and missing memberships are tracked.

The zero-unresolved/external gate stays mandatory. Synthetic typed proof fixtures
exercise adapter mechanics only; real OCI constructor/source-graph tests and actual
generated target records separately demonstrate the supported positive path.

The profile pins the complete ansible.posix collection bytes. Native callback
origin/manifest hashes and a real JSON callback command execution must agree
before/after the chain. Whole L5 exports bounded compact NDJSON frames through
captured stderr before container removal; raw frames participate in redaction and
sanitized typed rows persist in the record. The shared gate requires complete
row diagnostics, successful probe/rc/status, summary counts and every selected
host at an exact host/group limit. Missing export, malformed frames or partial
rows cannot be replaced by an aggregate PASS. Decoded V1 command expressions or argument escapes
that can perform controller-side Jinja lookups retain unresolved markers.

## Reviewed imports outside an incomplete closure

A machine record from the default (ambient) controller never has a complete closure:
resolver version 10 proves only literal `copy` and `debug.msg`, so templates, facts,
assertions, includes and every Jinja or `when:` expression stay unresolved, and a vault
is always external. `--evidence-controller=pinned` clears only the ambient entries. For
such a record the reviewed path above would never apply, and every base integration
that brought in runtime files would need a new run.

When the record's `kind: target-run` manifest item declares `rerun_paths`, the reviewed
path accepts a machine record whose closure has unresolved or external inputs. The
machine closure still supplies `execution_paths`, the controller proof is not required
(it answers whether the closure is complete, which this path does not rely on), and
`target_reuse` adds one list:

```json
"unrelated_runtime_changes": [
  {"path": "playbooks/apply/other-component-apply.yml",
   "reason": "Another component's playbook: no include, lookup, template or spec of this run names it."}
]
```

Every changed path from the candidate to HEAD must then be evidence-only, an audited
non-execution edit (check 4 above), or a pure base import, and each pure base import
must pass, in this order:

1. nothing in the closure can reach it (the same closure-reach test as the declared
   non-execution import): a recorded input cannot be explained away;
2. it is a regular file;
3. it is a declared non-execution path (no entry needed), or
4. it matches no `rerun_paths` glob: those always need a new run, whatever the
   explanation. This repository lists the compiled pilot sources (`cmd/**`,
   `internal/**`, every non-test `.go`, `go.mod`/`go.sum`/`go.work*`), since a default
   record has no Go closure, plus `images/**`, `contracts/**`, `group_vars/**`,
   `host_vars/**`, `ansible.cfg`, `requirements.yml` and the shared playbook
   `tasks/`, `templates/` and `files/` directories, which dynamic includes and
   lookups reach;
5. it has an `unrelated_runtime_changes` entry (exact path, 30+ character reason).

An entry must name a changed path, once, outside `execution_paths` and the audited
edits. Entries on a hand-written record, or on a machine record with a complete closure,
are refused: those already accept pure base imports outside their scope. Without
`rerun_paths` on the item, an incomplete closure fails closed as before. Accepted
reviews are reported with `closure_complete: false` and the entries.

What remains the reviewer's judgment: that an imported runtime file outside the closure
is not named by a reference the resolver could not read (a variable path, a computed
include). A file the closure names, or a path in `rerun_paths`, is never left to it.

## Merge train

After `pr-review-merge` queues a PR, its merge train may push one commit that merges the live
base tip into the PR (clean merge, every changed file equal to the base). For the target record
that commit is an ordinary pure base import: the rules above decide whether the record still
covers the new HEAD, and if not the train returns the PR to Draft for `pr-ready`. The independent
review carries across it as a pure import of any files (`Context.accepts_pure_import`); check
receipts never do. Details: `pr-review-merge/references/merge-train.md`.
