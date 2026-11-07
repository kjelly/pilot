# Merge train

kjelly/pilot#307. Merges go through one queue with one consumer, so a PR is never sent back to
`pr-ready` only because `main` moved while it waited for CI or for a review.

## Why

Before the train, both gates required the live base tip to be an ancestor of PR HEAD:

- `pr-ready` before Ready;
- `pr-review-merge` before merge.

When another PR merged in between, the PR went back to Draft. Then `pr-ready` ran a full round:
merge main, receipts, an independent review, CI, and sometimes a new target run.

From 2026-10-23 to 2026-11-06 this happened 9 times on 8 PRs, with no P0–P2 finding. Bounce to
Ready took 60 hours in total, median 3 hours. CI itself has a median of 24 minutes, and all 9 test
merges were clean.

## Rules

| Situation | Ready gate (`pr-ready`) | Merge gate (`pr-review-merge`) |
|---|---|---|
| HEAD contains the live base tip (`aligned`) | passes | MERGE → enqueued |
| HEAD lacks it; GitHub's test merge is clean and no file changed on both sides since the merge base (`train`) | passes | MERGE → enqueued; the train integrates the base |
| HEAD lacks it and the test merge conflicts (`conflict`), or a file changed on both sides (`overlap`) | error: integrate here and re-review | DRAFT (operational, no review needed) |
| GitHub has not computed mergeability, or a side changed too many files to list (`unknown`) | pending | WAITING |

Notes on the table:

- Lagging PR Base metadata alone is GitHub's to refresh. It no longer blocks.
- `review_gate.train_alignment()` classifies all four cases. `pr_gate.py` loads it from this skill,
  so both gates agree (`tests/test_pr_ready_handoff.py`).
- An independent review taken at commit R covers HEAD when one of these holds:
  - R equals HEAD;
  - every change from R to HEAD is evidence-only;
  - every change from R to HEAD is a pure import from the base: the file at R equals the fork, and
    at HEAD it equals the base.

  The last case covers the train's integration commit (`review_gate.review_covers()`,
  `repo_evidence.Context.accepts_pure_import()`). The reviewer's test entries stay bound to R; CI on
  HEAD covers the integration. Local check receipts in `pr-ready` do not use this.
- **HEAD must also carry the base's changes.** The "same bytes as R" rules above look only at paths
  where R and HEAD differ, so a merge that keeps the PR's side of a file the base changed (the `ours`
  merge strategy, a conflict resolved with the PR's version, a deletion of the base undone) differs from R
  nowhere and used to pass, while it silently reverts the base. Every review reuse therefore also
  checks, for each path the base changed since the fork F of R and the base B that HEAD contains
  (evidence-only paths excepted): HEAD holds B's bytes there, and R holds F's or B's. Otherwise the
  review does not cover HEAD: `base change not carried into HEAD: <path>`. It runs in
  `Context._non_execution_import` (both its modes: the merge gate's pure import and `pr-ready`'s
  non-execution review reuse) and before the evidence-only shortcut of those two (`_review_shortcut`).
  Check receipts and target evidence that is exactly the tested bytes keep the shortcut: a revert
  leaves the tested bytes in place, and the review is what refuses it.
- The reviewed Base must be on the live base branch: the PR's Base, or an ancestor of the live tip.
- Target evidence imports from the base HEAD actually contains (the merge base of HEAD and the live
  tip), and the manifest is read at the live tip. See `.agents/skills/_shared/target-evidence-reuse.md`.

## Queue

- **Label.** `merge-queue` (it must exist in the repository).
- **Order.** The time the label was last added: the newest `labeled` event in the PR timeline. The
  oldest goes first.
- **Enqueue.** `apply_decision.py --execute` on a MERGE gate decision calls
  `merge_train.enqueue()`, which does three things in this order:
  1. writes the gate-checked evidence to `$PRM_STATE_DIR/queue/<repo key>/<pr>.json` (mode 0600);
  2. adds the label;
  3. posts a "enqueued" comment (reviewed HEAD, and the HEAD the gate saw when it differs).

  The actor never merges. Only `--method merge` (the project default) can be enqueued.
- **What the entry holds.** The evidence, `entry_id` (a random id, new for every enqueue),
  `reviewed_head` (the HEAD the evidence names), `enqueued_head` (the HEAD the gate decided MERGE
  for), `train_commits` (every commit the train pushed to the PR branch) and `errors` (consecutive
  ERROR runs). An entry without an `entry_id`, written by a version before this one, is not trusted:
  the PR leaves the queue with "no saved review evidence" and `pr-review-merge` enqueues it again.
- **Binding.** The train works only on a PR whose HEAD is `enqueued_head` or one of `train_commits`.
  It checks this before it integrates, and again in the final step with a fresh read of the HEAD.
  Any other HEAD (a push after the enqueue, a merge of main by the author) was never gated for the
  merge, so the PR leaves the queue: "HEAD changed since it was enqueued; run `pr-review-merge`
  again". The train records its own commit in `train_commits` before it pushes it, so a crash
  between the two still leaves a HEAD it recognises. The saved review must also still cover HEAD,
  whatever the entry says. Under the lock the binding is checked against the entry as it is saved
  then, not the copy read earlier (see [Every write is guarded](#every-write-is-guarded)).
- **Leaving.** Removing the label withdraws a PR. The train reads the label at the start of every
  attempt, on every CI poll, and again under the mutation lock before every write, however late it
  notices: it then drops the saved entry it read and writes nothing to the PR (no comment, no label
  change). The train removes the label itself when it drafts or dequeues a PR, after the Draft is
  confirmed.

## Every write is guarded

The train decides on what it read, then waits for the repository mutation lock, and someone else may
act in between: push a repair, withdraw the label, make the PR a Draft, close or merge it, retarget
it, enqueue it again. A write made on the earlier read would then be wrong: a Draft and a comment
about a HEAD that was already repaired, a comment on a PR the author withdrew, the new entry of a PR
that was enqueued again deleted.

`Train._guard` is therefore the only way the train writes (a comment, the label, Draft, the merge,
the push, the saved entry). It takes the lock, then reads the saved entry, the PR and the base tip
again, and the caller writes only while all of this is what its decision was derived from:

| Compared under the lock | Refused as |
|---|---|
| the saved entry's `entry_id` (a new enqueue has a new one) | `entry-replaced` |
| the PR is open | `closed` |
| the PR is not a Draft | `drafted` |
| the `merge-queue` label is on it | `withdrawn` |
| HEAD is still the HEAD the decision used, and the entry as it is saved now binds it | `head-changed` |
| the base branch name, and the tip of that branch, are still the ones the decision used | `base-moved` |

A refusal writes nothing and returns `RETRY`: the run reloads the entry and looks at the PR again
from the top, at most `--max-align` times in one run, then WAITING (it stays enqueued). The existing
steps then give the outcome that fits what changed:

| What changed | What the next look does |
|---|---|
| the label was removed | DEQUEUED, silent: no comment, no label write; the entry that was read is dropped |
| the PR was made a Draft | DEQUEUED, silent: only the label is removed |
| the PR was closed or merged | SKIP: nothing is written; the entry is dropped |
| HEAD changed, or the author merged the base into it | DEQUEUED with "HEAD changed since it was enqueued"; no Draft and no claim about the old HEAD |
| the base moved, or the PR was retargeted | judged again against the live tip |
| the PR was enqueued again | the new entry is processed; its evidence is never overwritten, dropped or counted against |
| another actor holds the lock (or the lock cannot be created: the reason names which) | WAITING; nothing is counted (it is not an `ERROR`), the PR stays enqueued |

What each write does under the guard:

- **Draft.** Guard, comment, read again under the same lock, mark Draft, confirm `isDraft`, remove the
  label, drop the entry. Only a confirmed Draft takes the label off, so a conversion GitHub did not
  perform leaves the PR enqueued (`ERROR`, counted).
- **A voided comment.** A comment cannot be taken back. When the PR changed after the Draft comment was
  posted, the train does not mark it Draft and does not touch the label. It posts a second comment,
  "Draft comment superseded", that names the HEAD the first one judged and says the train did not
  convert the PR, and it logs `voided`. The next look decides what happens to the PR.
- **Dequeue.** Guard, comment (none for a Draft or a withdrawal), remove the label, drop the entry.
- **Merge.** Guard (HEAD the gate approved, bound by the entry as saved now; base name and tip), then
  `gh pr merge --match-head-commit`, then verify `MERGED`, then drop the entry. A refusal waits
  (`PR state/HEAD/base changed immediately before the merge`), except a withdrawal (silent dequeue),
  a closed PR (SKIP) and an entry that was replaced (looked at again). An unconfirmed merge stays
  enqueued, `ERROR`, counted.
- **Push.** Guard, record the commit in `train_commits` of the entry as saved now, push without force.
- **Error count.** Guard, then the count is written to the entry the failing run acted on; a run whose
  entry was replaced counts nothing, and a busy lock counts nothing either.

The window that cannot be closed: GitHub has no compare-and-swap for a comment, a label or Draft, so
a change between the last read under the lock and the write itself is not visible. Two writes have one
on the remote: the merge (`--match-head-commit`) and the push (never forced) are refused when the HEAD
moved. For Draft the train reads the PR after the request and logs when the HEAD moved in the
meantime; the Draft stands. The base tip is not compared by the merge on the remote (kjelly/pilot#309).
`tests/test_merge_train_guard.py` drives every write site through each of these moments with the real
`Train.run`, and a lint over `class Train` fails when any write is outside `with self._guard(...)`.

## Consumer

```bash
python3 "$SNAP/.agents/skills/pr-review-merge/scripts/merge_train.py" process \
  --repo kjelly/pilot --worktree ~/.cache/pr-review-merge/train/pilot.git
python3 "$SNAP/.agents/skills/pr-review-merge/scripts/merge_train.py" status --repo kjelly/pilot
```

- **Worktree.** `--worktree` is a dedicated clone of the repository with an `origin` remote; a bare
  one is enough: `git clone --bare https://github.com/kjelly/pilot ~/.cache/pr-review-merge/train/pilot.git`.
  - The consumer never checks anything out. It fetches into `refs/merge-train/*`, builds the merge
    commit with Git's `merge-tree --write-tree` and `commit-tree` (Git 2.38 or later), and pushes
    the commit object to the PR branch without force.
  - Commit identity comes from that clone's `user.name`/`user.email` or the `GIT_*` environment.
- **One consumer.** Each repository and host runs at most one consumer, guarded by a `flock` in
  `$PRM_STATE_DIR/locks`. A second one prints `BUSY` and exits 0.
- **Mutation lock.** Every write (pushes, merges, comments, label changes, Draft conversions and
  the saved entry) is made while holding the actor's repository mutation lock, after the guard has
  read the PR again. A lock another actor holds is WAITING, not an error.

The consumer takes the oldest PR in the queue and:

1. Load the entry and the PR, and check them:
   - Closed: skip it.
   - Draft: leave the queue silently.
   - Label removed: drop the entry, silently.
   - No saved evidence, or a fork PR: leave the queue with a comment.
   - HEAD neither the enqueued one nor a train commit: leave the queue with a comment.

   Each of these outcomes is a write made through the guard; when the guard refuses, this step starts
   again from the entry.
2. Fetch the PR head (`refs/pull/<n>/head`) and the base branch into `refs/merge-train/*`, on every
   attempt and on every path: the long-lived clone holds neither, and the secret scan of the PR's
   commits and the merge both need them. The fetched head must equal the PR's `headRefOid`; if GitHub
   has not caught up, retry at most `--max-align` times, then WAITING.
3. Classify alignment.
   - `conflict`/`overlap`: Draft with the reason (guarded; see [Every write is guarded](#every-write-is-guarded)).
   - `unknown`: mergeability not computed or an API failure: poll; after `--max-align` tries,
     WAITING. A comparison GitHub cut at 300 files: leave the queue (a person must integrate).
   - `train`:
     1. Build the merge of exactly the live tip.
     2. Check every file the merge changes against the base (defense in depth if GitHub's file
        lists are wrong).
     3. Push, under the mutation lock, after re-reading the entry and the PR (entry id, state, label,
        HEAD, Draft, base). The push is never forced: a PR branch that moved since is refused by Git
        and nothing is overwritten.
     4. Repeat at most `--max-align` times when the base keeps moving, then WAITING.
4. Wait for CI on HEAD. Checks that have not registered count as pending for 5 minutes.
   - The base moved: back to step 3.
   - HEAD changed outside the train: leave the queue, so a new review is needed.
   - Label removed, PR closed or made Draft: back to step 1.
   - `--ci-timeout`: WAITING.
5. Finish:
   - The saved review no longer covers HEAD: leave the queue (needs a new `pr-review-merge` run).
   - The target record no longer covers HEAD (for example, main brought in a `rerun_paths` file):
     Draft, so `pr-ready` runs the chain again or records `unrelated_runtime_changes`.
   - A GitHub or infrastructure failure while checking either of those: WAITING. A failure to read
     says nothing about the review or the record, so it never dequeues or drafts the PR.
   - Otherwise rerun `review_gate.evaluate()` with the saved evidence:
     - MERGE: under the mutation lock, re-read the entry and the PR (entry id, state, label, HEAD and
       that the entry binds it, base, Draft) and run `gh pr merge --merge --match-head-commit`, then
       verify MERGED and only then drop the entry.
     - DRAFT: Draft with the reasons.
     - WAITING: transient or needs a person, see below.

### Transient or needs a person

A WAITING gate result carries `wait_kind`. Every reason is registered where `review_gate.evaluate()`
emits it (`WaitKinds`); a reason nobody registered needs a person.

| `wait_kind` | Which reasons | The train |
|---|---|---|
| `transient` | CI pending; the PR or base moved during the gate; mergeability or merge state (`UNKNOWN`, `BEHIND`) GitHub has not computed; an API or infrastructure failure (PR, base, ancestry, checks, threads, rules, review coverage, target record, base manifest); a secret scan that could not run; the mutation lock held by another actor | stays enqueued; the run stops (nothing the train does changes the answer, so the PRs behind it keep their place) |
| `person` | requested changes; approval required (by decision or by rule); a failing check the reviewer confirmed unrelated; a finding disputed without new evidence; a merge state that is not clean for another reason (`BLOCKED`, `UNSTABLE`, ...); stale or invalid review evidence; no CI without a rationale; a branch with a GitHub merge queue; auto-merge already set; a comparison GitHub cut | leaves the queue with a comment that lists the reasons; the PR stays Ready; **the PRs behind it keep going** |

A merge state that is not clean is `derived`: it says only that something else is wrong, so it keeps
a PR enqueued when another transient reason (a pending check) explains it, and needs a person alone.
A transient reason next to a reason that needs a person needs a person.

The run stops at the first WAITING or ERROR, so later PRs keep their place; a PR that leaves the
queue (`MERGED`, `DRAFTED`, `DEQUEUED`, `SKIP`) does not stop it. Outcomes are `MERGED`, `DRAFTED`,
`DEQUEUED`, `WAITING`, `SKIP` and `ERROR`. A PR that ends in `ERROR` on three runs in a row (the
count is in its entry; a run that ends any other way resets it) leaves the queue with a comment
naming the last error, so one persistent error cannot stop the others for ever. A lock another actor
holds, a write the guard refused and an entry that was replaced are not errors and are not counted.

## Running it

The consumer must run for anything to merge. Two options:

**A user timer on the host.** Example; adjust the paths, and run `loginctl enable-linger` if it
should run while logged out:

```ini
# ~/.config/systemd/user/pilot-merge-train.service
[Unit]
Description=pilot merge train (kjelly/pilot#307)

[Service]
Type=oneshot
WorkingDirectory=%h/github/pilot
ExecStart=/usr/bin/python3 %h/github/pilot/.agents/skills/pr-review-merge/scripts/merge_train.py process --repo kjelly/pilot --worktree %h/.cache/pr-review-merge/train/pilot.git

# ~/.config/systemd/user/pilot-merge-train.timer
[Timer]
OnBootSec=2min
OnUnitActiveSec=3min

[Install]
WantedBy=timers.target
```

Then `systemctl --user enable --now pilot-merge-train.timer`. The service runs the script from a
checkout. Keep that checkout on an up-to-date `main`, since the script is the policy.

**By hand.** After `pr-review-merge` reports `ENQUEUED`, run `merge_train.py process --pr N` attached once.
It processes only that PR, and only when it is first in the queue (`NOT_AT_HEAD` otherwise), which
keeps a `pr-review-merge` invocation single-item. `BUSY` means a consumer is already running.

## Limits

- **Single host.** Saved evidence and the locks are local to this host. A consumer on another host
  finds no evidence and dequeues the PR. Run every `pr-review-merge` and the consumer on the same
  host.
- **Cooperation.** A person merging by hand or another tool is not blocked. The live checks and
  `--match-head-commit` keep the train correct; the train only integrates again. A change in the
  moment between the last read and a comment, a label change or Draft is not visible to anyone (see
  [Every write is guarded](#every-write-is-guarded)).
- **No batching.** PRs are tested one at a time, not several merged together. With about 6 merges a
  day, one PR at a time (about 25 minutes each) allows about 50 a day.
- **Same repository only.** Fork PRs are dequeued, because the train pushes only to this
  repository's branches.
