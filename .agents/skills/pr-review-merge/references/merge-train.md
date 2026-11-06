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
  3. posts a "enqueued" comment.

  The actor never merges. Only `--method merge` (the project default) can be enqueued.
- **Leaving.** Removing the label takes a PR out of the queue. The train removes it when it drafts or
  dequeues a PR.

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
- **Mutation lock.** Pushes, merges, comments and Draft conversions also take the actor's
  repository mutation lock.

The consumer takes the oldest PR in the queue and:

1. Check the entry:
   - Closed: skip it.
   - Draft: leave the queue silently.
   - No saved evidence, or a fork PR: leave the queue with a comment.
2. Classify alignment.
   - `conflict`/`overlap`: Draft with the reason.
   - `unknown`: poll; after `--max-align` tries, WAITING.
   - `train`:
     1. Fetch the PR head and base.
     2. Build the merge of exactly the live tip.
     3. Check every file the merge changes against the base (defense in depth if GitHub's file
        lists are wrong).
     4. Push.
     5. Repeat at most `--max-align` times when the base keeps moving, then WAITING.
3. Wait for CI on HEAD. Checks that have not registered count as pending for 5 minutes.
   - The base moved: back to step 2.
   - HEAD changed outside the train: leave the queue, so a new review is needed.
   - `--ci-timeout`: WAITING.
4. Finish:
   - The saved review no longer covers HEAD: leave the queue (needs a new `pr-review-merge` run).
   - The target record no longer covers HEAD (for example, main brought in a `rerun_paths` file):
     Draft, so `pr-ready` runs the chain again or records `unrelated_runtime_changes`.
   - Otherwise rerun `review_gate.evaluate()` with the saved evidence:
     - MERGE: `gh pr merge --merge --match-head-commit`, then verify MERGED.
     - DRAFT: Draft with the reasons.
     - WAITING: stays enqueued.

The run stops at the first WAITING or ERROR, so later PRs keep their place. Outcomes are `MERGED`,
`DRAFTED`, `DEQUEUED`, `WAITING`, `SKIP` and `ERROR`.

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
  `--match-head-commit` keep the train correct; the train only integrates again.
- **No batching.** PRs are tested one at a time, not several merged together. With about 6 merges a
  day, one PR at a time (about 25 minutes each) allows about 50 a day.
- **Same repository only.** Fork PRs are dequeued, because the train pushes only to this
  repository's branches.
