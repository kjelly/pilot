#!/usr/bin/env python3
"""Read-only preflight before switching the current checkout to another branch.

The single-item skills (issue-to-pr, pr-ready, pr-review-merge) switch the one
clean checkout to the selected item's branch. `git status --porcelain` is not a
sufficient guard for that: git treats *ignored* files as expendable, so a
switch silently overwrites an ignored `local.cfg` that the target branch tracks
(and deletes it again on the way back), and silently removes an ignored file
that stands where the target needs a directory (or the reverse). This script
refuses every case where that, or another silent loss, could happen.

Usage:
    checkout_preflight.py --target-ref SHA_OR_REF [--target-ref ...] [--branch NAME] [--repo DIR]

`--target-ref` is a commit whose tree may be checked out (fetch it first). It
is repeatable: every commit that can land in the working tree must be listed,
because the preflight checks each one. `--branch` is the local branch that will
be checked out. It is used for the "already checked out elsewhere" check, and
its existing local tip is checked as one more target: `git switch BRANCH` and
`gh pr checkout` first check out that tip, which can be stale and track other
paths than the fetched head. Prints one JSON object. Exit 0 = PASS; exit 1 =
STOP (a problem was found, or a check could not be run: fail closed). Any other
exit code (argument errors) is also not a pass. The script changes nothing in
the repository.

Restore check, at the end of an invocation:
    checkout_preflight.py --restore-check --start-sha SHA [--start-branch NAME]
                          [--checked-out-sha SHA] [--repo DIR]

Is it safe to switch the checkout back to where the invocation started
(`--start-branch`, or the detached `--start-sha` when HEAD started detached)?
PASS (exit 0) requires all of: the checkout is clean; the current branch has no
unpushed commits (its upstream exists and `@{u}..HEAD` is empty, or HEAD is still
`--checked-out-sha`, the commit the branch was checked out at, so nothing was
written locally: always so for pr-review-merge, also after a merge whose remote
branch GitHub deleted); and the ordinary preflight passes for the start SHA and
the start branch's local tip (ignored-file collisions, checked out elsewhere,
...). The report carries `switch_command`, which the caller runs itself; this
script never switches.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

MAX_PATHS = 50
IN_PROGRESS = ("rebase-merge", "rebase-apply", "MERGE_HEAD", "CHERRY_PICK_HEAD",
               "REVERT_HEAD", "BISECT_LOG", "sequencer")


class GitError(Exception):
    """A git command needed for a check failed, so the check cannot be trusted."""


def git(repo: Path, *args: str, ok: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess:
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", LC_ALL="C")
    p = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, env=env)
    if p.returncode not in ok:
        err = p.stderr.decode(errors="replace").strip()[:300]
        raise GitError(f"git {' '.join(args)} failed (rc={p.returncode}): {err}")
    return p


def split_z(data: bytes) -> list[str]:
    return [os.fsdecode(item) for item in data.split(b"\0") if item]


def problem(check: str, detail: str, paths: list[str] | None = None, target: str | None = None) -> dict:
    out: dict = {"check": check, "detail": detail}
    if target:
        out["target"] = target
    if paths:
        out["count"] = len(paths)
        out["paths"] = sorted(paths)[:MAX_PATHS]
    return out


def proper_prefixes(path: str):
    parts = path.split("/")
    for i in range(1, len(parts)):
        yield "/".join(parts[:i])


def check_dirty(top: Path) -> list[dict]:
    # --ignore-submodules=none: diff.ignoreSubmodules / .gitmodules `ignore` must not hide a dirty submodule
    entries = split_z(git(top, "status", "--porcelain=v1", "-z", "--untracked-files=all",
                          "--ignore-submodules=none").stdout)
    if not entries:
        return []
    return [problem("dirty", "tracked changes or untracked files; never stash, discard or "
                    "overwrite user work", entries)]


def check_in_progress(top: Path) -> list[dict]:
    found = []
    for name in IN_PROGRESS:
        raw = git(top, "rev-parse", "--git-path", name).stdout.decode().strip()
        path = Path(raw) if os.path.isabs(raw) else top / raw
        if path.exists():
            found.append(name)
    if not found:
        return []
    return [problem("operation_in_progress", "finish or abort the git operation first", found)]


def check_detached(top: Path) -> list[dict]:
    p = git(top, "symbolic-ref", "--quiet", "HEAD", ok=(0, 1))
    if p.returncode == 0:
        return []
    contained = git(top, "for-each-ref", "--contains", "HEAD", "--count=1",
                    "--format=%(refname)").stdout.strip()
    if contained:
        return []
    return [problem("detached_head_unreachable",
                    "HEAD is detached at a commit no branch or tag contains; switching away "
                    "would orphan it")]


def worktrees(top: Path) -> list[dict]:
    blocks: list[dict] = []
    current: dict = {}
    for line in git(top, "worktree", "list", "--porcelain").stdout.decode(errors="replace").splitlines():
        if not line.strip():
            if current:
                blocks.append(current)
            current = {}
            continue
        key, _, value = line.partition(" ")
        current[key] = value
    if current:
        blocks.append(current)
    return blocks


def check_checked_out_elsewhere(top: Path, branch: str) -> list[dict]:
    here = os.path.realpath(top)
    ref = f"refs/heads/{branch}"
    elsewhere = [w["worktree"] for w in worktrees(top)
                 if w.get("branch") == ref and os.path.realpath(w["worktree"]) != here]
    if not elsewhere:
        return []
    return [problem("checked_out_elsewhere", f"branch {branch} is checked out in another "
                    "worktree; do not force it or silently switch directories", elsewhere)]


def ignored_entries(top: Path) -> tuple[set[str], set[str]]:
    """(ignored files, ignored directory-shaped entries) of the working tree.

    `git ls-files --others --ignored --exclude-standard` lists every ignored file
    and nothing else, except that a nested git repository (a directory with its
    own .git, tracked or not by anyone) is listed as one entry with a trailing
    slash (`vendor/x/`), whatever it contains. Empty directories are not listed.
    """
    files: set[str] = set()
    dirs: set[str] = set()
    for entry in split_z(git(top, "ls-files", "-z", "--others", "--ignored",
                             "--exclude-standard").stdout):
        if entry.endswith("/"):
            dirs.add(entry.rstrip("/"))
        else:
            files.add(entry)
    return files, dirs


def check_ignored_collisions(top: Path, label: str, target: str,
                             ignored: tuple[set[str], set[str]]) -> list[dict]:
    """Ignored paths the switch to `target` would overwrite, remove or write into.

    With a clean `git status` every untracked path is ignored, so these are
    exactly the paths git considers expendable. Ways to lose one:
      * the target tracks the same path (it is overwritten);
      * the target tracks a directory where the ignored file `a` stands
        (the file is removed to make room: target tracks `a/b`);
      * the target tracks a file where an ignored directory stands
        (its ignored files are removed: ignored `a/b`, target tracks `a`);
      * the target tracks any path below an ignored nested repository entry
        (`vendor/x/`): its content is unknown, so every path under it counts.
    """
    files, dirs = ignored
    if not files and not dirs:
        return []
    tracked = set(split_z(git(top, "ls-tree", "-r", "-z", "--name-only", "--full-tree",
                              target).stdout))
    tracked_dirs = {d for t in tracked for d in proper_prefixes(t)}
    holding_dirs = {d for i in files for d in proper_prefixes(i)}
    holding_dirs |= dirs | {d for e in dirs for d in proper_prefixes(e)}
    found = []
    for paths, detail in (
        (files & tracked, "ignored file would be overwritten by a file the target tracks "
                          "(git does not warn about ignored files)"),
        (files & tracked_dirs, "ignored file would be deleted: the target tracks files "
                               "below that path"),
        (tracked & holding_dirs, "ignored files below this path would be deleted: the target "
                                 "tracks a file there"),
        ({t for t in tracked if any(p in dirs for p in proper_prefixes(t))},
         "tracked path of the target lies inside an ignored nested repository or directory "
         "entry; git writes into it and overwrites whatever is there"),
    ):
        if paths:
            found.append(problem("ignored_collision", detail, list(paths), target=label))
    return found


def resolve_targets(top: Path, refs: list[str], branch: str | None,
                    problems: list[dict]) -> list[dict]:
    """Resolve every commit that may be checked out; the local branch tip is one of them."""
    wanted = [(ref, "target-ref") for ref in refs]
    if branch:
        wanted.append((f"refs/heads/{branch}", "local branch tip"))
    targets: list[dict] = []
    for ref, source in wanted:
        sha = git(top, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}",
                  ok=(0, 1)).stdout.decode().strip()
        if not sha:
            if source == "target-ref":
                problems.append(problem("unresolvable_target", f"{ref} is not a commit "
                                        "in this repository; fetch it first"))
            continue  # no local branch yet: nothing stale to check out
        if all(t["sha"] != sha for t in targets):
            targets.append({"ref": ref, "sha": sha, "source": source})
    return targets


def run_preflight(repo: Path, target_refs: list[str], branch: str | None) -> dict:
    report: dict = {"status": "STOP", "repo": str(repo), "target_refs": target_refs,
                    "branch": branch, "problems": []}
    problems: list[dict] = report["problems"]
    try:
        top = Path(git(repo, "rev-parse", "--show-toplevel").stdout.decode().strip())
        report["toplevel"] = str(top)
        head = git(top, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", ok=(0, 1))
        report["head"] = head.stdout.decode().strip() or None
        cur = git(top, "symbolic-ref", "--quiet", "--short", "HEAD", ok=(0, 1))
        report["current_branch"] = cur.stdout.decode().strip() or None
        targets = resolve_targets(top, target_refs, branch, problems)
        report["targets"] = targets
        report["target"] = targets[0]["sha"] if targets else None
        problems += check_dirty(top)
        problems += check_in_progress(top)
        if report["head"]:
            problems += check_detached(top)
        if branch:
            problems += check_checked_out_elsewhere(top, branch)
        if targets:
            ignored = ignored_entries(top)
            for t in targets:
                problems += check_ignored_collisions(top, t["ref"], t["sha"], ignored)
    except (GitError, OSError) as exc:
        problems.append(problem("unverifiable", str(exc)))
    if not problems:
        report["status"] = "PASS"
    return report


def check_unpushed(top: Path, branch: str | None, head: str | None,
                   checked_out_sha: str | None) -> tuple[list[dict], list[str]]:
    """Problems that mean commits of the selected branch could be lost by leaving it."""
    if checked_out_sha:
        if head == checked_out_sha:
            return [], []  # nothing was written locally
        return [problem("head_moved", f"HEAD is {head}, not the commit {checked_out_sha} the branch "
                        "was checked out at: something was committed locally")], []
    if not branch:
        return [problem("no_upstream", "HEAD is detached: nothing shows its commits are pushed")], []
    p = git(top, "rev-parse", "--abbrev-ref", "--symbolic-full-name", f"{branch}@{{upstream}}",
            ok=(0, 128))
    if p.returncode:
        return [problem("no_upstream", f"branch {branch} has no (or a deleted) upstream: nothing "
                        "shows its commits are pushed")], []
    ahead = git(top, "rev-list", f"{branch}@{{upstream}}..{branch}").stdout.decode().split()
    if ahead:
        return [problem("unpushed_commits", f"branch {branch} has commits its upstream "
                        f"{p.stdout.decode().strip()} does not", ahead)], ahead
    return [], []


def run_restore_check(repo: Path, start_sha: str, start_branch: str | None,
                      checked_out_sha: str | None) -> dict:
    report: dict = {"status": "STOP", "mode": "restore-check", "repo": str(repo),
                    "start_sha": start_sha, "start_branch": start_branch,
                    "checked_out_sha": checked_out_sha, "problems": [], "restore_needed": True,
                    "switch_command": None}
    problems: list[dict] = report["problems"]
    try:
        top = Path(git(repo, "rev-parse", "--show-toplevel").stdout.decode().strip())
        head = git(top, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", ok=(0, 1)).stdout.decode().strip()
        cur = git(top, "symbolic-ref", "--quiet", "--short", "HEAD", ok=(0, 1)).stdout.decode().strip() or None
        report.update(toplevel=str(top), head=head or None, current_branch=cur)
        start = git(top, "rev-parse", "--verify", "--quiet", f"{start_sha}^{{commit}}",
                    ok=(0, 1)).stdout.decode().strip()
        if not start:
            problems.append(problem("unresolvable_target", f"start commit {start_sha} is not in "
                                    "this repository"))
        elif (start_branch and cur == start_branch) or (not start_branch and cur is None and head == start):
            report.update(restore_needed=False, switch_command=None)  # already where it started
            report["status"] = "PASS"
            return report
        if start_branch:
            tip = git(top, "rev-parse", "--verify", "--quiet", f"refs/heads/{start_branch}^{{commit}}",
                      ok=(0, 1)).stdout.decode().strip()
            if not tip:
                problems.append(problem("start_branch_missing", f"local branch {start_branch} no "
                                        "longer exists; `git switch` could recreate it from a remote"))
            report["start_branch_tip"] = tip or None
            report["tip_moved"] = bool(tip and start and tip != start)
            report["switch_command"] = ["git", "switch", start_branch]
        else:
            report["switch_command"] = ["git", "switch", "--detach", start]
        unpushed, ahead = check_unpushed(top, cur, head or None, checked_out_sha)
        problems += unpushed
        report["unpushed"] = ahead
        if start:
            inner = run_preflight(repo, [start], start_branch)
            problems += inner["problems"]
    except (GitError, OSError) as exc:
        problems.append(problem("unverifiable", str(exc)))
    if not problems:
        report["status"] = "PASS"
    else:
        report["switch_command"] = None  # not safe: the caller must stay on the branch
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--repo", type=Path, default=Path("."), help="the current checkout")
    parser.add_argument("--target-ref", action="append",
                        help="commit-ish that may be checked out (repeatable)")
    parser.add_argument("--branch", help="local branch that will be checked out; its local tip "
                        "is checked too")
    parser.add_argument("--restore-check", action="store_true",
                        help="is it safe to switch back to the starting branch/commit?")
    parser.add_argument("--start-sha", help="restore check: the HEAD the invocation started at")
    parser.add_argument("--start-branch", help="restore check: the branch it started on "
                        "(omit when HEAD started detached)")
    parser.add_argument("--checked-out-sha", help="restore check: the commit the selected branch "
                        "was checked out at; HEAD still equal to it means nothing was written locally")
    args = parser.parse_args(argv)
    if args.restore_check:
        if not args.start_sha or args.target_ref or args.branch:
            parser.error("--restore-check takes --start-sha [--start-branch] [--checked-out-sha], "
                         "not --target-ref/--branch")
        report = run_restore_check(args.repo, args.start_sha, args.start_branch, args.checked_out_sha)
    else:
        if not args.target_ref or args.start_sha or args.start_branch or args.checked_out_sha:
            parser.error("--target-ref is required (and --start-*/--checked-out-sha belong to "
                         "--restore-check)")
        report = run_preflight(args.repo, args.target_ref, args.branch)
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
