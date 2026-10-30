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
    checkout_preflight.py --target-ref SHA_OR_REF [--branch NAME] [--repo DIR]

`--target-ref` is the commit whose tree will be checked out (fetch it first).
`--branch` is the local branch that will be checked out, for the "already
checked out elsewhere" check. Prints one JSON object. Exit 0 = PASS; exit 1 =
STOP (a problem was found, or a check could not be run: fail closed). Any other
exit code (argument errors) is also not a pass. The script changes nothing in
the repository.
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


def problem(check: str, detail: str, paths: list[str] | None = None) -> dict:
    out: dict = {"check": check, "detail": detail}
    if paths:
        out["count"] = len(paths)
        out["paths"] = sorted(paths)[:MAX_PATHS]
    return out


def proper_prefixes(path: str):
    parts = path.split("/")
    for i in range(1, len(parts)):
        yield "/".join(parts[:i])


def check_dirty(top: Path) -> list[dict]:
    entries = split_z(git(top, "status", "--porcelain=v1", "-z", "--untracked-files=all").stdout)
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


def check_ignored_collisions(top: Path, target: str) -> list[dict]:
    """Ignored files the switch to `target` would overwrite, remove or block.

    With a clean `git status` every untracked file is ignored, so the ignored
    files are exactly the ones git considers expendable. Three ways to lose one:
      * the target tracks the same path (it is overwritten);
      * the target tracks a directory where the ignored file `a` stands
        (the file is removed to make room: target tracks `a/b`);
      * the target tracks a file where an ignored directory stands
        (its ignored files are removed: ignored `a/b`, target tracks `a`).
    """
    ignored = set(split_z(git(top, "ls-files", "-z", "--others", "--ignored",
                              "--exclude-standard").stdout))
    if not ignored:
        return []
    tracked = set(split_z(git(top, "ls-tree", "-r", "-z", "--name-only", "--full-tree",
                              target).stdout))
    tracked_dirs = {d for t in tracked for d in proper_prefixes(t)}
    ignored_dirs = {d for i in ignored for d in proper_prefixes(i)}
    problems = []
    overwritten = ignored & tracked
    if overwritten:
        problems.append(problem(
            "ignored_collision", "ignored file would be overwritten by a file the target "
            "branch tracks (git does not warn about ignored files)", list(overwritten)))
    blocked = ignored & tracked_dirs
    if blocked:
        problems.append(problem(
            "ignored_collision", "ignored file would be deleted: the target branch tracks "
            "files below that path", list(blocked)))
    removed = tracked & ignored_dirs
    if removed:
        problems.append(problem(
            "ignored_collision", "ignored files below this path would be deleted: the target "
            "branch tracks a file there", list(removed)))
    return problems


def run_preflight(repo: Path, target_ref: str, branch: str | None) -> dict:
    report: dict = {"status": "STOP", "repo": str(repo), "target_ref": target_ref,
                    "branch": branch, "problems": []}
    problems: list[dict] = report["problems"]
    try:
        top = Path(git(repo, "rev-parse", "--show-toplevel").stdout.decode().strip())
        report["toplevel"] = str(top)
        head = git(top, "rev-parse", "--verify", "--quiet", "HEAD^{commit}", ok=(0, 1))
        report["head"] = head.stdout.decode().strip() or None
        cur = git(top, "symbolic-ref", "--quiet", "--short", "HEAD", ok=(0, 1))
        report["current_branch"] = cur.stdout.decode().strip() or None
        resolved = git(top, "rev-parse", "--verify", "--quiet", f"{target_ref}^{{commit}}",
                       ok=(0, 1))
        target = resolved.stdout.decode().strip()
        if not target:
            problems.append(problem("unresolvable_target", f"{target_ref} is not a commit "
                                    "in this repository; fetch it first"))
        report["target"] = target or None
        problems += check_dirty(top)
        problems += check_in_progress(top)
        if report["head"]:
            problems += check_detached(top)
        if branch:
            problems += check_checked_out_elsewhere(top, branch)
        if target:
            problems += check_ignored_collisions(top, target)
    except (GitError, OSError) as exc:
        problems.append(problem("unverifiable", str(exc)))
    if not problems:
        report["status"] = "PASS"
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--repo", type=Path, default=Path("."), help="the current checkout")
    parser.add_argument("--target-ref", required=True, help="commit-ish that will be checked out")
    parser.add_argument("--branch", help="local branch that will be checked out")
    args = parser.parse_args(argv)
    report = run_preflight(args.repo, args.target_ref, args.branch)
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
