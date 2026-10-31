#!/usr/bin/env python3
"""Land the checkout on ONE verified commit and attach a branch only where that changes no tree.

Why this exists. `git status --porcelain` cannot see *ignored* files, and git overwrites or
deletes them on a switch without a warning. And the commands that land a branch (`git switch
BRANCH`, `gh pr checkout`, `--track -c origin/X`, `git merge BRANCH`) re-resolve their target
by name at run time: a stale local branch, a stale remote-tracking ref (DWIM), a fork head
named like the user's `main`, a ref named like a SHA. So the invariant is built in: the
caller resolves one full SHA, this script checks that object, lands on exactly it, and
attaches a branch only when that moves no file.

Usage:
    checkout_preflight.py --target SHA [--branch B] [--remote R --merge REF ...] [--new]
                          [--safe-sha SHA ...] [--execute] [--repo DIR]

Without --execute it is a read-only dry run that prints the plan. With --execute it re-runs
every check and then runs exactly the planned commands (like apply_decision.py --execute).
Exit 0 = PASS, 1 = STOP (a problem, or a check that could not run: fail closed); argument
errors also exit non-zero.

--target     full commit SHA (40 hex): the only tree that may land. Fetch it first.
--branch     the branch to end on. Without it the checkout is only detached at the target: that
             is a dry run (a merge preflight), and --execute then needs --safe-sha (a restore).
--remote/--merge   the upstream identity (a remote name or URL, and the accepted merge refs,
             e.g. refs/heads/H [refs/pull/N/head]). It is stored on a created branch. An existing
             branch at the target is attached if it carries it or has no upstream at all (a branch
             never pushed yet); one with a different upstream is a clash. Fast-forwarding needs it.
             URLs are compared literally after a trailing `/` and `.git` are stripped (ssh and
             https forms of one repository differ), so pass the same form every time.
--new        the branch must not exist (a new Issue branch).
--safe-sha   restore mode: HEAD must be one of these (the commit the selected branch was
             checked out at, or the remote head verified after the last push), else its local
             commits would be stranded; and a missing branch is a stop, never created.

Plan, after the checks (dirty, git operation in progress, orphaned detached HEAD, branch
checked out elsewhere, ignored-file collisions with the target tree, nested repositories
included):
    branch absent                          -> create it at the target
    tip == target (identity matches or
      no upstream configured)              -> attach
    tip is an ancestor of the target and
      the upstream identity matches        -> fast-forward by compare-and-swap, then attach
    anything else                          -> STOP branch_clash (never reset, never force)
Commands: `git switch --detach SHA^{commit}` is the only tree change; then create / attach /
`git update-ref REF SHA OLD` + attach. If a command fails the checkout is left wherever git
stopped (detached at the verified target, or on the new branch when only `config` failed);
the report re-reads HEAD and the branch and says so.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

MAX_PATHS = 50
HEX = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
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


def out(repo: Path, *args: str, ok: tuple[int, ...] = (0, 1)) -> str:
    return git(repo, *args, ok=ok).stdout.decode().strip()


def split_z(data: bytes) -> list[str]:
    return [os.fsdecode(item) for item in data.split(b"\0") if item]


def problem(check: str, detail: str, paths: list[str] | None = None) -> dict:
    found: dict = {"check": check, "detail": detail}
    if paths:
        found.update(count=len(paths), paths=sorted(paths)[:MAX_PATHS])
    return found


def proper_prefixes(path: str):
    parts = path.split("/")
    for i in range(1, len(parts)):
        yield "/".join(parts[:i])


def check_dirty(top: Path) -> list[dict]:
    # --ignore-submodules=none: diff.ignoreSubmodules / .gitmodules `ignore` must not hide a dirty submodule
    entries = split_z(git(top, "status", "--porcelain=v1", "-z", "--untracked-files=all",
                          "--ignore-submodules=none").stdout)
    return [problem("dirty", "tracked changes or untracked files; never stash, discard or "
                    "overwrite user work", entries)] if entries else []


def check_in_progress(top: Path) -> list[dict]:
    found = []
    for name in IN_PROGRESS:
        raw = out(top, "rev-parse", "--git-path", name)
        if (Path(raw) if os.path.isabs(raw) else top / raw).exists():
            found.append(name)
    return [problem("operation_in_progress", "finish or abort the git operation first", found)] if found else []


def check_detached(top: Path) -> list[dict]:
    if git(top, "symbolic-ref", "--quiet", "HEAD", ok=(0, 1)).returncode == 0:
        return []
    if out(top, "for-each-ref", "--contains", "HEAD", "--count=1", "--format=%(refname)"):
        return []
    return [problem("detached_head_unreachable", "HEAD is detached at a commit no branch or tag "
                    "contains; switching away would orphan it")]


def check_checked_out_elsewhere(top: Path, branch: str) -> list[dict]:
    here, elsewhere, path = os.path.realpath(top), [], ""
    for line in git(top, "worktree", "list", "--porcelain").stdout.decode(errors="replace").splitlines():
        if line.startswith("worktree "):
            path = line[len("worktree "):]
        elif line == f"branch refs/heads/{branch}" and os.path.realpath(path) != here:
            elsewhere.append(path)
    return [problem("checked_out_elsewhere", f"branch {branch} is checked out in another worktree; "
                    "do not force it or silently switch directories", elsewhere)] if elsewhere else []


def ignored_entries(top: Path) -> tuple[set[str], set[str]]:
    """(ignored files, ignored directory-shaped entries) of the working tree.

    `git ls-files --others --ignored --exclude-standard` lists every ignored file and nothing
    else, except that a nested git repository is listed as one entry with a trailing slash
    (`vendor/x/`), whatever it contains. Empty directories are not listed.
    """
    entries = split_z(git(top, "ls-files", "-z", "--others", "--ignored", "--exclude-standard").stdout)
    return ({e for e in entries if not e.endswith("/")}, {e.rstrip("/") for e in entries if e.endswith("/")})


def check_ignored_collisions(top: Path, target: str) -> list[dict]:
    """Ignored paths the switch to `target` would overwrite, remove or write into.

    With a clean `git status` every untracked path is ignored, so these are exactly the
    paths git considers expendable: the target tracks the same path; tracks files below an
    ignored file `a`; tracks a file where an ignored directory stands; or tracks any path
    below an ignored nested repository (its content is unknown).
    """
    files, dirs = ignored_entries(top)
    if not files and not dirs:
        return []
    tracked = set(split_z(git(top, "ls-tree", "-r", "-z", "--name-only", "--full-tree", target).stdout))
    tracked_dirs = {d for t in tracked for d in proper_prefixes(t)}
    holding = {d for i in files for d in proper_prefixes(i)} | dirs | {d for e in dirs for d in proper_prefixes(e)}
    return [problem("ignored_collision", detail, list(paths)) for paths, detail in (
        (files & tracked, "ignored file would be overwritten by a file the target tracks "
                          "(git does not warn about ignored files)"),
        (files & tracked_dirs, "ignored file would be deleted: the target tracks files below that path"),
        (tracked & holding, "ignored files below this path would be deleted: the target tracks a file there"),
        ({t for t in tracked if any(p in dirs for p in proper_prefixes(t))},
         "tracked path of the target lies inside an ignored nested repository or directory "
         "entry; git writes into it and overwrites whatever is there")) if paths]


def remote_id(top: Path, value: str) -> str:
    url = out(top, "config", "--get", f"remote.{value}.url", ok=(0, 1, 128)) or value
    return url.rstrip("/").removesuffix(".git")


def branch_upstream(top: Path, branch: str) -> tuple[str, str]:
    cfg = lambda key: out(top, "config", "--get", f"branch.{branch}.{key}", ok=(0, 1, 128))
    return cfg("remote"), cfg("merge")


def same_upstream(top: Path, have: tuple[str, str], remote: str | None, merges: list[str]) -> bool:
    return bool(remote and have[0] and have[1] in merges
                and remote_id(top, have[0]) == remote_id(top, remote))


def plan_branch(top: Path, sha: str, branch: str, remote: str | None, merges: list[str], new: bool,
                restore: bool) -> tuple[str | None, str | None, list[dict]]:
    """(action, old tip, problems) for ending on `branch` at `sha`."""
    tip = out(top, "rev-parse", "--verify", "--quiet", f"refs/heads/{branch}^{{commit}}")
    if not tip:
        if restore:
            return None, None, [problem("start_branch_missing", f"local branch {branch} no longer "
                                        "exists; it is never recreated from a remote-tracking ref")]
        return "create", None, []
    have = branch_upstream(top, branch)
    matches = same_upstream(top, have, remote, merges)
    if new:
        why = "it exists but a new branch was expected"
    elif tip == sha:
        if not remote or matches or not any(have):  # no upstream yet: never pushed, nothing to contradict
            return "attach", tip, []
        why = f"it is at the verified commit but tracks {have[0]} {have[1]}, not the expected upstream"
    elif matches and git(top, "merge-base", "--is-ancestor", tip, sha, ok=(0, 1)).returncode == 0:
        return "ff", tip, []
    elif matches:
        why = f"it is at {tip}, not an ancestor of the verified commit {sha} (diverged or ahead)"
    else:
        why = f"it is at {tip}, not at the verified commit {sha}, and does not track the expected upstream"
    return None, tip, [problem("branch_clash", f"local branch {branch}: {why}; ask the user, never "
                               "reset or force")]


def plan(repo: Path, sha: str, branch: str | None, remote: str | None, merges: list[str], new: bool,
         safe: list[str]) -> dict:
    report: dict = {"status": "STOP", "target": sha, "branch": branch, "action": None,
                    "commands": [], "problems": []}
    problems = report["problems"]
    try:
        top = Path(out(repo, "rev-parse", "--show-toplevel", ok=(0,)))
        head = out(top, "rev-parse", "--verify", "--quiet", "HEAD^{commit}")
        cur = out(top, "symbolic-ref", "--quiet", "--short", "HEAD") or None
        report.update(toplevel=str(top), head=head or None, current_branch=cur)
        resolved = out(top, "rev-parse", "--verify", "--quiet", f"{sha}^{{commit}}") == sha
        if not resolved:
            problems.append(problem("unresolvable_target", f"{sha} is not a commit in this repository; "
                                    "fetch it first"))
        valid = False
        if branch is not None:
            named = git(top, "check-ref-format", "--branch", branch, ok=(0, 128, 129))
            valid = named.returncode == 0 and named.stdout.decode().strip() == branch
            if not valid:
                problems.append(problem("invalid_branch_name", f"{branch!r} is not a valid branch name"))
        if resolved and head == sha and (cur == branch if branch is not None else cur is None):
            if not safe:  # landing: already there is fine only for a clean checkout and the right upstream
                problems += check_dirty(top) + check_in_progress(top)
                if valid and not problems:
                    problems += plan_branch(top, sha, branch, remote, merges, new, False)[2]
            if not problems:
                report.update(action="none", status="PASS")  # nothing to switch
            return report
        if safe and head not in safe:
            problems.append(problem("unpushed_commits", f"HEAD {head} is neither the commit the branch was "
                                    "checked out at nor the remote head verified after the last push: "
                                    "leaving now would strand local commits"))
        problems += check_dirty(top) + check_in_progress(top) + (check_detached(top) if head else [])
        if valid:
            problems += check_checked_out_elsewhere(top, branch)
        if resolved:
            problems += check_ignored_collisions(top, sha)
        action = tip = None
        if valid and resolved:
            action, tip, found = plan_branch(top, sha, branch, remote, merges, new, bool(safe))
            problems += found
        if not problems:
            cmds = [["git", "switch", "--detach", f"{sha}^{{commit}}"]]
            if action == "create":
                cmds.append(["git", "switch", "--no-track", "-c", branch])
                if remote:
                    cmds += [["git", "config", f"branch.{branch}.remote", remote],
                             ["git", "config", f"branch.{branch}.merge", merges[0]]]
            elif action == "ff":
                cmds.append(["git", "update-ref", "-m", "ff to verified head", f"refs/heads/{branch}", sha, tip])
            if action in ("attach", "ff"):
                cmds.append(["git", "switch", "--no-guess", branch])
            report.update(action=action or "detach", commands=cmds)
    except (GitError, OSError) as exc:
        problems.append(problem("unverifiable", str(exc)))
    if not problems:
        report["status"] = "PASS"
    return report


def execute(report: dict) -> dict:
    """Run exactly the planned commands, verify where HEAD ended up, and say where it is."""
    top = Path(report["toplevel"])
    failure = None
    try:
        for cmd in report["commands"]:
            git(top, *cmd[1:])
    except GitError as exc:
        failure = str(exc)
    head = out(top, "rev-parse", "--verify", "--quiet", "HEAD")
    cur = out(top, "symbolic-ref", "--quiet", "--short", "HEAD") or None
    report.update(executed=True, head=head or None, current_branch=cur)
    if failure is None and (head != report["target"] or cur != report["branch"]):
        failure = f"expected {report['branch'] or 'a detached HEAD'} at {report['target']}"
    if failure:
        report["status"] = "STOP"
        report["problems"].append(problem("unverifiable", f"{failure}; the checkout is now "
                                          f"{'on ' + cur if cur else 'detached'} at {head}"))
    return report


def full_sha(value: str) -> str:
    if not HEX.fullmatch(value):
        raise argparse.ArgumentTypeError(f"{value!r} is not a full lowercase commit SHA; "
                                         "resolve the name to a SHA first")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--repo", type=Path, default=Path("."), help="the current checkout")
    parser.add_argument("--target", type=full_sha, required=True)
    parser.add_argument("--branch")
    parser.add_argument("--remote")
    parser.add_argument("--merge", action="append", default=[])
    parser.add_argument("--new", action="store_true")
    parser.add_argument("--safe-sha", action="append", type=full_sha, default=[])
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if bool(args.remote) != bool(args.merge) or (args.new and args.safe_sha) or (
            (args.new or args.remote) and args.branch is None):
        parser.error("--remote and --merge go together with --branch; --new needs --branch and "
                     "excludes --safe-sha")
    if args.execute and args.branch is None and not args.safe_sha:
        parser.error("--execute without --branch is a restore to a detached start and needs "
                     "--safe-sha; a bare --target is a dry run (the merge preflight)")
    report = plan(args.repo, args.target, args.branch, args.remote, args.merge, args.new, args.safe_sha)
    if args.execute and report["status"] == "PASS":
        report = execute(report)
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
