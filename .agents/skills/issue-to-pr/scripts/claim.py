#!/usr/bin/env python3
"""Cross-session work claims for GitHub Issues and PRs.

Two agent sessions (often two clones of one repo on the same machine) must not repair the
same Issue or PR branch at once. A claim is a small JSON file in a *user-level* directory that
every session can see, plus a scan of the remote and local worktrees for branches that already
carry the number. A claim expires unless renewed, so a crashed session never locks a target
forever.

    claim.py acquire --repo O/R --issue 157 --skill issue-to-pr --branch fix/157-x --worktree PATH
    claim.py acquire --repo O/R --pr 148   --skill pr-ready     --branch fix/146-y --worktree PATH
    claim.py renew   --repo O/R --pr 148 --token T       # at every checkpoint / before long runs
    claim.py release --repo O/R --pr 148 --token T       # on READY, BLOCKED or any final report
    claim.py check   --repo O/R --issue 157              # read-only
    claim.py list [--repo O/R]
    claim.py acquire --repo O/R --issue 354 --member 142 --member 216 --skill issue-to-pr ...  # umbrella

Umbrella mode (issue-to-pr's references/workflow.md): one claim covers the umbrella Issue and its
sub-issues. It is one file, `issue-<umbrella>.json` with `members`, written by one os.replace, so a failed
write never leaves part of a group claimed. A member has no file of its own. `renew` and `release` take the
umbrella's number; `check` and `acquire` of any number also see a live group claim that lists it.

Invariant: for every Issue number, at most one LIVE claim (expires_at > now) covers it, where a claim
covers its own number and its members. Coverage is many-to-many across files, so one choke point enforces it:
every write goes through `commit_claim`, under the directory lock, which refuses an overlap with any other live
claim and then writes nothing (status CONFLICT, exit 3). The own token is never an exemption: a claim is told
apart from "my other claim" by its file path, and a token of yours on another file is a conflict that you
must release first. `now` is read inside the lock, after the branch scans.

Rules that follow (Issue claims, single or group):
  * `renew` only extends a LIVE claim. An expired one answers EXPIRED (exit 3) and writes nothing: another
    session may already have taken a number it covered, so stop writing and `acquire` again for a new token.
  * `acquire --token` on a live claim of yours is RENEWED and keeps the stored members: without `--member`
    they are kept, the same set is accepted, any different set is an error (exit 2, nothing written; release
    and acquire again). On an EXPIRED claim of yours it is not a renewal: it is CLAIMED_AFTER_EXPIRY with a
    new token, and the branch scans and the overlap check apply.
  * `--takeover` replaces only the claim at its own number; it never covers a number that another live claim
    holds. The replaced token then gets NOT_OWNER.
  * `check` of a number that more than one live claim covers (written by hand or by an older version) is
    OVERLAP (exit 3, no tokens); any write on it is a CONFLICT until one claim is released.
  * A claim file that cannot be read, or whose `members` is not a list of distinct positive integers other
    than its own number, is an error (exit 2): never guessed at, never skipped.
PR claims keep their one-file-per-number behaviour: no members, `renew` and `acquire --token` revive an
expired PR claim as before (pr-ready and pr-review-merge rely on that).

Exit codes: 0 ok, 3 conflict / not owner / claim lost (stop and re-evaluate), 2 usage or error.
Stdout is always one JSON object. The token printed by `acquire` is the only proof of ownership:
keep it in the task checkpoint. Directory: $GH_WORKFLOW_CLAIM_DIR or ~/.cache/gh-workflow-claims.
"""
from __future__ import annotations

import argparse
import fcntl
import getpass
import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator

REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
SKILLS = ("issue-to-pr", "pr-ready")


class ClaimError(RuntimeError):
    pass


def claim_root() -> Path:
    return Path(os.environ.get("GH_WORKFLOW_CLAIM_DIR") or Path.home() / ".cache" / "gh-workflow-claims")


def repo_dir(repo: str) -> Path:
    if not REPO.fullmatch(repo):
        raise ClaimError(f"Invalid --repo {repo!r}; expected OWNER/REPO")
    return claim_root() / repo.replace("/", "__")


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@contextmanager
def locked(directory: Path) -> Iterator[None]:
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(directory / ".lock", "a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(fh, fcntl.LOCK_UN)


def valid_members(value: Any, number: int) -> bool:
    """`members` is a list of distinct positive integers, none of them the claim's own number."""
    return (isinstance(value, list) and all(isinstance(m, int) and not isinstance(m, bool) and m > 0 for m in value)
            and len(set(value)) == len(value) and number not in value)


def read_claim(path: Path) -> dict[str, Any] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return None
    except (OSError, json.JSONDecodeError) as exc:
        raise ClaimError(f"Unreadable claim file {path}: {exc}") from exc
    if (not isinstance(data, dict) or isinstance(data.get("expires_at"), bool)
            or not isinstance(data.get("expires_at"), (int, float))):
        raise ClaimError(f"Malformed claim file {path}; inspect it or remove it by hand")
    number = data.get("number")
    if isinstance(number, bool) or not isinstance(number, int):
        raise ClaimError(f"Malformed claim file {path}: `number` is not an integer; inspect it or remove it by hand")
    if "members" in data and not valid_members(data["members"], number):
        raise ClaimError(f"Malformed claim file {path}: `members` must be distinct positive integers other than "
                         f"the claim's own number; inspect it or remove it by hand")
    return data


def live(claim: dict[str, Any], now: float) -> bool:
    """The only expiry predicate: a claim whose expires_at is now or earlier is expired."""
    return claim["expires_at"] > now


def covers(claim: dict[str, Any]) -> set[int]:
    """The Issue numbers a claim holds: its own and its members."""
    return {claim["number"], *claim.get("members", [])}


def covering(directory: Path, kind: str, numbers: set[int], now: float,
             *, skip: Path | None = None) -> list[tuple[int, dict[str, Any]]]:
    """Every live claim other than the file `skip` (told apart by PATH, never by token) that covers any of
    `numbers`, as (lowest shared number, claim). An Issue can be covered from any issue-*.json (group claims);
    a PR claim has no members, so only pr-N.json is read."""
    if not directory.is_dir():
        return []
    if kind == "issue":
        files = sorted(directory.glob("issue-*.json"))
    else:
        files = [directory / f"pr-{n}.json" for n in sorted(numbers)]
    found = []
    for f in files:
        if skip is not None and f == skip:
            continue
        claim = read_claim(f)
        if claim is None or not live(claim, now):
            continue
        shared = covers(claim) & numbers
        if shared:
            found.append((min(shared), claim))
    return found


def write_claim(path: Path, claim: dict[str, Any]) -> None:
    """One os.replace: the claim is written whole or not at all. A failure is a ClaimError (exit 2).
    Call it only through `commit_claim`."""
    tmp = None
    try:
        fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".claim-", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(claim, fh, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except OSError as exc:
        if tmp is not None:
            Path(tmp).unlink(missing_ok=True)
        raise ClaimError(f"Cannot write claim file {path} ({exc}); nothing was claimed") from exc


def commit_claim(directory: Path, path: Path, claim: dict[str, Any], now: float) -> tuple[int, dict[str, Any]] | None:
    """The ONLY caller of write_claim; call it under `locked(directory)`. If another live claim covers any
    number this claim covers, nothing is written and (number, that claim) is returned; otherwise None."""
    held = covering(directory, claim["kind"], covers(claim), now, skip=path)
    if held:
        return held[0]
    write_claim(path, claim)
    return None


def overlap_hint(number: int, other: dict[str, Any], token: str | None) -> str:
    where = (f"is held by the live claim #{other['number']}" if other["number"] == number
             else f"is a member of the live umbrella claim #{other['number']}")
    if token and digest(token) == other.get("token_sha256"):
        return (f"#{number} {where}, which is your own claim: release it first (claim.py release), then "
                f"acquire again. Nothing was written.")
    return f"#{number} {where} of another session. Nothing was written. Stop and tell the user."


def public(claim: dict[str, Any], now: float) -> dict[str, Any]:
    out = {k: v for k, v in claim.items() if k != "token_sha256"}
    out["active"] = live(claim, now)
    out["minutes_left"] = max(0, round((claim["expires_at"] - now) / 60))
    return out


def run(argv: list[str], cwd: Path | None = None, timeout: int = 60) -> str | None:
    try:
        p = subprocess.run(argv, cwd=cwd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    return p.stdout if p.returncode == 0 else None


def number_pattern(number: int) -> re.Pattern[str]:
    # 157 matches fix/157-x, issue-157, issue157 but not 1570, 2.157.1 or v1.157.
    return re.compile(rf"(?<![0-9.]){number}(?![0-9.])")


def scan_branches(kind: str, number: int, git_dir: Path, remote: str, branch: str | None,
                  worktree: str | None, allowed: set[str]) -> tuple[list[dict[str, str]], list[str]]:
    """Return (conflicts, warnings). Conflicts are branches/worktrees other work already owns."""
    conflicts: list[dict[str, str]] = []
    warnings: list[str] = []
    pattern = number_pattern(number)
    ok = allowed | ({branch} if branch else set())

    heads = run(["git", "-C", str(git_dir), "ls-remote", "--heads", remote])
    if heads is None:
        warnings.append(f"Could not list heads of remote {remote!r} from {git_dir}; remote branch scan skipped")
    elif kind == "issue":
        for line in heads.splitlines():
            ref = line.split("\t", 1)[-1].removeprefix("refs/heads/")
            if pattern.search(ref) and ref not in ok:
                conflicts.append({"type": "REMOTE_BRANCH", "ref": ref,
                                  "detail": "a branch for this Issue is already on the remote"})

    listing = run(["git", "-C", str(git_dir), "worktree", "list", "--porcelain"])
    if listing is None:
        warnings.append("Could not list local worktrees; local worktree scan skipped")
        return conflicts, warnings
    mine = os.path.realpath(worktree) if worktree else None
    path = ""
    for line in listing.splitlines() + [""]:
        if line.startswith("worktree "):
            path = line[9:]
        elif line.startswith("branch "):
            ref = line[7:].removeprefix("refs/heads/")
            if mine and os.path.realpath(path) == mine:
                continue
            same_pr_branch = kind == "pr" and branch is not None and ref == branch
            issue_branch = kind == "issue" and pattern.search(ref) and ref not in ok
            if same_pr_branch or issue_branch:
                conflicts.append({"type": "LOCAL_WORKTREE", "ref": ref,
                                  "detail": f"already checked out in worktree {path}"})
    return conflicts, warnings


def recent_pr_activity(repo: str, pr: int, minutes: int) -> str | None:
    out = run(["gh", "pr", "view", str(pr), "-R", repo, "--json", "commits",
               "--jq", ".commits[-1].committedDate"], timeout=30)
    if not out or not out.strip():
        return None
    try:
        when = datetime.fromisoformat(out.strip().replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None
    age = (time.time() - when) / 60
    if age < minutes:
        return f"PR head commit is only {round(age)} min old; another session may be pushing to it"
    return None


def key(args: argparse.Namespace) -> tuple[str, int]:
    if (args.issue is None) == (args.pr is None):
        raise ClaimError("Give exactly one of --issue or --pr")
    return ("issue", args.issue) if args.issue is not None else ("pr", args.pr)


def emit(status: str, code: int, **extra: Any) -> int:
    print(json.dumps({"status": status, **extra}, indent=2, sort_keys=True))
    return code


def members_of(args: argparse.Namespace, kind: str, number: int) -> list[int]:
    members = list(getattr(args, "member", None) or [])
    if members and kind != "issue":
        raise ClaimError("--member only goes with --issue (an umbrella Issue and its sub-issues)")
    if not valid_members(members, number):
        raise ClaimError("--member must name distinct positive sub-issue numbers other than --issue")
    return sorted(members)


def cmd_acquire(args: argparse.Namespace) -> int:
    kind, number = key(args)
    members = members_of(args, kind, number)
    directory = repo_dir(args.repo)
    path = directory / f"{kind}-{number}.json"
    conflicts, warnings = scan_branches(kind, number, Path(args.git_dir), args.remote, args.branch,
                                        args.worktree, set(args.allow_branch or []))
    for member in members:
        found, notes = scan_branches(kind, member, Path(args.git_dir), args.remote, args.branch,
                                     args.worktree, set(args.allow_branch or []))
        conflicts += [{**c, "number": member} for c in found]
        warnings += notes
    if args.no_remote_scan:
        conflicts, warnings = [], ["Branch scan disabled by --no-remote-scan"]
    if kind == "pr" and not args.no_gh:
        note = recent_pr_activity(args.repo, number, args.recent_minutes)
        if note:
            warnings.append(note)
    with locked(directory):
        now = time.time()  # inside the lock, after the scans: the clock the decisions below are made on
        existing = read_claim(path)
        previous = None
        status = "CLAIMED"
        token = args.token
        if existing:
            mine = bool(args.token) and digest(args.token) == existing.get("token_sha256")
            if live(existing, now) and not mine and not args.takeover:
                return emit("CONFLICT", 3, claim=public(existing, now), conflicts=conflicts, warnings=warnings,
                            hint="Another session holds this target. Stop and tell the user; use --takeover only "
                                 "if the user says the other session is gone.")
            if mine and (live(existing, now) or kind == "pr"):
                # An Issue claim is renewed only while it is live; an expired PR claim revives as it always did.
                status = "RENEWED"
                stored = existing.get("members", [])
                if members and set(members) != set(stored):
                    raise ClaimError(f"--member {sorted(members)} differs from the members {sorted(stored)} of your "
                                     f"live claim; nothing was written. Release the claim and acquire again to "
                                     f"change them.")
                members = sorted(stored)
            elif live(existing, now):
                status, previous = "TAKEN_OVER", public(existing, now)
            else:
                status, previous = "CLAIMED_AFTER_EXPIRY", public(existing, now)
        if conflicts and status != "RENEWED":
            return emit("CONFLICT", 3, conflicts=conflicts, warnings=warnings,
                        hint="Work for this target already exists elsewhere. Report it and stop; if it is your own "
                             "earlier branch, re-run with --branch NAME (or --allow-branch NAME) to resume it.")
        if not (status == "RENEWED" and token):
            token = secrets.token_hex(16)
        claim = {"schema_version": 1, "repo": args.repo, "kind": kind, "number": number, "skill": args.skill,
                 "branch": args.branch, "worktree": os.path.realpath(args.worktree) if args.worktree else None,
                 "owner": {"host": socket.gethostname(), "user": getpass.getuser(), "cwd": os.getcwd(),
                           "label": args.label},
                 "claimed_at": existing["claimed_at"] if status == "RENEWED" and existing else now,
                 "renewed_at": now, "expires_at": now + args.ttl_minutes * 60, "token_sha256": digest(token)}
        if members:
            claim["members"] = members
        # A sub-issue has no file of its own: the umbrella's claim lists it. commit_claim checks every number this
        # claim covers against every other live claim, and --takeover never covers another claim's numbers.
        refused = commit_claim(directory, path, claim, now)
        if refused:
            n, other = refused
            return emit("CONFLICT", 3, number=n, claim=public(other, now), conflicts=conflicts, warnings=warnings,
                        hint=overlap_hint(n, other, args.token))
        return emit(status, 0, token=token, claim=public(claim, now), previous=previous,
                    conflicts=[], warnings=warnings)


def cmd_renew(args: argparse.Namespace) -> int:
    kind, number = key(args)
    directory = repo_dir(args.repo)
    path = directory / f"{kind}-{number}.json"
    with locked(directory):
        now = time.time()
        claim = read_claim(path)
        if claim is None:
            return emit("CLAIM_LOST", 3, hint="Claim is gone. Stop writing, re-run acquire, and re-validate state.")
        if digest(args.token) != claim.get("token_sha256"):
            return emit("NOT_OWNER", 3, claim=public(claim, now),
                        hint="Another session now owns this target. Stop writing and report it.")
        if kind == "issue" and not live(claim, now):
            # Another session may have taken a number this claim covered while it was expired.
            return emit("EXPIRED", 3, claim=public(claim, now),
                        hint="The claim expired and was not extended. Stop writing, re-run acquire with --branch, "
                             "save the new token, and re-validate state.")
        claim["renewed_at"], claim["expires_at"] = now, now + args.ttl_minutes * 60
        refused = commit_claim(directory, path, claim, now)
        if refused:
            n, other = refused
            return emit("CONFLICT", 3, number=n, claim=public(other, now),
                        hint=overlap_hint(n, other, args.token) + " Stop writing and re-validate.")
        return emit("RENEWED", 0, claim=public(claim, now))


def cmd_release(args: argparse.Namespace) -> int:
    kind, number = key(args)
    directory = repo_dir(args.repo)
    path = directory / f"{kind}-{number}.json"
    now = time.time()
    with locked(directory):
        claim = read_claim(path)
        if claim is None:
            return emit("NOT_CLAIMED", 0)
        if not args.force and (not args.token or digest(args.token) != claim.get("token_sha256")):
            return emit("NOT_OWNER", 3, claim=public(claim, now))
        path.unlink()
        return emit("RELEASED", 0)


def cmd_check(args: argparse.Namespace) -> int:
    kind, number = key(args)
    directory = repo_dir(args.repo)
    path = directory / f"{kind}-{number}.json"
    conflicts, warnings = scan_branches(kind, number, Path(args.git_dir), args.remote, args.branch,
                                        args.worktree, set(args.allow_branch or []))
    now = time.time()
    # Every live claim that covers the number (a sub-issue is covered by its umbrella's claim).
    holders = [c for _, c in covering(directory, kind, {number}, now)]
    if len(holders) > 1:
        return emit("OVERLAP", 3, claims=[public(c, now) for c in holders], conflicts=conflicts, warnings=warnings,
                    hint=f"More than one live claim covers #{number}; release all but one (claim.py release) "
                         f"before anyone writes. Every write on it is refused until then.")
    claim = holders[0] if holders else read_claim(path)  # no live claim: the number's own, expired, file
    if claim is None:
        status = "FREE"
    elif not live(claim, now):
        status = "EXPIRED"
    elif args.token and digest(args.token) == claim.get("token_sha256"):
        status = "MINE"
    else:
        status = "CLAIMED_BY_OTHER"
    code = 3 if status == "CLAIMED_BY_OTHER" or (conflicts and status != "MINE") else 0
    return emit(status, code, claim=public(claim, now) if claim else None, conflicts=conflicts, warnings=warnings)


def cmd_list(args: argparse.Namespace) -> int:
    now = time.time()
    dirs = [repo_dir(args.repo)] if args.repo else sorted(p for p in claim_root().glob("*") if p.is_dir())
    items = []
    for d in dirs:
        for f in sorted(d.glob("*.json")):
            claim = read_claim(f)
            if claim:
                items.append(public(claim, now))
    return emit("OK", 0, claims=items)


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    def target(p: argparse.ArgumentParser) -> None:
        p.add_argument("--repo", required=True, help="OWNER/REPO")
        p.add_argument("--issue", type=int)
        p.add_argument("--pr", type=int)

    def scan(p: argparse.ArgumentParser) -> None:
        p.add_argument("--git-dir", default=".", help="A clone of the repo to scan (default: cwd)")
        p.add_argument("--remote", default="origin")
        p.add_argument("--branch", help="Your own branch; it is not reported as a conflict")
        p.add_argument("--worktree", help="Your own worktree; it is not reported as a conflict")
        p.add_argument("--allow-branch", action="append", help="Existing branch you are deliberately resuming")

    a = sub.add_parser("acquire")
    target(a)
    scan(a)
    a.add_argument("--skill", required=True, choices=SKILLS)
    a.add_argument("--label", help="Free-text name of this session, e.g. 'session-b'")
    a.add_argument("--ttl-minutes", type=int, default=240)
    a.add_argument("--member", action="append", type=int,
                   help="Umbrella mode: a sub-issue covered by this --issue claim (repeatable)")
    a.add_argument("--token", help="Token from an earlier acquire, to resume your own claim")
    a.add_argument("--takeover", action="store_true", help="Replace an active claim (only on explicit user instruction)")
    a.add_argument("--no-remote-scan", action="store_true")
    a.add_argument("--no-gh", action="store_true", help="Skip the gh recent-activity check for PRs")
    a.add_argument("--recent-minutes", type=int, default=60)
    a.set_defaults(fn=cmd_acquire)

    r = sub.add_parser("renew")
    target(r)
    r.add_argument("--token", required=True)
    r.add_argument("--ttl-minutes", type=int, default=240)
    r.set_defaults(fn=cmd_renew)

    d = sub.add_parser("release")
    target(d)
    d.add_argument("--token")
    d.add_argument("--force", action="store_true", help="Only on explicit user instruction")
    d.set_defaults(fn=cmd_release)

    c = sub.add_parser("check")
    target(c)
    scan(c)
    c.add_argument("--token")
    c.set_defaults(fn=cmd_check)

    ls = sub.add_parser("list")
    ls.add_argument("--repo")
    ls.set_defaults(fn=cmd_list)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "ttl_minutes", 1) < 1:
        print(json.dumps({"status": "ERROR", "error": "--ttl-minutes must be positive"}))
        return 2
    try:
        return args.fn(args)
    except (ClaimError, OSError) as exc:  # an unusable claim directory is an error, never a traceback
        return emit("ERROR", 2, error=str(exc))


if __name__ == "__main__":
    sys.exit(main())
