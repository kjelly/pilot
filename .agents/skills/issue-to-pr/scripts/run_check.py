#!/usr/bin/env python3
"""Run a validation command on a clean committed Issue worktree and save a SHA-bound receipt.

Usage: python3 run_check.py --worktree WT --name regression --out STATE/regression.json -- go test ./...
Python 3.10+; no third-party dependencies.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import re
import shlex
import subprocess
import sys
from pathlib import Path


def timestamp() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def git(worktree: Path, *args: str) -> str:
    p = subprocess.run(["git", "-C", str(worktree), *args], text=True, capture_output=True)
    if p.returncode:
        raise RuntimeError(f"git {' '.join(args)} failed: {p.stderr.strip()[:500]}")
    return p.stdout.strip()


def snapshot(worktree: Path) -> tuple[str, str]:
    sha = git(worktree, "rev-parse", "--verify", "HEAD")
    status = git(worktree, "status", "--porcelain=v1", "--untracked-files=all")
    return sha, status


def run_check(worktree: Path, name: str, out: Path, command: list[str], timeout: int) -> dict:
    if not command:
        raise ValueError("Command missing (provide argv after --)")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}", name):
        raise ValueError("Invalid --name; use 1–80 alphanumeric, hyphen or underscore characters")
    worktree = worktree.resolve(strict=True)
    out = out.expanduser().resolve()
    if out.is_relative_to(worktree):
        raise ValueError("Receipt must live outside the worktree")
    out.parent.mkdir(parents=True, exist_ok=True)
    sha, status = snapshot(worktree)
    if status:
        raise RuntimeError(f"Dirty worktree before check: {status[:500]}")
    log_dir = out.parent / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{name}-{sha[:12]}.log"
    command_text = shlex.join(command)
    started = timestamp()
    with log_path.open("w", encoding="utf-8", errors="replace") as log:
        log.write(f"# started={started} head_sha={sha}\n# command={command_text}\n")
        log.flush()
        try:
            result = subprocess.run(command, cwd=worktree, stdout=log,
                                    stderr=subprocess.STDOUT, timeout=timeout, check=False)
            rc = result.returncode
        except subprocess.TimeoutExpired:
            rc = 124
            log.write("\n# timeout\n")
        except OSError as exc:
            rc = 127
            log.write(f"\n# cannot execute: {exc}\n")
        log.write(f"\n# exit_code={rc}; finished={timestamp()}\n")
    after_sha, after_status = snapshot(worktree)
    head_unchanged = (sha == after_sha)
    clean_after = not bool(after_status)
    # SHA equality does NOT imply filesystem equality; requiring clean status catches writes.
    passed = rc == 0 and head_unchanged and clean_after
    receipt = {
        "schema_version": 1,
        "status": "pass" if passed else "fail",
        "name": name,
        "command": command_text,
        "exit_code": rc,
        "head_sha": sha,
        "head_unchanged": head_unchanged,
        "clean_before": True,
        "clean_after": clean_after,
        "started_at": started,
        "finished_at": timestamp(),
        "log": str(log_path),
    }
    temp = out.with_name(out.name + ".tmp")
    temp.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp.replace(out)
    return receipt


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--worktree", required=True, type=Path)
    ap.add_argument("--name", required=True)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--timeout", type=int, default=3600, help="Max seconds per check (default: 3600)")
    ap.add_argument("command", nargs=argparse.REMAINDER)
    opt = ap.parse_args(argv)
    command = opt.command[1:] if opt.command and opt.command[0] == "--" else opt.command
    if opt.timeout < 1:
        ap.error("--timeout must be positive")
    try:
        result = run_check(opt.worktree, opt.name, opt.out, command, opt.timeout)
    except (RuntimeError, ValueError, OSError) as exc:
        print(json.dumps({"status": "BLOCKED", "error": str(exc)}), file=sys.stderr)
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0 if result["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
