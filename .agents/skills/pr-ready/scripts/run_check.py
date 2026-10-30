#!/usr/bin/env python3
"""Run a validation command in the PR branch worktree and emit a HEAD-bound JSON receipt."""
from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def rev() -> str:
    p = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError(f"Cannot resolve HEAD: {p.stderr.strip()}")
    return p.stdout.strip()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--category", required=True, choices=["tests", "lint", "static_analysis"])
    p.add_argument("--log-dir", default=".pr-ready/logs")
    p.add_argument("--name", help="Optional log file identifier")
    p.add_argument("--receipt-dir", default=".pr-ready/receipts", help="Where to store the JSON receipt")
    p.add_argument("command", nargs=argparse.REMAINDER, help="Command after -- (no shell evaluation)")
    opts = p.parse_args()
    argv = opts.command[1:] if opts.command and opts.command[0] == "--" else opts.command
    if not argv:
        p.error("Command missing. Example: -- go test ./...")
    sha = rev()
    output_dir = Path(opts.log_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    label = opts.name or opts.category
    # Stable, safe logfile basename. Overwrite only within explicit log dir.
    safe_label = "".join(x if x.isalnum() or x in "-_" else "-" for x in label)
    path = output_dir / f"{safe_label}-{sha[:12]}.log"
    start = now()
    with path.open("w", encoding="utf-8", errors="replace") as log:
        log.write(f"# start={start} head={sha} command={shlex.join(argv)}\n")
        log.flush()
        try:
            proc = subprocess.run(argv, stdout=log, stderr=subprocess.STDOUT, check=False)
            rc = proc.returncode
        except OSError as exc:
            log.write(f"\n# EXECUTION ERROR: {exc}\n")
            rc = 127
        log.write(f"\n# exit={rc} end={now()}\n")
    end_sha = rev()
    if sha != end_sha:
        rc = 125  # A command changed HEAD, so the receipt is invalid.
    receipt = {"category": opts.category, "command": shlex.join(argv),
               "exit_code": rc, "head_sha": sha, "log": str(path),
               "started_at": start, "finished_at": now(), "head_unchanged": sha == end_sha}
    receipts = Path(opts.receipt_dir)
    receipts.mkdir(parents=True, exist_ok=True)
    receipt_file = receipts / f"{safe_label}-{sha[:12]}.json"
    receipt_file.write_text(json.dumps(receipt, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, ensure_ascii=False))
    return rc if 0 <= rc <= 125 else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError) as e:
        print(json.dumps({"error": str(e)}), file=sys.stderr)
        sys.exit(2)
