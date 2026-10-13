#!/usr/bin/env python3
"""Fail closed on repo-root inventory files that would shadow the checkpoint."""
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[2]
tracked = set(subprocess.check_output(["git", "ls-files", "-z"], cwd=root).decode().split("\0"))
shadows = []
for name in ("group_vars", "host_vars", ".vault"):
    directory = root / name
    if directory.exists():
        for path in directory.rglob("*"):
            if path.is_file() and path.suffix in (".yml", ".yaml"):
                relative = path.relative_to(root).as_posix()
                if relative not in tracked:
                    shadows.append(relative)
if shadows:
    raise SystemExit("untracked/ignored inventory shadows must be moved aside by their owner: " +
                     ", ".join(sorted(shadows)))
