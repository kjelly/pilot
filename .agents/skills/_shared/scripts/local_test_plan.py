#!/usr/bin/env python3
"""Compute local test scope; large cmd/spec packages require explicit regressions.

This is a plan, not a coverage verdict. Full normal/race suites belong in CI.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

LARGE = {"github.com/kjelly/pilot/cmd/pilot/cmd", "github.com/kjelly/pilot/internal/spec"}


def scope(paths, packages):
    direct = {p["name"] for p in packages if any(
        f.endswith(".go") and str(Path(f).parent) == p["dir"] for f in paths)}
    affected = set(direct)
    while True:
        expanded = affected | {p["name"] for p in packages if set(p["imports"]) & affected}
        if expanded == affected:
            break
        affected = expanded
    if any(f in ("go.mod", "go.sum") for f in paths):
        affected = {p["name"] for p in packages}
    if any(f.startswith((".github/", "scripts/", ".codex/", ".claude/", ".agents/"))
           or f == "Makefile" for f in paths):
        affected.add("github.com/kjelly/pilot/cmd/pilot/cmd")
    return sorted(affected)


def plan(paths, packages, regressions):
    affected = scope(paths, packages)
    commands = []
    missing = []
    for package in affected:
        regex = regressions.get(package)
        if package in LARGE and not regex:
            missing.append(package)
            continue
        cmd = ["go", "test", "-count=1", "-timeout", "10m"]
        if regex:
            cmd += ["-run", regex]
        commands.append(cmd + [package])
    if any(f.startswith((".agents/", ".codex/", ".claude/")) for f in paths):
        commands.append(["make", "skill-test"])
    return {"status": "NEEDS_SELECTION" if missing else "PLANNED", "packages": affected,
            "missing_regression_selectors": missing, "commands": commands,
            "full_suite": "GitHub CI", "requires_review": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--regression", action="append", default=[], metavar="PACKAGE=REGEX")
    args = parser.parse_args()
    try:
        def git(*argv):
            return subprocess.check_output(["git", "-C", str(args.repo), *argv])
        base = git("rev-parse", "--verify", args.base + "^{commit}").decode().strip()
        head = git("rev-parse", "--verify", args.head + "^{commit}").decode().strip()
        if git("rev-parse", "HEAD").decode().strip() != head:
            raise ValueError("go list must describe the selected checkout HEAD")
        if git("status", "--porcelain", "--untracked-files=normal").strip():
            raise ValueError("commit the candidate before planning authoritative local receipts")
        paths = [p.decode() for p in git("diff", "--name-only", "--no-renames", "-z", base, head).split(b"\0") if p]
        fmt = '{{.ImportPath}}|{{.Dir}}|{{join .Imports " "}} {{join .TestImports " "}} {{join .XTestImports " "}}'
        output = subprocess.check_output(["go", "list", "-f", fmt, "./..."], cwd=args.repo).decode()
        root = Path(git("rev-parse", "--show-toplevel").decode().strip())
        packages = []
        for line in output.splitlines():
            name, directory, imports = line.split("|", 2)
            packages.append({"name": name, "dir": str(Path(directory).relative_to(root)),
                             "imports": imports.split()})
        selectors = dict(item.split("=", 1) for item in args.regression)
        result = {**plan(paths, packages, selectors), "base_sha": base, "head_sha": head}
        print(json.dumps(result, indent=2))
        return 2 if result["status"] == "NEEDS_SELECTION" else 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "STOP", "error": str(exc)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
