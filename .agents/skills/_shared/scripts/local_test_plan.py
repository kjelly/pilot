#!/usr/bin/env python3
"""Compute local test scope; large cmd/spec packages require explicit regressions.

This is a plan, not a coverage verdict. Full normal/race suites belong in CI. For a change that reaches skill tests the plan
runs `make skill-test` for the suites the change can reach (skill_suites.py derives them, with the reason for each), or for
all of them when the mapping is unknown; CI runs the whole `make skill-test` either way.
"""
import argparse
import json
from pathlib import Path
import subprocess
import sys

# Run from a skill snapshot, this script must not add `__pycache__` there, and under `python3 -I` its own directory is not on
# sys.path: no bytecode, and the directory is added (last) before the import.
sys.dont_write_bytecode = True
_HERE = str(Path(__file__).resolve().parent)
if _HERE not in sys.path:
    sys.path.append(_HERE)
import skill_suites  # noqa: E402  (a pure module: it starts no process)

LARGE = {"github.com/kjelly/pilot/cmd/pilot/cmd", "github.com/kjelly/pilot/internal/spec"}


def scope(paths, packages):
    direct = {p["name"] for p in packages if any(
        f.endswith(".go") and str(Path(f).parent) == p["dir"] for f in paths)}
    # Test-only edits do not change the package imported by its consumers.
    # Propagating them can turn a CI consistency edit into 20+ package runs.
    propagated = {p["name"] for p in packages if any(
        f.endswith(".go") and not f.endswith("_test.go")
        and str(Path(f).parent) == p["dir"] for f in paths)}
    while True:
        expanded = propagated | {p["name"] for p in packages if set(p["imports"]) & propagated}
        if expanded == propagated:
            break
        propagated = expanded
    affected = direct | propagated
    if any(f in ("go.mod", "go.sum") for f in paths):
        affected = {p["name"] for p in packages}
    if any(f.startswith((".github/", "scripts/", ".codex/", ".claude/", ".agents/"))
           or f == "Makefile" for f in paths):
        affected.add("github.com/kjelly/pilot/cmd/pilot/cmd")
    return sorted(affected)


def skill_command(skills, paths):
    """The `make skill-test` command of a plan, or None when no skill test is needed. `skills` is the result of
    `skill_suites.select` for the change, or None when it was not derived: the whole suite then, as before the selection."""
    if skills is None:
        return ["make", "skill-test"] if any(f.startswith((".agents/", ".codex/", ".claude/")) for f in paths) else None
    if skills["selection"] == "all":
        return ["make", "skill-test"]
    if skills["selection"]:
        return ["make", "skill-test", "SKILL_SUITES=" + " ".join(skills["selection"])]
    return None


def plan(paths, packages, regressions, skills=None):
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
    skill = skill_command(skills, paths)
    if skill is not None:
        commands.append(skill)
    result = {"status": "NEEDS_SELECTION" if missing else "PLANNED", "packages": affected,
              "missing_regression_selectors": missing, "commands": commands,
              "full_suite": "GitHub CI", "requires_review": True}
    if skills is not None:
        result["skill_suites"] = skills
    return result


def select_skill_suites(root, changes):
    """The skill suites the change can reach (skill_suites.select); a failure to derive them selects every suite."""
    try:
        return skill_suites.select(changes, skill_suites.derive(str(root)))
    except Exception as exc:  # the derivation is advice for a local run: whatever goes wrong, run everything
        return {"selection": "all", "reasons": {}, "universe": [], "reason": f"the selection failed: {exc}"}


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
        changes = skill_suites.parse_name_status(git("diff", "--name-status", "--no-renames", "-z", base, head))
        paths = [path for _status, path in changes]
        fmt = '{{.ImportPath}}|{{.Dir}}|{{join .Imports " "}} {{join .TestImports " "}} {{join .XTestImports " "}}'
        output = subprocess.check_output(["go", "list", "-f", fmt, "./..."], cwd=args.repo).decode()
        root = Path(git("rev-parse", "--show-toplevel").decode().strip())
        packages = []
        for line in output.splitlines():
            name, directory, imports = line.split("|", 2)
            packages.append({"name": name, "dir": str(Path(directory).relative_to(root)),
                             "imports": imports.split()})
        selectors = dict(item.split("=", 1) for item in args.regression)
        skills = select_skill_suites(root, changes)
        result = {**plan(paths, packages, selectors, skills), "base_sha": base, "head_sha": head}
        result["skill_suites"] = {**skills, "base_sha": base, "head_sha": head}
        print(json.dumps(result, indent=2))
        return 2 if result["status"] == "NEEDS_SELECTION" else 0
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "STOP", "error": str(exc)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
