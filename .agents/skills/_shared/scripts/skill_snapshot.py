#!/usr/bin/env python3
"""Snapshot the skill bundle outside the checkout before the checkout is switched.

The single-item skills switch the one checkout to the selected item's branch.
An older PR branch can replace or delete the skill scripts, shared contract and
native role definitions the invocation is running from, so they are copied
first, from the committed HEAD of the *clean* checkout, to a directory outside
it, with a recorded tree ID and a sha256 manifest.

Usage:
    skill_snapshot.py create --repo DIR [--out-parent DIR]
        Refuse a dirty checkout; `git archive HEAD` the bundle paths into a new
        directory outside the checkout; write <dir>.manifest.json next to it.
    skill_snapshot.py verify --snapshot DIR
        The snapshot still matches its manifest.
    skill_snapshot.py verify-role --snapshot DIR --repo DIR --platform claude|codex --role NAME
        The role file the runtime will load from the checkout
        (.claude/agents/NAME.md or .codex/agents/NAME.toml) exists, is a regular
        file inside the checkout and is byte-identical to the snapshot's copy.
        Run it before every child dispatch; anything but exit 0 means BLOCKED.

Prints one JSON object. Exit 0 = PASS, 1 = STOP/BLOCKED (fail closed).
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

BUNDLE_PATHS = (
    ".agents/skills/_shared",
    ".agents/skills/pilot-code-review",
    ".agents/skills/issue-to-pr",
    ".agents/skills/pr-ready",
    ".agents/skills/pr-review-merge",
    ".codex/agents",
    ".claude/agents",
)
ROLE_FILES = {"claude": ".claude/agents/{role}.md", "codex": ".codex/agents/{role}.toml"}
ROLE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")


class Stop(Exception):
    """A condition that must stop the invocation (the message says why)."""


def git(repo: Path, *args: str, ok: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess:
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", LC_ALL="C")
    p = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, env=env)
    if p.returncode not in ok:
        raise Stop(f"git {' '.join(args)} failed (rc={p.returncode}): "
                   f"{p.stderr.decode(errors='replace').strip()[:300]}")
    return p


def toplevel(repo: Path) -> Path:
    return Path(git(repo, "rev-parse", "--show-toplevel").stdout.decode().strip())


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def scan(root: Path) -> dict[str, dict]:
    """Content fingerprint of a tree; symlinks are recorded, not followed."""
    files: dict[str, dict] = {}
    for dirpath, dirnames, filenames in os.walk(root):
        for name in sorted(dirnames + filenames):
            path = Path(dirpath) / name
            rel = path.relative_to(root).as_posix()
            if path.is_symlink():
                files[rel] = {"type": "symlink", "target": os.readlink(path)}
            elif path.is_file():
                files[rel] = {"type": "file", "sha256": sha256(path),
                              "executable": os.access(path, os.X_OK)}
    return dict(sorted(files.items()))


def manifest_path(snapshot: Path) -> Path:
    return snapshot.with_name(snapshot.name + ".manifest.json")


def create(repo: Path, out_parent: Path | None) -> dict:
    top = toplevel(repo)
    # --ignore-submodules=none: diff.ignoreSubmodules / .gitmodules `ignore` must not hide a dirty submodule
    if git(top, "status", "--porcelain=v1", "-z", "--untracked-files=all",
           "--ignore-submodules=none").stdout:
        raise Stop("checkout is not clean: run checkout_preflight.py and resolve it first; "
                   "the snapshot is taken only after the clean check")
    head = git(top, "rev-parse", "--verify", "HEAD^{commit}").stdout.decode().strip()
    tree = git(top, "rev-parse", "--verify", "HEAD^{tree}").stdout.decode().strip()
    missing = [p for p in BUNDLE_PATHS
               if git(top, "cat-file", "-e", f"HEAD:{p}", ok=(0, 1, 128)).returncode]
    if missing:
        raise Stop(f"HEAD does not contain the skill bundle path(s): {', '.join(missing)}")
    parent = Path(os.path.realpath(out_parent or tempfile.gettempdir()))
    if parent == top or top in parent.parents:
        raise Stop(f"snapshot directory must be outside the checkout ({top})")
    snapshot = Path(tempfile.mkdtemp(prefix="single-item-skills-", dir=parent))
    archive = git(top, "archive", "--format=tar", "HEAD", "--", *BUNDLE_PATHS).stdout
    p = subprocess.run(["tar", "-x", "-C", str(snapshot)], input=archive, capture_output=True)
    if p.returncode:
        raise Stop(f"tar extraction failed: {p.stderr.decode(errors='replace').strip()[:300]}")
    files = scan(snapshot)
    manifest = {"source_repo": str(top), "source_head": head, "source_tree": tree,
                "paths": list(BUNDLE_PATHS), "files": files}
    manifest_path(snapshot).write_text(json.dumps(manifest, indent=2) + "\n")
    return {"snapshot_dir": str(snapshot), "manifest": str(manifest_path(snapshot)),
            "source_repo": str(top), "head": head, "tree_id": tree, "files": len(files)}


def verify(snapshot: Path) -> dict:
    snapshot = Path(os.path.realpath(snapshot))
    mpath = manifest_path(snapshot)
    try:
        manifest = json.loads(mpath.read_text())
    except (OSError, ValueError) as exc:
        raise Stop(f"cannot read the snapshot manifest {mpath}: {exc}")
    now = scan(snapshot)
    was = manifest["files"]
    changed = sorted(p for p in now.keys() & was.keys() if now[p] != was[p])
    added = sorted(now.keys() - was.keys())
    removed = sorted(was.keys() - now.keys())
    if changed or added or removed:
        raise Stop(f"snapshot differs from its manifest: changed={changed[:10]} "
                   f"added={added[:10]} removed={removed[:10]}")
    return {"snapshot_dir": str(snapshot), "head": manifest["source_head"],
            "tree_id": manifest["source_tree"], "files": len(now)}


def verify_role(snapshot: Path, repo: Path, platform: str, role: str) -> dict:
    if not ROLE_NAME.fullmatch(role) or ".." in role:
        raise Stop(f"BLOCKED: invalid role name {role!r}: a role is a plain file name such as "
                   "issue-coder (no path separators, no '..', not empty)")
    result = verify(snapshot)
    top = Path(os.path.realpath(toplevel(repo)))
    rel = ROLE_FILES[platform].format(role=role)
    here = Path(os.path.realpath(top / rel))
    if not (top / rel).exists() or not here.is_file():
        raise Stop(f"BLOCKED: {rel} is missing in the checkout; the runtime would not load "
                   "the verified role. Do not install or substitute a role silently")
    if top != here and top not in here.parents:
        raise Stop(f"BLOCKED: {rel} resolves outside the checkout ({here})")
    there = Path(os.path.realpath(Path(result["snapshot_dir"]) / rel))
    if not there.is_file():
        raise Stop(f"BLOCKED: {rel} is not in the snapshot")
    if sha256(here) != sha256(there):
        raise Stop(f"BLOCKED: {rel} in the checkout differs from the verified snapshot copy; "
                   "the checked-out branch changed the role definition")
    return {"role": role, "platform": platform, "file": rel, "sha256": sha256(here),
            "snapshot_dir": result["snapshot_dir"]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("create")
    c.add_argument("--repo", type=Path, default=Path("."))
    c.add_argument("--out-parent", type=Path)
    v = sub.add_parser("verify")
    v.add_argument("--snapshot", type=Path, required=True)
    r = sub.add_parser("verify-role")
    r.add_argument("--snapshot", type=Path, required=True)
    r.add_argument("--repo", type=Path, default=Path("."))
    r.add_argument("--platform", choices=sorted(ROLE_FILES), required=True)
    r.add_argument("--role", required=True)
    args = parser.parse_args(argv)
    try:
        if args.cmd == "create":
            body = create(args.repo, args.out_parent)
        elif args.cmd == "verify":
            body = verify(args.snapshot)
        else:
            body = verify_role(args.snapshot, args.repo, args.platform, args.role)
        report = {"status": "PASS", **body}
    except (Stop, OSError) as exc:
        report = {"status": "STOP", "error": str(exc)}
    json.dump(report, sys.stdout, indent=2)
    sys.stdout.write("\n")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
