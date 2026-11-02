#!/usr/bin/env python3
"""Check every required role before work starts, then request real runtime probes.

Static file checks cannot prove that the current session can launch a role.
No configuration is installed or changed by this helper.
"""
import argparse
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
import skill_snapshot

ROLES = {"issue-to-pr": ["issue-sa", "issue-coder", "issue-reviewer"],
         "pr-ready": ["pr-sa", "pr-coder", "pr-reviewer"],
         "pr-review-merge": ["prm-reviewer"]}


def preflight(snapshot, repo, platform, workflow, dependency=False):
    reports = []
    warnings = []
    roles = ROLES[workflow] + (["prm-dependency"] if dependency and workflow == "pr-review-merge" else [])
    for role in roles:
        report = skill_snapshot.verify_role(snapshot, repo, platform, role)
        reports.append(report)
        # The Codex config loader can reject symlinks that normal open() accepts.
        if platform == "codex" and Path(report["checkout_role"]).is_symlink():
            warnings.append(f"{role}: installed Codex role is a symlink; the native loader "
                            "may reject it even when file validation succeeds. Inspect the "
                            "real launch result and follow the platform dispatch contract.")
    return {"status": "LAUNCH_REQUIRED", "workflow": workflow, "roles": reports,
            "warnings": warnings,
            "runtime_verified": False,
            "next": "Launch each required role in a fresh read-only context through the host; "
                    "save success/failure, session identity, role hash and actual model/effort "
                    "in the item checkpoint before implementation or expensive tests. "
                    "A dependency role is probed only when the selected PR needs it."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--platform", choices=["codex", "claude", "agy"], required=True)
    parser.add_argument("--workflow", choices=ROLES, required=True)
    parser.add_argument("--dependency", action="store_true", help="include optional merge dependency role")
    args = parser.parse_args()
    try:
        result = preflight(args.snapshot, args.repo, args.platform, args.workflow, args.dependency)
        print(json.dumps(result, indent=2))
        return 0
    except (skill_snapshot.Stop, OSError) as exc:
        print(json.dumps({"status": "STOP", "error": str(exc)}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
