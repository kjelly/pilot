#!/usr/bin/env python3
"""Reuse a completed full PR validation only across an evidence-only delta.

Artifacts bind the original PR base, head and run attempt. Missing history,
expired artifacts, API failures and unknown input always select a full run.
"""
import argparse
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

SHA = re.compile(r"[0-9a-f]{40}")
REPO = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


def git(*args):
    return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL)


def api(path, binary=False):
    data = subprocess.check_output(["gh", "api", path], stderr=subprocess.PIPE, timeout=45)
    return data if binary else json.loads(data)


def evidence_delta(candidate, head):
    if not SHA.fullmatch(candidate) or not SHA.fullmatch(head) or candidate == head:
        return False
    if subprocess.run(["git", "merge-base", "--is-ancestor", candidate, head],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        return False
    paths = git("diff", "--name-only", "--no-renames", "-z", candidate, head).split(b"\0")
    paths = [p for p in paths if p]
    # No rename inference: moving executable input into evidence still changes
    # the old path. Git modes and symlink targets are included in this diff.
    return bool(paths) and all(p.startswith(b"docs/evidence/") for p in paths)


def context(event, env):
    pr = event["pull_request"]
    repo = env["GITHUB_REPOSITORY"]
    if env.get("GITHUB_EVENT_NAME") != "pull_request" or not REPO.fullmatch(repo):
        raise ValueError("only same-repository pull_request runs can reuse validation")
    if pr["head"]["repo"]["full_name"] != repo or pr["base"]["repo"]["full_name"] != repo:
        raise ValueError("fork PRs run full validation")
    base, head = pr["base"]["sha"], pr["head"]["sha"]
    if not SHA.fullmatch(base) or not SHA.fullmatch(head):
        raise ValueError("invalid commit identity")
    if git("rev-parse", "HEAD").decode().strip() != head:
        raise ValueError("checkout must be the exact PR head")
    return {"schema_version": 1, "repository": repo, "pr_number": pr["number"],
            "base_sha": base, "head_sha": head, "validation": "full"}


def read_receipt(repo, run):
    rid, attempt = int(run["id"]), int(run["run_attempt"])
    data = api(f"repos/{repo}/actions/runs/{rid}/artifacts?per_page=100")
    matches = [a for a in data["artifacts"]
               if a["name"] == f"ci-validation-{attempt}" and not a["expired"]]
    if len(matches) != 1 or matches[0]["size_in_bytes"] > 65536:
        return None
    raw = api(f"repos/{repo}/actions/artifacts/{int(matches[0]['id'])}/zip", binary=True)
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        if archive.namelist() != ["ci-validation.json"]:
            return None
        info = archive.getinfo("ci-validation.json")
        if info.file_size > 16384:
            return None
        return json.loads(archive.read(info))


def find_candidate(ctx, current_id):
    repo = ctx["repository"]
    current = api(f"repos/{repo}/actions/runs/{current_id}")
    workflow = int(current["workflow_id"])
    # A bounded search can miss a reusable run; that safely costs a full run.
    runs = api(f"repos/{repo}/actions/workflows/{workflow}/runs?event=pull_request&per_page=100")
    for listed in runs["workflow_runs"]:
        if listed["id"] == current_id or not evidence_delta(listed["head_sha"], ctx["head_sha"]):
            continue
        # Re-read instead of trusting a list cached before a rerun was requested.
        run = api(f"repos/{repo}/actions/runs/{int(listed['id'])}")
        age = datetime.now(timezone.utc) - datetime.fromisoformat(run["created_at"].replace("Z", "+00:00"))
        if (run["status"] != "completed" or run["conclusion"] != "success"
                or run["event"] != "pull_request" or run["workflow_id"] != workflow
                or run["head_repository"]["full_name"] != repo
                or run["head_sha"] != listed["head_sha"]
                or age < timedelta(0) or age > timedelta(hours=24)):
            continue
        receipt = read_receipt(repo, run)
        expected = {**ctx, "head_sha": run["head_sha"], "run_id": run["id"],
                    "run_attempt": run["run_attempt"], "workflow_id": workflow}
        if receipt != expected:
            continue
        # Bind the decision to the latest attempt even if a rerun started
        # while the artifact was being downloaded.
        latest = api(f"repos/{repo}/actions/runs/{int(run['id'])}")
        if (latest["run_attempt"] == run["run_attempt"] and latest["status"] == "completed"
                and latest["conclusion"] == "success"):
            return run
    return None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--record", type=Path, help="write a receipt after every full CI job succeeded")
    args = parser.parse_args()
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text())
        ctx = context(event, os.environ)
        rid = int(os.environ["GITHUB_RUN_ID"])
        if args.record:
            run = api(f"repos/{ctx['repository']}/actions/runs/{rid}")
            receipt = {**ctx, "run_id": rid, "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
                       "workflow_id": run["workflow_id"]}
            args.record.write_text(json.dumps(receipt, sort_keys=True) + "\n")
            return 0
        run = find_candidate(ctx, rid)
        print(f"evidence_only={'true' if run else 'false'}")
        print(f"reused_run_id={run['id'] if run else ''}")
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            with open(summary, "a") as out:
                out.write(f"CI validation: {'reuse full run ' + str(run['id']) if run else 'full run required'}\n")
    except (OSError, ValueError, KeyError, TypeError, zipfile.BadZipFile,
            subprocess.SubprocessError) as exc:
        if args.record:
            print(f"cannot record validation: {type(exc).__name__}", file=sys.stderr)
            return 1
        print(f"Full validation required: {type(exc).__name__}", file=sys.stderr)
        print("evidence_only=false\nreused_run_id=")
    return 0


if __name__ == "__main__":
    sys.exit(main())
