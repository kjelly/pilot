#!/usr/bin/env python3
"""Reuse a completed full PR validation only across an evidence-only delta.

Artifacts bind the frozen tested merge, its tree and actual base/head parents,
plus the run attempt. Missing history, expired artifacts, API failures and
unknown input always select a full run.
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
    return subprocess.check_output(["git", *args], stderr=subprocess.DEVNULL, timeout=45)


def api(path, binary=False):
    data = subprocess.check_output(["gh", "api", path], stderr=subprocess.PIPE, timeout=45)
    return data if binary else json.loads(data)


def evidence_paths_only(before, after, allow_empty=False):
    paths = git("diff", "--name-only", "--no-renames", "-z", before, after).split(b"\0")
    paths = [p for p in paths if p]
    # No rename inference: moving executable input into evidence still changes
    # the old path. Git modes and symlink targets are included in this diff.
    return (bool(paths) or allow_empty) and all(p.startswith(b"docs/evidence/") for p in paths)


def evidence_delta(candidate, head):
    if not SHA.fullmatch(candidate) or not SHA.fullmatch(head) or candidate == head:
        return False
    if subprocess.run(["git", "merge-base", "--is-ancestor", candidate, head],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45).returncode:
        return False
    return evidence_paths_only(candidate, head)


def tested_inputs(merge_sha, head_sha, fetch=False):
    """Read immutable commit headers, including parents of a shallow fetch.

    Old GitHub synthetic merges may no longer be reachable from any local ref.
    Fetch only the validated object ID, never a moving pull/main ref, and never
    replace or check out the current worktree. Unavailable objects deny reuse.
    """
    if not isinstance(merge_sha, str) or not SHA.fullmatch(merge_sha):
        raise ValueError("invalid tested merge identity")
    if not isinstance(head_sha, str) or not SHA.fullmatch(head_sha):
        raise ValueError("invalid tested head identity")
    try:
        commit = git("cat-file", "commit", merge_sha)
    except subprocess.CalledProcessError:
        if not fetch:
            raise
        subprocess.run(["git", "fetch", "--no-tags", "--no-write-fetch-head",
                        "--recurse-submodules=no", "--depth=1", "origin", merge_sha],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=45)
        commit = git("cat-file", "commit", merge_sha)
    header = commit.split(b"\n\n", 1)[0].decode()
    parents = [line.removeprefix("parent ") for line in header.splitlines() if line.startswith("parent ")]
    trees = [line.removeprefix("tree ") for line in header.splitlines() if line.startswith("tree ")]
    if len(parents) != 2 or parents[1] != head_sha or any(not SHA.fullmatch(p) for p in parents):
        raise ValueError("tested merge must have the actual base and exact PR head as its two parents")
    if len(trees) != 1 or not SHA.fullmatch(trees[0]):
        raise ValueError("invalid tested merge tree")
    return {"base_sha": parents[0], "head_sha": head_sha,
            "tested_merge_sha": merge_sha, "tested_merge_tree": trees[0]}


def context(event, env):
    pr = event["pull_request"]
    repo = env["GITHUB_REPOSITORY"]
    if env.get("GITHUB_EVENT_NAME") != "pull_request" or not REPO.fullmatch(repo):
        raise ValueError("only same-repository pull_request runs can reuse validation")
    if pr["head"]["repo"]["full_name"] != repo or pr["base"]["repo"]["full_name"] != repo:
        raise ValueError("fork PRs run full validation")
    if type(pr["number"]) is not int or pr["number"] <= 0:
        raise ValueError("invalid PR identity")
    head, merge = pr["head"]["sha"], env["GITHUB_SHA"]
    if not SHA.fullmatch(pr["base"]["sha"]) or not SHA.fullmatch(head) or not SHA.fullmatch(merge):
        raise ValueError("invalid commit identity")
    if git("rev-parse", "HEAD").decode().strip() != merge:
        raise ValueError("checkout must be the exact frozen GITHUB_SHA merge")
    return {"schema_version": 2, "repository": repo, "pr_number": pr["number"],
            **tested_inputs(merge, head), "validation": "full"}


def run_matches(ctx, run, rid):
    return (run["id"] == rid and run["event"] == "pull_request"
            and type(run["workflow_id"]) is int and run["workflow_id"] > 0
            and type(run["run_attempt"]) is int and run["run_attempt"] > 0
            and run["head_repository"]["full_name"] == ctx["repository"]
            and run["head_sha"] == ctx["head_sha"])


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
    # Also verify a caller-supplied context rather than trusting tree/base fields.
    inputs = tested_inputs(ctx["tested_merge_sha"], ctx["head_sha"])
    if ctx["schema_version"] != 2 or any(ctx[k] != v for k, v in inputs.items()):
        return None
    current = api(f"repos/{repo}/actions/runs/{current_id}")
    if not run_matches(ctx, current, current_id):
        return None
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
        if not isinstance(receipt, dict) or receipt.get("schema_version") != 2:
            continue
        try:
            prior = tested_inputs(receipt.get("tested_merge_sha"), run["head_sha"], fetch=True)
        except (OSError, ValueError, subprocess.SubprocessError):
            continue
        # The PR event's base can be stale. Compare the actual tested base
        # parents, then compare merged inputs independently of raw ancestry.
        if prior["base_sha"] != ctx["base_sha"]:
            continue
        expected = {**ctx, **prior, "run_id": run["id"],
                    "run_attempt": run["run_attempt"], "workflow_id": workflow}
        if receipt != expected:
            continue
        # Two synthetic merge commits are usually siblings, not ancestors.
        # An unchanged merged tree is also safe after a nonempty raw docs delta.
        if not evidence_paths_only(prior["tested_merge_tree"], ctx["tested_merge_tree"], allow_empty=True):
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
        if rid <= 0:
            raise ValueError("invalid run identity")
        if args.record:
            run = api(f"repos/{ctx['repository']}/actions/runs/{rid}")
            attempt = int(os.environ["GITHUB_RUN_ATTEMPT"])
            if not run_matches(ctx, run, rid) or run["run_attempt"] != attempt:
                raise ValueError("run metadata does not match the frozen validation context")
            receipt = {**ctx, "run_id": rid, "run_attempt": attempt,
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
