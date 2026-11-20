#!/usr/bin/env python3
"""Paginated read-only list of the open, non-draft PRs in a GitHub repository that pr-review-merge can act on.

Left out (listed under `excluded` with the reason): a PR the merge train owns (`merge-queue` label) and a
PR waiting for a person (`needs-person` label, while its HEAD is the one the actor's needs-person comment
names). A PR whose HEAD moved since that comment is listed again with `stale_needs_person: true`: the push
may have resolved what it waited for, and the next pr-review-merge run removes the stale label.
"""
import argparse
import json
import sys

# Running from the skill snapshot must not add __pycache__ there: `skill_snapshot.py verify`
# counts any added file and would STOP every later step. Set before the first sibling import.
sys.dont_write_bytecode = True
from gh_runtime import GitHubError, Repo, current_repo, issue_comments, list_open_prs, viewer_login
import needs_person

# merge_train.QUEUE_LABEL, kept here so listing does not load the train (and through it the gate);
# tests/test_handoff.py fails when the two differ.
QUEUE_LABEL = "merge-queue"


def _labels(pr):
    labels = pr.get("labels")
    return {item.get("name") for item in labels if isinstance(item, dict)} if isinstance(labels, list) else set()


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", help="OWNER/REPO; defaults to current gh repository")
    args = p.parse_args()
    try:
        repo = Repo.parse(args.repo) if args.repo else current_repo()
        prs = list_open_prs(repo)
        output, excluded = [], []
        viewer = None
        for pr in prs:
            if pr.get("state") != "open" or pr.get("draft") is not False:
                continue
            number, head = pr.get("number"), pr.get("head", {}).get("sha")
            labels = _labels(pr)
            entry = {"number": number, "url": pr.get("html_url"),
                     "title": pr.get("title"), "head_sha": head,
                     "base_sha": pr.get("base", {}).get("sha"),
                     "base_branch": pr.get("base", {}).get("ref")}
            if QUEUE_LABEL in labels:
                excluded.append({"number": number, "reason": f"{QUEUE_LABEL}: the merge train owns it"})
                continue
            if needs_person.LABEL in labels:
                if viewer is None:
                    viewer = viewer_login(repo)
                marker = needs_person.latest_marker(issue_comments(repo, number), viewer)
                if marker and isinstance(head, str) and marker["head"] == head.lower():
                    excluded.append({"number": number,
                                     "reason": f"{needs_person.LABEL}: waiting for a person at HEAD {head[:12]}"})
                    continue
                entry["stale_needs_person"] = True
            output.append(entry)
        print(json.dumps({"repository": repo.raw, "count": len(output), "pull_requests": output,
                          "excluded": excluded}, indent=2))
        return 0
    except (GitHubError, ValueError) as exc:
        print(json.dumps({"error": str(exc), "pull_requests": []}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
