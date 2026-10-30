#!/usr/bin/env python3
"""Paginated read-only list of all open, non-draft PRs in a GitHub repository."""
import argparse
import json
from gh_runtime import GitHubError, Repo, current_repo, list_open_prs


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", help="OWNER/REPO; defaults to current gh repository")
    args = p.parse_args()
    try:
        repo = Repo.parse(args.repo) if args.repo else current_repo()
        prs = list_open_prs(repo)
        output = []
        for pr in prs:
            if pr.get("state") != "open" or pr.get("draft") is not False:
                continue
            output.append({"number": pr.get("number"), "url": pr.get("html_url"),
                           "title": pr.get("title"), "head_sha": pr.get("head", {}).get("sha"),
                           "base_sha": pr.get("base", {}).get("sha"),
                           "base_branch": pr.get("base", {}).get("ref")})
        print(json.dumps({"repository": repo.raw, "count": len(output), "pull_requests": output}, indent=2))
        return 0
    except (GitHubError, ValueError) as exc:
        print(json.dumps({"error": str(exc), "pull_requests": []}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
