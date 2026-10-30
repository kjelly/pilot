#!/usr/bin/env python3
"""Small, stdlib-only and testable GitHub CLI adapter for pr-review-merge."""
from __future__ import annotations
import json
import re
import subprocess
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote


class GitHubError(RuntimeError):
    pass


@dataclass(frozen=True)
class Repo:
    raw: str
    owner: str
    name: str
    host: str | None = None

    @classmethod
    def parse(cls, value: str) -> "Repo":
        chunks = value.strip().split("/")
        if len(chunks) not in (2, 3) or not all(re.fullmatch(r"[A-Za-z0-9_.-]+", c) for c in chunks):
            raise ValueError("repo must be OWNER/REPO or HOST/OWNER/REPO")
        if len(chunks) == 2:
            return cls(value, chunks[0], chunks[1])
        return cls(value, chunks[1], chunks[2], chunks[0])


def run_gh(args: list[str], *, input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    try:
        completed = subprocess.run(["gh", *args], input=input_text, text=True, capture_output=True, timeout=75)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitHubError(f"gh unavailable or timed out: {exc}") from exc
    if check and completed.returncode != 0:
        raise GitHubError(f"gh {' '.join(args[:4])} failed ({completed.returncode}): {completed.stderr.strip()[:500]}")
    return completed


def parse_json(text: str, what: str) -> Any:
    try:
        return json.loads(text)
    except (ValueError, TypeError) as exc:
        raise GitHubError(f"Could not parse {what} JSON") from exc


def gh_json(args: list[str], *, input_text: str | None = None) -> Any:
    return parse_json(run_gh(args, input_text=input_text).stdout, "gh response")


def current_repo() -> Repo:
    raw = run_gh(["repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"]).stdout.strip()
    return Repo.parse(raw)


def host_args(repo: Repo) -> list[str]:
    return ["--hostname", repo.host] if repo.host else []


def pr_view(repo: Repo, number: int) -> dict[str, Any]:
    fields = "number,url,title,body,state,isDraft,headRefOid,baseRefOid,baseRefName,mergeable,mergeStateStatus,reviewDecision,autoMergeRequest"
    data = gh_json(["pr", "view", str(number), "-R", repo.raw, "--json", fields])
    if not isinstance(data, dict) or data.get("number") != number:
        raise GitHubError("gh pr view returned invalid PR/number")
    return data


def pr_checks(repo: Repo, number: int) -> list[dict[str, Any]]:
    cp = run_gh(["pr", "checks", str(number), "-R", repo.raw,
                 "--json", "name,state,bucket,link,workflow"], check=False)
    # gh checks may exit nonzero for failing or pending checks; valid JSON still describes them.
    # Empty stdout with a nonzero rc is *not* proof there is no CI.
    if not cp.stdout.strip():
        raise GitHubError(f"gh pr checks returned no machine-readable result ({cp.returncode}): {cp.stderr.strip()[:200]}")
    result = parse_json(cp.stdout, "PR checks")
    if not isinstance(result, list) or not all(isinstance(x, dict) for x in result):
        raise GitHubError("Invalid PR checks response")
    return result


THREAD_QUERY = """query($owner:String!,$name:String!,$number:Int!,$after:String){
  repository(owner:$owner,name:$name){
    pullRequest(number:$number){
      reviewThreads(first:100,after:$after){
        nodes { isResolved isOutdated }
        pageInfo { hasNextPage endCursor }
      }
    }
  }
}"""


def unresolved_threads(repo: Repo, number: int) -> int:
    cursor: str | None = None
    total = 0
    for _ in range(100):
        payload = {"query": THREAD_QUERY, "variables": {
            "owner": repo.owner, "name": repo.name, "number": number, "after": cursor}}
        response = gh_json(["api", *host_args(repo), "graphql", "--input", "-"],
                           input_text=json.dumps(payload))
        if not isinstance(response, dict) or response.get("errors"):
            raise GitHubError("GraphQL returned errors for review threads")
        try:
            collection = response["data"]["repository"]["pullRequest"]["reviewThreads"]
            nodes = collection["nodes"]
            page = collection["pageInfo"]
            if not isinstance(nodes, list):
                raise TypeError("nodes")
            total += sum(node.get("isResolved") is not True for node in nodes)
            if not page["hasNextPage"]:
                return total
            cursor = page["endCursor"]
            if not isinstance(cursor, str) or not cursor:
                raise TypeError("missing pagination cursor")
        except (TypeError, KeyError, AttributeError) as exc:
            raise GitHubError("Invalid reviewThreads GraphQL response") from exc
    raise GitHubError("Review thread pagination exceeded safety limit")


def branch_rules(repo: Repo, base_name: str) -> list[dict[str, Any]]:
    endpoint = f"repos/{repo.owner}/{repo.name}/rules/branches/{quote(base_name, safe='')}?per_page=100"
    result = gh_json(["api", *host_args(repo), "--paginate", "--slurp", endpoint])
    if not isinstance(result, list):
        raise GitHubError("Unexpected branch rules response")
    # --slurp wraps all pages. Multiple pages of 100 are supported.
    rules = [rule for page in result for rule in page] if result and isinstance(result[0], list) else result
    if not all(isinstance(rule, dict) and isinstance(rule.get("type"), str) for rule in rules):
        raise GitHubError("Invalid active branch rules")
    return rules


def list_open_prs(repo: Repo) -> list[dict[str, Any]]:
    endpoint = f"repos/{repo.owner}/{repo.name}/pulls?state=open&per_page=100"
    result = gh_json(["api", *host_args(repo), "--paginate", "--slurp", endpoint])
    if not isinstance(result, list) or not all(isinstance(p, list) for p in result):
        raise GitHubError("gh api --paginate --slurp did not return pages")
    prs = [pr for page in result for pr in page]
    if not all(isinstance(pr, dict) for pr in prs):
        raise GitHubError("Invalid PR list response")
    return prs
