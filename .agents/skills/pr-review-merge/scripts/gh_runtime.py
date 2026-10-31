#!/usr/bin/env python3
"""Small, stdlib-only and testable GitHub CLI adapter for pr-review-merge."""
from __future__ import annotations
import base64
import binascii
import json
import re
import subprocess
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote

COMMIT_SHA = re.compile(r"[0-9a-f]{40}\Z")
# GitHub's compare API lists at most 300 changed files for the whole comparison and says
# nothing when it cuts the list (a 1554-commit compare of kjelly/pilot returned exactly 300).
COMPARE_FILE_LIMIT = 300


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


def _not_found(cp: subprocess.CompletedProcess[str]) -> bool:
    """True only for gh's exact answer to a path or commit GitHub does not have.

    Captured from `gh api` against kjelly/pilot: exit status 1, stdout
    {"message":"Not Found",...,"status":"404"}, stderr "gh: Not Found (HTTP 404)". An
    unknown ref for the contents API answers "No commit found for the ref ..." instead,
    and every other failure (auth, rate limit, 5xx) also differs: those raise.
    """
    if cp.returncode != 1 or cp.stderr.strip() != "gh: Not Found (HTTP 404)":
        return False
    try:
        body = json.loads(cp.stdout)
    except ValueError:
        return False
    return isinstance(body, dict) and body.get("message") == "Not Found" and body.get("status") == "404"


def file_at(repo: Repo, path: str, ref: str) -> bytes | None:
    """Content of a regular file at commit `ref`, or None when GitHub has no such path there."""
    if not COMMIT_SHA.fullmatch(ref):
        raise ValueError(f"file_at needs a full lowercase commit SHA, got {ref!r}")
    endpoint = f"repos/{repo.owner}/{repo.name}/contents/{quote(path, safe='/')}?ref={ref}"
    cp = run_gh(["api", *host_args(repo), endpoint], check=False)
    if cp.returncode != 0:
        if _not_found(cp):
            return None
        raise GitHubError(f"gh api contents {path} at {ref[:12]} failed ({cp.returncode}): {cp.stderr.strip()[:300]}")
    data = parse_json(cp.stdout, "contents")
    if isinstance(data, list):
        raise GitHubError(f"{path} is a directory at {ref[:12]}, not a file")
    if not isinstance(data, dict) or data.get("type") != "file" or data.get("path") != path:
        raise GitHubError(f"{path} at {ref[:12]} is not a regular file at that path")
    if data.get("encoding") != "base64" or not isinstance(data.get("content"), str):
        raise GitHubError(f"GitHub did not return the content of {path} at {ref[:12]} (file too large?)")
    try:
        return base64.b64decode(data["content"])
    except (ValueError, binascii.Error) as exc:
        raise GitHubError(f"Undecodable content for {path} at {ref[:12]}") from exc


def compare(repo: Repo, base: str, head: str) -> dict[str, Any] | None:
    """Files changed from the merge base of `base` and `head` to `head`, and whether `base` is an
    ancestor of `head`; None when GitHub does not know one of the commits.

    `files` lists both names of a rename (`previous_filename` too), like `git diff --no-renames`.
    A comparison GitHub may have cut at COMPARE_FILE_LIMIT files raises: it cannot be verified.
    """
    if not (COMMIT_SHA.fullmatch(base) and COMMIT_SHA.fullmatch(head)):
        raise ValueError("compare needs two full lowercase commit SHAs")
    cp = run_gh(["api", *host_args(repo), f"repos/{repo.owner}/{repo.name}/compare/{base}...{head}"], check=False)
    if cp.returncode != 0:
        if _not_found(cp):
            return None
        raise GitHubError(f"gh api compare {base[:12]}...{head[:12]} failed ({cp.returncode}): {cp.stderr.strip()[:300]}")
    data = parse_json(cp.stdout, "compare")
    try:
        status, behind, merge_base = data["status"], data["behind_by"], data["merge_base_commit"]["sha"]
        entries = data["files"]
        if status not in ("ahead", "behind", "identical", "diverged") or not isinstance(behind, int) \
                or not isinstance(merge_base, str) or not isinstance(entries, list):
            raise TypeError("compare fields")
        files: list[str] = []
        for entry in entries:
            names = [entry["filename"]] + ([entry["previous_filename"]] if "previous_filename" in entry else [])
            if not all(isinstance(name, str) and name for name in names):
                raise TypeError("file name")
            files.extend(names)
    except (KeyError, TypeError) as exc:
        raise GitHubError("Invalid compare response") from exc
    if len(entries) >= COMPARE_FILE_LIMIT:
        raise GitHubError(f"GitHub lists at most {COMPARE_FILE_LIMIT} changed files for {base[:12]}...{head[:12]}; "
                          "the full delta cannot be verified")
    return {"status": status, "files": files,
            "ancestor": status in ("ahead", "identical") and behind == 0 and merge_base.lower() == base}


def list_open_prs(repo: Repo) -> list[dict[str, Any]]:
    endpoint = f"repos/{repo.owner}/{repo.name}/pulls?state=open&per_page=100"
    result = gh_json(["api", *host_args(repo), "--paginate", "--slurp", endpoint])
    if not isinstance(result, list) or not all(isinstance(p, list) for p in result):
        raise GitHubError("gh api --paginate --slurp did not return pages")
    prs = [pr for page in result for pr in page]
    if not all(isinstance(pr, dict) for pr in prs):
        raise GitHubError("Invalid PR list response")
    return prs
