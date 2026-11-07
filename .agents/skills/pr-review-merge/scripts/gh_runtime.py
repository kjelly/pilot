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


class CompareLimitError(GitHubError):
    """GitHub cut a comparison's file list: nothing a retry fixes, so a person must integrate the PR."""


class MutationLockError(RuntimeError):
    """The repository mutation lock (`apply_decision.repo_mutation_lock`) could not be taken. Nothing was
    written. Deliberately not a `GitHubError`: it says nothing about GitHub, and the two causes below are
    told apart by type, never by message."""


class MutationLockHeld(MutationLockError):
    """Another pr-review-merge actor holds the lock right now: wait, and try again on the next run."""


class MutationLockUnavailable(MutationLockError):
    """The lock cannot be used at all (its directory or file cannot be created, opened or locked): an
    infrastructure failure that waiting does not fix."""


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
    fields = ("number,url,title,body,state,isDraft,headRefOid,headRefName,isCrossRepository,baseRefOid,"
              "baseRefName,mergeable,mergeStateStatus,reviewDecision,autoMergeRequest,labels")
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


def branch_head(repo: Repo, name: str) -> str:
    """Resolve the live branch; pullRequest.baseRefOid can lag after another PR merges."""
    if not isinstance(name, str) or not name:
        raise GitHubError("Live base branch name unavailable")
    data = gh_json(["api", *host_args(repo), "-H", "Cache-Control: no-cache",
                    f"repos/{repo.owner}/{repo.name}/git/ref/heads/{quote(name, safe='')}"])
    obj = data.get("object") if isinstance(data, dict) else None
    sha = obj.get("sha") if isinstance(obj, dict) else None
    if not isinstance(obj, dict) or obj.get("type") != "commit" or \
            not isinstance(sha, str) or not COMMIT_SHA.fullmatch(sha):
        raise GitHubError("Live base branch SHA unavailable")
    return sha


def is_ancestor(repo: Repo, base: str, head: str) -> bool:
    """Check commit ancestry from compare metadata, independent of its file-list limit."""
    if not (COMMIT_SHA.fullmatch(base) and COMMIT_SHA.fullmatch(head)):
        raise ValueError("is_ancestor needs two full lowercase commit SHAs")
    data = gh_json(["api", *host_args(repo), f"repos/{repo.owner}/{repo.name}/compare/{base}...{head}"])
    try:
        status, behind = data["status"], data["behind_by"]
        merge_base = data["merge_base_commit"]["sha"]
        if status not in ("ahead", "behind", "identical", "diverged") or type(behind) is not int or behind < 0 \
                or not isinstance(merge_base, str) or not COMMIT_SHA.fullmatch(merge_base):
            raise ValueError("compare metadata")
        if status in ("ahead", "identical") and behind == 0 and merge_base == base:
            return True
        if status in ("behind", "diverged") and behind > 0 and merge_base != base:
            return False
    except (KeyError, TypeError, ValueError) as exc:
        raise GitHubError("Invalid ancestry comparison response") from exc
    raise GitHubError("Inconsistent ancestry comparison response")


def merge_base(repo: Repo, a: str, b: str) -> str:
    """The merge base GitHub reports for `a...b`, independent of the compare file-list limit."""
    if not (COMMIT_SHA.fullmatch(a) and COMMIT_SHA.fullmatch(b)):
        raise ValueError("merge_base needs two full lowercase commit SHAs")
    data = gh_json(["api", *host_args(repo), f"repos/{repo.owner}/{repo.name}/compare/{a}...{b}"])
    try:
        sha = data["merge_base_commit"]["sha"]
    except (KeyError, TypeError) as exc:
        raise GitHubError("Invalid compare response: no merge base") from exc
    if not isinstance(sha, str) or not COMMIT_SHA.fullmatch(sha):
        raise GitHubError("Invalid merge base SHA")
    return sha


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
                or not isinstance(merge_base, str) or not COMMIT_SHA.fullmatch(merge_base) or not isinstance(entries, list):
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
        raise CompareLimitError(f"GitHub lists at most {COMPARE_FILE_LIMIT} changed files for {base[:12]}...{head[:12]}; "
                                "the full delta cannot be verified")
    return {"status": status, "files": files, "merge_base": merge_base,
            "ancestor": status in ("ahead", "identical") and behind == 0 and merge_base.lower() == base}


def commit_tree(repo: Repo, revision: str) -> str:
    if not COMMIT_SHA.fullmatch(revision):
        raise ValueError("commit_tree needs a full lowercase commit SHA")
    cp = run_gh(["api", *host_args(repo), f"repos/{repo.owner}/{repo.name}/git/commits/{revision}"])
    data = parse_json(cp.stdout, "commit")
    tree = data.get("tree", {}).get("sha") if isinstance(data, dict) else None
    if not isinstance(tree, str) or not COMMIT_SHA.fullmatch(tree):
        raise GitHubError("Invalid commit tree response")
    return tree


def tree_entries(repo: Repo, revision: str) -> dict[str, tuple[str, str]]:
    """Complete path -> (mode, object id) map; no content decoding or symlink following.

    GitHub returns truncated=true for oversized recursive trees. Never compare a
    partial tree: deletions/renames and omitted dependencies must remain visible.
    """
    if not COMMIT_SHA.fullmatch(revision):
        raise ValueError("tree_entries needs a full lowercase commit SHA")
    data = gh_json(["api", *host_args(repo),
                    f"repos/{repo.owner}/{repo.name}/git/trees/{revision}?recursive=1"])
    if not isinstance(data, dict) or data.get("truncated") is not False or not isinstance(data.get("tree"), list):
        raise GitHubError("Complete Git tree unavailable (truncated or invalid response)")
    result = {}
    seen = set()
    for entry in data["tree"]:
        if not isinstance(entry, dict):
            raise GitHubError("Invalid Git tree entry")
        path, mode, oid = entry.get("path"), entry.get("mode"), entry.get("sha")
        kind = {"040000": "tree", "160000": "commit"}.get(mode, "blob")
        if (not isinstance(path, str) or not path or path in seen or
                mode not in ("040000", "100644", "100755", "120000", "160000") or
                entry.get("type") != kind or
                not isinstance(oid, str) or not COMMIT_SHA.fullmatch(oid)):
            raise GitHubError("Invalid Git tree path, mode or object id")
        seen.add(path)
        if kind == "tree":
            continue
        result[path] = (mode, oid)
    return result


def list_open_prs(repo: Repo) -> list[dict[str, Any]]:
    endpoint = f"repos/{repo.owner}/{repo.name}/pulls?state=open&per_page=100"
    result = gh_json(["api", *host_args(repo), "--paginate", "--slurp", endpoint])
    if not isinstance(result, list) or not all(isinstance(p, list) for p in result):
        raise GitHubError("gh api --paginate --slurp did not return pages")
    prs = [pr for page in result for pr in page]
    if not all(isinstance(pr, dict) for pr in prs):
        raise GitHubError("Invalid PR list response")
    return prs


def labeled_open_prs(repo: Repo, label: str) -> list[int]:
    """Open pull requests carrying `label` (the issues endpoint lists PRs with a `pull_request` key)."""
    endpoint = (f"repos/{repo.owner}/{repo.name}/issues?state=open&labels={quote(label, safe='')}"
                "&per_page=100")
    result = gh_json(["api", *host_args(repo), "--paginate", "--slurp", endpoint])
    if not isinstance(result, list) or not all(isinstance(page, list) for page in result):
        raise GitHubError("gh api --paginate --slurp did not return pages")
    numbers = []
    for item in (entry for page in result for entry in page):
        if not isinstance(item, dict) or type(item.get("number")) is not int:
            raise GitHubError("Invalid issue list entry")
        if "pull_request" in item:
            numbers.append(item["number"])
    return numbers


def label_added_at(repo: Repo, number: int, label: str) -> str | None:
    """ISO time `label` was last added to the PR (timeline `labeled` events), or None."""
    endpoint = f"repos/{repo.owner}/{repo.name}/issues/{number}/timeline?per_page=100"
    result = gh_json(["api", *host_args(repo), "--paginate", "--slurp", endpoint])
    if not isinstance(result, list) or not all(isinstance(page, list) for page in result):
        raise GitHubError("gh api --paginate --slurp did not return pages")
    added = None
    for event in (entry for page in result for entry in page):
        if not isinstance(event, dict) or event.get("event") != "labeled":
            continue
        name = (event.get("label") or {}).get("name") if isinstance(event.get("label"), dict) else None
        created = event.get("created_at")
        if name == label:
            if not isinstance(created, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", created):
                raise GitHubError("Invalid labeled event time")
            added = created if added is None or created > added else added
    return added


def edit_label(repo: Repo, number: int, label: str, *, add: bool) -> None:
    run_gh(["pr", "edit", str(number), "-R", repo.raw, "--add-label" if add else "--remove-label", label])


def post_comment(repo: Repo, number: int, body: str) -> None:
    import os
    import tempfile
    filename = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", suffix=".md", prefix="prm-",
                                         delete=False) as tmp:
            tmp.write(body)
            filename = tmp.name
        run_gh(["pr", "comment", str(number), "-R", repo.raw, "--body-file", filename])
    finally:
        if filename:
            try:
                os.unlink(filename)
            except OSError:
                pass


def mark_draft(repo: Repo, number: int) -> None:
    run_gh(["pr", "ready", str(number), "-R", repo.raw, "--undo"])


def merge_pr(repo: Repo, number: int, head: str, method_flag: str = "--merge") -> None:
    run_gh(["pr", "merge", str(number), "-R", repo.raw, method_flag, "--match-head-commit", head])
