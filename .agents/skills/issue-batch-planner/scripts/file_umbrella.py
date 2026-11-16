#!/usr/bin/env python3
"""File one umbrella Issue for a user-approved MERGE_CANDIDATE batch of a REVIEWED planner report.

Dry run unless --execute: the dry run checks every precondition and writes the planned body to
--state-dir, but creates, edits and links nothing. This is the planner skill's only writer; every
external command goes through run_command(), which accepts only the forms in _command_problem().
Exit 0: done (or a successful dry run). Exit 2: refused, nothing was written to GitHub. Exit 3: partly
done or uncertain; the output says what is known, and a re-run continues without a second umbrella.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
import issue_batch_planner as planner  # noqa: E402

EXIT_OK, EXIT_REFUSED, EXIT_PARTIAL = 0, 2, 3
CREATE_ISSUE = Path(__file__).resolve().parents[2] / "issue-filing" / "scripts" / "create_issue.py"
VIEW_FIELDS = "number,state,url,body,parent,subIssues,labels,closedByPullRequestsReferences"
BATCH_ID_RE = re.compile(r"[0-9a-f]{12}\Z")
NUMBER_RE = re.compile(r"[1-9][0-9]{0,9}\Z")
LABEL_RE = re.compile(r"[^\x00-\x1f]{1,50}\Z")
MAX_BODY = 60000  # GitHub's limit is 65536 characters
MENTION_RE = re.compile(r"(?<![\w`])@[A-Za-z0-9][A-Za-z0-9-]*")


class Refused(RuntimeError):
    """A precondition failed; nothing was written to GitHub."""


class Partial(RuntimeError):
    """Something was or may have been written; `state` says what is known."""

    def __init__(self, message: str, state: dict[str, Any]) -> None:
        super().__init__(message)
        self.state = state


def marker(batch_id: str) -> str:
    return f"issue-batch-planner batch: {batch_id}"


# --------------------------------------------------------------------------- runner

def _command_problem(argv: Any) -> str | None:
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        return "argv must be a non-empty list of strings"
    repo_ok = lambda r: bool(planner.REPO_RE.fullmatch(r))  # noqa: E731
    if argv[:2] == [sys.executable, str(CREATE_ISSUE)]:
        rest = argv[2:]
        if (len(rest) >= 8 and rest[0] == "--repo" and repo_ok(rest[1]) and rest[2] == "--title" and rest[3].strip()
                and rest[4] == "--body-file" and rest[5] and len(rest[6:]) % 2 == 0
                and all(rest[i] == "--label" and LABEL_RE.fullmatch(rest[i + 1]) for i in range(6, len(rest), 2))):
            return None
        return "create_issue.py arguments are not in the expected form"
    if argv[0] != "gh":
        return f"{argv[0]!r} is not an allowed program"
    rest = argv[1:]
    if (len(rest) == 7 and rest[:2] == ["issue", "view"] and NUMBER_RE.fullmatch(rest[2]) and rest[3] == "-R"
            and repo_ok(rest[4]) and rest[5:] == ["--json", VIEW_FIELDS]):
        return None
    if (len(rest) == 12 and rest[:2] == ["issue", "list"] and rest[2] == "-R" and repo_ok(rest[3])
            and rest[4:7] == ["--state", "all", "--search"] and re.fullmatch(r"[0-9a-f]{12} in:body", rest[7])
            and rest[8:] == ["--limit", "20", "--json", "number,url,body"]):
        return None
    if (len(rest) == 10 and rest[:2] == ["pr", "list"] and rest[2] == "-R" and repo_ok(rest[3])
            and rest[4:] == ["--state", "open", "--limit", "1000", "--json", "number"]):
        return None
    if (len(rest) == 7 and rest[:2] == ["issue", "edit"] and NUMBER_RE.fullmatch(rest[2]) and rest[3] == "-R"
            and repo_ok(rest[4]) and rest[5] == "--add-sub-issue" and NUMBER_RE.fullmatch(rest[6])):
        return None
    return "gh command is not one of the allowed forms"


def run_command(argv: list[str], *, timeout: int = 120) -> planner.Result:
    """Run one allowed command. The only place in this script that starts a process."""
    problem = _command_problem(argv)
    if problem:
        raise Refused(f"refused {argv[:3]!r}: {problem}")
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise Refused(f"{argv[0]} failed to run: {exc}") from exc
    return planner.Result(p.returncode, p.stdout, p.stderr)


def _json(argv: list[str], what: str) -> Any:
    r = run_command(argv)
    if r.returncode != 0:
        raise Refused(f"{what} failed: {(r.stderr or r.stdout).strip()[:300]}")
    try:
        return json.loads(r.stdout)
    except json.JSONDecodeError as exc:
        raise Refused(f"{what} did not return JSON: {exc}") from exc


def view(repo: str, number: int) -> dict[str, Any]:
    data = _json(["gh", "issue", "view", str(number), "-R", repo, "--json", VIEW_FIELDS], f"gh issue view {number}")
    keys = ("number", "state", "url", "body", "parent", "subIssues", "labels", "closedByPullRequestsReferences")
    if not isinstance(data, dict) or any(k not in data for k in keys) or data["number"] != number \
            or not isinstance(data["subIssues"], dict) or not isinstance(data["subIssues"].get("nodes"), list) \
            or not isinstance(data["labels"], list) or not isinstance(data["closedByPullRequestsReferences"], list):
        raise Refused(f"unexpected gh issue view shape for #{number}")
    return data


def has_marker(body: Any, batch_id: str) -> bool:
    return isinstance(body, str) and marker(batch_id) in body.splitlines()


# --------------------------------------------------------------------------- inputs

def load_batch(report_path: Path, batch_id: str) -> tuple[dict[str, Any], dict[str, Any]]:
    report, _ = planner.read_json(report_path, "report")
    if not isinstance(report, dict) or report.get("schema_version") != planner.SCHEMA_VERSION:
        raise Refused("not a planner report")
    if report.get("status") != "REVIEWED":
        raise Refused(f"the report is {report.get('status')}, not REVIEWED; only reviewed batches get an umbrella")
    if report.get("content_sha256") != planner.report_content_sha256(report):
        raise Refused("the report's content_sha256 does not match its content (altered report)")
    batch = next((b for b in report.get("batches", []) if b.get("batch_id") == batch_id), None)
    if batch is None:
        raise Refused(f"batch {batch_id} is not in the report")
    if batch.get("classification") != "MERGE_CANDIDATE":
        raise Refused(f"batch {batch_id} is {batch.get('classification')}, not MERGE_CANDIDATE")
    return report, batch


def build_title(batch: dict[str, Any]) -> str:
    title = f"umbrella({batch['root_cause_class']}): {batch['invariant']}"
    return title if len(title) <= 120 else title[:117].rstrip() + "..."


def build_body(report: dict[str, Any], batch: dict[str, Any]) -> str:
    primary = batch["primary_issue"]
    coverage = {a["issue"]: a for a in batch["acceptance_by_issue"]}
    lines = [
        "This Issue only tracks a batch of Issues with one root cause; it changes no code itself.",
        f"Do not run `issue-to-pr` on this Issue: run it on the primary Issue #{primary}. The other sub-issues "
        "are referenced with `Refs` in that PR and closed after the merge through the existing-PR disposition "
        "(stage 0 in `.agents/skills/issue-to-pr/references/similar-defect-scan.md`).",
        "",
        "## Shared root cause",
        "",
        f"- Class: `{batch['root_cause_class']}`",
        f"- Invariant: {batch['invariant']}",
        "",
        "## Issues",
        "",
        "| Issue | Role | Coverage | Validation |",
        "|---|---|---|---|",
    ]
    for n in batch["issue_numbers"]:
        a = coverage.get(n, {})
        role = "primary (`Fixes`)" if n == primary else "related (`Refs`)"
        lines.append(f"| #{n} | {role} | {a.get('coverage', 'undecided')} | {a.get('validation', '')} |")
    lines += ["", "## Evidence", ""]
    lines += [f"- {e['kind']} {e['path'] or e['url']}: {e['summary']}" for e in batch["evidence"]]
    lines += ["", "## Pairwise compatibility", ""]
    lines += [f"- #{p['issues'][0]} + #{p['issues'][1]}: {p['evidence']}" for p in batch["pair_compatibility"]]
    blockers = [f"open PR #{n}" for n in batch["existing_prs"]] + list(batch["blockers"])
    lines += ["", "## Blockers", ""] + ([f"- {b}" for b in blockers] or ["- none"])
    if not batch["all_fully_addressable"]:
        lines += ["", "Not every Issue is fully addressable: keep the others open after the merge."]
    lines += ["", f"Planner report: base `{report['base']['sha']}`, content `{report['content_sha256']}`.", "",
              marker(batch["batch_id"]), ""]
    return "\n".join(lines)


def body_problems(title: str, body: str) -> list[str]:
    problems = []
    if len(body) > MAX_BODY:
        problems.append(f"the body is {len(body)} characters, over {MAX_BODY}")
    if MENTION_RE.search(title + "\n" + body):
        problems.append("the title or body contains an @mention, which would notify someone; reword the report")
    scanner = planner.secret_scan()
    for where, text in (("title", title), ("body", body)):
        for f in scanner.scan_text(where, text):
            problems.append(f"secret-shaped text in the {where} ({f.cls}, line {f.line})")
    return problems


# --------------------------------------------------------------------------- plan and execute

def open_pr_numbers(repo: str) -> set[int]:
    data = _json(["gh", "pr", "list", "-R", repo, "--state", "open", "--limit", "1000", "--json", "number"], "gh pr list")
    if not isinstance(data, list) or len(data) >= 1000:
        raise Refused("cannot list every open PR")
    return {p["number"] for p in data if isinstance(p, dict) and type(p.get("number")) is int}


def find_existing(repo: str, batch_id: str, children: dict[int, dict[str, Any]], state_file: Path) -> int | None:
    """The umbrella already filed for this batch, from (a) a child's parent, (b) the state file, (c) search."""
    found: set[int] = set()
    for child in children.values():
        parent = child["parent"]
        if parent and has_marker(view(repo, parent["number"])["body"], batch_id):
            found.add(parent["number"])
    if not found and state_file.exists():
        try:
            recorded = json.loads(state_file.read_text(encoding="utf-8"))["number"]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise Refused(f"unreadable state file {state_file}: {exc}") from exc
        if not has_marker(view(repo, recorded)["body"], batch_id):
            raise Refused(f"state file names #{recorded}, whose body does not carry the batch marker")
        found.add(recorded)
    if not found:
        hits = _json(["gh", "issue", "list", "-R", repo, "--state", "all", "--search", f"{batch_id} in:body",
                      "--limit", "20", "--json", "number,url,body"], "gh issue list --search")
        if not isinstance(hits, list):
            raise Refused("unexpected search result")
        found |= {h["number"] for h in hits if isinstance(h, dict) and has_marker(h.get("body"), batch_id)}
    if len(found) > 1:
        raise Refused(f"more than one umbrella carries the marker: {sorted(found)}; resolve by hand")
    return next(iter(found), None)


def check_children(repo: str, batch: dict[str, Any], batch_id: str) -> dict[int, dict[str, Any]]:
    open_prs = open_pr_numbers(repo)
    children = {}
    for n in batch["issue_numbers"]:
        child = view(repo, n)
        if child["state"] != "OPEN":
            raise Refused(f"#{n} is {child['state']}; the batch is stale, re-run the planner")
        for ref in child["closedByPullRequestsReferences"]:
            same = isinstance(ref, dict) and str(ref.get("url", "")).lower() == \
                f"https://github.com/{repo}/pull/{ref.get('number')}".lower()
            if not same or ref.get("number") in open_prs:
                raise Refused(f"#{n} has an open or unverifiable closing PR {ref.get('url')}; it is no longer part of a batch")
        parent = child["parent"]
        if parent is not None and (not isinstance(parent, dict) or str(parent.get("url", "")).lower()
                                   != f"https://github.com/{repo}/issues/{parent.get('number')}".lower()):
            raise Refused(f"#{n} already has a parent in another repository; do not take it")
        if parent is not None and not has_marker(view(repo, parent["number"])["body"], batch_id):
            raise Refused(f"#{n} already has another parent #{parent['number']}; GitHub allows one, do not take it")
        children[n] = child
    return children


def create_umbrella(repo: str, title: str, body_file: Path, labels: list[str]) -> tuple[int | None, str]:
    argv = [sys.executable, str(CREATE_ISSUE), "--repo", repo, "--title", title, "--body-file", str(body_file)]
    for label in labels:
        argv += ["--label", label]
    r = run_command(argv)
    url_re = re.compile(r"https://github\.com/" + re.escape(repo) + r"/issues/([0-9]+)", re.IGNORECASE)
    if r.returncode == 0:
        m = url_re.fullmatch(r.stdout.strip())
        if not m:
            raise Partial("create_issue.py succeeded but printed no Issue URL; search for the marker before re-running", {})
        return int(m.group(1)), "created"
    if r.returncode == 1:
        raise Refused(f"create_issue.py refused before creating anything: {r.stderr.strip()[:300]}")
    if r.returncode == 3:
        m = url_re.search(r.stderr)
        if m:
            return int(m.group(1)), "created; label verification failed"
    raise Partial("creation is uncertain (create_issue.py exit "
                  f"{r.returncode}); do not retry before searching for the marker", {"stderr": r.stderr.strip()[:300]})


def file_umbrella(args: argparse.Namespace) -> dict[str, Any]:
    if not planner.REPO_RE.fullmatch(args.repo):
        raise Refused("--repo must be OWNER/REPO")
    if not BATCH_ID_RE.fullmatch(args.batch):
        raise Refused("--batch must be a 12-hex batch_id from the report")
    labels = list(args.label)
    if not labels or len(set(labels)) != len(labels) or not all(LABEL_RE.fullmatch(x) for x in labels):
        raise Refused("give at least one --label, each once (chosen per the issue-filing skill)")
    report, batch = load_batch(args.report, args.batch)
    if report["repository"].lower() != args.repo.lower():
        raise Refused(f"the report is for {report['repository']}, not {args.repo}")
    title, body = build_title(batch), build_body(report, batch)
    problems = body_problems(title, body)
    if problems:
        raise Refused("; ".join(problems))
    state_dir = planner.prepare_out_dir(args.state_dir, refuse_existing=())
    body_file = state_dir / f"{args.batch}.body.md"
    planner.write_atomic(body_file, body)
    state_file = state_dir / f"{args.batch}.json"
    lock = open(state_dir / f"{args.batch}.lock", "a+")
    try:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Refused("another run holds the lock for this batch") from exc
        children = check_children(args.repo, batch, args.batch)
        umbrella = find_existing(args.repo, args.batch, children, state_file)
        missing = [n for n in batch["issue_numbers"]
                   if not (children[n]["parent"] and children[n]["parent"]["number"] == umbrella)]
        plan = {"mode": "execute" if args.execute else "dry-run", "repository": args.repo, "batch_id": args.batch,
                "umbrella": umbrella, "would_create": umbrella is None, "title": title, "labels": labels,
                "body_file": str(body_file), "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
                "sub_issues_to_add": missing if umbrella is not None else list(batch["issue_numbers"])}
        if not args.execute:
            return {"status": "DRY_RUN", **plan}
        note = "existing"
        if umbrella is None:
            umbrella, note = create_umbrella(args.repo, title, body_file, labels)
            planner.write_atomic(state_file, planner.dumps({"number": umbrella, "batch_id": args.batch,
                                                            "url": f"https://github.com/{args.repo}/issues/{umbrella}"}))
            if note != "created":
                raise Partial(f"#{umbrella} {note}; fix its labels, then re-run", {"umbrella": umbrella})
            missing = list(batch["issue_numbers"])
        for n in missing:
            r = run_command(["gh", "issue", "edit", str(umbrella), "-R", args.repo, "--add-sub-issue", str(n)])
            if r.returncode != 0:
                raise Partial(f"adding #{n} to #{umbrella} failed: {r.stderr.strip()[:200]}; re-run to continue",
                              {"umbrella": umbrella})
        after = view(args.repo, umbrella)
        subs = {node.get("number") for node in after["subIssues"]["nodes"] if isinstance(node, dict)}
        names = {x.get("name") for x in after["labels"] if isinstance(x, dict)}
        gaps = []
        if subs != set(batch["issue_numbers"]) or after["subIssues"].get("totalCount") != len(batch["issue_numbers"]):
            gaps.append(f"sub-issues are {sorted(x for x in subs if x)}, expected {batch['issue_numbers']}")
        if not set(labels) <= names:
            gaps.append(f"labels {sorted(set(labels) - names)} are missing")
        if not has_marker(after["body"], args.batch):
            gaps.append("the body lost the batch marker")
        if gaps:
            raise Partial("read-back differs: " + "; ".join(gaps), {"umbrella": umbrella})
        return {"status": "FILED" if note == "created" else "COMPLETED_EXISTING", **plan, "umbrella": umbrella,
                "url": after["url"], "sub_issues": sorted(subs)}
    finally:
        lock.close()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--report", required=True, type=Path)
    ap.add_argument("--batch", required=True)
    ap.add_argument("--label", action="append", default=[])
    ap.add_argument("--state-dir", required=True, type=Path)
    ap.add_argument("--execute", action="store_true", help="write to GitHub; without it, a dry run")
    args = ap.parse_args(argv)
    try:
        result, code = file_umbrella(args), EXIT_OK
    except (Refused, planner.PlannerError) as exc:
        result, code = {"status": "REFUSED", "error": str(exc)}, EXIT_REFUSED
    except Partial as exc:
        result, code = {"status": "PARTIAL", "error": str(exc), **exc.state}, EXIT_PARTIAL
    print(planner.dumps(result), end="")
    return code


if __name__ == "__main__":
    sys.exit(main())
