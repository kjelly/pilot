#!/usr/bin/env python3
"""File one umbrella Issue for a user-approved MERGE_CANDIDATE batch of a REVIEWED planner report.

Dry run unless --execute: the dry run checks every precondition, writes the planned body to --state-dir
and prints approval_sha256, but creates, edits and links nothing. --execute must name the approval_sha256
of the dry run the user approved, so it publishes exactly the title, labels and body that were shown.
--update-body replaces the body of the batch's existing umbrella instead (labels and sub-issues stay):
its approval_sha256 also covers the umbrella and the SHA-256 of the body it replaces.
This is the planner skill's only writer; every external command goes through run_command(), which
accepts only the forms in _command_problem().
Exit 0: done (or a successful dry run). Exit 2: refused, this run wrote nothing to GitHub. Exit 3: partly
done or uncertain; the output says what is known, and a re-run continues without a second umbrella.
Every error after a GitHub write has started is exit 3, never exit 2.
"""
from __future__ import annotations

import argparse
import contextlib
import difflib
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Iterator

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
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
# create_issue.py prints this, and exits 1, only when it stopped before `gh issue create`. Any other exit 1
# (an uncaught exception, possibly after the Issue was created) is uncertain.
BLOCKED_PREFIX = "BLOCKED before creation:"


class Refused(RuntimeError):
    """A precondition failed before this run started any GitHub write; this run wrote nothing to GitHub."""


class NotCreated(Refused):
    """create_issue.py proved that it created nothing."""


class Partial(RuntimeError):
    """Something was or may have been written; `state` says what is known."""

    def __init__(self, message: str, state: dict[str, Any]) -> None:
        super().__init__(message)
        self.state = state


def marker(batch_id: str) -> str:
    return f"issue-batch-planner batch: {batch_id}"


def members_line(numbers: list[int]) -> str:
    """The umbrella's member list. issue-to-pr's umbrella.py compares it with the umbrella's sub-issues, so
    an umbrella whose linking stopped part-way (exit 3) is never taken for the whole batch. No `#`: a bare
    number makes no cross-reference."""
    return "issue-batch-planner issues: " + " ".join(str(n) for n in sorted(numbers))


BODY_FILE_RE = re.compile(r"[0-9a-f]{12}\.body\.md\Z")


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
    # --update-body: one Issue, the body file this script wrote, nothing else (never --attach, which uploads
    # local files that the body names).
    if (len(rest) == 7 and rest[:2] == ["issue", "edit"] and NUMBER_RE.fullmatch(rest[2]) and rest[3] == "-R"
            and repo_ok(rest[4]) and rest[5] == "--body-file" and os.path.isabs(rest[6])
            and BODY_FILE_RE.fullmatch(os.path.basename(rest[6]))):
        return None
    return "gh command is not one of the allowed forms"


def run_command(argv: list[str], *, timeout: int = 120) -> planner.Result:
    """Run one allowed command. The only place in this script that starts a process."""
    problem = _command_problem(argv)
    if problem:
        raise Refused(f"refused {argv[:3]!r}: {problem}")
    try:
        p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except OSError as exc:
        raise Refused(f"{argv[0]} could not be started: {exc}") from exc
    except subprocess.TimeoutExpired as exc:
        message = f"{argv[0]} did not finish within {timeout}s"
        if argv[0] == sys.executable or argv[1:3] == ["issue", "edit"]:  # a write: it may still have happened
            raise Partial(f"{message}; the write it started may still have happened", {}) from exc
        raise Refused(message) from exc  # a read; execute() still reports it as PARTIAL after a write
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
        "This Issue tracks Issues that share one root cause; it changes no code itself.",
        "Run `issue-to-pr` on this Issue or on any of its sub-issues: one PR closes every open sub-issue, each "
        "with its own `Fixes #<sub-issue>`. When every sub-issue is fixed, that PR also closes this Issue; "
        "otherwise it only references this Issue (`Refs`) and this Issue stays open. A sub-issue the PR cannot "
        "fix gets `Refs #<sub-issue>` and a reply on it saying why (umbrella mode in "
        "`.agents/skills/issue-to-pr/references/workflow.md`).",
        f"Suggested first Issue to analyse: #{primary}.",
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
        role = "sub-issue, suggested first" if n == primary else "sub-issue"
        lines.append(f"| #{n} | {role} | {a.get('coverage', 'undecided')} | {a.get('validation', '')} |")
    lines += ["", "## Evidence", ""]
    lines += [f"- {e['kind']} {e['path'] or e['url']}: {e['summary']}" for e in batch["evidence"]]
    lines += ["", "## Pairwise compatibility", ""]
    lines += [f"- #{p['issues'][0]} + #{p['issues'][1]}: {p['evidence']}" for p in batch["pair_compatibility"]]
    blockers = [f"open PR #{n}" for n in batch["existing_prs"]] + list(batch["blockers"])
    lines += ["", "## Blockers", ""] + ([f"- {b}" for b in blockers] or ["- none"])
    if not batch["all_fully_addressable"]:
        lines += ["", "Not every Issue is fully addressable: the PR references those with `Refs` and this Issue "
                      "stays open."]
    lines += ["", f"Planner report: base `{report['base']['sha']}`, content `{report['content_sha256']}`.", "",
              members_line(batch["issue_numbers"]), marker(batch["batch_id"]), ""]
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


def approval_sha256(repo: str, batch_id: str, title: str, labels: list[str], body: str) -> str:
    """The value the user approves after the dry run: it covers everything --execute would publish."""
    payload = planner.dumps({"repository": repo, "batch_id": batch_id, "title": title, "labels": sorted(labels),
                             "body": body})
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def update_approval_sha256(repo: str, batch_id: str, umbrella: int, current_body_sha256: str, body: str) -> str:
    """The value the user approves for --update-body. `action` keeps a creation's approval from authorizing
    an edit; the umbrella and the replaced body's SHA-256 make an approval stale once someone else edits it."""
    payload = planner.dumps({"action": "update-body", "repository": repo, "batch_id": batch_id,
                             "umbrella": umbrella, "current_body_sha256": current_body_sha256, "body": body})
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------------- state file

def read_state(state_file: Path) -> dict[str, Any] | None:
    """{"number": N, ...}: this directory filed umbrella #N. {"pending_creation": {...}}: a creation was
    started and its result is not known, so no other creation may start until the umbrella is found."""
    if not state_file.exists():
        return None
    try:
        state = json.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise Refused(f"unreadable state file {state_file}: {exc}") from exc
    if not isinstance(state, dict) or not (type(state.get("number")) is int
                                           or isinstance(state.get("pending_creation"), dict)):
        raise Refused(f"unreadable state file {state_file}: neither an umbrella number nor a pending creation")
    return state


def write_number(state_file: Path, repo: str, batch_id: str, number: int) -> None:
    planner.write_atomic(state_file, planner.dumps({"number": number, "batch_id": batch_id,
                                                    "url": f"https://github.com/{repo}/issues/{number}"}))


def write_pending(state_file: Path, batch_id: str, approval: str) -> None:
    planner.write_atomic(state_file, planner.dumps({"batch_id": batch_id, "pending_creation": {
        "started_at": planner.now_iso(), "approval_sha256": approval}}))


def pending_guidance(batch_id: str, state_file: Path) -> str:
    return (f"an earlier creation attempt for this batch did not report its result, and no Issue carrying the "
            f"line `{marker(batch_id)}` is visible yet (GitHub search can lag); re-run later and it is picked up. "
            f"Only after checking on GitHub that no Issue carries that line, delete {state_file} to allow a new "
            "creation")


# --------------------------------------------------------------------------- plan and execute

def open_pr_numbers(repo: str) -> set[int]:
    data = _json(["gh", "pr", "list", "-R", repo, "--state", "open", "--limit", "1000", "--json", "number"], "gh pr list")
    if not isinstance(data, list) or len(data) >= 1000:
        raise Refused("cannot list every open PR")
    return {p["number"] for p in data if isinstance(p, dict) and type(p.get("number")) is int}


def find_existing(repo: str, batch_id: str, children: dict[int, dict[str, Any]],
                  state_file: Path) -> tuple[int | None, dict[str, Any] | None]:
    """The umbrella already filed for this batch, from (a) a child's parent, (b) the state file, (c) search,
    and the state file's unresolved creation attempt, if any."""
    found: set[int] = set()
    for child in children.values():
        parent = child["parent"]
        if parent and has_marker(view(repo, parent["number"])["body"], batch_id):
            found.add(parent["number"])
    state = read_state(state_file)
    if not found and state is not None and "number" in state:
        recorded = state["number"]
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
    return next(iter(found), None), (state or {}).get("pending_creation")


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


@contextlib.contextmanager
def batch_lock(state_dir: Path, batch_id: str) -> Iterator[None]:
    """The batch's lock in --state-dir, never waited for: a held lock is a refusal before anything is written."""
    with open(state_dir / f"{batch_id}.lock", "a+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Refused("another run holds the lock for this batch; this run changed nothing") from exc
        yield


def create_umbrella(repo: str, title: str, body_file: Path, labels: list[str]) -> tuple[int, str]:
    argv = [sys.executable, str(CREATE_ISSUE), "--repo", repo, "--title", title, "--body-file", str(body_file)]
    for label in labels:
        argv += ["--label", label]
    r = run_command(argv)
    url_re = re.compile(r"https://github\.com/" + re.escape(repo) + r"/issues/([0-9]+)", re.IGNORECASE)
    if r.returncode == 0:
        m = url_re.fullmatch(r.stdout.strip())
        if m:
            return int(m.group(1)), "created"
    elif r.returncode == 1 and r.stderr.lstrip().startswith(BLOCKED_PREFIX):
        raise NotCreated(f"create_issue.py refused before creating anything: {r.stderr.strip()[:300]}")
    elif r.returncode == 3:
        m = url_re.search(r.stderr)
        if m:
            return int(m.group(1)), "created; label verification failed"
    raise Partial(f"creation is uncertain (create_issue.py exit {r.returncode}, no Issue URL)",
                  {"stderr": (r.stderr or r.stdout).strip()[:300]})


def file_umbrella(args: argparse.Namespace) -> dict[str, Any]:
    if not planner.REPO_RE.fullmatch(args.repo):
        raise Refused("--repo must be OWNER/REPO")
    if not BATCH_ID_RE.fullmatch(args.batch):
        raise Refused("--batch must be a 12-hex batch_id from the report")
    labels = list(args.label)
    if getattr(args, "update_body", False):
        if labels:
            raise Refused("--update-body changes only the body: leave --label out (labels stay as they are)")
    elif not labels or len(set(labels)) != len(labels) or not all(LABEL_RE.fullmatch(x) for x in labels):
        raise Refused("give at least one --label, each once (chosen per the issue-filing skill)")
    report, batch = load_batch(args.report, args.batch)
    if report["repository"].lower() != args.repo.lower():
        raise Refused(f"the report is for {report['repository']}, not {args.repo}")
    title, body = build_title(batch), build_body(report, batch)
    problems = body_problems(title, body)
    if problems:
        raise Refused("; ".join(problems))
    if getattr(args, "update_body", False):
        return update_body(args, batch, body)
    approval = approval_sha256(args.repo, args.batch, title, labels, body)
    approved = getattr(args, "approval_sha256", None)
    if args.execute and approved is None:
        raise Refused("--execute needs --approval-sha256: the approval_sha256 of the dry run the user approved")
    if approved is not None and (not SHA256_RE.fullmatch(approved) or approved != approval):
        raise Refused("the title, labels or body are not the ones the user approved (approval_sha256 differs); "
                      "run the dry run again and get the user's approval for what it shows")
    state_dir = planner.prepare_out_dir(args.state_dir, refuse_existing=())
    body_file = state_dir / f"{args.batch}.body.md"
    state_file = state_dir / f"{args.batch}.json"
    with batch_lock(state_dir, args.batch):
        # Every file of the batch (body, state) is written only while holding the lock, so a run that is
        # refused here cannot change what the run holding it publishes.
        planner.write_atomic(body_file, body)
        children = check_children(args.repo, batch, args.batch)
        umbrella, pending = find_existing(args.repo, args.batch, children, state_file)
        if umbrella is None and pending is not None:
            raise Partial(pending_guidance(args.batch, state_file),
                          {"umbrella": None, "pending_creation": pending, "state_file": str(state_file)})
        missing = [n for n in batch["issue_numbers"]
                   if not (children[n]["parent"] and children[n]["parent"]["number"] == umbrella)]
        plan = {"mode": "execute" if args.execute else "dry-run", "repository": args.repo, "batch_id": args.batch,
                "umbrella": umbrella, "would_create": umbrella is None, "title": title, "labels": labels,
                "body_file": str(body_file), "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
                "approval_sha256": approval,
                "sub_issues_to_add": missing if umbrella is not None else list(batch["issue_numbers"])}
        if pending is not None:
            plan["resolved_pending_creation"] = pending
        if not args.execute:
            return {"status": "DRY_RUN", **plan}
        return execute(args, batch, labels, title, body, body_file, state_file, umbrella, pending, missing, plan)


def execute(args: argparse.Namespace, batch: dict[str, Any], labels: list[str], title: str, body: str,
            body_file: Path, state_file: Path, umbrella: int | None, pending: dict[str, Any] | None,
            missing: list[int], plan: dict[str, Any]) -> dict[str, Any]:
    """The writes, under the caller's lock. Before the first GitHub write an error is a refusal; from the
    first write on, every error is PARTIAL with what is known (a run that may have written never says it
    wrote nothing)."""
    if umbrella is not None and pending is not None:
        write_number(state_file, args.repo, args.batch, umbrella)  # an earlier attempt's umbrella, now found
    if umbrella is None:
        if body_file.read_text(encoding="utf-8") != body:
            raise Refused(f"{body_file} changed after this run wrote it; nothing was created")
        write_pending(state_file, args.batch, plan["approval_sha256"])  # before the attempt, kept if uncertain
    progress: dict[str, Any] = {"umbrella": umbrella, "phase": "create" if umbrella is None else "link"}
    note = "existing"
    try:
        if umbrella is None:
            umbrella, note = create_umbrella(args.repo, title, body_file, labels)
            progress["umbrella"] = umbrella
            write_number(state_file, args.repo, args.batch, umbrella)
            if note != "created":
                raise Partial(f"#{umbrella} {note}; fix its labels, then re-run", {})
            missing = list(batch["issue_numbers"])
        progress["phase"] = "link"
        for n in missing:
            r = run_command(["gh", "issue", "edit", str(umbrella), "-R", args.repo, "--add-sub-issue", str(n)])
            if r.returncode != 0:
                raise Partial(f"adding #{n} to #{umbrella} failed: {r.stderr.strip()[:200]}; re-run to continue", {})
        progress["phase"] = "read-back"
        after = view(args.repo, umbrella)
        subs = {node.get("number") for node in after["subIssues"]["nodes"] if isinstance(node, dict)}
        names = {x.get("name") for x in after["labels"] if isinstance(x, dict)}
        gaps = []
        if subs != set(batch["issue_numbers"]) or after["subIssues"].get("totalCount") != len(batch["issue_numbers"]):
            gaps.append(f"sub-issues are {sorted(x for x in subs if x)}, expected {batch['issue_numbers']}")
        if not set(labels) <= names:
            gaps.append(f"labels {sorted(set(labels) - names)} are missing")
        published_here = note == "created" or (
            pending is not None and pending.get("approval_sha256") == plan["approval_sha256"])
        if published_here and after["body"] != body:
            gaps.append("the body is not the approved body")
        elif not has_marker(after["body"], args.batch):
            gaps.append("the body lost the batch marker")
        if gaps:
            raise Partial("read-back differs: " + "; ".join(gaps), {})
    except NotCreated as exc:
        try:
            state_file.unlink(missing_ok=True)
        except OSError as unlink_exc:
            raise NotCreated(f"{exc}; also delete {state_file} by hand ({unlink_exc})") from exc
        raise
    except Partial as exc:
        exc.state = {**progress, **exc.state}
        if progress["phase"] == "create" and progress["umbrella"] is None:
            exc.state.update(state_file=str(state_file), guidance=pending_guidance(args.batch, state_file))
        raise
    except Exception as exc:  # noqa: BLE001 - after a write started, no error may read as "nothing written"
        state = dict(progress)
        if progress["phase"] == "create" and progress["umbrella"] is None:
            state.update(state_file=str(state_file), guidance=pending_guidance(args.batch, state_file))
        raise Partial(f"{exc} (during {progress['phase']}, after a GitHub write may have happened); re-run to "
                      "continue", state) from exc
    return {"status": "FILED" if note == "created" else "COMPLETED_EXISTING", **plan, "umbrella": umbrella,
            "url": after["url"], "sub_issues": sorted(subs)}


def shape(issue: dict[str, Any]) -> tuple[set[Any], Any, set[Any]]:
    """What --update-body must leave as it was: the sub-issue numbers, their totalCount and the label names."""
    subs = {node.get("number") for node in issue["subIssues"]["nodes"] if isinstance(node, dict)}
    names = {x.get("name") for x in issue["labels"] if isinstance(x, dict)}
    return subs, issue["subIssues"].get("totalCount"), names


def update_body(args: argparse.Namespace, batch: dict[str, Any], body: str) -> dict[str, Any]:
    """--update-body: replace the batch's existing umbrella body with the approved one; labels and sub-issues
    stay. Setting a body twice is harmless, unlike a creation, so there is no pending record: a re-run that
    finds the new body only reads it back, and one that still finds the approved old body writes again."""
    approved = getattr(args, "approval_sha256", None)
    if args.execute and approved is None:
        raise Refused("--execute needs --approval-sha256: the approval_sha256 of the dry run the user approved")
    if approved is not None and not SHA256_RE.fullmatch(approved):
        raise Refused("--approval-sha256 must be 64 lower-case hex digits")
    state_dir = planner.prepare_out_dir(args.state_dir, refuse_existing=())
    body_file = state_dir / f"{args.batch}.body.md"
    current_file = state_dir / f"{args.batch}.current.md"
    diff_file = state_dir / f"{args.batch}.body.diff"
    state_file = state_dir / f"{args.batch}.json"
    with batch_lock(state_dir, args.batch):
        planner.write_atomic(body_file, body)
        children = check_children(args.repo, batch, args.batch)
        umbrella, pending = find_existing(args.repo, args.batch, children, state_file)
        if umbrella is None:
            if pending is not None:
                raise Partial(pending_guidance(args.batch, state_file),
                              {"umbrella": None, "pending_creation": pending, "state_file": str(state_file)})
            raise Refused("no Issue carries this batch's marker line, so there is no umbrella body to update; "
                          "file the umbrella without --update-body")
        before = view(args.repo, umbrella)
        current = before["body"]
        if not isinstance(current, str):
            raise Refused(f"unexpected body of #{umbrella}")
        planner.write_atomic(current_file, current)
        planner.write_atomic(diff_file, "".join(difflib.unified_diff(
            current.splitlines(keepends=True), body.splitlines(keepends=True),
            f"#{umbrella} (current)", f"#{umbrella} (new)")))
        current_sha = sha256_text(current)
        plan = {"mode": "update-body", "execute": bool(args.execute), "repository": args.repo,
                "batch_id": args.batch, "umbrella": umbrella, "body_file": str(body_file),
                "current_body_file": str(current_file), "diff_file": str(diff_file),
                "current_body_sha256": current_sha, "body_sha256": sha256_text(body),
                "approval_sha256": update_approval_sha256(args.repo, args.batch, umbrella, current_sha, body)}
        if current == body:  # also an earlier run whose edit landed but whose response was lost
            return {"status": "ALREADY_UPDATED" if args.execute else "UP_TO_DATE", **plan, "url": before["url"]}
        if not args.execute:
            return {"status": "DRY_RUN", **plan}
        if approved != plan["approval_sha256"]:
            raise Refused(f"#{umbrella}'s current body, the new body or the umbrella are not the ones the user "
                          "approved (approval_sha256 differs); run the dry run again and get the user's approval "
                          "for what it shows")
        if pending is not None:
            write_number(state_file, args.repo, args.batch, umbrella)  # an earlier attempt's umbrella, now found
        if body_file.read_text(encoding="utf-8") != body:
            raise Refused(f"{body_file} changed after this run wrote it; nothing was edited")
        kept = shape(before)
        progress: dict[str, Any] = {"umbrella": umbrella, "phase": "update"}
        try:
            r = run_command(["gh", "issue", "edit", str(umbrella), "-R", args.repo, "--body-file", str(body_file)])
            if r.returncode != 0:
                raise Partial(f"gh issue edit #{umbrella} failed (exit {r.returncode}): "
                              f"{(r.stderr or r.stdout).strip()[:200]}; the body may or may not have changed, "
                              "re-run to check", {})
            progress["phase"] = "read-back"
            after = view(args.repo, umbrella)
            gaps = []
            if after["body"] != body:
                gaps.append("the body is not the approved body")
            now = shape(after)
            if now[:2] != kept[:2]:
                gaps.append(f"sub-issues changed from {sorted(x for x in kept[0] if x)} ({kept[1]}) to "
                            f"{sorted(x for x in now[0] if x)} ({now[1]})")
            if now[2] != kept[2]:
                gaps.append(f"labels changed from {sorted(str(x) for x in kept[2])} to {sorted(str(x) for x in now[2])}")
            if gaps:
                raise Partial("read-back differs: " + "; ".join(gaps), {})
        except Partial as exc:
            exc.state = {**progress, **exc.state}
            raise
        except Exception as exc:  # noqa: BLE001 - after the edit started, no error may read as "nothing written"
            raise Partial(f"{exc} (during {progress['phase']}, after the edit may have happened); re-run to "
                          "continue", dict(progress)) from exc
        return {"status": "UPDATED", **plan, "url": after["url"]}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--repo", required=True)
    ap.add_argument("--report", required=True, type=Path)
    ap.add_argument("--batch", required=True)
    ap.add_argument("--label", action="append", default=[])
    ap.add_argument("--state-dir", required=True, type=Path)
    ap.add_argument("--update-body", action="store_true",
                    help="replace the body of the batch's existing umbrella (no --label; labels and sub-issues stay)")
    ap.add_argument("--execute", action="store_true", help="write to GitHub; without it, a dry run")
    ap.add_argument("--approval-sha256", help="with --execute: the approval_sha256 of the dry run the user approved")
    args = ap.parse_args(argv)
    try:
        result, code = file_umbrella(args), EXIT_OK
    except (Refused, planner.PlannerError, OSError) as exc:  # execute() turns every error after a write into Partial
        result, code = {"status": "REFUSED", "error": str(exc)}, EXIT_REFUSED
    except Partial as exc:
        result, code = {"status": "PARTIAL", "error": str(exc), **exc.state}, EXIT_PARTIAL
    print(planner.dumps(result), end="")
    return code


if __name__ == "__main__":
    sys.exit(main())
