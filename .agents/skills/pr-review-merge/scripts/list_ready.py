#!/usr/bin/env python3
"""Paginated read-only list of the open, non-draft PRs in a GitHub repository that pr-review-merge can act on.

Left out (listed under `excluded` with the reason), in this order: a PR the merge train owns (`merge-queue`
label); a PR without a valid Ready signal, that is, one that did not get to Ready through pr-ready's (or
issue-to-pr's) verification (`ready_signal.assess`: the signal's label, a marker comment naming the verified
HEAD and the one Ready transition it certifies, which must still be the PR's latest; a PR without the label
is excluded without reading its timeline);
and a PR waiting for a person (`needs-person` label, while its HEAD is the one the actor's needs-person comment
names). A PR whose HEAD moved since that comment is listed again with `stale_needs_person: true`: the push may
have resolved what it waited for, and the next pr-review-merge run removes the stale label.

A PR whose signal names an earlier HEAD is listed with `stale_ready_signal: true`: the actor decides whether the
new HEAD is still covered (`review_covers`: a pure import of the base is, and so is a delta that touches only the
base manifest's `evidence_only_paths`; a push that changes any other file of the PR's own commits is not, and
leaves the PR with nothing to act on until it goes through Draft and pr-ready again).
"""
import argparse
import json
import sys
from pathlib import Path

# Running from the skill snapshot must not add __pycache__ there: `skill_snapshot.py verify`
# counts any added file and would STOP every later step. Set before the first sibling import.
sys.dont_write_bytecode = True
import gh_runtime
from gh_runtime import GitHubError, Repo, current_repo, issue_comments, list_open_prs, viewer_login
import needs_person

# The shared Ready-signal module sits in the `_shared` bundle directory next to the skills.
_SHARED_SCRIPTS = str(Path(__file__).resolve().parents[2] / "_shared" / "scripts")
if _SHARED_SCRIPTS not in sys.path:
    sys.path.append(_SHARED_SCRIPTS)
import ready_signal  # noqa: E402

# merge_train.QUEUE_LABEL, kept here so listing does not load the train (and through it the gate);
# tests/test_handoff.py fails when the two differ.
QUEUE_LABEL = "merge-queue"
# Said to whoever reads `excluded`: the only way back for a Ready PR without a valid signal (pr-ready and
# mark_ready.py refuse a PR that is not a Draft, so it cannot be signed where it stands).
SIGN_AGAIN = "convert the PR to Draft and run pr-ready again to have it verified and signed"


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
            if ready_signal.LABEL not in labels:
                # The label is the commit point of the signal: without it there is nothing to assess, and no
                # timeline is read for the PR.
                excluded.append({"number": number, "reason": (
                    f"ready signal absent: the PR does not carry the {ready_signal.LABEL} label; {SIGN_AGAIN}")})
                continue
            if viewer is None:
                viewer = viewer_login(repo)
            try:
                # Read through the module: tests/test_skill_snapshot.py plants a gh_runtime with the names imported
                # above and runs `--help`; a name imported here would need that stub to follow every new call.
                found = ready_signal.assess(head, pr.get("labels"), gh_runtime.timeline_events(repo, number), viewer)
            except ready_signal.SignalError as exc:
                # This PR's own data cannot be read (an entry of an unexpected shape): fail closed for it alone.
                excluded.append({"number": number, "reason": f"ready signal unreadable: {exc}"})
                continue
            if found.state == "stale":
                entry["stale_ready_signal"] = True
            elif not found.valid:
                excluded.append({"number": number,
                                 "reason": f"ready signal {found.state}: {found.reason}; {SIGN_AGAIN}"})
                continue
            if needs_person.LABEL in labels:
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
