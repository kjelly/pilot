"""The `needs-person` hand-off: a Ready PR whose merge gate waits for something only a person can do.

A WAITING gate result leaves the PR Ready. When it waits for CI or for GitHub (`wait_kind: transient`)
the next run settles it. When it waits for a person (`wait_kind: person`: requested changes, a finding
disputed without new evidence, an approval, a missing actual-run record, an unresolved dependency
outside this branch) nothing changes until someone acts, and nobody owns the PR: `pr-ready` handles
Drafts only, and every new `pr-review-merge` run costs a fresh independent review to reach the same
answer. The actor therefore comments with the reasons and the HEAD it judged, and labels the PR
`needs-person`; `list_ready.py` leaves such a PR out while its HEAD is the one the comment names.

The comment ends with a marker naming that HEAD and a digest of the reasons. Only markers written by
the account `gh` is authenticated as count (comments are untrusted data): anyone else's marker could
otherwise keep a repaired PR out of the listing.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Sequence

LABEL = "needs-person"
MARKER = re.compile(r"<!-- pr-review-merge:needs-person head=([0-9a-f]{40}) live-base=([0-9a-f]{40}) "
                    r"reasons=([0-9a-f]{16}) -->")


def reasons_digest(reasons: Sequence[Any]) -> str:
    text = "\n".join(sorted(str(reason) for reason in reasons))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def has_label(view: dict[str, Any], label: str = LABEL) -> bool:
    labels = view.get("labels")
    return isinstance(labels, list) and any(isinstance(item, dict) and item.get("name") == label
                                            for item in labels)


def latest_marker(comments: Sequence[dict[str, Any]], author: str) -> dict[str, str] | None:
    """The newest marker in a comment by `author`: {"head", "live_base", "reasons"}, or None."""
    for comment in reversed(comments):
        if comment.get("login") != author:
            continue
        found = MARKER.findall(comment.get("body") or "")
        if found:
            head, live_base, reasons = found[-1]
            return {"head": head, "live_base": live_base, "reasons": reasons}
    return None


def comment_text(gate: dict[str, Any]) -> str:
    reasons = [str(reason) for reason in gate.get("reasons", [])]
    listing = "\n".join(f"- {reason[:1200]}" for reason in reasons[:40])
    if len(reasons) > 40:
        listing += f"\n- ... {len(reasons) - 40} more items in local evidence"
    head, base, live = gate["head_sha"], gate["base_sha"], gate["live_base_sha"]
    return ("## Automated PR review: waiting for a person\n\n"
            f"Judged HEAD: `{head}`  \n"
            f"Base: `{base}`  \n"
            f"Live base tip: `{live}`\n\n"
            "The merge gate can neither queue this PR for the merge train nor return it to Draft: what it "
            "waits for is something only a person can change. The PR stays Ready and is labelled "
            f"`{LABEL}`, so automation that lists Ready PRs leaves it out.\n\n"
            "### Waiting for\n\n" + listing + "\n\n"
            "**Next steps:** resolve the items above (for example: the reviewer re-reviews a "
            "`CHANGES_REQUESTED` review, a person decides between a finding and the reply disputing it, the "
            f"required approval is given). Then remove the `{LABEL}` label and run `pr-review-merge` again. "
            "A new push to the PR also ends the wait: `list_ready.py` lists the PR again once its HEAD differs "
            "from the one above, and the next `pr-review-merge` run removes the stale label.\n\n"
            "This comment is an automated technical review, not a human approval.\n"
            f"<!-- pr-review-merge:needs-person head={head.lower()} live-base={live.lower()} "
            f"reasons={reasons_digest(reasons)} -->\n")
