---
name: issue-filing
description: File a GitHub issue with appropriate existing repository labels and verify them.
---

# Issue filing

Use this workflow whenever an agent creates an issue in this repository, including follow-up issues created from another skill. Respect the user's authorization and search for duplicates first. If an existing issue is the correct destination, update or report it as authorized; do not create a duplicate merely to apply labels.

1. Resolve the explicit `OWNER/REPO` and enumerate its current labels with `gh label list --repo OWNER/REPO --limit 1000 --json name,description`. If enumeration is truncated, paginate via the GitHub API; if it fails or completeness is unknown, stop and report the blocker. Never infer the taxonomy from another repository or a cached list.
2. Choose one or more applicable labels by their current names and descriptions, based on the issue's actual type, area, and severity. Use an existing type label when an appropriate one exists, plus area and priority labels when justified. Do not guess a severity or apply mutually contradictory labels. Do not create or rename repository labels without explicit authorization. If no applicable label exists, ask the user how to proceed rather than silently filing an unlabeled issue.
3. Use `scripts/create_issue.py` with explicit `--repo`, `--title`, `--body-file`, and one `--label` per selected name. It validates current names, creates once, and verifies readback. The agent remains responsible for semantic selection and duplicate search. If creation fails, determine whether an issue was nevertheless created before retrying. Do not create a duplicate after an uncertain response.
4. Read back the created issue from the same repository and verify its URL, number, and actual labels contain every selected label. If labels were dropped, apply the existing selected labels only if authorized, then read back again. On permissions, missing label, API or verification failure, report the issue URL, intended and observed labels, and the specific blocker; never report the issue as fully labeled. Do not create another issue to compensate. Do not remove labels added by another actor.

The issue body is public. It never carries a password, hash, key, token, cookie or unredacted raw log, and refers to a secret by name only (`.agents/skills/_shared/committed-secrets.md`).

Only report completion once at least one appropriate label is present and the selected labels have been verified. This is an agent workflow, not a server-side guarantee against manual issue creation or agents that do not follow this contract.
