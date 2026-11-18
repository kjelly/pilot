# Captured `gh` output (sanitized)

Structure captured on 2026-11-16 with gh 2.103.3, then sanitized. Field names, nesting, types and
the shape of every nested object come from the real output; titles, bodies, comment text, node ids,
comment authors, numbers, file paths and branch names were replaced. Do not hand-edit the structure:
re-capture instead (`AGENTS.md` section 5.6).

| File | Captured with | Source of the shape |
|---|---|---|
| `gh_issue_list.json` | `gh issue list -R kjelly/pilot --state open --limit 1000 --json number,title,url,labels,body,comments,createdAt,updatedAt,blockedBy,parent,subIssues,closedByPullRequestsReferences` | kjelly/pilot Issues; `subIssues` and `parent` from cli/cli, `blockedBy` (a cross-repository blocker) from microsoft/vscode, because kjelly/pilot had none |
| `gh_issue_view.json` | `gh issue view N -R OWNER/REPO --json number,state,url,body,parent,subIssues,labels,closedByPullRequestsReferences` (three samples, keyed by name) | `plain` and `closed_by_pr` from kjelly/pilot (#142, #330); `with_parent_and_sub_issues` from cli/cli #14529; `umbrella_after_execute` and `child_after_execute` from kjelly/pilot #354 and #142 right after the first `file_umbrella.py --execute` (2026-11-16). The URLs are rewritten to `OWNER/REPO`; nested URLs (parent, sub-issues, closing PRs) keep their real form |
| `gh_pr_list.json` | `gh pr list -R kjelly/pilot --state open --limit 1000 --json number,url,isDraft,headRefName,body,closingIssuesReferences,files,changedFiles` | kjelly/pilot PRs |

Facts observed in the same capture and relied on by `collect`:

- `gh issue list` returns at most 100 comments per Issue (two cli/cli Issues with more than 120
  comments returned exactly 100), and `gh pr list` at most 100 files per PR (cli/cli PRs with 150 and
  157 changed files returned 100); `changedFiles` gives the real count.
- `blockedBy` and `subIssues` are `{nodes, totalCount}`; nodes are `{id, number, state, title, url}` and
  a blocker may belong to another repository. `parent` is `null` or one such node.
- `closedByPullRequestsReferences` entries carry `{id, number, repository, url}` and no state.
- `labels` entries are `{id, name, description, color}`.

Issue 503 carries prompt-injection text on purpose: the tests check that none of it reaches a command
line or an output file.

Also observed for `file_umbrella.py`: `gh issue list --search "<text> in:body" --json number,url,body` returns `[]` with exit 0 when nothing matches. `gh issue edit N --add-sub-issue M` is only judged by its exit code and the read-back of `subIssues`, never by its output.

GitHub keeps the body exactly as `create_issue.py` (`gh issue create --body-file`) sent it: on 2026-11-17, kjelly/pilot#354's `body` from `gh issue view 354 --json body` was identical to the body file of the first `--execute`. Both were 1822 characters, the trailing newline was kept, and neither contained `\r`. `file_umbrella.py` therefore requires the read-back body of an umbrella it created to equal the approved body exactly.

`gh issue edit --body-file` keeps the body the same way (gh 2.104.0, 2026-11-17): after the first `file_umbrella.py --update-body --execute` (user-approved) on kjelly/pilot#354, `gh issue view 354 --json body` was identical to the approved body file: 2049 characters, the trailing newline kept, no `\r`. Its sub-issues and labels were unchanged. A second run with the same approval reported `ALREADY_UPDATED` and wrote nothing. `--update-body` therefore requires the read-back body to equal the approved body exactly. The edit's own output is never parsed: only its exit code and the read-back count.
