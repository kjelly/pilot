# Project-local changes to the packaged pr-review-merge skill

Upstream bundle: pr-review-merge 1.0.0 (`VERSION`). This copy is the canonical one for the
pilot repository: `.claude/skills/pr-review-merge` and `.claude/agents/prm-*.md` are symlinks
into it and `.codex/agents/prm-*.toml` are byte copies of `platforms/codex/agents/`
(`cmd/pilot/cmd/agent_skill_consistency_test.go` checks both, and that the claude, codex and
agy prompt bodies of each role are identical). Keep this list current so an upstream upgrade
is a three-way merge: `diff -r <upstream> .agents/skills/pr-review-merge`, re-apply the rows
below, then run `make skill-test` and `go test ./cmd/pilot/cmd -run TestAgentSkillLayout`.

| File | Project-specific change |
|---|---|
| `SKILL.md`, `README.md`, `references/{workflow,platforms}.md`, `platforms/{claude,codex,agy}/agents/prm-{reviewer,dependency}.*`, `.codex/agents/prm-*.toml` | Single PR per invocation; `prm-dependency` analyses only the selected PR. The branch lands by exact SHA (`checkout_preflight.py --execute`, never by name), the skill bundle is snapshotted first (`skill_snapshot.py`) and role files are checked before dispatch (a differing role is DRIFT: dispatch under the snapshot, report the header changes; a missing one is BLOCKED), and the starting branch is restored at the end. Contract `.agents/skills/_shared/single-item-checkout.md`, cited by repo-root path because Claude Code reads the skill through `.claude/skills/pr-review-merge`; guards in `_shared/tests/`. |
| `../pilot-code-review/references/pilot-history-checks.md` (shared with the other skills, not part of this bundle) | Hands children the assigned verified checkout (no worktree creation, no branch switching) and defines a candidate as the clean committed checkout or a read-only `git archive` scratch copy; included in the guard scan. |
| `SKILL.md` | "Project runtime configuration" and "Pilot: repository rules the review and the merge must respect" sections (merge commits, no branch rules, history reference, mandated actual-run evidence as a P1, cost, single-item completion); merge-policy sentence in §1; `--method merge` in the §4 example |
| `platforms/{claude,codex,agy}/agents/prm-{reviewer,dependency}.*` | one prompt body per role on every platform (upstream shipped three different texts); pilot lines (history reference, `target_validation`, missing actual-run record is a blocking P1, test scope); Claude `tools`/`model`/`effort` and Codex `model`/`model_reasoning_effort` pins |
| `scripts/apply_decision.py` | `--method` defaults to `merge` (upstream: `squash`); locked by `tests/test_project_defaults.py` |
| `references/evidence-contract.md` | `target_validation` object in the example and its rules (enforced by the gate, see the last row) |
| `references/quality-gate.md` | WAITING row for a missing mandated actual-run record (gate) and DRAFT row for the reviewer's P1 on it; merge command/method wording |
| `references/workflow.md` | step 3 (history reference + `.github/pr-evidence.json` check), renumbered steps, `Target validation` line in the reviewer return |
| `references/platforms.md` | rewritten for the repository-local layout (no installer, no global paths) |
| `tests/test_project_defaults.py` | new |
| `scripts/install.sh`, `tests/test_installer.py` | removed: the skill is repository-local, nothing installs it elsewhere |
| `README.md` | install section replaced by the repository layout; examples target `kjelly/pilot`; default merge method wording |
| `scripts/review_gate.py`, `tests/test_gate.py`, `tests/test_pr_ready_handoff.py` (new), `SKILL.md` ("Hand-off with `pr-ready`", "Disputed findings", §2, §3 table), `references/{evidence-contract,quality-gate,workflow}.md`, `platforms/{claude,codex,agy}/agents/prm-reviewer.*` | no Draft/Ready loop with `pr-ready`: `CHANGES_REQUESTED` and reviewer-confirmed `unrelated_failing_checks` decide `WAITING` instead of `DRAFT` (upstream: `DRAFT`); a finding that repeats a disputed claim carries `disputed_reply_url` and is `DRAFT` only with `new_evidence`, otherwise `WAITING` for a person; severity `P4` accepted (shared rubric); the hand-off test runs both gates over the same GitHub states |
| `scripts/review_gate.py`, `scripts/gh_runtime.py`, `tests/test_target_validation.py` (new), `tests/fixtures/github_api.json` (new), `tests/{test_gate,test_integration,test_pr_ready_handoff}.py`, `SKILL.md` ("Mandated actual-run evidence", hand-off, §3 table), `README.md`, `references/{evidence-contract,quality-gate,workflow}.md`, `platforms/{claude,codex,agy}/agents/prm-reviewer.*` | the gate enforces the actual-run record of the base branch's `.github/pr-evidence.json`: manifest read at the base SHA via the GitHub contents API, `target_validation` checked with issue-to-pr's `scripts/repo_evidence.py` (loaded by path; `RemoteContext` takes the evidence-only delta from GitHub `compare`), every gap `WAITING`; the manifest's `required_paths` (new key, validated in `repo_evidence.validate_manifest`; issue-to-pr refuses `not-applicable` for them too) refuse `not-needed`; integration tests use a per-test `PRM_STATE_DIR` |
| `scripts/{list_ready,review_gate,apply_decision}.py`, `_shared/tests/test_skill_snapshot.py` (`RunFromTheSnapshot`) | each entry script that imports a sibling module sets `sys.dont_write_bytecode = True` before that import: run from the skill snapshot, CPython would write `__pycache__` there and `skill_snapshot.py verify` (which counts any added file, and stays strict because CPython loads a `.pyc` beside a module) would STOP every later step |

Files not listed here are believed unchanged from upstream 1.0.0; verify against the upstream
archive when upgrading.
