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
| `SKILL.md`, `README.md`, `references/workflow.md` | Single item per invocation; checkout the selected branch in the current clean checkout before work, no per-item worktree/batch scheduling. Shared contract: `../_shared/single-item-checkout.md`, including stable skill snapshot, branch/HEAD verification and dirty-checkout protection. Regression guard: `../pr-review-merge/tests/test_single_item_contract.py`. |
| `SKILL.md` | "Project runtime configuration" and "Pilot: repository rules the review and the merge must respect" sections (merge commits, no branch rules, history reference, mandated actual-run evidence as a P1, cost, serial merges); merge-policy sentence in §1; `--method merge` in the §4 example |
| `platforms/{claude,codex,agy}/agents/prm-{reviewer,dependency}.*` | one prompt body per role on every platform (upstream shipped three different texts); pilot lines (history reference, `target_validation`, missing actual-run record is a blocking P1, test scope); Claude `tools`/`model`/`effort` and Codex `model`/`model_reasoning_effort` pins |
| `scripts/apply_decision.py` | `--method` defaults to `merge` (upstream: `squash`); locked by `tests/test_project_defaults.py` |
| `references/evidence-contract.md` | `target_validation` object in the example and its rules |
| `references/quality-gate.md` | DRAFT row for missing mandated actual-run evidence; merge command/method wording |
| `references/workflow.md` | step 3 (history reference + `.github/pr-evidence.json` check), renumbered steps, `Target validation` line in the reviewer return |
| `references/platforms.md` | rewritten for the repository-local layout (no installer, no global paths) |
| `tests/test_project_defaults.py` | new |
| `scripts/install.sh`, `tests/test_installer.py` | removed: the skill is repository-local, nothing installs it elsewhere |
| `README.md` | install section replaced by the repository layout; examples target `kjelly/pilot`; default merge method wording |

Files not listed here are believed unchanged from upstream 1.0.0; verify against the upstream
archive when upgrading.
