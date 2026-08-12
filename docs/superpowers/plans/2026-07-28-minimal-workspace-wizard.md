# Minimal Workspace Wizard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a quick `pilot edit` path that builds and validates a minimum deployable workspace while retaining every existing advanced editor menu.

**Architecture:** Add a top-level quick-start router flow in the existing Bubble Tea edit router. It reuses the hosts editor, inventory generation/scaffolding helpers, group-vars editor, vault editor, and workspace completeness checker; no new workspace format or deployment path is introduced. A small pure helper maps a failed completeness label back to an existing editor route.

**Tech Stack:** Go, Cobra, Bubble Tea, teatest, existing `internal/inventory`, `internal/groupvars`, and `internal/vaultfile` packages.

## Global Constraints

- The quick path and advanced path must read/write the same workspace files.
- Existing top-level advanced menu entries and their ordering after the new quick-start item must remain test-covered.
- Derived host values are pre-filled only when a source role resolves to exactly one `ansible_host`.
- User-supplied active group-vars values are never overwritten.
- Readiness requires `checkWorkspaceCompleteness` with no blocking failures and a successful inventory render.
- Direct `ansible-playbook` remains outside the quick path; it must not be invoked.

---

### Task 1: Add a testable quick-workspace preparation helper

**Files:**

- Create: `cmd/pilot/cmd/minimal_workspace.go`
- Create: `cmd/pilot/cmd/minimal_workspace_test.go`
- Reuse: `cmd/pilot/cmd/inventory.go`, `cmd/pilot/cmd/edit_tui_groupvars.go`

**Interfaces:**

- Produces: `prepareMinimalWorkspace(dir string) error`
- Produces: `minimalWorkspaceReadiness(dir string) ([]completenessCheck, error)`
- Consumes: `copyMissingGroupVars`, `copyMissingNestedGroupVarsExamples`, `writeMissingVaultSkeleton`, `writeMissingHostVarsSkeleton`, `writeMissingNFSRosterEntries`, and `inventory.Generate`.

- [x] **Step 1: Write failing preparation tests**

```go
func TestPrepareMinimalWorkspace_CreatesOnlyRoleDerivedArtifacts(t *testing.T) {
    dir := t.TempDir()
    writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  node:
    ansible_host: 10.0.0.10
    roles: [seaweedfs-s3, prometheus]
`)

    if err := prepareMinimalWorkspace(dir); err != nil { t.Fatal(err) }
    requireFile(t, filepath.Join(dir, "group_vars", "prometheus.yml"))
    requireFile(t, filepath.Join(dir, ".vault", "main.yaml"))
    requireFile(t, filepath.Join(dir, "host_vars", "node.yml"))
    requireFile(t, filepath.Join(dir, "inventory.yml"))
}
```

- [x] **Step 2: Run the focused test and confirm it fails**

Run: `rtk go test ./cmd/pilot/cmd -run TestPrepareMinimalWorkspace_CreatesOnlyRoleDerivedArtifacts -count=1`

Expected: FAIL because `prepareMinimalWorkspace` does not exist.

- [x] **Step 3: Implement preparation using existing inventory helpers**

```go
func prepareMinimalWorkspace(dir string) error {
    data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
    if err != nil { return fmt.Errorf("read hosts.yml: %w", err) }
    hf, err := inventory.Parse(data)
    if err != nil { return err }
    rendered, err := inventory.Generate(hf)
    if err != nil { return err }
    copyMissingGroupVars(io.Discard, dir, inventory.GroupVarsStems(hf))
    copyMissingNestedGroupVarsExamples(io.Discard, dir, inventory.UsedRoles(hf))
    writeMissingVaultSkeleton(io.Discard, filepath.Join(dir, ".vault", "main.yaml"), hf)
    writeMissingHostVarsSkeleton(io.Discard, dir, hf)
    writeMissingNFSRosterEntries(io.Discard, dir, hf)
    return os.WriteFile(filepath.Join(dir, "inventory.yml"), []byte(rendered), 0o644)
}
```

Call the helpers with `io.Discard`, `dir`, and `hf` exactly as shown; their
existing stat-before-write behavior preserves all user-created files.

- [x] **Step 4: Add readiness tests**

```go
func TestMinimalWorkspaceReadiness_ReturnsBlockingChecks(t *testing.T) {
    dir := preparedPrometheusWorkspace(t)
    checks, err := minimalWorkspaceReadiness(dir)
    if err != nil { t.Fatal(err) }
    if c := findCheck(t, checks, filepath.Join("host_vars", "node.yml")); c.OK {
        t.Fatalf("host_vars/node.yml = %+v, want missing prometheus_site_label", c)
    }
}

func TestMinimalWorkspaceReadiness_RendersInventoryBeforeReady(t *testing.T) {
    dir := t.TempDir()
    writeFile(t, filepath.Join(dir, "hosts.yml"), "hosts: [not-a-map]\n")
    if _, err := minimalWorkspaceReadiness(dir); err == nil {
        t.Fatal("minimalWorkspaceReadiness() error = nil, want invalid hosts.yml error")
    }
}
```

- [x] **Step 5: Implement readiness and run tests**

`minimalWorkspaceReadiness` must call `checkWorkspaceCompleteness` after a
successful `prepareMinimalWorkspace`; return the checks unchanged so quick and
advanced reporting stay identical.

Run: `rtk go test ./cmd/pilot/cmd -run 'TestPrepareMinimalWorkspace|TestMinimalWorkspaceReadiness' -count=1`

Expected: PASS.

### Task 2: Add the quick-start router flow without changing advanced editors

**Files:**

- Modify: `cmd/pilot/cmd/edit_tui.go`
- Modify: `cmd/pilot/cmd/edit_tui_flows_test.go`

**Interfaces:**

- Consumes: `prepareMinimalWorkspace`, `minimalWorkspaceReadiness`, `pushHostList`, `pushGroupVarsFilePicker`, `pushVaultFilePicker`, `pushConfigCompletenessCheck`.
- Produces: `pushMinimalWorkspaceWizard(r *editRouterModel, dir string) tea.Cmd`.

- [x] **Step 1: Write a failing top-menu flow test**

```go
func TestEditRouter_Teatest_MinimalWorkspaceEntryKeepsAdvancedEntries(t *testing.T) {
    dir := t.TempDir()
    tm := teatest.NewTestModel(t, newEditRouterModel(dir), teatest.WithInitialTermSize(100, 40))
    waitFor("快速建立最小 workspace")
    waitFor("hosts.yml — 機器清單與角色")
    waitFor("🔍 檢查設定完整性")
}
```

- [x] **Step 2: Run the focused test and confirm it fails**

Run: `rtk go test ./cmd/pilot/cmd -run TestEditRouter_Teatest_MinimalWorkspaceEntryKeepsAdvancedEntries -count=1`

Expected: FAIL because the quick-start item is absent.

- [x] **Step 3: Add the top-level menu item and router entry**

Insert the quick-start item at index 0. Shift the existing switch indexes
without changing their destinations. `pushMinimalWorkspaceWizard` presents a
quick-flow hub and its `設定主機與角色` item opens the existing
`pushHostsPathPrompt`; it does not duplicate host editing UI. Saving hosts
returns to the existing top menu, after which the user may re-enter the quick
path; this deliberately preserves the existing host-editor navigation rather
than threading a new callback through every host sub-screen.

- [x] **Step 4: Implement the post-host-save quick flow**

The quick-flow hub calls `prepareMinimalWorkspace(dir)` only after `hosts.yml`
exists and parses. It then shows:

```text
設定主機與角色
建立／更新最小設定骨架
設定 group_vars（已從角色範本建立）
設定 vault 必要秘密
驗證並檢查是否可部署
改用進階設定
取消快速流程
```

`設定主機與角色`, `設定 group_vars`, and `設定 vault` open the existing
editors. `建立／更新最小設定骨架` is idempotent and never overwrites active
user values. `改用進階設定` returns to `pushTopMenu` and preserves all current
files.

- [x] **Step 5: Run router flow tests**

Run: `rtk go test ./cmd/pilot/cmd -run 'TestEditRouter_Teatest_(MinimalWorkspace|HostsFlow)' -count=1`

Expected: PASS.

### Task 3: Present derived values as editable defaults

**Files:**

- Modify: `cmd/pilot/cmd/edit_tui_groupvars.go`
- Modify: `cmd/pilot/cmd/edit_tui_groupvars_test.go` or `cmd/pilot/cmd/edit_tui_flows_test.go`

**Interfaces:**

- Reuse: `groupVarsAutoHostVars`, `resolveSingleRoleHost`, `autofillCrossRoleHostVars`.
- Produces: `autofillCrossRoleHostVars` behavior for both commented and active-empty entries, without replacing an active non-empty user override.

- [x] **Step 1: Write failing derived-value tests**

```go
func TestAutofillCrossRoleHostVars_ActivatesEmptyThanosTarget(t *testing.T) {
    hf := hostsWithRoles("s3", "10.0.0.8", "seaweedfs-s3")
    got := string(autofillCrossRoleHostVars(hf, []byte("thanos_s3_target_host: \"\"\n")))
    if !strings.Contains(got, `thanos_s3_target_host: "10.0.0.8"`) { t.Fatal(got) }
}

func TestAutofillCrossRoleHostVars_DoesNotReplaceUserOverride(t *testing.T) {
    hf := hostsWithRoles("s3", "10.0.0.8", "seaweedfs-s3")
    got := string(autofillCrossRoleHostVars(hf, []byte("thanos_s3_target_host: \"s3.external.example\"\n")))
    if !strings.Contains(got, `thanos_s3_target_host: "s3.external.example"`) { t.Fatal(got) }
}
```

- [x] **Step 2: Run the focused tests and confirm failure**

Run: `rtk go test ./cmd/pilot/cmd -run TestAutofillCrossRoleHostVars -count=1`

Expected: the active-empty case fails before implementation.

- [x] **Step 3: Extend only the safe prefill behaviour**

Treat an active empty value as unconfigured only for known cross-role host
keys. Fill it when the source role resolves uniquely. Do not alter comments,
block scalars, unknown keys, active non-empty values, or ambiguous sources.

- [x] **Step 4: Run focused tests**

Run: `rtk go test ./cmd/pilot/cmd -run 'TestAutofillCrossRoleHostVars|TestCheckWorkspaceCompleteness' -count=1`

Expected: PASS.

### Task 4: Make quick readiness actionable and document the parallel path

**Files:**

- Modify: `cmd/pilot/cmd/edit_tui.go`
- Modify: `cmd/pilot/cmd/edit_tui_flows_test.go`
- Modify: `docs/runbooks/minimal-poc-architecture.md`

**Interfaces:**

- Consumes: `minimalWorkspaceReadiness` and `formatCompletenessReport`.
- Produces: a quick-flow readiness screen that either says deploy-ready or
  routes to an existing editor.

- [x] **Step 1: Write a failing readiness flow test**

```go
func TestEditRouter_Teatest_MinimalWorkspaceReadinessBlocksMissingSiteLabel(t *testing.T) {
    dir := preparedPrometheusWorkspace(t)
    router := newEditRouterModel(dir)
    pushMinimalWorkspaceWizard(&router, dir)
    tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))
    // Choose "驗證並檢查是否可部署" and wait for the blocking host_vars label.
    focusAndEnter(t, tm, "驗證並檢查是否可部署")
    waitForOutput(t, tm, "host_vars/node.yml")
    if strings.Contains(string(tm.Output()), "最小 workspace 已可部署") { t.Fatal("unexpected ready state") }
}
```

- [x] **Step 2: Run the focused test and confirm failure**

Run: `rtk go test ./cmd/pilot/cmd -run TestEditRouter_Teatest_MinimalWorkspaceReadinessBlocksMissingSiteLabel -count=1`

Expected: FAIL because the quick readiness flow is absent.

- [x] **Step 3: Implement readiness screen and routes**

Display all blocking checks using the existing report formatter. Provide
`前往 hosts 設定`, `前往 group_vars`, `前往 vault`, `改用進階設定`, and
`返回快速流程` only when their destinations are applicable. A passing screen
must show the exact inventory-generate and deploy commands using the chosen
workspace directory.

- [x] **Step 4: Document the parallel entry route**

Add a concise paragraph to the runbook's workspace-building section: the
quick-start route is an alternative to the existing advanced edit sequence;
both produce the same files and still require actual target deployment
evidence.

- [x] **Step 5: Run verification**

Run:

```bash
rtk go test ./cmd/pilot/cmd -run 'TestEditRouter_Teatest_MinimalWorkspace|TestAutofillCrossRoleHostVars|TestCheckWorkspaceCompleteness' -count=1
rtk go test ./internal/inventory -run 'TestAlertmanagerDefaultConfigIsMinimalAndOperational|TestGenerateVaultSkeleton' -count=1
rtk git diff --check
```

Expected: all targeted tests PASS and no whitespace errors.

---

## Implementation status

All four tasks are implemented and verified. Completed across two sittings:

- **Tasks 1-3** (2026-07-28) — `prepareMinimalWorkspace`,
  `minimalWorkspaceReadiness`, the quick-start router flow and its top-menu
  entry, and the `autofillCrossRoleHostVars` active-empty rule. Task 3's two
  required cases are covered by
  `TestAutofillCrossRoleHostVars_FillsActiveEmptyValue` and
  `TestAutofillCrossRoleHostVars_NeverOverwritesAlreadyActiveValue`.
- **Task 4** (2026-08-12) — the readiness screen, the pure
  `minimalWorkspaceRouteFor` / `minimalWorkspaceRoutes` label-to-route mapping,
  the ready banner carrying both the inventory-generate and deploy commands, and
  the runbook's parallel-entry-route paragraph (§3.3).

Deviations from the plan as written, both deliberate:

- The plan's Task 4 test sketch used helpers that do not exist in this
  repository (`preparedPrometheusWorkspace`, `focusAndEnter`, `waitForOutput`)
  and `string(tm.Output())`, which does not compile — `tm.Output()` is an
  `io.Reader`. The test follows this codebase's actual conventions instead:
  a local `waitFor` closure over `teatest.WaitFor`, and
  `io.ReadAll(tm.FinalOutput(...))` for negative assertions.
- `tm.Output()` is a *streaming* reader, so two consecutive `waitFor` calls
  against the same rendered screen cannot both match — the second sees an
  already-drained stream. Assertions for one screen are combined into a single
  condition.

Verification (all green): `go build ./...`; `go test ./...` across all 21
packages; the plan's Step 5 command set; `go test -race` on the new code;
`git diff --check`.

**Not covered:** this is local build/test evidence only. No live target
deployment was exercised for the quick path — the runbook's §3.4 onward still
requires real deployment evidence, per the note added to §3.3.
