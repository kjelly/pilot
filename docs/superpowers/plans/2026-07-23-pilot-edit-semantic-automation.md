# Pilot Edit Semantic Automation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans (recommended). Steps use checkbox syntax for tracking.

**Goal:** Add pilot-owned semantic automation for `pilot edit` that drives the existing Bubble Tea router through real `tea.KeyMsg` events and can optionally be recorded as a human-readable TUI teaching session.

**Architecture:** A versioned JSON scenario is parsed into typed edit actions. An automation engine resolves each action against live screen labels and emits the same key messages a human would send; it never calls inventory mutation helpers directly. Presentation trace and recording are optional; TREC and `trec verify` are not runtime dependencies.

**Tech Stack:** Go, Bubble Tea, JSON, existing teatest and PTY tests.

## Global Constraints

- Do not add a hard runtime dependency on TREC.
- All mutations must pass through existing screens using `tea.KeyMsg`; automation must not write YAML directly.
- Resolve targets by unique visible label, never fixed menu index.
- Stop on unexpected screen, ambiguous/missing target, validation failure, or save failure.
- Reject secret-looking fields in the first slice.
- Existing interactive behavior is unchanged when automation is disabled.

## Scope Extension: deploy and reconcile

The workflow continues after edit: the same scenario may contain `deploy` and
`reconcile` actions. Those actions do not call Ansible directly and do not
replace the existing business logic. They supply semantic answers to the
existing one-shot Bubble Tea prompts, so preflight, preview, stage gates,
confirmation, contract resolution, and transaction handling remain in force.
The optional PTY recording covers all three phases; TREC and `trec verify`
remain optional.

---

### Task 1: Scenario contract

**Files:**
- Create: `cmd/pilot/cmd/edit_automation.go`
- Create: `cmd/pilot/cmd/edit_automation_test.go`

**Interfaces:**
- Consumes JSON from `--actions <path>`.
- Produces package-local `editScenario`, `editAction`, and validation errors.

- [ ] **Step 1: Write failing parser tests.** Cover a valid scenario with `create_host`, `set_host_field`, `enable_role`, and `save_hosts`; reject missing/unsupported version, empty/unknown actions, malformed JSON, and secret-looking field names (`password`, `token`, `private_key`, including suffix variants).
- [ ] **Step 2: Run the focused tests and verify failure.** Run `go test ./cmd/pilot/cmd -run 'Test(EditScenario|ValidateEditAction)' -count=1`; expect compile/test failure because the contract is absent.
- [ ] **Step 3: Implement the contract.** Use:
  ```go
  type editScenario struct {
      Version int          `json:"version"`
      Title   string       `json:"title"`
      Steps   []editAction `json:"steps"`
  }
  type editAction struct {
      Action string `json:"action"`
      Host   string `json:"host,omitempty"`
      Field  string `json:"field,omitempty"`
      Value  string `json:"value,omitempty"`
      Role   string `json:"role,omitempty"`
      Label  string `json:"label,omitempty"`
  }
  func loadEditScenario(path string) (editScenario, error)
  func validateEditScenario(s editScenario) error
  ```
  Accept only version 1, reject unknown JSON fields, require at least one step, and never echo rejected values.
- [ ] **Step 4: Run `gofmt` and the focused tests; expect PASS.**

---

### Task 2: Key-event automation driver

**Files:**
- Modify: `cmd/pilot/cmd/edit_tui.go`
- Modify: `cmd/pilot/cmd/tui_screen.go`
- Modify: `cmd/pilot/cmd/tui_select.go`
- Modify: `cmd/pilot/cmd/tui_textinput.go`
- Modify: `cmd/pilot/cmd/tui_multiselect.go`
- Create: `cmd/pilot/cmd/edit_automation_driver.go`
- Create: `cmd/pilot/cmd/edit_automation_driver_test.go`

**Interfaces:**
- Consumes validated `editScenario` and a live `editRouterModel`.
- Produces `automationDriver`, `automationTraceEvent`, and fail-fast action errors.

- [ ] **Step 1: Write failing driver tests.** Drive the real router through hosts → default path → create blank → create `web-1` → set `ansible_host=10.0.0.5` → checklist toggle → host list → save. Assert the resulting hosts file and that actions resolve current labels. Add wrong-screen, unknown-host, ambiguous-label, and post-failure-stop tests.
- [ ] **Step 2: Run `go test ./cmd/pilot/cmd -run TestEditAutomationDriver -count=1`; expect failure.**
- [ ] **Step 3: Add stable internal screen IDs and read-only accessors.** Extend the internal screen contract with `automationScreenID() string`; implement it for select, text input, confirm, and multiselect without changing normal `View()` output. Add read-only accessors for live items and input labels.
- [ ] **Step 4: Implement the driver.** Use:
  ```go
  type automationDriver struct {
      trace func(automationTraceEvent)
  }
  type automationTraceEvent struct {
      Step int
      Action, ScreenID, Result, Error string
      Keys []string
  }
  func (d automationDriver) run(r *editRouterModel, s editScenario) error
  ```
  Each semantic action must find exactly one live label, emit standard up/down/enter/space/text key messages through the router's normal `Update`, verify the next screen/result, and emit one trace event. Replace prefilled input with ctrl+u before typing. Stop immediately on errors.
- [ ] **Step 5: Run `gofmt`, focused tests, and `go test -race ./cmd/pilot/cmd -run TestEditAutomationDriver -count=1`; expect PASS.**

- [ ] **Step 6: Add shared prompt automation for deploy/reconcile.** Make
  `runSelectProgram`, `runTextProgram`, and `runConfirmProgram` consult an
  optional prompt session. It resolves answers by prompt identity and live
  labels/defaults, sends standard key messages through `standaloneScreen`, and
  emits trace events. When unset, the existing `tea.NewProgram` path is
  unchanged. It must not bypass preflight or deployment transactions.
- [ ] **Step 7: Test prompt automation.** Cover select, text replacement,
  confirm, unknown prompt, and cancellation using the existing runner boundary
  with a fake runner; do not execute Ansible in unit tests.

---

### Task 3: CLI and presentation mode

**Files:**
- Modify: `cmd/pilot/cmd/edit_tui.go`
- Modify: `cmd/pilot/cmd/edit_automation.go`
- Create: `cmd/pilot/cmd/edit_automation_pty_test.go`
- Modify: `README.md`
- Modify: `DELIVERY.md`

**Interfaces:**
- Consumes `--actions <path>`, optional `--presentation`, and optional `--trace-out <path>`.
- Produces normal edit behavior or an automated session with optional captions and JSONL trace.

- [ ] **Step 1: Write failing real-PTY tests.** With `CI=1`, invoke the built binary in a temporary directory; assert correct hosts output, title/step captions only in presentation mode, one successful trace event per action, and early failure before TUI/file creation for invalid scenarios.
- [ ] **Step 2: Run `CI=1 go test ./cmd/pilot/cmd -run TestEditAutomationPTY -count=1`; expect failure.**
- [ ] **Step 3: Add flags and startup path.** When `--actions` is absent, preserve current interactive code. When present, load/validate before creating Bubble Tea, run the same router through the driver, optionally show short human-readable step captions, and atomically write trace events. Never include action values for rejected secret-like fields.
- [ ] **Step 4: Document optional recording.** Explain that TREC or another PTY recorder may wrap `pilot edit --actions ... --presentation`; recording and `trec verify` are optional, and the JSONL trace is the machine-readable companion to the human-facing cast.
- [ ] **Step 5: Run `gofmt` and the focused PTY tests; expect PASS.**

---

### Task 4: Regression and recording smoke check

**Files:**
- Modify: `TESTING.md`
- Modify existing edit tests only if explicit non-regression coverage is needed.

- [ ] **Step 1: Run `CI=1 go test ./cmd/pilot/cmd -count=1`; expect all existing edit/TUI tests to pass.**
- [ ] **Step 2: Run `go build ./...`, `go test ./... -count=1`, and `go test -race ./... -count=1`; expect exit 0.**
- [ ] **Step 3: Run one optional fixed-size PTY recording of presentation mode, inspect transcript/final screen, and run `trec verify` only when the cast is intended for archival.**
- [ ] **Step 4: Confirm normal edit has no changed labels/banner, no direct automation file mutation, and no recorder dependency; confirm the teaching cast and JSONL trace align action-by-action.**

