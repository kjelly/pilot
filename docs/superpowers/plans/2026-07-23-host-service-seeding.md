# Host service control-plane seeding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `pilot services up` create Harbor proxy-cache projects and Pulp RPM on-demand repositories, including the required initial metadata sync.

**Architecture:** Add a host-only API reconciler below `internal/services` that talks to Pulp and Harbor over their bound HTTP endpoints after Compose health succeeds. Reconciliation is idempotent, persists no credentials in VM state, and blocks successful `services up` until all configured resources exist and any first-time Pulp metadata task completes.

**Tech Stack:** Go `net/http`, Pulp RPM REST API, Harbor v2.0 REST API, existing Docker Compose lifecycle, `internal/statefile.Store`.

## Global Constraints

- RPM remotes use Pulp `policy: on_demand`; no full package mirror is downloaded during `services up`.
- A Pulp repository with no `latest_version_href` receives one initial metadata sync; an existing populated repository is not resynced on every `up`.
- Harbor registry endpoints and proxy-cache projects are created only when absent; same-name conflicting configuration fails closed.
- Any API or sync failure makes `services up` fail before it persists `Running: true`.
- Credentials stay in host-side secret files and are never placed in `ClientConfig`, cloud-init, CLI output, or evidence.
- All HTTP requests have the caller context; asynchronous Pulp tasks have a bounded polling timeout.

---

### Task 1: Extend the profile/client contract

**Files:**
- Modify: `internal/services/profile.go`
- Modify: `internal/services/compose.go`
- Modify: `internal/vmtarget/service_bootstrap.go`
- Test: `internal/services/profile_test.go`, `internal/services/compose_test.go`, `internal/vmtarget/service_bootstrap_test.go`

**Interfaces:**
- Add an explicit Harbor registry type to `OCIRegistry` with built-in `docker-hub` default and compatibility inference for existing profiles.
- Add `ClientConfig.RPMRepositories map[string]string`; retain `RPMBaseURL` as the first/default repository URL.
- Render one VM YUM/DNF repo stanza per map entry.

- [ ] **Step 1: Write failing tests** asserting the built-in profile has `docker-hub`, bundle client config contains the distribution URL, and cloud-init renders every RPM repository.
- [ ] **Step 2: Run `go test ./internal/services ./internal/vmtarget -run 'Test(BuiltIn|Render|ServiceBootstrap)' -count=1` and confirm failure.**
- [ ] **Step 3: Implement the fields, validation, URL projection, and cloud-init map rendering.**
- [ ] **Step 4: Run the focused tests and `gofmt`.**
- [ ] **Step 5: Commit `feat: add seeded repository client contract`.**

### Task 2: Add Pulp/Harbor API reconciliation

**Files:**
- Create: `internal/services/seed.go`
- Test: `internal/services/seed_test.go`

**Interfaces:**
- `seedServices(ctx context.Context, profile Profile, root string, bindIP net.IP, client *http.Client) (ClientConfig, error)`.
- Pulp helpers create/find remote, repository, distribution and poll initial sync task.
- Harbor helpers create/find registry endpoint and proxy-cache project.

- [ ] **Step 1: Write failing HTTP contract tests** for on-demand remote payload, metadata-only first sync, Harbor registry/project payloads, idempotent second reconcile, and conflict/API failure.
- [ ] **Step 2: Run `go test ./internal/services -run 'TestSeed' -count=1` and confirm failure.**
- [ ] **Step 3: Implement request/response decoding with status checks, URI validation, Basic auth from the host-only Harbor admin secret, and bounded Pulp task polling.**
- [ ] **Step 4: Run seed tests and `go test -race ./internal/services -run 'TestSeed'`.**
- [ ] **Step 5: Commit `feat: reconcile Pulp and Harbor cache resources`.**

### Task 3: Make seeding mandatory in `services up`

**Files:**
- Modify: `internal/services/manager.go`
- Modify: `internal/services/services_test.go`

**Interfaces:**
- `Manager.Up` runs Compose health, then `seedServices`, then persists `Running: true` with seeded client URLs.

- [ ] **Step 1: Write a failing manager test** proving a seed failure returns an error and leaves no successful state.
- [ ] **Step 2: Run `go test ./internal/services -run 'TestManager.*Seed' -count=1` and confirm failure.**
- [ ] **Step 3: Wire the reconciler after Harbor/Pulp health and before state mutation; preserve profile fingerprint refusal.**
- [ ] **Step 4: Run all service tests and `go test -race ./internal/services`.**
- [ ] **Step 5: Commit `feat: require cache resource seeding during services up`.**

### Task 4: Verify on the actual host and disposable VM

**Files:**
- Modify: `docs/superpowers/specs/2026-07-23-host-local-services-design.md`
- Create/update: `docs/evidence/host-local-services/latest.md`

- [ ] **Step 1: Freeze a candidate and record `vm-target list`, `virsh net-dumpxml default`, and current service status.**
- [ ] **Step 2: Run `services up` and inspect Pulp/Harbor API state without printing secrets.**
- [ ] **Step 3: Create a disposable Ubuntu VM with `--services local`, install a small RPM-compatible package through the generated local repository, and pull a test image through the Harbor proxy project.**
- [ ] **Step 4: Repeat `services up`, recreate the VM, and verify no duplicate resources or full resync.**
- [ ] **Step 5: Run `go build ./...`, `go test ./...`, `go test -race ./...`, and `git diff --check`; store the evidence separately from the candidate.**
