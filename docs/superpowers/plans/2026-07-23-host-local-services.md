# Host-local services for portable vm-target environments Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a host-local Docker Compose service bundle and fail-closed `vm-target` bootstrap so disposable VMs use apt-cacher-ng, Pulp RPM, and Harbor from first boot while service data persists on the host.

**Architecture:** A new `internal/services` package owns profile validation, persistent paths, Compose rendering/execution, health checks, and service state. The CLI exposes `pilot services up|status|down|purge`; `vm-target` resolves the service client contract, discovers the selected libvirt network gateway, and passes a non-secret client configuration into cloud-init. Topology YAML carries one root-level `services` profile and reuses the same client configuration for every node.

**Tech Stack:** Go, Cobra, YAML v3, Docker Compose v2, libvirt `virsh`, cloud-init NoCloud seed, `internal/statefile.Store`, existing KVM/SSH lifecycle.

## Global Constraints

- Host services run on the machine executing `pilot`, never inside a disposable VM.
- Docker Compose is the only supported host service runtime in the first version.
- Persistent service data lives below `~/.local/share/pilot/cache/` by default, or below the configured pilot data directory's `cache/` child.
- `vm-target up --services local` fails if the service stack is missing, unhealthy, unreachable, or fails TLS/repository/registry probes; there is no public-upstream fallback.
- Secrets never enter VM user-data, CLI output, target state, or evidence artifacts.
- All read-modify-write state changes use `internal/statefile.Store.Mutate`.
- New Go code must have unit tests, `gofmt`, `go test`, `go test -race`, and `go build ./...` coverage.
- Any executable command added to a runbook/spec must be executed against its stated target and have evidence before documentation is added.

## File Map

- Create `internal/services/profile.go`: profile schema, built-in `dev-lite`, validation, stable fingerprinting, persistent-path derivation.
- Create `internal/services/compose.go`: deterministic Compose/config/CA rendering with safe file permissions and no shell interpolation. Pulp uses the official OCI single-container layout (`settings`, `pulp_storage`, `pgsql`, `containers`, `container_build`) and the pinned `pulp/pulp` image.
- Create `internal/services/manager.go`: Docker Compose command runner, Harbor official-installer bootstrap, state persistence, lifecycle operations, health/status inspection, and purge confirmation boundary.
- Create `internal/services/services_test.go`, `internal/services/compose_test.go`, and `internal/services/profile_test.go`: unit and fake-runner tests.
- Create `cmd/pilot/cmd/services.go` and `cmd/pilot/cmd/services_test.go`: `pilot services` command tree, output, flags, and error mapping.
- Create `internal/vmtarget/service_bootstrap.go` and tests: non-secret VM client contract and cloud-init fragment rendering.
- Modify `internal/vmtarget/vmtarget.go` and `internal/vmtarget/vmtarget_test.go`: add optional service bootstrap to `Options`, render it in the NoCloud user-data, and preserve existing default output when absent.
- Modify `cmd/pilot/cmd/vm_target.go` and tests: `--services`, service-state resolution before mutation, endpoint/gateway checks, and fail-closed provisioning.
- Modify `internal/vmtarget/topology.go` and tests: root-level `services` field, validation, and option propagation.
- Modify `cmd/pilot/cmd/vm_target_topology.go` and tests: resolve one service profile before concurrent node provisioning and pass the same client contract to every node.
- Modify `docs/topologies/minimal-poc-topology.yaml` only after implementation is verified, adding no service profile unless the actual test environment has the host services running.

---

### Task 1: Define and validate service profiles

**Files:**
- Create: `internal/services/profile.go`
- Test: `internal/services/profile_test.go`

**Interfaces:**
- Produces `type Profile`, `type ClientConfig`, `LoadProfile(ref string) (Profile, error)`, `Validate() error`, `Fingerprint() (string, error)`, and `DataRoot(dataDir string) string` for later service and CLI tasks.
- `ClientConfig` contains only non-secret endpoint URLs, CA PEM, profile name, and fingerprint; it must not contain upstream passwords or private registry credentials.

- [ ] **Step 1: Write failing validation tests** for an unknown profile, malformed URL, empty allowlist, invalid retention/size values, and a valid built-in `dev-lite` profile. Assert fingerprint stability under YAML key ordering and fingerprint change after endpoint change.
- [ ] **Step 2: Run `go test ./internal/services -run 'TestProfile' -count=1`** and confirm the package/types are missing.
- [ ] **Step 3: Implement the profile schema and built-in profile** with explicit apt, RPM, and OCI upstream/repository fields; reject credentials in the client projection; canonicalize the profile before SHA-256 fingerprinting; derive the persistent root from the configured pilot data directory.
- [ ] **Step 4: Run the focused tests** and confirm PASS, then run `gofmt -w internal/services/profile.go internal/services/profile_test.go`.
- [ ] **Step 5: Commit** with `git add internal/services/profile.go internal/services/profile_test.go && git commit -m "feat: define host service profiles"`.

### Task 2: Render persistent Compose and client material

**Files:**
- Create: `internal/services/compose.go`
- Test: `internal/services/compose_test.go`

**Interfaces:**
- Consumes `services.Profile` and `services.ClientConfig`.
- Produces `RenderBundle(profile Profile, root string, bindIP net.IP) (Bundle, error)`, where `Bundle` identifies the Compose file, generated CA path, service metadata path, and client endpoint data.

- [ ] **Step 1: Write failing renderer tests** asserting deterministic Compose output, pinned image references, separate persistent mounts for apt-cacher-ng/Pulp/Harbor data, bind address restricted to the libvirt-reachable host IP, no host-wide `0.0.0.0` publish, generated CA mode `0600`, and no credentials in rendered files.
- [ ] **Step 2: Run `go test ./internal/services -run 'TestRender' -count=1`** and confirm FAIL.
- [ ] **Step 3: Implement deterministic Compose rendering** for apt-cacher-ng and the Pulp OCI quickstart's single-container mounts (`settings`, `pulp_storage`, `pgsql`, `containers`, `container_build`) with `PULP_HTTPS`/`/dev/fuse` settings. Render Harbor's official `harbor.yml` inputs and installer directory separately; do not hand-author Harbor's internal component Compose topology. Add generated service configuration, CA generation/reuse, metadata/fingerprint writing, and atomic file replacement. Keep all paths under the validated persistent root and reject traversal/symlink escape.
- [ ] **Step 4: Run renderer tests, `gofmt`, and `go vet ./internal/services`**; confirm PASS.
- [ ] **Step 5: Commit** with `git add internal/services/compose.go internal/services/compose_test.go && git commit -m "feat: render persistent host service stack"`.

### Task 3: Implement Compose lifecycle and state

**Files:**
- Create: `internal/services/manager.go`
- Test: `internal/services/services_test.go`

**Interfaces:**
- Consumes `RenderBundle` and a command-runner seam (`Run(ctx, name, args...)`).
- Produces `Manager.Up(ctx, profile, network) error`, `Manager.Status(ctx) (Status, error)`, `Manager.Down(ctx) error`, `Manager.Purge(ctx, confirmed bool) error`, and `Manager.ClientConfig(ctx) (ClientConfig, error)`.

- [ ] **Step 1: Write failing fake-runner tests** for Compose v2 preflight, `up -d --wait`, status parsing, idempotent repeated `Up`, down preserving data, purge requiring confirmation, unhealthy service failure, and profile-fingerprint mismatch refusal.
- [ ] **Step 2: Run `go test ./internal/services -run 'TestManager' -count=1`** and confirm FAIL.
- [ ] **Step 3: Implement lifecycle commands with argv-based execution** (`docker compose -f <file> -p pilot-services-<profile> ...`), bounded contexts, redacted diagnostics, and `statefile.Store` Mutate for service metadata. Never invoke a shell.
- [ ] **Step 4: Run focused tests plus `go test -race ./internal/services -count=1`** and confirm PASS.
- [ ] **Step 5: Commit** with `git add internal/services/manager.go internal/services/services_test.go && git commit -m "feat: manage host services lifecycle"`.

### Task 4: Add the `pilot services` CLI

**Files:**
- Create: `cmd/pilot/cmd/services.go`
- Test: `cmd/pilot/cmd/services_test.go`
- Modify: `cmd/pilot/cmd/root.go` only if explicit command registration is needed.

**Interfaces:**
- Consumes `internal/config.Config`, `services.Manager`, and the existing global `--data-dir` resolution.
- Produces registered commands `services up`, `services status`, `services down`, and `services purge`, with `--profile`, `--network`, `--confirm`, and `--json` flags where applicable.

- [ ] **Step 1: Write failing command tests** for registration, missing/invalid profile, successful status JSON, down retaining the data root, purge refusal without `--confirm`, and redaction of CA/credentials.
- [ ] **Step 2: Run `go test ./cmd/pilot/cmd -run 'TestServices' -count=1`** and confirm FAIL.
- [ ] **Step 3: Implement the command tree and user-facing output**; call `services.Manager` through injectable seams so unit tests never require Docker or libvirt.
- [ ] **Step 4: Run focused tests, `go test ./cmd/pilot/cmd -run 'TestServices' -race -count=1`, and `go build ./cmd/pilot`**.
- [ ] **Step 5: Commit** with `git add cmd/pilot/cmd/services.go cmd/pilot/cmd/services_test.go cmd/pilot/cmd/root.go && git commit -m "feat: add pilot services lifecycle commands"`.

### Task 5: Add fail-closed VM service bootstrap

**Files:**
- Create: `internal/vmtarget/service_bootstrap.go`
- Test: `internal/vmtarget/service_bootstrap_test.go`
- Modify: `internal/vmtarget/vmtarget.go`, `internal/vmtarget/vmtarget_test.go`

**Interfaces:**
- Consumes `services.ClientConfig` converted into a vmtarget bootstrap value.
- Produces `type ServiceBootstrap`, `Validate() error`, and `RenderCloudInit() (string, error)`; `Options.Services *ServiceBootstrap` is optional and preserves current behavior when nil.

- [ ] **Step 1: Write failing render tests** for Ubuntu APT, Alma/RHEL repo/key/CA, Docker mirror/project prefixes, stable `/etc/hosts` mapping, no secret material, and failure on missing endpoint/CA.
- [ ] **Step 2: Run `go test ./internal/vmtarget -run 'TestServiceBootstrap|TestRenderUserData' -count=1`** and confirm FAIL.
- [ ] **Step 3: Implement shell-free cloud-init YAML fragments** using validated values, install trust material before probes, and add bounded first-boot probes that exit non-zero on any service failure. Integrate the fragment into `renderUserData` and ensure existing SSH-only golden behavior is unchanged when services are absent.
- [ ] **Step 4: Run focused tests, `gofmt`, and `go test ./internal/vmtarget -race -count=1`**.
- [ ] **Step 5: Commit** with `git add internal/vmtarget/service_bootstrap.go internal/vmtarget/service_bootstrap_test.go internal/vmtarget/vmtarget.go internal/vmtarget/vmtarget_test.go && git commit -m "feat: bootstrap vm targets from host services"`.

### Task 6: Wire direct `vm-target up --services`

**Files:**
- Modify: `cmd/pilot/cmd/vm_target.go`
- Modify: `cmd/pilot/cmd/vm_target_test.go`, `cmd/pilot/cmd/vm_target_test_args_test.go`
- Test: add service-specific cases to the existing command tests.

**Interfaces:**
- Consumes `services.Manager.ClientConfig`, selected libvirt network, and `vmtarget.Options.Services`.
- Produces `--services <profile|local|none>` parsing; `local` resolves the configured local profile and fails before `Manager.Up` when the stack or gateway is unavailable.

- [ ] **Step 1: Write failing CLI tests** proving service resolution occurs before VM reservation, missing/unhealthy services fail closed, `--services none` preserves legacy behavior, and resolved client config reaches `Options` without secrets.
- [ ] **Step 2: Run focused command tests and confirm FAIL.**
- [ ] **Step 3: Implement flag plumbing and preflight**; discover the host IP for the selected libvirt network through a tested helper, bind/validate the service endpoint, and pass the bootstrap config to `m.Up`. Keep per-call service settings local rather than storing them on the long-lived manager.
- [ ] **Step 4: Run `go test ./cmd/pilot/cmd -run 'Test.*VMTarget.*Service|TestBuildApplyArgs' -count=1` and `go test -race ./cmd/pilot/cmd -run 'Test.*VMTarget.*Service'`**.
- [ ] **Step 5: Commit** with `git add cmd/pilot/cmd/vm_target.go cmd/pilot/cmd/vm_target_test.go cmd/pilot/cmd/vm_target_test_args_test.go && git commit -m "feat: enable fail-closed vm-target services"`.

### Task 7: Propagate services through topology

**Files:**
- Modify: `internal/vmtarget/topology.go`
- Modify: `internal/vmtarget/topology_test.go`
- Modify: `cmd/pilot/cmd/vm_target_topology.go`
- Modify: `cmd/pilot/cmd/vm_target_topology_test.go`

**Interfaces:**
- Consumes root-level YAML `services: local` and the same resolved `ClientConfig` used by direct `vm-target up`.
- Produces `TopologySpec.Services string`, validation for `none|local|<profile>`, and option propagation to every concurrently-provisioned node and ephemeral topology path.

- [ ] **Step 1: Write failing topology tests** for root-level parsing, invalid service mode, one preflight before concurrent node creation, propagation to all nodes, and no service data included in snapshots/rollback.
- [ ] **Step 2: Run `go test ./internal/vmtarget ./cmd/pilot/cmd -run 'Test.*Topology.*Service' -count=1`** and confirm FAIL.
- [ ] **Step 3: Implement root-level service selection and resolve it once before provisioning; pass immutable client config into each node's options, including `topology test --ephemeral`.
- [ ] **Step 4: Run focused tests and `go test -race ./internal/vmtarget ./cmd/pilot/cmd -run 'Test.*Topology.*Service'`**.
- [ ] **Step 5: Commit** with `git add internal/vmtarget/topology.go internal/vmtarget/topology_test.go cmd/pilot/cmd/vm_target_topology.go cmd/pilot/cmd/vm_target_topology_test.go && git commit -m "feat: propagate host services through topologies"`.

### Task 8: Integration verification and documentation

**Files:**
- Create: `docs/verification/host-local-services.md`
- Create: `docs/runbooks/host-local-services.md`
- Modify: `docs/topologies/minimal-poc-topology.yaml` only if the tested topology uses `services: local`.
- Add the appropriate regression test under `internal/spec/` if the verification spec is committed.

**Interfaces:**
- Consumes the completed CLI and VM bootstrap behavior.
- Produces an acceptance contract and runbook containing only commands executed against the actual host/libvirt network, with evidence links and tested revision/tree metadata.

- [ ] **Step 1: Add spec/regression tests first** for row IDs, no vague expected values, fail-closed behavior, profile/target alignment, and shell syntax.
- [ ] **Step 2: Run `go run ./cmd/pilot spec docs/verification/host-local-services.md --lint`, `go test -count=1 -run TestShellSyntax ./internal/spec/`, and the new regression test**; fix all failures before target execution.
- [ ] **Step 3: Freeze a local candidate commit, run the service stack on the actual host, inspect the selected libvirt network, then run the VM integration flow: service up/health, Ubuntu VM bootstrap, Alma/RHEL VM bootstrap, package retrieval, image pull, VM reboot/recreate, service down/up persistence, and fail-closed endpoint outage. Save complete output under `.verification/` and sanitized evidence under `docs/evidence/`.
- [ ] **Step 4: Update the spec/runbook with only the latest tested summary, candidate commit/tree, target network, PASS/FAIL counts, and evidence links. Do not append raw transcripts to the docs.
- [ ] **Step 5: Run `go build ./...`, `go test ./...`, `go test -race ./...`, and `git diff --check`; commit documentation/evidence separately from the tested candidate.

## Plan self-review

- Profile validation, persistence, Compose lifecycle, CLI, cloud-init, direct VM use, topology use, fail-closed behavior, security, and evidence requirements each have an explicit task.
- The plan does not require Podman, public-upstream fallback, secrets in user-data, or cache data inside VM state.
- The topology design is explicit: only a root-level `services` value is supported initially; node-level overrides are not silently inferred.
- No implementation claims are made until the real host/VM integration evidence passes.
