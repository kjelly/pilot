package services

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/kjelly/pilot/internal/statefile"
)

const serviceStateVersion = 1

// CommandRunner is the seam used by Manager for Docker/installer commands.
// dir is the working directory; no shell is involved.
type CommandRunner interface {
	Run(ctx context.Context, dir, name string, args ...string) (CommandResult, error)
}

// CommandResult captures bounded child-process output.
type CommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

type osCommandRunner struct{}

func (osCommandRunner) Run(ctx context.Context, dir, name string, args ...string) (CommandResult, error) {
	return (osCommandRunner{}).RunInput(ctx, dir, "", name, args...)
}

func (osCommandRunner) RunInput(ctx context.Context, dir, input, name string, args ...string) (CommandResult, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(input)
	cmd.Dir = dir
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	result := CommandResult{Stdout: stdout.String(), Stderr: stderr.String()}
	if err == nil {
		return result, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, nil
	}
	return result, err
}

// ServiceState is the persisted identity and health summary for one profile.
type ServiceState struct {
	InstanceID        string                          `json:"instance_id,omitempty"`
	Generation        uint64                          `json:"generation,omitempty"`
	AdoptedFrom       []string                        `json:"adopted_from,omitempty"`
	Profile           string                          `json:"profile"`
	Fingerprint       string                          `json:"fingerprint"`
	Root              string                          `json:"root"`
	ComposePath       string                          `json:"compose_path"`
	HarborComposePath string                          `json:"harbor_compose_path,omitempty"`
	Client            ClientConfig                    `json:"client"`
	BindIP            string                          `json:"bind_ip"`
	Running           bool                            `json:"running"`
	UpdatedAt         time.Time                       `json:"updated_at"`
	ConsumerTracking  bool                            `json:"consumer_tracking,omitempty"`
	Consumers         []Consumer                      `json:"consumers,omitempty"`
	Capabilities      map[Capability]CapabilityStatus `json:"capabilities,omitempty"`
}

// Status is the user-facing service health summary.
type Status struct {
	InstanceID   string                          `json:"instance_id,omitempty"`
	Generation   uint64                          `json:"generation,omitempty"`
	Configured   bool                            `json:"configured"`
	Running      bool                            `json:"running"`
	Profile      string                          `json:"profile,omitempty"`
	Fingerprint  string                          `json:"fingerprint,omitempty"`
	BindIP       string                          `json:"bind_ip,omitempty"`
	Root         string                          `json:"root,omitempty"`
	Services     []ServiceItem                   `json:"services,omitempty"`
	Capabilities map[Capability]CapabilityStatus `json:"capabilities,omitempty"`
}

// ServiceItem is one Compose service state line.
type ServiceItem struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Health string `json:"health,omitempty"`
}

// Manager owns the persistent host-service bundle for one pilot data dir.
type Manager struct {
	dataDir string
	root    string
	store   *statefile.Store[ServiceState]
	shared  bool
	runner  CommandRunner
	now     func() time.Time
	client  *http.Client
	seed    func(context.Context, Profile, string, net.IP, *http.Client) (ClientConfig, error)
}

// NewManager creates a host-service manager rooted below dataDir/cache.
func NewManager(dataDir string, runner CommandRunner) (*Manager, error) {
	if dataDir == "" {
		return nil, errors.New("services: data directory is required")
	}
	dataDir, err := CanonicalDirectory(dataDir)
	if err != nil {
		return nil, err
	}
	store, err := statefile.New[ServiceState](dataDir, "services.json", serviceStateVersion, "services")
	if err != nil {
		return nil, err
	}
	if runner == nil {
		runner = osCommandRunner{}
	}
	return &Manager{dataDir: dataDir, root: DataRoot(dataDir), store: store, runner: runner, seed: seedServices, now: time.Now, client: &http.Client{Timeout: 5 * time.Second}}, nil
}

// Up renders and starts the service bundle on bindIP. It is idempotent for an
// unchanged profile and refuses to silently replace a different profile.
func (m *Manager) Up(ctx context.Context, profile Profile, bindIP net.IP) error {
	return m.up(ctx, profile, bindIP, false, MaintenanceOptions{})
}

// Repair explicitly reconciles a compatible stack after verifying maintenance is safe.
func (m *Manager) Repair(ctx context.Context, profile Profile, bindIP net.IP, options MaintenanceOptions) error {
	return m.up(ctx, profile, bindIP, true, options)
}

func (m *Manager) up(ctx context.Context, profile Profile, bindIP net.IP, repair bool, options MaintenanceOptions) error {
	unlock, err := m.operationContext(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	if err := profile.Validate(); err != nil {
		return err
	}
	fingerprint, err := profile.Fingerprint()
	if err != nil {
		return err
	}
	current, currentErr := m.current()
	if currentErr != nil {
		return currentErr
	}
	if bindIP == nil || bindIP.IsUnspecified() {
		return errors.New("services: service bind IP is required")
	}
	if current.BindIP != "" && current.BindIP != bindIP.String() {
		return fmt.Errorf("services: bind endpoint conflict (registered=%s requested=%s); use the existing network", current.BindIP, bindIP)
	}
	if current.Root != "" && current.Root != m.root {
		return fmt.Errorf("services: registered root conflict (%s != %s)", current.Root, m.root)
	}
	legacyFingerprint := ""
	if currentErr == nil && current.Fingerprint != "" && current.Fingerprint != fingerprint {
		// The OCI registry type is derivable for the built-in profile. Accept
		// the pre-seeding fingerprint once so an existing persistent bundle can
		// be upgraded without purging its cache.
		legacy := profile
		legacy.OCI.Registries = slices.Clone(profile.OCI.Registries)
		for i := range legacy.OCI.Registries {
			legacy.OCI.Registries[i].Type = ""
		}
		legacyFingerprint, _ = legacy.Fingerprint()
	}
	if currentErr == nil && current.Fingerprint != "" && current.Fingerprint != fingerprint && current.Fingerprint != legacyFingerprint {
		return fmt.Errorf("services: profile fingerprint mismatch (running=%s requested=%s); purge or use the existing profile", current.Fingerprint, fingerprint)
	}
	if repair {
		if err := maintenanceAllowed(current, options); err != nil {
			return err
		}
		if current.Fingerprint != "" {
			if err := m.validateHarborCredentials(ctx, current); err != nil {
				if current.Running || !errors.Is(err, errHarborUnreachable) {
					return err
				}
				if err := m.validateStoppedCredentialBinding(); err != nil {
					return err
				}
				if err := m.activateRetainedBundle(ctx, current); err != nil {
					return err
				}
				if err := m.validateHarborCredentials(ctx, current); err != nil {
					return err
				}
			}
		}
	} else if current.Fingerprint != "" {
		if !current.Running || current.Fingerprint != fingerprint || current.Client.Fingerprint != fingerprint || len(current.Client.RPMRepositories) == 0 {
			return errors.New("services: existing stack needs explicit services repair; ordinary startup cannot reconcile stopped, incomplete or older state")
		}
		if err := m.probeEndpoints(ctx, current); err != nil {
			return fmt.Errorf("services: existing stack needs explicit services repair; refusing mutation after health probe: %w", err)
		}
		return nil
	}
	if len(current.Consumers) != 0 {
		return errors.New("services: incomplete discovery has registered consumers; restore its successful contract before startup")
	}
	if m.shared {
		if err := m.checkComposeOwnership(ctx, profile.Name); err != nil {
			return err
		}
		if current.Root == "" {
			data, err := hasServiceData(m.root)
			if err != nil {
				return err
			}
			if data {
				return errors.New("services: persistent service data appeared without discovery state; restore or adopt its original state before startup")
			}
		} else if current.ComposePath != "" {
			if err := validateLegacyData(current); err != nil {
				return err
			}
		}
		identity, err := m.claimRoot(current.InstanceID)
		if err != nil {
			return err
		}
		if current.InstanceID != "" && current.InstanceID != identity {
			return errors.New("services: physical root identity differs from discovery")
		}
		current.InstanceID = identity
		if current.Generation == 0 {
			current.Generation = 1
		}
		// Reserve identity and compatibility before rendering. A killed
		// registration reuses its identity without replacing credential files.
		if current.Fingerprint == "" {
			current.ConsumerTracking = true
			current.Root, current.Profile, current.Fingerprint, current.BindIP = m.root, profile.Name, fingerprint, bindIP.String()
			if err := m.store.Mutate(func(states []ServiceState) ([]ServiceState, error) { return []ServiceState{current}, nil }); err != nil {
				return err
			}
		}
	}
	// Recreation belongs only to explicit repair. A failed ordinary attach
	// has already returned without granting mutation authority.
	forceRecreate := repair && current.Fingerprint != ""
	recoverHarbor := forceRecreate
	// Older service state did not record the per-repository RPM endpoints. Force
	// one recreation on upgrade so the Pulp admin env file is consumed by the
	// container instead of silently keeping an old unauthenticated instance.
	if currentErr == nil && current.Fingerprint != "" && len(current.Client.RPMRepositories) == 0 {
		forceRecreate = true
	}
	if currentErr == nil && current.Running && m.probeEndpoints(ctx, current) != nil {
		forceRecreate = true
		recoverHarbor = true
	}
	if repair && current.Fingerprint != "" {
		if err := m.store.Mutate(func(states []ServiceState) ([]ServiceState, error) {
			for i := range states {
				states[i].Running = false
			}
			return states, nil
		}); err != nil {
			return err
		}
	}
	bundle, err := RenderBundle(profile, m.root, bindIP)
	if err != nil {
		return err
	}
	if m.shared && current.ComposePath == "" {
		bundle.Client.InstanceID, bundle.Client.Generation = current.InstanceID, current.Generation
		current.ComposePath, current.Client = bundle.ComposePath, bundle.Client
		if err := m.store.Mutate(func([]ServiceState) ([]ServiceState, error) { return []ServiceState{current}, nil }); err != nil {
			return err
		}
	}
	if err := m.requireCompose(ctx); err != nil {
		return err
	}
	if err := m.ensurePulpSettingsAccess(ctx, bundle.Root); err != nil {
		return err
	}
	if err := m.ensureHarbor(ctx, profile, bundle); err != nil {
		return err
	}
	installerDir := filepath.Join(bundle.Root, "harbor", "installer")
	harborCompose := filepath.Join(installerDir, "docker-compose.yml")
	if result, err := m.runner.Run(ctx, installerDir, "sudo", "-n", "./prepare"); err != nil {
		return errors.New("services: prepare harbor command unavailable")
	} else if result.ExitCode != 0 {
		return fmt.Errorf("services: prepare harbor failed: %s", redact(result.Stderr))
	}
	if err := namespaceHarborCompose(harborCompose, profile.Name, bindIP.String()); err != nil {
		return err
	}
	project := "pilot-services-" + profile.Name
	composeArgs := []string{"compose", "-f", bundle.ComposePath, "-p", project, "up", "-d", "--wait"}
	if forceRecreate {
		composeArgs = append(composeArgs, "--force-recreate", "--remove-orphans")
	}
	if result, err := m.runner.Run(ctx, m.root, "docker", composeArgs...); err != nil {
		return errors.New("services: start compose command unavailable")
	} else if result.ExitCode != 0 {
		// A Pulp worker can remain unhealthy after a bind-mounted setting
		// directory is repaired. Recreate this Compose project once so each
		// worker reloads the corrected access mode. This is intentionally
		// bounded: a second failure is returned to the caller.
		firstFailure := redact(result.Stderr)
		retryArgs := []string{"compose", "-f", bundle.ComposePath, "-p", project, "up", "-d", "--wait", "--force-recreate", "--remove-orphans"}
		retry, retryErr := m.runner.Run(ctx, m.root, "docker", retryArgs...)
		if retryErr != nil {
			return errors.New("services: start compose failed; recreate services command unavailable")
		}
		if retry.ExitCode != 0 {
			return fmt.Errorf("services: start compose failed: %s; recreate services failed: %s", firstFailure, redact(retry.Stderr))
		}
	}
	if harborCompose := harborComposePath(bundle); harborCompose != "" {
		if err := m.startHarbor(ctx, harborCompose, profile.Name, forceRecreate, recoverHarbor); err != nil {
			return err
		}
	}
	seededClient, err := m.seed(ctx, profile, bundle.Root, bindIP, m.client)
	if err != nil {
		// A failed control-plane reconcile must not leave a previously healthy
		// state usable by vm-target. Keep the persistent cache, but require the
		// next caller to complete seeding before provisioning another VM.
		if markErr := m.store.Mutate(func(states []ServiceState) ([]ServiceState, error) {
			for i := range states {
				states[i].Running = false
			}
			return states, nil
		}); markErr != nil {
			return fmt.Errorf("services: seed cache resources: %w (also mark stopped: %v)", err, markErr)
		}
		return fmt.Errorf("services: seed cache resources: %w", err)
	}
	seededClient.CAPEM = bundle.Client.CAPEM
	if err := m.recordCredentialBinding(""); err != nil {
		return err
	}
	seededClient.InstanceID, seededClient.Generation = current.InstanceID, current.Generation
	state := ServiceState{Profile: profile.Name, Fingerprint: fingerprint, Root: m.root, ComposePath: bundle.ComposePath, HarborComposePath: harborComposePath(bundle), Client: seededClient, BindIP: bindIP.String(), Running: true, UpdatedAt: m.now().UTC()}
	state.InstanceID, state.Generation = current.InstanceID, current.Generation
	state.AdoptedFrom = current.AdoptedFrom
	state.ConsumerTracking = current.ConsumerTracking || current.Fingerprint == ""
	state.Capabilities = m.observeCapabilities(ctx, state)
	if err := ctx.Err(); err != nil {
		return err
	}
	return m.store.MutateContext(ctx, func(states []ServiceState) ([]ServiceState, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return []ServiceState{state}, nil
	})
}

// activateRetainedBundle is the bounded offline-auth exception for explicit
// stopped→repair. It never renders, prepares, recreates, removes or seeds. Live
// authentication must succeed afterward before ordinary reconciliation begins.
func (m *Manager) activateRetainedBundle(ctx context.Context, state ServiceState) error {
	harbor := state.HarborComposePath
	if harbor == "" {
		harbor = filepath.Join(m.root, "harbor/installer/docker-compose.yml")
	}
	for _, path := range []string{state.ComposePath, harbor} {
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("services: retained stopped Compose configuration unavailable")
		}
	}
	if m.shared {
		if err := m.checkComposeOwnership(ctx, state.Profile); err != nil {
			return err
		}
	}
	for _, command := range []struct {
		dir, name string
		args      []string
	}{
		{m.root, "docker", []string{"compose", "-f", state.ComposePath, "-p", "pilot-services-" + state.Profile, "up", "-d", "--wait"}},
		{filepath.Dir(harbor), "sudo", []string{"-n", "docker", "compose", "-f", harbor, "-p", "pilot-harbor-" + state.Profile, "up", "-d", "--wait"}},
	} {
		result, err := m.runner.Run(ctx, command.dir, command.name, command.args...)
		if err != nil || result.ExitCode != 0 {
			return errors.New("services: retained stopped service activation failed; credential validation not completed")
		}
	}
	return nil
}

// checkComposeOwnership rejects a colliding global Compose identity before a
// fresh registry can render credentials or rebind an existing project's mounts.
func (m *Manager) checkComposeOwnership(ctx context.Context, profile string) error {
	for _, project := range []struct{ name, dir string }{
		{"pilot-services-" + profile, m.root},
		{"pilot-harbor-" + profile, filepath.Join(m.root, "harbor", "installer")},
	} {
		out, err := m.runner.Run(ctx, m.dataDir, "docker", "ps", "-a", "--filter", "label=com.docker.compose.project="+project.name, "--format", "{{.ID}}")
		if err != nil {
			return errors.New("services: inspect Compose ownership command unavailable")
		}
		if out.ExitCode != 0 {
			return errors.New("services: cannot inspect Compose ownership; Docker query failed")
		}
		for _, id := range strings.Fields(out.Stdout) {
			if !containerIDRE.MatchString(id) {
				return errors.New("services: invalid container identity in Docker ownership query")
			}
			labels, err := m.runner.Run(ctx, m.dataDir, "docker", "inspect", id, "--format", "{{json .Config.Labels}}")
			if err != nil {
				return errors.New("services: inspect Compose labels command unavailable")
			}
			if labels.ExitCode != 0 {
				return errors.New("services: cannot inspect Compose ownership; container query failed")
			}
			var values map[string]string
			if err := json.Unmarshal([]byte(labels.Stdout), &values); err != nil {
				return fmt.Errorf("services: decode Compose ownership: %w", err)
			}
			workdir, err := CanonicalDirectory(values["com.docker.compose.project.working_dir"])
			configPath, configErr := CanonicalDirectory(values["com.docker.compose.project.config_files"])
			if err != nil || configErr != nil || workdir != project.dir || configPath != filepath.Join(project.dir, "docker-compose.yml") || values["com.docker.compose.project"] != project.name {
				return fmt.Errorf("services: Compose project %s root conflict; existing containers belong to another service directory; use its --services-dir or --services-adopt-from", project.name)
			}
		}
	}
	return nil
}

var containerIDRE = regexp.MustCompile(`^[a-fA-F0-9]+$`)

// ensurePulpSettingsAccess repairs the modes of bind-mounted Pulp settings
// after a container-managed retry or image upgrade. Docker may own those
// directories, so this must use the same explicit sudo boundary as Compose.
// The database-field key remains root:pulp 0640; only directory traversal is
// granted to the unprivileged Pulp workers.
func (m *Manager) ensurePulpSettingsAccess(ctx context.Context, root string) error {
	settings := filepath.Join(root, "pulp", "settings")
	certs := filepath.Join(settings, "certs")
	result, err := m.runner.Run(ctx, root, "sudo", "-n", "chmod", "0755", settings, certs)
	if err != nil {
		return errors.New("services: set Pulp settings directory access command unavailable")
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("services: set Pulp settings directory access failed: %s", redact(result.Stderr))
	}
	return nil
}

// startHarbor starts the generated Harbor Compose project. A previous
// interrupted start can leave container network endpoints behind even though
// the persistent cache data is valid. Retry that case once by removing only
// this project's containers and orphan endpoints, then recreate the project.
// Compose volumes and the cache data below the service root are preserved.
func (m *Manager) startHarbor(ctx context.Context, harborCompose, profile string, forceRecreate, recoverStale bool) error {
	project := "pilot-harbor-" + profile
	dir := filepath.Dir(harborCompose)
	up := []string{"-n", "docker", "compose", "-f", harborCompose, "-p", project, "up", "-d", "--wait"}
	if forceRecreate {
		up = append(up, "--force-recreate", "--remove-orphans")
	}
	result, err := m.runner.Run(ctx, dir, "sudo", up...)
	if err != nil {
		return errors.New("services: start harbor command unavailable")
	}
	if result.ExitCode == 0 {
		return nil
	}
	firstFailure := redact(result.Stderr)
	if !recoverStale {
		return fmt.Errorf("services: start harbor failed: %s", firstFailure)
	}

	// This is intentionally a single, bounded recovery attempt for a
	// previously healthy stack. It addresses stale Docker network sandboxes
	// without interrupting a new Harbor database's initial schema migration or
	// turning a genuine configuration error into an unbounded restart loop.
	result, err = m.runner.Run(ctx, dir, "sudo", "-n", "docker", "compose", "-f", harborCompose, "-p", project, "down", "--remove-orphans")
	if err != nil {
		return errors.New("services: start harbor failed; recover Harbor topology command unavailable")
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("services: start harbor failed: %s; recover Harbor topology failed: %s", firstFailure, redact(result.Stderr))
	}

	up = append([]string{"-n", "docker", "compose", "-f", harborCompose, "-p", project, "up", "-d", "--wait"}, "--force-recreate", "--remove-orphans")
	result, err = m.runner.Run(ctx, dir, "sudo", up...)
	if err != nil {
		return errors.New("services: recover Harbor topology command unavailable")
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("services: recover Harbor topology failed after initial startup failure (%s): %s", firstFailure, redact(result.Stderr))
	}
	return nil
}

// Status returns persisted state and live Compose status where available.
func (m *Manager) Status(ctx context.Context) (Status, error) {
	unlock, err := m.operationContext(ctx)
	if err != nil {
		return Status{}, err
	}
	defer unlock()
	state, err := m.current()
	if err != nil {
		return Status{}, err
	}
	if state.Fingerprint == "" {
		return Status{Root: m.root, InstanceID: state.InstanceID, Generation: state.Generation}, nil
	}
	result := Status{Configured: true, Running: state.Running, Profile: state.Profile, Fingerprint: state.Fingerprint, BindIP: state.BindIP, Root: state.Root}
	result.InstanceID, result.Generation = state.InstanceID, state.Generation
	result.Capabilities = m.observeCapabilities(ctx, state)
	if err := ctx.Err(); err != nil {
		result.Running = false
		return result, err
	}
	result.Running = requireCapabilities(result.Capabilities, nil) == nil
	if state.ComposePath == "" {
		return result, nil
	}
	project := "pilot-services-" + state.Profile
	if out, runErr := m.runner.Run(ctx, m.root, "docker", "compose", "-f", state.ComposePath, "-p", project, "ps", "--format", "json"); runErr == nil && out.ExitCode == 0 && strings.TrimSpace(out.Stdout) != "" {
		_ = json.Unmarshal([]byte(out.Stdout), &result.Services)
	}
	if err := ctx.Err(); err != nil {
		result.Running = false
		return result, err
	}
	return result, nil
}

// Down stops services and retains all persistent content.
func (m *Manager) Down(ctx context.Context) error {
	return m.DownWithOptions(ctx, MaintenanceOptions{})
}

// DownWithOptions stops a stack, with explicit acknowledgement for legacy guests.
func (m *Manager) DownWithOptions(ctx context.Context, options MaintenanceOptions) error {
	unlock, err := m.operationContext(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	state, err := m.current()
	if err != nil {
		return err
	}
	if err := maintenanceAllowed(state, options); err != nil {
		return err
	}
	return m.down(ctx)
}

func (m *Manager) down(ctx context.Context) error {
	state, err := m.current()
	if err != nil {
		return err
	}
	if state.ComposePath == "" {
		return nil
	}
	if m.shared {
		if err := m.checkComposeOwnership(ctx, state.Profile); err != nil {
			return err
		}
	}
	project := "pilot-services-" + state.Profile
	if result, err := m.runner.Run(ctx, m.root, "docker", "compose", "-f", state.ComposePath, "-p", project, "down"); err != nil {
		return errors.New("services: stop compose command unavailable")
	} else if result.ExitCode != 0 {
		return fmt.Errorf("services: stop compose failed: %s", redact(result.Stderr))
	}
	if state.HarborComposePath != "" {
		harborProject := "pilot-harbor-" + state.Profile
		if result, err := m.runner.Run(ctx, filepath.Dir(state.HarborComposePath), "sudo", "-n", "docker", "compose", "-f", state.HarborComposePath, "-p", harborProject, "down"); err != nil {
			return errors.New("services: stop harbor command unavailable")
		} else if result.ExitCode != 0 {
			return fmt.Errorf("services: stop harbor failed: %s", redact(result.Stderr))
		}
	}
	return m.store.Mutate(func(states []ServiceState) ([]ServiceState, error) {
		if len(states) == 0 {
			return states, nil
		}
		states[0].Running = false
		states[0].UpdatedAt = m.now().UTC()
		return states, nil
	})
}

// Purge stops services and removes the persistent bundle only with explicit
// confirmation. It is intentionally not recoverable from the local disk.
func (m *Manager) Purge(ctx context.Context, confirmed bool) error {
	return m.PurgeWithOptions(ctx, confirmed, MaintenanceOptions{})
}

// PurgeWithOptions removes a stack only after consumer and legacy safety checks.
func (m *Manager) PurgeWithOptions(ctx context.Context, confirmed bool, options MaintenanceOptions) error {
	if !confirmed {
		return errors.New("services: purge requires explicit confirmation")
	}
	unlock, err := m.operationContext(ctx)
	if err != nil {
		return err
	}
	defer unlock()
	state, err := m.current()
	if err != nil {
		return err
	}
	if err := maintenanceAllowed(state, options); err != nil {
		return err
	}
	if err := m.down(ctx); err != nil {
		return err
	}
	// Detach the live root first. os.RemoveAll can fail part-way through a
	// root-owned container bind mount; deleting in place would otherwise leave
	// a new service render paired with an old Harbor database or secret.
	staged := fmt.Sprintf("%s.purge-%s", m.root, m.now().UTC().Format("20060102T150405.000000000Z"))
	if err := os.Rename(m.root, staged); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("services: stage purge data: %w", err)
	}
	if err := m.store.Mutate(func(states []ServiceState) ([]ServiceState, error) {
		if !m.shared || len(states) == 0 {
			return nil, nil
		}
		state := ServiceState{Root: m.root, InstanceID: states[0].InstanceID, Generation: states[0].Generation + 1, AdoptedFrom: states[0].AdoptedFrom}
		return []ServiceState{state}, nil
	}); err != nil {
		return fmt.Errorf("services: clear state after detaching data: %w", err)
	}
	if _, err := os.Stat(staged); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err := os.RemoveAll(staged); err != nil {
		return fmt.Errorf("services: purge detached data at %s but cleanup failed: %w", staged, err)
	}
	return nil
}

// ClientConfig returns the last successful non-secret client contract.
func (m *Manager) ClientConfig(ctx context.Context) (ClientConfig, error) {
	return m.ClientConfigFor(ctx, nil)
}

func (m *Manager) probeEndpoints(ctx context.Context, state ServiceState) error {
	bindIP := net.ParseIP(state.BindIP)
	if bindIP == nil || bindIP.IsUnspecified() {
		return errors.New("services: persisted service bind IP is invalid")
	}
	aptProbe, err := serviceProbeURL(state.Client.AptProxyURL, bindIP, "/acng-report.html")
	if err != nil {
		return fmt.Errorf("services: persisted apt URL is invalid: %w", err)
	}
	pulpProbe, err := serviceProbeURL(state.Client.RPMBaseURL, bindIP, "/pulp/api/v3/status/")
	if err != nil {
		return fmt.Errorf("services: persisted Pulp URL is invalid: %w", err)
	}
	harborProbe, err := serviceProbeURL(state.Client.RegistryMirrorURL, bindIP, "/api/v2.0/health")
	if err != nil {
		return fmt.Errorf("services: persisted Harbor URL is invalid: %w", err)
	}
	probes := []struct {
		name string
		url  string
	}{
		{name: "apt-cacher-ng", url: aptProbe},
		{name: "Pulp", url: pulpProbe},
		{name: "Harbor", url: harborProbe},
	}
	for _, probe := range probes {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, probe.url, nil)
		if err != nil {
			return fmt.Errorf("services: create %s health probe: %w", probe.name, err)
		}
		resp, err := m.client.Do(req)
		if err != nil {
			return fmt.Errorf("services: %s is unreachable", probe.name)
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		resp.Body.Close()
		if resp.StatusCode >= http.StatusInternalServerError {
			return fmt.Errorf("services: %s health probe returned HTTP %d", probe.name, resp.StatusCode)
		}
	}
	return m.validateHarborCredentials(ctx, state)
}

func serviceProbeURL(raw string, bindIP net.IP, path string) (string, error) {
	if bindIP == nil || bindIP.IsUnspecified() {
		return "", errors.New("invalid bind IP")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Port() == "" {
		return "", errors.New("missing scheme or port")
	}
	u.Host = net.JoinHostPort(bindIP.String(), u.Port())
	u.Path = path
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return u.String(), nil
}

func (m *Manager) current() (ServiceState, error) {
	states, err := m.store.Load()
	if err != nil {
		return ServiceState{}, err
	}
	if len(states) == 0 {
		return ServiceState{}, nil
	}
	return states[0], nil
}

func (m *Manager) requireCompose(ctx context.Context) error {
	result, err := m.runner.Run(ctx, m.root, "docker", "compose", "version")
	if err != nil {
		return fmt.Errorf("services: Docker Compose v2 is required: %w", err)
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("services: Docker Compose v2 is required: %s", redact(result.Stderr))
	}
	return nil
}

func (m *Manager) ensureHarbor(ctx context.Context, profile Profile, bundle Bundle) error {
	installerDir := filepath.Join(bundle.Root, "harbor", "installer")
	if _, err := os.Stat(filepath.Join(installerDir, "install.sh")); err == nil {
		return copyHarborConfig(bundle.HarborConfigPath, installerDir)
	}
	if err := os.MkdirAll(installerDir, 0o700); err != nil {
		return fmt.Errorf("services: create Harbor installer dir: %w", err)
	}
	tmp, err := os.CreateTemp(installerDir, "harbor-installer-*.tgz")
	if err != nil {
		return fmt.Errorf("services: create Harbor download: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profile.Harbor.InstallerURL, nil)
	if err != nil {
		tmp.Close()
		return fmt.Errorf("services: create Harbor download request: %w", err)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		tmp.Close()
		return fmt.Errorf("services: download Harbor installer: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		tmp.Close()
		return fmt.Errorf("services: download Harbor installer: HTTP %s", resp.Status)
	}
	if _, err := io.Copy(tmp, io.LimitReader(resp.Body, 2<<30)); err != nil {
		tmp.Close()
		return fmt.Errorf("services: save Harbor installer: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("services: close Harbor installer: %w", err)
	}
	if err := extractTarGz(tmpPath, installerDir); err != nil {
		return err
	}
	return copyHarborConfig(bundle.HarborConfigPath, installerDir)
}

func extractTarGz(path, dest string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("services: open Harbor installer: %w", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("services: read Harbor installer gzip: %w", err)
	}
	defer gz.Close() //nolint:errcheck
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("services: read Harbor installer archive: %w", err)
		}
		name := filepath.Clean(h.Name)
		if name == "." || filepath.IsAbs(name) || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			return fmt.Errorf("services: unsafe Harbor archive path %q", h.Name)
		}
		// Strip the release directory so the installer always lands directly
		// under the persistent installer root.
		parts := strings.Split(name, string(filepath.Separator))
		if len(parts) < 2 {
			continue
		}
		rel := filepath.Join(parts[1:]...)
		out := filepath.Join(dest, rel)
		if !within(dest, out) {
			return fmt.Errorf("services: unsafe Harbor archive output %q", h.Name)
		}
		if h.FileInfo().IsDir() {
			if err := os.MkdirAll(out, 0o700); err != nil {
				return fmt.Errorf("services: create Harbor directory: %w", err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
			return err
		}
		mode := h.FileInfo().Mode() & 0o777
		if mode == 0 {
			mode = 0o600
		}
		if err := writeStream(out, tr, mode); err != nil {
			return err
		}
	}
	return nil
}

func copyHarborConfig(src, installerDir string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return fmt.Errorf("services: read Harbor config: %w", err)
	}
	return writeAtomicMode(filepath.Join(installerDir, "harbor.yml"), b, 0o600)
}

func harborComposePath(bundle Bundle) string {
	path := filepath.Join(bundle.Root, "harbor", "installer", "docker-compose.yml")
	if _, err := os.Stat(path); err != nil {
		return ""
	}
	return path
}

var harborContainerNameRE = regexp.MustCompile(`^(\s*container_name:\s*)([^\s#]+)(\s*)$`)

// namespaceHarborCompose keeps the official generated topology intact while
// avoiding collisions with unrelated host containers and binding its proxy
// only to the selected libvirt gateway address.
func namespaceHarborCompose(path, profile, bindIP string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("services: read generated Harbor Compose: %w", err)
	}
	prefix := "pilot-harbor-" + profile + "-"
	lines := strings.Split(string(b), "\n")
	portRewritten := false
	for i, line := range lines {
		if match := harborContainerNameRE.FindStringSubmatch(line); match != nil {
			name := match[2]
			if !strings.HasPrefix(name, prefix) {
				name = prefix + name
			}
			lines[i] = match[1] + name + match[3]
			continue
		}
		if strings.TrimSpace(line) == "- 8081:8080" {
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			lines[i] = indent + "- " + bindIP + ":8081:8080"
			portRewritten = true
		}
	}
	if !portRewritten {
		return errors.New("services: generated Harbor Compose has no expected proxy port mapping")
	}
	if err := writeAtomicMode(path, []byte(strings.Join(lines, "\n")), 0o600); err != nil {
		return fmt.Errorf("services: namespace generated Harbor Compose: %w", err)
	}
	return nil
}

func writeStream(path string, r io.Reader, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return fmt.Errorf("services: create %s: %w", path, err)
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return fmt.Errorf("services: write %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("services: close %s: %w", path, err)
	}
	return nil
}

func within(root, path string) bool {
	r, err1 := filepath.Abs(root)
	p, err2 := filepath.Abs(path)
	if err1 != nil || err2 != nil {
		return false
	}
	return p == r || strings.HasPrefix(p, r+string(filepath.Separator))
}

func redact(s string) string {
	return "[service command output suppressed]"
}
