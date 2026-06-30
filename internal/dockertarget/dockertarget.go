// Package dockertarget manages "docker containers used as target hosts"
// for pilot. It is intentionally separate from internal/sandbox:
//
//   - internal/sandbox     controls where the pilot *agent's tool calls*
//                          run (LocalEnvironment vs DockerEnvironment).
//                          That mode is opt-in via `--sandbox`.
//
//   - internal/dockertarget controls the *target host* that ansible-playbook
//                          operates against. The user can spin up a
//                          disposable container, run a playbook against it,
//                          verify a spec, then tear it down. This is the
//                          "docker as a VM" use case.
//
// The two are orthogonal: a `pilot docker-target run ...` command talks
// to a docker container via the `docker` ansible connection plugin,
// without invoking the LLM agent loop or the sandbox environment.
package dockertarget

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Status is the lifecycle state of a docker target.
type Status string

const (
	StatusRunning Status = "running"
	StatusStopped Status = "stopped"
	StatusMissing Status = "missing" // record exists in state but container is gone
)

// Target describes one docker container that pilot is using as a target host.
type Target struct {
	Name        string    `json:"name"`
	Image       string    `json:"image"`
	ContainerID string    `json:"container_id"`
	Status      Status    `json:"status"`
	Hostname    string    `json:"hostname"` // primary ansible inventory host key
	Network     string    `json:"network"`
	Privileged  bool      `json:"privileged"`
	CreatedAt   time.Time `json:"created_at"`
	StartedAt   time.Time `json:"started_at"`
	// InventoryPath, when non-empty, points to a file the user has
	// pre-staged. When empty (the common case), pilot renders a
	// generated inventory string on demand via RenderInventory.
	InventoryPath string `json:"inventory_path,omitempty"`
	// Hosts, when non-empty, gives the target multiple ansible host
	// names all routing to the same container. Useful for playbooks
	// whose target_group is a role name ('dns', 'ntp', 'keycloak') —
	// with multi-host, one target can pretend to be all of them.
	Hosts []string `json:"hosts,omitempty"`
	// Systemd records whether the container was booted with systemd as
	// PID 1 (vs the default `sleep infinity`). Persisted so rollback
	// recreates the target with the same init, and so `list`/`get`
	// callers can tell whether `systemctl` tasks will work.
	Systemd bool `json:"systemd,omitempty"`
}

// Options bundles user-facing knobs for Up.
type Options struct {
	Name       string // required; the container name AND ansible host key
	Image      string // required; e.g. "ubuntu:24.04"
	Network    string // docker --network; default "host"
	// Privileged controls docker --privileged. Defaults to true so
	// the container can run apt / systemd / mount cgroups. Pass a
	// non-nil pointer set to false to opt out.
	Privileged *bool
	Hostname   string // container --hostname; default = Name
	// Hosts, when non-empty, are additional ansible host names that
	// all resolve to the same container. The container's --name is
	// always one of the names (so `pilot docker-target exec --name`
	// keeps working); the extras are inventory aliases useful for
	// playbooks that target groups by name.
	Hosts      []string
	ExtraArgs  []string
	// Systemd, when non-nil and true, boots the container with systemd
	// as PID 1 (entrypoint /sbin/init + writable /run tmpfs) instead of
	// `sleep infinity`. This is what makes ansible's systemd/service
	// modules and systemd-resolved work. Requires a privileged
	// container AND an image that actually ships systemd (e.g.
	// pilot-target:ubuntu-24.04); stock ubuntu:24.04 has no /sbin/init.
	Systemd *bool
}

// state is the on-disk JSON shape. Versioned so future schema breaks
// can be detected instead of silently corrupting the file.
type state struct {
	Version int      `json:"version"`
	Targets []Target `json:"targets"`
}

const stateVersion = 1

// Manager owns the lifecycle of all docker targets. One Manager per
// data directory; safe for concurrent use by multiple pilot commands
// because the on-disk state file is rewritten atomically (write to a
// temp file in the same directory then rename).
type Manager struct {
	mu       sync.Mutex
	stateDir string
	stateFile string
	now      func() time.Time // overridable in tests
}

// NewManager constructs a Manager rooted at stateDir.
// The state file is stateDir/docker-targets.json; stateDir is created
// if missing.
func NewManager(stateDir string) (*Manager, error) {
	if stateDir == "" {
		return nil, errors.New("dockertarget: stateDir is required")
	}
	if err := os.MkdirAll(stateDir, 0o755); err != nil {
		return nil, fmt.Errorf("dockertarget: mkdir %s: %w", stateDir, err)
	}
	return &Manager{
		stateDir:  stateDir,
		stateFile: filepath.Join(stateDir, "docker-targets.json"),
		now:       time.Now,
	}, nil
}

// load reads + parses the state file. Missing file is not an error —
// the user simply has no targets yet.
func (m *Manager) load() (*state, error) {
	data, err := os.ReadFile(m.stateFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return &state{Version: stateVersion}, nil
		}
		return nil, fmt.Errorf("dockertarget: read state: %w", err)
	}
	var s state
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("dockertarget: parse state: %w", err)
	}
	if s.Version != stateVersion {
		return nil, fmt.Errorf("dockertarget: state version %d (want %d); refusing to load", s.Version, stateVersion)
	}
	return &s, nil
}

// save writes the state file atomically.
func (m *Manager) save(s *state) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("dockertarget: marshal state: %w", err)
	}
	tmp, err := os.CreateTemp(m.stateDir, ".docker-targets-*.json.tmp")
	if err != nil {
		return fmt.Errorf("dockertarget: create temp: %w", err)
	}
	tmpName := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return fmt.Errorf("dockertarget: write temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("dockertarget: close temp: %w", err)
	}
	if err := os.Rename(tmpName, m.stateFile); err != nil {
		os.Remove(tmpName)
		return fmt.Errorf("dockertarget: rename temp: %w", err)
	}
	return nil
}

// dockerResult captures the output of one docker CLI invocation.
type dockerResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// DockerRaw runs an arbitrary `docker` subcommand and returns the
// combined (stdout, stderr, exit code) result. Exposed (vs the
// unexported docker helper) for callers that need ops beyond the
// Manager's typed API: e.g. `pilot docker-target snapshot` calls
// `docker commit`, `pilot docker-target rollback` calls `docker rm`
// + `docker run`.
//
// Honours the optional PILOT_DOCKER_BIN env override (so tests /
// power users can pick a different binary). 5 minute timeout is
// generous for pull / run.
func (m *Manager) DockerRaw(ctx context.Context, args ...string) (*dockerResult, error) {
	return m.docker(ctx, args...)
}

// docker runs the docker CLI with the given args. Honours the optional
// DOCKER env override (so tests / power users can pick a different
// binary). 5 minute timeout is generous for pull / run.
func (m *Manager) docker(ctx context.Context, args ...string) (*dockerResult, error) {
	bin := os.Getenv("PILOT_DOCKER_BIN")
	if bin == "" {
		bin = "docker"
	}
	c, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(c, bin, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	res := &dockerResult{Stdout: stdout.String(), Stderr: stderr.String()}
	if exitErr, ok := err.(*exec.ExitError); ok {
		res.ExitCode = exitErr.ExitCode()
		return res, nil
	}
	if err != nil {
		return res, fmt.Errorf("docker %s: %w", strings.Join(args, " "), err)
	}
	res.ExitCode = 0
	return res, nil
}

// Up brings up a new docker target. If a target with the same name
// already exists in state, Up returns an error (use Down first or pick
// a different name). If a container with the same name exists in
// docker but is NOT in state, Up also returns an error — the user has
// to either reuse via Reset or pick a new name. We refuse to silently
// hijack an unrelated container.
func (m *Manager) Up(ctx context.Context, opt Options) (*Target, error) {
	if opt.Name == "" {
		return nil, errors.New("dockertarget: name is required")
	}
	if opt.Image == "" {
		return nil, errors.New("dockertarget: image is required")
	}
	if !validName(opt.Name) {
		return nil, fmt.Errorf("dockertarget: invalid name %q (want [a-zA-Z0-9_.-]+)", opt.Name)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	s, err := m.load()
	if err != nil {
		return nil, err
	}
	for _, t := range s.Targets {
		if t.Name == opt.Name {
			return nil, fmt.Errorf("dockertarget: target %q already in state (status=%s); run `pilot docker-target down --name %s` first", opt.Name, t.Status, opt.Name)
		}
	}
	// Refuse to hijack an unrelated container with the same name.
	inspectRes, err := m.docker(ctx, "inspect", opt.Name)
	if err != nil {
		return nil, fmt.Errorf("dockertarget: inspect existing: %w", err)
	}
	if inspectRes.ExitCode == 0 {
		return nil, fmt.Errorf("dockertarget: a container named %q already exists outside pilot state; pick a different --name or remove it first", opt.Name)
	}

	network := opt.Network
	if network == "" {
		network = "host"
	}
	hostname := opt.Hostname
	if hostname == "" {
		hostname = opt.Name
	}
	privileged := true
	if opt.Privileged != nil {
		privileged = *opt.Privileged
	}
	systemd := false
	if opt.Systemd != nil {
		systemd = *opt.Systemd
	}
	// systemd as PID 1 needs the container to be privileged (it mounts
	// cgroups and talks to the kernel). Refuse the impossible combo up
	// front instead of letting the container boot-loop and leaving a
	// confusing half-started target in state.
	if systemd && !privileged {
		return nil, errors.New("dockertarget: systemd requires a privileged container; drop --no-privileged")
	}

	args := []string{
		"run", "-d",
		"--name", opt.Name,
		"--hostname", hostname,
		"--network", network,
	}
	if privileged {
		args = append(args, "--privileged")
	}
	if systemd {
		// Writable /run + /run/lock are what systemd needs to boot as
		// PID 1 inside a container. On a cgroup v2 host --privileged
		// already gives rw access to /sys/fs/cgroup, so no explicit
		// cgroup mount or --cgroupns is required.
		args = append(args, "--tmpfs", "/run", "--tmpfs", "/run/lock")
	}
	args = append(args, opt.ExtraArgs...)
	args = append(args, opt.Image)
	if systemd {
		// Boot the image's init so ansible's systemd/service modules and
		// systemd-resolved actually work. Requires an image that ships
		// systemd (e.g. pilot-target:ubuntu-24.04); a stock image with
		// no /sbin/init will fail at `docker run` and we surface that.
		args = append(args, "/sbin/init")
	} else {
		// No init: keep the container alive so `exec` can reach in.
		args = append(args, "sleep", "infinity")
	}

	runRes, err := m.docker(ctx, args...)
	if err != nil {
		return nil, err
	}
	if runRes.ExitCode != 0 {
		return nil, fmt.Errorf("dockertarget: docker run failed (exit %d): %s", runRes.ExitCode, runRes.Stderr)
	}
	containerID := strings.TrimSpace(runRes.Stdout)
	if containerID == "" {
		return nil, errors.New("dockertarget: docker run returned empty container ID")
	}

	now := m.now()
	hosts := []string{opt.Name}
	if len(opt.Hosts) > 0 {
		// De-dup + validate; refuse to duplicate opt.Name (it is
		// always the primary).
		seen := map[string]bool{opt.Name: true}
		for _, h := range opt.Hosts {
			if !seen[h] {
				if !validName(h) {
					return nil, fmt.Errorf("dockertarget: invalid host alias %q (want [a-zA-Z0-9_.-]+)", h)
				}
				hosts = append(hosts, h)
				seen[h] = true
			}
		}
	}
	t := Target{
		Name:        opt.Name,
		Image:       opt.Image,
		ContainerID: containerID,
		Status:      StatusRunning,
		Hostname:    hostname,
		Network:     network,
		Privileged:  privileged,
		Systemd:     systemd,
		Hosts:       hosts,
		CreatedAt:   now,
		StartedAt:   now,
	}
	s.Targets = append(s.Targets, t)
	if err := m.save(s); err != nil {
		// Best-effort rollback: try to remove the container we just
		// started so we don't leave orphans. If this fails too, the
		// user sees both errors and can `docker rm -f` manually.
		_, _ = m.docker(ctx, "rm", "-f", opt.Name)
		return nil, err
	}
	return &t, nil
}

// Down removes a target. If the target exists in state but the
// container is already gone (StatusMissing), Down clears the state
// record and returns nil — this is the "idempotent down" behaviour
// that matches `docker rm -f` semantics.
//
// If the target name isn't in state at all, Down returns an error so
// the CLI can surface it (the user may have mistyped the name).
func (m *Manager) Down(ctx context.Context, name string) error {
	if name == "" {
		return errors.New("dockertarget: name is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	s, err := m.load()
	if err != nil {
		return err
	}
	idx := -1
	for i, t := range s.Targets {
		if t.Name == name {
			idx = i
			break
		}
	}
	if idx < 0 {
		return fmt.Errorf("dockertarget: no target named %q in state", name)
	}
	t := s.Targets[idx]
	if t.Status == StatusRunning {
		rmRes, err := m.docker(ctx, "rm", "-f", name)
		if err != nil {
			return err
		}
		if rmRes.ExitCode != 0 {
			// Common case: container already gone. Don't fail — just
			// drop the state record.
			if !strings.Contains(strings.ToLower(rmRes.Stderr), "no such container") {
				return fmt.Errorf("dockertarget: docker rm %q failed (exit %d): %s", name, rmRes.ExitCode, rmRes.Stderr)
			}
		}
	}
	s.Targets = append(s.Targets[:idx], s.Targets[idx+1:]...)
	return m.save(s)
}

// Get returns the target record + a live status refresh.
// If the state record says running but docker says the container is
// gone, Get returns the record with Status=StatusMissing (caller can
// then decide to call Down to clean up the state).
func (m *Manager) Get(ctx context.Context, name string) (*Target, error) {
	if name == "" {
		return nil, errors.New("dockertarget: name is required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.load()
	if err != nil {
		return nil, err
	}
	for _, t := range s.Targets {
		if t.Name == name {
			live := t
			live.Status = m.refreshStatus(ctx, t)
			return &live, nil
		}
	}
	return nil, fmt.Errorf("dockertarget: no target named %q", name)
}

// List returns every target in state, each with a live status refresh.
// Sorted by name for stable CLI output.
func (m *Manager) List(ctx context.Context) ([]Target, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, err := m.load()
	if err != nil {
		return nil, err
	}
	out := make([]Target, 0, len(s.Targets))
	for _, t := range s.Targets {
		live := t
		live.Status = m.refreshStatus(ctx, t)
		out = append(out, live)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// refreshStatus is only safe to call with m.mu held. It does a single
// `docker inspect` per target — for the typical "few targets" case
// this is fine; if a user has hundreds we can batch later.
func (m *Manager) refreshStatus(ctx context.Context, t Target) Status {
	res, err := m.docker(ctx, "inspect", "--format", "{{.State.Running}}", t.Name)
	if err != nil || res.ExitCode != 0 {
		return StatusMissing
	}
	v := strings.TrimSpace(strings.ToLower(res.Stdout))
	if v == "true" {
		return StatusRunning
	}
	if v == "false" {
		return StatusStopped
	}
	return StatusMissing
}

// RenderInventory renders a YAML inventory targeting this single
// docker container via ansible_connection=docker. Suitable for
// passing to ansible-playbook with -i.
//
// If the user has a custom InventoryPath on the Target, we read that
// file instead — this lets power users override connection params
// (e.g. force docker_network_mode) without forking the package.
func (t *Target) RenderInventory() (string, error) {
	if t == nil {
		return "", errors.New("dockertarget: nil target")
	}
	if t.InventoryPath != "" {
		data, err := os.ReadFile(t.InventoryPath)
		if err != nil {
			return "", fmt.Errorf("dockertarget: read inventory_path %s: %w", t.InventoryPath, err)
		}
		return string(data), nil
	}
	var sb strings.Builder
	sb.WriteString("# Generated by pilot docker-target — do not edit by hand.\n")
	sb.WriteString("all:\n")
	sb.WriteString("  hosts:\n")
	// Primary host (always == t.Name)
	fmt.Fprintf(&sb, "    %s:\n", t.Name)
	fmt.Fprintf(&sb, "      ansible_connection: docker\n")
	fmt.Fprintf(&sb, "      ansible_host: %s\n", t.Name)
	fmt.Fprintf(&sb, "      ansible_user: root\n")
	// Alias hosts: same docker container, different inventory key
	for _, h := range t.Hosts {
		if h == t.Name {
			continue
		}
		fmt.Fprintf(&sb, "    %s:\n", h)
		fmt.Fprintf(&sb, "      ansible_connection: docker\n")
		fmt.Fprintf(&sb, "      ansible_host: %s\n", t.Name)
		fmt.Fprintf(&sb, "      ansible_user: root\n")
	}
	return sb.String(), nil
}

// Exec runs a single shell command inside the target container using
// `docker exec`. argv is passed positionally; no shell is invoked on
// the host (matches pilot's no-shell stance). For shell features
// (pipes, redirects) the caller must invoke `sh -c "<cmd>"` itself.
//
// Returns combined output and exit code.
func (m *Manager) Exec(ctx context.Context, name string, argv []string) (*dockerResult, error) {
	if name == "" {
		return nil, errors.New("dockertarget: name is required")
	}
	if len(argv) == 0 {
		return nil, errors.New("dockertarget: argv is required")
	}
	args := append([]string{"exec", name}, argv...)
	return m.docker(ctx, args...)
}

// validName keeps docker container names predictable across the
// inventory / state file / CLI. Docker itself accepts [a-zA-Z0-9_.-]
// for container names; we mirror that.
func validName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '_' || r == '.' || r == '-':
		default:
			return false
		}
	}
	return true
}
