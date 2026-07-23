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
	"os"
	"os/exec"
	"path/filepath"
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
	cmd := exec.CommandContext(ctx, name, args...)
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
	Profile           string       `json:"profile"`
	Fingerprint       string       `json:"fingerprint"`
	Root              string       `json:"root"`
	ComposePath       string       `json:"compose_path"`
	HarborComposePath string       `json:"harbor_compose_path,omitempty"`
	Client            ClientConfig `json:"client"`
	BindIP            string       `json:"bind_ip"`
	Running           bool         `json:"running"`
	UpdatedAt         time.Time    `json:"updated_at"`
}

// Status is the user-facing service health summary.
type Status struct {
	Configured  bool          `json:"configured"`
	Running     bool          `json:"running"`
	Profile     string        `json:"profile,omitempty"`
	Fingerprint string        `json:"fingerprint,omitempty"`
	BindIP      string        `json:"bind_ip,omitempty"`
	Root        string        `json:"root,omitempty"`
	Services    []ServiceItem `json:"services,omitempty"`
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
	runner  CommandRunner
	now     func() time.Time
	client  *http.Client
}

// NewManager creates a host-service manager rooted below dataDir/cache.
func NewManager(dataDir string, runner CommandRunner) (*Manager, error) {
	if dataDir == "" {
		return nil, errors.New("services: data directory is required")
	}
	store, err := statefile.New[ServiceState](dataDir, "services.json", serviceStateVersion, "services")
	if err != nil {
		return nil, err
	}
	if runner == nil {
		runner = osCommandRunner{}
	}
	return &Manager{dataDir: dataDir, root: DataRoot(dataDir), store: store, runner: runner, now: time.Now, client: &http.Client{Timeout: 5 * time.Second}}, nil
}

// Up renders and starts the service bundle on bindIP. It is idempotent for an
// unchanged profile and refuses to silently replace a different profile.
func (m *Manager) Up(ctx context.Context, profile Profile, bindIP net.IP) error {
	if err := profile.Validate(); err != nil {
		return err
	}
	fingerprint, err := profile.Fingerprint()
	if err != nil {
		return err
	}
	if current, err := m.current(); err == nil && current.Fingerprint != "" && current.Fingerprint != fingerprint {
		return fmt.Errorf("services: profile fingerprint mismatch (running=%s requested=%s); purge or use the existing profile", current.Fingerprint, fingerprint)
	}
	bundle, err := RenderBundle(profile, m.root, bindIP)
	if err != nil {
		return err
	}
	if err := m.requireCompose(ctx); err != nil {
		return err
	}
	if err := m.ensureHarbor(ctx, profile, bundle); err != nil {
		return err
	}
	installerDir := filepath.Join(bundle.Root, "harbor", "installer")
	if result, err := m.runner.Run(ctx, installerDir, "./install.sh"); err != nil {
		return fmt.Errorf("services: install harbor: %w", err)
	} else if result.ExitCode != 0 {
		return fmt.Errorf("services: install harbor failed: %s", redact(result.Stderr))
	}
	project := "pilot-services-" + profile.Name
	if result, err := m.runner.Run(ctx, m.root, "docker", "compose", "-f", bundle.ComposePath, "-p", project, "up", "-d", "--wait"); err != nil {
		return fmt.Errorf("services: start compose: %w", err)
	} else if result.ExitCode != 0 {
		return fmt.Errorf("services: start compose failed: %s", redact(result.Stderr))
	}
	if harborCompose := harborComposePath(bundle); harborCompose != "" {
		if result, err := m.runner.Run(ctx, filepath.Dir(harborCompose), "docker", "compose", "-f", harborCompose, "up", "-d"); err != nil {
			return fmt.Errorf("services: start harbor: %w", err)
		} else if result.ExitCode != 0 {
			return fmt.Errorf("services: start harbor failed: %s", redact(result.Stderr))
		}
	}
	state := ServiceState{Profile: profile.Name, Fingerprint: fingerprint, Root: m.root, ComposePath: bundle.ComposePath, HarborComposePath: harborComposePath(bundle), Client: bundle.Client, BindIP: bindIP.String(), Running: true, UpdatedAt: m.now().UTC()}
	return m.store.Mutate(func(states []ServiceState) ([]ServiceState, error) {
		return []ServiceState{state}, nil
	})
}

// Status returns persisted state and live Compose status where available.
func (m *Manager) Status(ctx context.Context) (Status, error) {
	state, err := m.current()
	if err != nil {
		return Status{}, err
	}
	if state.Fingerprint == "" {
		return Status{}, nil
	}
	result := Status{Configured: true, Running: state.Running, Profile: state.Profile, Fingerprint: state.Fingerprint, BindIP: state.BindIP, Root: state.Root}
	if state.ComposePath == "" {
		return result, nil
	}
	project := "pilot-services-" + state.Profile
	if out, runErr := m.runner.Run(ctx, m.root, "docker", "compose", "-f", state.ComposePath, "-p", project, "ps", "--format", "json"); runErr == nil && out.ExitCode == 0 && strings.TrimSpace(out.Stdout) != "" {
		_ = json.Unmarshal([]byte(out.Stdout), &result.Services)
	}
	return result, nil
}

// Down stops services and retains all persistent content.
func (m *Manager) Down(ctx context.Context) error {
	state, err := m.current()
	if err != nil {
		return err
	}
	if state.ComposePath == "" {
		return nil
	}
	project := "pilot-services-" + state.Profile
	if result, err := m.runner.Run(ctx, m.root, "docker", "compose", "-f", state.ComposePath, "-p", project, "down"); err != nil {
		return fmt.Errorf("services: stop compose: %w", err)
	} else if result.ExitCode != 0 {
		return fmt.Errorf("services: stop compose failed: %s", redact(result.Stderr))
	}
	if state.HarborComposePath != "" {
		if result, err := m.runner.Run(ctx, filepath.Dir(state.HarborComposePath), "docker", "compose", "-f", state.HarborComposePath, "down"); err != nil {
			return fmt.Errorf("services: stop harbor: %w", err)
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
	if !confirmed {
		return errors.New("services: purge requires explicit confirmation")
	}
	if err := m.Down(ctx); err != nil {
		return err
	}
	if err := os.RemoveAll(m.root); err != nil {
		return fmt.Errorf("services: purge data: %w", err)
	}
	return m.store.Mutate(func(states []ServiceState) ([]ServiceState, error) { return nil, nil })
}

// ClientConfig returns the last successful non-secret client contract.
func (m *Manager) ClientConfig(ctx context.Context) (ClientConfig, error) {
	state, err := m.current()
	if err != nil {
		return ClientConfig{}, err
	}
	if !state.Running {
		return ClientConfig{}, errors.New("services: service stack is not running")
	}
	return state.Client, nil
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
	defer gz.Close()
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
	return strings.ReplaceAll(strings.ReplaceAll(s, "password", "[redacted]"), "secret", "[redacted]")
}
