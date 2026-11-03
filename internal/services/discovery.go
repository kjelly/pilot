package services

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"github.com/kjelly/pilot/internal/statefile"
)

// DiscoveryOptions separates host service ownership from disposable VM state.
type DiscoveryOptions struct {
	Directory         string
	LegacyDirectories []string
	AdoptFrom         string
}

type rootOwner struct {
	Discovery  string `json:"discovery"`
	InstanceID string `json:"instance_id"`
}

// CanonicalDirectory resolves existing symlink ancestors even before the final
// directory exists, so creation and subsequent operations use the same lock.
func CanonicalDirectory(path string) (string, error) {
	if path == "" {
		return "", errors.New("services: directory is required")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err == nil {
		return resolved, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	parent := filepath.Dir(abs)
	if parent == abs {
		return "", err
	}
	parent, err = CanonicalDirectory(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(abs)), nil
}

func lockOperation(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, fmt.Errorf("services: open operation lock: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("services: lock operation: %w", err)
	}
	return f, nil
}

func rootLockPath(root string) string {
	return filepath.Join(filepath.Dir(root), "."+filepath.Base(root)+".services-operation.lock")
}

func composeLock() (*os.File, error) {
	// Compose identities share the host Docker namespace, independently of
	// HOME, TMPDIR, checkouts and directory overrides.
	return lockOperation(fmt.Sprintf("/tmp/pilot-services-compose-%d.lock", os.Getuid()))
}

// NewSharedManager discovers or adopts one host stack without relocating data.
// LegacyDirectories is a bounded caller-supplied list, never a recursive scan.
func NewSharedManager(options DiscoveryOptions, runner CommandRunner) (*Manager, error) {
	global, err := composeLock()
	if err != nil {
		return nil, err
	}
	defer global.Close()
	dir, err := CanonicalDirectory(options.Directory)
	if err != nil {
		return nil, err
	}
	lk, err := lockOperation(filepath.Join(dir, ".services-operation.lock"))
	if err != nil {
		return nil, err
	}
	defer lk.Close()
	m, err := NewManager(dir, runner)
	if err != nil {
		return nil, err
	}
	m.shared = true
	states, err := m.store.Load()
	if err != nil {
		return nil, fmt.Errorf("services: discovery state is unreadable; restore it before adoption: %w", err)
	}
	if len(states) > 1 {
		return nil, errors.New("services: ambiguous discovery state")
	}
	current, err := m.current()
	if err != nil {
		return nil, fmt.Errorf("services: discovery state is unreadable; restore it before adoption: %w", err)
	}
	if current.Root != "" {
		m.root = current.Root
	}
	root, err := CanonicalDirectory(m.root)
	if err != nil {
		return nil, err
	}
	m.root = root
	if current.Root != "" && current.Root != root {
		return nil, errors.New("services: registered root is not canonical; restore discovery state")
	}
	if current.ComposePath != "" && current.ComposePath != filepath.Join(root, "docker-compose.yml") {
		return nil, errors.New("services: registered Compose root conflict")
	}
	if current.HarborComposePath != "" && current.HarborComposePath != filepath.Join(root, "harbor", "installer", "docker-compose.yml") {
		return nil, errors.New("services: registered Harbor root conflict")
	}
	if current.Fingerprint != "" {
		rootLock, err := lockOperation(rootLockPath(root))
		if err != nil {
			return nil, err
		}
		ownerErr := m.verifyRootOwner(current.InstanceID)
		if ownerErr == nil && current.ComposePath != "" {
			ownerErr = validateLegacyData(current)
		}
		rootLock.Close()
		if ownerErr != nil {
			return nil, ownerErr
		}
	}
	candidates := options.LegacyDirectories
	if options.AdoptFrom != "" {
		candidates = append(append([]string{}, candidates...), options.AdoptFrom)
	}
	seen := map[string]bool{dir: true}
	var adopted *ServiceState
	var adoptedFrom []string
	for _, candidate := range candidates {
		legacyDir, err := CanonicalDirectory(candidate)
		if err != nil {
			return nil, err
		}
		if seen[legacyDir] {
			continue
		}
		seen[legacyDir] = true
		// Once registered, shared state is authoritative. The original input
		// remains a historical snapshot after upgrades, down or purge.
		if current.Root != "" && slices.Contains(current.AdoptedFrom, legacyDir) {
			continue
		}
		legacy, found, err := legacyState(legacyDir)
		if err != nil {
			return nil, err
		}
		if !found {
			if candidate == options.AdoptFrom {
				return nil, fmt.Errorf("services: adoption source %s has no usable service state", legacyDir)
			}
			continue
		}
		if current.Root != "" && legacy.Root == current.Root {
			if current.Fingerprint != "" && (legacy.Fingerprint != current.Fingerprint || legacy.BindIP != current.BindIP) {
				return nil, fmt.Errorf("services: legacy profile or bind endpoint conflicts with registered stack at %s", legacy.Root)
			}
			continue
		}
		if current.Root != "" && legacy.Root != current.Root {
			return nil, fmt.Errorf("services: conflicting legacy service root %s (registered %s); choose one discovery directory and diagnose --services-adopt-from", legacy.Root, current.Root)
		}
		if adopted != nil && legacy.Root != adopted.Root {
			return nil, fmt.Errorf("services: conflicting legacy service roots %s and %s; select an explicit --services-adopt-from with an isolated --services-dir", adopted.Root, legacy.Root)
		}
		adopted = &legacy
		adoptedFrom = append(adoptedFrom, legacyDir)
	}
	if current.Root != "" {
		if current.InstanceID == "" {
			return nil, errors.New("services: discovery state is missing instance identity")
		}
		return m, nil
	}
	if adopted == nil {
		if data, err := hasServiceData(root); err != nil {
			return nil, err
		} else if data {
			return nil, fmt.Errorf("services: persistent data at %s has no discovery state; restore state or explicitly adopt its original data directory", root)
		}
		return m, nil
	}
	m.root = adopted.Root
	rootLock, err := lockOperation(rootLockPath(m.root))
	if err != nil {
		return nil, err
	}
	defer rootLock.Close()
	if err := validateLegacyData(*adopted); err != nil {
		return nil, err
	}
	identity, err := m.claimRoot("")
	if err != nil {
		return nil, err
	}
	adopted.InstanceID, adopted.Generation = identity, 1
	adopted.AdoptedFrom = adoptedFrom
	adopted.Client.InstanceID, adopted.Client.Generation = identity, 1
	if err := m.store.Mutate(func(states []ServiceState) ([]ServiceState, error) { return []ServiceState{*adopted}, nil }); err != nil {
		return nil, err
	}
	return m, nil
}

func hasServiceData(root string) (bool, error) {
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.Name() != ".pilot-services-owner.json" && entry.Name() != ".pilot-services-owner.json.lock" {
			return true, nil
		}
	}
	return false, nil
}

func legacyState(dir string) (ServiceState, bool, error) {
	root := DataRoot(dir)
	_, err := os.Stat(filepath.Join(dir, "services.json"))
	if errors.Is(err, os.ErrNotExist) {
		data, err := hasServiceData(root)
		if err != nil {
			return ServiceState{}, false, err
		}
		if data {
			return ServiceState{}, false, fmt.Errorf("services: legacy persistent data at %s has missing service state; restore services.json before adoption", root)
		}
		return ServiceState{}, false, nil
	}
	if err != nil {
		return ServiceState{}, false, err
	}
	store, err := statefile.New[ServiceState](dir, "services.json", serviceStateVersion, "services")
	if err != nil {
		return ServiceState{}, false, err
	}
	states, err := store.Load()
	if err != nil {
		return ServiceState{}, false, fmt.Errorf("services: legacy state at %s is unreadable; restore it before adoption: %w", dir, err)
	}
	if len(states) == 0 {
		data, err := hasServiceData(root)
		if err != nil {
			return ServiceState{}, false, err
		}
		if data {
			return ServiceState{}, false, fmt.Errorf("services: legacy data at %s has empty service state", root)
		}
		return ServiceState{}, false, nil
	}
	if len(states) != 1 {
		return ServiceState{}, false, fmt.Errorf("services: ambiguous legacy state at %s", dir)
	}
	s := states[0]
	canonical, err := CanonicalDirectory(root)
	if err != nil {
		return ServiceState{}, false, err
	}
	actual, err := CanonicalDirectory(s.Root)
	if err != nil || actual != canonical || s.Fingerprint == "" || s.Profile == "" || s.BindIP == "" || s.ComposePath != filepath.Join(s.Root, "docker-compose.yml") {
		return ServiceState{}, false, fmt.Errorf("services: incompatible legacy service state at %s; restore its original root/profile/endpoints before adoption", dir)
	}
	if net.ParseIP(s.BindIP) == nil || s.Client.Profile != s.Profile || s.Client.Fingerprint != s.Fingerprint || (s.Client.HostIP != "" && s.Client.HostIP != s.BindIP) {
		return ServiceState{}, false, fmt.Errorf("services: incompatible legacy client/profile/bind endpoints at %s", dir)
	}
	s.Root = actual
	s.ComposePath = filepath.Join(actual, "docker-compose.yml")
	if s.HarborComposePath != "" {
		s.HarborComposePath = filepath.Join(actual, "harbor", "installer", "docker-compose.yml")
	}
	return s, true, nil
}

func validateLegacyData(s ServiceState) error {
	if _, err := os.Stat(s.ComposePath); err != nil {
		return fmt.Errorf("services: legacy Compose root is unavailable: %w", err)
	}
	for _, path := range []string{"ca/ca.pem", "ca/ca-key.pem", "harbor/secrets/admin-password", "harbor/secrets/database-password", "pulp/secrets/admin-password", "pulp/settings/secret-key"} {
		data, err := os.ReadFile(filepath.Join(s.Root, path))
		if err != nil || len(data) == 0 {
			return fmt.Errorf("services: legacy identity/credentials are unavailable at %s; restore them before adoption", filepath.Join(s.Root, path))
		}
		if path == "ca/ca.pem" && s.Client.CAPEM != "" && string(data) != s.Client.CAPEM {
			return fmt.Errorf("services: legacy CA does not match registered client at %s", s.Root)
		}
	}
	return nil
}

func (m *Manager) claimRoot(expected string) (string, error) {
	store, err := statefile.New[rootOwner](m.root, ".pilot-services-owner.json", 1, "services-owner")
	if err != nil {
		return "", err
	}
	var identity string
	err = store.Mutate(func(owners []rootOwner) ([]rootOwner, error) {
		if len(owners) > 1 {
			return nil, errors.New("services: ambiguous root ownership")
		}
		if len(owners) == 1 {
			if owners[0].Discovery != m.dataDir {
				return nil, fmt.Errorf("services: root %s is already owned by discovery %s; use that --services-dir", m.root, owners[0].Discovery)
			}
			identity = owners[0].InstanceID
			if identity == "" {
				return nil, errors.New("services: root ownership has missing identity")
			}
			if expected != "" && identity != expected {
				return nil, errors.New("services: physical root identity differs from discovery")
			}
			return owners, nil
		}
		identity = expected
		if identity == "" {
			var id [16]byte
			if _, err := rand.Read(id[:]); err != nil {
				return nil, err
			}
			identity = hex.EncodeToString(id[:])
		}
		return []rootOwner{{Discovery: m.dataDir, InstanceID: identity}}, nil
	})
	return identity, err
}

func (m *Manager) verifyRootOwner(expected string) error {
	if _, err := os.Stat(filepath.Join(m.root, ".pilot-services-owner.json")); err != nil {
		return fmt.Errorf("services: registered physical root ownership is unavailable; restore discovery/owner state before continuing: %w", err)
	}
	store, err := statefile.New[rootOwner](m.root, ".pilot-services-owner.json", 1, "services-owner")
	if err != nil {
		return err
	}
	owners, err := store.Load()
	if err != nil {
		return err
	}
	if len(owners) != 1 || owners[0].Discovery != m.dataDir || expected == "" || owners[0].InstanceID != expected {
		return errors.New("services: physical root ownership differs from discovery; use the owning --services-dir")
	}
	return nil
}

// operation serializes the whole physical service transaction, rather than just
// the final state write. Root ownership is checked again after taking both locks.
func (m *Manager) operation() (func(), error) {
	var global *os.File
	if m.shared {
		var err error
		global, err = composeLock()
		if err != nil {
			return nil, err
		}
	}
	closeGlobal := func() {
		if global != nil {
			global.Close()
		}
	}
	discovery, err := lockOperation(filepath.Join(m.dataDir, ".services-operation.lock"))
	if err != nil {
		closeGlobal()
		return nil, err
	}
	state, err := m.current()
	if err != nil {
		discovery.Close()
		closeGlobal()
		return nil, err
	}
	if m.shared && state.Root != "" {
		m.root = state.Root
	}
	root, err := lockOperation(rootLockPath(m.root))
	if err != nil {
		discovery.Close()
		closeGlobal()
		return nil, err
	}
	if m.shared && state.Fingerprint != "" {
		if err := m.verifyRootOwner(state.InstanceID); err != nil {
			root.Close()
			discovery.Close()
			closeGlobal()
			return nil, err
		}
	}
	return func() { root.Close(); discovery.Close(); closeGlobal() }, nil
}
