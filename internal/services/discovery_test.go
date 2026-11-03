package services

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func legacyFixture(t *testing.T, dir string) ServiceState {
	t.Helper()
	p := BuiltInDevLite()
	b, err := RenderBundle(p, DataRoot(dir), net.ParseIP("192.168.122.1"))
	if err != nil {
		t.Fatal(err)
	}
	s := ServiceState{Profile: p.Name, Fingerprint: b.Client.Fingerprint, Root: b.Root, ComposePath: b.ComposePath, Client: b.Client, BindIP: "192.168.122.1", Running: true}
	m, err := NewManager(dir, &fakeRunner{})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.store.Mutate(func([]ServiceState) ([]ServiceState, error) { return []ServiceState{s}, nil }); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"apt/cached.deb", "pulp/pgsql/db-sentinel", "harbor/data-sentinel"} {
		if err := os.WriteFile(filepath.Join(b.Root, path), []byte("existing-cache-and-db"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return s
}

func bundleHashes(t *testing.T, root string) map[string][32]byte {
	t.Helper()
	hashes := map[string][32]byte{}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() || strings.Contains(entry.Name(), ".pilot-services-owner") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		hashes[rel] = sha256.Sum256(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return hashes
}

func TestSharedDiscoveryAdoptsInPlaceAndKeepsPhysicalIdentity(t *testing.T) {
	legacy, discovery := t.TempDir(), filepath.Join(t.TempDir(), "services")
	s := legacyFixture(t, legacy)
	before := bundleHashes(t, s.Root)
	vmState := filepath.Join(legacy, "vm-targets.json")
	if err := os.WriteFile(vmState, []byte("vm state must remain untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	m, err := NewSharedManager(DiscoveryOptions{Directory: discovery, LegacyDirectories: []string{legacy}}, &fakeRunner{})
	if err != nil {
		t.Fatal(err)
	}
	got, err := m.current()
	if err != nil {
		t.Fatal(err)
	}
	if got.Root != s.Root || got.InstanceID == "" || got.Generation != 1 || got.Client.CAPEM != s.Client.CAPEM || got.Client.InstanceID != got.InstanceID {
		t.Fatalf("identity not adopted: %+v", got)
	}
	if !reflect.DeepEqual(before, bundleHashes(t, s.Root)) {
		t.Fatal("adoption altered persistent data or credentials")
	}
	if b, _ := os.ReadFile(vmState); string(b) != "vm state must remain untouched" {
		t.Fatal("adoption changed VM state")
	}
	if data, _ := hasServiceData(DataRoot(discovery)); data {
		t.Fatal("adoption duplicated the old cache")
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(discovery, alias); err != nil {
		t.Fatal(err)
	}
	m2, err := NewSharedManager(DiscoveryOptions{Directory: alias, LegacyDirectories: []string{legacy}}, &fakeRunner{})
	if err != nil {
		t.Fatal(err)
	}
	got2, _ := m2.current()
	if got2.InstanceID != got.InstanceID || m2.root != m.root {
		t.Fatal("symlink discovery selected another physical identity")
	}
	_, err = NewSharedManager(DiscoveryOptions{Directory: t.TempDir(), AdoptFrom: legacy}, &fakeRunner{})
	if err == nil || !strings.Contains(err.Error(), "already owned by discovery") {
		t.Fatalf("second discovery should reject physical root owner: %v", err)
	}
}

func TestSharedDiscoveryRejectsIncompleteLegacyStateBeforeRender(t *testing.T) {
	for _, kind := range []string{"missing", "corrupt", "empty", "missing-credentials", "ca-mismatch"} {
		t.Run(kind, func(t *testing.T) {
			legacy := t.TempDir()
			s := legacyFixture(t, legacy)
			switch kind {
			case "missing":
				if err := os.Remove(filepath.Join(legacy, "services.json")); err != nil {
					t.Fatal(err)
				}
			case "corrupt":
				if err := os.WriteFile(filepath.Join(legacy, "services.json"), []byte("not json"), 0600); err != nil {
					t.Fatal(err)
				}
			case "empty":
				m, _ := NewManager(legacy, &fakeRunner{})
				if err := m.store.Mutate(func([]ServiceState) ([]ServiceState, error) { return nil, nil }); err != nil {
					t.Fatal(err)
				}
			case "missing-credentials":
				if err := os.Remove(filepath.Join(s.Root, "harbor/secrets/database-password")); err != nil {
					t.Fatal(err)
				}
			case "ca-mismatch":
				if err := os.WriteFile(filepath.Join(s.Root, "ca/ca.pem"), []byte("wrong CA"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before := bundleHashes(t, s.Root)
			runner := &fakeRunner{}
			_, err := NewSharedManager(DiscoveryOptions{Directory: t.TempDir(), LegacyDirectories: []string{legacy}}, runner)
			if err == nil || (!strings.Contains(err.Error(), "state") && !strings.Contains(err.Error(), "credentials") && !strings.Contains(err.Error(), "CA")) {
				t.Fatalf("want specific adoption rejection, got %v", err)
			}
			if len(runner.calls) != 0 || !reflect.DeepEqual(before, bundleHashes(t, s.Root)) {
				t.Fatal("rejected migration mutated the bundle")
			}
		})
	}
}

func TestSharedDiscoveryConflictsBeforeRender(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	sa := legacyFixture(t, a)
	legacyFixture(t, b)
	_, err := NewSharedManager(DiscoveryOptions{Directory: t.TempDir(), LegacyDirectories: []string{a, b}}, &fakeRunner{})
	if err == nil || !strings.Contains(err.Error(), "conflicting legacy service roots") {
		t.Fatalf("want root conflict: %v", err)
	}
	runner := &fakeRunner{}
	m, err := NewSharedManager(DiscoveryOptions{Directory: t.TempDir(), AdoptFrom: a}, runner)
	if err != nil {
		t.Fatal(err)
	}
	before := bundleHashes(t, sa.Root)
	p := BuiltInDevLite()
	p.Apt.Port++
	err = m.Up(context.Background(), p, net.ParseIP(sa.BindIP))
	if err == nil || !strings.Contains(err.Error(), "fingerprint mismatch") {
		t.Fatalf("want profile conflict: %v", err)
	}
	err = m.Up(context.Background(), BuiltInDevLite(), net.ParseIP("192.168.123.1"))
	if err == nil || !strings.Contains(err.Error(), "bind endpoint conflict") {
		t.Fatalf("want endpoint conflict: %v", err)
	}
	if len(runner.calls) != 0 || !reflect.DeepEqual(before, bundleHashes(t, sa.Root)) {
		t.Fatal("conflict reached render/Compose")
	}
}

type ownershipRunner struct {
	root  string
	fail  bool
	calls []string
}

func (r *ownershipRunner) Run(_ context.Context, _ string, _ string, args ...string) (CommandResult, error) {
	r.calls = append(r.calls, strings.Join(args, " "))
	if len(args) > 0 && args[0] == "ps" {
		if r.fail {
			return CommandResult{ExitCode: 1}, nil
		}
		return CommandResult{Stdout: "220d24c73122\n"}, nil
	}
	if len(args) > 0 && args[0] == "inspect" {
		// Docker Compose 5.6.0 labels captured from a real container on
		// 2026-11-03; only project identity/path values are substituted.
		b, _ := json.Marshal(map[string]string{"com.docker.compose.project": "pilot-services-dev-lite", "com.docker.compose.project.working_dir": r.root, "com.docker.compose.project.config_files": filepath.Join(r.root, "docker-compose.yml")})
		return CommandResult{Stdout: string(b)}, nil
	}
	return CommandResult{}, fmt.Errorf("unexpected mutating command: %v", args)
}

func TestSharedDiscoveryDockerRootConflictAndProbeErrorDoNotRender(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprint(fail), func(t *testing.T) {
			dir := t.TempDir()
			runner := &ownershipRunner{root: filepath.Join(t.TempDir(), "foreign"), fail: fail}
			m, err := NewSharedManager(DiscoveryOptions{Directory: dir}, runner)
			if err != nil {
				t.Fatal(err)
			}
			err = m.Up(context.Background(), BuiltInDevLite(), net.ParseIP("192.168.122.1"))
			want := "root conflict"
			if fail {
				want = "Docker query failed"
			}
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("want %s, got %v", want, err)
			}
			if _, err := os.Stat(m.root); !os.IsNotExist(err) {
				t.Fatalf("conflict rendered fresh bundle: %v", err)
			}
			state, _ := m.current()
			if state.InstanceID != "" {
				t.Fatal("rejected startup reserved an instance")
			}
		})
	}
}

func TestSharedDiscoveryHelperProcess(t *testing.T) {
	mode := os.Getenv("PILOT_DISCOVERY_HELPER")
	if mode == "" {
		return
	}
	dir, legacy := os.Getenv("PILOT_TEST_DISCOVERY"), os.Getenv("PILOT_TEST_LEGACY")
	if mode == "before-registration" {
		m, err := NewManager(dir, &fakeRunner{})
		if err != nil {
			t.Fatal(err)
		}
		m.root = DataRoot(legacy)
		id, err := m.claimRoot("")
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println(id)
		os.Exit(0)
	}
	m, err := NewSharedManager(DiscoveryOptions{Directory: dir, AdoptFrom: legacy}, &fakeRunner{})
	if err != nil {
		t.Fatal(err)
	}
	if mode == "hold" {
		unlock, err := m.operation()
		if err != nil {
			t.Fatal(err)
		}
		defer unlock()
		fmt.Println("locked")
		select {}
	}
	s, err := m.current()
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(s.InstanceID)
	os.Exit(0)
}

func discoveryProcess(ctx context.Context, dir, legacy, mode string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSharedDiscoveryHelperProcess$")
	cmd.Env = append(os.Environ(), "PILOT_DISCOVERY_HELPER="+mode, "PILOT_TEST_DISCOVERY="+dir, "PILOT_TEST_LEGACY="+legacy)
	return cmd
}

func TestSharedDiscoveryInterruptedAndConcurrentAdoption(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	legacy, dir := t.TempDir(), t.TempDir()
	s := legacyFixture(t, legacy)
	before := bundleHashes(t, s.Root)
	first, err := discoveryProcess(ctx, dir, legacy, "before-registration").CombinedOutput()
	if err != nil {
		t.Fatalf("interrupted registration setup: %s %v", first, err)
	}
	identity := strings.TrimSpace(string(first))
	if identity == "" {
		t.Fatal("missing reserved identity")
	}
	commands := []*exec.Cmd{discoveryProcess(ctx, dir, legacy, "adopt"), discoveryProcess(ctx, dir, legacy, "adopt")}
	outputs := make([]strings.Builder, 2)
	for i, cmd := range commands {
		cmd.Stdout = &outputs[i]
		cmd.Stderr = &outputs[i]
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
	}
	for i, cmd := range commands {
		if err := cmd.Wait(); err != nil {
			t.Fatalf("concurrent adoption %d: %s %v", i, outputs[i].String(), err)
		}
		if strings.TrimSpace(outputs[i].String()) != identity {
			t.Fatalf("adoption changed identity: %q != %q", outputs[i].String(), identity)
		}
	}
	if !reflect.DeepEqual(before, bundleHashes(t, s.Root)) {
		t.Fatal("interrupted/concurrent adoption changed data")
	}
	// Kill a process while it owns the complete transaction; kernel flock
	// release must permit the next process to discover the same identity.
	held := discoveryProcess(ctx, dir, legacy, "hold")
	stdout, err := held.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := held.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() || scanner.Text() != "locked" {
		_ = held.Process.Kill()
		t.Fatal("helper did not acquire transaction")
	}
	probe, err := os.OpenFile(rootLockPath(s.Root), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(probe.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != syscall.EWOULDBLOCK {
		probe.Close()
		_ = held.Process.Kill()
		t.Fatalf("physical root was not locked across transaction: %v", err)
	}
	probe.Close()
	if err := held.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = held.Wait()
	retry, err := discoveryProcess(ctx, dir, legacy, "adopt").CombinedOutput()
	if err != nil || strings.TrimSpace(string(retry)) != identity {
		t.Fatalf("retry after killed owner: %s %v", retry, err)
	}
}

type sharedLifecycleRunner struct{ calls []string }

func (r *sharedLifecycleRunner) Run(_ context.Context, dir, name string, args ...string) (CommandResult, error) {
	r.calls = append(r.calls, strings.Join(append([]string{name}, args...), " "))
	if len(args) > 0 && args[0] == "ps" {
		return CommandResult{}, nil
	}
	if name == "sudo" && len(args) > 1 && args[1] == "./prepare" {
		if err := os.WriteFile(filepath.Join(dir, "docker-compose.yml"), []byte("services:\n  proxy:\n    container_name: nginx\n    ports:\n      - 8081:8080\n"), 0600); err != nil {
			return CommandResult{}, err
		}
	}
	return CommandResult{}, nil
}

func TestSharedDiscoveryLifecycleAndInterruptedUpRetainIdentity(t *testing.T) {
	dir := t.TempDir()
	runner := &sharedLifecycleRunner{}
	m, err := NewSharedManager(DiscoveryOptions{Directory: dir}, runner)
	if err != nil {
		t.Fatal(err)
	}
	// Runner emulates prepare's generated file only; native Docker/cache
	// behavior is separate target evidence.
	archive := harborTestArchive(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(archive) }))
	defer server.Close()
	m.client = server.Client()
	// Failure after render/Compose but before successful seeding must retain
	// the reserved instance and the original secret/CA bytes for retry.
	profile := BuiltInDevLite()
	profile.Harbor.InstallerURL = server.URL + "/harbor.tgz"
	m.seed = func(context.Context, Profile, string, net.IP, *http.Client) (ClientConfig, error) {
		return ClientConfig{}, fmt.Errorf("injected seed failure")
	}
	if err := m.Up(context.Background(), profile, net.ParseIP("192.168.122.1")); err == nil || !strings.Contains(err.Error(), "injected seed failure") {
		t.Fatalf("failure injection missed seed: %v", err)
	}
	failed, _ := m.current()
	if failed.InstanceID == "" || failed.Running {
		t.Fatal("failed startup lost identity or claims running")
	}
	before := bundleHashes(t, m.root)
	m.seed = func(_ context.Context, p Profile, root string, ip net.IP, _ *http.Client) (ClientConfig, error) {
		b, err := RenderBundle(p, root, ip)
		return b.Client, err
	}
	for i := 0; i < 2; i++ {
		if err := m.Up(context.Background(), profile, net.ParseIP("192.168.122.1")); err != nil {
			t.Fatal(err)
		}
	}
	state, _ := m.current()
	if !state.Running || state.InstanceID != failed.InstanceID || state.Generation != failed.Generation {
		t.Fatalf("retry changed identity: %+v", state)
	}
	if !reflect.DeepEqual(before, bundleHashes(t, m.root)) {
		t.Fatal("retry altered cache/credentials/CA")
	}
	if err := m.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	stopped, _ := m.current()
	if stopped.Running || stopped.InstanceID != state.InstanceID || !reflect.DeepEqual(before, bundleHashes(t, m.root)) {
		t.Fatal("down changed data or identity")
	}
	if err := m.Purge(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m.root); !os.IsNotExist(err) {
		t.Fatal("purge retained cache root")
	}
	reopened, err := NewSharedManager(DiscoveryOptions{Directory: dir}, runner)
	if err != nil {
		t.Fatal(err)
	}
	status, err := reopened.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Configured || status.InstanceID != state.InstanceID || status.Generation != state.Generation+1 {
		t.Fatalf("purge/retry registration = %+v", status)
	}
}

func TestSharedDiscoveryCanonicalMissingLeaf(t *testing.T) {
	dir := t.TempDir()
	actual := filepath.Join(dir, "actual")
	if err := os.Mkdir(actual, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(dir, "alias")
	if err := os.Symlink(actual, alias); err != nil {
		t.Fatal(err)
	}
	got, err := CanonicalDirectory(filepath.Join(alias, "uncreated/leaf"))
	if err != nil {
		t.Fatal(err)
	}
	if got != filepath.Join(actual, "uncreated/leaf") {
		t.Fatalf("missing leaf lost canonical ancestor: %s", got)
	}
}

func TestSharedDiscoveryAdoptedSourceIsHistoricalButRootRemainsAuthoritative(t *testing.T) {
	legacy, dir := t.TempDir(), t.TempDir()
	s := legacyFixture(t, legacy)
	opts := DiscoveryOptions{Directory: dir, AdoptFrom: legacy}
	m, err := NewSharedManager(opts, &fakeRunner{})
	if err != nil {
		t.Fatal(err)
	}
	registered, _ := m.current()
	// Reproduce the pre-seeding fingerprint transition accepted by Up. The
	// old source snapshot cannot veto the authoritative registered revision.
	p := BuiltInDevLite()
	for i := range p.OCI.Registries {
		p.OCI.Registries[i].Type = ""
	}
	oldFingerprint, _ := p.Fingerprint()
	source, err := NewManager(legacy, &fakeRunner{})
	if err != nil {
		t.Fatal(err)
	}
	if err := source.store.Mutate(func(states []ServiceState) ([]ServiceState, error) {
		states[0].Fingerprint = oldFingerprint
		states[0].Client.Fingerprint = oldFingerprint
		return states, nil
	}); err != nil {
		t.Fatal(err)
	}
	m, err = NewSharedManager(opts, &fakeRunner{})
	if err != nil {
		t.Fatalf("stale source vetoed migration: %v", err)
	}
	got, _ := m.current()
	if got.Fingerprint != registered.Fingerprint || got.InstanceID != registered.InstanceID {
		t.Fatal("historical source replaced discovery identity")
	}
	if err := os.Remove(filepath.Join(legacy, "services.json")); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewSharedManager(opts, &fakeRunner{})
	if err != nil {
		t.Fatalf("deleted historical source vetoed discovery: %v", err)
	}
	afterDeletion, _ := reopened.current()
	if afterDeletion.InstanceID != registered.InstanceID || afterDeletion.Root != registered.Root {
		t.Fatal("deleted source changed registered physical instance")
	}
	if err := os.WriteFile(filepath.Join(s.Root, "ca/ca.pem"), []byte("changed physical CA"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSharedManager(opts, &fakeRunner{}); err == nil || !strings.Contains(err.Error(), "CA does not match") {
		t.Fatalf("ignoring source hid physical CA drift: %v", err)
	}
	if err := os.WriteFile(filepath.Join(s.Root, "ca/ca.pem"), []byte(s.Client.CAPEM), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(s.Root, ".pilot-services-owner.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := NewSharedManager(opts, &fakeRunner{}); err == nil || !strings.Contains(err.Error(), "ownership is unavailable") {
		t.Fatalf("ignoring source hid root ownership drift: %v", err)
	}
}

func TestSharedDiscoveryPurgeDoesNotReadoptHistoricalLegacyState(t *testing.T) {
	legacy, dir := t.TempDir(), t.TempDir()
	s := legacyFixture(t, legacy)
	opts := DiscoveryOptions{Directory: dir, AdoptFrom: legacy}
	runner := &sharedLifecycleRunner{}
	m, err := NewSharedManager(opts, runner)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := m.current()
	if err := m.Purge(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewSharedManager(opts, runner)
	if err != nil {
		t.Fatalf("purge retried stale legacy registration: %v", err)
	}
	status, err := reopened.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Configured || status.Root != s.Root || status.InstanceID != before.InstanceID || status.Generation != before.Generation+1 {
		t.Fatalf("purge lost migration authority: %+v", status)
	}
}
