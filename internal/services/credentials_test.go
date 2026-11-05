package services

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
)

func TestEstablishedCredentialLossNeverRegenerates(t *testing.T) {
	for _, rel := range credentialPaths {
		for _, fault := range []string{"missing", "empty", "whitespace", "unreadable", "public", "symlink", "hardlink", "fifo"} {
			t.Run(rel+"/"+fault, func(t *testing.T) {
				root := t.TempDir()
				if _, err := RenderBundle(BuiltInDevLite(), root, net.ParseIP("127.0.0.1")); err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(root, rel)
				switch fault {
				case "missing":
					_ = os.Remove(target)
				case "empty":
					_ = os.WriteFile(target, nil, 0600)
				case "whitespace":
					_ = os.WriteFile(target, []byte(" \n\t\n"), 0600)
				case "unreadable":
					_ = os.Chmod(target, 0000)
				case "public":
					_ = os.Chmod(target, 0644)
				case "symlink":
					_ = os.Rename(target, target+".original")
					_ = os.Symlink(target+".original", target)
				case "hardlink":
					_ = os.Link(target, target+".alias")
				case "fifo":
					_ = os.Remove(target)
					if err := syscall.Mkfifo(target, 0600); err != nil {
						t.Fatal(err)
					}
				}
				ca, _ := os.ReadFile(filepath.Join(root, "ca/ca.pem"))
				config, _ := os.ReadFile(filepath.Join(root, "harbor/harbor.yml"))
				before, err := os.Lstat(target)
				_, renderErr := RenderBundle(BuiltInDevLite(), root, net.ParseIP("127.0.0.1"))
				if renderErr == nil || !strings.Contains(renderErr.Error(), "credential") {
					t.Fatalf("unsafe credential accepted: %v", renderErr)
				}
				after, afterErr := os.Lstat(target)
				if (err == nil) != (afterErr == nil) || (err == nil && (!os.SameFile(before, after) || before.Mode() != after.Mode())) {
					t.Fatal("refused render replaced or changed broken secret")
				}
				caAfter, _ := os.ReadFile(filepath.Join(root, "ca/ca.pem"))
				configAfter, _ := os.ReadFile(filepath.Join(root, "harbor/harbor.yml"))
				if string(ca) != string(caAfter) || string(config) != string(configAfter) {
					t.Fatal("refused render mutated identity/config")
				}
			})
		}
	}
}

func TestInterruptedCredentialInitializationNeverGeneratesAgain(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".pilot-credentials-initialized"), []byte("credential-set/v1\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := RenderBundle(BuiltInDevLite(), root, net.ParseIP("127.0.0.1")); err == nil {
		t.Fatal("interrupted initialization generated new credentials")
	}
	if _, err := os.Stat(filepath.Join(root, credentialPaths[0])); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("credential written after interrupted initialization")
	}
}

type credentialRunner struct {
	password    string
	trust       bool
	unavailable bool
	authFailure string
	inputs      []string
	mutations   int
}

func (r *credentialRunner) Run(context.Context, string, string, ...string) (CommandResult, error) {
	r.mutations++
	return CommandResult{Stderr: "SENTINEL-COMPOSE-SECRET", ExitCode: 1}, nil
}

func (r *credentialRunner) RunInput(_ context.Context, _ string, input, name string, args ...string) (CommandResult, error) {
	r.inputs = append(r.inputs, input)
	if name != "docker" || strings.Contains(strings.Join(args, " "), r.password) {
		return CommandResult{}, errors.New("secret leaked in argv")
	}
	if r.unavailable {
		return CommandResult{}, errors.New("SENTINEL-NATIVE-RUNNER-ERROR")
	}
	script := args[len(args)-1]
	// Native Harbor 2.15.1 calibration: loopback trusts every password, while
	// its container hostname selects the host-password rule. See testdata provenance.
	if strings.Contains(script, "-h 127.0.0.1 ") {
		return CommandResult{Stdout: "1\n"}, nil
	}
	if !strings.Contains(script, `-h "$(hostname)" `) {
		return CommandResult{}, errors.New("unrecognized database authentication boundary")
	}
	if r.trust || input == r.password+"\n" {
		return CommandResult{Stdout: "1\n"}, nil
	}
	return CommandResult{ExitCode: 2, Stderr: r.authFailure + "SENTINEL-POSTGRES-SECRET"}, nil
}

func credentialFixture(t *testing.T) (*Manager, Profile, *credentialRunner, string) {
	t.Helper()
	m, p, _ := healthyLifecycleFixture(t)
	admin, _ := readHarborAdminPassword(m.root)
	database, _ := readSecret(filepath.Join(m.root, credentialPaths[1]))
	authFailure, err := os.ReadFile("testdata/harbor-db-password-auth.stderr")
	if err != nil {
		t.Fatal(err)
	}
	runner := &credentialRunner{password: database, authFailure: string(authFailure)}
	m.runner = runner
	m.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/api/v2.0/users/current" {
			user, password, ok := req.BasicAuth()
			if !ok || user != "admin" || password != admin {
				return jsonResponse(401, map[string]string{"error": "SENTINEL-API-SECRET"}), nil
			}
			return jsonResponse(200, map[string]any{"username": "admin", "sysadmin_flag": true}), nil
		}
		return jsonResponse(200, map[string]string{}), nil
	})}
	return m, p, runner, admin
}

func TestEstablishedWrongCredentialsFailBeforeAnyMutation(t *testing.T) {
	for _, kind := range []CredentialKind{HarborAdmin, HarborDatabase} {
		t.Run(string(kind), func(t *testing.T) {
			m, p, runner, _ := credentialFixture(t)
			rel, _ := kind.relativePath()
			if err := os.WriteFile(filepath.Join(m.root, rel), []byte("SENTINEL-WRONG-CREDENTIAL\n"), 0600); err != nil {
				t.Fatal(err)
			}
			before := bundleHashes(t, m.root)
			stateBefore, _ := os.ReadFile(m.store.Path())
			for _, op := range []func() error{
				func() error { return m.Up(context.Background(), p, net.ParseIP("127.0.0.1")) },
				func() error { return m.Repair(context.Background(), p, net.ParseIP("127.0.0.1"), MaintenanceOptions{}) },
			} {
				err := op()
				if err == nil || !strings.Contains(err.Error(), "authentication failed") || strings.Contains(err.Error(), "SENTINEL") {
					t.Fatalf("wrong diagnostic: %v", err)
				}
			}
			stateAfter, _ := os.ReadFile(m.store.Path())
			if runner.mutations != 0 || string(stateBefore) != string(stateAfter) || !reflect.DeepEqual(before, bundleHashes(t, m.root)) {
				t.Fatal("failed credential gate mutated existing service")
			}
		})
	}
}

func TestHarborAdminDiagnosticCategoriesAndPrivilege(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		body any
		want string
	}{
		{"unauthenticated", 401, nil, "authentication failed"},
		{"forbidden", 403, nil, "authorization failed"},
		{"initializing", 503, nil, "initializing or server unavailable"},
		{"non-admin", 200, map[string]any{"username": "viewer", "sysadmin_flag": true}, "authorization failed"},
		{"unprivileged", 200, map[string]any{"username": "admin", "sysadmin_flag": false}, "authorization failed"},
		{"redirect", 302, nil, "unexpected HTTP"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _, _, admin := credentialFixture(t)
			m.client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
				r := jsonResponse(tc.code, tc.body)
				r.Header.Set("Location", "http://evil.invalid/SENTINEL")
				return r, nil
			})
			state, _ := m.current()
			err := m.harborAdminProbe(context.Background(), state, admin)
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), "SENTINEL") {
				t.Fatalf("wrong category: %v", err)
			}
		})
	}
}

func TestHarborDatabaseProbeRejectsTrustAndUsesStdin(t *testing.T) {
	m, _, runner, _ := credentialFixture(t)
	state, _ := m.current()
	if err := m.harborDatabaseProbe(context.Background(), state, runner.password); err != nil {
		t.Fatal(err)
	}
	if len(runner.inputs) != 2 || runner.inputs[0] == runner.inputs[1] {
		t.Fatal("database probe omitted independent negative control")
	}
	runner.trust = true
	if err := m.harborDatabaseProbe(context.Background(), state, runner.password); err == nil || !strings.Contains(err.Error(), "negative control") {
		t.Fatalf("trust accepted as password proof: %v", err)
	}
}

func TestHarborDatabaseProbeUsesNativePasswordAuthenticationBoundary(t *testing.T) {
	m, _, runner, _ := credentialFixture(t)
	state, _ := m.current()
	// Lock the observed counterexample into the oracle, rather than assuming
	// that any TCP destination causes PostgreSQL to inspect a password.
	for _, password := range []string{"incorrect-native-control", runner.password} {
		result, err := runner.RunInput(context.Background(), m.root, password+"\n", "docker", "exec", "-i", "fixture-db", "sh", "-c", "psql -h 127.0.0.1 -d registry")
		if err != nil || result.ExitCode != 0 || result.Stdout != "1\n" {
			t.Fatal("fixture lost native loopback-trust semantics")
		}
	}
	if err := m.harborDatabaseProbe(context.Background(), state, runner.password); err != nil {
		t.Fatalf("native container-hostname authentication boundary must validate the correct password: %v", err)
	}
	err := m.harborDatabaseProbe(context.Background(), state, "incorrect-native-password")
	if err == nil || !strings.Contains(err.Error(), "database authentication failed") || strings.Contains(err.Error(), "SENTINEL") || strings.Contains(err.Error(), "psql:") {
		t.Fatalf("native password rejection was not safely classified: %v", err)
	}
	runner.unavailable = true
	err = m.harborDatabaseProbe(context.Background(), state, runner.password)
	if err == nil || !strings.Contains(err.Error(), "unreachable") || strings.Contains(err.Error(), "SENTINEL") {
		t.Fatalf("unavailable database was not safely classified: %v", err)
	}
}

func TestCredentialRecoveryValidatesThenPublishesWithoutServiceMutation(t *testing.T) {
	for _, kind := range []CredentialKind{HarborAdmin, HarborDatabase} {
		t.Run(string(kind), func(t *testing.T) {
			m, _, runner, admin := credentialFixture(t)
			rel, _ := kind.relativePath()
			target := filepath.Join(m.root, rel)
			valid := admin
			if kind == HarborDatabase {
				valid = runner.password
			}
			_ = os.Remove(target)
			if _, err := NewSharedManager(DiscoveryOptions{Directory: m.dataDir}, runner); err == nil {
				t.Fatal("ordinary constructor ignored missing credential")
			}
			recovery, err := NewSharedManagerRecoveryContext(context.Background(), DiscoveryOptions{Directory: m.dataDir}, kind, runner)
			if err != nil {
				t.Fatal(err)
			}
			recovery.client = m.client
			before := bundleHashes(t, m.root)
			stateBefore, _ := os.ReadFile(m.store.Path())
			source := filepath.Join(t.TempDir(), "SENTINEL-source")
			_ = os.WriteFile(source, []byte("SENTINEL-invalid\n"), 0600)
			if err := recovery.ImportCredential(context.Background(), kind, source); err == nil || strings.Contains(err.Error(), "SENTINEL") {
				t.Fatalf("invalid import: %v", err)
			}
			if !reflect.DeepEqual(before, bundleHashes(t, m.root)) {
				t.Fatal("failed import changed bundle")
			}
			_ = os.WriteFile(source, []byte(valid+"\n"), 0600)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := recovery.ImportCredential(ctx, kind, source); err == nil {
				t.Fatal("canceled import succeeded")
			}
			if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("canceled import published credential")
			}
			for range 2 {
				if err := recovery.ImportCredential(context.Background(), kind, source); err != nil {
					t.Fatal(err)
				}
			}
			after := bundleHashes(t, m.root)
			delete(after, rel)
			delete(after, ".pilot-credential-import.json")
			delete(after, ".pilot-credential-import.json.lock")
			delete(after, ".pilot-credential-binding.json")
			delete(after, ".pilot-credential-binding.json.lock")
			if !reflect.DeepEqual(before, after) {
				t.Fatal("import changed cache, CA or unrelated bundle files")
			}
			stateAfter, _ := os.ReadFile(m.store.Path())
			if runner.mutations != 0 || string(stateBefore) != string(stateAfter) {
				t.Fatal("import mutated service/discovery state")
			}
			got, err := readSecret(target)
			if err != nil || got != valid {
				t.Fatal("validated association was not published")
			}
			audit, _ := os.ReadFile(filepath.Join(m.root, ".pilot-credential-import.json"))
			if strings.Contains(string(audit), valid) || strings.Contains(string(audit), source) || !strings.Contains(string(audit), "published") {
				t.Fatal("audit missing or contains secret material")
			}
		})
	}
}

func TestRecoveryRetainsEveryUnrelatedPrerequisite(t *testing.T) {
	for _, rel := range []string{"ca/ca.pem", "ca/ca-key.pem", "pulp/secrets/admin-password", "pulp/settings/secret-key"} {
		t.Run(rel, func(t *testing.T) {
			m, _, r, _ := credentialFixture(t)
			_ = os.Remove(filepath.Join(m.root, rel))
			if _, err := NewSharedManagerRecoveryContext(context.Background(), DiscoveryOptions{Directory: m.dataDir}, HarborAdmin, r); err == nil {
				t.Fatal("recovery bypassed unrelated prerequisite")
			}
		})
	}
}

func TestFailedInitialSeedMissingSecretCannotRegenerateThroughRepair(t *testing.T) {
	m, p, r, _ := credentialFixture(t)
	if err := m.store.Mutate(func(states []ServiceState) ([]ServiceState, error) {
		states[0].Running = false
		states[0].ComposePath = ""
		return states, nil
	}); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(m.root, credentialPaths[0]))
	err := m.Repair(context.Background(), p, net.ParseIP("127.0.0.1"), MaintenanceOptions{})
	if err == nil || !strings.Contains(err.Error(), "credential unavailable") || r.mutations != 0 {
		t.Fatalf("failed initial seed repair regenerated credentials: %v", err)
	}
	if _, err := os.Stat(filepath.Join(m.root, credentialPaths[0])); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing credential was regenerated")
	}
}

func TestEntireHarborSecretDirectoryCanBeRecoveredSequentially(t *testing.T) {
	m, _, runner, admin := credentialFixture(t)
	if err := os.RemoveAll(filepath.Join(m.root, "harbor/secrets")); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		kind     CredentialKind
		password string
	}{{HarborAdmin, admin}, {HarborDatabase, runner.password}} {
		recovery, err := NewSharedManagerRecoveryContext(context.Background(), DiscoveryOptions{Directory: m.dataDir}, tc.kind, runner)
		if err != nil {
			t.Fatal(err)
		}
		recovery.client = m.client
		source := filepath.Join(t.TempDir(), "authorized")
		if err := os.WriteFile(source, []byte(tc.password+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := recovery.ImportCredential(context.Background(), tc.kind, source); err != nil {
			t.Fatal(err)
		}
		if tc.kind == HarborAdmin {
			if _, err := NewSharedManager(DiscoveryOptions{Directory: m.dataDir}, runner); err == nil {
				t.Fatal("incomplete recovery enabled ordinary operations")
			}
		}
	}
	if _, err := NewSharedManager(DiscoveryOptions{Directory: m.dataDir}, runner); err != nil {
		t.Fatal(err)
	}
	if runner.mutations != 0 {
		t.Fatal("sequential recovery mutated services")
	}
}

func TestCredentialImportAuditFailurePreservesOldAssociationAndRetry(t *testing.T) {
	m, _, runner, admin := credentialFixture(t)
	target := filepath.Join(m.root, "harbor/secrets/admin-password")
	old, _ := os.ReadFile(target)
	source := filepath.Join(t.TempDir(), "authorized")
	if err := os.WriteFile(source, []byte(admin+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(m.root, ".pilot-credential-import.json")
	if err := os.Mkdir(auditPath, 0700); err != nil {
		t.Fatal(err)
	}
	if err := m.ImportCredential(context.Background(), HarborAdmin, source); err == nil || !strings.Contains(err.Error(), "audit") {
		t.Fatalf("audit fault did not refuse publication: %v", err)
	}
	after, _ := os.ReadFile(target)
	if string(old) != string(after) || runner.mutations != 0 {
		t.Fatal("audit failure replaced association or changed services")
	}
	if err := os.Remove(auditPath); err != nil {
		t.Fatal(err)
	}
	if err := m.ImportCredential(context.Background(), HarborAdmin, source); err != nil {
		t.Fatal(err)
	}
}

func TestCredentialImportCancellationAfterValidationPreservesOldAssociation(t *testing.T) {
	m, _, _, admin := credentialFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	originalTransport := m.client.Transport
	m.client.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		resp, err := originalTransport.RoundTrip(req)
		cancel()
		return resp, err
	})
	source := filepath.Join(t.TempDir(), "authorized")
	if err := os.WriteFile(source, []byte(admin+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	before := bundleHashes(t, m.root)
	if err := m.ImportCredential(ctx, HarborAdmin, source); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation after validation ignored: %v", err)
	}
	if !reflect.DeepEqual(before, bundleHashes(t, m.root)) {
		t.Fatal("canceled validation published or audited a credential")
	}
}

func TestLegacyFailedSeedRecoveryReadsOnlyOriginalEndpoint(t *testing.T) {
	m, _, runner, admin := credentialFixture(t)
	// The shared fixture changes its discovery bind address to loopback; make
	// its original installer endpoint agree before emulating legacy state.
	if _, err := RenderBundle(BuiltInDevLite(), m.root, net.ParseIP("127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	if err := m.store.Mutate(func(states []ServiceState) ([]ServiceState, error) {
		states[0].Client = ClientConfig{}
		states[0].ComposePath = ""
		states[0].Running = false
		return states, nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(m.root, "harbor/secrets/admin-password")); err != nil {
		t.Fatal(err)
	}
	recovery, err := NewSharedManagerRecoveryContext(context.Background(), DiscoveryOptions{Directory: m.dataDir}, HarborAdmin, runner)
	if err != nil {
		t.Fatal(err)
	}
	recovery.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "127.0.0.1:8081" || req.URL.Path != "/api/v2.0/users/current" {
			t.Errorf("recovery guessed another endpoint: %s", req.URL)
		}
		return jsonResponse(200, map[string]any{"username": "admin", "sysadmin_flag": true}), nil
	})}
	source := filepath.Join(t.TempDir(), "authorized")
	if err := os.WriteFile(source, []byte(admin+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	stateBefore, _ := os.ReadFile(m.store.Path())
	if err := recovery.ImportCredential(context.Background(), HarborAdmin, source); err != nil {
		t.Fatal(err)
	}
	stateAfter, _ := os.ReadFile(m.store.Path())
	if string(stateBefore) != string(stateAfter) || runner.mutations != 0 {
		t.Fatal("legacy recovery changed discovery or services")
	}
}

func TestStoppedRepairActivatesOnlyBoundRetainedConfiguration(t *testing.T) {
	for _, imported := range []bool{false, true} {
		t.Run(fmt.Sprint("imported=", imported), func(t *testing.T) {
			m, p, _, _ := credentialFixture(t)
			runner := &sharedLifecycleRunner{}
			m.runner = runner
			if _, err := RenderBundle(p, m.root, net.ParseIP("127.0.0.1")); err != nil {
				t.Fatal(err)
			}
			installer := filepath.Join(m.root, "harbor/installer")
			if err := os.MkdirAll(installer, 0700); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"install.sh", "docker-compose.yml"} {
				if err := os.WriteFile(filepath.Join(installer, name), []byte("fixture"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if imported {
				// The externally changed admin is valid but differs from the original
				// render. Import binds it privately without changing that render.
				admin := "SENTINEL-new-existing-admin"
				m.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
					return jsonResponse(200, map[string]any{"username": "admin", "sysadmin_flag": true}), nil
				})}
				source := filepath.Join(t.TempDir(), "authorized")
				if err := os.WriteFile(source, []byte(admin+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := m.ImportCredential(context.Background(), HarborAdmin, source); err != nil {
					t.Fatal(err)
				}
			}
			if err := m.Down(context.Background()); err != nil {
				t.Fatal(err)
			}
			runner.calls = nil
			m.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
				if !slices.ContainsFunc(runner.calls, func(s string) bool { return strings.Contains(s, "pilot-harbor-dev-lite up -d --wait") }) {
					return nil, errors.New("stopped")
				}
				return jsonResponse(200, map[string]any{"username": "admin", "sysadmin_flag": true}), nil
			})}
			m.seed = func(context.Context, Profile, string, net.IP, *http.Client) (ClientConfig, error) {
				state, _ := m.current()
				return state.Client, nil
			}
			if err := m.Repair(context.Background(), p, net.ParseIP("127.0.0.1"), MaintenanceOptions{}); err != nil {
				t.Fatal(err)
			}
			firstUp := -1
			for i, call := range runner.calls {
				if strings.Contains(call, " up -d --wait") {
					firstUp = i
					break
				}
			}
			if firstUp < 0 || strings.Contains(runner.calls[firstUp], "force-recreate") {
				t.Fatalf("offline activation recreated services: %v", runner.calls)
			}
			state, _ := m.current()
			if !state.Running {
				t.Fatal("authenticated stopped repair did not publish running")
			}
			if err := m.Down(context.Background()); err != nil {
				t.Fatal(err)
			}
			runner.calls = nil
			if err := os.WriteFile(filepath.Join(m.root, "harbor/secrets/admin-password"), []byte("wrong-after-stop\n"), 0600); err != nil {
				t.Fatal(err)
			}
			err := m.Repair(context.Background(), p, net.ParseIP("127.0.0.1"), MaintenanceOptions{})
			if err == nil || !strings.Contains(err.Error(), "stopped credential association differs") || len(runner.calls) != 0 {
				t.Fatalf("wrong stopped credential activated services: %v %v", err, runner.calls)
			}
		})
	}
}

func TestStoppedActivationMustAuthenticateBeforeReconciliation(t *testing.T) {
	m, p, _, _ := credentialFixture(t)
	runner := &sharedLifecycleRunner{}
	m.runner = runner
	if _, err := RenderBundle(p, m.root, net.ParseIP("127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	installer := filepath.Join(m.root, "harbor/installer")
	if err := os.MkdirAll(installer, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(installer, "docker-compose.yml"), []byte("retained"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := m.store.Mutate(func(states []ServiceState) ([]ServiceState, error) { states[0].Running = false; return states, nil }); err != nil {
		t.Fatal(err)
	}
	m.client = &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		if slices.ContainsFunc(runner.calls, func(s string) bool { return strings.Contains(s, "pilot-harbor-dev-lite up -d --wait") }) {
			return jsonResponse(401, nil), nil
		}
		return nil, errors.New("stopped")
	})}
	m.seed = func(context.Context, Profile, string, net.IP, *http.Client) (ClientConfig, error) {
		t.Fatal("failed activation auth reached seeding")
		return ClientConfig{}, nil
	}
	before := bundleHashes(t, m.root)
	err := m.Repair(context.Background(), p, net.ParseIP("127.0.0.1"), MaintenanceOptions{})
	if err == nil || !strings.Contains(err.Error(), "authentication failed") {
		t.Fatalf("post-activation auth was bypassed: %v", err)
	}
	if !reflect.DeepEqual(before, bundleHashes(t, m.root)) {
		t.Fatal("failed post-activation authentication rewrote retained configuration")
	}
	for _, call := range runner.calls {
		if strings.Contains(call, "prepare") || strings.Contains(call, "force-recreate") || strings.Contains(call, "down") {
			t.Fatalf("failed activation auth reconciled or destroyed service: %s", call)
		}
	}
	state, _ := m.current()
	if state.Running {
		t.Fatal("failed activation authentication published running")
	}
}
