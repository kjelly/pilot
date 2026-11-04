package vmtarget

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/kjelly/pilot/internal/services"
	"github.com/kjelly/pilot/internal/statefile"
)

type serviceConsumerProbes struct {
	mu                        sync.Mutex
	identity                  bool
	dataDown                  bool
	adminAllowed, adminDenied int
	databaseLog               string
	root                      string
}

func (p *serviceConsumerProbes) assertCounts(t *testing.T, allowed, denied, dbAllowed, dbDenied int) {
	t.Helper()
	p.mu.Lock()
	gotAllowed, gotDenied := p.adminAllowed, p.adminDenied
	p.mu.Unlock()
	data, err := os.ReadFile(p.databaseLog)
	if err != nil {
		t.Fatal(err)
	}
	var gotDBAllowed, gotDBDenied int
	for _, outcome := range strings.Fields(string(data)) {
		switch outcome {
		case "db-allow":
			gotDBAllowed++
		case "db-deny":
			gotDBDenied++
		default:
			t.Fatalf("unexpected service command outcome: %s", outcome)
		}
	}
	if gotAllowed != allowed || gotDenied != denied || gotDBAllowed != dbAllowed || gotDBDenied != dbDenied {
		t.Fatalf("payload-free probe outcomes: admin allow/deny=%d/%d, database allow/deny=%d/%d; want %d/%d,%d/%d", gotAllowed, gotDenied, gotDBAllowed, gotDBDenied, allowed, denied, dbAllowed, dbDenied)
	}
}

func registeredServiceFixture(t *testing.T) (*services.Manager, *ServiceBootstrap, *serviceConsumerProbes) {
	t.Helper()
	legacy, discovery := t.TempDir(), t.TempDir()
	bundle, err := services.RenderBundle(services.BuiltInDevLite(), services.DataRoot(legacy), net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	adminBytes, err := os.ReadFile(filepath.Join(bundle.Root, "harbor/secrets/admin-password"))
	if err != nil {
		t.Fatal(err)
	}
	// Capture server authority before any test can corrupt the managed association.
	adminPassword := strings.TrimSpace(string(adminBytes))
	shimDir := t.TempDir()
	probes := &serviceConsumerProbes{identity: true, databaseLog: filepath.Join(shimDir, "probe-outcomes"), root: bundle.Root}
	if err := os.WriteFile(probes.databaseLog, nil, 0600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2.0/users/current" {
			probes.mu.Lock()
			down := probes.dataDown
			probes.mu.Unlock()
			if down && strings.Contains(r.URL.Path, "/manifests/") {
				w.WriteHeader(503)
				return
			}
			_, _ = w.Write([]byte(vmServiceFixtureBody(r.URL.Path)))
			return
		}
		user, password, ok := r.BasicAuth()
		probes.mu.Lock()
		defer probes.mu.Unlock()
		if !ok || user != "admin" || password != adminPassword {
			probes.adminDenied++
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		probes.adminAllowed++
		if probes.identity {
			_, _ = w.Write([]byte(`{"username":"admin","sysadmin_flag":true}`))
		}
	}))
	t.Cleanup(server.Close)
	databaseBytes, err := os.ReadFile(filepath.Join(bundle.Root, "harbor/secrets/database-password"))
	if err != nil {
		t.Fatal(err)
	}
	expectedDatabase := filepath.Join(shimDir, "expected-database-password")
	if err := os.WriteFile(expectedDatabase, databaseBytes, 0600); err != nil {
		t.Fatal(err)
	}
	// The real manager is reconstructed inside central registration. A PATH
	// shim covers every instance and never forwards a command to host Docker.
	const readonlyProbe = `IFS= read -r PGPASSWORD; export PGPASSWORD; export PGPASSFILE=/dev/null; unset PGSERVICE PGSERVICEFILE; exec psql -X -w -h "$(hostname)" -p 5432 -U postgres -d registry -Atc 'SELECT 1'`
	probeCommand := filepath.Join(shimDir, "readonly-probe")
	if err := os.WriteFile(probeCommand, []byte(readonlyProbe), 0600); err != nil {
		t.Fatal(err)
	}
	const dockerShim = `#!/bin/sh
reject() { printf '%s\n' unexpected-docker >> "$PILOT_TEST_SERVICE_PROBE_LOG"; exit 99; }
[ "$#" -eq 6 ] || reject
[ "$1" = exec ] && [ "$2" = -i ] && [ "$3" = pilot-harbor-dev-lite-harbor-db ] && [ "$4" = sh ] && [ "$5" = -c ] || reject
expected_command=$(cat "$PILOT_TEST_SERVICE_DB_COMMAND") || reject
[ "$6" = "$expected_command" ] || reject
IFS= read -r candidate || reject
IFS= read -r expected < "$PILOT_TEST_SERVICE_DB_EXPECTED" || reject
if [ "$PILOT_TEST_SERVICE_DB_TRUST_ALL" = 1 ] || [ "$candidate" = "$expected" ]; then
  printf '%s\n' db-allow >> "$PILOT_TEST_SERVICE_PROBE_LOG"
  printf '1\n'
else
  printf '%s\n' db-deny >> "$PILOT_TEST_SERVICE_PROBE_LOG"
  printf 'password authentication failed\n' >&2
  exit 2
fi
`
	if err := os.WriteFile(filepath.Join(shimDir, "docker"), []byte(dockerShim), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(shimDir, "sudo"), []byte("#!/bin/sh\nprintf '%s\\n' unexpected-sudo >> \"$PILOT_TEST_SERVICE_PROBE_LOG\"\nexit 99\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", shimDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PILOT_TEST_SERVICE_PROBE_LOG", probes.databaseLog)
	t.Setenv("PILOT_TEST_SERVICE_DB_COMMAND", probeCommand)
	t.Setenv("PILOT_TEST_SERVICE_DB_EXPECTED", expectedDatabase)
	t.Setenv("PILOT_TEST_SERVICE_DB_TRUST_ALL", "")
	t.Cleanup(func() {
		data, err := os.ReadFile(probes.databaseLog)
		if err != nil {
			t.Error(err)
		}
		if strings.Contains(string(data), "unexpected-") {
			t.Error("service fixture rejected an unexpected Docker/sudo command")
		}
	})
	client := bundle.Client
	client.DataProbes = nil // Genuine pre-policy canonical client.
	installServiceFixtureRoute(t, server.URL)
	store, err := statefile.New[services.ServiceState](legacy, "services.json", 1, "services")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Mutate(func([]services.ServiceState) ([]services.ServiceState, error) {
		return []services.ServiceState{{Profile: client.Profile, Fingerprint: client.Fingerprint, Root: bundle.Root, ComposePath: bundle.ComposePath, Client: client, BindIP: "127.0.0.1", Running: true, ConsumerTracking: true}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	manager, err := services.NewSharedManager(services.DiscoveryOptions{Directory: discovery, AdoptFrom: legacy}, nil)
	if err != nil {
		t.Fatal(err)
	}
	profile := services.BuiltInDevLite()
	profile.DataProbes = vmServiceDescriptors()
	client, err = manager.ClientConfigForProfile(context.Background(), profile, net.ParseIP("127.0.0.1"), nil)
	if err != nil {
		t.Fatal(err)
	}
	probes.assertCounts(t, 1, 0, 0, 0)
	return manager, &ServiceBootstrap{DiscoveryDirectory: discovery, InstanceID: client.InstanceID, Generation: client.Generation, Profile: client.Profile, Fingerprint: client.Fingerprint, HostIP: client.HostIP, Hostname: client.Hostname, AptProxyURL: client.AptProxyURL, RPMBaseURL: client.RPMBaseURL, RPMRepositories: client.RPMRepositories, RegistryMirrorURL: client.RegistryMirrorURL, RegistryProjects: client.RegistryProjects, CAPEM: client.CAPEM, PhysicalProfile: &profile, DataProbes: profile.ClientDataProbes()}, probes
}

// The shim reads pilot's generated XML, and models the UUID/name lists used by
// the native virsh probes. Actual libvirt execution remains separate target evidence.
const serviceConsumerVirsh = `
define) cp "$2" "$0.domain"; exit 0 ;;
list)
  if [ -f "$0.domain" ]; then
    case "$3" in
      --uuid) sed -n 's/.*<uuid>\(.*\)<\/uuid>.*/\1/p' "$0.domain" ;;
      --name) sed -n 's/.*<name>\(.*\)<\/name>.*/\1/p' "$0.domain" ;;
    esac
  fi
  exit 0 ;;
domuuid) sed -n 's/.*<uuid>\(.*\)<\/uuid>.*/\1/p' "$0.domain"; exit 0 ;;
undefine) rm -f "$0.domain"; exit 0 ;;
`

func TestVMServiceConsumerPersistsAcrossManagerAndReleasesAfterVerifiedTeardown(t *testing.T) {
	serviceManager, bootstrap, probes := registeredServiceFixture(t)
	m, base := newTestManager(t, serviceConsumerVirsh+happyVirsh)
	target, err := m.Up(context.Background(), Options{Name: "service-vm", BaseImage: base, Services: bootstrap})
	if err != nil {
		t.Fatal(err)
	}
	if target.ServiceConsumer == nil {
		t.Fatal("central Up did not register guest")
	}
	probes.assertCounts(t, 2, 0, 0, 0)
	if _, err := uuid.Parse(target.ServiceConsumer.ID); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewManager(m.stateDir, m.vmDir)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := reopened.Get(context.Background(), target.Name)
	if err != nil || !reflect.DeepEqual(saved.ServiceConsumer, target.ServiceConsumer) {
		t.Fatalf("target round trip lost durable consumer: %+v %v", saved, err)
	}
	consumers, err := serviceManager.Consumers(context.Background())
	if err != nil || len(consumers) != 1 || consumers[0] != *saved.ServiceConsumer {
		t.Fatalf("guest protection did not survive reopen: %+v %v", consumers, err)
	}
	if err := serviceManager.Down(context.Background()); err == nil || !strings.Contains(err.Error(), "registered VM consumer") {
		t.Fatalf("persistent guest did not block maintenance: %v", err)
	}
	if err := reopened.Down(context.Background(), target.Name); err != nil {
		t.Fatal(err)
	}
	consumers, err = serviceManager.Consumers(context.Background())
	if err != nil || len(consumers) != 0 {
		t.Fatalf("verified teardown retained registration: %+v %v", consumers, err)
	}
	client, err := serviceManager.ClientConfigForProfile(context.Background(), *bootstrap.PhysicalProfile, net.ParseIP(bootstrap.HostIP), bootstrap.Requirements)
	if err != nil || client.InstanceID != bootstrap.InstanceID {
		t.Fatalf("VM teardown interrupted cache: %+v %v", client, err)
	}
	probes.assertCounts(t, 3, 0, 0, 0)
	if err := reopened.Down(context.Background(), target.Name); err != nil {
		t.Fatalf("repeated teardown: %v", err)
	}
}

func TestVMServiceConsumerProbeFailureAndForeignUUIDRetainStateAndRegistration(t *testing.T) {
	for _, fault := range []string{"query-error", "foreign-uuid", "undefine-error"} {
		t.Run(fault, func(t *testing.T) {
			serviceManager, bootstrap, _ := registeredServiceFixture(t)
			m, base := newTestManager(t, serviceConsumerVirsh+happyVirsh)
			target, err := m.Up(context.Background(), Options{Name: "guarded-service-vm", BaseImage: base, Services: bootstrap})
			if err != nil {
				t.Fatal(err)
			}
			body := serviceConsumerVirsh + happyVirsh
			switch fault {
			case "query-error":
				body = "list) exit 1 ;;\n" + body
			case "foreign-uuid":
				body = "domuuid) echo 11111111-1111-1111-1111-111111111111; exit 0 ;;\n" + body
			case "undefine-error":
				body = "undefine) exit 1 ;;\n" + body
			}
			writeShim(t, filepath.Dir(os.Getenv("PILOT_VIRSH_BIN")), "virsh", "PILOT_VIRSH_BIN", "case \"$1\" in\n"+body+"\nesac")
			if err := m.Down(context.Background(), target.Name); err == nil {
				t.Fatal("uncertain/failed teardown released protection")
			}
			consumers, err := serviceManager.Consumers(context.Background())
			if err != nil || len(consumers) != 1 {
				t.Fatalf("failed teardown dropped registration: %+v %v", consumers, err)
			}
			if _, err := m.Get(context.Background(), target.Name); err != nil {
				t.Fatal("failed teardown discarded target state")
			}
			if _, err := os.Stat(target.Dir); err != nil {
				t.Fatal("failed teardown discarded target artifacts")
			}
		})
	}
}

func TestVMServiceConsumerMissingIdentityRefusesBeforeDomainCreation(t *testing.T) {
	m, base := newTestManager(t, happyVirsh)
	bootstrap := testServiceBootstrap(t)
	_, err := m.Up(context.Background(), Options{Name: "untracked-service-vm", BaseImage: base, Services: &bootstrap})
	if err == nil || !strings.Contains(err.Error(), "durable guest protection") {
		t.Fatalf("untracked guest was provisioned: %v", err)
	}
	targets, err := m.store.Load()
	if err != nil || len(targets) != 0 {
		t.Fatalf("rejected guest persisted target: %+v %v", targets, err)
	}
}

func TestVMServiceConsumerManagementFailureRequiresIndependentDataProof(t *testing.T) {
	for _, fault := range []string{"wrong-admin", "wrong-database", "missing-current-identity", "trust-all-database", "data-failure"} {
		t.Run(fault, func(t *testing.T) {
			manager, bootstrap, probes := registeredServiceFixture(t)
			m, base := newTestManager(t, serviceConsumerVirsh+happyVirsh)
			switch fault {
			case "wrong-admin", "wrong-database":
				rel := "harbor/secrets/admin-password"
				if fault == "wrong-database" {
					rel = "harbor/secrets/database-password"
				}
				if e := os.WriteFile(filepath.Join(probes.root, rel), []byte("SENTINEL-wrong\n"), 0600); e != nil {
					t.Fatal(e)
				}
			case "missing-current-identity":
				probes.mu.Lock()
				probes.identity = false
				probes.mu.Unlock()
			case "trust-all-database":
				t.Setenv("PILOT_TEST_SERVICE_DB_TRUST_ALL", "1")
			case "data-failure":
				probes.mu.Lock()
				probes.dataDown = true
				probes.mu.Unlock()
			}
			target, e := m.Up(context.Background(), Options{Name: "independent-service-vm", BaseImage: base, Services: bootstrap})
			consumers, ce := manager.Consumers(context.Background())
			if ce != nil {
				t.Fatal(ce)
			}
			if fault == "data-failure" {
				if e == nil || !strings.Contains(e.Error(), "required oci") || len(consumers) != 0 {
					t.Fatalf("failed data proof accepted: %v %+v", e, consumers)
				}
				targets, _ := m.store.Load()
				if len(targets) != 0 {
					t.Fatal("failed readiness created VM state")
				}
				return
			}
			if e != nil || target.ServiceConsumer == nil || len(consumers) != 1 {
				t.Fatalf("proven data rejected by management association: %v %+v", e, consumers)
			}
			data, _ := os.ReadFile(probes.databaseLog)
			if len(data) != 0 {
				t.Fatal("consuming readiness ran a management database probe")
			}
		})
	}
}

const vmFixtureManifest = `{"schemaVersion":2,"layers":[]}`

func vmServiceDescriptors() map[services.Capability]services.DataProbe {
	sum := sha256.Sum256([]byte(vmFixtureManifest))
	digest := hex.EncodeToString(sum[:])
	return map[services.Capability]services.DataProbe{services.APT: {Resource: "http://upstream.invalid/dists/noble/InRelease", Contains: "PGP SIGNED MESSAGE"}, services.RPM: {Resource: "/pulp/content/test/repodata/repomd.xml", Contains: "<repomd"}, services.OCI: {Resource: "/v2/test/manifests/sha256:" + digest, SHA256: digest}}
}
func vmServiceFixtureBody(path string) string {
	switch path {
	case "/acng-report.html":
		return "<html><title>Apt-Cacher NG Command And Control Page</title></html>"
	case "/pulp/api/v3/status/":
		return `{"database_connection":{"connected":true},"online_workers":[{"name":"test-worker"}],"online_content_apps":[{"name":"test-content"}]}`
	case "/api/v2.0/health":
		return `{"status":"healthy","components":[{"name":"core","status":"healthy"},{"name":"database","status":"healthy"},{"name":"registry","status":"healthy"}]}`
	case "/pulp/api/v3/users/":
		return `{"results":[]}`
	}
	if strings.Contains(path, "InRelease") {
		return "PGP SIGNED MESSAGE"
	}
	if strings.Contains(path, "repomd.xml") {
		return "<repomd/>"
	}
	if strings.Contains(path, "/manifests/") {
		return vmFixtureManifest
	}
	return ""
}

// Route real HTTP requests to the native-response fixture while preserving the
// production canonical endpoint contract and HTTP Host header.
func installServiceFixtureRoute(t *testing.T, target string) {
	t.Helper()
	base := http.DefaultTransport
	u, e := url.Parse(target)
	if e != nil {
		t.Fatal(e)
	}
	http.DefaultTransport = serviceFixtureTransport(func(r *http.Request) (*http.Response, error) {
		clone := r.Clone(r.Context())
		copyURL := *r.URL
		clone.URL = &copyURL
		clone.URL.Scheme = u.Scheme
		clone.URL.Host = u.Host
		if clone.Host == "" {
			clone.Host = r.URL.Host
		}
		return base.RoundTrip(clone)
	})
	t.Cleanup(func() { http.DefaultTransport = base })
}

type serviceFixtureTransport func(*http.Request) (*http.Response, error)

func (f serviceFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestVMServiceConsumerPhysicalTamperingRefusesBeforeDomainCreation(t *testing.T) {
	for _, fault := range []string{"profile-name", "upstream", "bind", "endpoint", "generation", "ca", "owner", "state-endpoint"} {
		t.Run(fault, func(t *testing.T) {
			_, bootstrap, probes := registeredServiceFixture(t)
			m, base := newTestManager(t, serviceConsumerVirsh+happyVirsh)
			switch fault {
			case "profile-name", "upstream":
				profile := *bootstrap.PhysicalProfile
				if fault == "profile-name" {
					profile.Name = "other"
				} else {
					profile.Apt.Upstream += "/other"
				}
				bootstrap.PhysicalProfile = &profile
			case "bind":
				bootstrap.HostIP = "127.0.0.2"
			case "endpoint":
				bootstrap.RegistryMirrorURL = "http://foreign.invalid:8081"
			case "generation":
				bootstrap.Generation++
			case "ca":
				bootstrap.CAPEM = "not-a-certificate"
			case "owner":
				path := filepath.Join(probes.root, ".pilot-services-owner.json")
				data, e := os.ReadFile(path)
				if e != nil {
					t.Fatal(e)
				}
				data = []byte(strings.ReplaceAll(string(data), bootstrap.InstanceID, "foreign-owner"))
				if e = os.WriteFile(path, data, 0600); e != nil {
					t.Fatal(e)
				}
			case "state-endpoint":
				store, e := statefile.New[services.ServiceState](bootstrap.DiscoveryDirectory, "services.json", 1, "services")
				if e != nil {
					t.Fatal(e)
				}
				if e = store.Mutate(func(s []services.ServiceState) ([]services.ServiceState, error) {
					s[0].Client.AptProxyURL = "http://foreign.invalid:3142"
					return s, nil
				}); e != nil {
					t.Fatal(e)
				}
			}
			_, e := m.Up(context.Background(), Options{Name: "tamper-service-vm", BaseImage: base, Services: bootstrap})
			if e == nil {
				t.Fatal("tampered direct Manager.Up contract accepted")
			}
			targets, e := m.store.Load()
			if e != nil || len(targets) != 0 {
				t.Fatalf("rejected physical contract created target state: %v", e)
			}
			if _, e = os.Stat(os.Getenv("PILOT_VIRSH_BIN") + ".domain"); !os.IsNotExist(e) {
				t.Fatal("rejected physical contract created domain")
			}
			probes.assertCounts(t, 1, 0, 0, 0)
		})
	}
}
