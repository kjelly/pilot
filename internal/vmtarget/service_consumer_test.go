package vmtarget

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/kjelly/pilot/internal/services"
	"github.com/kjelly/pilot/internal/statefile"
)

func registeredServiceFixture(t *testing.T) (*services.Manager, *ServiceBootstrap) {
	t.Helper()
	legacy, discovery := t.TempDir(), t.TempDir()
	bundle, err := services.RenderBundle(services.BuiltInDevLite(), services.DataRoot(legacy), net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(server.Close)
	client := bundle.Client
	client.AptProxyURL, client.RPMBaseURL, client.RegistryMirrorURL = server.URL, server.URL, server.URL
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
	client, err = manager.ClientConfig(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return manager, &ServiceBootstrap{DiscoveryDirectory: discovery, InstanceID: client.InstanceID, Generation: client.Generation, Profile: client.Profile, Fingerprint: client.Fingerprint, HostIP: client.HostIP, Hostname: client.Hostname, AptProxyURL: client.AptProxyURL, RPMBaseURL: client.RPMBaseURL, RPMRepositories: client.RPMRepositories, RegistryMirrorURL: client.RegistryMirrorURL, RegistryProjects: client.RegistryProjects, CAPEM: client.CAPEM}
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
	serviceManager, bootstrap := registeredServiceFixture(t)
	m, base := newTestManager(t, serviceConsumerVirsh+happyVirsh)
	target, err := m.Up(context.Background(), Options{Name: "service-vm", BaseImage: base, Services: bootstrap})
	if err != nil {
		t.Fatal(err)
	}
	if target.ServiceConsumer == nil {
		t.Fatal("central Up did not register guest")
	}
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
	client, err := serviceManager.ClientConfig(context.Background())
	if err != nil || client.InstanceID != bootstrap.InstanceID {
		t.Fatalf("VM teardown interrupted cache: %+v %v", client, err)
	}
	if err := reopened.Down(context.Background(), target.Name); err != nil {
		t.Fatalf("repeated teardown: %v", err)
	}
}

func TestVMServiceConsumerProbeFailureAndForeignUUIDRetainStateAndRegistration(t *testing.T) {
	for _, fault := range []string{"query-error", "foreign-uuid", "undefine-error"} {
		t.Run(fault, func(t *testing.T) {
			serviceManager, bootstrap := registeredServiceFixture(t)
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
