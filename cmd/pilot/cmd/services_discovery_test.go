package cmd

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/services"
	"github.com/kjelly/pilot/internal/statefile"
)

func TestServicesDiscoveryDirectoryPrecedenceAndVMIndependence(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PILOT_SERVICES_DIR", "")
	oldDir, oldCfg, oldSvc, oldAdopt := dataDir, cfgFile, servicesDir, servicesAdoptFrom
	t.Cleanup(func() { dataDir, cfgFile, servicesDir, servicesAdoptFrom = oldDir, oldCfg, oldSvc, oldAdopt })
	servicesDir, servicesAdoptFrom = "", ""
	cfgFile = filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cfgFile, []byte("data_dir: "+filepath.Join(home, "configured-vm")+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	root := func() string {
		t.Helper()
		m, err := newServiceManager()
		if err != nil {
			t.Fatal(err)
		}
		s, err := m.Status(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		return s.Root
	}
	dataDir = filepath.Join(home, "vm-one")
	first := root()
	dataDir = filepath.Join(home, "vm-two")
	if second := root(); first != second {
		t.Fatalf("VM data directory selected another stack: %s != %s", first, second)
	}
	want := filepath.Join(home, ".local/share/pilot-services/cache")
	if first != want {
		t.Fatalf("default service root = %s, want %s", first, want)
	}
	configured := filepath.Join(home, "configured-services")
	if err := os.WriteFile(cfgFile, []byte("services_dir: "+configured+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if got := root(); got != filepath.Join(configured, "cache") {
		t.Fatalf("config ignored: %s", got)
	}
	env := filepath.Join(home, "env-services")
	t.Setenv("PILOT_SERVICES_DIR", env)
	if got := root(); got != filepath.Join(env, "cache") {
		t.Fatalf("env ignored: %s", got)
	}
	servicesDir = filepath.Join(home, "flag-services")
	if got := root(); got != filepath.Join(servicesDir, "cache") {
		t.Fatalf("flag ignored: %s", got)
	}
}

func TestServicesExplicitDirectoryDoesNotAdoptUserCache(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PILOT_SERVICES_DIR", "")
	oldDir, oldCfg, oldSvc, oldAdopt := dataDir, cfgFile, servicesDir, servicesAdoptFrom
	t.Cleanup(func() { dataDir, cfgFile, servicesDir, servicesAdoptFrom = oldDir, oldCfg, oldSvc, oldAdopt })
	cfgFile = filepath.Join(home, "missing-config")
	servicesAdoptFrom = ""
	dataDir = ""
	legacy := filepath.Join(home, ".local/share/pilot/cache")
	if err := os.MkdirAll(legacy, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacy, "credential-sentinel"), []byte("never adopt this scope"), 0600); err != nil {
		t.Fatal(err)
	}
	servicesDir = filepath.Join(home, "isolated")
	if _, err := newServiceManager(); err != nil {
		t.Fatalf("explicit service directory examined unrelated default cache: %v", err)
	}
	servicesDir = ""
	if _, err := newServiceManager(); err == nil {
		t.Fatal("default discovery must diagnose missing legacy state beside data")
	}
}

func TestServicesRootFlagsExtractedForRawVMCommands(t *testing.T) {
	oldSvc, oldAdopt := servicesDir, servicesAdoptFrom
	t.Cleanup(func() { servicesDir, servicesAdoptFrom = oldSvc, oldAdopt })
	args := applyRootFlags([]string{"--services-dir=/shared", "--services-adopt-from", "/legacy", "playbook.yml", "-e", "x=y"})
	if servicesDir != "/shared" || servicesAdoptFrom != "/legacy" || len(args) != 3 || args[0] != "playbook.yml" {
		t.Fatalf("services root flags not consumed: %v %s %s", args, servicesDir, servicesAdoptFrom)
	}
}

func TestServicesVMConsumersReuseAdoptedIdentityAcrossDataDirectories(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("PILOT_SERVICES_DIR", "")
	oldDir, oldCfg, oldSvc, oldAdopt := dataDir, cfgFile, servicesDir, servicesAdoptFrom
	t.Cleanup(func() { dataDir, cfgFile, servicesDir, servicesAdoptFrom = oldDir, oldCfg, oldSvc, oldAdopt })
	cfgFile = filepath.Join(home, "missing-config")
	servicesDir = filepath.Join(home, "services")
	servicesAdoptFrom = filepath.Join(home, "legacy")
	profile := services.BuiltInDevLite()
	bundle, err := services.RenderBundle(profile, services.DataRoot(servicesAdoptFrom), net.ParseIP("127.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	defer server.Close()
	client := bundle.Client
	client.AptProxyURL = server.URL
	client.RPMBaseURL = server.URL
	client.RegistryMirrorURL = server.URL
	store, err := statefile.New[services.ServiceState](servicesAdoptFrom, "services.json", 1, "services")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Mutate(func([]services.ServiceState) ([]services.ServiceState, error) {
		return []services.ServiceState{{Profile: profile.Name, Fingerprint: client.Fingerprint, Root: bundle.Root, ComposePath: bundle.ComposePath, Client: client, BindIP: "127.0.0.1", Running: true}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	virsh := filepath.Join(home, "virsh")
	if err := os.WriteFile(virsh, []byte("#!/bin/sh\necho '<network><ip address=\"127.0.0.1\"/></network>'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PILOT_VIRSH_BIN", virsh)
	dataDir = filepath.Join(home, "vm-one")
	first, err := resolveVMServiceBootstrap(context.Background(), "dev-lite", "default")
	if err != nil {
		t.Fatal(err)
	}
	dataDir = filepath.Join(home, "vm-two")
	second, err := resolveVMServiceBootstrap(context.Background(), "dev-lite", "default")
	if err != nil {
		t.Fatal(err)
	}
	if first.InstanceID == "" || second.InstanceID != first.InstanceID || first.Generation != second.Generation || second.CAPEM != first.CAPEM || second.AptProxyURL != first.AptProxyURL {
		t.Fatalf("VM consumers selected different services: %+v %+v", first, second)
	}
	cloud, err := second.RenderCloudInit()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(cloud, first.InstanceID) {
		t.Fatal("VM cloud-init lost shared instance identity")
	}
	for _, path := range []string{"ca/ca-key.pem", "harbor/secrets/admin-password", "harbor/secrets/database-password", "pulp/secrets/admin-password", "pulp/settings/secret-key"} {
		secret, err := os.ReadFile(filepath.Join(bundle.Root, path))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(cloud, strings.TrimSpace(string(secret))) {
			t.Fatalf("VM received host credential %s", path)
		}
	}
	for _, dir := range []string{filepath.Join(home, "vm-one"), filepath.Join(home, "vm-two")} {
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatalf("service discovery created VM state %s: %v", dir, err)
		}
	}
}
