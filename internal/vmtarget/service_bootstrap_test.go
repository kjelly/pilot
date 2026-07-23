package vmtarget

import (
	"net"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/services"
)

func testServiceBootstrap(t *testing.T) ServiceBootstrap {
	t.Helper()
	bundle, err := services.RenderBundle(services.BuiltInDevLite(), t.TempDir(), net.ParseIP("192.168.122.1"))
	if err != nil {
		t.Fatal(err)
	}
	return ServiceBootstrap{
		Profile:           bundle.Client.Profile,
		Fingerprint:       bundle.Client.Fingerprint,
		HostIP:            bundle.Client.HostIP,
		Hostname:          bundle.Client.Hostname,
		AptProxyURL:       bundle.Client.AptProxyURL,
		RPMBaseURL:        bundle.Client.RPMBaseURL,
		RegistryMirrorURL: bundle.Client.RegistryMirrorURL,
		RegistryProjects:  bundle.Client.RegistryProjects,
		CAPEM:             bundle.Client.CAPEM,
	}
}

func TestServiceBootstrapRenderCloudInit(t *testing.T) {
	service := testServiceBootstrap(t)
	got, err := service.RenderCloudInit()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"/usr/local/share/ca-certificates/pilot-services.crt",
		"/etc/apt/apt.conf.d/99pilot-services",
		"/etc/yum.repos.d/pilot-services.repo",
		"/etc/docker/daemon.json",
		"update-ca-certificates",
		"/pulp/api/v3/status/",
		"cache.pilot.internal",
		"192.168.122.1 cache.pilot.internal",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("cloud-init missing %q", want)
		}
	}
	if strings.Contains(got, "ca-key") || strings.Contains(got, "change-me") {
		t.Error("cloud-init contains host secret material")
	}
}

func TestRenderUserDataKeepsLegacyWithoutServices(t *testing.T) {
	target := &Target{Name: "test-vm", SSHUser: "root"}
	got, err := renderUserData(target, "ssh-ed25519 AAAA test", nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "pilot-services") {
		t.Fatal("legacy cloud-init unexpectedly contains service configuration")
	}
	if !strings.Contains(got, "/root/.ssh/authorized_keys") {
		t.Fatal("legacy cloud-init lost authorized_keys")
	}
}

func TestRenderUserDataWithServicesHasOneWriteFilesBlock(t *testing.T) {
	target := &Target{Name: "test-vm", SSHUser: "root"}
	got, err := renderUserData(target, "ssh-ed25519 AAAA test", func() *ServiceBootstrap {
		v := testServiceBootstrap(t)
		return &v
	}())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(got, "write_files:") != 1 {
		t.Fatalf("write_files block count = %d, want 1", strings.Count(got, "write_files:"))
	}
	if !strings.Contains(got, "runcmd:") {
		t.Fatal("service cloud-init missing runcmd")
	}
}

func TestServiceBootstrapRejectsInvalidCA(t *testing.T) {
	service := testServiceBootstrap(t)
	service.CAPEM = "not-a-certificate"
	if _, err := service.RenderCloudInit(); err == nil || !strings.Contains(err.Error(), "CA") {
		t.Fatalf("want CA validation error, got %v", err)
	}
}
