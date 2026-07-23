package services

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderBundlePersistentAndBound(t *testing.T) {
	root := t.TempDir()
	bundle, err := RenderBundle(BuiltInDevLite(), root, net.ParseIP("192.168.122.1"))
	if err != nil {
		t.Fatalf("render bundle: %v", err)
	}
	compose, err := os.ReadFile(bundle.ComposePath)
	if err != nil {
		t.Fatal(err)
	}
	s := string(compose)
	for _, want := range []string{"sameersbn/apt-cacher-ng:3.7.4", "pulp/pulp:3.85.25", "192.168.122.1:3142:3142", "/pulp/settings", "/pulp/pulp_storage", "/pulp/pgsql", "/dev/fuse:/dev/fuse"} {
		if !strings.Contains(s, want) {
			t.Errorf("compose missing %q", want)
		}
	}
	if strings.Contains(s, "0.0.0.0") {
		t.Error("compose must not bind services to all host interfaces")
	}
	if _, err := os.Stat(filepath.Join(root, "pulp", "pgsql")); err != nil {
		t.Errorf("pulp pgsql directory missing: %v", err)
	}
	if bundle.Client.Hostname != "cache.pilot.internal" || bundle.Client.CAPEM == "" {
		t.Fatalf("invalid client config: %+v", bundle.Client)
	}
	if mode := fileMode(t, bundle.CAKeyPath); mode.Perm() != 0o600 {
		t.Fatalf("CA key mode = %o, want 600", mode.Perm())
	}
	if mode := fileMode(t, bundle.CAPEMPath); mode.Perm() != 0o644 {
		t.Fatalf("CA cert mode = %o, want 644", mode.Perm())
	}
}

func TestRenderBundleRequiresBindIP(t *testing.T) {
	if _, err := RenderBundle(BuiltInDevLite(), t.TempDir(), nil); err == nil {
		t.Fatal("nil bind IP must fail")
	}
}

func TestRenderBundleCAIsReused(t *testing.T) {
	root := t.TempDir()
	one, err := RenderBundle(BuiltInDevLite(), root, net.ParseIP("192.168.122.1"))
	if err != nil {
		t.Fatal(err)
	}
	two, err := RenderBundle(BuiltInDevLite(), root, net.ParseIP("192.168.122.1"))
	if err != nil {
		t.Fatal(err)
	}
	if one.Client.CAPEM != two.Client.CAPEM {
		t.Fatal("CA changed across idempotent render")
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode()
}
