package services

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuiltInDevLiteValid(t *testing.T) {
	p := BuiltInDevLite()
	if err := p.Validate(); err != nil {
		t.Fatalf("built-in profile invalid: %v", err)
	}
	if got, err := p.Fingerprint(); err != nil || len(got) != 64 {
		t.Fatalf("fingerprint = %q, err = %v", got, err)
	}
}

func TestLoadProfileUnknownRefErrors(t *testing.T) {
	if _, err := LoadProfile(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Fatal("missing profile must fail")
	}
}

func TestProfileValidationRejectsUnsafeValues(t *testing.T) {
	p := BuiltInDevLite()
	p.Apt.Allowlist = nil
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("want allowlist error, got %v", err)
	}
	p = BuiltInDevLite()
	p.RPM.Repos[0].Upstream = "http://repo.example.invalid"
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("want https error, got %v", err)
	}
	p = BuiltInDevLite()
	p.Storage.MaxBytes = 0
	if err := p.Validate(); err == nil || !strings.Contains(err.Error(), "max_bytes") {
		t.Fatalf("want max_bytes error, got %v", err)
	}
}

func TestLoadProfileYAMLAndFingerprintChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile.yaml")
	content := "name: local\napt:\n  upstream: http://archive.ubuntu.com/ubuntu\n  allowlist: [archive.ubuntu.com]\n  port: 3142\nrpm:\n  port: 8443\n  repos:\n    - name: alma\n      upstream: https://repo.almalinux.org/almalinux/9/BaseOS/x86_64/os/\noci:\n  port: 5000\n  registries:\n    - name: docker\n      upstream: https://registry-1.docker.io\n      proxy_project: dockerhub\nharbor:\n  version: v2.15.1\n  installer_url: https://github.com/goharbor/harbor/releases/download/v2.15.1/harbor-online-installer-v2.15.1.tgz\n  http_port: 8081\nstorage:\n  max_bytes: 1000\nretention:\n  cache_ttl_hours: 1\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadProfile(path)
	if err != nil {
		t.Fatalf("load profile: %v", err)
	}
	one, err := loaded.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	loaded.Apt.Upstream = "http://security.ubuntu.com/ubuntu"
	two, err := loaded.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if one == two {
		t.Fatal("fingerprint must change when profile changes")
	}
}

func TestDataRoot(t *testing.T) {
	if got, want := DataRoot("/tmp/pilot"), "/tmp/pilot/cache"; got != want {
		t.Fatalf("DataRoot = %q, want %q", got, want)
	}
}
