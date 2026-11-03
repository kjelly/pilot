package config

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestDefaultHBACServices(t *testing.T) {
	want := []string{"sshd", "sudo", "sudo-i", "su", "su-l", "login", "gdm-password", "nx", "cockpit"}
	if got := Default().HBACServices; !reflect.DeepEqual(got, want) {
		t.Fatalf("default HBAC services = %v, want %v", got, want)
	}
}

func TestServicesDirectoryIndependentOfDataDirectory(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	want := Default().ServicesDir
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("data_dir: /a/disposable/vm/root\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServicesDir != want || cfg.ServicesDir == cfg.DataDir {
		t.Fatalf("services followed VM state: %+v", cfg)
	}
	if err := os.WriteFile(path, []byte("services_dir: /a/shared/service/root\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err = Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ServicesDir != "/a/shared/service/root" {
		t.Fatalf("services config ignored: %+v", cfg)
	}
}

func TestLoadReadsConfiguredHBACServices(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("hbac_services:\n  - sshd\n  - nx\n  - gdm-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"sshd", "nx", "gdm-password"}
	if !reflect.DeepEqual(cfg.HBACServices, want) {
		t.Fatalf("configured HBAC services = %v, want %v", cfg.HBACServices, want)
	}
}
