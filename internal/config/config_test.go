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
