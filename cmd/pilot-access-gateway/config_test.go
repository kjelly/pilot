package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "access-gateway.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

const validConfig = `
gateway:
  id: gpu-01
  scope: gpu
  fqdn: pilot-gw-gpu-01.linker.internal
  target_hostgroup: pilot-target-gpu
  socket_path: /run/pilot/access-gateway.sock
  portal_user_group: role-pilot-portal-user
  freeipa:
    servers:
      - ipa1.linker.internal
      - ipa2.linker.internal
    ca_file: /etc/ipa/ca.crt
    service_principal: pilot-access-gateway/pilot-gw-gpu-01.linker.internal
    keytab: /etc/pilot/pilot-access-gateway.keytab
    request_timeout: 5s
`

func TestLoadConfigValid(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, validConfig))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Gateway.ID != "gpu-01" || cfg.Gateway.Scope != "gpu" || cfg.Gateway.TargetHostgroup != "pilot-target-gpu" {
		t.Fatalf("Gateway = %+v", cfg.Gateway)
	}
	if len(cfg.Gateway.FreeIPA.Servers) != 2 {
		t.Fatalf("Servers = %v", cfg.Gateway.FreeIPA.Servers)
	}
	if time.Duration(cfg.Gateway.FreeIPA.RequestTimeout) != 5*time.Second {
		t.Fatalf("RequestTimeout = %v, want 5s", time.Duration(cfg.Gateway.FreeIPA.RequestTimeout))
	}
	if cfg.socketPath() != "/run/pilot/access-gateway.sock" {
		t.Fatalf("socketPath() = %q", cfg.socketPath())
	}
}

func TestLoadConfigMissingRequiredFields(t *testing.T) {
	_, err := LoadConfig(writeConfig(t, "gateway:\n  id: gpu-01\n"))
	if err == nil {
		t.Fatalf("expected an error for missing required fields")
	}
}

// TestLoadConfigRejectsForbiddenFields enforces spec.md §26's hard rule:
// roster_file/inventory_file/vault_password_file/state_dir/audit_db must
// never appear in this config, and KnownFields(true) rejects them (and
// any other unrecognized field) rather than silently ignoring them.
func TestLoadConfigRejectsForbiddenFields(t *testing.T) {
	cfg := validConfig + "  roster_file: /some/roster.yaml\n"
	if _, err := LoadConfig(writeConfig(t, cfg)); err == nil {
		t.Fatalf("expected an error for an unknown field (roster_file)")
	}
}

func TestLoadConfigDefaultsSocketPathAndTimeout(t *testing.T) {
	minimal := `
gateway:
  id: gpu-01
  scope: gpu
  fqdn: pilot-gw-gpu-01.linker.internal
  target_hostgroup: pilot-target-gpu
  freeipa:
    servers: [ipa1.linker.internal]
    ca_file: /etc/ipa/ca.crt
    service_principal: pilot-access-gateway/pilot-gw-gpu-01.linker.internal
    keytab: /etc/pilot/pilot-access-gateway.keytab
`
	cfg, err := LoadConfig(writeConfig(t, minimal))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.socketPath() != defaultSocketPath {
		t.Fatalf("socketPath() = %q, want default", cfg.socketPath())
	}
	if cfg.requestTimeout() != defaultRequestTimeout {
		t.Fatalf("requestTimeout() = %v, want default", cfg.requestTimeout())
	}
}
