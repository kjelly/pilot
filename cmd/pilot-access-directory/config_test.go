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
	path := filepath.Join(dir, "access-directory.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}

const validConfig = `
directory:
  id: access-01
  target_hostgroup_prefix: pilot-target-
  gateway_hostgroup_prefix: pilot-gateway-
  portal_user_group: role-pilot-portal-user
  socket_path: /run/pilot/access-directory.sock

freeipa:
  servers:
    - ipa1.linker.internal
    - ipa2.linker.internal
  ca_file: /etc/ipa/ca.crt
  service_principal: pilot-access-directory/access.linker.internal
  keytab: /etc/pilot/pilot-access-directory.keytab
  request_timeout: 5s

routing:
  ssh_config: /etc/pilot/directory_ssh_config
  connect_timeout: 5s
`

func TestLoadConfigValid(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, validConfig))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Directory.ID != "access-01" {
		t.Fatalf("Directory.ID = %q", cfg.Directory.ID)
	}
	if cfg.targetHostgroupPrefix() != "pilot-target-" || cfg.gatewayHostgroupPrefix() != "pilot-gateway-" {
		t.Fatalf("prefixes = %q / %q", cfg.targetHostgroupPrefix(), cfg.gatewayHostgroupPrefix())
	}
	if len(cfg.FreeIPA.Servers) != 2 {
		t.Fatalf("Servers = %v", cfg.FreeIPA.Servers)
	}
	if time.Duration(cfg.FreeIPA.RequestTimeout) != 5*time.Second {
		t.Fatalf("RequestTimeout = %v, want 5s", time.Duration(cfg.FreeIPA.RequestTimeout))
	}
	if cfg.socketPath() != "/run/pilot/access-directory.sock" {
		t.Fatalf("socketPath() = %q", cfg.socketPath())
	}
	if cfg.Routing.SSHConfig != "/etc/pilot/directory_ssh_config" {
		t.Fatalf("Routing.SSHConfig = %q", cfg.Routing.SSHConfig)
	}
}

func TestLoadConfigMissingRequiredFields(t *testing.T) {
	_, err := LoadConfig(writeConfig(t, "directory:\n  id: access-01\n"))
	if err == nil {
		t.Fatalf("expected an error for missing required fields")
	}
}

// TestLoadConfigRejectsForbiddenFields enforces spec.md §12.1's
// KnownFields(true) requirement: this file has no gateway_known_hosts
// (removed in the spec correction pass — host key verification is
// SSSD/sss_ssh_knownhostsproxy-based, see docs/tmp/now/spec.md §15.1),
// no roster_file/inventory_file, or anything else the schema doesn't
// name.
func TestLoadConfigRejectsForbiddenFields(t *testing.T) {
	for _, field := range []string{
		"  gateway_known_hosts: /etc/pilot/directory_gateway_known_hosts\n",
		"  roster_file: /some/roster.yaml\n",
	} {
		cfg := validConfig + field
		if _, err := LoadConfig(writeConfig(t, cfg)); err == nil {
			t.Fatalf("expected an error for an unknown field: %s", field)
		}
	}
}

func TestLoadConfigDefaultsSocketPathPrefixesAndTimeout(t *testing.T) {
	minimal := `
directory:
  id: access-01

freeipa:
  servers: [ipa1.linker.internal]
  ca_file: /etc/ipa/ca.crt
  service_principal: pilot-access-directory/access.linker.internal
  keytab: /etc/pilot/pilot-access-directory.keytab
`
	cfg, err := LoadConfig(writeConfig(t, minimal))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.socketPath() != defaultSocketPath {
		t.Fatalf("socketPath() = %q, want default", cfg.socketPath())
	}
	if cfg.targetHostgroupPrefix() != defaultTargetHostgroupPrefix {
		t.Fatalf("targetHostgroupPrefix() = %q, want default", cfg.targetHostgroupPrefix())
	}
	if cfg.gatewayHostgroupPrefix() != defaultGatewayHostgroupPrefix {
		t.Fatalf("gatewayHostgroupPrefix() = %q, want default", cfg.gatewayHostgroupPrefix())
	}
	if cfg.requestTimeout() != defaultRequestTimeout {
		t.Fatalf("requestTimeout() = %v, want default", cfg.requestTimeout())
	}
}
