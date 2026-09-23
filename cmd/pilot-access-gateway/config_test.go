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
	// D8: recording defaults to "metadata"/"best_effort" whenever the
	// operator says nothing at all — the unconditional safe default this
	// whole spec insists on, not just a config-loader convenience.
	if cfg.recordingMode() != "metadata" {
		t.Fatalf("recordingMode() = %q, want metadata", cfg.recordingMode())
	}
	if cfg.recordingFailurePolicy() != "best_effort" {
		t.Fatalf("recordingFailurePolicy() = %q, want best_effort", cfg.recordingFailurePolicy())
	}
	if cfg.recordingQueueEvents() != defaultRecordingQueueEvents {
		t.Fatalf("recordingQueueEvents() = %d, want %d", cfg.recordingQueueEvents(), defaultRecordingQueueEvents)
	}
	if cfg.recordingFlushInterval() != defaultRecordingFlushInterval {
		t.Fatalf("recordingFlushInterval() = %v, want %v", cfg.recordingFlushInterval(), defaultRecordingFlushInterval)
	}
}

func TestLoadConfigRecordingValidValues(t *testing.T) {
	cfg := validConfig + "  recording:\n    mode: terminal_io\n    failure_policy: fail_closed\n    queue_events: 256\n    flush_interval: 250ms\n"
	loaded, err := LoadConfig(writeConfig(t, cfg))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if loaded.recordingMode() != "terminal_io" {
		t.Fatalf("recordingMode() = %q, want terminal_io", loaded.recordingMode())
	}
	if loaded.recordingFailurePolicy() != "fail_closed" {
		t.Fatalf("recordingFailurePolicy() = %q, want fail_closed", loaded.recordingFailurePolicy())
	}
	if loaded.recordingQueueEvents() != 256 {
		t.Fatalf("recordingQueueEvents() = %d, want 256", loaded.recordingQueueEvents())
	}
	if loaded.recordingFlushInterval() != 250*time.Millisecond {
		t.Fatalf("recordingFlushInterval() = %v, want 250ms", loaded.recordingFlushInterval())
	}
}

func TestLoadConfigRecordingRejectsInvalidMode(t *testing.T) {
	cfg := validConfig + "  recording:\n    mode: full_video\n"
	if _, err := LoadConfig(writeConfig(t, cfg)); err == nil {
		t.Fatalf("expected an error for an invalid recording.mode")
	}
}

func TestLoadConfigRecordingRejectsInvalidFailurePolicy(t *testing.T) {
	cfg := validConfig + "  recording:\n    failure_policy: retry_forever\n"
	if _, err := LoadConfig(writeConfig(t, cfg)); err == nil {
		t.Fatalf("expected an error for an invalid recording.failure_policy")
	}
}

// TestLoadConfigSessionStoreURLRequiresTokenFile proves spec.md §28.2's
// ingest credential cannot be silently absent: a configured
// session_store_url with no session_store_ingest_token_file must fail
// config validation, not start a Gateway that would try to POST to the
// store with no Authorization header.
func TestLoadConfigSessionStoreURLRequiresTokenFile(t *testing.T) {
	cfg := validConfig + "  recording:\n    session_store_url: https://store.linker.internal:8443\n"
	if _, err := LoadConfig(writeConfig(t, cfg)); err == nil {
		t.Fatalf("expected an error when session_store_url is set without session_store_ingest_token_file")
	}
}

func TestLoadConfigSessionStoreFieldsRoundTrip(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "session-store.token")
	if err := os.WriteFile(tokenPath, []byte("ingest-token-abc\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	cfg := validConfig + "  recording:\n" +
		"    session_store_url: https://store.linker.internal:8443\n" +
		"    session_store_ingest_token_file: " + tokenPath + "\n" +
		"    session_store_ca_file: /etc/ipa/ca.crt\n"
	loaded, err := LoadConfig(writeConfig(t, cfg))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if loaded.sessionStoreURL() != "https://store.linker.internal:8443" {
		t.Fatalf("sessionStoreURL() = %q", loaded.sessionStoreURL())
	}
	if loaded.sessionStoreCAFile() != "/etc/ipa/ca.crt" {
		t.Fatalf("sessionStoreCAFile() = %q", loaded.sessionStoreCAFile())
	}
	token, err := loadSessionStoreIngestToken(loaded.Gateway.Recording.SessionStoreIngestTokenFile)
	if err != nil {
		t.Fatalf("loadSessionStoreIngestToken: %v", err)
	}
	if token != "ingest-token-abc" {
		t.Fatalf("loadSessionStoreIngestToken = %q, want %q", token, "ingest-token-abc")
	}
}

func TestLoadSessionStoreIngestTokenRejectsWorldReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	if _, err := loadSessionStoreIngestToken(path); err == nil {
		t.Fatalf("loadSessionStoreIngestToken accepted a mode-0644 file, want an error")
	}
}

// TestLoadConfigTransport is captive-transport spec AG59: a config without
// a transport: block (every config written before the feature) loads with
// transport disabled, enabled: true round-trips, and an unknown key under
// transport: is rejected like any other unknown field.
func TestLoadConfigTransport(t *testing.T) {
	cfg, err := LoadConfig(writeConfig(t, validConfig))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Gateway.Transport.Enabled {
		t.Fatalf("transport must default to disabled when the block is absent")
	}
	cfg, err = LoadConfig(writeConfig(t, validConfig+"  transport:\n    enabled: true\n"))
	if err != nil {
		t.Fatalf("LoadConfig(enabled): %v", err)
	}
	if !cfg.Gateway.Transport.Enabled {
		t.Fatalf("transport.enabled: true did not round-trip")
	}
	if _, err := LoadConfig(writeConfig(t, validConfig+"  transport:\n    enabled: true\n    port: 2222\n")); err == nil {
		t.Fatalf("expected an unknown transport field (port) to be rejected")
	}
}
