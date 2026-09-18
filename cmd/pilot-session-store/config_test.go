package main

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTestConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "session-store.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write test config: %v", err)
	}
	return path
}

const validConfigYAML = `
ingest:
  listen_addr: "127.0.0.1:8443"
  tls_cert_file: /etc/pilot/session-store-tls.crt
  tls_key_file: /etc/pilot/session-store-tls.key
  token_file: /etc/pilot/session-store-ingest.token
storage:
  index_db_path: /var/lib/pilot-session-store/index.db
  master_key_file: /etc/pilot/session-store-master.key
  key_id: key-2026-09
read:
  socket_path: /run/pilot/session-store.sock
  auditor_group: role-pilot-session-auditor
retention:
  retention_days: 90
`

func TestLoadConfigValid(t *testing.T) {
	cfg, err := LoadConfig(writeTestConfig(t, validConfigYAML))
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.Ingest.ListenAddr != "127.0.0.1:8443" {
		t.Errorf("Ingest.ListenAddr = %q", cfg.Ingest.ListenAddr)
	}
	if cfg.retentionPeriod().Hours() != 90*24 {
		t.Errorf("retentionPeriod() = %v, want 90 days", cfg.retentionPeriod())
	}
	if cfg.readSocketPath() != "/run/pilot/session-store.sock" {
		t.Errorf("readSocketPath() = %q", cfg.readSocketPath())
	}
}

func TestLoadConfigRejectsUnknownField(t *testing.T) {
	_, err := LoadConfig(writeTestConfig(t, validConfigYAML+"\nunknown_field: true\n"))
	if err == nil {
		t.Fatalf("LoadConfig accepted an unknown top-level field, want an error (KnownFields(true))")
	}
}

func TestLoadConfigRequiresRetentionDays(t *testing.T) {
	const missingRetention = `
ingest:
  listen_addr: "127.0.0.1:8443"
  tls_cert_file: /etc/pilot/session-store-tls.crt
  tls_key_file: /etc/pilot/session-store-tls.key
  token_file: /etc/pilot/session-store-ingest.token
storage:
  index_db_path: /var/lib/pilot-session-store/index.db
  master_key_file: /etc/pilot/session-store-master.key
  key_id: key-2026-09
`
	_, err := LoadConfig(writeTestConfig(t, missingRetention))
	if err == nil {
		t.Fatalf("LoadConfig accepted a config with no retention.retention_days, want an error (spec.md §28.5 forbids an implicit default)")
	}
}

func TestLoadIngestTokenRejectsWorldReadable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("secret-token"), 0o644); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	if _, err := loadIngestToken(path); err == nil {
		t.Fatalf("loadIngestToken accepted a mode-0644 token file, want an error")
	}
}

func TestLoadIngestTokenReadsTrimmedValue(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(path, []byte("secret-token\n"), 0o600); err != nil {
		t.Fatalf("write token file: %v", err)
	}
	token, err := loadIngestToken(path)
	if err != nil {
		t.Fatalf("loadIngestToken: %v", err)
	}
	if token != "secret-token" {
		t.Fatalf("loadIngestToken = %q, want %q", token, "secret-token")
	}
}
