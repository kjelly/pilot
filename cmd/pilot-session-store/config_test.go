package main

import (
	"os"
	"path/filepath"
	"strings"
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
  signing_key_file: /etc/pilot/session-store-ingest-signing.key
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
  signing_key_file: /etc/pilot/session-store-ingest-signing.key
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

// TestLoadConfig_SigningKeyFile locks per-host recording spec §21.1: the
// static bearer token_file is gone (KnownFields rejects it) and the
// signing key file is required.
func TestLoadConfig_SigningKeyFile(t *testing.T) {
	cfg, err := LoadConfig(writeTestConfig(t, validConfigYAML))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Ingest.SigningKeyFile != "/etc/pilot/session-store-ingest-signing.key" {
		t.Fatalf("SigningKeyFile = %q", cfg.Ingest.SigningKeyFile)
	}
	legacy := strings.Replace(validConfigYAML, "signing_key_file:", "token_file:", 1)
	if _, err := LoadConfig(writeTestConfig(t, legacy)); err == nil {
		t.Fatal("LoadConfig accepted the removed ingest.token_file")
	}
	missing := strings.Replace(validConfigYAML, "  signing_key_file: /etc/pilot/session-store-ingest-signing.key\n", "", 1)
	if _, err := LoadConfig(writeTestConfig(t, missing)); err == nil || !strings.Contains(err.Error(), "ingest.signing_key_file") {
		t.Fatalf("LoadConfig without signing_key_file = %v, want it reported missing", err)
	}
}

func TestLoadConfig_MetricsTextfilePath(t *testing.T) {
	for path, ok := range map[string]bool{
		"/var/lib/node_exporter/textfile/pilot_session_store.prom": true,
		"relative.prom":                         false,
		"/var/lib/node_exporter/textfile/x.txt": false,
	} {
		cfg := Config{
			Ingest:    IngestSection{ListenAddr: ":8443", TLSCertFile: "/c", TLSKeyFile: "/k", SigningKeyFile: "/s"},
			Storage:   StorageSection{IndexDBPath: "/db", MasterKeyFile: "/m", KeyID: "k1"},
			Retention: RetentionSection{RetentionDays: 30},
			Metrics:   MetricsSection{TextfilePath: path},
		}
		if err := cfg.validate(); (err == nil) != ok {
			t.Errorf("textfile_path %q: validate = %v, want ok=%v", path, err, ok)
		}
	}
}
