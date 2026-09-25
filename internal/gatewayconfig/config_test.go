package gatewayconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "access-gateway.yaml")
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

const storeRecording = "  recording:\n" +
	"    session_store_url: https://store.linker.internal:8443\n" +
	"    session_store_ingest_signing_key_file: /etc/pilot/session-store-ingest-signing.key\n" +
	"    session_store_ca_file: /etc/ipa/ca.crt\n"

func TestLoadConfigValid(t *testing.T) {
	cfg, err := Load(writeConfig(t, validConfig))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Gateway.ID != "gpu-01" || cfg.Gateway.Scope != "gpu" || cfg.Gateway.TargetHostgroup != "pilot-target-gpu" {
		t.Fatalf("Gateway = %+v", cfg.Gateway)
	}
	if len(cfg.Gateway.FreeIPA.Servers) != 2 {
		t.Fatalf("Servers = %v", cfg.Gateway.FreeIPA.Servers)
	}
	if cfg.RequestTimeout() != 5*time.Second {
		t.Fatalf("RequestTimeout = %v, want 5s", cfg.RequestTimeout())
	}
	if cfg.SocketPath() != "/run/pilot/access-gateway.sock" {
		t.Fatalf("SocketPath() = %q", cfg.SocketPath())
	}
}

func TestLoadConfigMissingRequiredFields(t *testing.T) {
	if _, err := Load(writeConfig(t, "gateway:\n  id: gpu-01\n")); err == nil {
		t.Fatal("expected an error for missing required fields")
	}
}

// TestLoadConfigRejectsForbiddenFields enforces spec.md §26's hard rule:
// roster_file/inventory_file/vault_password_file/state_dir/audit_db must
// never appear in this config.
func TestLoadConfigRejectsForbiddenFields(t *testing.T) {
	if _, err := Load(writeConfig(t, validConfig+"  roster_file: /some/roster.yaml\n")); err == nil {
		t.Fatal("expected an error for an unknown field (roster_file)")
	}
}

// TestLoadConfig_RecordingDefaults locks per-host recording spec §14: with
// nothing configured the mode stays unset (built-in metadata), the failure
// policy defaults to fail_closed, and the grace/lifetime defaults apply.
func TestLoadConfig_RecordingDefaults(t *testing.T) {
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
	cfg, err := Load(writeConfig(t, minimal))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.SocketPath() != DefaultSocketPath || cfg.RequestTimeout() != DefaultRequestTimeout {
		t.Fatalf("socket/timeout defaults = %q/%v", cfg.SocketPath(), cfg.RequestTimeout())
	}
	if cfg.RecordingDefaultModeRaw() != "" {
		t.Fatalf("RecordingDefaultModeRaw() = %q, want the unset raw value", cfg.RecordingDefaultModeRaw())
	}
	if cfg.RecordingFailurePolicy() != "fail_closed" {
		t.Fatalf("RecordingFailurePolicy() = %q, want fail_closed", cfg.RecordingFailurePolicy())
	}
	if cfg.RecordingQueueEvents() != 1024 || cfg.RecordingFlushInterval() != 500*time.Millisecond {
		t.Fatalf("queue/flush defaults = %d/%v", cfg.RecordingQueueEvents(), cfg.RecordingFlushInterval())
	}
	if cfg.RecordingFailureGrace() != 10*time.Second || cfg.RecordingMaxSessionDuration() != 24*time.Hour {
		t.Fatalf("grace/lifetime defaults = %v/%v", cfg.RecordingFailureGrace(), cfg.RecordingMaxSessionDuration())
	}
}

func TestLoadConfig_RecordingValidValues(t *testing.T) {
	cfg := validConfig + storeRecording +
		"    mode: terminal_io\n    failure_policy: best_effort\n    queue_events: 256\n" +
		"    flush_interval: 250ms\n    failure_grace: 30s\n    max_session_duration: 12h\n"
	loaded, err := Load(writeConfig(t, cfg))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if loaded.RecordingDefaultModeRaw() != "terminal_io" || loaded.RecordingFailurePolicy() != "best_effort" || loaded.RecordingQueueEvents() != 256 {
		t.Fatalf("recording = %+v", loaded.Gateway.Recording)
	}
	if loaded.RecordingFlushInterval() != 250*time.Millisecond || loaded.RecordingFailureGrace() != 30*time.Second || loaded.RecordingMaxSessionDuration() != 12*time.Hour {
		t.Fatalf("durations = %v %v %v", loaded.RecordingFlushInterval(), loaded.RecordingFailureGrace(), loaded.RecordingMaxSessionDuration())
	}
	if loaded.Gateway.Recording.SessionStoreIngestSigningKeyFile != "/etc/pilot/session-store-ingest-signing.key" {
		t.Fatalf("signing key file = %q", loaded.Gateway.Recording.SessionStoreIngestSigningKeyFile)
	}
}

func TestLoadConfig_RecordingRejects(t *testing.T) {
	cases := map[string]struct {
		body string
		want string
	}{
		"invalid mode":           {validConfig + "  recording:\n    mode: full_video\n", "gateway.recording.mode"},
		"invalid failure policy": {validConfig + "  recording:\n    failure_policy: retry_forever\n", "failure_policy"},
		"grace below 1s":         {validConfig + "  recording:\n    failure_grace: 500ms\n    flush_interval: 100ms\n", "failure_grace"},
		"grace below 2x flush":   {validConfig + "  recording:\n    failure_grace: 2s\n    flush_interval: 1500ms\n", "failure_grace"},
		"lifetime too short":     {validConfig + "  recording:\n    max_session_duration: 30m\n", "max_session_duration"},
		"lifetime too long":      {validConfig + "  recording:\n    max_session_duration: 200h\n", "max_session_duration"},
		"store url not https":    {validConfig + "  recording:\n    session_store_url: http://store:8443\n    session_store_ingest_signing_key_file: /k\n", "https://"},
		"store without key":      {validConfig + "  recording:\n    session_store_url: https://store:8443\n", "session_store_ingest_signing_key_file"},
		"terminal without store": {validConfig + "  recording:\n    mode: terminal_output\n", "no local recording fallback"},
		"legacy token file":      {validConfig + "  recording:\n    session_store_url: https://store:8443\n    session_store_ingest_token_file: /t\n", "replaced by session_store_ingest_signing_key_file"},
		"relative metrics path":  {validConfig + "  metrics:\n    textfile_path: gateway.prom\n", "gateway.metrics.textfile_path"},
		"metrics path not .prom": {validConfig + "  metrics:\n    textfile_path: /var/lib/node_exporter/textfile/gw.txt\n", "gateway.metrics.textfile_path"},
	}
	for name, c := range cases {
		_, err := Load(writeConfig(t, c.body))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: Load = %v, want an error mentioning %q", name, err, c.want)
		}
	}
}

// TestLoadConfig_RecordingSigningKey locks the key file contract: no store
// means no key is read; a configured store needs a 64-hex-character key
// file that is not group/world accessible.
func TestLoadConfig_RecordingSigningKey(t *testing.T) {
	cfg, err := Load(writeConfig(t, validConfig))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if key, err := cfg.RecordingSigningKey(); key != nil || err != nil {
		t.Fatalf("no store: RecordingSigningKey = %v, %v; want nil, nil", key, err)
	}

	dir := t.TempDir()
	keyFile := func(name, body string, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		return path
	}
	withKey := func(path string) Config {
		body := validConfig + "  recording:\n    session_store_url: https://store.linker.internal:8443\n" +
			"    session_store_ingest_signing_key_file: " + path + "\n"
		c, err := Load(writeConfig(t, body))
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		return c
	}
	hexKey := strings.Repeat("ab", 32)

	if key, err := withKey(keyFile("good.key", hexKey+"\n", 0o400)).RecordingSigningKey(); err != nil || len(key) != 32 {
		t.Fatalf("good key = %d bytes, %v", len(key), err)
	}
	rejects := map[string]string{
		"group readable": keyFile("loose.key", hexKey, 0o440),
		"too short":      keyFile("short.key", hexKey[:62], 0o400),
		"not hex":        keyFile("nothex.key", strings.Repeat("zz", 32), 0o400),
		"missing":        filepath.Join(dir, "absent.key"),
	}
	for name, path := range rejects {
		if _, err := withKey(path).RecordingSigningKey(); err == nil {
			t.Errorf("%s: RecordingSigningKey accepted %s", name, path)
		}
	}
}

func TestLoadConfig_MetricsTextfilePath(t *testing.T) {
	cfg, err := Load(writeConfig(t, validConfig))
	if err != nil || cfg.MetricsTextfilePath() != "" {
		t.Fatalf("default metrics path = %q, %v; want disabled", cfg.MetricsTextfilePath(), err)
	}
	cfg, err = Load(writeConfig(t, validConfig+"  metrics:\n    textfile_path: /var/lib/node_exporter/textfile/pilot_access_gateway.prom\n"))
	if err != nil || cfg.MetricsTextfilePath() != "/var/lib/node_exporter/textfile/pilot_access_gateway.prom" {
		t.Fatalf("metrics path = %q, %v", cfg.MetricsTextfilePath(), err)
	}
}

// TestLoadConfigTransport is captive-transport spec AG59: a config without
// a transport: block (every config written before the feature) loads with
// transport disabled, enabled: true round-trips, and an unknown key under
// transport: is rejected like any other unknown field.
func TestLoadConfigTransport(t *testing.T) {
	cfg, err := Load(writeConfig(t, validConfig))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Gateway.Transport.Enabled {
		t.Fatalf("transport must default to disabled when the block is absent")
	}
	cfg, err = Load(writeConfig(t, validConfig+"  transport:\n    enabled: true\n"))
	if err != nil {
		t.Fatalf("Load(enabled): %v", err)
	}
	if !cfg.Gateway.Transport.Enabled {
		t.Fatalf("transport.enabled: true did not round-trip")
	}
	if _, err := Load(writeConfig(t, validConfig+"  transport:\n    enabled: true\n    port: 2222\n")); err == nil {
		t.Fatalf("expected an unknown transport field (port) to be rejected")
	}
}
