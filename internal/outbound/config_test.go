package outbound

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// validConfigYAML is a fully valid, minimal integrations.yaml — every
// CFG negative test starts from a variant of this and breaks exactly one
// thing, so a failure always isolates to the field under test.
const validConfigYAML = `
schema_version: 1
source_id: linker-infra-prod
webhooks:
  - name: external-user-host-directory
    enabled: true
    endpoint: https://other-team.example.com/api/v1/pilot/events
    projection: user_host_access_v1
    events:
      - operation: deploy
        result: success
        payload: snapshot
      - operation: reconcile
        result: success
        effects_any:
          - identity.*
          - access.hbac
        payload: both
    auth:
      type: hmac_sha256
      secret_env: PILOT_EXTERNAL_DIRECTORY_WEBHOOK_SECRET
`

// TestOutboundConfig_CFG1 (design spec §46.1 CFG1): a missing
// integrations.yaml means outbound publishing is disabled, with no
// error.
func TestOutboundConfig_CFG1(t *testing.T) {
	dir := t.TempDir()
	cfg, err := LoadConfigFile(DefaultConfigPath(dir))
	if err != nil {
		t.Fatalf("LoadConfigFile: %v", err)
	}
	if cfg != nil {
		t.Fatalf("expected nil config for missing file, got %+v", cfg)
	}
}

// TestOutboundConfig_CFG2 (CFG2): an unknown field anywhere is rejected.
func TestOutboundConfig_CFG2(t *testing.T) {
	bad := strings.Replace(validConfigYAML, "schema_version: 1", "schema_version: 1\nunknown_top_level_field: true", 1)
	if _, err := ParseConfig([]byte(bad)); err == nil {
		t.Fatal("expected error for unknown top-level field")
	}

	badNested := strings.Replace(validConfigYAML, "enabled: true", "enabled: true\n    bogus_field: 1", 1)
	if _, err := ParseConfig([]byte(badNested)); err == nil {
		t.Fatal("expected error for unknown nested field")
	}
}

// TestOutboundConfig_CFG3 (CFG3): an invalid payload value is rejected.
func TestOutboundConfig_CFG3(t *testing.T) {
	bad := strings.Replace(validConfigYAML, "payload: snapshot", "payload: snapshots", 1)
	if _, err := ParseConfig([]byte(bad)); err == nil {
		t.Fatal("expected error for invalid payload value")
	}
}

// TestOutboundConfig_CFG4 (CFG4): a duplicate (operation, result) pair on
// one webhook is rejected.
func TestOutboundConfig_CFG4(t *testing.T) {
	bad := strings.Replace(validConfigYAML,
		"      - operation: reconcile\n        result: success",
		"      - operation: deploy\n        result: success",
		1)
	_, err := ParseConfig([]byte(bad))
	if err == nil {
		t.Fatal("expected error for duplicate (deploy, success) event rule")
	}
	if !strings.Contains(err.Error(), "duplicate event rule") {
		t.Fatalf("error = %v, want mention of duplicate event rule", err)
	}
}

// TestOutboundConfig_CFG5 (CFG5): an invalid effect wildcard is rejected
// — arbitrary glob and a namespace that matches no known effect.
func TestOutboundConfig_CFG5(t *testing.T) {
	cases := []string{"*", "identity.**", "bogus_namespace.*"}
	for _, wildcard := range cases {
		bad := strings.Replace(validConfigYAML, "- identity.*", "- "+wildcard, 1)
		if _, err := ParseConfig([]byte(bad)); err == nil {
			t.Errorf("wildcard %q: expected error, got nil", wildcard)
		}
	}
}

// TestOutboundConfig_CFG6 (CFG6): an unknown exact effect is rejected.
func TestOutboundConfig_CFG6(t *testing.T) {
	bad := strings.Replace(validConfigYAML, "- access.hbac", "- freeipa-identity", 1)
	_, err := ParseConfig([]byte(bad))
	if err == nil {
		t.Fatal("expected error for unknown exact effect")
	}
	if !strings.Contains(err.Error(), "unknown effect") {
		t.Fatalf("error = %v, want mention of unknown effect", err)
	}
}

// TestOutboundConfig_CFG7 (CFG7): duplicate webhook names are rejected.
func TestOutboundConfig_CFG7(t *testing.T) {
	second := strings.TrimPrefix(validConfigYAML, "\nschema_version: 1\nsource_id: linker-infra-prod\nwebhooks:\n")
	bad := validConfigYAML + "  " + strings.TrimSpace(second)
	// second copy keeps the same "name: external-user-host-directory".
	_, err := ParseConfig([]byte(bad))
	if err == nil {
		t.Fatal("expected error for duplicate webhook name")
	}
	if !strings.Contains(err.Error(), "duplicate webhook name") {
		t.Fatalf("error = %v, want mention of duplicate webhook name", err)
	}
}

// TestOutboundConfig_CFG8 (CFG8): plain http without explicit opt-in is
// rejected; with allow_insecure_http:true it is accepted.
func TestOutboundConfig_CFG8(t *testing.T) {
	badHTTP := strings.Replace(validConfigYAML, "https://other-team.example.com", "http://other-team.example.com", 1)
	if _, err := ParseConfig([]byte(badHTTP)); err == nil {
		t.Fatal("expected error for http endpoint without allow_insecure_http")
	}

	okHTTP := strings.Replace(badHTTP, "secret_env: PILOT_EXTERNAL_DIRECTORY_WEBHOOK_SECRET",
		"secret_env: PILOT_EXTERNAL_DIRECTORY_WEBHOOK_SECRET\n    tls:\n      allow_insecure_http: true", 1)
	if _, err := ParseConfig([]byte(okHTTP)); err != nil {
		t.Fatalf("http with allow_insecure_http:true should be valid: %v", err)
	}

	okHTTPS := strings.Replace(validConfigYAML, "secret_env: PILOT_EXTERNAL_DIRECTORY_WEBHOOK_SECRET",
		"secret_env: PILOT_EXTERNAL_DIRECTORY_WEBHOOK_SECRET\n    tls:\n      allow_insecure_https: true", 1)
	cfg, err := ParseConfig([]byte(okHTTPS))
	if err != nil {
		t.Fatalf("https with allow_insecure_https:true should be valid: %v", err)
	}
	if !cfg.Webhooks[0].TLS.AllowInsecureHTTPS {
		t.Fatal("allow_insecure_https was not retained in the parsed config")
	}
}

// TestOutboundConfig_CFG9 (CFG9): a secret value cannot be configured
// directly — only auth.secret_env or auth.secret_file is a known source;
// any literal-secret-shaped field is rejected as unknown.
func TestOutboundConfig_CFG9(t *testing.T) {
	bad := strings.Replace(validConfigYAML,
		"secret_env: PILOT_EXTERNAL_DIRECTORY_WEBHOOK_SECRET",
		"secret_env: PILOT_EXTERNAL_DIRECTORY_WEBHOOK_SECRET\n      secret: literal-value-not-allowed", 1)
	if _, err := ParseConfig([]byte(bad)); err == nil {
		t.Fatal("expected error for a literal auth.secret field")
	}
}

// TestOutboundConfig_CFG10 (CFG10): auth is required and strict — a
// missing type/secret source, or an invalid type, is rejected.
func TestOutboundConfig_CFG10(t *testing.T) {
	badType := strings.Replace(validConfigYAML, "type: hmac_sha256", "type: none", 1)
	if _, err := ParseConfig([]byte(badType)); err == nil {
		t.Fatal("expected error for invalid auth.type")
	}

	badSecretEnv := strings.Replace(validConfigYAML, "secret_env: PILOT_EXTERNAL_DIRECTORY_WEBHOOK_SECRET", "secret_env: lowercase-not-allowed", 1)
	if _, err := ParseConfig([]byte(badSecretEnv)); err == nil {
		t.Fatal("expected error for invalid auth.secret_env format")
	}

	missingSource := strings.Replace(validConfigYAML,
		"      secret_env: PILOT_EXTERNAL_DIRECTORY_WEBHOOK_SECRET\n", "", 1)
	if _, err := ParseConfig([]byte(missingSource)); err == nil {
		t.Fatal("expected error when auth has no secret source")
	}

	bothSources := strings.Replace(validConfigYAML,
		"      secret_env: PILOT_EXTERNAL_DIRECTORY_WEBHOOK_SECRET",
		"      secret_env: PILOT_EXTERNAL_DIRECTORY_WEBHOOK_SECRET\n      secret_file: /tmp/webhook-token", 1)
	if _, err := ParseConfig([]byte(bothSources)); err == nil {
		t.Fatal("expected error when auth has both secret sources")
	}
}

func TestOutboundConfig_AuthSecretFile(t *testing.T) {
	fileSource := strings.Replace(validConfigYAML,
		"      secret_env: PILOT_EXTERNAL_DIRECTORY_WEBHOOK_SECRET",
		"      secret_file: /tmp/webhook-token", 1)
	cfg, err := ParseConfig([]byte(fileSource))
	if err != nil {
		t.Fatalf("auth.secret_file should be valid: %v", err)
	}
	if got := cfg.Webhooks[0].Auth.SecretFile; got != "/tmp/webhook-token" {
		t.Fatalf("secret_file = %q, want /tmp/webhook-token", got)
	}
	if got := cfg.Webhooks[0].Auth.SecretEnv; got != "" {
		t.Fatalf("secret_env = %q, want empty for file source", got)
	}

	relative := strings.Replace(fileSource, "/tmp/webhook-token", "relative/webhook-token", 1)
	if _, err := ParseConfig([]byte(relative)); err == nil {
		t.Fatal("expected error for non-absolute auth.secret_file")
	}
}

// TestOutboundConfig_CFG11 (CFG11): endpoint userinfo/query/fragment and
// an invalid source_id are all rejected.
func TestOutboundConfig_CFG11(t *testing.T) {
	userinfo := strings.Replace(validConfigYAML, "https://other-team.example.com", "https://user:pass@other-team.example.com", 1)
	if _, err := ParseConfig([]byte(userinfo)); err == nil {
		t.Fatal("expected error for endpoint userinfo")
	}

	query := strings.Replace(validConfigYAML, "/api/v1/pilot/events", "/api/v1/pilot/events?token=abc", 1)
	if _, err := ParseConfig([]byte(query)); err == nil {
		t.Fatal("expected error for endpoint query string")
	}

	fragment := strings.Replace(validConfigYAML, "/api/v1/pilot/events", "/api/v1/pilot/events#frag", 1)
	if _, err := ParseConfig([]byte(fragment)); err == nil {
		t.Fatal("expected error for endpoint fragment")
	}

	badSource := strings.Replace(validConfigYAML, "source_id: linker-infra-prod", "source_id: ' has spaces'", 1)
	if _, err := ParseConfig([]byte(badSource)); err == nil {
		t.Fatal("expected error for invalid source_id")
	}
}

// TestOutboundConfig_CFG12 (CFG12): delivery defaults are applied exactly
// when omitted, and out-of-bounds values are rejected.
func TestOutboundConfig_CFG12(t *testing.T) {
	cfg, err := ParseConfig([]byte(validConfigYAML))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	got := cfg.Webhooks[0].Delivery
	want := DeliveryConfig{
		Timeout:        DefaultDeliveryTimeout,
		MaxAttempts:    DefaultDeliveryMaxAttempts,
		InitialBackoff: DefaultDeliveryInitialBackoff,
		MaxBackoff:     DefaultDeliveryMaxBackoff,
	}
	if got != want {
		t.Fatalf("delivery defaults = %+v, want %+v", got, want)
	}

	cases := []string{
		"    delivery:\n      timeout: 50ms\n",                                // below min
		"    delivery:\n      timeout: 31s\n",                                 // above max
		"    delivery:\n      max_attempts: 0\n",                              // below min
		"    delivery:\n      max_attempts: 101\n",                            // above max
		"    delivery:\n      initial_backoff: 500ms\n",                       // below min
		"    delivery:\n      initial_backoff: 30s\n      max_backoff: 10s\n", // max < initial
	}
	for _, extra := range cases {
		bad := strings.Replace(validConfigYAML, "    auth:", extra+"    auth:", 1)
		if _, err := ParseConfig([]byte(bad)); err == nil {
			t.Errorf("delivery override %q: expected error, got nil", strings.TrimSpace(extra))
		}
	}
}

// TestOutboundConfig_CFG13 (CFG13): a non-absolute ca_file fails
// Validate(); an absolute-but-unreadable ca_file fails CheckReadiness().
func TestOutboundConfig_CFG13(t *testing.T) {
	relative := strings.Replace(validConfigYAML, "    auth:", "    tls:\n      ca_file: relative/path.pem\n    auth:", 1)
	if _, err := ParseConfig([]byte(relative)); err == nil {
		t.Fatal("expected error for non-absolute tls.ca_file")
	}

	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist.pem")
	absMissing := strings.Replace(validConfigYAML, "    auth:", "    tls:\n      ca_file: "+missing+"\n    auth:", 1)
	cfg, err := ParseConfig([]byte(absMissing))
	if err != nil {
		t.Fatalf("ParseConfig (schema-valid, absolute path): %v", err)
	}
	if err := cfg.CheckReadiness(); err == nil {
		t.Fatal("expected CheckReadiness error for missing ca_file")
	}

	notPEM := filepath.Join(dir, "not-a-cert.pem")
	if err := os.WriteFile(notPEM, []byte("not a pem file"), 0o600); err != nil {
		t.Fatal(err)
	}
	badPEM := strings.Replace(validConfigYAML, "    auth:", "    tls:\n      ca_file: "+notPEM+"\n    auth:", 1)
	cfg2, err := ParseConfig([]byte(badPEM))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if err := cfg2.CheckReadiness(); err == nil {
		t.Fatal("expected CheckReadiness error for unparseable PEM")
	}

	// A disabled webhook's ca_file is never checked.
	disabled := strings.Replace(badPEM, "enabled: true", "enabled: false", 1)
	cfg3, err := ParseConfig([]byte(disabled))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	if err := cfg3.CheckReadiness(); err != nil {
		t.Fatalf("CheckReadiness must skip disabled webhooks: %v", err)
	}

	secretFile := filepath.Join(dir, "webhook-token")
	if err := os.WriteFile(secretFile, []byte("Bearer file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fileSource := strings.Replace(validConfigYAML,
		"      secret_env: PILOT_EXTERNAL_DIRECTORY_WEBHOOK_SECRET",
		"      secret_file: "+secretFile, 1)
	cfg4, err := ParseConfig([]byte(fileSource))
	if err != nil {
		t.Fatalf("ParseConfig with secret_file: %v", err)
	}
	if err := cfg4.CheckReadiness(); err != nil {
		t.Fatalf("CheckReadiness with readable secret_file: %v", err)
	}

	missingSecretFile := strings.Replace(fileSource, secretFile, filepath.Join(dir, "missing-token"), 1)
	cfg5, err := ParseConfig([]byte(missingSecretFile))
	if err != nil {
		t.Fatalf("ParseConfig with missing secret_file: %v", err)
	}
	if err := cfg5.CheckReadiness(); err == nil {
		t.Fatal("expected CheckReadiness error for missing secret_file")
	}
}

// TestOutboundConfig_CFG15 (CFG15): effects_any is rejected on a deploy
// rule and accepted on a reconcile rule.
func TestOutboundConfig_CFG15(t *testing.T) {
	badDeploy := strings.Replace(validConfigYAML,
		"      - operation: deploy\n        result: success\n        payload: snapshot",
		"      - operation: deploy\n        result: success\n        effects_any: [identity.*]\n        payload: snapshot",
		1)
	if _, err := ParseConfig([]byte(badDeploy)); err == nil {
		t.Fatal("expected error for effects_any on an operation=deploy rule")
	}

	if _, err := ParseConfig([]byte(validConfigYAML)); err != nil {
		t.Fatalf("reconcile rule with effects_any should be valid: %v", err)
	}
}

// TestOutboundConfig_CFG16 (CFG16): webhook count bounds are enforced,
// and a config where every webhook is explicitly disabled is still
// schema-valid (design spec §7.4: "所有entries都disabled時不產生新event",
// not a validation error).
func TestOutboundConfig_CFG16(t *testing.T) {
	zero := "schema_version: 1\nsource_id: linker-infra-prod\nwebhooks: []\n"
	if _, err := ParseConfig([]byte(zero)); err == nil {
		t.Fatal("expected error for zero webhooks")
	}

	allDisabled := strings.Replace(validConfigYAML, "enabled: true", "enabled: false", 1)
	cfg, err := ParseConfig([]byte(allDisabled))
	if err != nil {
		t.Fatalf("an all-disabled config must still be schema-valid: %v", err)
	}
	if cfg.Webhooks[0].Enabled {
		t.Fatal("expected webhook to be disabled")
	}

	var sb strings.Builder
	sb.WriteString("schema_version: 1\nsource_id: linker-infra-prod\nwebhooks:\n")
	for i := 0; i < 17; i++ {
		fmt.Fprintf(&sb, "  - name: webhook-%d\n    enabled: false\n    endpoint: https://example.com/hook\n    projection: user_host_access_v1\n", i)
		sb.WriteString("    events: [{operation: deploy, result: success, payload: snapshot}]\n")
		fmt.Fprintf(&sb, "    auth: {type: bearer, secret_env: TOKEN_%d}\n", i)
	}
	if _, err := ParseConfig([]byte(sb.String())); err == nil {
		t.Fatal("expected error for 17 webhooks (bound is 16)")
	}
}

// TestOutboundConfig_DurationParsing sanity-checks that a fully-specified
// delivery block round-trips to the exact durations/counts written.
func TestOutboundConfig_DurationParsing(t *testing.T) {
	withDelivery := strings.Replace(validConfigYAML, "    auth:",
		"    delivery:\n      timeout: 10s\n      max_attempts: 5\n      initial_backoff: 2s\n      max_backoff: 1h\n    auth:", 1)
	cfg, err := ParseConfig([]byte(withDelivery))
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	want := DeliveryConfig{Timeout: 10 * time.Second, MaxAttempts: 5, InitialBackoff: 2 * time.Second, MaxBackoff: time.Hour}
	if cfg.Webhooks[0].Delivery != want {
		t.Fatalf("delivery = %+v, want %+v", cfg.Webhooks[0].Delivery, want)
	}
}
