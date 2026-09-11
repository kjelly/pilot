package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/vaultfile"
)

func TestValidateAlertmanagerReceiver(t *testing.T) {
	for _, tt := range []struct {
		name    string
		mode    string
		value   string
		wantErr bool
	}{
		{"null", "null", "", false},
		{"teams HTTPS", "teams", "https://example.invalid/trigger?sig=redacted", false},
		{"teams HTTP rejected", "teams", "http://example.invalid", true},
		{"custom YAML", "custom", "route:\n  receiver: custom\nreceivers:\n  - name: custom", false},
		{"custom scalar rejected", "custom", "not-a-mapping", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAlertmanagerReceiver(tt.mode, tt.value)
			if (err != nil) != tt.wantErr {
				t.Fatalf("validateAlertmanagerReceiver(%q, ...) error = %v, wantErr=%t", tt.mode, err, tt.wantErr)
			}
		})
	}
}

func TestSaveAlertmanagerReceiverPreservesOtherVaultMappings(t *testing.T) {
	dir := t.TempDir()
	vaultDir := filepath.Join(dir, ".vault")
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(vaultDir, "main.yaml")
	if err := os.WriteFile(path, []byte("snmp_exporter_credentials:\n  router:\n    community: hidden\nipa_admin_password: preserved\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := saveAlertmanagerReceiver(dir, alertmanagerReceiverModeTeams, "https://example.invalid/trigger?sig=redacted"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "snmp_exporter_credentials:") {
		t.Fatalf("unrelated vault entries were not preserved:\n%s", data)
	}
	doc, err := vaultfile.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	values := map[string]string{}
	for _, entry := range doc.ScalarEntries() {
		values[entry.Key] = entry.Value.Value
	}
	if values["ipa_admin_password"] != "preserved" {
		t.Fatalf("unrelated scalar value = %q, want preserved", values["ipa_admin_password"])
	}
	if values[alertmanagerReceiverModeKey] != alertmanagerReceiverModeTeams {
		t.Fatalf("mode = %q, want teams", values[alertmanagerReceiverModeKey])
	}
	if values[alertmanagerTeamsWebhookURLKey] != "https://example.invalid/trigger?sig=redacted" {
		t.Fatal("Teams webhook value was not stored exactly")
	}
}

func TestAlertmanagerReceiverStatusTreatsLegacyConfigAsCustom(t *testing.T) {
	doc, err := vaultfile.Parse([]byte("alertmanager_config: |\n  route:\n    receiver: legacy\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := alertmanagerReceiverStatus(doc); got != "custom（legacy）" {
		t.Fatalf("status = %q, want legacy custom", got)
	}
}
