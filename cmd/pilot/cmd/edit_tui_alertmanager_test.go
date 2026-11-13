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

// F10 (minimal-PoC five-node run): the screen read the vault only. A workspace built
// from the old skeleton carries a live alertmanager_config in group_vars, which the
// playbook applies as the legacy `custom` configuration, and the screen said "null".
// Each case follows the playbook's resolution rules.
func TestAlertmanagerReceiverStatusFollowsThePlaybookResolution(t *testing.T) {
	const legacyGroupVars = "alertmanager_config: |\n  route:\n    receiver: 'null'\n"
	for _, tc := range []struct {
		name      string
		vault     string
		groupVars string // empty: no group_vars/alertmanager.yml at all
		want      string
	}{
		{"nothing anywhere", "---\n", "", "null"},
		{"comment-only group_vars (the current skeleton)", "---\n", "---\n# alertmanager_config: |\n#   ...\n", "null"},
		{"live config in group_vars only", "---\n", legacyGroupVars, "custom（legacy，來自 group_vars/alertmanager.yml）"},
		{"live config in the vault only", "alertmanager_config: |\n  route:\n    receiver: x\n", "---\n", "custom（legacy）"},
		{"an empty config in group_vars says nothing", "---\n", "alertmanager_config: \"\"\n", "null"},
		{"explicit null beats a live group_vars config", "alertmanager_receiver_mode: null\n", legacyGroupVars, "null"},
		{"explicit null beats a leftover vault config", "alertmanager_receiver_mode: \"null\"\nalertmanager_config: |\n  route:\n    receiver: x\n", "---\n", "null"},
		{"mode from group_vars", "---\n", "alertmanager_receiver_mode: Teams\n", "teams"},
		{"the vault mode beats the group_vars mode", "alertmanager_receiver_mode: custom\n", "alertmanager_receiver_mode: teams\n", "custom"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if tc.groupVars != "" {
				if err := os.MkdirAll(filepath.Join(dir, "group_vars"), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, "group_vars", "alertmanager.yml"), []byte(tc.groupVars), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			doc, err := vaultfile.Parse([]byte(tc.vault))
			if err != nil {
				t.Fatal(err)
			}
			if got := alertmanagerReceiverStatusIn(doc, readAlertmanagerGroupVars(dir)); got != tc.want {
				t.Fatalf("status = %q, want %q", got, tc.want)
			}
		})
	}
}
