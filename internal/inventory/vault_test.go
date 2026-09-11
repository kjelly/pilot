package inventory

import (
	"strings"
	"testing"
)

func TestVaultSectionIDs_DedupesAndOrdersSections(t *testing.T) {
	hf := &HostsFile{Hosts: []Host{
		{Name: "ipa-1", Roles: []string{"freeipa-server", "keycloak", "restic-backup"}},
		{Name: "web-1", Roles: []string{"freeipa-client", "keycloak-db", "prometheus", "alertmanager"}},
	}}

	got := VaultSectionIDs(hf)
	want := []string{"freeipa", "keycloak-admin", "keycloak-db", "restic-backup", "thanos-s3", "node-exporter-auth", "alertmanager"}
	if len(got) != len(want) {
		t.Fatalf("VaultSectionIDs() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("VaultSectionIDs() = %v, want %v", got, want)
		}
	}
}

func TestGenerateVaultSkeleton_IncludesRelevantKeysOnly(t *testing.T) {
	hf := &HostsFile{Hosts: []Host{
		{Name: "ipa-1", Roles: []string{"freeipa-server", "dashboard", "alertmanager"}},
	}}

	got := GenerateVaultSkeleton(hf)
	for _, want := range []string{
		"ipa_admin_password:",
		"# ipa_dm_password:",
		"grafana_admin_password:",
		"# alertmanager_receiver_mode:",
		"# alertmanager_teams_webhook_url:",
		"alertmanager_config: |",
		"Roles seen: freeipa-server, alertmanager, dashboard",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("GenerateVaultSkeleton() missing %q:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{
		"restic_password:",
		"thanos_aws_access_key_id:",
		"pg_keycloak_db_password:",
	} {
		if strings.Contains(got, unwanted) {
			t.Fatalf("GenerateVaultSkeleton() unexpectedly included %q:\n%s", unwanted, got)
		}
	}
}

func TestGenerateVaultSkeleton_NoVaultRolesReturnsEmpty(t *testing.T) {
	hf := &HostsFile{Hosts: []Host{{Name: "web-1", Roles: []string{"linux-servers", "audit-log-forwarding"}}}}
	if got := GenerateVaultSkeleton(hf); got != "" {
		t.Fatalf("GenerateVaultSkeleton() = %q, want empty", got)
	}
}

func TestGenerateVaultSkeleton_SNMPUsesCredentialRefNestedMapExample(t *testing.T) {
	skeleton := GenerateVaultSkeleton(&HostsFile{Hosts: []Host{{Name: "monitor-1", Roles: []string{"snmp-exporter"}}}})
	for _, want := range []string{
		"credentialRef（不是 authProfile ID）",
		"# snmp_exporter_credentials:",
		"#   core-switch-v3:",
	} {
		if !strings.Contains(skeleton, want) {
			t.Fatalf("SNMP vault skeleton missing %q:\n%s", want, skeleton)
		}
	}
	if strings.Contains(skeleton, "# snmp_exporter_credentials: |") {
		t.Fatalf("SNMP credential skeleton must be a commented nested map, not a scalar block:\n%s", skeleton)
	}
}

func TestVaultSectionExpectedKeys_KnownSection(t *testing.T) {
	got := VaultSectionExpectedKeys("restic-backup")
	want := []string{
		"restic_aws_access_key_id",
		"restic_aws_secret_access_key",
		"restic_password",
	}
	if len(got) != len(want) {
		t.Fatalf("VaultSectionExpectedKeys() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("VaultSectionExpectedKeys() = %v, want %v", got, want)
		}
	}
}

func TestExpectedVaultKeysForRoles_ExcludesOptionalKeys(t *testing.T) {
	// ipa_dm_password is the freeipa section's one Optional key — it must
	// never appear in the completeness-check input, even though it does
	// appear (commented out) in GenerateVaultSkeleton's output. Regression
	// test for the round-16 bug where `pilot deploy`'s hard completeness
	// gate demanded a value for this key despite it being marked Optional.
	got := ExpectedVaultKeysForRoles([]string{"freeipa-server"})
	for _, key := range got {
		if key == "ipa_dm_password" {
			t.Fatalf("ExpectedVaultKeysForRoles(freeipa-server) = %v, must not include Optional key %q", got, key)
		}
	}
	found := false
	for _, key := range got {
		if key == "ipa_admin_password" {
			found = true
		}
	}
	if !found {
		t.Fatalf("ExpectedVaultKeysForRoles(freeipa-server) = %v, want required key %q present", got, "ipa_admin_password")
	}
}

// TestExpectedVaultKeysForRoles_DetectionModelProviderKeyIsOptional locks
// spec §41.1/§42.1's Stage B requirement: detection-model-provider's one
// key (detection_model_provider_api_key) must never be demanded by the
// completeness gate just because detection-engine is deployed — it is
// only actually required when the role's own apply-time gate sees
// enabled=true and auth=bearer (a runtime/group-vars concern the static
// vault-completeness check can't see), not merely "role selected".
func TestExpectedVaultKeysForRoles_DetectionModelProviderKeyIsOptional(t *testing.T) {
	got := ExpectedVaultKeysForRoles([]string{"detection-engine"})
	for _, key := range got {
		if key == "detection_model_provider_api_key" {
			t.Fatalf("ExpectedVaultKeysForRoles(detection-engine) = %v, must not require the Optional detection_model_provider_api_key", got)
		}
	}

	skeleton := GenerateVaultSkeleton(&HostsFile{Hosts: []Host{{Name: "detect-1", Roles: []string{"detection-engine"}}}})
	if !strings.Contains(skeleton, "# detection_model_provider_api_key:") {
		t.Fatalf("GenerateVaultSkeleton(detection-engine) must still offer detection_model_provider_api_key commented-out:\n%s", skeleton)
	}
}

func TestGenerateVaultSkeleton_ContainsExactlyExpectedKeysForRoles(t *testing.T) {
	roles := []string{"freeipa-server", "keycloak", "alertmanager"}
	hf := &HostsFile{Hosts: []Host{{Name: "node-1", Roles: roles}}}

	got := GenerateVaultSkeleton(hf)
	expected := ExpectedVaultKeysForRoles(roles)
	for _, key := range expected {
		if !strings.Contains(got, key+":") && !strings.Contains(got, "# "+key+":") {
			t.Fatalf("GenerateVaultSkeleton() missing expected key %q:\n%s", key, got)
		}
	}

	for _, key := range []string{
		"grafana_admin_password",
		"restic_password",
		"thanos_aws_access_key_id",
	} {
		if strings.Contains(got, key+":") || strings.Contains(got, "# "+key+":") {
			t.Fatalf("GenerateVaultSkeleton() unexpectedly included unrelated key %q:\n%s", key, got)
		}
	}
}

func TestAlertmanagerDefaultConfigIsMinimalAndOperational(t *testing.T) {
	section := vaultSections["alertmanager"]
	if len(section.Keys) != 3 {
		t.Fatalf("alertmanager fields = %+v, want mode, Teams webhook, and custom config", section.Keys)
	}
	keys := map[string]vaultField{}
	for _, key := range section.Keys {
		keys[key.Name] = key
	}
	for _, name := range []string{"alertmanager_receiver_mode", "alertmanager_teams_webhook_url", "alertmanager_config"} {
		if !keys[name].Optional {
			t.Fatalf("%s must be optional so legacy and null-receiver workspaces remain deployable", name)
		}
	}
	for _, key := range ExpectedVaultKeysForRoles([]string{"alertmanager"}) {
		if strings.HasPrefix(key, "alertmanager_") {
			t.Fatalf("%s must not be a required vault key", key)
		}
	}
	config := keys["alertmanager_config"].Value
	for _, required := range []string{
		"global:",
		"route:",
		"receiver: \"null\"",
		"receivers:",
		"- name: \"null\"",
	} {
		if !strings.Contains(config, required) {
			t.Errorf("default alertmanager config missing %q:\n%s", required, config)
		}
	}
}
