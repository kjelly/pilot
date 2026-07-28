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
	want := []string{"freeipa", "keycloak-admin", "keycloak-db", "restic-backup", "thanos-s3", "alertmanager"}
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
	if len(section.Keys) != 1 || section.Keys[0].Name != "alertmanager_config" {
		t.Fatalf("alertmanager fields = %+v, want one alertmanager_config field", section.Keys)
	}
	if !section.Keys[0].Optional {
		t.Fatal("alertmanager_config must be optional so the apply playbook default can be used")
	}
	for _, key := range ExpectedVaultKeysForRoles([]string{"alertmanager"}) {
		if key == "alertmanager_config" {
			t.Fatalf("alertmanager_config must not be a required vault key")
		}
	}
	config := section.Keys[0].Value
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
