package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/vaultfile"
)

func TestBackfillVaultSkeletonKeys_AddsMissingRoleKeysWithoutOverwriting(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hosts.yml"), []byte(`hosts:
  core:
    roles: [dashboard, restic-backup, prometheus]
`), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, err := vaultfile.Parse([]byte("---\ngrafana_admin_password: existing\n"))
	if err != nil {
		t.Fatal(err)
	}

	added := backfillVaultSkeletonKeys(dir, doc)
	for _, key := range []string{
		"restic_aws_access_key_id",
		"restic_aws_secret_access_key",
		"restic_password",
		"thanos_aws_access_key_id",
		"thanos_aws_secret_access_key",
	} {
		if !containsString(added, key) {
			t.Errorf("added keys = %v, missing %q", added, key)
		}
		if !doc.HasKey(key) {
			t.Errorf("backfilled document missing %q", key)
		}
	}
	if got := doc.Entries()[0].DisplayValue(); got != "existing" {
		t.Fatalf("existing grafana_admin_password = %q, want existing", got)
	}
	if strings.Contains(string(doc.Bytes()), "CHANGE-ME-grafana-admin") {
		t.Fatal("existing grafana_admin_password was overwritten by skeleton value")
	}
}

func TestBackfillVaultSkeletonKeys_InvalidHostsIsBestEffort(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hosts.yml"), []byte("hosts: [broken\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, err := vaultfile.Parse([]byte("---\nfoo: bar\n"))
	if err != nil {
		t.Fatal(err)
	}
	if added := backfillVaultSkeletonKeys(dir, doc); len(added) != 0 {
		t.Fatalf("added keys = %v, want none for invalid hosts.yml", added)
	}
}

func TestDisplayVaultValue_MasksConfiguredValues(t *testing.T) {
	if got := displayVaultValue("Aa@real-secret", 80); got != "<已設定>" {
		t.Fatalf("displayVaultValue(real secret) = %q, want masked value", got)
	}
	if got := displayVaultValue("CHANGE-ME-restic-password", 80); got != "CHANGE-ME-restic-password" {
		t.Fatalf("displayVaultValue(placeholder) = %q, want placeholder", got)
	}
	if got := displayVaultValue("", 80); got != "<未設定>" {
		t.Fatalf("displayVaultValue(empty) = %q, want unset marker", got)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
