package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// thanos_s3_target_host is filled in here so tests exercising the
// pre-existing host_vars/roster checks don't also trip the either/or
// S3-target gate added alongside them (see TestValidateDeploymentCompleteness_
// ReportsMissingThanosS3EitherOr/ThanosS3SatisfiedViaOverriddenEndpoint for
// dedicated coverage of that gate itself, using their own inventory YAML).
const completenessInventoryYAML = `---
all:
  hosts:
    nexus:
      ansible_host: 10.0.0.1
      freeipa_roster_file: "%s"
      thanos_s3_target_host: 10.0.0.50
  children:
    prometheus:
      hosts:
        nexus:
    freeipa-nfs-server:
      hosts:
        nexus:
`

// completenessValidVault is a filled-in (no CHANGE-ME) .vault/main.yaml
// covering prometheus's thanos-s3 and node-exporter-auth vault sections —
// the only vault sections this file's fixture inventory's roles
// (prometheus, freeipa-nfs-server) imply — so tests exercising the
// pre-existing host_vars/roster checks don't also trip the vault
// completeness check added alongside them.
const completenessValidVault = `---
thanos_aws_access_key_id: "AKIAEXAMPLE1234567"
thanos_aws_secret_access_key: "s3cr3t-not-a-placeholder"
node_exporter_basic_auth_password: "not-a-placeholder-either"
`

func writeCompletenessFixture(t *testing.T, hostVarsContent, rosterContent, vaultContent string) (dir, inv string) {
	t.Helper()
	dir = t.TempDir()
	rosterPath := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(rosterPath, []byte(rosterContent), 0o600); err != nil {
		t.Fatalf("write roster: %v", err)
	}

	inv = filepath.Join(dir, "inventory.yml")
	invContent := strings.ReplaceAll(completenessInventoryYAML, "%s", rosterPath)
	if err := os.WriteFile(inv, []byte(invContent), 0o644); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	groupVarsDir := filepath.Join(dir, "group_vars")
	if err := os.MkdirAll(groupVarsDir, 0o755); err != nil {
		t.Fatalf("mkdir group_vars: %v", err)
	}
	if err := os.WriteFile(filepath.Join(groupVarsDir, "freeipa.yml"), []byte("freeipa_domain: ipa.pilot.internal\n"), 0o644); err != nil {
		t.Fatalf("write group_vars/freeipa.yml: %v", err)
	}

	if hostVarsContent != "" {
		hostVarsDir := filepath.Join(dir, "host_vars")
		if err := os.MkdirAll(hostVarsDir, 0o755); err != nil {
			t.Fatalf("mkdir host_vars: %v", err)
		}
		if err := os.WriteFile(filepath.Join(hostVarsDir, "nexus.yml"), []byte(hostVarsContent), 0o644); err != nil {
			t.Fatalf("write host_vars/nexus.yml: %v", err)
		}
	}
	if vaultContent != "" {
		vaultDir := filepath.Join(dir, ".vault")
		if err := os.MkdirAll(vaultDir, 0o755); err != nil {
			t.Fatalf("mkdir .vault: %v", err)
		}
		if err := os.WriteFile(filepath.Join(vaultDir, "main.yaml"), []byte(vaultContent), 0o644); err != nil {
			t.Fatalf("write .vault/main.yaml: %v", err)
		}
	}
	return dir, inv
}

const rosterWithDomainOnly = "---\nschema_version: 1\nfreeipa: {}\n"

const rosterWithNFSEntry = `---
schema_version: 1
freeipa:
nfs:
  servers:
    - host: nexus.ipa.pilot.internal
      state: present
      service_principal:
        ensure: true
        principal: nfs/nexus.ipa.pilot.internal
        keytab: /etc/krb5.keytab
      shares: []
`

func TestValidateDeploymentCompleteness_NoViolationsWhenEverythingPresent(t *testing.T) {
	_, inv := writeCompletenessFixture(t, "---\nprometheus_site_label: site-nexus\n", rosterWithNFSEntry, completenessValidVault)

	got, err := validateDeploymentCompleteness(context.Background(), inv)
	if err != nil {
		t.Fatalf("validateDeploymentCompleteness() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("validateDeploymentCompleteness() = %v, want no violations", got)
	}
}

func TestValidateDeploymentCompleteness_ReportsMissingRosterOnFreeIPAServerTarget(t *testing.T) {
	dir := t.TempDir()
	rosterPath := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(rosterPath, []byte(rosterWithDomainOnly), 0o600); err != nil {
		t.Fatal(err)
	}
	inv := filepath.Join(dir, "inventory.yml")
	if err := os.WriteFile(inv, []byte(`---
all:
  hosts:
    freeipa:
      ansible_host: 10.0.0.11
  children:
    freeipa-server:
      hosts:
        freeipa:
`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".vault"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".vault", "main.yaml"), []byte("ipa_admin_password: real-password\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := validateDeploymentCompleteness(context.Background(), inv)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Host != "freeipa" || !strings.Contains(got[0].Detail, "freeipa_roster_file") {
		t.Fatalf("violations = %v, want missing roster path on freeipa", got)
	}
}

func TestValidateDeploymentCompleteness_ReportsMissingPrometheusSiteLabel(t *testing.T) {
	_, inv := writeCompletenessFixture(t, "", rosterWithNFSEntry, completenessValidVault)

	got, err := validateDeploymentCompleteness(context.Background(), inv)
	if err != nil {
		t.Fatalf("validateDeploymentCompleteness() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("validateDeploymentCompleteness() = %v, want exactly 1 violation", got)
	}
	if got[0].Host != "nexus" || !strings.Contains(got[0].Detail, "prometheus_site_label") {
		t.Fatalf("violation = %+v, want nexus/prometheus_site_label", got[0])
	}
}

func TestValidateDeploymentCompleteness_ReportsMissingNFSRosterEntry(t *testing.T) {
	_, inv := writeCompletenessFixture(t, "---\nprometheus_site_label: site-nexus\n", rosterWithDomainOnly, completenessValidVault)

	got, err := validateDeploymentCompleteness(context.Background(), inv)
	if err != nil {
		t.Fatalf("validateDeploymentCompleteness() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("validateDeploymentCompleteness() = %v, want exactly 1 violation", got)
	}
	if got[0].Host != "nexus" || !strings.Contains(got[0].Detail, "nfs.servers") {
		t.Fatalf("violation = %+v, want nexus/nfs.servers", got[0])
	}
}

func TestValidateDeploymentCompleteness_ReportsBothWhenBothMissing(t *testing.T) {
	_, inv := writeCompletenessFixture(t, "", rosterWithDomainOnly, completenessValidVault)

	got, err := validateDeploymentCompleteness(context.Background(), inv)
	if err != nil {
		t.Fatalf("validateDeploymentCompleteness() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("validateDeploymentCompleteness() = %v, want exactly 2 violations", got)
	}
}

func TestValidateDeploymentCompleteness_SkipsEncryptedRosterWithoutViolation(t *testing.T) {
	_, inv := writeCompletenessFixture(t, "---\nprometheus_site_label: site-nexus\n", "$ANSIBLE_VAULT;1.1;AES256\n633864363...\n", completenessValidVault)

	got, err := validateDeploymentCompleteness(context.Background(), inv)
	if err != nil {
		t.Fatalf("validateDeploymentCompleteness() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("validateDeploymentCompleteness() = %v, want no violations for an encrypted roster we can't inspect", got)
	}
}

func TestValidateDeploymentCompleteness_ReportsMissingVaultFile(t *testing.T) {
	_, inv := writeCompletenessFixture(t, "---\nprometheus_site_label: site-nexus\n", rosterWithNFSEntry, "")

	got, err := validateDeploymentCompleteness(context.Background(), inv)
	if err != nil {
		t.Fatalf("validateDeploymentCompleteness() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("validateDeploymentCompleteness() = %v, want exactly 1 violation", got)
	}
	if got[0].Host != "vault" || !strings.Contains(got[0].Detail, "main.yaml") {
		t.Fatalf("violation = %+v, want a vault/main.yaml violation", got[0])
	}
}

func TestValidateDeploymentCompleteness_ReportsVaultChangeMePlaceholder(t *testing.T) {
	staleVault := "---\nthanos_aws_access_key_id: \"CHANGE-ME-thanos-access-key\"\nthanos_aws_secret_access_key: \"real-secret\"\nnode_exporter_basic_auth_password: \"real-password\"\n"
	_, inv := writeCompletenessFixture(t, "---\nprometheus_site_label: site-nexus\n", rosterWithNFSEntry, staleVault)

	got, err := validateDeploymentCompleteness(context.Background(), inv)
	if err != nil {
		t.Fatalf("validateDeploymentCompleteness() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("validateDeploymentCompleteness() = %v, want exactly 1 violation", got)
	}
	if got[0].Host != "vault" || !strings.Contains(got[0].Detail, "thanos_aws_access_key_id") || !strings.Contains(got[0].Detail, "CHANGE-ME") {
		t.Fatalf("violation = %+v, want a thanos_aws_access_key_id CHANGE-ME violation", got[0])
	}
}

func TestValidateDeploymentCompleteness_ReportsRosterStructuralViolation(t *testing.T) {
	// schema_version: 999 fails ValidateRoster's version dispatch — a
	// canonical-structure rule ValidateRosterFile enforces that the
	// narrower nfs.servers-only check this gate used to run on its own
	// would never have caught. (schema_version 1 and 2 are both valid as
	// of roster schema v2, so this must use a version beyond either.)
	badRoster := `---
schema_version: 999
freeipa:
  domain: ipa.pilot.internal
nfs:
  servers:
    - host: nexus.ipa.pilot.internal
      state: present
      service_principal:
        ensure: true
        principal: nfs/nexus.ipa.pilot.internal
        keytab: /etc/krb5.keytab
      shares: []
`
	_, inv := writeCompletenessFixture(t, "---\nprometheus_site_label: site-nexus\n", badRoster, completenessValidVault)

	got, err := validateDeploymentCompleteness(context.Background(), inv)
	if err != nil {
		t.Fatalf("validateDeploymentCompleteness() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("validateDeploymentCompleteness() = %v, want exactly 1 violation", got)
	}
	if got[0].Host != "nexus" || !strings.Contains(got[0].Detail, "schema_version") {
		t.Fatalf("violation = %+v, want a schema_version violation", got[0])
	}
}

func TestValidateDeploymentCompleteness_ReportsMissingThanosS3EitherOr(t *testing.T) {
	dir := t.TempDir()
	inv := filepath.Join(dir, "inventory.yml")
	writeFile(t, inv, `---
all:
  hosts:
    nexus:
      ansible_host: 10.0.0.1
  children:
    prometheus:
      hosts:
        nexus:
`)
	writeFile(t, filepath.Join(dir, "host_vars", "nexus.yml"), "---\nprometheus_site_label: site-nexus\n")
	writeFile(t, filepath.Join(dir, ".vault", "main.yaml"), completenessValidVault)

	got, err := validateDeploymentCompleteness(context.Background(), inv)
	if err != nil {
		t.Fatalf("validateDeploymentCompleteness() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("validateDeploymentCompleteness() = %v, want exactly 1 violation", got)
	}
	if got[0].Host != "nexus" || !strings.Contains(got[0].Detail, "thanos_s3_target_host") {
		t.Fatalf("violation = %+v, want a thanos_s3_target_host violation", got[0])
	}
}

func TestValidateDeploymentCompleteness_ThanosS3SatisfiedViaOverriddenEndpoint(t *testing.T) {
	dir := t.TempDir()
	inv := filepath.Join(dir, "inventory.yml")
	writeFile(t, inv, `---
all:
  hosts:
    nexus:
      ansible_host: 10.0.0.1
      thanos_s3_endpoint: s3.internal.example.com:443
  children:
    prometheus:
      hosts:
        nexus:
`)
	writeFile(t, filepath.Join(dir, "host_vars", "nexus.yml"), "---\nprometheus_site_label: site-nexus\n")
	writeFile(t, filepath.Join(dir, ".vault", "main.yaml"), completenessValidVault)

	got, err := validateDeploymentCompleteness(context.Background(), inv)
	if err != nil {
		t.Fatalf("validateDeploymentCompleteness() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("validateDeploymentCompleteness() = %v, want no violations (endpoint overridden away from the shared alias)", got)
	}
}

// TestValidateDeploymentCompleteness_ResticS3EitherOrSkippedWhenSeaweedfsS3Present
// covers finding #1's hard-gate parity: the same AutoDetectRole carve-out
// checkWorkspaceCompleteness gets must also apply here, or `pilot deploy`
// would block a restic-backup deploy that restic-backup-apply.yml's own
// in-playbook auto-detect (its "Auto-detect backup destination host from
// this inventory's seaweedfs-s3 group" set_fact) would actually let succeed.
func TestValidateDeploymentCompleteness_ResticS3EitherOrSkippedWhenSeaweedfsS3Present(t *testing.T) {
	dir := t.TempDir()
	inv := filepath.Join(dir, "inventory.yml")
	writeFile(t, inv, `---
all:
  hosts:
    nexus:
      ansible_host: 10.0.0.1
    s3-1:
      ansible_host: 10.0.0.2
  children:
    restic-backup:
      hosts:
        nexus:
    seaweedfs-s3:
      hosts:
        s3-1:
`)
	writeFile(t, filepath.Join(dir, ".vault", "main.yaml"), "---\nrestic_aws_access_key_id: \"AKIAEXAMPLE\"\nrestic_aws_secret_access_key: \"a-real-secret\"\nrestic_password: \"a-real-password\"\n")

	got, err := validateDeploymentCompleteness(context.Background(), inv)
	if err != nil {
		t.Fatalf("validateDeploymentCompleteness() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("validateDeploymentCompleteness() = %v, want no violations (seaweedfs-s3 present, auto-derived at runtime)", got)
	}
}

// TestValidateDeploymentCompleteness_ResticS3AutoDetectSkippedWhenRepositoryExplicitlyBlank
// mirrors the workspace-side coverage: a restic_repository resolved to an
// explicit blank string must not get the AutoDetectRole carve-out either —
// restic-backup-apply.yml's own auto-detect task requires `restic_s3_alias
// in restic_repository`, which is false for a blank string.
func TestValidateDeploymentCompleteness_ResticS3AutoDetectSkippedWhenRepositoryExplicitlyBlank(t *testing.T) {
	dir := t.TempDir()
	inv := filepath.Join(dir, "inventory.yml")
	writeFile(t, inv, `---
all:
  hosts:
    nexus:
      ansible_host: 10.0.0.1
      restic_repository: ""
    s3-1:
      ansible_host: 10.0.0.2
  children:
    restic-backup:
      hosts:
        nexus:
    seaweedfs-s3:
      hosts:
        s3-1:
`)
	writeFile(t, filepath.Join(dir, ".vault", "main.yaml"), "---\nrestic_aws_access_key_id: \"AKIAEXAMPLE\"\nrestic_aws_secret_access_key: \"a-real-secret\"\nrestic_password: \"a-real-password\"\n")

	got, err := validateDeploymentCompleteness(context.Background(), inv)
	if err != nil {
		t.Fatalf("validateDeploymentCompleteness() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("validateDeploymentCompleteness() = %v, want exactly 1 violation (repository explicitly blank — the playbook's own auto-detect condition would also be false)", got)
	}
	if got[0].Host != "nexus" || !strings.Contains(got[0].Detail, "restic_s3_target_host") {
		t.Fatalf("violation = %+v, want a restic_s3_target_host violation", got[0])
	}
}

// TestValidateDeploymentCompleteness_ReportsActiveEmptyThanosEndpoint covers
// finding #2's hard-gate parity: an active-but-blank thanos_s3_endpoint
// resolved from inventory must still be treated as unsatisfied.
func TestValidateDeploymentCompleteness_ReportsActiveEmptyThanosEndpoint(t *testing.T) {
	dir := t.TempDir()
	inv := filepath.Join(dir, "inventory.yml")
	writeFile(t, inv, `---
all:
  hosts:
    nexus:
      ansible_host: 10.0.0.1
      thanos_s3_endpoint: ""
  children:
    prometheus:
      hosts:
        nexus:
`)
	writeFile(t, filepath.Join(dir, "host_vars", "nexus.yml"), "---\nprometheus_site_label: site-nexus\n")
	writeFile(t, filepath.Join(dir, ".vault", "main.yaml"), completenessValidVault)

	got, err := validateDeploymentCompleteness(context.Background(), inv)
	if err != nil {
		t.Fatalf("validateDeploymentCompleteness() error = %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("validateDeploymentCompleteness() = %v, want exactly 1 violation (active but blank endpoint isn't a real override)", got)
	}
	if got[0].Host != "nexus" || !strings.Contains(got[0].Detail, "thanos_s3_target_host") {
		t.Fatalf("violation = %+v, want a thanos_s3_target_host violation", got[0])
	}
}

func TestFormatCompletenessViolations_ListsEveryViolation(t *testing.T) {
	err := formatCompletenessViolations([]completenessViolation{
		{Host: "nexus", Detail: "missing prometheus_site_label"},
		{Host: "nexus", Detail: "missing nfs.servers entry"},
	})
	msg := err.Error()
	for _, want := range []string{"nexus: missing prometheus_site_label", "nexus: missing nfs.servers entry"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("formatCompletenessViolations() = %q, missing %q", msg, want)
		}
	}
}
