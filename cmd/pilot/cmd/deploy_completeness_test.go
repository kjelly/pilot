package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const completenessInventoryYAML = `---
all:
  hosts:
    nexus:
      ansible_host: 10.0.0.1
      freeipa_roster_file: "%s"
  children:
    prometheus:
      hosts:
        nexus:
    freeipa-nfs-server:
      hosts:
        nexus:
`

func writeCompletenessFixture(t *testing.T, hostVarsContent, rosterContent string) (dir, inv string) {
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

	if hostVarsContent != "" {
		hostVarsDir := filepath.Join(dir, "host_vars")
		if err := os.MkdirAll(hostVarsDir, 0o755); err != nil {
			t.Fatalf("mkdir host_vars: %v", err)
		}
		if err := os.WriteFile(filepath.Join(hostVarsDir, "nexus.yml"), []byte(hostVarsContent), 0o644); err != nil {
			t.Fatalf("write host_vars/nexus.yml: %v", err)
		}
	}
	return dir, inv
}

const rosterWithDomainOnly = "---\nschema_version: 1\nfreeipa:\n  domain: ipa.pilot.internal\n"

const rosterWithNFSEntry = `---
schema_version: 1
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

func TestValidateDeploymentCompleteness_NoViolationsWhenEverythingPresent(t *testing.T) {
	_, inv := writeCompletenessFixture(t, "---\nprometheus_site_label: site-nexus\n", rosterWithNFSEntry)

	got, err := validateDeploymentCompleteness(context.Background(), inv)
	if err != nil {
		t.Fatalf("validateDeploymentCompleteness() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("validateDeploymentCompleteness() = %v, want no violations", got)
	}
}

func TestValidateDeploymentCompleteness_ReportsMissingPrometheusSiteLabel(t *testing.T) {
	_, inv := writeCompletenessFixture(t, "", rosterWithNFSEntry)

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
	_, inv := writeCompletenessFixture(t, "---\nprometheus_site_label: site-nexus\n", rosterWithDomainOnly)

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
	_, inv := writeCompletenessFixture(t, "", rosterWithDomainOnly)

	got, err := validateDeploymentCompleteness(context.Background(), inv)
	if err != nil {
		t.Fatalf("validateDeploymentCompleteness() error = %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("validateDeploymentCompleteness() = %v, want exactly 2 violations", got)
	}
}

func TestValidateDeploymentCompleteness_SkipsEncryptedRosterWithoutViolation(t *testing.T) {
	_, inv := writeCompletenessFixture(t, "---\nprometheus_site_label: site-nexus\n", "$ANSIBLE_VAULT;1.1;AES256\n633864363...\n")

	got, err := validateDeploymentCompleteness(context.Background(), inv)
	if err != nil {
		t.Fatalf("validateDeploymentCompleteness() error = %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("validateDeploymentCompleteness() = %v, want no violations for an encrypted roster we can't inspect", got)
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
