package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/anomalyco/pilot/internal/contract"
)

func TestLintContractsLoadsCanonicalDirectory(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	if err := lintContracts(repoRootForTest(t), &out); err != nil {
		t.Fatalf("lintContracts: %v", err)
	}
	got := out.String()
	for _, component := range []string{
		"alertmanager", "audit-log-forwarding", "dashboard", "dns", "docker",
		"freeipa-client", "freeipa-identity", "freeipa-server-replica",
		"freeipa-server", "keycloak-db", "keycloak", "log-server",
		"log-shipping", "ntp", "os-patch-sla", "pam-oidc-sshd",
		"prometheus", "restic-backup", "seaweedfs-s3", "thanos-query",
		"wazuh-fim", "wazuh-manager",
	} {
		if !strings.Contains(got, "✓ "+component+"\trole=") {
			t.Fatalf("output missing component %q:\n%s", component, got)
		}
	}
	if !strings.Contains(got, "contracts: 22 component(s) loaded from") {
		t.Fatalf("output missing summary:\n%s", got)
	}
}

func TestValidateDeployCatalogProjectionRejectsStageDrift(t *testing.T) {
	catalog, err := contract.NewCatalog([]contract.Contract{{
		ID: "docker", Playbooks: contract.Playbooks{Apply: "playbooks/apply/docker-apply.yml"},
		StagePolicy: contract.StagePolicy{Variable: "patch_stage"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	entries := []deployPlaybook{{Key: "docker", Playbook: "playbooks/apply/docker-apply.yml", StageVar: "stage"}}
	if err := validateDeployCatalogEntries(catalog, entries); err == nil || !strings.Contains(err.Error(), "stage variable") {
		t.Fatalf("err=%v", err)
	}
}
