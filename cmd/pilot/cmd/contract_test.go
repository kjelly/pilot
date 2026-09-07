package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
)

func TestLintContractsLoadsCanonicalDirectory(t *testing.T) {
	t.Parallel()

	var out bytes.Buffer
	if err := lintContracts(repoRootForTest(t), &out); err != nil {
		t.Fatalf("lintContracts: %v", err)
	}
	got := out.String()
	for _, component := range []string{
		"agent-controller",
		"alertmanager", "audit-log-forwarding", "dashboard", "dcgm-exporter", "detection-engine", "dns", "docker",
		"freeipa-ca-trust",
		"freeipa-client", "freeipa-dns-client", "freeipa-dns", "freeipa-identity", "freeipa-nfs-client", "freeipa-nfs-server",
		"freeipa-realm-replacement", "freeipa-server-replica",
		"freeipa-server", "host-monitoring", "internal-endpoint", "keycloak-db", "keycloak", "log-server",
		"log-shipping", "ntp", "os-patch-sla", "pam-oidc-sshd",
		"prometheus", "restic-backup", "reverse-proxy", "seaweedfs-s3", "thanos-query",
		"wazuh-fim", "wazuh-manager",
	} {
		if !strings.Contains(got, "✓ "+component+"\trole=") {
			t.Fatalf("output missing component %q:\n%s", component, got)
		}
	}
	if !strings.Contains(got, "contracts: 35 component(s) loaded from") {
		t.Fatalf("output missing summary:\n%s", got)
	}
	if !strings.Contains(got, "diagnostics coverage: 5/35 component(s)") {
		t.Fatalf("output missing diagnostics coverage summary:\n%s", got)
	}
}

func TestLintContractsRequireDiagnosticsFailsClosed(t *testing.T) {
	var out bytes.Buffer
	err := lintContractsWithOptions(repoRootForTest(t), &out, true)
	if err == nil || !strings.Contains(err.Error(), "diagnostics coverage incomplete") {
		t.Fatalf("error = %v, want diagnostics coverage failure", err)
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
