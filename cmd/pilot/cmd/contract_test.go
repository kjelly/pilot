package cmd

import (
	"bytes"
	"strings"
	"testing"
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
