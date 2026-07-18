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
	for _, component := range []string{"dns", "docker", "freeipa-server", "log-shipping", "ntp", "restic-backup"} {
		if !strings.Contains(got, "✓ "+component+"\trole=") {
			t.Fatalf("output missing component %q:\n%s", component, got)
		}
	}
	if !strings.Contains(got, "contracts: 6 component(s) loaded from") {
		t.Fatalf("output missing summary:\n%s", got)
	}
}
