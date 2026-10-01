package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

// The topology test writes its inventory to a temporary file, so aggregate
// spec rows that fan out over it (dns.md C20, internal-endpoint.md C9/C10)
// get the path through PILOT_INPUT_PILOT_INVENTORY_PATH during the verify
// step, and only then.
func TestWithTopologyInventoryInput_SetsAbsolutePathOnlyDuringVerify(t *testing.T) {
	t.Setenv(topologyInventoryInputEnv, "")
	os.Unsetenv(topologyInventoryInputEnv)
	dir := t.TempDir()
	t.Chdir(dir)

	var seen string
	var wasSet bool
	err := withTopologyInventoryInput("inv.yml", func() error {
		seen, wasSet = os.LookupEnv(topologyInventoryInputEnv)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "inv.yml"); !wasSet || seen != want {
		t.Fatalf("during verify %s=%q (set=%v), want %q", topologyInventoryInputEnv, seen, wasSet, want)
	}
	if _, still := os.LookupEnv(topologyInventoryInputEnv); still {
		t.Fatalf("%s must be unset again after verify", topologyInventoryInputEnv)
	}
}

func TestWithTopologyInventoryInput_KeepsOperatorValue(t *testing.T) {
	t.Setenv(topologyInventoryInputEnv, "/operator/inventory.yml")
	var seen string
	if err := withTopologyInventoryInput("/tmp/rendered.yml", func() error {
		seen = os.Getenv(topologyInventoryInputEnv)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if seen != "/operator/inventory.yml" {
		t.Fatalf("operator-supplied value replaced: got %q", seen)
	}
	if got := os.Getenv(topologyInventoryInputEnv); got != "/operator/inventory.yml" {
		t.Fatalf("operator-supplied value not kept after verify: %q", got)
	}
}
