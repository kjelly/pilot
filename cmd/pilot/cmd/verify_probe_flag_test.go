package cmd

import (
	"strings"
	"testing"
)

func TestCheckProbeFlag(t *testing.T) {
	cases := []struct {
		changed bool
		probe   string
		wantErr bool
	}{
		{changed: false, probe: "", wantErr: false},
		{changed: true, probe: "", wantErr: true},
		{changed: true, probe: "   ", wantErr: true},
		{changed: true, probe: "true", wantErr: false},
	}
	for _, c := range cases {
		if err := checkProbeFlag(c.changed, c.probe); (err != nil) != c.wantErr {
			t.Errorf("checkProbeFlag(%v, %q) = %v, want error %v", c.changed, c.probe, err, c.wantErr)
		}
	}
}

// TestRunVerifyWithoutSpecNeedsDir: with no spec.md and no --dir, verify
// must refuse instead of verifying every spec under docs/verification
// against the given inventory.
func TestRunVerifyWithoutSpecNeedsDir(t *testing.T) {
	oldDir, oldProbe, oldInv := verifyDir, verifyProbe, verifyInventory
	t.Cleanup(func() { verifyDir, verifyProbe, verifyInventory = oldDir, oldProbe, oldInv })
	verifyDir, verifyProbe, verifyInventory = "", "", "inventory.yml"

	err := runVerify(nil, nil)
	if err == nil || !strings.Contains(err.Error(), "--dir") {
		t.Fatalf("runVerify() with no spec and no --dir = %v, want an error asking for --dir", err)
	}
}
