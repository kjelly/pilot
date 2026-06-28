package cmd

import (
	"testing"
)

func TestParseDrift(t *testing.T) {
	stdout := `
PLAY RECAP *********************************************************************
localhost                  : ok=5    changed=1    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
otherhost                  : ok=2    changed=0    unreachable=0    failed=3    skipped=0    rescued=0    ignored=0
cleanhost                  : ok=10   changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
`
	drifts := parseDrift(stdout)
	if len(drifts) != 2 {
		t.Fatalf("expected 2 drifts, got %d", len(drifts))
	}

	if drifts[0].Host != "localhost" || drifts[0].Changed != 1 || drifts[0].Failed != 0 {
		t.Errorf("unexpected drift for host 0: %+v", drifts[0])
	}

	if drifts[1].Host != "otherhost" || drifts[1].Changed != 0 || drifts[1].Failed != 3 {
		t.Errorf("unexpected drift for host 1: %+v", drifts[1])
	}
}
