package detection

import "testing"

func TestFingerprint_CategoryAndSeverityDoNotChangeFingerprint(t *testing.T) {
	// Fingerprint's signature deliberately has no category/severity/score/
	// timestamp/model/provider parameters (spec §21) — calling it twice
	// with the same (host, profile id, profile version) must always
	// produce the same value regardless of anything else happening to the
	// episode in between.
	a := Fingerprint("web-1", "linux-host-v1", 1)
	b := Fingerprint("web-1", "linux-host-v1", 1)
	if a != b {
		t.Fatalf("fingerprint must be deterministic for the same (host, profile id, profile version): %q != %q", a, b)
	}
}

func TestFingerprint_ProfileVersionChangesFingerprint(t *testing.T) {
	v1 := Fingerprint("web-1", "linux-host-v1", 1)
	v2 := Fingerprint("web-1", "linux-host-v1", 2)
	if v1 == v2 {
		t.Fatal("a feature profile version bump must change the fingerprint")
	}
}
