package spec

import (
	"strings"
	"testing"
)

// TestRegression_DetectionEngineModelProviderSpec locks the structure of
// docs/verification/detection-engine-model-provider.md (Stage B, spec
// §60's M1-M5).
//
//	M1  provider configuration obeys §41.1 inputRules
//	M2  request/response batch schema + semantic validation round-trips
//	M3  status reports the configured protocol correctly
//	M4  circuit breaker reports closed under a healthy provider
//	M5  secret ownership — no secret required/exposed for this lane's auth=none
func TestRegression_DetectionEngineModelProviderSpec(t *testing.T) {
	const specPath = "../../docs/verification/detection-engine-model-provider.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{"M1", "M2", "M3", "M4", "M5"}
	if len(s.Rows) != len(wantIDs) {
		t.Fatalf("rows=%d want=%d", len(s.Rows), len(wantIDs))
	}
	for i, id := range wantIDs {
		if s.Rows[i].ID != id {
			t.Errorf("row[%d] id=%q want=%q", i, s.Rows[i].ID, id)
		}
	}

	// Every row is a real, executable readOnly check — none of them are
	// verifyOnly, since the fake-protocol provider fixture (spec §49/§60)
	// makes all five actually observable on a Stage-B-enabled host.
	for _, r := range s.Rows {
		if r.VerifyOnly {
			t.Errorf("%s: unexpectedly verifyOnly — every M row should be a real command against the provider-verification fixture lane", r.ID)
		}
		if r.Action == nil || r.Action.Mode != "readOnly" {
			t.Errorf("%s: action mode must be readOnly (provider verification never mutates the target)", r.ID)
		}
	}

	// No credentials belong in a spec (AGENTS.md) — same convention as
	// detection_engine_regression_test.go.
	for _, r := range s.Rows {
		lower := strings.ToLower(r.Command)
		for _, forbidden := range []string{"secret_key", "access_key", "api_key=", "password="} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("%s must not reference %q (no credentials in spec); got %q", r.ID, forbidden, r.Command)
			}
		}
	}

	fs := Lint(s)
	if HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", joinFindings(fs))
	}
}
