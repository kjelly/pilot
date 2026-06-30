package spec

import (
	"strings"
	"testing"
)

// TestRegression_CoreInfraSpec locks the structure of the spec that
// defines what counts as a "core infrastructure ready" host (internal
// DNS + time sync + identity provider). Without this regression, a
// well-meaning refactor could silently drop a row that catches a
// real production problem — for instance, someone deleting C7
// would let a misconfigured Keycloak issuer sail through to prod.
func TestRegression_CoreInfraSpec(t *testing.T) {
	const specPath = "../../docs/verification/core-infra.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	// C1..C8 inclusive, no gaps, no duplicates. The 8 rows are:
	//   C1 dns / resolv.conf
	//   C2 dns / systemd-resolved
	//   C3 dns / host resolution
	//   C4 time / timesyncd
	//   C5 time / sync offset
	//   C6 identity / keycloak discovery reachable
	//   C7 identity / keycloak issuer matches KEYCLOAK_ISSUER
	//   C8 identity / keycloak master realm enabled
	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8"}
	if len(s.Rows) != 8 {
		t.Fatalf("rows=%d want=8", len(s.Rows))
	}
	for i, id := range wantIDs {
		if s.Rows[i].ID != id {
			t.Errorf("row[%d] id=%q want=%q", i, s.Rows[i].ID, id)
		}
	}

	// No vague expected values.
	for _, r := range s.Rows {
		if strings.Contains(strings.ToLower(strings.TrimSpace(r.Expected)), "ok") {
			t.Errorf("row %s uses vague expected %q", r.ID, r.Expected)
		}
	}

	// C5 must use a substring marker present in every timedatectl
	// timesync-status output. A refactor that swaps "~Offset" for
	// something more-specific (e.g. "~Reference") breaks on distros
	// without a stratum-1 reference. Lock the contract.
	for _, r := range s.Rows {
		if r.ID == "C5" && !strings.Contains(r.Expected, "~Offset") {
			t.Errorf("C5 expected should keep ~Offset substring marker; got %q", r.Expected)
		}
	}

	// C6 must reference KEYCLOAK_ISSUER. Anyone who deletes it from
	// the shell command breaks the contract that the discovery URL
	// is configurable at verify-time (deployment repo policy).
	for _, r := range s.Rows {
		if r.ID == "C6" && !strings.Contains(r.Command, "$KEYCLOAK_ISSUER") {
			t.Errorf("C6 must use $KEYCLOAK_ISSUER; got %q", r.Command)
		}
		if r.ID == "C7" && !strings.Contains(r.Command, "$KEYCLOAK_ISSUER") {
			t.Errorf("C7 must use $KEYCLOAK_ISSUER; got %q", r.Command)
		}
		if r.ID == "C8" && !strings.Contains(r.Command, "$KEYCLOAK_TOKEN") {
			t.Errorf("C8 must use $KEYCLOAK_TOKEN; got %q", r.Command)
		}
	}

	// Lint must not produce errors. (Adding a row that fails this
	// assertion fails CI rather than slipping through silently.)
	fs := Lint(s)
	if HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", joinFindings(fs))
	}
}
