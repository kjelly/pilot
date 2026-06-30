package spec

import (
	"strings"
	"testing"
)

// TestRegression_CoreInfraProviderSpec locks the dual-side
// counterpart of core-infra.md. Where core-infra specifies what a
// *client* of internal DNS/NTP/Keycloak must satisfy, this spec
// locks what a *provider* host must satisfy:
//
//   C1-C3   DNS server installed + listening + authoritive
//   C4-C6   NTP server installed + active + valid stratum
//   C7-C9   Keycloak process + listener + discovery endpoint
//
// Why this matters: a provider-side regression (e.g. someone
// deletes C9 because "discovery will be checked upstream") lets a
// Keycloak whose OIDC config is borked still pass this host's
// spec — but every other host's spec then also silently flips to
// pass-on-bad-data. Pin it down.
func TestRegression_CoreInfraProviderSpec(t *testing.T) {
	const specPath = "../../docs/verification/core-infra-provider.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	// C1..C9 inclusive, no gaps, no duplicates.
	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9"}
	if len(s.Rows) != 9 {
		t.Fatalf("rows=%d want=9", len(s.Rows))
	}
	for i, id := range wantIDs {
		if s.Rows[i].ID != id {
			t.Errorf("row[%d] id=%q want=%q", i, s.Rows[i].ID, id)
		}
	}

	// No vague expected values. (vague → Lint warns; explicit pass.)
	for _, r := range s.Rows {
		if strings.Contains(strings.ToLower(strings.TrimSpace(r.Expected)), "ok") {
			t.Errorf("row %s uses vague expected %q", r.ID, r.Expected)
		}
	}

	// C9 must use $KEYCLOAK_ISSUER. URL / token policy: hard-coding is
	// forbidden, even in spec.md.
	for _, r := range s.Rows {
		if r.ID == "C9" && !strings.Contains(r.Command, "KEYCLOAK_ISSUER") {
			t.Errorf("C9 must reference KEYCLOAK_ISSUER (with or without default); got %q", r.Command)
		}
	}

	// Lint must not produce errors.
	fs := Lint(s)
	if HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", joinFindings(fs))
	}


	// C7 must use pidof, not pgrep. pgrep matches its own shell
	// command line (which contains the literal "keycloak") and
	// false-positives on every host — even ones without Keycloak.
	for _, r := range s.Rows {
		if r.ID == "C7" && strings.Contains(r.Command, "pgrep") {
			t.Errorf("C7 must use pidof (not pgrep); got %q", r.Command)
		}
	}
	// C1 must mention at least one server-only DNS package, NOT
	// bind9-dnsutils (that's the client tools package).
	for _, r := range s.Rows {
		if r.ID == "C1" {
			ok := strings.Contains(r.Command, "unbound") ||
				strings.Contains(r.Command, "bind9 ") ||
				strings.Contains(r.Command, "dnsmasq")
			if !ok {
				t.Errorf("C1 must mention a server DNS package (unbound|bind9|dnsmasq); got %q", r.Command)
			}
		}
	}

}
