package spec

import (
	"strings"
	"testing"
)

// TestRegression_CoreInfraProviderSpec locks the provider-side counterpart
// of core-infra.md for the NTP role:
//
//	C1-C3   NTP server installed + active + valid stratum
//
// The DNS provider rows that used to be C1-C3 and C7 moved to
// docs/verification/dns.md in v3.0 (with the apply side moving to
// playbooks/apply/dns-apply.yml); Keycloak moved to keycloak.md in v2.0.
// Neither may creep back in here.
func TestRegression_CoreInfraProviderSpec(t *testing.T) {
	const specPath = "../../docs/verification/core-infra-provider.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{"C1", "C2", "C3"}
	if len(s.Rows) != len(wantIDs) {
		t.Fatalf("rows=%d want=%d", len(s.Rows), len(wantIDs))
	}
	for i, id := range wantIDs {
		if s.Rows[i].ID != id {
			t.Errorf("row[%d] id=%q want=%q", i, s.Rows[i].ID, id)
		}
	}

	if fs := Lint(s); HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", joinFindings(fs))
	}

	for _, r := range s.Rows {
		if r.Category != "ntp" {
			t.Errorf("row %s category=%q: core-infra-provider.md is NTP-only since v3.0 (DNS lives in dns.md)", r.ID, r.Category)
		}
		lower := strings.ToLower(r.Command + " " + r.Check)
		for _, banned := range []string{"unbound", "bind9", "dnsmasq", "keycloak"} {
			if strings.Contains(lower, banned) {
				t.Errorf("row %s mentions %q — DNS belongs in dns.md, Keycloak in keycloak.md", r.ID, banned)
			}
		}
	}

	// C2 must use the numeric rc matcher: `~active` also matches "inactive",
	// so a host with neither chronyd nor ntpd running used to pass.
	if c2 := s.Rows[1]; strings.HasPrefix(strings.TrimSpace(c2.Expected), "~") {
		t.Errorf("C2 expected=%q: use rc 0 with `systemctl is-active`, not a substring matcher", c2.Expected)
	}
}
