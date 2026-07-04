package spec

import (
	"strings"
	"testing"
)

// TestRegression_CoreInfraProviderSpec locks the dual-side
// counterpart of core-infra.md. Where core-infra specifies what a
// *client* of internal DNS/NTP must satisfy, this spec locks what a
// *provider* host must satisfy:
//
//	C1-C3   DNS server installed + listening + authoritive
//	C4-C6   NTP server installed + active + valid stratum
//	C7      DNS server can resolve a custom internal domain (v2.1,
//	        optional — gated on $DNS_PROBE_NAME, SKIP-as-pass if unset)
//
// (Keycloak C7-C9 was here in v1.0, but has been split out into
// docs/verification/keycloak.md as of v2.0. Don't re-add them here —
// if you need a Keycloak regression invariant, write it in
// internal/spec/keycloak_regression_test.go. v2.1's C7 is unrelated
// to that split — it's the data-driven DNS zones feature's own probe
// row, reusing the ID that Keycloak vacated.)
//
// Why this matters: a provider-side regression (e.g. someone
// silently drops C6 because "Stratum is a NTS detail") lets a
// misconfigured NTP upstream still pass this host's spec — but
// every other host's spec then also silently flips to
// pass-on-bad-data. Pin it down.
func TestRegression_CoreInfraProviderSpec(t *testing.T) {
	const specPath = "../../docs/verification/core-infra-provider.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	// C1..C7 inclusive, no gaps, no duplicates. (Was C1..C6 in v2.0;
	// v2.1 added the optional DNS-probe C7.)
	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7"}
	if len(s.Rows) != 7 {
		t.Fatalf("rows=%d want=7", len(s.Rows))
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

	// Lint must not produce errors.
	fs := Lint(s)
	if HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", joinFindings(fs))
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

	// Regression: Keycloak's C8-C9 must NOT have crept back into this
	// spec (the whole point of the v2.0 split). Keycloak used to sit
	// at C7-C9; v2.1 reused C7 for the unrelated DNS-probe row above,
	// so only C8/C9 are guarded here — if you find yourself adding
	// either, move it to keycloak.md instead.
	for _, r := range s.Rows {
		if r.ID == "C8" || r.ID == "C9" {
			t.Errorf("row %s must not exist in core-infra-provider.md (Keycloak split out to keycloak.md in v2.0); got %q", r.ID, r.Command)
		}
	}

	// C7 (v2.1 DNS-probe row) must be env-gated on $DNS_PROBE_NAME
	// with a SKIP-as-pass fallback when unset — a plain forwarding
	// resolver (no custom zones configured) must not go red just
	// because this optional row exists.
	for _, r := range s.Rows {
		if r.ID != "C7" {
			continue
		}
		if !strings.Contains(r.Command, "DNS_PROBE_NAME") {
			t.Errorf("C7 must reference $DNS_PROBE_NAME; got %q", r.Command)
		}
		if !strings.Contains(r.Command, "SKIP-no-probe") {
			t.Errorf("C7 must SKIP-as-pass when $DNS_PROBE_NAME is unset; got %q", r.Command)
		}
	}

	// Regression: nothing in this spec should mention Keycloak.
	// Anything Keycloak-shaped belongs in keycloak.md.
	for _, r := range s.Rows {
		if strings.Contains(strings.ToLower(r.Command), "keycloak") ||
			strings.Contains(strings.ToLower(r.Check), "keycloak") {
			t.Errorf("row %s mentions Keycloak — must be in keycloak.md, not core-infra-provider.md: cmd=%q check=%q",
				r.ID, r.Command, r.Check)
		}
	}
}
