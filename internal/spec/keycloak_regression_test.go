package spec

import (
	"strings"
	"testing"
)

// TestRegression_KeycloakSpec locks the structure of
// docs/verification/keycloak.md (v1.0 — Keycloak server health, split
// out of core-infra-provider.md v1.0).
//
// Where core-infra-provider.md v1.0 mixed DNS / NTP / Keycloak into
// one 9-row spec, keycloak.md v1.0 owns only the Keycloak half:
//
//	C7      keycloak process visible (pidof java || pidof kc.sh)
//	C8      HTTP listener 8080 / 8443 at least one LISTEN
//	C9      OIDC discovery endpoint returns 200
//
// Why these specific IDs (C7-C9) and not C1-C3: cross-references in
// the existing runbooks (docs/runbooks/core-infra-provider-*.md,
// docs/runbooks/core-infra.md) cite C7/C8/C9 of core-infra-provider.md
// when discussing Keycloak. Keeping the same row IDs in the split
// spec means runbooks and playbooks (which tag with keycloak-C7 /
// keycloak-C8 / keycloak-C9 per AGENTS.md §4) stay readable across
// the refactor — only the spec filename changes.
//
// Cross-row invariants locked below:
//
//   - C7 must use `pidof` (NOT pgrep), because pgrep -f matches the
//     verifier's own shell command line (which contains the literal
//     "keycloak") and false-positives on every host.
//   - C9 must reference $KEYCLOAK_ISSUER (with or without `:-default`).
//   - C8 must use `ss` (not `netstat`); modern Ubuntu / RHEL
//     default to `ss -tulnH` and the spec must not regress.
func TestRegression_KeycloakSpec(t *testing.T) {
	const specPath = "../../docs/verification/keycloak.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	// 1. C7..C9 inclusive, no gaps, no duplicates. (Same IDs as
	//    core-infra-provider.md v1.0's Keycloak half; see comment
	//    above for why.)
	wantIDs := []string{"C7", "C8", "C9"}
	if len(s.Rows) != 3 {
		t.Fatalf("rows=%d want=3", len(s.Rows))
	}
	for i, id := range wantIDs {
		if s.Rows[i].ID != id {
			t.Errorf("row[%d] id=%q want=%q", i, s.Rows[i].ID, id)
		}
	}

	// 2. No vague expected values.
	for _, r := range s.Rows {
		if strings.Contains(strings.ToLower(strings.TrimSpace(r.Expected)), "ok") {
			t.Errorf("row %s uses vague expected %q", r.ID, r.Expected)
		}
	}

	// 3. C7 must use pidof, not pgrep. pgrep matches its own shell
	//    command line (which contains the literal "keycloak") and
	//    false-positives on every host — even ones without Keycloak.
	for _, r := range s.Rows {
		if r.ID == "C7" && strings.Contains(r.Command, "pgrep") {
			t.Errorf("C7 must use pidof (not pgrep); got %q", r.Command)
		}
	}

	// 4. C7 must reference at least one Keycloak process name
	//    (`java` or `kc.sh`). The `||` makes it tolerate either
	//    containerized (`java -jar keycloak.jar`) or binary
	//    (`kc.sh start`) startup.
	for _, r := range s.Rows {
		if r.ID == "C7" {
			hasJava := strings.Contains(r.Command, "pidof java") || strings.Contains(r.Command, "pidof  java")
			hasKcsh := strings.Contains(r.Command, "pidof kc.sh") || strings.Contains(r.Command, "pidof  kc.sh")
			if !hasJava && !hasKcsh {
				t.Errorf("C7 must reference pidof java OR pidof kc.sh; got %q", r.Command)
			}
		}
	}

	// 5. C8 must use `ss` (modern, default on Ubuntu 24.04+ and
	//    RHEL 9+). `netstat` is deprecated and may be missing.
	for _, r := range s.Rows {
		if r.ID == "C8" {
			if !strings.Contains(r.Command, "ss ") && !strings.HasPrefix(r.Command, "ss ") {
				t.Errorf("C8 must use ss; got %q", r.Command)
			}
			has8080 := strings.Contains(r.Command, "8080")
			has8443 := strings.Contains(r.Command, "8443")
			if !has8080 && !has8443 {
				t.Errorf("C8 must check 8080 or 8443; got %q", r.Command)
			}
		}
	}

	// 6. C9 must reference $KEYCLOAK_ISSUER (with or without
	//    `:-default` fallback). Hard-coding the URL is forbidden
	//    by the spec-authoring policy: the issuer URL is an env
	//    var injected at verify time, and hard-coding defeats
	//    the whole "verify across sandbox/staging/prod" point.
	for _, r := range s.Rows {
		if r.ID == "C9" && !strings.Contains(r.Command, "KEYCLOAK_ISSUER") {
			t.Errorf("C9 must reference KEYCLOAK_ISSUER (with or without default); got %q", r.Command)
		}
	}

	// 7. C9 must hit .well-known/openid-configuration — the OIDC
	//    discovery endpoint. Anything else (e.g. /auth) is a
	//    regression to the old Keycloak <17 path.
	for _, r := range s.Rows {
		if r.ID == "C9" && !strings.Contains(r.Command, "openid-configuration") {
			t.Errorf("C9 must hit .well-known/openid-configuration; got %q", r.Command)
		}
	}

	// 8. Lint must not produce errors.
	fs := Lint(s)
	if HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", joinFindings(fs))
	}
}
