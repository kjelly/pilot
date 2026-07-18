package spec

import (
	"strings"
	"testing"
)

// TestRegression_ThanosQuerySpec locks the structure of
// docs/verification/thanos-query.md (v1.0 — central Thanos Query + Store
// Gateway + Compactor, the inverted-discovery counterpart to
// docs/verification/prometheus.md):
//
//	C1-C3  pilot-thanos-query / pilot-thanos-store / pilot-thanos-compact
//	       containers running
//	C4-C5  Thanos Query /-/healthy, /-/ready (10912 — the host-published
//	       port; the container's internal listen port is 10902, but
//	       thanos-query-apply.yml maps it to host port 10912 by default
//	       to avoid colliding with a co-located Prometheus site's own
//	       Thanos Sidecar, which hardcodes host port 10902)
//	C6     Thanos Store Gateway /-/healthy (10904)
//	C7     Thanos Compactor /-/healthy (10905)
//	C8     Thanos Store Gateway can read the object storage bucket
//	C9     Thanos Query has discovered at least one StoreAPI endpoint up
//	C10    a global query result carries a "site" label
//
// Cross-row invariants locked below:
//
//   - C1-C3 must reference the exact container names the apply playbook
//     creates.
//   - C9 must hit /api/v1/stores (Thanos Query's store-discovery API,
//     not a guessed endpoint) and assert on the presence of a "sidecar"
//     group specifically, NOT just any healthy store endpoint — real bug
//     found via vm-target testing: this playbook always registers the
//     LOCAL Store Gateway as a permanent "store"-group endpoint
//     regardless of whether any site is connected, so a naive "at least
//     one endpoint has no error" check (or a nonexistent "status":"up"
//     field) passes trivially even with zero sites — caught by
//     deliberately testing the "no sites deployed yet" negative path.
//   - C10 must query the Prometheus-compatible /api/v1/query endpoint and
//     assert on the presence of the "site" label KEY, not a specific site
//     name (spec Command/Expected columns are static text authored once
//     and cannot be templated per deployment — see spec §2 note).
//   - No row may leak the S3 secret key into the spec text (AGENTS.md).
func TestRegression_ThanosQuerySpec(t *testing.T) {
	const specPath = "../../docs/verification/thanos-query.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10"}
	if len(s.Rows) != len(wantIDs) {
		t.Fatalf("rows=%d want=%d", len(s.Rows), len(wantIDs))
	}
	for i, id := range wantIDs {
		if s.Rows[i].ID != id {
			t.Errorf("row[%d] id=%q want=%q", i, s.Rows[i].ID, id)
		}
	}

	for _, r := range s.Rows {
		switch strings.ToLower(strings.TrimSpace(r.Expected)) {
		case "ok", "normal", "reasonable", "sufficient":
			t.Errorf("row %s uses vague expected %q", r.ID, r.Expected)
		}
	}

	wantContainer := map[string]string{
		"C1": "pilot-thanos-query",
		"C2": "pilot-thanos-store",
		"C3": "pilot-thanos-compact",
	}
	for _, r := range s.Rows {
		name, ok := wantContainer[r.ID]
		if !ok {
			continue
		}
		if !strings.Contains(r.Command, name) {
			t.Errorf("%s must reference container %s; got %q", r.ID, name, r.Command)
		}
		if !strings.Contains(r.Command, "docker ps") {
			t.Errorf("%s must check via docker ps; got %q", r.ID, r.Command)
		}
	}

	wantHTTP := map[string]struct{ port, path string }{
		"C4": {"10912", "/-/healthy"},
		"C5": {"10912", "/-/ready"},
		"C6": {"10904", "/-/healthy"},
		"C7": {"10905", "/-/healthy"},
	}
	for _, r := range s.Rows {
		want, ok := wantHTTP[r.ID]
		if !ok {
			continue
		}
		if !strings.Contains(r.Command, want.port) {
			t.Errorf("%s must reference port %s; got %q", r.ID, want.port, r.Command)
		}
		if !strings.Contains(r.Command, want.path) {
			t.Errorf("%s must reference path %s; got %q", r.ID, want.path, r.Command)
		}
		if r.Expected != "~200" {
			t.Errorf("%s expected must be ~200; got %q", r.ID, r.Expected)
		}
	}

	for _, r := range s.Rows {
		if r.ID != "C8" {
			continue
		}
		if !strings.Contains(r.Command, "thanos tools bucket ls") {
			t.Errorf("C8 must invoke thanos tools bucket ls; got %q", r.Command)
		}
	}

	// C9 must use /api/v1/stores + a numeric (rc-based) expected value,
	// and must specifically check for a "sidecar" group — not just any
	// store endpoint, which would trivially pass on the local Store
	// Gateway alone even with zero sites connected (see doc comment).
	for _, r := range s.Rows {
		if r.ID != "C9" {
			continue
		}
		if !strings.Contains(r.Command, "/api/v1/stores") {
			t.Errorf("C9 must hit /api/v1/stores; got %q", r.Command)
		}
		if !strings.Contains(r.Command, "sidecar") {
			t.Errorf(`C9 must check for a "sidecar" group specifically (not just any store endpoint); got %q`, r.Command)
		}
		if r.Expected != "0" {
			t.Errorf("C9 expected must be rc-based \"0\"; got %q", r.Expected)
		}
	}

	// C10 must query /api/v1/query and assert on the "site" label key
	// (not a hardcoded site name — deployments name their sites freely).
	for _, r := range s.Rows {
		if r.ID != "C10" {
			continue
		}
		if !strings.Contains(r.Command, "/api/v1/query") {
			t.Errorf("C10 must hit /api/v1/query; got %q", r.Command)
		}
		if !strings.Contains(r.Command, `site`) {
			t.Errorf(`C10 must assert on the "site" label key; got %q`, r.Command)
		}
	}

	// No credentials belong in a spec (AGENTS.md).
	for _, r := range s.Rows {
		lower := strings.ToLower(r.Command)
		for _, forbidden := range []string{"secret_key", "access_key", "password"} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("%s must not reference %q (no credentials in spec); got %q", r.ID, forbidden, r.Command)
			}
		}
	}

	fs := Lint(s)
	if HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", joinFindings(fs))
	}

	pb, err := Generate(s, GenerateOptions{IncludeRaw: true})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	covered := map[string]bool{}
	for _, tk := range pb.Tasks {
		for _, id := range tk.SourceIDs {
			covered[id] = true
		}
	}
	for _, id := range wantIDs {
		if !covered[id] {
			t.Errorf("spec row %s is not covered by any generated task", id)
		}
	}
}
