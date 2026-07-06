package spec

import (
	"strings"
	"testing"
)

// TestRegression_PrometheusSpec locks the structure of
// docs/verification/prometheus.md (v1.0 — per-site Prometheus + Thanos
// Sidecar, container-backed pair mirroring seaweedfs-s3.md/keycloak.md):
//
//	C1     pilot-prometheus container running
//	C2     pilot-thanos-sidecar container running
//	C3-C4  Prometheus /-/healthy, /-/ready (9090)
//	C5-C6  Thanos Sidecar /-/healthy, /-/ready (10902)
//	C7     Prometheus self-scrape up==1
//	C8     prometheus.yml has external_labels.site configured
//	C9     Thanos Sidecar can read the object storage bucket
//
// Cross-row invariants locked below:
//
//   - C1/C2 must reference the exact container names the apply playbook
//     creates (pilot-prometheus / pilot-thanos-sidecar) — these names are
//     also relied on by thanos-query-apply.yml's `--prometheus.url`
//     container-name resolution over the shared docker network.
//   - C3-C6 must each hit the Prometheus-family readiness/health paths
//     (/-/healthy, /-/ready) on the correct port — NOT a guessed path.
//   - C9 must invoke `thanos tools bucket ls` against the sidecar's own
//     objstore config file, not depend on waiting for a real 2h TSDB
//     block upload (impractical to verify synchronously at apply time —
//     see the spec's own note on this).
//   - No row may leak the S3 secret key into the spec text (AGENTS.md).
func TestRegression_PrometheusSpec(t *testing.T) {
	const specPath = "../../docs/verification/prometheus.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9"}
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

	wantContainer := map[string]string{"C1": "pilot-prometheus", "C2": "pilot-thanos-sidecar"}
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
		"C3": {"9090", "/-/healthy"},
		"C4": {"9090", "/-/ready"},
		"C5": {"10902", "/-/healthy"},
		"C6": {"10902", "/-/ready"},
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
		if r.ID != "C9" {
			continue
		}
		if !strings.Contains(r.Command, "thanos tools bucket ls") {
			t.Errorf("C9 must invoke thanos tools bucket ls; got %q", r.Command)
		}
		if !strings.Contains(r.Command, "objstore.config-file") {
			t.Errorf("C9 must reference the sidecar's objstore config file; got %q", r.Command)
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
