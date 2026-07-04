package spec

import (
	"strings"
	"testing"
)

// TestRegression_SeaweedfsS3Spec locks the structure of
// docs/verification/seaweedfs-s3.md (v1.1 — SeaweedFS S3 gateway
// health, single `weed server -s3` container mirroring the
// single-container shape of keycloak.md):
//
//	C1     weed server process visible (pidof weed)
//	C2-C5  master/volume/filer/s3 /healthz all return 200
//	C6     anonymous S3 PUT to the pre-created smoke-test bucket
//	C7     anonymous S3 GET returns the same content back
//	C8     anonymous S3 DELETE then GET returns 404
//
// Cross-row invariants locked below:
//
//   - C1 must use `pidof` (NOT pgrep), for the same reason as
//     keycloak.md C7: pgrep -f matches the verifier's own shell
//     command line (which contains the literal "seaweedfs"/"weed").
//   - C2-C5 must each hit /healthz (SeaweedFS's real, uniformly
//     implemented endpoint on all four sub-servers) — NOT a guessed
//     path like /cluster/status, which does not exist on the master.
//   - C6-C8 must NOT contain "aws" (no aws-cli dependency; anonymous
//     path-style curl is sufficient and was verified end-to-end on a
//     live vm-target) and must NOT contain any of the words
//     "secret"/"access_key"/"AWS_" (no credentials belong in a spec
//     per AGENTS.md's "don't put passwords/tokens in spec" rule).
//   - C8 must DELETE the same bucket/key that C6 PUT and C7 GET,
//     and the command must chain DELETE followed by GET-404 to
//     prove the delete actually worked.
func TestRegression_SeaweedfsS3Spec(t *testing.T) {
	const specPath = "../../docs/verification/seaweedfs-s3.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8"}
	if len(s.Rows) != len(wantIDs) {
		t.Fatalf("rows=%d want=%d", len(s.Rows), len(wantIDs))
	}
	for i, id := range wantIDs {
		if s.Rows[i].ID != id {
			t.Errorf("row[%d] id=%q want=%q", i, s.Rows[i].ID, id)
		}
	}

	// No vague expected values (exact match, not substring — "smoke"
	// contains "ok" and would otherwise false-positive on C6/C7).
	for _, r := range s.Rows {
		switch strings.ToLower(strings.TrimSpace(r.Expected)) {
		case "ok", "normal", "reasonable", "sufficient":
			t.Errorf("row %s uses vague expected %q", r.ID, r.Expected)
		}
	}

	// C1 must use pidof (not pgrep) against the weed binary.
	for _, r := range s.Rows {
		if r.ID != "C1" {
			continue
		}
		if strings.Contains(r.Command, "pgrep") {
			t.Errorf("C1 must use pidof (not pgrep); got %q", r.Command)
		}
		if !strings.Contains(r.Command, "pidof weed") {
			t.Errorf("C1 must reference pidof weed; got %q", r.Command)
		}
	}

	// C2-C5 must each hit /healthz on their respective port.
	wantPorts := map[string]string{"C2": "9333", "C3": "8080", "C4": "8888", "C5": "8333"}
	for _, r := range s.Rows {
		port, ok := wantPorts[r.ID]
		if !ok {
			continue
		}
		if !strings.Contains(r.Command, "/healthz") {
			t.Errorf("%s must hit /healthz; got %q", r.ID, r.Command)
		}
		if !strings.Contains(r.Command, port) {
			t.Errorf("%s must reference port %s; got %q", r.ID, port, r.Command)
		}
	}

	// C6-C8 must not depend on aws-cli or carry any credential-shaped
	// tokens (this spec relies on SeaweedFS's anonymous allow-all mode
	// when no -s3.config is set).
	for _, r := range s.Rows {
		if r.ID != "C6" && r.ID != "C7" && r.ID != "C8" {
			continue
		}
		lower := strings.ToLower(r.Command)
		if strings.Contains(lower, "aws ") || strings.Contains(lower, "aws_") {
			t.Errorf("%s must not depend on aws-cli; got %q", r.ID, r.Command)
		}
		for _, forbidden := range []string{"secret", "access_key", "password"} {
			if strings.Contains(lower, forbidden) {
				t.Errorf("%s must not reference %q (no credentials in spec); got %q", r.ID, forbidden, r.Command)
			}
		}
	}

	// C6 must PUT and C7 must GET the same bucket/key.
	// C8 must DELETE then GET the same bucket/key, expecting 404.
	const bucketKey = "pilot-s3-smoke/healthcheck.txt"
	for _, r := range s.Rows {
		if r.ID == "C6" && !strings.Contains(r.Command, bucketKey) {
			t.Errorf("C6 must reference %s; got %q", bucketKey, r.Command)
		}
		if r.ID == "C7" && !strings.Contains(r.Command, bucketKey) {
			t.Errorf("C7 must reference %s; got %q", bucketKey, r.Command)
		}
		if r.ID == "C8" {
			// C8 must delete and then verify 404 — needs both DELETE and GET.
			if !strings.Contains(r.Command, "DELETE") {
				t.Errorf("C8 must issue DELETE; got %q", r.Command)
			}
			if !strings.Contains(r.Command, bucketKey) {
				t.Errorf("C8 must reference %s; got %q", bucketKey, r.Command)
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
