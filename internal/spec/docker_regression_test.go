package spec

import (
	"strings"
	"testing"
)

// TestRegression_DockerSpec locks the structure of docs/verification/docker.md.
// C1-C8 cover docker engine end-to-end health: package, service, CLI,
// socket, hello-world pull, network, compose, cgroup.
//
// Cross-row invariants:
//
//   - C1 must use dpkg-query -W -f=${Package} (NOT `dpkg -l | grep`)
//     — same lesson as core-infra-provider-db C1: client-only false
//     positives. The package here is `docker.io` (not just `docker`).
//   - C5 must use `docker run --rm hello-world` (idempotent + the
//     smallest possible end-to-end smoke). If a future maintainer
//     swaps in a custom image, that change needs conscious review.
//   - C4 must reference /var/run/docker.sock by literal path.
//   - C7 must reference the v2 plugin (`docker compose version`, NOT
//     `docker-compose --version` which is the legacy v1 binary).
func TestRegression_DockerSpec(t *testing.T) {
	const specPath = "../../docs/verification/docker.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	// 1. C1..C8 inclusive, no gaps, no duplicates.
	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8"}
	if len(s.Rows) != 8 {
		t.Fatalf("rows=%d want=8", len(s.Rows))
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

	// 3. C1 must use dpkg-query (not `dpkg -l | grep`) and name `docker.io`.
	for _, r := range s.Rows {
		if r.ID == "C1" {
			if !strings.Contains(r.Command, "dpkg-query") {
				t.Errorf("C1 must use dpkg-query -W -f=%%{Package}; got %q", r.Command)
			}
			if !strings.Contains(r.Command, "docker.io") {
				t.Errorf("C1 must mention the docker.io package (not bare `docker`); got %q", r.Command)
			}
		}
	}

	// 4. C4 must reference /var/run/docker.sock by literal path.
	for _, r := range s.Rows {
		if r.ID == "C4" && !strings.Contains(r.Command, "/var/run/docker.sock") {
			t.Errorf("C4 must reference /var/run/docker.sock; got %q", r.Command)
		}
	}

	// 5. C5 must use `docker run --rm hello-world`.
	for _, r := range s.Rows {
		if r.ID == "C5" {
			if !strings.Contains(r.Command, "docker run") {
				t.Errorf("C5 must use `docker run`; got %q", r.Command)
			}
			if !strings.Contains(r.Command, "hello-world") {
				t.Errorf("C5 must use hello-world image; got %q", r.Command)
			}
			if !strings.Contains(r.Command, "--rm") {
				t.Errorf("C5 must use --rm (don't leave a stopped container); got %q", r.Command)
			}
		}
	}

	// 6. C7 must use the v2 plugin (`docker compose version`, NOT
	//    the legacy `docker-compose --version` v1 binary).
	for _, r := range s.Rows {
		if r.ID == "C7" {
			if strings.Contains(r.Command, "docker-compose ") || strings.Contains(r.Command, "docker-compose$") {
				t.Errorf("C7 must use v2 plugin `docker compose` (NOT legacy `docker-compose`); got %q", r.Command)
			}
		}
	}

	// 7. Lint must not produce errors.
	fs := Lint(s)
	if HasErrors(fs) {
		t.Errorf("Lint produced errors:\n%s", joinFindings(fs))
	}
}
