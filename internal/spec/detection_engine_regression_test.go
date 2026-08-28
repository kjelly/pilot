package spec

import (
	"os"
	"strings"
	"testing"
)

// TestRegression_DetectionEngineSpec locks the structure of
// docs/verification/detection-engine.md (Stage A, spec §47's C1-C12) and a
// handful of playbook-source invariants that must never regress:
//
//	C1  installed artifact + version format
//	C2  dedicated pilot-detect account + active service
//	C3  config schema validates
//	C4  SQLite integrity + ownership/mode
//	C5  no TCP/UDP listener
//	C6  status/textfile parseable and secret-free
//	C7  Thanos source healthy (never :10902)
//	C8  subjects derived from canonical identity
//	C9  telemetry cycles succeed against the real feed
//	C10 no false anomaly on a cold-start host
//	C11 fixture-lane-evidenced outbox/lifecycle scenario (verifyOnly)
//	C12 no provider secret while disabled
func TestRegression_DetectionEngineSpec(t *testing.T) {
	const specPath = "../../docs/verification/detection-engine.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12"}
	if len(s.Rows) != len(wantIDs) {
		t.Fatalf("rows=%d want=%d", len(s.Rows), len(wantIDs))
	}
	for i, id := range wantIDs {
		if s.Rows[i].ID != id {
			t.Errorf("row[%d] id=%q want=%q", i, s.Rows[i].ID, id)
		}
	}

	var c11 *Row
	for i := range s.Rows {
		if s.Rows[i].ID == "C11" {
			c11 = &s.Rows[i]
		}
	}
	if c11 == nil {
		t.Fatal("C11 row missing")
	}
	if !c11.VerifyOnly {
		t.Error("C11 must be verifyOnly — its scenario evidence comes from the fake-protocol topology lane (spec §49), not a single already-applied host")
	}

	// Every non-verifyOnly row must declare an isolatedMutation-free
	// (readOnly) action — Stage A verification never mutates the target.
	for _, r := range s.Rows {
		if r.Action == nil {
			continue
		}
		if r.Action.Mode != "readOnly" {
			t.Errorf("%s: action mode = %q, want readOnly (Stage A verification is read-only)", r.ID, r.Action.Mode)
		}
	}

	// C12 must assert on the exact provider.env path spec §33/§45 owns.
	for _, r := range s.Rows {
		if r.ID != "C12" {
			continue
		}
		if !strings.Contains(r.Command, "/etc/pilot/detection-engine/provider.env") {
			t.Errorf("C12 must assert on /etc/pilot/detection-engine/provider.env; got %q", r.Command)
		}
	}

	// No credentials belong in a spec (AGENTS.md).
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

	playbookRaw, err := os.ReadFile("../../playbooks/apply/detection-engine-apply.yml")
	if err != nil {
		t.Fatalf("read detection-engine-apply.yml: %v", err)
	}
	applyRaw := string(playbookRaw)

	// spec §10: the Detection-facing Thanos endpoint is always :10912;
	// :10902 must never appear as an actual `url:` connection target in
	// this playbook (only in explanatory comments, which legitimately
	// reference it to document the invariant).
	if !strings.Contains(applyRaw, ":10912") {
		t.Error("detection-engine-apply.yml must connect to Thanos Query on :10912")
	}
	for _, line := range strings.Split(applyRaw, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.Contains(trimmed, "url:") && strings.Contains(trimmed, "10902") {
			t.Errorf("detection-engine-apply.yml must never connect to :10902 (the Thanos Sidecar's container-internal port); got line %q", trimmed)
		}
	}

	// spec §6.3: controller-side artifact existence/SHA256/version must be
	// gated before any mutation, and re-verified again on the target after
	// copy.
	for _, want := range []string{
		"detection_engine_artifact_abs_path",
		"checksum_algorithm: sha256",
		"detection_engine_artifact_sha256",
	} {
		if !strings.Contains(applyRaw, want) {
			t.Errorf("detection-engine-apply.yml must reference %q (spec §6.3 artifact verification)", want)
		}
	}

	// spec §33/§45: Stage A always removes/never creates provider.env.
	if !strings.Contains(applyRaw, "provider.env") || !strings.Contains(applyRaw, "state: absent") {
		t.Error("detection-engine-apply.yml must ensure provider.env is absent (Stage A provider always disabled)")
	}

	// spec §8: minimum required systemd hardening directives.
	for _, want := range []string{
		"NoNewPrivileges=yes",
		"ProtectSystem=strict",
		"CapabilityBoundingSet=",
	} {
		if !strings.Contains(applyRaw, want) {
			t.Errorf("detection-engine-apply.yml systemd unit must set %q (spec §8)", want)
		}
	}

	// spec §44: `state: restarted` must stay conditional on something
	// actually changing — never unconditional (idempotency).
	if strings.Contains(applyRaw, "state: restarted\n          when: not ansible_check_mode\n") {
		t.Error("pilot-detection-engine.service restart must be gated on an actual change, not unconditional")
	}
}
