package spec

import (
	"os"
	"strings"
	"testing"
)

// TestRegression_AlertmanagerSpec locks the structure of
// docs/verification/alertmanager.md (v1.4 — central Alertmanager, container
// role co-located with docs/verification/thanos-query.md and consumed by
// docs/verification/prometheus.md per-site role):
//
//	C1     pilot-alertmanager container running
//	C2-C3  Alertmanager /-/healthy, /-/ready (9093)
//	C4     alertmanager.yml valid (amtool check-config)
//	C5     alertmanager.yml contains a "route:" block (non-empty)
//	C6     /api/v2/status returns 200
//	C7     push a synthetic alert and read it back via /api/v2/alerts
//	       (end-to-end self-test, mirrors dashboard.md C7 / Loki push-pull
//	       pattern; isolates Alertmanager's own receive API from downstream
//	       receiver routing which is configured via vault)
//	C8     pilot-alertmanager-teams-proxy container running + /healthz
//	       200 when present; absent (non-teams mode) also passes
//	C9     proxy's Alertmanager -> Adaptive Card transform is correct
//	       (POST /render self-test, no real Teams delivery); absent
//	       (non-teams mode) also passes
//
// C8/C9 exist because Alertmanager's webhook_configs always POSTs its own
// fixed JSON envelope, never an Adaptive Card — a Power Automate "When a
// Teams webhook request is received" flow rejects that body with
// AdaptiveSerializationException: Property 'type' must be 'AdaptiveCard'.
// alertmanager_teams_config now points webhook_configs at this proxy
// instead of the real Power Automate URL directly.
//
// Cross-row invariants locked below:
//
//   - C1 must reference the exact container name the apply playbook creates
//     (pilot-alertmanager).
//   - C2/C3/C6 must hit the Alertmanager HTTP API on the correct port (9093)
//     and check the standard Prometheus-style health/ready paths.
//   - C4 must invoke `amtool check-config` (not a plain file existence
//     check) — a syntactically-valid but semantically-broken config still
//     causes Alertmanager to fail at startup with a generic error, and
//     `amtool` is the canonical way to catch this before applying.
//   - C5 must assert on a `route:` line specifically (not just any
//     non-empty check) — confirms the operator actually configured a
//     routing tree rather than a half-empty stub.
//   - C7 must push via POST /api/v2/alerts and read back via GET
//     /api/v2/alerts; expected is a numeric rc (not a substring) so the
//     verify pipeline returns a stable pass/fail signal.
//   - No row may leak credentials into the spec text (AGENTS.md).
//
// This role follows the "single host + target_group override" exception
// pattern (AGENTS.md §3) — spec lists only the `alertmanager` group while
// real inventory sites the role on whatever host the operator wants
// (typically co-located with thanos-query), via -e target_group=... on
// real hosts. Therefore this test does NOT apply
// TestRegression_SpecAndInventoryAgree (that helper assumes the spec
// group's host set equals the inventory's group host set, which would
// force a 1:1 mapping that contradicts the documented co-location
// flexibility).
func TestRegression_AlertmanagerSpec(t *testing.T) {
	const specPath = "../../docs/verification/alertmanager.md"
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

	wantContainer := map[string]string{
		"C1": "pilot-alertmanager",
		"C8": "pilot-alertmanager-teams-proxy",
		"C9": "pilot-alertmanager-teams-proxy",
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
		"C2": {"9093", "/-/healthy"},
		"C3": {"9093", "/-/ready"},
		"C6": {"9093", "/api/v2/status"},
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

	// C4 must invoke `amtool check-config` (canonical Alertmanager config
	// linter), not just a file existence test — a syntactically valid YAML
	// that doesn't conform to Alertmanager's schema would still crash
	// Alertmanager at startup with a generic error, and only amtool catches
	// it before the container is up.
	for _, r := range s.Rows {
		if r.ID != "C4" {
			continue
		}
		if !strings.Contains(r.Command, "amtool check-config") {
			t.Errorf("C4 must invoke amtool check-config; got %q", r.Command)
		}
		if r.Expected != "0" {
			t.Errorf("C4 expected must be rc-based \"0\"; got %q", r.Expected)
		}
	}

	// C5 must assert on a route key in either YAML or JSON — Alertmanager
	// accepts both formats, and the vault editor stores multiline-free values
	// most safely as compact JSON.
	for _, r := range s.Rows {
		if r.ID != "C5" {
			continue
		}
		if !strings.Contains(r.Command, "route:") || !strings.Contains(r.Command, `\"route\"`) {
			t.Errorf(`C5 must accept both YAML "route:" and JSON "route" keys; got %q`, r.Command)
		}
		if r.Expected != "0" {
			t.Errorf("C5 expected must be rc-based \"0\"; got %q", r.Expected)
		}
	}

	// C7 must push via POST /api/v2/alerts and read back via GET
	// /api/v2/alerts; expected is rc-based 0 (curl + grep -q chain).
	for _, r := range s.Rows {
		if r.ID != "C7" {
			continue
		}
		if !strings.Contains(r.Command, "/api/v2/alerts") {
			t.Errorf("C7 must hit /api/v2/alerts; got %q", r.Command)
		}
		if r.Expected != "0" {
			t.Errorf("C7 expected must be rc-based \"0\"; got %q", r.Expected)
		}
	}

	// C8 must be present-or-healthy (not mandatory-present) so it doesn't
	// spuriously fail in null/custom mode, where the proxy container is
	// legitimately absent.
	for _, r := range s.Rows {
		if r.ID != "C8" {
			continue
		}
		if !strings.Contains(r.Command, "/healthz") {
			t.Errorf("C8 must probe /healthz; got %q", r.Command)
		}
		if !strings.Contains(r.Command, "else true; fi") {
			t.Errorf("C8 must treat proxy-absent as pass (non-teams mode); got %q", r.Command)
		}
		if r.Expected != "0" {
			t.Errorf("C8 expected must be rc-based \"0\"; got %q", r.Expected)
		}
	}

	// C9 exercises the Alertmanager -> Adaptive Card transform via the
	// proxy's /render self-test endpoint (no live Teams delivery), and
	// must assert on the literal AdaptiveCard type field — this is the
	// exact defect class (missing/wrong "type") that broke real Teams
	// delivery before this proxy existed.
	for _, r := range s.Rows {
		if r.ID != "C9" {
			continue
		}
		if !strings.Contains(r.Command, "/render") {
			t.Errorf("C9 must hit the proxy's /render self-test endpoint; got %q", r.Command)
		}
		if !strings.Contains(r.Command, `\"type\": \"AdaptiveCard\"`) {
			t.Errorf("C9 must assert on the AdaptiveCard type field; got %q", r.Command)
		}
		if !strings.Contains(r.Command, "else true; fi") {
			t.Errorf("C9 must treat proxy-absent as pass (non-teams mode); got %q", r.Command)
		}
		if r.Expected != "0" {
			t.Errorf("C9 expected must be rc-based \"0\"; got %q", r.Expected)
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

	data, err := os.ReadFile("../../playbooks/apply/alertmanager-apply.yml")
	if err != nil {
		t.Fatalf("read Alertmanager apply playbook: %v", err)
	}
	playbook := string(data)
	for _, required := range []string{
		"alertmanager_receiver_mode_effective",
		"['null', 'teams', 'custom']",
		"alertmanager_teams_webhook_url",
		"match('^https://\\S+$')",
		"send_resolved: true",
		"alertmanager_config | length > 0",
		"pilot-alertmanager-teams-proxy",
		"http://pilot-alertmanager-teams-proxy:8095/webhook",
		"TEAMS_WEBHOOK_URL",
		"alertmanager-teams-proxy.py",
		"alertmanager_forward_to_agent_controller",
		"alertmanager_agent_controller_webhook_url",
		"agent_controller_webhook_secret",
		"/webhooks/alertmanager",
	} {
		if !strings.Contains(playbook, required) {
			t.Errorf("Alertmanager receiver-mode playbook missing %q", required)
		}
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
