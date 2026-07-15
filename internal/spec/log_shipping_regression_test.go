package spec

import (
	"os"
	"strings"
	"testing"
)

// TestRegression_LogShippingSpec locks the structure of
// docs/verification/log-shipping.md (v1.0 — Promtail agent layered on top
// of log-server.md, forwarding to dashboard.md's Loki):
//
//	C1  pilot-promtail container running
//	C2  Promtail /ready (9080)
//	C3  config references the siem_log_root scrape glob
//	C4  config references the pilot-loki-backend push URL
//	C5  /etc/hosts has the pilot-loki-backend alias pinned
//	C6  cross-host functional self-test: inject locally, query back from
//	    the central Loki via the alias
//	C7  positions dir exists
//
// Cross-row invariants locked below:
//
//   - C1 must reference the exact container name the apply playbook
//     creates.
//   - C3/C4 must reference the DEFAULT siem_log_root/loki_alias values as
//     static text (deployments that override these are a documented known
//     deviation — spec §5 — not something this spec's Command column can
//     template per the "static text authored once" rule).
//   - C6 must be the one row that actually proves cross-host delivery
//     (hits the loki push-then-query round trip through the alias, not
//     just a local Promtail health check) — this is the row that would
//     have caught a real "Promtail up but nothing ever arrives" failure
//     that C1-C5 alone cannot detect.
//   - No row may leak credentials into the spec text (AGENTS.md).
func TestRegression_LogShippingSpec(t *testing.T) {
	const specPath = "../../docs/verification/log-shipping.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7"}
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

	for _, r := range s.Rows {
		if r.ID != "C1" {
			continue
		}
		if !strings.Contains(r.Command, "pilot-promtail") {
			t.Errorf("C1 must reference container pilot-promtail; got %q", r.Command)
		}
		if !strings.Contains(r.Command, "docker ps") {
			t.Errorf("C1 must check via docker ps; got %q", r.Command)
		}
	}

	for _, r := range s.Rows {
		if r.ID != "C2" {
			continue
		}
		if !strings.Contains(r.Command, "9080") || !strings.Contains(r.Command, "/ready") {
			t.Errorf("C2 must hit port 9080 /ready; got %q", r.Command)
		}
		if r.Expected != "~200" {
			t.Errorf("C2 expected must be ~200; got %q", r.Expected)
		}
	}

	for _, r := range s.Rows {
		if r.ID != "C3" {
			continue
		}
		if !strings.Contains(r.Command, "/var/log/siem") {
			t.Errorf("C3 must reference the default siem_log_root; got %q", r.Command)
		}
	}

	for _, r := range s.Rows {
		switch r.ID {
		case "C4", "C5":
			if !strings.Contains(r.Command, "pilot-loki-backend") {
				t.Errorf("%s must reference the pilot-loki-backend alias; got %q", r.ID, r.Command)
			}
		}
	}

	// C4's rendered config value is quoted (`url: "http://..."`, from the
	// apply playbook's `url: "http://{{ loki_endpoint }}/..."` template) —
	// a real bug caught via vm-target verify: an earlier unquoted grep
	// pattern never matched the actual file and always failed C4.
	for _, r := range s.Rows {
		if r.ID != "C4" {
			continue
		}
		if !strings.Contains(r.Command, `"http://pilot-loki-backend`) {
			t.Errorf(`C4 must match the quoted rendered URL (url: "http://..."); got %q`, r.Command)
		}
	}

	// C6 is the cross-host proof: must inject locally AND query back
	// through the central alias, not just check local Promtail health.
	for _, r := range s.Rows {
		if r.ID != "C6" {
			continue
		}
		if !strings.Contains(r.Command, "logger") {
			t.Errorf("C6 must inject a local test message via logger; got %q", r.Command)
		}
		if !strings.Contains(r.Command, "pilot-loki-backend") {
			t.Errorf("C6 must query back through the pilot-loki-backend alias; got %q", r.Command)
		}
		if !strings.Contains(r.Command, "/loki/api/v1/query") {
			t.Errorf("C6 must query via /loki/api/v1/query; got %q", r.Command)
		}
	}

	// No row's Command may contain a {{ var }} — Command/Expected columns
	// are static text authored once (see dashboard.md's C5/C6/C9/C10 real
	// bug: a leftover {{ var }} silently reports rc=2 under ansible
	// ad-hoc instead of an obvious "undefined variable" error).
	for _, r := range s.Rows {
		if strings.Contains(r.Command, "{{") {
			t.Errorf("%s command must be static text, not a templated var; got %q", r.ID, r.Command)
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

func TestRegression_LogShippingPlaybookAutoDetectsDashboardHost(t *testing.T) {
	playbookPath := "../../playbooks/apply/log-shipping-apply.yml"
	b, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	s := string(b)
	for _, required := range []string{
		`groups["dashboard"]`,
		`ansible_host`,
		`loki_effective_target_host`,
		`loki_target_host | default("", true) or loki_inventory_target_host`,
	} {
		if !strings.Contains(s, required) {
			t.Errorf("log-shipping playbook must contain inventory auto-detection fragment %q", required)
		}
	}
	if !strings.Contains(s, `line: "{{ loki_effective_target_host }}\t{{ loki_alias }}"`) {
		t.Error("/etc/hosts pin must use the effective Loki target")
	}
}
