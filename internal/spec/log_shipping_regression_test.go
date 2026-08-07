package spec

import (
	"os"
	"strings"
	"testing"
)

// TestRegression_LogShippingSpec locks the structure of
// docs/verification/log-shipping.md (v1.2 — Promtail agent layered on top
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
//	C8  config references the host-label pipeline stage (source: filename)
//	C9  functional: query back filtered by {job=..., host="$(hostname)"} —
//	    proves the host label is not just present but actually equals this
//	    host's own name, not just "some value"
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
//   - C9 must be the row that proves per-host coverage is actually
//     queryable (not just "some data arrived somewhere") — this is the row
//     that would have caught a real incident where multiple hosts'
//     forwarded logs landed in one undifferentiated Loki stream with no
//     way to confirm any specific host's coverage.
//   - No row may leak credentials into the spec text (AGENTS.md).
func TestRegression_LogShippingSpec(t *testing.T) {
	const specPath = "../../docs/verification/log-shipping.md"
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

	// C8: config check for the host-label pipeline stage.
	for _, r := range s.Rows {
		if r.ID != "C8" {
			continue
		}
		if !strings.Contains(r.Command, "filename") {
			t.Errorf("C8 must check for the filename-sourced pipeline stage; got %q", r.Command)
		}
	}

	// C9: functional per-host proof — must inject locally, use this host's
	// own hostname as the host label filter, and query through the
	// pilot-loki-backend alias (not just check C6's "arrived somewhere").
	for _, r := range s.Rows {
		if r.ID != "C9" {
			continue
		}
		if !strings.Contains(r.Command, "logger") {
			t.Errorf("C9 must inject a local test message via logger; got %q", r.Command)
		}
		if !strings.Contains(r.Command, `host=\"$(hostname)\"`) {
			t.Errorf(`C9 must filter the query by host=\"$(hostname)\" (this host's own name, not a fixed value); got %q`, r.Command)
		}
		if !strings.Contains(r.Command, "pilot-loki-backend") {
			t.Errorf("C9 must query back through the pilot-loki-backend alias; got %q", r.Command)
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

// TestRegression_LogShippingScrapesSiemLogRootAlwaysAndWazuhAlertsAdditively
// locks the fix for a real production incident (2026-08-06): v1.0 let a
// co-located wazuh-manager container's real alerts-log volume REPLACE
// siem_log_root_effective entirely, on the assumption that "when log-server
// is empty and wazuh-manager is the de facto SIEM receiver" was the normal
// case. Combined with a since-fixed bug in log-server-apply.yml (which
// never actually ran when wazuh-manager was present), this silently
// dropped every forwarded local6/auth/authpriv log — Promtail was tailing
// Wazuh's own alerts, never log-server's real receiver output, and
// docs/verification/log-shipping.md's own C3 hardcodes the siem_log_root
// path as always-expected. siem_log_root must always be scraped; the
// wazuh-manager alerts path must only ever be ADDED as a second, separate
// scrape job, never substituted in its place.
func TestRegression_LogShippingScrapesSiemLogRootAlwaysAndWazuhAlertsAdditively(t *testing.T) {
	playbookPath := "../../playbooks/apply/log-shipping-apply.yml"
	b, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	s := string(b)

	// siem_log_root_effective must resolve from siem_log_root/default only
	// — never from the wazuh-detected path.
	resolveIdx := strings.Index(s, "siem_log_root_effective:")
	if resolveIdx < 0 {
		t.Fatal("log-shipping-apply.yml must define siem_log_root_effective")
	}
	resolveLine := s[resolveIdx : resolveIdx+strings.Index(s[resolveIdx:], "\n")]
	if strings.Contains(resolveLine, "siem_log_root_wazuh_detected") {
		t.Error("siem_log_root_effective must never fall back to siem_log_root_wazuh_detected — that regresses to silently dropping log-server's real receiver output whenever a wazuh-manager container is co-located")
	}
	if !strings.Contains(resolveLine, "siem_log_root_default") {
		t.Error("siem_log_root_effective must fall back to siem_log_root_default, matching log-shipping.md C3's hardcoded /var/log/siem expectation")
	}

	if !strings.Contains(s, "siem_log_root_wazuh_detected") {
		t.Fatal("log-shipping-apply.yml must still resolve siem_log_root_wazuh_detected as a separate, additive fact")
	}
	if !strings.Contains(s, "promtail_wazuh_job_label") {
		t.Error("log-shipping-apply.yml must render a second, separate scrape job (promtail_wazuh_job_label) for the wazuh-detected path, additive to the primary siem_log_root job")
	}

	// The rendered Promtail config must always include the primary
	// siem_log_root scrape block unconditionally (never behind an
	// {% if %} on siem_log_root_wazuh_detected).
	primaryBlockIdx := strings.Index(s, "__path__: {{ siem_log_root_effective }}")
	if primaryBlockIdx < 0 {
		t.Fatal("rendered config must always scrape siem_log_root_effective")
	}
	precedingContent := s[:primaryBlockIdx]
	lastIf := strings.LastIndex(precedingContent, "{% if")
	lastEndif := strings.LastIndex(precedingContent, "{% endif %}")
	if lastIf > lastEndif {
		t.Error("the primary siem_log_root scrape block must not be wrapped in an {% if %} — it must always be present")
	}

	// The additive wazuh block must be conditional (only rendered when
	// siem_log_root_wazuh_detected is actually non-empty), and must scrape
	// only alerts/alerts.json (v1.3) — never the broad **/*.log glob, which
	// also matches archives.log/api.log/cluster.log that Wazuh's default
	// config (<logall>/<logall_json> both "no") never writes content into,
	// making their scrape targets permanently show a stuck read position
	// that looks like a bug but is actually just "nothing to read, by
	// design". It must also not scrape the plain-text alerts.log (v1.2's
	// mistake): Wazuh writes both alerts.log and alerts.json side by side
	// for every alert, but the json pipeline stage that extracts the host
	// label needs the JSON one — pointed at alerts.log, every line fails to
	// parse as JSON and the host label never populates at all (confirmed
	// live 2026-08-07, minimal-poc round 20: the Loki series API showed
	// zero host labels anywhere under this job despite the stream having
	// real content).
	wazuhBlockIdx := strings.Index(s, "siem_log_root_wazuh_detected }}/alerts/alerts.json")
	if wazuhBlockIdx < 0 {
		t.Fatal("rendered config must scrape siem_log_root_wazuh_detected + /alerts/alerts.json when present (not alerts.log, not a broader glob)")
	}
	if !strings.Contains(s[:wazuhBlockIdx], "{% if siem_log_root_wazuh_detected") {
		t.Error("the wazuh-alerts scrape block must be gated behind {% if siem_log_root_wazuh_detected %} — it is additive, not unconditional")
	}
	if strings.Contains(s, "siem_log_root_wazuh_detected }}/**/*.log") {
		t.Error("the wazuh-alerts scrape block must not use the broad **/*.log glob (v1.2 narrowed it to alerts/, v1.3 to the exact json file)")
	}
	if strings.Contains(s, "siem_log_root_wazuh_detected }}/alerts/*.log") {
		t.Error("the wazuh-alerts scrape block must not scrape the plain-text alerts.log — its json pipeline stage cannot parse non-JSON lines, so the host label never populates (v1.3 fix: point at alerts.json instead)")
	}
}

// TestRegression_LogShippingHostLabelIsQueryable locks the fix for a real
// gap (2026-08-06): v1.1's two scrape jobs (siem_log_root and the additive
// wazuh-alerts path) both landed in Loki with no label distinguishing which
// source host each line came from — an operator could confirm "some data
// arrived" (C6) but not "host X's data arrived" for any specific host,
// which is exactly what "prove every host is covered" requires. Both jobs
// must promote a real `host` label: the primary job via a regex pipeline
// stage on Promtail's built-in `filename` label (populated automatically
// per matched file — the rsyslog receiver already dynaFiles by %HOSTNAME%,
// see log-server-apply.yml), the wazuh-alerts job via a json pipeline
// stage extracting each alert's own `agent.name` field.
func TestRegression_LogShippingHostLabelIsQueryable(t *testing.T) {
	playbookPath := "../../playbooks/apply/log-shipping-apply.yml"
	b, err := os.ReadFile(playbookPath)
	if err != nil {
		t.Fatalf("read %s: %v", playbookPath, err)
	}
	s := string(b)

	primaryIdx := strings.Index(s, "__path__: {{ siem_log_root_effective }}")
	wazuhIdx := strings.Index(s, "__path__: {{ siem_log_root_wazuh_detected }}")
	if primaryIdx < 0 || wazuhIdx < 0 {
		t.Fatal("could not locate both scrape job __path__ lines")
	}

	primarySection := s[primaryIdx:wazuhIdx]
	if !strings.Contains(primarySection, "pipeline_stages") {
		t.Error("the primary siem_log_root job must have pipeline_stages to derive a host label")
	}
	if !strings.Contains(primarySection, "source: filename") {
		t.Error("the primary job's host label must be derived from Promtail's built-in filename label")
	}
	if !strings.Contains(primarySection, "labels:") || !strings.Contains(primarySection, "host:") {
		t.Error("the primary job must promote the regex capture to a real `host` label")
	}

	wazuhSection := s[wazuhIdx:]
	if !strings.Contains(wazuhSection, "pipeline_stages") {
		t.Error("the wazuh-alerts job must have pipeline_stages to derive a host label")
	}
	if !strings.Contains(wazuhSection, "agent.name") {
		t.Error("the wazuh-alerts job's host label must be derived from each alert's agent.name field")
	}
}
