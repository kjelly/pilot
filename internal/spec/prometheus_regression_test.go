package spec

import (
	"os"
	"strings"
	"testing"
)

// TestRegression_PrometheusSpec locks the structure of
// docs/verification/prometheus.md (v1.2 — per-site Prometheus + Thanos
// Sidecar + Alertmanager forwarding, container-backed trio mirroring
// seaweedfs-s3.md/keycloak.md; plus node-exporter scrape auto-discovery):
//
//	C1     pilot-prometheus container running
//	C2     pilot-thanos-sidecar container running
//	C3-C4  Prometheus /-/healthy, /-/ready (9090)
//	C5-C6  Thanos Sidecar /-/healthy, /-/ready (10902)
//	C7     Prometheus self-scrape up==1
//	C8     prometheus.yml has external_labels.site configured
//	C9     Thanos Sidecar can read the object storage bucket
//	C10    alert-rules.yml is valid (promtool check rules)
//	C11    prometheus.yml contains alerting.alertmanagers block
//	       (only when alertmanager_target_host is set; escape hatch
//	       matches dashboard.md C8's thanos-query 連通性 pattern — see
//	       spec §1.5/§5)
//	C12    Prometheus has loaded rules (GET /api/v1/rules non-empty)
//	C13    prometheus.yml contains the auto-discovered node-exporter scrape
//	       job (only when the host-monitoring group has hosts, or
//	       node_exporter_targets was set explicitly — escape hatch matching
//	       C11's pattern)
//	C14    at least one node-exporter target was successfully (and
//	       authenticated) scraped (up{job="node"}==1) — proves the Basic
//	       Auth credential wiring actually works end to end, not just that
//	       the scrape job is present in config
//	C15    prometheus.yml's node-exporter scrape job carries a pilot_host
//	       label (Detection Engine spec §9 canonical subject identity;
//	       auto-discovery only — an explicit node_exporter_targets override
//	       has no inventory-hostname mapping and renders no label)
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
//   - C10 must invoke `promtool check rules` (not just file existence) so
//     a syntactically-broken rules file is caught at apply time, not when
//     Prometheus first tries to load it on a hot reload.
//   - C11 must assert on a top-level `alerting:` line in prometheus.yml —
//     a deeper `alerting.alertmanagers` check would still match the
//     conditional render but also pass on a half-empty config that forgot
//     the `alertmanagers:` list.
//   - C12 must query /api/v1/rules (the canonical Prometheus "rules are
//     loaded" endpoint) and assert on a static substring, NOT a hardcoded
//     rule name (operator may override prometheus_alert_rules per host).
//   - C13 must assert on a `job_name: node` line WITHOUT anchoring on a
//     leading `^-` — prometheus-apply.yml serializes the scrape job with
//     to_nice_yaml, which alphabetizes dict keys, so `job_name` is NOT the
//     first key of the list item on real output (`- basic_auth:` comes
//     first). A `^-\s*job_name:` anchor was tried and failed against a real
//     vm-target apply; verified empirically before landing this row.
//   - C14 must query the PromQL label matcher up{job="node"} with the
//     braces percent-encoded (%7B/%7D) — curl interprets unescaped {...} in
//     a URL as its own globbing syntax and errors before the request ever
//     reaches Prometheus (verified empirically against a live instance).
//   - No row may leak the S3 secret key or the node-exporter basic-auth
//     password into the spec text (AGENTS.md) — this file documents a
//     shared-credential contract in prose (§1.5) precisely so the actual
//     value never has to appear in a Command cell.
func TestRegression_PrometheusSpec(t *testing.T) {
	const specPath = "../../docs/verification/prometheus.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12", "C13", "C14", "C15"}
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

	// C10 must invoke promtool check rules (canonical Prometheus rule
	// linter) — a plain file existence check would pass on a syntactically
	// broken rules file that crashes Prometheus at first load.
	for _, r := range s.Rows {
		if r.ID != "C10" {
			continue
		}
		if !strings.Contains(r.Command, "promtool check rules") {
			t.Errorf("C10 must invoke promtool check rules; got %q", r.Command)
		}
		if r.Expected != "0" {
			t.Errorf("C10 expected must be rc-based \"0\"; got %q", r.Expected)
		}
	}

	// C11 must assert on a top-level `alerting:` line — distinguishes
	// the "alerting wired up" case from a half-empty config.
	for _, r := range s.Rows {
		if r.ID != "C11" {
			continue
		}
		if !strings.Contains(r.Command, "alerting:") {
			t.Errorf("C11 must assert on a top-level `alerting:` line; got %q", r.Command)
		}
		if r.Expected != "0" {
			t.Errorf("C11 expected must be rc-based \"0\"; got %q", r.Expected)
		}
	}

	// C12 must hit /api/v1/rules and assert on a static substring, not a
	// hardcoded rule name (operator can override prometheus_alert_rules).
	for _, r := range s.Rows {
		if r.ID != "C12" {
			continue
		}
		if !strings.Contains(r.Command, "/api/v1/rules") {
			t.Errorf("C12 must hit /api/v1/rules; got %q", r.Command)
		}
		if r.Expected != "0" {
			t.Errorf("C12 expected must be rc-based \"0\"; got %q", r.Expected)
		}
	}

	// C13 must assert on job_name: node WITHOUT anchoring on a leading `^-`
	// — to_nice_yaml alphabetizes keys, so job_name is not the list item's
	// first key on real output (verified empirically; see doc comment).
	for _, r := range s.Rows {
		if r.ID != "C13" {
			continue
		}
		if !strings.Contains(r.Command, "job_name") || !strings.Contains(r.Command, "node") {
			t.Errorf("C13 must assert on a job_name: node line; got %q", r.Command)
		}
		if strings.Contains(r.Command, `^-`) {
			t.Errorf("C13 must not anchor on a leading ^- (to_nice_yaml alphabetizes keys, job_name isn't first — verified broken against a real vm-target); got %q", r.Command)
		}
		if r.Expected != "0" {
			t.Errorf("C13 expected must be rc-based \"0\"; got %q", r.Expected)
		}
	}

	// C14 must query up{job="node"} with the braces percent-encoded — curl
	// treats a literal {...} in a URL as its own globbing syntax and errors
	// (verified empirically) before the request reaches Prometheus at all.
	for _, r := range s.Rows {
		if r.ID != "C14" {
			continue
		}
		if strings.Contains(r.Command, `up{job`) {
			t.Errorf("C14 must percent-encode the { and } in the PromQL query (curl misinterprets literal braces as globbing); got %q", r.Command)
		}
		if !strings.Contains(r.Command, "%7Bjob%3D%22node%22%7D") {
			t.Errorf("C14 must query up%%7Bjob%%3D%%22node%%22%%7D (percent-encoded up{job=\"node\"}); got %q", r.Command)
		}
		if r.Expected != `~"1"]` {
			t.Errorf("C14 expected must be ~\"1\"] (same grammar as C7); got %q", r.Expected)
		}
	}

	// C15 must assert on a pilot_host: line — Detection Engine's canonical
	// subject identity (spec §9). It must not anchor on a leading `^-`
	// either, for the same to_nice_yaml key-alphabetization reason as C13.
	for _, r := range s.Rows {
		if r.ID != "C15" {
			continue
		}
		if !strings.Contains(r.Command, "pilot_host") {
			t.Errorf("C15 must assert on a pilot_host: line; got %q", r.Command)
		}
		if strings.Contains(r.Command, `^-`) {
			t.Errorf("C15 must not anchor on a leading ^- (to_nice_yaml alphabetizes keys); got %q", r.Command)
		}
		if r.Expected != "0" {
			t.Errorf("C15 expected must be rc-based \"0\"; got %q", r.Expected)
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

	playbookRaw, err := os.ReadFile("../../playbooks/apply/prometheus-apply.yml")
	if err != nil {
		t.Fatalf("read prometheus-apply.yml: %v", err)
	}
	applyRaw := string(playbookRaw)

	// The node-exporter scrape job must be built as native data and
	// serialized with to_nice_yaml, not hand-concatenated with a literal
	// "\n" — verified empirically that a Jinja string literal's \n does NOT
	// become a real newline under a `>-` folded YAML scalar, which would
	// silently corrupt prometheus.yml into invalid YAML.
	if !strings.Contains(applyRaw, "to_nice_yaml") {
		t.Errorf("prometheus-apply.yml must build the node-exporter scrape job as native data + to_nice_yaml, not string-concatenated \\n")
	}
	if strings.Contains(applyRaw, `~ "\n")`) || strings.Contains(applyRaw, `~ '\n'`) {
		t.Errorf("prometheus-apply.yml must not hand-concatenate a literal \\n into a Jinja string under a folded scalar (verified broken)")
	}

	// The scrape job must authenticate via basic_auth + password_file (not
	// an inline password:) so the main prometheus.yml render never needs
	// no_log, keeping --diff visibility on the non-secret bulk of the file.
	if !strings.Contains(applyRaw, "'basic_auth'") {
		t.Errorf("prometheus-apply.yml's node-exporter scrape job must set basic_auth")
	}
	if !strings.Contains(applyRaw, "'password_file'") {
		t.Errorf("prometheus-apply.yml must use basic_auth.password_file (not an inline password:), so the main prometheus.yml render doesn't need no_log")
	}

	// The password-file render is the ONLY task allowed to embed the raw
	// secret — it must be no_log.
	pwFileIdx := strings.Index(applyRaw, "node-exporter basic-auth password file")
	if pwFileIdx < 0 {
		t.Fatalf("prometheus-apply.yml must render a node-exporter basic-auth password file")
	}
	if !strings.Contains(applyRaw[pwFileIdx:], "no_log: true") {
		t.Errorf("prometheus-apply.yml's node-exporter basic-auth password file render must be no_log: true")
	}

	// The password-file bind-mount must be conditional on there actually
	// being node-exporter targets — an unconditional mount of a path whose
	// file wasn't rendered would make Docker auto-create a stray directory
	// there (the exact class of bug this file's own "Guard: check for
	// stray directory left at objstore.yml path" task exists to catch).
	if !strings.Contains(applyRaw, "if (prometheus_node_exporter_targets | length > 0) else []") {
		t.Errorf("prometheus-apply.yml's node-exporter password-file volume mount must be conditional on prometheus_node_exporter_targets being non-empty")
	}

	// Credentials must be gated (required) only when there are actually
	// node-exporter targets to scrape — a site with zero host-monitoring
	// hosts must never be forced to supply this.
	if !strings.Contains(applyRaw, "node-exporter basic-auth credentials required when there are scrape targets") {
		t.Errorf("prometheus-apply.yml must gate node_exporter_basic_auth_user/password as required only when prometheus_node_exporter_targets is non-empty")
	}

	// Restart must account for the password-file changing (credential
	// rotation), on top of the existing prometheus.yml/alert-rules gates.
	if !strings.Contains(applyRaw, "node_exporter_password_file_result is changed") {
		t.Errorf("prometheus-apply.yml's container restart condition must include node_exporter_password_file_result is changed")
	}

	// Detection Engine spec §9: auto-discovery from host-monitoring must
	// build one static_configs entry per host with labels.pilot_host =
	// inventory_hostname (the loop variable), sorted ASC for a
	// deterministic render — never guessed from the bare scrape address.
	if !strings.Contains(applyRaw, "groups.get('host-monitoring', []) | sort") {
		t.Errorf("prometheus-apply.yml must sort host-monitoring hosts ASC before building per-host pilot_host static_configs (spec §9.2 determinism)")
	}
	if !strings.Contains(applyRaw, "'labels': {'pilot_host': item}") {
		t.Errorf("prometheus-apply.yml must label each auto-discovered static_configs entry with labels.pilot_host = inventory_hostname (spec §9.2)")
	}

	// §9.3: an explicit node_exporter_targets override has no
	// inventory-hostname mapping and must keep the old flat/unlabeled
	// static_configs shape — never synthesize a pilot_host label for it.
	if !strings.Contains(applyRaw, "[{'targets': prometheus_node_exporter_targets}]") {
		t.Errorf("prometheus-apply.yml must keep the explicit-override static_configs shape flat and unlabeled (spec §9.3)")
	}
}
