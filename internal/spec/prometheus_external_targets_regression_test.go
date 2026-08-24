package spec

import (
	"strings"
	"testing"
)

// TestRegression_PrometheusExternalTargetsSpec locks the structure of
// docs/verification/prometheus-external-targets.md (v1.0 — file_sd-based
// external Prometheus exporter registry, spec.md §7-24):
//
//	C1  file_sd target directory exists
//	C2  every generated file_sd JSON file is valid JSON
//	C3  prometheus.yml contains at least one file_sd_configs job
//	C4  Prometheus targets API surfaces a pilot_source="external" target
//	C5  at least one enabled external target is successfully scraped
//	C6  prometheus.yml syntax is valid (promtool check config)
//	C7  the file_sd directory is not world-writable
//	C8  prometheus.yml never contains a literal `password:` key
//
// Cross-row invariants locked below — each one documents a real bug found
// and fixed on a genuine vm-target during this feature's development
// (docs/evidence/prometheus-external-targets/2026-08-24-fbd214f.md §6),
// not a hypothetical:
//
//   - C2's command must invoke `python3 -m json.tool` (a real JSON parse),
//     not merely `test -f` — the point of this row is catching a
//     compiler bug that emits syntactically invalid JSON, which a bare
//     existence check would silently miss.
//   - C3's regex must tolerate an OPTIONAL leading `-` (list-marker) before
//     `file_sd_configs:` — playbooks/apply/prometheus-apply.yml serializes
//     each scrape job dict with to_nice_yaml, which alphabetizes keys, so
//     `file_sd_configs` (alphabetically first) becomes the job's first key
//     and renders as `- file_sd_configs:`, not a bare
//     `  file_sd_configs:`. A bare `^[[:space:]]*file_sd_configs:` anchor
//     was tried first and failed against a real vm-target apply — the
//     exact same class of to_nice_yaml key-ordering bug
//     prometheus.md's own C13 already documents for `job_name:`.
//   - C6 must invoke `promtool check config` as a POST-apply, read-only
//     check (via `docker exec pilot-prometheus`) — NOT as a pre-apply gate
//     inside the playbook. spec.md §22/§55 were corrected earlier in this
//     feature's development to match this: the only place `promtool` is
//     ever invoked anywhere in this repo is a post-apply verification
//     row (mirroring prometheus.md's own C10), never an apply-time
//     validate-before-mutate gate, which does not exist in this codebase.
//   - C4/C5 must key off the `pilot_source="external"` label, never a
//     specific jobName — jobName is user-chosen (scrape-profiles.yml), not
//     a playbook-owned constant like node-exporter's fixed "node" job, so
//     a generic spec cannot hardcode one.
//   - C7 must reject exactly the "others can write" bit (mode & 0002),
//     independent of any other permission bit — 0644/0755/0700 must all
//     pass, 0646/0777 must all fail.
//   - C8 must scan the WHOLE rendered prometheus.yml for a literal
//     `password:` key with a non-empty value, proving basic_auth always
//     renders as password_file — this is an architectural invariant of
//     the scrape-job compiler, not a per-profile setting.
func TestRegression_PrometheusExternalTargetsSpec(t *testing.T) {
	const specPath = "../../docs/verification/prometheus-external-targets.md"
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

	for _, r := range s.Rows {
		switch strings.ToLower(strings.TrimSpace(r.Expected)) {
		case "ok", "normal", "reasonable", "sufficient":
			t.Errorf("row %s uses vague expected %q", r.ID, r.Expected)
		}
	}

	for _, r := range s.Rows {
		switch r.ID {
		case "C1":
			if !strings.Contains(r.Command, "test -d") {
				t.Errorf("C1 must be a directory-existence check; got %q", r.Command)
			}
			if r.Expected != "present" {
				t.Errorf("C1 expected must be \"present\"; got %q", r.Expected)
			}

		case "C2":
			if !strings.Contains(r.Command, "python3 -m json.tool") {
				t.Errorf("C2 must invoke a real JSON parse (python3 -m json.tool), not just file existence; got %q", r.Command)
			}
			if r.Expected != "0" {
				t.Errorf("C2 expected must be rc-based \"0\"; got %q", r.Expected)
			}

		case "C3":
			if !strings.Contains(r.Command, `-?[[:space:]]*file_sd_configs:`) {
				t.Errorf("C3 must tolerate an optional leading '-' before file_sd_configs: (to_nice_yaml key-ordering, see prometheus.md C13); got %q", r.Command)
			}
			if r.Expected != "0" {
				t.Errorf("C3 expected must be rc-based \"0\"; got %q", r.Expected)
			}

		case "C4":
			if !strings.Contains(r.Command, `pilot_source`) || strings.Contains(r.Command, "job_name") {
				t.Errorf("C4 must key off pilot_source, never a specific jobName; got %q", r.Command)
			}
			if !strings.Contains(r.Command, "/api/v1/targets") {
				t.Errorf("C4 must query the Prometheus targets API; got %q", r.Command)
			}

		case "C5":
			if !strings.Contains(r.Command, `pilot_source%3D%22external%22`) {
				t.Errorf("C5 must query up{pilot_source=\"external\"} (percent-encoded braces); got %q", r.Command)
			}
			if r.Expected != `~"1"]` {
				t.Errorf(`C5 expected must be ~"1"]; got %q`, r.Expected)
			}

		case "C6":
			if !strings.Contains(r.Command, "docker exec pilot-prometheus promtool check config") {
				t.Errorf("C6 must invoke promtool check config as a post-apply, read-only docker exec (spec.md §22 correction) — no apply-time gate exists in this repo; got %q", r.Command)
			}
			if r.Expected != "0" {
				t.Errorf("C6 expected must be rc-based \"0\"; got %q", r.Expected)
			}

		case "C7":
			if !strings.Contains(r.Command, "case") || !strings.Contains(r.Command, "[2367]") {
				t.Errorf("C7 must reject the world-writable bit via a case pattern; got %q", r.Command)
			}

		case "C8":
			if !strings.Contains(r.Command, `password:`) {
				t.Errorf("C8 must scan for a literal password: key; got %q", r.Command)
			}
			if !strings.Contains(r.Command, "!") {
				t.Errorf("C8 must assert absence (negated grep), not presence; got %q", r.Command)
			}
		}
	}
}
