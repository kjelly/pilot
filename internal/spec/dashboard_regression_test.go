package spec

import (
	"os"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// TestRegression_DashboardSpec locks the structure of
// docs/verification/dashboard.md (v1.1 — Grafana + Loki, the pure-consumer
// role that closes the observability triangle started by prometheus.md /
// thanos-query.md / log-server.md):
//
//	C1-C2  pilot-loki / pilot-grafana containers running
//	C3-C4  Loki /ready (3100), Grafana /api/health (3000)
//	C5-C6  Grafana datasource provisioning file references fixed UIDs
//	       pilot-loki / pilot-thanos-query
//	C7     Loki self-test: push then query a unique marker back
//	C8     connectivity to the thanos-query-backend alias (Prometheus
//	       datasource upstream)
//	C9-C10 Grafana / Loki host data dirs exist
//	C11    dashboard provisioning provider config file exists
//	C12-13 built-in dashboard JSON files exist with fixed uids
//	       pilot-sites-overview / pilot-logs-explorer
//	C14    Grafana logged no dashboard-provisioning errors
//
// Cross-row invariants locked below:
//
//   - C1/C2 must reference the exact container names the apply playbook
//     creates.
//   - C5/C6/C12/C13 must assert on FIXED uids (pilot-loki,
//     pilot-thanos-query, pilot-sites-overview, pilot-logs-explorer), not
//     a dynamically-queried Grafana API uid — the whole point of pinning
//     them in the apply playbook is so this spec's Command column can
//     stay static text (see verification-spec-template.md's "Command/
//     Expected are static text authored once" rule, and thanos-query.md's
//     C10 for the precedent).
//   - C8 must run inside pilot-grafana and use its actual provisioned
//     datasource URL. Host-only DNS/connectivity can pass while Grafana
//     cannot resolve its provider (the original hosts-pin regression).
//   - No row may leak the Grafana admin password or S3-style credentials
//     into the spec text (AGENTS.md).
func TestRegression_DashboardSpec(t *testing.T) {
	const specPath = "../../docs/verification/dashboard.md"
	s, err := Parse(specPath)
	if err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}

	wantIDs := []string{"C1", "C2", "C3", "C4", "C5", "C6", "C7", "C8", "C9", "C10", "C11", "C12", "C13", "C14"}
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

	wantContainer := map[string]string{"C1": "pilot-loki", "C2": "pilot-grafana"}
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
		"C3": {"3100", "/ready"},
		"C4": {"3000", "/api/health"},
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

	// C5/C6/C12/C13 must assert on the fixed uids, not just "uid:" — a
	// naive check that only looks for the word "uid" would trivially
	// pass on any provisioning/dashboard file, real or empty of content.
	wantUID := map[string]string{
		"C5": "pilot-loki", "C6": "pilot-thanos-query",
		"C12": "pilot-sites-overview", "C13": "pilot-logs-explorer",
	}
	for _, r := range s.Rows {
		uid, ok := wantUID[r.ID]
		if !ok {
			continue
		}
		if !strings.Contains(r.Command, uid) {
			t.Errorf("%s must assert on fixed uid %q; got %q", r.ID, uid, r.Command)
		}
		if r.Expected != "0" {
			t.Errorf("%s expected must be rc-based \"0\"; got %q", r.ID, r.Expected)
		}
	}

	// C7 is Loki's own self-test (push then query), independent of
	// Promtail/log-shipping — must hit both the push and query APIs.
	for _, r := range s.Rows {
		if r.ID != "C7" {
			continue
		}
		if !strings.Contains(r.Command, "/loki/api/v1/push") {
			t.Errorf("C7 must push via /loki/api/v1/push; got %q", r.Command)
		}
		if !strings.Contains(r.Command, "/loki/api/v1/query") {
			t.Errorf("C7 must read back via /loki/api/v1/query; got %q", r.Command)
		}
	}

	// C8 must exercise the consumer's namespace and actual datasource URL.
	for _, r := range s.Rows {
		if r.ID != "C8" {
			continue
		}
		for _, required := range []string{"docker exec pilot-grafana", "uid: pilot-thanos-query", "/etc/grafana/provisioning/datasources/datasources.yml", "test -n", "wget", "-T 5", "$url/-/healthy", "sh -ec"} {
			if !strings.Contains(r.Command, required) {
				t.Errorf("C8 must contain %q; got %q", required, r.Command)
			}
		}
		if r.Expected != "0" {
			t.Errorf("C8 must require a successful connection (rc=0), got %q", r.Expected)
		}
	}

	// C11 must check the dashboard provisioning provider config, not the
	// datasource provisioning config (easy to confuse — both live under
	// .../grafana/provisioning/).
	for _, r := range s.Rows {
		if r.ID != "C11" {
			continue
		}
		if !strings.Contains(r.Command, "provisioning/dashboards/dashboards.yml") {
			t.Errorf("C11 must check the dashboards provider config path; got %q", r.Command)
		}
	}

	// C14 is a real "no error" check, not a trivial file-existence check —
	// must hit docker logs and look for the provisioning.dashboard error
	// marker, with a leading `!` so the HEALTHY (no error) path exits 0
	// (see the spec's own note on why this trips the linter's reverse-logic
	// heuristic despite being correct positive logic).
	//
	// The pattern must be `logger=provisioning.dashboard.*level=error`, in
	// THAT field order — a real bug caught only by deliberately breaking a
	// dashboard JSON and re-verifying on a live VM: Grafana's structured
	// log lines always put `logger=` before `level=` (e.g. `logger=
	// provisioning.dashboard type=file name=... level=error msg="failed to
	// load dashboard from ..."`), so an earlier `level=error.*provisioning.
	// dashboard` pattern (fields in the opposite order) never matched a
	// real error line and silently always passed.
	//
	// C14 must also scope the log window to `--since` the container's
	// current start time — another real bug caught the same way: plain
	// `docker logs` (no --since) returns the FULL history since the
	// container was first created, and a mere `docker restart` does not
	// clear it, so a since-fixed historical error would fail C14 forever
	// until the container is destroyed and recreated.
	for _, r := range s.Rows {
		if r.ID != "C14" {
			continue
		}
		if !strings.Contains(r.Command, "docker logs") {
			t.Errorf("C14 must inspect docker logs; got %q", r.Command)
		}
		if !strings.Contains(r.Command, "--since") || !strings.Contains(r.Command, "StartedAt") {
			t.Errorf("C14 must scope docker logs to --since the container's current StartedAt; got %q", r.Command)
		}
		if strings.Contains(r.Command, "inspect -f") || strings.Contains(r.Command, "--format") {
			t.Errorf("C14 must not use docker's -f/--format (Go-template {{ }} syntax breaks ansible ad-hoc); use sed extraction instead; got %q", r.Command)
		}
		if !strings.Contains(r.Command, "logger=provisioning.dashboard.*level=error") {
			t.Errorf(`C14 must match "logger=provisioning.dashboard.*level=error" (real Grafana field order); got %q`, r.Command)
		}
		if !strings.HasPrefix(strings.TrimSpace(strings.TrimPrefix(r.Command, "sh -c '")), "!") {
			t.Errorf("C14 must lead with `!` to negate the grep so the healthy path exits 0; got %q", r.Command)
		}
		if r.Expected != "0" {
			t.Errorf("C14 expected must be rc-based \"0\"; got %q", r.Expected)
		}
	}

	// No row's Command may contain ANY `{{`/`}}` at all — not just
	// unreplaced Ansible vars (the original bug in C5/C6/C9/C10), but
	// also docker's own Go-template syntax (`docker inspect -f
	// '{{.State.StartedAt}}'`), confirmed via `pilot verify --probe` to
	// ALSO break: ansible ad-hoc's `-m shell`/`-a "..."` runs the entire
	// Command string through Jinja finalization, and `{{.Foo}}` is a
	// Jinja syntax error ("unexpected '.'") — not a silent passthrough.
	// This is a stricter rule than plain "no unreplaced Ansible vars";
	// docker.md's C6 (`--format '{{.Name}}'`) has this exact latent bug
	// today (confirmed via probe, not yet fixed — out of scope here).
	// C14 extracts the container start time via `docker inspect | sed`
	// instead, specifically to avoid any `{{`/`}}` in its Command text.
	for _, r := range s.Rows {
		if strings.Contains(r.Command, "{{") || strings.Contains(r.Command, "}}") {
			t.Errorf("%s command must not contain {{ or }} (breaks ansible ad-hoc's Jinja finalization); got %q", r.ID, r.Command)
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

// Provider and consumer must share their Docker network and service alias.
// Do not pin either container's changing IP in a host or extra_hosts mapping.
func TestRegression_DashboardDockerDNS(t *testing.T) {
	read := func(path string) []map[string]any {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var plays []map[string]any
		if err := yaml.Unmarshal(raw, &plays); err != nil {
			t.Fatal(err)
		}
		return plays
	}
	var walk func([]any, func(map[string]any))
	walk = func(tasks []any, visit func(map[string]any)) {
		for _, raw := range tasks {
			task := raw.(map[string]any)
			visit(task)
			for _, key := range []string{"block", "rescue", "always"} {
				if nested, ok := task[key].([]any); ok {
					walk(nested, visit)
				}
			}
		}
	}
	containers := map[string]map[string]any{}
	for _, path := range []string{"../../playbooks/apply/dashboard-apply.yml", "../../playbooks/apply/thanos-query-apply.yml"} {
		for _, play := range read(path) {
			walk(play["tasks"].([]any), func(task map[string]any) {
				if config, ok := task["community.docker.docker_container"].(map[string]any); ok {
					containers[config["name"].(string)] = config
				}
				if strings.Contains(path, "dashboard-apply") {
					if config, ok := task["ansible.builtin.lineinfile"].(map[string]any); ok && config["path"] == "/etc/hosts" && config["state"] != "absent" {
						t.Error("dashboard must only remove its legacy hosts pin")
					}
				}
			})
		}
	}
	for _, name := range []string{"pilot-grafana", "pilot-thanos-query"} {
		config, ok := containers[name]
		if !ok {
			t.Fatalf("missing container %s", name)
		}
		if _, pinned := config["etc_hosts"]; pinned {
			t.Errorf("%s must use DNS instead of etc_hosts", name)
		}
		network := config["networks"].([]any)[0].(map[string]any)
		if network["name"] != "{{ docker_network_name }}" {
			t.Errorf("%s must join the shared metrics network", name)
		}
		if name == "pilot-thanos-query" {
			aliases, ok := network["aliases"].([]any)
			if !ok || len(aliases) != 1 || aliases[0] != "{{ thanos_query_alias | default('thanos-query-backend', true) }}" {
				t.Errorf("provider must declare the consumer's DNS alias, got %v", network["aliases"])
			}
		}
	}
}
