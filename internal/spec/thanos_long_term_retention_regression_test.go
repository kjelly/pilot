package spec

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// TestRegression_ThanosLongTermRetention locks the long-term metrics path
// fixed on 2026-10-12. Every site's Thanos Sidecar mounted the Prometheus
// TSDB read-only, so every upload failed creating thanos/upload/<ulid>
// and the central Store Gateway loaded zero blocks: only the 6h of local
// Prometheus data was ever queryable. The requirement is 90 days of
// history with lower resolution for older data:
//
//   - the Sidecar runs as the Prometheus uid with /prometheus writable
//     (dropping :ro alone still fails, the image's own uid is 1001);
//   - the Compactor keeps raw, 5m and 1h for 90d. Raw is never shorter
//     than the downsampled resolutions: only raw blocks spanning 40h or
//     more are downsampled, so a short-lived site and the last blocks of a
//     stopped or relabelled site exist only as raw (review of PR #39;
//     scripts/thanos-retention-behavior-test.sh runs the Compactor on
//     such blocks in CI);
//   - Thanos Query runs with --query.auto-downsampling, without which a
//     range query reads raw blocks only and the 30-90 day range is empty;
//   - Prometheus keeps 24h locally as the upload buffer.
//
// Each default lives in the playbook, the spec's variable table and the
// group_vars example; this test keeps the three in step (AGENTS.md §5.7),
// and keeps the variables out of play-level vars so group_vars can
// override them (AGENTS.md §4.5 item 3).
func TestRegression_ThanosLongTermRetention(t *testing.T) {
	prom := readPlaybookContainers(t, "../../playbooks/apply/prometheus-apply.yml")
	thanos := readPlaybookContainers(t, "../../playbooks/apply/thanos-query-apply.yml")

	sidecar := prom.container(t, "pilot-thanos-sidecar")
	if got := fmt.Sprint(sidecar["user"]); got != "65534:65534" {
		t.Errorf("pilot-thanos-sidecar user = %q, want 65534:65534 (the Prometheus uid that owns the TSDB dir)", got)
	}
	var tsdbMount string
	for _, v := range asStrings(sidecar["volumes"]) {
		if strings.Contains(v, ":/prometheus") {
			tsdbMount = v
		}
	}
	if tsdbMount != "{{ prometheus_host_data_dir }}:/prometheus" {
		t.Errorf("pilot-thanos-sidecar must mount the TSDB dir read-write; got %q", tsdbMount)
	}

	promCmd := fmt.Sprint(prom.container(t, "pilot-prometheus")["command"])
	if !strings.Contains(promCmd, "--storage.tsdb.retention.time={{ prometheus_retention_time | default('24h', true) }}") {
		t.Errorf("pilot-prometheus must keep 24h locally by default; command:\n%s", promCmd)
	}

	compactCmd := fmt.Sprint(thanos.container(t, "pilot-thanos-compact")["command"])
	retention := map[string]string{}
	for _, res := range []string{"raw", "5m", "1h"} {
		re := regexp.MustCompile(`--retention\.resolution-` + res + `=\{\{ thanos_compact_retention_` + res + ` \| default\('([0-9]+[a-z])', true\) \}\}`)
		m := re.FindStringSubmatch(compactCmd)
		if m == nil {
			t.Errorf("pilot-thanos-compact must set --retention.resolution-%s from thanos_compact_retention_%s with a default; command:\n%s", res, res, compactCmd)
			continue
		}
		retention[res] = m[1]
	}
	want := map[string]string{"raw": "90d", "5m": "90d", "1h": "90d"}
	for res, w := range want {
		if retention[res] != w {
			t.Errorf("thanos_compact_retention_%s default = %q, want %q", res, retention[res], w)
		}
	}
	// thanos compact refuses to start otherwise (cmd/thanos/compact.go).
	if d := thanosDuration(t, retention["raw"]); d <= 40*time.Hour {
		t.Errorf("raw retention %s must exceed 40h", retention["raw"])
	}
	if d := thanosDuration(t, retention["5m"]); d <= 10*24*time.Hour {
		t.Errorf("5m retention %s must exceed 10d", retention["5m"])
	}
	for _, res := range []string{"5m", "1h"} {
		if thanosDuration(t, retention["raw"]) < thanosDuration(t, retention[res]) {
			t.Errorf("raw retention %s is shorter than %s retention %s: raw-only blocks (under 40h) would be deleted with no downsampled copy", retention["raw"], res, retention[res])
		}
	}

	queryCmd := fmt.Sprint(thanos.container(t, "pilot-thanos-query")["command"])
	if !strings.Contains(queryCmd, "--query.auto-downsampling") {
		t.Errorf("pilot-thanos-query must run with --query.auto-downsampling; command:\n%s", queryCmd)
	}

	for name, vars := range map[string]map[string]any{"prometheus-apply.yml": prom.vars, "thanos-query-apply.yml": thanos.vars} {
		for _, v := range []string{"prometheus_retention_time", "thanos_compact_retention_raw", "thanos_compact_retention_5m", "thanos_compact_retention_1h"} {
			if _, ok := vars[v]; ok {
				t.Errorf("%s declares %s in play vars, which shadows group_vars (AGENTS.md §4.5 item 3)", name, v)
			}
		}
	}

	defaults := map[string]struct{ spec, groupVars, specCell, example string }{
		"prometheus_retention_time":    {"prometheus.md", "prometheus.example.yml", "`24h`", `# prometheus_retention_time: "24h"`},
		"thanos_compact_retention_raw": {"thanos-query.md", "thanos-query.example.yml", "`90d`", "# thanos_compact_retention_raw: 90d"},
		"thanos_compact_retention_5m":  {"thanos-query.md", "thanos-query.example.yml", "`90d`", "# thanos_compact_retention_5m: 90d"},
		"thanos_compact_retention_1h":  {"thanos-query.md", "thanos-query.example.yml", "`90d`", "# thanos_compact_retention_1h: 90d"},
	}
	for v, d := range defaults {
		specText := readText(t, "../../docs/verification/"+d.spec)
		row := ""
		for _, line := range strings.Split(specText, "\n") {
			if strings.HasPrefix(line, "| `"+v+"` |") {
				row = line
			}
		}
		if !strings.HasSuffix(strings.TrimSpace(row), "| "+d.specCell+" |") {
			t.Errorf("%s §1.5 must list %s with default %s; row: %q", d.spec, v, d.specCell, row)
		}
		if !strings.Contains(readText(t, "../../group_vars/"+d.groupVars), d.example) {
			t.Errorf("group_vars/%s must show %q", d.groupVars, d.example)
		}
	}
}

// TestRegression_ThanosRetentionBehaviorRunsInCI keeps the behavioural
// retention check wired up: the script must read the defaults from the
// playbook (so it tests what is deployed), and CI must run it.
func TestRegression_ThanosRetentionBehaviorRunsInCI(t *testing.T) {
	script := readText(t, "../../scripts/thanos-retention-behavior-test.sh")
	for _, w := range []string{
		`--retention\.resolution-$1={{ thanos_compact_retention_$1 | default('`,
		"playbooks/apply/thanos-query-apply.yml",
		"play_var thanos_version",
		"play_var prometheus_version",
	} {
		if !strings.Contains(script, w) {
			t.Errorf("scripts/thanos-retention-behavior-test.sh must contain %q", w)
		}
	}
	if !strings.Contains(readText(t, "../../Makefile"), "thanos-retention-test:") {
		t.Error("Makefile must define thanos-retention-test")
	}
	if !strings.Contains(readText(t, "../../.github/workflows/ci.yml"), "run: make thanos-retention-test") {
		t.Error(".github/workflows/ci.yml must run make thanos-retention-test")
	}
}

// TestRegression_ThanosLongTermRetentionRows locks the spec rows that
// prove the path works end to end. C9 (prometheus.md) and C8
// (thanos-query.md) only list the bucket, which passed for months while
// nothing was uploaded; these rows check the Sidecar can write, that the
// site's blocks are in the bucket, and that the Store Gateway loaded them.
// The upload-failure counter is deliberately not used: it stayed at 0
// while every upload failed (reproduced with thanos v0.36.1).
func TestRegression_ThanosLongTermRetentionRows(t *testing.T) {
	prom, err := Parse("../../docs/verification/prometheus.md")
	if err != nil {
		t.Fatal(err)
	}
	thanos, err := Parse("../../docs/verification/thanos-query.md")
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]string{}
	for _, r := range prom.Rows {
		rows["prometheus "+r.ID] = r.Command
	}
	for _, r := range thanos.Rows {
		rows["thanos-query "+r.ID] = r.Command
	}

	for id, wants := range map[string][]string{
		"prometheus C21":   {"docker exec pilot-thanos-sidecar", "mkdir", "/prometheus/"},
		"prometheus C22":   {"docker exec pilot-thanos-sidecar thanos tools bucket inspect", "--selector=", "/etc/pilot/prometheus/prometheus.yml", "-6 hours"},
		"thanos-query C11": {"docker inspect pilot-thanos-compact", "for r in raw 5m 1h", "[1-9]"},
		"thanos-query C12": {"docker inspect pilot-thanos-query", "--query.auto-downsampling"},
		"thanos-query C13": {"127.0.0.1:10904/metrics", "^thanos_bucket_store_blocks_loaded [1-9]"},
	} {
		cmd, ok := rows[id]
		if !ok {
			t.Errorf("%s is missing", id)
			continue
		}
		for _, w := range wants {
			if !strings.Contains(cmd, w) {
				t.Errorf("%s must contain %q; got %q", id, w, cmd)
			}
		}
		if strings.Contains(cmd, "upload_failures") {
			t.Errorf("%s must not rely on thanos_shipper_upload_failures_total, which stays 0 while uploads fail", id)
		}
	}
}

type playbookContainers struct {
	vars       map[string]any
	containers map[string]map[string]any
}

func (p playbookContainers) container(t *testing.T, name string) map[string]any {
	t.Helper()
	c, ok := p.containers[name]
	if !ok {
		t.Fatalf("no docker_container task named %s", name)
	}
	return c
}

func readPlaybookContainers(t *testing.T, path string) playbookContainers {
	t.Helper()
	var doc any
	if err := yaml.Unmarshal([]byte(readText(t, path)), &doc); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	out := playbookContainers{vars: map[string]any{}, containers: map[string]map[string]any{}}
	plays, _ := doc.([]any)
	for _, p := range plays {
		play, _ := p.(map[string]any)
		if vars, ok := play["vars"].(map[string]any); ok {
			for k, v := range vars {
				out.vars[k] = v
			}
		}
		for _, section := range []string{"pre_tasks", "tasks", "post_tasks"} {
			walkTaskTree(play[section], nil, func(task map[string]any, _ []string) {
				if args := dockerContainerArgs(task); args != nil {
					out.containers[fmt.Sprint(args["name"])] = args
				}
			})
		}
	}
	return out
}

func readText(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func asStrings(v any) []string {
	list, _ := v.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		out = append(out, fmt.Sprint(item))
	}
	return out
}

// thanosDuration parses the Prometheus-style durations used for retention
// flags (a number followed by one unit, e.g. "30d").
func thanosDuration(t *testing.T, s string) time.Duration {
	t.Helper()
	units := map[byte]time.Duration{'h': time.Hour, 'd': 24 * time.Hour, 'w': 7 * 24 * time.Hour, 'y': 365 * 24 * time.Hour}
	if len(s) < 2 {
		t.Fatalf("bad duration %q", s)
	}
	n, err := strconv.Atoi(s[:len(s)-1])
	unit, ok := units[s[len(s)-1]]
	if err != nil || !ok {
		t.Fatalf("bad duration %q", s)
	}
	return time.Duration(n) * unit
}
