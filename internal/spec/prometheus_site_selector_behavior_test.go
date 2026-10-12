package spec

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// prometheus.md C8 and C22 read the site name from prometheus.yml. Both
// used to match every `site:` key in the file; with a kind:snmp profile
// the snmp_exporter self-scrape job also has a `site` label, so C22 built
// the selector `site="review-site\nreview-site"`, which Thanos rejects
// ("unquote label value: invalid syntax"), and C8 passed even without
// external_labels (review of PR #39). These tests run both rows as
// written, with the prometheus.yml path pointing at a fixture and a fake
// `docker` on PATH in place of `thanos tools bucket inspect`. The fake
// parses --selector like Thanos v0.36.1 (cmd/thanos/config.go
// parseFlagLabels: the value goes through strconv.Unquote) and lists only
// the blocks whose labels match.
//
// Fixtures: testdata/prometheus-site-selector/prometheus-snmp.yml is the
// prometheus.yml prometheus-apply.yml rendered on a vm-target with a
// kind:snmp profile (prometheus_site_label=review-site);
// bucket-inspect.tsv is `thanos tools bucket inspect --output=tsv` output
// from thanosio/thanos:v0.36.1.

const fakeThanosInspectEnv = "PILOT_TEST_FAKE_THANOS_INSPECT"

func TestMain(m *testing.M) {
	if blocks := os.Getenv(fakeThanosInspectEnv); blocks != "" {
		os.Exit(fakeThanosInspect(blocks, os.Args[1:]))
	}
	os.Exit(m.Run())
}

// fakeBlock is one block the fake bucket holds.
type fakeBlock struct {
	Labels map[string]string `json:"labels"`
	Until  time.Time         `json:"until"`
}

// fakeThanosInspect stands in for
// `docker exec pilot-thanos-sidecar thanos tools bucket inspect ...`.
func fakeThanosInspect(blocksFile string, args []string) int {
	want := []string{"exec", "pilot-thanos-sidecar", "thanos", "tools", "bucket", "inspect"}
	if len(args) < len(want) || strings.Join(args[:len(want)], " ") != strings.Join(want, " ") {
		fmt.Fprintf(os.Stderr, "fake docker: unexpected args %q\n", args)
		return 2
	}
	if f := os.Getenv(fakeThanosInspectEnv + "_ARGS"); f != "" {
		b, _ := json.Marshal(args)
		_ = os.WriteFile(f, b, 0o644)
	}
	selector := map[string]string{}
	for _, a := range args[len(want):] {
		s, ok := strings.CutPrefix(a, "--selector=")
		if !ok {
			continue
		}
		name, quoted, ok := strings.Cut(s, "=")
		if !ok {
			fmt.Fprintf(os.Stderr, "unrecognized label %q\n", s)
			return 1
		}
		val, err := strconv.Unquote(quoted)
		if err != nil {
			fmt.Fprintln(os.Stderr, "invalid syntax\nunquote label value\nerror parsing selector flag")
			return 1
		}
		selector[name] = val
	}
	tsv, err := os.ReadFile("testdata/prometheus-site-selector/bucket-inspect.tsv")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	lines := strings.Split(strings.TrimRight(string(tsv), "\n"), "\n")
	row := strings.Split(lines[1], "\t")
	var blocks []fakeBlock
	raw, err := os.ReadFile(blocksFile)
	if err == nil {
		err = json.Unmarshal(raw, &blocks)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	fmt.Println(lines[0])
next:
	for _, b := range blocks {
		for k, v := range selector {
			if b.Labels[k] != v {
				continue next
			}
		}
		row[1] = b.Until.Add(-2 * time.Hour).UTC().Format(time.RFC3339)
		row[2] = b.Until.UTC().Format(time.RFC3339)
		fmt.Println(strings.Join(row, "\t"))
	}
	return 0
}

type siteRowRun struct {
	pass     bool
	selector []string // the --selector arguments C22 passed
}

// runSiteRow runs a prometheus.md row against prometheusYML with the fake
// bucket holding blocks.
func runSiteRow(t *testing.T, id, prometheusYML string, blocks []fakeBlock) siteRowRun {
	t.Helper()
	s, err := Parse("../../docs/verification/prometheus.md")
	if err != nil {
		t.Fatal(err)
	}
	var command string
	for _, r := range s.Rows {
		if r.ID == id {
			command = r.Command
		}
	}
	const path = "/etc/pilot/prometheus/prometheus.yml"
	if !strings.Contains(command, path) {
		t.Fatalf("%s does not read %s: %q", id, path, command)
	}
	dir := t.TempDir()
	yml := filepath.Join(dir, "prometheus.yml")
	if err := os.WriteFile(yml, []byte(prometheusYML), 0o644); err != nil {
		t.Fatal(err)
	}
	blocksFile := filepath.Join(dir, "blocks.json")
	b, _ := json.Marshal(blocks)
	if err := os.WriteFile(blocksFile, b, 0o644); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte("#!/bin/sh\nexec "+strconv.Quote(self)+" \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	argsFile := filepath.Join(dir, "args.json")
	cmd := exec.Command("/bin/sh", "-c", strings.ReplaceAll(command, path, yml))
	cmd.Dir, _ = os.Getwd()
	cmd.Env = append(os.Environ(),
		"PATH="+bin+string(os.PathListSeparator)+os.Getenv("PATH"),
		fakeThanosInspectEnv+"="+blocksFile,
		fakeThanosInspectEnv+"_ARGS="+argsFile,
	)
	out, err := cmd.CombinedOutput()
	run := siteRowRun{pass: err == nil}
	if _, ok := err.(*exec.ExitError); err != nil && !ok {
		t.Fatalf("%s did not run: %v", id, err)
	}
	if raw, err := os.ReadFile(argsFile); err == nil {
		var args []string
		_ = json.Unmarshal(raw, &args)
		for _, a := range args {
			if s, ok := strings.CutPrefix(a, "--selector="); ok {
				run.selector = append(run.selector, s)
			}
		}
	}
	t.Logf("%s: pass=%v selector=%q output=%q", id, run.pass, run.selector, out)
	return run
}

func snmpPrometheusYML(t *testing.T) string {
	t.Helper()
	yml := readText(t, "testdata/prometheus-site-selector/prometheus-snmp.yml")
	if !strings.Contains(yml, "\n    site: \"review-site\"\n") {
		t.Fatal("fixture must have external_labels.site \"review-site\"")
	}
	if strings.Count(yml, "site: review-site") == 0 {
		t.Fatal("fixture must contain the snmp-exporter job's site label")
	}
	return yml
}

func TestPrometheusSiteRows_SNMPProfileRecentBlockPasses(t *testing.T) {
	yml := snmpPrometheusYML(t)
	blocks := []fakeBlock{
		{Labels: map[string]string{"site": "review-site"}, Until: time.Now().Add(-90 * time.Minute)},
		{Labels: map[string]string{"site": "other-site"}, Until: time.Now().Add(-30 * time.Minute)},
	}
	if !runSiteRow(t, "C8", yml, nil).pass {
		t.Error("C8 must pass on the SNMP render")
	}
	r := runSiteRow(t, "C22", yml, blocks)
	if !r.pass {
		t.Error("C22 must pass with a block from the last 6h")
	}
	if len(r.selector) != 1 || r.selector[0] != `site="review-site"` {
		t.Errorf("C22 selector = %q, want [site=\"review-site\"]", r.selector)
	}
}

func TestPrometheusSiteRows_C22FailsWithoutARecentBlockOfThisSite(t *testing.T) {
	yml := snmpPrometheusYML(t)
	for name, blocks := range map[string][]fakeBlock{
		"empty bucket":       nil,
		"only older than 6h": {{Labels: map[string]string{"site": "review-site"}, Until: time.Now().Add(-7 * time.Hour)}},
		"only another site":  {{Labels: map[string]string{"site": "other-site"}, Until: time.Now().Add(-30 * time.Minute)}},
	} {
		if runSiteRow(t, "C22", yml, blocks).pass {
			t.Errorf("%s: C22 must fail", name)
		}
	}
}

// The site line rendered by ansible-core 2.19 `to_json` for the label
// `a "b" \ c é` (captured from a real playbook run; to_json escapes
// non-ASCII as \uXXXX).
const trickySiteLine = `    site: "a \"b\" \\ c \u00e9"`

func TestPrometheusSiteRows_QuotedLabelReachesThanosUnchanged(t *testing.T) {
	yml := strings.Replace(snmpPrometheusYML(t), `    site: "review-site"`, trickySiteLine, 1)
	label := "a \"b\" \\ c é"
	r := runSiteRow(t, "C22", yml, []fakeBlock{{Labels: map[string]string{"site": label}, Until: time.Now().Add(-time.Hour)}})
	if !r.pass {
		t.Fatal("C22 must pass for a label with quotes, a backslash and non-ASCII")
	}
	if len(r.selector) != 1 {
		t.Fatalf("selector = %q", r.selector)
	}
	if v, err := strconv.Unquote(strings.TrimPrefix(r.selector[0], "site=")); err != nil || v != label {
		t.Errorf("selector %q decodes to %q (%v), want %q", r.selector[0], v, err, label)
	}
}

// Both rows must fail closed when the site cannot be read from
// global.external_labels, even though the snmp job still has a site label.
func TestPrometheusSiteRows_FailWithoutAQuotedExternalLabel(t *testing.T) {
	yml := snmpPrometheusYML(t)
	blocks := []fakeBlock{{Labels: map[string]string{"site": "review-site"}, Until: time.Now().Add(-time.Hour)}}
	for name, broken := range map[string]string{
		"no external_labels": strings.Replace(yml, "  external_labels:\n    site: \"review-site\"\n", "", 1),
		"unquoted site":      strings.Replace(yml, `    site: "review-site"`, "    site: review-site", 1),
		"empty site":         strings.Replace(yml, `    site: "review-site"`, `    site: ""`, 1),
	} {
		if broken == yml {
			t.Fatalf("%s: fixture edit did not apply", name)
		}
		for _, id := range []string{"C8", "C22"} {
			if runSiteRow(t, id, broken, blocks).pass {
				t.Errorf("%s: %s must fail", name, id)
			}
		}
	}
}
