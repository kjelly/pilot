package diagnose

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadDiagnosticProfile_Valid(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "network-device-ifmib-v1.yaml")
	content := []byte(`id: network-device-ifmib-v1
queries:
  - name: target_up
    description: is it up
    promql: 'up{pilot_target="__TARGET__"}'
`)
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write profile: %v", err)
	}
	p, err := LoadDiagnosticProfile(path)
	if err != nil {
		t.Fatalf("LoadDiagnosticProfile: %v", err)
	}
	if p.ID != "network-device-ifmib-v1" || len(p.Queries) != 1 {
		t.Fatalf("unexpected profile: %+v", p)
	}
}

func TestLoadDiagnosticProfile_RejectsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty.yaml")
	if err := os.WriteFile(path, []byte("id: x\nqueries: []\n"), 0o644); err != nil {
		t.Fatalf("write profile: %v", err)
	}
	if _, err := LoadDiagnosticProfile(path); err == nil {
		t.Fatal("expected an error for a profile with zero queries")
	}
}

func TestMonitoringTargetDiagnosisSteps_SubstitutesTargetWindowTopN(t *testing.T) {
	profile := DiagnosticProfile{
		ID: "test", Queries: []DiagnosticQuery{
			{Name: "top_errors", PromQL: `topk(__TOPN__, rate(ifInErrors{pilot_target="__TARGET__"}[__WINDOW__]))`},
		},
	}
	steps := MonitoringTargetDiagnosisSteps(profile, "core-sw-01", "30m", 10)
	if len(steps) != 1 {
		t.Fatalf("expected 1 step, got %d", len(steps))
	}
	cmd := steps[0].Command
	for _, want := range []string{"core-sw-01", "30m", "10"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("command %q does not contain %q", cmd, want)
		}
	}
	if strings.Contains(cmd, "__TARGET__") || strings.Contains(cmd, "__WINDOW__") || strings.Contains(cmd, "__TOPN__") {
		t.Errorf("command %q still contains an unsubstituted placeholder", cmd)
	}
}

func TestMonitoringTargetDiagnosisSteps_EscapesTargetName(t *testing.T) {
	profile := DiagnosticProfile{
		ID: "test", Queries: []DiagnosticQuery{
			{Name: "up", PromQL: `up{pilot_target="__TARGET__"}`},
		},
	}
	// A quote in the target name must never break out of the PromQL
	// string literal (defense in depth — targetNamePattern already
	// prevents this at the registry layer, spec §10.5).
	steps := MonitoringTargetDiagnosisSteps(profile, `x"} or up{job="evil`, "30m", 10)
	if strings.Contains(steps[0].Command, `job="evil`) {
		t.Errorf("unescaped target name allowed PromQL injection: %q", steps[0].Command)
	}
}

func TestParsePromInstantVector_SortsDescendingAndSkipsUnparsable(t *testing.T) {
	body := `{"status":"success","data":{"resultType":"vector","result":[
		{"metric":{"ifIndex":"1"},"value":[1700000000,"5"]},
		{"metric":{"ifIndex":"2"},"value":[1700000000,"42"]},
		{"metric":{"ifIndex":"3"},"value":[1700000000,"NaN"]}
	]}}`
	samples, err := parsePromInstantVector(body)
	if err != nil {
		t.Fatalf("parsePromInstantVector: %v", err)
	}
	if len(samples) != 3 {
		t.Fatalf("len(samples) = %d, want 3 (NaN still parses as a float)", len(samples))
	}
	if samples[0].Labels["ifIndex"] != "2" {
		t.Fatalf("expected descending sort, got %+v", samples)
	}
}

func TestParsePromInstantVector_RejectsFailedQuery(t *testing.T) {
	body := `{"status":"error","error":"bad query"}`
	if _, err := parsePromInstantVector(body); err == nil {
		t.Fatal("expected an error for status=error")
	}
}
