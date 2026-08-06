package diagnose

import "testing"

func TestMetricsSteps_InstantQueryWhenNoTimeRangeGiven(t *testing.T) {
	steps := MetricsSteps(`up{job="prometheus"}`, "", "", "", "")
	if len(steps) != 1 {
		t.Fatalf("MetricsSteps() returned %d steps, want 1", len(steps))
	}
	got := testShlexSplit(steps[0].Command)
	if got[3] != "http://127.0.0.1:10912/api/v1/query" {
		t.Fatalf("MetricsSteps() url token = %q, want the instant /api/v1/query endpoint", got[3])
	}
	for _, unwanted := range []string{"start=", "end=", "step="} {
		for _, tok := range got {
			if len(tok) >= len(unwanted) && tok[:len(unwanted)] == unwanted {
				t.Fatalf("MetricsSteps() instant query unexpectedly includes %q", tok)
			}
		}
	}
}

func TestMetricsSteps_InstantQueryWithEvalTime(t *testing.T) {
	steps := MetricsSteps("up", "2026-01-01T00:00:00Z", "", "", "")
	got := testShlexSplit(steps[0].Command)
	found := false
	for _, tok := range got {
		if tok == "time=2026-01-01T00:00:00Z" {
			found = true
		}
	}
	if !found {
		t.Fatalf("MetricsSteps() command tokens = %#v, missing time= param", got)
	}
}

func TestMetricsSteps_RangeQueryWhenStartAndEndGiven(t *testing.T) {
	steps := MetricsSteps("up", "ignored-when-range", "2026-01-01T00:00:00Z", "2026-01-01T01:00:00Z", "30s")
	got := testShlexSplit(steps[0].Command)
	if got[3] != "http://127.0.0.1:10912/api/v1/query_range" {
		t.Fatalf("MetricsSteps() url token = %q, want the /api/v1/query_range endpoint", got[3])
	}
	wantContains := []string{"start=2026-01-01T00:00:00Z", "end=2026-01-01T01:00:00Z", "step=30s"}
	for _, w := range wantContains {
		found := false
		for _, tok := range got {
			if tok == w {
				found = true
			}
		}
		if !found {
			t.Errorf("MetricsSteps() range query tokens = %#v, missing %q", got, w)
		}
	}
	for _, tok := range got {
		if tok == "time=ignored-when-range" {
			t.Fatalf("MetricsSteps() range query unexpectedly included the ignored evalTime param: %#v", got)
		}
	}
}

func TestMetricsSteps_RangeQueryRequiresBothStartAndEnd(t *testing.T) {
	steps := MetricsSteps("up", "", "2026-01-01T00:00:00Z", "", "30s")
	got := testShlexSplit(steps[0].Command)
	if got[3] != "http://127.0.0.1:10912/api/v1/query" {
		t.Fatalf("MetricsSteps() with only start set should still be an instant query, got url token %q", got[3])
	}
}
