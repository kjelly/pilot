package tools

import (
	"strings"
	"testing"
)

func TestSummarizeInSpec_AllPass(t *testing.T) {
	in := `[{"controls":[{"id":"1.1.1","title":"ok","results":[{"status":"passed"}]}]}]`
	out := summarizeInSpec(in)
	if !strings.Contains(out, "pass=1") || !strings.Contains(out, "fail=0") {
		t.Errorf("expected pass=1 fail=0, got: %s", out)
	}
	if strings.Contains(out, "Failed controls") {
		t.Errorf("did not expect 'Failed controls' section: %s", out)
	}
}

func TestSummarizeInSpec_OneFailed(t *testing.T) {
	in := `[{"controls":[{"id":"1.1.1","title":"ok","results":[{"status":"passed"}]},{"id":"1.1.2","title":"broken","results":[{"status":"failed","message":"denied"}]}]}]`
	out := summarizeInSpec(in)
	if !strings.Contains(out, "pass=1 fail=1") {
		t.Errorf("expected pass=1 fail=1, got: %s", out)
	}
	if !strings.Contains(out, "1.1.2") || !strings.Contains(out, "broken") {
		t.Errorf("failed control should be listed: %s", out)
	}
}

func TestSummarizeInSpec_MultiResultsControl(t *testing.T) {
	// InSpec control with multiple results — fails if ANY result fails.
	in := `[{"controls":[{"id":"1.2.3","title":"mix","results":[{"status":"passed"},{"status":"failed","message":"x"}]}]}]`
	out := summarizeInSpec(in)
	if !strings.Contains(out, "fail=1") {
		t.Errorf("expected fail=1, got: %s", out)
	}
	if !strings.Contains(out, "1.2.3") {
		t.Errorf("expected control id in output, got: %s", out)
	}
}

func TestSummarizeInSpec_Skipped(t *testing.T) {
	in := `[{"controls":[{"id":"9.9.9","title":"skipped ctrl","results":[{"status":"skipped"}]}]}]`
	out := summarizeInSpec(in)
	if !strings.Contains(out, "skip=1") {
		t.Errorf("expected skip=1, got: %s", out)
	}
}

func TestSummarizeInSpec_NoResultsIsFailing(t *testing.T) {
	in := `[{"controls":[{"id":"0.0.0","title":"no results"}]}]`
	out := summarizeInSpec(in)
	if !strings.Contains(out, "fail=1") {
		t.Errorf("expected fail=1 for no-results control, got: %s", out)
	}
}

func TestSummarizeInSpec_MalformedJSON(t *testing.T) {
	out := summarizeInSpec("not json at all")
	if !strings.Contains(out, "parse failed") {
		t.Errorf("expected parse-failed diagnostic, got: %s", out)
	}
}

func TestSummarizeInSpec_Empty(t *testing.T) {
	out := summarizeInSpec("")
	if !strings.Contains(out, "no JSON output") {
		t.Errorf("expected empty diagnostic, got: %s", out)
	}
}

func TestSummarizeInSpec_NoSpaces(t *testing.T) {
	// The previous string-counter implementation relied on
	// ` "status": "passed"` (with space). The new parser must
	// handle whitespace-flexible JSON.
	in := `[{"controls":[{"id":"1","title":"x","results":[{"status":"passed"}]}]}]`
	out := summarizeInSpec(in)
	if !strings.Contains(out, "pass=1") {
		t.Errorf("expected pass=1, got: %s", out)
	}
}

func TestSummarizeInSpec_StableFailedOrdering(t *testing.T) {
	// Failed controls should be sorted by ID for reproducibility.
	in := `[{"controls":[{"id":"3.3.3","title":"c","results":[{"status":"failed"}]},{"id":"1.1.1","title":"a","results":[{"status":"failed"}]},{"id":"2.2.2","title":"b","results":[{"status":"failed"}]}]}]`
	out := summarizeInSpec(in)
	idx1 := strings.Index(out, "1.1.1")
	idx2 := strings.Index(out, "2.2.2")
	idx3 := strings.Index(out, "3.3.3")
	if !(idx1 < idx2 && idx2 < idx3) {
		t.Errorf("failed controls not in sorted order: %s", out)
	}
}
