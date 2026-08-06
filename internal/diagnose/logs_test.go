package diagnose

import "testing"

func TestLogsSteps_SingleStepAgainstLoopbackLoki(t *testing.T) {
	steps := LogsSteps(`{job="pilot-siem"}`, "", "", "", "")
	if len(steps) != 1 {
		t.Fatalf("LogsSteps() returned %d steps, want 1", len(steps))
	}
	step := steps[0]
	if step.Module != "command" {
		t.Errorf("LogsSteps() Module = %q, want %q", step.Module, "command")
	}
	got := testShlexSplit(step.Command)
	want := []string{
		"curl", "-sS", "-G", "http://127.0.0.1:3100/loki/api/v1/query_range",
		"--data-urlencode", `query={job="pilot-siem"}`,
		"-w", `\nHTTP_STATUS:%{http_code}`,
	}
	for i, w := range want {
		if i >= len(got) || got[i] != w {
			t.Fatalf("LogsSteps() command tokens = %#v, want %#v", got, want)
		}
	}
}

func TestLogsSteps_OptionalParamsPassedThroughWhenSet(t *testing.T) {
	steps := LogsSteps("up", "1h", "now", "50", "forward")
	got := testShlexSplit(steps[0].Command)
	wantContains := []string{"start=1h", "end=now", "limit=50", "direction=forward"}
	for _, w := range wantContains {
		found := false
		for _, tok := range got {
			if tok == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("LogsSteps() command tokens = %#v, missing %q", got, w)
		}
	}
}
