package repair

import (
	"context"
	"testing"
)

func TestParseRecapChanged(t *testing.T) {
	stdout := "TASK [x] ****\nok: [web-1]\n\nPLAY RECAP *********************************************************************\nweb-1                      : ok=5    changed=1    unreachable=0    failed=0\n"
	if got := parseRecapChanged(stdout, "web-1"); got != 1 {
		t.Errorf("got %d, want 1", got)
	}
}

func TestParseRecapChanged_NoRecapReturnsNegativeOne(t *testing.T) {
	if got := parseRecapChanged("no recap here", "web-1"); got != -1 {
		t.Errorf("got %d, want -1 (ambiguous, no PLAY RECAP)", got)
	}
}

func TestParseRecapChanged_WrongHostNotMatched(t *testing.T) {
	stdout := "PLAY RECAP ***\nother-host : ok=5 changed=2\n"
	if got := parseRecapChanged(stdout, "web-1"); got != -1 {
		t.Errorf("got %d, want -1 (web-1 not in this recap)", got)
	}
}

func TestReapplyExecute_Success(t *testing.T) {
	stdout := "PLAY RECAP ***\nweb-1 : ok=5 changed=2\n"
	run := func(ctx context.Context, playbookPath, inventory, host, stage string) (string, int, error) {
		if playbookPath != "playbooks/apply/prometheus-apply.yml" || host != "web-1" || inventory != "/tmp/inv.yml" || stage != "sandbox" {
			t.Errorf("unexpected args: playbook=%s inv=%s host=%s stage=%s", playbookPath, inventory, host, stage)
		}
		return stdout, 0, nil
	}
	plan := ReapplyPlan{Host: "web-1", Resolved: ReapplyResolvedInput{PlaybookPath: "playbooks/apply/prometheus-apply.yml", Stage: "sandbox"}}
	got := ReapplyExecute(context.Background(), run, "/tmp/inv.yml", plan)
	if got.Result != "" {
		t.Errorf("Result = %q, want empty (ansible succeeded — caller classifies the semantic outcome)", got.Result)
	}
	if got.Changed != 2 {
		t.Errorf("Changed = %d, want 2", got.Changed)
	}
}

func TestReapplyExecute_NonZeroExitIsPartialFailure(t *testing.T) {
	run := func(ctx context.Context, playbookPath, inventory, host, stage string) (string, int, error) {
		return "PLAY RECAP ***\nweb-1 : ok=2 changed=1 failed=1\n", 2, nil
	}
	plan := ReapplyPlan{Host: "web-1", Resolved: ReapplyResolvedInput{PlaybookPath: "p.yml"}}
	got := ReapplyExecute(context.Background(), run, "/tmp/inv.yml", plan)
	if got.Result != ReapplyApplyFailedPartial {
		t.Errorf("Result = %q, want %q", got.Result, ReapplyApplyFailedPartial)
	}
}

func TestReapplyExecute_RunnerErrorIsPartialFailure(t *testing.T) {
	run := func(ctx context.Context, playbookPath, inventory, host, stage string) (string, int, error) {
		return "", -1, context.DeadlineExceeded
	}
	plan := ReapplyPlan{Host: "web-1", Resolved: ReapplyResolvedInput{PlaybookPath: "p.yml"}}
	got := ReapplyExecute(context.Background(), run, "/tmp/inv.yml", plan)
	if got.Result != ReapplyApplyFailedPartial {
		t.Errorf("Result = %q, want %q", got.Result, ReapplyApplyFailedPartial)
	}
	if got.Error == "" {
		t.Error("Error should be set")
	}
}
