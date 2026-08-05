package diagnose

import (
	"context"
	"fmt"
	"testing"
	"time"
)

// fakeRunner returns a canned ansible.posix.json doc (or an error) keyed by
// the ad-hoc command's step ID, so RunSteps' behavior is exercised without
// spawning ansible.
type fakeRunner struct {
	byCommand map[string]func() (string, int, error)
	calls     []string
}

func (f *fakeRunner) run(_ context.Context, args []string, _ int) (string, int, error) {
	// args = [host, "-i", inventory, "-m", module, "-a", command]
	command := args[len(args)-1]
	f.calls = append(f.calls, command)
	fn, ok := f.byCommand[command]
	if !ok {
		return "", 0, fmt.Errorf("no fake response configured for command %q", command)
	}
	return fn()
}

func TestRunSteps_OneStepFailureDoesNotBlankOthers(t *testing.T) {
	host := "web1"
	steps := []Step{
		{ID: "A", Module: "command", Command: "cmd-a"},
		{ID: "B", Module: "command", Command: "cmd-b"},
		{ID: "C", Module: "command", Command: "cmd-c"},
	}
	f := &fakeRunner{byCommand: map[string]func() (string, int, error){
		"cmd-a": func() (string, int, error) { return callbackDoc(t, host, 0, "a-ok", false, false), 0, nil },
		"cmd-b": func() (string, int, error) { return "", 0, fmt.Errorf("ansible timed out") },
		"cmd-c": func() (string, int, error) { return callbackDoc(t, host, 0, "c-ok", false, false), 0, nil },
	}}

	got := RunSteps(context.Background(), f.run, "inv.yml", host, steps, 5*time.Second)
	if len(got) != 3 {
		t.Fatalf("RunSteps() returned %d results, want 3", len(got))
	}
	if got[0].Result.RunErr != nil || got[0].Result.Stdout != "a-ok" {
		t.Fatalf("step A = %+v, want a clean success", got[0].Result)
	}
	if got[1].Result.RunErr == nil {
		t.Fatalf("step B = %+v, want a RunErr (the fake runner errored)", got[1].Result)
	}
	if got[2].Result.RunErr != nil || got[2].Result.Stdout != "c-ok" {
		t.Fatalf("step C = %+v, want a clean success — step B's failure must not blank step C", got[2].Result)
	}
}

func TestRunSteps_NonzeroRCIsPreservedAsData(t *testing.T) {
	host := "web1"
	steps := []Step{{ID: "A", Module: "command", Command: "systemctl is-active sssd"}}
	f := &fakeRunner{byCommand: map[string]func() (string, int, error){
		"systemctl is-active sssd": func() (string, int, error) {
			return callbackDoc(t, host, 3, "inactive", true, false), 0, nil
		},
	}}
	got := RunSteps(context.Background(), f.run, "inv.yml", host, steps, 5*time.Second)
	if got[0].Result.RunErr != nil {
		t.Fatalf("RunSteps() step = %+v, want no RunErr — a clean nonzero rc is data, not a run failure", got[0].Result)
	}
	if got[0].Result.RC != 3 {
		t.Fatalf("RunSteps() step.RC = %d, want 3", got[0].Result.RC)
	}
}

func TestRunSteps_PreservesOrder(t *testing.T) {
	host := "web1"
	steps := []Step{
		{ID: "A", Module: "command", Command: "cmd-a"},
		{ID: "B", Module: "command", Command: "cmd-b"},
	}
	f := &fakeRunner{byCommand: map[string]func() (string, int, error){
		"cmd-a": func() (string, int, error) { return callbackDoc(t, host, 0, "", false, false), 0, nil },
		"cmd-b": func() (string, int, error) { return callbackDoc(t, host, 0, "", false, false), 0, nil },
	}}
	got := RunSteps(context.Background(), f.run, "inv.yml", host, steps, 5*time.Second)
	if got[0].Step.ID != "A" || got[1].Step.ID != "B" {
		t.Fatalf("RunSteps() order = [%s, %s], want [A, B]", got[0].Step.ID, got[1].Step.ID)
	}
}
