package providers

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
)

// readLoginProbeQueryCapture loads real ansible-playbook stdout of
// playbooks/decommission/login-probe-target-query.yml (captured 2026-10-13
// with ansible-core 2.19, two probe hosts; AGENTS.md §5.6).
func readLoginProbeQueryCapture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "login_probe_target_query", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func newLoginProbeTestProvider(fake *fakeAnsibleExecutor, probes ...string) *LoginProbeTargetsProvider {
	return NewLoginProbeTargetsProvider(LoginProbeTargetsProviderConfig{
		Executor:      fake,
		Inventory:     "/ws/inventory.yml",
		QueryPlaybook: "playbooks/decommission/login-probe-target-query.yml",
		ApplyPlaybook: "playbooks/apply/login-probe-apply.yml",
		ProbeHosts:    probes,
		ApplyStageArgs: func() ([]string, error) {
			return []string{"-e", "stage=staging", "-e", "confirm_staging=true"}, nil
		},
	})
}

func isQuery(args []string) bool {
	return len(args) > 0 && strings.HasSuffix(args[0], "login-probe-target-query.yml")
}
func isReRender(args []string) bool {
	return len(args) > 0 && strings.HasSuffix(args[0], "login-probe-apply.yml")
}

func argAfter(args []string, flag string) string {
	for i := 0; i+1 < len(args); i++ {
		if args[i] == flag {
			return args[i+1]
		}
	}
	return ""
}

func TestLoginProbeTargets_PlanOnlyWhenAnotherProbeHostExists(t *testing.T) {
	ctx := context.Background()
	none := newLoginProbeTestProvider(&fakeAnsibleExecutor{})
	if steps, err := none.Plan(ctx, PlanInput{HostName: "web1", FQDN: "web1.ipa.pilot.internal"}); err != nil || len(steps) != 0 {
		t.Fatalf("no probe hosts: steps=%v err=%v, want none", steps, err)
	}
	// The retiring host being the only probe host leaves nobody to clean.
	self := newLoginProbeTestProvider(&fakeAnsibleExecutor{}, "mon1")
	if steps, _ := self.Plan(ctx, PlanInput{HostName: "MON1"}); len(steps) != 0 {
		t.Fatalf("only probe host is the retiring host: steps=%v, want none", steps)
	}
	p := newLoginProbeTestProvider(&fakeAnsibleExecutor{}, "mon1", "mon2")
	steps, err := p.Plan(ctx, PlanInput{HostName: "web1", FQDN: "web1.ipa.pilot.internal"})
	if err != nil || len(steps) != 1 {
		t.Fatalf("steps=%v err=%v, want exactly one", steps, err)
	}
	s := steps[0]
	if s.Phase != "central_cleanup" || s.Action != ActionLoginProbeTargetRemove || s.TargetIdentity != "web1" || s.Params["fqdn"] != "web1.ipa.pilot.internal" {
		t.Fatalf("unexpected step %+v", s)
	}
}

func TestLoginProbeTargets_QueryParsesRealCaptures(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		capture   string
		wantFound bool
		wantOn    string
	}{
		{"local-two-probes-one-listed.stdout", true, "probe-a"},
		{"local-two-probes-none-listed.stdout", false, ""},
	} {
		capture := readLoginProbeQueryCapture(t, c.capture)
		fake := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
			return &ansible.Result{Stdout: capture}, nil
		}}
		p := newLoginProbeTestProvider(fake, "probe-a", "probe-b")
		insp, err := p.Inspect(ctx, InspectInput{HostName: "lp-target-el", FQDN: "lp-target-el.ipa.pilot.internal"})
		if err != nil {
			t.Fatalf("%s: %v", c.capture, err)
		}
		if insp.Found != c.wantFound || (c.wantOn != "" && !strings.Contains(insp.Detail, c.wantOn)) || (c.wantOn == "" && strings.Contains(insp.Detail, "probe-b")) {
			t.Errorf("%s: inspection %+v, want found=%v on %q", c.capture, insp, c.wantFound, c.wantOn)
		}
		vs, err := p.Verify(ctx, VerifyInput{HostName: "lp-target-el", FQDN: "lp-target-el.ipa.pilot.internal"})
		if err != nil || len(vs) != 2 {
			t.Fatalf("%s: verify=%v err=%v", c.capture, vs, err)
		}
		active := 0
		for _, v := range vs {
			if v.Active {
				active++
				if v.Status != "active_residue" || !strings.HasSuffix(v.Identity, "@"+c.wantOn) {
					t.Errorf("%s: active verification %+v", c.capture, v)
				}
			} else if v.Status != "pass" {
				t.Errorf("%s: clean verification must pass: %+v", c.capture, v)
			}
		}
		if (active > 0) != c.wantFound {
			t.Errorf("%s: %d active verifications, want found=%v", c.capture, active, c.wantFound)
		}
		// The query is read-only, scoped to the probe hosts, and carries both
		// names of the retiring host as a JSON list.
		q := fake.calls[0]
		if !isQuery(q) || argAfter(q, "--limit") != "probe-a,probe-b" || argAfter(q, "--tags") != "target_query" {
			t.Fatalf("%s: unexpected query args %v", c.capture, q)
		}
		var names map[string][]string
		if err := json.Unmarshal([]byte(argAfter(q, "-e")), &names); err != nil || strings.Join(names["pilot_decommission_target_names"], ",") != "lp-target-el,lp-target-el.ipa.pilot.internal" {
			t.Fatalf("%s: query names %v (%v)", c.capture, names, err)
		}
		if argsContain(q, "stage=") {
			t.Errorf("%s: the read-only query must not carry stage arguments: %v", c.capture, q)
		}
	}
}

// A probe host that did not report (unreachable, failed play cut short,
// or the marker never printed) must be an error, never "absent".
func TestLoginProbeTargets_MissingReportIsAnErrorNotClean(t *testing.T) {
	ctx := context.Background()
	capture := readLoginProbeQueryCapture(t, "local-two-probes-none-listed.stdout")
	fake := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
		return &ansible.Result{Stdout: capture}, nil
	}}
	p := newLoginProbeTestProvider(fake, "probe-a", "probe-b", "probe-c")
	if _, err := p.Inspect(ctx, InspectInput{HostName: "web1"}); err == nil || !strings.Contains(err.Error(), "probe-c") {
		t.Fatalf("missing probe-c report must fail, got %v", err)
	}
	failing := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
		return &ansible.Result{ExitCode: 4, Stdout: "fatal: [probe-a]: UNREACHABLE!"}, nil
	}}
	p = newLoginProbeTestProvider(failing, "probe-a")
	if _, err := p.Verify(ctx, VerifyInput{HostName: "web1"}); err == nil {
		t.Fatal("a failed query run must be an error")
	}
}

func TestLoginProbeTargets_StepInspectThenExecute(t *testing.T) {
	ctx := context.Background()
	listed := readLoginProbeQueryCapture(t, "local-two-probes-one-listed.stdout")
	clean := readLoginProbeQueryCapture(t, "local-two-probes-none-listed.stdout")
	reRendered := false
	fake := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
		switch {
		case isQuery(args) && reRendered:
			return &ansible.Result{Stdout: clean}, nil
		case isQuery(args):
			return &ansible.Result{Stdout: listed}, nil
		case isReRender(args):
			reRendered = true
			return &ansible.Result{}, nil
		}
		t.Fatalf("unexpected call %v", args)
		return nil, nil
	}}
	p := newLoginProbeTestProvider(fake, "probe-b", "probe-a", "lp-target-el")
	steps, err := p.Plan(ctx, PlanInput{HostName: "lp-target-el", FQDN: "lp-target-el.ipa.pilot.internal"})
	if err != nil || len(steps) != 1 {
		t.Fatalf("plan: %v %v", steps, err)
	}
	exec, err := p.ExecutorForStep(steps[0])
	if err != nil {
		t.Fatal(err)
	}
	converged, err := exec.Inspect(ctx)
	if err != nil || converged {
		t.Fatalf("before re-render: converged=%v err=%v, want not converged", converged, err)
	}
	if err := exec.Execute(ctx); err != nil {
		t.Fatal(err)
	}
	var run []string
	for _, c := range fake.calls {
		if isReRender(c) {
			run = c
		}
	}
	if run == nil {
		t.Fatal("Execute did not re-render the probe hosts")
	}
	if argAfter(run, "--limit") != "probe-a,probe-b" {
		t.Errorf("re-render must target every other probe host (sorted, retiring host excluded), got %q", argAfter(run, "--limit"))
	}
	var exclude map[string][]string
	if err := json.Unmarshal([]byte(argAfter(run, "-e")), &exclude); err != nil || strings.Join(exclude["login_probe_exclude_targets"], ",") != "lp-target-el,lp-target-el.ipa.pilot.internal" {
		t.Errorf("exclusion %v (%v)", exclude, err)
	}
	if !argsContain(run, "stage=staging") || !argsContain(run, "confirm_staging=true") {
		t.Errorf("re-render must carry the probe hosts' stage arguments: %v", run)
	}
	if converged, err := exec.Inspect(ctx); err != nil || !converged {
		t.Fatalf("after re-render: converged=%v err=%v, want converged", converged, err)
	}
}

func TestLoginProbeTargets_ReRenderFailureSurfaces(t *testing.T) {
	fake := &fakeAnsibleExecutor{fn: func(args []string) (*ansible.Result, error) {
		if isReRender(args) {
			return &ansible.Result{ExitCode: 2, Stdout: "fatal: [probe-a]: FAILED! => {\"msg\": \"Gate: stage must match\"}"}, nil
		}
		return &ansible.Result{}, nil
	}}
	p := newLoginProbeTestProvider(fake, "probe-a")
	exec, err := p.ExecutorForStep(Step{Action: ActionLoginProbeTargetRemove, TargetIdentity: "web1"})
	if err != nil {
		t.Fatal(err)
	}
	if err := exec.Execute(context.Background()); err == nil || !strings.Contains(err.Error(), "exited 2") {
		t.Fatalf("a failed re-render must be an error (AGENTS.md §5.8), got %v", err)
	}
	if _, err := p.ExecutorForStep(Step{Action: "something_else"}); err == nil {
		t.Fatal("unknown action must be rejected")
	}
}
