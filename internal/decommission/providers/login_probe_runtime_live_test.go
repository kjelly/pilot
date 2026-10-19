package providers_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/decommission"
	"github.com/kjelly/pilot/internal/decommission/providers"
)

// This opt-in target test starts after the disposable lab deliberately
// interrupts a render before restart. It runs the production provider and
// real full apply, not the local adapter used by the mandatory regression.
func TestLoginProbeTargets_LiveInterruptedRuntime(t *testing.T) {
	inv := os.Getenv("PILOT_LOGIN_PROBE_LIVE_INVENTORY")
	if inv == "" {
		t.Skip("requires a deliberately interrupted disposable target")
	}
	vars := os.Getenv("PILOT_LOGIN_PROBE_LIVE_VARS")
	probe, target := os.Getenv("PILOT_LOGIN_PROBE_LIVE_HOST"), os.Getenv("PILOT_LOGIN_PROBE_LIVE_TARGET")
	if !filepath.IsAbs(inv) || !filepath.IsAbs(vars) || probe == "" || target == "" {
		t.Fatal("absolute inventory/vars paths and probe/target identities are required")
	}
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	query, apply := filepath.Join(root, "playbooks/decommission/login-probe-target-query.yml"), filepath.Join(root, "playbooks/apply/login-probe-apply.yml")
	applyCalls := 0
	lastApply := ""
	runner := loginProbeRuntimeExecutor{run: func(ctx context.Context, args ...string) (*ansible.Result, error) {
		cmd := exec.CommandContext(ctx, "ansible-playbook", args...)
		cmd.Dir = root
		out, err := cmd.CombinedOutput()
		rc := 0
		if err != nil {
			if exit, ok := err.(*exec.ExitError); ok {
				rc = exit.ExitCode()
			} else {
				return nil, err
			}
		}
		if args[0] == apply {
			applyCalls++
			lastApply = string(out)
		}
		if rc != 0 {
			t.Logf("failed target operation output:\n%s", out)
		}
		return &ansible.Result{Stdout: string(out), ExitCode: rc}, nil
	}}
	p := providers.NewLoginProbeTargetsProvider(providers.LoginProbeTargetsProviderConfig{Executor: runner, Inventory: inv, QueryPlaybook: query, ApplyPlaybook: apply, ProbeHosts: []string{probe}, ExtraArgs: []string{"-e", "@" + vars}})
	ctx := context.Background()
	inspect, err := p.Inspect(ctx, providers.InspectInput{HostName: target})
	if err != nil || !inspect.Found {
		t.Fatalf("interrupted runtime must need repair: %+v %v", inspect, err)
	}
	vs, err := p.Verify(ctx, providers.VerifyInput{HostName: target})
	if err != nil || len(vs) != 1 || !vs[0].Active {
		t.Fatalf("pre-repair Verify: %+v %v", vs, err)
	}
	steps, err := p.Plan(ctx, providers.PlanInput{HostName: target})
	if err != nil || len(steps) != 1 {
		t.Fatalf("Plan: %+v %v", steps, err)
	}
	step, err := p.ExecutorForStep(steps[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := decommission.NewExecutor([]*decommission.ExecStep{decommission.NewExecStep("live-remove", p.ID(), steps[0].Action, step)}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	if applyCalls != 1 {
		t.Fatalf("full apply calls=%d, want 1", applyCalls)
	}
	vs, err = p.Verify(ctx, providers.VerifyInput{HostName: target})
	if err != nil || len(vs) != 1 || vs[0].Active || vs[0].Status != "pass" {
		t.Fatalf("post-repair Verify: %+v %v", vs, err)
	}
	if err := decommission.NewExecutor([]*decommission.ExecStep{decommission.NewExecStep("live-repeat", p.ID(), steps[0].Action, step)}).Run(ctx); err != nil {
		t.Fatal(err)
	}
	if applyCalls != 1 {
		t.Fatal("converged retry did not skip Execute")
	}
	if err := step.Execute(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(lastApply, "changed=0") || !strings.Contains(lastApply, "failed=0") {
		t.Fatalf("full apply was not idempotent:\n%s", lastApply)
	}
	t.Log("production Inspect -> Executor full apply -> Verify PASS; converged state machine skipped mutation; explicit full reapply changed=0")
}
