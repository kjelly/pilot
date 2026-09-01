package repair

import (
	"context"
	"fmt"
	"time"

	"github.com/kjelly/pilot/internal/diagnose"
)

// validExecutorKinds mirrors internal/contract's own enum — kept
// independent (not imported) so this package's own fail-closed default
// in ExecutorStep does not silently depend on contract's validation
// having already run.
var validExecutorKinds = map[string]bool{
	"docker_restart":  true,
	"systemd_restart": true,
	"systemd_reload":  true,
}

// ExecutorStep builds the ONE fixed, read-only-shaped ad-hoc command for
// a plan's executor kind — Module is always "command" (ansible execs
// argv directly, no shell metacharacter interpretation), never "shell",
// and target is always the plan's own ExecutorTarget (contract-resolved,
// never caller input — see plan.go's BuildPlan). There is intentionally
// no case that accepts a caller-supplied command string.
func ExecutorStep(kind, target string) (diagnose.Step, error) {
	if !validExecutorKinds[kind] {
		return diagnose.Step{}, fmt.Errorf("unknown executor kind %q", kind)
	}
	switch kind {
	case "docker_restart":
		return diagnose.Step{ID: "execute", Description: "docker restart " + target, Module: "command",
			Command: fmt.Sprintf("docker restart %s", target)}, nil
	case "systemd_restart":
		return diagnose.Step{ID: "execute", Description: "systemctl restart " + target, Module: "command",
			Command: fmt.Sprintf("systemctl restart %s", target)}, nil
	case "systemd_reload":
		return diagnose.Step{ID: "execute", Description: "systemctl reload " + target, Module: "command",
			Command: fmt.Sprintf("systemctl reload %s", target)}, nil
	default:
		return diagnose.Step{}, fmt.Errorf("unknown executor kind %q", kind)
	}
}

// Execute runs plan's single executor step against plan.Host — exactly
// one ad-hoc call, exactly one host, reusing internal/diagnose's own
// AdHocRunner/RunSteps/StepResult machinery (Task 6: "Reuse Pilot
// isolated Ansible runtime... No shell") rather than a second executor
// implementation.
func Execute(ctx context.Context, runner diagnose.AdHocRunner, inventory string, p Plan, timeoutSeconds int) (diagnose.StepResult, error) {
	step, err := ExecutorStep(p.ExecutorKind, p.ExecutorTarget)
	if err != nil {
		return diagnose.StepResult{}, err
	}
	results := diagnose.RunSteps(ctx, runner, inventory, p.Host, []diagnose.Step{step},
		time.Duration(timeoutSeconds)*time.Second)
	return results[0], nil
}
