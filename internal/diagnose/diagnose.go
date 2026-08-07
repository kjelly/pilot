// Package diagnose runs fixed, read-only Ansible ad-hoc commands against a
// single real inventory host to answer "why isn't X working there" —
// starting with sudo and DNS resolution. Every command a check runs is a
// code-defined literal mirroring a docs/verification/*.md Checklist row
// (never a client-suppliable module/args pair), so the blast radius of
// exposing this over MCP is bounded to a small, auditable allow-list
// instead of "run anything as root on any host."
package diagnose

import (
	"context"
	"strconv"
	"time"
)

// Step is one fixed, read-only ad-hoc command. Command is either copied
// verbatim from a docs/verification/*.md Checklist row (ID cites that row)
// or is a %s-templated variant of one, with the %s already substituted by
// *validated* input before the Step is constructed — Step itself never
// carries raw, unvalidated caller input. Module is "command" for every
// templated Step (never "shell"), so ansible execs argv directly with no
// shell-metacharacter interpretation at any point — defense in depth on
// top of input validation.
type Step struct {
	ID          string
	Description string
	Module      string
	Command     string
}

// StepResult pairs a Step with what actually happened when it ran.
type StepResult struct {
	Step   Step
	Result AdHocResult
}

// AdHocRunner runs one `ansible <args...>` invocation and returns its raw
// stdout (an ansible.posix.json callback document — the caller is
// responsible for having set ANSIBLE_STDOUT_CALLBACK=ansible.posix.json in
// its own environment, see the production adapter in
// cmd/pilot/cmd/mcp_diagnose_tools.go), the ansible process's exit code,
// and any error starting/running the process itself. A clean nonzero exit
// from the *remote* command (e.g. `systemctl is-active sssd` when the
// service is down) is not a RunErr — see AdHocResult.RC — only a failure
// to run ansible at all (binary missing, context cancelled) is.
type AdHocRunner func(ctx context.Context, args []string, timeoutSeconds int) (rawJSON string, exitCode int, err error)

// RunSteps runs every step against host as its own independent ad-hoc call
// — never chained into a single script — so one step's timeout, nonzero
// rc, or unreachable status can never blank or suppress any other step's
// result. This is deliberate: if sssd is down (one step's expected,
// informative failure), we still want to know whether the nsswitch/sudo
// rule steps would *also* fail. Steps run serially; diagnose calls are
// low-QPS by nature, and deployAnsibleCommand's shared ControlMaster
// already keeps repeat connections to the same host cheap; a bounded
// concurrent pool is a documented follow-up, not needed for this
// increment. Returns one StepResult per input step, in the same order.
func RunSteps(ctx context.Context, run AdHocRunner, inventory, host string, steps []Step, perStepTimeout time.Duration) []StepResult {
	results := make([]StepResult, len(steps))
	for i, step := range steps {
		// Bound Ansible's own SSH connection setup as well as the runner's
		// outer context. Without -T, a TCP black hole can leave an ssh child
		// alive after cancellation and make an MCP diagnose request appear to
		// hang instead of returning evidence.
		args := []string{host, "-i", inventory, "-T", strconv.Itoa(int(perStepTimeout.Seconds())), "-m", step.Module, "-a", step.Command}
		rawJSON, _, err := run(ctx, args, int(perStepTimeout.Seconds()))
		var result AdHocResult
		if err != nil {
			result = AdHocResult{RunErr: err}
		} else {
			decoded, decodeErr := DecodeAdHocResult(rawJSON, host)
			if decodeErr != nil {
				result = AdHocResult{RunErr: decodeErr}
			} else {
				result = decoded
			}
		}
		results[i] = StepResult{Step: step, Result: result}
	}
	return results
}
