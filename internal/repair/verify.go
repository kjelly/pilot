package repair

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kjelly/pilot/internal/tools"
)

// VerifyOutcome is a repair action's post-execution verdict — never a
// process exit code alone (design doc §9). Passed is true only when
// EVERY row is pass/skip/not_applicable; a single fail row fails the
// whole outcome, matching the same PASS/FAIL rule `pilot verify` itself
// uses.
type VerifyOutcome struct {
	Passed bool
	Rows   []tools.VerifyRow
}

// VerifyExecutor is the subset of tools.VerifySpecTool this package
// depends on — an interface so tests can inject a fake without spinning
// up real ansible.
type VerifyExecutor interface {
	Execute(ctx context.Context, args json.RawMessage) (*tools.Result, error)
}

// VerifyAfterExecution runs specPath (the plan's own VerificationSpec)
// scoped to exactly host — reusing the SAME `pilot verify` machinery
// operators already trust, not a second ad-hoc success check (design
// doc §9: "execute component verification spec via existing Pilot
// verify machinery").
func VerifyAfterExecution(ctx context.Context, tool VerifyExecutor, specPath, host string, timeoutSec int) (VerifyOutcome, error) {
	args, err := json.Marshal(map[string]any{
		"spec_path":   specPath,
		"host":        host,
		"timeout_sec": timeoutSec,
	})
	if err != nil {
		return VerifyOutcome{}, fmt.Errorf("marshal verify args: %w", err)
	}
	res, err := tool.Execute(ctx, args)
	if err != nil {
		return VerifyOutcome{}, fmt.Errorf("run verification spec %s: %w", specPath, err)
	}
	if res.IsError {
		return VerifyOutcome{}, fmt.Errorf("verify_spec: %s", res.Content)
	}
	rows, err := tools.ReadNDJSON(res.Content)
	if err != nil {
		return VerifyOutcome{}, fmt.Errorf("read verify NDJSON: %w", err)
	}
	passed := true
	for _, r := range rows {
		if r.Status == "fail" {
			passed = false
			break
		}
	}
	return VerifyOutcome{Passed: passed, Rows: rows}, nil
}
