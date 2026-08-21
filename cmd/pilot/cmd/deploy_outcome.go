// deploy_outcome.go wires internal/ansible's structured-callback-based
// semantic deployment outcome classifier into executeDeploymentTransaction's
// apply step, so an optional host that goes transport-unreachable *during*
// the apply run — after Phase 5's pre-run probe already found it reachable
// — does not fail the deployment either (spec.md §17/§18, the mid-run
// shutdown race). This file never invokes ansible-playbook itself; it only
// prepares the private per-run event file pilot_result.py writes to and
// classifies its contents once the apply run returns.
package cmd

import (
	"context"
	"fmt"
	"os"
)

// resultCallbackEnv is the extra ANSIBLE_* environment pilot's own apply
// invocation needs to enable ansible_callback/pilot_result.py for exactly
// this one run — never globally, and never for a directly invoked
// ansible-playbook outside pilot's deploy/reconcile flows (spec §5
// non-goals).
func resultCallbackEnv(callbackPluginsDir, resultPath string) []string {
	return []string{
		"ANSIBLE_CALLBACK_PLUGINS=" + callbackPluginsDir,
		"ANSIBLE_CALLBACKS_ENABLED=pilot_result",
		"PILOT_ANSIBLE_RESULT_FILE=" + resultPath,
	}
}

// prepareDeploymentResultFile creates the private, restrictively
// permissioned (spec §25.2 — os.CreateTemp defaults to 0600) JSON-lines
// file pilot_result.py appends to for one apply invocation, under the
// same controller-private ansible runtime directory
// prepareDeployAnsibleRuntime already created (never under the repo tree
// or a shared/world-readable path). The returned cleanup func
// best-effort removes the file; a cleanup failure must never fail the
// deployment (spec §25.2 "cleaned after processing").
func prepareDeploymentResultFile(ctx context.Context) (path string, cleanup func(), err error) {
	runtime := deployAnsibleRuntimeFromContext(ctx)
	if runtime.TempDir == "" {
		return "", func() {}, fmt.Errorf("prepare deployment result file: no ansible runtime directory in context")
	}
	f, err := os.CreateTemp(runtime.TempDir, "pilot-result-*.jsonl")
	if err != nil {
		return "", func() {}, fmt.Errorf("create deployment result file: %w", err)
	}
	name := f.Name()
	if closeErr := f.Close(); closeErr != nil {
		return "", func() {}, fmt.Errorf("create deployment result file: %w", closeErr)
	}
	return name, func() { _ = os.Remove(name) }, nil
}
