package accessgrants

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/inventory"
)

// capabilityAwareFakeRunner distinguishes a capability-probe invocation
// (its extra-vars carry pilot_capability_output) from any other playbook
// invocation (ReconcileOnce's own apply-playbook call) — so one fake can
// drive both requireFreeIPACapabilities' internal/freeipa.ProbeCapabilities
// call and a full ReconcileOnce run within one test.
type capabilityAwareFakeRunner struct {
	// capabilityResult is the raw JSON ProbeCapabilities' output file
	// gets; "" simulates a probe that runs but never produces a result
	// (ProbeCapabilities then fails closed to all-unknown).
	capabilityResult string
	applyExitCode    int
	calls            []string // playbook path (args[0]) per call, in order
}

func (f *capabilityAwareFakeRunner) Run(_ context.Context, args ...string) (*ansible.Result, error) {
	if len(args) > 0 {
		f.calls = append(f.calls, args[0])
	}
	if outputPath := extraVarFromArgs(args, "pilot_capability_output"); outputPath != "" {
		if f.capabilityResult != "" {
			if err := os.WriteFile(outputPath, []byte(f.capabilityResult), 0o600); err != nil {
				panic(err)
			}
		}
		return &ansible.Result{ExitCode: 0}, nil
	}
	return &ansible.Result{ExitCode: f.applyExitCode}, nil
}

// extraVarFromArgs decodes the `-e @<file>` extra-vars JSON a probe call
// wrote and returns the named key's value.
func extraVarFromArgs(args []string, key string) string {
	for i, a := range args {
		if a == "-e" && i+1 < len(args) && len(args[i+1]) > 1 && args[i+1][0] == '@' {
			data, err := os.ReadFile(args[i+1][1:])
			if err != nil {
				return ""
			}
			var vars map[string]string
			if err := json.Unmarshal(data, &vars); err != nil {
				return ""
			}
			return vars[key]
		}
	}
	return ""
}

func TestRequireFreeIPACapabilities_SkipsProbeWhenNothingGated(t *testing.T) {
	runner := &capabilityAwareFakeRunner{}
	opts := ReconcileOptions{Inventory: "inv.yml", RosterFile: "roster.yaml", Runner: runner}
	plan := Plan{HBACRules: []inventory.CompiledHBACRule{{Name: "x", Present: true}}}

	if err := requireFreeIPACapabilities(context.Background(), opts, plan); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("expected zero probe calls for a plan with nothing capability-gated, got: %v", runner.calls)
	}
}

func TestRequireFreeIPACapabilities_PassesWhenSupported(t *testing.T) {
	runner := &capabilityAwareFakeRunner{capabilityResult: `{"schema_version":1,"capabilities":{"group_password_policy":"supported"}}`}
	opts := ReconcileOptions{Inventory: "inv.yml", RosterFile: "roster.yaml", Runner: runner}
	priority := 10
	plan := Plan{PasswordPolicies: []inventory.CompiledPasswordPolicy{{Name: "p", State: "present", Group: "role-privileged", Priority: &priority}}}

	if err := requireFreeIPACapabilities(context.Background(), opts, plan); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("expected exactly one capability probe call, got: %v", runner.calls)
	}
}

func TestRequireFreeIPACapabilities_FailsClosedWhenUnknown(t *testing.T) {
	runner := &capabilityAwareFakeRunner{} // no capabilityResult -> probe fails -> all-unknown
	opts := ReconcileOptions{Inventory: "inv.yml", RosterFile: "roster.yaml", Runner: runner}
	priority := 10
	plan := Plan{PasswordPolicies: []inventory.CompiledPasswordPolicy{{Name: "p", State: "present", Group: "role-privileged", Priority: &priority}}}

	if err := requireFreeIPACapabilities(context.Background(), opts, plan); err == nil {
		t.Fatal("expected an error when the capability probe cannot confirm support")
	}
}

func TestRequireFreeIPACapabilities_LockoutCheckedSeparatelyFromBasePolicy(t *testing.T) {
	runner := &capabilityAwareFakeRunner{capabilityResult: `{"schema_version":1,"capabilities":{"group_password_policy":"supported","password_lockout_policy":"unsupported"}}`}
	opts := ReconcileOptions{Inventory: "inv.yml", RosterFile: "roster.yaml", Runner: runner}
	priority, maxFailures := 10, 5
	plan := Plan{PasswordPolicies: []inventory.CompiledPasswordPolicy{{
		Name: "p", State: "present", Group: "role-privileged", Priority: &priority,
		LockoutMaxFailures: &maxFailures,
	}}}

	err := requireFreeIPACapabilities(context.Background(), opts, plan)
	if err == nil {
		t.Fatal("expected an error: base policy is supported but lockout is not, and this plan sets a lockout field")
	}
}

func TestRequireFreeIPACapabilities_UserAuthTypesGated(t *testing.T) {
	runner := &capabilityAwareFakeRunner{capabilityResult: `{"schema_version":1,"capabilities":{"user_auth_types":"unsupported"}}`}
	opts := ReconcileOptions{Inventory: "inv.yml", RosterFile: "roster.yaml", Runner: runner}
	plan := Plan{UserAuthTypes: []inventory.CompiledUserAuthType{{User: "alice", Allowed: []string{"otp"}}}}

	if err := requireFreeIPACapabilities(context.Background(), opts, plan); err == nil {
		t.Fatal("expected an error when user_auth_types capability is unsupported")
	}
}

// TestReconcileOnce_RefusesBeforeApplyWhenCapabilityUnknown is the
// end-to-end version: a roster with password_policies whose capability
// probe never produces a result must refuse before the main apply
// playbook is ever invoked.
func TestReconcileOnce_RefusesBeforeApplyWhenCapabilityUnknown(t *testing.T) {
	dir := t.TempDir()
	rosterPath := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(rosterPath, []byte(reconcileTestRosterWithPasswordPolicies), 0o600); err != nil {
		t.Fatalf("write roster: %v", err)
	}
	runner := &capabilityAwareFakeRunner{} // capability probe "runs" but produces nothing

	_, _, err := ReconcileOnce(context.Background(), ReconcileOptions{
		RosterFile: rosterPath, Inventory: "inv.yml", Runner: runner,
	})
	if err == nil {
		t.Fatal("expected ReconcileOnce to refuse when a capability-gated control's support is unknown")
	}
	if len(runner.calls) != 1 {
		t.Fatalf("expected the apply playbook to never be invoked once the capability gate refuses, got calls: %v", runner.calls)
	}
}
