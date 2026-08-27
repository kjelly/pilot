package freeipa

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
)

// extraVarFromArgs decodes the `-e @<file>` extra-vars JSON ProbeCapabilities
// wrote and returns the named key's value — a generic counterpart to
// probe_test.go's probeOutputPathFromArgs, which is hardcoded to the
// ever-applied probes' own extra-vars key.
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

// capabilityFakeRunner writes result (if non-empty) to whatever path the
// invocation's -e @<file> extra-vars named pilot_capability_output, then
// returns exitCode/runErr — mirroring probe_test.go's fakeRunner for the
// capability probe's own extra-vars key.
type capabilityFakeRunner struct {
	result   string
	exitCode int
	runErr   error
	calls    int
}

func (f *capabilityFakeRunner) Run(_ context.Context, args ...string) (*ansible.Result, error) {
	f.calls++
	if f.runErr != nil {
		return nil, f.runErr
	}
	if f.result != "" {
		outputPath := extraVarFromArgs(args, "pilot_capability_output")
		if outputPath == "" {
			panic("capabilityFakeRunner: could not find pilot_capability_output in extra-vars")
		}
		if err := os.WriteFile(outputPath, []byte(f.result), 0o600); err != nil {
			panic(err)
		}
	}
	return &ansible.Result{ExitCode: f.exitCode, Stderr: "boom"}, nil
}

func capabilityBaseOpts(r playbookRunner) CapabilityProbeOptions {
	return CapabilityProbeOptions{
		Inventory:  "inventory.yml",
		RosterFile: "roster.yaml",
		Runner:     r,
	}
}

func TestProbeCapabilities_AllStatesDistinguishable(t *testing.T) {
	r := &capabilityFakeRunner{result: `{
		"schema_version": 1,
		"capabilities": {
			"group_password_policy": "supported",
			"password_lockout_policy": "unsupported",
			"user_auth_types": "unknown",
			"authentication_indicator": "supported",
			"principal_expiration": "supported",
			"sudo_not_before_after": "unknown"
		}
	}`}
	caps, err := ProbeCapabilities(context.Background(), capabilityBaseOpts(r))
	if err != nil {
		t.Fatalf("ProbeCapabilities() error = %v", err)
	}
	if caps.GroupPasswordPolicy != CapabilitySupported {
		t.Errorf("GroupPasswordPolicy = %v, want supported", caps.GroupPasswordPolicy)
	}
	if caps.PasswordLockoutPolicy != CapabilityUnsupported {
		t.Errorf("PasswordLockoutPolicy = %v, want unsupported", caps.PasswordLockoutPolicy)
	}
	if caps.UserAuthTypes != CapabilityUnknown {
		t.Errorf("UserAuthTypes = %v, want unknown", caps.UserAuthTypes)
	}
	if caps.Get(CapAuthenticationIndicator) != CapabilitySupported {
		t.Errorf("Get(CapAuthenticationIndicator) = %v, want supported", caps.Get(CapAuthenticationIndicator))
	}
}

func TestProbeCapabilities_UnknownDueToRunFailure(t *testing.T) {
	r := &capabilityFakeRunner{runErr: errors.New("ansible-playbook not found")}
	caps, err := ProbeCapabilities(context.Background(), capabilityBaseOpts(r))
	if err == nil {
		t.Fatal("ProbeCapabilities() error = nil, want non-nil")
	}
	for _, name := range []string{
		CapGroupPasswordPolicy, CapPasswordLockoutPolicy, CapUserAuthTypes,
		CapAuthenticationIndicator, CapPrincipalExpiration, CapSudoNotBeforeAfter,
	} {
		if got := caps.Get(name); got != CapabilityUnknown {
			t.Errorf("Get(%q) = %v, want unknown on run failure", name, got)
		}
	}
}

func TestProbeCapabilities_UnknownDueToNonZeroExit(t *testing.T) {
	r := &capabilityFakeRunner{exitCode: 1}
	caps, err := ProbeCapabilities(context.Background(), capabilityBaseOpts(r))
	if err == nil {
		t.Fatal("ProbeCapabilities() error = nil, want non-nil")
	}
	if caps.Get(CapGroupPasswordPolicy) != CapabilityUnknown {
		t.Errorf("Get(CapGroupPasswordPolicy) = %v, want unknown on non-zero exit", caps.Get(CapGroupPasswordPolicy))
	}
}

func TestProbeCapabilities_MalformedResultNeverFabricates(t *testing.T) {
	r := &capabilityFakeRunner{result: `{not json`}
	caps, err := ProbeCapabilities(context.Background(), capabilityBaseOpts(r))
	if err == nil {
		t.Fatal("ProbeCapabilities() error = nil, want non-nil for malformed JSON")
	}
	if caps.Get(CapUserAuthTypes) != CapabilityUnknown {
		t.Errorf("Get(CapUserAuthTypes) = %v, want unknown for malformed result", caps.Get(CapUserAuthTypes))
	}
}

func TestProbeCapabilities_WrongSchemaVersionFailsClosed(t *testing.T) {
	r := &capabilityFakeRunner{result: `{"schema_version": 2, "capabilities": {"group_password_policy": "supported"}}`}
	caps, err := ProbeCapabilities(context.Background(), capabilityBaseOpts(r))
	if err == nil {
		t.Fatal("ProbeCapabilities() error = nil, want non-nil for unsupported schema_version")
	}
	if caps.Get(CapGroupPasswordPolicy) != CapabilityUnknown {
		t.Errorf("Get(CapGroupPasswordPolicy) = %v, want unknown, not the fabricated 'supported' from the wrong-schema payload", caps.Get(CapGroupPasswordPolicy))
	}
}

func TestProbeCapabilities_GarbageStateValueFailsClosed(t *testing.T) {
	r := &capabilityFakeRunner{result: `{"schema_version": 1, "capabilities": {"group_password_policy": "definitely-fine"}}`}
	caps, err := ProbeCapabilities(context.Background(), capabilityBaseOpts(r))
	if err != nil {
		t.Fatalf("ProbeCapabilities() error = %v", err)
	}
	if caps.Get(CapGroupPasswordPolicy) != CapabilityUnknown {
		t.Errorf("Get(CapGroupPasswordPolicy) = %v, want unknown for an unrecognized state string", caps.Get(CapGroupPasswordPolicy))
	}
}

func TestFreeIPACapabilities_Get_UnrecognizedNameIsUnknown(t *testing.T) {
	caps := FreeIPACapabilities{GroupPasswordPolicy: CapabilitySupported}
	if got := caps.Get("not-a-real-capability"); got != CapabilityUnknown {
		t.Errorf("Get(typo) = %v, want unknown", got)
	}
}

func TestRequireSupported(t *testing.T) {
	caps := FreeIPACapabilities{
		GroupPasswordPolicy: CapabilitySupported,
		UserAuthTypes:       CapabilityUnsupported,
		SudoNotBeforeAfter:  CapabilityUnknown,
	}
	if err := RequireSupported(caps, CapGroupPasswordPolicy); err != nil {
		t.Errorf("RequireSupported(supported) error = %v, want nil", err)
	}
	if err := RequireSupported(caps, CapUserAuthTypes); err == nil {
		t.Error("RequireSupported(unsupported) error = nil, want non-nil")
	}
	if err := RequireSupported(caps, CapSudoNotBeforeAfter); err == nil {
		t.Error("RequireSupported(unknown) error = nil, want non-nil — unknown must fail closed exactly like unsupported")
	}
}

func TestCapabilityCache_ProbesAtMostOnce(t *testing.T) {
	r := &capabilityFakeRunner{result: `{"schema_version": 1, "capabilities": {"group_password_policy": "supported"}}`}
	cache := &CapabilityCache{}
	opts := capabilityBaseOpts(r)

	for i := 0; i < 5; i++ {
		caps, err := cache.Get(context.Background(), opts)
		if err != nil {
			t.Fatalf("Get() call %d error = %v", i, err)
		}
		if caps.GroupPasswordPolicy != CapabilitySupported {
			t.Fatalf("Get() call %d GroupPasswordPolicy = %v, want supported", i, caps.GroupPasswordPolicy)
		}
	}
	if r.calls != 1 {
		t.Errorf("underlying runner invoked %d times, want exactly 1 (per-run cache)", r.calls)
	}
}

func TestCapabilityCache_MemoizesError(t *testing.T) {
	r := &capabilityFakeRunner{runErr: errors.New("boom")}
	cache := &CapabilityCache{}
	opts := capabilityBaseOpts(r)

	_, err1 := cache.Get(context.Background(), opts)
	_, err2 := cache.Get(context.Background(), opts)
	if err1 == nil || err2 == nil {
		t.Fatalf("Get() errors = %v, %v, want both non-nil", err1, err2)
	}
	if r.calls != 1 {
		t.Errorf("underlying runner invoked %d times, want exactly 1 even on error", r.calls)
	}
}
