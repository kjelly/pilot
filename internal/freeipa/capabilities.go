// capabilities.go implements spec.md v3.2 §13's read-only FreeIPA
// capability probing: before any v3.2 feature configures a native
// FreeIPA/Kerberos control, it asks whether the live target actually
// supports that control. Probes never mutate FreeIPA — the check playbook
// they run (playbooks/check/freeipa-capability-probe.yml) is `ipa
// *-show`/`ipa help *` reads only — and report one of
// CapabilitySupported/CapabilityUnsupported/CapabilityUnknown per control.
// A probe failure (ansible error, non-zero exit, missing/malformed
// result) never fabricates supported/unsupported: every control comes
// back CapabilityUnknown alongside a non-nil error.
//
// Callers MUST fail closed on CapabilityUnknown exactly like a confirmed
// CapabilityUnsupported (spec.md §13, §21.1) — RequireSupported below is
// the shared gate later phases use to do that instead of re-deriving the
// same fail-closed check per call site.
package freeipa

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/kjelly/pilot/internal/ansible"
)

// capabilityProbePlaybook is playbooks/check/freeipa-capability-probe.yml,
// referenced relative to the pilot repo root (same convention probe.go's
// userEverAppliedPlaybook/groupEverAppliedPlaybook use).
const capabilityProbePlaybook = "playbooks/check/freeipa-capability-probe.yml"

// CapabilityState is one control's probed support state.
type CapabilityState string

const (
	CapabilitySupported   CapabilityState = "supported"
	CapabilityUnsupported CapabilityState = "unsupported"
	CapabilityUnknown     CapabilityState = "unknown"
)

// Capability names — the map keys the check playbook's JSON result and
// FreeIPACapabilities' Get/set both key off. Kept as named constants so a
// typo in a call site is a compile error, not a silent always-unknown
// lookup.
const (
	CapGroupPasswordPolicy     = "group_password_policy"
	CapPasswordLockoutPolicy   = "password_lockout_policy"
	CapUserAuthTypes           = "user_auth_types"
	CapAuthenticationIndicator = "authentication_indicator"
	CapPrincipalExpiration     = "principal_expiration"
	CapSudoNotBeforeAfter      = "sudo_not_before_after"
)

// FreeIPACapabilities is the full set of controls v3.2 depends on,
// probed at once per spec.md §13's capability matrix (§6).
type FreeIPACapabilities struct {
	GroupPasswordPolicy     CapabilityState `json:"group_password_policy"`
	PasswordLockoutPolicy   CapabilityState `json:"password_lockout_policy"`
	UserAuthTypes           CapabilityState `json:"user_auth_types"`
	AuthenticationIndicator CapabilityState `json:"authentication_indicator"`
	PrincipalExpiration     CapabilityState `json:"principal_expiration"`
	SudoNotBeforeAfter      CapabilityState `json:"sudo_not_before_after"`
}

// unknownCapabilities is every control reported CapabilityUnknown — the
// safe return value for any probe failure path.
func unknownCapabilities() FreeIPACapabilities {
	return FreeIPACapabilities{
		GroupPasswordPolicy:     CapabilityUnknown,
		PasswordLockoutPolicy:   CapabilityUnknown,
		UserAuthTypes:           CapabilityUnknown,
		AuthenticationIndicator: CapabilityUnknown,
		PrincipalExpiration:     CapabilityUnknown,
		SudoNotBeforeAfter:      CapabilityUnknown,
	}
}

// Get returns the state for a named control (one of the Cap* constants).
// An unrecognized name returns CapabilityUnknown — the same fail-closed
// answer a genuinely-unprobed control gets, so a typo'd capability name at
// a call site degrades safely instead of panicking or reporting a false
// CapabilitySupported.
func (c FreeIPACapabilities) Get(name string) CapabilityState {
	switch name {
	case CapGroupPasswordPolicy:
		return c.GroupPasswordPolicy
	case CapPasswordLockoutPolicy:
		return c.PasswordLockoutPolicy
	case CapUserAuthTypes:
		return c.UserAuthTypes
	case CapAuthenticationIndicator:
		return c.AuthenticationIndicator
	case CapPrincipalExpiration:
		return c.PrincipalExpiration
	case CapSudoNotBeforeAfter:
		return c.SudoNotBeforeAfter
	default:
		return CapabilityUnknown
	}
}

// set writes state into the field named name, ignoring unrecognized names
// (a forward-compatible probe result naming a control this Go build
// doesn't know about yet must not error the whole probe out).
func (c *FreeIPACapabilities) set(name string, state CapabilityState) {
	switch state {
	case CapabilitySupported, CapabilityUnsupported, CapabilityUnknown:
	default:
		// A probe result carrying a value outside the three known states
		// is itself untrustworthy — fail closed rather than propagate an
		// unrecognized string a caller's switch might mis-handle.
		state = CapabilityUnknown
	}
	switch name {
	case CapGroupPasswordPolicy:
		c.GroupPasswordPolicy = state
	case CapPasswordLockoutPolicy:
		c.PasswordLockoutPolicy = state
	case CapUserAuthTypes:
		c.UserAuthTypes = state
	case CapAuthenticationIndicator:
		c.AuthenticationIndicator = state
	case CapPrincipalExpiration:
		c.PrincipalExpiration = state
	case CapSudoNotBeforeAfter:
		c.SudoNotBeforeAfter = state
	}
}

// RequireSupported returns nil only when caps reports name as
// CapabilitySupported. CapabilityUnsupported and CapabilityUnknown both
// return an error — spec.md §13/§21.1's fail-closed requirement: a native
// control whose capability state is unknown must be refused exactly like
// one confirmed unsupported, never silently skipped.
func RequireSupported(caps FreeIPACapabilities, name string) error {
	switch caps.Get(name) {
	case CapabilitySupported:
		return nil
	case CapabilityUnsupported:
		return fmt.Errorf("freeipa: capability %q is not supported by this FreeIPA target", name)
	default:
		return fmt.Errorf("freeipa: capability %q state is unknown; refusing to configure it without confirmed support", name)
	}
}

// capabilityProbeResult is playbooks/check/freeipa-capability-probe.yml's
// schema_version 1 JSON output contract.
type capabilityProbeResult struct {
	SchemaVersion int                        `json:"schema_version"`
	Capabilities  map[string]CapabilityState `json:"capabilities"`
}

// CapabilityProbeOptions configures a single ProbeCapabilities run.
type CapabilityProbeOptions struct {
	// Inventory and RosterFile are required.
	Inventory  string
	RosterFile string

	// VaultPasswordFile is required when RosterFile is ansible-vault
	// encrypted.
	VaultPasswordFile string

	// TargetGroup overrides the probe playbook's default host-targeting
	// group ("freeipa-server").
	TargetGroup string

	// Runner overrides the ansible.Runner used to execute the probe
	// playbook. nil selects a production ansible.NewRunner() — tests
	// inject a fake here instead of talking to a real FreeIPA server.
	Runner playbookRunner
}

func (o CapabilityProbeOptions) runner() playbookRunner {
	if o.Runner != nil {
		return o.Runner
	}
	return ansible.NewRunner()
}

// ProbeCapabilities runs playbooks/check/freeipa-capability-probe.yml and
// returns its parsed result. Every failure path (ansible didn't run,
// non-zero exit, unreadable/malformed/wrong-schema result) returns
// unknownCapabilities() alongside a non-nil error — never a partially
// fabricated supported/unsupported guess.
func ProbeCapabilities(ctx context.Context, opts CapabilityProbeOptions) (FreeIPACapabilities, error) {
	unknown := unknownCapabilities()

	if opts.Inventory == "" {
		return unknown, fmt.Errorf("freeipa: inventory is required")
	}
	if opts.RosterFile == "" {
		return unknown, fmt.Errorf("freeipa: roster file is required")
	}

	outputFile, err := os.CreateTemp("", "pilot-freeipa-capability-*.json")
	if err != nil {
		return unknown, fmt.Errorf("freeipa: create capability probe output file: %w", err)
	}
	outputPath := outputFile.Name()
	_ = outputFile.Close()
	defer os.Remove(outputPath)

	extraVars := map[string]string{
		"freeipa_roster_file":     opts.RosterFile,
		"pilot_capability_output": outputPath,
	}
	if opts.TargetGroup != "" {
		extraVars["target_group"] = opts.TargetGroup
	}
	// Extra-vars go through a JSON @file, never a bare `-e k=v` command
	// line — see probe.go's runEverAppliedProbe for why (a value
	// containing whitespace silently truncates under `-e k=v k2=v2`).
	extraVarsFile, err := os.CreateTemp("", "pilot-freeipa-capability-vars-*.json")
	if err != nil {
		return unknown, fmt.Errorf("freeipa: create capability probe extra-vars file: %w", err)
	}
	extraVarsPath := extraVarsFile.Name()
	defer os.Remove(extraVarsPath)
	if err := json.NewEncoder(extraVarsFile).Encode(extraVars); err != nil {
		_ = extraVarsFile.Close()
		return unknown, fmt.Errorf("freeipa: encode capability probe extra-vars: %w", err)
	}
	if err := extraVarsFile.Close(); err != nil {
		return unknown, fmt.Errorf("freeipa: write capability probe extra-vars: %w", err)
	}

	args := []string{capabilityProbePlaybook, "-i", opts.Inventory, "-e", "@" + extraVarsPath}
	if opts.VaultPasswordFile != "" {
		args = append(args, "--vault-password-file", opts.VaultPasswordFile)
	}

	result, err := opts.runner().Run(ctx, args...)
	if err != nil {
		return unknown, fmt.Errorf("freeipa: capability probe: ansible-playbook did not run: %w", err)
	}
	if result.ExitCode != 0 {
		detail := strings.TrimSpace(result.Stderr)
		if detail == "" {
			detail = strings.TrimSpace(result.Stdout)
		}
		return unknown, fmt.Errorf("freeipa: capability probe playbook %s exited %d: %s", filepath.Base(capabilityProbePlaybook), result.ExitCode, detail)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		return unknown, fmt.Errorf("freeipa: read capability probe result: %w", err)
	}
	var parsed capabilityProbeResult
	if err := json.Unmarshal(data, &parsed); err != nil {
		return unknown, fmt.Errorf("freeipa: malformed capability probe result JSON: %w", err)
	}
	if parsed.SchemaVersion != 1 {
		return unknown, fmt.Errorf("freeipa: unsupported capability probe schema_version %d", parsed.SchemaVersion)
	}

	out := unknownCapabilities()
	for name, state := range parsed.Capabilities {
		out.set(name, state)
	}
	return out, nil
}

// CapabilityCache probes FreeIPA capabilities at most once no matter how
// many times or from how many goroutines Get is called — spec.md §13's
// "cached per explicit command run": a single `pilot identity ...`
// invocation probes once and reuses the result across every control it
// touches. sync.Once-backed (not a bare bool) because this repo's MCP
// server dispatches concurrent tool calls with no recover() of its own —
// a data race here would be exactly the class of bug already fixed once
// in cmd/pilot/cmd's addRecoveredTool wiring. Not safe for reuse across
// separate command invocations — construct a new CapabilityCache per run.
type CapabilityCache struct {
	once   sync.Once
	result FreeIPACapabilities
	err    error
}

// Get returns the cached probe result, running ProbeCapabilities on the
// first call and memoizing both the result and the error for every
// subsequent call.
func (c *CapabilityCache) Get(ctx context.Context, opts CapabilityProbeOptions) (FreeIPACapabilities, error) {
	c.once.Do(func() {
		c.result, c.err = ProbeCapabilities(ctx, opts)
	})
	return c.result, c.err
}
