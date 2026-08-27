// capability_gate.go enforces spec.md §13/§21.1's fail-closed rule for
// every v3.2 control that requires a live FreeIPA capability before it
// may be applied: a control whose capability state comes back
// CapabilityUnknown must be refused exactly like one confirmed
// CapabilityUnsupported, never silently skipped. This is a separate,
// dedicated probe (internal/freeipa.ProbeCapabilities) from the apply
// playbook ReconcileOnce otherwise runs — it must happen BEFORE any
// mutation, so it cannot piggyback on the apply run itself.
package accessgrants

import (
	"context"
	"fmt"

	"github.com/kjelly/pilot/internal/freeipa"
)

// requireFreeIPACapabilities probes FreeIPA capabilities and enforces
// them for whatever capability-gated axes plan actually touches. The
// probe only runs when it is needed — a reconcile touching only grants/
// auth_policies/account_policies (none of which are capability-gated in
// this delivery) never pays for one.
func requireFreeIPACapabilities(ctx context.Context, opts ReconcileOptions, plan Plan) error {
	needsPasswordPolicy := false
	needsLockout := false
	for _, p := range plan.PasswordPolicies {
		if p.State != "present" {
			continue
		}
		needsPasswordPolicy = true
		if p.LockoutMaxFailures != nil || p.LockoutFailureResetSeconds != nil || p.LockoutDurationSeconds != nil {
			needsLockout = true
		}
	}
	needsUserAuthTypes := len(plan.UserAuthTypes) > 0

	if !needsPasswordPolicy && !needsUserAuthTypes {
		return nil
	}

	caps, err := freeipa.ProbeCapabilities(ctx, freeipa.CapabilityProbeOptions{
		Inventory:         opts.Inventory,
		RosterFile:        opts.RosterFile,
		VaultPasswordFile: opts.VaultPasswordFile,
		Runner:            opts.runner(),
	})
	if err != nil {
		return fmt.Errorf("accessgrants: capability probe failed, refusing to reconcile a capability-gated control: %w", err)
	}

	if needsPasswordPolicy {
		if err := freeipa.RequireSupported(caps, freeipa.CapGroupPasswordPolicy); err != nil {
			return fmt.Errorf("accessgrants: refusing to reconcile password_policies: %w", err)
		}
	}
	if needsLockout {
		if err := freeipa.RequireSupported(caps, freeipa.CapPasswordLockoutPolicy); err != nil {
			return fmt.Errorf("accessgrants: refusing to reconcile password_policies lockout fields: %w", err)
		}
	}
	if needsUserAuthTypes {
		if err := freeipa.RequireSupported(caps, freeipa.CapUserAuthTypes); err != nil {
			return fmt.Errorf("accessgrants: refusing to reconcile user authentication types: %w", err)
		}
	}
	return nil
}
