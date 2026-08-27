// breakglass_compile.go implements the request-validation half of
// spec.md §14's break-glass mechanism: checking a requested activation
// (duration/reason/ticket) against the grant definition's own activation
// policy (activation.max_duration/require_reason/require_ticket —
// already structurally checked by checkGrantActivation in
// roster_grants.go). FindGrant/CompileBreakglassActivation live in
// grant_compile.go alongside the other grant compilers; this file has no
// notion of *runtime* activation state itself — whether a breakglass
// grant is currently activated lives in internal/accessgrants (Activate/
// Deactivate/Status, breakglass.go), which calls
// ValidateBreakglassActivationRequest before ever compiling or applying
// anything, per spec.md §14's "does not rewrite the definition" rule.
package inventory

import (
	"fmt"
	"time"
)

// ValidateBreakglassActivationRequest checks a requested activation
// (duration/reason/ticket) against grant's own activation policy. grant
// MUST be a kind: breakglass entry that has already passed
// checkGrantActivation's structural validation (ValidateRosterV3) — this
// does not re-validate the policy's own shape, only the request against
// it.
func ValidateBreakglassActivationRequest(grant map[string]any, duration time.Duration, reason, ticket string) error {
	name := stringField(grant, "name")
	if kind := stringField(grant, "kind"); kind != grantKindBreakglass {
		return fmt.Errorf("grant %q is kind %q, not breakglass", name, kind)
	}
	if duration <= 0 {
		return fmt.Errorf("grant %q: duration must be positive", name)
	}

	activation := mapField(grant, "activation")
	maxDuration, err := ParseAccessDuration(stringField(activation, "max_duration"))
	if err != nil {
		return fmt.Errorf("grant %q: %w", name, err)
	}
	if duration > maxDuration {
		return fmt.Errorf("grant %q: requested duration exceeds activation.max_duration %s", name, stringField(activation, "max_duration"))
	}
	if boolFieldDefault(activation, "require_reason", true) && reason == "" {
		return fmt.Errorf("grant %q: reason is required to activate (activation.require_reason)", name)
	}
	if boolFieldDefault(activation, "require_ticket", true) && ticket == "" {
		return fmt.Errorf("grant %q: ticket is required to activate (activation.require_ticket)", name)
	}
	return nil
}
