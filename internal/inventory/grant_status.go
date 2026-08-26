package inventory

import (
	"fmt"
	"time"
)

// GrantStatus is one grants[] entry's current lifecycle snapshot — the
// shape `pilot access status` reports, including spec.md §9's
// next_transition_at, without touching FreeIPA at all.
type GrantStatus struct {
	Name      string
	Kind      string
	State     string // the grant's own top-level state: present|absent
	Lifecycle GrantLifecycleState
	// NextTransition is nil for a kind that carries no validity window
	// (breakglass — see §6.3/§8) as well as once a temporary_grant/
	// sudo_grant has expired or is absent.
	NextTransition *time.Time
}

// EvaluateGrantStatuses reports a GrantStatus for every grants[] entry in
// root, evaluated against the injected clock now (§8). kind: breakglass
// entries report Lifecycle == "" (the zero GrantLifecycleState) — a
// breakglass definition never has a validity window; its actual
// currently-granting-or-not state is separate runtime activation state
// (§14, Phase 3), not something this reports.
func EvaluateGrantStatuses(root map[string]any, now time.Time) ([]GrantStatus, error) {
	var out []GrantStatus
	for _, raw := range listField(root, "grants") {
		grant := asMap(raw)
		status := GrantStatus{
			Name:  stringField(grant, "name"),
			Kind:  stringField(grant, "kind"),
			State: stateOrDefault(grant, "present"),
		}
		if status.Kind == grantKindTemporary || status.Kind == grantKindSudo {
			var validity GrantValidity
			if status.State != "absent" {
				var err error
				validity, err = ParseGrantValidity(mapField(grant, "validity"))
				if err != nil {
					return nil, fmt.Errorf("grant %q: %w", status.Name, err)
				}
			}
			status.Lifecycle = EvaluateGrantLifecycle(status.State, validity, now)
			status.NextTransition = NextGrantTransition(status.State, validity, now)
		}
		out = append(out, status)
	}
	return out, nil
}

// EvaluateGrantStatusesFile is EvaluateGrantStatuses' file-reading
// counterpart, mirroring RosterUserNames' read/parse/dispatch shape
// (roster.go).
func EvaluateGrantStatusesFile(path string, now time.Time) ([]GrantStatus, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return EvaluateGrantStatuses(root, now)
}
