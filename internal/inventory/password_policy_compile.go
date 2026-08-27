// password_policy_compile.go compiles the v3.2 Identity & Credential
// Hardening spec's (spec.md §7, Phase 2) `password_policies:` section
// into the exact integer units FreeIPA's `ipa pwpolicy-*` CLI expects.
//
// Unit-mapping caveat (documented per this repo's established practice —
// see freeipa-capability-probe.yml's own header note, and
// freeipa-access-drift-probe.yml's before it): the specific units below
// (days for max life, hours for min life, seconds for the three lockout
// fields) are FreeIPA's documented `ipa pwpolicy-mod` CLI convention, not
// something this delivery confirmed against a live FreeIPA target.
// Confirm on a vm-target before treating this compiler's output as
// authoritative for a real apply gate.
package inventory

import (
	"fmt"
	"time"
)

// CompiledPasswordPolicy is one password_policies[] entry, converted for
// playbooks/apply/freeipa-identity-apply.yml's `ipa pwpolicy-*` tasks.
// Every optional field compiles to a nil pointer when absent from the
// roster — the apply playbook must pass no corresponding --flag at all in
// that case (leave FreeIPA's existing value alone), never a zero value
// that could be confused with an explicit "set this to zero"
// (history_size: 0 is a legitimate roster value, distinct from "unset").
type CompiledPasswordPolicy struct {
	// Name is the roster password_policies[].name — an audit/reference
	// label only. FreeIPA's pwpolicy object has no separate name; it is
	// identified entirely by Group (ipa pwpolicy-add/mod/remove <group>).
	Name  string
	State string // present | absent
	Group string

	Priority                   *int
	MinLength                  *int
	HistorySize                *int
	MaxLifeDays                *int
	MinLifeHours               *int
	LockoutMaxFailures         *int
	LockoutFailureResetSeconds *int
	LockoutDurationSeconds     *int
}

// CompilePasswordPolicies compiles password_policies: into one
// CompiledPasswordPolicy per entry. Callers MUST have already run
// ValidateRosterV3 (checkPasswordPolicies) — this does not re-validate
// shape, and returns an error only if a duration that already passed
// ValidAccessDuration somehow fails to divide evenly into the target
// unit (a programmer error in the caller/validator disagreement, not a
// normal user-facing outcome for a roster that passed validation, since
// checkPasswordPolicies only confirms m/h/d grammar, not unit
// divisibility — see durationToWholeUnit).
func CompilePasswordPolicies(root map[string]any) ([]CompiledPasswordPolicy, error) {
	var out []CompiledPasswordPolicy
	for _, raw := range listField(root, "password_policies") {
		item := asMap(raw)
		state := stateOrDefault(item, "present")
		compiled := CompiledPasswordPolicy{
			Name:  stringField(item, "name"),
			State: state,
			Group: stringField(item, "group"),
		}

		if state == "present" {
			if n, ok := toInt(item["priority"]); ok {
				compiled.Priority = &n
			}
			if n, ok := toInt(item["min_length"]); ok {
				compiled.MinLength = &n
			}
			if n, ok := toInt(item["history_size"]); ok {
				compiled.HistorySize = &n
			}
			if v := stringField(item, "max_life"); v != "" {
				days, err := durationToWholeUnit(v, 24*time.Hour)
				if err != nil {
					return nil, fmt.Errorf("password_policy %q: max_life: %w", compiled.Name, err)
				}
				compiled.MaxLifeDays = &days
			}
			if v := stringField(item, "min_life"); v != "" {
				hours, err := durationToWholeUnit(v, time.Hour)
				if err != nil {
					return nil, fmt.Errorf("password_policy %q: min_life: %w", compiled.Name, err)
				}
				compiled.MinLifeHours = &hours
			}

			lockout := mapField(item, "lockout")
			if n, ok := toInt(lockout["max_failures"]); ok {
				compiled.LockoutMaxFailures = &n
			}
			if v := stringField(lockout, "failure_reset_interval"); v != "" {
				seconds, err := durationToWholeUnit(v, time.Second)
				if err != nil {
					return nil, fmt.Errorf("password_policy %q: lockout.failure_reset_interval: %w", compiled.Name, err)
				}
				compiled.LockoutFailureResetSeconds = &seconds
			}
			if v := stringField(lockout, "lockout_duration"); v != "" {
				seconds, err := durationToWholeUnit(v, time.Second)
				if err != nil {
					return nil, fmt.Errorf("password_policy %q: lockout.lockout_duration: %w", compiled.Name, err)
				}
				compiled.LockoutDurationSeconds = &seconds
			}
		}

		out = append(out, compiled)
	}
	return out, nil
}

// CompilePasswordPoliciesFile is CompilePasswordPolicies' file-reading
// counterpart, mirroring CompileAuthPoliciesFile's read/parse/dispatch
// shape.
func CompilePasswordPoliciesFile(path string) ([]CompiledPasswordPolicy, error) {
	root, err := readRosterAsMap(path)
	if err != nil {
		return nil, err
	}
	return CompilePasswordPolicies(root)
}

// durationToWholeUnit parses an access-duration string (spec.md's m/h/d
// grammar, ParseAccessDuration) and converts it to a whole-number count
// of unit, erroring if the duration is not an exact multiple of unit.
// Silently truncating — say, min_life: 90m to 1 hour — would apply a
// materially different policy than the roster author wrote, which
// fail-before-write (spec.md §21.1) treats as unacceptable.
func durationToWholeUnit(s string, unit time.Duration) (int, error) {
	d, err := ParseAccessDuration(s)
	if err != nil {
		return 0, err
	}
	if d%unit != 0 {
		return 0, fmt.Errorf("duration %q does not divide evenly into whole units of %s; FreeIPA requires an exact integer here", s, unit)
	}
	return int(d / unit), nil
}
