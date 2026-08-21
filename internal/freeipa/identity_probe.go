package freeipa

import (
	"context"
	"fmt"
)

// userEverAppliedPlaybook is playbooks/check/freeipa-identity-user-ever-applied.yml,
// referenced as a path relative to the pilot repo root — the same
// convention deployCatalog's Playbook field uses.
const userEverAppliedPlaybook = "playbooks/check/freeipa-identity-user-ever-applied.yml"

// UserHistoryState is the freeipa_state value a user probe reports —
// see playbooks/check/freeipa-identity-user-ever-applied.yml's output
// contract (spec.md §8.2).
type UserHistoryState string

const (
	UserHistoryActiveOrPreserved UserHistoryState = "active_or_preserved"
	UserHistoryNotFound          UserHistoryState = "not_found"
)

// UserHistoryProbe is the parsed, validated result of ProbeUserHistory.
type UserHistoryProbe struct {
	SchemaVersion int              `json:"schema_version"`
	Kind          string           `json:"kind"`
	Name          string           `json:"name"`
	EverApplied   bool             `json:"ever_applied"`
	FreeIPAState  UserHistoryState `json:"freeipa_state"`
}

// ProbeUserHistory runs playbooks/check/freeipa-identity-user-ever-applied.yml
// against name and returns its parsed, validated result — never
// interpreting an Ansible failure, unrecognized schema_version, or a
// self-inconsistent ever_applied/freeipa_state pair as "not found"
// (spec.md §12).
func ProbeUserHistory(ctx context.Context, name string, opts ProbeOptions) (UserHistoryProbe, error) {
	var probe UserHistoryProbe
	if err := runEverAppliedProbe(ctx, userEverAppliedPlaybook, "user", name, opts, &probe); err != nil {
		return UserHistoryProbe{}, err
	}
	if probe.SchemaVersion != 1 {
		return UserHistoryProbe{}, fmt.Errorf("%w: unsupported probe schema_version %d", ErrFreeIPAHistoryUnknown, probe.SchemaVersion)
	}
	if probe.Kind != "user" {
		return UserHistoryProbe{}, fmt.Errorf("%w: probe result kind %q, want \"user\"", ErrFreeIPAHistoryUnknown, probe.Kind)
	}
	if probe.Name != name {
		return UserHistoryProbe{}, fmt.Errorf("%w: probe result name %q, want %q", ErrFreeIPAHistoryUnknown, probe.Name, name)
	}
	switch probe.FreeIPAState {
	case UserHistoryActiveOrPreserved:
		if !probe.EverApplied {
			return UserHistoryProbe{}, fmt.Errorf("%w: freeipa_state=%q is inconsistent with ever_applied=false", ErrFreeIPAHistoryUnknown, probe.FreeIPAState)
		}
	case UserHistoryNotFound:
		if probe.EverApplied {
			return UserHistoryProbe{}, fmt.Errorf("%w: freeipa_state=%q is inconsistent with ever_applied=true", ErrFreeIPAHistoryUnknown, probe.FreeIPAState)
		}
	default:
		return UserHistoryProbe{}, fmt.Errorf("%w: unrecognized freeipa_state %q", ErrFreeIPAHistoryUnknown, probe.FreeIPAState)
	}
	return probe, nil
}
