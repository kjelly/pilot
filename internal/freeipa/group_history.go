package freeipa

import (
	"context"
	"fmt"
)

// groupEverAppliedPlaybook is playbooks/check/freeipa-identity-group-ever-applied.yml.
const groupEverAppliedPlaybook = "playbooks/check/freeipa-identity-group-ever-applied.yml"

// GroupHistoryState is the freeipa_state value a group probe reports —
// see playbooks/check/freeipa-identity-group-ever-applied.yml's output
// contract (spec.md §10.1). FreeIPA has no preserved-group lifecycle
// equivalent to preserved users, so "ever applied" is proven by the
// union of the actual group existing OR a valid deterministic history
// marker existing.
type GroupHistoryState string

const (
	GroupHistoryActiveWithMarker    GroupHistoryState = "active_with_marker"
	GroupHistoryActiveWithoutMarker GroupHistoryState = "active_without_marker"
	GroupHistoryMarkerOnly          GroupHistoryState = "historical_marker"
	GroupHistoryNotFound            GroupHistoryState = "not_found"
)

// GroupHistoryProbe is the parsed, validated result of ProbeGroupHistory.
type GroupHistoryProbe struct {
	SchemaVersion int               `json:"schema_version"`
	Kind          string            `json:"kind"`
	Name          string            `json:"name"`
	EverApplied   bool              `json:"ever_applied"`
	FreeIPAState  GroupHistoryState `json:"freeipa_state"`
	HistoryMarker string            `json:"history_marker"`
}

// ProbeGroupHistory is ProbeUserHistory's group counterpart: it runs
// playbooks/check/freeipa-identity-group-ever-applied.yml against name
// and returns its parsed, validated result — rejecting every impossible
// ever_applied/freeipa_state combination spec.md §12 lists, plus a
// missing history_marker on any state other than not_found.
func ProbeGroupHistory(ctx context.Context, name string, opts ProbeOptions) (GroupHistoryProbe, error) {
	var probe GroupHistoryProbe
	if err := runEverAppliedProbe(ctx, groupEverAppliedPlaybook, "group", name, opts, &probe); err != nil {
		return GroupHistoryProbe{}, err
	}
	if probe.SchemaVersion != 1 {
		return GroupHistoryProbe{}, fmt.Errorf("%w: unsupported probe schema_version %d", ErrFreeIPAHistoryUnknown, probe.SchemaVersion)
	}
	if probe.Kind != "group" {
		return GroupHistoryProbe{}, fmt.Errorf("%w: probe result kind %q, want \"group\"", ErrFreeIPAHistoryUnknown, probe.Kind)
	}
	if probe.Name != name {
		return GroupHistoryProbe{}, fmt.Errorf("%w: probe result name %q, want %q", ErrFreeIPAHistoryUnknown, probe.Name, name)
	}
	switch probe.FreeIPAState {
	case GroupHistoryActiveWithMarker, GroupHistoryActiveWithoutMarker, GroupHistoryMarkerOnly, GroupHistoryNotFound:
	default:
		return GroupHistoryProbe{}, fmt.Errorf("%w: unrecognized freeipa_state %q", ErrFreeIPAHistoryUnknown, probe.FreeIPAState)
	}
	wantEverApplied := probe.FreeIPAState != GroupHistoryNotFound
	if probe.EverApplied != wantEverApplied {
		return GroupHistoryProbe{}, fmt.Errorf("%w: freeipa_state=%q is inconsistent with ever_applied=%t", ErrFreeIPAHistoryUnknown, probe.FreeIPAState, probe.EverApplied)
	}
	if wantEverApplied && probe.HistoryMarker == "" {
		return GroupHistoryProbe{}, fmt.Errorf("%w: freeipa_state=%q requires a non-empty history_marker", ErrFreeIPAHistoryUnknown, probe.FreeIPAState)
	}
	return probe, nil
}
