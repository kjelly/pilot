package freeipa

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
)

// fakeRunner writes result (if non-empty) to whatever path the invocation's
// -e @<file> extra-vars named pilot_identity_probe_output, then returns
// exitCode/runErr — simulating an ansible-playbook invocation without a
// real FreeIPA server or ansible-playbook binary.
type fakeRunner struct {
	result   string // raw JSON to write to the probe output path; "" writes nothing
	exitCode int
	runErr   error
	lastArgs []string
}

func (f *fakeRunner) Run(_ context.Context, args ...string) (*ansible.Result, error) {
	f.lastArgs = args
	if f.runErr != nil {
		return nil, f.runErr
	}
	if f.result != "" {
		outputPath := probeOutputPathFromArgs(args)
		if outputPath == "" {
			panic("fakeRunner: could not find pilot_identity_probe_output in extra-vars")
		}
		if err := os.WriteFile(outputPath, []byte(f.result), 0o600); err != nil {
			panic(err)
		}
	}
	return &ansible.Result{ExitCode: f.exitCode, Stderr: "boom"}, nil
}

// probeOutputPathFromArgs decodes the `-e @<file>` extra-vars JSON runEverAppliedProbe
// wrote and returns its pilot_identity_probe_output value.
func probeOutputPathFromArgs(args []string) string {
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
			return vars["pilot_identity_probe_output"]
		}
	}
	return ""
}

func baseOpts(t *testing.T, r playbookRunner) ProbeOptions {
	t.Helper()
	return ProbeOptions{
		Inventory:  "inventory.yml",
		RosterFile: "roster.yaml",
		Runner:     r,
	}
}

func TestProbeUserHistory_ActiveOrPreserved(t *testing.T) {
	r := &fakeRunner{result: `{"schema_version":1,"kind":"user","name":"alice","ever_applied":true,"freeipa_state":"active_or_preserved"}`}
	probe, err := ProbeUserHistory(context.Background(), "alice", baseOpts(t, r))
	if err != nil {
		t.Fatalf("ProbeUserHistory() error = %v", err)
	}
	if !probe.EverApplied || probe.FreeIPAState != UserHistoryActiveOrPreserved {
		t.Fatalf("ProbeUserHistory() = %+v", probe)
	}
}

func TestProbeUserHistory_NotFound(t *testing.T) {
	r := &fakeRunner{result: `{"schema_version":1,"kind":"user","name":"typo-user","ever_applied":false,"freeipa_state":"not_found"}`}
	probe, err := ProbeUserHistory(context.Background(), "typo-user", baseOpts(t, r))
	if err != nil {
		t.Fatalf("ProbeUserHistory() error = %v", err)
	}
	if probe.EverApplied || probe.FreeIPAState != UserHistoryNotFound {
		t.Fatalf("ProbeUserHistory() = %+v", probe)
	}
}

func TestProbeUserHistory_MismatchedNameFailsClosed(t *testing.T) {
	r := &fakeRunner{result: `{"schema_version":1,"kind":"user","name":"bob","ever_applied":false,"freeipa_state":"not_found"}`}
	if _, err := ProbeUserHistory(context.Background(), "alice", baseOpts(t, r)); !errors.Is(err, ErrFreeIPAHistoryUnknown) {
		t.Fatalf("ProbeUserHistory() error = %v, want ErrFreeIPAHistoryUnknown", err)
	}
}

func TestProbeUserHistory_WrongKindFailsClosed(t *testing.T) {
	r := &fakeRunner{result: `{"schema_version":1,"kind":"group","name":"alice","ever_applied":false,"freeipa_state":"not_found"}`}
	if _, err := ProbeUserHistory(context.Background(), "alice", baseOpts(t, r)); !errors.Is(err, ErrFreeIPAHistoryUnknown) {
		t.Fatalf("ProbeUserHistory() error = %v, want ErrFreeIPAHistoryUnknown", err)
	}
}

func TestProbeUserHistory_UnsupportedSchemaVersionFailsClosed(t *testing.T) {
	r := &fakeRunner{result: `{"schema_version":2,"kind":"user","name":"alice","ever_applied":false,"freeipa_state":"not_found"}`}
	if _, err := ProbeUserHistory(context.Background(), "alice", baseOpts(t, r)); !errors.Is(err, ErrFreeIPAHistoryUnknown) {
		t.Fatalf("ProbeUserHistory() error = %v, want ErrFreeIPAHistoryUnknown", err)
	}
}

func TestProbeUserHistory_ImpossibleCombinationFailsClosed(t *testing.T) {
	r := &fakeRunner{result: `{"schema_version":1,"kind":"user","name":"alice","ever_applied":true,"freeipa_state":"not_found"}`}
	if _, err := ProbeUserHistory(context.Background(), "alice", baseOpts(t, r)); !errors.Is(err, ErrFreeIPAHistoryUnknown) {
		t.Fatalf("ProbeUserHistory() error = %v, want ErrFreeIPAHistoryUnknown", err)
	}
}

func TestProbeUserHistory_MalformedJSONFailsClosed(t *testing.T) {
	r := &fakeRunner{result: `{not json`}
	if _, err := ProbeUserHistory(context.Background(), "alice", baseOpts(t, r)); !errors.Is(err, ErrFreeIPAHistoryUnknown) {
		t.Fatalf("ProbeUserHistory() error = %v, want ErrFreeIPAHistoryUnknown", err)
	}
}

func TestProbeUserHistory_MissingResultFileFailsClosed(t *testing.T) {
	r := &fakeRunner{} // writes nothing
	if _, err := ProbeUserHistory(context.Background(), "alice", baseOpts(t, r)); !errors.Is(err, ErrFreeIPAHistoryUnknown) {
		t.Fatalf("ProbeUserHistory() error = %v, want ErrFreeIPAHistoryUnknown", err)
	}
}

func TestProbeUserHistory_AnsibleNonZeroExitFailsClosed(t *testing.T) {
	r := &fakeRunner{result: `{"schema_version":1,"kind":"user","name":"alice","ever_applied":false,"freeipa_state":"not_found"}`, exitCode: 2}
	if _, err := ProbeUserHistory(context.Background(), "alice", baseOpts(t, r)); !errors.Is(err, ErrFreeIPAHistoryUnknown) {
		t.Fatalf("ProbeUserHistory() error = %v, want ErrFreeIPAHistoryUnknown", err)
	}
}

func TestProbeUserHistory_AnsibleLaunchErrorFailsClosed(t *testing.T) {
	r := &fakeRunner{runErr: errors.New("ansible-playbook not found")}
	if _, err := ProbeUserHistory(context.Background(), "alice", baseOpts(t, r)); !errors.Is(err, ErrFreeIPAHistoryUnknown) {
		t.Fatalf("ProbeUserHistory() error = %v, want ErrFreeIPAHistoryUnknown", err)
	}
}

func TestProbeUserHistory_ExtraVarsPassedByFileNotBareKV(t *testing.T) {
	r := &fakeRunner{result: `{"schema_version":1,"kind":"user","name":"alice","ever_applied":false,"freeipa_state":"not_found"}`}
	opts := baseOpts(t, r)
	opts.RosterFile = "/path with spaces/roster.yaml"
	if _, err := ProbeUserHistory(context.Background(), "alice", opts); err != nil {
		t.Fatalf("ProbeUserHistory() error = %v", err)
	}
	for i, a := range r.lastArgs {
		if a == "-e" && i+1 < len(r.lastArgs) {
			if r.lastArgs[i+1][0] != '@' {
				t.Fatalf("extra-vars must be passed as -e @file.json, got -e %q", r.lastArgs[i+1])
			}
		}
	}
}

func TestProbeGroupHistory_ActiveWithMarker(t *testing.T) {
	r := &fakeRunner{result: `{"schema_version":1,"kind":"group","name":"team-platform","ever_applied":true,"freeipa_state":"active_with_marker","history_marker":"pilot-internal-history-g-abc"}`}
	probe, err := ProbeGroupHistory(context.Background(), "team-platform", baseOpts(t, r))
	if err != nil {
		t.Fatalf("ProbeGroupHistory() error = %v", err)
	}
	if !probe.EverApplied || probe.FreeIPAState != GroupHistoryActiveWithMarker || probe.HistoryMarker == "" {
		t.Fatalf("ProbeGroupHistory() = %+v", probe)
	}
}

func TestProbeGroupHistory_HistoricalMarkerAfterDeletion(t *testing.T) {
	r := &fakeRunner{result: `{"schema_version":1,"kind":"group","name":"team-deleted","ever_applied":true,"freeipa_state":"historical_marker","history_marker":"pilot-internal-history-g-abc"}`}
	probe, err := ProbeGroupHistory(context.Background(), "team-deleted", baseOpts(t, r))
	if err != nil {
		t.Fatalf("ProbeGroupHistory() error = %v", err)
	}
	if !probe.EverApplied || probe.FreeIPAState != GroupHistoryMarkerOnly {
		t.Fatalf("ProbeGroupHistory() = %+v", probe)
	}
}

func TestProbeGroupHistory_ActiveWithoutMarkerStillBlocks(t *testing.T) {
	r := &fakeRunner{result: `{"schema_version":1,"kind":"group","name":"team-drift","ever_applied":true,"freeipa_state":"active_without_marker","history_marker":"pilot-internal-history-g-abc"}`}
	probe, err := ProbeGroupHistory(context.Background(), "team-drift", baseOpts(t, r))
	if err != nil {
		t.Fatalf("ProbeGroupHistory() error = %v", err)
	}
	if !probe.EverApplied {
		t.Fatalf("ProbeGroupHistory() = %+v, want EverApplied=true", probe)
	}
}

func TestProbeGroupHistory_NotFound(t *testing.T) {
	r := &fakeRunner{result: `{"schema_version":1,"kind":"group","name":"team-never-applied","ever_applied":false,"freeipa_state":"not_found","history_marker":"pilot-internal-history-g-abc"}`}
	probe, err := ProbeGroupHistory(context.Background(), "team-never-applied", baseOpts(t, r))
	if err != nil {
		t.Fatalf("ProbeGroupHistory() error = %v", err)
	}
	if probe.EverApplied || probe.FreeIPAState != GroupHistoryNotFound {
		t.Fatalf("ProbeGroupHistory() = %+v", probe)
	}
}

func TestProbeGroupHistory_ImpossibleCombinationFailsClosed(t *testing.T) {
	r := &fakeRunner{result: `{"schema_version":1,"kind":"group","name":"team-x","ever_applied":false,"freeipa_state":"active_with_marker","history_marker":"pilot-internal-history-g-abc"}`}
	if _, err := ProbeGroupHistory(context.Background(), "team-x", baseOpts(t, r)); !errors.Is(err, ErrFreeIPAHistoryUnknown) {
		t.Fatalf("ProbeGroupHistory() error = %v, want ErrFreeIPAHistoryUnknown", err)
	}
}

func TestProbeGroupHistory_MissingMarkerFieldOnAppliedStateFailsClosed(t *testing.T) {
	r := &fakeRunner{result: `{"schema_version":1,"kind":"group","name":"team-x","ever_applied":true,"freeipa_state":"active_with_marker","history_marker":""}`}
	if _, err := ProbeGroupHistory(context.Background(), "team-x", baseOpts(t, r)); !errors.Is(err, ErrFreeIPAHistoryUnknown) {
		t.Fatalf("ProbeGroupHistory() error = %v, want ErrFreeIPAHistoryUnknown", err)
	}
}

func TestProbeGroupHistory_UnrecognizedStateFailsClosed(t *testing.T) {
	r := &fakeRunner{result: `{"schema_version":1,"kind":"group","name":"team-x","ever_applied":true,"freeipa_state":"something_else","history_marker":"x"}`}
	if _, err := ProbeGroupHistory(context.Background(), "team-x", baseOpts(t, r)); !errors.Is(err, ErrFreeIPAHistoryUnknown) {
		t.Fatalf("ProbeGroupHistory() error = %v, want ErrFreeIPAHistoryUnknown", err)
	}
}

func TestProbeUserHistory_RequiresInventoryAndRosterFile(t *testing.T) {
	r := &fakeRunner{result: `{"schema_version":1,"kind":"user","name":"alice","ever_applied":false,"freeipa_state":"not_found"}`}
	if _, err := ProbeUserHistory(context.Background(), "alice", ProbeOptions{Runner: r}); err == nil {
		t.Fatalf("expected an error when Inventory/RosterFile are missing")
	}
}
