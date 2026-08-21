package ansible

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func writeResultFile(t *testing.T, dir string, lines ...string) string {
	t.Helper()
	path := filepath.Join(dir, "result.jsonl")
	var content string
	for _, l := range lines {
		content += l + "\n"
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write result file: %v", err)
	}
	return path
}

func TestClassifyDeploymentOutcome_RawExitZeroAlwaysSucceeds(t *testing.T) {
	outcome := ClassifyDeploymentOutcome(0, "/does/not/exist.jsonl", nil)
	if !outcome.Success {
		t.Fatalf("outcome = %+v, want Success=true for exit code 0", outcome)
	}
	if len(outcome.DeferredHosts) != 0 {
		t.Fatalf("outcome = %+v, want no deferred hosts for exit code 0", outcome)
	}
}

func TestClassifyDeploymentOutcome_ToleratedOptionalUnreachableSucceeds(t *testing.T) {
	dir := t.TempDir()
	path := writeResultFile(t, dir,
		`{"event":"unreachable","host":"dev-vm-01","reason":"connection_refused"}`,
		`{"event":"stats","hosts":{"ipa-1":{"ok":5,"changed":1,"failures":0,"unreachable":0,"skipped":0,"rescued":0,"ignored":0},"dev-vm-01":{"ok":0,"changed":0,"failures":0,"unreachable":1,"skipped":0,"rescued":0,"ignored":0}}}`,
	)
	outcome := ClassifyDeploymentOutcome(2, path, map[string]bool{"dev-vm-01": true})
	if !outcome.Success {
		t.Fatalf("outcome = %+v, want Success=true", outcome)
	}
	if !reflect.DeepEqual(outcome.DeferredHosts, []string{"dev-vm-01"}) {
		t.Fatalf("outcome.DeferredHosts = %v, want [dev-vm-01]", outcome.DeferredHosts)
	}
}

func TestClassifyDeploymentOutcome_RequiredHostUnreachableFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := writeResultFile(t, dir,
		`{"event":"unreachable","host":"ipa-1","reason":"connection_refused"}`,
		`{"event":"stats","hosts":{"ipa-1":{"unreachable":1}}}`,
	)
	// ipa-1 is not in optionalHosts, i.e. required.
	outcome := ClassifyDeploymentOutcome(2, path, map[string]bool{"dev-vm-01": true})
	if outcome.Success {
		t.Fatalf("outcome = %+v, want Success=false for an unreachable required host", outcome)
	}
}

func TestClassifyDeploymentOutcome_OptionalUnreachableWithFatalReasonFails(t *testing.T) {
	dir := t.TempDir()
	path := writeResultFile(t, dir,
		`{"event":"unreachable","host":"dev-vm-01","reason":"authentication_failed"}`,
		`{"event":"stats","hosts":{"dev-vm-01":{"unreachable":1}}}`,
	)
	outcome := ClassifyDeploymentOutcome(2, path, map[string]bool{"dev-vm-01": true})
	if outcome.Success {
		t.Fatalf("outcome = %+v, want Success=false for authentication_failed", outcome)
	}
}

func TestClassifyDeploymentOutcome_OptionalHostTaskFailureFails(t *testing.T) {
	dir := t.TempDir()
	path := writeResultFile(t, dir,
		`{"event":"failed","host":"dev-vm-01","task":"Install package"}`,
		`{"event":"stats","hosts":{"dev-vm-01":{"failures":1}}}`,
	)
	outcome := ClassifyDeploymentOutcome(2, path, map[string]bool{"dev-vm-01": true})
	if outcome.Success {
		t.Fatalf("outcome = %+v, want Success=false when a host has failures>0", outcome)
	}
}

func TestClassifyDeploymentOutcome_MissingStatsEventFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := writeResultFile(t, dir,
		`{"event":"unreachable","host":"dev-vm-01","reason":"connection_refused"}`,
	)
	outcome := ClassifyDeploymentOutcome(2, path, map[string]bool{"dev-vm-01": true})
	if outcome.Success {
		t.Fatalf("outcome = %+v, want Success=false with no stats event", outcome)
	}
}

func TestClassifyDeploymentOutcome_MalformedJSONFailsClosed(t *testing.T) {
	dir := t.TempDir()
	path := writeResultFile(t, dir,
		`{"event":"stats","hosts":{`, // truncated / invalid JSON
	)
	outcome := ClassifyDeploymentOutcome(2, path, map[string]bool{"dev-vm-01": true})
	if outcome.Success {
		t.Fatalf("outcome = %+v, want Success=false for malformed JSON", outcome)
	}
}

func TestClassifyDeploymentOutcome_MissingFileFailsClosed(t *testing.T) {
	outcome := ClassifyDeploymentOutcome(2, filepath.Join(t.TempDir(), "does-not-exist.jsonl"), map[string]bool{"dev-vm-01": true})
	if outcome.Success {
		t.Fatalf("outcome = %+v, want Success=false when the result file does not exist", outcome)
	}
}

func TestClassifyDeploymentOutcome_UnreachableHostWithNoRecordedReasonFailsClosed(t *testing.T) {
	dir := t.TempDir()
	// stats claims unreachable>0 for dev-vm-01 but no "unreachable" event
	// exists to prove which (tolerated or fatal) reason caused it.
	path := writeResultFile(t, dir,
		`{"event":"stats","hosts":{"dev-vm-01":{"unreachable":1}}}`,
	)
	outcome := ClassifyDeploymentOutcome(2, path, map[string]bool{"dev-vm-01": true})
	if outcome.Success {
		t.Fatalf("outcome = %+v, want Success=false with no recorded unreachable reason", outcome)
	}
}

func TestClassifyDeploymentOutcome_EmptyPathFailsClosed(t *testing.T) {
	outcome := ClassifyDeploymentOutcome(2, "", map[string]bool{"dev-vm-01": true})
	if outcome.Success {
		t.Fatalf("outcome = %+v, want Success=false for an empty result file path", outcome)
	}
}

func TestClassifyDeploymentOutcome_MultipleOptionalHostsAllToleratedSucceeds(t *testing.T) {
	dir := t.TempDir()
	path := writeResultFile(t, dir,
		`{"event":"unreachable","host":"dev-vm-01","reason":"connection_timeout"}`,
		`{"event":"unreachable","host":"dev-vm-03","reason":"no_route"}`,
		`{"event":"stats","hosts":{"ipa-1":{"ok":3},"dev-vm-01":{"unreachable":1},"dev-vm-02":{"ok":2},"dev-vm-03":{"unreachable":1}}}`,
	)
	outcome := ClassifyDeploymentOutcome(2, path, map[string]bool{"dev-vm-01": true, "dev-vm-02": true, "dev-vm-03": true})
	if !outcome.Success {
		t.Fatalf("outcome = %+v, want Success=true", outcome)
	}
	if !reflect.DeepEqual(outcome.DeferredHosts, []string{"dev-vm-01", "dev-vm-03"}) {
		t.Fatalf("outcome.DeferredHosts = %v, want [dev-vm-01 dev-vm-03]", outcome.DeferredHosts)
	}
}
