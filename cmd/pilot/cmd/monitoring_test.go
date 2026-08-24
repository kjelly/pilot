package cmd

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/monitoring"
)

// monCLIRun mirrors iepCLIRun (internal_endpoint_cli_test.go) — the
// established convention for exercising the real rootCmd/cobra wiring
// end-to-end rather than calling a RunE function directly.
func monCLIRun(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	rootCmd.SetArgs(args)
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	defer rootCmd.SetArgs(nil)
	err := rootCmd.Execute()
	return out.String(), err
}

// Every test below passes --dir explicitly on every single invocation and
// never relies on a flag being "left unset from a previous test" — pflag's
// Changed()/bound-variable state persists across repeated Execute() calls
// on the shared rootCmd within one test binary process (verified while
// writing this file; see targetFromFlags/profileFromFlags's own doc
// comments and their dedicated unit tests below, which exercise
// partial-update semantics WITHOUT going through cobra at all).

func TestMonitoringCLI_EndToEnd(t *testing.T) {
	dir := t.TempDir()

	out, err := monCLIRun(t, "monitoring", "target", "list", "--dir", dir)
	if err != nil {
		t.Fatalf("list (empty): %v, out=%s", err, out)
	}
	if !strings.Contains(out, "No external monitoring targets configured.") {
		t.Fatalf("expected empty-state message, got %q", out)
	}

	out, err = monCLIRun(t, "monitoring", "profile", "add", "--dir", dir, "--name", "storage-exporter", "--job-name", "storage", "--scheme", "https")
	if err != nil {
		t.Fatalf("profile add: %v, out=%s", err, out)
	}

	out, err = monCLIRun(t, "monitoring", "target", "add", "--dir", dir,
		"--name", "nas01", "--address", "10.0.0.20:9100", "--profile", "storage-exporter", "--site", "taipei", "--label", "owner=storage")
	if err != nil {
		t.Fatalf("target add: %v, out=%s", err, out)
	}

	out, err = monCLIRun(t, "monitoring", "target", "list", "--dir", dir)
	if err != nil || !strings.Contains(out, "nas01") || !strings.Contains(out, "enabled") {
		t.Fatalf("target list after add: err=%v out=%q", err, out)
	}

	if _, err := monCLIRun(t, "monitoring", "validate", "--dir", dir); err != nil {
		t.Fatalf("validate: expected OK, got %v", err)
	}

	// Unknown profile reference must be rejected and NOT persisted.
	out, err = monCLIRun(t, "monitoring", "target", "add", "--dir", dir, "--name", "bad", "--address", "10.0.0.1:9100", "--profile", "does-not-exist")
	if err == nil {
		t.Fatalf("expected target add with an unknown profile to fail, out=%q", out)
	}
	out, _ = monCLIRun(t, "monitoring", "target", "list", "--dir", dir)
	if strings.Contains(out, "bad") {
		t.Fatalf("rejected target must not be persisted, got %q", out)
	}

	if _, err := monCLIRun(t, "monitoring", "target", "disable", "nas01", "--dir", dir); err != nil {
		t.Fatalf("target disable: %v", err)
	}
	out, _ = monCLIRun(t, "monitoring", "target", "list", "--dir", dir)
	if !strings.Contains(out, "disabled") {
		t.Fatalf("expected nas01 to show disabled, got %q", out)
	}

	if _, err := monCLIRun(t, "monitoring", "target", "enable", "nas01", "--dir", dir); err != nil {
		t.Fatalf("target enable: %v", err)
	}
	out, _ = monCLIRun(t, "monitoring", "target", "list", "--dir", dir)
	if !strings.Contains(out, "enabled") || strings.Contains(out, "disabled") {
		t.Fatalf("expected nas01 to show enabled again, got %q", out)
	}

	// spec.md §50: a profile still referenced by a target cannot be removed.
	out, err = monCLIRun(t, "monitoring", "profile", "remove", "storage-exporter", "--dir", dir)
	if err == nil {
		t.Fatalf("expected profile remove to be refused while in use, out=%q", out)
	}

	if _, err := monCLIRun(t, "monitoring", "target", "remove", "nas01", "--dir", dir, "--yes"); err != nil {
		t.Fatalf("target remove --yes: %v", err)
	}
	out, _ = monCLIRun(t, "monitoring", "target", "list", "--dir", dir)
	if !strings.Contains(out, "No external monitoring targets configured.") {
		t.Fatalf("expected empty registry after remove, got %q", out)
	}

	// Now that nothing references it, removal must succeed.
	if _, err := monCLIRun(t, "monitoring", "profile", "remove", "storage-exporter", "--dir", dir); err != nil {
		t.Fatalf("profile remove after target removed: %v", err)
	}
}

func TestMonitoringCLI_TargetRemove_RequiresConfirmationOrYes(t *testing.T) {
	dir := t.TempDir()
	if _, err := monCLIRun(t, "monitoring", "profile", "add", "--dir", dir, "--name", "p", "--job-name", "j"); err != nil {
		t.Fatalf("profile add: %v", err)
	}
	if _, err := monCLIRun(t, "monitoring", "target", "add", "--dir", dir, "--name", "t", "--address", "1.2.3.4:9100", "--profile", "p"); err != nil {
		t.Fatalf("target add: %v", err)
	}
	// --yes=false is passed EXPLICITLY, not omitted: monTargetYes is a plain
	// BoolVar with no Changed() gate in runMonitoringTargetRemove, so it
	// would otherwise still read back as true here from
	// TestMonitoringCLI_EndToEnd's own "--yes" call above — the same
	// shared-flag-state hazard documented on targetFromFlags, just for a
	// bool with no partial-update logic to hide behind. Real `pilot`
	// invocations never hit this (each is a fresh process); this test would
	// have silently proven nothing without pinning it.
	rootCmd.SetArgs([]string{"monitoring", "target", "remove", "t", "--dir", dir, "--yes=false"})
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&out)
	rootCmd.SetIn(strings.NewReader(""))
	err := rootCmd.Execute()
	rootCmd.SetArgs(nil)
	rootCmd.SetIn(nil)
	if err != nil {
		t.Fatalf("unconfirmed remove should exit cleanly (cancelled), got error: %v", err)
	}
	listOut, _ := monCLIRun(t, "monitoring", "target", "list", "--dir", dir)
	if !strings.Contains(listOut, "t\t") && !strings.Contains(listOut, "\tt\t") {
		// tabwriter column widths vary; just check the name still appears at all.
		if !strings.Contains(listOut, "1.2.3.4:9100") {
			t.Fatalf("target should NOT have been removed without confirmation, got list=%q", listOut)
		}
	}
}

// ---- pure partial-update logic, no cobra involved ----------------------
//
// targetFromFlags takes its "was this flag passed" signal as a plain
// func(string) bool, so it needs no *cobra.Command/FlagSet at all here —
// sidestepping the Changed()-state-persists-across-Execute() hazard
// documented on targetFromFlags itself.

func monitoringTestTarget() monitoring.Target {
	return monitoring.Target{Address: "10.0.0.1:9100", Profile: "orig-profile", Site: "orig-site"}
}

func TestTargetFromFlags_OnlyChangedFieldsUpdated(t *testing.T) {
	base := monitoringTestTarget()
	changed := func(name string) bool { return name == "site" }
	got, err := targetFromFlags(changed, base, "should-not-apply:9999", "should-not-apply", "new-site", nil)
	if err != nil {
		t.Fatalf("targetFromFlags: %v", err)
	}
	if got.Address != base.Address || got.Profile != base.Profile {
		t.Fatalf("unchanged fields must not be touched: got %+v", got)
	}
	if got.Site != "new-site" {
		t.Fatalf("expected site to be updated, got %+v", got)
	}
}

func TestTargetFromFlags_NothingChangedIsANoOp(t *testing.T) {
	base := monitoringTestTarget()
	got, err := targetFromFlags(func(string) bool { return false }, base, "ignored", "ignored", "ignored", []string{"ignored=1"})
	if err != nil {
		t.Fatalf("targetFromFlags: %v", err)
	}
	if !reflect.DeepEqual(got, base) {
		t.Fatalf("expected a no-op when nothing changed: got %+v, want %+v", got, base)
	}
}
