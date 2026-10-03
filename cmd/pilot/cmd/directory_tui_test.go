package cmd

import (
	"context"
	"os/exec"
	"testing"

	"github.com/kjelly/pilot/internal/directoryapi"
)

// TestRunDirectoryFullMenuLoop drives every top-menu item once, in order
// (My Hosts -> target detail -> back, My Identity, Refresh, Logout),
// against a real directoryapi.Server (see directory_client_test.go) —
// spec.md §13.1's whole menu, exercised end-to-end.
func TestRunDirectoryFullMenuLoop(t *testing.T) {
	client := startFakeDirectory(t, currentOSUsername(t))
	p := &promptAutomation{answers: []promptAnswer{
		{Prompt: "Pilot Access Directory", Select: directoryMenuMyHosts},
		{Prompt: "My Hosts", Select: "gpu-a.example.com"},
		{Prompt: "Host: gpu-a.example.com", Select: directoryBackChoice},
		{Prompt: "Pilot Access Directory", Select: directoryMenuMyIdentity},
		{Prompt: "My Identity", Select: "OK"},
		{Prompt: "Pilot Access Directory", Select: directoryMenuRefresh},
		{Prompt: "Access refreshed", Select: "OK"},
		{Prompt: "Pilot Access Directory", Select: directoryMenuLogout},
		{Prompt: "Log out", Confirm: boolPtr(true)},
	}}
	withPromptAutomation(t, p, func() {
		credentials := &fakePortalCredentialSession{}
		if err := runDirectoryWithCredentials(context.Background(), client, credentials, testDirectoryEmitter(t), defaultDirectorySSHConfigPath); err != nil {
			t.Fatalf("runDirectory: %v", err)
		}
	})
	if len(p.answers) != 0 {
		t.Fatalf("not all scripted answers were consumed: %+v", p.answers)
	}
}

// TestDirectoryHostDetailConnectFlow drives the actual TUI: My Hosts ->
// target detail -> Connect, with directorySSHLauncher stubbed, proving
// the full menu path reaches connectToGateway with the right target.
func TestDirectoryHostDetailConnectFlow(t *testing.T) {
	client := startFakeDirectory(t, currentOSUsername(t))
	credentials := &fakePortalCredentialSession{cache: "FILE:/run/user/1000/pilot-directory-test/krb5cc"}
	var launchedTarget string
	withDirectorySSHLauncher(t, func(cmd *exec.Cmd) error {
		launchedTarget = cmd.Args[len(cmd.Args)-1]
		return nil
	})
	p := &promptAutomation{answers: []promptAnswer{
		{Prompt: "Pilot Access Directory", Select: directoryMenuMyHosts},
		{Prompt: "My Hosts", Select: "gpu-a.example.com"},
		{Prompt: "Host: gpu-a.example.com", Select: directoryActionConnect},
		{Prompt: "Connect to gpu-a.example.com", Confirm: boolPtr(true)},
		{Prompt: "Pilot Access Directory", Select: directoryMenuLogout},
		{Prompt: "Log out", Confirm: boolPtr(true)},
	}}
	withPromptAutomation(t, p, func() {
		if err := runDirectoryWithCredentials(context.Background(), client, credentials, testDirectoryEmitter(t), defaultDirectorySSHConfigPath); err != nil {
			t.Fatalf("runDirectory: %v", err)
		}
	})
	if launchedTarget != "gpu-a.example.com" {
		t.Fatalf("launchedTarget = %q", launchedTarget)
	}
	if len(p.answers) != 0 {
		t.Fatalf("not all scripted answers were consumed: %+v", p.answers)
	}
}

// TestDirectoryTargetIsReady / TestDirectoryTargetListLabel exercise the
// no-gateway marker logic directly (spec.md §13.1) without needing a full
// TUI drive.
func TestDirectoryTargetIsReadyAndLabel(t *testing.T) {
	ready := directoryTargetFixture(t, "ready")
	if !directoryTargetIsReady(ready) {
		t.Fatalf("expected ready target to report ready")
	}
	if got := directoryTargetListLabel(ready); containsWarning(got) {
		t.Fatalf("ready target label must not carry a warning marker: %q", got)
	}

	notReady := directoryTargetFixture(t, "no_gateway")
	if directoryTargetIsReady(notReady) {
		t.Fatalf("expected no-gateway target to report not ready")
	}
	if got := directoryTargetListLabel(notReady); !containsWarning(got) {
		t.Fatalf("no-gateway target label must carry a warning marker: %q", got)
	}
}

func directoryTargetFixture(t *testing.T, routeStatus string) directoryapi.TargetJSON {
	t.Helper()
	return directoryapi.TargetJSON{
		FQDN: "fixture.example.com",
		SSH:  directoryapi.SSHJSON{Allowed: true, Rules: []string{"grant"}},
		Sudo: directoryapi.SudoJSON{Scope: "none"},
		Routes: []directoryapi.RouteJSON{
			{Scope: "gpu", TargetHostgroup: "pilot-target-gpu", GatewayHostgroup: "pilot-gateway-gpu", RouteStatus: routeStatus},
		},
	}
}

func containsWarning(s string) bool {
	for _, r := range s {
		if r == '⚠' {
			return true
		}
	}
	return false
}

// TestDirectoryHostLabel_RecordingBadge locks AD31 (per-host recording spec
// §24.2): the Directory marks only the host override — [REC] for
// terminal_output, [REC ?] for an unreadable or invalid policy — and never
// guesses a gateway default.
func TestDirectoryHostLabel_RecordingBadge(t *testing.T) {
	target := func(status string) directoryapi.TargetJSON {
		return directoryapi.TargetJSON{
			FQDN:      "db-prod-01.ipa.pilot.internal",
			Routes:    []directoryapi.RouteJSON{{Scope: "gpu", RouteStatus: directoryRouteStatusReady}},
			Recording: directoryapi.DirectoryRecordingJSON{Status: status},
		}
	}
	cases := map[string]string{
		"terminal_output": "db-prod-01.ipa.pilot.internal  [gpu]  [REC]",
		"unknown":         "db-prod-01.ipa.pilot.internal  [gpu]  [REC ?]",
		"invalid":         "db-prod-01.ipa.pilot.internal  [gpu]  [REC ?]",
		"inherit":         "db-prod-01.ipa.pilot.internal  [gpu]",
		"off":             "db-prod-01.ipa.pilot.internal  [gpu]",
		"":                "db-prod-01.ipa.pilot.internal  [gpu]",
	}
	for status, want := range cases {
		if got := directoryTargetListLabel(target(status)); got != want {
			t.Errorf("status %q: label = %q, want %q", status, got, want)
		}
	}
}
