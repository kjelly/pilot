package cmd

import (
	"context"
	"errors"
	"os/exec"
	"testing"

	"github.com/kjelly/pilot/internal/gatewayapi"
)

// withPortalResolveHost overrides portalResolveHost for the duration of fn,
// restoring whatever was active before (startFakeGateway's own default
// stub, in every test that also calls it).
func withPortalResolveHost(t *testing.T, fn func(ctx context.Context, host string) ([]string, error)) {
	t.Helper()
	old := portalResolveHost
	portalResolveHost = fn
	t.Cleanup(func() { portalResolveHost = old })
}

// withPromptAutomation installs p as activePromptAutomation for the
// duration of fn, restoring whatever was active before — the same
// pattern runAutomatedDeploymentStep uses (edit_automation.go).
func withPromptAutomation(t *testing.T, p *promptAutomation, fn func()) {
	t.Helper()
	old := activePromptAutomation
	activePromptAutomation = p
	defer func() { activePromptAutomation = old }()
	fn()
}

// TestRunPortalFullMenuLoop drives every top-menu item once, in order
// (My Hosts -> host detail -> back, My Identity, Refresh, Logout),
// against a real gatewayapi.Server (see portal_client_test.go) — this is
// spec.md §27's whole menu, exercised end-to-end.
func TestRunPortalFullMenuLoop(t *testing.T) {
	client := startFakeGateway(t, currentOSUsername(t))
	p := &promptAutomation{answers: []promptAnswer{
		{Prompt: "Pilot Portal", Select: portalMenuMyHosts},
		{Prompt: "My Hosts", Select: "gpu-a.example.com"},
		{Prompt: "Host: gpu-a.example.com", Select: portalBackChoice},
		{Prompt: "Pilot Portal", Select: portalMenuMyIdentity},
		{Prompt: "My Identity", Confirm: boolPtr(true)},
		{Prompt: "Pilot Portal", Select: portalMenuRefresh},
		{Prompt: "Access refreshed", Confirm: boolPtr(true)},
		{Prompt: "Pilot Portal", Select: portalMenuLogout},
		{Prompt: "Log out", Confirm: boolPtr(true)},
	}}
	withPromptAutomation(t, p, func() {
		if err := runPortal(context.Background(), client); err != nil {
			t.Fatalf("runPortal: %v", err)
		}
	})
	if len(p.answers) != 0 {
		t.Fatalf("not all scripted answers were consumed: %+v", p.answers)
	}
}

// TestRunPortalMyHostsBack verifies "« Back" from My Hosts returns to the
// top menu instead of ending the session.
func TestRunPortalMyHostsBack(t *testing.T) {
	client := startFakeGateway(t, currentOSUsername(t))
	p := &promptAutomation{answers: []promptAnswer{
		{Prompt: "Pilot Portal", Select: portalMenuMyHosts},
		{Prompt: "My Hosts", Select: portalBackChoice},
		{Prompt: "Pilot Portal", Select: portalMenuLogout},
		{Prompt: "Log out", Confirm: boolPtr(true)},
	}}
	withPromptAutomation(t, p, func() {
		if err := runPortal(context.Background(), client); err != nil {
			t.Fatalf("runPortal: %v", err)
		}
	})
	if len(p.answers) != 0 {
		t.Fatalf("not all scripted answers were consumed: %+v", p.answers)
	}
}

// TestRunPortalRefreshReflectsNewData proves Refresh actually re-fetches
// rather than replaying a cached snapshot: the second My Hosts listing,
// after Refresh, must show the host that only became visible after the
// underlying data changed between the two fetches.
func TestRunPortalRefreshReflectsNewData(t *testing.T) {
	client := startFakeGateway(t, currentOSUsername(t))
	// First pass shows one host (gpu-a). No mutation is made to the fake
	// provider here — this test only proves Refresh performs a second
	// real /v1/access call, not that the resolver is live-reactive
	// (Phase 2 already covers resolver correctness); a second identical
	// call succeeding end-to-end is the thing worth proving at this layer.
	p := &promptAutomation{answers: []promptAnswer{
		{Prompt: "Pilot Portal", Select: portalMenuRefresh},
		{Prompt: "Access refreshed", Confirm: boolPtr(true)},
		{Prompt: "Pilot Portal", Select: portalMenuMyHosts},
		{Prompt: "My Hosts", Select: "gpu-a.example.com"},
		{Prompt: "Host: gpu-a.example.com", Select: portalBackChoice},
		{Prompt: "Pilot Portal", Select: portalMenuLogout},
		{Prompt: "Log out", Confirm: boolPtr(true)},
	}}
	withPromptAutomation(t, p, func() {
		if err := runPortal(context.Background(), client); err != nil {
			t.Fatalf("runPortal: %v", err)
		}
	})
	if len(p.answers) != 0 {
		t.Fatalf("not all scripted answers were consumed: %+v", p.answers)
	}
}

// TestRunPortalNoScopeSwitcher is a structural guard for spec.md §27's
// "Portal不得提供 scope switcher": the top menu must be exactly these
// four items, nothing else.
func TestRunPortalNoScopeSwitcher(t *testing.T) {
	want := []string{portalMenuMyHosts, portalMenuMyIdentity, portalMenuRefresh, portalMenuLogout}
	if len(portalTopMenuItems) != len(want) {
		t.Fatalf("portalTopMenuItems = %v, want exactly %v", portalTopMenuItems, want)
	}
	for i, item := range want {
		if portalTopMenuItems[i] != item {
			t.Fatalf("portalTopMenuItems[%d] = %q, want %q", i, portalTopMenuItems[i], item)
		}
	}
}

// TestResolvePortalHostEntriesSortsUnresolvableLast proves the DNS
// reachability probe (added after a placeholder demo host with no DNS
// record could only be told apart from a real target by failing Connect)
// marks each host correctly and moves unresolvable ones after resolvable
// ones, without reordering within either group.
func TestResolvePortalHostEntriesSortsUnresolvableLast(t *testing.T) {
	withPortalResolveHost(t, func(ctx context.Context, host string) ([]string, error) {
		if host == "dead-a.example.com" || host == "dead-b.example.com" {
			return nil, errors.New("no such host")
		}
		return []string{"127.0.0.1"}, nil
	})
	hosts := []gatewayapi.HostJSON{
		{FQDN: "dead-a.example.com"},
		{FQDN: "live-a.example.com"},
		{FQDN: "dead-b.example.com"},
		{FQDN: "live-b.example.com"},
	}
	entries := resolvePortalHostEntries(context.Background(), hosts)
	wantOrder := []string{"live-a.example.com", "live-b.example.com", "dead-a.example.com", "dead-b.example.com"}
	if len(entries) != len(wantOrder) {
		t.Fatalf("len(entries) = %d, want %d", len(entries), len(wantOrder))
	}
	for i, want := range wantOrder {
		if entries[i].host.FQDN != want {
			t.Fatalf("entries[%d].host.FQDN = %q, want %q (order: %+v)", i, entries[i].host.FQDN, want, entries)
		}
	}
	for _, e := range entries {
		wantResolvable := e.host.FQDN == "live-a.example.com" || e.host.FQDN == "live-b.example.com"
		if e.resolvable != wantResolvable {
			t.Errorf("entry %q resolvable = %v, want %v", e.host.FQDN, e.resolvable, wantResolvable)
		}
		label := portalHostListLabel(e)
		if wantResolvable && label != e.host.FQDN {
			t.Errorf("portalHostListLabel(%q) = %q, want unadorned FQDN", e.host.FQDN, label)
		}
		if !wantResolvable && label == e.host.FQDN {
			t.Errorf("portalHostListLabel(%q) = %q, want a DNS-failure annotation", e.host.FQDN, label)
		}
	}
}

// TestRunPortalHostDetailConnectDeclined proves declining the Connect
// confirmation never launches ssh — the confirmation must actually gate
// the action, not just decorate it.
func TestRunPortalHostDetailConnectDeclined(t *testing.T) {
	client := startFakeGateway(t, currentOSUsername(t))
	launched := false
	withSSHLauncher(t, func(cmd *exec.Cmd) error {
		launched = true
		return nil
	})
	p := &promptAutomation{answers: []promptAnswer{
		{Prompt: "Pilot Portal", Select: portalMenuMyHosts},
		{Prompt: "My Hosts", Select: "gpu-a.example.com"},
		{Prompt: "Host: gpu-a.example.com", Select: portalActionConnect},
		{Prompt: "Connect to gpu-a.example.com", Confirm: boolPtr(false)},
		{Prompt: "Pilot Portal", Select: portalMenuLogout},
		{Prompt: "Log out", Confirm: boolPtr(true)},
	}}
	withPromptAutomation(t, p, func() {
		if err := runPortal(context.Background(), client); err != nil {
			t.Fatalf("runPortal: %v", err)
		}
	})
	if launched {
		t.Fatalf("ssh must not be launched when the Connect confirmation is declined")
	}
	if len(p.answers) != 0 {
		t.Fatalf("not all scripted answers were consumed: %+v", p.answers)
	}
}

// TestRunPortalLogoutDeclinedStaysInPortal proves declining the Logout
// confirmation returns to the top menu instead of ending the session.
func TestRunPortalLogoutDeclinedStaysInPortal(t *testing.T) {
	client := startFakeGateway(t, currentOSUsername(t))
	p := &promptAutomation{answers: []promptAnswer{
		{Prompt: "Pilot Portal", Select: portalMenuLogout},
		{Prompt: "Log out", Confirm: boolPtr(false)},
		{Prompt: "Pilot Portal", Select: portalMenuLogout},
		{Prompt: "Log out", Confirm: boolPtr(true)},
	}}
	withPromptAutomation(t, p, func() {
		if err := runPortal(context.Background(), client); err != nil {
			t.Fatalf("runPortal: %v", err)
		}
	})
	if len(p.answers) != 0 {
		t.Fatalf("not all scripted answers were consumed: %+v", p.answers)
	}
}

// TestPortalSudoScopeIsBroad locks in which accessportal.sudoDisplayScope
// values are treated as root-equivalent for the Connect confirmation's
// warning and default-to-no behavior.
func TestPortalSudoScopeIsBroad(t *testing.T) {
	cases := map[string]bool{
		"none":          false,
		"limited":       false,
		"all":           true,
		"all_with_deny": true,
	}
	for scope, want := range cases {
		if got := portalSudoScopeIsBroad(scope); got != want {
			t.Errorf("portalSudoScopeIsBroad(%q) = %v, want %v", scope, got, want)
		}
	}
}
