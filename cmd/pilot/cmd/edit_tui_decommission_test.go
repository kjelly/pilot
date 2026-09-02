// edit_tui_decommission_test.go is an L1 unit test in the style of
// edit_tui_test.go (model.Update() with tea.Msg on a bare editRouterModel)
// — see that file's package doc comment for why this project mostly
// tests TUI flows either at that level or via teatest
// (edit_tui_flows_test.go); this test needs neither a full teatest
// program nor a real pty, since it only asserts what happens up to and
// including the delete menu item's selection.
package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"

	"github.com/kjelly/pilot/internal/inventory"
)

// TestEditTUI_HostDelete_EntersDecommissionFlow proves HD2/spec.md §7.2:
// selecting the host menu's delete action no longer calls removeHost or
// removes the host from the in-memory HostsFile immediately — it enters
// the decommission planner flow instead, landing on a screen that shows
// plan/blocker information.
func TestEditTUI_HostDelete_EntersDecommissionFlow(t *testing.T) {
	// Reset the package-level dataDir flag var: other tests in this
	// package set it directly without restoring it, and this test needs
	// PILOT_DATA_DIR (set below) to actually take effect so the
	// decommission plan store lands under t.TempDir(), never a real home
	// directory.
	origDataDir := dataDir
	dataDir = ""
	t.Cleanup(func() { dataDir = origDataDir })
	t.Setenv("PILOT_DATA_DIR", filepath.Join(t.TempDir(), "pilot-data"))

	dir := t.TempDir()
	hostsPath := filepath.Join(dir, "hosts.yml")
	const hostName = "edge1"
	if err := os.WriteFile(hostsPath, []byte("hosts:\n  "+hostName+":\n    ansible_host: \"10.0.0.50\"\n"), 0o644); err != nil {
		t.Fatalf("write hosts.yml: %v", err)
	}

	data, err := os.ReadFile(hostsPath)
	if err != nil {
		t.Fatalf("read hosts.yml: %v", err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		t.Fatalf("parse hosts.yml: %v", err)
	}

	h := findHost(hf, hostName)
	if h == nil {
		t.Fatalf("fixture host %q missing after parse", hostName)
	}
	items := hostMenuItems(h)
	deleteIdx := -1
	for i, item := range items {
		if item.choice.ID == "hosts.item.delete" {
			deleteIdx = i
			break
		}
	}
	if deleteIdx < 0 {
		t.Fatal("hosts.item.delete menu entry not found in hostMenuItems")
	}
	if !strings.Contains(items[deleteIdx].choice.Label, "下架") {
		t.Fatalf("delete menu item label = %q, want it to read as a decommission action, not a bare delete", items[deleteIdx].choice.Label)
	}

	var r editRouterModel
	pushHostMenu(&r, dir, hostsPath, hf, hostName)

	for i := 0; i < deleteIdx; i++ {
		nm, _ := r.Update(tea.KeyPressMsg{Code: tea.KeyDown})
		r = nm.(editRouterModel)
	}
	nm, _ := r.Update(tea.KeyPressMsg{Code: tea.KeyEnter})
	r = nm.(editRouterModel)

	// Core assertion: the host must NOT have been removed immediately.
	if len(hf.Hosts) != 1 || hf.Hosts[0].Name != hostName {
		t.Fatalf("host was removed from the in-memory HostsFile immediately upon selecting delete: %+v", hf.Hosts)
	}
	// hosts.yml on disk must also be untouched — planning is read-only.
	after, err := os.ReadFile(hostsPath)
	if err != nil {
		t.Fatalf("read hosts.yml after selecting delete: %v", err)
	}
	if string(after) != string(data) {
		t.Fatalf("hosts.yml on disk changed merely from selecting the delete menu item:\nbefore=%s\nafter=%s", data, after)
	}

	view := viewContent(r.View())
	if !strings.Contains(view, hostName) {
		t.Fatalf("expected the decommission plan screen to mention the host, got view:\n%s", view)
	}
	if !strings.Contains(view, "下架") {
		t.Fatalf("expected a decommission plan/blocker screen, got view:\n%s", view)
	}
	if strings.Contains(view, "確定要刪除主機") {
		t.Fatal("the old direct-delete confirmation screen must no longer be reachable")
	}
}
