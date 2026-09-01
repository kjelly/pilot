package cmd

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/kjelly/pilot/internal/inventory"
)

func TestDefaultRolePresets_CoversCompactTopology(t *testing.T) {
	presets := defaultRolePresets()
	// freeipa-dns-client was added to all three presets in spec.md §27.1
	// (Internal Endpoint / FreeIPA PKI feature): any host built from these
	// presets now gets the FreeIPA DNS resolver baseline by default.
	want := map[string][]string{
		"FreeIPA 身份伺服器(minimal PoC)": {"freeipa-server", "freeipa-dns-client", "audit-log-forwarding", "wazuh-fim", "restic-backup", "host-monitoring"},
		"Nexus 中央服務節點(minimal PoC)":  {"freeipa-client", "freeipa-dns-client", "docker", "audit-log-forwarding", "wazuh-manager", "wazuh-fim", "seaweedfs-s3", "restic-backup", "host-monitoring", "prometheus", "thanos-query", "alertmanager", "dashboard", "freeipa-nfs-server"},
		"被監控的 Linux 主機(minimal PoC)": {"freeipa-client", "freeipa-dns-client", "audit-log-forwarding", "wazuh-fim", "restic-backup", "host-monitoring"},
	}
	if len(presets) != len(want) {
		t.Fatalf("default preset count = %d, want %d", len(presets), len(want))
	}
	if err := validateRolePresets(presets); err != nil {
		t.Fatalf("default presets contain unknown roles: %v", err)
	}
	for _, preset := range presets {
		roles, ok := want[preset.Label]
		if !ok {
			t.Fatalf("unexpected default preset %q", preset.Label)
		}
		for _, role := range roles {
			if len(preset.Roles) != len(roles) {
				t.Errorf("preset %q roles = %v, want exactly %v", preset.Label, preset.Roles, roles)
				continue
			}
			if !hasRole(preset.Roles, role) {
				t.Errorf("preset %q does not include %q: %v", preset.Label, role, preset.Roles)
			}
		}
	}
}

func TestRolePresets_SaveLoadRoundTripReplacesDefaults(t *testing.T) {
	dir := t.TempDir()
	want := []rolePreset{{Label: "only this environment", Roles: []string{"freeipa-client", "wazuh-fim"}}}
	if err := saveRolePresets(dir, want); err != nil {
		t.Fatalf("saveRolePresets: %v", err)
	}

	got, customized, err := loadRolePresets(dir)
	if err != nil {
		t.Fatalf("loadRolePresets: %v", err)
	}
	if !customized {
		t.Fatal("customized = false, want true after saving role-presets.yml")
	}
	if len(got) != 1 || got[0].Label != want[0].Label || strings.Join(got[0].Roles, ",") != strings.Join(want[0].Roles, ",") {
		t.Fatalf("loaded presets = %+v, want %+v", got, want)
	}
	if _, err := os.Stat(filepath.Join(dir, rolePresetFilename)); err != nil {
		t.Fatalf("expected %s to be created: %v", rolePresetFilename, err)
	}
}

func TestLoadRolePresets_RejectsInvalidRole(t *testing.T) {
	dir := t.TempDir()
	data := "presets:\n  - label: bad\n    roles: [not-a-role]\n"
	if err := os.WriteFile(rolePresetPath(dir), []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := loadRolePresets(dir)
	if err == nil || !strings.Contains(err.Error(), "not-a-role") {
		t.Fatalf("loadRolePresets error = %v, want the invalid role name", err)
	}
}

func TestEditRouter_Teatest_RolePresetManagerCreatesEnvironmentOverride(t *testing.T) {
	dir := t.TempDir()
	hf := &inventory.HostsFile{Hosts: []inventory.Host{{Name: "node-1"}}}
	var router editRouterModel
	pushRolePresetManager(&router, dir, filepath.Join(dir, "hosts.yml"), hf, "node-1", "")
	// 48, not the usual 40: the role checklist this test drives into now
	// renders one more row (snmp-exporter, SNMP monitoring integration
	// spec Phase 0) than fits in a 40-row terminal alongside the huh
	// MultiSelect's title line, pushing the title off the top of the
	// fixed-size test terminal.
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 48))

	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		return strings.Contains(string(b), "管理 ")
	}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	for range defaultRolePresets() {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // add a preset
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		return strings.Contains(string(b), "角色範本名稱")
	}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	tm.Type("test monitored node")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	// tm.Output() is a draining reader: once a WaitFor reads past a
	// substring to satisfy its condition, those bytes are gone from any
	// later read. The checklist screen's role names (checked below, after
	// toggling one with Space) are only ever fully painted once, in this
	// same initial frame — so the tee starts here and both WaitFor calls
	// below share it, letting the later check still see a role name this
	// one already read past, without weakening what either verifies.
	var checklistOutput strings.Builder
	teed := io.TeeReader(tm.Output(), &checklistOutput)
	teatest.WaitFor(t, teed, func(_ []byte) bool {
		return strings.Contains(checklistOutput.String(), `範本 "test monitored node" 的角色`)
	}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	tm.Send(tea.KeyPressMsg{Code: tea.KeySpace}) // first catalog role
	// Checks "•]" rather than "[x]": this screen is now Huh-backed (see
	// docs/superpowers/specs/2026-08-19-pilot-tui-v2-huh-migration-spec.md),
	// and Huh's own MultiSelect renders a checked row as "[•]" rather than
	// the hand-written multiSelectModel's "[x]" — a permitted rendering
	// difference (Core Invariant 7 explicitly allows checkbox/cursor glyph
	// differences), not a functional regression. Bubble Tea v2's cell-level
	// render diff also means only the changed "•]" half of the bracket pair
	// is retransmitted, not the unchanged leading "[" (see the analogous
	// "變數值" comments in edit_tui_flows_test.go for the fuller explanation
	// of that underlying behavior, which is unrelated to the glyph change).
	teatest.WaitFor(t, teed, func(_ []byte) bool {
		screen := checklistOutput.String()
		return strings.Contains(screen, "•]") && strings.Contains(screen, inventory.Roles()[0].Name)
	}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		return strings.Contains(string(b), "✅ 已儲存 ")
	}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	waitForRolePresetOverride(t, dir)
	// Esc here now steps back to the roles menu rather than quitting (see
	// edit_tui.go's package doc comment); this test only cares about the
	// preset persisted to disk, so end the program directly.
	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	presets, customized, err := loadRolePresets(dir)
	if err != nil {
		t.Fatalf("load created preset: %v", err)
	}
	if !customized {
		t.Fatal("role preset manager did not create an environment override")
	}
	if len(presets) != len(defaultRolePresets())+1 {
		t.Fatalf("preset count = %d, want %d", len(presets), len(defaultRolePresets())+1)
	}
	last := presets[len(presets)-1]
	if last.Label != "test monitored node" || !hasRole(last.Roles, inventory.Roles()[0].Name) {
		t.Fatalf("created preset = %+v, want label and first catalog role", last)
	}
}

// TestEditRouter_Teatest_RolePresetNameFlow_EscOnCreateReturnsToManager proves
// pushRolePresetName's idx<0 (create) branch: esc out of the new-preset name
// prompt lands back on the preset manager's list, not some other screen.
func TestEditRouter_Teatest_RolePresetNameFlow_EscOnCreateReturnsToManager(t *testing.T) {
	dir := t.TempDir()
	hf := &inventory.HostsFile{Hosts: []inventory.Host{{Name: "node-1"}}}
	var router editRouterModel
	pushRolePresetManager(&router, dir, filepath.Join(dir, "hosts.yml"), hf, "node-1", "")
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	waitFor("管理 ")
	for range defaultRolePresets() {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "➕ 新增範本"
	waitFor("角色範本名稱")

	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // create-flow esc -> back to the manager list
	waitFor("管理 ")

	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	if _, customized, err := loadRolePresets(dir); err != nil || customized {
		t.Fatalf("esc-canceling a create should not have persisted a preset: customized=%v err=%v", customized, err)
	}
}

// TestEditRouter_Teatest_RolePresetNameFlow_EscOnRenameReturnsToAction proves
// pushRolePresetName's idx>=0 (rename) branch: esc out of the rename name
// prompt lands back on that SAME preset's action menu, not the manager list
// two levels up.
func TestEditRouter_Teatest_RolePresetNameFlow_EscOnRenameReturnsToAction(t *testing.T) {
	dir := t.TempDir()
	hf := &inventory.HostsFile{Hosts: []inventory.Host{{Name: "node-1"}}}
	var router editRouterModel
	pushRolePresetManager(&router, dir, filepath.Join(dir, "hosts.yml"), hf, "node-1", "")
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	waitFor("管理 ")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // first preset in the list -> its action menu
	waitFor("範本 ")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "✏ 修改名稱與角色"
	waitFor("角色範本名稱")

	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // rename-flow esc -> back to THIS preset's action menu
	waitFor("範本 ")

	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	if presets, customized, err := loadRolePresets(dir); err != nil || customized || len(presets) != len(defaultRolePresets()) {
		t.Fatalf("esc-canceling a rename should leave the default presets untouched: presets=%+v customized=%v err=%v", presets, customized, err)
	}
}

func waitForRolePresetOverride(t *testing.T, dir string) {
	t.Helper()
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()

	for {
		if _, customized, err := loadRolePresets(dir); err == nil && customized {
			return
		}
		select {
		case <-timeout.C:
			t.Fatalf("%s was not created within 2s", rolePresetPath(dir))
		case <-tick.C:
		}
	}
}
