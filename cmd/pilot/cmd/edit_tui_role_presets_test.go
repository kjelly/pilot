package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"

	"github.com/kjelly/pilot/internal/inventory"
)

func TestDefaultRolePresets_CoversCompactTopology(t *testing.T) {
	presets := defaultRolePresets()
	want := map[string][]string{
		"FreeIPA 身份伺服器(minimal PoC)": {"freeipa-server", "audit-log-forwarding", "wazuh-fim", "restic-backup"},
		"Nexus 中央服務節點(minimal PoC)":  {"docker", "audit-log-forwarding", "wazuh-manager", "wazuh-fim", "seaweedfs-s3", "restic-backup", "prometheus", "thanos-query", "alertmanager", "dashboard", "freeipa-nfs-server"},
		"被監控的 Linux 主機(minimal PoC)": {"freeipa-client", "docker", "audit-log-forwarding", "wazuh-fim", "restic-backup", "freeipa-nfs-client"},
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
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))

	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		return strings.Contains(string(b), "管理 ")
	}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	for range defaultRolePresets() {
		tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // add a preset
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		return strings.Contains(string(b), "角色範本名稱")
	}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	tm.Type("test monitored node")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		return strings.Contains(string(b), `範本 "test monitored node" 的角色`)
	}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	tm.Send(tea.KeyMsg{Type: tea.KeySpace}) // first catalog role
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		screen := string(b)
		return strings.Contains(screen, "[x]") && strings.Contains(screen, inventory.Roles()[0].Name)
	}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		return strings.Contains(string(b), "✅ 已儲存 ")
	}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	waitForRolePresetOverride(t, dir)
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc}) // cleanly exit the wizard
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
