package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

func TestEditAutomationDriverApplyRolePreset(t *testing.T) {
	dir := t.TempDir()
	defaults := defaultRolePresets()
	preset := defaults[0]
	otherRole := inventory.Roles()[0].Name

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "enable_role", Host: "web-1", Role: otherRole},
			{Action: "apply_role_preset", Host: "web-1", Preset: preset.Label},
			{Action: "save_hosts"},
		},
	}
	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("read hosts.yml: %v", err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		t.Fatalf("parse hosts.yml: %v\n%s", err, data)
	}
	roles := hf.Hosts[0].Roles
	if !hasRole(roles, otherRole) {
		t.Fatalf("pre-existing role %q lost after apply_role_preset (should union, not replace): %+v", otherRole, roles)
	}
	for _, want := range preset.Roles {
		if !hasRole(roles, want) {
			t.Fatalf("preset role %q missing after apply_role_preset: %+v", want, roles)
		}
	}
}

func TestEditAutomationDriverCopyRolesFromHost(t *testing.T) {
	dir := t.TempDir()
	roles := inventory.Roles()
	roleA, roleB := roles[0].Name, roles[1].Name

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "source-1"},
			{Action: "enable_role", Host: "source-1", Role: roleA},
			{Action: "create_host", Host: "target-1"},
			{Action: "enable_role", Host: "target-1", Role: roleB},
			{Action: "copy_roles_from_host", Host: "target-1", SourceHost: "source-1"},
			{Action: "save_hosts"},
		},
	}
	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("read hosts.yml: %v", err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		t.Fatalf("parse hosts.yml: %v\n%s", err, data)
	}
	byName := map[string]inventory.Host{}
	for _, h := range hf.Hosts {
		byName[h.Name] = h
	}
	target := byName["target-1"]
	if !hasRole(target.Roles, roleA) || !hasRole(target.Roles, roleB) {
		t.Fatalf("target-1 roles = %+v, want both %q and %q", target.Roles, roleA, roleB)
	}
}

func TestEditAutomationDriverCopyRolesFromHostNoCandidatesErrors(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "copy_roles_from_host", Host: "web-1", SourceHost: "nobody"},
			{Action: "save_hosts"},
		},
	}
	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err == nil {
		t.Fatal("driver.run() unexpectedly succeeded with no candidate hosts")
	}
}

func TestEditAutomationDriverCreateRolePreset(t *testing.T) {
	dir := t.TempDir()
	roles := inventory.Roles()
	roleA, roleB := roles[0].Name, roles[1].Name

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "create_role_preset", Host: "web-1", Label: "My Preset", Roles: []string{roleA, roleB}},
			{Action: "save_hosts"},
		},
	}
	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	presets, customized, err := loadRolePresets(dir)
	if err != nil {
		t.Fatalf("loadRolePresets() error = %v", err)
	}
	if !customized {
		t.Fatal("role-presets.yml was not written")
	}
	var found *rolePreset
	for i := range presets {
		if presets[i].Label == "My Preset" {
			found = &presets[i]
		}
	}
	if found == nil {
		t.Fatalf("preset %q not found among %+v", "My Preset", presets)
	}
	if !hasRole(found.Roles, roleA) || !hasRole(found.Roles, roleB) {
		t.Fatalf("preset roles = %+v, want %q and %q", found.Roles, roleA, roleB)
	}
}

func TestValidateCreateRolePresetRejectsEmptyRoles(t *testing.T) {
	err := validateEditScenario(editScenario{Version: 1, Steps: []editAction{
		{Action: "create_role_preset", Host: "web-1", Label: "Empty"},
	}})
	if err == nil || !strings.Contains(err.Error(), "at least one role") {
		t.Fatalf("validateEditScenario() error = %v, want at-least-one-role rejection", err)
	}
}

func TestEditAutomationDriverRenameRolePreset(t *testing.T) {
	dir := t.TempDir()
	original := defaultRolePresets()[0]

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "rename_role_preset", Host: "web-1", Preset: original.Label, Label: "Renamed Preset"},
			{Action: "save_hosts"},
		},
	}
	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	presets, customized, err := loadRolePresets(dir)
	if err != nil {
		t.Fatalf("loadRolePresets() error = %v", err)
	}
	if !customized {
		t.Fatal("role-presets.yml was not written")
	}
	var found *rolePreset
	for i := range presets {
		if presets[i].Label == "Renamed Preset" {
			found = &presets[i]
		}
	}
	if found == nil {
		t.Fatalf("renamed preset not found among %+v", presets)
	}
	// pushRolePresetChecklist always re-sorts roles on save (even a pure
	// rename re-confirms the checklist), so compare as a set, not by order.
	if len(found.Roles) != len(original.Roles) {
		t.Fatalf("rename changed role count: got %+v, want %+v", found.Roles, original.Roles)
	}
	for _, want := range original.Roles {
		if !hasRole(found.Roles, want) {
			t.Fatalf("rename dropped role %q: got %+v, want %+v", want, found.Roles, original.Roles)
		}
	}
	for _, p := range presets {
		if p.Label == original.Label {
			t.Fatalf("old label %q still present after rename: %+v", original.Label, presets)
		}
	}
}

func TestEditAutomationDriverDeleteRolePreset(t *testing.T) {
	dir := t.TempDir()
	defaults := defaultRolePresets()
	toDelete := defaults[0]

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "delete_role_preset", Host: "web-1", Preset: toDelete.Label},
			{Action: "save_hosts"},
		},
	}
	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	presets, customized, err := loadRolePresets(dir)
	if err != nil {
		t.Fatalf("loadRolePresets() error = %v", err)
	}
	if !customized {
		t.Fatal("role-presets.yml was not written")
	}
	if len(presets) != len(defaults)-1 {
		t.Fatalf("presets = %+v, want %d entries", presets, len(defaults)-1)
	}
	for _, p := range presets {
		if p.Label == toDelete.Label {
			t.Fatalf("deleted preset %q still present: %+v", toDelete.Label, presets)
		}
	}
}

func TestEditAutomationDriverRestoreRolePresetsFailsWhenNotCustomized(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "restore_role_presets", Host: "web-1"},
			{Action: "save_hosts"},
		},
	}
	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err == nil {
		t.Fatal("driver.run() unexpectedly succeeded restoring an already-default role-presets.yml")
	}
}

func TestEditAutomationDriverRestoreRolePresets(t *testing.T) {
	dir := t.TempDir()
	defaults := defaultRolePresets()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_host", Host: "web-1"},
			{Action: "delete_role_preset", Host: "web-1", Preset: defaults[0].Label},
			{Action: "restore_role_presets", Host: "web-1"},
			{Action: "save_hosts"},
		},
	}
	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, rolePresetFilename)); !os.IsNotExist(err) {
		t.Fatalf("role-presets.yml still exists after restore_role_presets, err=%v", err)
	}
	presets, customized, err := loadRolePresets(dir)
	if err != nil {
		t.Fatalf("loadRolePresets() error = %v", err)
	}
	if customized {
		t.Fatal("loadRolePresets() reports customized after restore")
	}
	if len(presets) != len(defaults) {
		t.Fatalf("presets = %+v, want the %d built-in defaults", presets, len(defaults))
	}
}
