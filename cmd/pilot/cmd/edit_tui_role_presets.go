package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"gopkg.in/yaml.v3"

	"github.com/kjelly/pilot/internal/inventory"
)

const rolePresetFilename = "role-presets.yml"

// rolePreset is one reusable role bundle shown by `pilot edit`.
// Applying it only adds its roles to a host; it never removes a role.
type rolePreset struct {
	Label string   `yaml:"label"`
	Roles []string `yaml:"roles"`
}

type rolePresetFile struct {
	Presets []rolePreset `yaml:"presets"`
}

// defaultRolePresets is the actual three-host minimal-PoC inventory from
// docs/runbooks/minimal-poc-architecture.md. Other topologies, including a
// FreeIPA replica, are intentionally added through the per-environment editor.
func defaultRolePresets() []rolePreset {
	return []rolePreset{
		{
			Label: "FreeIPA 身份伺服器(minimal PoC)",
			Roles: []string{"freeipa-server", "audit-log-forwarding", "wazuh-fim", "restic-backup"},
		},
		{
			Label: "Nexus 中央服務節點(minimal PoC)",
			Roles: []string{"freeipa-client", "docker", "audit-log-forwarding", "wazuh-manager", "wazuh-fim", "seaweedfs-s3", "restic-backup", "prometheus", "thanos-query", "alertmanager", "dashboard", "freeipa-nfs-server"},
		},
		{
			Label: "被監控的 Linux 主機(minimal PoC)",
			Roles: []string{"freeipa-client", "docker", "audit-log-forwarding", "wazuh-fim", "restic-backup", "freeipa-nfs-client"},
		},
	}
}

func rolePresetPath(dir string) string {
	return filepath.Join(dir, rolePresetFilename)
}

// loadRolePresets returns the built-in topology defaults until the environment
// has a role-presets.yml. An existing file deliberately replaces, rather than
// extends, the defaults so every environment can control its menu exactly.
func loadRolePresets(dir string) ([]rolePreset, bool, error) {
	path := rolePresetPath(dir)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return cloneRolePresets(defaultRolePresets()), false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("read %s: %w", path, err)
	}
	var file rolePresetFile
	if err := yaml.Unmarshal(data, &file); err != nil {
		return nil, false, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := validateRolePresets(file.Presets); err != nil {
		return nil, false, fmt.Errorf("invalid %s: %w", path, err)
	}
	return cloneRolePresets(file.Presets), true, nil
}

func saveRolePresets(dir string, presets []rolePreset) error {
	if err := validateRolePresets(presets); err != nil {
		return err
	}
	data, err := yaml.Marshal(rolePresetFile{Presets: presets})
	if err != nil {
		return fmt.Errorf("marshal %s: %w", rolePresetFilename, err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", dir, err)
	}
	path := rolePresetPath(dir)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	return nil
}

func validateRolePresets(presets []rolePreset) error {
	known := make(map[string]bool)
	for _, role := range inventory.Roles() {
		known[role.Name] = true
	}
	labels := make(map[string]bool, len(presets))
	for i, preset := range presets {
		label := strings.TrimSpace(preset.Label)
		if label == "" {
			return fmt.Errorf("第 %d 個範本名稱不能留空", i+1)
		}
		if labels[label] {
			return fmt.Errorf("範本名稱 %q 重複", label)
		}
		labels[label] = true
		if len(preset.Roles) == 0 {
			return fmt.Errorf("範本 %q 至少要有一個角色", label)
		}
		roles := make(map[string]bool, len(preset.Roles))
		for _, role := range preset.Roles {
			if !known[role] {
				return fmt.Errorf("範本 %q 有未知角色 %q", label, role)
			}
			if roles[role] {
				return fmt.Errorf("範本 %q 的角色 %q 重複", label, role)
			}
			roles[role] = true
		}
	}
	return nil
}

func cloneRolePresets(presets []rolePreset) []rolePreset {
	out := make([]rolePreset, len(presets))
	for i, preset := range presets {
		out[i] = rolePreset{Label: preset.Label, Roles: append([]string(nil), preset.Roles...)}
	}
	return out
}

func pushRolePresetManager(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name, banner string) tea.Cmd {
	presets, customized, err := loadRolePresets(dir)
	if err != nil {
		r.err = err
		return nil
	}
	items := make([]string, 0, len(presets)+3)
	for _, preset := range presets {
		items = append(items, fmt.Sprintf("📝 %s — %s", preset.Label, strings.Join(preset.Roles, ", ")))
	}
	items = append(items, "➕ 新增範本")
	if customized {
		items = append(items, "↺ 還原為內建範本")
	}
	items = append(items, "↩ 返回")
	title := fmt.Sprintf("管理 %s", rolePresetPath(dir))
	return r.transitionTo(newSelectModel(title, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return quitWizard(r)
		}
		idx := m.Selected()
		switch {
		case idx < len(presets):
			return pushRolePresetAction(r, dir, path, hf, name, presets, idx)
		case idx == len(presets):
			return pushRolePresetName(r, dir, path, hf, name, presets, -1)
		case customized && idx == len(presets)+1:
			return pushConfirmRestoreRolePresets(r, dir, path, hf, name)
		default:
			return pushRolesMenu(r, dir, path, hf, name)
		}
	})
}

func pushRolePresetAction(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name string, presets []rolePreset, idx int) tea.Cmd {
	title := fmt.Sprintf("範本 %q", presets[idx].Label)
	items := []string{"✏ 修改名稱與角色", "🗑 刪除範本", "↩ 返回"}
	return r.transitionTo(newSelectModel(title, items), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return quitWizard(r)
		}
		switch m.Selected() {
		case 0:
			return pushRolePresetName(r, dir, path, hf, name, presets, idx)
		case 1:
			return pushConfirmDeleteRolePreset(r, dir, path, hf, name, presets, idx)
		default:
			return pushRolePresetManager(r, dir, path, hf, name, "")
		}
	})
}

func pushRolePresetName(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name string, presets []rolePreset, idx int) tea.Cmd {
	current := ""
	if idx >= 0 {
		current = presets[idx].Label
	}
	validate := func(value string) error {
		value = strings.TrimSpace(value)
		if value == "" {
			return fmt.Errorf("範本名稱不能留空")
		}
		for i, preset := range presets {
			if i != idx && preset.Label == value {
				return fmt.Errorf("範本名稱 %q 已存在", value)
			}
		}
		return nil
	}
	return r.transitionTo(newTextInputModel("角色範本名稱", current, validate), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return quitWizard(r)
		}
		label := strings.TrimSpace(m.Value())
		if idx < 0 {
			presets = append(presets, rolePreset{Label: label})
			idx = len(presets) - 1
		} else {
			presets[idx].Label = label
		}
		return pushRolePresetChecklist(r, dir, path, hf, name, presets, idx)
	})
}

func pushRolePresetChecklist(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name string, presets []rolePreset, idx int) tea.Cmd {
	roles := inventory.Roles()
	items := make([]multiSelectItem, len(roles))
	for i, role := range roles {
		items[i] = multiSelectItem{Label: role.Name, Description: role.Description, Checked: hasRole(presets[idx].Roles, role.Name)}
	}
	title := fmt.Sprintf("範本 %q 的角色", presets[idx].Label)
	return r.transitionTo(newMultiSelectModel(title, items), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(multiSelectModel)
		if m.Canceled() {
			return pushRolePresetManager(r, dir, path, hf, name, "")
		}
		roles := m.CheckedLabels()
		if len(roles) == 0 {
			return pushRolePresetManager(r, dir, path, hf, name, "範本至少要選一個角色，尚未儲存。")
		}
		sort.Strings(roles)
		presets[idx].Roles = roles
		if err := saveRolePresets(dir, presets); err != nil {
			r.err = err
			return nil
		}
		return pushRolePresetManager(r, dir, path, hf, name, fmt.Sprintf("✅ 已儲存 %s", rolePresetPath(dir)))
	})
}

func pushConfirmDeleteRolePreset(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name string, presets []rolePreset, idx int) tea.Cmd {
	question := fmt.Sprintf("確定刪除範本 %q 嗎？", presets[idx].Label)
	return r.transitionTo(newConfirmModel(question, false), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(confirmModel)
		if !m.Value() {
			return pushRolePresetAction(r, dir, path, hf, name, presets, idx)
		}
		updated := append(append([]rolePreset(nil), presets[:idx]...), presets[idx+1:]...)
		if err := saveRolePresets(dir, updated); err != nil {
			r.err = err
			return nil
		}
		return pushRolePresetManager(r, dir, path, hf, name, fmt.Sprintf("已刪除範本 %q。", presets[idx].Label))
	})
}

func pushConfirmRestoreRolePresets(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name string) tea.Cmd {
	question := fmt.Sprintf("確定刪除 %s，還原為內建範本嗎？", rolePresetPath(dir))
	return r.transitionTo(newConfirmModel(question, false), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(confirmModel)
		if !m.Value() {
			return pushRolePresetManager(r, dir, path, hf, name, "")
		}
		if err := os.Remove(rolePresetPath(dir)); err != nil && !errors.Is(err, os.ErrNotExist) {
			r.err = fmt.Errorf("remove %s: %w", rolePresetPath(dir), err)
			return nil
		}
		return pushRolePresetManager(r, dir, path, hf, name, "已還原內建範本。")
	})
}
