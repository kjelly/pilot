// edit_tui_monitoring.go implements the Monitoring screens of the `pilot
// edit` router (edit_tui.go): a manager for the external monitoring target
// registry (spec.md §7-24, internal/monitoring). Unlike
// edit_tui_internal_endpoints.go/edit_tui_dns.go there is no caller-chosen
// manifest path to prompt for — spec.md §6 fixes the layout to
// <dir>/monitoring/targets.yml and <dir>/monitoring/scrape-profiles.yml, so
// this manager goes straight there from the top menu.
//
// Every mutation follows the same immediate load -> mutate -> Validate ->
// (save | show violations, don't save) sequence as `pilot monitoring`'s CLI
// commands (monitoring_target.go/monitoring_profile.go) — an invalid
// registry is never persisted, matching the Simulate-then-write discipline
// edit_tui_internal_endpoints.go documents for its own manifest.
package cmd

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/kjelly/pilot/internal/monitoring"
	"github.com/kjelly/pilot/internal/tui"
)

func monitoringTargetsPath(dir string) string { return filepath.Join(dir, "monitoring", "targets.yml") }
func monitoringProfilesPath(dir string) string {
	return filepath.Join(dir, "monitoring", "scrape-profiles.yml")
}

func loadMonitoring(dir string) (monitoring.TargetFile, monitoring.ProfileFile, error) {
	tf, err := monitoring.LoadTargets(monitoringTargetsPath(dir))
	if err != nil {
		return monitoring.TargetFile{}, monitoring.ProfileFile{}, err
	}
	pf, err := monitoring.LoadProfiles(monitoringProfilesPath(dir))
	if err != nil {
		return monitoring.TargetFile{}, monitoring.ProfileFile{}, err
	}
	return tf, pf, nil
}

// saveMonitoringTargets validates the FULL registry (tf against pf) before
// writing tf — an edit to one target can only be judged valid in the
// context of every other target/profile, so Validate always takes both.
func saveMonitoringTargets(dir string, tf monitoring.TargetFile, pf monitoring.ProfileFile) (monitoring.Result, error) {
	r := monitoring.Validate(tf, pf)
	if !r.OK() {
		return r, nil
	}
	return r, monitoring.SaveTargets(monitoringTargetsPath(dir), tf)
}

func saveMonitoringProfiles(dir string, tf monitoring.TargetFile, pf monitoring.ProfileFile) (monitoring.Result, error) {
	r := monitoring.Validate(tf, pf)
	if !r.OK() {
		return r, nil
	}
	return r, monitoring.SaveProfiles(monitoringProfilesPath(dir), pf)
}

func formatViolations(r monitoring.Result) string {
	var b strings.Builder
	for _, e := range r.Errors {
		b.WriteString("⚠️  error: " + e + "\n")
	}
	for _, w := range r.Warnings {
		b.WriteString("⚠️  warning: " + w + "\n")
	}
	return strings.TrimRight(b.String(), "\n")
}

// ---- manager ------------------------------------------------------------

func pushMonitoringManager(r *editRouterModel, dir, banner string) tea.Cmd {
	choices := []tui.Choice{
		{ID: "mon.manager.targets", Label: "🎯 Exporter Targets"},
		{ID: "mon.manager.profiles", Label: "📋 Scrape Profiles"},
		{ID: "mon.manager.validate", Label: "🔍 驗證 monitoring/targets.yml + scrape-profiles.yml"},
		{ID: "mon.manager.back", Label: "↩  返回"},
	}
	spec := tui.SelectSpec{ScreenID: "mon.manager", Title: "Monitoring — Prometheus external exporter targets", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushTopMenu(r, dir, "")
		}
		switch m.Selected() {
		case 0:
			return pushMonitoringTargetsMenu(r, dir, "")
		case 1:
			return pushMonitoringProfilesMenu(r, dir, "")
		case 2:
			return pushMonitoringValidateReport(r, dir)
		case 3:
			return pushTopMenu(r, dir, "")
		}
		return nil
	})
}

// pushMonitoringValidateReport runs monitoring.Validate read-only (spec.md
// §32 — no network, no mutation) and shows the result as a banner on the
// manager menu, mirroring pushConfigCompletenessCheck's exact pattern.
func pushMonitoringValidateReport(r *editRouterModel, dir string) tea.Cmd {
	tf, pf, err := loadMonitoring(dir)
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  無法讀取 monitoring 設定：%v", err))
	}
	res := monitoring.Validate(tf, pf)
	banner := "✅ monitoring/targets.yml + scrape-profiles.yml 驗證通過。"
	if !res.OK() || len(res.Warnings) > 0 {
		banner = formatViolations(res)
	}
	return pushMonitoringManager(r, dir, banner)
}

// ---- targets: list + add --------------------------------------------------

func pushMonitoringTargetsMenu(r *editRouterModel, dir, banner string) tea.Cmd {
	tf, _, err := loadMonitoring(dir)
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  無法讀取 %s：%v", monitoringTargetsPath(dir), err))
	}
	names := make([]string, 0, len(tf.Targets))
	for _, t := range tf.Targets {
		names = append(names, t.Name)
	}
	sort.Strings(names)

	note := "目前沒有任何 target。"
	if len(names) > 0 {
		note = "選一個查看/編輯，或新增一個。"
	}
	if banner == "" {
		banner = note
	} else {
		banner += "\n" + note
	}

	choices := make([]tui.Choice, 0, len(names)+2)
	for _, name := range names {
		t := findMonitoringTarget(tf, name)
		status := "enabled"
		if t != nil && !t.IsEnabled() {
			status = "disabled"
		}
		choices = append(choices, tui.Choice{ID: name, Label: fmt.Sprintf("🎯 %s (%s)", name, status)})
	}
	choices = append(choices,
		tui.Choice{ID: "mon.target.list.add", Label: "➕ 新增 target"},
		tui.Choice{ID: "mon.target.list.back", Label: "↩  返回"},
	)

	spec := tui.SelectSpec{ScreenID: "mon.target.list", Title: fmt.Sprintf("Exporter Targets — %s", monitoringTargetsPath(dir)), Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushMonitoringManager(r, dir, "")
		}
		switch {
		case m.Selected() < len(names):
			return pushMonitoringTargetDetail(r, dir, names[m.Selected()], "")
		case m.Selected() == len(names):
			return pushMonitoringTargetAddName(r, dir)
		default:
			return pushMonitoringManager(r, dir, "")
		}
	})
}

func findMonitoringTarget(tf monitoring.TargetFile, name string) *monitoring.Target {
	for i := range tf.Targets {
		if tf.Targets[i].Name == name {
			return &tf.Targets[i]
		}
	}
	return nil
}

func pushMonitoringTargetAddName(r *editRouterModel, dir string) tea.Cmd {
	tf, _, err := loadMonitoring(dir)
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	validate := func(s string) error {
		s = strings.TrimSpace(s)
		if s == "" {
			return fmt.Errorf("不能留空")
		}
		if findMonitoringTarget(tf, s) != nil {
			return fmt.Errorf("target %q 已存在", s)
		}
		return nil
	}
	spec := tui.InputSpec{ScreenID: "mon.target.add.name", Title: "新 target 名稱(唯一，例如 nas01)", Validate: validate}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushMonitoringTargetsMenu(r, dir, "")
		}
		return pushMonitoringTargetAddAddress(r, dir, strings.TrimSpace(m.Value()))
	})
}

func pushMonitoringTargetAddAddress(r *editRouterModel, dir, name string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "mon.target.add.address", Title: "address(host:port，例如 nas01.pilot.internal:9633)"}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushMonitoringTargetsMenu(r, dir, "")
		}
		return pushMonitoringTargetAddProfile(r, dir, name, strings.TrimSpace(m.Value()))
	})
}

// pushMonitoringTargetAddProfile offers a SELECT list of existing profiles,
// never free text (spec.md §35's explicit requirement — a target must not
// be able to name an unvalidated profile string).
func pushMonitoringTargetAddProfile(r *editRouterModel, dir, name, address string) tea.Cmd {
	_, pf, err := loadMonitoring(dir)
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	profileNames := sortedProfileNames(pf)
	if len(profileNames) == 0 {
		return pushMonitoringTargetsMenu(r, dir, "⚠️  目前沒有任何 scrape profile；請先到「Scrape Profiles」新增一個。")
	}
	choices := make([]tui.Choice, len(profileNames)+1)
	for i, p := range profileNames {
		choices[i] = tui.Choice{ID: p, Label: p}
	}
	choices[len(profileNames)] = tui.Choice{ID: "mon.target.add.profile.cancel", Label: "↩  取消"}
	spec := tui.SelectSpec{ScreenID: "mon.target.add.profile", Title: "選一個 scrape profile", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() || m.Selected() == len(profileNames) {
			return pushMonitoringTargetsMenu(r, dir, "")
		}
		return commitMonitoringTargetAdd(r, dir, monitoring.Target{Name: name, Address: address, Profile: profileNames[m.Selected()]})
	})
}

func commitMonitoringTargetAdd(r *editRouterModel, dir string, t monitoring.Target) tea.Cmd {
	tf, pf, err := loadMonitoring(dir)
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	tf.Targets = append(tf.Targets, t)
	res, err := saveMonitoringTargets(dir, tf, pf)
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  存檔失敗：%v", err))
	}
	if !res.OK() {
		return pushMonitoringTargetsMenu(r, dir, formatViolations(res))
	}
	return pushMonitoringTargetDetail(r, dir, t.Name, fmt.Sprintf("✅ 已新增 target %q", t.Name))
}

// ---- target detail + fields ------------------------------------------

func pushMonitoringTargetDetail(r *editRouterModel, dir, name, banner string) tea.Cmd {
	tf, _, err := loadMonitoring(dir)
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	t := findMonitoringTarget(tf, name)
	if t == nil {
		return pushMonitoringTargetsMenu(r, dir, "") // deleted from within a sub-menu
	}
	status := "enabled"
	if !t.IsEnabled() {
		status = "disabled"
	}
	choices := []tui.Choice{
		{ID: "mon.target.detail.address", Label: fmt.Sprintf("address：%s", t.Address)},
		{ID: "mon.target.detail.profile", Label: fmt.Sprintf("profile：%s", t.Profile)},
		{ID: "mon.target.detail.site", Label: fmt.Sprintf("site：%s", displayOrPlaceholder(t.Site))},
		{ID: "mon.target.detail.enabled", Label: fmt.Sprintf("enabled：%s", status)},
		{ID: "mon.target.detail.labels", Label: fmt.Sprintf("labels(共 %d 個)", len(t.Labels))},
		{ID: "mon.target.detail.test", Label: "🔌 測試連線(target test)"},
		{ID: "mon.target.detail.delete", Label: "🗑  刪除這個 target"},
		{ID: "mon.target.detail.back", Label: "↩  返回 target 清單"},
	}
	spec := tui.SelectSpec{ScreenID: "mon.target.detail", Title: fmt.Sprintf("Target %q — 選要編輯的項目", name), Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushMonitoringTargetsMenu(r, dir, "")
		}
		switch m.Selected() {
		case 0:
			return pushMonitoringTargetFieldAddress(r, dir, name)
		case 1:
			return pushMonitoringTargetFieldProfile(r, dir, name)
		case 2:
			return pushMonitoringTargetFieldSite(r, dir, name)
		case 3:
			return pushMonitoringTargetFieldEnabled(r, dir, name)
		case 4:
			return pushMonitoringTargetLabels(r, dir, name, "")
		case 5:
			return pushMonitoringTargetTestScreen(r, dir, name)
		case 6:
			return pushMonitoringTargetDeleteConfirm(r, dir, name)
		case 7:
			return pushMonitoringTargetsMenu(r, dir, "")
		}
		return nil
	})
}

func pushMonitoringTargetFieldAddress(r *editRouterModel, dir, name string) tea.Cmd {
	tf, pf, err := loadMonitoring(dir)
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	idx := findMonitoringTargetIndex(tf, name)
	if idx < 0 {
		return pushMonitoringTargetsMenu(r, dir, "")
	}
	spec := tui.InputSpec{ScreenID: "mon.target.field.address", Title: "address(host:port)", Default: tf.Targets[idx].Address}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushMonitoringTargetDetail(r, dir, name, "")
		}
		tf.Targets[idx].Address = strings.TrimSpace(m.Value())
		res, err := saveMonitoringTargets(dir, tf, pf)
		if err != nil {
			return pushMonitoringTargetDetail(r, dir, name, fmt.Sprintf("⚠️  存檔失敗：%v", err))
		}
		if !res.OK() {
			return pushMonitoringTargetDetail(r, dir, name, formatViolations(res))
		}
		return pushMonitoringTargetDetail(r, dir, name, "")
	})
}

func pushMonitoringTargetFieldProfile(r *editRouterModel, dir, name string) tea.Cmd {
	tf, pf, err := loadMonitoring(dir)
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	idx := findMonitoringTargetIndex(tf, name)
	if idx < 0 {
		return pushMonitoringTargetsMenu(r, dir, "")
	}
	profileNames := sortedProfileNames(pf)
	if len(profileNames) == 0 {
		return pushMonitoringTargetDetail(r, dir, name, "⚠️  目前沒有任何 scrape profile可選；請先到「Scrape Profiles」新增一個。")
	}
	choices := make([]tui.Choice, len(profileNames)+1)
	for i, p := range profileNames {
		choices[i] = tui.Choice{ID: p, Label: p}
	}
	choices[len(profileNames)] = tui.Choice{ID: "mon.target.field.profile.cancel", Label: "↩  取消"}
	spec := tui.SelectSpec{ScreenID: "mon.target.field.profile", Title: "選一個 scrape profile", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() || m.Selected() == len(profileNames) {
			return pushMonitoringTargetDetail(r, dir, name, "")
		}
		tf.Targets[idx].Profile = profileNames[m.Selected()]
		res, err := saveMonitoringTargets(dir, tf, pf)
		if err != nil {
			return pushMonitoringTargetDetail(r, dir, name, fmt.Sprintf("⚠️  存檔失敗：%v", err))
		}
		if !res.OK() {
			return pushMonitoringTargetDetail(r, dir, name, formatViolations(res))
		}
		return pushMonitoringTargetDetail(r, dir, name, "")
	})
}

func pushMonitoringTargetFieldSite(r *editRouterModel, dir, name string) tea.Cmd {
	tf, pf, err := loadMonitoring(dir)
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	idx := findMonitoringTargetIndex(tf, name)
	if idx < 0 {
		return pushMonitoringTargetsMenu(r, dir, "")
	}
	spec := tui.InputSpec{ScreenID: "mon.target.field.site", Title: "site(邏輯站台標籤，選填)", Default: tf.Targets[idx].Site}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushMonitoringTargetDetail(r, dir, name, "")
		}
		tf.Targets[idx].Site = strings.TrimSpace(m.Value())
		res, err := saveMonitoringTargets(dir, tf, pf)
		if err != nil {
			return pushMonitoringTargetDetail(r, dir, name, fmt.Sprintf("⚠️  存檔失敗：%v", err))
		}
		if !res.OK() {
			return pushMonitoringTargetDetail(r, dir, name, formatViolations(res))
		}
		return pushMonitoringTargetDetail(r, dir, name, "")
	})
}

func pushMonitoringTargetFieldEnabled(r *editRouterModel, dir, name string) tea.Cmd {
	tf, pf, err := loadMonitoring(dir)
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	idx := findMonitoringTargetIndex(tf, name)
	if idx < 0 {
		return pushMonitoringTargetsMenu(r, dir, "")
	}
	choices := []tui.Choice{
		{ID: "mon.target.field.enabled.true", Label: "enabled"},
		{ID: "mon.target.field.enabled.false", Label: "disabled"},
	}
	spec := tui.SelectSpec{ScreenID: "mon.target.field.enabled", Title: fmt.Sprintf("target %q 的狀態", name), Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushMonitoringTargetDetail(r, dir, name, "")
		}
		enabled := m.Selected() == 0
		tf.Targets[idx].Enabled = &enabled
		res, err := saveMonitoringTargets(dir, tf, pf)
		if err != nil {
			return pushMonitoringTargetDetail(r, dir, name, fmt.Sprintf("⚠️  存檔失敗：%v", err))
		}
		if !res.OK() {
			return pushMonitoringTargetDetail(r, dir, name, formatViolations(res))
		}
		return pushMonitoringTargetDetail(r, dir, name, "")
	})
}

// ---- target labels (key=value CRUD, same shape as pushExtraVarsMenu) ----

func pushMonitoringTargetLabels(r *editRouterModel, dir, name, banner string) tea.Cmd {
	tf, err := monitoring.LoadTargets(monitoringTargetsPath(dir))
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	idx := findMonitoringTargetIndex(tf, name)
	if idx < 0 {
		return pushMonitoringTargetsMenu(r, dir, "")
	}
	if tf.Targets[idx].Labels == nil {
		tf.Targets[idx].Labels = map[string]string{}
	}
	labels := tf.Targets[idx].Labels
	keys := sortedKeysOf(labels)
	choices := make([]tui.Choice, 0, len(keys)+2)
	for _, k := range keys {
		choices = append(choices, tui.Choice{ID: k, Label: fmt.Sprintf("%s = %s", k, labels[k])})
	}
	choices = append(choices,
		tui.Choice{ID: "mon.target.labels.add", Label: "➕ 新增 label"},
		tui.Choice{ID: "mon.target.labels.back", Label: "↩  返回"},
	)
	spec := tui.SelectSpec{ScreenID: "mon.target.labels", Title: fmt.Sprintf("target %q 的 labels", name), Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushMonitoringTargetDetail(r, dir, name, "")
		}
		idx := len(choices) - 1
		switch {
		case m.Selected() == idx:
			return pushMonitoringTargetDetail(r, dir, name, "")
		case m.Selected() == idx-1:
			return pushMonitoringTargetLabelAddKey(r, dir, name)
		default:
			return pushMonitoringTargetLabelAction(r, dir, name, keys[m.Selected()])
		}
	})
}

func pushMonitoringTargetLabelAddKey(r *editRouterModel, dir, name string) tea.Cmd {
	tf, _, err := loadMonitoring(dir)
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	t := findMonitoringTarget(tf, name)
	validate := func(s string) error {
		s = strings.TrimSpace(s)
		if s == "" {
			return fmt.Errorf("不能留空")
		}
		if t != nil {
			if _, ok := t.Labels[s]; ok {
				return fmt.Errorf("label %q 已存在，請從清單選它來修改", s)
			}
		}
		for _, reserved := range monitoring.ReservedLabels {
			if s == reserved {
				return fmt.Errorf("label %q 是保留字，由 Pilot 自動加上", s)
			}
		}
		return nil
	}
	spec := tui.InputSpec{Title: "label 名稱", Validate: validate}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushMonitoringTargetLabels(r, dir, name, "")
		}
		return pushMonitoringTargetLabelAddValue(r, dir, name, strings.TrimSpace(m.Value()))
	})
}

func pushMonitoringTargetLabelAddValue(r *editRouterModel, dir, name, key string) tea.Cmd {
	spec := tui.InputSpec{Title: "label 值"}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushMonitoringTargetLabels(r, dir, name, "")
		}
		tf, pf, err := loadMonitoring(dir)
		if err != nil {
			return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
		}
		idx := findMonitoringTargetIndex(tf, name)
		if idx < 0 {
			return pushMonitoringTargetsMenu(r, dir, "")
		}
		if tf.Targets[idx].Labels == nil {
			tf.Targets[idx].Labels = map[string]string{}
		}
		tf.Targets[idx].Labels[key] = m.Value()
		res, err := saveMonitoringTargets(dir, tf, pf)
		if err != nil {
			return pushMonitoringTargetLabels(r, dir, name, fmt.Sprintf("⚠️  存檔失敗：%v", err))
		}
		if !res.OK() {
			return pushMonitoringTargetLabels(r, dir, name, formatViolations(res))
		}
		return pushMonitoringTargetLabels(r, dir, name, "")
	})
}

func pushMonitoringTargetLabelAction(r *editRouterModel, dir, name, key string) tea.Cmd {
	tf, _, err := loadMonitoring(dir)
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	t := findMonitoringTarget(tf, name)
	val := ""
	if t != nil {
		val = t.Labels[key]
	}
	choices := []tui.Choice{
		{ID: "mon.target.label_action.edit", Label: "修改值"},
		{ID: "mon.target.label_action.delete", Label: "刪除"},
		{ID: "mon.target.label_action.back", Label: "返回"},
	}
	spec := tui.SelectSpec{ScreenID: "mon.target.label_action", Title: fmt.Sprintf("label %s = %s", key, val), Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushMonitoringTargetLabels(r, dir, name, "")
		}
		switch m.Selected() {
		case 0:
			return pushMonitoringTargetLabelEditValue(r, dir, name, key)
		case 1:
			tf, pf, err := loadMonitoring(dir)
			if err != nil {
				return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
			}
			idx := findMonitoringTargetIndex(tf, name)
			if idx >= 0 {
				delete(tf.Targets[idx].Labels, key)
			}
			if _, err := saveMonitoringTargets(dir, tf, pf); err != nil {
				return pushMonitoringTargetLabels(r, dir, name, fmt.Sprintf("⚠️  存檔失敗：%v", err))
			}
			return pushMonitoringTargetLabels(r, dir, name, "")
		case 2:
			return pushMonitoringTargetLabels(r, dir, name, "")
		}
		return nil
	})
}

func pushMonitoringTargetLabelEditValue(r *editRouterModel, dir, name, key string) tea.Cmd {
	tf, _, err := loadMonitoring(dir)
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	t := findMonitoringTarget(tf, name)
	cur := ""
	if t != nil {
		cur = t.Labels[key]
	}
	spec := tui.InputSpec{Title: fmt.Sprintf("%s 的新值", key), Default: cur}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushMonitoringTargetLabelAction(r, dir, name, key)
		}
		tf, pf, err := loadMonitoring(dir)
		if err != nil {
			return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
		}
		idx := findMonitoringTargetIndex(tf, name)
		if idx < 0 {
			return pushMonitoringTargetsMenu(r, dir, "")
		}
		tf.Targets[idx].Labels[key] = m.Value()
		if _, err := saveMonitoringTargets(dir, tf, pf); err != nil {
			return pushMonitoringTargetLabels(r, dir, name, fmt.Sprintf("⚠️  存檔失敗：%v", err))
		}
		return pushMonitoringTargetLabels(r, dir, name, "")
	})
}

// ---- target test (read-only, spec.md §29-31) -------------------------

func pushMonitoringTargetTestScreen(r *editRouterModel, dir, name string) tea.Cmd {
	tf, pf, err := loadMonitoring(dir)
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	rt, ok := monitoring.Resolve(tf, pf, name)
	if !ok {
		return pushMonitoringTargetDetail(r, dir, name, "⚠️  無法解析 target/profile，請先確認 profile 存在。")
	}
	if rt.Profile.AuthRef != "" {
		return pushMonitoringTargetDetail(r, dir, name, fmt.Sprintf("⚠️  profile %q 需要 authRef %q — TUI 尚不支援輸入密碼測試，請改用 `pilot monitoring target test %s` CLI（PILOT_MONITORING_AUTH_PASSWORD 環境變數）。", rt.Target.Profile, rt.Profile.AuthRef, name))
	}
	report := monitoring.TestConnectivity(context.Background(), rt, nil, monitoring.DefaultTestOptions())
	var b strings.Builder
	for _, step := range report.Steps {
		mark := "PASS"
		if !step.Pass {
			mark = "FAIL"
		}
		fmt.Fprintf(&b, "[%s] %s -> %s\n", mark, step.Name, step.Detail)
	}
	result := "PASS"
	if !report.Pass {
		result = "FAIL"
	}
	fmt.Fprintf(&b, "Result: %s", result)
	return pushMonitoringTargetDetail(r, dir, name, b.String())
}

// ---- target delete ---------------------------------------------------

func pushMonitoringTargetDeleteConfirm(r *editRouterModel, dir, name string) tea.Cmd {
	question := fmt.Sprintf("確定要刪除 target %q 嗎？(只移除 registry，不會對遠端主機做任何操作)", name)
	spec := tui.ConfirmSpec{ScreenID: "mon.target.delete.confirm", Title: question, Default: false}
	return r.transitionTo(r.uiFactory().Confirm(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.ConfirmScreen)
		if !m.Value() {
			return pushMonitoringTargetDetail(r, dir, name, "")
		}
		tf, _, err := loadMonitoring(dir)
		if err != nil {
			return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
		}
		idx := findMonitoringTargetIndex(tf, name)
		if idx >= 0 {
			tf.Targets = append(tf.Targets[:idx], tf.Targets[idx+1:]...)
		}
		if err := monitoring.SaveTargets(monitoringTargetsPath(dir), tf); err != nil {
			return pushMonitoringTargetsMenu(r, dir, fmt.Sprintf("⚠️  存檔失敗：%v", err))
		}
		return pushMonitoringTargetsMenu(r, dir, fmt.Sprintf("已刪除 target %q", name))
	})
}

// ---- shared helpers -----------------------------------------------------

func findMonitoringTargetIndex(tf monitoring.TargetFile, name string) int {
	for i, t := range tf.Targets {
		if t.Name == name {
			return i
		}
	}
	return -1
}

func sortedProfileNames(pf monitoring.ProfileFile) []string {
	names := make([]string, 0, len(pf.Profiles))
	for name := range pf.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
