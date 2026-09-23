package cmd

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/kjelly/pilot/internal/tui"
)

// Top-menu screen for prometheus_host_annotation_labels: which hosts.yml
// annotations become node/DCGM Prometheus target labels. Every add/edit/
// delete is validated (prometheus_annotation_labels.go, same rules as the
// playbook gates) and written to group_vars/prometheus.yml immediately —
// the same save-on-action shape as pushAlertmanagerReceiverManager.

const prometheusLabelsSavedBanner = "✅ 已更新 group_vars/prometheus.yml；請執行 pilot deploy 套用 prometheus。改動會讓受影響主機的 series 換 label set。"

func pushPrometheusAnnotationLabelsManager(r *editRouterModel, dir, banner string) tea.Cmd {
	m, err := loadPrometheusAnnotationLabels(dir)
	if err != nil {
		return pushTopMenu(r, dir, fmt.Sprintf("⚠️  無法讀取 %s：%v(請直接修正檔案)", prometheusAnnotationLabelsRelPath, err))
	}
	keys := sortedKeysOf(m)
	choices := make([]tui.Choice, 0, len(keys)+3)
	for _, k := range keys {
		choices = append(choices, tui.Choice{ID: "prometheus_labels.entry." + k, Label: fmt.Sprintf("%s → %s", k, m[k])})
	}
	choices = append(choices, tui.Choice{ID: "prometheus_labels.add", Label: "➕ 新增對應(註解 key → label)"})
	if len(keys) > 0 {
		choices = append(choices, tui.Choice{ID: "prometheus_labels.clear", Label: "🗑  全部清除(停用，metrics 只保留 pilot_host)"})
	}
	choices = append(choices, tui.Choice{ID: "prometheus_labels.back", Label: "↩  返回"})

	state := "未啟用(metrics 只有 pilot_host)"
	if len(keys) > 0 {
		state = fmt.Sprintf("%d 個對應", len(keys))
	}
	title := fmt.Sprintf("Prometheus 主機註解 labels（%s，目前：%s）—— 列出的 hosts.yml 註解會成為 node/DCGM metrics 的 label；未列出的不會進 metrics。只選低變動欄位(location/project/owner…)，值會出現在 Prometheus/Grafana/告警通知", prometheusAnnotationLabelsRelPath, state)
	spec := tui.SelectSpec{ScreenID: "prometheus_labels", Title: title, Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		sel := s.(tui.SelectScreen)
		if sel.Canceled() {
			return pushTopMenu(r, dir, "")
		}
		idx := sel.Selected()
		switch {
		case idx < len(keys):
			return pushPrometheusAnnotationLabelAction(r, dir, keys[idx])
		case choices[idx].ID == "prometheus_labels.add":
			return pushPrometheusAnnotationLabelAddSource(r, dir)
		case choices[idx].ID == "prometheus_labels.clear":
			if err := savePrometheusAnnotationLabels(dir, map[string]string{}); err != nil {
				return pushPrometheusAnnotationLabelsManager(r, dir, fmt.Sprintf("⚠️  無法儲存：%v", err))
			}
			return pushPrometheusAnnotationLabelsManager(r, dir, prometheusLabelsSavedBanner)
		default:
			return pushTopMenu(r, dir, "")
		}
	})
}

// pushPrometheusAnnotationLabelAddSource picks the annotation key: the
// keys already used in hosts.yml (minus mapped ones), or manual entry.
func pushPrometheusAnnotationLabelAddSource(r *editRouterModel, dir string) tea.Cmd {
	m, err := loadPrometheusAnnotationLabels(dir)
	if err != nil {
		return pushPrometheusAnnotationLabelsManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	var candidates []string
	for _, k := range workspaceAnnotationKeys(dir) {
		if _, mapped := m[k]; !mapped {
			candidates = append(candidates, k)
		}
	}
	if len(candidates) == 0 {
		return pushPrometheusAnnotationLabelManualSource(r, dir, m)
	}
	choices := make([]tui.Choice, 0, len(candidates)+2)
	for _, k := range candidates {
		choices = append(choices, tui.Choice{ID: "prometheus_labels.source." + k, Label: k})
	}
	choices = append(choices,
		tui.Choice{ID: "prometheus_labels.source.manual", Label: "✏️  手動輸入註解 key"},
		tui.Choice{ID: "prometheus_labels.source.back", Label: "↩  返回"},
	)
	spec := tui.SelectSpec{ScreenID: "prometheus_labels.source", Title: "要把哪個 hosts.yml 註解變成 label？(清單來自目前 hosts.yml 用到的註解 key)", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		sel := s.(tui.SelectScreen)
		if sel.Canceled() || sel.Selected() == len(choices)-1 {
			return pushPrometheusAnnotationLabelsManager(r, dir, "")
		}
		if sel.Selected() == len(choices)-2 {
			return pushPrometheusAnnotationLabelManualSource(r, dir, m)
		}
		return pushPrometheusAnnotationLabelName(r, dir, candidates[sel.Selected()], false)
	})
}

func pushPrometheusAnnotationLabelManualSource(r *editRouterModel, dir string, current map[string]string) tea.Cmd {
	validate := func(s string) error {
		s = strings.TrimSpace(s)
		if _, mapped := current[s]; mapped {
			return fmt.Errorf("註解 %q 已有對應，請從清單選它來修改", s)
		}
		return validatePrometheusAnnotationLabel(s, defaultPrometheusAnnotationLabel(s))
	}
	spec := tui.InputSpec{ScreenID: "prometheus_labels.source_key", Title: "註解 key(跟 hosts.yml annotations 的 key 相同，例如 location、project)", Validate: validate}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		in := s.(tui.InputScreen)
		if in.Canceled() {
			return pushPrometheusAnnotationLabelsManager(r, dir, "")
		}
		return pushPrometheusAnnotationLabelName(r, dir, strings.TrimSpace(in.Value()), false)
	})
}

// pushPrometheusAnnotationLabelName asks for the label name (default
// pilot_<key>) and saves. editing=true replaces an existing mapping.
func pushPrometheusAnnotationLabelName(r *editRouterModel, dir, source string, editing bool) tea.Cmd {
	m, err := loadPrometheusAnnotationLabels(dir)
	if err != nil {
		return pushPrometheusAnnotationLabelsManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	def := defaultPrometheusAnnotationLabel(source)
	if cur, ok := m[source]; ok {
		def = cur
	}
	validate := func(s string) error {
		next := copyStringMap(m)
		next[source] = strings.TrimSpace(s)
		return validatePrometheusAnnotationLabels(next)
	}
	title := fmt.Sprintf("註解 %q 對應的 Prometheus label 名稱(必須是 pilot_ 開頭，小寫/數字/_)", source)
	spec := tui.InputSpec{ScreenID: "prometheus_labels.label", Title: title, Default: def, Validate: validate}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		in := s.(tui.InputScreen)
		if in.Canceled() {
			if editing {
				return pushPrometheusAnnotationLabelAction(r, dir, source)
			}
			return pushPrometheusAnnotationLabelsManager(r, dir, "")
		}
		next := copyStringMap(m)
		next[source] = strings.TrimSpace(in.Value())
		if err := savePrometheusAnnotationLabels(dir, next); err != nil {
			return pushPrometheusAnnotationLabelsManager(r, dir, fmt.Sprintf("⚠️  無法儲存：%v", err))
		}
		return pushPrometheusAnnotationLabelsManager(r, dir, prometheusLabelsSavedBanner)
	})
}

func pushPrometheusAnnotationLabelAction(r *editRouterModel, dir, source string) tea.Cmd {
	m, err := loadPrometheusAnnotationLabels(dir)
	if err != nil {
		return pushPrometheusAnnotationLabelsManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	choices := []tui.Choice{
		{ID: "prometheus_labels.action.edit", Label: "修改 label 名稱"},
		{ID: "prometheus_labels.action.delete", Label: "刪除這個對應"},
		{ID: "prometheus_labels.action.back", Label: "返回"},
	}
	title := fmt.Sprintf("註解 %s → label %s", source, m[source])
	spec := tui.SelectSpec{ScreenID: "prometheus_labels.action", Title: title, Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		sel := s.(tui.SelectScreen)
		if sel.Canceled() {
			return pushPrometheusAnnotationLabelsManager(r, dir, "")
		}
		switch sel.Selected() {
		case 0:
			return pushPrometheusAnnotationLabelName(r, dir, source, true)
		case 1:
			next := copyStringMap(m)
			delete(next, source)
			if err := savePrometheusAnnotationLabels(dir, next); err != nil {
				return pushPrometheusAnnotationLabelsManager(r, dir, fmt.Sprintf("⚠️  無法儲存：%v", err))
			}
			return pushPrometheusAnnotationLabelsManager(r, dir, prometheusLabelsSavedBanner)
		default:
			return pushPrometheusAnnotationLabelsManager(r, dir, "")
		}
	})
}

func copyStringMap(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
