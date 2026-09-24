// edit_automation_driver_prometheus_labels.go drives the "Prometheus 主機註解
// labels" screens (edit_tui_prometheus_labels.go) for the semantic actions
// set_prometheus_annotation_label / delete_prometheus_annotation_label.
// Both start and end on the top menu, like configure_alertmanager_receiver.
package cmd

import (
	"fmt"
	"strings"

	"github.com/kjelly/pilot/internal/tui"
)

const prometheusLabelsTopMenuLabel = "Prometheus 主機註解 labels"

func (d *automationDriver) openPrometheusLabels(r *editRouterModel) error {
	if st := automationState(r); st.Kind != tui.ScreenSelect || st.Title != "要編輯什麼？" {
		return fmt.Errorf("cannot edit Prometheus annotation labels from %s screen", automationScreenID(r))
	}
	return d.choose(r, prometheusLabelsTopMenuLabel)
}

// setPrometheusAnnotationLabel maps annotation key → label, adding the
// mapping or replacing an existing one's label name.
func (d *automationDriver) setPrometheusAnnotationLabel(r *editRouterModel, key, label string) error {
	if err := d.openPrometheusLabels(r); err != nil {
		return err
	}
	if d.hasItemLabel(r, key+" → ") {
		if err := d.chooseByPrefix(r, key+" → "); err != nil {
			return err
		}
		if err := d.choose(r, "修改 label 名稱"); err != nil {
			return err
		}
	} else {
		if err := d.choose(r, "新增對應"); err != nil {
			return err
		}
		// The source screen is a pick-list when hosts.yml already uses
		// annotation keys, or goes straight to manual entry when it does not.
		if automationState(r).Kind == tui.ScreenSelect {
			if d.hasExactItemLabel(r, key) {
				if err := d.chooseExact(r, key); err != nil {
					return err
				}
			} else if err := d.choose(r, "手動輸入註解 key"); err != nil {
				return err
			}
		}
		if automationScreenID(r) == "prometheus_labels.source_key" {
			if err := d.typeText(r, key, false); err != nil {
				return err
			}
			if err := d.enter(r); err != nil {
				return err
			}
		}
	}
	if automationScreenID(r) != "prometheus_labels.label" {
		return fmt.Errorf("annotation key %q was rejected (still on %s screen)", key, automationScreenID(r))
	}
	if err := d.typeText(r, label, true); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if automationScreenID(r) != "prometheus_labels" {
		return fmt.Errorf("label %q for %q was rejected (still on %s screen)", label, key, automationScreenID(r))
	}
	d.present(r, fmt.Sprintf("Prometheus label：%s → %s", key, label))
	return d.choose(r, "↩  返回")
}

func (d *automationDriver) deletePrometheusAnnotationLabel(r *editRouterModel, key string) error {
	if err := d.openPrometheusLabels(r); err != nil {
		return err
	}
	if !d.hasItemLabel(r, key+" → ") {
		return fmt.Errorf("prometheus_host_annotation_labels has no mapping for %q", key)
	}
	if err := d.chooseByPrefix(r, key+" → "); err != nil {
		return err
	}
	if err := d.choose(r, "刪除這個對應"); err != nil {
		return err
	}
	d.present(r, fmt.Sprintf("刪除 Prometheus label 對應：%s", key))
	return d.choose(r, "↩  返回")
}

// chooseExact selects the item whose label is exactly label (choose()
// matches substrings, which would be ambiguous between e.g. "project" and
// "project_code").
func (d *automationDriver) chooseExact(r *editRouterModel, label string) error {
	st := automationState(r)
	if st.Kind != tui.ScreenSelect {
		return fmt.Errorf("cannot choose %q on %s screen", label, automationScreenID(r))
	}
	for i, l := range automationLabels(st.Items) {
		if l == label {
			if err := d.moveCursor(r, i); err != nil {
				return err
			}
			return d.enter(r)
		}
	}
	return fmt.Errorf("no item labelled exactly %q on %s screen", label, automationScreenID(r))
}

// hasItemLabel reports whether any item on the current select screen
// starts with prefix (mapping rows render as "<key> → <label>").
func (d *automationDriver) hasItemLabel(r *editRouterModel, prefix string) bool {
	for _, l := range automationLabels(automationState(r).Items) {
		if strings.HasPrefix(l, prefix) {
			return true
		}
	}
	return false
}

func (d *automationDriver) hasExactItemLabel(r *editRouterModel, label string) bool {
	for _, l := range automationLabels(automationState(r).Items) {
		if l == label {
			return true
		}
	}
	return false
}

// chooseByPrefix selects the single item whose label starts with prefix.
func (d *automationDriver) chooseByPrefix(r *editRouterModel, prefix string) error {
	match := -1
	for i, l := range automationLabels(automationState(r).Items) {
		if strings.HasPrefix(l, prefix) {
			if match >= 0 {
				return fmt.Errorf("more than one item starts with %q on %s screen", prefix, automationScreenID(r))
			}
			match = i
		}
	}
	if match < 0 {
		return fmt.Errorf("no item starts with %q on %s screen", prefix, automationScreenID(r))
	}
	if err := d.moveCursor(r, match); err != nil {
		return err
	}
	return d.enter(r)
}
