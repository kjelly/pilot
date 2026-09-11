// edit_automation_driver_annotations.go drives the "註解 / 資產資訊" (host
// annotations) CRUD screens (pushAnnotationsMenu et al., edit_tui_annotations.go)
// for semantic edit-scenario actions — add_annotation, edit_annotation,
// delete_annotation. Mirrors edit_automation_driver_extravars.go's shape
// exactly, minus the secret/value_env branch: annotations are never a
// secret-bearing field (spec.md §14.2), so every value is typed as plain
// text and always presented.
package cmd

import "fmt"

func (d *automationDriver) addAnnotation(r *editRouterModel, host, key, value string) error {
	if err := d.ensureHostMenu(r, host); err != nil {
		return err
	}
	if err := d.choose(r, "註解 / 資產資訊"); err != nil {
		return err
	}
	if err := d.choose(r, "新增註解"); err != nil {
		return err
	}
	if err := d.typeText(r, key, false); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.typeText(r, value, false); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	d.present(r, fmt.Sprintf("新增註解：%s", key))
	return d.choose(r, "返回")
}

// editAnnotation navigates to the existing "key = value" row by matching on
// "key = " rather than the bare key, mirroring editExtraVar's own collision-
// avoidance note: a bare key could otherwise collide with the *value* text
// of a different entry.
func (d *automationDriver) editAnnotation(r *editRouterModel, host, key, value string) error {
	if err := d.ensureHostMenu(r, host); err != nil {
		return err
	}
	if err := d.choose(r, "註解 / 資產資訊"); err != nil {
		return err
	}
	if err := d.choose(r, key+" = "); err != nil {
		return err
	}
	if err := d.choose(r, "修改值"); err != nil {
		return err
	}
	if err := d.typeText(r, value, true); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	d.present(r, fmt.Sprintf("修改註解：%s", key))
	return d.choose(r, "返回")
}

func (d *automationDriver) deleteAnnotation(r *editRouterModel, host, key string) error {
	if err := d.ensureHostMenu(r, host); err != nil {
		return err
	}
	if err := d.choose(r, "註解 / 資產資訊"); err != nil {
		return err
	}
	if err := d.choose(r, key+" = "); err != nil {
		return err
	}
	// No confirm here — matches pushAnnotationActionMenu's immediate delete.
	if err := d.choose(r, "刪除"); err != nil {
		return err
	}
	d.present(r, fmt.Sprintf("刪除註解：%s", key))
	return d.choose(r, "返回")
}
