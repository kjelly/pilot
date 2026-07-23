// edit_automation_driver_extravars.go drives the "其他變數" (extra host
// vars) CRUD screens (pushExtraVarsMenu et al., edit_tui.go) for semantic
// edit-scenario actions — add_extra_var, edit_extra_var, delete_extra_var.
//
// Every action here finishes by returning to the host menu (mirroring
// setRoleChecked's "✅ 完成" tail) rather than leaving the router sitting on
// the 其他變數 submenu — ensureHostMenu only knows how to resolve from the
// host list or the host menu itself, not from an arbitrary submenu, so a
// second extra-var action in the same scenario would otherwise have nowhere
// to navigate from.
package cmd

func (d *automationDriver) addExtraVar(r *editRouterModel, host, key, value string, secret bool) error {
	if err := d.ensureHostMenu(r, host); err != nil {
		return err
	}
	if err := d.choose(r, "其他變數"); err != nil {
		return err
	}
	if err := d.choose(r, "新增變數"); err != nil {
		return err
	}
	if err := d.typeText(r, key, false); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.typeSecretOrPlain(r, value, secret, false); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	return d.choose(r, "返回")
}

// editExtraVar navigates to the existing "key = value" row by matching on
// "key = " rather than the bare key — a bare key could otherwise collide
// with the *value* text of a different entry (e.g. a key named "region"
// matching inside another entry's "site = region-west" row).
func (d *automationDriver) editExtraVar(r *editRouterModel, host, key, value string, secret bool) error {
	if err := d.ensureHostMenu(r, host); err != nil {
		return err
	}
	if err := d.choose(r, "其他變數"); err != nil {
		return err
	}
	if err := d.choose(r, key+" = "); err != nil {
		return err
	}
	if err := d.choose(r, "修改值"); err != nil {
		return err
	}
	if err := d.typeSecretOrPlain(r, value, secret, true); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	return d.choose(r, "返回")
}

func (d *automationDriver) deleteExtraVar(r *editRouterModel, host, key string) error {
	if err := d.ensureHostMenu(r, host); err != nil {
		return err
	}
	if err := d.choose(r, "其他變數"); err != nil {
		return err
	}
	if err := d.choose(r, key+" = "); err != nil {
		return err
	}
	// No confirm here — matches pushExtraVarActionMenu's immediate delete.
	if err := d.choose(r, "刪除"); err != nil {
		return err
	}
	return d.choose(r, "返回")
}
