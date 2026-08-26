// edit_automation_driver_monitoring.go is edit_automation_driver_internal_endpoint.go's
// counterpart for the Monitoring screens (edit_tui_monitoring.go /
// edit_tui_monitoring_profiles.go): it turns each semantic monitoring
// action (spec.md §52) into scripted keypresses against the real
// `editRouterModel`, exactly like every other feature's driver file — never
// a separate mock execution path.
package cmd

import (
	"fmt"
	"strings"

	"github.com/kjelly/pilot/internal/tui"
)

// ---- navigation chains (ensure*) ----------------------------------------

func (d *automationDriver) ensureMonitoringManager(r *editRouterModel) error {
	for attempts := 0; attempts < 8; attempts++ {
		switch automationScreenID(r) {
		case "mon.manager":
			return nil
		case "edit.top":
			if err := d.choose(r, "monitoring"); err != nil {
				return err
			}
		default:
			if err := d.choose(r, "返回"); err != nil {
				return fmt.Errorf("cannot navigate to monitoring manager from %s screen: %w", automationScreenID(r), err)
			}
		}
	}
	return fmt.Errorf("could not resolve navigation to monitoring manager")
}

func (d *automationDriver) ensureMonitoringTargetsList(r *editRouterModel) error {
	for attempts := 0; attempts < 8; attempts++ {
		switch automationScreenID(r) {
		case "mon.target.list":
			return nil
		case "edit.top":
			if err := d.choose(r, "monitoring"); err != nil {
				return err
			}
		case "mon.manager":
			if err := d.choose(r, "Exporter Targets"); err != nil {
				return err
			}
		default:
			if err := d.choose(r, "返回"); err != nil {
				return fmt.Errorf("cannot navigate to monitoring targets list from %s screen: %w", automationScreenID(r), err)
			}
		}
	}
	return fmt.Errorf("could not resolve navigation to monitoring targets list")
}

func (d *automationDriver) ensureMonitoringProfilesList(r *editRouterModel) error {
	for attempts := 0; attempts < 8; attempts++ {
		switch automationScreenID(r) {
		case "mon.profile.list":
			return nil
		case "edit.top":
			if err := d.choose(r, "monitoring"); err != nil {
				return err
			}
		case "mon.manager":
			if err := d.choose(r, "Scrape Profiles"); err != nil {
				return err
			}
		default:
			if err := d.choose(r, "返回"); err != nil {
				return fmt.Errorf("cannot navigate to monitoring profiles list from %s screen: %w", automationScreenID(r), err)
			}
		}
	}
	return fmt.Errorf("could not resolve navigation to monitoring profiles list")
}

// titleNamesMonitoringEntity reports whether title is pushMonitoringTarget-
// /ProfileDetail's title for exactly this name — `<kind> "name" — ...`.
func titleNamesMonitoringEntity(title, kind, name string) bool {
	prefix := fmt.Sprintf("%s %q ", kind, name)
	return len(title) >= len(prefix) && title[:len(prefix)] == prefix
}

func (d *automationDriver) ensureMonitoringTargetDetail(r *editRouterModel, name string) error {
	if automationScreenID(r) == "mon.target.detail" {
		if st := automationState(r); st.Kind == tui.ScreenSelect && titleNamesMonitoringEntity(st.Title, "Target", name) {
			return nil
		}
		if err := d.choose(r, "返回"); err != nil {
			return err
		}
	}
	if err := d.ensureMonitoringTargetsList(r); err != nil {
		return err
	}
	return d.choose(r, "🎯 "+name)
}

func (d *automationDriver) ensureMonitoringProfileDetail(r *editRouterModel, name string) error {
	if automationScreenID(r) == "mon.profile.detail" {
		if st := automationState(r); st.Kind == tui.ScreenSelect && titleNamesMonitoringEntity(st.Title, "Profile", name) {
			return nil
		}
		if err := d.choose(r, "返回"); err != nil {
			return err
		}
	}
	if err := d.ensureMonitoringProfilesList(r); err != nil {
		return err
	}
	return d.choose(r, "📋 "+name)
}

// ---- target actions -------------------------------------------------------

func (d *automationDriver) createMonitoringTarget(r *editRouterModel, name, address, profile string) error {
	if err := d.ensureMonitoringTargetsList(r); err != nil {
		return err
	}
	if err := d.choose(r, "新增 target"); err != nil {
		return err
	}
	if err := d.typeText(r, name, false); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.typeText(r, address, false); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	// pushMonitoringTargetAddProfile is a select list of real profile
	// names, never free text (spec.md §35).
	return d.choose(r, profile)
}

func (d *automationDriver) setMonitoringTargetAddress(r *editRouterModel, name, address string) error {
	if err := d.ensureMonitoringTargetDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "address"); err != nil {
		return err
	}
	if err := d.typeText(r, address, true); err != nil {
		return err
	}
	return d.enter(r)
}

func (d *automationDriver) setMonitoringTargetProfile(r *editRouterModel, name, profile string) error {
	if err := d.ensureMonitoringTargetDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "profile"); err != nil {
		return err
	}
	return d.choose(r, profile)
}

func (d *automationDriver) setMonitoringTargetSite(r *editRouterModel, name, site string) error {
	if err := d.ensureMonitoringTargetDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "site"); err != nil {
		return err
	}
	if err := d.typeText(r, site, true); err != nil {
		return err
	}
	return d.enter(r)
}

func (d *automationDriver) setMonitoringTargetEnabled(r *editRouterModel, name string, enabled bool) error {
	if err := d.ensureMonitoringTargetDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "enabled"); err != nil {
		return err
	}
	if enabled {
		return d.choose(r, "enabled")
	}
	return d.choose(r, "disabled")
}

// setMonitoringTargetLabel adds or updates one label (add and edit share the
// same underlying map write, so one action covers both — the TUI itself
// only distinguishes them by whether the key already exists, same as
// pushMonitoringTargetLabelAddKey/-EditValue).
func (d *automationDriver) setMonitoringTargetLabel(r *editRouterModel, name, key, value string) error {
	if err := d.ensureMonitoringTargetDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "labels"); err != nil {
		return err
	}
	if err := d.choose(r, key); err == nil {
		// key already exists -> action menu -> "修改值"
		if err := d.choose(r, "修改值"); err != nil {
			return err
		}
		if err := d.typeText(r, value, true); err != nil {
			return err
		}
		return d.enter(r)
	}
	if err := d.choose(r, "新增 label"); err != nil {
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
	return d.enter(r)
}

func (d *automationDriver) deleteMonitoringTarget(r *editRouterModel, name string) error {
	if err := d.ensureMonitoringTargetDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "刪除這個 target"); err != nil {
		return err
	}
	return d.confirmYesNo(r, true)
}

// ---- profile actions --------------------------------------------------

func (d *automationDriver) createMonitoringProfile(r *editRouterModel, name, jobName string) error {
	if err := d.ensureMonitoringProfilesList(r); err != nil {
		return err
	}
	if err := d.choose(r, "新增 profile"); err != nil {
		return err
	}
	if err := d.typeText(r, name, false); err != nil {
		return err
	}
	if err := d.enter(r); err != nil {
		return err
	}
	if err := d.typeText(r, jobName, false); err != nil {
		return err
	}
	return d.enter(r)
}

func (d *automationDriver) setMonitoringProfileJobName(r *editRouterModel, name, jobName string) error {
	if err := d.ensureMonitoringProfileDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "jobName"); err != nil {
		return err
	}
	if err := d.typeText(r, jobName, true); err != nil {
		return err
	}
	return d.enter(r)
}

func (d *automationDriver) setMonitoringProfileScheme(r *editRouterModel, name, scheme string) error {
	if err := d.ensureMonitoringProfileDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "scheme"); err != nil {
		return err
	}
	return d.choose(r, scheme)
}

func (d *automationDriver) setMonitoringProfileMetricsPath(r *editRouterModel, name, metricsPath string) error {
	if err := d.ensureMonitoringProfileDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "metricsPath"); err != nil {
		return err
	}
	switch metricsPath {
	case "/pve":
		return d.choose(r, "PVE exporter：/pve")
	case "/metrics":
		return d.choose(r, "一般 Prometheus exporter：/metrics")
	default:
		if err := d.choose(r, "自訂 metricsPath…"); err != nil {
			return err
		}
		if err := d.typeText(r, metricsPath, true); err != nil {
			return err
		}
		return d.enter(r)
	}
}

// setMonitoringProfileTextField shares one implementation for the three
// plain-text profile fields (scrapeInterval/scrapeTimeout/authRef) — label is
// the detail screen's row label to select
// (e.g. "scrapeInterval"), matching pushMonitoringProfileFieldText's own
// single shared TUI implementation for these fields.
func (d *automationDriver) setMonitoringProfileTextField(r *editRouterModel, name, label, value string) error {
	if err := d.ensureMonitoringProfileDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, label); err != nil {
		return err
	}
	if err := d.typeText(r, value, true); err != nil {
		return err
	}
	return d.enter(r)
}

// setMonitoringProfileTLS sets serverName and/or insecureSkipVerify in one
// action (mirrors setInternalEndpointDNS bundling two fields behind one
// screen). Pass "" for serverName to leave it untouched; pass
// insecureSkipVerify == "" to leave that toggle untouched too.
func (d *automationDriver) setMonitoringProfileTLS(r *editRouterModel, name, serverName, insecureSkipVerify string) error {
	if err := d.ensureMonitoringProfileDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "tls"); err != nil {
		return err
	}
	if serverName != "" {
		if err := d.choose(r, "serverName"); err != nil {
			return err
		}
		if err := d.typeText(r, serverName, true); err != nil {
			return err
		}
		if err := d.enter(r); err != nil {
			return err
		}
	}
	if insecureSkipVerify != "" {
		// pushMonitoringProfileTLSMenu's "insecureSkipVerify" row TOGGLES
		// the current value on select (there is no separate true/false
		// choice) — only press it when the current displayed value
		// disagrees with the requested one.
		want := insecureSkipVerify == "true"
		if monitoringTLSMenuInsecureValue(automationState(r)) != want {
			if err := d.choose(r, "insecureSkipVerify"); err != nil {
				return err
			}
		}
	}
	return d.choose(r, "返回")
}

// monitoringTLSMenuInsecureValue reads the current insecureSkipVerify value
// straight off pushMonitoringProfileTLSMenu's own row label
// ("insecureSkipVerify：true"/"false") rather than re-deriving it from the
// manifest file — the TUI's on-screen state is the single source of truth
// automation drives against everywhere else in this file too.
func monitoringTLSMenuInsecureValue(st tui.AutomationState) bool {
	for _, item := range st.Items {
		if strings.HasPrefix(item.Label, "insecureSkipVerify：") {
			return strings.HasSuffix(item.Label, "true")
		}
	}
	return false
}

func (d *automationDriver) deleteMonitoringProfile(r *editRouterModel, name string) error {
	if err := d.ensureMonitoringProfileDetail(r, name); err != nil {
		return err
	}
	if err := d.choose(r, "刪除這個 profile"); err != nil {
		return err
	}
	return d.confirmYesNo(r, true)
}
