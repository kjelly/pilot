// edit_tui_monitoring_profiles.go implements the Scrape Profiles screens of
// the Monitoring manager (edit_tui_monitoring.go) — same load/mutate/
// validate/save discipline, same ScreenID-prefix convention ("mon.profile.").
package cmd

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/kjelly/pilot/internal/monitoring"
	"github.com/kjelly/pilot/internal/tui"
)

// ---- list + add -----------------------------------------------------------

func pushMonitoringProfilesMenu(r *editRouterModel, dir, banner string) tea.Cmd {
	_, pf, err := loadMonitoring(dir)
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	names := sortedProfileNames(pf)

	note := "目前沒有任何 profile。"
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
		choices = append(choices, tui.Choice{ID: name, Label: fmt.Sprintf("📋 %s (job=%s)", name, pf.Profiles[name].JobName)})
	}
	choices = append(choices,
		tui.Choice{ID: "mon.profile.list.add", Label: "➕ 新增 profile"},
		tui.Choice{ID: "mon.profile.list.back", Label: "↩  返回"},
	)
	spec := tui.SelectSpec{ScreenID: "mon.profile.list", Title: fmt.Sprintf("Scrape Profiles — %s", monitoringProfilesPath(dir)), Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushMonitoringManager(r, dir, "")
		}
		switch {
		case m.Selected() < len(names):
			return pushMonitoringProfileDetail(r, dir, names[m.Selected()], "")
		case m.Selected() == len(names):
			return pushMonitoringProfileAddName(r, dir)
		default:
			return pushMonitoringManager(r, dir, "")
		}
	})
}

func pushMonitoringProfileAddName(r *editRouterModel, dir string) tea.Cmd {
	_, pf, err := loadMonitoring(dir)
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	validate := func(s string) error {
		s = strings.TrimSpace(s)
		if s == "" {
			return fmt.Errorf("不能留空")
		}
		if _, ok := pf.Profiles[s]; ok {
			return fmt.Errorf("profile %q 已存在", s)
		}
		return nil
	}
	spec := tui.InputSpec{ScreenID: "mon.profile.add.name", Title: "新 profile 名稱(唯一，例如 storage-exporter)", Validate: validate}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushMonitoringProfilesMenu(r, dir, "")
		}
		return pushMonitoringProfileAddJobName(r, dir, strings.TrimSpace(m.Value()))
	})
}

func pushMonitoringProfileAddJobName(r *editRouterModel, dir, name string) tea.Cmd {
	validate := func(s string) error {
		s = strings.TrimSpace(s)
		if s == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}
	spec := tui.InputSpec{ScreenID: "mon.profile.add.jobname", Title: "Prometheus job_name(必須全域唯一，不可用 prometheus/node)", Validate: validate}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushMonitoringProfilesMenu(r, dir, "")
		}
		tf, pf, err := loadMonitoring(dir)
		if err != nil {
			return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
		}
		if pf.Profiles == nil {
			pf.Profiles = map[string]monitoring.Profile{}
		}
		pf.Profiles[name] = monitoring.Profile{JobName: strings.TrimSpace(m.Value())}
		res, err := saveMonitoringProfiles(dir, tf, pf)
		if err != nil {
			return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  存檔失敗：%v", err))
		}
		if !res.OK() {
			delete(pf.Profiles, name)
			return pushMonitoringProfilesMenu(r, dir, formatViolations(res))
		}
		return pushMonitoringProfileDetail(r, dir, name, fmt.Sprintf("✅ 已新增 profile %q", name))
	})
}

// ---- detail + fields ----------------------------------------------------

func pushMonitoringProfileDetail(r *editRouterModel, dir, name, banner string) tea.Cmd {
	_, pf, err := loadMonitoring(dir)
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	p, ok := pf.Profiles[name]
	if !ok {
		return pushMonitoringProfilesMenu(r, dir, "") // deleted from within a sub-menu
	}
	tlsSummary := "disabled"
	if p.TLS != nil {
		tlsSummary = fmt.Sprintf("serverName=%s insecureSkipVerify=%v", displayOrPlaceholder(p.TLS.ServerName), p.TLS.InsecureSkipVerify)
	}
	choices := []tui.Choice{
		{ID: "mon.profile.detail.jobname", Label: fmt.Sprintf("jobName：%s", p.JobName)},
		{ID: "mon.profile.detail.scheme", Label: fmt.Sprintf("scheme：%s", p.EffectiveScheme())},
		{ID: "mon.profile.detail.metricspath", Label: fmt.Sprintf("metricsPath：%s", p.EffectiveMetricsPath())},
		{ID: "mon.profile.detail.scrapeinterval", Label: fmt.Sprintf("scrapeInterval：%s", displayOrPlaceholder(p.ScrapeInterval))},
		{ID: "mon.profile.detail.scrapetimeout", Label: fmt.Sprintf("scrapeTimeout：%s", displayOrPlaceholder(p.ScrapeTimeout))},
		{ID: "mon.profile.detail.authref", Label: fmt.Sprintf("authRef：%s", displayOrPlaceholder(p.AuthRef))},
		{ID: "mon.profile.detail.tls", Label: fmt.Sprintf("tls：%s", tlsSummary)},
		{ID: "mon.profile.detail.delete", Label: "🗑  刪除這個 profile"},
		{ID: "mon.profile.detail.back", Label: "↩  返回 profile 清單"},
	}
	spec := tui.SelectSpec{ScreenID: "mon.profile.detail", Title: fmt.Sprintf("Profile %q — 選要編輯的項目", name), Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushMonitoringProfilesMenu(r, dir, "")
		}
		switch m.Selected() {
		case 0:
			return pushMonitoringProfileFieldJobName(r, dir, name)
		case 1:
			return pushMonitoringProfileFieldScheme(r, dir, name)
		case 2:
			return pushMonitoringProfileFieldText(r, dir, name, "metrics-path", "metricsPath(留空使用預設 /metrics)", func(p *monitoring.Profile) *string { return &p.MetricsPath })
		case 3:
			return pushMonitoringProfileFieldText(r, dir, name, "scrape-interval", "scrapeInterval(例如 15s；留空使用 Prometheus global 設定)", func(p *monitoring.Profile) *string { return &p.ScrapeInterval })
		case 4:
			return pushMonitoringProfileFieldText(r, dir, name, "scrape-timeout", "scrapeTimeout(例如 10s；留空使用 Prometheus global 設定)", func(p *monitoring.Profile) *string { return &p.ScrapeTimeout })
		case 5:
			return pushMonitoringProfileFieldText(r, dir, name, "auth-ref", "authRef(monitoring_auth 裡的 key；留空表示不需要認證)", func(p *monitoring.Profile) *string { return &p.AuthRef })
		case 6:
			return pushMonitoringProfileTLSMenu(r, dir, name, "")
		case 7:
			return pushMonitoringProfileDeleteConfirm(r, dir, name)
		case 8:
			return pushMonitoringProfilesMenu(r, dir, "")
		}
		return nil
	})
}

func pushMonitoringProfileFieldJobName(r *editRouterModel, dir, name string) tea.Cmd {
	_, pf, err := loadMonitoring(dir)
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	p := pf.Profiles[name]
	validate := func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}
	spec := tui.InputSpec{ScreenID: "mon.profile.field.jobname", Title: "jobName", Default: p.JobName, Validate: validate}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushMonitoringProfileDetail(r, dir, name, "")
		}
		return commitMonitoringProfileMutation(r, dir, name, "", func(p *monitoring.Profile) { p.JobName = strings.TrimSpace(m.Value()) })
	})
}

func pushMonitoringProfileFieldScheme(r *editRouterModel, dir, name string) tea.Cmd {
	choices := []tui.Choice{{ID: "mon.profile.field.scheme.http", Label: "http"}, {ID: "mon.profile.field.scheme.https", Label: "https"}}
	spec := tui.SelectSpec{ScreenID: "mon.profile.field.scheme", Title: "scheme", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushMonitoringProfileDetail(r, dir, name, "")
		}
		scheme := "http"
		if m.Selected() == 1 {
			scheme = "https"
		}
		return commitMonitoringProfileMutation(r, dir, name, "", func(p *monitoring.Profile) { p.Scheme = scheme })
	})
}

// pushMonitoringProfileFieldText edits one plain string field, located via
// fieldPtr on a *monitoring.Profile — one screen implementation shared by
// metricsPath/scrapeInterval/scrapeTimeout/authRef instead of four
// near-identical copies.
func pushMonitoringProfileFieldText(r *editRouterModel, dir, name, screenSuffix, title string, fieldPtr func(*monitoring.Profile) *string) tea.Cmd {
	_, pf, err := loadMonitoring(dir)
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	p := pf.Profiles[name]
	spec := tui.InputSpec{ScreenID: "mon.profile.field." + screenSuffix, Title: title, Default: *fieldPtr(&p)}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushMonitoringProfileDetail(r, dir, name, "")
		}
		return commitMonitoringProfileMutation(r, dir, name, "", func(p *monitoring.Profile) { *fieldPtr(p) = strings.TrimSpace(m.Value()) })
	})
}

// ---- tls sub-menu ---------------------------------------------------------

func pushMonitoringProfileTLSMenu(r *editRouterModel, dir, name, banner string) tea.Cmd {
	_, pf, err := loadMonitoring(dir)
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	p := pf.Profiles[name]
	serverName, insecure := "", false
	if p.TLS != nil {
		serverName, insecure = p.TLS.ServerName, p.TLS.InsecureSkipVerify
	}
	choices := []tui.Choice{
		{ID: "mon.profile.tls.server_name", Label: fmt.Sprintf("serverName：%s", displayOrPlaceholder(serverName))},
		{ID: "mon.profile.tls.insecure", Label: fmt.Sprintf("insecureSkipVerify：%v", insecure)},
		{ID: "mon.profile.tls.back", Label: "↩  返回"},
	}
	spec := tui.SelectSpec{ScreenID: "mon.profile.tls", Title: fmt.Sprintf("profile %q 的 TLS 設定", name), Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushMonitoringProfileDetail(r, dir, name, "")
		}
		switch m.Selected() {
		case 0:
			return pushMonitoringProfileTLSServerName(r, dir, name)
		case 1:
			return commitMonitoringProfileMutation(r, dir, name, "mon.profile.tls", func(p *monitoring.Profile) {
				if p.TLS == nil {
					p.TLS = &monitoring.TLSConfig{}
				}
				p.TLS.InsecureSkipVerify = !p.TLS.InsecureSkipVerify
			})
		case 2:
			return pushMonitoringProfileDetail(r, dir, name, "")
		}
		return nil
	})
}

func pushMonitoringProfileTLSServerName(r *editRouterModel, dir, name string) tea.Cmd {
	_, pf, err := loadMonitoring(dir)
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	p := pf.Profiles[name]
	cur := ""
	if p.TLS != nil {
		cur = p.TLS.ServerName
	}
	spec := tui.InputSpec{ScreenID: "mon.profile.tls.server_name.input", Title: "TLS serverName override", Default: cur}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushMonitoringProfileTLSMenu(r, dir, name, "")
		}
		return commitMonitoringProfileMutation(r, dir, name, "mon.profile.tls", func(p *monitoring.Profile) {
			if p.TLS == nil {
				p.TLS = &monitoring.TLSConfig{}
			}
			p.TLS.ServerName = strings.TrimSpace(m.Value())
		})
	})
}

// commitMonitoringProfileMutation loads, mutates pf.Profiles[name] via
// mutate, validates, and saves — the single choke point every profile field
// screen above funnels through, so "load -> mutate -> validate -> save"
// is written exactly once. returnScreenID selects which screen to land on
// after a successful save: "" means the top-level detail screen, anything
// else names a sub-menu (currently only the TLS menu) to return to instead.
func commitMonitoringProfileMutation(r *editRouterModel, dir, name, returnScreenID string, mutate func(*monitoring.Profile)) tea.Cmd {
	tf, pf, err := loadMonitoring(dir)
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	p := pf.Profiles[name]
	mutate(&p)
	pf.Profiles[name] = p
	res, err := saveMonitoringProfiles(dir, tf, pf)
	banner := ""
	if err != nil {
		banner = fmt.Sprintf("⚠️  存檔失敗：%v", err)
	} else if !res.OK() {
		banner = formatViolations(res)
	}
	if returnScreenID == "mon.profile.tls" {
		return pushMonitoringProfileTLSMenu(r, dir, name, banner)
	}
	return pushMonitoringProfileDetail(r, dir, name, banner)
}

// ---- delete ---------------------------------------------------------------

func pushMonitoringProfileDeleteConfirm(r *editRouterModel, dir, name string) tea.Cmd {
	_, pf, err := loadMonitoring(dir)
	if err != nil {
		return pushMonitoringManager(r, dir, fmt.Sprintf("⚠️  %v", err))
	}
	tf, _, _ := loadMonitoring(dir)
	if inUse := monitoring.ProfileInUse(tf, name); len(inUse) > 0 {
		return pushMonitoringProfileDetail(r, dir, name, fmt.Sprintf("⚠️  無法刪除：仍被下列 target 使用：%v（spec.md §50 不允許 cascade delete）", inUse))
	}
	question := fmt.Sprintf("確定要刪除 profile %q 嗎？", name)
	spec := tui.ConfirmSpec{ScreenID: "mon.profile.delete.confirm", Title: question, Default: false}
	return r.transitionTo(r.uiFactory().Confirm(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.ConfirmScreen)
		if !m.Value() {
			return pushMonitoringProfileDetail(r, dir, name, "")
		}
		delete(pf.Profiles, name)
		if err := monitoring.SaveProfiles(monitoringProfilesPath(dir), pf); err != nil {
			return pushMonitoringProfilesMenu(r, dir, fmt.Sprintf("⚠️  存檔失敗：%v", err))
		}
		return pushMonitoringProfilesMenu(r, dir, fmt.Sprintf("已刪除 profile %q", name))
	})
}
