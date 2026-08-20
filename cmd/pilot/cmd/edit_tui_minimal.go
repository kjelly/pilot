package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/kjelly/pilot/internal/tui"
)

// pushMinimalWorkspaceWizard is a shortcut into the established editors. It
// intentionally owns no separate configuration format: every action reads or
// writes the same workspace files as the advanced top-level menu.
func pushMinimalWorkspaceWizard(r *editRouterModel, dir, banner string) tea.Cmd {
	choices := []tui.Choice{
		{ID: "minimal.wizard.hosts", Label: "設定主機與角色"},
		{ID: "minimal.wizard.skeleton", Label: "建立／更新最小設定骨架"},
		{ID: "minimal.wizard.group_vars", Label: "設定 group_vars（已從角色範本建立）"},
		{ID: "minimal.wizard.vault", Label: "設定 vault 必要秘密"},
		{ID: "minimal.wizard.readiness", Label: "驗證並檢查是否可部署"},
		{ID: "minimal.wizard.advanced", Label: "改用進階設定"},
		{ID: "minimal.wizard.back", Label: "↩  返回"},
	}
	spec := tui.SelectSpec{Title: "快速建立最小 workspace", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushTopMenu(r, dir, "")
		}
		switch m.Selected() {
		case 0:
			r.afterHostsSave = func(r *editRouterModel) tea.Cmd {
				if err := prepareMinimalWorkspace(dir); err != nil {
					return pushMinimalWorkspaceWizard(r, dir, minimalWorkspaceErrorBanner(err))
				}
				return pushMinimalWorkspaceWizard(r, dir, "✅ 主機已存檔，最小設定骨架已建立。接著填寫 group_vars 與 vault。")
			}
			// The quick path owns one self-contained workspace, so always use
			// its canonical hosts.yml rather than letting a different source
			// path make the later generated artifacts ambiguous.
			return pushLoadOrInitHosts(r, dir, filepath.Join(dir, "hosts.yml"))
		case 1:
			return prepareMinimalWorkspaceAndReturn(r, dir)
		case 2:
			if err := prepareMinimalWorkspace(dir); err != nil {
				return pushMinimalWorkspaceWizard(r, dir, minimalWorkspaceErrorBanner(err))
			}
			return pushGroupVarsFilePicker(r, dir, "ℹ️  已建立最小設定骨架；推導出的主機位址已預填，可視需要改寫。")
		case 3:
			if err := prepareMinimalWorkspace(dir); err != nil {
				return pushMinimalWorkspaceWizard(r, dir, minimalWorkspaceErrorBanner(err))
			}
			return pushVaultOpen(r, dir, filepath.Join(dir, ".vault", "main.yaml"))
		case 4:
			return pushMinimalWorkspaceReadiness(r, dir)
		case 5, 6:
			return pushTopMenu(r, dir, "")
		}
		return nil
	})
}

// minimalWorkspaceRoute is a remediation destination the quick wizard can send
// the operator to. It exists so a failed completeness label can be mapped to an
// existing editor without the readiness screen knowing anything about routing.
type minimalWorkspaceRoute int

const (
	minimalRouteNone minimalWorkspaceRoute = iota
	minimalRouteHosts
	minimalRouteGroupVars
	minimalRouteVault
	minimalRouteAdvanced
)

// minimalWorkspaceRouteFor maps one completeness label
// (see checkWorkspaceCompleteness) to the editor that can actually fix it.
// Pure and total: an unrecognized or self-healing label yields minimalRouteNone.
//
// `inventory.yml` deliberately maps to None — prepareMinimalWorkspace rewrites
// it on every quick-flow action, so there is no user destination to offer.
func minimalWorkspaceRouteFor(label string) minimalWorkspaceRoute {
	switch {
	case label == "hosts.yml":
		return minimalRouteHosts
	case strings.HasPrefix(label, "host_vars"+string(filepath.Separator)):
		// host_vars is edited from the owning host's own menu, inside the
		// hosts editor — not as a separate top-level destination.
		return minimalRouteHosts
	case strings.HasPrefix(label, "group_vars"+string(filepath.Separator)):
		return minimalRouteGroupVars
	case strings.HasPrefix(label, ".vault"+string(filepath.Separator)):
		return minimalRouteVault
	case label == "roster" || strings.HasPrefix(label, "roster ("):
		// The roster is nested YAML the quick flow deliberately does not own.
		return minimalRouteAdvanced
	default:
		return minimalRouteNone
	}
}

// minimalWorkspaceRoutes returns the applicable destinations for the failing
// checks only, in a stable order and without duplicates, so the readiness
// screen offers a route only when it can actually resolve something.
func minimalWorkspaceRoutes(checks []completenessCheck) []minimalWorkspaceRoute {
	seen := map[minimalWorkspaceRoute]bool{}
	for _, c := range checks {
		if c.OK {
			continue
		}
		if route := minimalWorkspaceRouteFor(c.Label); route != minimalRouteNone {
			seen[route] = true
		}
	}
	var out []minimalWorkspaceRoute
	for _, route := range []minimalWorkspaceRoute{
		minimalRouteHosts, minimalRouteGroupVars, minimalRouteVault, minimalRouteAdvanced,
	} {
		if seen[route] {
			out = append(out, route)
		}
	}
	return out
}

func (route minimalWorkspaceRoute) label() string {
	switch route {
	case minimalRouteHosts:
		return "前往 hosts 設定"
	case minimalRouteGroupVars:
		return "前往 group_vars"
	case minimalRouteVault:
		return "前往 vault"
	case minimalRouteAdvanced:
		return "改用進階設定"
	default:
		return ""
	}
}

// id is route's stable automation identity — the enum value itself is
// already a fixed, finite identity, so this just names it.
func (route minimalWorkspaceRoute) id() string {
	switch route {
	case minimalRouteHosts:
		return "minimal.readiness.hosts"
	case minimalRouteGroupVars:
		return "minimal.readiness.group_vars"
	case minimalRouteVault:
		return "minimal.readiness.vault"
	case minimalRouteAdvanced:
		return "minimal.readiness.advanced"
	default:
		return ""
	}
}

// minimalWorkspaceReadyBanner states the deploy-ready outcome together with the
// exact commands for this workspace, so the operator never has to guess the
// path the quick flow just built.
func minimalWorkspaceReadyBanner(dir string) string {
	return fmt.Sprintf(
		"✅ 最小 workspace 已可部署。\n下一步(依序執行)：\n  pilot inventory generate --dir %s\n  pilot deploy -i %s",
		dir, filepath.Join(dir, "inventory.yml"))
}

// pushMinimalWorkspaceReadiness runs the same completeness contract the
// advanced menu and `pilot deploy`'s hard gate use, then either reports
// deploy-readiness or routes to the editor that can fix each blocking check.
func pushMinimalWorkspaceReadiness(r *editRouterModel, dir string) tea.Cmd {
	checks, err := minimalWorkspaceReadiness(dir)
	if err != nil {
		return pushMinimalWorkspaceWizard(r, dir, minimalWorkspaceErrorBanner(err))
	}
	if allCompletenessChecksOK(checks) {
		return pushMinimalWorkspaceWizard(r, dir, minimalWorkspaceReadyBanner(dir))
	}

	routes := minimalWorkspaceRoutes(checks)
	choices := make([]tui.Choice, 0, len(routes)+1)
	for _, route := range routes {
		choices = append(choices, tui.Choice{ID: route.id(), Label: route.label()})
	}
	choices = append(choices, tui.Choice{ID: "minimal.readiness.back", Label: "返回快速流程"})

	spec := tui.SelectSpec{ScreenID: "edit.minimal.readiness", Title: "還不能部署 — 選一個要修的地方", Choices: choices}
	return r.transitionTo(
		r.uiFactory().Select(spec),
		formatCompletenessReport(checks),
		func(r *editRouterModel, s screen) tea.Cmd {
			m := s.(tui.SelectScreen)
			if m.Canceled() {
				return pushMinimalWorkspaceWizard(r, dir, "")
			}
			if m.Selected() >= len(routes) {
				return pushMinimalWorkspaceWizard(r, dir, "")
			}
			switch routes[m.Selected()] {
			case minimalRouteHosts:
				r.afterHostsSave = func(r *editRouterModel) tea.Cmd {
					return pushMinimalWorkspaceReadiness(r, dir)
				}
				return pushLoadOrInitHosts(r, dir, filepath.Join(dir, "hosts.yml"))
			case minimalRouteGroupVars:
				return pushGroupVarsFilePicker(r, dir, "填完後回到快速流程再驗證一次。")
			case minimalRouteVault:
				return pushVaultOpen(r, dir, filepath.Join(dir, ".vault", "main.yaml"))
			case minimalRouteAdvanced:
				return pushTopMenu(r, dir, "roster 需要用進階選單編輯(巢狀 YAML 不在快速流程範圍)。")
			}
			return pushMinimalWorkspaceWizard(r, dir, "")
		})
}

func prepareMinimalWorkspaceAndReturn(r *editRouterModel, dir string) tea.Cmd {
	if err := prepareMinimalWorkspace(dir); err != nil {
		return pushMinimalWorkspaceWizard(r, dir, minimalWorkspaceErrorBanner(err))
	}
	return pushMinimalWorkspaceWizard(r, dir, "✅ 已建立或更新最小設定骨架；既有設定未被覆寫。")
}

func minimalWorkspaceErrorBanner(err error) string {
	if os.IsNotExist(err) || strings.Contains(err.Error(), "hosts.yml") {
		return "⚠️  先選「設定主機與角色」並存檔，才能建立最小設定骨架。"
	}
	return fmt.Sprintf("⚠️  無法建立最小設定骨架：%v", err)
}

func allCompletenessChecksOK(checks []completenessCheck) bool {
	for _, check := range checks {
		if !check.OK {
			return false
		}
	}
	return true
}
