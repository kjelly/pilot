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
	items := []string{
		"設定主機與角色",
		"建立／更新最小設定骨架",
		"設定 group_vars（已從角色範本建立）",
		"設定 vault 必要秘密",
		"驗證並檢查是否可部署",
		"改用進階設定",
		"↩  返回",
	}
	return r.transitionTo(newSelectModel("快速建立最小 workspace", items), banner, func(r *editRouterModel, s screen) tea.Cmd {
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
	items := make([]string, 0, len(routes)+1)
	for _, route := range routes {
		items = append(items, route.label())
	}
	items = append(items, "返回快速流程")

	return r.transitionTo(
		newSelectModelWithScreenID("edit.minimal.readiness", "還不能部署 — 選一個要修的地方", items),
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
