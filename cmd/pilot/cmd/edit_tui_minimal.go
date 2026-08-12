package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
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
		m := s.(selectModel)
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
			checks, err := minimalWorkspaceReadiness(dir)
			if err != nil {
				return pushMinimalWorkspaceWizard(r, dir, minimalWorkspaceErrorBanner(err))
			}
			if allCompletenessChecksOK(checks) {
				return pushMinimalWorkspaceWizard(r, dir, fmt.Sprintf(
					"✅ 最小 workspace 已可部署。\n下一步：pilot deploy -i %s",
					filepath.Join(dir, "inventory.yml")))
			}
			return pushMinimalWorkspaceWizard(r, dir, formatCompletenessReport(checks))
		case 5, 6:
			return pushTopMenu(r, dir, "")
		}
		return nil
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
