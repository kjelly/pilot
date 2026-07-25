// edit_tui_roster.go implements the roster screens of the `pilot edit`
// router (edit_tui.go): a manager for the canonical FreeIPA-identity
// roster file, scoped deliberately narrow — append-only users/groups,
// nothing else. Every write goes through
// internal/inventory.SimulateAddRosterUser/Group first (mirroring
// freeipa-identity-apply.yml's own "Gate: canonical ..." assert chain) so
// a mistake is caught before it ever touches disk, then
// AppendRosterUser/Group persists via the same yaml.Node surgery
// AppendMissingNFSServerStub already uses — never a full-struct remarshal,
// so no comment or section this wizard doesn't know about is disturbed.
//
// hostgroups/hbac/sudo/nfs_clients/migration and editing or deleting an
// existing user/group are all explicitly out of scope this round: those
// carry referential-integrity risk (do the subjects/targets they'd
// reference actually exist?) that the validator above exists to catch,
// and should only get an editor once it's proven against real rosters.
package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/kjelly/pilot/internal/inventory"
)

func pushRosterPathPrompt(r *editRouterModel, dir string) tea.Cmd {
	def := filepath.Join(dir, ".vault", "ipa-identity.yaml")
	return r.transitionTo(newTextInputModel("Roster 檔路徑(canonical FreeIPA roster)", def, nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushTopMenu(r, dir, "")
		}
		return pushRosterManager(r, dir, strings.TrimSpace(m.Value()), "")
	})
}

func pushRosterManager(r *editRouterModel, dir, path, banner string) tea.Cmd {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			r.err = fmt.Errorf(
				"%s 不存在；請先參考 playbooks/apply/freeipa-identity.roster.example.yaml 手動建立一份最小 roster，"+
					"再回來用這個精靈新增 users/groups", path)
			return nil
		}
		r.err = fmt.Errorf("stat %s: %w", path, err)
		return nil
	}

	items := []string{"👤 Users", "👥 Groups", "↩  返回"}
	title := fmt.Sprintf("管理 %s", path)
	return r.transitionTo(newSelectModel(title, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			// mirrors the trailing "↩ 返回" item.
			return pushTopMenu(r, dir, "")
		}
		switch m.Selected() {
		case 0:
			return pushRosterUsersMenu(r, dir, path, "")
		case 1:
			return pushRosterGroupsMenu(r, dir, path, "")
		case 2:
			return pushTopMenu(r, dir, "")
		}
		return nil
	})
}

func pushRosterUsersMenu(r *editRouterModel, dir, path, banner string) tea.Cmd {
	names, err := inventory.RosterUserNames(path)
	if err != nil {
		r.err = fmt.Errorf("read %s: %w", path, err)
		return nil
	}
	note := "目前沒有任何 user。"
	if len(names) > 0 {
		note = fmt.Sprintf("現有 users(唯讀，本精靈只支援新增)：%s", strings.Join(names, ", "))
	}
	if banner == "" {
		banner = note
	} else {
		banner += "\n" + note
	}

	items := []string{"➕ 新增 User", "↩  返回"}
	return r.transitionTo(newSelectModel(fmt.Sprintf("Users — %s", path), items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			// mirrors "↩ 返回".
			return pushRosterManager(r, dir, path, "")
		}
		switch m.Selected() {
		case 0:
			return pushRosterAddUser(r, dir, path)
		case 1:
			return pushRosterManager(r, dir, path, "")
		}
		return nil
	})
}

func pushRosterAddUser(r *editRouterModel, dir, path string) tea.Cmd {
	validate := func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}
	return r.transitionTo(newTextInputModel("新 user 的名稱(小寫英數字/底線/點/連字號)", "", validate), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushRosterUsersMenu(r, dir, path, "")
		}
		name := strings.TrimSpace(m.Value())
		violations, err := inventory.SimulateAddRosterUser(path, name)
		if err != nil {
			r.err = fmt.Errorf("%s: %w", path, err)
			return nil
		}
		if len(violations) > 0 {
			return pushRosterUsersMenu(r, dir, path, formatRosterViolations(violations))
		}
		if err := inventory.AppendRosterUser(path, name); err != nil {
			r.err = fmt.Errorf("write %s: %w", path, err)
			return nil
		}
		return pushRosterUsersMenu(r, dir, path, fmt.Sprintf(
			"✅ 已新增 user %s；其餘欄位(email/ssh key/密碼...)請直接編輯檔案補上。", name))
	})
}

func pushRosterGroupsMenu(r *editRouterModel, dir, path, banner string) tea.Cmd {
	names, err := inventory.RosterGroupNames(path)
	if err != nil {
		r.err = fmt.Errorf("read %s: %w", path, err)
		return nil
	}
	note := "目前沒有任何 group。"
	if len(names) > 0 {
		note = fmt.Sprintf("現有 groups(唯讀，本精靈只支援新增)：%s", strings.Join(names, ", "))
	}
	if banner == "" {
		banner = note
	} else {
		banner += "\n" + note
	}

	items := []string{"➕ 新增 Group", "↩  返回"}
	return r.transitionTo(newSelectModel(fmt.Sprintf("Groups — %s", path), items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			// mirrors "↩ 返回".
			return pushRosterManager(r, dir, path, "")
		}
		switch m.Selected() {
		case 0:
			return pushRosterAddGroupCategory(r, dir, path)
		case 1:
			return pushRosterManager(r, dir, path, "")
		}
		return nil
	})
}

// rosterGroupCategories pairs each canonical group category with the name
// prefix freeipa-identity-apply.yml's "Gate: canonical group objects and
// category prefixes are valid" requires — kept in sync by hand with
// internal/inventory/roster_validate.go's groupCategoryPrefix (unexported,
// so duplicated here rather than shared).
var rosterGroupCategories = []struct {
	Category, Label string
}{
	{"team", "team-*(團隊/team)"},
	{"filesystem", "data-*(檔案系統存取/filesystem)"},
	{"access", "access-*(存取權限/access，給 HBAC 用)"},
	{"role", "role-*(職務角色/role，給 sudo 用)"},
}

func pushRosterAddGroupCategory(r *editRouterModel, dir, path string) tea.Cmd {
	items := make([]string, 0, len(rosterGroupCategories)+1)
	for _, c := range rosterGroupCategories {
		items = append(items, c.Label)
	}
	items = append(items, "↩  返回")
	return r.transitionTo(newSelectModel("新 group 的分類(決定名稱前綴規則)", items), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			// mirrors "↩ 返回".
			return pushRosterGroupsMenu(r, dir, path, "")
		}
		idx := m.Selected()
		if idx == len(items)-1 {
			return pushRosterGroupsMenu(r, dir, path, "")
		}
		return pushRosterAddGroupName(r, dir, path, rosterGroupCategories[idx].Category)
	})
}

func pushRosterAddGroupName(r *editRouterModel, dir, path, category string) tea.Cmd {
	validate := func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}
	label := fmt.Sprintf("新 group 的名稱(category=%s，記得帶前綴)", category)
	return r.transitionTo(newTextInputModel(label, "", validate), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushRosterAddGroupCategory(r, dir, path)
		}
		name := strings.TrimSpace(m.Value())
		violations, err := inventory.SimulateAddRosterGroup(path, name, category)
		if err != nil {
			r.err = fmt.Errorf("%s: %w", path, err)
			return nil
		}
		if len(violations) > 0 {
			return pushRosterGroupsMenu(r, dir, path, formatRosterViolations(violations))
		}
		if err := inventory.AppendRosterGroup(path, name, category); err != nil {
			r.err = fmt.Errorf("write %s: %w", path, err)
			return nil
		}
		return pushRosterGroupsMenu(r, dir, path, fmt.Sprintf(
			"✅ 已新增 group %s(category=%s)；membership 等其餘欄位請直接編輯檔案補上。", name, category))
	})
}

func formatRosterViolations(violations []inventory.RosterViolation) string {
	lines := make([]string, 0, len(violations)+1)
	lines = append(lines, fmt.Sprintf("⚠️  驗證沒過，尚未寫入(%d 項)：", len(violations)))
	for _, v := range violations {
		lines = append(lines, "  - "+v.String())
	}
	return strings.Join(lines, "\n")
}
