package cmd

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/kjelly/pilot/internal/inventory"
)

// pushRosterSudoMenu manages the two pieces of declarative sudo policy:
// reusable command groups and rules that grant those commands to role groups.
func pushRosterSudoMenu(r *editRouterModel, dir, path, banner string) tea.Cmd {
	items := []string{"Command groups — 可重用的 sudo 指令清單", "Sudo rules — role group → commands", "↩  返回"}
	return r.transitionTo(newSelectModel("Sudo authorization", items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() || m.Selected() == 2 {
			return pushRosterManager(r, dir, path, "")
		}
		if m.Selected() == 0 {
			return pushRosterSudoCommandGroupsMenu(r, dir, path, "")
		}
		return pushRosterSudoRulesMenu(r, dir, path, "")
	})
}

func pushRosterSudoCommandGroupsMenu(r *editRouterModel, dir, path, banner string) tea.Cmd {
	names, err := inventory.RosterSudoCommandGroupNames(path)
	if err != nil {
		r.err = err
		return nil
	}
	items := make([]string, 0, len(names)+2)
	for _, name := range names {
		items = append(items, "⌘ "+name)
	}
	items = append(items, "➕ 新增 command group", "↩  返回")
	return r.transitionTo(newSelectModel("Sudo command groups", items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() || m.Selected() == len(items)-1 {
			return pushRosterSudoMenu(r, dir, path, "")
		}
		if m.Selected() < len(names) {
			return pushRosterSudoCommandGroupDetail(r, dir, path, names[m.Selected()], "")
		}
		return pushRosterAddSudoCommandGroupName(r, dir, path)
	})
}

func pushRosterAddSudoCommandGroupName(r *editRouterModel, dir, path string) tea.Cmd {
	return r.transitionTo(newTextInputModel("sudo command group 名稱", "", nonBlank), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushRosterSudoCommandGroupsMenu(r, dir, path, "")
		}
		return pushRosterAddSudoCommandGroupCommands(r, dir, path, strings.TrimSpace(m.Value()))
	})
}

func pushRosterAddSudoCommandGroupCommands(r *editRouterModel, dir, path, name string) tea.Cmd {
	return r.transitionTo(newTextInputModel("允許的完整 sudo 指令（逗號分隔）", "", nonBlank), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushRosterSudoCommandGroupsMenu(r, dir, path, "")
		}
		entry := map[string]any{"name": name, "state": "present", "commands": rosterCommaList(m.Value())}
		v, err := inventory.SimulateAddRosterSudoCommandGroup(path, entry)
		if err != nil {
			r.err = err
			return nil
		}
		if len(v) > 0 {
			return pushRosterSudoCommandGroupsMenu(r, dir, path, formatRosterViolations(v))
		}
		if err := inventory.AppendRosterSudoCommandGroup(path, entry); err != nil {
			r.err = err
			return nil
		}
		return pushRosterSudoCommandGroupDetail(r, dir, path, name, "✅ 已新增 command group")
	})
}

func pushRosterSudoCommandGroupDetail(r *editRouterModel, dir, path, name, banner string) tea.Cmd {
	f, found, err := inventory.RosterSudoCommandGroup(path, name)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushRosterSudoCommandGroupsMenu(r, dir, path, "command group 已不存在")
	}
	items := []string{
		"name：" + name + "（唯讀）",
		fmt.Sprintf("commands（%d 條；逗號分隔）", len(rosterStringSlice(f, "commands"))),
		"↩  返回",
	}
	return r.transitionTo(newSelectModel("Sudo command group "+name, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() || m.Selected() == 2 {
			return pushRosterSudoCommandGroupsMenu(r, dir, path, "")
		}
		if m.Selected() == 0 {
			return pushRosterSudoCommandGroupDetail(r, dir, path, name, "名稱不可修改，避免 rule reference 失效")
		}
		return pushRosterSudoCommandGroupCommands(r, dir, path, name, rosterStringSlice(f, "commands"))
	})
}

func pushRosterSudoCommandGroupCommands(r *editRouterModel, dir, path, name string, current []string) tea.Cmd {
	return r.transitionTo(newTextInputModel("允許的完整 sudo 指令（逗號分隔）", strings.Join(current, ", "), nonBlank), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushRosterSudoCommandGroupDetail(r, dir, path, name, "")
		}
		return pushRosterSudoCommandGroupEdit(r, dir, path, name, func(f map[string]any) { f["commands"] = rosterCommaList(m.Value()) })
	})
}

func pushRosterSudoCommandGroupEdit(r *editRouterModel, dir, path, name string, mutate func(map[string]any)) tea.Cmd {
	f, found, err := inventory.RosterSudoCommandGroup(path, name)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushRosterSudoCommandGroupsMenu(r, dir, path, "command group 已不存在")
	}
	mutate(f)
	v, _, err := inventory.SimulateSetRosterSudoCommandGroup(path, name, f)
	if err != nil {
		r.err = err
		return nil
	}
	if len(v) > 0 {
		return pushRosterSudoCommandGroupDetail(r, dir, path, name, formatRosterViolations(v))
	}
	if err := inventory.SetRosterSudoCommandGroup(path, name, f); err != nil {
		r.err = err
		return nil
	}
	return pushRosterSudoCommandGroupDetail(r, dir, path, name, "✅ 已更新")
}

func pushRosterSudoRulesMenu(r *editRouterModel, dir, path, banner string) tea.Cmd {
	names, err := inventory.RosterSudoRuleNames(path)
	if err != nil {
		r.err = err
		return nil
	}
	items := make([]string, 0, len(names)+2)
	for _, name := range names {
		items = append(items, "⚙ "+name)
	}
	items = append(items, "➕ 新增 sudo rule", "↩  返回")
	return r.transitionTo(newSelectModel("Sudo rules", items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() || m.Selected() == len(items)-1 {
			return pushRosterSudoMenu(r, dir, path, "")
		}
		if m.Selected() < len(names) {
			return pushRosterSudoRuleDetail(r, dir, path, names[m.Selected()], "")
		}
		return pushRosterAddSudoRuleName(r, dir, path)
	})
}

func pushRosterAddSudoRuleName(r *editRouterModel, dir, path string) tea.Cmd {
	return r.transitionTo(newTextInputModel("sudo rule 名稱", "", nonBlank), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushRosterSudoRulesMenu(r, dir, path, "")
		}
		return pushRosterAddSudoRuleGroups(r, dir, path, strings.TrimSpace(m.Value()))
	})
}

func roleGroupChoices(path string) ([]string, error) {
	names, err := inventory.RosterGroupNames(path)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, name := range names {
		f, found, err := inventory.RosterGroup(path, name)
		if err != nil {
			return nil, err
		}
		if found && rosterStringOr(f, "category", "") == "role" {
			out = append(out, name)
		}
	}
	return out, nil
}

func pushRosterAddSudoRuleGroups(r *editRouterModel, dir, path, name string) tea.Cmd {
	groups, err := roleGroupChoices(path)
	if err != nil {
		r.err = err
		return nil
	}
	return checklist(r, "可使用 sudo 的 role group", groups, nil, func(selected []string) tea.Cmd {
		return pushRosterAddSudoRuleCommandGroups(r, dir, path, name, selected)
	}, pushRosterSudoRulesMenu(r, dir, path, ""))
}

func pushRosterAddSudoRuleCommandGroups(r *editRouterModel, dir, path, name string, groups []string) tea.Cmd {
	choices, err := inventory.RosterSudoCommandGroupNames(path)
	if err != nil {
		r.err = err
		return nil
	}
	return checklist(r, "允許的 command group", choices, nil, func(selected []string) tea.Cmd {
		return pushRosterAddSudoRuleCommands(r, dir, path, name, groups, selected)
	}, pushRosterSudoRulesMenu(r, dir, path, ""))
}

func pushRosterAddSudoRuleCommands(r *editRouterModel, dir, path, name string, groups, commandGroups []string) tea.Cmd {
	return r.transitionTo(newTextInputModel("額外允許的完整 sudo 指令（逗號分隔；留空 = 只用 command group）", "", nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushRosterSudoRulesMenu(r, dir, path, "")
		}
		entry := newRosterSudoRule(name, groups, commandGroups, rosterCommaList(m.Value()))
		v, err := inventory.SimulateAddRosterSudoRule(path, entry)
		if err != nil {
			r.err = err
			return nil
		}
		if len(v) > 0 {
			return pushRosterSudoRulesMenu(r, dir, path, formatRosterViolations(v))
		}
		if err := inventory.AppendRosterSudoRule(path, entry); err != nil {
			r.err = err
			return nil
		}
		return pushRosterSudoRuleDetail(r, dir, path, name, "✅ 已新增 sudo rule")
	})
}

func newRosterSudoRule(name string, groups, commandGroups, commands []string) map[string]any {
	return map[string]any{
		"name": name, "state": "present", "enabled": true,
		"subjects": map[string]any{"users": []string{}, "groups": groups},
		"targets":  map[string]any{"hostcat": "all", "hosts": []string{}, "hostgroups": []string{}},
		"allow":    map[string]any{"command_groups": commandGroups, "commands": commands},
		"deny":     map[string]any{"command_groups": []string{}, "commands": []string{}},
		"run_as":   map[string]any{"users": []string{"root"}, "groups": []string{}},
		"options":  []string{"!authenticate"},
	}
}

func pushRosterSudoRuleDetail(r *editRouterModel, dir, path, name, banner string) tea.Cmd {
	f, found, err := inventory.RosterSudoRule(path, name)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushRosterSudoRulesMenu(r, dir, path, "sudo rule 已不存在")
	}
	subjects := rosterSubmap(f, "subjects")
	allow := rosterSubmap(f, "allow")
	items := []string{
		fmt.Sprintf("subjects.groups（%v）", rosterStringSlice(subjects, "groups")),
		fmt.Sprintf("allow.command_groups（%v）", rosterStringSlice(allow, "command_groups")),
		fmt.Sprintf("allow.commands（%d 條；逗號分隔）", len(rosterStringSlice(allow, "commands"))),
		"↩  返回",
	}
	return r.transitionTo(newSelectModel("Sudo rule "+name, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() || m.Selected() == 3 {
			return pushRosterSudoRulesMenu(r, dir, path, "")
		}
		switch m.Selected() {
		case 0:
			return pushRosterSudoRuleGroups(r, dir, path, name)
		case 1:
			return pushRosterSudoRuleCommandGroups(r, dir, path, name)
		case 2:
			return pushRosterSudoRuleCommands(r, dir, path, name)
		}
		return nil
	})
}

func pushRosterSudoRuleGroups(r *editRouterModel, dir, path, name string) tea.Cmd {
	f, _, _ := inventory.RosterSudoRule(path, name)
	groups, err := roleGroupChoices(path)
	if err != nil {
		r.err = err
		return nil
	}
	return checklist(r, "role groups", groups, rosterStringSlice(rosterSubmap(f, "subjects"), "groups"), func(selected []string) tea.Cmd {
		return pushRosterSudoRuleEdit(r, dir, path, name, func(rule map[string]any) {
			subjects := rosterSubmapClone(rule, "subjects")
			subjects["groups"] = selected
			rule["subjects"] = subjects
		})
	}, pushRosterSudoRuleDetail(r, dir, path, name, ""))
}

func pushRosterSudoRuleCommandGroups(r *editRouterModel, dir, path, name string) tea.Cmd {
	f, _, _ := inventory.RosterSudoRule(path, name)
	choices, err := inventory.RosterSudoCommandGroupNames(path)
	if err != nil {
		r.err = err
		return nil
	}
	return checklist(r, "allowed command groups", choices, rosterStringSlice(rosterSubmap(f, "allow"), "command_groups"), func(selected []string) tea.Cmd {
		return pushRosterSudoRuleEdit(r, dir, path, name, func(rule map[string]any) {
			allow := rosterSubmapClone(rule, "allow")
			allow["command_groups"] = selected
			rule["allow"] = allow
		})
	}, pushRosterSudoRuleDetail(r, dir, path, name, ""))
}

func pushRosterSudoRuleCommands(r *editRouterModel, dir, path, name string) tea.Cmd {
	f, _, _ := inventory.RosterSudoRule(path, name)
	current := rosterStringSlice(rosterSubmap(f, "allow"), "commands")
	return r.transitionTo(newTextInputModel("額外允許的完整 sudo 指令（逗號分隔）", strings.Join(current, ", "), nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushRosterSudoRuleDetail(r, dir, path, name, "")
		}
		return pushRosterSudoRuleEdit(r, dir, path, name, func(rule map[string]any) {
			allow := rosterSubmapClone(rule, "allow")
			allow["commands"] = rosterCommaList(m.Value())
			rule["allow"] = allow
		})
	})
}

func pushRosterSudoRuleEdit(r *editRouterModel, dir, path, name string, mutate func(map[string]any)) tea.Cmd {
	f, found, err := inventory.RosterSudoRule(path, name)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushRosterSudoRulesMenu(r, dir, path, "sudo rule 已不存在")
	}
	mutate(f)
	v, _, err := inventory.SimulateSetRosterSudoRule(path, name, f)
	if err != nil {
		r.err = err
		return nil
	}
	if len(v) > 0 {
		return pushRosterSudoRuleDetail(r, dir, path, name, formatRosterViolations(v))
	}
	if err := inventory.SetRosterSudoRule(path, name, f); err != nil {
		r.err = err
		return nil
	}
	return pushRosterSudoRuleDetail(r, dir, path, name, "✅ 已更新")
}

func rosterCommaList(value string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, item := range strings.Split(value, ",") {
		item = strings.TrimSpace(item)
		if item != "" && !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	sort.Strings(out)
	return out
}

func nonBlank(value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("不能留空")
	}
	return nil
}
