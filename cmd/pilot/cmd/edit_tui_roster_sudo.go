package cmd

import (
	"fmt"
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/tui"
)

// pushRosterSudoMenu manages the two pieces of declarative sudo policy:
// reusable command groups and rules that grant those commands to role groups.
func pushRosterSudoMenu(r *editRouterModel, dir, path, banner string) tea.Cmd {
	choices := []tui.Choice{
		{ID: "roster.sudo.top.command_groups", Label: "Command groups — 可重用的 sudo 指令清單"},
		{ID: "roster.sudo.top.rules", Label: "Sudo rules — role group → commands"},
		{ID: "roster.sudo.top.back", Label: "↩  返回"},
	}
	spec := tui.SelectSpec{ScreenID: "roster.sudo.top", Title: "Sudo authorization", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
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
	// The command group's own name is its stable identity (sudo rules
	// reference it by name).
	choices := make([]tui.Choice, 0, len(names)+2)
	for _, name := range names {
		choices = append(choices, tui.Choice{ID: name, Label: "⌘ " + name})
	}
	choices = append(choices,
		tui.Choice{ID: "roster.sudo.command_groups.list.add", Label: "➕ 新增 command group"},
		tui.Choice{ID: "roster.sudo.command_groups.list.back", Label: "↩  返回"},
	)
	spec := tui.SelectSpec{ScreenID: "roster.sudo.command_groups.list", Title: "Sudo command groups", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() || m.Selected() == len(choices)-1 {
			return pushRosterSudoMenu(r, dir, path, "")
		}
		if m.Selected() < len(names) {
			return pushRosterSudoCommandGroupDetail(r, dir, path, names[m.Selected()], "")
		}
		return pushRosterAddSudoCommandGroupName(r, dir, path)
	})
}

func pushRosterAddSudoCommandGroupName(r *editRouterModel, dir, path string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "roster.sudo.command_group.add_name", Title: "sudo command group 名稱", Validate: nonBlank}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushRosterSudoCommandGroupsMenu(r, dir, path, "")
		}
		return pushRosterAddSudoCommandGroupCommands(r, dir, path, strings.TrimSpace(m.Value()))
	})
}

func pushRosterAddSudoCommandGroupCommands(r *editRouterModel, dir, path, name string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "roster.sudo.command_group.add_commands", Title: "允許的完整 sudo 指令（逗號分隔）", Validate: nonBlank}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
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
	choices := []tui.Choice{
		{ID: "roster.sudo.command_group.detail.name", Label: "name：" + name + "（唯讀）"},
		{ID: "roster.sudo.command_group.detail.commands", Label: fmt.Sprintf("commands（%d 條；逗號分隔）", len(rosterStringSlice(f, "commands")))},
		{ID: "roster.sudo.command_group.detail.back", Label: "↩  返回"},
	}
	spec := tui.SelectSpec{ScreenID: "roster.sudo.command_group.detail", Title: "Sudo command group " + name, Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
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
	spec := tui.InputSpec{
		ScreenID: "roster.sudo.command_group.commands",
		Title:    "允許的完整 sudo 指令（逗號分隔）",
		Default:  strings.Join(current, ", "),
		Validate: nonBlank,
	}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
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
	// The sudo rule's own name is its stable identity.
	choices := make([]tui.Choice, 0, len(names)+2)
	for _, name := range names {
		choices = append(choices, tui.Choice{ID: name, Label: "⚙ " + name})
	}
	choices = append(choices,
		tui.Choice{ID: "roster.sudo.rules.list.add", Label: "➕ 新增 sudo rule"},
		tui.Choice{ID: "roster.sudo.rules.list.back", Label: "↩  返回"},
	)
	spec := tui.SelectSpec{ScreenID: "roster.sudo.rules.list", Title: "Sudo rules", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() || m.Selected() == len(choices)-1 {
			return pushRosterSudoMenu(r, dir, path, "")
		}
		if m.Selected() < len(names) {
			return pushRosterSudoRuleDetail(r, dir, path, names[m.Selected()], "")
		}
		return pushRosterAddSudoRuleName(r, dir, path)
	})
}

func pushRosterAddSudoRuleName(r *editRouterModel, dir, path string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "roster.sudo.rule.add_name", Title: "sudo rule 名稱", Validate: nonBlank}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
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
	return checklist(r, "roster.sudo.rule.add_groups", "可使用 sudo 的 role group", groups, nil, func(r *editRouterModel, selected []string) tea.Cmd {
		return pushRosterAddSudoRuleCommandGroups(r, dir, path, name, selected)
	}, func(r *editRouterModel) tea.Cmd { return pushRosterSudoRulesMenu(r, dir, path, "") })
}

func pushRosterAddSudoRuleCommandGroups(r *editRouterModel, dir, path, name string, groups []string) tea.Cmd {
	choices, err := inventory.RosterSudoCommandGroupNames(path)
	if err != nil {
		r.err = err
		return nil
	}
	return checklist(r, "roster.sudo.rule.add_command_groups", "允許的 command group", choices, nil, func(r *editRouterModel, selected []string) tea.Cmd {
		return pushRosterAddSudoRuleCommands(r, dir, path, name, groups, selected)
	}, func(r *editRouterModel) tea.Cmd { return pushRosterSudoRulesMenu(r, dir, path, "") })
}

func pushRosterAddSudoRuleCommands(r *editRouterModel, dir, path, name string, groups, commandGroups []string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "roster.sudo.rule.add_commands", Title: "額外允許的完整 sudo 指令（逗號分隔；留空 = 只用 command group）"}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
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
	allow := map[string]any{"command_groups": commandGroups, "commands": commands}
	// An empty selection in the creation wizard is an intentional allow-all
	// policy, not an accidentally empty explicit list. Persist that decision
	// in the canonical roster so reconciliation always sets FreeIPA cmdcat=all.
	if len(commandGroups)+len(commands) == 0 {
		allow["command_category"] = "all"
	}
	return map[string]any{
		"name": name, "state": "present", "enabled": true,
		"subjects": map[string]any{"users": []string{}, "groups": groups},
		"targets":  map[string]any{"hostcat": "all", "hosts": []string{}, "hostgroups": []string{}},
		"allow":    allow,
		"deny":     map[string]any{"command_groups": []string{}, "commands": []string{}},
		"run_as":   map[string]any{"users": []string{"root"}, "groups": []string{}},
		// Password authentication is the safe default. Operators may grant
		// !authenticate only through an explicit existing-rule policy change.
		"options": []string{},
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
	choices := []tui.Choice{
		{ID: "roster.sudo.rule.detail.subjects_groups", Label: fmt.Sprintf("subjects.groups（%v）", rosterStringSlice(subjects, "groups"))},
		{ID: "roster.sudo.rule.detail.allow_command_category", Label: "allow.command_category（" + rosterSudoAllowMode(allow) + "）"},
		{ID: "roster.sudo.rule.detail.allow_command_groups", Label: fmt.Sprintf("allow.command_groups（%v）", rosterStringSlice(allow, "command_groups"))},
		{ID: "roster.sudo.rule.detail.allow_commands", Label: fmt.Sprintf("allow.commands（%d 條；逗號分隔）", len(rosterStringSlice(allow, "commands")))},
		{ID: "roster.sudo.rule.detail.back", Label: "↩  返回"},
	}
	spec := tui.SelectSpec{ScreenID: "roster.sudo.rule.detail", Title: "Sudo rule " + name, Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() || m.Selected() == 4 {
			return pushRosterSudoRulesMenu(r, dir, path, "")
		}
		switch m.Selected() {
		case 0:
			return pushRosterSudoRuleGroups(r, dir, path, name)
		case 1:
			return pushRosterSudoRuleAllowMode(r, dir, path, name)
		case 2:
			return pushRosterSudoRuleCommandGroups(r, dir, path, name)
		case 3:
			return pushRosterSudoRuleCommands(r, dir, path, name)
		}
		return nil
	})
}

func rosterSudoAllowMode(allow map[string]any) string {
	if rosterStringOr(allow, "command_category", "") == "all" ||
		(len(rosterStringSlice(allow, "commands")) == 0 && len(rosterStringSlice(allow, "command_groups")) == 0) {
		return "all commands"
	}
	return "restricted allow-list"
}

func pushRosterSudoRuleAllowMode(r *editRouterModel, dir, path, name string) tea.Cmd {
	f, found, err := inventory.RosterSudoRule(path, name)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushRosterSudoRulesMenu(r, dir, path, "sudo rule 已不存在")
	}
	allow := rosterSubmap(f, "allow")
	choices := []tui.Choice{
		{ID: "roster.sudo.rule.allow_mode.all", Label: "Allow all commands（危險：可執行任何 sudo 指令）"},
		{ID: "roster.sudo.rule.allow_mode.restricted", Label: "Restricted allow-list（只允許下方 commands / command groups）"},
		{ID: "roster.sudo.rule.allow_mode.back", Label: "↩  返回"},
	}
	spec := tui.SelectSpec{ScreenID: "roster.sudo.rule.allow_mode", Title: "Sudo command scope", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), "目前："+rosterSudoAllowMode(allow), func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() || m.Selected() == 2 {
			return pushRosterSudoRuleDetail(r, dir, path, name, "")
		}
		if m.Selected() == 0 {
			// Deliberately left without a ScreenID, exactly as
			// newConfirmModel had none: this screen reports the generic
			// "confirm" automation ID today and that contract is not
			// being changed here.
			confirmSpec := tui.ConfirmSpec{Title: "確認 allow all？此 role group 可用 sudo 執行任何指令。", Default: false}
			return r.transitionTo(r.uiFactory().Confirm(confirmSpec), "", func(r *editRouterModel, s screen) tea.Cmd {
				confirm := s.(tui.ConfirmScreen)
				if !confirm.Value() {
					return pushRosterSudoRuleDetail(r, dir, path, name, "未變更 sudo command scope")
				}
				return pushRosterSudoRuleEdit(r, dir, path, name, func(rule map[string]any) {
					allow := rosterSubmapClone(rule, "allow")
					allow["command_category"] = "all"
					allow["commands"] = []string{}
					allow["command_groups"] = []string{}
					rule["allow"] = allow
				})
			})
		}
		if len(rosterStringSlice(allow, "commands"))+len(rosterStringSlice(allow, "command_groups")) == 0 {
			return pushRosterSudoRuleDetail(r, dir, path, name, "先設定至少一條 command 或 command group，才能改為 restricted allow-list")
		}
		return pushRosterSudoRuleEdit(r, dir, path, name, func(rule map[string]any) {
			allow := rosterSubmapClone(rule, "allow")
			delete(allow, "command_category")
			rule["allow"] = allow
		})
	})
}

func pushRosterSudoRuleGroups(r *editRouterModel, dir, path, name string) tea.Cmd {
	f, _, _ := inventory.RosterSudoRule(path, name)
	groups, err := roleGroupChoices(path)
	if err != nil {
		r.err = err
		return nil
	}
	return checklist(r, "roster.sudo.rule.groups", "role groups", groups, rosterStringSlice(rosterSubmap(f, "subjects"), "groups"), func(r *editRouterModel, selected []string) tea.Cmd {
		return pushRosterSudoRuleEdit(r, dir, path, name, func(rule map[string]any) {
			subjects := rosterSubmapClone(rule, "subjects")
			subjects["groups"] = selected
			rule["subjects"] = subjects
		})
	}, func(r *editRouterModel) tea.Cmd { return pushRosterSudoRuleDetail(r, dir, path, name, "") })
}

func pushRosterSudoRuleCommandGroups(r *editRouterModel, dir, path, name string) tea.Cmd {
	f, _, _ := inventory.RosterSudoRule(path, name)
	choices, err := inventory.RosterSudoCommandGroupNames(path)
	if err != nil {
		r.err = err
		return nil
	}
	return checklist(r, "roster.sudo.rule.command_groups", "allowed command groups", choices, rosterStringSlice(rosterSubmap(f, "allow"), "command_groups"), func(r *editRouterModel, selected []string) tea.Cmd {
		return pushRosterSudoRuleEdit(r, dir, path, name, func(rule map[string]any) {
			allow := rosterSubmapClone(rule, "allow")
			allow["command_groups"] = selected
			rule["allow"] = allow
		})
	}, func(r *editRouterModel) tea.Cmd { return pushRosterSudoRuleDetail(r, dir, path, name, "") })
}

func pushRosterSudoRuleCommands(r *editRouterModel, dir, path, name string) tea.Cmd {
	f, _, _ := inventory.RosterSudoRule(path, name)
	current := rosterStringSlice(rosterSubmap(f, "allow"), "commands")
	spec := tui.InputSpec{
		ScreenID: "roster.sudo.rule.commands",
		Title:    "額外允許的完整 sudo 指令（逗號分隔）",
		Default:  strings.Join(current, ", "),
	}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
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
