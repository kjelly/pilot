package cmd

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/kjelly/pilot/internal/inventory"
)

// Host access is kept separate from the users/groups screens because it is a
// relationship editor: enrolled hosts are grouped first, then an HBAC rule
// connects an access group to those hostgroups.
func pushRosterHostAccessMenu(r *editRouterModel, dir, path, banner string) tea.Cmd {
	disabled, err := inventory.RosterHBACDisableAllowAll(path)
	if err != nil {
		r.err = err
		return nil
	}
	items := []string{"Hostgroups", "HBAC rules", fmt.Sprintf("hbac.disable_allow_all：%t", disabled), "↩  返回"}
	return r.transitionTo(newSelectModelWithScreenID("roster.access.top", "Host access — 誰可以登入哪些主機", items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() || m.Selected() == 3 {
			return pushRosterManager(r, dir, path, "")
		}
		switch m.Selected() {
		case 0:
			return pushRosterHostgroupsMenu(r, dir, path, "")
		case 1:
			return pushRosterHBACMenu(r, dir, path, "")
		case 2:
			if err := inventory.SetRosterHBACDisableAllowAll(path, !disabled); err != nil {
				r.err = err
				return nil
			}
			return pushRosterHostAccessMenu(r, dir, path, fmt.Sprintf("✅ hbac.disable_allow_all 已設為 %t", !disabled))
		}
		return nil
	})
}

func pushRosterHostgroupsMenu(r *editRouterModel, dir, path, banner string) tea.Cmd {
	names, err := inventory.RosterHostgroupNames(path)
	if err != nil {
		r.err = err
		return nil
	}
	items := make([]string, 0, len(names)+2)
	for _, n := range names {
		items = append(items, "🖥 "+n)
	}
	items = append(items, "➕ 新增 Hostgroup", "↩  返回")
	return r.transitionTo(newSelectModelWithScreenID("roster.hostgroups.list", "Hostgroups — 已 enroll 主機的群組", items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushRosterHostAccessMenu(r, dir, path, "")
		}
		if m.Selected() < len(names) {
			return pushRosterHostgroupDetail(r, dir, path, names[m.Selected()], "")
		}
		if m.Selected() == len(names) {
			return pushRosterAddHostgroup(r, dir, path)
		}
		return pushRosterHostAccessMenu(r, dir, path, "")
	})
}

func pushRosterAddHostgroup(r *editRouterModel, dir, path string) tea.Cmd {
	return r.transitionTo(newTextInputModelWithScreenID("roster.hostgroup.add", "Hostgroup 名稱(例如 webhosts)", "", func(v string) error {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushRosterHostgroupsMenu(r, dir, path, "")
		}
		name := strings.TrimSpace(m.Value())
		if err := inventory.AppendRosterHostgroup(path, name); err != nil {
			r.err = err
			return nil
		}
		return pushRosterHostgroupDetail(r, dir, path, name, "✅ 已新增 hostgroup；接著填入已 enroll 主機 FQDN")
	})
}

func pushRosterHostgroupDetail(r *editRouterModel, dir, path, name, banner string) tea.Cmd {
	f, found, err := inventory.RosterHostgroup(path, name)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushRosterHostgroupsMenu(r, dir, path, "hostgroup 已不存在")
	}
	mem := rosterSubmap(f, "membership")
	hosts := rosterStringSlice(mem, "hosts")
	hostgroups := rosterStringSlice(mem, "hostgroups")
	items := []string{
		"name：" + name + "（唯讀）",
		"description：" + rosterDisplay(f, "description"),
		fmt.Sprintf("membership.hosts（%d 台；輸入逗號分隔 FQDN）", len(hosts)),
		fmt.Sprintf("membership.hostgroups（%d 個巢狀 hostgroup）", len(hostgroups)),
		"↩  返回",
	}
	return r.transitionTo(newSelectModelWithScreenID("roster.hostgroup.detail", "Hostgroup "+name, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() || m.Selected() == 4 {
			return pushRosterHostgroupsMenu(r, dir, path, "")
		}
		switch m.Selected() {
		case 0:
			return pushRosterHostgroupDetail(r, dir, path, name, "hostgroup 名稱不可修改")
		case 1:
			return pushRosterHostgroupText(r, dir, path, name, "description", rosterStringValue(f, "description"))
		case 2:
			return pushRosterHostgroupHosts(r, dir, path, name, hosts)
		case 3:
			return pushRosterHostgroupHostgroups(r, dir, path, name, hostgroups)
		}
		return nil
	})
}

func pushRosterHostgroupText(r *editRouterModel, dir, path, name, key, current string) tea.Cmd {
	return r.transitionTo(newTextInputModelWithScreenID("roster.hostgroup.field_text", key, current, nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushRosterHostgroupDetail(r, dir, path, name, "")
		}
		return pushRosterHostgroupEdit(r, dir, path, name, func(f map[string]any) { f[key] = strings.TrimSpace(m.Value()) })
	})
}

func pushRosterHostgroupHosts(r *editRouterModel, dir, path, name string, current []string) tea.Cmd {
	return r.transitionTo(newTextInputModelWithScreenID("roster.hostgroup.field_hosts", "已 enroll 主機 FQDN（逗號分隔；例如 web1.ipa.pilot.internal）", strings.Join(current, ", "), nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushRosterHostgroupDetail(r, dir, path, name, "")
		}
		var hosts []string
		for _, v := range strings.Split(m.Value(), ",") {
			if v = strings.TrimSpace(v); v != "" {
				hosts = append(hosts, v)
			}
		}
		sort.Strings(hosts)
		return pushRosterHostgroupEdit(r, dir, path, name, func(f map[string]any) {
			mem := rosterSubmapClone(f, "membership")
			mem["hosts"] = hosts
			f["membership"] = mem
		})
	})
}

// pushRosterHostgroupHostgroups edits membership.hostgroups (nested
// hostgroup membership — freeipa-identity-apply.yml now reconciles this
// authoritatively via hostgroup-add-member/-remove-member --hostgroups,
// alongside the long-standing --hosts reconciliation pushRosterHostgroupHosts
// edits). Unlike hosts (free-form FQDNs, possibly outside the roster
// entirely), a nested hostgroup must itself be a roster-declared hostgroup,
// so this is a checklist over inventory.RosterHostgroupNames — same idiom
// as pushRosterHBACTargets's hostgroup picker — rather than free text. The
// current hostgroup is excluded from its own choices: the roster/Ansible
// gates don't reject a direct self-reference here (unlike netgroups, which
// schema v2 added strict cycle protection for — see roster_netgroup.go),
// but there's no reason the picker should ever offer it.
func pushRosterHostgroupHostgroups(r *editRouterModel, dir, path, name string, current []string) tea.Cmd {
	all, err := inventory.RosterHostgroupNames(path)
	if err != nil {
		r.err = err
		return nil
	}
	choices := make([]string, 0, len(all))
	for _, hg := range all {
		if hg != name {
			choices = append(choices, hg)
		}
	}
	return checklist(r, "roster.hostgroup.field_hostgroups", "membership.hostgroups（巢狀 hostgroup）", choices, current, func(r *editRouterModel, v []string) tea.Cmd {
		return pushRosterHostgroupEdit(r, dir, path, name, func(f map[string]any) {
			mem := rosterSubmapClone(f, "membership")
			mem["hostgroups"] = v
			f["membership"] = mem
		})
	}, func(r *editRouterModel) tea.Cmd { return pushRosterHostgroupDetail(r, dir, path, name, "") })
}

func pushRosterHostgroupEdit(r *editRouterModel, dir, path, name string, mutate func(map[string]any)) tea.Cmd {
	f, found, err := inventory.RosterHostgroup(path, name)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushRosterHostgroupsMenu(r, dir, path, "hostgroup 已不存在")
	}
	mutate(f)
	v, _, err := inventory.SimulateSetRosterHostgroup(path, name, f)
	if err != nil {
		r.err = err
		return nil
	}
	if len(v) > 0 {
		return pushRosterHostgroupDetail(r, dir, path, name, formatRosterViolations(v))
	}
	if err := inventory.SetRosterHostgroup(path, name, f); err != nil {
		r.err = err
		return nil
	}
	return pushRosterHostgroupDetail(r, dir, path, name, "✅ 已更新")
}

func rosterHBACServiceChoices() []string {
	services := loadConfig().HBACServices
	if len(services) == 0 {
		return []string{"sshd", "sudo", "sudo-i", "su", "su-l", "login", "gdm-password", "nx", "cockpit"}
	}
	return append([]string(nil), services...)
}

func pushRosterHBACMenu(r *editRouterModel, dir, path, banner string) tea.Cmd {
	names, err := inventory.RosterHBACRuleNames(path)
	if err != nil {
		r.err = err
		return nil
	}
	items := make([]string, 0, len(names)+2)
	for _, n := range names {
		items = append(items, "🔑 "+n)
	}
	items = append(items, "➕ 新增登入規則", "↩  返回")
	return r.transitionTo(newSelectModelWithScreenID("roster.hbac.list", "HBAC rules — group → hostgroup", items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() || m.Selected() == len(items)-1 {
			return pushRosterHostAccessMenu(r, dir, path, "")
		}
		if m.Selected() < len(names) {
			return pushRosterHBACDetail(r, dir, path, names[m.Selected()], "")
		}
		return pushRosterAddHBACRuleName(r, dir, path)
	})
}

func pushRosterAddHBACRuleName(r *editRouterModel, dir, path string) tea.Cmd {
	return r.transitionTo(newTextInputModelWithScreenID("roster.hbac.add_name", "HBAC rule 名稱", "", func(v string) error {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushRosterHBACMenu(r, dir, path, "")
		}
		return pushRosterAddHBACGroups(r, dir, path, strings.TrimSpace(m.Value()))
	})
}

func accessGroupChoices(path string) ([]string, error) {
	names, err := inventory.RosterGroupNames(path)
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, n := range names {
		f, ok, err := inventory.RosterGroup(path, n)
		if err != nil {
			return nil, err
		}
		if ok && rosterStringOr(f, "category", "") == "access" {
			out = append(out, n)
		}
	}
	return out, nil
}

func checklist(r *editRouterModel, screenID, title string, options, current []string, next func(*editRouterModel, []string) tea.Cmd, cancel func(*editRouterModel) tea.Cmd) tea.Cmd {
	items := make([]multiSelectItem, len(options))
	for i, o := range options {
		items[i] = multiSelectItem{Label: o, Checked: hasRole(current, o)}
	}
	return r.transitionTo(newMultiSelectModelWithScreenID(screenID, title+"（space 勾選、enter 完成）", items), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(multiSelectModel)
		if m.Canceled() {
			return cancel(r)
		}
		return next(r, m.CheckedLabels())
	})
}

func pushRosterAddHBACGroups(r *editRouterModel, dir, path, name string) tea.Cmd {
	groups, err := accessGroupChoices(path)
	if err != nil {
		r.err = err
		return nil
	}
	return checklist(r, "roster.hbac.add_groups", "允許登入的 access group", groups, nil, func(r *editRouterModel, selected []string) tea.Cmd {
		return pushRosterAddHBACHostgroups(r, dir, path, name, selected)
	}, func(r *editRouterModel) tea.Cmd { return pushRosterHBACMenu(r, dir, path, "") })
}

func pushRosterAddHBACHostgroups(r *editRouterModel, dir, path, name string, groups []string) tea.Cmd {
	hostgroups, err := inventory.RosterHostgroupNames(path)
	if err != nil {
		r.err = err
		return nil
	}
	return checklist(r, "roster.hbac.add_hostgroups", "允許登入的 hostgroup", hostgroups, nil, func(r *editRouterModel, selected []string) tea.Cmd {
		return pushRosterAddHBACServices(r, dir, path, name, groups, selected)
	}, func(r *editRouterModel) tea.Cmd { return pushRosterHBACMenu(r, dir, path, "") })
}

func pushRosterAddHBACServices(r *editRouterModel, dir, path, name string, groups, hostgroups []string) tea.Cmd {
	return checklist(r, "roster.hbac.add_services", "允許的 PAM service", rosterHBACServiceChoices(), []string{"sshd"}, func(r *editRouterModel, services []string) tea.Cmd {
		rule := map[string]any{"name": name, "state": "present", "enabled": true, "subjects": map[string]any{"users": []string{}, "groups": groups}, "targets": map[string]any{"hosts": []string{}, "hostgroups": hostgroups}, "services": services}
		v, err := inventory.SimulateAddRosterHBACRule(path, rule)
		if err != nil {
			r.err = err
			return nil
		}
		if len(v) > 0 {
			return pushRosterHBACMenu(r, dir, path, formatRosterViolations(v))
		}
		if err := inventory.AppendRosterHBACRule(path, rule); err != nil {
			r.err = err
			return nil
		}
		return pushRosterHBACMenu(r, dir, path, "✅ 已新增登入規則")
	}, func(r *editRouterModel) tea.Cmd { return pushRosterHBACMenu(r, dir, path, "") })
}

func pushRosterHBACDetail(r *editRouterModel, dir, path, name, banner string) tea.Cmd {
	f, found, err := inventory.RosterHBACRule(path, name)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushRosterHBACMenu(r, dir, path, "rule 已不存在")
	}
	sub := rosterSubmap(f, "subjects")
	tar := rosterSubmap(f, "targets")
	items := []string{fmt.Sprintf("subjects.groups（%v）", rosterStringSlice(sub, "groups")), fmt.Sprintf("targets.hostgroups（%v）", rosterStringSlice(tar, "hostgroups")), fmt.Sprintf("services（%v）", rosterStringSlice(f, "services")), "↩  返回"}
	return r.transitionTo(newSelectModelWithScreenID("roster.hbac.detail", "HBAC rule "+name, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() || m.Selected() == 3 {
			return pushRosterHBACMenu(r, dir, path, "")
		}
		switch m.Selected() {
		case 0:
			return pushRosterHBACGroups(r, dir, path, name)
		case 1:
			return pushRosterHBACTargets(r, dir, path, name)
		case 2:
			return pushRosterHBACServices(r, dir, path, name)
		}
		return nil
	})
}

func pushRosterHBACGroups(r *editRouterModel, dir, path, name string) tea.Cmd {
	f, _, _ := inventory.RosterHBACRule(path, name)
	groups, err := accessGroupChoices(path)
	if err != nil {
		r.err = err
		return nil
	}
	return checklist(r, "roster.hbac.groups", "access groups", groups, rosterStringSlice(rosterSubmap(f, "subjects"), "groups"), func(r *editRouterModel, v []string) tea.Cmd {
		return pushRosterHBACEdit(r, dir, path, name, func(x map[string]any) { s := rosterSubmapClone(x, "subjects"); s["groups"] = v; x["subjects"] = s })
	}, func(r *editRouterModel) tea.Cmd { return pushRosterHBACDetail(r, dir, path, name, "") })
}
func pushRosterHBACTargets(r *editRouterModel, dir, path, name string) tea.Cmd {
	f, _, _ := inventory.RosterHBACRule(path, name)
	hgs, err := inventory.RosterHostgroupNames(path)
	if err != nil {
		r.err = err
		return nil
	}
	return checklist(r, "roster.hbac.targets", "hostgroups", hgs, rosterStringSlice(rosterSubmap(f, "targets"), "hostgroups"), func(r *editRouterModel, v []string) tea.Cmd {
		return pushRosterHBACEdit(r, dir, path, name, func(x map[string]any) {
			t := rosterSubmapClone(x, "targets")
			t["hostgroups"] = v
			t["hosts"] = []string{}
			delete(t, "hostcat")
			x["targets"] = t
		})
	}, func(r *editRouterModel) tea.Cmd { return pushRosterHBACDetail(r, dir, path, name, "") })
}
func pushRosterHBACServices(r *editRouterModel, dir, path, name string) tea.Cmd {
	f, _, _ := inventory.RosterHBACRule(path, name)
	return checklist(r, "roster.hbac.services", "services", rosterHBACServiceChoices(), rosterStringSlice(f, "services"), func(r *editRouterModel, v []string) tea.Cmd {
		return pushRosterHBACEdit(r, dir, path, name, func(x map[string]any) { x["services"] = v })
	}, func(r *editRouterModel) tea.Cmd { return pushRosterHBACDetail(r, dir, path, name, "") })
}
func pushRosterHBACEdit(r *editRouterModel, dir, path, name string, mutate func(map[string]any)) tea.Cmd {
	f, ok, err := inventory.RosterHBACRule(path, name)
	if err != nil {
		r.err = err
		return nil
	}
	if !ok {
		return pushRosterHBACMenu(r, dir, path, "rule 已不存在")
	}
	mutate(f)
	v, _, err := inventory.SimulateSetRosterHBACRule(path, name, f)
	if err != nil {
		r.err = err
		return nil
	}
	if len(v) > 0 {
		return pushRosterHBACDetail(r, dir, path, name, formatRosterViolations(v))
	}
	if err := inventory.SetRosterHBACRule(path, name, f); err != nil {
		r.err = err
		return nil
	}
	return pushRosterHBACDetail(r, dir, path, name, "✅ 已更新")
}
