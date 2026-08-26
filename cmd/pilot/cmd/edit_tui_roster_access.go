package cmd

import (
	"fmt"
	"sort"
	"strings"

	tea "charm.land/bubbletea/v2"
	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/tui"
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
	choices := []tui.Choice{
		{ID: "roster.access.top.hostgroups", Label: "Hostgroups"},
		{ID: "roster.access.top.hbac_rules", Label: "HBAC rules"},
		{ID: "roster.access.top.disable_allow_all", Label: fmt.Sprintf("hbac.disable_allow_all：%t", disabled)},
		{ID: "roster.access.top.back", Label: "↩  返回"},
	}
	spec := tui.SelectSpec{ScreenID: "roster.access.top", Title: "Host access — 誰可以登入哪些主機", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
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
	// The hostgroup's own name is its stable identity (HBAC targets and
	// nested hostgroup membership both reference it by name).
	choices := make([]tui.Choice, 0, len(names)+2)
	for _, n := range names {
		choices = append(choices, tui.Choice{ID: n, Label: "🖥 " + n})
	}
	choices = append(choices,
		tui.Choice{ID: "roster.hostgroups.list.add", Label: "➕ 新增 Hostgroup"},
		tui.Choice{ID: "roster.hostgroups.list.back", Label: "↩  返回"},
	)
	spec := tui.SelectSpec{ScreenID: "roster.hostgroups.list", Title: "Hostgroups — 已 enroll 主機的群組", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
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
	spec := tui.InputSpec{ScreenID: "roster.hostgroup.add", Title: "Hostgroup 名稱(例如 webhosts)", Validate: func(v string) error {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
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
	choices := []tui.Choice{
		{ID: "roster.hostgroup.detail.name", Label: "name：" + name + "（唯讀）"},
		{ID: "roster.hostgroup.detail.description", Label: "description：" + rosterDisplay(f, "description")},
		{ID: "roster.hostgroup.detail.membership_hosts", Label: fmt.Sprintf("membership.hosts（%d 台；輸入逗號分隔 FQDN）", len(hosts))},
		{ID: "roster.hostgroup.detail.membership_hostgroups", Label: fmt.Sprintf("membership.hostgroups（%d 個巢狀 hostgroup）", len(hostgroups))},
		{ID: "roster.hostgroup.detail.back", Label: "↩  返回"},
	}
	spec := tui.SelectSpec{ScreenID: "roster.hostgroup.detail", Title: "Hostgroup " + name, Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
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
	spec := tui.InputSpec{ScreenID: "roster.hostgroup.field_text", Title: key, Default: current}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushRosterHostgroupDetail(r, dir, path, name, "")
		}
		return pushRosterHostgroupEdit(r, dir, path, name, func(f map[string]any) { f[key] = strings.TrimSpace(m.Value()) })
	})
}

func pushRosterHostgroupHosts(r *editRouterModel, dir, path, name string, current []string) tea.Cmd {
	spec := tui.InputSpec{
		ScreenID: "roster.hostgroup.field_hosts",
		Title:    "已 enroll 主機 FQDN（逗號分隔；例如 web1.ipa.pilot.internal）",
		Default:  strings.Join(current, ", "),
	}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
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
	// The HBAC rule's own name is its stable identity.
	choices := make([]tui.Choice, 0, len(names)+2)
	for _, n := range names {
		choices = append(choices, tui.Choice{ID: n, Label: "🔑 " + n})
	}
	choices = append(choices,
		tui.Choice{ID: "roster.hbac.list.add", Label: "➕ 新增登入規則"},
		tui.Choice{ID: "roster.hbac.list.back", Label: "↩  返回"},
	)
	spec := tui.SelectSpec{ScreenID: "roster.hbac.list", Title: "HBAC rules — 誰可以透過哪些服務登入哪些主機", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() || m.Selected() == len(choices)-1 {
			return pushRosterHostAccessMenu(r, dir, path, "")
		}
		if m.Selected() < len(names) {
			return pushRosterHBACDetail(r, dir, path, names[m.Selected()], "")
		}
		return pushRosterAddHBACRuleName(r, dir, path)
	})
}

func pushRosterAddHBACRuleName(r *editRouterModel, dir, path string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "roster.hbac.add_name", Title: "HBAC rule 名稱", Validate: func(v string) error {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushRosterHBACMenu(r, dir, path, "")
		}
		return pushRosterAddHBACGroups(r, dir, path, strings.TrimSpace(m.Value()))
	})
}

// hbacSubjectGroupChoices returns every roster group valid as an HBAC
// subject — team, role, or legacy access (inventory.IsHBACSubjectGroupCategory)
// — labeling legacy access groups distinctly without changing their stable
// choice ID, which stays the actual group name (spec.md §11.2).
func hbacSubjectGroupChoices(path string) ([]tui.MultiSelectChoice, error) {
	names, err := inventory.RosterGroupNames(path)
	if err != nil {
		return nil, err
	}
	choices := []tui.MultiSelectChoice{}
	for _, n := range names {
		f, ok, err := inventory.RosterGroup(path, n)
		if err != nil {
			return nil, err
		}
		category := rosterStringOr(f, "category", "")
		if !ok || !inventory.IsHBACSubjectGroupCategory(category) {
			continue
		}
		label := n
		if inventory.IsDeprecatedGroupCategory(category) {
			label = n + " [legacy access]"
		}
		choices = append(choices, tui.MultiSelectChoice{Choice: tui.Choice{ID: n, Label: label}})
	}
	return choices, nil
}

// hbacSubjectUserChoices returns every valid HBAC direct-user subject:
// the built-in admin principal plus every roster user, in deterministic
// order with no duplicate admin (spec.md §11.3).
func hbacSubjectUserChoices(path string) ([]string, error) {
	names, err := inventory.RosterUserNames(path)
	if err != nil {
		return nil, err
	}
	out := []string{"admin"}
	for _, n := range names {
		if n != "admin" {
			out = append(out, n)
		}
	}
	return out, nil
}

// markChecked sets Checked on every choice whose ID is in current — used by
// HBAC/sudo detail screens that need custom per-choice labels (so they build
// choices via hbacSubjectGroupChoices instead of the checklist() helper) but
// still need to preselect the rule's current values.
func markChecked(choices []tui.MultiSelectChoice, current []string) []tui.MultiSelectChoice {
	for i := range choices {
		choices[i].Checked = hasRole(current, choices[i].ID)
	}
	return choices
}

// validateDirectHostsInput is the InputSpec.Validate for every HBAC
// direct-host field: each comma-separated, trimmed entry must be
// FQDN-shaped, but the field as a whole may be empty (spec.md §7.5, §11.3).
func validateDirectHostsInput(v string) error {
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !inventory.ValidRosterHostFQDN(part) {
			return fmt.Errorf("%q 不是合法的 FQDN", part)
		}
	}
	return nil
}

// normalizeDirectHosts splits a comma-separated direct-host input into a
// trimmed, deduplicated, deterministically sorted list — the same
// normalization every HBAC direct-host field applies before it's ever
// written to the roster (spec.md §7.5, §11.3).
func normalizeDirectHosts(v string) []string {
	seen := map[string]bool{}
	var out []string
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" || seen[part] {
			continue
		}
		seen[part] = true
		out = append(out, part)
	}
	sort.Strings(out)
	return out
}

// checklistIDs is checklist's counterpart for callers that need a per-choice
// display label distinct from the stable ID (e.g. flagging a legacy access
// group) — it reads back CheckedIDs() rather than CheckedLabels() so a
// decorated label can never leak into roster data.
func checklistIDs(r *editRouterModel, screenID, title string, choices []tui.MultiSelectChoice, next func(*editRouterModel, []string) tea.Cmd, cancel func(*editRouterModel) tea.Cmd) tea.Cmd {
	spec := tui.MultiSelectSpec{ScreenID: screenID, Title: title + "（space 勾選、enter 完成）", Choices: choices}
	return r.transitionTo(r.uiFactory().MultiSelect(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.MultiSelectScreen)
		if m.Canceled() {
			return cancel(r)
		}
		return next(r, m.CheckedIDs())
	})
}

// checklist is the shared multi-select used by every roster relationship
// picker (HBAC groups/hostgroups/services, nested hostgroups, sudo role
// groups and command groups). Every option is a live roster entity named
// by a unique string — a group, hostgroup, PAM service or command-group
// name — so that name is both the Label and the stable Choice.ID.
func checklist(r *editRouterModel, screenID, title string, options, current []string, next func(*editRouterModel, []string) tea.Cmd, cancel func(*editRouterModel) tea.Cmd) tea.Cmd {
	choices := make([]tui.MultiSelectChoice, len(options))
	for i, o := range options {
		choices[i] = tui.MultiSelectChoice{Choice: tui.Choice{ID: o, Label: o}, Checked: hasRole(current, o)}
	}
	spec := tui.MultiSelectSpec{ScreenID: screenID, Title: title + "（space 勾選、enter 完成）", Choices: choices}
	return r.transitionTo(r.uiFactory().MultiSelect(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.MultiSelectScreen)
		if m.Canceled() {
			return cancel(r)
		}
		return next(r, m.CheckedLabels())
	})
}

func pushRosterAddHBACGroups(r *editRouterModel, dir, path, name string) tea.Cmd {
	choices, err := hbacSubjectGroupChoices(path)
	if err != nil {
		r.err = err
		return nil
	}
	return checklistIDs(r, "roster.hbac.add_groups", "允許登入的 group（team/role/legacy access）", choices, func(r *editRouterModel, selected []string) tea.Cmd {
		return pushRosterAddHBACUsers(r, dir, path, name, selected)
	}, func(r *editRouterModel) tea.Cmd { return pushRosterHBACMenu(r, dir, path, "") })
}

func pushRosterAddHBACUsers(r *editRouterModel, dir, path, name string, groups []string) tea.Cmd {
	users, err := hbacSubjectUserChoices(path)
	if err != nil {
		r.err = err
		return nil
	}
	return checklist(r, "roster.hbac.add_users", "允許登入的使用者", users, nil, func(r *editRouterModel, selected []string) tea.Cmd {
		return pushRosterAddHBACHostgroups(r, dir, path, name, groups, selected)
	}, func(r *editRouterModel) tea.Cmd { return pushRosterHBACMenu(r, dir, path, "") })
}

func pushRosterAddHBACHostgroups(r *editRouterModel, dir, path, name string, groups, users []string) tea.Cmd {
	hostgroups, err := inventory.RosterHostgroupNames(path)
	if err != nil {
		r.err = err
		return nil
	}
	return checklist(r, "roster.hbac.add_hostgroups", "允許登入的 hostgroup", hostgroups, nil, func(r *editRouterModel, selected []string) tea.Cmd {
		return pushRosterAddHBACHosts(r, dir, path, name, groups, users, selected)
	}, func(r *editRouterModel) tea.Cmd { return pushRosterHBACMenu(r, dir, path, "") })
}

func pushRosterAddHBACHosts(r *editRouterModel, dir, path, name string, groups, users, hostgroups []string) tea.Cmd {
	spec := tui.InputSpec{
		ScreenID: "roster.hbac.add_hosts",
		Title:    "Direct hosts / exceptions（可留空；逗號分隔已 enroll FQDN）",
		Validate: validateDirectHostsInput,
	}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushRosterHBACMenu(r, dir, path, "")
		}
		return pushRosterAddHBACServices(r, dir, path, name, groups, users, hostgroups, normalizeDirectHosts(m.Value()))
	})
}

func pushRosterAddHBACServices(r *editRouterModel, dir, path, name string, groups, users, hostgroups, hosts []string) tea.Cmd {
	return checklist(r, "roster.hbac.add_services", "允許的 PAM service", rosterHBACServiceChoices(), []string{"sshd"}, func(r *editRouterModel, services []string) tea.Cmd {
		rule := map[string]any{"name": name, "state": "present", "enabled": true, "subjects": map[string]any{"users": users, "groups": groups}, "targets": map[string]any{"hosts": hosts, "hostgroups": hostgroups}, "services": services}
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
	choices := []tui.Choice{
		{ID: "roster.hbac.detail.subjects_groups", Label: fmt.Sprintf("subjects.groups（%v）", rosterStringSlice(sub, "groups"))},
		{ID: "roster.hbac.detail.subjects_users", Label: fmt.Sprintf("subjects.users（%v）", rosterStringSlice(sub, "users"))},
		{ID: "roster.hbac.detail.targets_hostgroups", Label: fmt.Sprintf("targets.hostgroups（%v）", rosterStringSlice(tar, "hostgroups"))},
		{ID: "roster.hbac.detail.targets_hosts", Label: fmt.Sprintf("targets.hosts（%v）", rosterStringSlice(tar, "hosts"))},
		{ID: "roster.hbac.detail.services", Label: fmt.Sprintf("services（%v）", rosterStringSlice(f, "services"))},
		{ID: "roster.hbac.detail.back", Label: "↩  返回"},
	}
	spec := tui.SelectSpec{ScreenID: "roster.hbac.detail", Title: "HBAC rule " + name, Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() || m.Selected() == 5 {
			return pushRosterHBACMenu(r, dir, path, "")
		}
		switch m.Selected() {
		case 0:
			return pushRosterHBACGroups(r, dir, path, name)
		case 1:
			return pushRosterHBACUsers(r, dir, path, name)
		case 2:
			return pushRosterHBACTargets(r, dir, path, name)
		case 3:
			return pushRosterHBACHosts(r, dir, path, name)
		case 4:
			return pushRosterHBACServices(r, dir, path, name)
		}
		return nil
	})
}

func pushRosterHBACGroups(r *editRouterModel, dir, path, name string) tea.Cmd {
	f, _, _ := inventory.RosterHBACRule(path, name)
	choices, err := hbacSubjectGroupChoices(path)
	if err != nil {
		r.err = err
		return nil
	}
	current := rosterStringSlice(rosterSubmap(f, "subjects"), "groups")
	return checklistIDs(r, "roster.hbac.detail.subjects_groups", "subjects.groups（team/role/legacy access）", markChecked(choices, current), func(r *editRouterModel, v []string) tea.Cmd {
		// Cloning "subjects" and setting only "groups" preserves the
		// sibling subjects.users field untouched (spec.md §11.5).
		return pushRosterHBACEdit(r, dir, path, name, func(x map[string]any) { s := rosterSubmapClone(x, "subjects"); s["groups"] = v; x["subjects"] = s })
	}, func(r *editRouterModel) tea.Cmd { return pushRosterHBACDetail(r, dir, path, name, "") })
}

func pushRosterHBACUsers(r *editRouterModel, dir, path, name string) tea.Cmd {
	f, _, _ := inventory.RosterHBACRule(path, name)
	users, err := hbacSubjectUserChoices(path)
	if err != nil {
		r.err = err
		return nil
	}
	return checklist(r, "roster.hbac.detail.subjects_users", "subjects.users", users, rosterStringSlice(rosterSubmap(f, "subjects"), "users"), func(r *editRouterModel, v []string) tea.Cmd {
		// Cloning "subjects" and setting only "users" preserves the
		// sibling subjects.groups field untouched (spec.md §11.5).
		return pushRosterHBACEdit(r, dir, path, name, func(x map[string]any) { s := rosterSubmapClone(x, "subjects"); s["users"] = v; x["subjects"] = s })
	}, func(r *editRouterModel) tea.Cmd { return pushRosterHBACDetail(r, dir, path, name, "") })
}

func pushRosterHBACTargets(r *editRouterModel, dir, path, name string) tea.Cmd {
	f, _, _ := inventory.RosterHBACRule(path, name)
	hgs, err := inventory.RosterHostgroupNames(path)
	if err != nil {
		r.err = err
		return nil
	}
	return checklist(r, "roster.hbac.detail.targets_hostgroups", "targets.hostgroups", hgs, rosterStringSlice(rosterSubmap(f, "targets"), "hostgroups"), func(r *editRouterModel, v []string) tea.Cmd {
		return pushRosterHBACEdit(r, dir, path, name, func(x map[string]any) {
			// Cloning "targets" and setting only "hostgroups" preserves
			// the sibling targets.hosts field untouched — this used to
			// zero it out, a data-loss bug fixed by spec.md §3.3/§11.5.
			t := rosterSubmapClone(x, "targets")
			t["hostgroups"] = v
			delete(t, "hostcat")
			x["targets"] = t
		})
	}, func(r *editRouterModel) tea.Cmd { return pushRosterHBACDetail(r, dir, path, name, "") })
}

func pushRosterHBACHosts(r *editRouterModel, dir, path, name string) tea.Cmd {
	f, _, _ := inventory.RosterHBACRule(path, name)
	current := rosterStringSlice(rosterSubmap(f, "targets"), "hosts")
	spec := tui.InputSpec{
		ScreenID: "roster.hbac.detail.targets_hosts",
		Title:    "Direct hosts / exceptions（可留空；逗號分隔已 enroll FQDN）",
		Default:  strings.Join(current, ", "),
		Validate: validateDirectHostsInput,
	}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushRosterHBACDetail(r, dir, path, name, "")
		}
		hosts := normalizeDirectHosts(m.Value())
		return pushRosterHBACEdit(r, dir, path, name, func(x map[string]any) {
			// Cloning "targets" and setting only "hosts" preserves the
			// sibling targets.hostgroups field untouched (spec.md §11.5).
			t := rosterSubmapClone(x, "targets")
			t["hosts"] = hosts
			delete(t, "hostcat")
			x["targets"] = t
		})
	})
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
