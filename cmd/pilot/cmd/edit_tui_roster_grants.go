// edit_tui_roster_grants.go implements the v3.0 Core Access Governance
// spec's (spec.md §17, Phase 3) "Access governance" area for grants:
// list, a kind-branching create wizard (temporary_grant/sudo_grant/
// breakglass — each has a different required field set, see
// roster_grants.go's checkGrants), and per-field detail editors. Every
// write goes through internal/inventory.Simulate{Add,Set}RosterGrant
// first (mirroring freeipa-identity-apply.yml's own "Gate: canonical ..."
// assert chain, same as every other roster editor in this package) before
// Append/SetRosterGrant persists via yaml.Node surgery.
//
// Deliberately out of scope here: authentication policies, security
// policies, and account lifecycle CRUD (spec.md §17's menu lists these as
// sibling areas, but none of them has roster.go CRUD primitives yet —
// see this feature's own commit history for the explicit scoping
// decision). "Static HBAC" under Access governance is not a second
// editor — it delegates straight into pushRosterHostAccessMenu.
package cmd

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/tui"
)

// pushAccessGovernanceMenu is spec.md §17's "Access governance" area menu.
func pushAccessGovernanceMenu(r *editRouterModel, dir, path, banner string) tea.Cmd {
	choices := []tui.Choice{
		{ID: "roster.access_gov.top.static_hbac", Label: "🔑 Static HBAC"},
		{ID: "roster.access_gov.top.grants", Label: "⏳ Grants"},
		{ID: "roster.access_gov.top.breakglass", Label: "🚨 Break-glass"},
		{ID: "roster.access_gov.top.explain", Label: "🔍 Explain access"},
		{ID: "roster.access_gov.top.back", Label: "↩  返回"},
	}
	spec := tui.SelectSpec{ScreenID: "roster.access_gov.top", Title: "Access governance", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() || m.Selected() == 4 {
			return pushRosterManager(r, dir, path, "")
		}
		switch m.Selected() {
		case 0:
			return pushRosterHostAccessMenu(r, dir, path, "")
		case 1:
			return pushRosterGrantsMenu(r, dir, path, "")
		case 2:
			return pushBreakglassMenu(r, dir, path, "")
		case 3:
			return pushExplainAccessPrompt(r, dir, path, "")
		}
		return nil
	})
}

func grantKindLabel(kind string) string {
	switch kind {
	case "temporary_grant":
		return "⏳"
	case "sudo_grant":
		return "🛡️"
	case "breakglass":
		return "🚨"
	}
	return "❓"
}

func pushRosterGrantsMenu(r *editRouterModel, dir, path, banner string) tea.Cmd {
	names, err := inventory.RosterGrantNames(path)
	if err != nil {
		r.err = err
		return nil
	}
	choices := make([]tui.Choice, 0, len(names)+2)
	for _, n := range names {
		f, _, _ := inventory.RosterGrant(path, n)
		choices = append(choices, tui.Choice{ID: n, Label: grantKindLabel(rosterStringValue(f, "kind")) + " " + n})
	}
	choices = append(choices,
		tui.Choice{ID: "roster.grants.list.add", Label: "➕ 新增 grant"},
		tui.Choice{ID: "roster.grants.list.back", Label: "↩  返回"},
	)
	spec := tui.SelectSpec{ScreenID: "roster.grants.list", Title: "Grants — 時效性授權（temporary_grant / sudo_grant / breakglass）", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() || m.Selected() == len(choices)-1 {
			return pushAccessGovernanceMenu(r, dir, path, "")
		}
		if m.Selected() < len(names) {
			return pushGrantDetail(r, dir, path, names[m.Selected()], "")
		}
		return pushAddGrantKind(r, dir, path)
	})
}

// grantKindChoices is create_grant's first step — spec.md §17's "kind
// required: temporary_grant | sudo_grant | breakglass".
func pushAddGrantKind(r *editRouterModel, dir, path string) tea.Cmd {
	choices := []tui.Choice{
		{ID: "temporary_grant", Label: "⏳ temporary_grant（時效性登入授權）"},
		{ID: "sudo_grant", Label: "🛡️  sudo_grant（時效性 sudo 授權）"},
		{ID: "breakglass", Label: "🚨 breakglass（緊急存取定義）"},
	}
	spec := tui.SelectSpec{ScreenID: "roster.grants.add_kind", Title: "新增 grant — 選擇 kind", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushRosterGrantsMenu(r, dir, path, "")
		}
		return pushAddGrantName(r, dir, path, choices[m.Selected()].ID)
	})
}

func pushAddGrantName(r *editRouterModel, dir, path, kind string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "roster.grants.add_name", Title: "Grant 名稱", Validate: func(v string) error {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushAddGrantKind(r, dir, path)
		}
		return pushAddGrantUsers(r, dir, path, kind, strings.TrimSpace(m.Value()))
	})
}

// pushAddGrantUsers collects subjects.users for every kind, then branches:
// breakglass's subjects.groups MUST be empty (checkGrants, roster_grants.go
// §7) so it skips straight to targets; temporary_grant/sudo_grant continue
// to a groups checklist scoped to what each kind's subject-group category
// policy allows (§7: team/role/legacy-access for temporary_grant, role
// only for sudo_grant).
func pushAddGrantUsers(r *editRouterModel, dir, path, kind, name string) tea.Cmd {
	users, err := hbacSubjectUserChoices(path)
	if err != nil {
		r.err = err
		return nil
	}
	return checklist(r, "roster.grants.add_users", "subjects.users", users, nil, func(r *editRouterModel, selected []string) tea.Cmd {
		if kind == "breakglass" {
			return pushAddGrantTargetsHostgroups(r, dir, path, kind, name, nil, selected)
		}
		return pushAddGrantGroups(r, dir, path, kind, name, selected)
	}, func(r *editRouterModel) tea.Cmd { return pushRosterGrantsMenu(r, dir, path, "") })
}

func pushAddGrantGroups(r *editRouterModel, dir, path, kind, name string, users []string) tea.Cmd {
	var choices []tui.MultiSelectChoice
	var err error
	if kind == "sudo_grant" {
		names, e := inventory.RosterGroupNames(path)
		if e != nil {
			r.err = e
			return nil
		}
		for _, n := range names {
			f, ok, e := inventory.RosterGroup(path, n)
			if e != nil {
				r.err = e
				return nil
			}
			if ok && inventory.IsSudoSubjectGroupCategory(rosterStringOr(f, "category", "")) {
				choices = append(choices, tui.MultiSelectChoice{Choice: tui.Choice{ID: n, Label: n}})
			}
		}
	} else {
		choices, err = hbacSubjectGroupChoices(path)
		if err != nil {
			r.err = err
			return nil
		}
	}
	return checklistIDs(r, "roster.grants.add_groups", "subjects.groups", choices, func(r *editRouterModel, groups []string) tea.Cmd {
		return pushAddGrantTargetsHostgroups(r, dir, path, kind, name, groups, users)
	}, func(r *editRouterModel) tea.Cmd { return pushRosterGrantsMenu(r, dir, path, "") })
}

func pushAddGrantTargetsHostgroups(r *editRouterModel, dir, path, kind, name string, groups, users []string) tea.Cmd {
	hostgroups, err := inventory.RosterHostgroupNames(path)
	if err != nil {
		r.err = err
		return nil
	}
	return checklist(r, "roster.grants.add_hostgroups", "targets.hostgroups", hostgroups, nil, func(r *editRouterModel, selectedHostgroups []string) tea.Cmd {
		return pushAddGrantTargetsHosts(r, dir, path, kind, name, groups, users, selectedHostgroups)
	}, func(r *editRouterModel) tea.Cmd { return pushRosterGrantsMenu(r, dir, path, "") })
}

func pushAddGrantTargetsHosts(r *editRouterModel, dir, path, kind, name string, groups, users, hostgroups []string) tea.Cmd {
	spec := tui.InputSpec{
		ScreenID: "roster.grants.add_hosts",
		Title:    "targets.hosts（可留空；逗號分隔已 enroll FQDN）",
		Validate: validateDirectHostsInput,
	}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushRosterGrantsMenu(r, dir, path, "")
		}
		hosts := normalizeDirectHosts(m.Value())
		if kind == "sudo_grant" {
			return pushAddGrantValidityNotBefore(r, dir, path, kind, name, groups, users, hostgroups, hosts, nil)
		}
		return pushAddGrantServices(r, dir, path, kind, name, groups, users, hostgroups, hosts)
	})
}

func pushAddGrantServices(r *editRouterModel, dir, path, kind, name string, groups, users, hostgroups, hosts []string) tea.Cmd {
	return checklist(r, "roster.grants.add_services", "services", rosterHBACServiceChoices(), []string{"sshd"}, func(r *editRouterModel, services []string) tea.Cmd {
		if kind == "breakglass" {
			return pushAddGrantMaxDuration(r, dir, path, name, groups, users, hostgroups, hosts, services)
		}
		return pushAddGrantValidityNotBefore(r, dir, path, kind, name, groups, users, hostgroups, hosts, services)
	}, func(r *editRouterModel) tea.Cmd { return pushRosterGrantsMenu(r, dir, path, "") })
}

// pushAddGrantValidityNotBefore/NotAfter/Reason/Ticket are shared by
// temporary_grant and sudo_grant — the two kinds that carry validity/
// justification (roster_grants.go §7); breakglass never reaches these
// (it branches to pushAddGrantMaxDuration from pushAddGrantServices instead).
func pushAddGrantValidityNotBefore(r *editRouterModel, dir, path, kind, name string, groups, users, hostgroups, hosts, services []string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "roster.grants.add_not_before", Title: "validity.not_before（可留空；RFC3339，例如 2026-08-21T09:00:00+08:00）"}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushRosterGrantsMenu(r, dir, path, "")
		}
		return pushAddGrantValidityNotAfter(r, dir, path, kind, name, groups, users, hostgroups, hosts, services, strings.TrimSpace(m.Value()))
	})
}

func pushAddGrantValidityNotAfter(r *editRouterModel, dir, path, kind, name string, groups, users, hostgroups, hosts, services []string, notBefore string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "roster.grants.add_not_after", Title: "validity.not_after（必填；RFC3339，例如 2026-08-31T18:00:00+08:00）", Validate: func(v string) error {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushRosterGrantsMenu(r, dir, path, "")
		}
		return pushAddGrantReason(r, dir, path, kind, name, groups, users, hostgroups, hosts, services, notBefore, strings.TrimSpace(m.Value()))
	})
}

func pushAddGrantReason(r *editRouterModel, dir, path, kind, name string, groups, users, hostgroups, hosts, services []string, notBefore, notAfter string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "roster.grants.add_reason", Title: "justification.reason（必填）", Validate: func(v string) error {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushRosterGrantsMenu(r, dir, path, "")
		}
		return pushAddGrantTicket(r, dir, path, kind, name, groups, users, hostgroups, hosts, services, notBefore, notAfter, strings.TrimSpace(m.Value()))
	})
}

func pushAddGrantTicket(r *editRouterModel, dir, path, kind, name string, groups, users, hostgroups, hosts, services []string, notBefore, notAfter, reason string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "roster.grants.add_ticket", Title: "justification.ticket（可留空）"}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushRosterGrantsMenu(r, dir, path, "")
		}
		ticket := strings.TrimSpace(m.Value())

		grant := map[string]any{
			"name":     name,
			"state":    "present",
			"kind":     kind,
			"subjects": map[string]any{"users": users, "groups": groups},
			"targets":  map[string]any{"hosts": hosts, "hostgroups": hostgroups},
			"validity": grantValidityMap(notBefore, notAfter),
			"justification": map[string]any{
				"reason": reason, "ticket": ticket,
			},
		}
		if kind == "temporary_grant" {
			grant["services"] = services
		} else {
			grant["privilege"] = map[string]any{"command_category": "all", "commands": []string{}, "command_groups": []string{}}
			grant["run_as"] = map[string]any{"users": []string{"root"}, "groups": []string{}}
			grant["options"] = []string{}
		}
		return saveNewGrant(r, dir, path, grant)
	})
}

func pushAddGrantMaxDuration(r *editRouterModel, dir, path, name string, groups, users, hostgroups, hosts, services []string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "roster.grants.add_max_duration", Title: "activation.max_duration（必填；例如 1h、45m、7d）", Validate: func(v string) error {
		if !inventory.ValidAccessDuration(strings.TrimSpace(v)) {
			return fmt.Errorf("格式須為 <數字>(m|h|d)，例如 30m、1h、7d")
		}
		return nil
	}}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushRosterGrantsMenu(r, dir, path, "")
		}
		grant := map[string]any{
			"name":     name,
			"state":    "present",
			"kind":     "breakglass",
			"subjects": map[string]any{"users": users, "groups": groups},
			"targets":  map[string]any{"hosts": hosts, "hostgroups": hostgroups},
			"services": services,
			"activation": map[string]any{
				"max_duration": strings.TrimSpace(m.Value()), "require_reason": true, "require_ticket": true,
			},
		}
		return saveNewGrant(r, dir, path, grant)
	})
}

func grantValidityMap(notBefore, notAfter string) map[string]any {
	v := map[string]any{"not_after": notAfter}
	if notBefore != "" {
		v["not_before"] = notBefore
	}
	return v
}

func saveNewGrant(r *editRouterModel, dir, path string, grant map[string]any) tea.Cmd {
	v, err := inventory.SimulateAddRosterGrant(path, grant)
	if err != nil {
		r.err = err
		return nil
	}
	if len(v) > 0 {
		return pushRosterGrantsMenu(r, dir, path, formatRosterViolations(v))
	}
	if err := inventory.AppendRosterGrant(path, grant); err != nil {
		r.err = err
		return nil
	}
	return pushRosterGrantsMenu(r, dir, path, "✅ 已新增 grant")
}

func pushGrantDetail(r *editRouterModel, dir, path, name, banner string) tea.Cmd {
	f, found, err := inventory.RosterGrant(path, name)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushRosterGrantsMenu(r, dir, path, "grant 已不存在")
	}
	kind := rosterStringValue(f, "kind")
	sub := rosterSubmap(f, "subjects")
	tar := rosterSubmap(f, "targets")
	state := rosterStringOr(f, "state", "present")
	choices := []tui.Choice{
		{ID: "roster.grants.detail.kind", Label: "kind：" + kind + "（唯讀）"},
		{ID: "roster.grants.detail.state", Label: fmt.Sprintf("state：%s（選取切換 present/absent）", state)},
		{ID: "roster.grants.detail.subjects_users", Label: fmt.Sprintf("subjects.users（%v）", rosterStringSlice(sub, "users"))},
		{ID: "roster.grants.detail.subjects_groups", Label: fmt.Sprintf("subjects.groups（%v）", rosterStringSlice(sub, "groups"))},
		{ID: "roster.grants.detail.targets_hostgroups", Label: fmt.Sprintf("targets.hostgroups（%v）", rosterStringSlice(tar, "hostgroups"))},
		{ID: "roster.grants.detail.targets_hosts", Label: fmt.Sprintf("targets.hosts（%v）", rosterStringSlice(tar, "hosts"))},
	}
	if kind == "temporary_grant" {
		choices = append(choices, tui.Choice{ID: "roster.grants.detail.services", Label: fmt.Sprintf("services（%v）", rosterStringSlice(f, "services"))})
	}
	if kind == "temporary_grant" || kind == "sudo_grant" {
		val := rosterSubmap(f, "validity")
		just := rosterSubmap(f, "justification")
		choices = append(choices,
			tui.Choice{ID: "roster.grants.detail.validity", Label: fmt.Sprintf("validity（not_before=%s, not_after=%s）", rosterStringOr(val, "not_before", "-"), rosterStringOr(val, "not_after", "-"))},
			tui.Choice{ID: "roster.grants.detail.justification", Label: fmt.Sprintf("justification（reason=%s, ticket=%s）", rosterStringOr(just, "reason", "-"), rosterStringOr(just, "ticket", "-"))},
		)
	}
	if kind == "sudo_grant" {
		priv := rosterSubmap(f, "privilege")
		choices = append(choices, tui.Choice{ID: "roster.grants.detail.privilege", Label: fmt.Sprintf("privilege.command_groups（%v；空清單=command_category all）", rosterStringSlice(priv, "command_groups"))})
	}
	if kind == "breakglass" {
		act := rosterSubmap(f, "activation")
		choices = append(choices,
			tui.Choice{ID: "roster.grants.detail.services", Label: fmt.Sprintf("services（%v）", rosterStringSlice(f, "services"))},
			tui.Choice{ID: "roster.grants.detail.max_duration", Label: "activation.max_duration：" + rosterStringOr(act, "max_duration", "(未設定)")},
		)
	}
	choices = append(choices, tui.Choice{ID: "roster.grants.detail.back", Label: "↩  返回"})
	backIdx := len(choices) - 1

	spec := tui.SelectSpec{ScreenID: "roster.grants.detail", Title: "Grant " + name, Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() || m.Selected() == backIdx {
			return pushRosterGrantsMenu(r, dir, path, "")
		}
		switch choices[m.Selected()].ID {
		case "roster.grants.detail.kind":
			return pushGrantDetail(r, dir, path, name, "kind 不可修改")
		case "roster.grants.detail.state":
			next := "absent"
			if state == "absent" {
				next = "present"
			}
			return pushGrantEdit(r, dir, path, name, func(x map[string]any) { x["state"] = next })
		case "roster.grants.detail.subjects_users":
			return pushGrantUsers(r, dir, path, name)
		case "roster.grants.detail.subjects_groups":
			return pushGrantGroups(r, dir, path, name, kind)
		case "roster.grants.detail.targets_hostgroups":
			return pushGrantTargetsHostgroups(r, dir, path, name)
		case "roster.grants.detail.targets_hosts":
			return pushGrantTargetsHosts(r, dir, path, name)
		case "roster.grants.detail.services":
			return pushGrantServices(r, dir, path, name)
		case "roster.grants.detail.max_duration":
			return pushGrantMaxDuration(r, dir, path, name)
		case "roster.grants.detail.validity":
			return pushGrantValidityNotBefore(r, dir, path, name)
		case "roster.grants.detail.justification":
			return pushGrantReason(r, dir, path, name)
		case "roster.grants.detail.privilege":
			return pushGrantPrivilege(r, dir, path, name)
		}
		return nil
	})
}

func pushGrantValidityNotBefore(r *editRouterModel, dir, path, name string) tea.Cmd {
	f, _, _ := inventory.RosterGrant(path, name)
	current := rosterStringOr(rosterSubmap(f, "validity"), "not_before", "")
	spec := tui.InputSpec{ScreenID: "roster.grants.detail.validity_not_before", Title: "validity.not_before（可留空；RFC3339）", Default: current}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushGrantDetail(r, dir, path, name, "")
		}
		return pushGrantValidityNotAfter(r, dir, path, name, strings.TrimSpace(m.Value()))
	})
}

func pushGrantValidityNotAfter(r *editRouterModel, dir, path, name, notBefore string) tea.Cmd {
	f, _, _ := inventory.RosterGrant(path, name)
	current := rosterStringOr(rosterSubmap(f, "validity"), "not_after", "")
	spec := tui.InputSpec{ScreenID: "roster.grants.detail.validity_not_after", Title: "validity.not_after（必填；RFC3339）", Default: current, Validate: func(v string) error {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushGrantDetail(r, dir, path, name, "")
		}
		return pushGrantEdit(r, dir, path, name, func(x map[string]any) {
			x["validity"] = grantValidityMap(notBefore, strings.TrimSpace(m.Value()))
		})
	})
}

func pushGrantReason(r *editRouterModel, dir, path, name string) tea.Cmd {
	f, _, _ := inventory.RosterGrant(path, name)
	current := rosterStringOr(rosterSubmap(f, "justification"), "reason", "")
	spec := tui.InputSpec{ScreenID: "roster.grants.detail.justification_reason", Title: "justification.reason（必填）", Default: current, Validate: func(v string) error {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushGrantDetail(r, dir, path, name, "")
		}
		return pushGrantTicket(r, dir, path, name, strings.TrimSpace(m.Value()))
	})
}

func pushGrantTicket(r *editRouterModel, dir, path, name, reason string) tea.Cmd {
	f, _, _ := inventory.RosterGrant(path, name)
	current := rosterStringOr(rosterSubmap(f, "justification"), "ticket", "")
	spec := tui.InputSpec{ScreenID: "roster.grants.detail.justification_ticket", Title: "justification.ticket（可留空）", Default: current}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushGrantDetail(r, dir, path, name, "")
		}
		return pushGrantEdit(r, dir, path, name, func(x map[string]any) {
			x["justification"] = map[string]any{"reason": reason, "ticket": strings.TrimSpace(m.Value())}
		})
	})
}

// pushGrantPrivilege edits a sudo_grant's privilege.command_groups —
// scope deliberately kept to command_groups only (checkGrantSudoPrivilege,
// roster_grants.go): an empty selection compiles to command_category:
// "all" (the same default the create wizard already applies), a non-empty
// one clears the category, matching CompileSudoGrant's own
// AllowCommandGroups-vs-CommandCategory logic. Free-form privilege.commands
// (individually denylist-checked strings) is out of scope for this screen —
// author those via the roster YAML directly or the create_grant/
// set_grant_privilege structured action, which accepts them unchanged.
func pushGrantPrivilege(r *editRouterModel, dir, path, name string) tea.Cmd {
	f, _, _ := inventory.RosterGrant(path, name)
	names, err := inventory.RosterSudoCommandGroupNames(path)
	if err != nil {
		r.err = err
		return nil
	}
	current := rosterStringSlice(rosterSubmap(f, "privilege"), "command_groups")
	return checklist(r, "roster.grants.detail.privilege", "privilege.command_groups", names, current, func(r *editRouterModel, v []string) tea.Cmd {
		return pushGrantEdit(r, dir, path, name, func(x map[string]any) {
			priv := rosterSubmapClone(x, "privilege")
			priv["command_groups"] = v
			priv["commands"] = rosterStringSlice(priv, "commands")
			if len(v) > 0 {
				priv["command_category"] = ""
			} else {
				priv["command_category"] = "all"
			}
			x["privilege"] = priv
		})
	}, func(r *editRouterModel) tea.Cmd { return pushGrantDetail(r, dir, path, name, "") })
}

func pushGrantUsers(r *editRouterModel, dir, path, name string) tea.Cmd {
	f, _, _ := inventory.RosterGrant(path, name)
	users, err := hbacSubjectUserChoices(path)
	if err != nil {
		r.err = err
		return nil
	}
	return checklist(r, "roster.grants.detail.subjects_users", "subjects.users", users, rosterStringSlice(rosterSubmap(f, "subjects"), "users"), func(r *editRouterModel, v []string) tea.Cmd {
		return pushGrantEdit(r, dir, path, name, func(x map[string]any) { s := rosterSubmapClone(x, "subjects"); s["users"] = v; x["subjects"] = s })
	}, func(r *editRouterModel) tea.Cmd { return pushGrantDetail(r, dir, path, name, "") })
}

func pushGrantGroups(r *editRouterModel, dir, path, name, kind string) tea.Cmd {
	if kind == "breakglass" {
		return pushGrantDetail(r, dir, path, name, "breakglass subjects.groups 恆為空（僅接受具名使用者）")
	}
	f, _, _ := inventory.RosterGrant(path, name)
	var choices []tui.MultiSelectChoice
	var err error
	if kind == "sudo_grant" {
		names, e := inventory.RosterGroupNames(path)
		if e != nil {
			r.err = e
			return nil
		}
		for _, n := range names {
			gf, ok, e := inventory.RosterGroup(path, n)
			if e != nil {
				r.err = e
				return nil
			}
			if ok && inventory.IsSudoSubjectGroupCategory(rosterStringOr(gf, "category", "")) {
				choices = append(choices, tui.MultiSelectChoice{Choice: tui.Choice{ID: n, Label: n}})
			}
		}
	} else {
		choices, err = hbacSubjectGroupChoices(path)
		if err != nil {
			r.err = err
			return nil
		}
	}
	current := rosterStringSlice(rosterSubmap(f, "subjects"), "groups")
	return checklistIDs(r, "roster.grants.detail.subjects_groups", "subjects.groups", markChecked(choices, current), func(r *editRouterModel, v []string) tea.Cmd {
		return pushGrantEdit(r, dir, path, name, func(x map[string]any) { s := rosterSubmapClone(x, "subjects"); s["groups"] = v; x["subjects"] = s })
	}, func(r *editRouterModel) tea.Cmd { return pushGrantDetail(r, dir, path, name, "") })
}

func pushGrantTargetsHostgroups(r *editRouterModel, dir, path, name string) tea.Cmd {
	f, _, _ := inventory.RosterGrant(path, name)
	hgs, err := inventory.RosterHostgroupNames(path)
	if err != nil {
		r.err = err
		return nil
	}
	return checklist(r, "roster.grants.detail.targets_hostgroups", "targets.hostgroups", hgs, rosterStringSlice(rosterSubmap(f, "targets"), "hostgroups"), func(r *editRouterModel, v []string) tea.Cmd {
		return pushGrantEdit(r, dir, path, name, func(x map[string]any) { t := rosterSubmapClone(x, "targets"); t["hostgroups"] = v; x["targets"] = t })
	}, func(r *editRouterModel) tea.Cmd { return pushGrantDetail(r, dir, path, name, "") })
}

func pushGrantTargetsHosts(r *editRouterModel, dir, path, name string) tea.Cmd {
	f, _, _ := inventory.RosterGrant(path, name)
	current := rosterStringSlice(rosterSubmap(f, "targets"), "hosts")
	spec := tui.InputSpec{
		ScreenID: "roster.grants.detail.targets_hosts",
		Title:    "targets.hosts（可留空；逗號分隔已 enroll FQDN）",
		Default:  strings.Join(current, ", "),
		Validate: validateDirectHostsInput,
	}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushGrantDetail(r, dir, path, name, "")
		}
		hosts := normalizeDirectHosts(m.Value())
		return pushGrantEdit(r, dir, path, name, func(x map[string]any) { t := rosterSubmapClone(x, "targets"); t["hosts"] = hosts; x["targets"] = t })
	})
}

func pushGrantServices(r *editRouterModel, dir, path, name string) tea.Cmd {
	f, _, _ := inventory.RosterGrant(path, name)
	return checklist(r, "roster.grants.detail.services", "services", rosterHBACServiceChoices(), rosterStringSlice(f, "services"), func(r *editRouterModel, v []string) tea.Cmd {
		return pushGrantEdit(r, dir, path, name, func(x map[string]any) { x["services"] = v })
	}, func(r *editRouterModel) tea.Cmd { return pushGrantDetail(r, dir, path, name, "") })
}

func pushGrantMaxDuration(r *editRouterModel, dir, path, name string) tea.Cmd {
	f, _, _ := inventory.RosterGrant(path, name)
	act := rosterSubmap(f, "activation")
	spec := tui.InputSpec{ScreenID: "roster.grants.detail.max_duration", Title: "activation.max_duration（例如 1h、45m、7d）", Default: rosterStringOr(act, "max_duration", ""), Validate: func(v string) error {
		if !inventory.ValidAccessDuration(strings.TrimSpace(v)) {
			return fmt.Errorf("格式須為 <數字>(m|h|d)，例如 30m、1h、7d")
		}
		return nil
	}}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushGrantDetail(r, dir, path, name, "")
		}
		return pushGrantEdit(r, dir, path, name, func(x map[string]any) {
			a := rosterSubmapClone(x, "activation")
			a["max_duration"] = strings.TrimSpace(m.Value())
			x["activation"] = a
		})
	})
}

func pushGrantEdit(r *editRouterModel, dir, path, name string, mutate func(map[string]any)) tea.Cmd {
	f, ok, err := inventory.RosterGrant(path, name)
	if err != nil {
		r.err = err
		return nil
	}
	if !ok {
		return pushRosterGrantsMenu(r, dir, path, "grant 已不存在")
	}
	mutate(f)
	v, _, err := inventory.SimulateSetRosterGrant(path, name, f)
	if err != nil {
		r.err = err
		return nil
	}
	if len(v) > 0 {
		return pushGrantDetail(r, dir, path, name, formatRosterViolations(v))
	}
	if err := inventory.SetRosterGrant(path, name, f); err != nil {
		r.err = err
		return nil
	}
	return pushGrantDetail(r, dir, path, name, "✅ 已更新")
}
