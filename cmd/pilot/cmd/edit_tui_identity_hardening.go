// edit_tui_identity_hardening.go implements the v3.2 Identity &
// Credential Hardening spec's (spec.md §17, Phase 5→6) "Identity
// hardening" TUI area: password_policies and credential_policies list-
// CRUD (modeled directly on pushRosterHostgroupsMenu's list/detail/
// field-edit shape, edit_tui_roster_access.go), the single
// security.privileged_identity baseline editor, and a read-only hygiene
// report.
//
// Deliberately out of scope here, matching this package's own established
// practice of explicit scope notes (see edit_tui_roster_grants.go's
// header comment for the v3.0 precedent):
//   - credential_policies[].review — already has its own CLI
//     (`pilot identity review list/mark`, spec.md §11); a roster-editing
//     wizard has no session/history context a review decision should be
//     made from, so it stays CLI-only rather than duplicating that flow
//     here.
//   - Identity drift (spec.md §15) — needs a live FreeIPA inventory/
//     ansible-playbook run, unlike every other screen in this file (which
//     only ever reads/writes the roster file); `pilot identity drift`
//     remains the sanctioned entry point.
//   - "User authentication" is not a separate top-level list here (unlike
//     spec.md §17's suggested menu shape): users[].authentication.allowed
//     is a per-user field, added directly to the existing user detail
//     screen (pushRosterUserDetail, edit_tui_roster.go) instead of a
//     second "pick a user" flow under this menu.
package cmd

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/kjelly/pilot/internal/accessgrants"
	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/tui"
)

// pushIdentityHardeningMenu is spec.md §17's "Identity hardening" area
// top menu.
func pushIdentityHardeningMenu(r *editRouterModel, dir, path, banner string) tea.Cmd {
	choices := []tui.Choice{
		{ID: "roster.identity.top.password_policies", Label: "🔑 Password policies"},
		{ID: "roster.identity.top.credential_policies", Label: "🗝️  Credential policies (SSH hygiene)"},
		{ID: "roster.identity.top.privileged_identity", Label: "🛡️  Privileged identity baseline"},
		{ID: "roster.identity.top.hygiene", Label: "🩺 Hygiene report (read-only)"},
		{ID: "roster.identity.top.back", Label: "↩  返回"},
	}
	spec := tui.SelectSpec{ScreenID: "roster.identity.top", Title: "Identity hardening — v3.2", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() || m.Selected() == 4 {
			return pushRosterManager(r, dir, path, "")
		}
		switch m.Selected() {
		case 0:
			return pushRosterPasswordPoliciesMenu(r, dir, path, "")
		case 1:
			return pushRosterCredentialPoliciesMenu(r, dir, path, "")
		case 2:
			return pushPrivilegedIdentityDetail(r, dir, path, "")
		case 3:
			return pushIdentityHygieneReport(r, dir, path)
		}
		return nil
	})
}

// ---- Password policies (spec.md §7) ------------------------------------

func pushRosterPasswordPoliciesMenu(r *editRouterModel, dir, path, banner string) tea.Cmd {
	names, err := inventory.RosterPasswordPolicyNames(path)
	if err != nil {
		r.err = err
		return nil
	}
	choices := make([]tui.Choice, 0, len(names)+2)
	for _, n := range names {
		choices = append(choices, tui.Choice{ID: n, Label: "🔑 " + n})
	}
	choices = append(choices,
		tui.Choice{ID: "roster.password_policies.list.add", Label: "➕ 新增 Password policy"},
		tui.Choice{ID: "roster.password_policies.list.back", Label: "↩  返回"},
	)
	spec := tui.SelectSpec{ScreenID: "roster.password_policies.list", Title: "Password policies — FreeIPA group password policies", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushIdentityHardeningMenu(r, dir, path, "")
		}
		if m.Selected() < len(names) {
			return pushRosterPasswordPolicyDetail(r, dir, path, names[m.Selected()], "")
		}
		if m.Selected() == len(names) {
			return pushRosterAddPasswordPolicy(r, dir, path)
		}
		return pushIdentityHardeningMenu(r, dir, path, "")
	})
}

// pushRosterAddPasswordPolicy chains name -> group -> priority before ever
// calling AppendRosterPasswordPolicy — group and priority are co-required
// (checkPasswordPolicies rejects a present entry missing either), so
// appending a bare stub and editing the two fields one at a time would
// have the FIRST field-set fail simulate-validation (the other required
// field still absent) no matter which one goes first, silently no-oping.
// Found live while writing this screen's automation-driver test. Mirrors
// pushAddGrantKind's multi-prompt create-wizard shape (edit_tui_roster_grants.go)
// for the same reason grants use it: co-required fields need to all be
// known before the very first write.
func pushRosterAddPasswordPolicy(r *editRouterModel, dir, path string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "roster.password_policy.add", Title: "Password policy 名稱(例如 privileged-users)", Validate: func(v string) error {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushRosterPasswordPoliciesMenu(r, dir, path, "")
		}
		name := strings.TrimSpace(m.Value())
		return pushRosterAddPasswordPolicyGroup(r, dir, path, name)
	})
}

func pushRosterAddPasswordPolicyGroup(r *editRouterModel, dir, path, name string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "roster.password_policy.add_group", Title: "group（必填；不可為 access-* 類別）", Validate: func(v string) error {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushRosterPasswordPoliciesMenu(r, dir, path, "")
		}
		return pushRosterAddPasswordPolicyPriority(r, dir, path, name, strings.TrimSpace(m.Value()))
	})
}

func pushRosterAddPasswordPolicyPriority(r *editRouterModel, dir, path, name, group string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "roster.password_policy.add_priority", Title: "priority（必填；正整數）", Validate: func(v string) error {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err != nil || n <= 0 {
			return fmt.Errorf("必須是正整數")
		}
		return nil
	}}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushRosterPasswordPoliciesMenu(r, dir, path, "")
		}
		priority, _ := strconv.Atoi(strings.TrimSpace(m.Value()))
		if err := inventory.AppendRosterPasswordPolicy(path, name); err != nil {
			r.err = err
			return nil
		}
		return pushRosterPasswordPolicyEdit(r, dir, path, name, func(f map[string]any) {
			f["group"] = group
			f["priority"] = priority
		})
	})
}

func pushRosterPasswordPolicyDetail(r *editRouterModel, dir, path, name, banner string) tea.Cmd {
	f, found, err := inventory.RosterPasswordPolicy(path, name)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushRosterPasswordPoliciesMenu(r, dir, path, "password policy 已不存在")
	}
	lockout := rosterSubmap(f, "lockout")
	choices := []tui.Choice{
		{ID: "roster.password_policy.detail.name", Label: "name：" + name + "（唯讀）"},
		{ID: "roster.password_policy.detail.state", Label: fmt.Sprintf("state：%s", rosterStringOr(f, "state", "present"))},
		{ID: "roster.password_policy.detail.group", Label: fmt.Sprintf("group：%s（必填；不可為 access-* 類別）", rosterDisplay(f, "group"))},
		{ID: "roster.password_policy.detail.priority", Label: fmt.Sprintf("priority：%s（必填，正整數）", rosterIntDisplay(f, "priority"))},
		{ID: "roster.password_policy.detail.min_length", Label: fmt.Sprintf("min_length：%s", rosterIntDisplay(f, "min_length"))},
		{ID: "roster.password_policy.detail.history_size", Label: fmt.Sprintf("history_size：%s", rosterIntDisplay(f, "history_size"))},
		{ID: "roster.password_policy.detail.max_life", Label: fmt.Sprintf("max_life：%s（例如 90d）", rosterDisplay(f, "max_life"))},
		{ID: "roster.password_policy.detail.min_life", Label: fmt.Sprintf("min_life：%s（例如 1h）", rosterDisplay(f, "min_life"))},
		{ID: "roster.password_policy.detail.lockout_max_failures", Label: fmt.Sprintf("lockout.max_failures：%s", rosterIntDisplay(lockout, "max_failures"))},
		{ID: "roster.password_policy.detail.lockout_failure_reset_interval", Label: fmt.Sprintf("lockout.failure_reset_interval：%s（例如 15m）", rosterDisplay(lockout, "failure_reset_interval"))},
		{ID: "roster.password_policy.detail.lockout_lockout_duration", Label: fmt.Sprintf("lockout.lockout_duration：%s（例如 15m）", rosterDisplay(lockout, "lockout_duration"))},
		{ID: "roster.password_policy.detail.back", Label: "↩  返回"},
	}
	spec := tui.SelectSpec{ScreenID: "roster.password_policy.detail", Title: "Password policy " + name, Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() || m.Selected() == 11 {
			return pushRosterPasswordPoliciesMenu(r, dir, path, "")
		}
		switch m.Selected() {
		case 0:
			return pushRosterPasswordPolicyDetail(r, dir, path, name, "name 不可修改：priority 唯一性等規則會用名稱互相參照")
		case 1:
			return pushIdentityStateField(r, dir, path, name, "roster.password_policy.field_state", func(r *editRouterModel, v string) tea.Cmd {
				return pushRosterPasswordPolicyEdit(r, dir, path, name, func(f map[string]any) { f["state"] = v })
			}, func(r *editRouterModel) tea.Cmd { return pushRosterPasswordPolicyDetail(r, dir, path, name, "") })
		case 2:
			return pushIdentityTextField(r, dir, path, "roster.password_policy.field_text", "group", rosterStringValue(f, "group"), func(r *editRouterModel, v string) tea.Cmd {
				return pushRosterPasswordPolicyEdit(r, dir, path, name, func(f map[string]any) { f["group"] = v })
			}, func(r *editRouterModel) tea.Cmd { return pushRosterPasswordPolicyDetail(r, dir, path, name, "") })
		case 3:
			return pushIdentityIntField(r, dir, path, "roster.password_policy.field_int", "priority", rosterIntValue(f, "priority"), func(r *editRouterModel, n int, has bool) tea.Cmd {
				return pushRosterPasswordPolicyEdit(r, dir, path, name, func(f map[string]any) { setOrDeleteInt(f, "priority", n, has) })
			}, func(r *editRouterModel) tea.Cmd { return pushRosterPasswordPolicyDetail(r, dir, path, name, "") })
		case 4:
			return pushIdentityIntField(r, dir, path, "roster.password_policy.field_int", "min_length", rosterIntValue(f, "min_length"), func(r *editRouterModel, n int, has bool) tea.Cmd {
				return pushRosterPasswordPolicyEdit(r, dir, path, name, func(f map[string]any) { setOrDeleteInt(f, "min_length", n, has) })
			}, func(r *editRouterModel) tea.Cmd { return pushRosterPasswordPolicyDetail(r, dir, path, name, "") })
		case 5:
			return pushIdentityIntField(r, dir, path, "roster.password_policy.field_int", "history_size", rosterIntValue(f, "history_size"), func(r *editRouterModel, n int, has bool) tea.Cmd {
				return pushRosterPasswordPolicyEdit(r, dir, path, name, func(f map[string]any) { setOrDeleteInt(f, "history_size", n, has) })
			}, func(r *editRouterModel) tea.Cmd { return pushRosterPasswordPolicyDetail(r, dir, path, name, "") })
		case 6:
			return pushIdentityTextField(r, dir, path, "roster.password_policy.field_duration", "max_life", rosterStringValue(f, "max_life"), func(r *editRouterModel, v string) tea.Cmd {
				return pushRosterPasswordPolicyEdit(r, dir, path, name, func(f map[string]any) { setOrDeleteString(f, "max_life", v) })
			}, func(r *editRouterModel) tea.Cmd { return pushRosterPasswordPolicyDetail(r, dir, path, name, "") })
		case 7:
			return pushIdentityTextField(r, dir, path, "roster.password_policy.field_duration", "min_life", rosterStringValue(f, "min_life"), func(r *editRouterModel, v string) tea.Cmd {
				return pushRosterPasswordPolicyEdit(r, dir, path, name, func(f map[string]any) { setOrDeleteString(f, "min_life", v) })
			}, func(r *editRouterModel) tea.Cmd { return pushRosterPasswordPolicyDetail(r, dir, path, name, "") })
		case 8:
			return pushIdentityIntField(r, dir, path, "roster.password_policy.field_int", "lockout.max_failures", rosterIntValue(lockout, "max_failures"), func(r *editRouterModel, n int, has bool) tea.Cmd {
				return pushRosterPasswordPolicyEdit(r, dir, path, name, func(f map[string]any) {
					lo := rosterSubmapClone(f, "lockout")
					setOrDeleteInt(lo, "max_failures", n, has)
					setLockout(f, lo)
				})
			}, func(r *editRouterModel) tea.Cmd { return pushRosterPasswordPolicyDetail(r, dir, path, name, "") })
		case 9:
			return pushIdentityTextField(r, dir, path, "roster.password_policy.field_duration", "lockout.failure_reset_interval", rosterStringValue(lockout, "failure_reset_interval"), func(r *editRouterModel, v string) tea.Cmd {
				return pushRosterPasswordPolicyEdit(r, dir, path, name, func(f map[string]any) {
					lo := rosterSubmapClone(f, "lockout")
					setOrDeleteString(lo, "failure_reset_interval", v)
					setLockout(f, lo)
				})
			}, func(r *editRouterModel) tea.Cmd { return pushRosterPasswordPolicyDetail(r, dir, path, name, "") })
		case 10:
			return pushIdentityTextField(r, dir, path, "roster.password_policy.field_duration", "lockout.lockout_duration", rosterStringValue(lockout, "lockout_duration"), func(r *editRouterModel, v string) tea.Cmd {
				return pushRosterPasswordPolicyEdit(r, dir, path, name, func(f map[string]any) {
					lo := rosterSubmapClone(f, "lockout")
					setOrDeleteString(lo, "lockout_duration", v)
					setLockout(f, lo)
				})
			}, func(r *editRouterModel) tea.Cmd { return pushRosterPasswordPolicyDetail(r, dir, path, name, "") })
		}
		return nil
	})
}

func pushRosterPasswordPolicyEdit(r *editRouterModel, dir, path, name string, mutate func(map[string]any)) tea.Cmd {
	f, found, err := inventory.RosterPasswordPolicy(path, name)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushRosterPasswordPoliciesMenu(r, dir, path, "password policy 已不存在")
	}
	mutate(f)
	v, _, err := inventory.SimulateSetRosterPasswordPolicy(path, name, f)
	if err != nil {
		r.err = err
		return nil
	}
	if len(v) > 0 {
		return pushRosterPasswordPolicyDetail(r, dir, path, name, formatRosterViolations(v))
	}
	if err := inventory.SetRosterPasswordPolicy(path, name, f); err != nil {
		r.err = err
		return nil
	}
	return pushRosterPasswordPolicyDetail(r, dir, path, name, "✅ 已更新")
}

// ---- Credential policies (spec.md §10/§11) -----------------------------

func pushRosterCredentialPoliciesMenu(r *editRouterModel, dir, path, banner string) tea.Cmd {
	names, err := inventory.RosterCredentialPolicyNames(path)
	if err != nil {
		r.err = err
		return nil
	}
	choices := make([]tui.Choice, 0, len(names)+2)
	for _, n := range names {
		choices = append(choices, tui.Choice{ID: n, Label: "🗝️  " + n})
	}
	choices = append(choices,
		tui.Choice{ID: "roster.credential_policies.list.add", Label: "➕ 新增 Credential policy"},
		tui.Choice{ID: "roster.credential_policies.list.back", Label: "↩  返回"},
	)
	spec := tui.SelectSpec{ScreenID: "roster.credential_policies.list", Title: "Credential policies — SSH key hygiene", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return pushIdentityHardeningMenu(r, dir, path, "")
		}
		if m.Selected() < len(names) {
			return pushRosterCredentialPolicyDetail(r, dir, path, names[m.Selected()], "")
		}
		if m.Selected() == len(names) {
			return pushRosterAddCredentialPolicy(r, dir, path)
		}
		return pushIdentityHardeningMenu(r, dir, path, "")
	})
}

func pushRosterAddCredentialPolicy(r *editRouterModel, dir, path string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "roster.credential_policy.add", Title: "Credential policy 名稱(例如 privileged-ssh)", Validate: func(v string) error {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushRosterCredentialPoliciesMenu(r, dir, path, "")
		}
		name := strings.TrimSpace(m.Value())
		if err := inventory.AppendRosterCredentialPolicy(path, name); err != nil {
			r.err = err
			return nil
		}
		return pushRosterCredentialPolicyDetail(r, dir, path, name, "✅ 已新增；match.users/match.groups 至少要選一個")
	})
}

func pushRosterCredentialPolicyDetail(r *editRouterModel, dir, path, name, banner string) tea.Cmd {
	f, found, err := inventory.RosterCredentialPolicy(path, name)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushRosterCredentialPoliciesMenu(r, dir, path, "credential policy 已不存在")
	}
	match := rosterSubmap(f, "match")
	ssh := rosterSubmap(f, "ssh")
	matchUsers := rosterStringSlice(match, "users")
	matchGroups := rosterStringSlice(match, "groups")
	algorithms := rosterStringSlice(ssh, "allowed_algorithms")
	_, hasReview := f["review"]
	reviewNote := "未設定"
	if hasReview {
		reviewNote = "已設定 — 用 `pilot identity review list/mark` 管理"
	}
	choices := []tui.Choice{
		{ID: "roster.credential_policy.detail.name", Label: "name：" + name + "（唯讀）"},
		{ID: "roster.credential_policy.detail.state", Label: fmt.Sprintf("state：%s", rosterStringOr(f, "state", "present"))},
		{ID: "roster.credential_policy.detail.match_users", Label: fmt.Sprintf("match.users（%d 位）", len(matchUsers))},
		{ID: "roster.credential_policy.detail.match_groups", Label: fmt.Sprintf("match.groups（%d 個）", len(matchGroups))},
		{ID: "roster.credential_policy.detail.ssh_allowed_algorithms", Label: fmt.Sprintf("ssh.allowed_algorithms（%d 個；不設定 = 不限制）", len(algorithms))},
		{ID: "roster.credential_policy.detail.ssh_require_comment", Label: fmt.Sprintf("ssh.require_comment：%s", rosterBoolDisplay(ssh, "require_comment"))},
		{ID: "roster.credential_policy.detail.ssh_max_age", Label: fmt.Sprintf("ssh.max_age：%s（report-only，例如 365d）", rosterDisplay(ssh, "max_age"))},
		{ID: "roster.credential_policy.detail.review", Label: "review：" + reviewNote + "（唯讀，本畫面不編輯）"},
		{ID: "roster.credential_policy.detail.back", Label: "↩  返回"},
	}
	spec := tui.SelectSpec{ScreenID: "roster.credential_policy.detail", Title: "Credential policy " + name, Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() || m.Selected() == 8 {
			return pushRosterCredentialPoliciesMenu(r, dir, path, "")
		}
		switch m.Selected() {
		case 0:
			return pushRosterCredentialPolicyDetail(r, dir, path, name, "name 不可修改")
		case 1:
			return pushIdentityStateField(r, dir, path, name, "roster.credential_policy.field_state", func(r *editRouterModel, v string) tea.Cmd {
				return pushRosterCredentialPolicyEdit(r, dir, path, name, func(f map[string]any) { f["state"] = v })
			}, func(r *editRouterModel) tea.Cmd { return pushRosterCredentialPolicyDetail(r, dir, path, name, "") })
		case 2:
			allUsers, err := inventory.RosterUserNames(path)
			if err != nil {
				r.err = err
				return nil
			}
			return checklist(r, "roster.credential_policy.field_match_users", "match.users", allUsers, matchUsers, func(r *editRouterModel, v []string) tea.Cmd {
				return pushRosterCredentialPolicyEdit(r, dir, path, name, func(f map[string]any) {
					m := rosterSubmapClone(f, "match")
					m["users"] = v
					f["match"] = m
				})
			}, func(r *editRouterModel) tea.Cmd { return pushRosterCredentialPolicyDetail(r, dir, path, name, "") })
		case 3:
			allGroups, err := inventory.RosterGroupNames(path)
			if err != nil {
				r.err = err
				return nil
			}
			return checklist(r, "roster.credential_policy.field_match_groups", "match.groups", allGroups, matchGroups, func(r *editRouterModel, v []string) tea.Cmd {
				return pushRosterCredentialPolicyEdit(r, dir, path, name, func(f map[string]any) {
					m := rosterSubmapClone(f, "match")
					m["groups"] = v
					f["match"] = m
				})
			}, func(r *editRouterModel) tea.Cmd { return pushRosterCredentialPolicyDetail(r, dir, path, name, "") })
		case 4:
			return pushIdentityCommaListField(r, dir, path, "roster.credential_policy.field_algorithms", "ssh.allowed_algorithms（逗號分隔；例如 ssh-ed25519, ecdsa-sha2-nistp256）", algorithms, func(r *editRouterModel, v []string) tea.Cmd {
				return pushRosterCredentialPolicyEdit(r, dir, path, name, func(f map[string]any) {
					s := rosterSubmapClone(f, "ssh")
					if len(v) == 0 {
						delete(s, "allowed_algorithms")
					} else {
						s["allowed_algorithms"] = v
					}
					f["ssh"] = s
				})
			}, func(r *editRouterModel) tea.Cmd { return pushRosterCredentialPolicyDetail(r, dir, path, name, "") })
		case 5:
			return pushIdentityBoolField(r, dir, path, "roster.credential_policy.field_bool", "ssh.require_comment", func(r *editRouterModel, v bool) tea.Cmd {
				return pushRosterCredentialPolicyEdit(r, dir, path, name, func(f map[string]any) {
					s := rosterSubmapClone(f, "ssh")
					s["require_comment"] = v
					f["ssh"] = s
				})
			}, func(r *editRouterModel) tea.Cmd { return pushRosterCredentialPolicyDetail(r, dir, path, name, "") })
		case 6:
			return pushIdentityTextField(r, dir, path, "roster.credential_policy.field_duration", "ssh.max_age", rosterStringValue(ssh, "max_age"), func(r *editRouterModel, v string) tea.Cmd {
				return pushRosterCredentialPolicyEdit(r, dir, path, name, func(f map[string]any) {
					s := rosterSubmapClone(f, "ssh")
					setOrDeleteString(s, "max_age", v)
					f["ssh"] = s
				})
			}, func(r *editRouterModel) tea.Cmd { return pushRosterCredentialPolicyDetail(r, dir, path, name, "") })
		case 7:
			return pushRosterCredentialPolicyDetail(r, dir, path, name, "review 由 `pilot identity review mark "+path+" "+name+" --reviewer <you>` 管理")
		}
		return nil
	})
}

func pushRosterCredentialPolicyEdit(r *editRouterModel, dir, path, name string, mutate func(map[string]any)) tea.Cmd {
	f, found, err := inventory.RosterCredentialPolicy(path, name)
	if err != nil {
		r.err = err
		return nil
	}
	if !found {
		return pushRosterCredentialPoliciesMenu(r, dir, path, "credential policy 已不存在")
	}
	mutate(f)
	v, _, err := inventory.SimulateSetRosterCredentialPolicy(path, name, f)
	if err != nil {
		r.err = err
		return nil
	}
	if len(v) > 0 {
		return pushRosterCredentialPolicyDetail(r, dir, path, name, formatRosterViolations(v))
	}
	if err := inventory.SetRosterCredentialPolicy(path, name, f); err != nil {
		r.err = err
		return nil
	}
	return pushRosterCredentialPolicyDetail(r, dir, path, name, "✅ 已更新")
}

// ---- Privileged identity baseline (spec.md §9, singleton) --------------

func pushPrivilegedIdentityDetail(r *editRouterModel, dir, path, banner string) tea.Cmd {
	f, _, err := inventory.RosterPrivilegedIdentity(path)
	if err != nil {
		r.err = err
		return nil
	}
	if f == nil {
		f = map[string]any{}
	}
	matchGroups := rosterStringSlice(f, "match_groups")
	require := rosterSubmap(f, "require")
	authTypes := rosterStringSlice(require, "auth_types")
	choices := []tui.Choice{
		{ID: "roster.privileged_identity.detail.match_groups", Label: fmt.Sprintf("match_groups（%d 個；誰算「特權使用者」）", len(matchGroups))},
		{ID: "roster.privileged_identity.detail.auth_types", Label: fmt.Sprintf("require.auth_types（%d 個；符合其一即可）", len(authTypes))},
		{ID: "roster.privileged_identity.detail.no_password_only", Label: fmt.Sprintf("require.no_password_only：%s", rosterBoolDisplay(require, "no_password_only"))},
		{ID: "roster.privileged_identity.detail.ssh_key_policy", Label: fmt.Sprintf("require.ssh_key_policy：%s", rosterDisplay(require, "ssh_key_policy"))},
		{ID: "roster.privileged_identity.detail.back", Label: "↩  返回"},
	}
	spec := tui.SelectSpec{ScreenID: "roster.privileged_identity.detail", Title: "Privileged identity baseline — v3.2 §9", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() || m.Selected() == 4 {
			return pushIdentityHardeningMenu(r, dir, path, "")
		}
		switch m.Selected() {
		case 0:
			allGroups, err := inventory.RosterGroupNames(path)
			if err != nil {
				r.err = err
				return nil
			}
			return checklist(r, "roster.privileged_identity.field_match_groups", "match_groups", allGroups, matchGroups, func(r *editRouterModel, v []string) tea.Cmd {
				return pushPrivilegedIdentityEdit(r, dir, path, func(f map[string]any) { f["match_groups"] = v })
			}, func(r *editRouterModel) tea.Cmd { return pushPrivilegedIdentityDetail(r, dir, path, "") })
		case 1:
			return checklist(r, "roster.privileged_identity.field_auth_types", "require.auth_types", inventory.KnownUserAuthTypes(), authTypes, func(r *editRouterModel, v []string) tea.Cmd {
				return pushPrivilegedIdentityEdit(r, dir, path, func(f map[string]any) {
					req := rosterSubmapClone(f, "require")
					req["auth_types"] = v
					f["require"] = req
				})
			}, func(r *editRouterModel) tea.Cmd { return pushPrivilegedIdentityDetail(r, dir, path, "") })
		case 2:
			return pushIdentityBoolField(r, dir, path, "roster.privileged_identity.field_bool", "require.no_password_only", func(r *editRouterModel, v bool) tea.Cmd {
				return pushPrivilegedIdentityEdit(r, dir, path, func(f map[string]any) {
					req := rosterSubmapClone(f, "require")
					req["no_password_only"] = v
					f["require"] = req
				})
			}, func(r *editRouterModel) tea.Cmd { return pushPrivilegedIdentityDetail(r, dir, path, "") })
		case 3:
			return pushIdentityTextField(r, dir, path, "roster.privileged_identity.field_text", "require.ssh_key_policy", rosterStringValue(require, "ssh_key_policy"), func(r *editRouterModel, v string) tea.Cmd {
				return pushPrivilegedIdentityEdit(r, dir, path, func(f map[string]any) {
					req := rosterSubmapClone(f, "require")
					setOrDeleteString(req, "ssh_key_policy", v)
					f["require"] = req
				})
			}, func(r *editRouterModel) tea.Cmd { return pushPrivilegedIdentityDetail(r, dir, path, "") })
		}
		return nil
	})
}

func pushPrivilegedIdentityEdit(r *editRouterModel, dir, path string, mutate func(map[string]any)) tea.Cmd {
	f, _, err := inventory.RosterPrivilegedIdentity(path)
	if err != nil {
		r.err = err
		return nil
	}
	if f == nil {
		f = map[string]any{}
	} else {
		f = cloneRosterFields(f)
	}
	mutate(f)
	v, err := inventory.SimulateSetRosterPrivilegedIdentity(path, f)
	if err != nil {
		r.err = err
		return nil
	}
	if len(v) > 0 {
		return pushPrivilegedIdentityDetail(r, dir, path, formatRosterViolations(v))
	}
	if err := inventory.SetRosterPrivilegedIdentity(path, f); err != nil {
		r.err = err
		return nil
	}
	return pushPrivilegedIdentityDetail(r, dir, path, "✅ 已更新")
}

// ---- Hygiene report (read-only, spec.md §14) ---------------------------

// pushIdentityHygieneReport runs accessgrants.EvaluateIdentityHygiene
// against the roster file alone (no --inventory) — the same
// roster-only mode `pilot identity hygiene` supports when live FreeIPA
// capability data isn't needed/available; this wizard has no natural
// place to prompt for an inventory/vault-password-file/target-group, so
// it never attempts the live capability probe. Never mutates anything —
// selecting a row or canceling both just return to the menu (mirrors
// pushExplainAccessResults' read-only-results convention exactly).
func pushIdentityHygieneReport(r *editRouterModel, dir, path string) tea.Cmd {
	report, err := accessgrants.EvaluateIdentityHygiene(context.Background(), accessgrants.HygieneOptions{RosterFile: path, Now: time.Now()})
	if err != nil {
		r.err = err
		return nil
	}
	choices := make([]tui.Choice, 0, len(report.Users)+1)
	for _, u := range report.Users {
		label := fmt.Sprintf("%s | privileged=%t | auth=%s | ssh=%s | review=%s", u.Name, u.Privileged, u.AuthCompliance, u.SSHKeyCompliance, u.CredentialReview)
		choices = append(choices, tui.Choice{ID: "hygiene." + u.Name, Label: label})
	}
	title := fmt.Sprintf("Hygiene report（%s，共 %d 位使用者，%d 個 SSH finding，%d 個特權基準違規）",
		report.EvaluatedAt.Format(time.RFC3339), len(report.Users), len(report.SSHFindings), len(report.PrivilegedIdentityViolations))
	choices = append(choices, tui.Choice{ID: "roster.identity.hygiene.back", Label: "↩  返回"})
	spec := tui.SelectSpec{ScreenID: "roster.identity.hygiene", Title: title, Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		return pushIdentityHardeningMenu(r, dir, path, "")
	})
}

// ---- shared field-edit widgets ------------------------------------------
//
// These are generic across every screen above (password_policy/
// credential_policy/privileged_identity all need text/int/bool/state
// fields) — one shared set rather than three near-duplicates, following
// this package's own established "reuse one shared field" precedent
// (edit_automation.go's editAction struct doc comment).

var identityStateChoices = []string{"present", "absent"}

// pushIdentityStateField is the present/absent toggle password_policies/
// credential_policies both use — unlike users (rosterUserStateChoices,
// which deliberately excludes "absent"), these ARE declaratively
// soft-deletable via state: absent, matching every other list section in
// this schema (grants, hbac.rules, sudo.rules, ...).
func pushIdentityStateField(r *editRouterModel, dir, path, name, screenID string, commit func(*editRouterModel, string) tea.Cmd, cancel func(*editRouterModel) tea.Cmd) tea.Cmd {
	spec := tui.SelectSpec{ScreenID: screenID, Title: "state", Choices: rosterEnumChoices(screenID, identityStateChoices)}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return cancel(r)
		}
		return commit(r, identityStateChoices[m.Selected()])
	})
}

func pushIdentityTextField(r *editRouterModel, dir, path, screenID, title, current string, commit func(*editRouterModel, string) tea.Cmd, cancel func(*editRouterModel) tea.Cmd) tea.Cmd {
	spec := tui.InputSpec{ScreenID: screenID, Title: title + "（留空 = 清空）", Default: current}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return cancel(r)
		}
		return commit(r, strings.TrimSpace(m.Value()))
	})
}

func pushIdentityBoolField(r *editRouterModel, dir, path, screenID, title string, commit func(*editRouterModel, bool) tea.Cmd, cancel func(*editRouterModel) tea.Cmd) tea.Cmd {
	spec := tui.SelectSpec{ScreenID: screenID, Title: title, Choices: rosterEnumChoices(screenID, rosterBoolChoices)}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() {
			return cancel(r)
		}
		return commit(r, m.Selected() == 0)
	})
}

// pushIdentityIntField parses to (n, has) rather than rosterIntField's own
// "nil on empty" convention (pushRosterUserIntField): checkPasswordPolicies
// distinguishes "key absent" (no opinion) from "key present with a
// non-int value" (a validation error) via a presence check
// (`if raw, has := item[key]; has`) — a literal YAML `null` still counts
// as present there, so this must actually delete the key on empty input,
// not set it to nil, to mean "no opinion" the way the validator expects.
func pushIdentityIntField(r *editRouterModel, dir, path, screenID, title, current string, commit func(*editRouterModel, int, bool) tea.Cmd, cancel func(*editRouterModel) tea.Cmd) tea.Cmd {
	spec := tui.InputSpec{ScreenID: screenID, Title: title + "（留空 = 未設定；正整數）", Default: current, Validate: rosterIntValidator}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return cancel(r)
		}
		value := strings.TrimSpace(m.Value())
		if value == "" {
			return commit(r, 0, false)
		}
		n, _ := strconv.Atoi(value)
		return commit(r, n, true)
	})
}

// pushIdentityCommaListField edits a free-form comma-separated string
// list (ssh.allowed_algorithms — deliberately NOT a checklist, since
// spec.md §10 forbids Pilot from imposing any fixed algorithm enum: the
// roster author may type any algorithm name).
func pushIdentityCommaListField(r *editRouterModel, dir, path, screenID, title string, current []string, commit func(*editRouterModel, []string) tea.Cmd, cancel func(*editRouterModel) tea.Cmd) tea.Cmd {
	spec := tui.InputSpec{ScreenID: screenID, Title: title, Default: strings.Join(current, ", ")}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return cancel(r)
		}
		var out []string
		for _, v := range strings.Split(m.Value(), ",") {
			if v = strings.TrimSpace(v); v != "" {
				out = append(out, v)
			}
		}
		return commit(r, out)
	})
}

// setOrDeleteInt sets f[key]=n when has, or deletes f[key] entirely when
// !has — see pushIdentityIntField's doc comment for why this must delete
// rather than set nil.
func setOrDeleteInt(f map[string]any, key string, n int, has bool) {
	if !has {
		delete(f, key)
		return
	}
	f[key] = n
}

// setOrDeleteString sets f[key]=v when v is non-empty, or deletes f[key]
// entirely when v is empty — the string-field counterpart to
// setOrDeleteInt, for the same "absent means no opinion" reason.
func setOrDeleteString(f map[string]any, key, v string) {
	if v == "" {
		delete(f, key)
		return
	}
	f[key] = v
}

// setLockout writes lo back into f["lockout"], or removes the whole
// lockout: block once every field inside it has been cleared — an empty
// lockout: {} is syntactically harmless (checkPasswordPolicies has no
// required lockout field) but a needless empty block in the rendered
// YAML, so this keeps the roster tidy the same way setOrDeleteString
// keeps a single field tidy.
func setLockout(f map[string]any, lo map[string]any) {
	if len(lo) == 0 {
		delete(f, "lockout")
		return
	}
	f["lockout"] = lo
}
