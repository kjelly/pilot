// edit_tui_roster_breakglass.go implements spec.md §14/§16's interactive
// surfaces under "Access governance" (§17): activating/deactivating a
// kind: breakglass grant and viewing its activation history, and the
// read-only "Explain access" query. Both wrap the exact same
// internal/accessgrants functions `pilot access breakglass`/`pilot access
// explain` call (access_breakglass_cli.go, access_explain_cli.go) — there
// is no separate business logic here, only screens.
package cmd

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/kjelly/pilot/internal/accessgrants"
	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/tui"
)

// accessGovernanceInventoryPath is the default inventory this workspace's
// Access governance screens apply compiled grants/breakglass activations
// against — the same `<dir>/inventory.yml` convention
// minimalWorkspaceReadyBanner documents for `pilot deploy`.
func accessGovernanceInventoryPath(dir string) string {
	return filepath.Join(dir, "inventory.yml")
}

func breakglassGrantNames(path string) ([]string, error) {
	names, err := inventory.RosterGrantNames(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, n := range names {
		f, ok, err := inventory.RosterGrant(path, n)
		if err != nil {
			return nil, err
		}
		if ok && rosterStringValue(f, "kind") == "breakglass" {
			out = append(out, n)
		}
	}
	return out, nil
}

func pushBreakglassMenu(r *editRouterModel, dir, path, banner string) tea.Cmd {
	names, err := breakglassGrantNames(path)
	if err != nil {
		r.err = err
		return nil
	}
	choices := make([]tui.Choice, 0, len(names)+2)
	for _, n := range names {
		choices = append(choices, tui.Choice{ID: n, Label: "🚨 " + n})
	}
	choices = append(choices,
		tui.Choice{ID: "roster.breakglass.list.status", Label: "📋 所有啟用紀錄（status）"},
		tui.Choice{ID: "roster.breakglass.list.back", Label: "↩  返回"},
	)
	spec := tui.SelectSpec{ScreenID: "roster.breakglass.list", Title: "Break-glass — 緊急存取定義（啟用/停用）", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() || m.Selected() == len(choices)-1 {
			return pushAccessGovernanceMenu(r, dir, path, "")
		}
		if m.Selected() < len(names) {
			return pushBreakglassDetail(r, dir, path, names[m.Selected()], "")
		}
		return pushBreakglassStatus(r, dir, path, "", "")
	})
}

func pushBreakglassDetail(r *editRouterModel, dir, path, name, banner string) tea.Cmd {
	now := time.Now()
	activations, err := accessgrants.Status(resolveDataDir(), name)
	if err != nil {
		r.err = err
		return nil
	}
	active := false
	for _, a := range activations {
		if a.IsActive(now) {
			active = true
			break
		}
	}
	stateLabel := "🔴 目前未啟用"
	if active {
		stateLabel = "🟢 目前已啟用"
	}
	choices := []tui.Choice{
		{ID: "roster.breakglass.detail.state", Label: stateLabel},
		{ID: "roster.breakglass.detail.definition", Label: "📄 查看定義（subjects/targets/activation policy）"},
		{ID: "roster.breakglass.detail.activate", Label: "▶️  Activate"},
		{ID: "roster.breakglass.detail.deactivate", Label: "⏹  Deactivate"},
		{ID: "roster.breakglass.detail.history", Label: fmt.Sprintf("📋 啟用紀錄（%d 筆）", len(activations))},
		{ID: "roster.breakglass.detail.back", Label: "↩  返回"},
	}
	spec := tui.SelectSpec{ScreenID: "roster.breakglass.detail", Title: "Break-glass " + name, Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() || m.Selected() == 5 {
			return pushBreakglassMenu(r, dir, path, "")
		}
		switch m.Selected() {
		case 0:
			return pushBreakglassDetail(r, dir, path, name, "")
		case 1:
			return pushGrantDetail(r, dir, path, name, "")
		case 2:
			return pushBreakglassActivateDuration(r, dir, path, name)
		case 3:
			return pushBreakglassDeactivateConfirm(r, dir, path, name)
		case 4:
			return pushBreakglassStatus(r, dir, path, name, "")
		}
		return nil
	})
}

func pushBreakglassActivateDuration(r *editRouterModel, dir, path, name string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "roster.breakglass.activate.duration", Title: "啟用時長 --duration（例如 45m、1h；不可超過 activation.max_duration）", Validate: func(v string) error {
		if !inventory.ValidAccessDuration(strings.TrimSpace(v)) {
			return fmt.Errorf("格式須為 <數字>(m|h|d)，例如 30m、1h")
		}
		return nil
	}}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushBreakglassDetail(r, dir, path, name, "")
		}
		return pushBreakglassActivateReason(r, dir, path, name, strings.TrimSpace(m.Value()))
	})
}

func pushBreakglassActivateReason(r *editRouterModel, dir, path, name, duration string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "roster.breakglass.activate.reason", Title: "--reason（依 activation.require_reason 決定是否必填）"}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushBreakglassDetail(r, dir, path, name, "")
		}
		return pushBreakglassActivateTicket(r, dir, path, name, duration, strings.TrimSpace(m.Value()))
	})
}

func pushBreakglassActivateTicket(r *editRouterModel, dir, path, name, duration, reason string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "roster.breakglass.activate.ticket", Title: "--ticket（依 activation.require_ticket 決定是否必填）"}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushBreakglassDetail(r, dir, path, name, "")
		}
		ticket := strings.TrimSpace(m.Value())
		parsed, err := inventory.ParseAccessDuration(duration)
		if err != nil {
			return pushBreakglassDetail(r, dir, path, name, "❌ "+err.Error())
		}
		activation, err := accessgrants.Activate(context.Background(), accessgrants.ActivateOptions{
			RosterFile:  path,
			Inventory:   accessGovernanceInventoryPath(dir),
			StateDir:    resolveDataDir(),
			Name:        name,
			Duration:    parsed,
			Reason:      reason,
			Ticket:      ticket,
			ActivatedBy: activatedByCurrentUser(),
			Now:         time.Now(),
		})
		if err != nil {
			return pushBreakglassDetail(r, dir, path, name, "❌ "+err.Error())
		}
		return pushBreakglassDetail(r, dir, path, name, fmt.Sprintf("✅ 已啟用，到期時間 %s", activation.ExpiresAt.Format(time.RFC3339)))
	})
}

func pushBreakglassDeactivateConfirm(r *editRouterModel, dir, path, name string) tea.Cmd {
	choices := []tui.Choice{
		{ID: "roster.breakglass.deactivate.yes", Label: "是，立即停用"},
		{ID: "roster.breakglass.deactivate.no", Label: "取消"},
	}
	spec := tui.SelectSpec{ScreenID: "roster.breakglass.deactivate.confirm", Title: "確定要停用 " + name + " 嗎？", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() || m.Selected() == 1 {
			return pushBreakglassDetail(r, dir, path, name, "")
		}
		if err := accessgrants.Deactivate(context.Background(), accessgrants.DeactivateOptions{
			RosterFile: path,
			Inventory:  accessGovernanceInventoryPath(dir),
			StateDir:   resolveDataDir(),
			Name:       name,
			Now:        time.Now(),
		}); err != nil {
			return pushBreakglassDetail(r, dir, path, name, "❌ "+err.Error())
		}
		return pushBreakglassDetail(r, dir, path, name, "✅ 已停用")
	})
}

// pushBreakglassStatus shows activation history for one name, or every
// breakglass grant's history when name is "".
func pushBreakglassStatus(r *editRouterModel, dir, path, name, banner string) tea.Cmd {
	activations, err := accessgrants.Status(resolveDataDir(), name)
	if err != nil {
		r.err = err
		return nil
	}
	now := time.Now()
	choices := make([]tui.Choice, 0, len(activations)+1)
	for _, a := range activations {
		state := "inactive"
		if a.IsActive(now) {
			state = "active"
		}
		label := fmt.Sprintf("%s | %s | %s → %s | %s", a.Name, state, a.ActivatedAt.Format(time.RFC3339), a.ExpiresAt.Format(time.RFC3339), a.Reason)
		choices = append(choices, tui.Choice{ID: a.Name, Label: label})
	}
	choices = append(choices, tui.Choice{ID: "roster.breakglass.status.back", Label: "↩  返回"})
	spec := tui.SelectSpec{ScreenID: "roster.breakglass.status", Title: "Break-glass 啟用紀錄（最新在前）", Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		if name != "" {
			return pushBreakglassDetail(r, dir, path, name, "")
		}
		return pushBreakglassMenu(r, dir, path, "")
	})
}

// pushExplainAccessPrompt is the interactive equivalent of `pilot access
// explain` (spec.md §16) — three sequential inputs (user/host/service),
// then a read-only results screen.
func pushExplainAccessPrompt(r *editRouterModel, dir, path, banner string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "roster.explain.user", Title: "--user", Validate: func(v string) error {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}}
	return r.transitionTo(r.uiFactory().Input(spec), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushAccessGovernanceMenu(r, dir, path, "")
		}
		return pushExplainAccessHost(r, dir, path, strings.TrimSpace(m.Value()))
	})
}

func pushExplainAccessHost(r *editRouterModel, dir, path, user string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "roster.explain.host", Title: "--host", Validate: func(v string) error {
		if strings.TrimSpace(v) == "" {
			return fmt.Errorf("不能留空")
		}
		return nil
	}}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushAccessGovernanceMenu(r, dir, path, "")
		}
		return pushExplainAccessService(r, dir, path, user, strings.TrimSpace(m.Value()))
	})
}

func pushExplainAccessService(r *editRouterModel, dir, path, user, host string) tea.Cmd {
	spec := tui.InputSpec{ScreenID: "roster.explain.service", Title: "--service（sudo_grant 不需要，可留空）"}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() {
			return pushAccessGovernanceMenu(r, dir, path, "")
		}
		return pushExplainAccessResults(r, dir, path, user, host, strings.TrimSpace(m.Value()))
	})
}

func pushExplainAccessResults(r *editRouterModel, dir, path, user, host, service string) tea.Cmd {
	sources, err := accessgrants.Explain(path, resolveDataDir(), user, host, service, time.Now())
	if err != nil {
		r.err = err
		return nil
	}
	choices := make([]tui.Choice, 0, len(sources)+1)
	for _, s := range sources {
		userPath := "direct"
		if !s.DirectUserHit {
			userPath = fmt.Sprintf("via group %v", s.GroupPath)
		}
		hostPath := "direct"
		if s.AllHosts {
			hostPath = "hostcat: all"
		} else if !s.DirectHostHit {
			hostPath = fmt.Sprintf("via hostgroup %v", s.HostgroupPath)
		}
		label := fmt.Sprintf("%s | %s | user:%s | host:%s", s.Kind, s.Rule, userPath, hostPath)
		choices = append(choices, tui.Choice{ID: s.Rule, Label: label})
	}
	title := fmt.Sprintf("Explain access — %s @ %s (%s)：%d 個來源", user, host, service, len(sources))
	if len(sources) == 0 {
		title = fmt.Sprintf("Explain access — %s @ %s (%s)：查無存取來源", user, host, service)
	}
	choices = append(choices, tui.Choice{ID: "roster.explain.results.back", Label: "↩  返回"})
	spec := tui.SelectSpec{ScreenID: "roster.explain.results", Title: title, Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		return pushAccessGovernanceMenu(r, dir, path, "")
	})
}
