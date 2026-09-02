// edit_tui_decommission.go replaces the old direct "🗑 刪除這台主機" delete
// action (spec.md §7.2/§11): selecting it never mutates hf immediately.
// It plans (read-only, decommission.PlanHost), persists the plan, and
// shows a summary screen; a host is only actually removed after a
// completed decommission (INV-1) — driven through the exact same
// runHostDecommissionApply orchestration host_decommission.go's `apply`
// CLI command uses, never a separate/divergent implementation, and never
// a subprocess shell-out to `pilot` itself.
package cmd

import (
	"context"
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"

	"github.com/kjelly/pilot/internal/decommission"
	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/tui"
)

// pushDecommissionFlow is the host menu's "🗑 下架 / Decommission 主機"
// action (spec.md §11.1): it plans read-only and shows a summary screen.
// It never calls removeHost and never mutates hf.
func pushDecommissionFlow(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name string) tea.Cmd {
	st, err := openSpecStore()
	if err != nil {
		return pushDecommissionError(r, dir, path, hf, name, fmt.Errorf("開啟 pilot store 失敗：%w", err))
	}
	ds := decommission.NewStore(st)

	catalog, _ := loadContractCatalogBestEffort()
	plan, err := decommission.PlanHost(context.Background(), decommission.PlanInput{
		WorkspaceDir: dir, HostName: name, Catalog: catalog,
	})
	if err != nil {
		_ = st.Close()
		return pushDecommissionError(r, dir, path, hf, name, err)
	}
	if err := ds.SavePlan(plan); err != nil {
		_ = st.Close()
		return pushDecommissionError(r, dir, path, hf, name, fmt.Errorf("儲存 decommission plan 失敗：%w", err))
	}
	_ = st.Close()

	return pushDecommissionPlanSummary(r, dir, path, hf, name, plan)
}

// decommissionPlanSummaryText renders plan's plan/blocker/reference
// summary (spec.md §11.1: host, roles, component cleanup order, external
// managed resources, references, retention requirements, blockers).
func decommissionPlanSummaryText(plan *decommission.Plan) string {
	var b strings.Builder
	fmt.Fprintf(&b, "下架主機 %q 的規劃\n", plan.Host.Name)
	fmt.Fprintf(&b, "plan id：%s　狀態：%s　hash=%s\n", plan.ID, plan.Status, shortHash(plan.PlanHash))
	if len(plan.Host.Roles) > 0 {
		fmt.Fprintf(&b, "角色：%s\n", strings.Join(plan.Host.Roles, ", "))
	} else {
		b.WriteString("角色：(無)\n")
	}
	if len(plan.TeardownOrder) > 0 {
		fmt.Fprintf(&b, "元件拆除順序：%s\n", strings.Join(plan.TeardownOrder, " -> "))
	}
	for _, c := range plan.Components {
		fmt.Fprintf(&b, "  元件 role=%s id=%s 可執行=%v\n", c.Role, c.ComponentID, !c.Blocked())
		for _, bl := range c.Blockers {
			fmt.Fprintf(&b, "    ⛔ [%s] %s\n", bl.Code, bl.Detail)
		}
	}
	for _, ref := range plan.References {
		fmt.Fprintf(&b, "  參照 %s/%s %q -> %s（%s）\n", ref.Source, ref.Kind, ref.Identity, ref.Classification, ref.Detail)
	}
	for _, req := range plan.RetentionRequirements {
		fmt.Fprintf(&b, "  保留需求 component=%s satisfied=%v\n", req.ComponentID, req.Satisfied)
	}
	for _, bl := range plan.Blockers {
		fmt.Fprintf(&b, "⛔ [%s] %s\n", bl.Code, bl.Detail)
	}
	for _, w := range plan.Warnings {
		fmt.Fprintf(&b, "⚠️  [%s] %s\n", w.Code, w.Detail)
	}
	return b.String()
}

const (
	decommissionChoiceConfirm = "hosts.decommission.confirm"
	decommissionChoiceBack    = "hosts.decommission.back"
)

// pushDecommissionPlanSummary is spec.md §11.1's plan summary screen.
// §11.2: a blocked plan offers no destructive control at all — only
// return/edit. §11.3: an executable plan's "continue" choice leads to the
// exact-host-name confirmation, never straight to execution.
func pushDecommissionPlanSummary(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name string, plan *decommission.Plan) tea.Cmd {
	title := decommissionPlanSummaryText(plan)

	var choices []tui.Choice
	if plan.Blocked() {
		choices = []tui.Choice{
			{ID: decommissionChoiceBack, Label: "↩  返回主機設定（下架目前被封鎖，無法繼續）"},
		}
	} else {
		choices = []tui.Choice{
			{ID: decommissionChoiceConfirm, Label: "✅  繼續 — 下一步需輸入主機名稱確認"},
			{ID: decommissionChoiceBack, Label: "↩  返回，不下架"},
		}
	}

	spec := tui.SelectSpec{ScreenID: "hosts.decommission.plan", Title: title, Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.SelectScreen)
		if m.Canceled() || m.SelectedID() != decommissionChoiceConfirm {
			return pushHostMenu(r, dir, path, hf, name)
		}
		return pushDecommissionConfirmHostName(r, dir, path, hf, name, plan)
	})
}

// pushDecommissionConfirmHostName is spec.md §11.3: typing the exact host
// name is required to proceed; default (esc/cancel/mismatch) is cancel —
// it never falls through to execution.
func pushDecommissionConfirmHostName(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name string, plan *decommission.Plan) tea.Cmd {
	title := fmt.Sprintf("輸入主機名稱 %q 以確認下架（Esc = 取消，預設不下架）", name)
	validate := func(v string) error {
		if strings.TrimSpace(v) != name {
			return fmt.Errorf("必須完全輸入主機名稱 %q 才能確認下架", name)
		}
		return nil
	}
	spec := tui.InputSpec{ScreenID: "hosts.decommission.confirm_name", Title: title, Validate: validate}
	return r.transitionTo(r.uiFactory().Input(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(tui.InputScreen)
		if m.Canceled() || strings.TrimSpace(m.Value()) != name {
			return pushDecommissionPlanSummary(r, dir, path, hf, name, plan)
		}
		return pushDecommissionExecute(r, dir, path, hf, name, plan)
	})
}

// pushDecommissionExecute drives the confirmed decommission through the
// same runHostDecommissionApply orchestration the CLI's `apply` command
// uses (host_decommission.go) — never a subprocess `pilot` call. On
// success it syncs the in-memory hf mirror (the host is already safely
// removed on disk by Finalize at this point — this call is bookkeeping,
// not the destructive action) and reports the outcome; on block/error it
// shows spec.md §11.5's failure screen with the resumable plan ID.
func pushDecommissionExecute(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name string, plan *decommission.Plan) tea.Cmd {
	st, err := openSpecStore()
	if err != nil {
		return pushDecommissionError(r, dir, path, hf, name, fmt.Errorf("開啟 pilot store 失敗：%w", err))
	}
	defer func() { _ = st.Close() }()
	ds := decommission.NewStore(st)

	catalog, _ := loadContractCatalogBestEffort()
	result, err := runHostDecommissionApply(context.Background(), ds, plan, dir, catalog, "confirmed via pilot edit TUI (typed exact host name)")
	if err != nil {
		return pushDecommissionError(r, dir, path, hf, name, err)
	}

	switch result.Status {
	case "completed":
		removeHost(hf, name)
		return pushHostList(r, dir, path, hf, fmt.Sprintf("已完成下架主機 %q（decommission_id=%s，hosts.yml/inventory.yml 已更新）。", name, plan.ID))
	case "already_completed":
		removeHost(hf, name)
		return pushHostList(r, dir, path, hf, fmt.Sprintf("主機 %q 的下架先前已完成（plan=%s），未重複執行。", name, plan.ID))
	default: // "blocked"
		return pushDecommissionFailure(r, dir, path, hf, name, plan, result)
	}
}

// pushDecommissionFailure is spec.md §11.5: completed steps, the blocking
// reason, the plan ID, and a resume action — never implying rollback
// recreated anything.
func pushDecommissionFailure(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name string, plan *decommission.Plan, result *decommission.FinalizeResult) tea.Cmd {
	var b strings.Builder
	fmt.Fprintf(&b, "下架主機 %q 尚未完成（plan id=%s）\n", name, plan.ID)
	b.WriteString("主機仍保留在 hosts.yml 中；尚未進行任何刪除，也沒有還原任何已完成的清理。\n")
	for _, bl := range result.Blockers {
		fmt.Fprintf(&b, "⛔ %s\n", bl)
	}
	fmt.Fprintf(&b, "之後可用 `pilot host decommission resume --id %s` 或重新進入這個畫面繼續。\n", plan.ID)

	choices := []tui.Choice{{ID: decommissionChoiceBack, Label: "↩  返回主機設定"}}
	spec := tui.SelectSpec{ScreenID: "hosts.decommission.failure", Title: b.String(), Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		return pushHostMenu(r, dir, path, hf, name)
	})
}

// pushDecommissionError shows a plain error screen (planning failed
// outright — e.g. the store could not be opened, or the workspace could
// not be read) with only a way back; it never mutates hf.
func pushDecommissionError(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name string, err error) tea.Cmd {
	choices := []tui.Choice{{ID: decommissionChoiceBack, Label: "↩  返回主機設定"}}
	spec := tui.SelectSpec{ScreenID: "hosts.decommission.error", Title: fmt.Sprintf("下架規劃失敗：%v", err), Choices: choices}
	return r.transitionTo(r.uiFactory().Select(spec), "", func(r *editRouterModel, s screen) tea.Cmd {
		return pushHostMenu(r, dir, path, hf, name)
	})
}
