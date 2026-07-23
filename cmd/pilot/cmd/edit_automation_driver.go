package cmd

import (
	"fmt"
	"io"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// automationTraceEvent records the observable outcome of one semantic action.
// It intentionally contains no action values so it is safe to write beside a
// presentation recording.
type automationTraceEvent struct {
	Step     int      `json:"step"`
	Action   string   `json:"action"`
	ScreenID string   `json:"screen_id"`
	Keys     []string `json:"keys,omitempty"`
	Result   string   `json:"result"`
	Error    string   `json:"error,omitempty"`
}

// automationDriver translates semantic edit actions into the same key
// messages handled by a human-driven editRouterModel.
type automationDriver struct {
	trace        func(automationTraceEvent)
	presentation bool
	out          io.Writer
	keys         []string
}

func (d *automationDriver) run(r *editRouterModel, scenario editScenario) error {
	if err := validateEditScenario(scenario); err != nil {
		return err
	}
	for i, step := range scenario.Steps {
		d.keys = nil
		err := d.runStep(r, step)
		event := automationTraceEvent{
			Step:     i + 1,
			Action:   step.Action,
			ScreenID: automationScreenID(r),
			Keys:     append([]string(nil), d.keys...),
			Result:   "ok",
		}
		if err != nil {
			event.Result = "error"
			event.Error = err.Error()
			if d.trace != nil {
				d.trace(event)
			}
			return fmt.Errorf("step %d (%s): %w", i+1, step.Action, err)
		}
		if d.presentation && d.out != nil {
			fmt.Fprintf(d.out, "\n── %s ──\n%s", step.Action, r.View())
		}
		if d.trace != nil {
			d.trace(event)
		}
	}
	return nil
}

func (d *automationDriver) runStep(r *editRouterModel, step editAction) error {
	switch step.Action {
	case "create_host":
		return d.createHost(r, step.Host)
	case "set_host_field":
		return d.setHostField(r, step.Host, step.Field, step.Value)
	case "enable_role":
		return d.enableRole(r, step.Host, step.Role)
	case "save_hosts":
		return d.saveHosts(r)
	default:
		return fmt.Errorf("unsupported action %q", step.Action)
	}
}

func (d *automationDriver) createHost(r *editRouterModel, host string) error {
	if err := d.ensureHostsList(r); err != nil {
		return err
	}
	if list, ok := r.current.(selectModel); !ok || !strings.Contains(list.title, "編輯") {
		return fmt.Errorf("expected host list screen")
	} else if err := d.choose(r, "新增主機"); err != nil {
		return err
	}
	if err := d.typeText(r, host, false); err != nil {
		return err
	}
	return d.enter(r)
}

func (d *automationDriver) setHostField(r *editRouterModel, host, field, value string) error {
	if err := d.ensureHostMenu(r, host); err != nil {
		return err
	}
	labels := map[string]string{
		"ansible_host": "ansible_host(連線位址)",
		"ansible_user": "ansible_user(登入帳號)",
		"ssh_key_file": "SSH 私鑰路徑",
	}
	label, ok := labels[field]
	if !ok {
		return fmt.Errorf("unsupported host field")
	}
	if err := d.choose(r, label); err != nil {
		return err
	}
	if err := d.typeText(r, value, true); err != nil {
		return err
	}
	return d.enter(r)
}

func (d *automationDriver) enableRole(r *editRouterModel, host, role string) error {
	if err := d.ensureHostMenu(r, host); err != nil {
		return err
	}
	if err := d.choose(r, "角色(roles)"); err != nil {
		return err
	}
	if err := d.choose(r, "逐項勾選角色"); err != nil {
		return err
	}
	list, ok := r.current.(multiSelectModel)
	if !ok {
		return fmt.Errorf("expected role checklist screen")
	}
	idx, err := uniqueItemIndex(list.automationItems(), role)
	if err != nil {
		return err
	}
	if !list.items[idx].Checked {
		if err := d.moveCursor(r, idx); err != nil {
			return err
		}
		if err := d.send(r, tea.KeyMsg{Type: tea.KeySpace}); err != nil {
			return err
		}
	}
	if err := d.enter(r); err != nil {
		return err
	}
	return d.choose(r, "✅ 完成")
}

func (d *automationDriver) saveHosts(r *editRouterModel) error {
	if list, ok := r.current.(selectModel); ok && strings.Contains(list.title, "選要編輯的項目") {
		if err := d.choose(r, "返回主機清單"); err != nil {
			return err
		}
	}
	list, ok := r.current.(selectModel)
	if !ok || !strings.Contains(list.title, "編輯") {
		return fmt.Errorf("expected host list before save")
	}
	if err := d.choose(r, "存檔並離開"); err != nil {
		return err
	}
	if err := d.choose(r, "離開"); err != nil {
		return err
	}
	return nil
}

func (d *automationDriver) ensureHostMenu(r *editRouterModel, host string) error {
	if list, ok := r.current.(selectModel); ok && strings.Contains(list.title, "選要編輯") {
		if strings.Contains(list.title, fmt.Sprintf("主機 %q", host)) {
			return nil
		}
		if err := d.choose(r, "返回主機清單"); err != nil {
			return err
		}
	}
	if err := d.ensureHostsList(r); err != nil {
		return err
	}
	return d.choose(r, host)
}

func (d *automationDriver) ensureHostsList(r *editRouterModel) error {
	if list, ok := r.current.(selectModel); ok {
		switch {
		case list.title == "要編輯什麼？":
			if err := d.choose(r, "hosts.yml"); err != nil {
				return err
			}
		case strings.Contains(list.title, "編輯") && strings.Contains(list.title, "選一台主機"):
			return nil
		case strings.Contains(list.title, "選要編輯的項目"):
			return fmt.Errorf("host menu must return to host list first")
		}
	}
	if input, ok := r.current.(textInputModel); ok && input.label == "hosts.yml 路徑" {
		if err := d.enter(r); err != nil {
			return err
		}
	}
	if _, ok := r.current.(confirmModel); ok {
		if err := d.enter(r); err != nil {
			return err
		}
	}
	if list, ok := r.current.(selectModel); ok && strings.Contains(list.title, "編輯") && strings.Contains(list.title, "選一台主機") {
		return nil
	}
	return fmt.Errorf("expected hosts list screen, got %s", automationScreenID(r))
}

func (d *automationDriver) choose(r *editRouterModel, label string) error {
	list, ok := r.current.(selectModel)
	if !ok {
		return fmt.Errorf("cannot choose %q on %s screen", label, automationScreenID(r))
	}
	idx, err := uniqueItemIndex(list.items, label)
	if err != nil {
		return err
	}
	if err := d.moveCursor(r, idx); err != nil {
		return err
	}
	return d.enter(r)
}

func (d *automationDriver) moveCursor(r *editRouterModel, target int) error {
	var cursor int
	switch list := r.current.(type) {
	case selectModel:
		cursor = list.cursor
	case multiSelectModel:
		cursor = list.cursor
	default:
		return fmt.Errorf("cannot move cursor on %s screen", automationScreenID(r))
	}
	for cursor > 0 {
		if err := d.send(r, tea.KeyMsg{Type: tea.KeyUp}); err != nil {
			return err
		}
		cursor--
	}
	for cursor < target {
		if err := d.send(r, tea.KeyMsg{Type: tea.KeyDown}); err != nil {
			return err
		}
		cursor++
	}
	return nil
}

func (d *automationDriver) typeText(r *editRouterModel, value string, replace bool) error {
	if _, ok := r.current.(textInputModel); !ok {
		return fmt.Errorf("cannot type on %s screen", automationScreenID(r))
	}
	if replace {
		if err := d.send(r, tea.KeyMsg{Type: tea.KeyCtrlU}); err != nil {
			return err
		}
	}
	if value != "" {
		if err := d.send(r, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(value)}); err != nil {
			return err
		}
	}
	return nil
}

func (d *automationDriver) enter(r *editRouterModel) error {
	return d.send(r, tea.KeyMsg{Type: tea.KeyEnter})
}

func (d *automationDriver) send(r *editRouterModel, msg tea.KeyMsg) error {
	d.keys = append(d.keys, msg.String())
	model, _ := r.Update(msg)
	next, ok := model.(editRouterModel)
	if !ok {
		return fmt.Errorf("edit router returned unexpected model")
	}
	*r = next
	if r.err != nil {
		return r.err
	}
	return nil
}

func uniqueItemIndex(items []string, label string) (int, error) {
	exact := -1
	exactCount := 0
	for i, item := range items {
		if item == label {
			exact = i
			exactCount++
		}
	}
	if exactCount == 1 {
		return exact, nil
	}
	if exactCount > 1 {
		return -1, fmt.Errorf("label %q is ambiguous", label)
	}
	index := -1
	for i, item := range items {
		if !strings.Contains(item, label) {
			continue
		}
		if index >= 0 {
			return -1, fmt.Errorf("label %q is ambiguous", label)
		}
		index = i
	}
	if index < 0 {
		return -1, fmt.Errorf("label %q not found", label)
	}
	return index, nil
}

func automationScreenID(r *editRouterModel) string {
	if r == nil || r.current == nil {
		return "none"
	}
	return r.current.automationScreenID()
}
