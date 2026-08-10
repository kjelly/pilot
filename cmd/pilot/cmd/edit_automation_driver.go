package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

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
// messages handled by a human-driven editRouterModel. In presentation mode it
// also renders that expansion as keyboard commands, so a PTY recording makes
// the operation auditable instead of showing only the high-level action name.
type automationDriver struct {
	trace        func(automationTraceEvent)
	presentation bool
	out          io.Writer
	keys         []string
	// dir is the --dir value the router was built with. It's only needed to
	// construct a full path when creating a brand-new .vault/ file that
	// doesn't show up in the file picker yet (openVaultFile) — every other
	// navigation resolves against on-screen labels alone.
	dir string
	// marker, if non-nil, receives one line per completed step (same
	// action/result/error fields as the trace event, so it carries no
	// action values either). This drives the router directly against the
	// TUI model rather than through real PTY keystrokes, so a trec
	// recording wrapping this process would otherwise have "o" output but
	// no "i"/"m" trail of what produced each screen. Wired to
	// TREC_MARKER_FD when trec is the one running this process; nil
	// (no-op) otherwise.
	marker io.Writer
	// pausePresentation keeps each rendered screen visible long enough for a
	// presentation recording to show the transition. It is injected so model
	// tests do not need to wait in real time.
	pausePresentation func(time.Duration)
	// recorder observes each key/frame/action boundary (see edit_audit.go)
	// without altering driver behavior. Left unset by every existing
	// construction of automationDriver, so recorderOrNoop's noopAuditRecorder
	// fallback makes this field's addition behavior-neutral.
	recorder AuditRecorder
	frameSeq int
}

// recorderOrNoop is every recorder-calling site's entry point — never
// read d.recorder directly, so a driver built before AuditRecorder
// existed (every current construction) keeps behaving exactly as it
// did.
func (d *automationDriver) recorderOrNoop() AuditRecorder {
	if d.recorder == nil {
		return noopAuditRecorder{}
	}
	return d.recorder
}

func (d *automationDriver) run(r *editRouterModel, scenario editScenario) error {
	if err := validateEditScenario(scenario); err != nil {
		return err
	}
	for i, step := range scenario.Steps {
		d.keys = nil
		if err := d.recorderOrNoop().RecordActionStart(step); err != nil {
			return fmt.Errorf("step %d (%s): record action start: %w", i+1, step.Action, err)
		}
		err := d.runStep(r, step)
		if recErr := d.recorderOrNoop().RecordActionResult(step, err); recErr != nil && err == nil {
			err = fmt.Errorf("record action result: %w", recErr)
		}
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
			d.emitMarker(event)
			if d.trace != nil {
				d.trace(event)
			}
			return fmt.Errorf("step %d (%s): %w", i+1, step.Action, err)
		}
		if d.presentation && d.out != nil {
			fmt.Fprintf(d.out, "\n── %s ──\n⌨ 按鍵：%s\n%s", step.Action, formatKeyboardCommands(event.Keys), r.View())
			d.pause(time.Second)
		}
		d.emitMarker(event)
		if d.trace != nil {
			d.trace(event)
		}
	}
	return nil
}

func (d *automationDriver) pause(duration time.Duration) {
	if d.pausePresentation != nil {
		d.pausePresentation(duration)
	}
}

// formatKeyboardCommands turns the driver's low-level Tea key trace into a
// compact, recording-friendly representation. Consecutive cursor moves are
// folded only for display; the driver still sends every individual KeyMsg to
// the router, exactly as a human-driven session would receive them.
func formatKeyboardCommands(keys []string) string {
	if len(keys) == 0 {
		return "（無；此操作未送出按鍵）"
	}

	labels := map[string]string{
		"up":         "↑",
		"down":       "↓",
		"enter":      "Enter",
		"space":      "Space",
		"ctrl+u":     "Ctrl+U",
		"«redacted»": "TEXT «redacted»",
	}

	var commands []string
	for i := 0; i < len(keys); {
		key := keys[i]
		label, known := labels[key]
		if !known {
			label = fmt.Sprintf("TEXT %q", key)
		}
		run := 1
		for i+run < len(keys) && keys[i+run] == key {
			run++
		}
		if run > 1 && (key == "up" || key == "down") {
			label = fmt.Sprintf("%s × %d", label, run)
		}
		commands = append(commands, label)
		i += run
	}
	return strings.Join(commands, " → ")
}

// present renders r's current screen under label when running in
// presentation mode, mirroring run()'s per-step render. It exists for
// interior sub-steps whose content wouldn't otherwise reach the recording:
// e.g. an extra host var's key/value, since the host menu it's navigated
// back to only ever shows a count ("其他變數(共 N 個)"), never the content.
func (d *automationDriver) present(r *editRouterModel, label string) {
	if d.presentation && d.out != nil {
		fmt.Fprintf(d.out, "\n── %s ──\n%s", label, r.View())
	}
}

// emitMarker writes event to d.marker as a trec STEP_ marker line, so
// markers.go's parseMarkerKind classifies a failed step as "failure" and a
// completed one as "action". No-op when d.marker is nil.
func (d *automationDriver) emitMarker(event automationTraceEvent) {
	if d.marker == nil {
		return
	}
	if event.Result == "error" {
		fmt.Fprintf(d.marker, "STEP_FAILED step=%d action=%s screen=%s: %s\n", event.Step, event.Action, event.ScreenID, event.Error)
		return
	}
	fmt.Fprintf(d.marker, "STEP_ACTION step=%d action=%s screen=%s\n", event.Step, event.Action, event.ScreenID)
}

func (d *automationDriver) runStep(r *editRouterModel, step editAction) error {
	for _, def := range editActionRegistry() {
		if def.Spec.Name == step.Action {
			return def.Run(d, r, step)
		}
	}
	return fmt.Errorf("unsupported action %q", step.Action)
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
	if field == "env" {
		if err := d.choose(r, "env(環境標籤)"); err != nil {
			return err
		}
		idx := -1
		for i, c := range envChoices {
			if c == value {
				idx = i
				break
			}
		}
		if idx < 0 {
			return fmt.Errorf("unsupported env value %q", value)
		}
		if err := d.moveCursor(r, idx); err != nil {
			return err
		}
		return d.enter(r)
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

// setRoleChecked drives the role checklist so role ends up with
// Checked == want, mirroring the same navigation enableRole always
// used. It only toggles Space when the role's current state doesn't
// already match want, exactly like a human would only press Space on
// a role that needs to change.
func (d *automationDriver) setRoleChecked(r *editRouterModel, host, role string, want bool, step editAction) error {
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
	if list.items[idx].Checked != want {
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
	return d.resolveRoleChangeFollowUp(r, step)
}

// resolveRoleChangeFollowUp drives whatever screen a role change's
// confirming Enter landed on, back to the host menu — shared by the
// checklist (setRoleChecked), preset (applyRolePreset), and copy
// (copyRolesFromHost) flows, since all three can land on the exact same
// two detours. Most of the time that's the roles menu (pushRolesMenuBanner)
// with "✅ 完成" straight away, but:
//
//   - a newly-checked role that introduces a host_vars key with no existing
//     value (inventory.roleContract.HostVarsKeys, e.g. prometheus's
//     prometheus_site_label) detours through pushForcedHostVarsPrompt first:
//     one text-input screen per missing key, then the host_vars list editor —
//     exactly like a human filling in host_vars/<host>.yml by hand
//     (edit_tui_hostvars.go). step.HostVars supplies the values for that
//     detour; a key it doesn't cover is a hard error rather than silently
//     keeping whatever blank/placeholder value the screen was scaffolded
//     with.
//   - newly enabling freeipa-nfs-server with no reusable
//     .vault/main.yaml ipa_admin_password detours through
//     pushNFSRoleBootstrap's own secret prompt
//     (nfsRosterBootstrapPasswordScreenID, edit_tui.go) first. step's
//     Value/ValueEnv (the same fields add_extra_var/add_vault_key already
//     use for their own secret-or-plain input) supply that password.
func (d *automationDriver) resolveRoleChangeFollowUp(r *editRouterModel, step editAction) error {
	for {
		input, ok := r.current.(textInputModel)
		if !ok {
			break
		}
		if input.automationScreenID() == nfsRosterBootstrapPasswordScreenID {
			value, secret, err := resolveValueOrEnv(step)
			if err != nil {
				return err
			}
			if value == "" {
				return fmt.Errorf("newly enabling freeipa-nfs-server requires a FreeIPA admin password to bootstrap its roster; supply it via this action's value or value_env (or pre-set .vault/main.yaml's ipa_admin_password)")
			}
			if err := d.typeSecretOrPlain(r, value, secret, true); err != nil {
				return err
			}
			if err := d.enter(r); err != nil {
				return err
			}
			continue
		}
		key, ok := forcedHostVarsPromptKey(input.automationScreenID())
		if !ok {
			return fmt.Errorf("unexpected text-input screen %q after role change", automationScreenID(r))
		}
		value, known := step.HostVars[key]
		if !known {
			return fmt.Errorf("role change requires a value for host_vars key %q; supply it via this action's host_vars.%s", key, key)
		}
		if err := d.typeText(r, value, true); err != nil {
			return err
		}
		if err := d.enter(r); err != nil {
			return err
		}
	}
	if automationScreenID(r) == "host_vars.entries" {
		return d.choose(r, "💾 存檔並離開")
	}
	return d.choose(r, "✅ 完成")
}

// setChecklistSelection drives the multiSelectModel currently on screen
// so that exactly the labels in want end up checked, then presses Enter
// to commit — a bulk replace, matching how the roster group/HBAC/sudo
// checklists work (pushRosterGroupMembershipUsers et al.: pick the whole
// set, then Enter), unlike setRoleChecked's single-item toggle. want
// entries are matched by exact Label equality, not uniqueItemIndex's
// substring match, since these checklist Labels are already complete,
// unambiguous entity names (usernames/group names/hostgroup names/
// service names) rather than prose field labels.
func (d *automationDriver) setChecklistSelection(r *editRouterModel, want []string) error {
	wantSet := make(map[string]bool, len(want))
	for _, w := range want {
		wantSet[w] = true
	}
	for {
		list, ok := r.current.(multiSelectModel)
		if !ok {
			return fmt.Errorf("expected a checklist screen, got %s", automationScreenID(r))
		}
		mismatch := -1
		for i, item := range list.items {
			if item.Checked != wantSet[item.Label] {
				mismatch = i
				break
			}
		}
		if mismatch < 0 {
			break
		}
		if err := d.moveCursor(r, mismatch); err != nil {
			return err
		}
		if err := d.send(r, tea.KeyMsg{Type: tea.KeySpace}); err != nil {
			return err
		}
	}
	return d.enter(r)
}

func (d *automationDriver) enableRole(r *editRouterModel, step editAction) error {
	return d.setRoleChecked(r, step.Host, step.Role, true, step)
}

func (d *automationDriver) disableRole(r *editRouterModel, host, role string) error {
	return d.setRoleChecked(r, host, role, false, editAction{})
}

func (d *automationDriver) deleteHost(r *editRouterModel, host string) error {
	if err := d.ensureHostMenu(r, host); err != nil {
		return err
	}
	if err := d.choose(r, "刪除這台主機"); err != nil {
		return err
	}
	// The confirm defaults to No; an explicit "y" is required to actually delete.
	return d.confirmYesNo(r, true)
}

func (d *automationDriver) discardHosts(r *editRouterModel) error {
	if err := d.ensureHostsList(r); err != nil {
		return err
	}
	if err := d.choose(r, "不存檔離開"); err != nil {
		return err
	}
	return d.confirmYesNo(r, true)
}

// saveHosts leaves the router at the top menu (where "存檔並離開" always
// lands, via pushSaveHostsAndReturnTop -> pushTopMenu) rather than also
// choosing "離開" to quit the whole session: quitting sets r.quit, and
// editRouterModel.Update short-circuits every message to tea.Quit once
// that's set — silently freezing the router if any group_vars/vault
// action follows save_hosts in the same scenario. A hosts.yml-only
// scenario ending here simply returns from d.run normally; nothing
// downstream depends on r.quit being true.
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
	return d.choose(r, "存檔並離開")
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
			return d.choose(r, "返回主機清單")
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
	idx, err := uniqueItemIndex(list.automationItems(), label)
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

// typeSecretOrPlain is typeText for a value that may have come from
// ValueEnv: when secret is true, the literal characters are still sent to
// the model (so the real value ends up in the file, exactly like a human
// typing it), but the trace records a fixed placeholder instead of the
// value itself. replace behaves like typeText's replace (send Ctrl-U
// first) — clearing the field isn't itself sensitive, so that key always
// goes through the normal (unredacted) send.
func (d *automationDriver) typeSecretOrPlain(r *editRouterModel, value string, secret, replace bool) error {
	if _, ok := r.current.(textInputModel); !ok {
		return fmt.Errorf("cannot type on %s screen", automationScreenID(r))
	}
	if replace {
		if err := d.send(r, tea.KeyMsg{Type: tea.KeyCtrlU}); err != nil {
			return err
		}
	}
	if value == "" {
		return nil
	}
	msg := tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(value)}
	if !secret {
		return d.send(r, msg)
	}
	return d.sendRedacted(r, msg, "«redacted»")
}

// resolveValueOrEnv reads step's actual value at execution time — from
// ValueEnv (the environment) if set, otherwise from Value — never at
// validation time (see validateValueOrEnv). A ValueEnv naming an unset or
// empty variable is a hard error rather than a silently-empty secret.
func resolveValueOrEnv(step editAction) (value string, secret bool, err error) {
	if step.ValueEnv != "" {
		v := os.Getenv(step.ValueEnv)
		if v == "" {
			return "", false, fmt.Errorf("value_env %q is not set in the environment", step.ValueEnv)
		}
		return v, true, nil
	}
	return step.Value, false, nil
}

func (d *automationDriver) enter(r *editRouterModel) error {
	return d.send(r, tea.KeyMsg{Type: tea.KeyEnter})
}

// confirmYesNo answers the current confirmModel with an explicit y/n
// rune rather than relying on Enter (which would only ever accept
// whatever the screen's own defaultYes is) — needed by any action that
// must override a confirm defaulting to "no" (e.g. delete/discard).
func (d *automationDriver) confirmYesNo(r *editRouterModel, yes bool) error {
	if _, ok := r.current.(confirmModel); !ok {
		return fmt.Errorf("cannot answer yes/no on %s screen", automationScreenID(r))
	}
	key := "n"
	if yes {
		key = "y"
	}
	return d.send(r, tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)})
}

func (d *automationDriver) send(r *editRouterModel, msg tea.KeyMsg) error {
	d.keys = append(d.keys, msg.String())
	model, _ := r.Update(msg)
	next, ok := model.(editRouterModel)
	if !ok {
		return fmt.Errorf("edit router returned unexpected model")
	}
	*r = next
	if err := d.notifyRecorder(r, msg.String()); err != nil {
		return err
	}
	if r.err != nil {
		return r.err
	}
	if err := textInputRejectionError(r); err != nil {
		return err
	}
	return nil
}

// sendRedacted is send, except the trace records placeholder instead of the
// key message's literal text — used exclusively for secret-bearing input
// (see typeSecretOrPlain) so a ValueEnv-sourced secret never appears in
// --trace-out JSONL, even though the model itself still receives the real
// characters.
func (d *automationDriver) sendRedacted(r *editRouterModel, msg tea.KeyMsg, placeholder string) error {
	d.keys = append(d.keys, placeholder)
	model, _ := r.Update(msg)
	next, ok := model.(editRouterModel)
	if !ok {
		return fmt.Errorf("edit router returned unexpected model")
	}
	*r = next
	if err := d.notifyRecorder(r, placeholder); err != nil {
		return err
	}
	if r.err != nil {
		return r.err
	}
	if err := textInputRejectionError(r); err != nil {
		return err
	}
	return nil
}

// textInputRejectionError surfaces a textInputModel's own validate()
// rejection (e.g. "變數 ... 已存在") the moment it happens. Without this, a
// rejected Enter leaves the router sitting on the same not-yet-confirmed
// text-input screen with only its local, string-typed m.err set — a state
// editRouterModel.err (checked above) never learns about, since transitionTo's
// onResult callback only fires once the screen actually finishes. The driver
// would otherwise treat the rejected Enter as a no-op and push its next
// scripted keystrokes into that same stale field, eventually failing much
// later with an opaque "cannot choose ... on text-input screen" that names
// the wrong step.
func textInputRejectionError(r *editRouterModel) error {
	ti, ok := r.current.(textInputModel)
	if !ok || ti.err == "" {
		return nil
	}
	return fmt.Errorf("input rejected on %s screen: %s", automationScreenID(r), ti.err)
}

// notifyRecorder reports the key just applied and the resulting live
// frame to d.recorderOrNoop() — called from send/sendRedacted only, so
// every key either function applies is observed exactly once,
// regardless of which one a given automationDriver method used.
func (d *automationDriver) notifyRecorder(r *editRouterModel, keyRepr string) error {
	rec := d.recorderOrNoop()
	if err := rec.RecordKeys([]string{keyRepr}); err != nil {
		return fmt.Errorf("record keys: %w", err)
	}
	d.frameSeq++
	frame := FrameEvent{Sequence: d.frameSeq, ScreenID: automationScreenID(r), View: r.View()}
	if err := rec.RecordFrame(frame); err != nil {
		return fmt.Errorf("record frame: %w", err)
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

// itemIndexByID is uniqueItemIndex's ID-based counterpart, for the
// MCP-facing automation path (docs/superpowers/specs/2026-08-04-pilot-edit-mcp-semantic-tui-design.md's
// "Agent 不操作 raw terminal" invariant): it requires an exact, unique,
// non-empty ID match and never falls back to substring or label
// matching, so an item with no AutomationID assigned can never be
// targeted this way — that's fail-closed by construction, not by an
// extra check.
func itemIndexByID(items []selectItem, id string) (int, error) {
	if id == "" {
		return -1, fmt.Errorf("item id must not be empty")
	}
	index := -1
	count := 0
	for i, item := range items {
		if item.ID == id {
			index = i
			count++
		}
	}
	if count == 0 {
		return -1, fmt.Errorf("item id %q not found", id)
	}
	if count > 1 {
		return -1, fmt.Errorf("item id %q is ambiguous", id)
	}
	return index, nil
}

// chooseByID is choose's ID-based counterpart. Unlike choose (which
// trusts the caller to already be on the right screen, matching
// today's --actions automation path), it first asserts the current
// screen's automationScreenID() equals wantScreenID and fails closed on
// a mismatch — the ID-based replacement for the ad-hoc
// strings.Contains(list.title, ...) screen checks scattered through
// this file's label-based driver methods. No existing caller uses this
// yet; it's the primitive a future ID-based MVP action executor (spec
// Phase 3/4) will call.
func (d *automationDriver) chooseByID(r *editRouterModel, wantScreenID, itemID string) error {
	if got := automationScreenID(r); got != wantScreenID {
		return fmt.Errorf("expected %s screen, got %s", wantScreenID, got)
	}
	list, ok := r.current.(selectModel)
	if !ok {
		return fmt.Errorf("cannot choose item %q: %s screen is not a select list", itemID, wantScreenID)
	}
	idx, err := itemIndexByID(list.items, itemID)
	if err != nil {
		return err
	}
	if err := d.moveCursor(r, idx); err != nil {
		return err
	}
	return d.enter(r)
}

func automationScreenID(r *editRouterModel) string {
	if r == nil || r.current == nil {
		return "none"
	}
	return r.current.automationScreenID()
}
