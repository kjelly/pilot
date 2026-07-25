// edit_tui.go implements the Bubble Tea router backing `pilot edit`,
// plus the top menu and the whole hosts.yml flow (the pure data
// helpers it and edit_tui_groupvars.go/edit_tui_vault.go depend on
// live in edit.go). It replaces the old promptui-driven nested-loop
// implementation
// with one continuous tea.Program for the entire `pilot edit`
// invocation: screens are replaced wholesale as the wizard advances
// instead of each step spinning up its own Program/prompt.
//
// This intentionally does not implement a generic push/pop navigation
// stack. Every "go back to a list" transition in this wizard already
// rebuilds that list from current data (the host list, group_vars
// entries, and vault keys can all change between visits), so there is
// nothing useful to pop back to — each transition explicitly names
// what screen comes next, mirroring the original code's control flow
// (a switch-case per menu choice) almost 1:1, just deferred into a
// callback the router invokes once the current screen finishes
// instead of running inline after a blocking prompt call returns.
//
// Cancel semantics: esc/ctrl+c on every screen steps back exactly one
// level — the same destination (and, where one already exists, the
// same dirty-gated discard confirmation) that screen's own explicit
// "back"/"cancel"/"🚪 不存檔離開" menu item already uses. It is not new
// behavior invented for esc; it's binding an already-correct action to
// a second key. The only screen where esc still quits the whole wizard
// is the top-level "要編輯什麼？" menu (pushTopMenu) — there is no level
// above it to go back to.
//
// This used to be the reverse (esc aborted the whole wizard everywhere,
// mirroring errDeployAborted propagating, unhandled, all the way up to
// runEdit's original abortOrErr — a straight port of the old promptui
// version's behavior). Two narrow exceptions were carved out first (the
// role checklist, then the whole 其他變數 CRUD flow) after each was
// separately reported as a surprising bug; a further report generalized
// this to every remaining screen, at which point the wizard-wide
// "quits everything" default was inverted instead of adding a longer
// list of one-off exceptions.
package cmd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/kjelly/pilot/internal/inventory"
)

// editRouterModel is the single long-lived Bubble Tea model backing
// the whole `pilot edit` session.
type editRouterModel struct {
	current  screen
	onResult func(r *editRouterModel, s screen) tea.Cmd

	banner string // shown above the current screen; explicitly set (or cleared to "") by every transition

	lastWidth, lastHeight int

	quit bool
	err  error
}

func (r editRouterModel) Init() tea.Cmd {
	if r.current == nil {
		return nil
	}
	return r.current.Init()
}

// transitionTo replaces the current screen with s. onResult runs once
// s.Finished() becomes true; s is passed to it so the callback can
// read result accessors (Selected()/Value()/CheckedLabels()/...).
func (r *editRouterModel) transitionTo(s screen, banner string, onResult func(*editRouterModel, screen) tea.Cmd) tea.Cmd {
	r.current = s
	r.banner = banner
	r.onResult = onResult
	cmd := s.Init()
	if r.lastHeight > 0 {
		nm, sc := r.current.Update(tea.WindowSizeMsg{Height: r.lastHeight, Width: r.lastWidth})
		r.current = nm.(screen)
		cmd = tea.Batch(cmd, sc)
	}
	return cmd
}

// quitWizard aborts the whole `pilot edit` session. Only pushTopMenu's
// cancel handler still calls this directly — see the package doc
// comment above for why every other screen instead steps back one level.
func quitWizard(r *editRouterModel) tea.Cmd {
	r.quit = true
	return nil
}

func (r editRouterModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if wsz, ok := msg.(tea.WindowSizeMsg); ok {
		r.lastWidth, r.lastHeight = wsz.Width, wsz.Height
	}
	// vaultShelloutDoneMsg (edit_tui_vault.go) is the one message the
	// router itself must handle rather than forward to the current
	// screen: it's delivered once the ansible-vault edit subprocess
	// (suspended via tea.ExecProcess) exits, and decides the next
	// screen itself rather than being interpreted by whatever screen
	// happens to be "current" (there is none — the Program was
	// suspended, not showing any screen, while that subprocess ran).
	if m, ok := msg.(vaultShelloutDoneMsg); ok {
		if m.err != nil {
			r.err = m.err
			return r, tea.Quit
		}
		cmd := pushVaultFilePicker(&r, m.dir, "")
		return r, cmd
	}
	if r.current == nil || r.quit {
		return r, tea.Quit
	}

	nm, cmd := r.current.Update(msg)
	r.current = nm.(screen)

	if !r.current.Finished() {
		return r, cmd
	}

	finished := r.current
	cb := r.onResult
	r.onResult = nil
	var cbCmd tea.Cmd
	if cb != nil {
		cbCmd = cb(&r, finished)
	}
	if r.quit || r.err != nil {
		return r, tea.Quit
	}
	return r, tea.Batch(cmd, cbCmd)
}

func (r editRouterModel) View() string {
	var s string
	if r.banner != "" {
		s += r.banner + "\n\n"
	}
	if r.current != nil {
		s += r.current.View()
	}
	return s
}

func newEditRouterModel(dir string) editRouterModel {
	var r editRouterModel
	pushTopMenu(&r, dir, "")
	return r
}

var editDir string
var editActionsPath string
var editPresentation bool
var editTracePath string

var editCmd = &cobra.Command{
	Use:   "edit",
	Short: "選單式編輯精靈 — 修改 hosts.yml / 角色範本 / group_vars / .vault 不需要會用文字編輯器",
	Long: `pilot edit 用問答/選單的方式編輯 hosts.yml(機器清單與角色)跟
role-presets.yml(常用角色範本)、group_vars/*.yml(角色的設定值，例如 FreeIPA
realm、DNS 位址...)，以及 .vault/*.yaml(明文 vault skeleton，或跳到
ansible-vault edit 編輯加密檔)。

適合不熟悉終端機文字編輯器(vim/nano)、只習慣 VSCode 之類 GUI 介面的人 ——
每一步都是從清單挑選或回答一個問題，存檔前會再確認一次。熟悉 YAML 的人
仍可以直接用文字編輯器改這些檔案，兩種方式改出來的檔案格式相容。

預設編輯目前資料夾底下的 hosts.yml / role-presets.yml / group_vars/ / .vault/；
用 --dir 指到另一個資料夾就會改編輯那裡的檔案 —— 適合同時維護多個環境
(envs/staging/、envs/prod/…)各自一包設定的情況。`,
	RunE: runEdit,
}

func init() {
	editCmd.Flags().StringVar(&editDir, "dir", ".", "要編輯哪個資料夾底下的 hosts.yml / group_vars/ / .vault/(預設目前資料夾)")
	editCmd.Flags().StringVar(&editActionsPath, "actions", "", "以 JSON scenario 自動操作 edit，並可接續 deploy/reconcile")
	editCmd.Flags().BoolVar(&editPresentation, "presentation", false, "自動操作時顯示教學步驟與每個 TUI 畫面")
	editCmd.Flags().StringVar(&editTracePath, "trace-out", "", "將 automation action 以 JSONL 寫入指定檔案")
	rootCmd.AddCommand(editCmd)
}

func runEdit(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("pilot edit 需要互動式終端機(TTY)才能顯示選單；非互動場景請直接編輯檔案")
	}

	fmt.Fprintln(out, "═══ pilot edit — hosts.yml / 角色範本 / group_vars / .vault 編輯精靈 ═══")
	if editDir != "." {
		fmt.Fprintf(out, "編輯目標資料夾：%s\n", editDir)
	}
	fmt.Fprintln(out, "每一步都可以直接按 Enter 採用預設值；Ctrl-C 隨時可以取消。")
	fmt.Fprintln(out)
	if editActionsPath != "" {
		scenario, err := loadEditScenario(editActionsPath)
		if err != nil {
			return err
		}
		return runAutomatedEditWorkflow(cmd, scenario, editPresentation, editTracePath)
	}

	router := newEditRouterModel(editDir)
	final, err := tea.NewProgram(router, tea.WithOutput(os.Stdout)).Run()
	if err != nil {
		return fmt.Errorf("編輯精靈失敗: %w", err)
	}
	return final.(editRouterModel).err
}

// ---- top menu ---------------------------------------------------------------

func pushTopMenu(r *editRouterModel, dir, banner string) tea.Cmd {
	items := []string{
		"hosts.yml — 機器清單與角色",
		"group_vars/ — 角色的設定值(FreeIPA realm、DNS 位址...)",
		".vault/ — vault 變數檔(明文 skeleton 或 ansible-vault 加密檔)",
		"roster — FreeIPA users/groups(canonical roster，僅支援新增)",
		"🔍 檢查設定完整性 — 跟 pilot deploy 共用同一套規則",
		"離開",
	}
	return r.transitionTo(newSelectModel("要編輯什麼？", items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return quitWizard(r)
		}
		switch m.Selected() {
		case 0:
			return pushHostsPathPrompt(r, dir)
		case 1:
			return pushGroupVarsFilePicker(r, dir, "")
		case 2:
			return pushVaultFilePicker(r, dir, "")
		case 3:
			return pushRosterPathPrompt(r, dir)
		case 4:
			return pushConfigCompletenessCheck(r, dir)
		case 5:
			r.quit = true
			return nil
		}
		return nil
	})
}

// pushConfigCompletenessCheck runs checkWorkspaceCompleteness (shared with
// pilot deploy's hard gate, see workspace_completeness.go /
// deploy_completeness.go) and shows the result as a banner on the top
// menu — a read-only report, nothing here writes to any file.
func pushConfigCompletenessCheck(r *editRouterModel, dir string) tea.Cmd {
	checks := checkWorkspaceCompleteness(dir)
	return pushTopMenu(r, dir, formatCompletenessReport(checks))
}

// ---- hosts.yml ----------------------------------------------------------

func pushHostsPathPrompt(r *editRouterModel, dir string) tea.Cmd {
	def := filepath.Join(dir, "hosts.yml")
	return r.transitionTo(newTextInputModel("hosts.yml 路徑", def, nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushTopMenu(r, dir, "")
		}
		return pushLoadOrInitHosts(r, dir, strings.TrimSpace(m.Value()))
	})
}

func pushLoadOrInitHosts(r *editRouterModel, dir, path string) tea.Cmd {
	data, err := os.ReadFile(path)
	if err == nil {
		hf, perr := inventory.Parse(data)
		if perr != nil {
			r.err = fmt.Errorf("%s 解析失敗: %w", path, perr)
			return nil
		}
		return pushHostList(r, dir, path, hf, "")
	}
	if !errors.Is(err, os.ErrNotExist) {
		r.err = fmt.Errorf("read %s: %w", path, err)
		return nil
	}
	question := fmt.Sprintf("%s 不存在，要從空白清單開始嗎？", path)
	return r.transitionTo(newConfirmModel(question, true), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(confirmModel)
		if !m.Value() {
			return quitWizard(r)
		}
		banner := fmt.Sprintf("從空白的 hosts.yml 開始，稍後存檔時會建立 %s。", path)
		return pushHostList(r, dir, path, &inventory.HostsFile{}, banner)
	})
}

func pushHostList(r *editRouterModel, dir, path string, hf *inventory.HostsFile, banner string) tea.Cmd {
	names := hostNames(hf)
	items := make([]string, 0, len(names)+4)
	items = append(items, "➕ 新增主機")
	for _, n := range names {
		items = append(items, fmt.Sprintf("🖥  %s", hostSummary(hf, n)))
	}
	fleetVarsIdx := len(items)
	items = append(items, "⚙  共用變數(vars: — 所有主機共用的連線預設值，例如 ansible_user)")
	items = append(items, "💾 存檔並離開", "🚪 不存檔離開")

	title := fmt.Sprintf("編輯 %s — 選一台主機，或選下面的操作", path)
	return r.transitionTo(newSelectModel(title, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			// mirrors "🚪 不存檔離開" exactly — this screen has no dirty
			// flag of its own, so that item (and now esc) always confirms.
			return pushConfirmDiscardHosts(r, dir, path, hf)
		}
		idx := m.Selected()
		switch {
		case idx == 0:
			return pushAddHost(r, dir, path, hf)
		case idx == fleetVarsIdx:
			return pushFleetVarsMenu(r, dir, path, hf, "")
		case idx == len(items)-2:
			return pushSaveHostsAndReturnTop(r, dir, path, hf)
		case idx == len(items)-1:
			return pushConfirmDiscardHosts(r, dir, path, hf)
		default:
			return pushHostMenu(r, dir, path, hf, names[idx-1])
		}
	})
}

// pushFleetVarsMenu edits hf.Vars — the fleet-wide "vars:" block at the top
// of hosts.yml (shared connection defaults like ansible_user,
// ansible_ssh_private_key_file; see hosts.example.yml). It mirrors
// pushExtraVarsMenu's CRUD pattern exactly, just keyed to hf.Vars instead of
// one host's Extra — hosts.yml's own Render/Parse already round-trip
// Vars, this only adds the missing wizard screen for it.
func pushFleetVarsMenu(r *editRouterModel, dir, path string, hf *inventory.HostsFile, banner string) tea.Cmd {
	if hf.Vars == nil {
		hf.Vars = map[string]string{}
	}
	keys := sortedKeysOf(hf.Vars)
	items := make([]string, 0, len(keys)+2)
	for _, k := range keys {
		items = append(items, fmt.Sprintf("%s = %s", k, hf.Vars[k]))
	}
	items = append(items, "➕ 新增變數", "↩  返回")
	title := "共用變數(vars: — 所有主機共用的連線預設值，例如 ansible_user)"
	return r.transitionTo(newSelectModel(title, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushHostList(r, dir, path, hf, "")
		}
		idx := m.Selected()
		switch {
		case idx == len(items)-1:
			return pushHostList(r, dir, path, hf, "")
		case idx == len(items)-2:
			return pushAddFleetVar(r, dir, path, hf)
		default:
			return pushFleetVarActionMenu(r, dir, path, hf, keys[idx])
		}
	})
}

func pushAddFleetVar(r *editRouterModel, dir, path string, hf *inventory.HostsFile) tea.Cmd {
	validate := func(s string) error {
		s = strings.TrimSpace(s)
		if s == "" {
			return fmt.Errorf("不能留空")
		}
		if _, ok := hf.Vars[s]; ok {
			return fmt.Errorf("變數 %q 已存在，請從清單選它來修改", s)
		}
		return nil
	}
	return r.transitionTo(newTextInputModel("變數名稱", "", validate), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushFleetVarsMenu(r, dir, path, hf, "")
		}
		return pushAddFleetVarValue(r, dir, path, hf, strings.TrimSpace(m.Value()))
	})
}

func pushAddFleetVarValue(r *editRouterModel, dir, path string, hf *inventory.HostsFile, key string) tea.Cmd {
	return r.transitionTo(newTextInputModel("變數值", "", nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushFleetVarsMenu(r, dir, path, hf, "")
		}
		if hf.Vars == nil {
			hf.Vars = map[string]string{}
		}
		hf.Vars[key] = m.Value()
		return pushFleetVarsMenu(r, dir, path, hf, "")
	})
}

func pushFleetVarActionMenu(r *editRouterModel, dir, path string, hf *inventory.HostsFile, key string) tea.Cmd {
	title := fmt.Sprintf("變數 %s = %s", key, hf.Vars[key])
	items := []string{"修改值", "刪除", "返回"}
	return r.transitionTo(newSelectModel(title, items), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushFleetVarsMenu(r, dir, path, hf, "")
		}
		switch m.Selected() {
		case 0:
			return pushEditFleetVarValue(r, dir, path, hf, key)
		case 1:
			delete(hf.Vars, key)
			return pushFleetVarsMenu(r, dir, path, hf, "")
		case 2:
			return pushFleetVarsMenu(r, dir, path, hf, "")
		}
		return nil
	})
}

func pushEditFleetVarValue(r *editRouterModel, dir, path string, hf *inventory.HostsFile, key string) tea.Cmd {
	label := fmt.Sprintf("%s 的新值", key)
	return r.transitionTo(newTextInputModel(label, hf.Vars[key], nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushFleetVarActionMenu(r, dir, path, hf, key)
		}
		hf.Vars[key] = m.Value()
		return pushFleetVarsMenu(r, dir, path, hf, "")
	})
}

func pushSaveHostsAndReturnTop(r *editRouterModel, dir, path string, hf *inventory.HostsFile) tea.Cmd {
	var buf strings.Builder
	if err := saveHosts(&buf, path, hf); err != nil {
		r.err = err
		return nil
	}
	return pushTopMenu(r, dir, strings.TrimRight(buf.String(), "\n"))
}

func pushConfirmDiscardHosts(r *editRouterModel, dir, path string, hf *inventory.HostsFile) tea.Cmd {
	return r.transitionTo(newConfirmModel("確定不存檔離開嗎？這次的修改會遺失", false), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(confirmModel)
		if m.Value() {
			return pushTopMenu(r, dir, "")
		}
		return pushHostList(r, dir, path, hf, "")
	})
}

func pushAddHost(r *editRouterModel, dir, path string, hf *inventory.HostsFile) tea.Cmd {
	validate := func(s string) error {
		s = strings.TrimSpace(s)
		if s == "" {
			return fmt.Errorf("不能留空")
		}
		if findHost(hf, s) != nil {
			return fmt.Errorf("主機 %q 已存在", s)
		}
		return nil
	}
	return r.transitionTo(newTextInputModel("新主機名稱(唯一，例如 web-3)", "", validate), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushHostList(r, dir, path, hf, "")
		}
		name := strings.TrimSpace(m.Value())
		hf.Hosts = append(hf.Hosts, inventory.Host{Name: name, Extra: map[string]string{}})
		return pushHostMenu(r, dir, path, hf, name)
	})
}

func pushHostMenu(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name string) tea.Cmd {
	h := findHost(hf, name)
	if h == nil {
		return pushHostList(r, dir, path, hf, "") // deleted from within a sub-menu
	}
	items := []string{
		fmt.Sprintf("ansible_host(連線位址)：%s", displayOrPlaceholder(h.AnsibleHost)),
		fmt.Sprintf("ansible_user(登入帳號)：%s", displayOrPlaceholder(h.AnsibleUser)),
		fmt.Sprintf("SSH 私鑰路徑：%s", displayOrPlaceholder(h.SSHKeyFile)),
		fmt.Sprintf("env(環境標籤)：%s", displayOrPlaceholder(h.Env)),
		fmt.Sprintf("角色(roles)：%s", displayOrPlaceholder(strings.Join(h.Roles, ", "))),
		fmt.Sprintf("其他變數(共 %d 個)", len(h.Extra)),
	}
	// host_vars/<name>.yml only ever appears when h's current roles
	// actually need a var with no safe cross-host default (e.g.
	// prometheus_site_label) — mirrors how the group_vars picker only
	// lists stems applicable to the roles in play. Item count varies by
	// host, so the trailing delete/return items are addressed relative
	// to len(items) rather than fixed indices (same pattern
	// pushGroupVarsFilePicker already uses).
	hostVarsIdx := -1
	if len(inventory.HostVarsKeysForRoles(h.Roles)) > 0 {
		hostVarsIdx = len(items)
		items = append(items, fmt.Sprintf("host_vars/%s.yml(必填、無安全預設值的設定)", name))
	}
	deleteIdx := len(items)
	items = append(items, "🗑  刪除這台主機")
	returnIdx := len(items)
	items = append(items, "↩  返回主機清單")

	title := fmt.Sprintf("主機 %q — 選要編輯的項目", name)
	return r.transitionTo(newSelectModel(title, items), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			// mirrors "↩ 返回主機清單" — unconditional, no data at risk
			// (hf stays in memory regardless of which screen shows it).
			return pushHostList(r, dir, path, hf, "")
		}
		switch {
		case m.Selected() == 0:
			return pushHostFieldEdit(r, dir, path, hf, name, "ansible_host(可路由的 IP 或主機名)", h.AnsibleHost, func(h *inventory.Host, v string) { h.AnsibleHost = v })
		case m.Selected() == 1:
			return pushHostFieldEdit(r, dir, path, hf, name, "ansible_user(登入帳號，留空 = 用 vars 裡的預設)", h.AnsibleUser, func(h *inventory.Host, v string) { h.AnsibleUser = v })
		case m.Selected() == 2:
			return pushHostFieldEdit(r, dir, path, hf, name, "SSH 私鑰路徑(留空 = 用 vars 裡的預設)", h.SSHKeyFile, func(h *inventory.Host, v string) { h.SSHKeyFile = v })
		case m.Selected() == 3:
			return pushEnvMenu(r, dir, path, hf, name)
		case m.Selected() == 4:
			return pushRolesMenu(r, dir, path, hf, name)
		case m.Selected() == 5:
			return pushExtraVarsMenu(r, dir, path, hf, name, "")
		case hostVarsIdx >= 0 && m.Selected() == hostVarsIdx:
			return pushHostVarsEditor(r, dir, path, hf, name)
		case m.Selected() == deleteIdx:
			return pushConfirmDeleteHost(r, dir, path, hf, name)
		case m.Selected() == returnIdx:
			return pushHostList(r, dir, path, hf, "")
		}
		return nil
	})
}

func pushHostFieldEdit(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name, label, current string, apply func(*inventory.Host, string)) tea.Cmd {
	return r.transitionTo(newTextInputModel(label, current, nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushHostMenu(r, dir, path, hf, name)
		}
		if h := findHost(hf, name); h != nil {
			apply(h, strings.TrimSpace(m.Value()))
		}
		return pushHostMenu(r, dir, path, hf, name)
	})
}

func pushConfirmDeleteHost(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name string) tea.Cmd {
	question := fmt.Sprintf("確定要刪除主機 %q 嗎？", name)
	return r.transitionTo(newConfirmModel(question, false), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(confirmModel)
		if !m.Value() {
			return pushHostMenu(r, dir, path, hf, name)
		}
		removeHost(hf, name)
		return pushHostList(r, dir, path, hf, fmt.Sprintf("已刪除主機 %q(還沒存檔)。", name))
	})
}

var envChoices = []string{"", "prod", "staging", "sandbox"}

func pushEnvMenu(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name string) tea.Cmd {
	title := "env(環境標籤，給 -e target_group='dns:&prod' 這種交集查詢用)"
	items := []string{"(留空/不歸類，預設等同 sandbox)", "prod", "staging", "sandbox"}
	return r.transitionTo(newSelectModel(title, items), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			// no explicit "back" item exists (every item IS a choice), but
			// nothing has been applied yet, so cancel is a plain, safe
			// return with h.Env untouched.
			return pushHostMenu(r, dir, path, hf, name)
		}
		if h := findHost(hf, name); h != nil {
			h.Env = envChoices[m.Selected()]
		}
		return pushHostMenu(r, dir, path, hf, name)
	})
}

// pushRolesMenu offers a full space-to-toggle/enter-to-confirm
// checklist screen (pushRoleChecklist) plus two shortcuts for the
// common case that most hosts of the same kind end up needing the
// exact same role set: applying a role preset, managing the preset
// catalog, or copying wholesale from a host that's already configured.
// The apply/copy shortcuts only ever add roles (see unionRoles) — they
// never silently remove one — so the checklist remains the tool for
// removing anything a shortcut brought in that this host doesn't need.
func pushRolesMenu(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name string) tea.Cmd {
	return pushRolesMenuBanner(r, dir, path, hf, name, "")
}

func pushRolesMenuBanner(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name, banner string) tea.Cmd {
	if findHost(hf, name) == nil {
		return pushHostList(r, dir, path, hf, "")
	}
	title := fmt.Sprintf("主機 %q 的角色", name)
	items := []string{
		"☑  逐項勾選角色(方向鍵移動、space 勾選/取消、enter 完成)",
		"📋 套用常用角色範本",
		"⚙  管理角色範本",
		"📄 複製自其他主機的角色",
		"✅ 完成",
	}
	return r.transitionTo(newSelectModel(title, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			// mirrors "✅ 完成" (case 4) — roles changes are already
			// applied in-memory the moment the checklist/preset/copy
			// screens confirm, so there's nothing left to lose here.
			return pushHostMenu(r, dir, path, hf, name)
		}
		switch m.Selected() {
		case 0:
			return pushRoleChecklist(r, dir, path, hf, name)
		case 1:
			return pushApplyRolePreset(r, dir, path, hf, name)
		case 2:
			return pushRolePresetManager(r, dir, path, hf, name, "")
		case 3:
			return pushCopyRolesFromHost(r, dir, path, hf, name)
		case 4:
			return pushHostMenu(r, dir, path, hf, name)
		}
		return nil
	})
}

func pushRoleChecklist(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name string) tea.Cmd {
	h := findHost(hf, name)
	if h == nil {
		return pushHostList(r, dir, path, hf, "")
	}
	roles := inventory.Roles()
	items := make([]multiSelectItem, len(roles))
	for i, ri := range roles {
		items[i] = multiSelectItem{Label: ri.Name, Description: ri.Description, Checked: hasRole(h.Roles, ri.Name)}
	}
	title := fmt.Sprintf("主機 %q 的角色", name)
	return r.transitionTo(newMultiSelectModel(title, items), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(multiSelectModel)
		if m.Canceled() {
			// esc/ctrl+c inside the checklist: no change, back to the
			// roles menu (mirrors editRolesMenu's original explicit
			// errDeployAborted catch, from before this file's rewrite).
			return pushRolesMenu(r, dir, path, hf, name)
		}
		checked := m.CheckedLabels()
		sort.Strings(checked)
		banner := ""
		if h := findHost(hf, name); h != nil {
			hadNFSServer := hasRole(h.Roles, "freeipa-nfs-server")
			h.Roles = checked
			if !hadNFSServer && hasRole(checked, "freeipa-nfs-server") {
				// freeipa-nfs-server was just added: the roster's
				// nfs.servers entry for this host is safe to auto-write in
				// full (unlike host_vars' prometheus_site_label, the NFS
				// service principal is fully derived, not a judgment call)
				// — see internal/inventory/roster.go.
				banner = autofixNFSRosterEntry(dir, *h)
			}
		}
		return pushRolesMenuBanner(r, dir, path, hf, name, banner)
	})
}

// autofixNFSRosterEntry appends a missing nfs.servers entry for h to its
// freeipa_roster_file, returning a one-line banner describing what
// happened — empty if there's nothing worth telling the user (no roster
// path set yet, or an entry already existed). A relative freeipa_roster_file
// is resolved against dir (the workspace `pilot edit --dir` is pointed at),
// matching writeMissingNFSRosterEntries' convention (inventory.go).
func autofixNFSRosterEntry(dir string, h inventory.Host) string {
	rosterPath := resolveRosterPath(dir, h.Extra["freeipa_roster_file"])
	if rosterPath == "" {
		return ""
	}
	appended, err := inventory.AppendMissingNFSServerStub(rosterPath, h.Name)
	switch {
	case err != nil:
		return fmt.Sprintf("⚠️  已勾選 freeipa-nfs-server，但無法檢查/補齊 roster %s 的 nfs.servers 項目（%v）；請自行確認", rosterPath, err)
	case appended:
		return fmt.Sprintf("✅ 已自動在 %s 補上 %s 的 nfs.servers 項目", rosterPath, h.Name)
	default:
		return ""
	}
}

func pushApplyRolePreset(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name string) tea.Cmd {
	presets, _, err := loadRolePresets(dir)
	if err != nil {
		r.err = err
		return nil
	}
	if len(presets) == 0 {
		return r.transitionTo(newSelectModel("套用哪個範本？", []string{"↩  取消"}), "目前沒有角色範本；請從「管理角色範本」新增。", func(r *editRouterModel, s screen) tea.Cmd {
			return pushRolesMenu(r, dir, path, hf, name)
		})
	}
	items := make([]string, len(presets)+1)
	for i, p := range presets {
		items[i] = fmt.Sprintf("%s — %s", p.Label, strings.Join(p.Roles, ", "))
	}
	items[len(presets)] = "↩  取消"
	title := "套用哪個範本？(把範本的角色加進目前已勾選的角色，不會移除既有的)"
	return r.transitionTo(newSelectModel(title, items), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			// mirrors the trailing "↩ 取消" item.
			return pushRolesMenu(r, dir, path, hf, name)
		}
		if idx := m.Selected(); idx < len(presets) {
			if h := findHost(hf, name); h != nil {
				h.Roles = unionRoles(h.Roles, presets[idx].Roles)
			}
		}
		return pushRolesMenu(r, dir, path, hf, name)
	})
}

func pushCopyRolesFromHost(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name string) tea.Cmd {
	candidates := otherHostsWithRoles(hf, name)
	if len(candidates) == 0 {
		return pushRolesMenuBanner(r, dir, path, hf, name, "目前沒有其他已設定角色的主機可以複製。")
	}
	items := make([]string, len(candidates)+1)
	for i, c := range candidates {
		items[i] = fmt.Sprintf("%s — %s", c.Name, strings.Join(c.Roles, ", "))
	}
	items[len(candidates)] = "↩  取消"
	title := fmt.Sprintf("把哪台主機的角色複製到 %q？(加進目前已勾選的角色)", name)
	return r.transitionTo(newSelectModel(title, items), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			// mirrors the trailing "↩ 取消" item.
			return pushRolesMenu(r, dir, path, hf, name)
		}
		if idx := m.Selected(); idx < len(candidates) {
			if h := findHost(hf, name); h != nil {
				h.Roles = unionRoles(h.Roles, candidates[idx].Roles)
			}
		}
		return pushRolesMenu(r, dir, path, hf, name)
	})
}

// unionRoles returns dst with every role in add present, in sorted
// order, without duplicating one dst already has.
func unionRoles(dst, add []string) []string {
	for _, r := range add {
		if !hasRole(dst, r) {
			dst = append(dst, r)
		}
	}
	sort.Strings(dst)
	return dst
}

// otherHostsWithRoles returns every host in hf other than exclude
// that already has at least one role assigned — the candidate list
// for "copy roles from another host".
func otherHostsWithRoles(hf *inventory.HostsFile, exclude string) []inventory.Host {
	var out []inventory.Host
	for _, h := range hf.Hosts {
		if h.Name != exclude && len(h.Roles) > 0 {
			out = append(out, h)
		}
	}
	return out
}

func hasRole(roles []string, name string) bool {
	for _, r := range roles {
		if r == name {
			return true
		}
	}
	return false
}

func pushExtraVarsMenu(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name, banner string) tea.Cmd {
	h := findHost(hf, name)
	if h == nil {
		return pushHostList(r, dir, path, hf, "")
	}
	if h.Extra == nil {
		h.Extra = map[string]string{}
	}
	keys := sortedKeysOf(h.Extra)
	items := make([]string, 0, len(keys)+2)
	for _, k := range keys {
		items = append(items, fmt.Sprintf("%s = %s", k, h.Extra[k]))
	}
	items = append(items, "➕ 新增變數", "↩  返回")
	title := fmt.Sprintf("主機 %q 的其他變數(例如 ipa_server_ip)", name)
	return r.transitionTo(newSelectModel(title, items), banner, func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			// esc/ctrl+c here: back to the host menu.
			return pushHostMenu(r, dir, path, hf, name)
		}
		idx := m.Selected()
		switch {
		case idx == len(items)-1:
			return pushHostMenu(r, dir, path, hf, name)
		case idx == len(items)-2:
			return pushAddExtraVar(r, dir, path, hf, name)
		default:
			return pushExtraVarActionMenu(r, dir, path, hf, name, keys[idx])
		}
	})
}

func pushAddExtraVar(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name string) tea.Cmd {
	h := findHost(hf, name)
	validate := func(s string) error {
		s = strings.TrimSpace(s)
		if s == "" {
			return fmt.Errorf("不能留空")
		}
		if h != nil {
			if _, ok := h.Extra[s]; ok {
				return fmt.Errorf("變數 %q 已存在，請從清單選它來修改", s)
			}
		}
		return nil
	}
	return r.transitionTo(newTextInputModel("變數名稱", "", validate), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushExtraVarsMenu(r, dir, path, hf, name, "")
		}
		return pushAddExtraVarValue(r, dir, path, hf, name, strings.TrimSpace(m.Value()))
	})
}

func pushAddExtraVarValue(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name, key string) tea.Cmd {
	return r.transitionTo(newTextInputModel("變數值", "", nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushExtraVarsMenu(r, dir, path, hf, name, "")
		}
		if h := findHost(hf, name); h != nil {
			if h.Extra == nil {
				h.Extra = map[string]string{}
			}
			h.Extra[key] = m.Value()
		}
		return pushExtraVarsMenu(r, dir, path, hf, name, "")
	})
}

func pushExtraVarActionMenu(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name, key string) tea.Cmd {
	h := findHost(hf, name)
	val := ""
	if h != nil {
		val = h.Extra[key]
	}
	title := fmt.Sprintf("變數 %s = %s", key, val)
	items := []string{"修改值", "刪除", "返回"}
	return r.transitionTo(newSelectModel(title, items), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(selectModel)
		if m.Canceled() {
			return pushExtraVarsMenu(r, dir, path, hf, name, "")
		}
		switch m.Selected() {
		case 0:
			return pushEditExtraVarValue(r, dir, path, hf, name, key)
		case 1:
			if h := findHost(hf, name); h != nil {
				delete(h.Extra, key)
			}
			return pushExtraVarsMenu(r, dir, path, hf, name, "")
		case 2:
			return pushExtraVarsMenu(r, dir, path, hf, name, "")
		}
		return nil
	})
}

func pushEditExtraVarValue(r *editRouterModel, dir, path string, hf *inventory.HostsFile, name, key string) tea.Cmd {
	h := findHost(hf, name)
	cur := ""
	if h != nil {
		cur = h.Extra[key]
	}
	label := fmt.Sprintf("%s 的新值", key)
	return r.transitionTo(newTextInputModel(label, cur, nil), "", func(r *editRouterModel, s screen) tea.Cmd {
		m := s.(textInputModel)
		if m.Canceled() {
			return pushExtraVarActionMenu(r, dir, path, hf, name, key)
		}
		if h := findHost(hf, name); h != nil {
			h.Extra[key] = m.Value()
		}
		return pushExtraVarsMenu(r, dir, path, hf, name, "")
	})
}
