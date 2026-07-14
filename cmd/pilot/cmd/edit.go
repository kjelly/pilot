// edit.go implements `pilot edit`, a menu-driven wizard for people who
// aren't comfortable in a terminal editor (vim/nano) but need to
// tweak hosts.yml, group_vars/*.yml, or .vault/*.yaml files — the
// places DELIVERY.md's onboarding asks an operator to hand-edit.
// It doesn't add any capability the raw files don't already have; it
// just wraps `pilot inventory` (Parse/Render) and internal/groupvars
// in the same promptui Select/Prompt menus `pilot deploy` uses, so
// someone used to a GUI can pick from a list instead of remembering
// YAML syntax.
package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	"github.com/anomalyco/pilot/internal/groupvars"
	"github.com/anomalyco/pilot/internal/inventory"
)

var editDir string

var editCmd = &cobra.Command{
	Use:   "edit",
	Short: "選單式編輯精靈 — 修改 hosts.yml / group_vars / .vault 不需要會用文字編輯器",
	Long: `pilot edit 用問答/選單的方式編輯 hosts.yml(機器清單與角色)跟
group_vars/*.yml(角色的設定值，例如 FreeIPA realm、DNS 位址...)，以及
.vault/*.yaml(明文 vault skeleton，或跳到 ansible-vault edit 編輯加密檔)。

適合不熟悉終端機文字編輯器(vim/nano)、只習慣 VSCode 之類 GUI 介面的人 ——
每一步都是從清單挑選或回答一個問題，存檔前會再確認一次。熟悉 YAML 的人
仍可以直接用文字編輯器改這些檔案，兩種方式改出來的檔案格式相容。

預設編輯目前資料夾底下的 hosts.yml / group_vars/ / .vault/；用 --dir 指到另一個資料夾
就會改編輯那裡的檔案 —— 適合同時維護多個環境(envs/staging/、envs/prod/…)
各自一包 hosts.yml / group_vars/ / .vault/ 的情況。`,
	RunE: runEdit,
}

func init() {
	editCmd.Flags().StringVar(&editDir, "dir", ".", "要編輯哪個資料夾底下的 hosts.yml / group_vars/ / .vault/(預設目前資料夾)")
	rootCmd.AddCommand(editCmd)
}

func runEdit(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return fmt.Errorf("pilot edit 需要互動式終端機(TTY)才能顯示選單；非互動場景請直接編輯檔案")
	}

	fmt.Fprintln(out, "═══ pilot edit — hosts.yml / group_vars / .vault 編輯精靈 ═══")
	if editDir != "." {
		fmt.Fprintf(out, "編輯目標資料夾：%s\n", editDir)
	}
	fmt.Fprintln(out, "每一步都可以直接按 Enter 採用預設值；Ctrl-C 隨時可以取消。")
	fmt.Fprintln(out)

	for {
		idx, err := promptSelectIndex("要編輯什麼？", []string{
			"hosts.yml — 機器清單與角色",
			"group_vars/ — 角色的設定值(FreeIPA realm、DNS 位址...)",
			".vault/ — vault 變數檔(明文 skeleton 或 ansible-vault 加密檔)",
			"離開",
		})
		if err != nil {
			return abortOrErr(err)
		}
		switch idx {
		case 0:
			if err := runEditHosts(out, editDir); err != nil {
				return abortOrErr(err)
			}
		case 1:
			if err := runEditGroupVars(out, editDir); err != nil {
				return abortOrErr(err)
			}
		case 2:
			if err := runEditVault(out, editDir); err != nil {
				return abortOrErr(err)
			}
		case 3:
			return nil
		}
		fmt.Fprintln(out)
	}
}

// ---- hosts.yml -------------------------------------------------------------

func runEditHosts(out io.Writer, dir string) error {
	path, err := promptText("hosts.yml 路徑", filepath.Join(dir, "hosts.yml"), nil)
	if err != nil {
		return err
	}
	path = strings.TrimSpace(path)

	hf, err := loadOrInitHostsFile(out, path)
	if err != nil {
		return err
	}

	for {
		names := hostNames(hf)
		items := make([]string, 0, len(names)+3)
		items = append(items, "➕ 新增主機")
		for _, n := range names {
			items = append(items, fmt.Sprintf("🖥  %s", hostSummary(hf, n)))
		}
		items = append(items, "💾 存檔並離開", "🚪 不存檔離開")

		idx, err := promptSelectIndex(fmt.Sprintf("編輯 %s — 選一台主機，或選下面的操作", path), items)
		if err != nil {
			return err
		}
		switch {
		case idx == 0:
			if err := addHost(out, hf); err != nil {
				return err
			}
		case idx == len(items)-2:
			return saveHosts(out, path, hf)
		case idx == len(items)-1:
			if promptConfirm("確定不存檔離開嗎？這次的修改會遺失", false) {
				return nil
			}
		default:
			if err := editHostMenu(out, hf, names[idx-1]); err != nil {
				return err
			}
		}
	}
}

func loadOrInitHostsFile(out io.Writer, path string) (*inventory.HostsFile, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		hf, err := inventory.Parse(data)
		if err != nil {
			return nil, fmt.Errorf("%s 解析失敗: %w", path, err)
		}
		return hf, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if !promptConfirm(fmt.Sprintf("%s 不存在，要從空白清單開始嗎？", path), true) {
		return nil, errDeployAborted
	}
	fmt.Fprintf(out, "從空白的 hosts.yml 開始，稍後存檔時會建立 %s。\n", path)
	return &inventory.HostsFile{}, nil
}

func saveHosts(out io.Writer, path string, hf *inventory.HostsFile) error {
	if issues := inventory.Lint(hf); len(issues) > 0 {
		fmt.Fprintln(out, "ℹ️  存檔前的檢查結果(不會擋存檔，但套用前建議先解決 error)：")
		for _, i := range issues {
			fmt.Fprintf(out, "   %s\n", i)
		}
	}
	rendered, err := inventory.Render(hf)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(rendered), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Fprintf(out, "✅ 已存檔 %s\n", path)
	return nil
}

func hostNames(hf *inventory.HostsFile) []string {
	names := make([]string, len(hf.Hosts))
	for i, h := range hf.Hosts {
		names[i] = h.Name
	}
	return names
}

func hostSummary(hf *inventory.HostsFile, name string) string {
	h := findHost(hf, name)
	if h == nil {
		return name
	}
	host := h.AnsibleHost
	if host == "" {
		host = "(尚未填 ansible_host)"
	}
	roles := "(尚未選角色)"
	if len(h.Roles) > 0 {
		roles = strings.Join(h.Roles, ", ")
	}
	return fmt.Sprintf("%s — %s — %s", name, host, roles)
}

func findHost(hf *inventory.HostsFile, name string) *inventory.Host {
	for i := range hf.Hosts {
		if hf.Hosts[i].Name == name {
			return &hf.Hosts[i]
		}
	}
	return nil
}

func removeHost(hf *inventory.HostsFile, name string) {
	out := hf.Hosts[:0]
	for _, h := range hf.Hosts {
		if h.Name != name {
			out = append(out, h)
		}
	}
	hf.Hosts = out
}

func addHost(out io.Writer, hf *inventory.HostsFile) error {
	name, err := promptText("新主機名稱(唯一，例如 web-3)", "", func(s string) error {
		s = strings.TrimSpace(s)
		if s == "" {
			return fmt.Errorf("不能留空")
		}
		if findHost(hf, s) != nil {
			return fmt.Errorf("主機 %q 已存在", s)
		}
		return nil
	})
	if err != nil {
		return err
	}
	name = strings.TrimSpace(name)
	hf.Hosts = append(hf.Hosts, inventory.Host{Name: name, Extra: map[string]string{}})
	return editHostMenu(out, hf, name)
}

func editHostMenu(out io.Writer, hf *inventory.HostsFile, name string) error {
	for {
		h := findHost(hf, name)
		if h == nil {
			return nil // deleted from within this menu
		}
		items := []string{
			fmt.Sprintf("ansible_host(連線位址)：%s", displayOrPlaceholder(h.AnsibleHost)),
			fmt.Sprintf("ansible_user(SSH 帳號)：%s", displayOrPlaceholder(h.AnsibleUser)),
			fmt.Sprintf("SSH 私鑰路徑：%s", displayOrPlaceholder(h.SSHKeyFile)),
			fmt.Sprintf("env(環境標籤)：%s", displayOrPlaceholder(h.Env)),
			fmt.Sprintf("角色(roles)：%s", displayOrPlaceholder(strings.Join(h.Roles, ", "))),
			fmt.Sprintf("其他變數(共 %d 個)", len(h.Extra)),
			"🗑  刪除這台主機",
			"↩  返回主機清單",
		}
		choice, err := promptSelectIndex(fmt.Sprintf("主機 %q — 選要編輯的項目", name), items)
		if err != nil {
			return err
		}
		switch choice {
		case 0:
			v, err := promptText("ansible_host(可路由的 IP 或主機名)", h.AnsibleHost, nil)
			if err != nil {
				return err
			}
			h.AnsibleHost = strings.TrimSpace(v)
		case 1:
			v, err := promptText("ansible_user(SSH 登入帳號，留空 = 用 vars 裡的預設)", h.AnsibleUser, nil)
			if err != nil {
				return err
			}
			h.AnsibleUser = strings.TrimSpace(v)
		case 2:
			v, err := promptText("SSH 私鑰路徑(留空 = 用 vars 裡的預設)", h.SSHKeyFile, nil)
			if err != nil {
				return err
			}
			h.SSHKeyFile = strings.TrimSpace(v)
		case 3:
			if err := editEnvMenu(h); err != nil {
				return err
			}
		case 4:
			if err := editRolesMenu(out, hf, h); err != nil {
				return err
			}
		case 5:
			if err := editExtraVarsMenu(h); err != nil {
				return err
			}
		case 6:
			if promptConfirm(fmt.Sprintf("確定要刪除主機 %q 嗎？", name), false) {
				removeHost(hf, name)
				fmt.Fprintf(out, "已刪除主機 %q(還沒存檔)。\n", name)
				return nil
			}
		case 7:
			return nil
		}
	}
}

var envChoices = []string{"", "prod", "staging", "sandbox"}

func editEnvMenu(h *inventory.Host) error {
	idx, err := promptSelectIndex("env(環境標籤，給 -e target_group='dns:&prod' 這種交集查詢用)", []string{
		"(留空/不歸類，預設等同 sandbox)", "prod", "staging", "sandbox",
	})
	if err != nil {
		return err
	}
	h.Env = envChoices[idx]
	return nil
}

// rolePreset is a quick-apply role bundle for a combo this repo's own
// hosts.example.yml already documents as typical — not an exhaustive
// catalog of every valid combination (see DELIVERY.md's "Playbook
// 對照表" for that). Applying one unions its roles into whatever the
// host already has selected; a preset never removes a role, so it's
// safe to apply more than one, or fine-tune with the checkboxes right
// after.
type rolePreset struct {
	Label string
	Roles []string
}

var rolePresets = []rolePreset{
	{
		Label: "FreeIPA 身份伺服器(含 DNS/NTP)",
		Roles: []string{"freeipa-server", "dns", "ntp", "audit-log-forwarding", "wazuh-fim", "restic-backup"},
	},
	{
		Label: "一般 Linux server(納入 FreeIPA)",
		Roles: []string{"freeipa-client", "linux-servers", "audit-log-forwarding", "wazuh-fim", "restic-backup"},
	},
	{
		Label: "核心基礎服務(DNS/NTP/Docker)",
		Roles: []string{"dns", "ntp", "docker"},
	},
}

// editRolesMenu offers a full space-to-toggle/enter-to-confirm
// checklist screen (see edit_role_checklist.go) plus two shortcuts
// for the common case that most hosts of the same kind end up needing
// the exact same role set: applying a rolePreset, or copying wholesale
// from a host that's already configured. The two shortcuts only ever
// add roles (see unionRoles) — they never silently remove one — so
// the checklist remains the tool for removing anything a shortcut
// brought in that this host doesn't need.
func editRolesMenu(out io.Writer, hf *inventory.HostsFile, h *inventory.Host) error {
	for {
		idx, err := promptSelectIndex(fmt.Sprintf("主機 %q 的角色", h.Name), []string{
			"☑  逐項勾選角色(方向鍵移動、space 勾選/取消、enter 完成)",
			"📋 套用常用角色範本",
			"📄 複製自其他主機的角色",
			"✅ 完成",
		})
		if err != nil {
			return err
		}
		switch idx {
		case 0:
			roles, err := promptRoleChecklist(fmt.Sprintf("主機 %q 的角色", h.Name), inventory.Roles(), h.Roles)
			if err != nil {
				if errors.Is(err, errDeployAborted) {
					continue // esc/Ctrl-C inside the checklist: no change, back to this menu
				}
				return err
			}
			h.Roles = roles
		case 1:
			if err := applyRolePreset(h); err != nil {
				return err
			}
		case 2:
			if err := copyRolesFromHost(out, hf, h); err != nil {
				return err
			}
		case 3:
			return nil
		}
	}
}

func applyRolePreset(h *inventory.Host) error {
	items := make([]string, len(rolePresets)+1)
	for i, p := range rolePresets {
		items[i] = fmt.Sprintf("%s — %s", p.Label, strings.Join(p.Roles, ", "))
	}
	items[len(rolePresets)] = "↩  取消"

	idx, err := promptSelectIndex("套用哪個範本？(把範本的角色加進目前已勾選的角色，不會移除既有的)", items)
	if err != nil {
		return err
	}
	if idx == len(rolePresets) {
		return nil
	}
	h.Roles = unionRoles(h.Roles, rolePresets[idx].Roles)
	return nil
}

func copyRolesFromHost(out io.Writer, hf *inventory.HostsFile, h *inventory.Host) error {
	candidates := otherHostsWithRoles(hf, h.Name)
	if len(candidates) == 0 {
		fmt.Fprintln(out, "目前沒有其他已設定角色的主機可以複製。")
		return nil
	}
	items := make([]string, len(candidates)+1)
	for i, c := range candidates {
		items[i] = fmt.Sprintf("%s — %s", c.Name, strings.Join(c.Roles, ", "))
	}
	items[len(candidates)] = "↩  取消"

	idx, err := promptSelectIndex(fmt.Sprintf("把哪台主機的角色複製到 %q？(加進目前已勾選的角色)", h.Name), items)
	if err != nil {
		return err
	}
	if idx == len(candidates) {
		return nil
	}
	h.Roles = unionRoles(h.Roles, candidates[idx].Roles)
	return nil
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

func editExtraVarsMenu(h *inventory.Host) error {
	if h.Extra == nil {
		h.Extra = map[string]string{}
	}
	for {
		keys := sortedKeysOf(h.Extra)
		items := make([]string, 0, len(keys)+2)
		for _, k := range keys {
			items = append(items, fmt.Sprintf("%s = %s", k, h.Extra[k]))
		}
		items = append(items, "➕ 新增變數", "↩  返回")

		idx, err := promptSelectIndex(fmt.Sprintf("主機 %q 的其他變數(例如 ipa_server_ip)", h.Name), items)
		if err != nil {
			return err
		}
		switch {
		case idx == len(items)-1:
			return nil
		case idx == len(items)-2:
			key, err := promptText("變數名稱", "", func(s string) error {
				s = strings.TrimSpace(s)
				if s == "" {
					return fmt.Errorf("不能留空")
				}
				if _, ok := h.Extra[s]; ok {
					return fmt.Errorf("變數 %q 已存在，請從清單選它來修改", s)
				}
				return nil
			})
			if err != nil {
				return err
			}
			val, err := promptText("變數值", "", nil)
			if err != nil {
				return err
			}
			h.Extra[strings.TrimSpace(key)] = val
		default:
			key := keys[idx]
			action, err := promptSelectIndex(fmt.Sprintf("變數 %s = %s", key, h.Extra[key]), []string{"修改值", "刪除", "返回"})
			if err != nil {
				return err
			}
			switch action {
			case 0:
				val, err := promptText(fmt.Sprintf("%s 的新值", key), h.Extra[key], nil)
				if err != nil {
					return err
				}
				h.Extra[key] = val
			case 1:
				delete(h.Extra, key)
			}
		}
	}
}

func sortedKeysOf(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func displayOrPlaceholder(s string) string {
	if s == "" {
		return "(未設定)"
	}
	return s
}

// ---- group_vars/*.yml -------------------------------------------------------

func runEditGroupVars(out io.Writer, dir string) error {
	for {
		path, err := selectGroupVarsFile(out, dir)
		if err != nil {
			return err
		}
		if path == "" {
			return nil
		}
		if err := editGroupVarsFile(out, path); err != nil {
			return err
		}
	}
}

// selectGroupVarsFile lists group_vars files under <dir>/group_vars —
// the actual settings files being edited — but always offers to seed
// a missing one from the fixed, CWD-relative group_vars/*.example.yml
// templates (same split as inventory.go's copyMissingGroupVars: the
// shipped example templates live in one fixed place; the files this
// wizard reads/writes follow --dir).
func selectGroupVarsFile(out io.Writer, dir string) (string, error) {
	targetDir := filepath.Join(dir, "group_vars")
	exampleDir := "group_vars"

	existing, missingExamples, err := scanGroupVars(targetDir, exampleDir)
	if err != nil {
		return "", err
	}

	items := make([]string, 0, len(existing)+len(missingExamples)+1)
	for _, f := range existing {
		items = append(items, "📝 "+f)
	}
	for _, stem := range missingExamples {
		items = append(items, fmt.Sprintf("➕ 從範例建立 %s.yml", stem))
	}
	items = append(items, "↩  返回")

	idx, err := promptSelectIndex(fmt.Sprintf("選一個 %s 底下的檔案", targetDir), items)
	if err != nil {
		return "", err
	}
	switch {
	case idx == len(items)-1:
		return "", nil
	case idx < len(existing):
		return filepath.Join(targetDir, existing[idx]), nil
	default:
		stem := missingExamples[idx-len(existing)]
		src := filepath.Join(exampleDir, stem+".example.yml")
		dst := filepath.Join(targetDir, stem+".yml")
		data, err := os.ReadFile(src)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", src, err)
		}
		if err := os.MkdirAll(targetDir, 0o755); err != nil {
			return "", fmt.Errorf("mkdir %s: %w", targetDir, err)
		}
		if err := os.WriteFile(dst, data, 0o644); err != nil {
			return "", fmt.Errorf("write %s: %w", dst, err)
		}
		fmt.Fprintf(out, "已從 %s 建立 %s\n", src, dst)
		return dst, nil
	}
}

// scanGroupVars lists the *.yml files already under targetDir
// (existing) plus the exampleDir/*.example.yml stems that don't have
// a counterpart in targetDir yet (missingExamples) — offered as
// "create from example" menu entries. targetDir and exampleDir are
// often the same path (the default, un-"--dir"'d case) but don't have
// to be. A targetDir that doesn't exist yet just yields no existing
// files, not an error — it may not have been created yet.
func scanGroupVars(targetDir, exampleDir string) (existing []string, missingExamples []string, err error) {
	haveYML := map[string]bool{}
	if entries, err := os.ReadDir(targetDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			name := e.Name()
			if strings.HasSuffix(name, ".yml") && !strings.HasSuffix(name, ".example.yml") {
				haveYML[strings.TrimSuffix(name, ".yml")] = true
				existing = append(existing, name)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("read %s: %w", targetDir, err)
	}
	sort.Strings(existing)

	haveExample := map[string]bool{}
	if entries, err := os.ReadDir(exampleDir); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			if name := e.Name(); strings.HasSuffix(name, ".example.yml") {
				haveExample[strings.TrimSuffix(name, ".example.yml")] = true
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, fmt.Errorf("read %s: %w", exampleDir, err)
	}

	for stem := range haveExample {
		if !haveYML[stem] {
			missingExamples = append(missingExamples, stem)
		}
	}
	sort.Strings(missingExamples)
	return existing, missingExamples, nil
}

func editGroupVarsFile(out io.Writer, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read %s: %w", path, err)
	}
	doc := groupvars.Parse(data)
	dirty := false

	for {
		entries := doc.Entries()
		items := make([]string, 0, len(entries)+2)
		for _, e := range entries {
			state := "已設定"
			if !e.Active {
				state = "未設定，使用內建預設"
			}
			items = append(items, fmt.Sprintf("%s = %s  [%s]", e.Key, e.Value, state))
		}
		items = append(items, "💾 存檔並離開", "🚪 不存檔離開")

		idx, err := promptSelectIndex(fmt.Sprintf("編輯 %s", path), items)
		if err != nil {
			return err
		}
		switch {
		case idx == len(items)-2:
			if err := os.WriteFile(path, doc.Bytes(), 0o644); err != nil {
				return fmt.Errorf("write %s: %w", path, err)
			}
			fmt.Fprintf(out, "✅ 已存檔 %s\n", path)
			return nil
		case idx == len(items)-1:
			if !dirty || promptConfirm("有未存檔的修改，確定要放棄離開嗎？", false) {
				return nil
			}
		default:
			e := entries[idx]
			if e.Description != "" {
				fmt.Fprintln(out, "──────────────────────────────────")
				fmt.Fprintln(out, e.Description)
				fmt.Fprintln(out, "──────────────────────────────────")
			}
			action, err := promptSelectIndex(fmt.Sprintf("%s 目前值：%s", e.Key, e.Value), []string{
				"修改值", "還原成內建預設(取消設定)", "返回",
			})
			if err != nil {
				return err
			}
			switch action {
			case 0:
				val, err := promptText(fmt.Sprintf("%s 的新值", e.Key), e.Value, nil)
				if err != nil {
					return err
				}
				if err := doc.SetValue(e.Line, val); err != nil {
					return err
				}
				dirty = true
			case 1:
				if err := doc.CommentOut(e.Line); err != nil {
					return err
				}
				dirty = true
			}
		}
	}
}

// ---- .vault/*.yaml ---------------------------------------------------------

func runEditVault(out io.Writer, dir string) error {
	for {
		path, err := selectVaultFile(out, dir)
		if err != nil {
			return err
		}
		if path == "" {
			return nil
		}
		if err := editVaultFile(out, path); err != nil {
			return err
		}
	}
}

func selectVaultFile(out io.Writer, dir string) (string, error) {
	targetDir := filepath.Join(dir, ".vault")
	files, err := scanVaultFiles(targetDir)
	if err != nil {
		return "", err
	}

	items := make([]string, 0, len(files)+2)
	for _, f := range files {
		items = append(items, "📝 "+f)
	}
	items = append(items, "📍 輸入其他 vault 檔路徑", "↩  返回")

	idx, err := promptSelectIndex(fmt.Sprintf("選一個 %s 底下的 vault 檔", targetDir), items)
	if err != nil {
		return "", err
	}
	switch {
	case idx == len(items)-1:
		return "", nil
	case idx < len(files):
		return filepath.Join(targetDir, files[idx]), nil
	default:
		path, err := promptText("vault 檔路徑", filepath.Join(targetDir, "main.yaml"), nil)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(path), nil
	}
}

func scanVaultFiles(targetDir string) ([]string, error) {
	var files []string
	entries, err := os.ReadDir(targetDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read %s: %w", targetDir, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml") {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	return files, nil
}

func editVaultFile(out io.Writer, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if !promptConfirm(fmt.Sprintf("%s 不存在，要建立新的明文 vault 檔嗎？", path), true) {
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
		}
		data = []byte("---\n")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		fmt.Fprintf(out, "已建立 %s\n", path)
	}

	if isAnsibleVaultEncrypted(data) {
		fmt.Fprintf(out, "偵測到 %s 是 ansible-vault 加密檔，改用 `ansible-vault edit`。\n", path)
		return runAnsibleVaultEdit(path)
	}

	doc, err := parseVaultYAML(data)
	if err != nil {
		return fmt.Errorf("%s 解析失敗: %w", path, err)
	}
	if !doc.Editable() {
		return fmt.Errorf("%s 是複雜 YAML（例如 roster/list/nested map）；目前 `pilot edit` 只支援編輯 top-level scalar 的明文 vault skeleton，請改用文字編輯器或先加密後走 ansible-vault edit", path)
	}
	if len(doc.entries) == 0 {
		fmt.Fprintln(out, "目前是空的 vault 檔。先新增一個 key。")
	}

	dirty := false
	for {
		items := make([]string, 0, len(doc.entries)+3)
		for _, e := range doc.entries {
			items = append(items, fmt.Sprintf("%s = %s", e.Key, truncateForErr(e.DisplayValue(), 80)))
		}
		items = append(items, "➕ 新增 key", "💾 存檔並離開", "🚪 不存檔離開")

		idx, err := promptSelectIndex(fmt.Sprintf("編輯 %s", path), items)
		if err != nil {
			return err
		}
		switch {
		case idx == len(items)-3:
			key, err := promptText("新的 key 名稱", "", func(s string) error {
				s = strings.TrimSpace(s)
				if s == "" {
					return fmt.Errorf("不能留空")
				}
				if doc.HasKey(s) {
					return fmt.Errorf("key %q 已存在", s)
				}
				return nil
			})
			if err != nil {
				return err
			}
			val, err := promptText("值（多行請直接輸入 \\n）", "", nil)
			if err != nil {
				return err
			}
			doc.Add(strings.TrimSpace(key), strings.ReplaceAll(val, `\n`, "\n"))
			dirty = true
		case idx == len(items)-2:
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				return fmt.Errorf("mkdir %s: %w", filepath.Dir(path), err)
			}
			if err := os.WriteFile(path, doc.Bytes(), 0o600); err != nil {
				return fmt.Errorf("write %s: %w", path, err)
			}
			fmt.Fprintf(out, "✅ 已存檔 %s\n", path)
			return nil
		case idx == len(items)-1:
			if !dirty || promptConfirm("有未存檔的修改，確定要放棄離開嗎？", false) {
				return nil
			}
		default:
			entry := doc.entries[idx]
			action, err := promptSelectIndex(fmt.Sprintf("%s 目前值：%s", entry.Key, truncateForErr(entry.DisplayValue(), 120)), []string{
				"修改值", "刪除", "返回",
			})
			if err != nil {
				return err
			}
			switch action {
			case 0:
				val, err := promptText(fmt.Sprintf("%s 的新值（多行請直接輸入 \\n）", entry.Key), entry.EditValue(), nil)
				if err != nil {
					return err
				}
				doc.Set(entry.Key, strings.ReplaceAll(val, `\n`, "\n"))
				dirty = true
			case 1:
				doc.Delete(entry.Key)
				dirty = true
			}
		}
	}
}

func isAnsibleVaultEncrypted(data []byte) bool {
	return bytes.HasPrefix(bytes.TrimSpace(data), []byte("$ANSIBLE_VAULT;"))
}

func runAnsibleVaultEdit(path string) error {
	bin, err := exec.LookPath("ansible-vault")
	if err != nil {
		return fmt.Errorf("ansible-vault 不在 PATH 上: %w", err)
	}
	cmd := exec.Command(bin, "edit", path)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ansible-vault edit %s: %w", path, err)
	}
	return nil
}

type vaultYAMLDoc struct {
	root    *yaml.Node
	mapping *yaml.Node
	entries []vaultYAMLEntry
}

type vaultYAMLEntry struct {
	Key   string
	Value *yaml.Node
}

func parseVaultYAML(data []byte) (*vaultYAMLDoc, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	doc := &vaultYAMLDoc{root: &root}
	// A brand-new "---\n" skeleton (what editVaultFile writes for a
	// missing file) doesn't unmarshal to zero content — it's one
	// ScalarNode with tag !!null representing the empty document — so
	// that case needs the same "start a fresh empty mapping" treatment
	// as truly empty content, or Editable() below rejects every new
	// vault file before a single key is ever added.
	if len(root.Content) == 0 || isNullScalar(root.Content[0]) {
		doc.mapping = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		root.Content = []*yaml.Node{doc.mapping}
		return doc, nil
	}
	if root.Content[0].Kind != yaml.MappingNode {
		return doc, nil
	}
	doc.mapping = root.Content[0]
	doc.refresh()
	return doc, nil
}

func isNullScalar(n *yaml.Node) bool {
	return n.Kind == yaml.ScalarNode && n.Tag == "!!null"
}

func (d *vaultYAMLDoc) refresh() {
	d.entries = nil
	if d.mapping == nil {
		return
	}
	for i := 0; i+1 < len(d.mapping.Content); i += 2 {
		d.entries = append(d.entries, vaultYAMLEntry{
			Key:   d.mapping.Content[i].Value,
			Value: d.mapping.Content[i+1],
		})
	}
}

func (d *vaultYAMLDoc) Editable() bool {
	if d.mapping == nil {
		return false
	}
	for _, e := range d.entries {
		if e.Value.Kind != yaml.ScalarNode {
			return false
		}
	}
	return true
}

func (d *vaultYAMLDoc) HasKey(key string) bool {
	for _, e := range d.entries {
		if e.Key == key {
			return true
		}
	}
	return false
}

func (d *vaultYAMLDoc) Add(key, value string) {
	style := yaml.DoubleQuotedStyle
	if strings.Contains(value, "\n") {
		style = yaml.LiteralStyle
	}
	d.mapping.Content = append(d.mapping.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: value, Style: style},
	)
	d.refresh()
}

func (d *vaultYAMLDoc) Set(key, value string) {
	for _, e := range d.entries {
		if e.Key == key {
			e.Value.Value = value
			if strings.Contains(value, "\n") {
				e.Value.Style = yaml.LiteralStyle
			} else {
				e.Value.Style = yaml.DoubleQuotedStyle
			}
			return
		}
	}
	d.Add(key, value)
}

func (d *vaultYAMLDoc) Delete(key string) {
	if d.mapping == nil {
		return
	}
	var content []*yaml.Node
	for i := 0; i+1 < len(d.mapping.Content); i += 2 {
		if d.mapping.Content[i].Value == key {
			continue
		}
		content = append(content, d.mapping.Content[i], d.mapping.Content[i+1])
	}
	d.mapping.Content = content
	d.refresh()
}

func (d *vaultYAMLDoc) Bytes() []byte {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	_ = enc.Encode(d.root)
	_ = enc.Close()
	return buf.Bytes()
}

func (e vaultYAMLEntry) DisplayValue() string {
	return strings.ReplaceAll(e.Value.Value, "\n", `\n`)
}

func (e vaultYAMLEntry) EditValue() string {
	return e.DisplayValue()
}
