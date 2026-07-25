// L3 teatest integration tests driving editRouterModel (the real
// production code, not a reimplementation) through full multi-screen
// wizard flows, verifying the actual files written to disk at the
// end — the closest thing to the old promptui version's missing
// flow-level test coverage (edit_test.go only ever unit-tested pure
// data helpers; see edit_tui.go's package doc comment).
package cmd

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"

	"github.com/kjelly/pilot/internal/groupvars"
	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/vaultfile"
)

func TestEditRouter_Teatest_HostsFlow_AddHostSetFieldToggleRoleAndSave(t *testing.T) {
	dir := t.TempDir()
	router := newEditRouterModel(dir)
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))

	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // top menu: "hosts.yml" (cursor 0)
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // accept default hosts.yml path
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // confirm "start blank?" (default yes)
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // host list: "➕ 新增主機" (cursor 0)
	tm.Type("web-1")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // confirm new host name
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // host menu: "ansible_host" (cursor 0)
	tm.Type("10.0.0.5")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // confirm ansible_host value -> back to host menu

	// host menu items: 0 ansible_host, 1 ansible_user, 2 ssh key, 3 env,
	// 4 roles, 5 extra vars, 6 delete, 7 back-to-list
	for i := 0; i < 4; i++ {
		tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // roles menu

	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // roles menu: "☑ 逐項勾選角色" (cursor 0) -> checklist
	tm.Send(tea.KeyMsg{Type: tea.KeySpace}) // toggle the first role on
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // confirm checklist -> back to roles menu

	// roles menu items: 0 checklist, 1 preset, 2 manage presets, 3 copy, 4 done
	for i := 0; i < 4; i++ {
		tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // "✅ 完成" -> back to host menu

	// host menu again (cursor reset to 0); navigate to "↩ 返回主機清單" (index 7)
	for i := 0; i < 7; i++ {
		tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // back to host list

	// host list items now: 0 新增主機, 1 host summary, 2 共用變數,
	// 3 存檔並離開, 4 不存檔離開
	for i := 0; i < 3; i++ {
		tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // save and return to top menu

	// top menu items: 0 hosts.yml, 1 group_vars, 2 vault, 3 roster,
	// 4 檢查設定完整性, 5 離開
	for i := 0; i < 5; i++ {
		tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // quit

	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("expected hosts.yml to be written: %v", err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		t.Fatalf("written hosts.yml did not parse: %v\n%s", err, data)
	}
	if len(hf.Hosts) != 1 {
		t.Fatalf("expected 1 host, got %d:\n%s", len(hf.Hosts), data)
	}
	h := hf.Hosts[0]
	if h.Name != "web-1" {
		t.Fatalf("host name = %q, want web-1", h.Name)
	}
	if h.AnsibleHost != "10.0.0.5" {
		t.Fatalf("ansible_host = %q, want 10.0.0.5", h.AnsibleHost)
	}
	wantRole := inventory.Roles()[0].Name
	if !hasRole(h.Roles, wantRole) {
		t.Fatalf("expected role %q to be set, got %v", wantRole, h.Roles)
	}
}

// TestEditRouter_Teatest_FleetVarsFlow_AddEditDeleteAndSave exercises the
// hosts.yml top-level "vars:" (fleet-wide connection defaults, e.g.
// ansible_user) CRUD screen — mirrors pushExtraVarsMenu's pattern exactly,
// just keyed to hf.Vars, and proves the round-trip through Render/Parse.
func TestEditRouter_Teatest_FleetVarsFlow_AddEditDeleteAndSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.yml")
	hf := &inventory.HostsFile{Hosts: []inventory.Host{{Name: "web-1"}}}
	var router editRouterModel
	pushHostList(&router, dir, path, hf, "")
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	waitFor("共用變數")
	// host list items: 0 新增主機, 1 web-1, 2 共用變數, 3 存檔並離開, 4 不存檔離開
	for i := 0; i < 2; i++ {
		tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // -> fleet vars menu
	waitFor("➕ 新增變數")

	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // "➕ 新增變數" (only item, cursor 0)
	waitFor("變數名稱")
	tm.Type("ansible_user")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitFor("變數值")
	tm.Type("ubuntu")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // confirm -> back to fleet vars menu
	waitFor("ansible_user = ubuntu")

	// edit it
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // pick "ansible_user = ubuntu" (cursor 0)
	waitFor("修改值")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // "修改值"
	waitFor("的新值")
	for range "ubuntu" {
		tm.Send(tea.KeyMsg{Type: tea.KeyBackspace})
	}
	tm.Type("admin")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // confirm -> back to fleet vars menu
	waitFor("ansible_user = admin")

	// add a second var, then delete it, proving delete actually removes it
	tm.Send(tea.KeyMsg{Type: tea.KeyDown})  // "➕ 新增變數" (index 1 now)
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // add
	waitFor("變數名稱")
	tm.Type("scratch_var")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitFor("變數值")
	tm.Type("temp")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitFor("scratch_var = temp")

	tm.Send(tea.KeyMsg{Type: tea.KeyDown})  // scratch_var entry (sorted after ansible_user)
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // its action menu
	waitFor("刪除")
	tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // "刪除" -> back to fleet vars menu

	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		out := string(b)
		return strings.Contains(out, "ansible_user = admin") && !strings.Contains(out, "scratch_var")
	}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc}) // fleet vars menu -> host list
	waitFor("💾 存檔並離開")
	for i := 0; i < 3; i++ {
		tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // save -> top menu
	waitFor("要編輯什麼")
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc}) // top menu -> quit

	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("expected hosts.yml to be written: %v", err)
	}
	got, err := inventory.Parse(data)
	if err != nil {
		t.Fatalf("written hosts.yml did not parse: %v\n%s", err, data)
	}
	if got.Vars["ansible_user"] != "admin" {
		t.Fatalf("Vars[ansible_user] = %q, want admin (full vars: %v)", got.Vars["ansible_user"], got.Vars)
	}
	if _, ok := got.Vars["scratch_var"]; ok {
		t.Fatalf("scratch_var should have been deleted, got %v", got.Vars)
	}
}

func TestEditRouter_Teatest_HostsFlow_CancelAnywhereQuitsTheWholeWizard(t *testing.T) {
	dir := t.TempDir()
	router := newEditRouterModel(dir)
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))

	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // top menu -> hosts.yml
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // accept default path
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})   // cancel the "start blank?" confirm... but confirmModel maps esc to "no", not abort

	// promptConfirm's esc->no semantics mean this particular esc just
	// answers "no" (declining to start blank), which pushLoadOrInitHosts
	// maps to quitWizard — matching the original errDeployAborted path.
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	if _, err := os.Stat(filepath.Join(dir, "hosts.yml")); err == nil {
		t.Fatal("expected no hosts.yml to be written after declining to start blank")
	}
}

func TestEditRouter_Teatest_HostsFlow_EscOnSelectQuitsWholeWizard(t *testing.T) {
	dir := t.TempDir()
	router := newEditRouterModel(dir)
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc}) // esc on the very first (top menu) screen

	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

// TestEditRouter_Teatest_EscWalksBackThroughDeepChainThenQuitsAtTopMenu walks
// esc back through host menu -> roles menu -> role preset manager and all
// the way back out, proving the wizard-wide default (see edit_tui.go's
// package doc comment) is "go back one level" at every one of those
// screens, with the top menu as the sole screen where esc still quits for
// real, and pushHostList's unconditional confirm-discard (no dirty flag of
// its own) still gates leaving the whole hosts.yml flow.
func TestEditRouter_Teatest_EscWalksBackThroughDeepChainThenQuitsAtTopMenu(t *testing.T) {
	dir := t.TempDir()
	router := newEditRouterModel(dir)
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // top menu -> hosts.yml
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // accept default hosts.yml path
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // confirm "start blank?" (default yes)
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // host list: "➕ 新增主機"
	tm.Type("web-1")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // confirm new host name -> host menu
	waitFor("web-1")

	// host menu items: 0 ansible_host, 1 ansible_user, 2 ssh key, 3 env,
	// 4 roles, 5 extra vars, 6 delete, 7 return.
	for i := 0; i < 4; i++ {
		tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // -> roles menu
	waitFor("的角色")

	// roles menu items: 0 checklist, 1 preset, 2 manage presets, 3 copy, 4 done
	for i := 0; i < 2; i++ {
		tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // -> role preset manager
	waitFor("管理 ")

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc}) // preset manager -> roles menu
	waitFor("的角色")
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc}) // roles menu -> host menu
	waitFor("選要編輯的項目")
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc}) // host menu -> host list
	waitFor("💾 存檔並離開")
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc}) // host list -> confirm discard (unconditional here)
	waitFor("確定不存檔離開嗎")
	tm.Type("y") // confirm discard -> top menu
	waitFor("要編輯什麼")
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc}) // top menu -> the one screen that still quits for real

	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	if _, err := os.Stat(filepath.Join(dir, "hosts.yml")); !os.IsNotExist(err) {
		t.Fatalf("expected no hosts.yml to be written after discarding, stat err=%v", err)
	}
}

// TestEditRouter_Teatest_ExtraVarsFlow_EscStepsBackInsteadOfQuitting proves
// esc on any of the 其他變數 (extra host vars) CRUD flow's four nested
// screens steps back one level instead of aborting the whole wizard.
func TestEditRouter_Teatest_ExtraVarsFlow_EscStepsBackInsteadOfQuitting(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.yml")
	hf := &inventory.HostsFile{Hosts: []inventory.Host{{Name: "web-1", Extra: map[string]string{"ipa_server_ip": "10.0.0.9"}}}}
	var router editRouterModel
	pushExtraVarsMenu(&router, dir, path, hf, "web-1", "")
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	waitFor("ipa_server_ip = 10.0.0.9")

	// esc on the 其他變數 list itself: back to the host menu (which still
	// shows a live count), not a whole-wizard quit.
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	waitFor("其他變數(共 1 個)")

	// host menu index 5 = 其他變數 -> back into the list.
	for i := 0; i < 5; i++ {
		tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitFor("➕ 新增變數")

	// start adding a var, esc out of the key step: back to the list.
	tm.Send(tea.KeyMsg{Type: tea.KeyDown}) // "➕ 新增變數"
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitFor("變數名稱")
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	waitFor("➕ 新增變數")

	// start adding a var again, esc out of the value step: back to the
	// list, and the half-added key must not have been kept.
	tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitFor("變數名稱")
	tm.Type("foo_key")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitFor("變數值")
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	waitFor("➕ 新增變數")

	// select the existing var, esc out of the action menu: back to the list.
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // "ipa_server_ip = 10.0.0.9" (cursor reset to 0)
	waitFor("變數 ipa_server_ip = 10.0.0.9")
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	waitFor("➕ 新增變數")

	// re-enter the action menu, then esc out of the edit-value step:
	// back to the action menu (one level), not all the way to the list.
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitFor("變數 ipa_server_ip = 10.0.0.9")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // "修改值"
	waitFor("ipa_server_ip 的新值")
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc})
	waitFor("變數 ipa_server_ip = 10.0.0.9")

	// esc back out through the list, the host menu, and the host list —
	// none of these carry the 其他變數 exception, so each now steps back
	// one level per the wizard-wide "esc = go back" default; only the top
	// menu, reached at the very end of this chain, still quits for real.
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc}) // action menu -> list
	waitFor("➕ 新增變數")
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc}) // list -> host menu
	waitFor("其他變數(共 1 個)")
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc}) // host menu -> host list
	waitFor("💾 存檔並離開")
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc}) // host list -> confirm discard (unconditional here)
	waitFor("確定不存檔離開嗎")
	tm.Type("y") // confirm discard -> top menu
	waitFor("要編輯什麼")
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc}) // top menu -> whole-wizard quit

	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	if hf.Hosts[0].Extra["foo_key"] != "" {
		t.Fatalf("expected foo_key to not be added after esc-cancel, got %q", hf.Hosts[0].Extra["foo_key"])
	}
	if len(hf.Hosts[0].Extra) != 1 {
		t.Fatalf("expected exactly the original 1 extra var, got %v", hf.Hosts[0].Extra)
	}
}

// TestEditRouter_Teatest_HostVarsFlow_ScaffoldsEditsAndSaves proves the
// host_vars/<host>.yml menu item only appears for a host whose roles
// actually need it (prometheus here, via prometheus_site_label), that
// entering it auto-scaffolds an empty placeholder flagged as required, and
// that filling in and saving a real value round-trips to disk.
func TestEditRouter_Teatest_HostVarsFlow_ScaffoldsEditsAndSaves(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.yml")
	hf := &inventory.HostsFile{Hosts: []inventory.Host{{Name: "nexus", Roles: []string{"docker", "prometheus"}}}}
	var router editRouterModel
	pushHostMenu(&router, dir, path, hf, "nexus")
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	waitFor("host_vars/nexus.yml")

	// host menu items: 0 ansible_host, 1 ansible_user, 2 ssh key, 3 env,
	// 4 roles, 5 extra vars, 6 host_vars (present because of the
	// prometheus role), 7 delete, 8 return.
	for i := 0; i < 6; i++ {
		tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // enter host_vars editor -> auto-scaffolds
	// Both the "already created" banner and the entry's required-placeholder
	// state render in this same first frame — check them together in one
	// WaitFor, since each call drains tm.Output() and a second call looking
	// for text already emitted in an already-consumed frame would hang.
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		out := string(b)
		return strings.Contains(out, "已建立") && strings.Contains(out, "尚未填寫，必填！")
	}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))

	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // "prometheus_site_label = ...  [...]" (cursor 0)
	waitFor("修改值")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // "修改值" (cursor 0)
	waitFor("的新值")
	tm.Type("site-nexus")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // confirm new value -> back to editor screen
	waitFor("已設定")

	// editor screen items now: 0 the entry, 1 save, 2 discard.
	tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // "💾 存檔並離開" -> back to host menu

	waitFor("host_vars/nexus.yml")
	// Esc here now steps back to the host list rather than quitting (host
	// menu carries no cancel exception, but the wizard-wide default is
	// itself "go back one level" now — see edit_tui.go's package doc
	// comment); this test is only about the file round-trip, not further
	// navigation, so end the program directly instead of chaining through
	// the rest of the wizard.
	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	data, err := os.ReadFile(filepath.Join(dir, "host_vars", "nexus.yml"))
	if err != nil {
		t.Fatalf("expected host_vars/nexus.yml to be written: %v", err)
	}
	if !strings.Contains(string(data), "prometheus_site_label: site-nexus") {
		t.Fatalf("host_vars/nexus.yml = %q, want prometheus_site_label: site-nexus", data)
	}
}

// TestEditRouter_Teatest_HostVarsFlow_NotOfferedWithoutApplicableRole proves
// the host_vars menu item is absent for a host whose roles need no such var
// — matching how the group_vars picker only lists applicable stems.
func TestEditRouter_Teatest_HostVarsFlow_NotOfferedWithoutApplicableRole(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.yml")
	hf := &inventory.HostsFile{Hosts: []inventory.Host{{Name: "client-vm", Roles: []string{"docker", "freeipa-client"}}}}
	var router editRouterModel
	pushHostMenu(&router, dir, path, hf, "client-vm")
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))

	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		return strings.Contains(string(b), "🗑  刪除這台主機")
	}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))

	// Esc here now steps back to the host list rather than quitting (see
	// edit_tui.go's package doc comment); this test only cares about the
	// host menu's own rendered content, so end the program directly.
	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}

	final, err := io.ReadAll(tm.FinalOutput(t, teatest.WithFinalTimeout(3*time.Second)))
	if err != nil {
		t.Fatalf("read final output: %v", err)
	}
	if strings.Contains(string(final), "host_vars/") {
		t.Fatalf("host_vars menu item should not appear for a host with no applicable role:\n%s", final)
	}
}

// TestEditRouter_Teatest_HostVarsFlow_EscMirrorsDirtyDiscardGate is the
// host_vars analogue of the group_vars/vault dirty-mirroring tests: clean
// editor -> esc goes straight back to the host menu; dirty editor -> esc
// shows the same discard confirm "🚪 不存檔離開" would.
func TestEditRouter_Teatest_HostVarsFlow_EscMirrorsDirtyDiscardGate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.yml")
	hf := &inventory.HostsFile{Hosts: []inventory.Host{{Name: "nexus", Roles: []string{"docker", "prometheus"}}}}
	var router editRouterModel
	pushHostVarsEditor(&router, dir, path, hf, "nexus")
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	waitFor("尚未填寫，必填！")
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc}) // clean editor (freshly scaffolded, untouched): esc goes straight back
	waitFor("選要編輯的項目")

	// host_vars/nexus.yml (index 6: docker/ansible_host/user/ssh/env/roles/
	// extra vars precede it) already exists now, so re-entering just opens
	// it without the "已建立" scaffold banner.
	for i := 0; i < 6; i++ {
		tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitFor("尚未填寫，必填！")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // pick the prometheus_site_label entry
	waitFor("修改值")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // "修改值"
	waitFor("的新值")
	tm.Type("site-x")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // confirm -> back to the now-dirty editor
	waitFor("site-x")

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc}) // dirty editor: esc mirrors "🚪 不存檔離開"'s dirty gate
	waitFor("確定要放棄離開嗎")
	tm.Type("n") // decline discard -> back to the still-dirty editor
	waitFor("site-x")

	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	data, err := os.ReadFile(filepath.Join(dir, "host_vars", "nexus.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "site-x") {
		t.Fatalf("declining the discard confirm should not have saved to disk: %s", data)
	}
}

// TestEditRouter_Teatest_RoleChecklistFlow_AddingFreeIPANFSServerAutofixesRoster
// proves that checking freeipa-nfs-server on for a host that didn't have it
// before auto-appends its nfs.servers entry to the roster the host already
// points at (Host.Extra["freeipa_roster_file"]) — the one roster fact safe
// to write for real (not just scaffold) since it's fully derived, not a
// judgment call. See internal/inventory/roster.go.
func TestEditRouter_Teatest_RoleChecklistFlow_AddingFreeIPANFSServerAutofixesRoster(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.yml")
	rosterPath := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(rosterPath, []byte("---\nschema_version: 1\nfreeipa:\n  domain: ipa.pilot.internal\n"), 0o600); err != nil {
		t.Fatalf("write roster fixture: %v", err)
	}
	hf := &inventory.HostsFile{Hosts: []inventory.Host{{Name: "nexus", Extra: map[string]string{"freeipa_roster_file": rosterPath}}}}
	var router editRouterModel
	pushRoleChecklist(&router, dir, path, hf, "nexus")
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	waitFor("freeipa-nfs-server")

	// roleContracts order: 0 freeipa-server, 1 freeipa-client,
	// 2 freeipa-server-replica, 3 freeipa-nfs-server.
	for i := 0; i < 3; i++ {
		tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	}
	tm.Send(tea.KeyMsg{Type: tea.KeySpace}) // toggle freeipa-nfs-server on
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // confirm checklist -> roles menu

	waitFor("已自動在")

	// Esc here now steps back to the host menu rather than quitting (see
	// edit_tui.go's package doc comment); this test only cares about the
	// roster round-trip, so end the program directly.
	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	has, err := inventory.RosterHasNFSServer(rosterPath, "nexus.ipa.pilot.internal")
	if err != nil {
		t.Fatalf("RosterHasNFSServer() error = %v", err)
	}
	if !has {
		t.Fatalf("expected nexus.ipa.pilot.internal to have been appended to the roster")
	}
}

func TestEditRouter_Teatest_RoleChecklistFlow_BootstrapsMissingNFSRoster(t *testing.T) {
	dir := t.TempDir()
	hf := &inventory.HostsFile{Hosts: []inventory.Host{{Name: "nfs-demo", Extra: map[string]string{}}}}
	var router editRouterModel
	pushRoleChecklist(&router, dir, filepath.Join(dir, "hosts.yml"), hf, "nfs-demo")
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	waitFor("freeipa-nfs-server")
	for i := 0; i < 3; i++ {
		tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	}
	tm.Send(tea.KeyMsg{Type: tea.KeySpace})
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitFor("FreeIPA admin password")
	tm.Type("demo-password")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitFor("已建立最小 NFS roster")

	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	h := hf.Hosts[0]
	wantRosterPath, err := filepath.Abs(filepath.Join(dir, ".vault", "ipa-identity.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if h.Extra["freeipa_roster_file"] != wantRosterPath {
		t.Fatalf("freeipa_roster_file = %q, want absolute default roster path %q", h.Extra["freeipa_roster_file"], wantRosterPath)
	}
	rosterPath := h.Extra["freeipa_roster_file"]
	if has, err := inventory.RosterHasNFSServer(rosterPath, "nfs-demo.ipa.pilot.internal"); err != nil || !has {
		t.Fatalf("minimal roster NFS entry = has:%v err:%v, want present", has, err)
	}
	vault, err := os.ReadFile(filepath.Join(dir, ".vault", "main.yaml"))
	if err != nil {
		t.Fatalf("minimal FreeIPA vault missing: %v", err)
	}
	if string(vault) != "ipa_admin_password: demo-password\n" {
		t.Fatalf("minimal FreeIPA vault = %q, want generated admin password", vault)
	}
}

// TestEditRouter_Teatest_GroupVarsFlow_FiltersToUsedRolesAndAutofillsHostVar
// proves two things together: the "➕ 從範例建立" list only offers stems for
// roles hosts.yml actually uses (dns is never shown when nothing has the dns
// role), and creating freeipa.yml from its example auto-fills the
// commented-out freeipa_server_ip placeholder with the sole freeipa-server
// host's ansible_host — the one case safe to write for real, since the
// value is fully derived, not guessed (see groupVarsAutoHostVars).
func TestEditRouter_Teatest_GroupVarsFlow_FiltersToUsedRolesAndAutofillsHostVar(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hosts.yml"), []byte(
		"hosts:\n  ipa-1:\n    ansible_host: \"10.0.0.9\"\n    roles: [freeipa-server]\n"),
		0o644); err != nil {
		t.Fatal(err)
	}

	exampleDir := filepath.Join(dir, "group_vars")
	if err := os.MkdirAll(exampleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	freeipaExample := "---\n# freeipa_server_ip: \"192.0.2.10\"\nfreeipa_domain: ipa.pilot.internal\n"
	if err := os.WriteFile(filepath.Join(exampleDir, "freeipa.example.yml"), []byte(freeipaExample), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(exampleDir, "dns.example.yml"), []byte("dns_forwarders: \"8.8.8.8\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })

	router := newEditRouterModel(".")
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	tm.Send(tea.KeyMsg{Type: tea.KeyDown}) // top menu -> group_vars/ (index 1)
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitFor("➕ 從範例建立 freeipa.yml")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // "➕ 從範例建立 freeipa.yml" (only entry — dns is filtered out)

	// editor items in file order: 0 freeipa_server_ip (now autofilled and
	// active), 1 freeipa_domain, 2 save, 3 discard.
	waitFor("freeipa_server_ip = 10.0.0.9")

	for i := 0; i < 2; i++ {
		tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // "💾 存檔並離開" -> back to file picker

	// esc now steps back to the top menu instead of quitting directly; the
	// top menu is the one screen that still quits for real.
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc}) // file picker -> top menu
	waitFor("要編輯什麼")
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc}) // top menu -> whole-wizard quit
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	data, err := os.ReadFile(filepath.Join(dir, "group_vars", "freeipa.yml"))
	if err != nil {
		t.Fatalf("expected group_vars/freeipa.yml to be written: %v", err)
	}
	if !strings.Contains(string(data), "freeipa_server_ip: 10.0.0.9") {
		t.Fatalf("group_vars/freeipa.yml = %q, want an autofilled freeipa_server_ip: 10.0.0.9", data)
	}
}

// TestEditRouter_Teatest_GroupVarsFlow_DnsZonesDiscoverableButNotEditable
// proves the nested group_vars/dns/zones.example.yaml (previously invisible
// to both `pilot inventory generate` and `pilot edit`) is now discoverable
// and scaffoldable through the wizard's file picker, while still pointing
// at hand-editing rather than opening a confusingly empty structured editor
// (dns_zones is a 2-level nested list-of-maps with no top-level "key:
// value" line groupvars.Doc can represent).
func TestEditRouter_Teatest_GroupVarsFlow_DnsZonesDiscoverableButNotEditable(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "hosts.yml"), []byte(
		"hosts:\n  ns-1:\n    ansible_host: \"10.0.0.53\"\n    roles: [dns]\n"),
		0o644); err != nil {
		t.Fatal(err)
	}

	exampleDir := filepath.Join(dir, "group_vars")
	if err := os.MkdirAll(filepath.Join(exampleDir, "dns"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(exampleDir, "dns", "zones.example.yaml"), []byte("dns_zones:\n  - name: pilot.lan\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })

	router := newEditRouterModel(".")
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	tm.Send(tea.KeyMsg{Type: tea.KeyDown}) // top menu -> group_vars/ (index 1)
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitFor("➕ 從範例建立 dns/zones.yaml")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // create it (only entry, cursor 0)
	waitFor("巢狀清單設定")

	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	data, err := os.ReadFile(filepath.Join(dir, "group_vars", "dns", "zones.yaml"))
	if err != nil {
		t.Fatalf("expected group_vars/dns/zones.yaml to be created: %v", err)
	}
	if !strings.Contains(string(data), "pilot.lan") {
		t.Fatalf("created file = %q, want the copied example content", data)
	}
}

func TestEditRouter_Teatest_GroupVarsFlow_CreateFromExampleEditAndSave(t *testing.T) {
	dir := t.TempDir()
	exampleDir := filepath.Join(dir, "group_vars")
	if err := os.MkdirAll(exampleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	example := "# 說明\n# 這是一個測試設定\ndns_forwarders: \"8.8.8.8\"\n"
	if err := os.WriteFile(filepath.Join(exampleDir, "dns.example.yml"), []byte(example), 0o644); err != nil {
		t.Fatal(err)
	}

	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// selectGroupVarsFile/pushGroupVarsFilePicker reads the shipped
	// example templates from a fixed, CWD-relative "group_vars" dir —
	// chdir into our temp dir so that resolves to our fixture instead
	// of the real repo's group_vars/.
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })

	router := newEditRouterModel(".")
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))

	tm.Send(tea.KeyMsg{Type: tea.KeyDown}) // top menu -> group_vars/ (index 1)
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // file picker: "➕ 從範例建立 dns.yml" (only entry, cursor 0)
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // editor: pick the dns_forwarders entry (cursor 0)
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // entry menu: "修改值" (cursor 0)
	for range "8.8.8.8" {
		tm.Send(tea.KeyMsg{Type: tea.KeyBackspace})
	}
	tm.Type("1.1.1.1")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // confirm new value -> back to editor

	// editor items now: 0 dns_forwarders entry, 1 存檔並離開, 2 不存檔離開
	tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // save -> back to file picker

	// file picker items now: 0 dns.yml (now exists), 1 返回
	tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // back to top menu

	// top menu items: 0 hosts.yml, 1 group_vars, 2 vault, 3 roster,
	// 4 檢查設定完整性, 5 離開
	for i := 0; i < 5; i++ {
		tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // quit

	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	data, err := os.ReadFile(filepath.Join(dir, "group_vars", "dns.yml"))
	if err != nil {
		t.Fatalf("expected group_vars/dns.yml to be written: %v", err)
	}
	doc := groupvars.Parse(data)
	entries := doc.Entries()
	if len(entries) != 1 || entries[0].Value != "1.1.1.1" {
		t.Fatalf("expected dns_forwarders = 1.1.1.1, got entries: %+v\n%s", entries, data)
	}
}

// TestEditRouter_Teatest_GroupVarsFlow_ListEntryAddEditRemoveAndSave exercises
// the flow-list ("key: [a, b]") CRUD screens end to end through the real
// wizard: activating a commented-default list, adding an item, editing an
// existing item, removing one, and saving — proving the corruption bug
// found in Initiative 0 (restic_backup_paths-style settings silently
// getting quoted into a string) stays fixed all the way through real use.
func TestEditRouter_Teatest_GroupVarsFlow_ListEntryAddEditRemoveAndSave(t *testing.T) {
	dir := t.TempDir()
	gvDir := filepath.Join(dir, "group_vars")
	if err := os.MkdirAll(gvDir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(gvDir, "restic-backup.yml")
	if err := os.WriteFile(path, []byte("# 備份路徑\n# restic_backup_paths: [\"/etc\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var router editRouterModel
	pushGroupVarsEditor(&router, dir, path, "")
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	waitFor("restic_backup_paths = [/etc]")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // the only row (cursor 0) -> list entry menu
	waitFor("編輯清單項目")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // "編輯清單項目" -> items menu
	waitFor("➕ 新增項目")

	// add a second item
	tm.Send(tea.KeyMsg{Type: tea.KeyDown})  // "/etc" (0) -> "➕ 新增項目" (1)
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // add
	waitFor("新項目的值")
	tm.Type("/srv/data")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // confirm -> back to top-level editor screen
	waitFor("restic_backup_paths = [/etc, /srv/data]")

	// edit the first item ("/etc" -> "/var/log")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // the only row (cursor reset to 0)
	waitFor("編輯清單項目")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // -> items menu (now /etc, /srv/data, 新增, 返回)
	waitFor("的項目")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // "/etc" (cursor 0)
	waitFor("修改值")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // "修改值"
	waitFor("的新值")
	for range "/etc" {
		tm.Send(tea.KeyMsg{Type: tea.KeyBackspace})
	}
	tm.Type("/var/log")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // confirm -> back to top-level editor screen
	waitFor("restic_backup_paths = [/var/log, /srv/data]")

	// remove the second item ("/srv/data")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // the only row (cursor reset to 0)
	waitFor("編輯清單項目")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // -> items menu
	waitFor("的項目")
	tm.Send(tea.KeyMsg{Type: tea.KeyDown})  // "/var/log" (0) -> "/srv/data" (1)
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // "/srv/data"
	waitFor("移除")
	tm.Send(tea.KeyMsg{Type: tea.KeyDown})  // "修改值" (0) -> "移除" (1)
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // confirm removal -> back to top-level editor screen
	waitFor("restic_backup_paths = [/var/log]")

	// save
	tm.Send(tea.KeyMsg{Type: tea.KeyDown})  // the only row (0) -> "💾 存檔並離開" (1)
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // save
	waitFor("✅ 已存檔")

	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if !strings.Contains(got, "restic_backup_paths: [/var/log]") {
		t.Fatalf("saved file = %q, want an active restic_backup_paths: [/var/log]", got)
	}
	if strings.Contains(got, "/srv/data") || strings.Contains(got, "\"/etc\"") {
		t.Fatalf("saved file = %q, want /srv/data removed and /etc edited away, not both lingering", got)
	}
}

// TestEditRouter_Teatest_GroupVarsFlow_EscMirrorsDirtyDiscardGate proves esc
// on the group_vars editor screen does exactly what "🚪 不存檔離開" already
// does: a clean editor goes straight back to the file picker with no
// prompt, but a dirty one shows the same "有未存檔的修改" discard confirm —
// esc is not a way to silently bypass that safety net.
func TestEditRouter_Teatest_GroupVarsFlow_EscMirrorsDirtyDiscardGate(t *testing.T) {
	dir := t.TempDir()
	gvDir := filepath.Join(dir, "group_vars")
	if err := os.MkdirAll(gvDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gvDir, "dns.yml"), []byte("dns_forwarders: \"8.8.8.8\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var router editRouterModel
	pushGroupVarsEditor(&router, dir, filepath.Join(gvDir, "dns.yml"), "")
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	waitFor("dns_forwarders")
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc}) // clean editor: esc goes straight back, no confirm
	waitFor("選一個")

	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // file picker: dns.yml (the only entry, cursor 0)
	waitFor("dns_forwarders")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // pick the dns_forwarders entry
	waitFor("修改值")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // "修改值"
	waitFor("的新值")
	tm.Type("1.1.1.1")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // confirm -> back to the now-dirty editor
	waitFor("1.1.1.1")

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc}) // dirty editor: esc mirrors "🚪 不存檔離開"'s dirty gate
	waitFor("確定要放棄離開嗎")
	tm.Type("n") // decline discard -> back to the still-dirty editor
	waitFor("1.1.1.1")

	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	data, err := os.ReadFile(filepath.Join(gvDir, "dns.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "1.1.1.1") {
		t.Fatalf("declining the discard confirm should not have saved to disk: %s", data)
	}
}

func TestEditRouter_Teatest_VaultFlow_CreateAddKeyAndSave(t *testing.T) {
	dir := t.TempDir()
	router := newEditRouterModel(dir)
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))

	for i := 0; i < 2; i++ {
		tm.Send(tea.KeyMsg{Type: tea.KeyDown}) // top menu -> .vault/ (index 2)
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // vault file picker: "📍 輸入其他 vault 檔路徑" (only real entry besides 返回, cursor 0)
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // accept default vault path
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // confirm "create new plaintext vault file?" default yes

	// vault editor (empty): items 0 新增 key, 1 存檔並離開, 2 不存檔離開
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // "➕ 新增 key"
	tm.Type("ipa_admin_password")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	tm.Type("s3cr3t")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // confirm value -> back to editor

	// editor items now: 0 ipa_admin_password entry, 1 新增 key, 2 存檔並離開, 3 不存檔離開
	tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // save -> back to vault file picker

	// file picker items now: 0 <created file>, 1 輸入其他路徑, 2 返回
	for i := 0; i < 2; i++ {
		tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // back to top menu

	// top menu items: 0 hosts.yml, 1 group_vars, 2 vault, 3 roster,
	// 4 檢查設定完整性, 5 離開
	for i := 0; i < 5; i++ {
		tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // quit

	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	data, err := os.ReadFile(filepath.Join(dir, ".vault", "main.yaml"))
	if err != nil {
		t.Fatalf("expected .vault/main.yaml to be written: %v", err)
	}
	doc, err := vaultfile.Parse(data)
	if err != nil {
		t.Fatalf("written vault file did not parse: %v\n%s", err, data)
	}
	entries := doc.Entries()
	if len(entries) != 1 || entries[0].Key != "ipa_admin_password" || entries[0].DisplayValue() != "s3cr3t" {
		t.Fatalf("unexpected vault entries: %+v\n%s", entries, data)
	}
}

// TestEditRouter_Teatest_VaultFlow_EscMirrorsDirtyDiscardGate is the vault
// analogue of the group_vars dirty-mirroring test: clean editor -> esc goes
// straight back; dirty editor -> esc shows the same discard confirm
// "🚪 不存檔離開" would.
func TestEditRouter_Teatest_VaultFlow_EscMirrorsDirtyDiscardGate(t *testing.T) {
	dir := t.TempDir()
	vaultDir := filepath.Join(dir, ".vault")
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vaultDir, "main.yaml"), []byte("---\nfoo: \"bar\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var router editRouterModel
	pushVaultOpen(&router, dir, filepath.Join(vaultDir, "main.yaml"))
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	waitFor("foo = ")
	tm.Send(tea.KeyMsg{Type: tea.KeyEsc}) // clean editor: esc goes straight back, no confirm
	waitFor("選一個")

	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // file picker: main.yaml (cursor 0)
	waitFor("foo = ")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // pick the foo entry
	waitFor("修改值")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // "修改值"
	waitFor("的新值")
	for range "bar" {
		tm.Send(tea.KeyMsg{Type: tea.KeyBackspace})
	}
	tm.Type("baz")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // confirm -> back to the now-dirty editor
	waitFor("foo = baz")

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc}) // dirty editor: esc mirrors "🚪 不存檔離開"'s dirty gate
	waitFor("確定要放棄離開嗎")
	tm.Type("n") // decline discard -> back to the still-dirty editor
	waitFor("foo = baz")

	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	data, err := os.ReadFile(filepath.Join(vaultDir, "main.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "baz") {
		t.Fatalf("declining the discard confirm should not have saved to disk: %s", data)
	}
}

// TestEditRouter_Teatest_RosterFlow_TopMenuReachesManager proves the new
// "roster" top-menu item (alongside hosts.yml/group_vars/.vault) actually
// reaches the roster manager for an existing roster file.
func TestEditRouter_Teatest_RosterFlow_TopMenuReachesManager(t *testing.T) {
	dir := t.TempDir()
	rosterPath := filepath.Join(dir, ".vault", "ipa-identity.yaml")
	if err := os.MkdirAll(filepath.Dir(rosterPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rosterPath, []byte("schema_version: 1\nusers: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	router := newEditRouterModel(dir)
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	// top menu items: 0 hosts.yml, 1 group_vars, 2 vault, 3 roster, 4 離開
	for i := 0; i < 3; i++ {
		tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // -> roster path prompt
	waitFor("Roster 檔路徑")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // accept the default (.vault/ipa-identity.yaml matches our fixture)
	waitFor("👤 Users")

	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

// TestEditRouter_Teatest_RosterFlow_AddUserAndGroupWithValidationGate
// exercises the append-only users/groups CRUD end to end: a valid add
// persists and still validates clean; an invalid add (duplicate name, wrong
// category prefix) is blocked before ever touching disk, with the
// violation surfaced instead of silently failing or silently succeeding.
func TestEditRouter_Teatest_RosterFlow_AddUserAndGroupWithValidationGate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	if err := os.WriteFile(path, []byte("schema_version: 1\nusers:\n  - name: alice\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var router editRouterModel
	pushRosterManager(&router, dir, path, "")
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	waitFor("👤 Users")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // -> Users menu
	waitFor("現有 users")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // "➕ 新增 User"
	waitFor("新 user 的名稱")
	tm.Type("bob")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // valid -> appended
	waitFor("已新增 user bob")

	// duplicate name: blocked by the validator, never written.
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // "➕ 新增 User"
	waitFor("新 user 的名稱")
	tm.Type("bob")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitFor("驗證沒過")

	tm.Send(tea.KeyMsg{Type: tea.KeyEsc}) // Users menu -> roster manager
	waitFor("👥 Groups")
	tm.Send(tea.KeyMsg{Type: tea.KeyDown})  // "👤 Users" (0) -> "👥 Groups" (1)
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // -> Groups menu
	waitFor("目前沒有任何 group")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // "➕ 新增 Group"
	waitFor("分類")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // category: team (cursor 0)
	waitFor("記得帶前綴")
	tm.Type("team-ops")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // valid -> appended
	waitFor("已新增 group team-ops")

	// wrong prefix for the chosen category: blocked by the validator.
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // "➕ 新增 Group"
	waitFor("分類")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // category: team
	waitFor("記得帶前綴")
	tm.Type("ops-nomatch")
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter})
	waitFor("驗證沒過")

	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	users, err := inventory.RosterUserNames(path)
	if err != nil {
		t.Fatalf("RosterUserNames() error = %v", err)
	}
	if len(users) != 2 || users[0] != "alice" || users[1] != "bob" {
		t.Fatalf("RosterUserNames() = %v, want [alice bob] (no duplicate)", users)
	}
	groups, err := inventory.RosterGroupNames(path)
	if err != nil {
		t.Fatalf("RosterGroupNames() error = %v", err)
	}
	if len(groups) != 1 || groups[0] != "team-ops" {
		t.Fatalf("RosterGroupNames() = %v, want [team-ops] (bad-prefix group rejected)", groups)
	}
	violations, err := inventory.ValidateRosterFile(path)
	if err != nil {
		t.Fatalf("ValidateRosterFile() error = %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("expected the final roster to still validate clean, got %v", violations)
	}
}
