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

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/kjelly/pilot/internal/groupvars"
	"github.com/kjelly/pilot/internal/inventory"
	"github.com/kjelly/pilot/internal/vaultfile"
)

func TestEditRouter_Teatest_HostsFlow_AddHostSetFieldToggleRoleAndSave(t *testing.T) {
	dir := t.TempDir()
	router := newEditRouterModel(dir)
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))

	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // top menu: "hosts.yml" (cursor 0)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // accept default hosts.yml path
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm "start blank?" (default yes)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // host list: "➕ 新增主機" (cursor 0)
	tm.Type("web-1")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm new host name
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // host menu: "ansible_host" (cursor 0)
	tm.Type("10.0.0.5")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm ansible_host value -> back to host menu

	// host menu items: 0 ansible_host, 1 ansible_user, 2 ssh key, 3 env,
	// 4 roles, 5 extra vars, 6 deployment availability, 7 delete, 8 back-to-list
	for i := 0; i < 4; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // roles menu

	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // roles menu: "☑ 逐項勾選角色" (cursor 0) -> checklist
	tm.Send(tea.KeyPressMsg{Code: tea.KeySpace}) // toggle the first role on
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm checklist -> back to roles menu

	// roles menu items: 0 checklist, 1 preset, 2 manage presets, 3 copy, 4 done
	for i := 0; i < 4; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "✅ 完成" -> back to host menu

	// host menu again (cursor reset to 0); navigate to "↩ 返回主機清單" (index 8)
	for i := 0; i < 8; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // back to host list

	// host list items now: 0 新增主機, 1 host summary, 2 共用變數,
	// 3 存檔並離開, 4 不存檔離開
	for i := 0; i < 3; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // save and return to top menu

	// top menu items: 0 hosts.yml, 1 group_vars, 2 vault, 3 roster,
	// 4 freeipa-dns manifest, 5 internal-endpoints manifest, 6 monitoring,
	// 7 檢查設定完整性, 8 快速建立最小 workspace, 9 離開
	for i := 0; i < 9; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // quit

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

func TestEditRouter_Teatest_HostDeploymentAvailabilityOptionalAndSave(t *testing.T) {
	dir := t.TempDir()
	router := newEditRouterModel(dir)
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))

	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // top menu: hosts.yml
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // default path
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // start blank
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // add host
	tm.Type("laptop-1")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // host name -> host menu

	for i := 0; i < 6; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // deployment availability
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // optional -> host menu

	for i := 0; i < 8; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // return to host list
	for i := 0; i < 3; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // save
	for i := 0; i < 9; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // quit
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	data, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("read hosts.yml: %v", err)
	}
	hf, err := inventory.Parse(data)
	if err != nil {
		t.Fatalf("parse hosts.yml: %v\n%s", err, data)
	}
	if got := hf.Hosts[0].DeploymentAvailability; got != inventory.DeploymentAvailabilityOptional {
		t.Fatalf("deployment_availability = %q, want optional\n%s", got, data)
	}
}

func TestHostMenuItems_MetadataHasStableUniqueIDs(t *testing.T) {
	h := &inventory.Host{Name: "nexus", Roles: []string{"prometheus"}}
	items := hostMenuItems(h)
	got := make(map[string]bool, len(items))
	for _, item := range items {
		if item.choice.ID == "" {
			t.Fatal("host menu item has an empty ID")
		}
		if got[item.choice.ID] {
			t.Fatalf("host menu item ID %q is duplicated", item.choice.ID)
		}
		got[item.choice.ID] = true
		if item.open == nil {
			t.Fatalf("host menu item %q has no handler", item.choice.ID)
		}
	}
	for _, id := range []string{
		"hosts.item.ansible_host",
		"hosts.item.ansible_user",
		"hosts.item.ssh_key_file",
		"hosts.item.env",
		"hosts.item.roles",
		"hosts.item.extra_vars",
		"hosts.item.host_vars",
		"hosts.item.deployment_availability",
		"hosts.item.delete",
		"hosts.item.back",
	} {
		if !got[id] {
			t.Errorf("host menu metadata is missing %q", id)
		}
	}
}

func TestEditRouter_Teatest_MinimalWorkspaceEntryKeepsAdvancedEntries(t *testing.T) {
	dir := t.TempDir()
	router := newEditRouterModel(dir)
	view := viewContent(router.View())
	for _, want := range []string{
		"快速建立最小 workspace",
		"hosts.yml — 機器清單與角色",
		"group_vars/ — 角色的設定值",
		".vault/ — vault 變數檔",
		"🔍 檢查設定完整性",
	} {
		if !strings.Contains(view, want) {
			t.Errorf("top-menu view missing %q:\n%s", want, view)
		}
	}
}

func TestEditRouter_Teatest_MinimalWorkspaceRequiresHostsBeforeScaffolding(t *testing.T) {
	dir := t.TempDir()
	tm := teatest.NewTestModel(t, newEditRouterModel(dir), teatest.WithInitialTermSize(100, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	// top menu: 0 hosts.yml, 1 group_vars, 2 vault, 3 roster,
	// 4 freeipa-dns manifest, 5 internal-endpoints manifest, 6 monitoring,
	// 7 檢查設定完整性, 8 快速建立最小 workspace, 9 離開
	for i := 0; i < 8; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor("快速建立最小 workspace")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown}) // 建立／更新最小設定骨架
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor("先選「設定主機與角色」")

	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc})
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
}

func TestEditRouter_Teatest_MinimalWorkspaceReadinessBlocksAndOffersRoute(t *testing.T) {
	useRepositoryTemplates(t)
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "hosts.yml"), `hosts:
  nexus:
    ansible_host: 10.0.0.10
    roles: [prometheus]
`)
	tm := teatest.NewTestModel(t, newEditRouterModel(dir), teatest.WithInitialTermSize(100, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(3*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	// top menu: 0 hosts.yml, 1 group_vars, 2 vault, 3 roster,
	// 4 freeipa-dns manifest, 5 internal-endpoints manifest, 6 monitoring,
	// 7 檢查設定完整性, 8 快速建立最小 workspace, 9 離開
	for i := 0; i < 8; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor("快速建立最小 workspace")

	// quick wizard: 0 設定主機與角色 ... 4 驗證並檢查是否可部署
	for i := 0; i < 4; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})

	// prometheus_site_label has no safe cross-host default, so host_vars blocks.
	// Both the report line and the offered route render together, so assert them
	// in one condition — tm.Output() is a streaming reader, not a re-readable
	// snapshot, so a second waitFor on the same screen would see nothing.
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		out := string(b)
		return strings.Contains(out, filepath.Join("host_vars", "nexus.yml")) &&
			strings.Contains(out, "前往 hosts 設定")
	}, teatest.WithDuration(3*time.Second), teatest.WithCheckInterval(10*time.Millisecond))

	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // readiness -> quick wizard
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // quick wizard -> top menu
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // top menu -> quit

	final, err := io.ReadAll(tm.FinalOutput(t, teatest.WithFinalTimeout(3*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(final), "最小 workspace 已可部署") {
		t.Fatalf("reported deploy-ready while host_vars was still incomplete:\n%s", final)
	}
	// The blocking screen must not offer a destination that cannot fix anything.
	if strings.Contains(string(final), "前往 vault") {
		t.Fatalf("offered a vault route with no failing vault check:\n%s", final)
	}
}

func TestPushSaveHostsAndReturnTop_UsesQuickPathContinuation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.yml")
	router := editRouterModel{}
	called := false
	router.afterHostsSave = func(r *editRouterModel) tea.Cmd {
		called = true
		return nil
	}

	pushSaveHostsAndReturnTop(&router, dir, path, &inventory.HostsFile{Hosts: []inventory.Host{{Name: "node"}}})
	if !called {
		t.Fatal("quick-path continuation was not called after hosts save")
	}
	if router.afterHostsSave != nil {
		t.Fatal("quick-path continuation was not cleared")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("hosts.yml was not saved before continuation: %v", err)
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
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> fleet vars menu
	waitFor("新增變數")                              // dropped the emoji prefix: v2 sometimes splits it from the text across a small cursor-adjust diff (see the "值" comment above)

	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "➕ 新增變數" (only item, cursor 0)
	waitFor("變數名稱")
	tm.Type("ansible_user")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	// Checks the label's distinguishing suffix, not the full "變數值"
	// phrase: Bubble Tea v2's renderer diffs at the cell level, and since
	// this label shares the "變數" prefix with the previous screen's
	// "變數名稱" label at the same position, only the differing tail
	// ("值" replacing "名稱") is ever retransmitted — see the analogous
	// comment in edit_tui_dns_test.go for the fuller explanation.
	waitFor("值")
	tm.Type("ubuntu")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm -> back to fleet vars menu
	waitFor("ansible_user = ubuntu")

	// edit it
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // pick "ansible_user = ubuntu" (cursor 0)
	waitFor("修改值")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "修改值"
	waitFor("的新值")
	for range "ubuntu" {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyBackspace})
	}
	tm.Type("admin")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm -> back to fleet vars menu
	waitFor("ansible_user = admin")

	// add a second var, then delete it, proving delete actually removes it
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})  // "➕ 新增變數" (index 1 now)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // add
	waitFor("變數名稱")
	tm.Type("scratch_var")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor("值") // see the comment above the first "變數值" waitFor in this test
	tm.Type("temp")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor("scratch_var = temp")

	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})  // scratch_var entry (sorted after ansible_user)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // its action menu
	waitFor("刪除")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "刪除" -> back to fleet vars menu

	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		out := string(b)
		return strings.Contains(out, "ansible_user = admin") && !strings.Contains(out, "scratch_var")
	}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))

	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // fleet vars menu -> host list
	waitFor("💾 存檔並離開")
	for i := 0; i < 3; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // save -> top menu
	waitFor("要編輯什麼")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // top menu -> quit

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

	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // top menu -> hosts.yml
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // accept default path
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc})   // cancel the "start blank?" confirm... but confirmModel maps esc to "no", not abort

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

	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // esc on the very first (top menu) screen

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

	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // top menu -> hosts.yml
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // accept default hosts.yml path
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm "start blank?" (default yes)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // host list: "➕ 新增主機"
	tm.Type("web-1")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm new host name -> host menu
	waitFor("web-1")

	// host menu items: 0 ansible_host, 1 ansible_user, 2 ssh key, 3 env,
	// 4 roles, 5 extra vars, 6 delete, 7 return.
	for i := 0; i < 4; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> roles menu
	waitFor("的角色")

	// roles menu items: 0 checklist, 1 preset, 2 manage presets, 3 copy, 4 done
	for i := 0; i < 2; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> role preset manager
	waitFor("管理 ")

	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // preset manager -> roles menu
	waitFor("的角色")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // roles menu -> host menu
	waitFor("選要編輯的項目")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // host menu -> host list
	waitFor("💾 存檔並離開")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // host list -> confirm discard (unconditional here)
	waitFor("確定不存檔離開嗎")
	tm.Type("y") // confirm discard -> top menu
	waitFor("要編輯什麼")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // top menu -> the one screen that still quits for real

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
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc})
	waitFor("其他變數(共 1 個)")

	// host menu index 5 = 其他變數 -> back into the list.
	for i := 0; i < 5; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor("新增變數") // dropped the emoji prefix: v2 sometimes splits it from the text across a small cursor-adjust diff (see the "值" comment above)

	// start adding a var, esc out of the key step: back to the list.
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown}) // "➕ 新增變數"
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor("變數名稱")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc})
	waitFor("新增變數") // dropped the emoji prefix: v2 sometimes splits it from the text across a small cursor-adjust diff (see the "值" comment above)

	// start adding a var again, esc out of the value step: back to the
	// list, and the half-added key must not have been kept.
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor("變數名稱")
	tm.Type("foo_key")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	// See the "變數值" comment on TestEditRouter_Teatest_FleetVarsFlow_AddEditDeleteAndSave
	// above: only the label's distinguishing suffix survives Bubble Tea
	// v2's cell-level render diff, since "變數" is already on screen from
	// the previous "變數名稱" label at the same position.
	waitFor("值")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc})
	waitFor("新增變數") // dropped the emoji prefix: v2 sometimes splits it from the text across a small cursor-adjust diff (see the "值" comment above)

	// select the existing var, esc out of the action menu: back to the list.
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "ipa_server_ip = 10.0.0.9" (cursor reset to 0)
	waitFor("變數 ipa_server_ip = 10.0.0.9")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc})
	waitFor("新增變數") // dropped the emoji prefix: v2 sometimes splits it from the text across a small cursor-adjust diff (see the "值" comment above)

	// re-enter the action menu, then esc out of the edit-value step:
	// back to the action menu (one level), not all the way to the list.
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor("變數 ipa_server_ip = 10.0.0.9")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "修改值"
	waitFor("ipa_server_ip 的新值")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc})
	waitFor("變數 ipa_server_ip = 10.0.0.9")

	// esc back out through the list, the host menu, and the host list —
	// none of these carry the 其他變數 exception, so each now steps back
	// one level per the wizard-wide "esc = go back" default; only the top
	// menu, reached at the very end of this chain, still quits for real.
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // action menu -> list
	waitFor("新增變數")                            // dropped the emoji prefix: v2 sometimes splits it from the text across a small cursor-adjust diff (see the "值" comment above)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // list -> host menu
	waitFor("其他變數(共 1 個)")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // host menu -> host list
	waitFor("💾 存檔並離開")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // host list -> confirm discard (unconditional here)
	waitFor("確定不存檔離開嗎")
	tm.Type("y") // confirm discard -> top menu
	waitFor("要編輯什麼")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // top menu -> whole-wizard quit

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
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // enter host_vars editor -> auto-scaffolds
	// Both the "already created" banner and the entry's required-placeholder
	// state render in this same first frame — check them together in one
	// WaitFor, since each call drains tm.Output() and a second call looking
	// for text already emitted in an already-consumed frame would hang.
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		out := string(b)
		return strings.Contains(out, "已建立") && strings.Contains(out, "尚未填寫，必填！")
	}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))

	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "prometheus_site_label = ...  [...]" (cursor 0)
	waitFor("修改值")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "修改值" (cursor 0)
	waitFor("的新值")
	tm.Type("site-nexus")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm new value -> back to editor screen
	waitFor("已設定")

	// editor screen items now: 0 the entry, 1 save, 2 discard.
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "💾 存檔並離開" -> back to host menu

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
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // clean editor (freshly scaffolded, untouched): esc goes straight back
	waitFor("選要編輯的項目")

	// host_vars/nexus.yml (index 6: docker/ansible_host/user/ssh/env/roles/
	// extra vars precede it) already exists now, so re-entering just opens
	// it without the "已建立" scaffold banner.
	for i := 0; i < 6; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor("尚未填寫，必填！")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // pick the prometheus_site_label entry
	waitFor("修改值")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "修改值"
	waitFor("的新值")
	tm.Type("site-x")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm -> back to the now-dirty editor
	waitFor("site-x")

	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // dirty editor: esc mirrors "🚪 不存檔離開"'s dirty gate
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
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeySpace}) // toggle freeipa-nfs-server on
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm checklist -> roles menu

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

// TestEditRouter_Teatest_RoleChecklistFlow_PrometheusForcesHostVarsPrompt
// proves the gap this closes: checking "prometheus" on for a host that
// didn't have it before must not silently leave prometheus_site_label
// unfilled for the user to stumble on later. The checklist confirm now
// jumps straight into that field's text input — generalizing
// freeipa-nfs-server's own forced bootstrap prompt to any HostVarsKeys role
// (see pushForcedHostVarsPrompt, edit_tui_hostvars.go) — instead of
// returning to the plain roles menu and leaving host_vars/<host>.yml's menu
// item to be noticed on its own.
func TestEditRouter_Teatest_RoleChecklistFlow_PrometheusForcesHostVarsPrompt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hosts.yml")
	hf := &inventory.HostsFile{Hosts: []inventory.Host{{Name: "nexus", Roles: []string{"docker"}}}}
	var router editRouterModel
	pushRoleChecklist(&router, dir, path, hf, "nexus")
	// 48, not the usual 40: one more role row (snmp-exporter, SNMP
	// monitoring integration spec Phase 0) now overflows a 40-row test
	// terminal alongside the huh MultiSelect's title line.
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 48))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	waitFor("prometheus")

	// Home the cursor before counting rows: a Huh-backed checklist starts
	// focused on the first ALREADY-CHECKED option, not on row 0 (huh
	// v2.0.3 field_multiselect.go, "set the cursor to the existing value
	// or the last selected option"), and this host starts with docker
	// (row 9) checked. Pressing Up past the top — huh clamps the cursor
	// at 0 — is exactly how the production automation driver's own
	// moveCursor normalizes the cursor before navigating, so the DOWN
	// count below means the same thing it always did regardless of which
	// roles happen to be checked on entry.
	for i := 0; i < len(inventory.Roles()); i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyUp})
	}
	// roleContracts order: 0 freeipa-server .. 19 host-monitoring ..
	// 20 dcgm-exporter .. 21 alertmanager .. 22 snmp-exporter ..
	// 23 prometheus (SNMP monitoring integration spec Phase 0 inserted
	// snmp-exporter between alertmanager and prometheus, shifting
	// prometheus's index by one again).
	for i := 0; i < 23; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeySpace}) // toggle prometheus on
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm checklist -> forced host_vars prompt, NOT the roles menu

	waitFor("prometheus_site_label 的新值")
	tm.Type("site-nexus")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm value -> lands on host_vars list editor, dirty

	waitFor("已設定")
	// editor screen items: 0 the entry, 1 save, 2 discard.
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "💾 存檔並離開" -> back to host menu

	waitFor("host_vars/nexus.yml")
	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	data, err := os.ReadFile(filepath.Join(dir, "host_vars", "nexus.yml"))
	if err != nil {
		t.Fatalf("expected host_vars/nexus.yml to be written: %v", err)
	}
	if !strings.Contains(string(data), "prometheus_site_label: site-nexus") {
		t.Fatalf("expected prometheus_site_label to be filled, got:\n%s", data)
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
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeySpace})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor("FreeIPA admin password")
	tm.Type("demo-password")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
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

// TestEditRouter_Teatest_RoleChecklistFlow_NFSBootstrapReusesExistingAdminPassword
// proves the fix for a real complaint: when .vault/main.yaml already has a
// real ipa_admin_password (e.g. from an earlier bootstrap), toggling
// freeipa-nfs-server on for a NEW host must not make the operator type
// that same password again — it should reuse it silently (with a banner
// saying so), never showing the password prompt at all.
func TestEditRouter_Teatest_RoleChecklistFlow_NFSBootstrapReusesExistingAdminPassword(t *testing.T) {
	dir := t.TempDir()
	vaultDir := filepath.Join(dir, ".vault")
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vaultDir, "main.yaml"), []byte("ipa_admin_password: \"existing-secret\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	hf := &inventory.HostsFile{Hosts: []inventory.Host{{Name: "nfs-demo", Extra: map[string]string{}}}}
	var router editRouterModel
	pushRoleChecklist(&router, dir, filepath.Join(dir, "hosts.yml"), hf, "nfs-demo")
	// Much wider than this file's usual 100 columns: the success banner
	// embeds the full (absolute, t.TempDir()-rooted) roster path plus its
	// own explanatory text plus the reuse note — comfortably past 220
	// columns before the reuse note is even reached.
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(400, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	waitFor("freeipa-nfs-server")
	for i := 0; i < 3; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeySpace})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm checklist -> straight to the roster, no password prompt
	waitFor("沿用 .vault/main.yaml 現有的 ipa_admin_password")

	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	rosterPath := hf.Hosts[0].Extra["freeipa_roster_file"]
	data, err := os.ReadFile(rosterPath)
	if err != nil {
		t.Fatalf("read %s: %v", rosterPath, err)
	}
	if !strings.Contains(string(data), "existing-secret") {
		t.Fatalf("expected the reused password in the generated roster:\n%s", data)
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

	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown}) // top menu -> group_vars/ (index 1)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor("➕ 從範例建立 freeipa.yml")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "➕ 從範例建立 freeipa.yml" (only entry — dns is filtered out)

	// editor items in file order: 0 freeipa_server_ip (now autofilled and
	// active), 1 freeipa_domain, 2 save, 3 discard.
	waitFor("freeipa_server_ip = 10.0.0.9")

	for i := 0; i < 2; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "💾 存檔並離開" -> back to file picker

	// esc now steps back to the top menu instead of quitting directly; the
	// top menu is the one screen that still quits for real.
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // file picker -> top menu
	waitFor("要編輯什麼")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // top menu -> whole-wizard quit
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

	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown}) // top menu -> group_vars/ (index 1)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor("➕ 從範例建立 dns/zones.yaml")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // create it (only entry, cursor 0)
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

	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown}) // top menu -> group_vars/ (index 1)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // file picker: "➕ 從範例建立 dns.yml" (only entry, cursor 0)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // editor: pick the dns_forwarders entry (cursor 0)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // entry menu: "修改值" (cursor 0)
	for range "8.8.8.8" {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyBackspace})
	}
	tm.Type("1.1.1.1")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm new value -> back to editor

	// editor items now: 0 dns_forwarders entry, 1 存檔並離開, 2 不存檔離開
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // save -> back to file picker

	// file picker items now: 0 dns.yml (now exists), 1 返回
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // back to top menu

	// top menu items: 0 hosts.yml, 1 group_vars, 2 vault, 3 roster,
	// 4 freeipa-dns manifest, 5 internal-endpoints manifest, 6 monitoring,
	// 7 檢查設定完整性, 8 快速建立最小 workspace, 9 離開
	for i := 0; i < 9; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // quit

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
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // the only row (cursor 0) -> list entry menu
	waitFor("編輯清單項目")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "編輯清單項目" -> items menu
	waitFor("➕ 新增項目")

	// add a second item
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})  // "/etc" (0) -> "➕ 新增項目" (1)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // add
	waitFor("新項目的值")
	tm.Type("/srv/data")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm -> back to top-level editor screen
	waitFor("restic_backup_paths = [/etc, /srv/data]")

	// edit the first item ("/etc" -> "/var/log")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // the only row (cursor reset to 0)
	waitFor("編輯清單項目")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> items menu (now /etc, /srv/data, 新增, 返回)
	waitFor("的項目")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "/etc" (cursor 0)
	waitFor("修改值")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "修改值"
	waitFor("的新值")
	for range "/etc" {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyBackspace})
	}
	tm.Type("/var/log")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm -> back to top-level editor screen
	waitFor("restic_backup_paths = [/var/log, /srv/data]")

	// remove the second item ("/srv/data")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // the only row (cursor reset to 0)
	waitFor("編輯清單項目")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> items menu
	waitFor("的項目")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})  // "/var/log" (0) -> "/srv/data" (1)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "/srv/data"
	waitFor("移除")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})  // "修改值" (0) -> "移除" (1)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm removal -> back to top-level editor screen
	waitFor("restic_backup_paths = [/var/log]")

	// save
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})  // the only row (0) -> "💾 存檔並離開" (1)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // save
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
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // clean editor: esc goes straight back, no confirm
	waitFor("選一個")

	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // file picker: dns.yml (the only entry, cursor 0)
	waitFor("dns_forwarders")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // pick the dns_forwarders entry
	waitFor("修改值")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "修改值"
	waitFor("的新值")
	tm.Type("1.1.1.1")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm -> back to the now-dirty editor
	waitFor("1.1.1.1")

	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // dirty editor: esc mirrors "🚪 不存檔離開"'s dirty gate
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
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown}) // top menu -> .vault/ (index 2)
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // vault file picker: "📍 輸入其他 vault 檔路徑" (only real entry besides 返回, cursor 0)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // accept default vault path
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm "create new plaintext vault file?" default yes

	// vault editor (empty): items 0 新增 key, 1 存檔並離開, 2 不存檔離開
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "➕ 新增 key"
	tm.Type("ipa_admin_password")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	tm.Type("s3cr3t")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm value -> back to editor

	// editor items now: 0 ipa_admin_password entry, 1 新增 key, 2 存檔並離開, 3 不存檔離開
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // save -> back to vault file picker

	// file picker items now: 0 <created file>, 1 輸入其他路徑, 2 返回
	for i := 0; i < 2; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // back to top menu

	// top menu items: 0 hosts.yml, 1 group_vars, 2 vault, 3 roster,
	// 4 freeipa-dns manifest, 5 internal-endpoints manifest, 6 monitoring,
	// 7 檢查設定完整性, 8 快速建立最小 workspace, 9 離開
	for i := 0; i < 9; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // quit

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

// TestEditRouter_Teatest_VaultFlow_PickingRosterShapedFileStaysInWizard
// reproduces a real support report: .vault/ipa-identity.yaml (the default
// freeipa_roster_file convention) sits right next to main.yaml in the vault
// picker, and picking it used to set editRouterModel.err — which quits the
// ENTIRE `pilot edit` session (see editRouterModel.Update's `r.err != nil`
// branch), losing any other unsaved work. It must instead bounce back to
// this same picker with an explanatory banner, and the wizard must still be
// fully usable afterward (e.g. opening main.yaml right after).
func TestEditRouter_Teatest_VaultFlow_PickingRosterShapedFileStaysInWizard(t *testing.T) {
	dir := t.TempDir()
	vaultDir := filepath.Join(dir, ".vault")
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		t.Fatal(err)
	}
	roster := "schema_version: 1\nfreeipa:\n  domain: ipa.pilot.internal\nusers: []\n"
	if err := os.WriteFile(filepath.Join(vaultDir, "ipa-identity.yaml"), []byte(roster), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vaultDir, "main.yaml"), []byte("---\nfoo: \"bar\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var router editRouterModel
	pushVaultFilePicker(&router, dir, "")
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	// picker items: 0 ipa-identity.yaml, 1 main.yaml, 2 輸入其他, 3 返回.
	waitFor("ipa-identity.yaml")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // pick ipa-identity.yaml (cursor 0)

	// The banner (roster-specific pointer) and the picker's own title
	// ("still on the picker, not quit") render in the same first frame —
	// check both in one WaitFor, since a second call looking for text
	// already emitted in an already-drained frame would hang.
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
		out := string(b)
		return strings.Contains(out, "roster — FreeIPA") && strings.Contains(out, "選一個")
	}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))

	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // now pick main.yaml — wizard must still work
	waitFor("foo = ")

	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))
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
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // clean editor: esc goes straight back, no confirm
	waitFor("選一個")

	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // file picker: main.yaml (cursor 0)
	waitFor("foo = ")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // pick the foo entry
	waitFor("修改值")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "修改值"
	waitFor("的新值")
	for range "bar" {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyBackspace})
	}
	tm.Type("baz")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm -> back to the now-dirty editor
	waitFor("foo = <已設定>")                       // displayVaultValue masks any real value (edit_tui_vault.go)

	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // dirty editor: esc mirrors "🚪 不存檔離開"'s dirty gate
	waitFor("確定要放棄離開嗎")
	tm.Type("n")           // decline discard -> back to the still-dirty editor
	waitFor("foo = <已設定>") // displayVaultValue masks any real value (edit_tui_vault.go)

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
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> roster path prompt
	waitFor("Roster 檔路徑")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // accept the default (.vault/ipa-identity.yaml matches our fixture)
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
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> Users menu
	waitFor("選一個查看/編輯欄位，或新增一個")
	// menu: 0 "👤 alice", 1 "➕ 新增 User", 2 "↩ 返回".
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "➕ 新增 User"
	waitFor("新 user 的名稱")
	tm.Type("bob")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // valid -> appended
	waitFor("已新增 user bob")

	// duplicate name: blocked by the validator, never written. menu is now
	// 0 "👤 alice", 1 "👤 bob", 2 "➕ 新增 User", 3 "↩ 返回".
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "➕ 新增 User"
	waitFor("新 user 的名稱")
	tm.Type("bob")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor("驗證沒過")

	tm.Send(tea.KeyPressMsg{Code: tea.KeyEsc}) // Users menu -> roster manager
	waitFor("👥 Groups")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})  // "👤 Users" (0) -> "👥 Groups" (1)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> Groups menu
	waitFor("目前沒有任何 group")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "➕ 新增 Group"
	waitFor("分類")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // category: team (cursor 0)
	waitFor("記得帶前綴")
	tm.Type("team-ops")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // valid -> appended
	waitFor("已新增 group team-ops")

	// wrong prefix for the chosen category: blocked by the validator. menu
	// is now 0 "👥 team-ops", 1 "➕ 新增 Group", 2 "↩ 返回".
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "➕ 新增 Group"
	waitFor("分類")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // category: team
	waitFor("記得帶前綴")
	tm.Type("ops-nomatch")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
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

// TestEditRouter_Teatest_RosterSudoFlow creates a command group and then edits
// a rule's direct allow-list through the roster UI. It proves sudo commands
// use the same simulated-validation-before-write path as users and groups.
func TestEditRouter_Teatest_RosterSudoFlow(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	fixture := "schema_version: 1\ngroups:\n  - name: role-ops\n    state: present\n    category: role\nsudo:\n  command_groups: []\n  rules: []\n"
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}

	var router editRouterModel
	pushRosterSudoMenu(&router, dir, path, "")
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	waitFor("Command groups")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // command groups
	waitFor("新增 command group")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor("command group 名稱")
	tm.Type("ops-status")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor("完整 sudo 指令")
	tm.Type("/usr/bin/systemctl status nginx")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor("已新增 command group")

	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	rule := newRosterSudoRule("ops-status-sudo", []string{"role-ops"}, []string{"ops-status"}, nil)
	if got, _ := rule["options"].([]string); len(got) != 0 {
		t.Fatalf("new sudo rule options = %v, want password authentication by default", got)
	}
	if err := inventory.AppendRosterSudoRule(path, rule); err != nil {
		t.Fatal(err)
	}

	var ruleRouter editRouterModel
	pushRosterSudoRuleDetail(&ruleRouter, dir, path, "ops-status-sudo", "")
	ruleTM := teatest.NewTestModel(t, ruleRouter, teatest.WithInitialTermSize(100, 40))
	ruleWaitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, ruleTM.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}
	ruleWaitFor("allow.commands")
	ruleTM.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	ruleTM.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	ruleTM.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	ruleTM.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	ruleWaitFor("額外允許")
	ruleTM.Type("/usr/bin/id")
	ruleTM.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	ruleWaitFor("已更新")
	if err := ruleTM.Quit(); err != nil {
		t.Fatal(err)
	}
	ruleTM.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	stored, found, err := inventory.RosterSudoRule(path, "ops-status-sudo")
	if err != nil || !found {
		t.Fatalf("RosterSudoRule() found=%v err=%v", found, err)
	}
	if got := rosterStringSlice(rosterSubmap(stored, "allow"), "commands"); len(got) != 1 || got[0] != "/usr/bin/id" {
		t.Fatalf("allow.commands = %v, want [/usr/bin/id]", got)
	}
	if violations, err := inventory.ValidateRosterFile(path); err != nil || len(violations) != 0 {
		t.Fatalf("final roster violations: %v err=%v", violations, err)
	}
}

func TestEditRouter_Teatest_RosterSudoRuleCanSetExplicitAllowAll(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	fixture := "schema_version: 1\ngroups:\n  - name: role-ops\n    state: present\n    category: role\nsudo:\n  command_groups: []\n  rules:\n    - name: ops-sudo\n      state: present\n      enabled: true\n      subjects: {users: [], groups: [role-ops]}\n      targets: {hostcat: all, hosts: [], hostgroups: []}\n      allow: {command_groups: [], commands: [/usr/bin/id]}\n      deny: {command_groups: [], commands: []}\n      run_as: {users: [root], groups: []}\n      options: ['!authenticate']\n"
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	var router editRouterModel
	pushRosterSudoRuleDetail(&router, dir, path, "ops-sudo", "")
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool { return strings.Contains(string(b), "allow.command_category") }, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool { return strings.Contains(string(b), "Allow all commands") }, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool { return strings.Contains(string(b), "確認 allow all") }, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	tm.Type("y")
	teatest.WaitFor(t, tm.Output(), func(b []byte) bool { return strings.Contains(string(b), "✅ 已更新") }, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	stored, found, err := inventory.RosterSudoRule(path, "ops-sudo")
	if err != nil || !found {
		t.Fatalf("RosterSudoRule() found=%v err=%v", found, err)
	}
	allow := rosterSubmap(stored, "allow")
	if got := rosterStringOr(allow, "command_category", ""); got != "all" {
		t.Fatalf("allow.command_category = %q, want all", got)
	}
	if len(rosterStringSlice(allow, "commands"))+len(rosterStringSlice(allow, "command_groups")) != 0 {
		t.Fatalf("allow all must clear restricted allow lists: %#v", allow)
	}
}

// TestEditRouter_Teatest_RosterFlow_UserDetailPreviewAndScalarEditRoundTrips
// proves the roster editor's new preview+edit capability (previously
// add-only, see edit_tui_roster.go's package doc comment): opening an
// existing user's detail screen renders every known field with its current
// value/placeholder, and editing one plain scalar field persists to disk.
func TestEditRouter_Teatest_RosterFlow_UserDetailPreviewAndScalarEditRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	fixture := "schema_version: 1\nfreeipa:\n  domain: ipa.pilot.internal\nusers:\n  - name: alice\n    state: present\n"
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	var router editRouterModel
	pushRosterUserDetail(&router, dir, path, "alice", "")
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	// full field-detail preview: every known field rendered, unset ones as
	// a placeholder rather than silently omitted.
	waitFor("email：(未設定)")

	// items: 0 name,1 state,2 first,3 last,4 display_name,5 email,...
	for i := 0; i < 5; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "email" -> straight to text input
	waitFor("email")
	tm.Type("alice@example.internal")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm -> re-validate + write -> back to detail
	waitFor("alice@example.internal")

	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	fields, found, err := inventory.RosterUser(path, "alice")
	if err != nil {
		t.Fatalf("RosterUser() error = %v", err)
	}
	if !found || fields["email"] != "alice@example.internal" {
		t.Fatalf("RosterUser() fields = %v, want email persisted", fields)
	}
}

// TestEditRouter_Teatest_RosterFlow_GroupMembershipChecklistEditRoundTrips
// proves membership.users edits via the checklist (not an open-ended list
// editor — see pushRosterGroupMembershipUsers' doc comment on why) persist
// correctly.
func TestEditRouter_Teatest_RosterFlow_GroupMembershipChecklistEditRoundTrips(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	fixture := "schema_version: 1\nfreeipa:\n  domain: ipa.pilot.internal\nusers:\n  - name: alice\n    state: present\ngroups:\n  - name: team-ops\n    state: present\n    category: team\n"
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	var router editRouterModel
	pushRosterGroupDetail(&router, dir, path, "team-ops", "")
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	waitFor("membership.users（共 0 位）")

	// items: 0 name,1 state,2 category,3 type,4 description,5 gid,
	// 6 membership.authoritative,7 membership.users,8 membership.groups,9 返回.
	for i := 0; i < 7; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // membership.users -> checklist (only alice, unchecked)
	waitFor("membership.users")
	tm.Send(tea.KeyPressMsg{Code: tea.KeySpace}) // check alice (cursor 0)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm -> re-validate + write -> back to detail
	waitFor("membership.users（共 1 位）")

	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	fields, found, err := inventory.RosterGroup(path, "team-ops")
	if err != nil {
		t.Fatalf("RosterGroup() error = %v", err)
	}
	if !found {
		t.Fatalf("expected team-ops to still exist")
	}
	mem, _ := fields["membership"].(map[string]any)
	users, _ := mem["users"].([]any)
	if len(users) != 1 || users[0] != "alice" {
		t.Fatalf("membership.users = %v, want [alice]", users)
	}
}

// TestEditRouter_Teatest_RosterFlow_DisablingUserSynchronizesEnabled proves
// that choosing state:disabled also writes enabled:false, rather than
// leaving the roster in the invalid state:disabled + enabled:true shape.
func TestEditRouter_Teatest_RosterFlow_DisablingUserSynchronizesEnabled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "roster.yaml")
	fixture := "schema_version: 1\nfreeipa:\n  domain: ipa.pilot.internal\nusers:\n  - name: alice\n    state: present\n"
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	var router editRouterModel
	pushRosterUserDetail(&router, dir, path, "alice", "")
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	waitFor("enabled：true")

	// items: 0 name,1 state,...,10 enabled. Set enabled=true first — no
	// violation on its own (checkUsers only rejects state:disabled +
	// enabled:true together).
	for i := 0; i < 10; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // "enabled" -> ["true","false"]
	waitFor("true")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // pick "true" (cursor 0) -> write -> fresh detail (cursor reset)
	waitFor("enabled：true")

	// Now flip state to disabled — the state editor must synchronize enabled.
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown}) // "state" is index 1
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})
	waitFor("disabled")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})  // choices ["present","disabled"]; pick "disabled"
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // synchronize enabled:false and write
	waitFor("state：disabled")

	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	fields, found, err := inventory.RosterUser(path, "alice")
	if err != nil {
		t.Fatalf("RosterUser() error = %v", err)
	}
	if !found {
		t.Fatalf("expected alice to still exist")
	}
	if fields["state"] != "disabled" {
		t.Fatalf("state = %v, want disabled", fields["state"])
	}
	if fields["enabled"] != false {
		t.Fatalf("enabled = %v, want false after selecting disabled", fields["enabled"])
	}
}

// TestEditRouter_Teatest_RosterFlow_MissingRosterOffersToCreateSkeleton
// reproduces a real support report: pointing pushRosterManager at a roster
// path that doesn't exist yet must not kill the whole `pilot edit` session
// (r.err would do exactly that, see editRouterModel.Update's `r.err != nil`
// branch) — it should offer to auto-generate the minimal schema_version/
// freeipa.admin skeleton instead, then land in the normal Users/Groups
// manager on that new file.
func TestEditRouter_Teatest_RosterFlow_MissingRosterOffersToCreateSkeleton(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".vault", "ipa-identity.yaml")

	var router editRouterModel
	pushRosterManager(&router, dir, path, "")
	// Wider than this file's usual 100 columns: the confirm/prompt text
	// below embeds path in full, and t.TempDir()'s directory name (which
	// includes this whole test function name) alone can approach 100
	// columns, wrapping mid-path before the Chinese question text even
	// starts.
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(220, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	waitFor("要建立最小 roster 骨架嗎")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm, default yes

	waitFor("FreeIPA admin password")
	tm.Type("s3cr3tpass")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter})

	waitFor("👤 Users") // landed on the normal roster manager

	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	violations, err := inventory.ValidateRosterFile(path)
	if err != nil {
		t.Fatalf("ValidateRosterFile() error = %v", err)
	}
	if len(violations) != 0 {
		t.Fatalf("expected the generated skeleton to validate clean, got %v", violations)
	}
	// A new schema-v2 roster deliberately omits freeipa.domain — that field
	// is migration-compatibility-only for old v1 rosters; a new roster's
	// domain comes from group_vars/freeipa.yml instead (see
	// minimalRosterBase's doc comment).
	domain, err := inventory.RosterDomain(path)
	if err != nil {
		t.Fatalf("RosterDomain() error = %v", err)
	}
	if domain != "" {
		t.Fatalf("RosterDomain() = %q, want empty for a freshly-generated schema-v2 roster", domain)
	}
}

// TestEditRouter_Teatest_RosterFlow_CreateSkeletonReusesExistingAdminPassword
// is the roster-manager analogue of the NFS-bootstrap reuse test: creating
// a missing roster skeleton must reuse .vault/main.yaml's existing
// ipa_admin_password instead of asking the operator to type it again.
func TestEditRouter_Teatest_RosterFlow_CreateSkeletonReusesExistingAdminPassword(t *testing.T) {
	dir := t.TempDir()
	vaultDir := filepath.Join(dir, ".vault")
	if err := os.MkdirAll(vaultDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(vaultDir, "main.yaml"), []byte("ipa_admin_password: \"existing-secret\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(vaultDir, "ipa-identity.yaml")

	var router editRouterModel
	pushRosterManager(&router, dir, path, "")
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(220, 40))
	waitFor := func(want string) {
		t.Helper()
		teatest.WaitFor(t, tm.Output(), func(b []byte) bool {
			return strings.Contains(string(b), want)
		}, teatest.WithDuration(2*time.Second), teatest.WithCheckInterval(10*time.Millisecond))
	}

	waitFor("要建立最小 roster 骨架嗎")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // confirm, default yes -> straight to skeleton creation, no password prompt
	waitFor("沿用 .vault/main.yaml 現有的 ipa_admin_password")

	if err := tm.Quit(); err != nil {
		t.Fatal(err)
	}
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !strings.Contains(string(data), "existing-secret") {
		t.Fatalf("expected the reused password in the generated roster:\n%s", data)
	}
}
