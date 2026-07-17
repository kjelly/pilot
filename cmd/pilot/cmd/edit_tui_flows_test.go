// L3 teatest integration tests driving editRouterModel (the real
// production code, not a reimplementation) through full multi-screen
// wizard flows, verifying the actual files written to disk at the
// end — the closest thing to the old promptui version's missing
// flow-level test coverage (edit_test.go only ever unit-tested pure
// data helpers; see edit_tui.go's package doc comment).
package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/exp/teatest"

	"github.com/anomalyco/pilot/internal/groupvars"
	"github.com/anomalyco/pilot/internal/inventory"
	"github.com/anomalyco/pilot/internal/vaultfile"
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

	// roles menu items: 0 checklist, 1 preset, 2 copy, 3 done
	for i := 0; i < 3; i++ {
		tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // "✅ 完成" -> back to host menu

	// host menu again (cursor reset to 0); navigate to "↩ 返回主機清單" (index 7)
	for i := 0; i < 7; i++ {
		tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	}
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // back to host list

	// host list items now: 0 新增主機, 1 host summary, 2 存檔並離開, 3 不存檔離開
	tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	tm.Send(tea.KeyMsg{Type: tea.KeyDown})
	tm.Send(tea.KeyMsg{Type: tea.KeyEnter}) // save and return to top menu

	// top menu items: 0 hosts.yml, 1 group_vars, 2 vault, 3 離開
	for i := 0; i < 3; i++ {
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

	tm.Send(tea.KeyMsg{Type: tea.KeyDown})  // top menu -> group_vars/ (index 1)
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

	for i := 0; i < 3; i++ {
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

	for i := 0; i < 3; i++ {
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
