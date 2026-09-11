// L3 teatest integration test driving editRouterModel (production code)
// through the SNMP 認證(vault) flow: top menu -> monitoring manager -> SNMP
// 認證 -> pick a new vault file path -> add a v3 credentialRef -> save ->
// quit, then verifies the actual vault file written to disk via
// monitoring.LoadSNMPCredentialDoc — same convention as
// edit_tui_monitoring_test.go's MonitoringFlow test.
package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/kjelly/pilot/internal/monitoring"
)

func TestEditRouter_Teatest_SNMPCredentialsFlow_AddV3RefAndSave(t *testing.T) {
	dir := t.TempDir()
	router := newEditRouterModel(dir)
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))

	// top menu: 0 hosts.yml, 1 group_vars, 2 vault, 3 roster,
	// 4 freeipa-dns manifest, 5 internal-endpoints manifest, 6 monitoring,
	// 7 Alertmanager 通知, 8 檢查設定完整性, 9 快速建立最小 workspace, 10 離開
	for i := 0; i < 6; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> monitoring manager

	// manager: 0 Targets, 1 Profiles, 2 Validate, 3 SNMP Catalog,
	// 4 SNMP baseline, 5 SNMP 認證, 6 Back
	for i := 0; i < 5; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> SNMP credential file picker (no .vault/ yet)

	// file picker (no existing files): 0 輸入其他 vault 檔路徑, 1 返回
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> path prompt (default .vault/main.yaml)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // accept default -> credentials editor (empty)

	// editor (empty): 0 新增 credentialRef, 1 存檔並離開, 2 不存檔離開
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> add ref id prompt
	tm.Type("core-switch-v3")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> kind select

	// kind select: 0 SNMPv3, 1 SNMPv1/v2c
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // pick SNMPv3 -> username prompt
	tm.Type("labuser")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> authPassword prompt
	tm.Type("authpw123")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> privPassword prompt
	tm.Type("privpw123")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // saved to memory -> back to editor list

	// editor: 0 core-switch-v3, 1 新增 credentialRef, 2 存檔並離開, 3 不存檔離開
	for i := 0; i < 2; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> write to disk -> back to file picker

	// file picker (now: .vault/main.yaml, 輸入其他路徑, 返回)
	for i := 0; i < 2; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> back to monitoring manager

	// manager: 0 Targets, 1 Profiles, 2 Validate, 3 SNMP Catalog,
	// 4 SNMP baseline, 5 SNMP 認證, 6 Back
	for i := 0; i < 6; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> back to top menu

	for i := 0; i < 10; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // quit

	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	path := filepath.Join(dir, ".vault", "main.yaml")
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}
	doc, err := monitoring.LoadSNMPCredentialDoc(path)
	if err != nil {
		t.Fatalf("LoadSNMPCredentialDoc: %v", err)
	}
	fields, ok := doc.Get("core-switch-v3")
	if !ok {
		t.Fatalf("expected credentialRef core-switch-v3, refs=%v", doc.Refs())
	}
	if fields["username"] != "labuser" || fields["authPassword"] != "authpw123" || fields["privPassword"] != "privpw123" {
		t.Fatalf("unexpected fields: %+v", fields)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Fatalf("expected vault file to not be group/other readable, mode=%v", perm)
	}
}

// TestEditRouter_Teatest_SNMPCredentialsFlow_PreservesOtherVaultKeys guards
// against this narrow editor clobbering unrelated scalar secrets that
// already live in the same vault file (see
// monitoring.SNMPCredentialDoc.OtherTopLevelKeys).
func TestEditRouter_Teatest_SNMPCredentialsFlow_PreservesOtherVaultKeys(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".vault"), 0o700); err != nil {
		t.Fatal(err)
	}
	seedPath := filepath.Join(dir, ".vault", "main.yaml")
	if err := os.WriteFile(seedPath, []byte("---\nfreeipa_admin_password: \"CHANGE-ME\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	router := newEditRouterModel(dir)
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))

	for i := 0; i < 6; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> monitoring manager
	for i := 0; i < 5; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> file picker (main.yaml, other, back)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // pick main.yaml -> credentials editor (empty)

	// editor (empty): 0 新增 credentialRef, 1 存檔並離開, 2 不存檔離開
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> add ref id prompt
	tm.Type("lab-switch-v2c")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> kind select
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})  // move to SNMPv1/v2c
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // pick v1/v2c -> community prompt
	tm.Type("public")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // saved to memory -> back to editor list

	for i := 0; i < 2; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> write to disk -> back to file picker
	for i := 0; i < 2; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> back to monitoring manager
	for i := 0; i < 6; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> back to top menu
	for i := 0; i < 10; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // quit
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	data, err := os.ReadFile(seedPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "freeipa_admin_password") {
		t.Fatalf("unrelated vault key was lost:\n%s", data)
	}
	doc, err := monitoring.LoadSNMPCredentialDoc(seedPath)
	if err != nil {
		t.Fatalf("LoadSNMPCredentialDoc: %v", err)
	}
	fields, ok := doc.Get("lab-switch-v2c")
	if !ok || fields["community"] != "public" {
		t.Fatalf("unexpected fields: %+v", fields)
	}
}
