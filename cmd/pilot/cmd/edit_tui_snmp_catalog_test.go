// L3 teatest integration test driving editRouterModel (production code)
// through the SNMP Catalog flow: top menu -> monitoring manager -> SNMP
// Catalog -> add a module, add a v3 auth profile -> quit, then verifies the
// actual monitoring/snmp/catalog.yml written to disk — same convention as
// edit_tui_monitoring_test.go's MonitoringFlow test.
package cmd

import (
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/kjelly/pilot/internal/monitoring"
)

func TestEditRouter_Teatest_SNMPCatalogFlow_AddModuleAndAuthProfile(t *testing.T) {
	dir := t.TempDir()
	router := newEditRouterModel(dir)
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))

	// top menu: 0 hosts.yml, 1 group_vars, 2 vault, 3 roster,
	// 4 freeipa-dns manifest, 5 internal-endpoints manifest, 6 monitoring,
	// 7 檢查設定完整性, 8 快速建立最小 workspace, 9 離開
	for i := 0; i < 6; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> monitoring manager

	// manager: 0 Targets, 1 Profiles, 2 Validate, 3 SNMP Catalog,
	// 4 SNMP 認證, 5 Back
	for i := 0; i < 3; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> SNMP catalog menu

	// catalog menu: 0 Modules, 1 Auth Profiles, 2 Back
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> modules list (empty)

	// modules list (empty): 0 新增 module, 1 返回
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> add module id prompt
	tm.Type("if_mib")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> add module file prompt
	tm.Type("generated/if_mib.yml")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // saved -> modules list (now: if_mib, add, back)

	// modules list: 0 if_mib, 1 新增 module, 2 返回
	for i := 0; i < 2; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> back to catalog menu

	// catalog menu: 0 Modules, 1 Auth Profiles, 2 Back
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> auth profiles list (empty)

	// auth profiles list (empty): 0 新增 auth profile, 1 返回
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> add id prompt
	tm.Type("core-switch-v3")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> version select

	// version select: 0 SNMPv3, 1 SNMPv2c, 2 SNMPv1
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // pick SNMPv3 (cursor 0) -> securityLevel select

	// securityLevel select: 0 noAuthNoPriv, 1 authNoPriv, 2 authPriv
	for i := 0; i < 2; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // pick authPriv -> authProtocol prompt (default SHA-256)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // accept default -> privProtocol prompt (default AES)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // accept default -> credentialRef prompt
	tm.Type("core-switch-v3")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // saved -> auth profiles list

	// auth profiles list: 0 core-switch-v3, 1 新增 auth profile, 2 返回
	for i := 0; i < 2; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> back to catalog menu

	// catalog menu: 0 Modules, 1 Auth Profiles, 2 Back
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

	// top menu: quit (index 9)
	for i := 0; i < 9; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // quit

	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	catalog, err := monitoring.LoadSNMPCatalog(monitoringSNMPCatalogPath(dir))
	if err != nil {
		t.Fatalf("LoadSNMPCatalog: %v", err)
	}
	if err := catalog.Validate(); err != nil {
		t.Fatalf("saved catalog fails Validate: %v", err)
	}
	module, ok := catalog.Modules["if_mib"]
	if !ok || module.File != "generated/if_mib.yml" {
		t.Fatalf("unexpected modules: %+v", catalog.Modules)
	}
	auth, ok := catalog.AuthProfiles["core-switch-v3"]
	if !ok || auth.Version != 3 || auth.SecurityLevel != "authPriv" ||
		auth.AuthProtocol != "SHA-256" || auth.PrivProtocol != "AES" || auth.CredentialRef != "core-switch-v3" {
		t.Fatalf("unexpected auth profile: %+v", auth)
	}
}

// TestEditRouter_Teatest_SNMPCatalogFlow_DeleteModule guards the delete
// path end to end: add a module then immediately delete it, and confirm no
// trace of it survives on disk.
func TestEditRouter_Teatest_SNMPCatalogFlow_DeleteModule(t *testing.T) {
	dir := t.TempDir()
	router := newEditRouterModel(dir)
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))

	for i := 0; i < 6; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> monitoring manager
	for i := 0; i < 3; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> SNMP catalog menu
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> modules list (empty)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> add module id prompt
	tm.Type("if_mib")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> add module file prompt
	tm.Type("generated/if_mib.yml")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // saved -> modules list (if_mib, add, back)

	// modules list: 0 if_mib, 1 新增 module, 2 返回
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // pick if_mib -> module detail

	// module detail: 0 修改檔案路徑, 1 刪除, 2 返回
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> delete confirm
	tm.Type("y")                                 // confirm delete -> modules list (empty again)

	// modules list (empty): 0 新增 module, 1 返回
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> back to catalog menu
	for i := 0; i < 2; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> back to monitoring manager
	for i := 0; i < 6; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> back to top menu
	for i := 0; i < 9; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // quit

	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	catalog, err := monitoring.LoadSNMPCatalog(monitoringSNMPCatalogPath(dir))
	if err != nil {
		t.Fatalf("LoadSNMPCatalog: %v", err)
	}
	if len(catalog.Modules) != 0 {
		t.Fatalf("expected module to be deleted, got: %+v", catalog.Modules)
	}
}
