// L3 teatest integration test driving editRouterModel (production code)
// through the full Monitoring flow: top menu -> add a scrape profile -> add
// a target referencing it -> quit, then verifies the actual files written to
// disk — same convention as edit_tui_flows_test.go's other *Flow tests.
package cmd

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/exp/teatest/v2"

	"github.com/kjelly/pilot/internal/monitoring"
)

func TestEditRouter_Teatest_MonitoringFlow_AddProfileAddTargetAndSave(t *testing.T) {
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

	// manager: 0 Targets, 1 Profiles, 2 Validate, 3 Back
	tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> profiles list (empty)

	// profile list (empty): 0 新增 profile, 1 返回
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> add profile name prompt
	tm.Type("storage-exporter")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> add profile jobName prompt
	tm.Type("storage")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // saved -> profile detail screen

	// profile detail: 0 jobname,1 scheme,2 metricspath,3 scrapeinterval,
	// 4 scrapetimeout,5 authref,6 tls,7 delete,8 back
	for i := 0; i < 8; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> profiles list (now: name,add,back)

	// profile list: 0 storage-exporter, 1 新增 profile, 2 返回
	for i := 0; i < 2; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> back to manager

	// manager: 0 Targets, 1 Profiles, 2 Validate, 3 Back
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> targets list (empty)

	// target list (empty): 0 新增 target, 1 返回
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> add target name prompt
	tm.Type("nas01")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> add target address prompt
	tm.Type("10.0.0.20:9100")
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> add target profile select (only "storage-exporter" + cancel)
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // pick "storage-exporter" (cursor 0) -> saved, target detail screen

	// target detail: 0 address,1 profile,2 site,3 enabled,4 labels,5 test,6 delete,7 back
	for i := 0; i < 7; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> targets list (now: name,add,back)

	// target list: 0 nas01, 1 新增 target, 2 返回
	for i := 0; i < 2; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> back to manager

	// manager: 0 Targets, 1 Profiles, 2 Validate, 3 Back
	for i := 0; i < 3; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> back to top menu

	// top menu: quit (index 9, see the comment at the top of this test)
	for i := 0; i < 9; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // quit

	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	tf, err := monitoring.LoadTargets(filepath.Join(dir, "monitoring", "targets.yml"))
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	if len(tf.Targets) != 1 || tf.Targets[0].Name != "nas01" || tf.Targets[0].Address != "10.0.0.20:9100" || tf.Targets[0].Profile != "storage-exporter" {
		t.Fatalf("unexpected targets.yml content: %+v", tf.Targets)
	}
	if !tf.Targets[0].IsEnabled() {
		t.Fatalf("expected the new target to default to enabled")
	}

	pf, err := monitoring.LoadProfiles(filepath.Join(dir, "monitoring", "scrape-profiles.yml"))
	if err != nil {
		t.Fatalf("LoadProfiles: %v", err)
	}
	p, ok := pf.Profiles["storage-exporter"]
	if !ok || p.JobName != "storage" {
		t.Fatalf("unexpected scrape-profiles.yml content: %+v", pf.Profiles)
	}
}

// TestEditRouter_Teatest_MonitoringFlow_EmptyWorkspaceHasNoMonitoringFiles
// guards spec.md §64/AC12: opening the Monitoring manager and immediately
// leaving must not create monitoring/ at all in a workspace that never
// asked for it.
func TestEditRouter_Teatest_MonitoringFlow_EmptyWorkspaceHasNoMonitoringFiles(t *testing.T) {
	dir := t.TempDir()
	router := newEditRouterModel(dir)
	tm := teatest.NewTestModel(t, router, teatest.WithInitialTermSize(100, 40))

	for i := 0; i < 6; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> monitoring manager

	// manager: 0 Targets, 1 Profiles, 2 Validate, 3 Back
	for i := 0; i < 3; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // -> back to top menu

	for i := 0; i < 9; i++ {
		tm.Send(tea.KeyPressMsg{Code: tea.KeyDown})
	}
	tm.Send(tea.KeyPressMsg{Code: tea.KeyEnter}) // quit
	tm.WaitFinished(t, teatest.WithFinalTimeout(3*time.Second))

	if _, err := os.Stat(filepath.Join(dir, "monitoring")); !os.IsNotExist(err) {
		t.Fatalf("expected no monitoring/ directory to be created, stat err=%v", err)
	}
}
