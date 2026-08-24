package cmd

import (
	"testing"

	"github.com/kjelly/pilot/internal/monitoring"
)

// TestEditAutomationDriverMonitoringFlow drives every monitoring action
// (spec.md §52) through the real TUI (edit_automation_driver_monitoring.go
// replays scripted keystrokes against editRouterModel, not a mock execution
// path — same convention as every other feature's driver test), then
// asserts on the resulting monitoring/targets.yml + scrape-profiles.yml.
func TestEditAutomationDriverMonitoringFlow(t *testing.T) {
	dir := t.TempDir()

	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_monitoring_profile", Name: "storage-exporter", JobName: "storage"},
			{Action: "create_monitoring_target", Name: "nas01", Address: "10.0.0.20:9100", Profile: "storage-exporter"},
			{Action: "set_monitoring_target_address", Name: "nas01", Address: "10.0.0.21:9100"},
			{Action: "set_monitoring_target_site", Name: "nas01", Site: "taipei"},
			{Action: "set_monitoring_target_label", Name: "nas01", Key: "owner", Value: "storage"},
			{Action: "set_monitoring_target_label", Name: "nas01", Key: "owner", Value: "infra"}, // update the same key
			{Action: "disable_monitoring_target", Name: "nas01"},
			{Action: "enable_monitoring_target", Name: "nas01"},
			{Action: "set_monitoring_profile_scheme", Name: "storage-exporter", Scheme: "https"},
			{Action: "set_monitoring_profile_metrics_path", Name: "storage-exporter", MetricsPath: "/custom-metrics"},
			{Action: "set_monitoring_profile_scrape_interval", Name: "storage-exporter", ScrapeInterval: "30s"},
			{Action: "set_monitoring_profile_auth_ref", Name: "storage-exporter", AuthRef: "storage-auth"},
			{Action: "set_monitoring_profile_tls", Name: "storage-exporter", TLSServerName: "exporter.pilot.internal", TLSInsecureSkipVerify: "true"},
		},
	}

	var events []automationTraceEvent
	r := newEditRouterModel(dir)
	d := automationDriver{trace: func(event automationTraceEvent) { events = append(events, event) }}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	for _, event := range events {
		if event.Result != "ok" {
			t.Fatalf("bad trace event: %+v", event)
		}
	}

	pf, err := monitoring.LoadProfiles(monitoringProfilesPath(dir))
	if err != nil {
		t.Fatalf("LoadProfiles: %v", err)
	}
	p, ok := pf.Profiles["storage-exporter"]
	if !ok {
		t.Fatal("expected profile storage-exporter to exist")
	}
	if p.Scheme != "https" || p.MetricsPath != "/custom-metrics" || p.ScrapeInterval != "30s" || p.AuthRef != "storage-auth" {
		t.Fatalf("unexpected profile fields: %+v", p)
	}
	if p.TLS == nil || p.TLS.ServerName != "exporter.pilot.internal" || !p.TLS.InsecureSkipVerify {
		t.Fatalf("unexpected profile TLS: %+v", p.TLS)
	}

	tf, err := monitoring.LoadTargets(monitoringTargetsPath(dir))
	if err != nil {
		t.Fatalf("LoadTargets: %v", err)
	}
	if len(tf.Targets) != 1 {
		t.Fatalf("expected exactly one target, got %+v", tf.Targets)
	}
	target := tf.Targets[0]
	if target.Name != "nas01" || target.Address != "10.0.0.21:9100" || target.Site != "taipei" {
		t.Fatalf("unexpected target: %+v", target)
	}
	if !target.IsEnabled() {
		t.Fatalf("expected target to be enabled after enable_monitoring_target, got %+v", target)
	}
	if target.Labels["owner"] != "infra" {
		t.Fatalf("expected label owner=infra (updated, not appended), got %+v", target.Labels)
	}

	// Now delete the target, then the now-unreferenced profile.
	cleanup := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "delete_monitoring_target", Name: "nas01"},
			{Action: "delete_monitoring_profile", Name: "storage-exporter"},
		},
	}
	events = nil
	if err := d.run(&r, cleanup); err != nil {
		t.Fatalf("driver.run() cleanup error = %v", err)
	}
	for _, event := range events {
		if event.Result != "ok" {
			t.Fatalf("bad trace event during cleanup: %+v", event)
		}
	}

	tf, err = monitoring.LoadTargets(monitoringTargetsPath(dir))
	if err != nil {
		t.Fatalf("LoadTargets after delete: %v", err)
	}
	if len(tf.Targets) != 0 {
		t.Fatalf("expected no targets after delete_monitoring_target, got %+v", tf.Targets)
	}
	pf, err = monitoring.LoadProfiles(monitoringProfilesPath(dir))
	if err != nil {
		t.Fatalf("LoadProfiles after delete: %v", err)
	}
	if len(pf.Profiles) != 0 {
		t.Fatalf("expected no profiles after delete_monitoring_profile, got %+v", pf.Profiles)
	}
}

// TestEditAutomationDriverMonitoring_DeleteProfileInUseRejected exercises
// the driver path of spec.md §50's "no cascade delete" rule — the
// confirmation prompt never even appears because the TUI refuses to offer
// it (pushMonitoringProfileDeleteConfirm), so the action must fail cleanly
// rather than silently deleting a still-referenced profile.
func TestEditAutomationDriverMonitoring_DeleteProfileInUseRejected(t *testing.T) {
	dir := t.TempDir()
	scenario := editScenario{
		Version: 1,
		Steps: []editAction{
			{Action: "create_monitoring_profile", Name: "p", JobName: "j"},
			{Action: "create_monitoring_target", Name: "t", Address: "10.0.0.1:9100", Profile: "p"},
		},
	}
	r := newEditRouterModel(dir)
	d := automationDriver{trace: func(automationTraceEvent) {}}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() setup error = %v", err)
	}

	deleteScenario := editScenario{Version: 1, Steps: []editAction{{Action: "delete_monitoring_profile", Name: "p"}}}
	if err := d.run(&r, deleteScenario); err == nil {
		t.Fatal("expected delete_monitoring_profile to fail while target \"t\" still references it")
	}

	pf, err := monitoring.LoadProfiles(monitoringProfilesPath(dir))
	if err != nil {
		t.Fatalf("LoadProfiles: %v", err)
	}
	if _, ok := pf.Profiles["p"]; !ok {
		t.Fatal("profile \"p\" must still exist after the rejected delete")
	}
}
