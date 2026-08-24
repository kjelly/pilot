package cmd

import (
	"context"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/kjelly/pilot/internal/monitoring"
)

func TestInspectHandler_MonitoringIncludedOnlyWhenRequested(t *testing.T) {
	dir := t.TempDir()
	insecure := true
	if err := monitoring.SaveProfiles(monitoringProfilesPath(dir), monitoring.ProfileFile{
		Profiles: map[string]monitoring.Profile{
			"storage-exporter": {JobName: "storage", Scheme: "https", TLS: &monitoring.TLSConfig{InsecureSkipVerify: insecure}},
		},
	}); err != nil {
		t.Fatalf("SaveProfiles: %v", err)
	}
	if err := monitoring.SaveTargets(monitoringTargetsPath(dir), monitoring.TargetFile{
		Targets: []monitoring.Target{{Name: "nas01", Address: "10.0.0.20:9100", Profile: "storage-exporter", Site: "taipei"}},
	}); err != nil {
		t.Fatalf("SaveTargets: %v", err)
	}

	handler := inspectHandler(editMCPToolsOptions{Dir: dir})

	_, out, err := handler(context.Background(), &mcp.CallToolRequest{}, inspectInput{IncludeMonitoring: true})
	if err != nil {
		t.Fatalf("inspectHandler() error = %v", err)
	}
	if len(out.MonitoringTargets) != 1 || out.MonitoringTargets[0].Name != "nas01" || out.MonitoringTargets[0].Address != "10.0.0.20:9100" {
		t.Fatalf("MonitoringTargets = %+v, want one nas01 entry", out.MonitoringTargets)
	}
	if !out.MonitoringTargets[0].Enabled {
		t.Fatalf("expected the target to report enabled=true by default: %+v", out.MonitoringTargets[0])
	}
	if len(out.MonitoringProfiles) != 1 || out.MonitoringProfiles[0].JobName != "storage" || out.MonitoringProfiles[0].TLS == nil || !out.MonitoringProfiles[0].TLS.InsecureSkipVerify {
		t.Fatalf("MonitoringProfiles = %+v, want one storage-exporter entry with TLS.InsecureSkipVerify=true", out.MonitoringProfiles)
	}

	_, out2, err := handler(context.Background(), &mcp.CallToolRequest{}, inspectInput{IncludeMonitoring: false})
	if err != nil {
		t.Fatalf("inspectHandler() (excluded) error = %v", err)
	}
	if out2.MonitoringTargets != nil || out2.MonitoringProfiles != nil {
		t.Fatalf("expected monitoring fields omitted when not requested, got targets=%+v profiles=%+v", out2.MonitoringTargets, out2.MonitoringProfiles)
	}
}
