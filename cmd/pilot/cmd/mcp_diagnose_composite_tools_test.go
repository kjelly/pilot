package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// writeDiagnoseMultiGroupFixtureInventory writes web1 into `all.hosts`
// plus one singleton host per named group — the shape
// pilot_diagnose_host_health/component/network_path need (a target host
// plus the central thanos-query/detection-engine/alertmanager roles).
func writeDiagnoseMultiGroupFixtureInventory(t *testing.T, groups map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	var b strings.Builder
	b.WriteString("all:\n  hosts:\n    web1: {ansible_connection: local, ansible_host: 127.0.0.1}\n")
	for _, host := range groups {
		b.WriteString("    " + host + ": {ansible_connection: local, ansible_host: 127.0.0.1}\n")
	}
	if len(groups) > 0 {
		b.WriteString("  children:\n")
		for group, host := range groups {
			b.WriteString("    " + group + ":\n      hosts:\n        " + host + ": {}\n")
		}
	}
	path := filepath.Join(dir, "inventory.yml")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// ---- pilot_diagnose_host_health -----------------------------------------

func TestDiagnoseHostHealthHandler_UnknownHostRejectedBeforeAnyCall(t *testing.T) {
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseHostHealthHandler(baseDiagnoseOpts(t, writeDiagnoseFixtureInventory(t), fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseHostHealthInput{Host: "nope"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil {
		t.Fatal("result = nil, want a structured tool error")
	}
}

func TestDiagnoseHostHealthHandler_InvalidLookbackRejectedBeforeAnyCall(t *testing.T) {
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseHostHealthHandler(baseDiagnoseOpts(t, writeDiagnoseFixtureInventory(t), fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseHostHealthInput{Host: "web1", Lookback: "not-a-duration"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil {
		t.Fatal("result = nil, want a structured tool error")
	}
}

func TestDiagnoseHostHealthHandler_SuccessWithoutThanosOrDetectionGroups(t *testing.T) {
	requireRealAnsible(t)
	inv := writeDiagnoseFixtureInventory(t)
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		"cat /proc/uptime":  func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "1000.0 500.0"), 0, nil },
		"cat /proc/loadavg": func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "0.1 0.2 0.3 1/1 1"), 0, nil },
		"cat /proc/meminfo": func() (string, int, error) {
			return diagnoseOKDoc(t, "web1", 0, "MemTotal: 1000 kB\nMemAvailable: 500 kB"), 0, nil
		},
		"df -P -T -x tmpfs -x devtmpfs -x squashfs 2>/dev/null; echo ---INODES---; df -Pi -T -x tmpfs -x devtmpfs -x squashfs 2>/dev/null": func() (string, int, error) {
			return diagnoseOKDoc(t, "web1", 0, "F T B U A C M\n/dev/sda1 ext4 1 1 1 10% /\n---INODES---\nF T I IU IF IU% M\n/dev/sda1 ext4 1 1 1 5% /"), 0, nil
		},
		"systemctl list-units --state=failed --no-legend --plain --no-pager": func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, ""), 0, nil },
		"timedatectl show -p NTPSynchronized --value":                        func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "yes"), 0, nil },
		"ip -o link show":                                           func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "1: lo: <LOOPBACK,UP>"), 0, nil },
		"systemctl is-active node_exporter":                         func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "active"), 0, nil },
		"journalctl -k -p err --no-pager -n 20 2>/dev/null || true": func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, ""), 0, nil },
	}}
	handler := diagnoseHostHealthHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseHostHealthInput{Host: "web1"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil (success)", result)
	}
	if out.Verdict != "healthy" {
		t.Fatalf("verdict = %q, want healthy; out=%+v", out.Verdict, out)
	}
	if out.ThanosNote == "" {
		t.Error("ThanosNote should explain thanos-query group is missing")
	}
	if out.DetectionNote == "" {
		t.Error("DetectionNote should explain detection-engine group is missing")
	}
	if out.AuditDirectory == "" {
		t.Fatal("AuditDirectory is empty")
	}
}

// ---- pilot_diagnose_component ---------------------------------------------

func TestDiagnoseComponentHandler_UnknownComponentRejected(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseComponentHandler(baseDiagnoseOpts(t, writeDiagnoseFixtureInventory(t), fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseComponentInput{Host: "web1", Component: "not-a-real-component"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil {
		t.Fatal("result = nil, want a structured tool error")
	}
}

func TestDiagnoseComponentHandler_ComponentWithoutDiagnosticsRejected(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseComponentHandler(baseDiagnoseOpts(t, writeDiagnoseFixtureInventory(t), fake.run))
	// "docker" itself has no diagnostics block configured.
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseComponentInput{Host: "web1", Component: "docker"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil {
		t.Fatal("result = nil, want a structured tool error naming the missing diagnostics block")
	}
}

func TestDiagnoseComponentHandler_AlertmanagerSuccessBuildsOutput(t *testing.T) {
	requireRealAnsible(t)
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	inv := writeDiagnoseFixtureInventory(t)
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		"docker inspect -f '{{.State.Status}}' 'pilot-alertmanager' 2>/dev/null || echo absent": func() (string, int, error) {
			return diagnoseOKDoc(t, "web1", 0, "running"), 0, nil
		},
		"curl -sS -G http://127.0.0.1:9093/-/ready -w '\\nHTTP_STATUS:%{http_code}'": func() (string, int, error) {
			return diagnoseOKDoc(t, "web1", 0, "\nHTTP_STATUS:200"), 0, nil
		},
		"docker logs --tail 30 'pilot-alertmanager' 2>&1": func() (string, int, error) {
			return diagnoseOKDoc(t, "web1", 0, ""), 0, nil
		},
	}}
	handler := diagnoseComponentHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseComponentInput{Host: "web1", Component: "alertmanager"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil (success); calls=%v", result, fake.calls)
	}
	if out.Verdict != "healthy" {
		t.Fatalf("verdict = %q, want healthy; out=%+v calls=%v", out.Verdict, out, fake.calls)
	}
	if out.VerifySpec != "docs/verification/alertmanager.md" {
		t.Errorf("VerifySpec = %q", out.VerifySpec)
	}
	if !out.RuntimePresent || !out.RuntimeRunning {
		t.Errorf("runtime present/running = %v/%v", out.RuntimePresent, out.RuntimeRunning)
	}
}

// ---- pilot_diagnose_network_path -------------------------------------------

func TestDiagnoseNetworkPathHandler_UnknownEndpointRejected(t *testing.T) {
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseNetworkPathHandler(baseDiagnoseOpts(t, writeDiagnoseFixtureInventory(t), fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseNetworkPathInput{SourceHost: "web1", Component: "alertmanager", Endpoint: "not-real"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil {
		t.Fatal("result = nil, want a structured tool error")
	}
}

func TestDiagnoseNetworkPathHandler_SuccessReachable(t *testing.T) {
	requireRealAnsible(t)
	t.Setenv("PILOT_ROOT", repoRootForTest(t))
	inv := writeDiagnoseMultiGroupFixtureInventory(t, map[string]string{"alertmanager": "am1"})
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){
		"getent hosts 127.0.0.1":        func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "127.0.0.1 localhost"), 0, nil },
		"ip route get '127.0.0.1' 2>&1": func() (string, int, error) { return diagnoseOKDoc(t, "web1", 0, "127.0.0.1 dev lo"), 0, nil },
		"timeout 2 bash -c 'exec 3<>/dev/tcp/127.0.0.1/9093' 2>/dev/null && echo open || echo closed": func() (string, int, error) {
			return diagnoseOKDoc(t, "web1", 0, "open"), 0, nil
		},
		"curl -sS -G http://127.0.0.1:9093/-/ready -w '\\nHTTP_STATUS:%{http_code}'": func() (string, int, error) {
			return diagnoseOKDoc(t, "web1", 0, "\nHTTP_STATUS:200"), 0, nil
		},
	}}
	handler := diagnoseNetworkPathHandler(baseDiagnoseOpts(t, inv, fake.run))
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseNetworkPathInput{SourceHost: "web1", Component: "alertmanager", Endpoint: "api"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil (success); calls=%v", result, fake.calls)
	}
	if out.Verdict != "reachable" {
		t.Fatalf("verdict = %q, want reachable; out=%+v calls=%v", out.Verdict, out, fake.calls)
	}
	if out.DestPort != 9093 || out.Scheme != "http" {
		t.Errorf("dest = %s:%d/%s, want 9093/http", out.DestHost, out.DestPort, out.Scheme)
	}
}

// ---- pilot_diagnose_recent_changes -----------------------------------------

func TestDiagnoseRecentChangesHandler_InvalidWindowRejected(t *testing.T) {
	t.Setenv("PILOT_DATA_DIR", t.TempDir())
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseRecentChangesHandler(baseDiagnoseOpts(t, "unused.yml", fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseRecentChangesInput{Start: "not-a-time", End: "2026-09-01T00:00:00Z"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil {
		t.Fatal("result = nil, want a structured tool error")
	}
}

func TestDiagnoseRecentChangesHandler_StartAfterEndRejected(t *testing.T) {
	t.Setenv("PILOT_DATA_DIR", t.TempDir())
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	handler := diagnoseRecentChangesHandler(baseDiagnoseOpts(t, "unused.yml", fake.run))
	result, _, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseRecentChangesInput{Start: "2026-09-01T12:00:00Z", End: "2026-09-01T00:00:00Z"})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result == nil {
		t.Fatal("result = nil, want a structured tool error")
	}
}

func TestDiagnoseRecentChangesHandler_FindsEditApplyAuditSession(t *testing.T) {
	t.Setenv("PILOT_DATA_DIR", t.TempDir())
	fake := &diagnoseFakeRunner{byCommand: map[string]func() (string, int, error){}}
	opts := baseDiagnoseOpts(t, "unused.yml", fake.run)

	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	sessionDir := filepath.Join(opts.AuditDir, "session1-apply")
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	meta := map[string]any{
		"session_id": "session1", "kind": "apply",
		"start": now.Add(-10 * time.Minute).Format(time.RFC3339), "finish": now.Add(-9 * time.Minute).Format(time.RFC3339),
		"workspace_revision": "deadbeef",
	}
	data, _ := json.Marshal(meta)
	if err := os.WriteFile(filepath.Join(sessionDir, "metadata.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	handler := diagnoseRecentChangesHandler(opts)
	result, out, err := handler(context.Background(), &mcp.CallToolRequest{}, diagnoseRecentChangesInput{
		Start: now.Add(-30 * time.Minute).Format(time.RFC3339), End: now.Format(time.RFC3339),
	})
	if err != nil {
		t.Fatalf("handler() error = %v", err)
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil (success)", result)
	}
	if len(out.Records) != 1 || out.Records[0].ID != "session1" || out.Records[0].Kind != "edit_apply" {
		t.Fatalf("records = %+v, want one edit_apply record for session1", out.Records)
	}
	if out.Records[0].WorkspaceRevision != "deadbeef" {
		t.Errorf("workspace_revision = %q, want deadbeef", out.Records[0].WorkspaceRevision)
	}
}
