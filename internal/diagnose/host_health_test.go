package diagnose

import "testing"

func TestBuildHostHealthOutput_Unreachable(t *testing.T) {
	out := BuildHostHealthOutput(false, nil)
	if out.Verdict != "unreachable" {
		t.Fatalf("verdict = %q, want unreachable", out.Verdict)
	}
}

func TestBuildHostHealthOutput_Healthy(t *testing.T) {
	results := []StepResult{
		stepResult("uptime", 0, "123456.78 98765.43\n"),
		stepResult("load", 0, "0.10 0.20 0.15 1/234 5678\n"),
		stepResult("memory", 0, "MemTotal:       16384000 kB\nMemAvailable:   12000000 kB\n"),
		stepResult("disk", 0, "Filesystem Type 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 ext4 100000 10000 90000 10% /\n---INODES---\nFilesystem Type Inodes IUsed IFree IUse% Mounted on\n/dev/sda1 ext4 100000 5000 95000 5% /\n"),
		stepResult("failed-units", 0, ""),
		stepResult("clock-sync", 0, "yes\n"),
		stepResult("interfaces", 0, "1: lo: <LOOPBACK,UP>\n2: eth0: <BROADCAST,MULTICAST,UP>\n"),
		stepResult("node-exporter", 0, "active"),
		stepResult("kernel-errors", 0, ""),
	}
	out := BuildHostHealthOutput(true, results)
	if out.Verdict != "healthy" {
		t.Fatalf("verdict = %q, want healthy; out=%+v", out.Verdict, out)
	}
	if out.UptimeSeconds != 123456.78 {
		t.Errorf("UptimeSeconds = %v, want 123456.78", out.UptimeSeconds)
	}
	if out.Load1 != 0.10 || out.Load5 != 0.20 || out.Load15 != 0.15 {
		t.Errorf("load = %v/%v/%v, want 0.10/0.20/0.15", out.Load1, out.Load5, out.Load15)
	}
	if out.MemTotalKiB != 16384000 || out.MemAvailableKiB != 12000000 {
		t.Errorf("mem = %d/%d, want 16384000/12000000", out.MemTotalKiB, out.MemAvailableKiB)
	}
	if len(out.Filesystems) != 1 || out.Filesystems[0].Mount != "/" || out.Filesystems[0].UsedPercent != 10 || out.Filesystems[0].InodeUsedPercent != 5 {
		t.Errorf("filesystems = %+v", out.Filesystems)
	}
	if !out.ClockSynchronized {
		t.Error("ClockSynchronized = false, want true")
	}
	if !out.NodeExporterActive {
		t.Error("NodeExporterActive = false, want true")
	}
}

func TestBuildHostHealthOutput_DegradedOnFailedUnitsAndDiskPressure(t *testing.T) {
	results := []StepResult{
		stepResult("uptime", 0, "100.0 50.0\n"),
		stepResult("load", 0, "0.1 0.1 0.1 1/1 1\n"),
		stepResult("memory", 0, "MemTotal:       1000 kB\nMemAvailable:   10 kB\n"),
		stepResult("disk", 0, "Filesystem Type 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 ext4 100000 95000 5000 95% /\n---INODES---\nFilesystem Type Inodes IUsed IFree IUse% Mounted on\n/dev/sda1 ext4 100000 5000 95000 5% /\n"),
		stepResult("failed-units", 0, "docker.service loaded failed failed Docker\n"),
		stepResult("clock-sync", 0, "yes\n"),
		stepResult("interfaces", 0, "1: lo: <LOOPBACK,UP>\n"),
		stepResult("node-exporter", 0, "active"),
		stepResult("kernel-errors", 0, ""),
	}
	out := BuildHostHealthOutput(true, results)
	if out.Verdict != "degraded" {
		t.Fatalf("verdict = %q, want degraded (failed unit + disk >=90%%); out=%+v", out.Verdict, out)
	}
	if len(out.FailedUnits) != 1 {
		t.Errorf("FailedUnits = %v, want 1 entry", out.FailedUnits)
	}
}

func TestBuildHostHealthOutput_InsufficientEvidence(t *testing.T) {
	// Every step ran (host reachable) but returned nothing usable (e.g.
	// all steps hit an unexpected shell that produced empty stdout) —
	// must not silently claim "healthy".
	out := BuildHostHealthOutput(true, nil)
	if out.Verdict != "insufficient_evidence" {
		t.Fatalf("verdict = %q, want insufficient_evidence", out.Verdict)
	}
}

func TestTruncateLines(t *testing.T) {
	lines := []string{"a", "b", "c", "d", "e"}
	got := truncateLines(lines, 3)
	if len(got) != 4 || got[3] != "... (2 more, truncated)" {
		t.Fatalf("truncateLines = %v", got)
	}
	if got := truncateLines(lines, 10); len(got) != 5 {
		t.Fatalf("truncateLines under limit should be unchanged, got %v", got)
	}
}
