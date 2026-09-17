package detection

import (
	"strings"
	"testing"
)

func TestLifecyclePolicy_RequiresConfiguredCriticalDuration(t *testing.T) {
	policy := LifecyclePolicy{
		WarningWindowCycles:       8,
		WarningRequiredCycles:     6,
		CriticalConsecutiveCycles: 4,
		RecoveryConsecutiveCycles: 8,
	}
	lc := NewHostLifecycleWithPolicy(policy)
	for i := 0; i < 3; i++ {
		if got := lc.Advance(1).Action; got != ActionNone {
			t.Fatalf("critical cycle %d action=%s, want no action before four consecutive cycles", i+1, got)
		}
	}
	if got := lc.Advance(1); got.Action != ActionCreateCritical || got.Severity != SeverityCritical {
		t.Fatalf("fourth critical cycle transition=%+v, want create critical", got)
	}
}

func TestFeatureProfile_LifecycleScoreCapsUncorroboratedNonCriticalFeature(t *testing.T) {
	nonCritical := false
	profile := FeatureProfile{Features: []Feature{
		{Name: "disk_io_busy", Critical: &nonCritical},
		{Name: "cpu_utilization"}, // nil preserves the legacy critical-eligible default.
	}}

	diskOnly := FusedResult{Score: 1, Contributors: []Contributor{
		{Feature: "disk_io_busy", Score: 1},
		{Feature: "cpu_utilization", Score: 0.5},
	}}
	if got := profile.LifecycleScore(diskOnly, map[string]float64{"disk_io_busy": 1, "cpu_utilization": 0.5}); got < WarningThreshold || got >= CriticalThreshold {
		t.Fatalf("disk-only lifecycle score=%v, want warning-only range [%v,%v)", got, WarningThreshold, CriticalThreshold)
	}

	corroborated := FusedResult{Score: 1, Contributors: []Contributor{
		{Feature: "disk_io_busy", Score: 1},
		{Feature: "cpu_utilization", Score: WarningThreshold},
	}}
	if got := profile.LifecycleScore(corroborated, map[string]float64{"disk_io_busy": 1, "cpu_utilization": 0.8}); got != 1 {
		t.Fatalf("corroborated lifecycle score=%v, want raw critical score", got)
	}
}

func TestFeatureProfile_LifecycleScoreRejectsHighScoreWithoutEvidence(t *testing.T) {
	profile := FeatureProfile{Features: []Feature{{Name: "cpu_utilization"}}}
	if got := profile.LifecycleScore(FusedResult{Score: 1}, nil); got >= WarningThreshold {
		t.Fatalf("evidence-free lifecycle score=%v, want below warning threshold", got)
	}
}

func TestLifecyclePolicy_ValidateRejectsImpossibleWarningRule(t *testing.T) {
	policy := LifecyclePolicy{WarningWindowCycles: 4, WarningRequiredCycles: 5}
	if err := policy.Validate(); err == nil {
		t.Fatal("expected warning count larger than its window to be rejected")
	}
}

func TestLinuxHostProfile_RequiresAbsolutePressureForCritical(t *testing.T) {
	profile, err := LoadFeatureProfile("../../monitoring/detection/feature-profiles/linux-host-v1.yaml")
	if err != nil {
		t.Fatalf("load linux host profile: %v", err)
	}
	if profile.Version != 4 {
		t.Fatalf("linux host profile version=%d, want 4 for actionable warning policy", profile.Version)
	}
	policy := profile.EffectiveLifecyclePolicy()
	if policy.WarningWindowCycles != 8 || policy.WarningRequiredCycles != 6 || policy.CriticalConsecutiveCycles != 4 || policy.RecoveryConsecutiveCycles != 8 {
		t.Fatalf("linux host lifecycle policy = %+v", policy)
	}
	disk, found := profile.Feature("disk_io_busy")
	if !found || disk.Critical == nil || *disk.Critical {
		t.Fatalf("disk_io_busy critical policy = %+v, want explicitly false", disk)
	}
	if disk.ValidMax != 1.05 || !strings.Contains(disk.PromQL, "max by") || !strings.Contains(disk.PromQL, "[5m]") {
		t.Fatalf("disk_io_busy profile did not retain normalized five-minute max semantics: %+v", disk)
	}
	if disk.WarningMinValue == nil || *disk.WarningMinValue != 0.80 || len(disk.WarningRequireAny) != 2 {
		t.Fatalf("disk_io_busy warning policy = %+v, want 0.80 plus queue/latency corroboration", disk)
	}
	load, found := profile.Feature("load1_per_cpu")
	if !found || load.Critical == nil || *load.Critical {
		t.Fatalf("load1_per_cpu critical policy = %+v, want explicitly false", load)
	}
	cpu, found := profile.Feature("cpu_utilization")
	if !found || cpu.WarningMinValue == nil || *cpu.WarningMinValue != 0.60 || cpu.CriticalMinValue == nil || *cpu.CriticalMinValue != 0.80 {
		t.Fatalf("cpu_utilization warning/critical floors = %+v, want 0.60/0.80", cpu)
	}
	if notify := profile.EffectiveNotifyPolicy(); notify.Warning != "dashboard" || notify.Critical != "teams" {
		t.Fatalf("notification policy = %+v, want dashboard/teams", notify)
	}

	// This is the observed it-core event: statistically extreme, but only 24%
	// CPU and therefore not a capacity-critical incident.
	moderateCPU := FusedResult{Score: 1, Contributors: []Contributor{
		{Feature: "cpu_utilization", Score: 1},
		{Feature: "disk_io_busy", Score: 1},
		{Feature: "load1_per_cpu", Score: 1},
	}}
	current := map[string]float64{
		"cpu_utilization": 0.23825,
		"disk_io_busy":    0.63744,
		"load1_per_cpu":   0.2925,
	}
	if got := profile.LifecycleScore(moderateCPU, current); got >= WarningThreshold {
		t.Fatalf("moderate CPU burst lifecycle score=%v, want below warning threshold %v", got, WarningThreshold)
	}

	current["cpu_utilization"] = 0.60
	if got := profile.LifecycleScore(moderateCPU, current); got < WarningThreshold || got >= CriticalThreshold {
		t.Fatalf("actionable CPU warning lifecycle score=%v, want warning-only range [%v,%v)", got, WarningThreshold, CriticalThreshold)
	}
	current["cpu_utilization"] = 0.80
	if got := profile.LifecycleScore(moderateCPU, current); got != 1 {
		t.Fatalf("sustained CPU saturation lifecycle score=%v, want critical raw score", got)
	}

	falseValue := false
	cpu.Critical = &falseValue
	for i := range profile.Features {
		if profile.Features[i].Name == "cpu_utilization" {
			profile.Features[i] = cpu
		}
	}
	if err := profile.Validate(); err == nil {
		t.Fatal("expected criticalMinValue with critical:false to be rejected")
	}
}

func TestLinuxHostProfile_DiskWarningRequiresQueueOrLatency(t *testing.T) {
	profile, err := LoadFeatureProfile("../../monitoring/detection/feature-profiles/linux-host-v1.yaml")
	if err != nil {
		t.Fatalf("load linux host profile: %v", err)
	}
	fused := FusedResult{Score: 1, Contributors: []Contributor{{Feature: "disk_io_busy", Score: 1}}}
	current := map[string]float64{
		"disk_io_busy":            0.95,
		"disk_io_queue_depth":     0.5,
		"disk_io_latency_seconds": 0.01,
	}
	if got := profile.LifecycleScore(fused, current); got >= WarningThreshold {
		t.Fatalf("uncorroborated disk busy score=%v, want below warning threshold", got)
	}
	current["disk_io_queue_depth"] = 1.2
	if got := profile.LifecycleScore(fused, current); got < WarningThreshold || got >= CriticalThreshold {
		t.Fatalf("queue-corroborated disk busy score=%v, want warning-only range", got)
	}
	current["disk_io_queue_depth"] = 0.5
	current["disk_io_latency_seconds"] = 0.025
	if got := profile.LifecycleScore(fused, current); got < WarningThreshold || got >= CriticalThreshold {
		t.Fatalf("latency-corroborated disk busy score=%v, want warning-only range", got)
	}
}
