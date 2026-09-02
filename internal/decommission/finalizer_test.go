package decommission

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/decommission/providers"
	"github.com/kjelly/pilot/internal/inventory"
	pstore "github.com/kjelly/pilot/internal/store"
)

// newZeroRoleHostWorkspace builds the realistic Phase 2 happy-path fixture
// spec.md §37 describes: a host with zero roles, which is the only plan
// shape that reaches "executable" with no registered provider (every role
// that resolves to a contract is unconditionally external_state_unsupported
// in this phase — see planner.go's planComponent).
func newZeroRoleHostWorkspace(t *testing.T, hostName string) string {
	t.Helper()
	dir := t.TempDir()
	writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML(hostName, "10.0.0.9", nil, ""))
	return dir
}

func planZeroRoleHost(t *testing.T, dir, hostName string, ds *Store) *Plan {
	t.Helper()
	// A zero-role host never reaches catalog.ComponentsForRole at all
	// (PlanHost returns early for zero roles) — an empty catalog (which
	// contract.NewCatalog(nil) refuses to construct) is fine here, so use
	// the zero-value Catalog rather than newCatalog(t)'s hard failure.
	catalog := newCatalogNoT()
	plan, err := PlanHost(context.Background(), PlanInput{
		WorkspaceDir: dir, HostName: hostName, Catalog: catalog, Now: fixedNow,
	})
	if err != nil {
		t.Fatalf("PlanHost: %v", err)
	}
	if plan.Blocked() {
		t.Fatalf("expected a zero-role host plan to be unblocked, got blockers: %+v", plan.Blockers)
	}
	if ds != nil {
		if err := ds.SavePlan(plan); err != nil {
			t.Fatalf("SavePlan: %v", err)
		}
	}
	return plan
}

func finalizeInputFor(dir, hostName string, plan *Plan, verifications []providers.Verification, decommissionID string, ds *Store) FinalizeInput {
	return FinalizeInput{
		Plan: plan,
		PlanInputForFreshness: PlanInput{
			WorkspaceDir: dir, HostName: hostName, Catalog: newCatalogNoT(), Now: fixedNow,
		},
		Verifications:  verifications,
		DecommissionID: decommissionID,
		StartedAt:      fixedNow(),
		Now:            fixedNow,
		Store:          ds,
	}
}

// newCatalogNoT is newCatalog without requiring *testing.T, for use inside
// helpers that build a FinalizeInput without a live *testing.T handle
// (contract.NewCatalog(nil) never fails for an empty contract list).
func newCatalogNoT() contract.Catalog {
	cat, _ := contract.NewCatalog(nil)
	return cat
}

// TestFinalizer_HostRemainsUntilVerificationPasses proves INV-1/INV-11/
// HD20: while independent verification reports active residue, hosts.yml
// on disk is byte-for-byte unchanged and finalization stays blocked; once
// verification passes, the host is actually removed.
func TestFinalizer_HostRemainsUntilVerificationPasses(t *testing.T) {
	hostName := "hd20-host"
	dir := newZeroRoleHostWorkspace(t, hostName)
	hostsPath := filepath.Join(dir, "hosts.yml")

	before, err := os.ReadFile(hostsPath)
	if err != nil {
		t.Fatalf("read hosts.yml: %v", err)
	}

	st := openTestStore(t)
	ds := NewStore(st)
	plan := planZeroRoleHost(t, dir, hostName, ds)

	blockedVerifications := []providers.Verification{
		{Provider: "fake", Kind: "residue_check", Identity: hostName, Status: "active_residue", Active: true},
	}
	blocked, err := Finalize(context.Background(), finalizeInputFor(dir, hostName, plan, blockedVerifications, "hd20", ds))
	if err != nil {
		t.Fatalf("Finalize (blocked) returned error, want a blocked result: %v", err)
	}
	if blocked.Status != "blocked" {
		t.Fatalf("Status = %q, want blocked", blocked.Status)
	}
	if blocked.Receipt != nil {
		t.Fatal("expected no receipt while verification blocks finalization")
	}

	after, err := os.ReadFile(hostsPath)
	if err != nil {
		t.Fatalf("read hosts.yml after blocked finalize: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Fatalf("hosts.yml changed while verification was blocking finalization:\nbefore=%s\nafter=%s", before, after)
	}
	if !strings.Contains(string(after), hostName) {
		t.Fatalf("host %q must remain in hosts.yml until verification passes", hostName)
	}

	passed, err := Finalize(context.Background(), finalizeInputFor(dir, hostName, plan, nil, "hd20", ds))
	if err != nil {
		t.Fatalf("Finalize (pass) error: %v", err)
	}
	if passed.Status != "completed" {
		t.Fatalf("Status = %q, want completed", passed.Status)
	}
	if passed.Receipt == nil {
		t.Fatal("expected a receipt on successful finalization")
	}

	final, err := os.ReadFile(hostsPath)
	if err != nil {
		t.Fatalf("read hosts.yml after successful finalize: %v", err)
	}
	if strings.Contains(string(final), hostName) {
		t.Fatalf("host %q still present in hosts.yml after verification passed and finalize completed", hostName)
	}
}

// TestFinalizer_RegeneratesAndValidatesInventory proves HD21: a successful
// finalize regenerates inventory.yml via internal/inventory.Generate (the
// decommissioned host is gone, a surviving host is not) and the resulting
// hosts.yml still lints clean.
func TestFinalizer_RegeneratesAndValidatesInventory(t *testing.T) {
	hostName := "hd21-host"
	otherHost := "hd21-keep"
	dir := t.TempDir()
	writeWorkspaceFile(t, dir, "hosts.yml",
		"hosts:\n"+
			"  "+hostName+":\n    ansible_host: \"10.0.0.21\"\n"+
			"  "+otherHost+":\n    ansible_host: \"10.0.0.22\"\n    roles:\n      - docker\n")
	// A stale pre-existing inventory.yml proves regeneration actually
	// happens, rather than the file merely already looking right.
	writeWorkspaceFile(t, dir, "inventory.yml", "stale: true\n")

	st := openTestStore(t)
	ds := NewStore(st)
	plan := planZeroRoleHost(t, dir, hostName, ds)

	result, err := Finalize(context.Background(), finalizeInputFor(dir, hostName, plan, nil, "hd21", ds))
	if err != nil {
		t.Fatalf("Finalize error: %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("Status = %q, want completed", result.Status)
	}

	generated, err := os.ReadFile(filepath.Join(dir, "inventory.yml"))
	if err != nil {
		t.Fatalf("read regenerated inventory.yml: %v", err)
	}
	genStr := string(generated)
	if strings.Contains(genStr, "stale: true") {
		t.Fatal("inventory.yml was not actually regenerated")
	}
	if strings.Contains(genStr, hostName) {
		t.Fatalf("regenerated inventory.yml still references the decommissioned host %q", hostName)
	}
	if !strings.Contains(genStr, otherHost) {
		t.Fatalf("regenerated inventory.yml lost the surviving host %q", otherHost)
	}

	hostsData, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("read hosts.yml: %v", err)
	}
	hf, err := inventory.Parse(hostsData)
	if err != nil {
		t.Fatalf("parse post-finalize hosts.yml: %v", err)
	}
	if issues := inventory.Lint(hf); inventory.HasErrors(issues) {
		t.Fatalf("post-finalize hosts.yml has lint errors: %v", issues)
	}
	if len(hf.Hosts) != 1 || hf.Hosts[0].Name != otherHost {
		t.Fatalf("hosts.yml after finalize = %+v, want only %q", hf.Hosts, otherHost)
	}
}

// TestFinalizer_HistoricalEvidenceRetained proves HD22/INV-12: finalize
// never touches Pilot's delivery/verify evidence tables. Finalize's Store
// parameter wraps the exact same *store.Store rows are seeded into here —
// if any future change made Finalize issue a DELETE against
// delivery_events/verify_evidence, this test would catch it (both tables
// are additionally append-only at the schema level — see sqlite.go's
// _no_delete triggers — so this is defense in depth, not the only guard).
func TestFinalizer_HistoricalEvidenceRetained(t *testing.T) {
	hostName := "hd22-host"
	dir := newZeroRoleHostWorkspace(t, hostName)

	st := openTestStore(t)
	ds := NewStore(st)
	plan := planZeroRoleHost(t, dir, hostName, ds)

	ctx := context.Background()
	rw, err := pstore.StartRun(ctx, st, pstore.RunStarted{RunID: "hd22-evidence-run", Stage: "sandbox", StartedAt: fixedNow()})
	if err != nil {
		t.Fatalf("seed delivery run: %v", err)
	}
	if err := rw.AppendEvidence(ctx, []pstore.VerifyEvidence{{
		SpecPath: "docs/verification/hd22-fixture.md", RowID: "C1", Host: hostName, Attempt: 1,
		OperationID: "op-1", Command: "true", Expected: "rc=0", ExitCode: 0,
		ProbeStatus: "ok", Verdict: "pass", StartedAt: fixedNow(), FinishedAt: fixedNow(),
	}}); err != nil {
		t.Fatalf("seed verify evidence: %v", err)
	}
	if err := rw.Finish(ctx, pstore.RunFinished{OperationID: "run_finished", Outcome: "pass", ExitCode: 0, FinishedAt: fixedNow()}); err != nil {
		t.Fatalf("finish seeded run: %v", err)
	}

	beforeRun, beforeEvidence, err := st.GetRun("hd22-evidence-run")
	if err != nil {
		t.Fatalf("GetRun before finalize: %v", err)
	}
	if len(beforeEvidence) == 0 {
		t.Fatal("expected at least one seeded evidence row before finalize")
	}

	result, err := Finalize(ctx, finalizeInputFor(dir, hostName, plan, nil, "hd22", ds))
	if err != nil {
		t.Fatalf("Finalize error: %v", err)
	}
	if result.Status != "completed" {
		t.Fatalf("Status = %q, want completed", result.Status)
	}

	afterRun, afterEvidence, err := st.GetRun("hd22-evidence-run")
	if err != nil {
		t.Fatalf("GetRun after finalize: %v", err)
	}
	if afterRun.RunID != beforeRun.RunID {
		t.Fatalf("delivery run row changed identity: before=%+v after=%+v", beforeRun, afterRun)
	}
	if len(afterEvidence) != len(beforeEvidence) {
		t.Fatalf("verify_evidence row count changed: before=%d after=%d", len(beforeEvidence), len(afterEvidence))
	}
}

// TestFinalizer_CompletedDecommissionReplaySafe proves INV-15/HD24: once a
// plan has completed, a repeated Finalize call against the SAME persisted
// (now-completed) plan returns already_completed plus the original
// receipt, and never re-touches hosts.yml/inventory.yml.
func TestFinalizer_CompletedDecommissionReplaySafe(t *testing.T) {
	hostName := "hd24-host"
	dir := newZeroRoleHostWorkspace(t, hostName)

	st := openTestStore(t)
	ds := NewStore(st)
	plan := planZeroRoleHost(t, dir, hostName, ds)

	first, err := Finalize(context.Background(), finalizeInputFor(dir, hostName, plan, nil, "hd24", ds))
	if err != nil {
		t.Fatalf("first Finalize error: %v", err)
	}
	if first.Status != "completed" {
		t.Fatalf("first Status = %q, want completed", first.Status)
	}

	hostsAfterFirst, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("read hosts.yml after first finalize: %v", err)
	}
	invAfterFirst, err := os.ReadFile(filepath.Join(dir, "inventory.yml"))
	if err != nil {
		t.Fatalf("read inventory.yml after first finalize: %v", err)
	}

	reloaded, err := ds.LoadPlan(plan.ID)
	if err != nil {
		t.Fatalf("LoadPlan (reload persisted completed plan): %v", err)
	}
	if reloaded.Status != PlanStatusCompleted {
		t.Fatalf("reloaded plan status = %q, want completed", reloaded.Status)
	}

	second, err := Finalize(context.Background(), finalizeInputFor(dir, hostName, reloaded, nil, "hd24", ds))
	if err != nil {
		t.Fatalf("replay Finalize returned an error, want already_completed: %v", err)
	}
	if second.Status != "already_completed" {
		t.Fatalf("replay Status = %q, want already_completed", second.Status)
	}
	if second.Receipt == nil || second.Receipt.DecommissionID != first.Receipt.DecommissionID {
		t.Fatalf("replay result did not carry the original receipt: got %+v, want decommission_id=%s", second.Receipt, first.Receipt.DecommissionID)
	}

	hostsAfterReplay, err := os.ReadFile(filepath.Join(dir, "hosts.yml"))
	if err != nil {
		t.Fatalf("read hosts.yml after replay: %v", err)
	}
	invAfterReplay, err := os.ReadFile(filepath.Join(dir, "inventory.yml"))
	if err != nil {
		t.Fatalf("read inventory.yml after replay: %v", err)
	}
	if !bytes.Equal(hostsAfterFirst, hostsAfterReplay) {
		t.Fatal("replay re-touched hosts.yml")
	}
	if !bytes.Equal(invAfterFirst, invAfterReplay) {
		t.Fatal("replay re-touched inventory.yml")
	}
}
