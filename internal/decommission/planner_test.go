package decommission

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/contract"
)

func fixedNow() time.Time {
	return time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
}

func hashFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// TestPlanner_PlanIsReadOnly proves HD1: PlanHost mutates nothing on disk,
// even when it exercises every optional scanner path (roster, DNS
// manifest, internal-endpoints manifest, host_vars).
func TestPlanner_PlanIsReadOnly(t *testing.T) {
	dir := t.TempDir()
	writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML("web1", "10.0.0.5", []string{"freeipa-client"},
		"    freeipa_roster_file: roster.yaml\n    env: sandbox\n"))
	writeWorkspaceFile(t, dir, "host_vars/web1.yml", "some_var: 1\n")
	writeWorkspaceFile(t, dir, "roster.yaml", `schema_version: 2
freeipa:
  server: ipa1.example.internal
hosts:
  - name: web1
    state: present
hostgroups:
  - name: web-servers
    state: present
    membership: {authoritative: true, hosts: [web1]}
hbac:
  rules:
    - name: web-login
      targets: {hosts: [web1], hostgroups: []}
sudo:
  rules:
    - name: web-sudo
      targets: {hosts: [web1], hostgroups: []}
`)

	catalog := newCatalog(t, contract.Contract{ID: "freeipa-client", Role: "freeipa-client"})

	// Snapshot every file under dir before planning.
	var paths []string
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		paths = append(paths, path)
		return nil
	})
	before := map[string]string{}
	for _, p := range paths {
		before[p] = hashFile(t, p)
	}
	if len(before) == 0 {
		t.Fatal("expected at least one fixture file on disk before planning")
	}

	plan, err := PlanHost(context.Background(), PlanInput{
		WorkspaceDir: dir, HostName: "web1", Catalog: catalog, Now: fixedNow,
	})
	if err != nil {
		t.Fatalf("PlanHost() error = %v", err)
	}
	if plan == nil {
		t.Fatal("PlanHost() returned nil plan")
	}

	// No new/removed files, no changed content.
	var after []string
	_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		after = append(after, path)
		return nil
	})
	if len(after) != len(paths) {
		t.Fatalf("file count changed: before=%d after=%d (PlanHost must not create/remove workspace files)", len(paths), len(after))
	}
	for _, p := range after {
		got := hashFile(t, p)
		want, ok := before[p]
		if !ok {
			t.Fatalf("PlanHost() created a new file: %s", p)
		}
		if got != want {
			t.Fatalf("PlanHost() mutated %s (hash changed) — planning must be read-only", p)
		}
	}
}

// TestPlanner_PlanHashDeterministicAndSnapshotPersisted proves HD3: the
// plan hash is deterministic for identical inputs, semantically identical
// YAML in different key order yields the same hash, and the persisted
// host snapshot round-trips through the store unchanged.
func TestPlanner_PlanHashDeterministicAndSnapshotPersisted(t *testing.T) {
	dir := t.TempDir()
	writeWorkspaceFile(t, dir, "hosts.yml", `hosts:
  web1:
    ansible_host: "10.0.0.5"
    ansible_user: "root"
    env: sandbox
    roles:
      - freeipa-client
`)
	catalog := newCatalog(t, contract.Contract{ID: "freeipa-client", Role: "freeipa-client"})

	in := PlanInput{WorkspaceDir: dir, HostName: "web1", Catalog: catalog, Now: fixedNow}
	planA, err := PlanHost(context.Background(), in)
	if err != nil {
		t.Fatalf("PlanHost() error = %v", err)
	}
	planB, err := PlanHost(context.Background(), in)
	if err != nil {
		t.Fatalf("PlanHost() error = %v", err)
	}
	if planA.PlanHash == "" {
		t.Fatal("PlanHash is empty")
	}
	if planA.PlanHash != planB.PlanHash {
		t.Fatalf("PlanHash not deterministic: %s != %s", planA.PlanHash, planB.PlanHash)
	}
	if planA.ID == planB.ID {
		t.Fatal("expected two distinct plan IDs from two separate PlanHost calls")
	}

	// Sub-case: semantically identical hosts.yml with a different key
	// order (vars scrambled inside the host block, plus a second host
	// added AFTER the target in one file and BEFORE it in the other —
	// inventory.Parse sorts by name, so map/list order must not matter)
	// must still hash the same.
	dir2 := t.TempDir()
	writeWorkspaceFile(t, dir2, "hosts.yml", `hosts:
  aaa-other:
    roles: [dns]
    ansible_host: "10.0.0.9"
  web1:
    roles:
      - freeipa-client
    env: sandbox
    ansible_user: "root"
    ansible_host: "10.0.0.5"
`)
	in2 := PlanInput{WorkspaceDir: dir2, HostName: "web1", Catalog: catalog, Now: fixedNow}
	planC, err := PlanHost(context.Background(), in2)
	if err != nil {
		t.Fatalf("PlanHost() (dir2) error = %v", err)
	}

	dir3 := t.TempDir()
	writeWorkspaceFile(t, dir3, "hosts.yml", `hosts:
  web1:
    ansible_user: "root"
    ansible_host: "10.0.0.5"
    env: sandbox
    roles: [freeipa-client]
  aaa-other:
    ansible_host: "10.0.0.9"
    roles:
      - dns
`)
	in3 := PlanInput{WorkspaceDir: dir3, HostName: "web1", Catalog: catalog, Now: fixedNow}
	planD, err := PlanHost(context.Background(), in3)
	if err != nil {
		t.Fatalf("PlanHost() (dir3) error = %v", err)
	}
	if planC.PlanHash != planD.PlanHash {
		t.Fatalf("semantically identical hosts.yml in different key/host order produced different hashes: %s != %s", planC.PlanHash, planD.PlanHash)
	}
	if planC.InventoryRevision != planD.InventoryRevision {
		t.Fatalf("semantically identical hosts.yml in different key/host order produced different InventoryRevision: %s != %s", planC.InventoryRevision, planD.InventoryRevision)
	}

	// Snapshot persistence: SavePlan/LoadPlan round-trips the host snapshot
	// unchanged.
	st := NewStore(openTestStore(t))
	if err := st.SavePlan(planA); err != nil {
		t.Fatalf("SavePlan() error = %v", err)
	}
	loaded, err := st.LoadPlan(planA.ID)
	if err != nil {
		t.Fatalf("LoadPlan() error = %v", err)
	}
	if loaded.Host.Name != "web1" || loaded.Host.AnsibleHost != "10.0.0.5" || loaded.Host.Env != "sandbox" {
		t.Fatalf("persisted host snapshot = %+v, want name=web1 ansible_host=10.0.0.5 env=sandbox", loaded.Host)
	}
	if loaded.PlanHash != planA.PlanHash {
		t.Fatalf("persisted plan hash = %s, want %s", loaded.PlanHash, planA.PlanHash)
	}
}

// TestPlanner_UnsupportedExternalStateBlocks proves HD7: a component with
// no registered decommission provider blocks planning (external_state_
// unsupported), whether or not its contract declares a decommission
// playbook, and whether or not the role even has a contract at all.
func TestPlanner_UnsupportedExternalStateBlocks(t *testing.T) {
	decommissionPlaybook := "playbooks/decommission/freeipa-client-decommission.yml"
	catalog := newCatalog(t,
		contract.Contract{ID: "freeipa-client", Role: "freeipa-client"},
		contract.Contract{ID: "wazuh-fim", Role: "wazuh-fim", Playbooks: contract.Playbooks{Decommission: &decommissionPlaybook}},
	)

	cases := []struct {
		name            string
		role            string
		wantDeclares    bool
		wantHasContract bool
	}{
		{name: "no decommission playbook declared", role: "freeipa-client", wantHasContract: true, wantDeclares: false},
		{name: "decommission playbook declared but no executor", role: "wazuh-fim", wantHasContract: true, wantDeclares: true},
		{name: "role has no contract at all", role: "dns", wantHasContract: false, wantDeclares: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML("h1", "10.0.0.1", []string{tc.role}, ""))
			plan, err := PlanHost(context.Background(), PlanInput{WorkspaceDir: dir, HostName: "h1", Catalog: catalog, Now: fixedNow})
			if err != nil {
				t.Fatalf("PlanHost() error = %v", err)
			}
			if !plan.Blocked() {
				t.Fatalf("plan for role %q = %+v, want Blocked()", tc.role, plan)
			}
			if len(plan.Components) != 1 {
				t.Fatalf("Components = %+v, want exactly 1", plan.Components)
			}
			cp := plan.Components[0]
			if cp.HasContract != tc.wantHasContract {
				t.Fatalf("HasContract = %v, want %v", cp.HasContract, tc.wantHasContract)
			}
			if cp.DeclaresDecommission != tc.wantDeclares {
				t.Fatalf("DeclaresDecommission = %v, want %v", cp.DeclaresDecommission, tc.wantDeclares)
			}
			found := false
			for _, b := range cp.Blockers {
				if b.Code == ErrExternalStateUnsupported {
					found = true
				}
			}
			if !found {
				t.Fatalf("component blockers = %+v, want one with Code=external_state_unsupported", cp.Blockers)
			}
		})
	}
}

// TestPlanner_StatefulRetentionRequired proves HD15: a stateful component
// with retention=required blocks planning until an explicit retention
// disposition is supplied.
func TestPlanner_StatefulRetentionRequired(t *testing.T) {
	statefulPolicy := map[string]any{"class": "stateful", "retention": "required"}
	catalog := newCatalog(t, contract.Contract{
		ID: "seaweedfs-s3", Role: "seaweedfs-s3",
		Lifecycle: contract.Lifecycle{Decommission: statefulPolicy},
	})

	dir := t.TempDir()
	writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML("s3-1", "10.0.0.2", []string{"seaweedfs-s3"}, ""))

	// No disposition supplied -> blocked with retention_required.
	plan, err := PlanHost(context.Background(), PlanInput{WorkspaceDir: dir, HostName: "s3-1", Catalog: catalog, Now: fixedNow})
	if err != nil {
		t.Fatalf("PlanHost() error = %v", err)
	}
	if len(plan.Components) != 1 || !plan.Components[0].RetentionRequired {
		t.Fatalf("Components = %+v, want exactly 1 with RetentionRequired=true", plan.Components)
	}
	if plan.Components[0].RetentionSatisfied {
		t.Fatal("RetentionSatisfied = true with no disposition supplied, want false")
	}
	foundRetention := false
	for _, b := range plan.Components[0].Blockers {
		if b.Code == ErrRetentionRequired {
			foundRetention = true
		}
	}
	if !foundRetention {
		t.Fatalf("component blockers = %+v, want one with Code=retention_required", plan.Components[0].Blockers)
	}
	if len(plan.RetentionRequirements) != 1 || plan.RetentionRequirements[0].Satisfied {
		t.Fatalf("plan.RetentionRequirements = %+v, want exactly 1 unsatisfied requirement", plan.RetentionRequirements)
	}

	// Disposition supplied -> retention gate satisfied (component may
	// still be Blocked overall for the unrelated external_state_
	// unsupported reason — HD15 only concerns the retention gate itself).
	plan2, err := PlanHost(context.Background(), PlanInput{
		WorkspaceDir: dir, HostName: "s3-1", Catalog: catalog, Now: fixedNow,
		RetentionDispositions: map[string]RetentionDisposition{"seaweedfs-s3": RetentionDispositionExported},
	})
	if err != nil {
		t.Fatalf("PlanHost() error = %v", err)
	}
	if !plan2.Components[0].RetentionSatisfied {
		t.Fatal("RetentionSatisfied = false with an explicit disposition supplied, want true")
	}
	for _, b := range plan2.Components[0].Blockers {
		if b.Code == ErrRetentionRequired {
			t.Fatalf("still has a retention_required blocker after supplying a disposition: %+v", plan2.Components[0].Blockers)
		}
	}
	if len(plan2.RetentionRequirements) != 1 || !plan2.RetentionRequirements[0].Satisfied || plan2.RetentionRequirements[0].Disposition != RetentionDispositionExported {
		t.Fatalf("plan2.RetentionRequirements = %+v, want exactly 1 satisfied requirement with disposition=exported", plan2.RetentionRequirements)
	}
}

// TestPlanner_RejectsFreeIPAServerAndReplica proves HD23/INV-13: the
// generic decommission workflow returns a hard blocker for
// freeipa-server/freeipa-server-replica, with no way to bypass it and no
// further generic planning performed.
func TestPlanner_RejectsFreeIPAServerAndReplica(t *testing.T) {
	for _, role := range []string{"freeipa-server", "freeipa-server-replica"} {
		t.Run(role, func(t *testing.T) {
			dir := t.TempDir()
			writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML("ipa1", "10.0.0.10", []string{role}, ""))
			catalog := newCatalog(t, contract.Contract{ID: role, Role: role})

			plan, err := PlanHost(context.Background(), PlanInput{WorkspaceDir: dir, HostName: "ipa1", Catalog: catalog, Now: fixedNow})
			if err != nil {
				t.Fatalf("PlanHost() error = %v", err)
			}
			if !plan.Blocked() || plan.Status != PlanStatusBlocked {
				t.Fatalf("plan = %+v, want Blocked/PlanStatusBlocked", plan)
			}
			if len(plan.Blockers) != 1 || plan.Blockers[0].Code != ErrControlPlaneRequiresDedicated {
				t.Fatalf("plan.Blockers = %+v, want exactly 1 control_plane_host_requires_dedicated_workflow blocker", plan.Blockers)
			}
			// No further generic planning: no per-component classification
			// ran at all for this host.
			if len(plan.Components) != 0 {
				t.Fatalf("Components = %+v, want none — INV-13 stops before generic component planning", plan.Components)
			}
			if len(plan.References) != 0 {
				t.Fatalf("References = %+v, want none — INV-13 stops before the reference scan", plan.References)
			}
		})
	}
}

// Extra table-driven coverage (spec.md §33): missing host, host with no
// roles.
func TestPlanner_MissingHostAndNoRoles(t *testing.T) {
	dir := t.TempDir()
	writeWorkspaceFile(t, dir, "hosts.yml", `hosts:
  h1:
    ansible_host: "10.0.0.1"
  h-no-roles:
    ansible_host: "10.0.0.2"
`)
	catalog := newCatalog(t, contract.Contract{ID: "freeipa-client", Role: "freeipa-client"})

	if _, err := PlanHost(context.Background(), PlanInput{WorkspaceDir: dir, HostName: "does-not-exist", Catalog: catalog, Now: fixedNow}); ClassOf(err) != ErrHostNotFound {
		t.Fatalf("PlanHost(missing host) error = %v, want class host_not_found", err)
	}

	plan, err := PlanHost(context.Background(), PlanInput{WorkspaceDir: dir, HostName: "h-no-roles", Catalog: catalog, Now: fixedNow})
	if err != nil {
		t.Fatalf("PlanHost() error = %v", err)
	}
	if plan.Blocked() {
		t.Fatalf("plan for a roleless host = %+v, want not Blocked", plan)
	}
	if len(plan.Components) != 0 {
		t.Fatalf("Components = %+v, want none for a roleless host", plan.Components)
	}
	if len(plan.Warnings) == 0 {
		t.Fatal("expected an informational warning for a roleless host, got none")
	}
}

func TestPlanner_MalformedWorkspaceReturnsError(t *testing.T) {
	dir := t.TempDir() // no hosts.yml at all
	catalog := newCatalog(t, contract.Contract{ID: "freeipa-client", Role: "freeipa-client"})
	_, err := PlanHost(context.Background(), PlanInput{WorkspaceDir: dir, HostName: "h1", Catalog: catalog})
	if ClassOf(err) != ErrWorkspaceMalformed {
		t.Fatalf("PlanHost(no hosts.yml) error = %v, want class workspace_malformed", err)
	}
}
