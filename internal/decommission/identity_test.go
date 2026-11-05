package decommission

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/decommission/providers"
	pstore "github.com/kjelly/pilot/internal/store"
)

// The real provider resolves the authoritative name; this boundary models
// the host object disappearing when its central cleanup step runs.
type identityIPAExecutor struct {
	present             bool
	fqdn                string
	gatewayTargets      []string
	canonicalRejections []string
	queryError          bool
	malformedHost       bool
}

func (e *identityIPAExecutor) Run(_ context.Context, args ...string) (*ansible.Result, error) {
	var target string
	var controls map[string]string
	for _, arg := range args {
		if value, ok := strings.CutPrefix(arg, "pilot_decommission_target_fqdn="); ok {
			target = value
		}
		var binding map[string]string
		if json.Unmarshal([]byte(arg), &binding) == nil && binding["pilot_decommission_query"] != "" {
			controls = binding
			target = binding["pilot_decommission_target_fqdn"]
		}
	}
	if controls["pilot_decommission_query"] == "gateway_scope" {
		e.gatewayTargets = append(e.gatewayTargets, target)
		// Exercise the exact production helper's independent canonical boundary.
		// A blanket READY response would mask the short-alias recovery defect.
		helper, err := filepath.Abs("../../playbooks/apply/files/freeipa-gateway-scope.py")
		if err != nil {
			return nil, err
		}
		out, err := exec.Command("python3", "-c", "import runpy,sys; runpy.run_path(sys.argv[1])['fqdn'](sys.argv[2])", helper, target).CombinedOutput()
		if err != nil {
			if !strings.Contains(string(out), "ValueError: an explicit canonical FQDN is required") {
				return nil, fmt.Errorf("native canonical oracle failed unexpectedly: %w: %s", err, out)
			}
			e.canonicalRejections = append(e.canonicalRejections, target)
			return &ansible.Result{ExitCode: 2, Stderr: "native canonical oracle rejected target: " + string(out)}, nil
		}
		return &ansible.Result{Stdout: "HOST_INSPECT[" + target + "]: GATEWAY_SCOPE_READY=true"}, nil
	}
	if e.queryError {
		return &ansible.Result{ExitCode: 2, Stderr: "native host query unavailable"}, nil
	}
	if e.malformedHost {
		return &ansible.Result{Stdout: "HOST_INSPECT[" + target + "]: Number of entries returned 0"}, nil
	}
	if controls["pilot_decommission_query"] == "ssh_retirement" {
		raw, _ := json.Marshal(map[string]any{"schema_version": 1, "kind": "ssh_retirement", "fqdn": target,
			"alias": controls["pilot_decommission_target_alias"], "stage": controls["pilot_decommission_retirement_stage"], "status": "settled"})
		return &ansible.Result{Stdout: "PILOT_SSH_RETIREMENT_V1:" + base64.StdEncoding.EncodeToString(raw)}, nil
	}
	body := "ipa: ERROR: host not found"
	if e.present {
		fqdn := e.fqdn
		if fqdn == "" {
			fqdn = "CLIENT.Example.TEST"
		}
		body = "Host name: " + fqdn + "\nPrincipal name: host/" + fqdn + "@EXAMPLE.TEST\n0 services matched"
	}
	return &ansible.Result{Stdout: "HOST_INSPECT[" + target + "]: " + body}, nil
}

type identityIPAProvider struct {
	*providers.FreeIPAClientProvider
	executor            *identityIPAExecutor
	verificationBlocked bool
	cleanupTarget       string
	verificationTargets []string
}

func (p *identityIPAProvider) Verify(_ context.Context, in providers.VerifyInput) ([]providers.Verification, error) {
	p.verificationTargets = append(p.verificationTargets, in.FQDN)
	status := "pass"
	if p.verificationBlocked {
		status = "active_residue"
	}
	return []providers.Verification{{Provider: p.ID(), Identity: in.FQDN, Status: status, Active: p.verificationBlocked}}, nil
}

func (p *identityIPAProvider) ExecutorForStep(step providers.Step) (providers.StepExecutor, error) {
	return identityIPAStep{p: p, step: step}, nil
}

type identityIPAStep struct {
	p    *identityIPAProvider
	step providers.Step
}

func (s identityIPAStep) Inspect(context.Context) (bool, error) { return !s.p.executor.present, nil }
func (s identityIPAStep) Execute(context.Context) error {
	if s.step.Action == providers.ActionFreeIPAIdentityApplyConverge {
		s.p.cleanupTarget = s.step.TargetIdentity
		s.p.executor.present = false
	}
	return nil
}

func TestHostIdentity_MetadataSurvivesCleanupAndResume(t *testing.T) {
	for _, hostName := range []string{"Client", "ALIAS.example.test"} {
		for _, mode := range []string{"apply", "resume before post-cleanup persistence", "resume after post-cleanup persistence"} {
			t.Run(hostName+"/"+mode, func(t *testing.T) {
				dir := t.TempDir()
				const want = "client.example.test"
				writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML(hostName, "10.0.0.9", []string{"freeipa-client"}, ""))
				exec := &identityIPAExecutor{present: true}
				provider := &identityIPAProvider{
					FreeIPAClientProvider: providers.NewFreeIPAClientProvider(providers.FreeIPAClientProviderConfig{Executor: exec}),
					executor:              exec,
				}
				planInput := PlanInput{WorkspaceDir: dir, HostName: hostName, Now: fixedNow,
					Catalog:   newCatalog(t, fakeComponentContract("freeipa-client", "freeipa-client")),
					Providers: map[string]providers.Provider{"freeipa-client": provider},
				}
				plan, err := PlanHost(context.Background(), planInput)
				if err != nil || plan.Blocked() {
					t.Fatalf("PlanHost = %+v, %v", plan, err)
				}
				assertGatewayScopeQueriesTarget(t, exec.gatewayTargets, want)
				path := filepath.Join(t.TempDir(), "identity.db")
				db, err := pstore.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = db.Close() })
				store := NewStore(db)
				if err := store.SavePlan(plan); err != nil {
					t.Fatal(err)
				}
				assertPlanIdentity(t, db, plan.ID, want)
				if mode == "resume before post-cleanup persistence" {
					// Older binaries wrote the address scalar and no plan FQDN.
					// Preserve their original resolved steps in the legacy JSON.
					record, err := db.GetDecommissionPlan(plan.ID)
					if err != nil {
						t.Fatal(err)
					}
					var legacy Plan
					if err := json.Unmarshal([]byte(record.PlanJSON), &legacy); err != nil {
						t.Fatal(err)
					}
					legacy.FQDN = ""
					for i := range legacy.Components {
						for j := range legacy.Components[i].Steps {
							legacy.Components[i].Steps[j].HostIdentitySource = ""
						}
					}
					payload, err := json.Marshal(legacy)
					if err != nil {
						t.Fatal(err)
					}
					record.PlanJSON, record.FQDN = string(payload), "10.0.0.9"
					if err := db.SaveDecommissionPlan(*record); err != nil {
						t.Fatal(err)
					}
					// Simulate cleanup completing before the process can persist
					// its post-cleanup plan. Resume reloads the original record.
					if err := executeComponents(context.Background(), plan, planInput.Providers); err != nil {
						t.Fatal(err)
					}
					plan, err = store.LoadPlan(plan.ID)
					if err != nil {
						t.Fatal(err)
					}
					if plan.FQDN != want {
						t.Fatalf("legacy LoadPlan FQDN = %q, want %q", plan.FQDN, want)
					}
				}
				if mode == "resume after post-cleanup persistence" {
					provider.verificationBlocked = true
					blocked, err := Apply(context.Background(), ApplyInput{Plan: plan, PlanInputForFreshness: planInput,
						DecommissionID: "identity", StartedAt: fixedNow(), Now: fixedNow, Store: store})
					if err != nil || blocked.Status != "blocked" {
						t.Fatalf("first Apply = %+v, %v, want blocked finalization", blocked, err)
					}
					assertPlanIdentity(t, db, plan.ID, want)
					plan, err = store.LoadPlan(plan.ID)
					if err != nil {
						t.Fatal(err)
					}
					provider.verificationBlocked = false
				}
				result, err := Apply(context.Background(), ApplyInput{Plan: plan, PlanInputForFreshness: planInput,
					DecommissionID: "identity", StartedAt: fixedNow(), Now: fixedNow, Store: store})
				if err != nil || result.Status != "completed" {
					t.Fatalf("Apply = %+v, %v; native canonical rejections=%v", result, err, exec.canonicalRejections)
				}
				if exec.present {
					t.Fatal("fixture did not delete the authoritative host object")
				}
				if result.Receipt.Host != hostName || result.Receipt.FQDN != want {
					t.Fatalf("receipt identity = %q / %q, want %q / %q", result.Receipt.Host, result.Receipt.FQDN, hostName, want)
				}
				assertGatewayScopeQueriesTarget(t, exec.gatewayTargets, want)
				assertGatewayScopeQueriesTarget(t, provider.verificationTargets, want)
				assertPlanIdentity(t, db, plan.ID, want)
				reader, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				defer reader.Close()
				var retired string
				if err := reader.QueryRow("SELECT fqdn FROM retired_hosts WHERE host = ?", hostName).Scan(&retired); err != nil || retired != want {
					t.Fatalf("retired fqdn = %q, %v, want %q", retired, err, want)
				}
				loaded, err := store.LoadPlan(plan.ID)
				if err != nil {
					t.Fatal(err)
				}
				queries := len(exec.gatewayTargets)
				replay, err := Apply(context.Background(), ApplyInput{Plan: loaded})
				if err != nil || replay.Status != "already_completed" || replay.Receipt.FQDN != want {
					t.Fatalf("replay = %+v, %v", replay, err)
				}
				if len(exec.gatewayTargets) != queries {
					t.Fatal("completed replay performed another gateway query")
				}
			})
		}
	}
}

func TestHostIdentity_BoundLifecycleRejectsIdentityChanges(t *testing.T) {
	for _, tc := range []struct {
		name       string
		hostName   string
		freshName  string
		present    bool
		want       string
		wantSource providers.HostIdentitySource
		wantStale  bool
	}{
		{"changed live canonical", "Client", "NEW.Example.TEST", true, "new.example.test", providers.HostIdentityAuthoritative, true},
		{"new live name equals alias but differs from plan", "ALIAS.example.test", "ALIAS.Example.TEST", true, "alias.example.test", providers.HostIdentityAuthoritative, true},
		{"unchanged live canonical", "Client", "OLD.Example.TEST", true, "old.example.test", providers.HostIdentityAuthoritative, false},
		{"confirmed native absence", "ALIAS.example.test", "", false, "old.example.test", providers.HostIdentityRecovered, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hostName, want := tc.hostName, tc.want
			dir := t.TempDir()
			writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML(hostName, "10.0.0.9", []string{"freeipa-client"}, ""))
			exec := &identityIPAExecutor{present: true, fqdn: "OLD.Example.TEST"}
			provider := &identityIPAProvider{
				FreeIPAClientProvider: providers.NewFreeIPAClientProvider(providers.FreeIPAClientProviderConfig{Executor: exec}),
				executor:              exec,
			}
			input := PlanInput{WorkspaceDir: dir, HostName: hostName, Now: fixedNow,
				Catalog:   newCatalog(t, fakeComponentContract("freeipa-client", "freeipa-client")),
				Providers: map[string]providers.Provider{"freeipa-client": provider},
			}
			plan, err := PlanHost(context.Background(), input)
			if err != nil || plan.Blocked() {
				t.Fatalf("PlanHost = %+v, %v", plan, err)
			}
			assertGatewayScopeQueriesTarget(t, exec.gatewayTargets, "old.example.test")
			path := filepath.Join(t.TempDir(), "identity-change.db")
			db, err := pstore.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			store := NewStore(db)
			if err := store.SavePlan(plan); err != nil {
				t.Fatal(err)
			}
			assertPlanIdentity(t, db, plan.ID, "old.example.test")

			// Step identities are outside the approval hash. Lifecycle replans
			// must therefore bind the prior canonical name independently.
			exec.fqdn, exec.present = tc.freshName, tc.present
			gatewayStart := len(exec.gatewayTargets)
			bound := input
			bound.previousPlan = plan
			fresh, err := CheckFreshness(context.Background(), bound, plan.PlanHash)
			if tc.wantStale {
				if ClassOf(err) != ErrPlanStale {
					t.Fatalf("changed live identity error = %v, want plan_stale", err)
				}
				_, err = Apply(context.Background(), ApplyInput{Plan: plan, PlanInputForFreshness: input, Now: fixedNow})
				if ClassOf(err) != ErrPlanStale || provider.cleanupTarget != "" || len(exec.gatewayTargets) != gatewayStart {
					t.Fatalf("identity drift reached cleanup/preflight: err=%v target=%q queries=%v", err, provider.cleanupTarget, exec.gatewayTargets)
				}
				return
			}
			if err != nil || fresh.InventoryRevision != plan.InventoryRevision || fresh.PlanHash != plan.PlanHash {
				t.Fatalf("fresh plan = %+v, %v; expected unchanged inventory and hash", fresh, err)
			}
			if _, source := freeIPAPlanIdentity(fresh); source != tc.wantSource {
				t.Fatalf("fresh identity source = %q, want %q", source, tc.wantSource)
			}
			gatewayWant := want
			assertGatewayScopeQueriesTarget(t, exec.gatewayTargets[gatewayStart:], gatewayWant)
			result, err := Apply(context.Background(), ApplyInput{Plan: plan, PlanInputForFreshness: input,
				DecommissionID: "identity-change", StartedAt: fixedNow(), Now: fixedNow, Store: store})
			if err != nil || result.Status != "completed" {
				t.Fatalf("Apply = %+v, %v", result, err)
			}
			if tc.present && !strings.EqualFold(provider.cleanupTarget, want) {
				t.Fatalf("cleanup target = %q, want %q", provider.cleanupTarget, want)
			}
			if result.Receipt.FQDN != want {
				t.Fatalf("receipt FQDN = %q, want actual cleanup identity %q", result.Receipt.FQDN, want)
			}
			assertPlanIdentity(t, db, plan.ID, want)
			reader, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			var retired string
			if err := reader.QueryRow("SELECT fqdn FROM retired_hosts WHERE host = ?", hostName).Scan(&retired); err != nil || retired != want {
				t.Fatalf("retired fqdn = %q, %v, want actual cleanup identity %q", retired, err, want)
			}
		})
	}
}

// This is the provider's explicit protocol observation, not IPA CLI output.
// Keep importer fixtures honest about the mandatory preflight and its actual
// authoritative/fallback identity, rather than returning a generic pass.
func assertGatewayScopeQueriesTarget(t *testing.T, targets []string, want string) {
	t.Helper()
	if len(targets) == 0 {
		t.Fatal("mandatory gateway_scope ownership query was not issued")
	}
	for _, target := range targets {
		if strings.ToLower(strings.TrimSuffix(target, ".")) != want {
			t.Fatalf("gateway_scope target=%q, want actual resolved identity %q", target, want)
		}
	}
}

func assertPlanIdentity(t *testing.T, db *pstore.Store, id, want string) {
	t.Helper()
	record, err := db.GetDecommissionPlan(id)
	if err != nil {
		t.Fatal(err)
	}
	if record.FQDN != want {
		t.Errorf("plan scalar FQDN = %q, want %q", record.FQDN, want)
	}
	var payload struct{ FQDN string }
	if err := json.Unmarshal([]byte(record.PlanJSON), &payload); err != nil || payload.FQDN != want {
		t.Errorf("plan JSON FQDN = %q, %v, want %q", payload.FQDN, err, want)
	}
}

func TestHostIdentity_MetadataUsesInventoryNameWithoutIPA(t *testing.T) {
	for _, hostName := range []string{"Client", "CLIENT.Example.TEST"} {
		t.Run(hostName, func(t *testing.T) {
			dir := newZeroRoleHostWorkspace(t, hostName)
			db := openTestStore(t)
			store := NewStore(db)
			plan := planZeroRoleHost(t, dir, hostName, store)
			want := strings.ToLower(hostName)
			assertPlanIdentity(t, db, plan.ID, want)
			result, err := Finalize(context.Background(), finalizeInputFor(dir, hostName, plan, nil, "fallback", store))
			if err != nil || result.Receipt.FQDN != want {
				t.Fatalf("Finalize = %+v, %v; want FQDN %q", result, err, want)
			}
		})
	}
}

func TestHostIdentity_DoesNotUseReferencedEndpointIdentity(t *testing.T) {
	plan := &Plan{
		ID: "endpoint-reference", Host: HostSnapshot{Name: "Client", AnsibleHost: "10.0.0.9"},
		Components: []ComponentPlan{{ComponentID: "internal-endpoint", Steps: []providers.Step{{
			Provider: "internal-endpoint", Phase: "central_cleanup", TargetIdentity: "endpoint.example.test",
		}}}},
	}
	db := openTestStore(t)
	if err := NewStore(db).SavePlan(plan); err != nil {
		t.Fatal(err)
	}
	assertPlanIdentity(t, db, plan.ID, "client")
	if plan.FQDN != "" {
		t.Fatal("SavePlan mutated its caller's plan")
	}
}

func TestHostIdentity_MetadataPreservesFreshnessChecks(t *testing.T) {
	const hostName = "Client"
	dir := newZeroRoleHostWorkspace(t, hostName)
	plan := planZeroRoleHost(t, dir, hostName, nil)
	plan.FQDN = "client.example.test"
	if got := computePlanHash(plan); got != plan.PlanHash {
		t.Fatalf("descriptive FQDN changed the approval hash: got %q, want %q", got, plan.PlanHash)
	}
	writeWorkspaceFile(t, dir, "hosts.yml", simpleHostsYAML(hostName, "10.0.0.10", nil, ""))
	_, err := Apply(context.Background(), ApplyInput{Plan: plan,
		PlanInputForFreshness: PlanInput{WorkspaceDir: dir, HostName: hostName, Catalog: newCatalogNoT(), Now: fixedNow},
	})
	if ClassOf(err) != ErrPlanStale {
		t.Fatalf("Apply after transport drift error = %v, want plan_stale", err)
	}
}
