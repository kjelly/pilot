package outbound

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/kjelly/pilot/internal/inventory"
	"go.yaml.in/yaml/v3"
)

const externalProjectionHost = "nas.ipa.pilot.internal"

func writeExternalProjectionRoster(t *testing.T, dir string, root map[string]any) string {
	t.Helper()
	data, err := yaml.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "external-roster.yaml")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func externalProjectionRoster(t *testing.T, path string) map[string]any {
	t.Helper()
	root, err := inventory.ReadRosterAsMapWithVault(path, "")
	if err != nil {
		t.Fatal(err)
	}
	root["hosts"] = append(root["hosts"].([]any), map[string]any{
		"name": externalProjectionHost, "state": "present", "ip_address": "10.0.1.50",
	})
	return root
}

// Runs under the existing C22/P20 probe as well as the package suite.
func testProjectionExternalDevices(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	baseline := buildTestProjection(t, dir, rosterPath)
	root := externalProjectionRoster(t, rosterPath)
	path := writeExternalProjectionRoster(t, dir, root)
	result := buildTestProjection(t, dir, path)
	if !baseline.Available || !result.Available {
		t.Fatalf("external NFS device disabled projection: baseline=%v external=%v", baseline.ErrorClass, result.ErrorClass)
	}
	if !reflect.DeepEqual(baseline.Snapshot, result.Snapshot) {
		t.Fatal("an unreferenced external device changed the inventory-scoped snapshot")
	}
	if SnapshotID(baseline.Snapshot) != SnapshotID(result.Snapshot) {
		t.Fatal("an unreferenced external device changed the snapshot ID")
	}
	env, err := BuildEnvelope(BuildEnvelopeParams{
		Payload: PayloadBoth, Projection: result, Target: result.Snapshot,
		Base: SnapshotRef{ID: SnapshotID(baseline.Snapshot), JSON: mustExternalSnapshotJSON(t, baseline.Snapshot)},
		Op:   OperationMetadata{Operation: OperationReconcile, Result: ResultSuccess}, Authoritative: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !env.State.Available || !env.State.SourceComplete || !env.State.Authoritative || len(env.Snapshot) == 0 {
		t.Fatalf("external device prevented authoritative full snapshot publication: %+v", env.State)
	}
	diff := Diff(baseline.Snapshot, result.Snapshot, false)
	if len(diff.Hosts.Upsert)+len(diff.Hosts.Delete)+len(diff.LoginAccess.Delete)+len(diff.SudoAccess.Delete) != 0 {
		t.Fatal("external-only roster addition generated managed host/access changes")
	}
}

func mustExternalSnapshotJSON(t *testing.T, snapshot UserHostAccessSnapshotV1) json.RawMessage {
	t.Helper()
	data, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestOutboundProjection_ExternalHostTargets(t *testing.T) {
	for _, mode := range []string{"external_only", "mixed", "nested_external_only", "nested_mixed"} {
		t.Run(mode, func(t *testing.T) {
			dir, rosterPath := writeProjectionFixture(t)
			root := externalProjectionRoster(t, rosterPath)
			targetHosts := []any{externalProjectionHost}
			mixed := strings.HasSuffix(mode, "mixed")
			wantHosts := 0
			if mixed {
				targetHosts = append(targetHosts, "web1.ipa.pilot.internal")
				wantHosts = 1
			}
			root["hostgroups"] = append(root["hostgroups"].([]any),
				map[string]any{"name": "external-members", "membership": map[string]any{"hosts": targetHosts}},
				map[string]any{"name": "external-parent", "membership": map[string]any{"hostgroups": []any{"external-members"}}},
			)
			targets := map[string]any{"hosts": targetHosts}
			if strings.HasPrefix(mode, "nested") {
				targets = map[string]any{"hostgroups": []any{"external-parent"}}
			}
			for _, section := range []string{"hbac", "sudo"} {
				rules := root[section].(map[string]any)["rules"].([]any)
				rules[0].(map[string]any)["targets"] = targets
			}
			for _, raw := range root["grants"].([]any) {
				raw.(map[string]any)["targets"] = targets
			}
			path := writeExternalProjectionRoster(t, dir, root)
			result := BuildProjection(ProjectionRequest{
				WorkspaceDir: dir, HostVars: hostVarsForRoster(path, "web1"), Now: projectionTestNow,
				BreakglassActivations: []inventory.BreakglassActivationInput{{Name: "bg-emergency", ExpiresAt: projectionTestNow.Add(time.Hour)}},
			})
			if !result.Available {
				t.Fatalf("declared external host targets disabled snapshot: %s", result.ErrorClass)
			}
			if len(result.Snapshot.Hosts) != 2 || len(result.Snapshot.Users) != 3 || len(result.Snapshot.Groups) != 2 {
				t.Fatal("external targets changed managed hosts, users, or groups")
			}
			for _, id := range []string{"static_hbac:allow-team", "temporary_grant:vendor-active", "breakglass:bg-emergency"} {
				rule, present := findLogin(result.Snapshot.Access.Login, id)
				if present != mixed || (present && (rule.AllHosts || !reflect.DeepEqual(rule.HostIDs, []string{"inventory:web1"}))) {
					t.Fatalf("login %s must retain only inventory targets: present=%v rule=%+v", id, present, rule)
				}
			}
			for _, id := range []string{"static_sudo:sudo-ops", "sudo_grant:sudo-active-grant"} {
				rule, present := findSudo(result.Snapshot.Access.Sudo, id)
				if present != mixed || (present && (rule.AllHosts || !reflect.DeepEqual(rule.HostIDs, []string{"inventory:web1"}))) {
					t.Fatalf("sudo %s must retain only inventory targets: present=%v rule=%+v", id, present, rule)
				}
			}
			for _, hg := range result.Snapshot.Hostgroups {
				if hg.Name == "external-members" || hg.Name == "external-parent" {
					if len(hg.EffectiveHostIDs) != wantHosts {
						t.Fatalf("hostgroup %s retained external targets: %+v", hg.Name, hg)
					}
				}
			}
			data := string(mustExternalSnapshotJSON(t, result.Snapshot))
			if strings.Contains(data, externalProjectionHost) || strings.Contains(data, `"host_ids":[""]`) {
				t.Fatal("snapshot retained an external or empty host ID")
			}
			// Existing hostcat:all rules retain their inventory-scoped semantics.
			if rule, present := findLogin(result.Snapshot.Access.Login, "static_hbac:allow-direct"); !present || !rule.AllHosts {
				t.Fatal("external filtering changed an existing all-host login rule")
			}
		})
	}
}

func TestOutboundProjection_ExternalTargetsWithdrawManagedAccess(t *testing.T) {
	dir, rosterPath := writeProjectionFixture(t)
	root := externalProjectionRoster(t, rosterPath)
	setTargets := func(hosts []any) {
		for _, section := range []string{"hbac", "sudo"} {
			rule := root[section].(map[string]any)["rules"].([]any)[0].(map[string]any)
			rule["targets"] = map[string]any{"hosts": hosts}
		}
	}
	setTargets([]any{"web1.ipa.pilot.internal", externalProjectionHost})
	path := writeExternalProjectionRoster(t, dir, root)
	before := buildTestProjection(t, dir, path)
	setTargets([]any{externalProjectionHost})
	path = writeExternalProjectionRoster(t, dir, root)
	after := buildTestProjection(t, dir, path)
	if !before.Available || !after.Available {
		t.Fatal("withdrawing the last managed target must keep the snapshot available")
	}
	diff := Diff(before.Snapshot, after.Snapshot, false)
	if !reflect.DeepEqual(diff.LoginAccess.Delete, []string{"static_hbac:allow-team"}) ||
		!reflect.DeepEqual(diff.SudoAccess.Delete, []string{"static_sudo:sudo-ops"}) {
		t.Fatalf("removing the last managed target must publish access revocation: login=%v sudo=%v", diff.LoginAccess.Delete, diff.SudoAccess.Delete)
	}
	if !reflect.DeepEqual(before.Snapshot.Hosts, after.Snapshot.Hosts) || !reflect.DeepEqual(before.Snapshot.Users, after.Snapshot.Users) {
		t.Fatal("access revocation removed unrelated managed host/user data")
	}
}
