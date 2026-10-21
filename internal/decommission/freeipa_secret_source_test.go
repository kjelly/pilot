package decommission

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/ansible"
	"github.com/kjelly/pilot/internal/contract"
	"github.com/kjelly/pilot/internal/decommission/providers"
)

// Return an unchanged captured Ansible transcript. No live host is contacted,
// and both planning and execution use the production provider implementations.
type decommissionRosterFixtureRunner struct{ stdout string }

func (r decommissionRosterFixtureRunner) Run(context.Context, ...string) (*ansible.Result, error) {
	return &ansible.Result{Stdout: r.stdout}, nil
}

func TestDecommissionRosterSourceBoundary(t *testing.T) {
	for _, kind := range []string{"freeipa-client", "freeipa-nfs-server"} {
		for _, tree := range []string{"group_vars", "host_vars"} {
			for _, nested := range []bool{false, true} {
				for _, late := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%s/nested=%t/late=%t", kind, tree, nested, late), func(t *testing.T) {
						in, roster, original := setupDecommissionRosterSource(t, kind)
						alias := filepath.Join(in.WorkspaceDir, tree)
						if nested {
							if err := os.Mkdir(alias, 0o700); err != nil {
								t.Fatal(err)
							}
							alias = filepath.Join(alias, "all")
						}
						installAlias := func() {
							if err := os.Symlink(filepath.Dir(roster), alias); err != nil {
								t.Fatal(err)
							}
						}
						if !late {
							installAlias()
						}
						plan, err := PlanHost(context.Background(), in)
						if err != nil {
							t.Fatal(err)
						}
						if plan.Blocked() {
							if late {
								t.Fatalf("safe source blocked before alias installed: %+v", blockerDetails(plan))
							}
							if !strings.Contains(fmt.Sprint(blockerDetails(plan)), "outside group_vars/ and host_vars/") {
								t.Fatalf("unexpected planning blocker: %+v", blockerDetails(plan))
							}
						} else {
							if late {
								installAlias()
							}
							err := executeComponents(context.Background(), plan, in.Providers)
							if err == nil || !strings.Contains(err.Error(), "outside group_vars/ and host_vars/") {
								t.Errorf("expected roster-source refusal, got %v", err)
							}
						}
						after, err := os.ReadFile(roster)
						if err != nil {
							t.Fatal(err)
						}
						if !bytes.Equal(original, after) {
							t.Error("selected inventory vars alias allowed credential-bearing roster bytes to change")
						}
					})
				}
			}
		}
	}
}

func TestDecommissionRosterSourceExternalAllowed(t *testing.T) {
	for _, kind := range []string{"freeipa-client", "freeipa-nfs-server"} {
		t.Run(kind, func(t *testing.T) {
			in, roster, original := setupDecommissionRosterSource(t, kind)
			plan, err := PlanHost(context.Background(), in)
			if err != nil {
				t.Fatal(err)
			}
			if plan.Blocked() {
				t.Fatalf("safe source blocked: %+v", blockerDetails(plan))
			}
			if err := executeComponents(context.Background(), plan, in.Providers); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(roster)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Equal(original, after) || !bytes.Contains(after, []byte("state: absent")) {
				t.Fatal("external roster did not converge to absent")
			}
			if !bytes.Contains(after, []byte("test-decommission-password")) {
				t.Fatal("roster credentials were not preserved")
			}
			// Resume builds fresh executors and must observe the already
			// converged roster, without rewriting any source bytes.
			if err := executeComponents(context.Background(), plan, in.Providers); err != nil {
				t.Fatal(err)
			}
			resumed, err := os.ReadFile(roster)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, resumed) {
				t.Fatal("resumed converged source changed")
			}
		})
	}
}

func setupDecommissionRosterSource(t *testing.T, kind string) (PlanInput, string, []byte) {
	t.Helper()
	const target = "pwc-host2.ipa.pilot.internal"
	workspace, external := t.TempDir(), t.TempDir()
	roster := filepath.Join(external, "roster.yaml")
	fixture := "schema_version: 2\nfreeipa:\n  domain: ipa.pilot.internal\n  admin: {principal: admin, password: test-decommission-password}\n"
	if kind == "freeipa-client" {
		fixture += "hosts:\n  - name: " + target + "\n    state: present\n    ip_address: 10.0.0.5\nhostgroups:\n  - name: web-servers\n    membership: {hosts: [" + target + "]}\n"
	} else {
		fixture += "nfs:\n  servers:\n    - host: " + target + "\n      state: present\n      service_principal:\n        ensure: true\n        principal: nfs/" + target + "\n        keytab: /etc/krb5.keytab\n      shares: []\n"
	}
	if err := os.WriteFile(roster, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	writeWorkspaceFile(t, workspace, "hosts.yml", simpleHostsYAML(target, "10.0.0.5", []string{kind}, fmt.Sprintf("    freeipa_roster_file: %q\n    env: sandbox\n", roster)))
	inv := writeWorkspaceFile(t, workspace, "inventory.yml", "all:\n  hosts:\n    "+target+": {}\n")
	captured, err := os.ReadFile(filepath.Join("providers", "testdata", "inspect", "host-object-present-with-tombstone.stdout"))
	if err != nil {
		t.Fatal(err)
	}
	// The captured pwc-host2 block proves an absent host with zero services;
	// the other host's HTTP principal remains in the untouched transcript.
	runner := decommissionRosterFixtureRunner{stdout: string(captured)}
	var provider providers.Provider
	if kind == "freeipa-client" {
		provider = providers.NewFreeIPAClientProvider(providers.FreeIPAClientProviderConfig{
			Executor: runner, ClientInventory: inv, ServerInventory: inv,
			DecommissionPlaybook:  "playbooks/decommission/freeipa-client-decommission.yml",
			IdentityApplyPlaybook: "playbooks/apply/freeipa-identity-apply.yml",
			ExtraArgs:             []string{"-e", "freeipa_roster_file=" + roster},
		})
	} else {
		provider = providers.NewFreeIPANFSServerProvider(providers.FreeIPANFSServerProviderConfig{
			Executor: runner, Inventory: inv,
			DecommissionPlaybook: "playbooks/decommission/freeipa-nfs-server-decommission.yml",
			ExtraArgs:            []string{"-e", "freeipa_roster_file=" + roster},
		})
	}
	component := contract.Contract{ID: kind, Role: kind}
	dispositions := map[string]RetentionDisposition{}
	if kind == "freeipa-nfs-server" {
		component.Lifecycle.Decommission = &contract.DecommissionPolicy{Class: "stateful", Retention: "required", RequiresReachableHost: true}
		dispositions[kind] = RetentionDispositionExported
	}
	return PlanInput{
		WorkspaceDir: workspace, HostName: target, Catalog: newCatalog(t, component), Now: fixedNow,
		Providers: map[string]providers.Provider{kind: provider}, RetentionDispositions: dispositions,
	}, roster, []byte(fixture)
}
