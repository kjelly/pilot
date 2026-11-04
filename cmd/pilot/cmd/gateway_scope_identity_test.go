package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func gatewayIdentityInventory(t *testing.T, document string) string {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nprintf 'snapshot\\n' >> \"$PILOT_GATEWAY_SNAPSHOT_CALLS\"\nprintf '%s\\n' '" + document + "'\n"
	if err := os.WriteFile(filepath.Join(dir, "ansible-inventory"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PILOT_GATEWAY_SNAPSHOT_CALLS", filepath.Join(dir, "snapshot-calls"))
	return dir
}

const gatewayMappedInventory = `{"_meta":{"hostvars":{"transport-alias":{"ipa_client_fqdn":"KEEP.IPA227.TEST.","ansible_host":"192.0.2.7"},"duplicate":{"ipa_client_fqdn":"keep.ipa227.test"},"gateway":{"ipa_client_fqdn":"gateway.ipa227.test"},"shadow":{"ipa_client_fqdn":"GATEWAY.IPA227.TEST."}}},"all":{"children":["freeipa-client","pilot-access-gateway"]},"freeipa-client":{"children":["nested"]},"nested":{"hosts":["transport-alias","duplicate","gateway","shadow"]},"pilot-access-gateway":{"hosts":["gateway"]}}`

func TestGatewayScopeIdentityUsesOneSnapshotAndCanonicalGatewayExclusion(t *testing.T) {
	for _, request := range [][]string{{"all"}, {"transport-alias", "KEEP.IPA227.TEST.", "shadow"}} {
		t.Run(strings.Join(request, ","), func(t *testing.T) {
			gatewayIdentityInventory(t, gatewayMappedInventory)
			hosts, expanded, err := resolveGatewayScopeHosts(context.Background(), filepath.Join(t.TempDir(), "inventory.yml"), request)
			if err != nil || !slices.Equal(hosts, []string{"keep.ipa227.test"}) || expanded != (request[0] == "all") {
				t.Fatalf("canonical identities=%v expanded=%v err=%v", hosts, expanded, err)
			}
			calls, err := os.ReadFile(os.Getenv("PILOT_GATEWAY_SNAPSHOT_CALLS"))
			if err != nil || string(calls) != "snapshot\n" {
				t.Fatalf("groups and hostvars must come from exactly one coherent snapshot: %q %v", calls, err)
			}
		})
	}
}

func TestGatewayScopeIdentityRejectsMalformedMappingsAndAmbiguity(t *testing.T) {
	for _, value := range []any{"keep", "192.0.2.7", "keep..test", "bad_host.test", false, []string{"keep.ipa227.test"}} {
		t.Run(strings.TrimSpace(strings.ReplaceAll(strings.TrimSpace(stringMustJSON(t, value)), "/", "_")), func(t *testing.T) {
			doc := `{"_meta":{"hostvars":{"alias":{"ipa_client_fqdn":` + stringMustJSON(t, value) + `,"ansible_host":"keep.ipa227.test"}}},"all":{"hosts":["alias"]}}`
			gatewayIdentityInventory(t, doc)
			if _, _, err := resolveGatewayScopeHosts(context.Background(), filepath.Join(t.TempDir(), "inventory.yml"), []string{"alias"}); err == nil || !strings.Contains(err.Error(), "malformed ipa_client_fqdn") {
				t.Fatalf("malformed mapping must fail explicitly, got %v", err)
			}
		})
	}
	t.Run("ambiguous", func(t *testing.T) {
		gatewayIdentityInventory(t, `{"_meta":{"hostvars":{"Keep":{"ipa_client_fqdn":"keep.ipa227.test"},"keep":{"ipa_client_fqdn":"keep.other.test"}}},"all":{"hosts":["Keep","keep"]}}`)
		if _, _, err := resolveGatewayScopeHosts(context.Background(), filepath.Join(t.TempDir(), "inventory.yml"), []string{"keep"}); err == nil || !strings.Contains(err.Error(), "ambiguous inventory alias") {
			t.Fatalf("case-colliding inventory identity must fail explicitly, got %v", err)
		}
	})
	t.Run("legacy short never uses transport", func(t *testing.T) {
		gatewayIdentityInventory(t, `{"_meta":{"hostvars":{"keep":{"ansible_host":"192.0.2.7"}}},"all":{"hosts":["keep"]}}`)
		hosts, _, err := resolveGatewayScopeHosts(context.Background(), filepath.Join(t.TempDir(), "inventory.yml"), []string{"keep"})
		if err != nil || !slices.Equal(hosts, []string{"keep"}) {
			t.Fatalf("native legacy short must be resolved by IPA, never transport/suffix guessing: %v %v", hosts, err)
		}
	})
}

func stringMustJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestGatewayScopeIdentityFrontendToNativeHelperBoundary(t *testing.T) {
	for _, operation := range []string{"explicit", "all", "enable-auto", "retired-mapped-alias", "missing-mapping-counterexample"} {
		t.Run(operation, func(t *testing.T) {
			inventory := gatewayMappedInventory
			if operation == "missing-mapping-counterexample" {
				inventory = strings.Replace(inventory, `"ipa_client_fqdn":"KEEP.IPA227.TEST.",`, "", 1)
			}
			dir := gatewayIdentityInventory(t, inventory)
			modelPath, err := filepath.Abs("../../../scripts/test-freeipa-gateway-scope.py")
			if err != nil {
				t.Fatal(err)
			}
			// Exercise the actual frontend argv and production helper together.
			// Only the IPA backend is the captured-envelope model; native daemon
			// and real CLI all/enable-auto access remain the VM validation gate.
			program := "#!/usr/bin/env python3\nimport importlib.util,json,os,pathlib,sys\n" +
				"s=importlib.util.spec_from_file_location('gateway_model'," + stringMustJSON(t, modelPath) + ");m=importlib.util.module_from_spec(s);s.loader.exec_module(m)\n" +
				"hosts=next(json.loads(a)['gateway_scope_hosts'] for a in sys.argv[1:] if a.startswith('{') and 'gateway_scope_hosts' in a)\n" +
				"case=m.LifecycleTest();case.setUp();helper=case.helper()\n" +
				"if os.environ.get('PILOT_GATEWAY_RETIRED')=='1':\n case.state['retired']['keep.ipa227.test']={'status':'detached'}\n original=helper.show\n def guarded(kind,name,**options):\n  if kind=='host': raise AssertionError('retired identity must not require a host lookup')\n  return original(kind,name,**options)\n helper.show=guarded\n" +
				"try:\n r=helper.publish(case.state,dict(scope='i227-capture',hosts=hosts),True)\n pathlib.Path(os.environ['PILOT_GATEWAY_IDENTITY_OBSERVATION']).write_text(json.dumps(dict(hosts=hosts,plan=r)))\nfinally: case.doCleanups()\n"
			if err := os.WriteFile(filepath.Join(dir, "ansible-playbook"), []byte(program), 0o755); err != nil {
				t.Fatal(err)
			}
			observation := filepath.Join(dir, "identity-observation")
			t.Setenv("PILOT_GATEWAY_IDENTITY_OBSERVATION", observation)
			t.Setenv("PILOT_GATEWAY_RETIRED", "0")
			if operation == "retired-mapped-alias" {
				t.Setenv("PILOT_GATEWAY_RETIRED", "1")
			}
			oldScope, oldHosts, oldInventory, oldTarget, oldVault := gatewayScopeFlag, gatewayScopeHostsFlag, gatewayScopeInventory, gatewayScopeTargetGroup, gatewayScopeVaultFile
			oldDir, oldData, oldAdopt, oldAuto := gatewayScopeDirFlag, dataDir, gatewayScopeAdoptID, gatewayScopeAdoptAutoID
			t.Cleanup(func() {
				gatewayScopeFlag, gatewayScopeHostsFlag, gatewayScopeInventory, gatewayScopeTargetGroup, gatewayScopeVaultFile = oldScope, oldHosts, oldInventory, oldTarget, oldVault
				gatewayScopeDirFlag, dataDir, gatewayScopeAdoptID, gatewayScopeAdoptAutoID = oldDir, oldData, oldAdopt, oldAuto
			})
			gatewayScopeFlag, gatewayScopeHostsFlag = "i227-capture", []string{"transport-alias"}
			gatewayScopeInventory, gatewayScopeTargetGroup, gatewayScopeVaultFile = "inventory.yml", "freeipa-server", "/vault/vars.yaml"
			gatewayScopeDirFlag, dataDir, gatewayScopeAdoptID, gatewayScopeAdoptAutoID = dir, dir, "", ""
			command := &cobra.Command{}
			command.SetContext(context.Background())
			command.SetOut(&bytes.Buffer{})
			var stderr bytes.Buffer
			command.SetErr(&stderr)
			if operation == "enable-auto" {
				err = runGatewayScopeAutomember(command, true)
			} else {
				if operation == "all" {
					gatewayScopeHostsFlag = []string{"all"}
				}
				err = runGatewayScope(command, true)
			}
			if operation == "missing-mapping-counterexample" {
				if err == nil || !strings.Contains(err.Error(), "plan failed (exit=1)") || !strings.Contains(stderr.String(), "canonical FQDN") {
					t.Fatalf("old raw alias pass-through must fail at the native identity boundary: err=%v stderr=%s", err, stderr.String())
				}
				if _, err := os.Stat(observation); !os.IsNotExist(err) {
					t.Fatalf("unresolved raw alias produced an effective plan: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("actual frontend must reach canonical helper boundary: %v", err)
			}
			raw, err := os.ReadFile(observation)
			if err != nil {
				t.Fatal(err)
			}
			var got struct {
				Hosts []string                        `json:"hosts"`
				Plan  struct{ Add, Blocked []string } `json:"plan"`
			}
			if err := json.Unmarshal(raw, &got); err != nil || !slices.Equal(got.Hosts, []string{"keep.ipa227.test"}) {
				t.Fatalf("frontend/helper effective canonical identity mismatch: %s err=%v", raw, err)
			}
			if operation == "retired-mapped-alias" {
				if len(got.Plan.Add) != 0 || !slices.Equal(got.Plan.Blocked, got.Hosts) {
					t.Fatalf("mapped retired identity must be blocked without live lookup: %s", raw)
				}
			} else if !slices.Equal(got.Plan.Add, got.Hosts) {
				t.Fatalf("canonical active target must reach the helper plan: %s", raw)
			}
		})
	}
}
