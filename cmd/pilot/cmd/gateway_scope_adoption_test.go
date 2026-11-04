package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestGatewayScopeAdoptionRejectsNamesAndIncompleteAuthorization(t *testing.T) {
	group := "6b3d399c-d833-11f1-8d71-525400b6d333"
	rule := "863b583a-b4ec-4870-8fe2-f0743606c31a"
	for _, tc := range []struct{ group, rule string }{
		{"pilot-target-prefix", ""}, {"", rule}, {group, "same-name-rule"},
	} {
		if _, err := appendGatewayScopeAutomemberAdoption(nil, tc.group, tc.rule); err == nil {
			t.Fatalf("accepted non-exact or incomplete adoption: %+v", tc)
		}
	}
	args, err := appendGatewayScopeAutomemberAdoption([]string{"playbook.yml", "-e", "@operator-vars"}, strings.ToUpper(group), strings.ToUpper(rule))
	if err != nil {
		t.Fatal(err)
	}
	want := "playbook.yml -e @operator-vars -e gateway_scope_adopt_id=" + group + " -e gateway_scope_adopt_automember_id=" + rule
	if strings.Join(args, " ") != want {
		t.Fatalf("adoption must follow operator vars with exact normalized IDs: %v", args)
	}
}

func TestGatewayScopePlanFrontendPassesExplicitAdoption(t *testing.T) {
	dir := t.TempDir()
	argsPath := filepath.Join(dir, "actual-argv")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$PILOT_GATEWAY_SCOPE_ARGS\"\n"
	if err := os.WriteFile(filepath.Join(dir, "ansible-playbook"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PILOT_GATEWAY_SCOPE_ARGS", argsPath)
	originalScope, originalHosts, originalVault := gatewayScopeFlag, gatewayScopeHostsFlag, gatewayScopeVaultFile
	originalDataDir := dataDir
	originalGroup, originalAuto := gatewayScopeAdoptID, gatewayScopeAdoptAutoID
	for _, name := range []string{"adopt-group-id", "adopt-automember-id"} {
		flag := gatewayScopePlanCmd.Flags().Lookup(name)
		value, changed := flag.Value.String(), flag.Changed
		t.Cleanup(func() {
			_ = flag.Value.Set(value)
			flag.Changed = changed
		})
	}
	t.Cleanup(func() {
		gatewayScopeFlag, gatewayScopeHostsFlag, gatewayScopeVaultFile = originalScope, originalHosts, originalVault
		gatewayScopeAdoptID, gatewayScopeAdoptAutoID, dataDir = originalGroup, originalAuto, originalDataDir
	})
	dataDir = dir
	gatewayScopeFlag, gatewayScopeHostsFlag, gatewayScopeVaultFile = "i227", []string{"keep.ipa227.test"}, "/vault/vars.yaml"
	group, rule := "6b3d399c-d833-11f1-8d71-525400b6d333", "863b583a-b4ec-4870-8fe2-f0743606c31a"
	if err := gatewayScopePlanCmd.ParseFlags([]string{"--adopt-group-id", group, "--adopt-automember-id", rule}); err != nil {
		t.Fatal(err)
	}
	command := &cobra.Command{}
	command.SetContext(context.Background())
	command.SetOut(&bytes.Buffer{})
	if err := gatewayScopePlanCmd.RunE(command, nil); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"gateway_scope_adopt_id=" + group, "gateway_scope_adopt_automember_id=" + rule, "gateway_scope_plan_only=true"} {
		if !strings.Contains(string(actual), want) {
			t.Fatalf("frontend did not pass explicit adoption/readonly contract %s: %s", want, actual)
		}
	}
}
