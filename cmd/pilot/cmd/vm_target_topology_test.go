package cmd

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func TestVMTargetTopologyCmdRegistered(t *testing.T) {
	var found bool
	for _, c := range vmTargetCmd.Commands() {
		if c.Name() == "topology" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("topology subcommand not registered on vmTargetCmd")
	}
}

func TestVMTargetTopologySubCommandsAllRegistered(t *testing.T) {
	want := []string{"up", "down", "inventory", "status", "snapshot", "rollback", "reset"}
	var have []string
	for _, c := range vtTopologyCmd.Commands() {
		have = append(have, c.Name())
	}
	for _, w := range want {
		ok := false
		for _, h := range have {
			if h == w {
				ok = true
				break
			}
		}
		if !ok {
			t.Errorf("topology subcommand %q missing; have %v", w, have)
		}
	}
}

func TestRunVtTopologyUp_RequiresSpecFlag(t *testing.T) {
	vtTopoSpecPath = ""
	rootCmd.SetArgs([]string{"vm-target", "topology", "up"})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "topology") {
		t.Fatalf("want a missing --topology error, got %v", err)
	}
}

func TestRunVtTopologyUp_MissingSpecFileErrors(t *testing.T) {
	vtTopoSpecPath = "/nonexistent/topology.yaml"
	rootCmd.SetArgs([]string{"vm-target", "topology", "up", "--topology", vtTopoSpecPath})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "topology spec") {
		t.Fatalf("want a topology-spec load error, got %v", err)
	}
}

func TestRunVtTopologySnapshot_RequiresTagFlag(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/topo.yaml"
	if err := os.WriteFile(path, []byte("nodes:\n  - name: a\n"), 0o644); err != nil {
		t.Fatalf("write spec: %v", err)
	}
	rootCmd.SetArgs([]string{"vm-target", "topology", "snapshot", "--topology", path})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "tag") {
		t.Fatalf("want a missing --tag error, got %v", err)
	}
}

func TestRunVtTopologyRollback_RequiresTagFlag(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/topo.yaml"
	if err := os.WriteFile(path, []byte("nodes:\n  - name: a\n"), 0o644); err != nil {
		t.Fatalf("write spec: %v", err)
	}
	rootCmd.SetArgs([]string{"vm-target", "topology", "rollback", "--topology", path})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "tag") {
		t.Fatalf("want a missing --tag error, got %v", err)
	}
}

func TestRunVtTopologyReset_MissingSpecFileErrors(t *testing.T) {
	vtTopoSpecPath = "/nonexistent/topology.yaml"
	rootCmd.SetArgs([]string{"vm-target", "topology", "reset", "--topology", vtTopoSpecPath})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "topology spec") {
		t.Fatalf("want a topology-spec load error, got %v", err)
	}
}

func TestRunVtTopologyInventory_RequiresGroups(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/no-groups.yaml"
	if err := os.WriteFile(path, []byte("nodes:\n  - name: a\n"), 0o644); err != nil {
		t.Fatalf("write spec: %v", err)
	}
	vtTopoSpecPath = path
	vtTopoOut = ""
	rootCmd.SetArgs([]string{"vm-target", "topology", "inventory", "--topology", path})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "declares no node 'groups:'") {
		t.Fatalf("want a no-groups error, got %v", err)
	}
}

func TestParseTopoVerifyArgs(t *testing.T) {
	got, err := parseTopoVerifyArgs([]string{
		"docs/verification/freeipa-server.md=ipa_masters",
		"docs/verification/freeipa-client.md",
		"docs/verification/x.md=ipa_masters:ipa_replicas",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []topoVerify{
		{spec: "docs/verification/freeipa-server.md", limit: "ipa_masters"},
		{spec: "docs/verification/freeipa-client.md", limit: ""},
		{spec: "docs/verification/x.md", limit: "ipa_masters:ipa_replicas"},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: got %+v, want %+v", i, got[i], want[i])
		}
	}

	if _, err := parseTopoVerifyArgs([]string{"=ipa_masters"}); err == nil {
		t.Error("empty spec path must be rejected")
	}
}

func TestTopologyTestEphemeralFlagsRegistered(t *testing.T) {
	for _, name := range []string{"ephemeral", "keep-on-failure"} {
		flag := vtTopologyTestCmd.Flags().Lookup(name)
		if flag == nil {
			t.Fatalf("topology test flag %q is not registered", name)
		}
		if flag.Value.Type() != "bool" {
			t.Errorf("topology test flag %q type = %s, want bool", name, flag.Value.Type())
		}
	}
}

func TestValidateTopologyTestMode(t *testing.T) {
	if err := validateTopologyTestMode(false, false); err != nil {
		t.Fatalf("normal topology test rejected: %v", err)
	}
	if err := validateTopologyTestMode(true, false); err != nil {
		t.Fatalf("ephemeral default cleanup rejected: %v", err)
	}
	if err := validateTopologyTestMode(true, true); err != nil {
		t.Fatalf("ephemeral keep-on-failure rejected: %v", err)
	}
	err := validateTopologyTestMode(false, true)
	if err == nil || !strings.Contains(err.Error(), "--keep-on-failure requires --ephemeral") {
		t.Fatalf("want keep-on-failure mode error, got %v", err)
	}
}

func TestPrintEphemeralDebugHints(t *testing.T) {
	var got bytes.Buffer
	printEphemeralDebugHints(&got, "tmp/topology.yaml")
	for _, want := range []string{
		"--keep-on-failure preserved",
		"topology status --topology tmp/topology.yaml",
		"topology inventory --topology tmp/topology.yaml",
		"topology down --topology tmp/topology.yaml",
	} {
		if !strings.Contains(got.String(), want) {
			t.Errorf("debug hints missing %q:\n%s", want, got.String())
		}
	}
}
