package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/statefile"
	"github.com/kjelly/pilot/internal/vmtarget"
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
	// The command opens a vm-target manager through resolveStateDir. With
	// --data-dir set it skips the legacy-location notice, which would
	// otherwise look for the operator's real ~/.local/share/pilot/vm-targets.json.
	savedDataDir := dataDir
	dataDir = dir + "/data"
	t.Cleanup(func() { dataDir = savedDataDir })
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

// TestTopologyUpFreshRefusesAnExistingNode: vm-target is shared by every
// clone and session on the host. Plain `topology up` adopts a running VM
// with a declared name, and scripts/topology-checkmode-test.sh then tore it
// down on exit. `up --fresh` must refuse before touching libvirt and leave
// that VM and its state alone.
func TestTopologyUpFreshRefusesAnExistingNode(t *testing.T) {
	isolateDataDirInputs(t)
	dir := t.TempDir()
	dataDir = filepath.Join(dir, "data")
	oldVMDir, oldSpec, oldFresh := vtVMDir, vtTopoSpecPath, vtTopoUpFresh
	t.Cleanup(func() { vtVMDir, vtTopoSpecPath, vtTopoUpFresh = oldVMDir, oldSpec, oldFresh })
	vtVMDir = filepath.Join(dir, "vmdir")

	// Another session's running VM named like a node of this topology.
	saveVMTargetState(t, dataDir, "nexus")
	virshLog := filepath.Join(dir, "virsh.log")
	shim := filepath.Join(dir, "virsh")
	script := "#!/bin/sh\necho \"$@\" >> " + virshLog + "\n[ \"$1\" = domstate ] && echo running\nexit 0\n"
	if err := os.WriteFile(shim, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PILOT_VIRSH_BIN", shim)
	topo := filepath.Join(dir, "topology.yaml")
	if err := os.WriteFile(topo, []byte("nodes:\n  - name: mine\n  - name: nexus\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	rootCmd.SetArgs([]string{"vm-target", "topology", "up", "--fresh", "--topology", topo})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	t.Cleanup(func() { rootCmd.SetOut(nil); rootCmd.SetErr(nil); rootCmd.SetArgs(nil) })
	err := rootCmd.Execute()
	if err == nil || !strings.Contains(err.Error(), `--fresh requires node "nexus" to be absent`) {
		t.Fatalf("want the --fresh refusal for nexus, got %v", err)
	}

	calls, _ := os.ReadFile(virshLog)
	for _, line := range strings.Split(strings.TrimSpace(string(calls)), "\n") {
		if line != "" && !strings.HasPrefix(line, "domstate ") {
			t.Errorf("--fresh touched libvirt before refusing: virsh %s", line)
		}
	}
	store, err := statefile.New[vmtarget.Target](dataDir, "vm-targets.json", 1, "vmtarget")
	if err != nil {
		t.Fatal(err)
	}
	targets, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) != 1 || targets[0].Name != "nexus" {
		t.Fatalf("state changed: %+v", targets)
	}
}

func TestTopologyUpFreshFlagRegistered(t *testing.T) {
	if vtTopologyUpCmd.Flags().Lookup("fresh") == nil {
		t.Fatal("topology up --fresh not registered")
	}
}
