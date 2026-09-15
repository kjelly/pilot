package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestNormalizeGatewayScopeHostRequestAllIsExplicitAndExclusive(t *testing.T) {
	hosts, expanded, err := normalizeGatewayScopeHostRequest([]string{"all"})
	if err != nil {
		t.Fatalf("normalizeGatewayScopeHostRequest(all): %v", err)
	}
	if !expanded || !slices.Equal(hosts, []string{"all"}) {
		t.Fatalf("normalized all = (%v, %v), want ([all], true)", hosts, expanded)
	}

	for _, requested := range [][]string{nil, {""}, {"all", "host-a"}, {"host-a", "all"}} {
		if _, _, err := normalizeGatewayScopeHostRequest(requested); err == nil {
			t.Errorf("normalizeGatewayScopeHostRequest(%v) error = nil, want fail closed", requested)
		}
	}
}

func TestResolveGatewayScopeHostsAllUsesOnlyFreeIPAClientGroup(t *testing.T) {
	binDir := t.TempDir()
	invJSON := `{"_meta":{"hostvars":{}},"all":{"hosts":["outside-all"],"children":["freeipa-client"]},"freeipa-client":{"hosts":["client-b","client-a"]}}`
	script := "#!/bin/sh\nprintf '%s\\n' '" + invJSON + "'\n"
	if err := os.WriteFile(filepath.Join(binDir, "ansible-inventory"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	hosts, expanded, err := resolveGatewayScopeHosts(context.Background(), "inventory.yml", []string{"all"})
	if err != nil {
		t.Fatalf("resolveGatewayScopeHosts(all): %v", err)
	}
	if !expanded {
		t.Fatal("resolveGatewayScopeHosts(all) expanded = false, want true")
	}
	want := []string{"client-a", "client-b"}
	if !slices.Equal(hosts, want) {
		t.Fatalf("resolved hosts = %v, want %v", hosts, want)
	}
}

// TestResolveGatewayScopeHostsAllExcludesGatewayHosts guards against the bug
// found live 2026-09-15 (docs/evidence/pilot-gateway-scope/2026-09-15-all-
// keyword.md): every pilot-access-gateway host is structurally also a
// freeipa-client host (contracts/pilot-access-gateway.yaml declares
// freeipa-client as a required sameHosts dependency), so a naive expansion
// of "all" published every gateway — including itself — as one of its own
// SSH targets. "all" must resolve to freeipa-client minus pilot-access-
// gateway.
func TestResolveGatewayScopeHostsAllExcludesGatewayHosts(t *testing.T) {
	binDir := t.TempDir()
	invJSON := `{"_meta":{"hostvars":{}},"all":{"children":["freeipa-client","pilot-access-gateway"]},` +
		`"freeipa-client":{"hosts":["gw-a","gw-b","target-a"]},` +
		`"pilot-access-gateway":{"hosts":["gw-a","gw-b"]}}`
	script := "#!/bin/sh\nprintf '%s\\n' '" + invJSON + "'\n"
	if err := os.WriteFile(filepath.Join(binDir, "ansible-inventory"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	hosts, expanded, err := resolveGatewayScopeHosts(context.Background(), "inventory.yml", []string{"all"})
	if err != nil {
		t.Fatalf("resolveGatewayScopeHosts(all): %v", err)
	}
	if !expanded {
		t.Fatal("resolveGatewayScopeHosts(all) expanded = false, want true")
	}
	want := []string{"target-a"}
	if !slices.Equal(hosts, want) {
		t.Fatalf("resolved hosts = %v, want %v (gateway hosts gw-a/gw-b must be excluded)", hosts, want)
	}
}

// TestResolveGatewayScopeHostsAllFailsWhenEveryHostIsAGateway proves the
// exclusion fails closed (a clear error) rather than silently publishing an
// empty target hostgroup when every freeipa-client host happens to be a
// pilot-access-gateway host.
func TestResolveGatewayScopeHostsAllFailsWhenEveryHostIsAGateway(t *testing.T) {
	binDir := t.TempDir()
	invJSON := `{"_meta":{"hostvars":{}},"all":{"children":["freeipa-client","pilot-access-gateway"]},` +
		`"freeipa-client":{"hosts":["gw-a"]},"pilot-access-gateway":{"hosts":["gw-a"]}}`
	script := "#!/bin/sh\nprintf '%s\\n' '" + invJSON + "'\n"
	if err := os.WriteFile(filepath.Join(binDir, "ansible-inventory"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if _, _, err := resolveGatewayScopeHosts(context.Background(), "inventory.yml", []string{"all"}); err == nil {
		t.Fatal("resolveGatewayScopeHosts(all) error = nil, want a fail-closed error when every host is a gateway")
	}
}

func TestResolveGatewayScopeHostsAllRequiresNonEmptyFreeIPAClientGroup(t *testing.T) {
	binDir := t.TempDir()
	script := "#!/bin/sh\nprintf '%s\\n' '{\"_meta\":{\"hostvars\":{}},\"all\":{\"hosts\":[]}}'\n"
	if err := os.WriteFile(filepath.Join(binDir, "ansible-inventory"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	if _, _, err := resolveGatewayScopeHosts(context.Background(), "inventory.yml", []string{"all"}); err == nil {
		t.Fatal("resolveGatewayScopeHosts(all) error = nil, want missing freeipa-client group error")
	} else if !strings.Contains(err.Error(), `freeipa-client`) {
		t.Fatalf("resolveGatewayScopeHosts(all) error = %v, want freeipa-client detail", err)
	}
}

func TestRunGatewayScopeAllPassesExpandedHostsToPlaybook(t *testing.T) {
	binDir := t.TempDir()
	argsPath := filepath.Join(t.TempDir(), "ansible-playbook-args")
	invJSON := `{"_meta":{"hostvars":{}},"all":{"hosts":["outside-all"],"children":["freeipa-client"]},"freeipa-client":{"hosts":["client-b","client-a"]}}`
	inventoryScript := "#!/bin/sh\nprintf '%s\\n' '" + invJSON + "'\n"
	playbookScript := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$PILOT_GATEWAY_SCOPE_ARGS\"\n"
	for name, script := range map[string]string{
		"ansible-inventory": inventoryScript,
		"ansible-playbook":  playbookScript,
	} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PILOT_GATEWAY_SCOPE_ARGS", argsPath)

	original := struct {
		scope       string
		hosts       []string
		inventory   string
		targetGroup string
		vaultFile   string
		timeout     time.Duration
		dataDir     string
	}{
		gatewayScopeFlag,
		gatewayScopeHostsFlag,
		gatewayScopeInventory,
		gatewayScopeTargetGroup,
		gatewayScopeVaultFile,
		gatewayScopeTimeout,
		dataDir,
	}
	t.Cleanup(func() {
		gatewayScopeFlag = original.scope
		gatewayScopeHostsFlag = original.hosts
		gatewayScopeInventory = original.inventory
		gatewayScopeTargetGroup = original.targetGroup
		gatewayScopeVaultFile = original.vaultFile
		gatewayScopeTimeout = original.timeout
		dataDir = original.dataDir
	})
	dataDir = t.TempDir()
	gatewayScopeFlag = "all"
	gatewayScopeHostsFlag = []string{"all"}
	gatewayScopeInventory = "inventory.yml"
	gatewayScopeTargetGroup = "freeipa-server"
	gatewayScopeVaultFile = "/vault/main.yaml"

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetOut(&out)
	if err := runGatewayScope(cmd, true); err != nil {
		t.Fatalf("runGatewayScope(all): %v", err)
	}
	raw, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	args := strings.Fields(string(raw))
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, `{"gateway_scope_hosts":["client-a","client-b"]}`) {
		t.Fatalf("ansible-playbook args = %q, want expanded host list", joined)
	}
	if strings.Contains(joined, `{"gateway_scope_hosts":["all"]}`) {
		t.Fatalf("unexpanded all keyword reached ansible-playbook: %q", joined)
	}
	if !strings.Contains(out.String(), `expanded from inventory group "freeipa-client"`) {
		t.Fatalf("output = %q, want visible all expansion", out.String())
	}
}

func TestBuildGatewayScopeArgsPlan(t *testing.T) {
	args, err := buildGatewayScopeArgs("gpu", []string{"gpu-a.example.com", "gpu-b.example.com"}, "inv.yml", "all", "/vault/main.yaml", true)
	if err != nil {
		t.Fatalf("buildGatewayScopeArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{
		gatewayScopeApplyPlaybook,
		"-i inv.yml",
		"-e target_group=all",
		"-e gateway_scope=gpu",
		`-e {"gateway_scope_hosts":["gpu-a.example.com","gpu-b.example.com"]}`,
		"-e @/vault/main.yaml",
		"-e gateway_scope_plan_only=true",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args %v missing %q", args, want)
		}
	}
}

func TestBuildGatewayScopeArgsReconcileOmitsPlanOnly(t *testing.T) {
	args, err := buildGatewayScopeArgs("gpu", []string{"gpu-a.example.com"}, "inv.yml", "all", "/vault/main.yaml", false)
	if err != nil {
		t.Fatalf("buildGatewayScopeArgs: %v", err)
	}
	if strings.Contains(strings.Join(args, " "), "gateway_scope_plan_only") {
		t.Fatalf("reconcile (planOnly=false) must not set gateway_scope_plan_only: %v", args)
	}
}

func TestBuildGatewayScopeArgsRequiresScopeAndHosts(t *testing.T) {
	if _, err := buildGatewayScopeArgs("", []string{"h"}, "inv.yml", "all", "v.yml", false); err == nil {
		t.Fatalf("expected an error for empty scope")
	}
	if _, err := buildGatewayScopeArgs("gpu", nil, "inv.yml", "all", "v.yml", false); err == nil {
		t.Fatalf("expected an error for empty hosts")
	}
	if _, err := buildGatewayScopeArgs("gpu", []string{""}, "inv.yml", "all", "v.yml", false); err == nil {
		t.Fatalf("expected an error for blank host")
	}
	if _, err := buildGatewayScopeArgs("gpu", []string{"all"}, "inv.yml", "all", "v.yml", false); err == nil {
		t.Fatalf("expected an error for unresolved all keyword")
	}
}

func TestBuildGatewayScopeAutomemberArgsEnableIncludesHosts(t *testing.T) {
	args, err := buildGatewayScopeAutomemberArgs("gpu", []string{"target-a", "target-b"}, gatewayScopeAutomemberEnable, "inv.yml", "freeipa-server", "/vault/main.yaml")
	if err != nil {
		t.Fatalf("buildGatewayScopeAutomemberArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{
		gatewayScopeApplyPlaybook,
		"-e gateway_scope=gpu",
		"-e gateway_scope_automember_action=enable",
		`-e {"gateway_scope_hosts":["target-a","target-b"]}`,
		"-e @/vault/main.yaml",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args %v missing %q", args, want)
		}
	}
}

func TestBuildGatewayScopeAutomemberArgsDisableOmitsHosts(t *testing.T) {
	args, err := buildGatewayScopeAutomemberArgs("gpu", nil, gatewayScopeAutomemberDisable, "inv.yml", "freeipa-server", "/vault/main.yaml")
	if err != nil {
		t.Fatalf("buildGatewayScopeAutomemberArgs: %v", err)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-e gateway_scope_automember_action=disable") {
		t.Fatalf("args %v missing automember_action=disable", args)
	}
	if strings.Contains(joined, "gateway_scope_hosts") {
		t.Fatalf("disable-auto must never pass gateway_scope_hosts: %v", args)
	}
}

func TestBuildGatewayScopeAutomemberArgsRejectsHostsWithDisable(t *testing.T) {
	if _, err := buildGatewayScopeAutomemberArgs("gpu", []string{"target-a"}, gatewayScopeAutomemberDisable, "inv.yml", "freeipa-server", "/vault/main.yaml"); err == nil {
		t.Fatal("expected an error when disable-auto is given hosts")
	}
}

func TestBuildGatewayScopeAutomemberArgsRequiresScope(t *testing.T) {
	if _, err := buildGatewayScopeAutomemberArgs("", nil, gatewayScopeAutomemberDisable, "inv.yml", "freeipa-server", "v.yml"); err == nil {
		t.Fatal("expected an error for empty scope")
	}
}

// TestResolveGatewayScopeInventoryAndVaultJoinsDirAndAutodetectsVault proves
// the `--dir` convenience matches `pilot deploy --dir`/`pilot edit --dir`:
// a relative --inventory joins with --dir, and an unset --vault-file
// auto-detects <dir>/.vault/main.yaml — letting `--dir <workspace>` replace
// separately spelling out --inventory and --vault-file every time.
func TestResolveGatewayScopeInventoryAndVaultJoinsDirAndAutodetectsVault(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "inventory.yml"), []byte("all:\n  hosts: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, ".vault"), 0o755); err != nil {
		t.Fatal(err)
	}
	vaultPath := filepath.Join(dir, ".vault", "main.yaml")
	if err := os.WriteFile(vaultPath, []byte("ipa_admin_password: secret\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	inv, vault, err := resolveGatewayScopeInventoryAndVault(cmd, dir, "inventory.yml", "")
	if err != nil {
		t.Fatalf("resolveGatewayScopeInventoryAndVault: %v", err)
	}
	if wantInv := filepath.Join(dir, "inventory.yml"); inv != wantInv {
		t.Fatalf("inventory = %q, want %q", inv, wantInv)
	}
	if vault != vaultPath {
		t.Fatalf("vault = %q, want auto-detected %q", vault, vaultPath)
	}
	if !strings.Contains(out.String(), "auto-detected vault file") {
		t.Fatalf("output = %q, want a visible auto-detect note", out.String())
	}
}

// TestResolveGatewayScopeInventoryAndVaultExplicitVaultWins proves an
// explicit --vault-file is used as-is, with no auto-detection attempted.
func TestResolveGatewayScopeInventoryAndVaultExplicitVaultWins(t *testing.T) {
	dir := t.TempDir()
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	_, vault, err := resolveGatewayScopeInventoryAndVault(cmd, dir, "inventory.yml", "/explicit/vault.yml")
	if err != nil {
		t.Fatalf("resolveGatewayScopeInventoryAndVault: %v", err)
	}
	if vault != "/explicit/vault.yml" {
		t.Fatalf("vault = %q, want the explicit path unchanged", vault)
	}
	if strings.Contains(out.String(), "auto-detected") {
		t.Fatalf("output = %q, must not claim auto-detection when --vault-file was given", out.String())
	}
}

// TestResolveGatewayScopeInventoryAndVaultFailsClosedWithoutAnyVault proves
// a missing --vault-file with no .vault/main.yaml to fall back on is a
// clear CLI-level error, not a cryptic failure deep inside the playbook's
// own ipa_admin_password assert.
func TestResolveGatewayScopeInventoryAndVaultFailsClosedWithoutAnyVault(t *testing.T) {
	dir := t.TempDir()
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	if _, _, err := resolveGatewayScopeInventoryAndVault(cmd, dir, "inventory.yml", ""); err == nil {
		t.Fatal("expected an error when no --vault-file is given and none can be auto-detected")
	}
}

// TestRunGatewayScopeEnableAutoBackfillsExpandedHostsAndSetsAction proves
// enable-auto reuses the same gateway-excluding "all" expansion as reconcile
// (never publishing a gateway as its own target) and passes the automember
// action through to the playbook.
func TestRunGatewayScopeEnableAutoBackfillsExpandedHostsAndSetsAction(t *testing.T) {
	binDir := t.TempDir()
	argsPath := filepath.Join(t.TempDir(), "ansible-playbook-args")
	invJSON := `{"_meta":{"hostvars":{}},"all":{"children":["freeipa-client","pilot-access-gateway"]},` +
		`"freeipa-client":{"hosts":["gw-a","target-a"]},"pilot-access-gateway":{"hosts":["gw-a"]}}`
	inventoryScript := "#!/bin/sh\nprintf '%s\\n' '" + invJSON + "'\n"
	playbookScript := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$PILOT_GATEWAY_SCOPE_ARGS\"\n"
	for name, script := range map[string]string{
		"ansible-inventory": inventoryScript,
		"ansible-playbook":  playbookScript,
	} {
		if err := os.WriteFile(filepath.Join(binDir, name), []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PILOT_GATEWAY_SCOPE_ARGS", argsPath)

	original := struct {
		scope       string
		inventory   string
		targetGroup string
		vaultFile   string
		timeout     time.Duration
		dataDir     string
	}{gatewayScopeFlag, gatewayScopeInventory, gatewayScopeTargetGroup, gatewayScopeVaultFile, gatewayScopeTimeout, dataDir}
	t.Cleanup(func() {
		gatewayScopeFlag = original.scope
		gatewayScopeInventory = original.inventory
		gatewayScopeTargetGroup = original.targetGroup
		gatewayScopeVaultFile = original.vaultFile
		gatewayScopeTimeout = original.timeout
		dataDir = original.dataDir
	})
	dataDir = t.TempDir()
	gatewayScopeFlag = "auto-scope"
	gatewayScopeInventory = "inventory.yml"
	gatewayScopeTargetGroup = "freeipa-server"
	gatewayScopeVaultFile = "/vault/main.yaml"

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetOut(&out)
	if err := runGatewayScopeAutomember(cmd, true); err != nil {
		t.Fatalf("runGatewayScopeAutomember(enable): %v", err)
	}
	raw, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(strings.Fields(string(raw)), " ")
	if !strings.Contains(joined, "gateway_scope_automember_action=enable") {
		t.Fatalf("args = %q, want automember_action=enable", joined)
	}
	if !strings.Contains(joined, `{"gateway_scope_hosts":["target-a"]}`) {
		t.Fatalf("args = %q, want gateway-excluded backfill host list", joined)
	}
	if strings.Contains(joined, `"gw-a"`) {
		t.Fatalf("args = %q, gateway host gw-a must be excluded from the backfill", joined)
	}
	if !strings.Contains(out.String(), "backfilling from inventory group") {
		t.Fatalf("output = %q, want visible backfill expansion", out.String())
	}
}

// TestRunGatewayScopeDisableAutoNeverExpandsOrPassesHosts proves disable-auto
// never resolves "all" and never passes gateway_scope_hosts — it only ever
// removes the automember rule.
func TestRunGatewayScopeDisableAutoNeverExpandsOrPassesHosts(t *testing.T) {
	binDir := t.TempDir()
	argsPath := filepath.Join(t.TempDir(), "ansible-playbook-args")
	// No ansible-inventory script at all: if disable-auto ever tried to
	// resolve "all" it would fail immediately with "executable file not found".
	playbookScript := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$PILOT_GATEWAY_SCOPE_ARGS\"\n"
	if err := os.WriteFile(filepath.Join(binDir, "ansible-playbook"), []byte(playbookScript), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("PILOT_GATEWAY_SCOPE_ARGS", argsPath)

	original := struct {
		scope       string
		inventory   string
		targetGroup string
		vaultFile   string
		timeout     time.Duration
		dataDir     string
	}{gatewayScopeFlag, gatewayScopeInventory, gatewayScopeTargetGroup, gatewayScopeVaultFile, gatewayScopeTimeout, dataDir}
	t.Cleanup(func() {
		gatewayScopeFlag = original.scope
		gatewayScopeInventory = original.inventory
		gatewayScopeTargetGroup = original.targetGroup
		gatewayScopeVaultFile = original.vaultFile
		gatewayScopeTimeout = original.timeout
		dataDir = original.dataDir
	})
	dataDir = t.TempDir()
	gatewayScopeFlag = "auto-scope"
	gatewayScopeInventory = "inventory.yml"
	gatewayScopeTargetGroup = "freeipa-server"
	gatewayScopeVaultFile = "/vault/main.yaml"

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	cmd.SetOut(&out)
	if err := runGatewayScopeAutomember(cmd, false); err != nil {
		t.Fatalf("runGatewayScopeAutomember(disable): %v", err)
	}
	raw, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(strings.Fields(string(raw)), " ")
	if !strings.Contains(joined, "gateway_scope_automember_action=disable") {
		t.Fatalf("args = %q, want automember_action=disable", joined)
	}
	if strings.Contains(joined, "gateway_scope_hosts") {
		t.Fatalf("args = %q, disable-auto must never pass gateway_scope_hosts", joined)
	}
}
