package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/groupvars"
)

func TestEditAutomationDriverGroupVarsCreateFromExampleSetSave(t *testing.T) {
	dir := t.TempDir()
	exampleDir := filepath.Join(dir, "group_vars")
	if err := os.MkdirAll(exampleDir, 0o755); err != nil {
		t.Fatal(err)
	}
	example := "dns_forwarders: \"8.8.8.8\"\n"
	if err := os.WriteFile(filepath.Join(exampleDir, "dns.example.yml"), []byte(example), 0o644); err != nil {
		t.Fatal(err)
	}

	oldWd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// pushGroupVarsFilePicker reads the shipped example templates from a
	// fixed, CWD-relative "group_vars" dir — chdir so that resolves to our
	// fixture instead of the real repo's group_vars/.
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(oldWd) })

	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "set_group_var", File: "dns.yml", Key: "dns_forwarders", Value: "1.1.1.1"},
		{Action: "save_group_vars", File: "dns.yml"},
	}}
	r := newEditRouterModel(".")
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "group_vars", "dns.yml"))
	if err != nil {
		t.Fatalf("read group_vars/dns.yml: %v", err)
	}
	entries := groupvars.Parse(data).Entries()
	if len(entries) != 1 || entries[0].Value != "1.1.1.1" {
		t.Fatalf("entries = %+v, want dns_forwarders=1.1.1.1\n%s", entries, data)
	}
}

func TestEditAutomationDriverRestoreGroupVarDefault(t *testing.T) {
	dir := t.TempDir()
	gvDir := filepath.Join(dir, "group_vars")
	if err := os.MkdirAll(gvDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gvDir, "dns.yml"), []byte("dns_forwarders: \"1.1.1.1\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "restore_group_var_default", File: "dns.yml", Key: "dns_forwarders"},
		{Action: "save_group_vars", File: "dns.yml"},
	}}
	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(gvDir, "dns.yml"))
	if err != nil {
		t.Fatal(err)
	}
	entries := groupvars.Parse(data).Entries()
	if len(entries) != 1 || entries[0].Active {
		t.Fatalf("entries = %+v, want dns_forwarders inactive (commented out)\n%s", entries, data)
	}
}

func TestEditAutomationDriverDiscardGroupVarsNoOpWhenClean(t *testing.T) {
	dir := t.TempDir()
	gvDir := filepath.Join(dir, "group_vars")
	if err := os.MkdirAll(gvDir, 0o755); err != nil {
		t.Fatal(err)
	}
	original := []byte("dns_forwarders: \"8.8.8.8\"\n")
	if err := os.WriteFile(filepath.Join(gvDir, "dns.yml"), original, 0o644); err != nil {
		t.Fatal(err)
	}

	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "discard_group_vars", File: "dns.yml"},
	}}
	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}
	data, err := os.ReadFile(filepath.Join(gvDir, "dns.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(original) {
		t.Fatalf("file changed despite no edits: got %q want %q", data, original)
	}
}

func TestEditAutomationDriverDiscardGroupVarsWithPendingEdit(t *testing.T) {
	dir := t.TempDir()
	gvDir := filepath.Join(dir, "group_vars")
	if err := os.MkdirAll(gvDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gvDir, "dns.yml"), []byte("dns_forwarders: \"8.8.8.8\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "set_group_var", File: "dns.yml", Key: "dns_forwarders", Value: "1.1.1.1"},
		{Action: "discard_group_vars", File: "dns.yml"},
	}}
	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	data, err := os.ReadFile(filepath.Join(gvDir, "dns.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "8.8.8.8") {
		t.Fatalf("discard_group_vars should have kept the original on-disk value:\n%s", data)
	}
}

// TestEditAutomationDriverGroupVarsMultiFileInOneScenario proves
// openGroupVarsFile's "resolve current position" navigation actually works
// across two separate files within one scenario, not just from a fresh
// router.
func TestEditAutomationDriverGroupVarsMultiFileInOneScenario(t *testing.T) {
	dir := t.TempDir()
	gvDir := filepath.Join(dir, "group_vars")
	if err := os.MkdirAll(gvDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gvDir, "dns.yml"), []byte("dns_forwarders: \"8.8.8.8\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gvDir, "freeipa.yml"), []byte("freeipa_realm: \"EXAMPLE.TEST\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "set_group_var", File: "dns.yml", Key: "dns_forwarders", Value: "1.1.1.1"},
		{Action: "save_group_vars", File: "dns.yml"},
		{Action: "set_group_var", File: "freeipa.yml", Key: "freeipa_realm", Value: "PROD.TEST"},
		{Action: "save_group_vars", File: "freeipa.yml"},
	}}
	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err != nil {
		t.Fatalf("driver.run() error = %v", err)
	}

	dnsData, err := os.ReadFile(filepath.Join(gvDir, "dns.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(dnsData), "1.1.1.1") {
		t.Fatalf("dns.yml not updated:\n%s", dnsData)
	}
	ipaData, err := os.ReadFile(filepath.Join(gvDir, "freeipa.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ipaData), "PROD.TEST") {
		t.Fatalf("freeipa.yml not updated:\n%s", ipaData)
	}
}

func TestEditAutomationDriverGroupVarsSwitchingFileWithoutSaveErrors(t *testing.T) {
	dir := t.TempDir()
	gvDir := filepath.Join(dir, "group_vars")
	if err := os.MkdirAll(gvDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gvDir, "dns.yml"), []byte("dns_forwarders: \"8.8.8.8\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gvDir, "freeipa.yml"), []byte("freeipa_realm: \"EXAMPLE.TEST\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	scenario := editScenario{Version: 1, Steps: []editAction{
		{Action: "set_group_var", File: "dns.yml", Key: "dns_forwarders", Value: "1.1.1.1"},
		// No save_group_vars/discard_group_vars for dns.yml before switching.
		{Action: "set_group_var", File: "freeipa.yml", Key: "freeipa_realm", Value: "PROD.TEST"},
	}}
	r := newEditRouterModel(dir)
	d := automationDriver{}
	if err := d.run(&r, scenario); err == nil {
		t.Fatal("driver.run() unexpectedly succeeded switching files without saving/discarding first")
	}
}
