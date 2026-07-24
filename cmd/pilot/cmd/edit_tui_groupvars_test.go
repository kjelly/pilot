package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

func TestResolveSingleRoleHost_ReturnsSoleMatch(t *testing.T) {
	hf := &inventory.HostsFile{Hosts: []inventory.Host{
		{Name: "ipa-1", AnsibleHost: "10.0.0.5", Roles: []string{"freeipa-server"}},
		{Name: "client-1", AnsibleHost: "10.0.0.6", Roles: []string{"freeipa-client"}},
	}}
	got, ok := resolveSingleRoleHost(hf, "freeipa-server")
	if !ok || got != "10.0.0.5" {
		t.Fatalf("resolveSingleRoleHost() = (%q, %v), want (10.0.0.5, true)", got, ok)
	}
}

func TestResolveSingleRoleHost_AmbiguousWhenMultipleHostsMatch(t *testing.T) {
	hf := &inventory.HostsFile{Hosts: []inventory.Host{
		{Name: "ipa-1", AnsibleHost: "10.0.0.5", Roles: []string{"freeipa-server"}},
		{Name: "ipa-2", AnsibleHost: "10.0.0.6", Roles: []string{"freeipa-server"}},
	}}
	if _, ok := resolveSingleRoleHost(hf, "freeipa-server"); ok {
		t.Fatalf("resolveSingleRoleHost() ok = true, want false for an ambiguous (2-host) role")
	}
}

func TestResolveSingleRoleHost_FalseWhenRoleAbsent(t *testing.T) {
	hf := &inventory.HostsFile{Hosts: []inventory.Host{
		{Name: "client-1", AnsibleHost: "10.0.0.6", Roles: []string{"freeipa-client"}},
	}}
	if _, ok := resolveSingleRoleHost(hf, "freeipa-server"); ok {
		t.Fatalf("resolveSingleRoleHost() ok = true, want false when no host has the role")
	}
}

func TestResolveSingleRoleHost_FalseWhenAnsibleHostEmpty(t *testing.T) {
	hf := &inventory.HostsFile{Hosts: []inventory.Host{
		{Name: "ipa-1", Roles: []string{"freeipa-server"}},
	}}
	if _, ok := resolveSingleRoleHost(hf, "freeipa-server"); ok {
		t.Fatalf("resolveSingleRoleHost() ok = true, want false when the sole match has no ansible_host set")
	}
}

func TestFilterStemsToUsedRoles_KeepsOnlyUsedRoleStems(t *testing.T) {
	hf := &inventory.HostsFile{Hosts: []inventory.Host{
		{Name: "ipa-1", Roles: []string{"freeipa-server"}},
	}}
	got := filterStemsToUsedRoles([]string{"freeipa", "dns", "prometheus"}, hf)
	if len(got) != 1 || got[0] != "freeipa" {
		t.Fatalf("filterStemsToUsedRoles() = %v, want [freeipa]", got)
	}
}

func TestAutofillCrossRoleHostVars_FillsUnambiguousMatch(t *testing.T) {
	hf := &inventory.HostsFile{Hosts: []inventory.Host{
		{Name: "ipa-1", AnsibleHost: "10.0.0.5", Roles: []string{"freeipa-server"}},
	}}
	data := []byte("---\n# freeipa_server_ip: \"192.0.2.10\"\nfreeipa_domain: ipa.pilot.internal\n")

	got := autofillCrossRoleHostVars(hf, data)
	if !strings.Contains(string(got), "freeipa_server_ip: 10.0.0.5") {
		t.Fatalf("autofillCrossRoleHostVars() = %q, want an uncommented freeipa_server_ip: 10.0.0.5", got)
	}
}

func TestAutofillCrossRoleHostVars_LeavesAmbiguousRoleCommentedOut(t *testing.T) {
	hf := &inventory.HostsFile{Hosts: []inventory.Host{
		{Name: "ipa-1", AnsibleHost: "10.0.0.5", Roles: []string{"freeipa-server"}},
		{Name: "ipa-2", AnsibleHost: "10.0.0.6", Roles: []string{"freeipa-server"}},
	}}
	data := []byte("---\n# freeipa_server_ip: \"192.0.2.10\"\nfreeipa_domain: ipa.pilot.internal\n")

	got := autofillCrossRoleHostVars(hf, data)
	if string(got) != string(data) {
		t.Fatalf("autofillCrossRoleHostVars() = %q, want unchanged (ambiguous role)", got)
	}
}

func TestAutofillCrossRoleHostVars_NeverOverwritesAlreadyActiveValue(t *testing.T) {
	hf := &inventory.HostsFile{Hosts: []inventory.Host{
		{Name: "ipa-1", AnsibleHost: "10.0.0.5", Roles: []string{"freeipa-server"}},
	}}
	data := []byte("---\nfreeipa_server_ip: \"10.9.9.9\"\nfreeipa_domain: ipa.pilot.internal\n")

	got := autofillCrossRoleHostVars(hf, data)
	if string(got) != string(data) {
		t.Fatalf("autofillCrossRoleHostVars() = %q, want unchanged (already active)", got)
	}
}

func TestAutofillCrossRoleHostVars_NilHostsFileIsNoop(t *testing.T) {
	data := []byte("---\n# freeipa_server_ip: \"192.0.2.10\"\n")
	got := autofillCrossRoleHostVars(nil, data)
	if string(got) != string(data) {
		t.Fatalf("autofillCrossRoleHostVars(nil, ...) = %q, want unchanged", got)
	}
}

// TestAutofillCrossRoleHostVars_RealFreeIPAExampleFile ties the autofill
// regex/parsing to the actual shipped group_vars/freeipa.example.yml (not
// just a synthetic fixture) — catches a future edit to that file's comment
// formatting silently breaking the match.
func TestAutofillCrossRoleHostVars_RealFreeIPAExampleFile(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "group_vars", "freeipa.example.yml"))
	if err != nil {
		t.Skipf("real group_vars/freeipa.example.yml not found: %v", err)
	}
	hf := &inventory.HostsFile{Hosts: []inventory.Host{
		{Name: "ipa-1", AnsibleHost: "10.0.0.9", Roles: []string{"freeipa-server"}},
	}}
	got := autofillCrossRoleHostVars(hf, data)
	if !strings.Contains(string(got), "freeipa_server_ip: 10.0.0.9") {
		t.Fatalf("autofill against the real freeipa.example.yml did not produce freeipa_server_ip: 10.0.0.9:\n%s", got)
	}
}
