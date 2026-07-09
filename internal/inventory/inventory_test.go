package inventory

import (
	"strings"
	"testing"
)

const sampleSource = `
vars:
  ansible_user: "ubuntu"
  ansible_ssh_private_key_file: "~/.ssh/id_ed25519"

hosts:
  ipa-1:
    ansible_host: "10.0.0.10"
    ipa_server_ip: "10.0.0.10"
    roles: [freeipa-server, dns, ntp]
    env: prod
  web-1:
    ansible_host: "10.0.0.21"
    roles: [freeipa-client, linux-servers, audit-log-forwarding]
    env: prod
  web-2:
    ansible_host: "10.0.0.22"
    roles: [freeipa-client, linux-servers]
    env: staging
`

func TestParse(t *testing.T) {
	hf, err := Parse([]byte(sampleSource))
	if err != nil {
		t.Fatal(err)
	}
	if len(hf.Hosts) != 3 {
		t.Fatalf("got %d hosts, want 3", len(hf.Hosts))
	}
	if hf.Vars["ansible_user"] != "ubuntu" {
		t.Errorf("vars.ansible_user = %q, want ubuntu", hf.Vars["ansible_user"])
	}
	// Hosts come back sorted by name for deterministic output.
	if hf.Hosts[0].Name != "ipa-1" || hf.Hosts[1].Name != "web-1" || hf.Hosts[2].Name != "web-2" {
		t.Fatalf("hosts not sorted: %+v", hf.Hosts)
	}
	ipa := hf.Hosts[0]
	if ipa.AnsibleHost != "10.0.0.10" || ipa.Env != "prod" {
		t.Errorf("ipa-1 = %+v", ipa)
	}
	if ipa.Extra["ipa_server_ip"] != "10.0.0.10" {
		t.Errorf("ipa-1 extra ipa_server_ip = %q", ipa.Extra["ipa_server_ip"])
	}
	if len(ipa.Roles) != 3 {
		t.Errorf("ipa-1 roles = %v", ipa.Roles)
	}
}

func TestLint_Clean(t *testing.T) {
	hf, err := Parse([]byte(sampleSource))
	if err != nil {
		t.Fatal(err)
	}
	issues := Lint(hf)
	if HasErrors(issues) {
		t.Fatalf("unexpected errors: %v", issues)
	}
}

func TestLint_UnknownRole(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "10.0.0.1"
    roles: [not-a-real-role]
`))
	if err != nil {
		t.Fatal(err)
	}
	issues := Lint(hf)
	if !HasErrors(issues) {
		t.Fatal("expected an error for an unknown role")
	}
	found := false
	for _, i := range issues {
		if strings.Contains(i.Message, "not-a-real-role") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an issue mentioning the bad role name, got %v", issues)
	}
}

func TestLint_EmptyAnsibleHost(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  web-1:
    roles: [linux-servers]
`))
	if err != nil {
		t.Fatal(err)
	}
	issues := Lint(hf)
	if !HasErrors(issues) {
		t.Fatal("expected an error for empty ansible_host")
	}
}

func TestLint_FillMeLeftover(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "<FILL-ME>"
    roles: [linux-servers]
`))
	if err != nil {
		t.Fatal(err)
	}
	issues := Lint(hf)
	if !HasErrors(issues) {
		t.Fatal("expected an error for a leftover <FILL-ME> placeholder")
	}
}

func TestLint_UnknownEnv(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "10.0.0.1"
    roles: [linux-servers]
    env: production
`))
	if err != nil {
		t.Fatal(err)
	}
	issues := Lint(hf)
	if !HasErrors(issues) {
		t.Fatal("expected an error for an unknown env value")
	}
}

func TestLint_NoRolesIsWarningNotError(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "10.0.0.1"
`))
	if err != nil {
		t.Fatal(err)
	}
	issues := Lint(hf)
	if HasErrors(issues) {
		t.Fatalf("a roleless host should only warn, got %v", issues)
	}
	if len(issues) == 0 {
		t.Fatal("expected a warning for a roleless host")
	}
}

func TestGenerate_RejectsLintErrors(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  web-1:
    ansible_host: "<FILL-ME>"
    roles: [linux-servers]
`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(hf); err == nil {
		t.Fatal("expected Generate to refuse a source file with lint errors")
	}
}

func TestGenerate_Shape(t *testing.T) {
	hf, err := Parse([]byte(sampleSource))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Generate(hf)
	if err != nil {
		t.Fatal(err)
	}

	// all.hosts carries connection info once per host.
	if !strings.Contains(out, "    ipa-1:\n      ansible_host: \"10.0.0.10\"\n") {
		t.Errorf("missing ipa-1 host block:\n%s", out)
	}
	if !strings.Contains(out, "      ipa_server_ip: \"10.0.0.10\"\n") {
		t.Errorf("missing passthrough ipa_server_ip var:\n%s", out)
	}

	// freeipa is a pure aggregator: freeipa-server/-client nest under it,
	// each with just a bare hostname (no re-declared vars).
	if !strings.Contains(out, "    freeipa:\n      children:\n        freeipa-server:\n          hosts:\n            ipa-1:\n") {
		t.Errorf("missing freeipa > freeipa-server > ipa-1 nesting:\n%s", out)
	}
	if !strings.Contains(out, "        freeipa-client:\n          hosts:\n            web-1:\n            web-2:\n") {
		t.Errorf("missing freeipa > freeipa-client hosts:\n%s", out)
	}

	// A role nobody used still renders as an empty group so playbooks
	// that target it by default don't blow up on a missing group.
	if !strings.Contains(out, "    keycloak:\n      hosts: {}\n") {
		t.Errorf("expected keycloak to render as an empty group:\n%s", out)
	}

	// infra-provider aggregates dns/ntp/docker/keycloak/keycloak-db by
	// bare reference — those groups already carry their own hosts
	// blocks at top level; Ansible merges membership from there.
	if !strings.Contains(out, "    infra-provider:\n      children:\n        dns:\n        ntp:\n        docker:\n        keycloak:\n        keycloak-db:\n") {
		t.Errorf("missing infra-provider aggregation:\n%s", out)
	}

	// env groups.
	if !strings.Contains(out, "    prod:\n      hosts:\n        ipa-1:\n        web-1:\n") {
		t.Errorf("missing prod env group:\n%s", out)
	}
	if !strings.Contains(out, "    staging:\n      hosts:\n        web-2:\n") {
		t.Errorf("missing staging env group:\n%s", out)
	}
	if !strings.Contains(out, "    sandbox:\n      hosts: {}\n") {
		t.Errorf("expected sandbox to render as an empty group:\n%s", out)
	}

	// fleet-wide vars.
	if !strings.Contains(out, "  vars:\n    ansible_ssh_private_key_file: \"~/.ssh/id_ed25519\"\n    ansible_user: \"ubuntu\"\n") {
		t.Errorf("missing all.vars block:\n%s", out)
	}
}

func TestGenerate_Deterministic(t *testing.T) {
	hf, err := Parse([]byte(sampleSource))
	if err != nil {
		t.Fatal(err)
	}
	a, err := Generate(hf)
	if err != nil {
		t.Fatal(err)
	}
	hf2, err := Parse([]byte(sampleSource))
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate(hf2)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("Generate must be deterministic across identical input")
	}
}

func TestRoles_NonEmptyAndStable(t *testing.T) {
	roles := Roles()
	if len(roles) == 0 {
		t.Fatal("expected a non-empty role catalog")
	}
	for _, r := range roles {
		if r.Name == "" || r.Description == "" {
			t.Errorf("role with empty field: %+v", r)
		}
	}
}

func TestGroupVarsStems_DedupesSharedFreeipaStem(t *testing.T) {
	hf := &HostsFile{Hosts: []Host{
		{Name: "ipa-1", Roles: []string{"freeipa-server"}},
		{Name: "web-1", Roles: []string{"freeipa-client", "dns"}},
		{Name: "web-2", Roles: []string{"freeipa-client"}},
	}}
	got := GroupVarsStems(hf)
	want := []string{"dns", "freeipa"}
	if len(got) != len(want) {
		t.Fatalf("GroupVarsStems() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("GroupVarsStems() = %v, want %v", got, want)
		}
	}
}

func TestGroupVarsStems_UnmappedRoleUsesOwnName(t *testing.T) {
	hf := &HostsFile{Hosts: []Host{
		{Name: "d-1", Roles: []string{"docker"}},
	}}
	got := GroupVarsStems(hf)
	if len(got) != 1 || got[0] != "docker" {
		t.Fatalf("GroupVarsStems() = %v, want [docker]", got)
	}
}

func TestGroupVarsStems_NoRolesIsEmpty(t *testing.T) {
	hf := &HostsFile{Hosts: []Host{{Name: "lonely"}}}
	got := GroupVarsStems(hf)
	if len(got) != 0 {
		t.Fatalf("GroupVarsStems() = %v, want empty", got)
	}
}

func TestRender_RoundTrip(t *testing.T) {
	hf, err := Parse([]byte(sampleSource))
	if err != nil {
		t.Fatal(err)
	}
	rendered, err := Render(hf)
	if err != nil {
		t.Fatal(err)
	}
	hf2, err := Parse([]byte(rendered))
	if err != nil {
		t.Fatalf("re-parsing rendered output failed: %v\n%s", err, rendered)
	}
	if len(hf2.Hosts) != len(hf.Hosts) {
		t.Fatalf("got %d hosts after round-trip, want %d", len(hf2.Hosts), len(hf.Hosts))
	}
	for i := range hf.Hosts {
		a, b := hf.Hosts[i], hf2.Hosts[i]
		if a.Name != b.Name || a.AnsibleHost != b.AnsibleHost || a.Env != b.Env || strings.Join(a.Roles, ",") != strings.Join(b.Roles, ",") {
			t.Errorf("host %d mismatch after round-trip:\nbefore=%+v\nafter=%+v", i, a, b)
		}
	}
	if hf2.Vars["ansible_user"] != hf.Vars["ansible_user"] {
		t.Errorf("vars.ansible_user lost in round-trip: %+v", hf2.Vars)
	}
}

func TestRender_EmptyRolesRendersAsEmptyList(t *testing.T) {
	hf := &HostsFile{Hosts: []Host{{Name: "lonely", AnsibleHost: "10.0.0.1"}}}
	out, err := Render(hf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "roles: []\n") {
		t.Errorf("expected an empty roles list, got:\n%s", out)
	}
}

func TestRender_NilHostsFileErrors(t *testing.T) {
	if _, err := Render(nil); err == nil {
		t.Fatal("expected an error for a nil HostsFile")
	}
}
