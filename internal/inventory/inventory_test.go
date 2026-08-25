package inventory

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
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
    ansible_user: "ipaadmin"
    ansible_ssh_private_key_file: "~/.ssh/ipa"
    ipa_server_ip: "10.0.0.10"
    freeipa_roster_file: ".vault/ipa-identity.yaml"
    roles: [freeipa-server, dns, ntp]
    env: prod
    deployment_availability: optional
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

func TestLint_FreeIPARosterRequiredForConsumerRoles(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  ipa-1:
    ansible_host: "10.0.0.10"
    roles: [freeipa-server]
`))
	if err != nil {
		t.Fatal(err)
	}
	issues := Lint(hf)
	for _, issue := range issues {
		if strings.Contains(issue.Message, "require freeipa_roster_file") {
			return
		}
	}
	t.Fatalf("expected missing roster path error, got %v", issues)
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

func TestGenerate_FreeIPANFSGroups(t *testing.T) {
	hf, err := Parse([]byte(`
hosts:
  nfs-1:
    ansible_host: "10.0.0.30"
    freeipa_roster_file: ".vault/ipa-identity.yaml"
    roles: [freeipa-nfs-server]
  client-1:
    ansible_host: "10.0.0.31"
    roles: [freeipa-nfs-client]
`))
	if err != nil {
		t.Fatal(err)
	}
	out, err := Generate(hf)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "        freeipa-nfs-server:\n          hosts:\n            nfs-1:\n") {
		t.Errorf("missing freeipa > freeipa-nfs-server > nfs-1 nesting:\n%s", out)
	}
	if !strings.Contains(out, "        freeipa-nfs-client:\n          hosts:\n            client-1:\n") {
		t.Errorf("missing freeipa > freeipa-nfs-client > client-1 nesting:\n%s", out)
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

func TestGroupVarsStems_AuditLogForwardingContributesItsOwnStem(t *testing.T) {
	// group_vars/audit-log-forwarding.example.yml ships in the repo but
	// this role had no GroupVarsStem set, so `pilot inventory generate`
	// never backfilled it and `pilot edit` never offered "從範例建立" for
	// it — found while auditing pilot edit's group_vars scaffolding gaps.
	hf := &HostsFile{Hosts: []Host{{Name: "web-1", Roles: []string{"audit-log-forwarding"}}}}
	got := GroupVarsStems(hf)
	if len(got) != 1 || got[0] != "audit-log-forwarding" {
		t.Fatalf("GroupVarsStems() = %v, want [audit-log-forwarding]", got)
	}
}

func TestGroupVarsStems_RoleWithoutGroupVarsContractContributesNothing(t *testing.T) {
	hf := &HostsFile{Hosts: []Host{
		{Name: "d-1", Roles: []string{"docker"}},
	}}
	got := GroupVarsStems(hf)
	if len(got) != 0 {
		t.Fatalf("GroupVarsStems() = %v, want empty", got)
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
	if !reflect.DeepEqual(hf.Hosts, hf2.Hosts) {
		t.Errorf("hosts mismatch after round-trip:\nbefore=%+v\nafter=%+v", hf.Hosts, hf2.Hosts)
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

// TestHostTypedFieldSerializationContract makes each typed Host field's two
// serialization contracts explicit: Render must preserve it in hosts.yml,
// while Generate must put host variables and role/environment membership in
// the corresponding Ansible inventory locations.
func TestHostTypedFieldSerializationContract(t *testing.T) {
	hf := &HostsFile{Hosts: []Host{{
		Name:                   "sentinel",
		AnsibleHost:            "10.0.0.42",
		AnsibleUser:            "operator",
		SSHKeyFile:             "~/.ssh/sentinel",
		Roles:                  []string{"docker"},
		Env:                    "staging",
		DeploymentAvailability: DeploymentAvailabilityOptional,
		Extra:                  map[string]string{},
	}}}
	rendered, err := Render(hf)
	if err != nil {
		t.Fatalf("Render() error: %v", err)
	}
	roundTripped, err := Parse([]byte(rendered))
	if err != nil {
		t.Fatalf("Parse(Render()) error: %v\n%s", err, rendered)
	}
	if !reflect.DeepEqual(hf.Hosts, roundTripped.Hosts) {
		t.Fatalf("Render lost a typed Host field:\nbefore=%+v\nafter=%+v\n%s", hf.Hosts, roundTripped.Hosts, rendered)
	}

	generated, err := Generate(hf)
	if err != nil {
		t.Fatalf("Generate() error: %v", err)
	}
	for _, want := range []string{
		"sentinel:",
		`ansible_host: "10.0.0.42"`,
		`ansible_user: "operator"`,
		`ansible_ssh_private_key_file: "~/.ssh/sentinel"`,
		`deployment_availability: "optional"`,
		"docker:",
		"staging:",
	} {
		if !strings.Contains(generated, want) {
			t.Errorf("Generate() omitted typed Host field contract %q:\n%s", want, generated)
		}
	}
}

func TestRoleContracts_GroupVarsExamplesExistForDeclaredStems(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	repoRoot := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	for _, c := range roleContracts {
		if c.GroupVarsStem == "" {
			continue
		}
		path := filepath.Join(repoRoot, "group_vars", c.GroupVarsStem+".example.yml")
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("role %q declares group_vars stem %q but %s is missing: %v", c.Name, c.GroupVarsStem, path, err)
		}
	}
}

func TestRoleContracts_VaultSectionsExist(t *testing.T) {
	for _, c := range roleContracts {
		for _, sectionID := range c.VaultSections {
			if _, ok := vaultSections[sectionID]; !ok {
				t.Fatalf("role %q references unknown vault section %q", c.Name, sectionID)
			}
			// Deliberately checks every declared key, not just required
			// ones (VaultSectionExpectedKeys excludes Optional keys by
			// design — see vaultSection.keyNames) — a section can be
			// legitimately all-Optional (e.g. "alertmanager", whose
			// apply playbook supplies a working default; see
			// TestAlertmanagerDefaultConfigIsMinimalAndOperational)
			// without that being a catalog gap.
			if len(vaultSections[sectionID].Keys) == 0 {
				t.Fatalf("role %q references vault section %q but it declares no vault keys at all", c.Name, sectionID)
			}
		}
	}
}

func TestTopLevelOrder_LeafEntriesComeFromRoleContracts(t *testing.T) {
	valid := validRoleNames()
	for _, name := range topLevelOrder {
		if aggregateChildren(name) != nil {
			continue
		}
		if !valid[name] {
			t.Fatalf("topLevelOrder contains %q but no role contract defines it", name)
		}
	}
}

func TestRoleContracts_AllRolesAppearInRenderedCatalog(t *testing.T) {
	renderedRoles := make(map[string]bool, len(roleContracts))
	for _, name := range topLevelOrder {
		children := aggregateChildren(name)
		if children == nil {
			renderedRoles[name] = true
			continue
		}
		for _, child := range children {
			renderedRoles[child] = true
		}
	}

	for _, contract := range roleContracts {
		if !renderedRoles[contract.Name] {
			t.Errorf("role contract %q is accepted by lint but cannot be rendered", contract.Name)
		}
	}
}
