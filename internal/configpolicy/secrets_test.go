package configpolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kjelly/pilot/internal/contract"
)

func testPolicy(t *testing.T) Policy {
	t.Helper()
	catalog, err := contract.NewCatalog([]contract.Contract{{ID: "fixture", GroupVars: []contract.GroupVar{{Name: "opaque_input", Secret: true}, {Name: "freeipa_roster_file", Secret: true}}}})
	if err != nil {
		t.Fatal(err)
	}
	return New(catalog)
}

func TestSecretStorageForms(t *testing.T) {
	p := testPolicy(t)
	for _, tc := range []struct {
		name, yaml string
		reject     bool
	}{
		{"contract metadata", "opaque_input: DUMMY130", true},
		{"ansible password", "ansible_password: DUMMY130", true},
		{"ansible legacy pass", "ansible_ssh_pass: DUMMY130", true},
		{"unknown API key", "custom_api_key: DUMMY130", true},
		{"uppercase password", "PASSWORD: DUMMY130", true},
		{"uppercase API key", "API_KEY: DUMMY130", true},
		{"uppercase SNMP", "SNMP_AUTH_PASSWORD: DUMMY130", true},
		{"acronym camel key", "vendorAPIKey: DUMMY130", true},
		{"unknown nested list", "items:\n  - config:\n      password: DUMMY130", true},
		{"SNMP camel case", "profiles:\n  - authPassword: DUMMY130", true},
		{"SNMP community", "profiles: [{community: DUMMY130}]", true},
		{"Jinja prefix", "opaque_input: 'DUMMY130{{ vault_secret }}'", true},
		{"Jinja default", "opaque_input: \"{{ vault_secret | default('DUMMY130') }}\"", true},
		{"Jinja literal", "opaque_input: \"{{ 'DUMMY130' }}\"", true},
		{"Jinja joined literal", "opaque_input: \"{{ vault_secret ~ 'DUMMY130' }}\"", true},
		{"alias contextual", "public: &value DUMMY130\nopaque_input: *value", true},
		{"merge map", "defaults: &defaults {password: DUMMY130}\nconfig: {<<: *defaults}", true},
		{"overridden merge", "defaults: &defaults {password: DUMMY130}\nconfig: {<<: *defaults, password: '{{ vault_password }}'}", true},
		{"merge sequence", "a: &a {token: DUMMY130}\nconfig: {<<: [*a]}", true},
		{"encrypted scalar", "password: !vault |\n  $ANSIBLE_VAULT;1.1;AES256\n  DUMMY130", true},
		{"encrypted file", "$ANSIBLE_VAULT;1.1;AES256\nDUMMY130", true},
		{"embedded YAML", "configuration: |\n  service:\n    token: DUMMY130", true},
		{"private key", "public_input: '-----BEGIN PRIVATE KEY-----DUMMY130'", true},
		{"URI credentials", "url: https://user:DUMMY130@example.org", true},
		{"parse error", "opaque_input: [DUMMY130", true},
		{"alias cycle", "a: &a {password: *a}", true},
		{"nonsecret", "port: 8443\nname: dashboard\nsite: one", false},
		{"nonsecret credential settings", "token_ttl: 60\npassword_policy: {min_length: 12}\ncredentials_enabled: true", false},
		{"nonsecret arbitrary map key", "routes: {'*:22': allow}", false},
		{"pure variable", "opaque_input: '{{ vault_opaque_input }}'", false},
		{"pure dotted variable", "opaque_input: '{{ vault.dashboard.password }}'", false},
		{"nested references", "items: [{password: '{{ vault_password }}'}]", false},
		{"empty skeleton", "password: ''\ntoken:\napi_key: null\ncredentials: {}", false},
		{"path and ref", "ansible_ssh_private_key_file: /secure/id_ed25519\ncredentialRef: edge-1\nfreeipa_roster_file: /secure/roster.yml", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			violations := p.Validate("group_vars/test.yml", []byte(tc.yaml))
			if (len(violations) > 0) != tc.reject {
				t.Fatalf("rejected=%v, want %v (locations=%v)", len(violations) > 0, tc.reject, violations)
			}
			for _, violation := range violations {
				if strings.Contains(violation.String(), "DUMMY130") {
					t.Fatal("credential leaked")
				}
			}
		})
	}
}

func TestShippedSecretMetadataSurvivesMissingRuntimeCatalog(t *testing.T) {
	p := New(contract.Catalog{})
	if len(p.Validate("host_vars/test.yml", []byte("siem_relp_key_pem: DUMMY130"))) != 1 {
		t.Fatal("shipped opaque secret metadata was lost")
	}
	catalog, err := contract.NewCatalog([]contract.Contract{{ID: "override", GroupVars: []contract.GroupVar{{Name: "siem_relp_key_pem", Secret: false}}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(New(catalog).Validate("group_vars/test.yml", []byte("siem_relp_key_pem: DUMMY130"))) != 1 {
		t.Fatal("custom catalog downgraded shipped secret")
	}
}

func TestWorkspaceChecksBothTreesRecursively(t *testing.T) {
	for _, tree := range []string{"group_vars", "host_vars"} {
		t.Run(tree, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tree, "node", "nested", "vars.yaml")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte("items:\n  - password: DUMMY130\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			violations, err := testPolicy(t).Workspace(dir)
			if err != nil || len(violations) != 1 {
				t.Fatalf("violations=%v err=%v", violations, err)
			}
			if violations[0].Path != "items[0].password" || violations[0].Line != 2 {
				t.Fatalf("wrong location: %+v", violations[0])
			}
		})
	}
}

func TestWorkspaceRejectsDirectorySymlink(t *testing.T) {
	dir := t.TempDir()
	if err := os.Symlink(t.TempDir(), filepath.Join(dir, "host_vars")); err != nil {
		t.Fatal(err)
	}
	violations, err := testPolicy(t).Workspace(dir)
	if err != nil || len(violations) != 1 {
		t.Fatalf("violations=%v err=%v", violations, err)
	}
}
