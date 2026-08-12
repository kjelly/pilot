package inventory

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func mustParseRosterNode(t *testing.T, doc string) *yaml.Node {
	t.Helper()
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(doc), &root); err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return &root
}

func marshalNode(t *testing.T, node *yaml.Node) []byte {
	t.Helper()
	out, err := yaml.Marshal(node)
	if err != nil {
		t.Fatalf("marshal node: %v", err)
	}
	return out
}

// migrateCanonicalFixtureForTest loads the repo's real v1 canonical
// fixture, migrates it, and validates both ends — the M2 "full canonical
// fixture" migration test, shared by every assertion that needs a
// realistic before/after pair rather than a hand-written minimal one.
func migrateCanonicalFixtureForTest(t *testing.T) (before, after map[string]any) {
	t.Helper()
	path := filepath.Join("..", "..", "playbooks", "test", "fixtures", "freeipa-identity-canonical.roster.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("canonical fixture not found: %v", err)
	}

	before = mustParseRoster(t, string(data))
	if v := ValidateRosterV1(before); len(v) != 0 {
		t.Fatalf("canonical fixture failed ValidateRosterV1: %v", v)
	}

	migrated, err := MigrateRosterV1ToV2(mustParseRosterNode(t, string(data)))
	if err != nil {
		t.Fatalf("MigrateRosterV1ToV2() error = %v", err)
	}
	after = mustParseRoster(t, string(marshalNode(t, migrated)))
	if v := ValidateRosterV2(after); len(v) != 0 {
		t.Fatalf("migrated fixture failed ValidateRosterV2: %v", v)
	}
	return before, after
}

// ---- M1: minimal v1 -----------------------------------------------------

func TestMigrateRosterV1ToV2_MinimalDocument(t *testing.T) {
	migrated, err := MigrateRosterV1ToV2(mustParseRosterNode(t, `
schema_version: 1
freeipa:
  admin:
    principal: admin
    password: secret123
`))
	if err != nil {
		t.Fatalf("MigrateRosterV1ToV2() error = %v", err)
	}
	root := mustParseRoster(t, string(marshalNode(t, migrated)))

	if n, _ := toInt(root["schema_version"]); n != 2 {
		t.Fatalf("schema_version = %v, want 2", root["schema_version"])
	}
	netgroups, ok := root["netgroups"].([]any)
	if !ok || len(netgroups) != 0 {
		t.Fatalf("netgroups = %#v, want an empty list", root["netgroups"])
	}
	admin := mapField(mapField(root, "freeipa"), "admin")
	if stringField(admin, "principal") != "admin" || stringField(admin, "password") != "secret123" {
		t.Fatalf("freeipa.admin = %v, want principal/password preserved unchanged", admin)
	}
	if v := ValidateRosterV2(root); len(v) != 0 {
		t.Fatalf("migrated result failed ValidateRosterV2: %v", v)
	}
}

func TestMigrateRosterV1ToV2_RejectsNonV1SchemaVersion(t *testing.T) {
	if _, err := MigrateRosterV1ToV2(mustParseRosterNode(t, "schema_version: 2\n")); err == nil {
		t.Fatal("expected an error migrating a document that already declares schema_version: 2")
	}
}

func TestMigrateRosterV1ToV2_RejectsMissingSchemaVersion(t *testing.T) {
	if _, err := MigrateRosterV1ToV2(mustParseRosterNode(t, "users: []\n")); err == nil {
		t.Fatal("expected an error migrating a document with no schema_version")
	}
}

func TestMigrateRosterV1ToV2_RejectsNonMappingDocument(t *testing.T) {
	if _, err := MigrateRosterV1ToV2(mustParseRosterNode(t, "- just\n- a\n- list\n")); err == nil {
		t.Fatal("expected an error migrating a document whose top level isn't a mapping")
	}
}

func TestMigrateRosterV1ToV2_NetgroupsIdempotentIfAlreadyPresent(t *testing.T) {
	// Defensive only: a valid v1 document never actually has this key
	// (ValidateRosterV1 fails it closed as unknown), but MigrateRosterV1ToV2
	// itself should never duplicate the key if called on one anyway.
	node := mustParseRosterNode(t, `
schema_version: 1
freeipa: {admin: {principal: admin, password: x}}
netgroups: []
`)
	migrated, err := MigrateRosterV1ToV2(node)
	if err != nil {
		t.Fatalf("MigrateRosterV1ToV2() error = %v", err)
	}
	out := string(marshalNode(t, migrated))
	if strings.Count(out, "netgroups:") != 1 {
		t.Fatalf("expected exactly one netgroups: key, got:\n%s", out)
	}
}

// ---- M2: full canonical fixture ------------------------------------------

func TestMigrateRosterV1ToV2_CanonicalFixtureSemanticEquivalence(t *testing.T) {
	before, after := migrateCanonicalFixtureForTest(t)
	bf := ComputeRosterSemanticFingerprint(before)
	af := ComputeRosterSemanticFingerprint(after)
	if !RosterSemanticFingerprintsEqual(bf, af) {
		t.Fatalf("semantic fingerprint changed by migration:\nbefore: %+v\nafter:  %+v", bf, af)
	}
}

// ---- M3: legacy freeipa.domain/realm -------------------------------------

func TestMigrateRosterV1ToV2_PreservesFreeIPADomainAndRealm(t *testing.T) {
	migrated, err := MigrateRosterV1ToV2(mustParseRosterNode(t, `
schema_version: 1
freeipa:
  domain: ipa.pilot.internal
  realm: IPA.PILOT.INTERNAL
  admin: {principal: admin, password: x}
`))
	if err != nil {
		t.Fatalf("MigrateRosterV1ToV2() error = %v", err)
	}
	root := mustParseRoster(t, string(marshalNode(t, migrated)))
	freeipa := mapField(root, "freeipa")
	if stringField(freeipa, "domain") != "ipa.pilot.internal" || stringField(freeipa, "realm") != "IPA.PILOT.INTERNAL" {
		t.Fatalf("freeipa = %v, want domain/realm preserved", freeipa)
	}
}

// ---- M4: comments ---------------------------------------------------------

func TestMigrateRosterV1ToV2_PreservesComments(t *testing.T) {
	migrated, err := MigrateRosterV1ToV2(mustParseRosterNode(t, `schema_version: 1
freeipa:
  admin: {principal: admin, password: x}
users:
  - name: alice # keep this human note
`))
	if err != nil {
		t.Fatalf("MigrateRosterV1ToV2() error = %v", err)
	}
	out := string(marshalNode(t, migrated))
	if !strings.Contains(out, "keep this human note") {
		t.Fatalf("migrated output lost a comment:\n%s", out)
	}
}

// ---- M5: YAML anchors -----------------------------------------------------

func TestMigrateRosterV1ToV2_PreservesAnchorsAndAliases(t *testing.T) {
	migrated, err := MigrateRosterV1ToV2(mustParseRosterNode(t, `schema_version: 1
freeipa:
  admin: {principal: admin, password: x}
groups:
  - name: team-devs
    category: team
    membership: &shared_membership {authoritative: true, users: [], groups: []}
  - name: role-devs
    category: role
    membership: *shared_membership
`))
	if err != nil {
		t.Fatalf("MigrateRosterV1ToV2() error = %v", err)
	}
	out := string(marshalNode(t, migrated))
	if !strings.Contains(out, "&shared_membership") || !strings.Contains(out, "*shared_membership") {
		t.Fatalf("migrated output lost the anchor/alias:\n%s", out)
	}
	root := mustParseRoster(t, out)
	groups := listField(root, "groups")
	m0 := mapField(asMap(groups[0]), "membership")
	m1 := mapField(asMap(groups[1]), "membership")
	if !reflect.DeepEqual(m0, m1) {
		t.Fatalf("aliased membership diverged after migration: %v vs %v", m0, m1)
	}
}

// ---- M14/M15: effective HBAC/sudo access unchanged -----------------------

func TestMigrateRosterV1ToV2_EffectiveHBACAccessUnchanged(t *testing.T) {
	before, after := migrateCanonicalFixtureForTest(t)
	if !reflect.DeepEqual(EffectiveHBACAccessFromRoster(before), EffectiveHBACAccessFromRoster(after)) {
		t.Fatalf("effective HBAC access changed by migration:\nbefore: %+v\nafter:  %+v",
			EffectiveHBACAccessFromRoster(before), EffectiveHBACAccessFromRoster(after))
	}
}

func TestMigrateRosterV1ToV2_EffectiveSudoAccessUnchanged(t *testing.T) {
	before, after := migrateCanonicalFixtureForTest(t)
	if !reflect.DeepEqual(EffectiveSudoAccessFromRoster(before), EffectiveSudoAccessFromRoster(after)) {
		t.Fatalf("effective sudo access changed by migration:\nbefore: %+v\nafter:  %+v",
			EffectiveSudoAccessFromRoster(before), EffectiveSudoAccessFromRoster(after))
	}
}

// RosterSemanticFingerprintsEqual must not be vacuously true — prove it
// actually detects a real authorization change (a group gaining an
// HBAC-relevant member), or the migration-safety net above would pass for
// the wrong reason.
func TestRosterSemanticFingerprintsEqual_DetectsAddedHBACSubject(t *testing.T) {
	base := mustParseRoster(t, `
schema_version: 1
freeipa: {admin: {principal: admin, password: x}}
users:
  - name: alice
  - name: bob
groups:
  - name: access-ssh
    category: access
    membership: {authoritative: true, users: [alice], groups: []}
hbac:
  rules:
    - name: ssh-access
      subjects: {users: [], groups: [access-ssh]}
      targets: {hostcat: all}
      services: [sshd]
`)
	changed := mustParseRoster(t, `
schema_version: 1
freeipa: {admin: {principal: admin, password: x}}
users:
  - name: alice
  - name: bob
groups:
  - name: access-ssh
    category: access
    membership: {authoritative: true, users: [alice, bob], groups: []}
hbac:
  rules:
    - name: ssh-access
      subjects: {users: [], groups: [access-ssh]}
      targets: {hostcat: all}
      services: [sshd]
`)
	if RosterSemanticFingerprintsEqual(ComputeRosterSemanticFingerprint(base), ComputeRosterSemanticFingerprint(changed)) {
		t.Fatal("expected fingerprints to differ when a group gains an HBAC-relevant member")
	}
}

// ---- M16/M17: NFS client selector migration ------------------------------

func migrateSingleNFSClient(t *testing.T, clientType, value string) map[string]any {
	t.Helper()
	return migrateSingleNFSClientFromDoc(t, fmt.Sprintf(`
schema_version: 1
freeipa: {admin: {principal: admin, password: x}}
nfs:
  servers:
    - host: nfs1.ipa.pilot.internal
      state: present
      service_principal: {ensure: true, principal: nfs/nfs1.ipa.pilot.internal, keytab: /etc/krb5.keytab}
      shares:
        - name: alpha
          state: present
          source_path: /srv/nfs/alpha
          export:
            clients: [{type: %s, value: %q}]
            options: [rw]
`, clientType, value))
}

func migrateSingleNFSClientFromDoc(t *testing.T, doc string) map[string]any {
	t.Helper()
	migrated, err := MigrateRosterV1ToV2(mustParseRosterNode(t, doc))
	if err != nil {
		t.Fatalf("MigrateRosterV1ToV2() error = %v", err)
	}
	root := mustParseRoster(t, string(marshalNode(t, migrated)))
	servers := listField(mapField(root, "nfs"), "servers")
	shares := listField(asMap(servers[0]), "shares")
	export := mapField(asMap(shares[0]), "export")
	clients := listField(export, "clients")
	return asMap(clients[0])
}

func TestMigrateRosterV1ToV2_NFSNetworkTypePreservedAndRendersIdentically(t *testing.T) {
	client := migrateSingleNFSClient(t, "network", "192.168.122.0/24")
	if stringField(client, "type") != "network" {
		t.Fatalf("type = %v, want network preserved (provably output-equivalent)", client["type"])
	}
	if got := RenderNFSClientSelector(stringField(client, "type"), stringField(client, "value")); got != "192.168.122.0/24" {
		t.Fatalf("rendered = %q, want the old bare-value rendering unchanged", got)
	}
}

func TestMigrateRosterV1ToV2_NFSHostTypePreservedAndRendersIdentically(t *testing.T) {
	client := migrateSingleNFSClient(t, "host", "backup01.ipa.pilot.internal")
	if stringField(client, "type") != "host" {
		t.Fatalf("type = %v, want host preserved (provably output-equivalent)", client["type"])
	}
	if got := RenderNFSClientSelector(stringField(client, "type"), stringField(client, "value")); got != "backup01.ipa.pilot.internal" {
		t.Fatalf("rendered = %q, want the old bare-value rendering unchanged", got)
	}
}

func TestMigrateRosterV1ToV2_NFSLegacyHostgroupTypeBecomesRaw(t *testing.T) {
	// v1 rendering ignored type entirely, so a hand-written "hostgroup" here
	// never actually got an "@" prefix — migrating it to "hostgroup" as-is
	// under the v2 renderer would silently add one and break the export.
	client := migrateSingleNFSClient(t, "hostgroup", "@legacy-clients")
	if stringField(client, "type") != "raw" {
		t.Fatalf("type = %v, want raw", client["type"])
	}
	if got := RenderNFSClientSelector(stringField(client, "type"), stringField(client, "value")); got != "@legacy-clients" {
		t.Fatalf("rendered = %q, want the old bare-value rendering unchanged", got)
	}
}

func TestMigrateRosterV1ToV2_NFSUnrecognizedTypeBecomesRaw(t *testing.T) {
	client := migrateSingleNFSClient(t, "something-old", "@legacy-clients")
	if stringField(client, "type") != "raw" {
		t.Fatalf("type = %v, want raw", client["type"])
	}
	if got := RenderNFSClientSelector(stringField(client, "type"), stringField(client, "value")); got != "@legacy-clients" {
		t.Fatalf("rendered = %q, want the old bare-value rendering unchanged", got)
	}
}

func TestMigrateRosterV1ToV2_NFSMissingTypeBecomesRaw(t *testing.T) {
	client := migrateSingleNFSClientFromDoc(t, `
schema_version: 1
freeipa: {admin: {principal: admin, password: x}}
nfs:
  servers:
    - host: nfs1.ipa.pilot.internal
      state: present
      service_principal: {ensure: true, principal: nfs/nfs1.ipa.pilot.internal, keytab: /etc/krb5.keytab}
      shares:
        - name: alpha
          state: present
          source_path: /srv/nfs/alpha
          export:
            clients: [{value: 192.168.50.0/24}]
            options: [rw]
`)
	if stringField(client, "type") != "raw" {
		t.Fatalf("type = %v, want raw for a client with no declared type", client["type"])
	}
	if got := RenderNFSClientSelector(stringField(client, "type"), stringField(client, "value")); got != "192.168.50.0/24" {
		t.Fatalf("rendered = %q, want the old bare-value rendering unchanged", got)
	}
}

// ---- RenderNFSClientSelector unit coverage -------------------------------

func TestRenderNFSClientSelector(t *testing.T) {
	cases := []struct{ clientType, value, want string }{
		{"network", "192.168.1.0/24", "192.168.1.0/24"},
		{"host", "backup01.example.internal", "backup01.example.internal"},
		{"hostgroup", "web-servers", "@web-servers"},
		{"netgroup", "ng-project-alpha", "@ng-project-alpha"},
		{"raw", "@legacy-clients", "@legacy-clients"},
		{"", "192.168.1.0/24", "192.168.1.0/24"},
		{"unknown-future-type", "x", "x"},
	}
	for _, c := range cases {
		if got := RenderNFSClientSelector(c.clientType, c.value); got != c.want {
			t.Errorf("RenderNFSClientSelector(%q, %q) = %q, want %q", c.clientType, c.value, got, c.want)
		}
	}
}
