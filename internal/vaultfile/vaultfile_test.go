package vaultfile

import (
	"strings"
	"testing"
)

func TestParse_EditableTopLevelScalars(t *testing.T) {
	doc, err := Parse([]byte("---\nipa_admin_password: \"x\"\nalertmanager_config: |\n  route:\n    receiver: \"null\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !doc.Editable() {
		t.Fatal("expected top-level scalar/block-scalar vault doc to be editable")
	}
	if len(doc.Entries()) != 2 {
		t.Fatalf("entries = %d, want 2", len(doc.Entries()))
	}
	if doc.Entries()[1].DisplayValue() != "route:\\n  receiver: \"null\"\\n" {
		t.Fatalf("unexpected display value: %q", doc.Entries()[1].DisplayValue())
	}
}

func TestParse_ComplexStructureIsNotEditable(t *testing.T) {
	doc, err := Parse([]byte("---\nipa_users:\n  - name: alice\n"))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Editable() {
		t.Fatal("expected sequence-based vault yaml to be treated as non-editable")
	}
}

func TestDoc_HasNestedMappingIdentifiesSchemaOwnedBlock(t *testing.T) {
	doc, err := Parse([]byte("---\nipa_admin_password: x\nsnmp_exporter_credentials:\n  switch-v3:\n    username: operator\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !doc.HasNestedMapping("snmp_exporter_credentials") {
		t.Fatal("snmp_exporter_credentials nested map was not detected")
	}
	if doc.HasNestedMapping("ipa_admin_password") {
		t.Fatal("scalar vault value was reported as a nested map")
	}
}

func TestDoc_EditableWithPreservedNestedMappings(t *testing.T) {
	doc, err := Parse([]byte("---\nipa_admin_password: x\nsnmp_exporter_credentials:\n  switch-v3:\n    username: operator\n"))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Editable() {
		t.Fatal("nested mapping must not be generically editable by default")
	}
	if !doc.EditableWithPreservedNestedMappings("snmp_exporter_credentials") {
		t.Fatal("named SNMP mapping should be preservable alongside scalar keys")
	}
	if got := doc.ScalarEntries(); len(got) != 1 || got[0].Key != "ipa_admin_password" {
		t.Fatalf("scalar entries = %#v, want only ipa_admin_password", got)
	}

	doc.Set("snmp_exporter_credentials", "must-not-replace")
	doc.Delete("snmp_exporter_credentials")
	got := string(doc.Bytes())
	if !strings.Contains(got, "snmp_exporter_credentials:") || !strings.Contains(got, "switch-v3:") {
		t.Fatalf("generic mutation altered preserved mapping:\n%s", got)
	}

	complex, err := Parse([]byte("---\nsnmp_exporter_credentials:\n  switch-v3: {}\nother: []\n"))
	if err != nil {
		t.Fatal(err)
	}
	if complex.EditableWithPreservedNestedMappings("snmp_exporter_credentials") {
		t.Fatal("unlisted sequence must remain unsupported")
	}
}

func TestDoc_SetAddDeleteAndBytes(t *testing.T) {
	doc, err := Parse([]byte("---\nipa_admin_password: \"x\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	doc.Set("ipa_admin_password", "updated")
	doc.Add("restic_password", "line1\nline2")
	doc.Delete("missing")
	doc.Delete("ipa_admin_password")

	got := string(doc.Bytes())
	if strings.Contains(got, "ipa_admin_password") {
		t.Fatalf("deleted key still present:\n%s", got)
	}
	if !strings.Contains(got, "restic_password: |") {
		t.Fatalf("multiline key should render as literal block:\n%s", got)
	}
	if !strings.Contains(got, "  line1\n  line2\n") {
		t.Fatalf("multiline content missing:\n%s", got)
	}
}

// TestDoc_EmptySkeletonIsEditable covers the exact bytes `pilot edit`
// writes for a brand-new vault file ("---\n" with nothing after it,
// i.e. yaml.v3's representation of an empty document is one ScalarNode
// tagged !!null, not zero content) — Editable() must accept it and Add
// must work, or `pilot edit`'s "create new plaintext vault file" flow
// fails before a single key can ever be added.
func TestDoc_EmptySkeletonIsEditable(t *testing.T) {
	doc, err := Parse([]byte("---\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !doc.Editable() {
		t.Fatal("empty --- skeleton should be Editable()")
	}
	doc.Add("ipa_admin_password", "x")
	got := string(doc.Bytes())
	if !strings.Contains(got, `ipa_admin_password: "x"`) {
		t.Fatalf("added key missing:\n%s", got)
	}
}
