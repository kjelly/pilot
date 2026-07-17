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
