package monitoring

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSNMPCredentialDoc_MissingFileStartsEmpty(t *testing.T) {
	dir := t.TempDir()
	doc, err := LoadSNMPCredentialDoc(filepath.Join(dir, "main.yaml"))
	if err != nil {
		t.Fatalf("LoadSNMPCredentialDoc: %v", err)
	}
	if refs := doc.Refs(); len(refs) != 0 {
		t.Fatalf("expected no refs, got %v", refs)
	}
	if keys := doc.OtherTopLevelKeys(); len(keys) != 0 {
		t.Fatalf("expected no other keys, got %v", keys)
	}
}

func TestSNMPCredentialDoc_SaveRejectsReverseDirectoryAlias(t *testing.T) {
	for _, tree := range []string{"group_vars", "host_vars"} {
		t.Run(tree, func(t *testing.T) {
			dir, external := t.TempDir(), t.TempDir()
			t.Chdir(dir)
			path := filepath.Join(external, "new", "all.yml")
			doc, err := LoadSNMPCredentialDoc(path)
			if err != nil {
				t.Fatal(err)
			}
			doc.Set("switch", SNMPCredentialFields{"community": "DUMMY130_PASSWORD"})
			if err := os.Symlink(external, filepath.Join(dir, tree)); err != nil {
				t.Fatal(err)
			}
			if err := WriteSNMPCredentialDoc(path, doc); err == nil {
				t.Fatal("SNMP creation accepted reverse vars alias")
			}
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatal("SNMP creation wrote forbidden destination")
			}
			if _, err := os.Stat(filepath.Dir(path)); !os.IsNotExist(err) {
				t.Fatal("SNMP creation created forbidden parent directory")
			}
			const original = "port: 8080\n"
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := WriteSNMPCredentialDoc(path, doc); err == nil {
				t.Fatal("SNMP save accepted reverse vars alias")
			}
			data, err := os.ReadFile(path)
			if err != nil || string(data) != original {
				t.Fatal("SNMP save changed forbidden destination")
			}
		})
	}
}

func TestSNMPCredentialDoc_SetGetDeleteRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".vault", "main.yaml")

	doc, err := LoadSNMPCredentialDoc(path)
	if err != nil {
		t.Fatalf("LoadSNMPCredentialDoc: %v", err)
	}
	doc.Set("lab-switch-v3", SNMPCredentialFields{
		"username":     "labuser",
		"authPassword": "authpw",
		"privPassword": "privpw",
	})
	if err := WriteSNMPCredentialDoc(path, doc); err != nil {
		t.Fatalf("WriteSNMPCredentialDoc: %v", err)
	}

	reloaded, err := LoadSNMPCredentialDoc(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if refs := reloaded.Refs(); len(refs) != 1 || refs[0] != "lab-switch-v3" {
		t.Fatalf("refs = %v, want [lab-switch-v3]", refs)
	}
	fields, ok := reloaded.Get("lab-switch-v3")
	if !ok || fields["username"] != "labuser" || fields["authPassword"] != "authpw" || fields["privPassword"] != "privpw" {
		t.Fatalf("fields = %+v", fields)
	}

	reloaded.Set("lab-switch-v3", SNMPCredentialFields{"username": "changed", "authPassword": "authpw", "privPassword": "privpw"})
	reloaded.Delete("does-not-exist") // no-op
	if err := WriteSNMPCredentialDoc(path, reloaded); err != nil {
		t.Fatalf("WriteSNMPCredentialDoc (update): %v", err)
	}
	again, err := LoadSNMPCredentialDoc(path)
	if err != nil {
		t.Fatalf("reload 2: %v", err)
	}
	if fields, _ := again.Get("lab-switch-v3"); fields["username"] != "changed" {
		t.Fatalf("update did not persist: %+v", fields)
	}

	again.Delete("lab-switch-v3")
	if err := WriteSNMPCredentialDoc(path, again); err != nil {
		t.Fatalf("WriteSNMPCredentialDoc (delete): %v", err)
	}
	final, err := LoadSNMPCredentialDoc(path)
	if err != nil {
		t.Fatalf("reload 3: %v", err)
	}
	if refs := final.Refs(); len(refs) != 0 {
		t.Fatalf("expected ref deleted, got %v", refs)
	}
}

// TestSNMPCredentialDoc_PreservesOtherTopLevelKeys guards the whole reason
// this type exists instead of reusing internal/vaultfile: a vault file that
// already holds unrelated scalar secrets must survive editing the
// snmp_exporter_credentials block byte-for-byte on its other keys.
func TestSNMPCredentialDoc_PreservesOtherTopLevelKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "main.yaml")
	seed := "---\nfreeipa_admin_password: \"CHANGE-ME\"\nother_secret: \"keep-me\"\n"
	if err := os.WriteFile(path, []byte(seed), 0o600); err != nil {
		t.Fatal(err)
	}

	doc, err := LoadSNMPCredentialDoc(path)
	if err != nil {
		t.Fatalf("LoadSNMPCredentialDoc: %v", err)
	}
	if keys := doc.OtherTopLevelKeys(); len(keys) != 2 {
		t.Fatalf("OtherTopLevelKeys = %v, want 2 entries", keys)
	}
	doc.Set("core-switch-v3", SNMPCredentialFields{"community": "public"})
	if err := WriteSNMPCredentialDoc(path, doc); err != nil {
		t.Fatalf("WriteSNMPCredentialDoc: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	if !strings.Contains(got, "freeipa_admin_password") || !strings.Contains(got, "other_secret") || !strings.Contains(got, "keep-me") {
		t.Fatalf("other top-level keys were lost:\n%s", got)
	}
	if !strings.Contains(got, SNMPCredentialsKey) || !strings.Contains(got, "core-switch-v3") {
		t.Fatalf("new credential block missing:\n%s", got)
	}
}
