package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/kjelly/pilot/internal/inventory"
)

func TestFindHost_AndRemoveHost(t *testing.T) {
	hf := &inventory.HostsFile{Hosts: []inventory.Host{
		{Name: "web-1", AnsibleHost: "10.0.0.1"},
		{Name: "web-2", AnsibleHost: "10.0.0.2"},
	}}

	if h := findHost(hf, "web-2"); h == nil || h.AnsibleHost != "10.0.0.2" {
		t.Fatalf("findHost(web-2) = %+v", h)
	}
	if h := findHost(hf, "nope"); h != nil {
		t.Fatalf("findHost(nope) = %+v, want nil", h)
	}

	removeHost(hf, "web-1")
	if len(hf.Hosts) != 1 || hf.Hosts[0].Name != "web-2" {
		t.Fatalf("after removeHost(web-1): %+v", hf.Hosts)
	}
}

func TestHostSummary_ShowsPlaceholdersForEmptyFields(t *testing.T) {
	hf := &inventory.HostsFile{Hosts: []inventory.Host{{Name: "web-1"}}}
	got := hostSummary(hf, "web-1")
	if got != "web-1 — (尚未填 ansible_host) — (尚未選角色)" {
		t.Fatalf("hostSummary = %q", got)
	}
}

func TestHostSummary_UnknownHostFallsBackToName(t *testing.T) {
	hf := &inventory.HostsFile{}
	if got := hostSummary(hf, "ghost"); got != "ghost" {
		t.Fatalf("hostSummary(ghost) = %q, want %q", got, "ghost")
	}
}

func TestHasRole(t *testing.T) {
	roles := []string{"dns", "ntp"}
	if !hasRole(roles, "dns") {
		t.Fatal("expected hasRole(dns) = true")
	}
	if hasRole(roles, "docker") {
		t.Fatal("expected hasRole(docker) = false")
	}
}

func TestUnionRoles_AddsWithoutDuplicatingOrRemoving(t *testing.T) {
	got := unionRoles([]string{"dns", "ntp"}, []string{"ntp", "docker"})
	want := []string{"dns", "docker", "ntp"} // sorted
	if len(got) != len(want) {
		t.Fatalf("unionRoles = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unionRoles = %v, want %v", got, want)
		}
	}
}

func TestUnionRoles_EmptyDstJustSortsAdd(t *testing.T) {
	got := unionRoles(nil, []string{"ntp", "dns"})
	if len(got) != 2 || got[0] != "dns" || got[1] != "ntp" {
		t.Fatalf("unionRoles(nil, ...) = %v", got)
	}
}

func TestOtherHostsWithRoles_ExcludesSelfAndRoleless(t *testing.T) {
	hf := &inventory.HostsFile{Hosts: []inventory.Host{
		{Name: "web-1", Roles: []string{"linux-servers"}},
		{Name: "web-2"}, // no roles yet — not a candidate
		{Name: "web-3", Roles: []string{"linux-servers", "dns"}},
	}}
	got := otherHostsWithRoles(hf, "web-1")
	if len(got) != 1 || got[0].Name != "web-3" {
		t.Fatalf("otherHostsWithRoles(web-1) = %+v, want just web-3", got)
	}
}

func TestOtherHostsWithRoles_NoneAvailable(t *testing.T) {
	hf := &inventory.HostsFile{Hosts: []inventory.Host{{Name: "web-1", Roles: []string{"linux-servers"}}}}
	if got := otherHostsWithRoles(hf, "web-1"); len(got) != 0 {
		t.Fatalf("otherHostsWithRoles = %+v, want empty (only self has roles)", got)
	}
}

func TestSortedKeysOf(t *testing.T) {
	got := sortedKeysOf(map[string]string{"b": "2", "a": "1", "c": "3"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("sortedKeysOf = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sortedKeysOf = %v, want %v", got, want)
		}
	}
}

func TestDisplayOrPlaceholder(t *testing.T) {
	if got := displayOrPlaceholder(""); got != "(未設定)" {
		t.Errorf("displayOrPlaceholder(\"\") = %q", got)
	}
	if got := displayOrPlaceholder("x"); got != "x" {
		t.Errorf("displayOrPlaceholder(x) = %q", got)
	}
}

func TestScanGroupVars_SplitsExistingFromMissingExamples(t *testing.T) {
	t.Chdir(t.TempDir())
	mustWriteFile(t, "group_vars/dns.yml", "dns_listen_addr: 10.0.0.1\n")
	mustWriteFile(t, "group_vars/dns.example.yml", "dns_listen_addr: 10.0.0.1\n")
	mustWriteFile(t, "group_vars/freeipa.example.yml", "freeipa_domain: ipa.pilot.internal\n")
	mustWriteFile(t, "group_vars/dns/zones.example.yaml", "zones: []\n") // nested dir, must be ignored

	existing, missing, err := scanGroupVars("group_vars", "group_vars")
	if err != nil {
		t.Fatal(err)
	}
	if len(existing) != 1 || existing[0] != "dns.yml" {
		t.Fatalf("existing = %v, want [dns.yml]", existing)
	}
	if len(missing) != 1 || missing[0] != "freeipa" {
		t.Fatalf("missing = %v, want [freeipa]", missing)
	}
}

func TestScanGroupVars_MissingDirIsNotAnError(t *testing.T) {
	t.Chdir(t.TempDir())
	existing, missing, err := scanGroupVars("group_vars", "group_vars")
	if err != nil {
		t.Fatal(err)
	}
	if len(existing) != 0 || len(missing) != 0 {
		t.Fatalf("existing=%v missing=%v, want both empty", existing, missing)
	}
}

func TestScanGroupVars_TargetAndExampleDirsCanDiffer(t *testing.T) {
	t.Chdir(t.TempDir())
	// The example templates live in the fixed CWD-relative group_vars/
	// (as if this were the repo root or Docker image), but the actual
	// settings files being edited live under envs/staging/group_vars/
	// (as if --dir pointed there) — mirroring inventory.go's
	// source-fixed / destination-follows-dir split.
	mustWriteFile(t, "group_vars/dns.example.yml", "dns_listen_addr: 10.0.0.1\n")
	mustWriteFile(t, "group_vars/freeipa.example.yml", "freeipa_domain: ipa.pilot.internal\n")
	mustWriteFile(t, "envs/staging/group_vars/dns.yml", "dns_listen_addr: 10.0.0.99\n")

	existing, missing, err := scanGroupVars(filepath.Join("envs", "staging", "group_vars"), "group_vars")
	if err != nil {
		t.Fatal(err)
	}
	if len(existing) != 1 || existing[0] != "dns.yml" {
		t.Fatalf("existing = %v, want [dns.yml] (from the target dir, not the example dir)", existing)
	}
	if len(missing) != 1 || missing[0] != "freeipa" {
		t.Fatalf("missing = %v, want [freeipa] (dns already has a target-dir file, so it's not missing)", missing)
	}
}

func TestSaveHosts_RendersAndWritesFile(t *testing.T) {
	t.Chdir(t.TempDir())
	hf := &inventory.HostsFile{
		Vars: map[string]string{"ansible_user": "ubuntu"},
		Hosts: []inventory.Host{
			{Name: "web-1", AnsibleHost: "10.0.0.1", Roles: []string{"linux-servers"}},
		},
	}

	var buf bytes.Buffer
	if err := saveHosts(&buf, "hosts.yml", hf); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile("hosts.yml")
	if err != nil {
		t.Fatal(err)
	}
	reparsed, err := inventory.Parse(data)
	if err != nil {
		t.Fatalf("saved hosts.yml doesn't parse: %v\n%s", err, data)
	}
	if len(reparsed.Hosts) != 1 || reparsed.Hosts[0].Name != "web-1" {
		t.Fatalf("reparsed = %+v", reparsed.Hosts)
	}
	if buf.String() == "" {
		t.Fatal("expected a confirmation message to be written")
	}
}

func TestSaveHosts_CreatesTargetDirWhenMissing(t *testing.T) {
	t.Chdir(t.TempDir())
	hf := &inventory.HostsFile{Hosts: []inventory.Host{{Name: "web-1", AnsibleHost: "10.0.0.1"}}}
	path := filepath.Join("envs", "staging", "hosts.yml") // --dir envs/staging, not created yet

	var buf bytes.Buffer
	if err := saveHosts(&buf, path, hf); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s to be created: %v", path, err)
	}
}

func TestSaveHosts_ReportsLintIssuesWithoutBlockingSave(t *testing.T) {
	t.Chdir(t.TempDir())
	hf := &inventory.HostsFile{Hosts: []inventory.Host{{Name: "web-1"}}} // no ansible_host: lint error

	var buf bytes.Buffer
	if err := saveHosts(&buf, "hosts.yml", hf); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat("hosts.yml"); err != nil {
		t.Fatalf("expected hosts.yml to be written despite lint errors: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("error")) {
		t.Errorf("expected the lint error to be reported, got: %q", buf.String())
	}
}

func TestScanVaultFiles_ListsOnlyYAMLFiles(t *testing.T) {
	t.Chdir(t.TempDir())
	mustWriteFile(t, ".vault/main.yaml", "---\n")
	mustWriteFile(t, ".vault/ipa-identity.yml", "---\n")
	mustWriteFile(t, ".vault/notes.txt", "ignore\n")
	if err := os.MkdirAll(".vault/subdir", 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := scanVaultFiles(".vault")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"ipa-identity.yml", "main.yaml"}
	if len(got) != len(want) {
		t.Fatalf("scanVaultFiles = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("scanVaultFiles = %v, want %v", got, want)
		}
	}
}

func TestScanVaultFiles_MissingDirIsNotAnError(t *testing.T) {
	t.Chdir(t.TempDir())
	got, err := scanVaultFiles(".vault")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("scanVaultFiles = %v, want empty", got)
	}
}

func TestIsAnsibleVaultEncrypted(t *testing.T) {
	if !isAnsibleVaultEncrypted([]byte("$ANSIBLE_VAULT;1.1;AES256\nabcdef\n")) {
		t.Fatal("expected ansible-vault header to be detected")
	}
	if isAnsibleVaultEncrypted([]byte("---\nipa_admin_password: x\n")) {
		t.Fatal("plaintext yaml should not be detected as ansible-vault")
	}
}

// Vault-document parsing/editing tests (Parse/Doc.Editable/Set/Add/
// Delete/Bytes) live in internal/vaultfile/vaultfile_test.go now that
// that logic has moved out of this UI-layer file.
