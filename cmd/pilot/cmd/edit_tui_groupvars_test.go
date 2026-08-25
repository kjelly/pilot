package cmd

import (
	"bytes"
	"io"
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

// TestReadFreeIPADomain fixes the behavior spec for looking up the
// workspace's configured FreeIPA zone: a missing group_vars/freeipa.yml
// means FreeIPA isn't even part of this workspace (so no host could pass
// the freeipa-client eligibility check either), an active explicit value
// wins, and a present-but-commented-out key falls back to the same default
// every apply playbook already assumes ("ipa.pilot.internal" |
// freeipa-client-apply.yml's `ipa_domain` default).
func TestReadFreeIPADomain(t *testing.T) {
	t.Run("missing file returns empty", func(t *testing.T) {
		if got := readFreeIPADomain(t.TempDir()); got != "" {
			t.Fatalf("readFreeIPADomain() = %q, want empty for a workspace with no freeipa.yml", got)
		}
	})
	t.Run("active explicit value wins", func(t *testing.T) {
		dir := t.TempDir()
		mustWriteFile(t, filepath.Join(dir, "group_vars", "freeipa.yml"), "freeipa_domain: corp.example.com\n")
		if got := readFreeIPADomain(dir); got != "corp.example.com" {
			t.Fatalf("readFreeIPADomain() = %q, want corp.example.com", got)
		}
	})
	t.Run("commented-out key falls back to the shipped default", func(t *testing.T) {
		dir := t.TempDir()
		mustWriteFile(t, filepath.Join(dir, "group_vars", "freeipa.yml"), "# freeipa_domain: ipa.pilot.internal\n")
		if got := readFreeIPADomain(dir); got != "ipa.pilot.internal" {
			t.Fatalf("readFreeIPADomain() = %q, want the shipped default ipa.pilot.internal", got)
		}
	})
}

// TestFqdnForRoleHost fixes the behavior spec for edit-time group_vars
// scaffolding's FQDN upgrade: role's sole host must itself be a
// freeipa-client (a real A record exists) and — since a freshly scaffolded
// file doesn't pin down which host will actually read this value — every
// host in the fleet must already be a freeipa-dns-client, or the upgrade
// conservatively declines and the caller keeps the plain IP.
func TestFqdnForRoleHost(t *testing.T) {
	freeIPADomainDir := func(t *testing.T) string {
		t.Helper()
		dir := t.TempDir()
		mustWriteFile(t, filepath.Join(dir, "group_vars", "freeipa.yml"), "freeipa_domain: ipa.pilot.internal\n")
		return dir
	}

	t.Run("eligible: target enrolled, whole fleet dns-covered", func(t *testing.T) {
		hf := &inventory.HostsFile{Hosts: []inventory.Host{
			{Name: "ipa-1", AnsibleHost: "10.0.0.5", Roles: []string{"freeipa-server", "freeipa-client", "freeipa-dns-client"}},
			{Name: "client-1", AnsibleHost: "10.0.0.6", Roles: []string{"freeipa-client", "freeipa-dns-client"}},
		}}
		got, ok := fqdnForRoleHost(hf, "freeipa-server", freeIPADomainDir(t))
		if !ok || got != "ipa-1.ipa.pilot.internal" {
			t.Fatalf("fqdnForRoleHost() = (%q, %v), want (ipa-1.ipa.pilot.internal, true)", got, ok)
		}
	})

	t.Run("target lacks freeipa-client role -> ineligible", func(t *testing.T) {
		hf := &inventory.HostsFile{Hosts: []inventory.Host{
			{Name: "ipa-1", AnsibleHost: "10.0.0.5", Roles: []string{"freeipa-server", "freeipa-dns-client"}},
			{Name: "client-1", AnsibleHost: "10.0.0.6", Roles: []string{"freeipa-client", "freeipa-dns-client"}},
		}}
		if _, ok := fqdnForRoleHost(hf, "freeipa-server", freeIPADomainDir(t)); ok {
			t.Fatalf("fqdnForRoleHost() ok = true, want false when the target has no A record")
		}
	})

	t.Run("some other fleet host lacks freeipa-dns-client -> ineligible", func(t *testing.T) {
		hf := &inventory.HostsFile{Hosts: []inventory.Host{
			{Name: "ipa-1", AnsibleHost: "10.0.0.5", Roles: []string{"freeipa-server", "freeipa-client", "freeipa-dns-client"}},
			{Name: "client-1", AnsibleHost: "10.0.0.6", Roles: []string{"freeipa-client"}},
		}}
		if _, ok := fqdnForRoleHost(hf, "freeipa-server", freeIPADomainDir(t)); ok {
			t.Fatalf("fqdnForRoleHost() ok = true, want false when any fleet host can't resolve FreeIPA DNS")
		}
	})

	t.Run("no freeipa.yml in workspace -> domain unresolved -> ineligible", func(t *testing.T) {
		hf := &inventory.HostsFile{Hosts: []inventory.Host{
			{Name: "ipa-1", AnsibleHost: "10.0.0.5", Roles: []string{"freeipa-server", "freeipa-client", "freeipa-dns-client"}},
		}}
		if _, ok := fqdnForRoleHost(hf, "freeipa-server", t.TempDir()); ok {
			t.Fatalf("fqdnForRoleHost() ok = true, want false with no configured freeipa_domain")
		}
	})

	t.Run("ambiguous role match -> ineligible", func(t *testing.T) {
		hf := &inventory.HostsFile{Hosts: []inventory.Host{
			{Name: "ipa-1", AnsibleHost: "10.0.0.5", Roles: []string{"freeipa-server", "freeipa-client", "freeipa-dns-client"}},
			{Name: "ipa-2", AnsibleHost: "10.0.0.6", Roles: []string{"freeipa-server", "freeipa-client", "freeipa-dns-client"}},
		}}
		if _, ok := fqdnForRoleHost(hf, "freeipa-server", freeIPADomainDir(t)); ok {
			t.Fatalf("fqdnForRoleHost() ok = true, want false for an ambiguous (2-host) role")
		}
	})
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

	got := autofillCrossRoleHostVars(t.TempDir(), hf, data)
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

	got := autofillCrossRoleHostVars(t.TempDir(), hf, data)
	if string(got) != string(data) {
		t.Fatalf("autofillCrossRoleHostVars() = %q, want unchanged (ambiguous role)", got)
	}
}

func TestAutofillCrossRoleHostVars_NeverOverwritesAlreadyActiveValue(t *testing.T) {
	hf := &inventory.HostsFile{Hosts: []inventory.Host{
		{Name: "ipa-1", AnsibleHost: "10.0.0.5", Roles: []string{"freeipa-server"}},
	}}
	data := []byte("---\nfreeipa_server_ip: \"10.9.9.9\"\nfreeipa_domain: ipa.pilot.internal\n")

	got := autofillCrossRoleHostVars(t.TempDir(), hf, data)
	if string(got) != string(data) {
		t.Fatalf("autofillCrossRoleHostVars() = %q, want unchanged (already active)", got)
	}
}

func TestAutofillCrossRoleHostVars_FillsActiveEmptyValue(t *testing.T) {
	hf := &inventory.HostsFile{Hosts: []inventory.Host{
		{Name: "s3-1", AnsibleHost: "10.0.0.8", Roles: []string{"seaweedfs-s3"}},
	}}
	data := []byte("---\nthanos_s3_target_host: \"\"\n")

	got := autofillCrossRoleHostVars(t.TempDir(), hf, data)
	if !strings.Contains(string(got), "thanos_s3_target_host: 10.0.0.8") {
		t.Fatalf("autofillCrossRoleHostVars() = %q, want an active derived thanos S3 host", got)
	}
}

func TestAutofillCrossRoleHostVars_NilHostsFileIsNoop(t *testing.T) {
	data := []byte("---\n# freeipa_server_ip: \"192.0.2.10\"\n")
	got := autofillCrossRoleHostVars("", nil, data)
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
	got := autofillCrossRoleHostVars(t.TempDir(), hf, data)
	if !strings.Contains(string(got), "freeipa_server_ip: 10.0.0.9") {
		t.Fatalf("autofill against the real freeipa.example.yml did not produce freeipa_server_ip: 10.0.0.9:\n%s", got)
	}
}

func TestGroupVarsKeyAlreadyConfigured_TrueWhenActiveInEveryFileThatHasIt(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "group_vars", "wazuh-fim.yml"), "wazuh_manager_host: 10.1.58.12\n")
	mustWriteFile(t, filepath.Join(dir, "group_vars", "other.yml"), "some_unrelated_key: 1\n")

	got, err := groupVarsKeyAlreadyConfigured(dir, "wazuh_manager_host")
	if err != nil {
		t.Fatal(err)
	}
	if !got {
		t.Fatalf("groupVarsKeyAlreadyConfigured() = false, want true (key is active with a real value)")
	}
}

func TestGroupVarsKeyAlreadyConfigured_FalseWhenCommentedOut(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "group_vars", "wazuh-fim.yml"), "# wazuh_manager_host: CHANGE-ME\n")

	got, err := groupVarsKeyAlreadyConfigured(dir, "wazuh_manager_host")
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Fatalf("groupVarsKeyAlreadyConfigured() = true, want false (key is only a commented-out example)")
	}
}

func TestGroupVarsKeyAlreadyConfigured_FalseWhenAbsentEverywhere(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "group_vars", "other.yml"), "some_unrelated_key: 1\n")

	got, err := groupVarsKeyAlreadyConfigured(dir, "wazuh_manager_host")
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Fatalf("groupVarsKeyAlreadyConfigured() = true, want false (key never appears in any group_vars file)")
	}
}

func TestGroupVarsKeyAlreadyConfigured_FalseWhenAnyFileStillLacksIt(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "group_vars", "audit-log-forwarding.yml"), "siem_forward_host: 10.1.58.12\n")
	mustWriteFile(t, filepath.Join(dir, "group_vars", "wazuh-manager.yml"), "# siem_forward_host: CHANGE-ME\n")

	got, err := groupVarsKeyAlreadyConfigured(dir, "siem_forward_host")
	if err != nil {
		t.Fatal(err)
	}
	if got {
		t.Fatalf("groupVarsKeyAlreadyConfigured() = true, want false — wazuh-manager.yml still needs it")
	}
}

func TestPersistAutoHostVarToGroupVars_ActivatesEveryFileThatMentionsTheKey(t *testing.T) {
	dir := t.TempDir()
	mustWriteFile(t, filepath.Join(dir, "group_vars", "wazuh-fim.yml"), "# wazuh_manager_host: CHANGE-ME\n")
	mustWriteFile(t, filepath.Join(dir, "group_vars", "unrelated.yml"), "some_unrelated_key: 1\n")

	if err := persistAutoHostVarToGroupVars(io.Discard, dir, "wazuh_manager_host", "10.1.58.12"); err != nil {
		t.Fatal(err)
	}

	assertFileContent(t, filepath.Join(dir, "group_vars", "wazuh-fim.yml"), "wazuh_manager_host: 10.1.58.12\n")
	assertFileContent(t, filepath.Join(dir, "group_vars", "unrelated.yml"), "some_unrelated_key: 1\n")

	configured, err := groupVarsKeyAlreadyConfigured(dir, "wazuh_manager_host")
	if err != nil {
		t.Fatal(err)
	}
	if !configured {
		t.Fatalf("wazuh_manager_host should read as already configured immediately after persisting")
	}
}

func TestPersistAutoHostVarToGroupVars_NoopWhenAlreadyCorrect(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "group_vars", "wazuh-fim.yml")
	mustWriteFile(t, path, "wazuh_manager_host: 10.1.58.12\n")

	if err := persistAutoHostVarToGroupVars(io.Discard, dir, "wazuh_manager_host", "10.1.58.12"); err != nil {
		t.Fatal(err)
	}
	assertFileContent(t, path, "wazuh_manager_host: 10.1.58.12\n")
}

// TestCopyMissingGroupVars_AutofillsCrossRoleHostVarsForFreshFile locks the
// 2026-08-19 fix: `pilot inventory generate`'s backfill used to copy each
// group_vars example verbatim (no autofill), unlike pilot edit's own
// group_vars picker — the documented gap behind operators seeing `pilot
// deploy`'s "偵測到...這次要用它嗎？" prompt fire on every single run even
// against a workspace whose topology has always unambiguously resolved
// these vars.
func TestCopyMissingGroupVars_AutofillsCrossRoleHostVarsForFreshFile(t *testing.T) {
	t.Chdir(t.TempDir())
	mustWriteFile(t, "group_vars/freeipa.example.yml", "# freeipa_server_ip: \"192.0.2.10\"\nfreeipa_domain: ipa.pilot.internal\n")
	hf := &inventory.HostsFile{Hosts: []inventory.Host{
		{Name: "ipa-1", AnsibleHost: "10.1.58.11", Roles: []string{"freeipa-server"}},
	}}

	var buf bytes.Buffer
	copyMissingGroupVars(&buf, ".", []string{"freeipa"}, hf)

	assertFileContent(t, "group_vars/freeipa.yml", "freeipa_server_ip: 10.1.58.11\nfreeipa_domain: ipa.pilot.internal\n")
}
