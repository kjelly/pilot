package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const hostsYMLWithFreeIPAClients = `hosts:
  web1:
    ansible_host: "10.0.0.1"
    roles: [freeipa-client, host-monitoring]
  web2.example.internal:
    ansible_host: "10.0.0.2"
    roles: [freeipa-client]
  plain:
    ansible_host: "10.0.0.3"
    roles: [host-monitoring]
`

func writeAutoFillWorkspace(t *testing.T, rosterContent, hostsYML string) (dir, rosterPath string) {
	t.Helper()
	dir = t.TempDir()
	rosterPath = filepath.Join(dir, "ipa-identity.yaml")
	if err := os.WriteFile(rosterPath, []byte(rosterContent), 0o600); err != nil {
		t.Fatalf("write roster: %v", err)
	}
	if hostsYML != "" {
		if err := os.WriteFile(filepath.Join(dir, "hosts.yml"), []byte(hostsYML), 0o600); err != nil {
			t.Fatalf("write hosts.yml: %v", err)
		}
	}
	return dir, rosterPath
}

func TestAutoFillFreeIPAClientRosterHosts_AddsMissingClientsOnly(t *testing.T) {
	dir, path := writeAutoFillWorkspace(t, rosterFixtureNoNFS, hostsYMLWithFreeIPAClients)

	added, err := AutoFillFreeIPAClientRosterHosts(dir, path)
	if err != nil {
		t.Fatalf("AutoFillFreeIPAClientRosterHosts() error = %v", err)
	}
	want := []string{"web1.ipa.pilot.internal", "web2.example.internal"}
	if len(added) != len(want) || added[0] != want[0] || added[1] != want[1] {
		t.Fatalf("added = %v, want %v", added, want)
	}

	data := readFileHelper(t, path)
	if !strings.Contains(data, "alice") {
		t.Fatalf("autofill should not disturb existing users content:\n%s", data)
	}
	if !strings.Contains(data, "name: web1.ipa.pilot.internal") || !strings.Contains(data, "ip_address: 10.0.0.1") {
		t.Fatalf("expected web1 host stub with derived FQDN in roster:\n%s", data)
	}
	if !strings.Contains(data, "name: web2.example.internal") {
		t.Fatalf("expected web2 host stub (already FQDN-shaped, no domain suffix) in roster:\n%s", data)
	}
	if strings.Contains(data, "plain") {
		t.Fatalf("host without freeipa-client role must not be added:\n%s", data)
	}
}

func TestAutoFillFreeIPAClientRosterHosts_IdempotentOnRepeatedCalls(t *testing.T) {
	dir, path := writeAutoFillWorkspace(t, rosterFixtureNoNFS, hostsYMLWithFreeIPAClients)

	if _, err := AutoFillFreeIPAClientRosterHosts(dir, path); err != nil {
		t.Fatalf("first call error = %v", err)
	}
	added, err := AutoFillFreeIPAClientRosterHosts(dir, path)
	if err != nil {
		t.Fatalf("second call error = %v", err)
	}
	if len(added) != 0 {
		t.Fatalf("second call added = %v, want none (already present)", added)
	}

	data := readFileHelper(t, path)
	if strings.Count(data, "web1.ipa.pilot.internal") != 1 {
		t.Fatalf("expected exactly one web1 entry after idempotent rerun:\n%s", data)
	}
}

func TestAutoFillFreeIPAClientRosterHosts_NeverResurrectsAbsentHost(t *testing.T) {
	roster := rosterFixtureNoNFS + `hosts:
- name: web1.ipa.pilot.internal
  state: absent
  ip_address: 10.0.0.1
`
	dir, path := writeAutoFillWorkspace(t, roster, hostsYMLWithFreeIPAClients)

	added, err := AutoFillFreeIPAClientRosterHosts(dir, path)
	if err != nil {
		t.Fatalf("AutoFillFreeIPAClientRosterHosts() error = %v", err)
	}
	if len(added) != 1 || added[0] != "web2.example.internal" {
		t.Fatalf("added = %v, want only web2.example.internal (web1 already has a decommissioned entry)", added)
	}

	data := readFileHelper(t, path)
	if strings.Count(data, "web1.ipa.pilot.internal") != 1 {
		t.Fatalf("expected the pre-existing absent web1 entry to remain untouched, not duplicated:\n%s", data)
	}
	if !strings.Contains(data, "state: absent") {
		t.Fatalf("expected web1's state: absent to be preserved:\n%s", data)
	}
}

func TestAutoFillFreeIPAClientRosterHosts_NoHostsYMLIsANoOp(t *testing.T) {
	dir, path := writeAutoFillWorkspace(t, rosterFixtureNoNFS, "")

	added, err := AutoFillFreeIPAClientRosterHosts(dir, path)
	if err != nil {
		t.Fatalf("AutoFillFreeIPAClientRosterHosts() error = %v", err)
	}
	if added != nil {
		t.Fatalf("added = %v, want nil when hosts.yml does not exist", added)
	}
}
