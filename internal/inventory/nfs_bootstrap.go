package inventory

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/kjelly/pilot/internal/vaultfile"
)

// minimalRosterBase is the smallest canonical roster common to every
// "create a fresh roster from within pilot edit" flow: just schema_version
// plus freeipa.domain/admin. WriteMinimalNFSServerRoster adds an
// nfs.servers entry on top of this for the NFS-role bootstrap case;
// WriteMinimalRosterSkeleton uses it as-is for the generic "roster —
// FreeIPA" entry point, which isn't tied to any specific host.
func minimalRosterBase(domain, adminPrincipal, adminPassword string) map[string]any {
	return map[string]any{
		"schema_version": 1,
		"freeipa": map[string]any{
			"domain": domain,
			"admin": map[string]any{
				"principal": adminPrincipal,
				"password":  adminPassword,
			},
		},
	}
}

func writeRosterSkeleton(path string, roster map[string]any) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("roster %s already exists", path)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat roster %s: %w", path, err)
	}
	rendered, err := yaml.Marshal(roster)
	if err != nil {
		return fmt.Errorf("encode minimal roster: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir roster directory: %w", err)
	}
	if err := os.WriteFile(path, rendered, 0o600); err != nil {
		return fmt.Errorf("write roster %s: %w", path, err)
	}
	return nil
}

// WriteMinimalNFSServerRoster creates the smallest canonical roster that
// freeipa-nfs-server-apply.yml needs for a demo Linux NFS server. It only
// creates a missing file; existing rosters must go through the append-only
// NFS helper so a user's identity/HBAC/sudo data is never replaced.
//
// The password is supplied by the edit TUI's masked input and the file is
// created mode 0600. The caller should still encrypt the result before using
// it for production. shares is intentionally empty: an external provider
// such as NetApp must not be represented as a Linux-managed share here.
func WriteMinimalNFSServerRoster(path, hostName, domain, adminPrincipal, adminPassword string) error {
	fqdn := RosterHostFQDN(hostName, domain)
	roster := minimalRosterBase(domain, adminPrincipal, adminPassword)
	roster["nfs"] = map[string]any{
		"servers": []any{map[string]any{
			"host":  fqdn,
			"state": "present",
			"service_principal": map[string]any{
				"ensure":    true,
				"principal": "nfs/" + fqdn,
				"keytab":    "/etc/krb5.keytab",
			},
			"shares": []any{},
		}},
	}
	return writeRosterSkeleton(path, roster)
}

// WriteMinimalRosterSkeleton creates the smallest canonical roster with no
// users/groups/hosts yet — just enough (schema_version + freeipa.domain/
// admin) to pass ValidateRosterFile and let pilot edit's roster manager add
// users/groups from here. Used when a workspace's "roster — FreeIPA" entry
// point finds no roster file yet at all (not tied to any specific host, so
// it never gets an nfs.servers entry the way WriteMinimalNFSServerRoster
// does) — a completely foreseeable first visit to a fresh workspace, not
// something that should end the whole `pilot edit` session. Create-only,
// same posture as WriteMinimalNFSServerRoster.
func WriteMinimalRosterSkeleton(path, domain, adminPrincipal, adminPassword string) error {
	return writeRosterSkeleton(path, minimalRosterBase(domain, adminPrincipal, adminPassword))
}

// WriteMinimalFreeIPAVault creates the one shared vault value required by
// freeipa-client/freeipa-server when no workspace vault exists yet. It is
// deliberately create-only, just like WriteMinimalNFSServerRoster.
func WriteMinimalFreeIPAVault(path, adminPassword string) error {
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("vault %s already exists", path)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat vault %s: %w", path, err)
	}
	rendered, err := yaml.Marshal(map[string]string{"ipa_admin_password": adminPassword})
	if err != nil {
		return fmt.Errorf("encode minimal FreeIPA vault: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("mkdir vault directory: %w", err)
	}
	if err := os.WriteFile(path, rendered, 0o600); err != nil {
		return fmt.Errorf("write vault %s: %w", path, err)
	}
	return nil
}

// FillFreeIPAAdminPassword updates only an empty or CHANGE-ME
// ipa_admin_password in an existing plaintext vault. A real value and an
// encrypted file are left untouched, so edit cannot silently replace an
// operator's credential.
func FillFreeIPAAdminPassword(path, adminPassword string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	if strings.HasPrefix(strings.TrimSpace(string(data)), "$ANSIBLE_VAULT") {
		return false, nil
	}
	doc, err := vaultfile.Parse(data)
	if err != nil {
		return false, fmt.Errorf("parse vault %s: %w", path, err)
	}
	if !doc.Editable() {
		return false, fmt.Errorf("vault %s is not a top-level scalar mapping", path)
	}
	for _, entry := range doc.Entries() {
		if entry.Key != "ipa_admin_password" {
			continue
		}
		if entry.Value.Value != "" && entry.Value.Value != "CHANGE-ME-min-8-chars" && entry.Value.Value != "CHANGE-ME" {
			return false, nil
		}
		doc.Set("ipa_admin_password", adminPassword)
		if err := os.WriteFile(path, doc.Bytes(), 0o600); err != nil {
			return false, fmt.Errorf("write vault %s: %w", path, err)
		}
		return true, nil
	}
	doc.Set("ipa_admin_password", adminPassword)
	if err := os.WriteFile(path, doc.Bytes(), 0o600); err != nil {
		return false, fmt.Errorf("write vault %s: %w", path, err)
	}
	return true, nil
}
