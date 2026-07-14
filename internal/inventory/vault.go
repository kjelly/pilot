package inventory

import (
	"fmt"
	"sort"
	"strings"
)

type vaultField struct {
	Name      string
	Value     string
	Comment   string
	Optional  bool
	Multiline bool
}

type vaultSection struct {
	Title string
	Note  string
	Keys  []vaultField
}

func (s vaultSection) keyNames() []string {
	out := make([]string, 0, len(s.Keys))
	for _, k := range s.Keys {
		out = append(out, k.Name)
	}
	return out
}

var vaultSections = map[string]vaultSection{
	"freeipa": {
		Title: "FreeIPA 相關",
		Note:  "server/client/replica 共用的管理密碼。freeipa-identity 的 roster schema 是另一份獨立檔案，不能只靠 inventory 推導。",
		Keys: []vaultField{
			{
				Name:    "ipa_admin_password",
				Value:   "CHANGE-ME-min-8-chars",
				Comment: "FreeIPA admin 密碼（必填）",
			},
			{
				Name:     "ipa_dm_password",
				Value:    "CHANGE-ME-if-separate-from-admin",
				Comment:  "Optional: Directory Manager 密碼；不填則沿用 ipa_admin_password",
				Optional: true,
			},
		},
	},
	"keycloak-admin": {
		Title: "Keycloak 相關",
		Note:  "Keycloak server 本身需要的管理者密碼。",
		Keys: []vaultField{
			{
				Name:    "keycloak_admin_password",
				Value:   "CHANGE-ME-keycloak-admin",
				Comment: "Keycloak admin 密碼（必填）",
			},
		},
	},
	"keycloak-db": {
		Title: "Keycloak PostgreSQL 相關",
		Note:  "Keycloak DB provider 與 keycloak-db role 共用的 PostgreSQL 密碼。",
		Keys: []vaultField{
			{
				Name:    "pg_keycloak_db_password",
				Value:   "CHANGE-ME-keycloak-db-password",
				Comment: "PostgreSQL 密碼（必填）",
			},
		},
	},
	"dashboard": {
		Title: "Dashboard 相關",
		Note:  "Grafana admin 密碼。",
		Keys: []vaultField{
			{
				Name:    "grafana_admin_password",
				Value:   "CHANGE-ME-grafana-admin",
				Comment: "Grafana admin 密碼（必填）",
			},
		},
	},
	"restic-backup": {
		Title: "Restic 備份相關",
		Note:  "S3 backend credentials + repository encryption password。",
		Keys: []vaultField{
			{
				Name:    "restic_aws_access_key_id",
				Value:   "CHANGE-ME-restic-access-key",
				Comment: "S3 access key（必填）",
			},
			{
				Name:    "restic_aws_secret_access_key",
				Value:   "CHANGE-ME-restic-secret-key",
				Comment: "S3 secret key（必填）",
			},
			{
				Name:    "restic_password",
				Value:   "CHANGE-ME-restic-repository-password",
				Comment: "restic repository 加密密碼（必填）",
			},
		},
	},
	"thanos-s3": {
		Title: "Prometheus / Thanos S3 相關",
		Note:  "Prometheus 與 thanos-query 共用的 object storage credentials。",
		Keys: []vaultField{
			{
				Name:    "thanos_aws_access_key_id",
				Value:   "CHANGE-ME-thanos-access-key",
				Comment: "S3 access key（必填）",
			},
			{
				Name:    "thanos_aws_secret_access_key",
				Value:   "CHANGE-ME-thanos-secret-key",
				Comment: "S3 secret key（必填）",
			},
		},
	},
	"alertmanager": {
		Title: "Alertmanager 相關",
		Note:  "這不是密碼，但正式環境通常會把完整 receiver config 跟 secret webhook 一起放進 vault。",
		Keys: []vaultField{
			{
				Name:      "alertmanager_config",
				Comment:   "完整 alertmanager.yml 內容；先放一個可用的 null receiver stub",
				Multiline: true,
				Value: strings.Join([]string{
					"route:",
					"  receiver: \"null\"",
					"receivers:",
					"  - name: \"null\"",
				}, "\n"),
			},
		},
	},
}

var vaultSectionOrder = []string{
	"freeipa",
	"keycloak-admin",
	"keycloak-db",
	"dashboard",
	"restic-backup",
	"thanos-s3",
	"alertmanager",
}

// VaultSectionExpectedKeys returns the declared key names for one vault section.
func VaultSectionExpectedKeys(sectionID string) []string {
	section, ok := vaultSections[sectionID]
	if !ok {
		return nil
	}
	return append([]string(nil), section.keyNames()...)
}

// ExpectedVaultKeysForRoles returns the deduped, ordered set of vault keys
// that should appear in the generated skeleton for the given roles.
func ExpectedVaultKeysForRoles(roles []string) []string {
	contracts := roleContractsByName()
	seenSections := map[string]bool{}
	var sectionIDs []string
	for _, role := range roles {
		for _, sectionID := range contracts[role].VaultSections {
			if !seenSections[sectionID] {
				seenSections[sectionID] = true
				sectionIDs = append(sectionIDs, sectionID)
			}
		}
	}
	sortStringsByReference(sectionIDs, vaultSectionOrder)

	seenKeys := map[string]bool{}
	var out []string
	for _, sectionID := range sectionIDs {
		for _, key := range VaultSectionExpectedKeys(sectionID) {
			if !seenKeys[key] {
				seenKeys[key] = true
				out = append(out, key)
			}
		}
	}
	return out
}

// VaultSectionIDs returns the deduped, ordered set of vault skeleton
// sections implied by the roles used in hf.
func VaultSectionIDs(hf *HostsFile) []string {
	if hf == nil {
		return nil
	}
	contracts := roleContractsByName()
	seen := map[string]bool{}
	for _, h := range hf.Hosts {
		for _, r := range h.Roles {
			for _, sectionID := range contracts[r].VaultSections {
				seen[sectionID] = true
			}
		}
	}
	var out []string
	for _, sectionID := range vaultSectionOrder {
		if seen[sectionID] {
			out = append(out, sectionID)
		}
	}
	return out
}

// UsedRoles returns the deduped, sorted roles actually assigned across hf.
func UsedRoles(hf *HostsFile) []string {
	if hf == nil {
		return nil
	}
	seen := map[string]bool{}
	for _, h := range hf.Hosts {
		for _, r := range h.Roles {
			seen[r] = true
		}
	}
	out := make([]string, 0, len(seen))
	for role := range seen {
		out = append(out, role)
	}
	ordered := roleNames()
	sortStringsByReference(out, ordered)
	return out
}

func sortStringsByReference(values, ordered []string) {
	rank := make(map[string]int, len(ordered))
	for i, v := range ordered {
		rank[v] = i
	}
	sort.Slice(values, func(i, j int) bool {
		ri, iok := rank[values[i]]
		rj, jok := rank[values[j]]
		switch {
		case iok && jok:
			return ri < rj
		case iok:
			return true
		case jok:
			return false
		default:
			return values[i] < values[j]
		}
	})
}

// GenerateVaultSkeleton renders a plaintext ansible-vault candidate
// containing only the vault-appropriate keys implied by hf's roles.
// An empty string means none of the assigned roles need a generated
// vault skeleton.
func GenerateVaultSkeleton(hf *HostsFile) string {
	sectionIDs := VaultSectionIDs(hf)
	if len(sectionIDs) == 0 {
		return ""
	}

	roles := UsedRoles(hf)

	var sb strings.Builder
	sb.WriteString("# =============================================================================\n")
	sb.WriteString("#  Ansible Vault skeleton — generated by `pilot inventory generate`\n")
	sb.WriteString("# =============================================================================\n")
	sb.WriteString("#\n")
	sb.WriteString("# This file only covers vault-appropriate vars inferred from the roles in your\n")
	sb.WriteString("# inventory source. Non-secret required vars (IPs, hostnames, target groups,\n")
	sb.WriteString("# schedules, etc.) stay in inventory/group_vars/host_vars.\n")
	sb.WriteString("#\n")
	sb.WriteString("# Fill in real values, then encrypt it, e.g.:\n")
	sb.WriteString("#   ansible-vault encrypt .vault/main.yaml\n")
	sb.WriteString("#\n")
	sb.WriteString(fmt.Sprintf("# Roles seen: %s\n", strings.Join(roles, ", ")))
	sb.WriteString("#\n")
	sb.WriteString("# Not included automatically:\n")
	sb.WriteString("#   - freeipa-identity roster schema (use playbooks/apply/freeipa-identity.roster.example.yaml)\n")
	sb.WriteString("#   - group_vars/host_vars-backed settings\n")
	sb.WriteString("# =============================================================================\n")
	sb.WriteString("---\n\n")

	for idx, sectionID := range sectionIDs {
		section := vaultSections[sectionID]
		sb.WriteString("# -----------------------------------------------------------------------------\n")
		sb.WriteString(fmt.Sprintf("# %s\n", section.Title))
		sb.WriteString("# -----------------------------------------------------------------------------\n")
		if section.Note != "" {
			sb.WriteString(fmt.Sprintf("# %s\n", section.Note))
		}
		for _, key := range section.Keys {
			if key.Comment != "" {
				sb.WriteString(fmt.Sprintf("# %s\n", key.Comment))
			}
			if key.Optional {
				if key.Multiline {
					sb.WriteString(fmt.Sprintf("# %s: |\n", key.Name))
					for _, line := range strings.Split(key.Value, "\n") {
						sb.WriteString(fmt.Sprintf("#   %s\n", line))
					}
				} else {
					sb.WriteString(fmt.Sprintf("# %s: %q\n", key.Name, key.Value))
				}
				continue
			}
			if key.Multiline {
				sb.WriteString(fmt.Sprintf("%s: |\n", key.Name))
				for _, line := range strings.Split(key.Value, "\n") {
					sb.WriteString(fmt.Sprintf("  %s\n", line))
				}
			} else {
				sb.WriteString(fmt.Sprintf("%s: %q\n", key.Name, key.Value))
			}
		}
		if idx < len(sectionIDs)-1 {
			sb.WriteString("\n")
		}
	}

	return sb.String()
}
