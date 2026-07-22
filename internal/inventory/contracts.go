package inventory

import "sort"

// roleContract is the single source of truth for one inventory role's
// generated companions: descriptive catalog text, shared group_vars
// stem (if any), and vault skeleton sections (if any).
type roleContract struct {
	Name          string
	Description   string
	GroupVarsStem string
	VaultSections []string
}

// roleContracts must stay in the same order as inventory.example.yml's
// rendered leaf groups.
var roleContracts = []roleContract{
	{Name: "freeipa-server", Description: "FreeIPA 身份伺服器 (freeipa-server-apply.yml)", GroupVarsStem: "freeipa", VaultSections: []string{"freeipa"}},
	{Name: "freeipa-client", Description: "納入 FreeIPA 的機器 (freeipa-client-apply.yml)", GroupVarsStem: "freeipa", VaultSections: []string{"freeipa"}},
	{Name: "freeipa-server-replica", Description: "FreeIPA multi-master replica（day-2/opt-in，已實跑驗證），見 docs/verification/freeipa-server-replica.md", GroupVarsStem: "freeipa", VaultSections: []string{"freeipa"}},
	{Name: "freeipa-nfs-server", Description: "Kerberos NFSv4 exports + ACL (freeipa-nfs-server-apply.yml)"},
	{Name: "freeipa-nfs-client", Description: "IPA automount client (freeipa-nfs-client-apply.yml)"},
	{Name: "dns", Description: "core-infra-provider-apply.yml -e infra_role=dns", GroupVarsStem: "dns"},
	{Name: "ntp", Description: "core-infra-provider-apply.yml -e infra_role=ntp", GroupVarsStem: "ntp"},
	{Name: "docker", Description: "Container 引擎 (docker-apply.yml)"},
	{Name: "keycloak", Description: "IdP (keycloak-apply.yml)", VaultSections: []string{"keycloak-admin", "keycloak-db"}},
	{Name: "keycloak-db", Description: "Keycloak 的 PostgreSQL (keycloak-db-apply.yml)", VaultSections: []string{"keycloak-db"}},
	{Name: "linux-servers", Description: "SSH 走 OIDC 登入 (pam-oidc-sshd-apply.yml)", GroupVarsStem: "linux-servers"},
	{Name: "log-server", Description: "中央稽核日誌接收 (log-server-apply.yml)"},
	{Name: "audit-log-forwarding", Description: "主機稽核 + 轉送到 log-server (audit-log-forwarding-apply.yml)"},
	{Name: "wazuh-manager", Description: "Wazuh 中央伺服器，需先過 docker，資源需求見 docs/runbooks/wazuh-manager.md §5 (wazuh-manager-apply.yml)", GroupVarsStem: "wazuh-manager"},
	{Name: "wazuh-fim", Description: "Wazuh agent：FIM + auditd who-data (wazuh-fim-apply.yml)", GroupVarsStem: "wazuh-fim"},
	{Name: "seaweedfs-s3", Description: "S3 相容物件儲存，需先過 docker (seaweedfs-s3-apply.yml)"},
	{Name: "restic-backup", Description: "跨主機備份到 S3，見 docs/runbooks/restic-backup.md §5 (restic-backup-apply.yml)", GroupVarsStem: "restic-backup", VaultSections: []string{"restic-backup"}},
	{Name: "prometheus", Description: "每站 Prometheus + Thanos Sidecar (prometheus-apply.yml)", GroupVarsStem: "prometheus", VaultSections: []string{"thanos-s3"}},
	{Name: "thanos-query", Description: "中央 Thanos Query，只需一台 (thanos-query-apply.yml)", GroupVarsStem: "thanos-query", VaultSections: []string{"thanos-s3"}},
	{Name: "alertmanager", Description: "中央 Alertmanager，只需一台 (alertmanager-apply.yml)", GroupVarsStem: "alertmanager", VaultSections: []string{"alertmanager"}},
	{Name: "dashboard", Description: "Grafana + Loki，只需一台 (dashboard-apply.yml)", GroupVarsStem: "dashboard", VaultSections: []string{"dashboard"}},
}

func roleContractsByName() map[string]roleContract {
	out := make(map[string]roleContract, len(roleContracts))
	for _, c := range roleContracts {
		out[c.Name] = c
	}
	return out
}

func roleNames() []string {
	out := make([]string, 0, len(roleContracts))
	for _, c := range roleContracts {
		out = append(out, c.Name)
	}
	return out
}

// RoleContracts returns the inventory role contract catalog in render order.
func RoleContracts() []struct {
	Name          string
	Description   string
	GroupVarsStem string
	VaultSections []string
} {
	out := make([]struct {
		Name          string
		Description   string
		GroupVarsStem string
		VaultSections []string
	}, len(roleContracts))
	for i, c := range roleContracts {
		sections := append([]string(nil), c.VaultSections...)
		out[i] = struct {
			Name          string
			Description   string
			GroupVarsStem string
			VaultSections []string
		}{
			Name:          c.Name,
			Description:   c.Description,
			GroupVarsStem: c.GroupVarsStem,
			VaultSections: sections,
		}
	}
	return out
}

// GroupVarsStemsForRoles returns the deduped, sorted set of group_vars stems
// implied by the given roles. Roles with no group_vars stem contribute nothing.
func GroupVarsStemsForRoles(roles []string) []string {
	contracts := roleContractsByName()
	seen := map[string]bool{}
	for _, role := range roles {
		stem := contracts[role].GroupVarsStem
		if stem != "" {
			seen[stem] = true
		}
	}
	out := make([]string, 0, len(seen))
	for stem := range seen {
		out = append(out, stem)
	}
	sort.Strings(out)
	return out
}
