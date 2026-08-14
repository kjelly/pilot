package cmd

// deployPlaybook describes one entry in the `pilot deploy` menu: a
// plain-language "what do you want to do" choice mapped to its apply
// playbook, the name of the variable that gates its stage (almost
// always "stage"; os-patch-sla uses "patch_stage"), and anything else
// the wizard needs to ask before it can build a safe ansible-playbook
// command. This mirrors DELIVERY.md's "Playbook 對照表" — update both
// together when a playbook is added, renamed, or removed.
type deployPlaybook struct {
	Key            string        // stable id, unique across the catalog
	Label          string        // shown in the menu
	Playbook       string        // path relative to the ansible.cfg working directory
	DefaultGroup   string        // informational only — the playbook already defaults to this
	StageVar       string        // "stage" or "patch_stage"
	InfraRoles     []string      // non-empty => prompt a role select, sets -e infra_role=<choice>
	Note           string        // shown before running: prerequisites, resource sizing, draft status…
	VaultHint      string        // shown when offering the vault-file prompt; "" skips extra context
	PromptS3Config bool          // true => ask about signed-mode S3 identity, sets -e seaweedfs_s3_config_path=<path>
	AutoHostVars   []autoHostVar // each => auto-detect a cross-role host address from inventory, sets -e <Var>=<ip>
	Reconcile      bool          // true => eligible for pilot reconcile's day-2 declarative configuration flow
}

// autoHostVar describes one "-e <Var>=<ip>" pilot deploy can offer to fill
// in automatically by resolving Group's first host from the same
// inventory (see resolveGroupHost), instead of making the user look the
// address up by hand and paste it into the free-form extra-vars prompt.
// This is the generic form of the "core service lives in exactly one
// group" convention several apply playbooks already assume — e.g.
// restic-backup's restic_s3_target_host wants the seaweedfs-s3 group's
// host, wazuh-fim's wazuh_manager_host wants the wazuh-manager group's.
type autoHostVar struct {
	Var   string // the -e variable name, e.g. "restic_s3_target_host"
	Group string // the inventory group whose first host's ansible_host to use
	Label string // human description shown in the prompt, e.g. "SeaweedFS S3 gateway(備份目的地)"
}

// deployCatalog is every playbooks/apply/*.yml entry `pilot deploy` can
// drive in "single component" mode. Order matches DELIVERY.md's table.
var deployCatalog = []deployPlaybook{
	{
		Key: "core-infra-provider", Label: "核心基礎服務 — DNS / NTP",
		Playbook: "playbooks/apply/core-infra-provider-apply.yml", StageVar: "stage",
		InfraRoles: []string{"dns", "ntp"},
		Note:       "同一支 playbook 用 -e infra_role= 選角色。",
	},
	{
		Key: "docker", Label: "Container 引擎(Docker)",
		Playbook: "playbooks/apply/docker-apply.yml", DefaultGroup: "docker", StageVar: "stage",
		Note: "keycloak-db/keycloak、seaweedfs-s3、wazuh-manager、prometheus/thanos-query/alertmanager 等角色的前置，需先套用。",
	},
	{
		Key: "freeipa-server", Label: "FreeIPA 身份伺服器",
		Playbook: "playbooks/apply/freeipa-server-apply.yml", DefaultGroup: "freeipa-server", StageVar: "stage",
		VaultHint: "管理員 / Directory Manager 密碼(ipa_admin_password)",
	},
	{
		Key: "freeipa-client", Label: "把機器納入 FreeIPA(AAA)",
		Playbook: "playbooks/apply/freeipa-client-apply.yml", DefaultGroup: "freeipa-client", StageVar: "stage",
	},
	{
		Key: "freeipa-identity", Label: "管理 FreeIPA 使用者／權限(資料驅動,需要 vault roster)",
		Playbook: "playbooks/apply/freeipa-identity-apply.yml", DefaultGroup: "freeipa-server", StageVar: "stage",
		Note:      "資料驅動的 reconciler，需要一份 ansible-vault 加密的 roster 檔（範本：playbooks/apply/freeipa-identity.roster.example.yaml），接下來會問你 roster 檔路徑。",
		VaultHint: "roster 檔(含 ipa_users/ipa_groups/ipa_hbac_rules/ipa_sudo_rules 與 ipa_admin_password)",
		Reconcile: true,
	},
	{
		Key: "freeipa-dns", Label: "管理 FreeIPA DNS zones／records(資料驅動,day-2 reconciler)",
		Playbook: "playbooks/apply/freeipa-dns-apply.yml", DefaultGroup: "freeipa-server", StageVar: "stage",
		Note:      "資料驅動的 DNS reconciler；需在 freeipa-server host_vars 設定 freeipa_dns_manifest_file(絕對路徑，範本：playbooks/apply/freeipa-dns.manifest.example.yaml)。支援 zone 建立/刪除、A/AAAA/CNAME present record 的 value/TTL reconcile、明確 RRset 刪除與 authoritative prune;已對活體 FreeIPA server 實跑驗證(v1.0，見 docs/verification/freeipa-dns.md)。",
		VaultHint: "FreeIPA 管理員密碼(ipa_admin_password，跟 freeipa-identity 共用同一份 vault 檔)",
		Reconcile: true,
	},
	{
		Key: "freeipa-dns-client", Label: "把機器的 DNS resolver 指向 FreeIPA DNS(server/replica)",
		Playbook: "playbooks/apply/freeipa-dns-client-apply.yml", DefaultGroup: "freeipa-dns-client", StageVar: "stage",
		Note: "day-2/opt-in 角色(不在 site.yml);與 freeipa-client(AAA 納管)互不相依,不需先做身分 enrollment。自動從 inventory 偵測 freeipa-server/freeipa-server-replica 裡有開 DNS 的主機;也可套用到 FreeIPA server/replica 自己身上(自動優先指向自己)。支援 Debian/Ubuntu(systemd-resolved)與 EL(NetworkManager)。",
	},
	{
		Key: "freeipa-ca-trust", Label: "把 FreeIPA integrated CA 裝進機器的 OS trust store",
		Playbook: "playbooks/apply/freeipa-ca-trust-apply.yml", DefaultGroup: "all", StageVar: "stage",
		Note: "day-2/opt-in 角色(不在 site.yml);與 freeipa-client(AAA 納管)互不相依,不需先做身分 enrollment。Phase-1 骨架:目前只有 placeholder task,真正的 CA fetch-and-install 邏輯待 spec.md §63 Phase 3 補上。",
	},
	{
		Key: "freeipa-nfs-server", Label: "FreeIPA Kerberos NFSv4 server",
		Playbook: "playbooks/apply/freeipa-nfs-server-apply.yml", DefaultGroup: "freeipa-nfs-server", StageVar: "stage",
		Note:      "目標主機必須先完成 freeipa-client enrollment；使用 canonical FreeIPA roster 建立 nfs/FQDN principal、keytab、ACL 與安全 exports（支援 RedHat 與 Debian/Ubuntu）。",
		VaultHint: "canonical roster 檔(含 FreeIPA admin 密碼與 nfs.servers)",
	},
	{
		Key: "freeipa-nfs-client", Label: "FreeIPA automount NFS client",
		Playbook: "playbooks/apply/freeipa-nfs-client-apply.yml", DefaultGroup: "freeipa-nfs-client", StageVar: "stage",
		Note: "主機必須先完成 freeipa-client enrollment；設定 IPA automount location，不修改 /etc/fstab。",
	},
	{
		Key: "freeipa-server-replica", Label: "第二台 FreeIPA server(multi-master HA replica)",
		Playbook: "playbooks/apply/freeipa-server-replica-apply.yml", DefaultGroup: "freeipa-server-replica", StageVar: "stage",
		Note:      "day-2/opt-in 角色(不在 site.yml);已於三台 vm-target 全鏈路實跑過,見 docs/verification/freeipa-server-replica.md §0/§5。",
		VaultHint: "既有 realm 的管理員密碼(ipa_admin_password)",
	},
	{
		Key: "freeipa-realm-replacement", Label: "把一台 FreeIPA client 換到另一個 realm(client-wave migration)",
		Playbook: "playbooks/apply/freeipa-realm-replacement-apply.yml", DefaultGroup: "freeipa-client", StageVar: "stage",
		Note:      "day-2/opt-in 角色(不在 site.yml);僅換 client 端 enrollment，不是 server 端 restore；舊 server 若已重裝/退役，本機 archive 只剩鑑識用途，不能拿來 rollback trust。見 docs/verification/freeipa-realm-replacement.md。",
		VaultHint: "新 realm 的管理員密碼(ipa_admin_password)",
	},
	{
		Key: "reverse-proxy", Label: "Nginx reverse proxy 基礎安裝",
		Playbook: "playbooks/apply/reverse-proxy-apply.yml", DefaultGroup: "reverse-proxy", StageVar: "stage",
		Note: "site.yml 角色(所有 reverse-proxy group 主機都會套用);只裝 nginx、關掉 distro default site、建立 Pilot config namespace，不管任何 endpoint 的 vhost——那是 internal-endpoint 的責任。Phase-1 骨架:目前只有 placeholder task,真正的 nginx 安裝邏輯待 spec.md §63 Phase 4 補上。",
	},
	{
		Key: "internal-endpoint", Label: "管理內部 FQDN 的 DNS/TLS/nginx route(資料驅動,day-2 reconciler)",
		Playbook: "playbooks/apply/internal-endpoint-apply.yml", DefaultGroup: "freeipa-server", StageVar: "stage",
		Note:      "資料驅動的 day-2 reconciler;需要在 freeipa-server host_vars 設定 internal_endpoint_manifest_file(絕對路徑)。管理內部 FQDN 的 DNS record、FreeIPA service certificate(certmonger)、以及可選的 nginx reverse proxy vhost。依賴 freeipa-server(sameHosts)、freeipa-dns(zone 必須先存在且為 merge mode)、freeipa-ca-trust(CA trust baseline)。Phase-1 骨架:目前只有 placeholder task,真正的 reconcile 邏輯待 spec.md §63 Phase 2/5/6/7 補上。",
		VaultHint: "FreeIPA 管理員密碼(ipa_admin_password，跟 freeipa-identity/freeipa-dns 共用同一份 vault 檔)",
		Reconcile: true,
	},
	{
		Key: "keycloak-db", Label: "Keycloak 的 PostgreSQL",
		Playbook: "playbooks/apply/keycloak-db-apply.yml", DefaultGroup: "keycloak-db", StageVar: "stage",
		VaultHint: "資料庫密碼(keycloak_db_password)",
	},
	{
		Key: "keycloak", Label: "Keycloak(IdP)",
		Playbook: "playbooks/apply/keycloak-apply.yml", DefaultGroup: "keycloak", StageVar: "stage",
		VaultHint: "管理員密碼與資料庫密碼(keycloak_admin_password / keycloak_db_password)",
	},
	{
		Key: "pam-oidc-sshd", Label: "SSH 走 OIDC 登入",
		Playbook: "playbooks/apply/pam-oidc-sshd-apply.yml", DefaultGroup: "linux-servers", StageVar: "stage",
	},
	{
		Key: "log-server", Label: "中央稽核日誌接收(SIEM)",
		Playbook: "playbooks/apply/log-server-apply.yml", DefaultGroup: "log-server", StageVar: "stage",
	},
	{
		Key: "audit-log-forwarding", Label: "主機稽核(auditd)+ 轉送到 log-server",
		Playbook: "playbooks/apply/audit-log-forwarding-apply.yml", DefaultGroup: "audit-log-forwarding", StageVar: "stage",
		AutoHostVars: []autoHostVar{{Var: "siem_forward_host", Group: "log-server", Label: "log-server(SIEM 轉送目的地)"}},
	},
	{
		Key: "wazuh-manager", Label: "Wazuh 中央伺服器(FIM/告警引擎 + CVE 掃描)",
		Playbook: "playbooks/apply/wazuh-manager-apply.yml", DefaultGroup: "wazuh-manager", StageVar: "stage",
		Note:         "Docker 部署，目標主機需先過 docker preflight，且至少 4 vCPU/8GB RAM/50GB 磁碟(見 docs/runbooks/wazuh-manager.md §5)。",
		AutoHostVars: []autoHostVar{{Var: "siem_forward_host", Group: "log-server", Label: "log-server(SIEM 轉送目的地)"}},
	},
	{
		Key: "wazuh-fim", Label: "Wazuh agent(檔案完整性監控 + auditd)",
		Playbook: "playbooks/apply/wazuh-fim-apply.yml", DefaultGroup: "wazuh-fim", StageVar: "stage",
		AutoHostVars: []autoHostVar{{Var: "wazuh_manager_host", Group: "wazuh-manager", Label: "Wazuh manager(enrollment 目的地)"}},
	},
	{
		Key: "seaweedfs-s3", Label: "S3 相容物件儲存(SeaweedFS)",
		Playbook: "playbooks/apply/seaweedfs-s3-apply.yml", DefaultGroup: "seaweedfs-s3", StageVar: "stage",
		PromptS3Config: true,
		VaultHint:      "簽章模式 S3 存取用的 identity(沿用 restic_aws_access_key_id / restic_aws_secret_access_key)",
	},
	{
		Key: "restic-backup", Label: "跨主機通用備份到 S3(restic)",
		Playbook: "playbooks/apply/restic-backup-apply.yml", DefaultGroup: "restic-backup", StageVar: "stage",
		Note:         "需要先有 S3 目的地(seaweedfs-s3 或外部 S3)，見 docs/runbooks/restic-backup.md §5。",
		VaultHint:    "S3 credentials 與 repository 加密密碼(restic_aws_access_key_id / restic_aws_secret_access_key / restic_password)",
		AutoHostVars: []autoHostVar{{Var: "restic_s3_target_host", Group: "seaweedfs-s3", Label: "SeaweedFS S3 gateway(備份目的地)"}},
	},
	{
		Key: "log-shipping", Label: "把 log-server 的日誌轉送到 Loki",
		Playbook: "playbooks/apply/log-shipping-apply.yml", DefaultGroup: "log-server", StageVar: "stage",
		AutoHostVars: []autoHostVar{{Var: "loki_target_host", Group: "dashboard", Label: "Loki(dashboard 主機)"}},
	},
	{
		Key: "os-patch-sla", Label: "OS 補丁 SLA",
		Playbook: "playbooks/apply/os-patch-sla-apply.yml", StageVar: "patch_stage",
		Note: "旗標名稱是 patch_stage，不是 stage；沒有另外覆寫 target_group 時，預設目標 group 就等於你接下來選的 patch_stage(sandbox/staging/prod)；confirm/attestation 規則跟其它角色一致。",
	},
	{
		Key: "host-monitoring", Label: "被監控主機的監控 agent(node_exporter)",
		Playbook: "playbooks/apply/host-monitoring-apply.yml", DefaultGroup: "host-monitoring", StageVar: "stage",
		Note: "裝在任何被監控主機上,兩種 distro(Ubuntu/AlmaLinux)都走同一份 pinned 官方 release binary;prometheus 會自動從 inventory 的 host-monitoring group 展開 scrape target,不需要額外設定。",
	},
	{
		Key: "prometheus", Label: "Prometheus + Thanos Sidecar",
		Playbook: "playbooks/apply/prometheus-apply.yml", DefaultGroup: "prometheus", StageVar: "stage",
		AutoHostVars: []autoHostVar{
			{Var: "thanos_s3_target_host", Group: "seaweedfs-s3", Label: "SeaweedFS S3 gateway(Thanos 物件儲存)"},
			{Var: "alertmanager_target_host", Group: "alertmanager", Label: "中央 Alertmanager"},
		},
	},
	{
		Key: "thanos-query", Label: "中央 Thanos Query",
		Playbook: "playbooks/apply/thanos-query-apply.yml", DefaultGroup: "thanos-query", StageVar: "stage",
		AutoHostVars: []autoHostVar{{Var: "thanos_s3_target_host", Group: "seaweedfs-s3", Label: "SeaweedFS S3 gateway(Thanos 物件儲存)"}},
	},
	{
		Key: "alertmanager", Label: "中央 Alertmanager",
		Playbook: "playbooks/apply/alertmanager-apply.yml", DefaultGroup: "alertmanager", StageVar: "stage",
	},
	{
		Key: "dashboard", Label: "觀測畫面(Grafana + Loki)",
		Playbook: "playbooks/apply/dashboard-apply.yml", DefaultGroup: "dashboard", StageVar: "stage",
		AutoHostVars: []autoHostVar{{Var: "thanos_query_target_host", Group: "thanos-query", Label: "中央 Thanos Query"}},
	},
}
