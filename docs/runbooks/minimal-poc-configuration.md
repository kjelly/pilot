# 原始問題

Minimal PoC 的 `prometheus_site_label`、restic 與 Thanos 必要值沒有在
`docs/runbooks/minimal-poc-architecture.md` 或
`tmp/pilot-semantic-actions-r15/` 的錄影中完整示範；需要一份可照做的設定指南，並確認
delivery test 是否已涵蓋這些設定。

# 報告內文

## 0. 文件狀態與適用範圍

本文件是 Minimal PoC 的設定契約，描述在執行 `pilot inventory generate` 前後，
`hosts.yml`、`group_vars/`、`host_vars/` 與 `.vault/main.yaml` 必須具備的內容。

它補充而不取代：

- [`minimal-poc-architecture.md`](minimal-poc-architecture.md)：拓撲生命週期與整體驗證流程。
- [`DELIVERY.md`](../../DELIVERY.md)：一般 delivery wizard 與 preflight 說明。
- [`docs/verification/prometheus.md`](../verification/prometheus.md)：Prometheus/Thanos 變數契約。
- [`docs/verification/restic-backup.md`](../verification/restic-backup.md)：restic 變數契約。

Repo 已有 delivery test skill：`.agents/skills/delivery-test/SKILL.md`。它包含本文件的
三 VM integration topology 與完整值清單，但此前沒有一份 tracked runbook 把設定步驟
整理給使用者。`tmp/pilot-semantic-actions-r15/` 的錄影只是 semantic action smoke
coverage；它沒有驗證本拓撲的 restic、Thanos 或 Prometheus site label 值。

## 0.1 執行前提

部署前必須確認：

- 三台 VM 的實際 IP、SSH user、SSH private-key path 都能連線；不可沿用舊 evidence 的 IP。
- `freeipa-server` 使用 AlmaLinux 9；`nexus`、`client-vm` 使用 Ubuntu 24.04。
- `nexus` 至少有 4 vCPU、8 GiB RAM、50 GiB disk；Minimal PoC 建議使用 6 vCPU、12 GiB、80 GiB。
- `freeipa-server` 至少有 2 vCPU、4 GiB RAM、30 GiB disk；`client-vm` 至少有 2 vCPU、2 GiB、20 GiB。
- 三台主機彼此可連線，FreeIPA FQDN/IP、NFS FQDN/IP、S3 endpoint 可解析。
- `nexus` 與 `client-vm` 具備 Docker；Wazuh manager 的目標主機符合上述資源需求。
- 使用同一個目前 revision 的 `pilot` binary、workspace、inventory；不可混用舊 workspace。

## 1. 目標拓撲與角色

使用實際 VM IP 替換下表的 `<...>`；不可沿用舊 round 的 IP。

| Host | 必要 roles |
|---|---|
| `freeipa-server` | `freeipa-server`, `audit-log-forwarding`, `wazuh-fim`, `restic-backup` |
| `nexus` | `freeipa-client`, `freeipa-nfs-server`, `docker`, `audit-log-forwarding`, `wazuh-manager`, `wazuh-fim`, `seaweedfs-s3`, `restic-backup`, `prometheus`, `thanos-query`, `alertmanager`, `dashboard` |
| `client-vm` | `freeipa-client`, `freeipa-nfs-client`, `docker`, `audit-log-forwarding`, `wazuh-fim`, `restic-backup` |

留空：`dns`、`ntp`、`keycloak`、`keycloak-db`、`linux-servers`、`log-server`。

`restic-backup` 不是自動加入的 role；若三台主機的 `hosts.yml` 沒有它，生成的
`inventory.yml` 會有 `restic-backup: hosts: {}`，delivery test 不會有任何 restic
備份目標。

## 2. group vars 與 host vars

下列值填在 workspace 的實際檔案（不是 repo 裡的 `.example.yml`）。

### 2.1 `group_vars/freeipa.yml`

```yaml
freeipa_domain: <FreeIPA domain，server/client 必須一致>
freeipa_realm: <通常是大寫的 freeipa_domain>
freeipa_server_fqdn: <FreeIPA server 的 canonical FQDN>
freeipa_server_ip: <freeipa-server 的實際 IP>
```

若使用 playbook 預設的 `ipa1.<freeipa_domain>` 命名，`freeipa_realm` 與
`freeipa_server_fqdn` 可省略；但 `freeipa_server_ip` 必須與 inventory 的
`freeipa-server.ansible_host` 一致，除非你明確使用外部 provider address。

### 2.2 `group_vars/prometheus.yml`

```yaml
thanos_s3_target_host: <nexus 的實際 IP>
```

`thanos_s3_target_host` 必須指向同時承載 `seaweedfs-s3` 的 `nexus`。

### 2.3 `group_vars/thanos-query.yml`

```yaml
thanos_s3_target_host: <與 prometheus.yml 相同的 nexus IP>
```

`prometheus.yml` 與 `thanos-query.yml` 的 S3 host、bucket 必須一致。

### 2.4 `group_vars/dashboard.yml`

```yaml
thanos_query_target_host: <nexus 的實際 IP>
```

Grafana datasource 應指向 Thanos Query，而不是直接指向 Prometheus。

### 2.4.1 `group_vars/freeipa-nfs-client.yml`（必要時）

```yaml
nfs_server_fqdn: <roster 中 nexus NFS server 的 canonical FQDN>
```

若這個值能由 canonical roster/拓撲可靠推導，可使用預設；在跨網段或 DNS 不完整時應
明確填入，且必須與 `nfs.servers` 的 FQDN 相同。

### 2.5 `group_vars/restic-backup.yml`

```yaml
restic_s3_target_host: <nexus 的實際 IP>
```

這是 restic 的 S3 destination。`restic_aws_access_key_id`、
`restic_aws_secret_access_key`、`restic_password` 不應放在這個明文 group vars 檔，
而應放在下一節的 vault。

### 2.6 `group_vars/wazuh-fim.yml`

```yaml
wazuh_manager_host: <nexus 的實際 IP>
```

### 2.6.1 `group_vars/audit-log-forwarding.yml` 與 `group_vars/wazuh-manager.yml`

`siem_forward_host` 是選填。Minimal PoC 沒有 `log-server` group，因此不要為了填滿欄位
而指向不存在的 host；Wazuh manager 作為中央接收端時，audit/FIM 的 provider discovery
會使用 `wazuh-manager` group。只有要轉送到另一個外部 SIEM 時才填：

```yaml
siem_forward_host: <外部或 log-server 的實際 IP/FQDN>
```

### 2.7 `host_vars/nexus.yml`

`prometheus_site_label` 是每一站唯一的識別值，建議放 host vars，不要使用共享的空字串
group-var 預設：

```yaml
prometheus_site_label: site-nexus
```

這個值不可留空，也不可在多個站台重複。它會寫入
`Prometheus external_labels.site`，供 Thanos Query 區分不同站台。

`pilot edit` 目前沒有 `host_vars/` semantic action；因此這個檔案是明確的 tool-endorsed
例外，需在 workspace 中建立或編輯。完成後必須檢查檔案確實存在，再產生/使用 inventory。

### 2.8 由 inventory 自動推導、但必須能推導的值

以下值可由 site-wide wizard 依 provider group 自動帶入，但 provider group 不可為空：

| 變數 | Provider group | Minimal PoC 來源 |
|---|---|---|
| `thanos_s3_target_host` | `seaweedfs-s3` | `nexus` 的 `ansible_host` |
| `restic_s3_target_host` | `seaweedfs-s3` | `nexus` 的 `ansible_host` |
| `alertmanager_target_host` | `alertmanager` | `nexus` 的 `ansible_host` |
| `thanos_query_target_host` | `thanos-query` | `nexus` 的 `ansible_host` |
| `wazuh_manager_host` | `wazuh-manager` | `nexus` 的 `ansible_host` |

使用單一 component 或直接執行 apply playbook 時，不要依賴 wizard 自動推導；應在對應
group vars 明確填入 `nexus` 的 IP。Site-wide deploy 仍必須先確認這些 provider group
在實際 inventory 中有正確 host。

## 3. `.vault/main.yaml` 必要 key

透過 `pilot edit` 的 vault editor，或既有安全的 vault workflow，確保下列 scalar key
存在且非空。錄影與 trace 只能使用 `value_env`/secret input，不能把值寫進 scenario 或
公開 transcript。

```yaml
ipa_admin_password: <FreeIPA admin password，至少 8 字元>
grafana_admin_password: <Grafana admin password>

restic_aws_access_key_id: <SeaweedFS S3 identity access key>
restic_aws_secret_access_key: <SeaweedFS S3 identity secret key>
restic_password: <restic repository encryption password>

thanos_aws_access_key_id: <必須等於 restic_aws_access_key_id>
thanos_aws_secret_access_key: <必須等於 restic_aws_secret_access_key>
```

Minimal PoC 使用本專案自建的 signed SeaweedFS S3 時，restic 與 Thanos 必須共用同一組
S3 identity。`restic_password` 是 repository 加密密碼，不能用 S3 secret 代替。

`alertmanager_config` 可使用 `group_vars/alertmanager.yml` 的 sandbox `null` receiver；
只有需要真實通知 receiver 時才另加 vault/group-var 設定。

不要把以下內容誤當成已完成設定：

- 註解掉的 key。
- 空字串。
- `CHANGE-ME`、`your-access-key-id`、`your-secret-access-key` 等範例值。
- 只存在於 `vault.example.all.yaml` 的值；它只是範本，不是目前 workspace 的 vault。

## 3.1 FreeIPA canonical roster 與 NFS 設定

`freeipa-identity` 是 day-2 reconcile，但 `freeipa-nfs-server` 在 day-1 也會讀取同一份
canonical roster。因此 `.vault/ipa-identity.yaml` 必須具備：

- `schema_version: 1`。
- `freeipa` connection/safety block。
- `users`、`groups`、`hosts`、`hbac`、`sudo`、`nfs` objects。
- `nfs.servers` 中有 `nexus` 的 canonical FQDN/IP、NFS service principal、export、ACL
  與 automount objects。
- 若設定 `hbac.disable_allow_all: true`，同一份 roster 必須有 enabled 的 admin
  break-glass HBAC rule，否則安全 gate 會拒絕套用。

`freeipa_roster_file` 必須以 host extra var 設在兩台讀取它的主機：

本專案的 **workspace 預設路徑約定**是 `.vault/ipa-identity.yaml`；解析到 deployment
controller 後，必須轉成 workspace 下的 absolute path。`freeipa_roster_file` **沒有
playbook 內建 default**。`freeipa-nfs-server-apply.yml` 會無條件
使用它；未設定會直接以 `freeipa_roster_file is undefined` 失敗。它必須是執行 Ansible 的
deployment controller 可讀取的 absolute path，不是只存在於 target VM 的相對路徑。

本次 `ssh ubuntu@10.1.56.102` 的 deployment workspace，其正確路徑是：

```text
/home/ubuntu/ansible/.vault/ipa-identity.yaml
```

因此兩台 host 的 host extra var 都應設定為完全相同的值：

```text
freeipa_roster_file=/home/ubuntu/ansible/.vault/ipa-identity.yaml
```

若 workspace 換位置，必須把這個值改成新 workspace 下 `.vault/ipa-identity.yaml` 的
absolute path；不可假設 `~/.vault/ipa-identity.yaml`、`./.vault/ipa-identity.yaml` 或
`.vault/main.yaml` 會自動代替它。

| Host | 讀取它的 component |
|---|---|
| `freeipa-server` | `freeipa-identity` reconcile |
| `nexus` | `freeipa-nfs-server` day-1 apply |

兩台都要指向同一個 absolute roster path。不要把 bare top-level `ipa_admin_password`
放進 canonical roster；credential 應在 roster 的 `freeipa.admin.password`，而
contract-level 的 `ipa_admin_password` 由 `.vault/main.yaml` 提供。

## 4. 使用 `pilot edit` 時的 action 對照

Semantic scenario 的 action 應按照下表使用；scenario 只放非秘密值或 `value_env` 名稱。

| 目的 | action | 目標 |
|---|---|---|
| 加入缺少的 vault key | `add_vault_key` | `.vault/main.yaml` + key name + secret input |
| 修改 vault key | `set_vault_value` | `.vault/main.yaml` + key name + `value_env` |
| 儲存 vault | `save_vault` | `.vault/main.yaml` |
| 修改一般設定 | `set_group_var` | 對應的 `group_vars/<role>.yml` |
| 儲存一般設定 | `save_group_vars` | 對應的 group vars 檔 |
| 加入 role | `enable_role` | `hosts.yml` 的指定 host |
| 設定 host extra var | `add_extra_var` / `edit_extra_var` | `hosts.yml` |

每次存檔後都要讀回檔案，確認 key 名稱、檔案路徑、role membership 正確。TUI 顯示
`已存檔` 只證明寫檔成功，不證明游標曾停在正確欄位。

`host_vars/nexus.yml` 不在上述 semantic action 覆蓋範圍內；它必須另外建立，這正是
此前 `prometheus_site_label` 在實際 deployment 遺漏的原因。

## 5. 生成 inventory 前後的檢查表

先確認 `hosts.yml` 的 role membership，再執行 `pilot inventory generate`。生成後檢查：

- `prometheus` group 只有預期的 `nexus`。
- `seaweedfs-s3`、`thanos-query`、`alertmanager`、`dashboard` 都包含 `nexus`。
- `restic-backup` 包含所有需要備份的 hosts，至少是 PoC 表格中的三台。
- `freeipa-server`、`freeipa-client`、NFS groups 與拓撲一致。
- `host_vars/nexus.yml` 存在且含非空 `prometheus_site_label`。
- `.vault/main.yaml` 包含本文件第 3 節所有必要 key。
- `.vault/ipa-identity.yaml` 存在、schema 正確，且 `nfs.servers` 與 `nexus` 的實際
  hostname/IP 相符。
- `freeipa_roster_file` 已設定在 `freeipa-server` 與 `nexus` 的 host extra vars。

若 `restic-backup` 是空 group，必須先修正 `hosts.yml` 再重新產生 inventory；不能只
補 vault key，因為沒有 target host 時不會部署 backup timer。

## 6. deployment 前 preflight 契約

Site-wide deploy 應只選一次 `全站部署(site.yml)`。不要以單一 component 逐個模擬全站，
也不要對 `site.yml` 傳 `target_group`；空 inventory group 由 site entry 自動跳過。

在進入 apply 前，以下條件必須全部成立：

1. `prometheus_site_label` 非空。
2. restic 三個 required secret 都已由目前選取的 vault 提供。
3. Thanos 兩個 required secret 都已由目前選取的 vault 提供。
4. `seaweedfs-s3`、`prometheus`、`thanos-query`、`restic-backup` 的 S3 destination
   都指向同一個 `nexus`/S3 endpoint。
5. `restic` 與 `thanos` 使用同一組 S3 access/secret identity。
6. `restic-backup` 的 target group 非空。
7. stage 與 inventory 的 `staging`/`prod` group（若有）一致。

只要 preflight 報 required input，先修正 workspace/vault；不要用 skip preflight，也不要
把秘密臨時貼到公開 command line。

### 6.1 stage 與確認旗標

本 PoC 使用 `sandbox`，不需額外 confirm flag。若主機屬於 `staging` 或 `prod`：

- 必須帶正確的 `stage=staging` 或 `stage=prod`。
- `staging` 必須有 `confirm_staging=true`。
- `prod` 必須有 `confirm_prod=true`，且 staging attestation 不得超過 168 小時。
- service role group 與 environment group 是兩件事；不能只因 host 在 `staging`/`prod`
  group 就省略 service role，也不能期待 inventory group 自動決定 `stage`。

### 6.2 site-wide component order

正常 site-wide deployment 的依賴鏈應涵蓋：

1. FreeIPA server。
2. FreeIPA clients。
3. FreeIPA NFS server，再到 NFS client。
4. Docker。
5. Wazuh manager、SeaweedFS S3。
6. Restic backup。
7. Prometheus、Thanos Query、Alertmanager、Dashboard。
8. Audit/FIM/log shipping 等依賴中央服務的元件。

`freeipa-identity` 是 site-wide deployment 後另外執行的 day-2 reconcile；不要把
canonical roster 當普通 group var，也不要只依賴 reconcile 成功來代表 day-1 roles 已部署。

### 6.3 S3 signed mode 與 buckets

當 vault 中有 restic S3 access/secret 時，SeaweedFS 應使用 signed configuration；其
identity 必須與 restic/Thanos 使用的 access/secret 相同。不要讓 SeaweedFS 留在
anonymous mode 後期待 restic 的 signed request 能成功。

| 用途 | 預設 bucket |
|---|---|
| Restic | `pilot-restic-backup` |
| Thanos metrics | `pilot-thanos-metrics` |

兩個 bucket 名稱必須在各自的 producer/query 設定中一致；不要把 restic bucket 與
Thanos bucket 混成同一個值，除非另有明確且已驗證的 storage contract。

## 7. 與 r15 錄影的差異

`tmp/pilot-semantic-actions-r15/` 的有效示範範圍只有：

- 建立 host、設定一般 host field、套用 role preset。
- 修改 `dns.yml` 的 `dns_listen_addr`。
- 新增/修改 `ipa_admin_password`。
- 儲存 group vars/vault。

它沒有示範或驗證：

- `prometheus_site_label` 的 `host_vars/nexus.yml` 建立。
- `restic-backup` role 加入三台 host。
- restic 三個 required vault key。
- Thanos 兩個 required vault key。
- 這些值是否被同一個 `pilot deploy` transaction 讀取。

因此 r15 錄影不能作為上述設定已完成的 evidence；它只能作為 semantic action API 的
smoke evidence。

## 8. 目前問題的對應修正

針對已調查的 `/home/ubuntu/ansible`：

- `hosts.yml` 的三台 host 補上需要的 `restic-backup` role。
- 建立 `host_vars/nexus.yml`，填入唯一的 `prometheus_site_label`。
- 把 restic access key/secret 與 Thanos access key/secret 放入目前 deploy 會選取的
  `.vault/main.yaml`；兩組 S3 identity 必須相同。
- 保留 `restic_s3_target_host`、`thanos_s3_target_host` 的 destination 指向 `nexus`。
- 不要把真實 credentials 留在權限 `644` 的 `group_vars/restic-backup.yml`；若那些值
  已被使用，先輪換後再移入 vault。
- 修正明文 identity roster 的檔案權限，至少避免其他使用者讀取。

完成上述修改後，重新產生 `inventory.yml`，再次查看實際 inventory group membership，
再執行完整 preflight。舊的 failed transaction 不可被當成新設定的 evidence。
