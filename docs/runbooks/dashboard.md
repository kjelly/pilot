# Runbook — dashboard + log-shipping（Grafana + Loki）

## 0. 目標

Grafana 透過 Thanos Query 的 Prometheus-compatible API 查 metrics，透過本機 Loki 查日誌。服務連線以 DNS 名稱維持，容器 IP 改變時不需要改 datasource 設定。

## 0.5 目前有效的事實快照

- 驗證日期：2026-10-12 UTC；candidate `9bcc4fa95552f99553ba126bb2963fcdf445aa60`，tree `d42b0dd91cb9838e94e8633038f8985ed9a9f4a5`。
- 目標：由 `docs/topologies/dashboard-dns-topology.yaml` 建立的全新 Ubuntu 24.04 KVM VM，實際 inventory 的 `docker`、`seaweedfs-s3`、`prometheus`、`thanos-query`、`dashboard` 都指向同一個測試 host。
- 外部 state：重用既有 local cache services；測試變數檔包含 Grafana 密碼、Thanos S3 access/secret key、S3 endpoint、site label 與測試 bucket 清單，秘密值不放入文件。
- 對齊決定：A，建立具備上述 role groups 的拋棄式 inventory；沒有以 spec 推測實際 host。完整測試後 VM 已清除。
- 結果：fresh check mode `failed=0`，apply `changed=31 failed=0`，dashboard v1.3 **14/14 PASS**，第二次 apply **changed=0 failed=0**。
- [目前有效的驗證證據](../evidence/dashboard/2026-10-12-9bcc4fa.md)。本輪涵蓋 Grafana/Loki 與同機 Thanos datasource；沒有重驗跨主機 log-shipping 或修改正式環境。

## 1. 服務連線契約

| 情境 | Datasource URL | 名稱解析 |
|------|----------------|----------|
| Grafana 與 Thanos 共用同主機的 Docker network | `http://thanos-query-backend:10902` | Thanos Query 的 network alias，由 Docker DNS 解析目前容器 IP |
| Grafana 與 Thanos 分開主機 | `thanos_query_url` 指定的服務 FQDN URL，或相容的 `thanos_query_target_host` 搭配公開 port | 容器可使用的中央 DNS；保留名稱，避免將查到的 IP 寫入 hosts |

同機使用 **容器 port 10902**。主機公開 port **10912** 是跨主機或主機端存取的入口，避免與 Prometheus Sidecar 的主機 port 10902 衝突。

`thanos_query_alias` 在 provider 與 dashboard 必須一致，且兩者必須共用同一個 `docker_network_name`。預設為 `thanos-query-backend` 與 `pilot-metrics`。重建 provider 時，Docker DNS 更新名稱對應的 IP；datasource URL 維持不變。

## 2. 套用與升級

1. 先確認實際 inventory 的 `dashboard` 與 `thanos-query` provider 是否共置，以及環境 group / stage 是否一致。
2. 先套用 `thanos-query`，讓 provider 宣告 network alias；再套用 `dashboard`，讓 Grafana 更新 datasource URL。同機預設不需要提供 IP。
3. 跨主機提供容器能解析的服務 FQDN；完整 URL 可由 `thanos_query_url` 覆寫。URL 必須是 HTTP(S) 根路徑位址，不含帳密、query 或 fragment。TLS 憑證必須受 Grafana 容器信任。
4. dashboard 升級會備份 hosts 至 `/etc/hosts.pre-dashboard.bak`，並移除它管理的舊 Thanos hosts alias；移除失敗時還原並停止。其他 hosts entries 不受影響。
5. 依 [dashboard verification spec](../verification/dashboard.md) 驗收。C8 從 Grafana 容器讀取實際 datasource URL 後連線，不能用主機 curl 成功代替。

上游尚未部署時允許 Grafana/Loki 先上線，但 C8 fail 表示 datasource 尚未就緒，不能宣告完整交付成功。

## 3. 可重跑的隔離驗證

本次正式測試使用 `docs/topologies/dashboard-dns-topology.yaml` 與 `playbooks/test/dashboard-dns-chain.yml`。安裝順序為 Docker → SeaweedFS S3 → Prometheus/Sidecar → Thanos Query → Grafana/Loki。

透過 `vm-target topology test` 的 ephemeral 模式跑 syntax → fresh check mode → cluster snapshot → apply → dashboard verify → 第二次 apply（changed=0），成功或失敗後清除本次建立的 VM。完整命令、revision/tree、檔案 hashes 與結果存於上述 evidence record；測試秘密由 private extra-vars 檔提供。

## 4. 失敗定位與復原邊界

| 症狀 | 檢查 |
|------|------|
| Grafana 日誌出現 `lookup thanos-query-backend ... no such host` | provider 是否已套用 alias；兩個容器是否共用 network |
| alias 可解析但 connection refused | 同機 datasource 是否誤用主機 port 10912；Query 是否正在監聽容器 port 10902 |
| 跨主機無法解析 FQDN | 從 Grafana 容器檢查 DNS；主機 hosts pin 不會自動進入容器 |
| C8 pass 但畫面沒有資料 | 再檢查 Thanos StoreAPI、Prometheus scrape 與 dashboard 查詢條件 |
| Loki 暫時回 503 | 等待 ring/compactor join；playbook 已有 readiness retries |

測試 topology 的 snapshot / rollback 保護拋棄式 VM。正式環境升級需要其自身復原安排；本次程式碼修改沒有部署到正式環境。

## 5. log-shipping 的操作契約

日誌路徑為來源主機 → log-server 接收與落地 → 同主機 Promtail → dashboard 的 Loki → Grafana。這條鏈的驗收與變數以 [log-shipping spec](../verification/log-shipping.md) 為準；本次沒有變更 Promtail 或它的連線機制。

- 先確認 log-server 已能接收日誌並寫入 `siem_log_root`，再套用該主機的 log-shipping。
- `siem_log_root` 必須與 log-server 相同，預設為 `/var/log/siem`；Promtail 的 positions 持久化在 `/var/lib/pilot/promtail`。
- `loki_target_host` 指向 dashboard 主機；既有 `loki_alias` 為 `pilot-loki-backend`，公開 port 預設 3100。跨主機應確認 Promtail 容器可達設定的 endpoint。
- 同主機偵測到 Wazuh manager 時，另加一個 alerts scrape job，保留原有 SIEM scrape；不能以 Wazuh logs 取代 log-server 落地資料。
- C6 驗證真正注入、轉送與查回日誌，C9 再以來源 `host` label 篩選，證明該主機有資料；單純看到 Promtail running 或 Loki 有其他主機的資料不足以通過。
- 歷史 smoke-test transcript 由 Git history 保留；本文件目前的 evidence 僅宣告本輪 dashboard/Docker DNS 的實測範圍。
