# Runbook — dashboard + log-shipping（Grafana + Loki）

## 0. 目標

Grafana 透過 Thanos Query 的 Prometheus-compatible API 查 metrics，透過本機 Loki 查日誌。服務連線以 DNS 名稱維持，容器 IP 改變時不需要改 datasource 設定。

## 0.5 目前有效的事實快照

- 交付入口（deploy/reconcile）驗證日期：2026-10-13 UTC；candidate `0966cedadaa0ee0c5bdcf8c10e577e2b4a2bc8c1`，tree `39cd8232f42c2f9940d487d1027f64d038885245`。
- 目標：兩台全新 Ubuntu 24.04 KVM VM。實際 inventory：provider 在 `docker`、`seaweedfs-s3`、`thanos-query`；consumer 在 `docker`、`dashboard`。`--limit` 只框 consumer；本輪沒有 Prometheus sites。
- 外部 state：先只在 provider 套用 Docker 與 SeaweedFS S3。測試變數檔包含 Grafana 密碼、Thanos S3 access/secret key 與測試 bucket，另含 `target_group: dashboard`（PR #39 review 的衝突情境）；秘密值不放入文件。
- 對齊決定：A，建立具備上述 role groups 的拋棄式 inventory，以 `ansible-inventory --graph` 確認。完整測試後 VM 已清除。
- 結果：計畫為 Docker（兩台）→ Thanos Query（provider）→ dashboard（consumer），每個依賴的 `target_group` 都排在變數檔之後。deploy 全部 `failed=0`，dashboard **14/14 PASS**；reconcile 後 dashboard **14/14 PASS**，thanos-query 10/13（C9/C10/C13 需要 Prometheus site）；再跑 reconcile 每個 apply 都是 `changed=0`。修正前的 control 同樣流程回報成功，但 Thanos Query 的 apply 是 `skipping: no hosts matched`，dashboard C8 FAIL。
- 全新 topology chain（同機、check mode → apply → verify → 第二次 apply）最後一次在 2026-10-12 的 `9e6d684` 驗證：dashboard 14/14 PASS，第二次 apply changed=0；之後 playbook、contract 與 dashboard 驗收 row 沒有變更。
- [目前有效的交付入口證據](../evidence/dashboard/2026-10-13-0966ced-delivery.md)；[topology chain 證據](../evidence/dashboard/2026-10-12-9e6d684-delivery.md)。沒有重驗跨主機 DNS/TLS、log-shipping，也沒有修改正式環境。

## 1. 服務連線契約

| 情境 | Datasource URL | 名稱解析 |
|------|----------------|----------|
| Grafana 與 Thanos 共用同主機的 Docker network | `http://thanos-query-backend:10902` | Thanos Query 的 network alias，由 Docker DNS 解析目前容器 IP |
| Grafana 與 Thanos 分開主機 | `thanos_query_url` 指定的服務 FQDN URL，或相容的 `thanos_query_target_host` 搭配公開 port | 容器可使用的中央 DNS；保留名稱，避免將查到的 IP 寫入 hosts |

同機使用 **容器 port 10902**。主機公開 port **10912** 是跨主機或主機端存取的入口，避免與 Prometheus Sidecar 的主機 port 10902 衝突。

`thanos_query_alias` 在 provider 與 dashboard 必須一致，且兩者必須共用同一個 `docker_network_name`。預設為 `thanos-query-backend` 與 `pilot-metrics`。重建 provider 時，Docker DNS 更新名稱對應的 IP；datasource URL 維持不變。

## 2. 套用與升級

1. 先確認實際 inventory 的 `dashboard` 與 `thanos-query` provider 是否共置，以及環境 group / stage 是否一致。
2. 執行 `pilot deploy` 的單一元件模式，或 `pilot reconcile`，只選 `dashboard`。確認畫面會列出實際 host 與 Docker → Thanos Query → dashboard 的套用計畫；確認後自動宣告 provider network alias 並更新 Grafana datasource。同機預設不需要提供 IP，也不需要另跑 Thanos 的部署。
3. 跨主機提供容器能解析的服務 FQDN；完整 URL 可由 `thanos_query_url` 覆寫。URL 必須是 HTTP(S) 根路徑位址，不含帳密、query 或 fragment。TLS 憑證必須受 Grafana 容器信任。
4. dashboard 升級會備份 hosts 至 `/etc/hosts.pre-dashboard.bak`，並移除它管理的舊 Thanos hosts alias；移除失敗時還原並停止。其他 hosts entries 不受影響。
5. 依 [dashboard verification spec](../verification/dashboard.md) 驗收。C8 從 Grafana 容器讀取實際 datasource URL 後連線，不能用主機 curl 成功代替。

SeaweedFS S3 是既有前置服務，這個計畫不會自動部署它；先備妥 S3、必要 credentials 與實際 inventory 的 provider group。缺少或無法唯一選定 Thanos provider 時，計畫在 apply 前停止。依賴套用失敗時不執行 dashboard，已完成的依賴保留於 delivery evidence；不是整條鏈的原子 rollback。

`reconcile` 會修復 provider alias 與 datasource 設定；狀態已符合時，實際 apply 可收斂到 changed=0。完整設定更新請讓 tags 留空；consumer row tags 不會傳給依賴。跨主機仍需使用容器可解析的服務名稱。C8 fail 表示 datasource 尚未就緒，不能宣告完整交付成功。

## 3. 可重跑的隔離驗證

本次正式測試使用 `docs/topologies/dashboard-delivery-topology.yaml` 與 `playbooks/test/dashboard-delivery-chain.yml`。安裝順序為 Docker → SeaweedFS S3 → Thanos Query → Grafana/Loki。另從真實 deploy/reconcile 入口只選 dashboard，驗證 provider 自動套用、移除 alias 後的修復與再次套用收斂。

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
