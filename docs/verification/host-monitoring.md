# Verification Spec — host-monitoring（被監控主機的監控 agent：node_exporter）

> 版本：v1.2
> 對齊規範：pilot 通用「每台受管主機都裝一份」agent 規範，跟
> `wazuh-fim.md`/`audit-log-forwarding.md` 同一類 Shape（cross-cutting agent
> role，可疊加到任何既有主機上，不擁有專屬 role 之外的意義）。
> 維護者：sre

> 這份 spec 目前只實作 `node_exporter`（OS/硬體層 metrics：CPU、記憶體、磁碟、
> 網路），角色名稱刻意取通用的 `host-monitoring` 而非 `node-exporter`——之後
> 若要在同一批被監控主機上加裝其他監控 agent（例如 blackbox_exporter 探測
> 外部端點、process-exporter 盯特定行程），比照本 repo「一個軟體一個
> component」的慣例（`wazuh-fim`/`audit-log-forwarding` 也是分開的
> component，即使都是「裝在受管主機上的 agent」）新增獨立的
> `docs/verification/<name>.md` + `playbooks/apply/<name>-apply.yml`，不要
> 硬塞進這份 spec 或這支 playbook——名稱通用只是方便之後在同一個「主機監控」
> 語意下找到相關 component，不代表這裡會變成一個吃各種軟體的萬用 role。
>
> 消費端（`docs/verification/prometheus.md`）如何找到這裡裝好的
> node_exporter：見 `prometheus.md` §1.5 的 `node_exporter_targets`——留空時
> 會自動展開 inventory 裡 `host-monitoring` group 的所有主機，不需要手動
> 逐台填 IP。
>
> **Kubernetes 自動偵測（v1.2）**：`host-monitoring` group 裡的某些主機可能
> 已經透過 Kubernetes DaemonSet（例如 kube-prometheus-stack 用 hostPort
> 9100）跑了 node_exporter，不是靠這支 playbook。apply 在動手前會先檢查
> `node_exporter_port` 是否已經被監聽、且不是這支 playbook 自己管理的
> pinned binary——如果是，整段原生安裝直接跳過（不搶 port、不因為不支援的
> OS 而 fail、也不要求任何密碼），Prometheus 仍會照常把這台主機當 scrape
> target（純粹靠 inventory group 成員資格，跟這支 playbook 有沒有真的做過
> 事無關，見 `prometheus.md` §1.5）。這種主機上 `pilot verify` 本檔會有
> 多條 row 預期 fail，見 §5。

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Hostname / Inventory group | `host-monitoring`（vm-target 測試時用單一 host，見 §7） |
| OS / version | Ubuntu 22.04/24.04 LTS（apt）、AlmaLinux 9（dnf，走官方 binary release，見 §1.5） |
| 角色 | 一般受管主機：以固定版本的官方 release binary 安裝 `node_exporter`，用專屬系統帳號透過 systemd 常駐，對外提供 `:9100/metrics` |
| 套用範圍 | `/usr/local/bin/node_exporter`、`/etc/systemd/system/node_exporter.service`、專屬系統帳號 `node_exporter` |
| 風險等級 | Low（純唯讀 metrics exporter，不接受任何寫入型 API；主要風險是暴露主機硬體/OS 細節，故不綁定公開網路介面之外的額外考量） |

## 1.5 依賴變數契約

在套用或驗證此主機時，Playbook 與變數參數必須嚴格遵守以下命名，禁止擅自縮寫或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 | 預設值 |
|---------|----------|---------|--------|
| `node_exporter_version` | 固定安裝的官方 release 版本號（不含 `v` 前綴），兩種 distro 都裝同一份 binary，不吃各 distro 套件庫版本 | 否 | `1.12.1` |
| `node_exporter_port` | `--web.listen-address` 監聽的 port | 否 | `9100` |
| `node_exporter_user` | 專屬系統帳號/群組名稱（無 home、無互動 shell） | 否 | `node_exporter` |
| `node_exporter_basic_auth_user` | HTTP Basic Auth 使用者名稱（非機密） | 否 | `prometheus` |
| `node_exporter_basic_auth_password` | HTTP Basic Auth 密碼；**必須跟 `prometheus.md` 的 `node_exporter_basic_auth_password` 用同一個值**，否則 Prometheus 端會被 401 擋下，永遠抓不到資料 | 是 | 無（空值會被 gate 擋下） |

> **為何兩種 distro 統一走官方 binary，不用各 distro 套件庫**：Ubuntu
> 22.04/24.04 的 `prometheus-node-exporter` apt 套件版本停在 1.7.0（實測
> 2026-08-10）；AlmaLinux 9（含 EPEL）完全沒有 node_exporter 套件（實測
> `dnf search node_exporter` 零結果）。若各 distro 各自吃套件庫版本，兩邊
> 版本/行為會分岔，且 EL 這邊本來就無法只靠套件管理器解決。改用固定版本的
> 官方 release binary（`get_url` 帶 `checksum:` 參數，下載後自動驗證
> sha256，不符即 fail）在兩種 distro 上裝出一致的行為，也跟這個 repo 對
> Prometheus/Thanos 本身「版本固定的 image/binary」的既有慣例一致（見
> `prometheus.md` 的 `prometheus_version`/`thanos_version`）。
>
> **架構支援**：apply playbook 依 `ansible_architecture` 自動選擇
> `linux-amd64`/`linux-arm64` 對應的官方 release 與 checksum；目前只預先
> 內建這兩種架構的 checksum，其他架構會在 pre_tasks gate 直接 fail（清楚
> 訊息，不會裝出一個沒驗證過 checksum 的 binary）。
>
> **為何 Basic Auth 是強制而非選填**：`node_exporter` 預設會把主機的
> CPU/記憶體/磁碟/網路/掛載點/process 等硬體與 OS 細節，原封不動地用純文字
> 攤在 `:9100/metrics` 上，任何連得到這個 port 的人都能讀——這是實質的
> 主機偵查（reconnaissance）資訊洩漏，不是「內部網路所以還好」可以接受的
> 風險。node_exporter 內建的 `--web.config.file`（exporter-toolkit）機制
> 支援 HTTP Basic Auth：密碼用 `htpasswd -nbBC 10`（`apache2-utils`/
> `httpd-tools` 提供，**只是拿它的 CLI 工具產生 bcrypt hash，不是要在這台
> 主機上跑 Apache**）在目標主機上就地產生 bcrypt hash 寫進
> `/etc/node_exporter/web-config.yml`，明文密碼不落地、不進 Ansible log
> （所有相關 task 都是 `no_log: true`）。bcrypt 雜湊每次呼叫的 salt 都不同
> （非 deterministic），所以 apply playbook 用一個密碼明文的 sha256
> fingerprint（不可逆、非密碼本身）判斷憑證是否真的變了，只有真的變了才
> 重新雜湊、重寫檔案、重啟服務——避免密碼沒換也被每次 apply 判定成
> `changed=1`。Prometheus 端要能通過驗證抓到資料，見 `prometheus.md` §1.5
> 的對應設定（**兩邊必須帶同一組密碼**，這是操作者的責任，跟
> `thanos_s3_bucket` 兩邊要填同一個值是同一種契約）。

## 2. Checklist

| ID  | Category | Check                                             | Expected  | Command |
|-----|----------|----------------------------------------------------|-----------|---------|
| C1  | file     | `node_exporter` binary 已安裝                       | present   | test -f /usr/local/bin/node_exporter |
| C2  | version  | 安裝版本符合固定版本號                                 | ~1.12.1   | /usr/local/bin/node_exporter --version 2>&1 |
| C3  | user     | 專屬系統帳號存在，且為無互動 shell（nologin）           | ~nologin  | getent passwd node_exporter | cut -d: -f7 |
| C4  | file     | systemd unit 檔存在                                 | present   | test -f /etc/systemd/system/node_exporter.service |
| C5  | config   | systemd unit 以專屬帳號執行（不是 root）                | 0         | grep -qE '^User=node_exporter$' /etc/systemd/system/node_exporter.service; echo $? |
| C6  | config   | systemd unit 有 `NoNewPrivileges=true`（權限限縮）      | 0         | grep -qE '^NoNewPrivileges=true$' /etc/systemd/system/node_exporter.service; echo $? |
| C7  | service  | `node_exporter.service` 為 active                    | 0         | systemctl is-active node_exporter >/dev/null 2>&1; echo $? |
| C8  | port     | `9100/tcp` 有在監聽                                  | present   | ss -tln 'sport = :9100' |
| C9  | http     | 未帶認證的 `/metrics`（9100）請求被拒絕（驗證確實有生效，不是設定了但沒生效） | ~401 | curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:9100/metrics |
| C10 | config   | `web-config.yml` 已宣告 `basic_auth_users` 且含指定的使用者名稱             | 0    | grep -qE '^\s*prometheus:' /etc/node_exporter/web-config.yml; echo $? |

> C2 只驗證「這個版本號的 binary 確實被裝上」，不是重新做一次 checksum
> 比對——checksum 驗證已經在 apply 當下由 `get_url` 的 `checksum:` 參數強制
> 做過（不符即 fail，不會裝出未驗證的 binary），這裡不重複驗證同一件事。
> C9 驗證的是「認證真的擋下未授權請求」這個**行為**，不只是「設定檔裡有
> `basic_auth_users` 這個 key」（C10 驗證那個，兩條合起來才是完整證明——
> 只驗證設定存在，抓不到「exporter-toolkit 版本太舊/flag 打錯導致設定形同
> 虛設」這種真實會發生的 gap，見 spec-driven-feature-workflow skill §5
> 「只在 true-positive 狀態下跑過的檢查不能證明自己是真檢查」）。
> **含認證資料的內容驗證（「認證後真的能抓到 `node_uname_info`」）刻意不放
> 進這份 spec**：spec 的 Command/Expected 欄位是所有部署共用的固定字串，
> 沒有地方能安全內插每個站台不同的密碼（AGENTS.md 禁止 spec 出現密碼）。
> 這個端到端證明改由 `prometheus.md` 的 `up{job="node"}==1` 檢查完成——
> Prometheus 端本來就合法持有這組密碼（來自 vault/group_vars，從不出現在
> 任何 spec 文字裡），用它去抓 node_exporter 成功，等於同時證明了「認證通過
> 且回傳的是真正的 node_exporter metrics」，不需要在這份 spec 裡重複驗證，
> 跟 `wazuh-fim.md` 把「FIM+who-data 端到端證明」交給 runbook 層 cross-check
> 是同一種設計（見該檔 §5）。

## 3. 證據收集

- 工具：`pilot verify docs/verification/host-monitoring.md -i <inventory> -l host-monitoring`
- 輸出格式：`.verification/host-monitoring-<UTC>.{ndjson,md}`
- 預期 row 數：10

## 4. PASS / FAIL 規則

- C1–C10 全部 `status=pass` → **PASS**
- 任一 `status=fail` → **FAIL**，常見修法：
  - C1/C2 fail → binary 沒裝上或版本不符；重跑 apply，檢查 `node_exporter_version`/架構是否在支援清單內
  - C3 fail → 專屬帳號沒建立成功或 shell 不是 nologin
  - C4–C6 fail → systemd unit 沒渲染成功或內容跑掉
  - C7 fail → 服務沒啟動；`journalctl -u node_exporter`
  - C8 fail → port 沒監聽；檢查 C7 是否先 pass
  - C9 fail（回 200 而不是 401）→ 認證形同虛設；檢查 systemd unit 的
    `ExecStart` 是否真的帶了 `--web.config.file`，以及 C10 是否 pass
  - C10 fail → `web-config.yml` 沒渲染成功或找不到指定使用者；檢查
    `node_exporter_basic_auth_password` 是否有帶、`htpasswd`（`apache2-utils`/
    `httpd-tools`）是否安裝成功

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| — | 目前只預先內建 `linux-amd64`/`linux-arm64` 兩種架構的 release checksum；其他架構（例：`386`、`ppc64le`）會在 pre_tasks gate 直接 fail，不會裝出未驗證 checksum 的 binary | 非 amd64/arm64 主機 | 需要時在 apply playbook 的 `node_exporter_checksums` 補上對應架構與其官方 sha256sums.txt 的值 |
| C1, C3–C7, C9, C10 | 當 `node_exporter_port` 已被非本 playbook 管理的程式佔用（常見於 Kubernetes DaemonSet 已部署 node_exporter，見 §0），apply 會整段跳過原生安裝，本檔全部 row 都不適用於這台主機——C1/C3–C7/C10 因為沒有真的裝任何東西必定 fail；C8（port 監聽）通常仍會 pass（有別的東西在 serve）；C9（未認證應回 401）視現有 exporter 是否有自己的認證機制而定，Kubernetes 版 node_exporter 預設沒有認證，通常會回 200 而 fail，這是**預期行為，不是 bug** | 由 Kubernetes（或任何其他機制）自行管理 node_exporter 的主機 | 不會解除——這種主機的 node_exporter 健康狀態改由該機制自己的健康檢查（例如 `kubectl` 查 DaemonSet/Pod 狀態）負責，不屬於本 spec 範圍 |

## 6. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-08-10 | v1.0 | 初版：node_exporter，兩種 distro（Ubuntu apt 版本過舊、AlmaLinux 9 無套件）統一走固定版本官方 release binary + systemd | sre |
| 2026-08-10 | v1.1 | 新增強制 HTTP Basic Auth（`--web.config.file` + bcrypt hash，密碼不落地/不進 log）；C9 從「未認證回 200」改成「未認證回 401」（驗證認證真的生效，不只是設定存在）；C10 從「exposition 含 node_uname_info」改成「web-config.yml 已宣告 basic_auth_users」，含認證的內容驗證改交給 `prometheus.md` 的 `up{job="node"}==1` | sre |
| 2026-08-10 | v1.2 | 新增 Kubernetes 自動偵測：`node_exporter_port` 已被非本 playbook 管理的程式佔用時（例如 DaemonSet），整段跳過原生安裝，不搶 port、不要求密碼；Prometheus 仍照常把該主機當 scrape target（純靠 inventory group 成員資格）；新增對應 §5 例外列 | sre |
