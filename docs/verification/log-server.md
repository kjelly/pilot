# Verification Spec — log-server（rsyslog 中央日誌接收端 / SIEM forward 目標）

> 版本：v1.3
> 對齊規範：pilot 通用 config-only 服務規範（比照 `pam-oidc-sshd.md` 的
> block/rescue + tags 模式）；為 `audit-log-forwarding.md`（client 端 auditd +
> rsyslog 轉送）提供中央接收端，兩份 spec 搭配構成一組 Shape 3（server+client）。
> 維護者：sre

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Hostname / Inventory group | log-server |
| OS / version | Ubuntu 24.04 LTS（rsyslog 8.2312+，內建 RainerScript / imtcp） |
| 角色 | 中央 syslog 接收端：收 client 端 rsyslog 轉送的 `auth,authpriv.*` 與 `local6.*`（auditd），依來源 hostname 分檔落地 |
| 套用範圍 | `/etc/rsyslog.d/10-siem-receiver.conf`、`/etc/logrotate.d/siem-incoming`、`/var/log/siem/` |
| 風險等級 | Medium（對外開 514/tcp 收網路日誌；設定錯誤頂多漏收，不影響本機既有日誌） |

> 為何選 rsyslog 而非 Loki/syslog-ng：client 端轉送已固定用 rsyslog 協定
> （`@@host:514`，TCP），中央端用同一套軟體收沒有協定/格式落差風險，且
> Ubuntu/EL9 都預裝，符合本 repo「單一 systemd service + 檔案」的 spec 模式
> （比照 `seaweedfs-s3.md`）。查詢/dashboard 需求可日後在此之上疊
> Promtail→Loki（見 `log-shipping.md`），不影響本 spec。
>
> **只收 TCP，不收 UDP**（v1.2 起）：`audit-log-forwarding-apply.yml` 只用
> `@@`（TCP）轉送，本 repo也沒有任何其他角色會轉送 syslog——v1.0/v1.1 的
> `imudp` 接收能力是為了「假設未來有台只會講 UDP syslog 的網路設備」預留的
> 推測性容量，從沒被實際用過。拿掉整條 UDP 支援，換掉原本用來避開
> 514/udp 跟官方 wazuh-docker compose 撞埠的 `siem_receiver_udp_enabled`
> 條件邏輯——反正 UDP 本身就沒人用，不用特別保留、也不用為它繞開撞埠問題。
> 如果之後真的出現只會講 UDP 的來源，再重新加回 `imudp` 即可，不要為了
> 「以後可能需要」預先保留一份沒人在跑的能力。

## 1.5 依賴變數契約

在套用或驗證此主機時，Playbook 與變數參數必須嚴格遵守以下命名，禁止擅自縮寫或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 | 預設值 |
|---------|----------|---------|--------|
| `siem_receiver_tcp_port` | rsyslog `imtcp` 監聽埠 | 否 | `514` |
| `siem_log_root` | 依來源 hostname 分檔落地的根目錄 | 否 | `/var/log/siem` |
| `siem_logrotate_rotate` | logrotate 保留檔案數 | 否 | `14` |
| `siem_logrotate_maxage` | logrotate `maxage`（天） | 否 | `90` |

## 2. Checklist

| ID  | Category  | Check                                                              | Expected | Command |
|-----|-----------|----------------------------------------------------------------------|----------|---------|
| C1  | package   | `rsyslog` 已安裝                                                     | 0        | dpkg -s rsyslog >/dev/null 2>&1; echo $? |
| C2  | service   | `rsyslog.service` 為 active                                          | 0        | systemctl is-active rsyslog >/dev/null 2>&1; echo $? |
| C3  | file      | 接收端 drop-in 設定檔存在                                             | present  | test -f /etc/rsyslog.d/10-siem-receiver.conf |
| C4  | config    | 設定檔含 `imtcp` module + input                                       | 0        | grep -qE 'module\(load="imtcp"\)' /etc/rsyslog.d/10-siem-receiver.conf; echo $? |
| C5  | network   | TCP 514 確實在監聽                                                    | 0        | sh -c 'ss -lnt | grep -q ":514" && echo 0 || echo 1' |
| C6  | dir       | 落地根目錄 `/var/log/siem` 存在                                       | present  | test -d /var/log/siem |
| C7  | functional| 本機注入 `local6` 測試訊息，依 `%HOSTNAME%` 落地到 `audit.log`         | ~PILOT-SIEM-SELFTEST-AUDIT | sh -c 'logger -p local6.info "PILOT-SIEM-SELFTEST-AUDIT"; sleep 1; grep -r "PILOT-SIEM-SELFTEST-AUDIT" /var/log/siem/*/audit.log 2>/dev/null; true' |
| C8  | functional| 本機注入 `authpriv` 測試訊息，依 `%HOSTNAME%` 落地到 `auth.log`        | ~PILOT-SIEM-SELFTEST-AUTH | sh -c 'logger -p authpriv.info "PILOT-SIEM-SELFTEST-AUTH"; sleep 1; grep -r "PILOT-SIEM-SELFTEST-AUTH" /var/log/siem/*/auth.log 2>/dev/null; true' |
| C9  | file      | logrotate 策略檔存在                                                  | present  | test -f /etc/logrotate.d/siem-incoming |
| C10 | logrotate | logrotate 策略檔語法正確（dry-run 不出錯）                            | 0        | logrotate -d /etc/logrotate.d/siem-incoming >/dev/null 2>&1; echo $? |
| C11 | config    | `imtcp` input 綁定專屬 ruleset（不會落回 default ruleset 被轉送規則二次處理） | 0        | grep -qE 'input\(type="imtcp"[^)]*ruleset="siemReceiver"\)' /etc/rsyslog.d/10-siem-receiver.conf; echo $? |

> C1/C2/C4/C5/C10 用**正邏輯 rc**（`; echo $?` 或原生 rc），不用反邏輯
> grep + 數字 expected；C5 用 `sh -c '... && echo 0 || echo 1'` 讓外層指令
> 恆回 rc=0，避免 ansible ad-hoc 把「沒監聽」的判定結果誤判成 task FAILED
> 而把 rc 吃成 2（見 `verification-spec-template.md` 陷阱 1）。
> C7/C8 用 `~contains` 而非 `^` 錨點，且用 `; true` 吸收 grep 找不到時的
> non-zero rc，避免 wrapper 把「訊息還沒落地」的合法 FAIL 結果變成不可判讀
> 的 ansible FAILED 輸出（陷阱 2）。
> C7/C8 只驗證**本機注入**（走 `/dev/log` 進同一個 rsyslog daemon 的規則引擎，
> `%HOSTNAME%` 會是 log-server 自己的 hostname）；驗證**跨主機**轉送有沒有真的
> 送到（client 端 `@@` 轉送 → 這台收到），屬於 Shape 3 cross-check，做法見
> `docs/runbooks/audit-log-forwarding.md` §4（在 client 端注入、在這台讀檔驗證）。
> **C11 的由來**：本 spec 原本假設「收到的訊息本來就只會被寫進 dynaFile，
> 不會再發生什麼事」，但沒考慮到本機同時也是 `audit-log-forwarding.md` 的
> client（這個拓樸的設計就是中央 SIEM 主機也要收集自己的稽核/認證日誌）。
> v1.2 以前，`imtcp` input 沒有綁定專屬 ruleset，落在跟
> `99-siem-forward.conf` 轉送規則相同的 default ruleset 裡——本機轉送給
> 自己的訊息，被 `imtcp` 收下後又重新進了同一個 default ruleset，再被同一條
> 轉送規則轉送出去，永遠迴圈下去。minimal-poc round 20（2026-08-07）實測：
> 3 台主機其中身兼兩角色的那台，`auth.log` 在不到一小時內長到 1.2 千萬行
> /13GB，把 77GB 的磁碟塞爆到 100%。v1.3 把 `imtcp` 的 receive 動作移進專屬
> `ruleset(name="siemReceiver")`，收到的訊息只會被寫進 dynaFile 一次，永遠
> 不會再進到 default ruleset 的轉送規則——C11 直接 grep 這個綁定關係。

## 3. 證據收集

- 工具：`go run ./cmd/pilot vm-target verify --name log-server docs/verification/log-server.md`
- 輸出格式：`.verification/log-server-<UTC>.{ndjson,md}`
- 預期 row 數：11（C1–C11）

## 4. PASS / FAIL 規則

- 全部 C1–C11 `status=pass` → **PASS**
- 任一 `status=fail` → **FAIL**，列出 fail id + actual + want

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| — | 防火牆（ufw/firewalld）開放 514/tcp 不在本 checklist 內：拋棄式 vm-target 預設無啟用防火牆，spec 只驗證 rsyslog 自身確實監聽（C5）；上真實主機且有啟用防火牆的站台，apply playbook 會在偵測到 `ufw`/`firewalld` 為 active 時才加規則（見 §6），但驗證責任落在該站台自己的防火牆 spec，不重複進本 spec | 有啟用防火牆的真實主機 | 視站台 |
| C7/C8 | 兩者皆為本機 selftest，不代表跨主機轉送已驗證（見上方 checklist 註記） | 所有環境 | 永久（設計如此，非暫時偏差） |

## 6. Playbook 對應

對應 apply playbook：`playbooks/apply/log-server-apply.yml`

| Spec ID | Apply task | 備註 |
|---------|------------|------|
| C1 | `install rsyslog` | apt/dnf 依 `ansible_os_family` |
| C2, C5 | `ensure rsyslog enabled+restarted` | 只在設定檔語法檢查通過後才重啟（`rsyslogd -N1` gate） |
| C3, C4, C7, C8, C11 | `template 10-siem-receiver.conf` | RainerScript：`imtcp` + `%HOSTNAME%` dynaFile 路由，`imtcp` 綁定 `ruleset="siemReceiver"` 避免自我轉送迴圈 |
| C6 | `create /var/log/siem` | `createDirs="on"` 讓 rsyslog 自動建每台來源主機的子目錄，這裡先建根目錄 |
| C9, C10 | `template /etc/logrotate.d/siem-incoming` | `rotate`/`maxage` 走 `siem_logrotate_*` 變數 |

## 7. SOP

```bash
# 1. 起 VM
go run ./cmd/pilot vm-target up --name log-server \
    --ssh-user ubuntu --disk 20 --memory 2048 --vcpus 2 \
    --ssh-timeout 8m --boot-timeout 8m

# 2. apply（無敏感變數，不需要 vault）
go run ./cmd/pilot vm-target run --name log-server \
    playbooks/apply/log-server-apply.yml -e target_group=all

# 3. verify
go run ./cmd/pilot vm-target verify --name log-server \
    docs/verification/log-server.md

# 4. 冪等檢查（重跑一次 apply，PLAY RECAP 應 changed=0）
go run ./cmd/pilot vm-target run --name log-server \
    playbooks/apply/log-server-apply.yml -e target_group=all
```

> vm-target 的 inventory 只有單一 host key（見 `vm-target-basics.md`），
> `pilot vm-target run/verify` 會自動加 `-l log-server`；本 spec §1 宣告的
> group `log-server`與該 host key 同名，不需要 `-e target_group=` override
> （不同於 freeipa-client/freeipa-server 用 `all` 的例外情形）。

## 8. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-06 | v1.0 | 初版：rsyslog 中央接收端，供 `audit-log-forwarding.md` client 轉送的目標 | sre |
| 2026-08-06 | v1.1 | 修真實 incident：6 台主機轉送到同時是 `wazuh-manager` 的主機（`siem-log-server` fallback 到 wazuh-manager），但該主機從未真正跑過 `log-server` 角色——舊版 apply playbook 有一個 `end_play` gate，只要 inventory 裡任何一台是 `wazuh-manager` 就整個跳過 log-server，理由是「避免 double-deployed syslog collectors」，但這個假設是錯的：官方 wazuh-docker compose 映射的 514/udp 從未接任何東西（`wazuh-manager.md` §5 早就記錄這件事）。移除該 gate；新增 `siem_receiver_udp_enabled`（同機是 wazuh-manager 時預設關閉 UDP，避開唯一真的會撞的埠），保留 TCP 514（`audit-log-forwarding.md` 實際轉送用的協定）一律開啟。新增 C4 對應的已知偏差列（§5；C6 實測不受影響，因為 Wazuh 自己的 compose 已經佔了 514/udp，通用監聽檢查依然回報有東西在聽） | sre |
| 2026-08-06 | v1.2 | 拿掉整條 UDP 支援（`imudp`、`siem_receiver_udp_port`、`siem_receiver_udp_enabled` 全部移除）：確認本 repo 沒有任何角色轉送 UDP syslog，v1.1 留著的條件式 UDP 只是沒人用的推測性容量，直接拿掉比繼續維護「同機是 wazuh-manager 時關閉」的條件邏輯更簡單。Checklist 從 12 條收斂成 10 條（移除舊 C4「imudp module」與 C6「UDP 514 監聽」，其餘全部往前遞補：舊 C5→新 C4、舊 C7→新 C5、舊 C8→新 C6、舊 C9→新 C7、舊 C10→新 C8、舊 C11→新 C9、舊 C12→新 C10）；v1.1 新增的 C4 已知偏差列連同 UDP 一起移除，因為已經沒有 UDP 分支會 fail | sre |
| 2026-08-07 | v1.3 | 新增 C11：`imtcp` input 綁定專屬 `ruleset="siemReceiver"`。real incident（minimal-poc round 20）：這個拓樸的中央 SIEM 主機同時也是 `audit-log-forwarding.md` 的 client，轉送給自己時，`imtcp` 收到的訊息若落回 default ruleset 會被 `99-siem-forward.conf` 的轉送規則二次處理、再度轉送出去，形成無窮迴圈——3 台主機中身兼兩角色的那台，`auth.log` 在不到一小時內長到 1.2 千萬行/13GB，把 77GB 磁碟塞到 100% 滿。修法：把接收動作移進專屬 ruleset，收到的訊息只寫一次 dynaFile，不再進 default ruleset | sre |
