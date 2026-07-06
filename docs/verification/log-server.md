# Verification Spec — log-server（rsyslog 中央日誌接收端 / SIEM forward 目標）

> 版本：v1.0
> 對齊規範：pilot 通用 config-only 服務規範（比照 `pam-oidc-sshd.md` 的
> block/rescue + tags 模式）；為 `audit-log-forwarding.md`（client 端 auditd +
> rsyslog 轉送）提供中央接收端，兩份 spec 搭配構成一組 Shape 3（server+client）。
> 維護者：sre

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Hostname / Inventory group | log-server |
| OS / version | Ubuntu 24.04 LTS（rsyslog 8.2312+，內建 RainerScript / imudp / imtcp） |
| 角色 | 中央 syslog 接收端：收 client 端 rsyslog 轉送的 `auth,authpriv.*` 與 `local6.*`（auditd），依來源 hostname 分檔落地 |
| 套用範圍 | `/etc/rsyslog.d/10-siem-receiver.conf`、`/etc/logrotate.d/siem-incoming`、`/var/log/siem/` |
| 風險等級 | Medium（對外開 514/udp+tcp 收網路日誌；設定錯誤頂多漏收，不影響本機既有日誌） |

> 為何選 rsyslog 而非 Loki/syslog-ng：client 端轉送已固定用 rsyslog 協定
> （`@@host:514`），中央端用同一套軟體收沒有協定/格式落差風險，且 Ubuntu/EL9
> 都預裝，符合本 repo「單一 systemd service + 檔案」的 spec 模式（比照
> `seaweedfs-s3.md`）。查詢/dashboard 需求可日後在此之上疊 Promtail→Loki，
> 不影響本 spec。

## 1.5 依賴變數契約

在套用或驗證此主機時，Playbook 與變數參數必須嚴格遵守以下命名，禁止擅自縮寫或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 | 預設值 |
|---------|----------|---------|--------|
| `siem_receiver_udp_port` | rsyslog `imudp` 監聽埠 | 否 | `514` |
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
| C4  | config    | 設定檔含 `imudp` module + input                                       | 0        | grep -qE 'module\(load="imudp"\)' /etc/rsyslog.d/10-siem-receiver.conf; echo $? |
| C5  | config    | 設定檔含 `imtcp` module + input                                       | 0        | grep -qE 'module\(load="imtcp"\)' /etc/rsyslog.d/10-siem-receiver.conf; echo $? |
| C6  | network   | UDP 514 確實在監聽                                                    | 0        | sh -c 'ss -lnu | grep -q ":514" && echo 0 || echo 1' |
| C7  | network   | TCP 514 確實在監聽                                                    | 0        | sh -c 'ss -lnt | grep -q ":514" && echo 0 || echo 1' |
| C8  | dir       | 落地根目錄 `/var/log/siem` 存在                                       | present  | test -d /var/log/siem |
| C9  | functional| 本機注入 `local6` 測試訊息，依 `%HOSTNAME%` 落地到 `audit.log`         | ~PILOT-SIEM-SELFTEST-AUDIT | sh -c 'logger -p local6.info "PILOT-SIEM-SELFTEST-AUDIT"; sleep 1; grep -r "PILOT-SIEM-SELFTEST-AUDIT" /var/log/siem/*/audit.log 2>/dev/null; true' |
| C10 | functional| 本機注入 `authpriv` 測試訊息，依 `%HOSTNAME%` 落地到 `auth.log`        | ~PILOT-SIEM-SELFTEST-AUTH | sh -c 'logger -p authpriv.info "PILOT-SIEM-SELFTEST-AUTH"; sleep 1; grep -r "PILOT-SIEM-SELFTEST-AUTH" /var/log/siem/*/auth.log 2>/dev/null; true' |
| C11 | file      | logrotate 策略檔存在                                                  | present  | test -f /etc/logrotate.d/siem-incoming |
| C12 | logrotate | logrotate 策略檔語法正確（dry-run 不出錯）                            | 0        | logrotate -d /etc/logrotate.d/siem-incoming >/dev/null 2>&1; echo $? |

> C1/C2/C4/C5/C6/C7/C12 用**正邏輯 rc**（`; echo $?` 或原生 rc），不用反邏輯
> grep + 數字 expected；C6/C7 用 `sh -c '... && echo 0 || echo 1'` 讓外層指令
> 恆回 rc=0，避免 ansible ad-hoc 把「沒監聽」的判定結果誤判成 task FAILED
> 而把 rc 吃成 2（見 `verification-spec-template.md` 陷阱 1）。
> C9/C10 用 `~contains` 而非 `^` 錨點，且用 `; true` 吸收 grep 找不到時的
> non-zero rc，避免 wrapper 把「訊息還沒落地」的合法 FAIL 結果變成不可判讀
> 的 ansible FAILED 輸出（陷阱 2）。
> C9/C10 只驗證**本機注入**（走 `/dev/log` 進同一個 rsyslog daemon 的規則引擎，
> `%HOSTNAME%` 會是 log-server 自己的 hostname）；驗證**跨主機**轉送有沒有真的
> 送到（client 端 `@@` 轉送 → 這台收到），屬於 Shape 3 cross-check，做法見
> `docs/runbooks/audit-log-forwarding.md` §4（在 client 端注入、在這台讀檔驗證）。

## 3. 證據收集

- 工具：`go run ./cmd/pilot vm-target verify --name log-server docs/verification/log-server.md`
- 輸出格式：`.verification/log-server-<UTC>.{ndjson,md}`
- 預期 row 數：12（C1–C12）

## 4. PASS / FAIL 規則

- 全部 C1–C12 `status=pass` → **PASS**
- 任一 `status=fail` → **FAIL**，列出 fail id + actual + want

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| — | 防火牆（ufw/firewalld）開放 514/udp+tcp 不在本 checklist 內：拋棄式 vm-target 預設無啟用防火牆，spec 只驗證 rsyslog 自身確實監聽（C6/C7）；上真實主機且有啟用防火牆的站台，apply playbook 會在偵測到 `ufw`/`firewalld` 為 active 時才加規則（見 §6），但驗證責任落在該站台自己的防火牆 spec，不重複進本 spec | 有啟用防火牆的真實主機 | 視站台 |
| C9/C10 | 兩者皆為本機 selftest，不代表跨主機轉送已驗證（見上方 checklist 註記） | 所有環境 | 永久（設計如此，非暫時偏差） |

## 6. Playbook 對應

對應 apply playbook：`playbooks/apply/log-server-apply.yml`

| Spec ID | Apply task | 備註 |
|---------|------------|------|
| C1 | `install rsyslog` | apt/dnf 依 `ansible_os_family` |
| C2, C6, C7 | `ensure rsyslog enabled+restarted` | 只在設定檔語法檢查通過後才重啟（`rsyslogd -N1` gate） |
| C3, C4, C5, C9, C10 | `template 10-siem-receiver.conf` | RainerScript：`imudp`/`imtcp` + `%HOSTNAME%` dynaFile 路由 |
| C8 | `create /var/log/siem` | `createDirs="on"` 讓 rsyslog 自動建每台來源主機的子目錄，這裡先建根目錄 |
| C11, C12 | `template /etc/logrotate.d/siem-incoming` | `rotate`/`maxage` 走 `siem_logrotate_*` 變數 |

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
