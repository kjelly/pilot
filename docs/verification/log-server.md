# Verification Spec — log-server（rsyslog 中央日誌接收端 / SIEM forward 目標）

> 版本：v1.9
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
| 套用範圍 | `/etc/rsyslog.d/10-siem-receiver.conf`、`/etc/logrotate.d/siem-incoming`、`siem_log_root`（預設 `/var/log/siem/`）；`siem_log_root` 不在 `/var/log` 底下時，另外寫 `/etc/apparmor.d/local/usr.sbin.rsyslogd` 的 pilot 區塊並重新載入 rsyslogd 的 AppArmor profile（Ubuntu），或加 `var_log_t` 的 SELinux file-context 規則並 `restorecon`（EL）。換根目錄時，AppArmor 區塊在 rsyslog 重啟前同時保留舊根目錄與新根目錄的規則；等 rsyslog 以新的接收設定啟動、rsyslogd 在接收 port 監聽之後，才拿掉舊根目錄的規則。舊根目錄的 SELinux 規則刻意保留，不會移除。apply 失敗時 rescue 把兩個 drop-in 還原成這次 run 之前的內容、移除這次加的 file-context 規則，再用 `rsyslogd -N1` 檢查還原後的設定，通過才重啟 rsyslog（不通過時，例如失敗原因是別的 drop-in，就不重啟，讓正在跑的 rsyslog 維持原狀）。AppArmor local 檔在 rescue 中先同時授權這次 run 之前與這次 run 的規則；rsyslog 跑的是舊規則涵蓋的設定（rescue 重啟了它，或這次 run 沒有重啟過它）時，才還原成這次 run 之前的內容，否則保留兩者。根目錄與 SELinux port 標籤留著 |
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
| C5  | network   | 接收設定裡 `imtcp` 的 TCP port（`siem_receiver_tcp_port`，預設 514）確實在監聽 | 0        | sh -c 'p=$(grep -o "imtcp\" port=\"[0-9]*" /etc/rsyslog.d/10-siem-receiver.conf 2>/dev/null | grep -o "[0-9]*$"); [ -n "$p" ] && ss -Hlnt "( sport = :$p )" | grep -q . && echo 0 || echo 1' |
| C6  | dir       | 接收設定裡 `SiemAuditPath` 的落地根目錄（`siem_log_root`，預設 `/var/log/siem`）存在 | 0        | sh -c 'r=$(sed -n "s#.*\"SiemAuditPath\".*string=\"\(/[^\"]*\)/%HOSTNAME%/audit\.log\".*#\1#p" /etc/rsyslog.d/10-siem-receiver.conf 2>/dev/null); [ -n "$r" ] && [ -d "$r" ] && echo 0 || echo 1' |
| C7  | functional| 本機注入這次唯一的 `local6` 測試訊息，6 秒內依 `%HOSTNAME%` 落地到接收設定那個根目錄下的 `audit.log` | 0        | sh -c 'r=$(sed -n "s#.*\"SiemAuditPath\".*string=\"\(/[^\"]*\)/%HOSTNAME%/audit\.log\".*#\1#p" /etc/rsyslog.d/10-siem-receiver.conf 2>/dev/null); [ -n "$r" ] || { echo 1; exit 0; }; n="PILOT-SIEM-SELFTEST-AUDIT-$$-$(date +%s%N)"; logger -p local6.info "$n"; i=0; while [ $i -lt 6 ]; do grep -qsF "$n" "$r"/*/audit.log && { echo 0; exit 0; }; sleep 1; i=$((i+1)); done; echo 1' |
| C8  | functional| 本機注入這次唯一的 `authpriv` 測試訊息，6 秒內依 `%HOSTNAME%` 落地到接收設定那個根目錄下的 `auth.log` | 0        | sh -c 'r=$(sed -n "s#.*\"SiemAuditPath\".*string=\"\(/[^\"]*\)/%HOSTNAME%/audit\.log\".*#\1#p" /etc/rsyslog.d/10-siem-receiver.conf 2>/dev/null); [ -n "$r" ] || { echo 1; exit 0; }; n="PILOT-SIEM-SELFTEST-AUTH-$$-$(date +%s%N)"; logger -p authpriv.info "$n"; i=0; while [ $i -lt 6 ]; do grep -qsF "$n" "$r"/*/auth.log && { echo 0; exit 0; }; sleep 1; i=$((i+1)); done; echo 1' |
| C9  | file      | logrotate 策略檔存在                                                  | present  | test -f /etc/logrotate.d/siem-incoming |
| C10 | logrotate | logrotate 策略檔語法正確（dry-run 不出錯）                            | 0        | logrotate -d /etc/logrotate.d/siem-incoming >/dev/null 2>&1; echo $? |
| C11 | config    | `imtcp` input 綁定專屬 ruleset（不會落回 default ruleset 被轉送規則二次處理） | 0        | grep -qE 'input\(type="imtcp"[^)]*ruleset="siemReceiver"\)' /etc/rsyslog.d/10-siem-receiver.conf; echo $? |

> C1/C2/C4/C5/C10 用**正邏輯 rc**（`; echo $?` 或原生 rc），不用反邏輯
> grep + 數字 expected；C5 用 `sh -c '... && echo 0 || echo 1'` 讓外層指令
> 恆回 rc=0，避免 ansible ad-hoc 把「沒監聽」的判定結果誤判成 task FAILED
> 而把 rc 吃成 2（見 `verification-spec-template.md` 陷阱 1）。
> C6–C8 從 `10-siem-receiver.conf` 的 `SiemAuditPath` 讀出實際生效的落地根目錄
> （`siem_log_root`），不寫死 `/var/log/siem`。C7/C8 每次送出唯一的 nonce 訊息（`$$` 加
> `date +%s%N`），最多等 6 秒，只認這一則（`grep -qsF "$n"`），用 `sh -c '… echo 0 … echo 1'`
> 讓外層恆回 rc=0、expected `0`：先前留在任何目錄裡的舊 selftest 字串都不會讓它們 PASS。
> C7/C8 只驗證**本機注入**：訊息走 `/dev/log` 進 default ruleset，由同機的
> `audit-log-forwarding` 轉送規則以 TCP 送回本機的 `imtcp`，再由 `siemReceiver` 依
> `%HOSTNAME%`（log-server 自己的 hostname）落地，所以需要同機也部署 `audit-log-forwarding`
> （本專案的 topology 一律如此，見 C11 的由來）；驗證**跨主機**轉送有沒有真的
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
| C2, C5 | `ensure rsyslog enabled+restarted` | 只在設定檔語法檢查通過後才重啟（`rsyslogd -N1` gate）；rsyslog 啟動時間早於接收設定最後寫入的時間（上一次 run 中斷，或 rescue 還原設定卻無法重啟）時也重啟 |
| C2, C5 | `Step 7: rsyslog runs the receiver config and listens on its port` | 重啟後 rsyslog 必須在跑、接收 port 由 rsyslogd 監聽，否則 apply 失敗 |
| C3, C4, C7, C8, C11 | `template 10-siem-receiver.conf` | RainerScript：`imtcp` + `%HOSTNAME%` dynaFile 路由，`imtcp` 綁定 `ruleset="siemReceiver"` 避免自我轉送迴圈 |
| C6 | `create siem_log_root`（預設 `/var/log/siem`） | `createDirs="on"` 讓 rsyslog 自動建每台來源主機的子目錄，這裡先建根目錄 |
| C6, C7, C8 | `let a confined rsyslogd write siem_log_root`（Step 2a，`tasks/rsyslog-confined-log-root.yml`，phase `grant`） | 根目錄不在 `/var/log` 底下時：AppArmor local 規則（保留區塊裡現有的規則）+ 依已載入 profile 的 sha256 判斷要不要重新載入；SELinux `var_log_t` 規則，看目錄實際的 type 決定要不要 `restorecon` |
| C6, C7, C8 | `drop the AppArmor rules for roots rsyslog no longer writes`（Step 7a，同一個 task 檔，phase `narrow`） | 只在 Step 7 的檢查此刻成立時執行：區塊只留新根目錄的規則（`/var/log` 底下則整段移除），有變才重新載入 |
| C9, C10 | `template /etc/logrotate.d/siem-incoming` | `rotate`/`maxage` 走 `siem_logrotate_*` 變數 |

> playbook 的每個 task 都帶全部 row tag（C1–C11）：這些步驟共用根目錄、port 與接收設定，只跑其中幾步會讓改過的 `siem_log_root` 只套用一半（例如 `--tags C6` 把 AppArmor 規則換成新目錄，rsyslog 卻還寫舊目錄）。上表是每列驗的是哪一步，不是 `--tags` 只跑哪一步。
>
> 反過來，`--skip-tags` 任一列（例如 `--skip-tags C9`）會跳過整個 log-server 的步驟，只剩 `always` 的 gate 與 snapshot。

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
| 2026-10-14 | v1.4 | C5 改成讀接收設定裡 `imtcp` 的 port 再檢查它在監聽，不再寫死 514。PR #79 讓 inventory 的 `siem_receiver_tcp_port` 生效後，`siem_receiver_tcp_port: 2514` 的 log-server 在 2514 監聽、client 的訊息也送達，舊 C5（`grep ":514"`）卻 FAIL；新 C5 在 2514 PASS，rsyslog 停掉時 FAIL（2026-10-14 對 pr79-log 實測）。也修掉舊寫法 `:514` 會被 `:5140` 這類 port 誤判成 PASS 的問題 | pilot |
| 2026-10-15 | v1.5 | C6–C8 改成從接收設定的 `SiemAuditPath` 讀出實際生效的 `siem_log_root`，不再寫死 `/var/log/siem`；C7/C8 改送這次唯一的 nonce 訊息（`PILOT-SIEM-SELFTEST-<AUDIT|AUTH>-$$-$(date +%s%N)`），只認這則訊息，最多等 6 秒，改用 rc 形式（expected `0`）。起因：PR #79 讓 inventory 的 `siem_log_root` 生效後，非預設根目錄的主機 C6–C8 會 FAIL，而預設目錄留有舊的固定字串時 C7/C8 會假 PASS（PR #79 review） | pilot |
| 2026-10-15 | v1.6 | 只改說明，row 不變：§1 套用範圍補上 Step 2a 對 AppArmor local 檔、SELinux file-context 規則的修改與 rescue 會還原什麼；§6 補上 Step 2a 一列，並說明 playbook 每個 task 都帶全部 row tag（PR #79 review：`--tags C6` 改 `siem_log_root` 時只換了 AppArmor 規則，rsyslog 仍寫舊目錄，訊息全部丟失） | pilot |
| 2026-10-15 | v1.7 | 只改說明，row 不變：§6 的說明移到表格下面（原本插在表格中間，C9/C10 那列因此沒有算在表格裡），並註明 `--skip-tags` 任一列會跳過整個 log-server 的步驟。§1 的 rescue 說明補上：rescue 先用 `rsyslogd -N1` 檢查還原後的設定，通過才重啟 rsyslog | pilot |
| 2026-10-15 | v1.8 | 只改說明，row 不變：v1.7 拿掉 §6 表格中間的說明時留下一個空行，C9/C10 那列仍然沒有算在表格裡（GitHub 把它顯示成表格後的一段文字）；拿掉這個空行 | pilot |
| 2026-10-16 | v1.9 | 只改說明，row 不變：§1、§6 補上換根目錄時 AppArmor 規則的兩階段處理（重啟前保留舊根目錄的規則，Step 7 確認 rsyslog 以新設定在監聽後才拿掉）、Step 6a 對啟動時間早於設定檔的 rsyslog 也重啟，以及 rescue 對 AppArmor local 檔的處理。起因：Step 2a 重新載入只含新根目錄的 profile 後、rsyslog 重啟前，正在跑的 rsyslogd 不能寫舊根目錄，訊息遺失（PR #79，2026-10-16 在 pr79-log 實測） | pilot |
