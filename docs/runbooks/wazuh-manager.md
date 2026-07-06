# Runbook — wazuh-manager（Wazuh all-in-one：manager + indexer + dashboard，CVE 掃描，選填轉送 SIEM）

> 撰寫日期：2026-07-06 (UTC)
> 對齊：`docs/verification/wazuh-manager.md`（v1.0）、`playbooks/apply/wazuh-manager-apply.yml`
> 維護者：sre

---

## 0. 目標與範圍

在一台獨立的 Ubuntu 24.04 vm-target 上部署 **Wazuh all-in-one**（manager +
indexer + dashboard 同一台主機，官方 `wazuh-install.sh -a` 組裝腳本）：
接收 `wazuh-fim.md` agent 送來的 FIM(syscheck)/who-data 事件、跑規則引擎
產生告警、跑 CVE 弱點掃描（vulnerability-detection，需要 indexer 儲存/關聯
結果），選填把告警轉送至中央 SIEM（`docs/verification/log-server.md`）。

本 runbook 是 `docs/verification/wazuh-fim.md`（agent 端）的前置依賴——agent
端註冊的目標就是這台。

---

## 1. §0.5 事實快照（AGENTS.md §2）

```
$ go run ./cmd/pilot vm-target list
wazuh-manager  running  192.168.122.5  4  8192  60  2026-07-06

$ go run ./cmd/pilot vm-target show-inventory --name wazuh-manager
all:
  hosts:
    wazuh-manager:
      ansible_connection: ssh
      ansible_host: 192.168.122.5
      ansible_user: ubuntu
      ...
```

**規格對齊**：vm-target 的 inventory 只有單一 host key，playbook
`hosts: "{{ target_group | default('wazuh-manager') }}"` 直接命中，不需要
`-e target_group=` override（同 `log-server.md` 的設計）。

無 vault 依賴——本 spec 唯一的機密（indexer/dashboard/API 管理者密碼）是官方
安裝腳本**隨機產生**、留在目標主機本地的 `/root/wazuh-install-files.tar`，
不經過 ansible-vault、也不會被 playbook 搬離目標主機（見 §5.2）。

---

## 2. 部署（apply）

### 2.1 首次 apply（不轉送，log server 尚未存在）

```bash
go run ./cmd/pilot vm-target up --name wazuh-manager \
    --ssh-user ubuntu --disk 60 --memory 8192 --vcpus 4 \
    --ssh-timeout 8m --boot-timeout 8m

go run ./cmd/pilot vm-target run --name wazuh-manager \
    playbooks/apply/wazuh-manager-apply.yml
```

**真實輸出**（2026-07-06，全新 60GB/8192MB/4vCPU VM 首次 apply；官方安裝腳本
本身跑了幾分鐘，playbook 用 `async: 1800 poll: 20` 等待）：

```
TASK [Step 0: Report whether SIEM forwarding is enabled this run] **************
ok: [wazuh-manager] => {
    "msg": "siem_forward_host not provided — skipping /etc/hosts pin and <syslog_output>; only local alerting + CVE scanning (C1-C9) will be configured. ..."
}
TASK [Step 2: Download the official wazuh-install.sh assistant (spec C1, C2)] ***
changed: [wazuh-manager]
TASK [Step 3: Run wazuh-install.sh -a -i (all-in-one: manager+indexer+dashboard; spec C1, C2)] ***
ASYNC POLL on wazuh-manager: jid=j862792701954.1423 started=True finished=False
   (... 11 poll cycles ...)
ASYNC OK on wazuh-manager: jid=j862792701954.1423
changed: [wazuh-manager]
TASK [Step 4: Ensure wazuh-manager enabled+started (spec C3)] ******************
ok: [wazuh-manager]
TASK [Step 5: Ensure wazuh-indexer enabled+started (spec C4)] ******************
ok: [wazuh-manager]
TASK [Step 6: Pin siem-log-server ->  in /etc/hosts (spec C10)] ****************
skipping: [wazuh-manager]
TASK [Step 7: Append <syslog_output> block to ossec.conf (spec C11)] ***********
skipping: [wazuh-manager]
TASK [Step 8: Restart wazuh-manager only if the forward config actually changed] ***
skipping: [wazuh-manager]
PLAY RECAP *********************************************************************
wazuh-manager              : ok=8    changed=2    unreachable=0    failed=0    skipped=3    rescued=0    ignored=0
```

### 2.2 補上轉送（log server 就緒後）

```bash
go run ./cmd/pilot vm-target run --name wazuh-manager \
    playbooks/apply/wazuh-manager-apply.yml \
    -e siem_forward_host=192.168.122.8
```

**真實輸出**（同一台已裝好的 manager，第二次 apply 補轉送）：

```
TASK [Step 2: Download the official wazuh-install.sh assistant (spec C1, C2)] ***
skipping: [wazuh-manager]
TASK [Step 3: Run wazuh-install.sh -a -i (all-in-one: manager+indexer+dashboard; spec C1, C2)] ***
skipping: [wazuh-manager]
TASK [Step 6: Pin siem-log-server -> 192.168.122.8 in /etc/hosts (spec C10)] ***
changed: [wazuh-manager]
TASK [Step 7: Append <syslog_output> block to ossec.conf (spec C11)] ***********
changed: [wazuh-manager]
TASK [Step 8: Restart wazuh-manager only if the forward config actually changed] ***
changed: [wazuh-manager]
PLAY RECAP *********************************************************************
wazuh-manager              : ok=8    changed=3    unreachable=0    failed=0    skipped=2    rescued=0    ignored=0
```

確認官方安裝步驟（Step 2/3）確實被跳過（不重跑一次全套安裝腳本），只做
新增的轉送設定——這是 apply playbook 冪等性設計的核心：安裝步驟只在
`dpkg-query wazuh-manager` 偵測到尚未安裝時才跑一次。

---

## 3. 驗證（spec C1–C11）

```bash
go run ./cmd/pilot vm-target verify --name wazuh-manager \
    docs/verification/wazuh-manager.md
```

**真實輸出 — §2.1 之後（未轉送，預期 C10/C11 fail）**：

```json
{"id":"C1","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C2","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C3","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C4","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C5","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C6","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C7","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C8","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C9","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C10","status":"fail","detail":"rc-from-stdout=2, expected 0"}
{"id":"C11","status":"fail","detail":"rc-from-stdout=1, expected 0"}
```

`verdict: FAIL (pass=9 fail=2 skip=0)` — 這是**預期行為**（spec §5），只看
C1–C9 是否全 pass。

**真實輸出 — §2.2 之後（轉送啟用，全部 11 條）**：

```json
{"id":"C1","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C2","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C3","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C4","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C5","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C6","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C7","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C8","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C9","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C10","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C11","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
```

`verdict: PASS (pass=11 fail=0 skip=0)`。全部 rows 都是 `rc-from-stdout=`
（不是回退到 ansible 進程自己的 exit code），代表這是真正被 matcher 檢驗過
的 PASS，不是巧合（見 `audit-log-forwarding.md` runbook §5.3 的 matcher bug
教訓——本 spec 是在那個 bug 已經修好之後才寫的，一開始就用正確的 matcher）。

**冪等驗證**（§2.2 之後同指令再跑一次 apply，PLAY RECAP）：

```
wazuh-manager              : ok=7    changed=0    unreachable=0    failed=0    skipped=3    rescued=0    ignored=0
```

---

## 4. 跨主機 cross-check（完整鏈路：agent FIM 變更 → manager 告警含 who-data → 轉送到 log-server）

這是本功能真正的價值主張，spec 本身不驗證（見 `wazuh-manager.md` §2 註記），
必須在三台主機間實測：

```bash
# 1. 在 agent（wazuh-fim）端觸發一筆真實的檔案異動
go run ./cmd/pilot vm-target exec --name wazuh-fim -- \
    sudo sh -c 'echo "# PILOT-WAZUH-CHAIN-TEST $(date)" >> /etc/pilot-fim-chaintest.conf'
sleep 12

# 2. 在 manager 端確認告警含完整 who-data（誰、透過什麼程序改的）
go run ./cmd/pilot vm-target exec --name wazuh-manager -- \
    sudo grep "pilot-fim-chaintest" /var/ossec/logs/alerts/alerts.json

# 3. 在 log-server 端確認告警被轉送落地
go run ./cmd/pilot vm-target exec --name log-server -- \
    sudo grep "pilot-fim-chaintest" /var/log/syslog
```

**真實輸出（2026-07-06T07:15:52Z）— manager 端告警**（節錄關鍵欄位）：

```json
{"rule":{"level":5,"description":"File added to the system.","id":"554"},
 "agent":{"id":"001","name":"wazuh-fim","ip":"192.168.122.6"},
 "full_log":"File '/etc/pilot-fim-chaintest.conf' added\nMode: whodata\n",
 "syscheck":{"path":"/etc/pilot-fim-chaintest.conf","mode":"whodata","event":"added",
   "audit":{
     "user":{"id":"0","name":"root"},
     "process":{"id":"6126","name":"/usr/bin/dash","parent_name":"/usr/bin/sudo","ppid":"6125"},
     "login_user":{"id":"1000","name":"ubuntu"},
     "effective_user":{"id":"0","name":"root"}
   }}}
```

`syscheck.audit` 就是「進階未授權行為追蹤」的完整證據：**`login_user`
是真正登入的人（`ubuntu`）、`effective_user` 是實際生效的身分（`root`，
透過 sudo）、`process` 是實際執行變更的程序鏈（`sudo` → `dash`）**——這是
單純 auditd+rsyslog 轉送原始日誌（`audit-log-forwarding.md`）做不到的層次：
FIM 事件跟稽核事件在同一筆告警裡被關聯起來。

**真實輸出 — log-server 端**（同一筆告警，透過 `<syslog_output>` 轉送過來）：

```
2026-07-06T07:15:52+00:00 wazuh-manager ossec: Alert Level: 5; Rule: 554 - File added to the system.; Location: (wazuh-fim) any->syscheck; classification: ossec,syscheck,syscheck_entry_added,syscheck_file,...; File '/etc/pilot-fim-chaintest.conf' added
```

**這一筆落地在 log-server 的 `/var/log/syslog`（一般預設檔），不是
`audit-log-forwarding.md` 專用的 `/var/log/siem/<host>/` 分檔目錄**——
見 §5.1 的說明與設計取捨。

---

## 5. 踩過的雷（實測 vm-target 時發現）

### 5.1 Wazuh 告警走 `<syslog_output>` 轉送時，落地在 log-server 的一般 `/var/log/syslog`，不是 `/var/log/siem/` 分檔目錄

一開始以為轉送過去的 Wazuh 告警會跟 `audit-log-forwarding.md` 的
`local6.*`/`auth,authpriv.*` 一樣，落進 `log-server-apply.yml` 為那份 spec
特別佈的 `/var/log/siem/<hostname>/{audit,auth}.log`。實測發現不是——注入
測試訊息後 `/var/log/siem/` 底下完全沒有新內容，反而在 log-server 的
`/var/log/syslog`（rsyslog 出廠預設的萬用落地檔）找到。

**根因**：`wazuh-csyslogd` 送出的 syslog 訊息用的 facility **不是**
`local6`（`audit-log-forwarding.md` 特別佈線的那個），落進 log-server 端
rsyslog 出廠預設的萬用規則（`*.*;auth,authpriv.none -/var/log/syslog`）。
`log-server.md` 目前只為 `local6`/`auth,authpriv` 兩個 facility 佈了專屬
落地路由，沒有涵蓋 Wazuh 用的 facility。

**取捨（沒有改 `log-server.md`/`log-server-apply.yml`）**：本 spec 的需求是
「log 拋轉至 SIEM」，訊息確實送達 log-server 主機這件事已經達成（§4 的
cross-check 就是證據）；只是沒有跟 auditd 轉送共用同一套分類落地目錄結構。
沒有回頭改 `log-server.md`（一份已經完成、測試過、有自己版本紀錄的獨立
spec）新增第三個 facility 路由，是刻意的範圍控制——那會是 `log-server.md`
自己的 v1.1（新增一個 facility → 落地路徑的規則），如果之後要統一收斂
Wazuh 告警到跟 auditd 一樣的目錄結構，應該在那份 spec 上做，不是在這裡
夾帶。目前的設計：Wazuh 告警在 log-server 找 `/var/log/syslog`，auditd
原始日誌在 `/var/log/siem/<host>/`，兩條路徑分開。

### 5.2 CVE 弱點掃描把磁碟塞爆，且完全沒有服務層級的失敗徵兆——所有告警（含 FIM）因此靜默停產

第一次實測用了跟 `log-server`/`audit-log-forwarding` 一樣的規格
（20GB/2048MB/2vCPU），`wazuh-install.sh -a` 跑完看起來一切正常
（`systemctl is-active wazuh-manager` 顯示 `active`），但觸發一筆 FIM
測試變更後，**manager 端的 `alerts.json` 完全沒有任何新紀錄**——連最基本
的 FIM 告警都沒有，而不只是 CVE 掃描壞掉。

**除錯過程**：`sudo tail -n 40 /var/ossec/logs/ossec.log` 才看到問題：

```
2026/07/06 06:43:57 wazuh-db: ERROR: SQLite: database or disk is full
2026/07/06 06:43:57 wazuh-analysisd: ERROR: dbsync: Bad response from database: Cannot save Syscollector
2026/07/06 06:43:57 wazuh-analysisd: ERROR: dbsync: Bad response from database: Cannot save Syscheck
```

`df -h /` 確認：`/dev/vda1  19G  19G  0  100%  /`。追下去發現
`/var/ossec/queue/vd`（CVE feed 常駐目錄）加上 `/var/ossec/tmp` 底下一個
解壓中的暫存 tar 檔（`vd_1.0.0_vd_4.13.0.tar`，單一檔案就 **8.4GB**），
兩者合計把 20GB 磁碟吃到只剩個位數 MB。

**這個事故最危險的地方不是「壞了」，是「壞得沒有徵兆」**：`wazuh-manager`
的 systemd 狀態全程顯示 `active`，沒有崩潰、沒有非零結束碼、`vm-target
verify` 若剛好只測服務是否 active 完全測不出來——只有告警安靜地生不出來。

**修法**：不是關掉 CVE 功能（這是這個 spec 的核心需求之一），而是把資源
規劃拉到官方文件的建議值：**60GB 磁碟 / 8192MB 記憶體 / 4 vCPU**（見 spec
§1）。這也是為何本 spec 的 vm-target SOP **不能沿用**其他 spec 慣用的
20GB/2048MB 規格——這是實測撞出來的真事故，不是紙上談兵的保守估計。C8
（磁碟可用空間 ≥5GB）這條 checklist 就是從這次事故直接生出來的。

### 5.3 官方 all-in-one 腳本比手刻裝 indexer+manager+CVE 連線可靠得多

一開始評估過手動裝 `wazuh-manager`（apt）+ 手動裝 `wazuh-indexer` + 手動
產生憑證（root CA、indexer 憑證、filebeat 憑證）+ 手動接上 `<indexer>` 連線
設定的做法，但 Wazuh 4.8+ 的 CVE 掃描（`vulnerability-detection`）架構上
**依賴 indexer 才能真正存/查掃描結果**，憑證鏈只要有一步做錯就整條斷掉，
且沒有官方文件逐項核對每個憑證欄位的正確值。改用官方
`curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh && sudo bash
wazuh-install.sh -a -i` 後，實測**一次就裝好全部（indexer/manager/
dashboard/filebeat 皆 active，CVE 掃描器啟動、憑證鏈全對）**，沒有再踩到
任何憑證相關的坑。这不是「偷懶」，是「官方已經驗證過的路徑」對「自己重新
發明且沒有回頭路的憑證鏈」之間的風險取捨，詳見 spec §1 的完整理由。

### 5.4 Wazuh 的 `ossec.conf` 允許同一份檔案有多個 `<ossec_config>` 根節點，而且對同一路徑重複宣告的模組選項是聯集而非覆蓋

一開始擔心「新增自己的 `<syslog_output>` 區塊」或 `wazuh-fim-apply.yml`
「新增自己的 `<syscheck>` 區塊」會不會跟套件出廠的預設設定衝突（尤其
`/etc`、`/boot` 這兩個路徑套件出廠的 `<syscheck>` 本來就已經監控了，只是
沒有 `whodata`）。實測前特地 `cat` 套件裝完的預設 `ossec.conf`，發現**套件
自己的出廠設定就是分成兩段 `<ossec_config>...</ossec_config>` 根節點**
（第二段是給 journald/dpkg.log 的 `<localfile>`）——這代表 Wazuh 的 XML
parser 本來就設計成允許、並合併多個根節點,不是我們發明的技巧。

實際套用 `wazuh-fim-apply.yml` 後，`ossec.log` 顯示：

```
wazuh-syscheckd: INFO: (6003): Monitoring path: '/etc', with options 'size | ... | whodata'.
wazuh-syscheckd: INFO: (6003): Monitoring path: '/bin', with options 'size | ... | scheduled'.
```

確認 `/etc`（我們額外宣告過 whodata）拿到的是**聯集後**的完整選項（含
`whodata`），而沒有额外宣告的 `/bin` 維持原本的 `scheduled`——兩段宣告
correctly 合併，不是互相覆蓋或衝突。這讓 apply playbook 可以用純附加
（append-only）的方式管理設定，完全不用碰、不用理解套件出廠設定裡其餘幾百
行預設值，風險面小很多（等同 `log-server-apply.yml`/`audit-log-forwarding-
apply.yml` 一貫的「只管自己新增的檔案/區塊」原則）。

### 5.5 `wazuh-logtest` 的功能性自證：測試訊息格式與斷言字串都要對，光讀文件猜不出來

C9 這條「規則引擎自證」原本的草稿有兩個問題，都是先跑過一次
`wazuh-logtest` 才發現：

1. 灌入的測試訊息如果只有裸的 `"Failed password for invalid user test from
   10.0.0.9 port 12345 ssh2"`（沒有 syslog 表頭：時間戳/hostname/
   `sshd[pid]:`），decoder 完全配對不到，落到泛用規則 `1002`
   （`Unknown problem somewhere in the system.`，level 2）而不是真正的
   sshd 規則 `5710`（level 5）。
2. 原本打算 grep 的字串 `"Level:"` 在 `wazuh-logtest` 輸出裡根本不存在
   （實際是小寫 `level:`），而且即使改成小寫，泛用規則 1002 一樣會印出
   `level: '2'`——兩種「有配對到規則」和「完全沒配對到」的情況都會讓這條
   assertion 通過，等於沒測到東西。

**修法**：測試行改成完整格式
`"Jul  6 00:00:00 wazuh-fim sshd[12345]: Failed password for invalid user
test from 10.0.0.9 port 12345 ssh2"`，確保配對到具名規則 `5710`；斷言字串
改成 `wazuh-logtest` 只在配對到的規則等級**超過告警門檻**（`ossec.conf`
出廠預設 `<log_alert_level>3</log_alert_level>`）時才會印出的
`"Alert to be generated."`，兩者合起來才是「規則引擎真的認得這個事件、
且判定為需要告警」的可靠證據。

---

## 6. 常見問題

- **C10/C11 fail（沒轉送）**：這是預期行為（見 spec §5），沒帶
  `-e siem_forward_host=` 就是如此；補跑一次 apply 帶上這個變數即可。
- **想在 log-server 找 Wazuh 轉送過來的告警**：查 `/var/log/syslog`
  （§4/§5.1），不是 `/var/log/siem/`——那個目錄是 `audit-log-forwarding.md`
  專用的。
- **C1-C9 也 fail、`wazuh-manager.service` 疑似沒真的在運作**：先看
  `sudo tail -n 100 /var/ossec/logs/ossec.log` 有沒有 `disk is full`
  （§5.2），再看 `df -h /`；20GB/2048MB 的規格會踩坑，改用 60GB/8192MB/4vCPU。
- **想確認 CVE 掃描結果**：admin 密碼在目標主機的
  `/root/wazuh-install-files.tar`（`tar -O -xvf wazuh-install-files.tar
  wazuh-install-files/wazuh-passwords.txt`），登入 dashboard（443）查看；
  這個檔案不會被搬離目標主機，也不進 vault（見 §1、spec §5）。
- **想重灌/重跑整個 all-in-one 安裝**：本 playbook 的 rescue 只覆蓋
  Step 6-8（轉送設定）的還原，**不會**自動修復一次失敗一半的
  `wazuh-install.sh` 執行（見 spec §5、playbook 內的 rescue 訊息）——先看
  `/var/log/wazuh-install.log` 找失敗點，官方腳本支援 `-o`（overwrite）
  選項可以重來，但那是破壞性操作，需要人工確認後手動下。
