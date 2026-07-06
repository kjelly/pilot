# Runbook — wazuh-fim（Wazuh agent：檔案完整性監控 FIM + auditd who-data）

> 撰寫日期：2026-07-06 (UTC)；v1.1 更新：2026-07-06 (UTC)
> 對齊：`docs/verification/wazuh-fim.md`（v1.1）、`playbooks/apply/wazuh-fim-apply.yml`
> 維護者：sre

---

## 0. 目標與範圍

在一台 Ubuntu 24.04 vm-target 上部署 **Wazuh agent**，對可設定的目錄清單
（預設 `/etc`、`/boot`，**可依主機覆寫**，見 §2.3）做即時檔案完整性監控
（FIM/syscheck），whodata 模式（底層由 auditd 提供事件來源）取得 who-data
（誰、透過什麼程序、什麼時候改了檔案），並向中央
`docs/runbooks/wazuh-manager.md` 註冊回報。

本 runbook 依賴 `wazuh-manager.md` 已先部署完成（agent 註冊需要一個可連的
manager；manager 不存在時 agent 仍可先裝好本機 FIM 規則，見 §2.2）。

---

## 1. §0.5 事實快照（AGENTS.md §2）

```
$ go run ./cmd/pilot vm-target list
wazuh-fim      running  192.168.122.6  2  2048  20  2026-07-06
wazuh-manager  running  192.168.122.5  4  8192  60  2026-07-06

$ go run ./cmd/pilot vm-target show-inventory --name wazuh-fim
all:
  hosts:
    wazuh-fim:
      ansible_connection: ssh
      ansible_host: 192.168.122.6
      ansible_user: ubuntu
      ...
```

**規格對齊**：vm-target 的 inventory 只有單一 host key，playbook
`hosts: "{{ target_group | default('wazuh-fim') }}"` 直接命中，不需要
`-e target_group=` override（同 `log-server.md`/`wazuh-manager.md` 的設計）。

無 vault 依賴（開放式 enrollment，見 spec §5 的加固建議）。

---

## 2. 部署（apply）

### 2.1 標準情境：manager 已存在（註冊啟用）

```bash
go run ./cmd/pilot vm-target up --name wazuh-fim \
    --ssh-user ubuntu --disk 20 --memory 2048 --vcpus 2 \
    --ssh-timeout 8m --boot-timeout 8m

go run ./cmd/pilot vm-target run --name wazuh-fim \
    playbooks/apply/wazuh-fim-apply.yml \
    -e wazuh_manager_host=192.168.122.5
```

**真實輸出**（2026-07-06，全新 VM 首次 apply）：

```
TASK [Step 0: Report whether manager enrollment is enabled this run] ***********
ok: [wazuh-fim] => {
    "msg": "wazuh_manager_host=192.168.122.5 — enrollment will be configured (spec C7-C9)."
}
TASK [Step 2: Import Wazuh apt GPG key (idempotent via creates:)] **************
changed: [wazuh-fim]
TASK [Step 3: Add Wazuh apt repository] ****************************************
changed: [wazuh-fim]
TASK [Step 4: Install wazuh-agent + auditd (spec C1, C2)] **********************
changed: [wazuh-fim]
TASK [Step 5: Append FIM whodata syscheck block to ossec.conf (spec C5, C6)] ***
changed: [wazuh-fim]
TASK [Step 6: Pin wazuh-manager -> 192.168.122.5 in /etc/hosts (spec C7)] ******
changed: [wazuh-fim]
TASK [Step 7: Point ossec.conf's <address> at the manager alias (or loopback placeholder) (spec C8)] ***
changed: [wazuh-fim]
TASK [Step 8: Check whether this agent is already enrolled (client.keys populated)] ***
ok: [wazuh-fim]
TASK [Step 9: Register with the manager via agent-auth (only once; spec C9)] ***
changed: [wazuh-fim]
TASK [Step 10: Ensure wazuh-agent + auditd enabled+started (spec C3, C4)] ******
changed: [wazuh-fim] => (item=wazuh-agent)
ok: [wazuh-fim] => (item=auditd)
TASK [Step 11: Restart wazuh-agent if config changed or a new enrollment just happened] ***
changed: [wazuh-fim]
PLAY RECAP *********************************************************************
wazuh-fim                  : ok=13   changed=9    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```

**冪等驗證**（同指令再跑一次，注意 Step 9 正確 `skipping`——不會重新註冊）：

```
TASK [Step 9: Register with the manager via agent-auth (only once; spec C9)] ***
skipping: [wazuh-fim]
TASK [Step 11: Restart wazuh-agent if config changed or a new enrollment just happened] ***
skipping: [wazuh-fim]
PLAY RECAP *********************************************************************
wazuh-fim                  : ok=10   changed=0    unreachable=0    failed=0    skipped=2    rescued=0    ignored=0
```

### 2.2 過渡情境：manager 尚不存在（先裝 agent + FIM 規則）

```bash
go run ./cmd/pilot vm-target run --name wazuh-fim \
    playbooks/apply/wazuh-fim-apply.yml
# verify 時 C7-C9 預期 fail（見 spec §5），只看 C1-C6 是否全 pass
```

### 2.3 自訂監控路徑（v1.1，per-host 覆寫）

`wazuh_fim_directories` 可依主機覆寫，讓不同角色的主機盯不同路徑（真實
inventory 部署放進 `host_vars/<hostname>.yml`，見
`group_vars/wazuh-fim.example.yml`；這裡示範用 `-e` 帶入等效效果）：

```bash
go run ./cmd/pilot vm-target run --name wazuh-fim \
    playbooks/apply/wazuh-fim-apply.yml \
    -e '{"wazuh_fim_directories": ["/etc", "/boot", "/var/www"]}'
```

**真實輸出**（2026-07-06T07:32Z，`/var/www` 是本機一個全新、套件出廠設定
完全沒碰過的路徑）：

```
TASK [Step 0a: Report which paths this host is monitoring] *********************
ok: [wazuh-fim] => {
    "msg": "wazuh_fim_directories=['/etc', '/boot', '/var/www']"
}
```

`sudo grep "Monitoring path" /var/ossec/logs/ossec.log` 確認 `/var/www`
真的被納入 whodata 監控：

```
wazuh-syscheckd: INFO: (6003): Monitoring path: '/var/www', with options 'size | permissions | owner | group | mtime | inode | hash_md5 | hash_sha1 | hash_sha256 | whodata'.
wazuh-syscheckd: INFO: (6003): Monitoring path: '/etc', with options '... | whodata'.
wazuh-syscheckd: INFO: (6003): Monitoring path: '/boot', with options '... | whodata'.
```

再帶同一組清單重跑一次，`PLAY RECAP` 為 `changed=0`（冪等）；換一組不同的
清單重跑，`blockinfile` 會偵測內容差異、正確更新並重啟 agent。

---

## 3. 驗證（spec C1–C9）

```bash
go run ./cmd/pilot vm-target verify --name wazuh-fim \
    docs/verification/wazuh-fim.md
```

**真實輸出**（2026-07-06T07:14:46Z，§2.1 之後，預設路徑清單）：

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
```

`verdict: PASS (pass=9 fail=0 skip=0)`。全部 rows 都是 `rc-from-stdout=`
（真正被 matcher 檢驗過，非回退到 ansible 進程自己永遠 0 的 exit code）。

**真實輸出**（2026-07-06T07:33:18Z，§2.3 之後，自訂清單 `["/etc", "/boot",
"/var/www"]`，manager 未設定）：

```
total: 9  pass: 6  fail: 3  skip: 0
verdict: FAIL
C7 fail  rc-from-stdout=2, expected 0   (manager 未設定，預期)
C8 fail  rc-from-stdout=1, expected 0   (manager 未設定，預期)
C9 fail  rc-from-stdout=1, expected 0   (manager 未設定，預期)
C1-C6    全部 pass
```

**這就是 C5 從 v1.0 改成通用檢查後的實際效果**：套用了完全不同的目錄清單
（含全新路徑 `/var/www`），C5（「至少一個目錄設定 whodata」）依然正確
`pass`，不會因為清單內容跟 v1.0 假設的 `/etc`/`/boot` 不一樣而誤判 fail。

---

## 4. 跨主機 cross-check（完整鏈路：FIM 變更 → manager 告警含 who-data → 轉送到 log-server）

C7-C9 只驗證「agent 端自己拿到憑證」，**不**驗證「manager 真的認得、真的
連上」；C1-C6 也只驗證「本機規則設定正確」，**不**驗證「規則真的觸發、
who-data 真的被附加」。完整鏈路的證明見
`docs/runbooks/wazuh-manager.md` §4（本文件不重複，指令與真實輸出都在
那邊）——簡述流程：

```bash
# 1. agent 端：觸發一筆真實檔案異動
go run ./cmd/pilot vm-target exec --name wazuh-fim -- \
    sudo sh -c 'echo "# PILOT-WAZUH-CHAIN-TEST $(date)" >> /etc/pilot-fim-chaintest.conf'

# 2. manager 端：確認 agent_control 顯示這台是 Active
go run ./cmd/pilot vm-target exec --name wazuh-manager -- \
    sudo /var/ossec/bin/agent_control -l

# 3. manager 端：確認告警含完整 who-data（見 wazuh-manager.md §4 的完整輸出）
go run ./cmd/pilot vm-target exec --name wazuh-manager -- \
    sudo grep "pilot-fim-chaintest" /var/ossec/logs/alerts/alerts.json
```

**真實輸出（agent_control -l）**：

```
Wazuh agent_control. List of available agents:
   ID: 000, Name: wazuh-manager (server), IP: 127.0.0.1, Active/Local
   ID: 001, Name: wazuh-fim, IP: any, Active
```

---

## 5. 踩過的雷（實測 vm-target 時發現）

### 5.1 Wazuh 的 `ossec.conf` 允許附加新的 `<ossec_config>` 根節點，對同一路徑重複宣告是聯集不是覆蓋

跟 `wazuh-manager.md` §5.4 是同一個發現、同一個機制，這裡從 agent 端的
角度說明：套件出廠的 `<syscheck>` 本來就已經監控 `/etc`、`/boot`（在一個
逗號分隔的 `<directories>/etc,/usr/bin,/usr/sbin</directories>` 裡，沒有
`whodata`）。`wazuh-fim-apply.yml` 沒有去找、去改這行既有設定，而是在檔案
末端**附加**一個新的 `<ossec_config><syscheck><directories check_all="yes"
whodata="yes">/etc</directories>...` 區塊。

實測套用後 `ossec.log` 證實兩邊設定被正確合併，`/etc` 拿到聯集後的完整
選項：

```
wazuh-syscheckd: INFO: (6003): Monitoring path: '/etc', with options 'size | permissions | owner | group | mtime | inode | hash_md5 | hash_sha1 | hash_sha256 | whodata'.
wazuh-syscheckd: INFO: (6003): Monitoring path: '/bin', with options 'size | permissions | owner | group | mtime | inode | hash_md5 | hash_sha1 | hash_sha256 | scheduled'.
```

`/etc`（我們額外宣告過）多了 `whodata`；`/bin`（我们没碰）維持原本的
`scheduled`。這代表**完全不需要去理解或修改套件出廠的其餘設定**就能疊加
自己要的行為，風險面比「找到既有行、原地修改」小很多——同樣的技巧也用在
`wazuh-manager.md` 的 `<syslog_output>`。

### 5.2 who-data 的證據要在 manager 端看，不是 agent 端

一開始想在 agent 端本機找 FIM 事件的 who-data 證據（例如翻 agent 自己的
`/var/ossec/logs/ossec.log`），但 syscheckd 在 agent 端只會記錄「哪個檔案
被改了、什麼屬性變了」這類本機層級訊息，**真正組裝出 `syscheck.audit`
（`login_user`/`effective_user`/`process` 完整鏈）的是 manager 端的
`wazuh-analysisd`**——agent 只負責把原始事件（含 auditd 提供的 raw
audit 資料）送過去，關聯分析是在 manager 端做的。

**結論**：本 spec（C1-C9）刻意只驗證 agent 端「規則設定正確、憑證已拿到」
這類本機可判定的狀態；真正「who-data 有沒有生效」的證明只能去 manager 端
的 `alerts.json` 找（見 §4、`wazuh-manager.md` §4），這也是為什麼這個
spec 沒有嘗試在 agent 端自己實作一條 who-data 功能性檢查——那個證據本來
就不在這台主機上。

### 5.3 apt 安裝 `wazuh-agent` 時**不要**用 `WAZUH_MANAGER` 環境變數觸發套件安裝時自動註冊

官方文件建議 `WAZUH_MANAGER="10.0.0.2" apt-get install wazuh-agent` 讓
套件的 postinst script 在安裝當下自動跑 `agent-auth`。這個做法在
「manager 選填、可能在 agent 裝好之後才出現」的場景下有個根本問題：
**postinst 只在套件第一次被安裝的那一刻執行**。若第一次 apply 時
`wazuh_manager_host` 是空的（manager 還不存在），套件裝好但沒有註冊；
之後 manager 就緒、帶著 `-e wazuh_manager_host=...` 重新 apply，`apt`
模組發現套件已安裝、視為無變化（不會重新觸發 postinst），**永遠不會
自動補上註冊**。

**修法**：完全不依賴套件安裝流程做註冊，改成明確、獨立的
`ansible.builtin.command: /var/ossec/bin/agent-auth -m {{ alias }}` task，
用 `client.keys` 是否為空當 idempotency 判斷（同 `freeipa-client-apply.yml`
的 `ipa-client-install --creates` 精神,只是 agent-auth 沒有原生
`creates:` 語法,改用明確 `when:`）。這樣「先裝 agent、之後才補 manager」
的過渡情境（spec §7.2）才能真的補得上,不用重裝任何東西。

### 5.4（v1.1）監控路徑改成可依主機覆寫後，spec checklist 不能再綁死字面路徑

v1.0 的 C5/C6 各自寫死 `grep '.../etc</directories>'`、
`grep '.../boot</directories>'`——這在「所有主機都監控同一組固定路徑」的
前提下沒問題，但一旦要支援「不同主機監控不同路徑」（例：web 主機多盯
`/var/www`），這兩條字面值檢查在**覆寫了清單的主機上會非預期 fail**，因為
spec 的 Command/Expected 欄位是跨主機共用的固定字串，沒辦法知道某台主機
實際填了什麼清單。

**修法**：把 C5/C6 合併成一條通用檢查——只驗證「至少一個目錄設定了
`check_all="yes" whodata="yes"`」，不管字面上是哪個路徑；原本的 C7（provider
檢查）遞補成 C6，後面的 register 系列（原 C8/C9/C10）依序遞補成 C7/C8/C9
（row 數 10 → 9）。實測驗證：套用一個含全新路徑 `/var/www` 的自訂清單後，
新版 C5 依然正確 `pass`（見 §2.3、§3），舊版寫法在同樣情境下會 `fail`
（因為 `/var/www` 不是 `/etc` 也不是 `/boot`）。

**這個教訓可以泛化**：spec 的 checklist 檢查的是「機制有沒有生效」，不是
「站台特定的設定值是什麼」——只要一個變數變成「允許逐站台/逐主機不同」，
所有依賴該變數具體值的 checklist row 都要重新檢視是不是綁死了字面值。

---

## 6. 常見問題

- **C7-C9 fail（沒註冊）**：這是預期行為（見 spec §5），沒帶
  `-e wazuh_manager_host=` 就是如此；補跑一次 apply 帶上這個變數即可
  （agent-auth 會在 client.keys 為空時自動觸發，見 §5.3）。
- **重新註冊/憑證疑似壞掉**：`sudo rm -f /var/ossec/etc/client.keys` 後
  重跑 apply，Step 9 的 `when:` 條件會判定 client.keys 為空、重新執行
  `agent-auth`。
- **manager 端 `agent_control -l` 看不到這台**：先確認
  `getent hosts wazuh-manager`（agent 端）解析到正確 IP，再確認 manager
  的 1515/tcp（authd）真的在監聽（`wazuh-manager.md` C6）。
- **想讓不同主機監控不同路徑**：見 §2.3——放進該主機的
  `host_vars/<hostname>.yml`，設定 `wazuh_fim_directories`（見
  `group_vars/wazuh-fim.example.yml`），不需要複製新 spec 或改這份的
  預設值（v1.1 起 C5 是通用檢查，不綁死特定路徑）。
