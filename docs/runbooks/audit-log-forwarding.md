# Runbook — audit-log-forwarding（auditd 稽核規則 + rsyslog 轉送至 SIEM）

> 撰寫日期：2026-07-06 (UTC)（v1.1 修訂：`siem_forward_host` 改選填 + §5.3 記錄
> `pilot verify` matcher 引擎本身的一個真實 bug）
> 對齊：`docs/verification/audit-log-forwarding.md`（v1.1）、
> `playbooks/apply/audit-log-forwarding-apply.yml`、
> `playbooks/templates/audit.rules.j2`
> 前置依賴：`docs/runbooks/log-server.md`（若要驗證轉送，須先 apply 完成；
> 若 log-server 尚不存在，本 spec 仍可獨立套用只做本機稽核，見 §2.2）
> 維護者：sre

---

## 0. 目標與範圍

在一台受管主機上部署：

1. **Client 端稽核**：`auditd` + `audispd-plugins`，自訂規則監控
   setuid/setgid 的**變更**與**執行**、`sudo` 執行、`/etc/passwd`、
   `/etc/sudoers` 異動。
2. **Logrotate**：`/etc/logrotate.d/{auditd,syslog}` 限制本機空間。
3. **轉送**：`/etc/rsyslog.d/99-siem-forward.conf` 把 `auth,authpriv.*` 與
   `local6.*`（auditd）用 TCP（`@@`）轉送到中央 SIEM（見 `log-server.md`）。

本 runbook 是 Shape 3（client+server）：client 端本機規則/服務用單機
`pilot verify` 驗證，跨主機「訊息真的送到了」在 §4 用 client→server 的
`vm-target exec` cross-check 驗證。

---

## 1. §0.5 事實快照（AGENTS.md §2）

```
$ go run ./cmd/pilot vm-target list
audit-log-forwarding  running  192.168.122.7  2  2048  20  2026-07-06
log-server            running  192.168.122.6  2  2048  20  2026-07-06

$ go run ./cmd/pilot vm-target show-inventory --name audit-log-forwarding
all:
  hosts:
    audit-log-forwarding:
      ansible_connection: ssh
      ansible_host: 192.168.122.7
      ansible_user: ubuntu
      ...
```

**對齊決定**：跟 `log-server.md` 同一個設計——vm-target host key 直接是
`audit-log-forwarding`，playbook `hosts:` 預設值同名，不需要
`-e target_group=` override。

無 vault 依賴（本 spec 不含任何機密；`siem_forward_host` 是 IP，不是密碼）。

---

## 2. 部署（apply）

```bash
# 前置：log-server 必須先 up + apply 完成，記下其當下 IP
LOG_SERVER_IP=$(go run ./cmd/pilot vm-target show-inventory --name log-server \
    | awk '/ansible_host:/{print $2; exit}')   # 本次實測值: 192.168.122.6

go run ./cmd/pilot vm-target up --name audit-log-forwarding \
    --ssh-user ubuntu --disk 20 --memory 2048 --vcpus 2 \
    --ssh-timeout 8m --boot-timeout 8m

go run ./cmd/pilot vm-target run --name audit-log-forwarding \
    playbooks/apply/audit-log-forwarding-apply.yml \
    -e siem_forward_host=$LOG_SERVER_IP
```

**真實輸出**（2026-07-06，全新 VM 首次 apply）：

```
TASK [Step 1: Install auditd + audispd-plugins (Debian family)] ****************
changed: [audit-log-forwarding]
TASK [Step 2: Render audit.rules.j2 (setuid/setgid, sudo, passwd/sudoers watches)] ***
changed: [audit-log-forwarding]
TASK [Step 3: Load the custom rules into the running kernel audit list (spec C10)] ***
ok: [audit-log-forwarding]
TASK [Step 4: Render /etc/logrotate.d/auditd] **********************************
changed: [audit-log-forwarding]
TASK [Step 5: Render /etc/logrotate.d/syslog] **********************************
changed: [audit-log-forwarding]
TASK [Step 6: Pin siem-log-server -> 192.168.122.6 in /etc/hosts (spec C15)] ***
changed: [audit-log-forwarding]
TASK [Step 7: Render 99-siem-forward.conf (local6.* + auth,authpriv.* -> siem-log-server)] ***
changed: [audit-log-forwarding]
TASK [Step 8: Ensure auditd enabled + started (spec C18)] **********************
ok: [audit-log-forwarding]
TASK [Step 9: Ensure rsyslog enabled + started (spec C19)] *********************
ok: [audit-log-forwarding]
TASK [Step 9a: Restart rsyslog only if the forward config actually changed] ****
changed: [audit-log-forwarding]
PLAY RECAP *********************************************************************
audit-log-forwarding       : ok=12   changed=7    unreachable=0    failed=0    skipped=1    rescued=0    ignored=0
```

### 2.2 v1.1：`siem_forward_host` 未提供時（log-server 尚不存在）

實測跑法（不帶 `-e siem_forward_host=...`）：

```bash
go run ./cmd/pilot vm-target run --name audit-log-forwarding \
    playbooks/apply/audit-log-forwarding-apply.yml
```

**真實輸出**（2026-07-06T03:34Z）：

```
TASK [Step 0: Report whether SIEM forwarding is enabled this run] **************
ok: [audit-log-forwarding] => {
    "msg": "siem_forward_host not provided — skipping /etc/hosts pin and 99-siem-forward.conf; only local auditd monitoring (C1-C14, C18) will be configured. Re-run with -e siem_forward_host=<log-server IP/FQDN> once a log server exists to add forwarding."
}
TASK [Step 6: Pin siem-log-server ->  in /etc/hosts (spec C15)] ****************
skipping: [audit-log-forwarding]
TASK [Step 7: Render 99-siem-forward.conf (local6.* + auth,authpriv.* -> siem-log-server)] ***
skipping: [audit-log-forwarding]
PLAY RECAP *********************************************************************
audit-log-forwarding       : ok=8    changed=4    unreachable=0    failed=0    skipped=4    rescued=0    ignored=0
```

無 hard fail——本機稽核規則、logrotate、`auditd`/`rsyslog` 服務照常套用，
只有轉送相關的兩個 task 被跳過。之後 log-server 就緒，用同一份 playbook
補 `-e siem_forward_host=<ip>` 重跑即可補上轉送（見 §2 的完整 apply），
其餘 task 全部維持 `ok`（冪等），只有轉送相關的兩個 task 變成 `changed`：

```
TASK [Step 1: Install auditd + audispd-plugins (Debian family)] ****************
ok: [audit-log-forwarding]
TASK [Step 6: Pin siem-log-server -> 192.168.122.9 in /etc/hosts (spec C15)] ***
changed: [audit-log-forwarding]
TASK [Step 7: Render 99-siem-forward.conf (local6.* + auth,authpriv.* -> siem-log-server)] ***
changed: [audit-log-forwarding]
TASK [Step 9a: Restart rsyslog only if the forward config actually changed] ****
changed: [audit-log-forwarding]
PLAY RECAP *********************************************************************
audit-log-forwarding       : ok=11   changed=3    unreachable=0    failed=0    skipped=1    rescued=0    ignored=0
```

---

## 3. 驗證（spec C1–C19）

```bash
go run ./cmd/pilot vm-target verify --name audit-log-forwarding \
    docs/verification/audit-log-forwarding.md --timeout 40
```

### 3.1 未帶 `siem_forward_host` 時（v1.1，§2.2 的狀態）：預期 C15–C17 fail

**真實輸出**（2026-07-06T03:46Z，verdict **FAIL pass=16 fail=3 skip=0**——
這是**設計如此**，見 spec §5 已知偏差，不是 bug）：

```json
{"id":"C15","status":"fail","detail":"rc-from-stdout=2, expected 0"}
{"id":"C16","status":"fail","detail":"rc-from-stdout=2, expected 0"}
{"id":"C17","status":"fail","detail":"rc-from-stdout=2, expected 0"}
```

其餘 C1–C14, C18, C19 全數 pass，證明「本機稽核與 log server 是否存在無關」
這個 v1.1 的設計目標確實成立。

### 3.2 補上 `siem_forward_host` 後：全數 19 條（§5.3 matcher 修復後的真實輸出）

```bash
go run ./cmd/pilot vm-target verify --name audit-log-forwarding \
    docs/verification/audit-log-forwarding.md --timeout 40
```

**真實輸出**（2026-07-06T03:47Z，verdict **PASS pass=19 fail=0 skip=0**，
已套用 §5.1/§5.2/§5.3 的修法，且這次的 pass 是 matcher 真的解析出
`rc-from-stdout` 而得出，不是 §5.3 描述的那種「巧合式假 PASS」）：

```json
{"id":"C1","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C2","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C3","status":"pass","detail":"expected: present (rc=0)"}
{"id":"C4","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C5","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C6","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C7","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C8","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C9","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C10","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C11","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C12","status":"pass","detail":"expected: present (rc=0)"}
{"id":"C13","status":"pass","detail":"expected: present (rc=0)"}
{"id":"C14","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C15","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C16","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C17","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C18","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C19","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
```

> 每一條 numeric-expected row 的 `detail` 現在都是 `"rc-from-stdout=0
> matches expected 0"`——代表 matcher 真的從 ad-hoc 輸出解析出
> `; echo $?`/`&& echo 0 || echo 1` 迴避 trap 1 產生的數字，而不是 §5.3
> 描述的那種「解析失敗、退回 ansible 進程自身 rc、恰好巧合等於 0」的假
> PASS。修 §5.3 之前，這裡的 detail 全部是 `"rc=0 matches expected 0"`
> （沒有 `-from-stdout`）——這就是判斷「這條 PASS 是不是巧合」的可觀察
> 訊號，見 §5.3。

**冪等驗證**（同指令再跑一次 apply，PLAY RECAP）：

```
audit-log-forwarding       : ok=10   changed=0    unreachable=0    failed=0    skipped=2    rescued=0    ignored=0
```

---

## 4. Shape 3 cross-check（client 轉送的訊息真的被 log-server 收到）

```bash
go run ./cmd/pilot vm-target exec --name audit-log-forwarding -- \
    logger -p local6.info "PILOT-E2E-FORWARD-TEST-LOCAL6"
go run ./cmd/pilot vm-target exec --name audit-log-forwarding -- \
    logger -p authpriv.info "PILOT-E2E-FORWARD-TEST-AUTHPRIV"
sleep 2
go run ./cmd/pilot vm-target exec --name log-server -- \
    sudo grep -r "PILOT-E2E-FORWARD-TEST" /var/log/siem/
```

**真實輸出**（2026-07-06T03:18Z）：

```
/var/log/siem/audit-log-forwarding/audit.log:2026-07-06T03:18:17+00:00 audit-log-forwarding ubuntu: PILOT-E2E-FORWARD-TEST-LOCAL6
/var/log/siem/audit-log-forwarding/auth.log:2026-07-06T03:18:17+00:00 audit-log-forwarding ubuntu: PILOT-E2E-FORWARD-TEST-AUTHPRIV
```

**v1.1 複測**（§5.3 matcher 修好、siem_forward_host 改選填後，重新走一次
apply→verify→cross-check，2026-07-06T03:48Z）：

```
/var/log/siem/audit-log-forwarding/audit.log:2026-07-06T03:48:07+00:00 audit-log-forwarding ubuntu: PILOT-E2E-FORWARD-RECHECK-LOCAL6
/var/log/siem/audit-log-forwarding/auth.log:2026-07-06T03:48:08+00:00 audit-log-forwarding ubuntu: PILOT-E2E-FORWARD-RECHECK-AUTHPRIV
```

`local6.*`（模擬 auditd 轉送）與 `authpriv.*` 都正確依來源 hostname
（`audit-log-forwarding`）分檔落地在 log-server 上，證明整條轉送鏈路
（client `lineinfile` pin 別名 → `@@` TCP 轉送 → server `imtcp` 接收 →
`%HOSTNAME%` dynaFile 路由）端到端是通的。

---

## 5. 踩過的雷（實測 vm-target 時發現，均已修進 playbook/template）

### 5.1 稽核規則順序錯誤 → `sudo` 執行監控的 key 永遠不會出現（C11 一開始 FAIL）

第一次 verify，C11（真的執行 `sudo` 後應該有對應稽核事件）失敗。追查發現
`auditctl -l` 顯示規則都有載入，`/var/log/audit/audit.log` 裡也真的有
`sudo` 的 SYSCALL 記錄——但 key 全部是 `setuid_setgid_exec`，從來沒有出現
`privileged-sudo`。

**根因**：Linux 核心稽核的 `-a always,exit` filterlist 是**由上到下評估、
第一條符合就停**（跟 iptables 一樣的短路語意），**不是**每條都評估後合併。
`/usr/bin/sudo` 本身是 setuid-root binary，所以每次 `sudo` 呼叫的 execve
在 exit 時 `uid!=euid`（`uid=1000` 呼叫者、`euid=0` 因為 setuid 生效）恆成立，
一定先命中泛用的 `setuid_setgid_exec` 規則、短路掉，排在後面的
`-w /usr/bin/sudo -p x -k privileged-sudo` 規則永遠沒機會判定。

**修法**：`audit.rules.j2` 把 `sudo`/`/etc/passwd`/`/etc/sudoers` 這些**具體**
規則放在 setuid/setgid **泛用** execve 規則**之前**——具體規則先攔下
`/usr/bin/sudo` 的呼叫、貼上 `privileged-sudo`，泛用規則仍然會攔到其他
所有 setuid/setgid binary 的呼叫（因為它們不會先被具體規則攔走）。

驗證修法生效：
```bash
sudo -n true; sleep 1
sudo grep -o 'key="[a-z_-]*"' /var/log/audit/audit.log | sort | uniq -c
#   19 key="privileged-sudo"     <- 修好後才出現
#   41 key="setuid_setgid_change"
#   45 key="setuid_setgid_exec"
```

**這是規則撰寫的通用教訓，不只限這個 spec**：任何時候寫多條
`-a always,exit` 規則且它們的匹配範圍有重疊（如「泛用 A」與「A 的子集
B」），**具體規則必須排在泛用規則之前**，否則具體規則會被永久短路掉。

### 5.2 `ausearch` 找不到明明存在的事件（C11 原始設計是用 `ausearch`）

C11 原本設計是 `sudo ausearch -k privileged-sudo -ts recent`，即使 §5.1 的
順序問題修好、`grep /var/log/audit/audit.log` 也證實記錄確實存在，
`ausearch` 依然回 `<no matches>`（`-ts recent`/`-ts today` 都一樣）。

**根因**：這個 Ubuntu 24.04 的 audit 版本，enriched（解讀後）欄位跟原始
`key="..."` 欄位之間**沒有空格**（`key="privileged-sudo"ARCH=x86_64...`，
正常應該是 `key="privileged-sudo" ARCH=x86_64`），破壞了 `ausearch` 自己
的 parser，即使原始檔案內容完全正常。

**修法**：C11 改成直接 `grep` `/var/log/audit/audit.log`（正邏輯 rc，
`sh -c '... && echo 0 || echo 1'`），不依賴 `ausearch` 的查詢/索引行為。
少一層工具依賴，也更直接反映「稽核記錄真的寫進日誌了」這件事。

### 5.3 `pilot verify` matcher 引擎本身的 bug：ad-hoc 模式下數字 Expected 恆為 PASS

v1.1 加入「`siem_forward_host` 未提供時應該只做本機稽核」這個能力後，第一次
用**沒有 log-server 的狀態**跑 verify——這是這個 spec 第一次真正跑到「應該
FAIL」的路徑（先前所有 apply 都是先起好 log-server 才 apply，從沒驗證過
「轉送設定真的不存在」這個負向狀態）。結果 C15（`/etc/hosts` 沒有
`siem-log-server` 別名）回報 **pass**，即使 `getent hosts siem-log-server`
直接在主機上執行明明是 rc=2。

**根因**：`pilot vm-target verify`（以及任何 `pilot verify -i <inventory>`）
透過 `ansible <host> -m shell -a '<cmd>' --one-line` ad-hoc 呼叫執行每一條
Command，真正的指令輸出被 ansible 包成
`<host> | CHANGED | rc=0 | (stdout) <文字>`（可能前面還有
`[WARNING]`/`[DEPRECATION WARNING]` 雜訊行）。`internal/tools/verify_spec.go`
的 `extractRC()` 只認得「stdout 剝掉 `(rc=N)` 前綴後整段就是純數字」這一種
形狀（本機/`--local` 模式下確實是這樣），完全不認得 ad-hoc 這種
`host | CHANGED | rc=0 | (stdout) N` 的包法，所以永遠回傳 `-1`，
`matchExpected()` 退回比較 **ansible ad-hoc 進程自己的 exit code**——而
`cmd; echo $?`／`cmd && echo 0 || echo 1` 這兩種本 spec 樣板文件明文建議
的「迴避 trap 1」寫法，最後一個執行的指令永遠是 `echo`，**永遠成功**，
所以 ansible 進程的 exit code 永遠是 0。結果就是：**任何用這個推薦寫法、
數字 Expected 為 `0` 的 row，只要透過 ad-hoc/inventory 模式驗證，不管遠端
真實狀態是什麼，一律回報 PASS。**

這代表這個 session（以及很可能本專案其他用同一寫法驗證的 spec）先前所有
「PASS」證據，凡是數字 Expected 用 `; echo $?` 或 `&& echo 0 || echo 1`
寫法、且透過 `vm-target verify` 跑的，都只是**巧合式**PASS——剛好遠端真實
狀態等於 expected，從沒真正被 matcher 檢驗過。`log-server.md` 的 C6/C7、
本 spec的 C1/C2/C4/C5/C6/C7/C8/C9/C10/C11/C14/C15/C16/C17/C18/C19（幾乎
全部數字 row）都在此列。

**修法**（`internal/tools/verify_spec.go`）：新增 `unwrapAdhocOneline()`，
從最後一行往前找 `| rc=N` 這個 ad-hoc 結果行的標記（跳過前面的
WARNING/DEPRECATION 雜訊行），抓出 `(stdout)` 後面、`(stderr)`（如果指令
同時寫了 stderr，例如 `grep` 對不存在的檔案）前面的那段文字，才是真正的
遠端 stdout。`extractRC()`／`stripRunnerPrefix()` 都改用這個 unwrap 後的
文字做判斷。修好後同一個 verify 指令：C15 正確回報
`rc-from-stdout=2, expected 0` → **fail**（見 §3.1），數字 row 的 `detail`
也從 `"rc=0 matches expected 0"` 變成 `"rc-from-stdout=0 matches expected
0"`（見 §3.2 的說明框）——這個 detail 字串本身就是「這條 PASS 是不是真的
被檢驗過」的可觀察訊號。

回歸測試鎖在 `internal/tools/verify_spec_match_test.go`（含真實捕捉到的
`stdout+stderr` 同行案例），單元測試層級直接餵入捕捉到的真實 ad-hoc 輸出
字串斷言修復前後的行為差異。

**通用教訓**：一個「一直 PASS」的檢查，如果從沒真正跑過負向狀態（這裡是
「log-server 不存在」），永遠無法分辨「真的通過」跟「matcher 壞掉、
結構上不可能 FAIL」。幫既有能力加一個新的可選/條件分支（像這次的
`siem_forward_host` 選填化）時，順便把「關閉」那條路徑也真的跑一次
apply+verify，往往是第一次真正踩到負向狀態、也是這類 matcher/工具本身的
bug 第一次有機會現形的時候。

### 5.4 `/etc/logrotate.d/syslog` 的 dry-run 檢查（C14）在 Ubuntu 24.04 上原生就會 fail

`logrotate -d /etc/logrotate.d/auditd /etc/logrotate.d/syslog` 在 §5.3
修好 matcher 之後第一次「真的被檢驗」，結果 C14 fail
（`rc-from-stdout=1`）。手動執行确认：

```
error: skipping "/var/log/syslog" because parent directory has insecure
permissions (It's world writable or writable by group which is not "root")
Set "su" directive in config file to tell logrotate which user/group
should be used for rotation.
```

**根因**：這是 Ubuntu 24.04 這個 logrotate 版本的通用行為，不是我們的檔案
寫錯——連 Ubuntu **自己內建**的 `/etc/logrotate.d/rsyslog` 對同一個
`/var/log`（`root:syslog 0775`，group-writable）也會踩到一模一樣的
"insecure permissions" 檢查（`sudo logrotate -d /etc/logrotate.d/rsyslog`
可重現）。`/var/log/audit/audit.log` 不受影響，因為 `auditd` 自己建立的
`/var/log/audit` 目錄權限比較嚴格（不對 group 開寫）。

**修法**：`/etc/logrotate.d/syslog` 加一行 `su root syslog`，明確告訴
logrotate「以 `root:syslog` 身分執行這個 policy 的檔案動作」，logrotate
的 insecure-permissions 檢查就會信任這個宣告過的身分，不再對 `/var/log`
本身的 group-writable 屬性報錯。（Ubuntu 自己內建的 `/etc/logrotate.d/rsyslog`
沒有加這行，所以它本身在 `-d` dry-run 下仍然會顯示同樣的錯誤——那不是我們
能修的範圍，且它不影響真正的 rotation cron 行為，只影響 `-d` 這種預覽/驗證
路徑，但既然我們的 spec C14 要驗證「dry-run 不出錯」，我們自己的檔案就該
加上這個宣告讓檢查有意義。）

### 5.5 五台正式站台的 logrotate 全機中止：`/var/log/syslog` 被兩份 policy 檔重複宣告

2026-08-06，五台主機（`it-core`、`lkvs-ovx2`、`vlm`、`pro6k-edge`、
`dt-port6000`）在幾乎同一時間（UTC 00:00 前後，`dt-port6000` 晚一輪，UTC
16:00）出現 logrotate 失敗。逐台看 journal 的根因都一樣：

```
syslog:2 duplicate log entry for /var/log/syslog
```

**根因**：這五台上同時存在兩份 logrotate policy 檔，都宣告了
`/var/log/syslog`：

- `/etc/logrotate.d/rsyslog` —— Ubuntu `rsyslog` 套件內建的預設檔，實測內容
  是把 `/var/log/syslog`、`/var/log/mail.log`、`/var/log/kern.log`、
  `/var/log/auth.log`、`/var/log/user.log`、`/var/log/cron.log` 全部列在
  同一個共用 block 裡。
- `/etc/logrotate.d/syslog` —— 本 playbook Step 5 自己 render 的檔案，同樣
  管 `/var/log/syslog`（Debian family 上 `audit_syslog_path` 就是這個路徑）。

logrotate 讀 `/etc/logrotate.conf` 的 `include /etc/logrotate.d` 時，一旦同一
個路徑在兩份檔案裡出現，會直接整個 run 回報 error、退出 `status=1`——不是只
跳過衝突的那個路徑，而是**整台機器所有 log 都不再輪替**（`auth.log`、
`kern.log`、`mail.log`... 全部受影響，不只 syslog 自己）。另外查證：

- `/etc/logrotate.d/auditd`（管 `/var/log/audit/audit.log`）內容正常，不在
  衝突範圍內——`auditd` 自己建的 `/var/log/audit` 目錄權限較嚴，且路徑跟
  `rsyslog`/`syslog` 兩份檔案都不重疊。
- 五台在對應時間窗都查不到 AVC；`getenforce`/`/sys/fs/selinux` 在這些環境
  不存在——手上證據不支持「SELinux `logrotate_t` → `auditd_log_t` 被擋」這個
  假設，`lkvs-ovx2` 曾出現過的 AVC 說法對不上這次事件的時間點/環境，不能拿
  來解釋這次的 service failure。

**修法**（`playbooks/apply/audit-log-forwarding-apply.yml` Step 5a–5d，
v1.3 版最初只蓋 Debian family，v1.4 版擴大到 RedHat family——見下方
「5.5.1 後續發現」）：不是整份刪掉 `/etc/logrotate.d/rsyslog`（那會連
`mail.log`/`kern.log`/`auth.log`/`user.log`/`cron.log` 的輪替都一起丟掉），
而是先數一下這份 distro 檔案裡，除了 `audit_syslog_path` 之外還剩幾個其他
路徑：

- 還有其他路徑（實測 Ubuntu 24.04 就是這種情況，剩 5 個）→ 只用
  `lineinfile` 移除 `/var/log/syslog` 這一行，其他路徑跟共用的 block（`{
  ... postrotate ... }`）原封不動留給 distro 自己管。
- 沒有其他路徑（該檔案本來就只列這一個路徑）→ 整份 `file: state=absent`
  刪掉，因為只移除路徑行會留下一個沒有檔名的空 block，logrotate 解析會噴
  `lines must begin with a keyword or a filename` 這個新錯誤——比原來的
  duplicate 更糟。

兩種分支都在本機用一個 repro（`/etc/logrotate.d/` 底下放兩份都宣告同一個
假路徑的檔案）驗證過：修前 `logrotate -d` 回報
`error: syslog:1 duplicate log entry for ...` 且 `exit_rc=1`；修後（無論是
「移除一行、留其他路徑」還是「整份刪除」）`exit_rc=0`，且原本共用 block 裡
的其他路徑仍然存在、仍會被輪替。

**回歸檢查**：新增 C20，直接掃描整個 `/etc/logrotate.d/` 目錄找重複路徑
（`grep -rhoE '^/[^ {]+' /etc/logrotate.d/ | sort | uniq -d`，非空即 fail），
不像原本的 C14 只對本模組自己管理的兩個檔案做 dry-run。C14 保留原範圍不變：
如果 C20 改成對整個 `/etc/logrotate.conf` 做 `logrotate -d`，會重新踩到
§5.4 那個「distro 自己的 `/etc/logrotate.d/rsyslog` 沒加 `su` 宣告，`-d`
下永遠對 `/var/log` 的 group-writable 報 insecure-permissions」的已知雜訊
（而且這次波及的路徑更多，因為那份檔案本來就管六個路徑，不是只有
`/var/log/syslog`）——純粹的路徑重複掃描才是對兩種問題都精準的解法。

#### 5.5.1 後續發現（2026-08-06，minimal-poc round-19 clean-room 重建）：RedHat family 也有同一個 bug

v1.3 的 Step 5a–5d 只在 `ansible_os_family == "Debian"` 時檢查
`/etc/logrotate.d/rsyslog`，隱含假設是「只有 Ubuntu 的 `rsyslog` 套件會把
`/var/log/syslog` 跟其他路徑塞進同一個內建檔案」。minimal-poc 3-VM 重建
（`freeipa-server` 是 AlmaLinux 9）跑新增的 C20 時，在這台上實測抓到同一種
bug：AlmaLinux 的 `rsyslog-logrotate` RPM 套件同樣把 `/etc/logrotate.d/`
底下一個叫 `rsyslog` 的檔案內建成共用 block，只是列的路徑換成 RHEL 這邊的
預設稽核日誌集合：

```
/var/log/cron
/var/log/maillog
/var/log/messages
/var/log/secure
/var/log/spooler
{
    missingok
    sharedscripts
    postrotate
        /usr/bin/systemctl -s HUP kill rsyslog.service >/dev/null 2>&1 || true
    endscript
}
```

而本 playbook 在 RedHat family 上 `audit_syslog_path` 解析成
`/var/log/messages`（見 §1.5），Step 5 render 的 `/etc/logrotate.d/syslog`
也管這個路徑——跟 Debian 案例一模一樣的跨檔案重複宣告，只是路徑跟檔名
（distro 內建檔案剛好兩邊都叫 `rsyslog`）不同。

**修法**：拿掉 Step 5a–5d 的 `ansible_os_family == "Debian"` 限制，改成只靠
`distro_rsyslog_logrotate.stat.exists` 把關——因為兩個 family 內建檔案剛好
都叫 `rsyslog`、格式都是「多行路徑 + 一個共用 block」，同一套
`grep -vFx`/`lineinfile` 移除單行的邏輯兩邊通用，不需要另外分支。已在
`freeipa-server` 實測：`--check --diff` 預覽正確只會刪掉
`/var/log/messages` 這一行、保留其他 4 個路徑；真套用 `changed=1`；
`changed=0` 冪等重跑；`pilot verify docs/verification/audit-log-forwarding.md`
在 `client-vm`/`freeipa-server`/`nexus` 三台上 C20（連同其餘 19 條）全部
`PASS`（60/60）。

這個發現本身印證了 C20「掃全目錄」比原本 C14「只查自己兩個檔案」更有用的
設計初衷——如果只驗證本模組自己的 `auditd`/`syslog` 兩個檔案語法正確，
AlmaLinux 上這個新的跨檔案重複永遠不會被抓到。

---

## 6. 常見問題

- **C4/C5/C6/C7/C8/C9 fail（規則不存在）**：確認
  `playbooks/templates/audit.rules.j2` 有正確 render 到
  `/etc/audit/rules.d/99-custom.rules`（`sudo cat` 該檔）。
- **C10 fail（規則沒載入核心）**：手動 `sudo augenrules --load` 後
  `sudo auditctl -l` 確認；apply playbook 每次都會呼叫 `augenrules --load`，
  若規則檔語法有誤這一步會直接 fail（`changed_when: false` + rc gate）。
- **C11 fail**：先確認 §5.1 的規則順序沒有重演（`sudo auditctl -l` 看
  `/usr/bin/sudo` watch 是否排在 setuid/setgid 泛用規則前面）。
- **C15/C16/C17 fail（轉送設定）**：先確認套用時有沒有帶
  `-e siem_forward_host=<log-server 當下 IP>`——v1.1 起這個變數選填，沒帶
  的話 apply 會**照設計**跳過轉送設定（見 §2.2），這時 C15-C17 fail 是
  預期行為，不是 bug。有帶的話再確認 `/etc/hosts` 有
  `<log-server IP>  siem-log-server` 這行（`getent hosts siem-log-server`）
  ——vm-target 每次 `up` 都是新 IP，重跑前務必重新查詢。
- **C14 fail（logrotate dry-run 有 "insecure permissions" 錯誤）**：見
  §5.4——確認 `/etc/logrotate.d/syslog` 有 `su root syslog` 這行。
- **§4 cross-check 收不到**：先確認 log-server 自己的 selftest（C9/C10）
  過，再確認這台的 `siem-log-server` 別名解析正確，最後確認雙方
  `ping`/`nc -vz <ip> 514` 網路可達。
- **懷疑某個 PASS 是不是巧合式假陽性**：看 NDJSON 的 `detail` 欄位——數字
  Expected 的 row，真正被 matcher 解析出來的會顯示
  `"rc-from-stdout=N matches expected M"`；如果看到單純
  `"rc=N matches expected M"`（沒有 `-from-stdout`），代表這條 row 用的
  Command 沒有 `; echo $?`/`&& echo 0 || echo 1` 這種需要從 stdout 才能還原
  真實結果的寫法（例如直接用原生 rc 的指令），這種情況本身是正常的，只有
  「明明用了 echo 迴避寫法、卻還是 `rc=` 沒有 `-from-stdout`」才代表 §5.3
  的 matcher bug 復發了。
