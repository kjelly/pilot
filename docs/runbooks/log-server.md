# Runbook — log-server（rsyslog 中央日誌接收端）

> 撰寫日期：2026-07-06 (UTC)
> 對齊：`docs/verification/log-server.md`（v1.0）、`playbooks/apply/log-server-apply.yml`
> 維護者：sre

---

## 0. 目標與範圍

在一台獨立的 Ubuntu 24.04 vm-target 上部署 **rsyslog 中央 SIEM 接收端**：
監聽 UDP/TCP 514，收其他主機（如 `audit-log-forwarding.md` 的 client）轉送的
`auth,authpriv.*`（一般認證日誌）與 `local6.*`（auditd 稽核，經 audisp-syslog）
，依來源 `%HOSTNAME%` 分檔落地到 `/var/log/siem/<hostname>/{audit,auth}.log`。

本 runbook 是 `docs/verification/audit-log-forwarding.md`（client 端）的前置
依賴——client 端的轉送目標就是這台。

---

## 1. §0.5 事實快照（AGENTS.md §2）

```
$ go run ./cmd/pilot vm-target list
log-server   running  192.168.122.6  2  2048  20  2026-07-06

$ go run ./cmd/pilot vm-target show-inventory --name log-server
all:
  hosts:
    log-server:
      ansible_connection: ssh
      ansible_host: 192.168.122.6
      ansible_user: ubuntu
      ...
```

**對齊決定**：vm-target 的 inventory 只有單一 host key（即 VM 名稱本身，
`vm-target-basics.md` 有記載），playbook `hosts: "{{ target_group |
default('log-server') }}"` 直接用 host 名稱當 pattern 命中，**不需要**
`-e target_group=` override（跟 freeipa-server/freeipa-client 用 `all` 的例外
情形不同——這裡 spec §1 宣告的 group 名稱本來就跟 vm-target host key 同名）。

無 vault 依賴（本 spec 不含任何機密）。

---

## 2. 部署（apply）

```bash
go run ./cmd/pilot vm-target up --name log-server \
    --ssh-user ubuntu --disk 20 --memory 2048 --vcpus 2 \
    --ssh-timeout 8m --boot-timeout 8m

go run ./cmd/pilot vm-target run --name log-server \
    playbooks/apply/log-server-apply.yml
```

**真實輸出**（2026-07-06，全新 VM 首次 apply）：

```
TASK [Step 1: Install rsyslog (Debian family)] *********************************
ok: [log-server]
TASK [Step 2: Ensure /var/log/siem exists] *************************************
changed: [log-server]
TASK [Step 3: Render 10-siem-receiver.conf (imudp/imtcp + %HOSTNAME% dynaFile routing)] ***
changed: [log-server]
TASK [Step 4: Render /etc/logrotate.d/siem-incoming] ***************************
changed: [log-server]
TASK [Step 5: Validate the effective rsyslog config (rsyslogd -N1)] ************
ok: [log-server]
TASK [Step 6: Ensure rsyslog enabled + started (spec C2, C6, C7)] **************
ok: [log-server]
TASK [Step 6a: Restart rsyslog only if the receiver config actually changed] ***
changed: [log-server]
PLAY RECAP *********************************************************************
log-server                 : ok=8    changed=4    unreachable=0    failed=0    skipped=4    rescued=0    ignored=0
```

---

## 3. 驗證（spec C1–C12）

```bash
go run ./cmd/pilot vm-target verify --name log-server \
    docs/verification/log-server.md --timeout 40
```

**真實輸出**（2026-07-06T03:47Z 重驗，verdict **PASS pass=12 fail=0
skip=0**——此為 §5.4 matcher 修復後重跑的證據，C1/C2/C4/C5/C6/C7/C12 的
`detail` 都已是 `rc-from-stdout=...`，代表這次是真的被檢驗過，而非修復前
巧合式的 `rc=0 matches...`，詳見 §5.4）：

```json
{"id":"C1","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C2","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C3","status":"pass","detail":"expected: present (rc=0)"}
{"id":"C4","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C5","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C6","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C7","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
{"id":"C8","status":"pass","detail":"expected: present (rc=0)"}
{"id":"C9","status":"pass","detail":"stdout contains \"PILOT-SIEM-SELFTEST-AUDIT\""}
{"id":"C10","status":"pass","detail":"stdout contains \"PILOT-SIEM-SELFTEST-AUTH\""}
{"id":"C11","status":"pass","detail":"expected: present (rc=0)"}
{"id":"C12","status":"pass","detail":"rc-from-stdout=0 matches expected 0"}
```

**冪等驗證**（同指令再跑一次 apply，PLAY RECAP）：

```
log-server                 : ok=7    changed=0    unreachable=0    failed=0    skipped=5    rescued=0    ignored=0
```

---

## 4. 跨主機 cross-check（訊息真的從別台主機收到）

C9/C10 只驗證**本機注入**（見 `log-server.md` §2 註記）。要證明「別台主機轉送
過來的真的有收到」，實際從 `audit-log-forwarding` client 端注入、在這台讀檔：

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

兩筆訊息都正確依來源 `%HOSTNAME%`（`audit-log-forwarding`）分檔落地，證明
`local6.*` 與 `auth,authpriv.*` 的跨主機轉送鏈路（client `@@` TCP 轉送 →
這台 `imtcp` 接收 → RainerScript 路由）確實通。

---

## 5. 踩過的雷（實測 vm-target 時發現，均已修進 playbook）

### 5.1 `/var/log/siem` 一開始用 `root:root 0755` → rsyslog 寫不進去

第一次 apply 後，C9/C10 verify 失敗，`journalctl -u rsyslog` 顯示：

```
error during config processing: omfile: creating parent directories for file
'/var/log/siem/log-server/auth.log' failed: Permission denied
```

原因：Ubuntu 的 rsyslog 套件把 `rsyslogd` 設成用**非特權使用者 `syslog`**
執行（`ps -o user,cmd -C rsyslogd` 可確認），但落地根目錄一開始建成
`root:root 0755`，`syslog` 使用者無法在裡面建立 `createDirs="on"` 要求的
per-hostname 子目錄。

**修法**：`log-server-apply.yml` 的 `siem_log_owner` 變數依
`ansible_os_family` 決定擁有者（Debian → `syslog`，RedHat → `root`，因為
RHEL/EL 傳統上 `rsyslogd` 用 root 執行、沒有專屬 `syslog` 系統帳號），
`/var/log/siem` 目錄一律用這個變數當 owner/group。

### 5.2 `systemd: state: restarted` 每次都回 `changed` → 冪等檢查必掛

`pilot vm-target test` 的 L6 冪等檢查（AGENTS.md §1.4）第一次跑就抓到：
第二次 apply 仍然 `changed=1`，因為 `state: restarted` **本質上不是冪等操作**
——它每次都真的執行一次 restart 動作，不管有沒有必要。

**修法**：拆成兩個 task——`state: started` 確保服務起著（冪等），另一個
`state: restarted` **只在** `siem_receiver_conf_result is changed` 時才跑
（比照 `freeipa-client-apply.yml` 對 sssd 的處理方式）。

### 5.3 `pilot vm-target test` 的 auto-snapshot/rollback 後，SSH 卡在「等待 sudo 提示」逾時

連續兩次 `vm-target test` 在 snapshot→rollback 之後，緊接著的下一次 apply
在第一個 `become: true` 的 task 就卡住：

```
[ERROR]: Task failed: Timeout (32s) waiting for privilege escalation prompt
fatal: [log-server]: UNREACHABLE!
```

但直接 `vm-target exec -- sudo -n id` 當下完全正常。根因：libvirt
snapshot revert 會讓既有的 SSH **ControlMaster 多工 socket**
（`~/.ansible/cp/pilot-<user>@<host>:<port>`）失效但沒有真的斷線，
ansible 用同一個殭屍 socket 導致後續連線卡死。

**排除步驟**：
```bash
rm -f ~/.ansible/cp/pilot-ubuntu@<vm-ip>:22
```
刪掉該 host 的 ControlMaster socket 檔案後重跑即恢復正常。這不是
playbook 或 spec 的問題，是 snapshot/rollback 操作對既有連線的副作用；
遇到「exec 正常但 ansible-playbook 卡在 become」時，先懷疑這個。

### 5.4 補充（2026-07-06）：C6/C7 在 v1.0 期間其實沒有被真正檢驗過

`audit-log-forwarding.md` 開發到 v1.1 時發現 `pilot verify` 的 ad-hoc
matcher（`internal/tools/verify_spec.go`）有個真實 bug：透過
`vm-target verify`（inventory/ad-hoc 模式）驗證時，數字 Expected 若靠
`cmd; echo $?`／`cmd && echo 0 || echo 1` 這種本 spec 樣板文件推薦的寫法
（本 spec 的 **C6/C7** 正是這樣寫的）取得真實結果，matcher 會解析失敗、
退回比較 ansible ad-hoc 進程自己的 exit code——而這個 idiom 底下那個 exit
code 永遠是 0（最後執行的指令永遠是 `echo`），所以只要 Expected 是 `0`，
**不管遠端真實狀態為何，一律回報 PASS**。也就是說本 runbook §3 最初捕捉的
C6/C7 PASS 證據，是遠端真實狀態剛好等於 expected 的巧合式 PASS，從沒被
matcher 真正檢驗過。

已在 `internal/tools/verify_spec.go` 修好（新增 `unwrapAdhocOneline()`
正確解析 ansible `--one-line` 的 `host | CHANGED | rc=N | (stdout) <val>`
包裝格式），回歸測試見 `internal/tools/verify_spec_match_test.go`。完整
根因分析、修復細節、以及「PASS 是否巧合」的判讀方式（看 NDJSON `detail`
欄位有沒有 `-from-stdout`）見 `docs/runbooks/audit-log-forwarding.md` §5.3
——這裡不重複，只記錄本 spec 也受影響這件事。修復後重新對這台 log-server
跑 `pilot vm-target verify`，C1-C12 依然全數 **PASS**（見 §3 的原始證據），
但現在是真正被檢驗過的 PASS。

---

## 6. 常見問題

- **C6/C7 fail（埠沒監聽）**：確認 rsyslog 真的 active（`systemctl status
  rsyslog`）且設定檔語法正確（`sudo rsyslogd -N1 -f /etc/rsyslog.conf`）。
- **C9/C10 fail（selftest 訊息沒落地）**：先確認 §5.1 的權限問題沒有重演
  （`ls -la /var/log/siem`，owner 應為 `syslog`，Ubuntu）。
- **跨主機轉送收不到（§4 cross-check 失敗）**：先在 client 端確認
  `siem-log-server` 別名解析到正確 IP（`getent hosts siem-log-server`），
  再確認 log-server 這邊防火牆沒擋（拋棄式 vm-target 預設沒開防火牆，
  真實主機才需要檢查 `ufw`/`firewalld`）。
- **想換落地目錄/埠**：`-e siem_log_root=... -e siem_receiver_udp_port=...
  -e siem_receiver_tcp_port=...`，spec 的 hardcoded `514`/`/var/log/siem`
  字串要跟著改（見 spec §1.5）。
