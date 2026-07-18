# Runbook — wazuh-manager（Wazuh single-node：manager + indexer + dashboard，Docker 部署，CVE 掃描，選填轉送 SIEM）

> 撰寫日期：2026-07-06 (UTC)；v2.0 Docker 化改寫同日
> 對齊：`docs/verification/wazuh-manager.md`（v2.0）、`playbooks/apply/wazuh-manager-apply.yml`
> 維護者：sre

---

## 0. 目標與範圍

在一台獨立的 Ubuntu 24.04 vm-target 上以 **Docker** 部署 Wazuh single-node
（manager + indexer + dashboard 三個官方容器，官方 `wazuh-docker` 發行包 +
官方憑證產生容器 + compose）：接收 `wazuh-fim.md` agent 送來的
FIM(syscheck)/who-data 事件、跑規則引擎產生告警、跑 CVE 弱點掃描
（vulnerability-detection，需要 indexer 儲存/關聯結果），選填把告警轉送至
中央 SIEM（`docs/verification/log-server.md`）。

本 runbook 是 `docs/verification/wazuh-fim.md`（agent 端）的前置依賴——agent
端註冊的目標就是這台（1514/1515 埠由 compose 映射到 host，agent 端**不需要**
知道 manager 是容器還是原生安裝）。

v1.0（官方 `wazuh-install.sh -a` 原生安裝）→ v2.0（Docker）的動機與取捨見
spec §1；v1.0 實測踩到的磁碟事故教訓（60GB 規格）原樣沿用，見 §5.1。

---

## 1. §0.5 事實快照（AGENTS.md §2）

```
$ go run ./cmd/pilot vm-target list
NAME           STATUS   IP             VCPU  MEM(MiB)  DISK(GiB)  CREATED
log-server     running  192.168.122.5  2     2048      20         2026-07-06 21:59:38
wazuh-manager  running  192.168.122.6  4     8192      60         2026-07-06 21:57:32

$ go run ./cmd/pilot vm-target show-inventory --name wazuh-manager
all:
  hosts:
    wazuh-manager:
      ansible_connection: ssh
      ansible_host: 192.168.122.6
      ansible_user: ubuntu
      ...
```

**規格對齊**：vm-target 的 inventory 只有單一 host key，playbook
`hosts: "{{ target_group | default('wazuh-manager') }}"` 直接命中，不需要
`-e target_group=` override（同 `log-server.md` 的設計）。

無 vault 依賴——官方 compose 檔的管理者密碼是**寫死的出廠預設值**
（sandbox 可接受；正式站台上線前必須照官方文件手動變更，見 spec §5，這是
相對 v1.0 隨機密碼的已知退步）。

> ⚠️ 工具層陷阱：需要多台 vm-target 時**循序** `up`，不要兩個 `vm-target up`
> 並行——state file 是整檔 read-modify-write，並行會 last-writer-wins,其中
> 一台的 state 條目會消失（libvirt domain 還在，變孤兒，要用 `virsh` 手動清）。
> 本次實測撞到一次。

---

## 2. 部署（apply）

### 2.1 docker preflight（前置依賴，先跑一次）

```bash
go run ./cmd/pilot vm-target up --name wazuh-manager \
    --ssh-user ubuntu --disk 60 --memory 8192 --vcpus 4 \
    --ssh-timeout 8m --boot-timeout 8m

go run ./cmd/pilot vm-target run --name wazuh-manager \
    playbooks/apply/docker-apply.yml \
    -e target_group=all
# PLAY RECAP: ok=5 changed=2 failed=0 skipped=2

go run ./cmd/pilot vm-target verify --name wazuh-manager docs/verification/docker.md
# verdict: **PASS**  (pass=8 fail=0 skip=0)
```

（docker.md 的 C6 在這次 preflight 撞出一個既有 spec bug 並已修正，見 §5.3。）

> 2026-07-17：docker preflight 改用獨立的 `playbooks/apply/docker-apply.yml`
> （原本是 `core-infra-provider-apply.yml -e infra_role=docker`），見
> `docs/runbooks/docker.md`；任務內容不變，只是不再跟 dns/ntp 共用同一支檔案。

### 2.2 首次 apply（不轉送，log server 尚未存在）

```bash
go run ./cmd/pilot vm-target run --name wazuh-manager \
    playbooks/apply/wazuh-manager-apply.yml
```

**真實輸出**（2026-07-06，60GB/8192MB/4vCPU VM，docker preflight 已過；
首次會拉三個官方 image ~3-4GB，indexer 首次初始化 ~1 分鐘由 Step 11 的
retry 吸收）：

```
TASK [Pre-flight: docker engine is up (spec docs/verification/docker.md)] ******
ok: [wazuh-manager]
TASK [Step 1: Set vm.max_map_count=262144 (indexer requirement, persistent)] ***
ok: [wazuh-manager]        # 本輪為 ok 因為同 VM 曾套用過;全新主機為 changed
TASK [Step 2: Ensure /opt/pilot/wazuh-docker exists] ***************************
changed: [wazuh-manager]
TASK [Step 3: Download the official wazuh-docker release bundle (spec C1-C3)] ***
changed: [wazuh-manager]
TASK [Step 4: Unpack the release bundle (spec C1-C3)] **************************
changed: [wazuh-manager]
TASK [Step 5: Generate the indexer TLS cert chain (official generator; spec C1-C3)] ***
changed: [wazuh-manager]
TASK [Step 6: Pin siem-log-server ->  in /etc/hosts (spec C10)] ****************
skipping: [wazuh-manager]
TASK [Step 7: Append <syslog_output> block to wazuh_manager.conf (spec C11)] ***
skipping: [wazuh-manager]
TASK [Step 8: Compose up the official single-node project (spec C1-C3)] ********
changed: [wazuh-manager]
TASK [Step 9: Probe the live in-container forward config (drift check; spec C11)] ***
skipping: [wazuh-manager]
TASK [Step 10: Wait for agent port 1514/tcp (wazuh-remoted; spec C5)] **********
ok: [wazuh-manager]
TASK [Step 11: Wait for the indexer HTTPS API to answer 401 (spec C4)] *********
FAILED - RETRYING: ... (3 次 retry 後就緒)
ok: [wazuh-manager]
PLAY RECAP *********************************************************************
wazuh-manager              : ok=10   changed=5    unreachable=0    failed=0    skipped=5    rescued=0    ignored=0
```

部署後的容器（名稱是確定值：project=`single-node` + 官方 service 名）：

```
$ sudo docker ps
NAMES                           IMAGE                          STATUS
single-node-wazuh.manager-1     wazuh/wazuh-manager:4.14.1     Up ...
single-node-wazuh.dashboard-1   wazuh/wazuh-dashboard:4.14.1   Up ...
single-node-wazuh.indexer-1     wazuh/wazuh-indexer:4.14.1     Up ...
```

### 2.3 補上轉送（log server 就緒後）＋一次跑完 verify/冪等

首選 `vm-target test`（AGENTS.md §1.4：syntax → snapshot → apply → verify →
冪等）：

```bash
go run ./cmd/pilot vm-target test --name wazuh-manager \
    --playbook playbooks/apply/wazuh-manager-apply.yml \
    --spec docs/verification/wazuh-manager.md \
    --verify-timeout 60 \
    -- -e siem_forward_host=192.168.122.5
```

**真實輸出**（2026-07-06，接在 §2.2 之後補轉送；apply 階段 Step 6/7 changed、
Step 9 偵測到容器內尚無轉送區塊 → Step 9a recreate manager 容器 →
Step 9b 收斂斷言 ok；verify 11/11；冪等第二次 apply）：

```
TASK [Step 9: Probe the live in-container forward config (drift check; spec C11)] ***
ok: [wazuh-manager]
TASK [Step 9a: Recreate wazuh.manager so /wazuh-config-mount re-injects the config (spec C11)] ***
skipping: [wazuh-manager]
TASK [Step 9b: Assert the live forward config converged after recreate (spec C11)] ***
skipping: [wazuh-manager]
PLAY RECAP *********************************************************************
wazuh-manager              : ok=12   changed=0    unreachable=0    failed=0    skipped=3    rescued=0    ignored=0

✓ Idempotency check passed (changed=0)
🎉 ALL TESTS PASSED SUCCESSFULLY!
```

（上面截錄的是**冪等第二輪**——穩定態下 Step 9 的漂移探測一次就過、
9a/9b 跳過、全程 changed=0。第一輪 apply 的漂移修復路徑輸出見 §5.2。）

---

## 3. 驗證（spec C1–C11）

```bash
go run ./cmd/pilot vm-target verify --name wazuh-manager \
    docs/verification/wazuh-manager.md
```

**真實輸出 — §2.2 之後（未轉送，預期 C10/C11 fail）**：

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

**真實輸出 — 轉送啟用之後（全部 11 條）**：

```
verdict: **PASS**  (pass=11 fail=0 skip=0)
```

（11 rows 全部 `rc-from-stdout=0 matches expected 0`。）全部 rows 都是
`rc-from-stdout=`（不是回退到 ansible 進程自己的 exit code），代表這是真正
被 matcher 檢驗過的 PASS。C10/C11 的 fail 路徑也在 §2.2 的未轉送情境真的
跑出來過——兩條 checklist 的 FAIL 路徑都被實測驗證過，不是「只會回報 PASS
的檢查」。

---

## 4. 跨主機 cross-check（轉送鏈路：manager 告警 → 轉送到 log-server 落地）

spec 本身不驗證端到端轉送（C11 只驗證設定生效），必須跨主機實測。v2.0 的
做法**不需要真實 agent**：官方容器的 `ossec.conf` 出廠就監控
`/var/ossec/logs/active-responses.log`（syslog 格式），把一行完整 syslog
格式的 sshd 失敗登入寫進去，規則引擎就會走完「decode → 規則比對 → 告警 →
csyslogd 轉送」全鏈路：

```bash
# 1. manager 端:注入一行 syslog 格式測試訊息到被監控的檔案(容器內)
go run ./cmd/pilot vm-target exec --name wazuh-manager -- \
    sudo docker exec single-node-wazuh.manager-1 sh -c \
    'echo "Jul  6 14:40:00 wazuh-manager sshd[9999]: Failed password for invalid user pilot-forward-test from 10.9.9.9 port 4242 ssh2" >> /var/ossec/logs/active-responses.log'

# 2. manager 端:確認告警已生成(容器內 alerts.json)
go run ./cmd/pilot vm-target exec --name wazuh-manager -- \
    sudo docker exec single-node-wazuh.manager-1 sh -c \
    'grep -m1 "pilot-forward-test" /var/ossec/logs/alerts/alerts.json'

# 3. log-server 端:確認告警被轉送落地
go run ./cmd/pilot vm-target exec --name log-server -- \
    sudo grep -m1 'pilot-forward-test' /var/log/syslog
```

**真實輸出（2026-07-06T14:21:28Z）— manager 端告警**（節錄關鍵欄位）：

```json
{"rule":{"level":5,"description":"sshd: Attempt to login using a non-existent user","id":"5710",
  "mitre":{"id":["T1110.001","T1021.004"],"tactic":["Credential Access","Lateral Movement"]}},
 "agent":{"id":"000","name":"wazuh.manager"},
 "full_log":"Jul  6 14:40:00 wazuh-manager sshd[9999]: Failed password for invalid user pilot-forward-test from 10.9.9.9 port 4242 ssh2",
 "decoder":{"parent":"sshd","name":"sshd"},
 "data":{"srcip":"10.9.9.9","srcuser":"pilot-forward-test"},
 "location":"/var/ossec/logs/active-responses.log"}
```

**真實輸出 — log-server 端**（同一筆告警，透過 `<syslog_output>` 轉送）：

```
2026-07-06T14:21:28+00:00 wazuh ossec: Alert Level: 5; Rule: 5710 - sshd: Attempt to login using a non-existent user; Location: wazuh-manager->/var/ossec/logs/active-responses.log; ...; srcip: 10.9.9.9; Jul  6 14:40:00 wazuh-manager sshd[9999]: Failed password for invalid user pilot-forward-test from 10.9.9.9 port 4242 ssh2
```

**落地在 log-server 的 `/var/log/syslog`（rsyslog 出廠萬用檔），不是
`audit-log-forwarding.md` 專用的 `/var/log/siem/<host>/` 分檔目錄**——
與 v1.0 相同的行為與取捨，根因與不改 `log-server.md` 的理由見 §5.5。

**完整的 agent FIM+who-data 鏈路**（agent 端改檔案 → manager 告警含
who-data → 轉送）與 v1.0 相同，見 `docs/runbooks/wazuh-fim.md` §4——agent
連的 1514/1515 埠由 compose 映射，agent 端流程完全不變；manager 端查
alerts.json 的指令改成上面的 `docker exec` 形式即可。

---

## 5. 踩過的雷（實測 vm-target 時發現）

### 5.1 （v1.0 沿用）CVE 弱點掃描把磁碟塞爆時完全沒有服務層級徵兆——所有告警靜默停產

v1.0 用 20GB 磁碟實測時，CVE feed（解壓後常駐 ~7-9GB、解壓中暫存單檔 8.4GB）
把磁碟吃到 100%，`wazuh-db`/`wazuh-analysisd` 持續報
`SQLite: database or disk is full`，但服務狀態全程顯示正常——只有告警安靜地
生不出來。**Docker 化不改變這件事**：CVE feed 現在位於
`single-node_wazuh_queue` named volume（`/var/lib/docker/volumes/` 底下，
同一顆磁碟），容器 `running` 狀態跟當年的 `systemctl is-active` 一樣不會
反映內部寫入失敗。診斷：
`sudo docker exec single-node-wazuh.manager-1 tail -n 40 /var/ossec/logs/ossec.log`
看 `disk is full`，或 `df -h /`。修法：磁碟給足（60GB 起），C8 這條
checklist 就是當年事故直接生出來的。

### 5.2 官方 manager image「restart 不等於 recreate」：單純 restart 時 config 注入永遠不會發生——這是 v2.0 最大的雷

**症狀**：host 端 `config/wazuh_cluster/wazuh_manager.conf` 已含
`<syslog_output>` 區塊、bind mount 進容器的
`/wazuh-config-mount/etc/ossec.conf` 也看得到，但
`docker compose restart wazuh.manager` 之後容器內生效的
`/var/ossec/etc/ossec.conf` 就是沒有那個區塊，C11 一直 fail。第一版
playbook 用 `state: restarted` 重啟，`vm-target test` 直接抓到
（pass=10 fail=1，自動 rollback）。

**根因**（讀容器內 `/etc/cont-init.d/0-wazuh-init` + `docker logs -t` 對時間
戳追出來的）：官方 image 的 init 腳本在**首次開機**結尾
`rm -rf /var/ossec/data_tmp`（節省空間的設計）。之後任何一次**單純 restart**：

```
2026-07-06T14:10:20 Installing /var/ossec/var/multigroups
2026-07-06T14:10:20 Error executing command: 'cp -ar /var/ossec/data_tmp/permanent/var/ossec/var/multigroups/. /var/ossec/var/multigroups'.
2026-07-06T14:10:20 Exiting.
2026-07-06T14:10:20 [cont-init.d] 0-wazuh-init: exited 1.
```

`mount_permanent_data` 看到 `multigroups` 這個 named volume 是空的（沒建過
agent group 時本來就空），想從已被刪掉的 `data_tmp` 補檔 → `cp` 失敗 →
init 腳本 exit 1 → 排在後面的 `mount_files`（把 `/wazuh-config-mount/*` 覆蓋
進 `/var/ossec` 的那一步）**永遠不會執行**。而且 s6 在 cont-init 失敗後仍
繼續把服務拉起來，容器看起來一切正常——設定漂移完全靜默。

**修法**（現行 playbook 設計，三個 task）：

1. **Step 9 漂移探測**：`docker exec` 直接 grep 容器內**生效中**的
   `/var/ossec/etc/ossec.conf`（不是 host 檔、不是 bind mount），才是真相。
   不能只靠「host 檔本輪有沒有 changed」當 gate——上一輪注入失敗的漂移
   永遠不會被修復（不收斂）。
2. **Step 9a 用 recreate 不用 restart**（`docker_compose_v2` 的
   `recreate: always` + `services: [wazuh.manager]`）：重建的容器有全新的
   image 檔案系統，`data_tmp` 存在，init 全程跑完、`mount_files` 正常注入。
3. **Step 9b 收斂硬斷言**：recreate 後再 grep 一次，還是沒有就讓 playbook
   FAIL 進 rescue，不留靜默漂移。

**真實輸出**（漂移狀態下的修復路徑；probe 6 次 retry 確認漂移 → recreate →
收斂）：

```
TASK [Step 9: Probe the live in-container forward config (drift check; spec C11)] ***
FAILED - RETRYING: ... (6 retries left) ... (1 retries left)
TASK [Step 9a: Recreate wazuh.manager so /wazuh-config-mount re-injects the config (spec C11)] ***
changed: [wazuh-manager]
TASK [Step 9b: Assert the live forward config converged after recreate (spec C11)] ***
FAILED - RETRYING: ... (12 retries left)
ok: [wazuh-manager]
PLAY RECAP *********************************************************************
wazuh-manager              : ok=14   changed=1    unreachable=0    failed=0    skipped=1
```

regression test 鎖了「playbook 不准出現 `state: restarted`、必須有
`recreate: always`」。附帶教訓:**「重啟後設定會重新注入」這種 entrypoint
行為假設,一定要用 `docker logs -t` 對時間戳實證,不能只讀 entrypoint 原始碼
的 happy path**——`mount_files` 的程式碼確實是每次開機都跑,但它前面有一步
會在非首次開機時把整個 init 弄死。

### 5.3 既有 `docker.md` spec 的 C6 用了 docker Go template——在 `pilot verify` 底下永遠 fail（Jinja 陷阱實例）

跑本角色的 docker preflight verify 時，`docker.md` C6
（`docker network ls --format '{{.Name}}'`）回報 fail、`exit_code=2`。用
`pilot verify --probe` 走完全相同管線重現：

```
rc: 2
"msg": "... Syntax error in template: unexpected '.'"
```

**根因**：`pilot verify` 的每條 Command 都經過 ansible ad-hoc，`{{ }}` 先被
Jinja 模板引擎吃掉，docker 的 Go template 語法直接讓 task FAILED。已修
（`docker.md` v1.1 改用 `awk '$2 == "bridge"'`，regression test 加了
「Command 欄禁用 `{{`」invariant）。本 spec（wazuh-manager v2.0）的容器檢查
一開始就為此避開 `docker inspect -f`，全部用 `docker ps --filter`。

### 5.4 `pilot verify` 是以 `become=true`（root）跑每條 Command——不要假設 ansible 使用者在 docker group

實測 `id ubuntu` 只有 `ubuntu sudo wheel`，**沒有** docker group；spec 裡
`docker ...` 指令不帶 sudo 能過，是因為 verify 管線本身 become=true
（`pilot verify --probe` 的輸出印有 `module: shell (become=true)`），不是
group 成員資格。寫 spec Command 時照這個事實設計；手動 SSH 到目標主機重現
spec 指令時要自己加 `sudo`。

### 5.5 （v1.0 沿用）Wazuh 告警走 `<syslog_output>` 轉送時，落地在 log-server 的一般 `/var/log/syslog`，不是 `/var/log/siem/` 分檔目錄

`wazuh-csyslogd` 送出的 syslog 訊息 facility **不是** `local6`
（`audit-log-forwarding.md` 特別佈線的那個），落進 log-server rsyslog 出廠
預設的萬用規則（`*.*;auth,authpriv.none -/var/log/syslog`）。沒有回頭改
`log-server.md` 新增第三個 facility 路由是刻意的範圍控制（那應該是
`log-server.md` 自己的 v1.1）。目前的設計：Wazuh 告警在 log-server 查
`/var/log/syslog`，auditd 原始日誌在 `/var/log/siem/<host>/`，兩條路徑分開。

### 5.6 （v1.0 沿用，v2.0 重新驗證）多個 `<ossec_config>` 根節點合併 + `wazuh-logtest` 的測試訊息格式

- Wazuh 的 `ossec.conf` parser 允許同一份檔案有多個 `<ossec_config>` 根節點
  並全部合併——官方 `wazuh_manager.conf` 出廠自己就是多段。v2.0 的
  `<syslog_output>` 注入沿用這個機制（`blockinfile` 附加到 host 端檔案
  末端），C11 全 PASS 證明容器內合併行為一致。
- C9 的 `wazuh-logtest` 測試行必須是**完整 syslog 格式**（時間戳 + hostname +
  `sshd[pid]:`），否則 decoder 配對不到、落到泛用規則 1002；斷言字串必須用
  告警門檻以上才印的 `Alert to be generated.`。v2.0 改成
  `docker exec -i single-node-wazuh.manager-1 timeout 15 /var/ossec/bin/wazuh-logtest`
  管線灌 stdin，實測可用（C9 PASS）。

---

## 6. 常見問題

- **C10/C11 fail（沒轉送）**：預期行為（spec §5），沒帶
  `-e siem_forward_host=` 就是如此；補跑一次 apply 帶上這個變數即可——
  playbook 的漂移探測 + recreate 會把設定注入做完（§5.2），不需要重建
  indexer/dashboard 或重新產生憑證。
- **host 端 conf 改了但 C11 還是 fail**：先確認你是用 playbook 收斂的，
  不是手動 `docker compose restart`——單純 restart 不會重新注入設定
  （§5.2 的根因）。手動救急：`cd /opt/pilot/wazuh-docker/wazuh-docker-<版本>/single-node
  && sudo docker compose -p single-node up -d --force-recreate wazuh.manager`。
- **想在 log-server 找 Wazuh 轉送過來的告警**：查 `/var/log/syslog`
  （§4/§5.5），不是 `/var/log/siem/`。
- **C1-C9 也 fail、告警疑似沒在產生**：先
  `sudo docker exec single-node-wazuh.manager-1 tail -n 100 /var/ossec/logs/ossec.log`
  看有沒有 `disk is full`（§5.1），再 `df -h /`。
- **想看 dashboard / 確認 CVE 掃描結果**：`https://<host>/`（443），出廠帳密
  見官方 compose 檔 env（`admin`/`SecretPassword`——sandbox 預設，正式站台
  必須先改掉，spec §5）。
- **想升級 Wazuh 版本**：改 `-e wazuh_docker_version=<新版>` 重跑 apply
  （新發行包解到新目錄、compose 拉新 tag image）。named volumes 屬於
  compose project（`single-node_*`），不隨發行包目錄改變，資料保留;正式
  站台升級前先照官方 release note 確認 indexer 相容性。
- **想整組拆掉重來**：`cd <single-node 目錄> && sudo docker compose -p
  single-node down --volumes && sudo rm -rf /opt/pilot/wazuh-docker`
  （`--volumes` 會刪掉所有 Wazuh 資料，是破壞性操作,需要人工確認後手動下）。
