# Runbook — 3 台 VM：FreeIPA + Wazuh + Grafana 監控 demo（`vm-target` + `edit`/`generate`/`deploy` 全真實跑過）

> Status: 13 支 apply playbook 全部真實跑過（v1.1 重新驗證，2026-07-17）；權限管理
> （HBAC allow/deny）與 log/metric 可從 Grafana 查詢兩項都在真實環境上驗證通過。
>
> **v1.1 重新驗證的目的**：`pilot edit`/`pilot deploy` 在 2026-07-17 從 promptui
> 整個改寫成 Bubble Tea（見 `cmd/pilot/cmd/edit_tui.go`/`deploy_tui.go`）。這次
> 重新驗證的重點是確認這份 runbook 的操作方式跟 §7 記錄的 promptui 特有行為
> （`promptui.Select` 丟鍵）在新引擎下是否還準確——3 台 VM 全部砍掉重建，13 支
> 元件全部透過新版 `pilot edit`/`pilot deploy` 重新走過一次 wizard、真實佈署、
> 真實驗證。**這一輪沒有重跑 idempotency**（13 支 playbook 本身的 ansible 邏輯
> 這次沒有改動，v1.0 已經驗證過重跑 idempotent；這輪只驗證「新 UI 引擎能不能
> 正確把同一組決策送給同一組 playbook」，不是重新驗證 ansible 邏輯本身）。
>
> **Dry-run 說明**：跟 v1.0 一樣，每一步都直接跳過 `pilot deploy` 提供的
> `--check --diff` 預覽、直接套用真正的變更（wizard 問「要先預覽嗎？」時答
> `n`）。所以本文沒有真實 dry-run diff 輸出——這是誠實記錄這次「怎麼做」，不是
> 省略掉忘記做。

> 撰寫日期：2026-07-14 (UTC)；v1.1 重新驗證：2026-07-17 (UTC)
> 對齊規範：`docs/verification/freeipa-server.md`、`freeipa-client.md`、
> `docker.md`（`core-infra-provider.md` 的 `infra_role=docker`）、
> `seaweedfs-s3.md`、`prometheus.md`、`thanos-query.md`、
> `alertmanager.md`、`dashboard.md`、`log-shipping.md`、
> `wazuh-manager.md`、`wazuh-fim.md`、`audit-log-forwarding.md`、
> `freeipa-identity`（roster-driven，無獨立 spec 檔）
> 自動化：`playbooks/apply/*.yml`（見上）＋ 一次性 `./tmp/pilot-verify-<slug>/demo/
> {hosts.yml, inventory.yml, group_vars/, .vault/}`（`pilot inventory generate`
> 產出，用完即可整個資料夾刪除——見 `.agents/skills/pilot-trec-verification`）
> 維護者：sre

---

## 0. 一句話目標

用 `pilot vm-target` 建 3 台 VM（AlmaLinux FreeIPA 身份伺服器、Ubuntu
docker+Wazuh+Grafana 監控主機、Ubuntu 模擬用戶端），只透過 `pilot edit` /
`pilot inventory generate` / `pilot deploy` 三個子指令（不手寫
`ansible-playbook` 指令、不手改 YAML）完成整套佈署，並在真實環境上驗證
兩件事：(1) FreeIPA 的 HBAC/sudo 權限管理機制真的有生效（allow + deny
都要真的測到）、(2) client 端的 log 跟站台的 metric 都能透過 Grafana
查到。

---

## 0.5 Fact snapshot (2026-07-17T02:56:37Z, v1.1 重新驗證)

> 以下都是這次重新驗證時重新執行的真實輸出，不是預測值。VM 是這輪重新建的，
> IP 跟 v1.0 不同（libvirt DHCP 重新分配）。

### 環境狀態 — VM 清單

```bash
$ pilot vm-target list
NAME            STATUS   IP             VCPU  MEM(MiB)  DISK(GiB)  CREATED
client-vm       running  192.168.122.6  2     2048      20         2026-07-17 10:14:20
freeipa-server  running  192.168.122.2  2     4096      30         2026-07-17 10:14:15
monitor-vm      running  192.168.122.4  6     12288     80         2026-07-17 10:14:17
```

### 目標/資源集合 — inventory 樹

```bash
$ ansible-inventory -i inventory.yml --graph
@all:
  |--@ungrouped:
  |--@freeipa:
  |  |--@freeipa-server:
  |  |  |--freeipa-server
  |  |--@freeipa-client:
  |  |  |--client-vm
  |  |--@freeipa-server-replica:
  |--@dns:
  |--@ntp:
  |--@docker:
  |  |--client-vm
  |  |--monitor-vm
  |--@keycloak:
  |--@keycloak-db:
  |--@infra-provider:
  |  |--@dns:
  |  |--@ntp:
  |  |--@docker:
  |  |  |--client-vm
  |  |  |--monitor-vm
  |  |--@keycloak:
  |  |--@keycloak-db:
  |--@linux-servers:
  |--@log-server:
  |--@audit-log-forwarding:
  |  |--client-vm
  |--@wazuh-manager:
  |  |--monitor-vm
  |--@wazuh-fim:
  |  |--client-vm
  |--@seaweedfs-s3:
  |  |--monitor-vm
  |--@restic-backup:
  |--@prometheus:
  |  |--monitor-vm
  |--@thanos-query:
  |  |--monitor-vm
  |--@alertmanager:
  |  |--monitor-vm
  |--@dashboard:
  |  |--monitor-vm
  |--@prod:
  |--@staging:
  |--@sandbox:
```

> 跟 v1.0 完全同一個拓樸形狀——`log-server` group 故意留空（見 §1「架構決策」）。

### Secrets — key 名稱（不印值）

```bash
$ grep -oE '^[a-z_0-9]+:' .vault/main.yaml
ipa_admin_password:
grafana_admin_password:
thanos_aws_access_key_id:
thanos_aws_secret_access_key:
alertmanager_config:

$ grep -oE '^[a-z_0-9]+:' .vault/ipa-identity.yaml
ipa_admin_password:
ipa_groups:
ipa_users:
ipa_sudo_rules:
ipa_hostgroups:
ipa_hbac_rules:
ipa_hbac_disable_allow_all:
```

> `alertmanager_config` 是這輪 `pilot inventory generate` 才發現的新 key（v1.0
> 撰寫時的 vault skeleton 沒有這個）——不是這次重寫加的，是 `internal/inventory/
> vault.go` 在 v1.0 之後某次改動新增的 alertmanager vault section；skeleton
> 已經內建一個可用的 null-receiver stub 當預設值，不改也能直接套用。
>
> `.vault/*.yaml` 兩份都是**明文**——sandbox 拋棄式demo 才允許，正式環境一律要
> `ansible-vault encrypt`。

---

## 1. Why

這是一次端到端 dogfooding：驗證 `pilot vm-target` + `pilot edit` +
`pilot inventory generate` + `pilot deploy` 這條「不用手寫
`ansible-playbook` 指令」的路徑，能不能真的撐起一個有意義的多機拓樸
（身份伺服器 + 監控主機 + 模擬用戶端），而不只是單一元件的 demo。

**架構決策（過程中跟使用者確認過，記錄在這裡避免下一個人重新踩一次）**：

1. `log-server-apply.yml` 有一個 `meta: end_play` guard：只要 inventory
   裡**任何地方**出現 `wazuh-manager` group，這支 playbook 就整個跳過
   （不分機器）。使用者確認這是刻意設計——**wazuh-manager 就是這個
   拓樸裡的 log server**，不需要另外疊一份 rsyslog 中央收集器。所以
   `monitor-vm` 的 `roles:` 沒有 `log-server`，`audit-log-forwarding`
   的 `siem_forward_host` 也沒有東西可以自動解析到。
2. 但 `wazuh-manager`（官方 docker image）雖然發布了 UDP 514，
   `ossec.conf` 的 `<remote>` 只定義了原生 agent 協定（`1514/tcp`），
   沒有任何 syslog `<remote>` 監聽——所以 `audit-log-forwarding` 轉送過去
   完全沒有東西在收（見 §6 bug #4）。
3. 解法：`log-shipping-apply.yml`（Promtail agent）本身沒有 wazuh-manager
   guard，`target_group`／`siem_log_root` 都是變數，所以直接把它指到
   `client-vm` 自己（tail 自己的 `/var/log`），不透過 `log-server`／
   `audit-log-forwarding` 這條路徑，一樣把 log 送進 monitor-vm 的 Loki。

---

## 2. Prerequisites

- Host 需要 `/dev/kvm` 存取（`sudo setfacl -m u:$USER:rw /dev/kvm`）、
  一個 active 的 libvirt `default` NAT network、`--vm-dir` 底下
  qemu 使用者可寫（見 `docs/runbooks/vm-target.md` §2.1）。
- `pilot edit` / `pilot deploy` 需要真實 TTY（`term.IsTerminal` 檢查）；
  **v1.1 起改用 `trec drive` 錄影驅動**（`.agents/skills/pilot-trec-verification`），
  取代 v1.0 用的臨時 PTY driver（`tools/ptydrive/`）——兩者行為一致（都是
  透過真實 PTY 自動打字操作），`trec` 額外提供 `SELECT <label>` 這種
  以畫面內容導覽而非硬編 `DOWN <n>` 的選單操作方式，錄影格式跟
  `scriptreplay` 相容。**兩個指令都要帶 `CI=1`**（見 §7）。
- 一份 disposable 的 `hosts.yml`／`group_vars/`／`.vault/`（`pilot edit`
  產出，放在 repo 自己的 `./tmp/` 下，用完即丟）；`inventory.yml`
  用 `pilot inventory generate` 從它展開。
- `freeipa-identity` 需要的 roster（`ipa_users`/`ipa_groups`/
  `ipa_hbac_rules`/`ipa_sudo_rules`）不是 `pilot inventory generate` 自動產生
  的——複製 `playbooks/apply/freeipa-identity.roster.example.yaml`，手動填入
  （`pilot edit` 的 vault 編輯器故意拒絕這種巢狀 YAML，這是工具認可的例外，
  見 §6 bug #3 的說明）。

---

## 3. 佈署（13 支元件，全部經 `pilot deploy`，v1.1 真實重跑）

> 每個元件的表格都是這次 v1.1 重新驗證時 `pilot deploy`（新版 Bubble Tea
> 精靈）真實印出的 PLAY RECAP。順序即實際套用順序（有依賴關係：docker 要
> 先於 wazuh-manager/seaweedfs-s3/prometheus/…；freeipa-server 要先於
> freeipa-client/freeipa-identity；……)。**這輪沒有重跑第二次驗證
> idempotency**——13 支 playbook 的 ansible 邏輯本身這次沒有改動，v1.0 已經
> 驗證過重跑 idempotent（見 v1.0 changelog），這輪的目的是驗證新 UI 引擎，
> 不是重新驗證 ansible 邏輯。

### 3.1 `core-infra-provider`（docker，monitor-vm + client-vm）

```
client-vm                  : ok=7    changed=2    unreachable=0    failed=0    skipped=13
monitor-vm                 : ok=7    changed=2    unreachable=0    failed=0    skipped=13
```

### 3.2 `freeipa-server`

```
freeipa-server              : ok=30   changed=10   unreachable=0    failed=0    skipped=5
```

> `ok`/`changed` 比 v1.0（ok=25 changed=9）略多——`freeipa-server-apply.yml`
> 在 v1.0 之後新增了幾個檢查/收斂 task，屬於預期內的正常演進，不是這次重寫
> 造成的差異（這次重寫完全沒動任何 `playbooks/apply/*.yml`）。

### 3.3 `seaweedfs-s3`

```
monitor-vm                  : ok=11   changed=7    unreachable=0    failed=0    skipped=4
```

> 跟 v1.0 完全一致。`pilot-thanos-metrics` bucket 依然不在
> `seaweedfs-s3-apply.yml` 預設的 `seaweedfs_extra_buckets` 裡——**但這不
> 再是問題**（見 §6 bug #1 更正）：`prometheus-apply.yml`/
> `thanos-query-apply.yml` 各自都已經有一段等冪的「bucket 不存在就建立」
> task，會在它們自己套用時自動處理，不需要在這一步手動介入。v1.1 一開始
> 沿用 v1.0 的手動 `weed shell` 補建，是照抄舊版 runbook 步驟、沒有先確認
> 是否還需要——見 §6 的 regression test，證明手動步驟其實是多餘的。

### 3.4 `alertmanager`

```
monitor-vm                  : ok=8    changed=4    unreachable=0    failed=0    skipped=1
```

> 跟 v1.0 完全一致。

### 3.5 `prometheus`

```
monitor-vm                  : ok=19   changed=9    unreachable=0    failed=0    skipped=2
```

> `-e thanos_s3_target_host=... -e alertmanager_target_host=...` 這兩個都由
> `AutoHostVars` 自動偵測、精靈問「這次要用它嗎？」按預設 Y 即可，只有
> `prometheus_site_label=monitor-vm-site` 需要在「還有其他 -e 變數」手動輸入
> （這個變數本來就沒有安全預設值，見 spec §1.5）。

### 3.6 `thanos-query`

```
monitor-vm                  : ok=15   changed=4    unreachable=0    failed=0    skipped=1
```

> **§6 bug #2 已確認修好**：`thanos_query_http_port` 現在預設值就是
> `10912`（不再是會跟 Prometheus 的 Thanos Sidecar 撞埠的 `10902`），這輪
> 完全沒有手動帶 `-e thanos_query_http_port=` 也沒有撞埠——port 衝突的
> workaround 已經內建成預設行為，見 §6。

### 3.7 `dashboard`（Grafana + Loki）

```
monitor-vm                  : ok=17   changed=11   unreachable=0    failed=0    skipped=1
```

> 同樣受惠於 bug #2 的預設值修復，`dashboard-apply.yml` 的
> `thanos_query_port` 也已經預設 `10912`，無需手動覆寫。跟 v1.0 完全一致。

### 3.8 `wazuh-manager`

```
monitor-vm                  : ok=12   changed=6    unreachable=0    failed=0    skipped=7
```

> 跟 v1.0 完全一致。

### 3.9 `freeipa-client`（client-vm 加入 realm）

```
client-vm                   : ok=24   changed=13   unreachable=0    failed=0    skipped=4
```

> `ipa_server_ip` 依然沒有對應的 `AutoHostVars`，要在「還有其他 -e 變數要帶
> 嗎？」那一步手動輸入 `ipa_server_ip=192.168.122.2`。

### 3.10 `wazuh-fim`（client-vm 加入 Wazuh agent）

```
client-vm                   : ok=15   changed=9    unreachable=0    failed=0    skipped=3
```

> 跟 v1.0 完全一致。`wazuh_manager_host` 這次由 `AutoHostVars` 正確自動偵測到
> monitor-vm 的新 IP，不需要手動輸入。

### 3.11 `freeipa-identity`（HBAC/sudo roster，權限管理測試用資料）

```
freeipa-server               : ok=37   changed=16   unreachable=0    failed=0    skipped=18
```

> **這輪 roster 從一開始就把 `services: [sshd, sudo, sudo-i]` 寫進
> `allow-sysops-ssh` HBAC rule**（v1.0 是先漏了 `sudo`，套用後才發現 bug #4
> 再補一次）——這次一次到位，不需要「先套用一次、發現 sudo 不通、再補
> service 重跑」這個中間步驟。`pilot edit` 的 vault 編輯器仍然正確拒絕這份
> 巢狀 roster YAML（見 §6 bug #3），維持用文字編輯器直接編輯這一份檔案的
> 例外路徑。

### 3.12 `audit-log-forwarding`（client-vm，轉送目標 monitor-vm）

```
client-vm                   : ok=13   changed=7    unreachable=0    failed=0    skipped=2
```

> 跟 v1.0 一致。這支套用「成功」只代表 rsyslog client 端設定正確、語法過
> 關——實際轉送到 monitor-vm:514/tcp 一律 connection refused（§6 bug #5），
> 這是**預期中的已知限制**，不是這次套用的失敗。

### 3.13 `log-shipping`（改指向 client-vm 自己，繞過 log-server）

```
client-vm                   : ok=10   changed=5    unreachable=0    failed=0    skipped=1
```

> `-e target_group=client-vm` 是手動覆寫（log-shipping 的預設 group
> `log-server` 這個拓樸故意留空）；`loki_target_host` 由 `AutoHostVars`
> 自動偵測到 dashboard 主機；`siem_log_root=/var/log` 手動輸入。

---

## 4. Verify — 兩項原始需求的真實查詢結果（v1.1 重新驗證，2026-07-17）

### 4.1 權限管理（FreeIPA HBAC/sudo）— allow + deny 都真實測過

Roster（`.vault/ipa-identity.yaml`）定義：group `sysops`（成員 `alice`）、
`allow-sysops-ssh` HBAC rule（`services: [sshd, sudo, sudo-i]`，只准
`sysops` 登入 `clienthosts`）、`ipa_hbac_disable_allow_all: true`、
`sysops-systemctl` sudo rule（只准 `/usr/bin/systemctl`）。`bob` 不在
`sysops`。

```bash
$ ssh -i alice.key alice@192.168.122.6 "whoami; id; echo '***' | sudo -S /usr/bin/systemctl is-active ssh"
alice
uid=1712600004(alice) gid=1712600004(alice) groups=1712600004(alice),1712600003(sysops)
[sudo] password for alice: active
# exit=0 — 允許登入 + 允許的 sudo 指令成功

$ ssh -i alice.key alice@192.168.122.6 "echo '***' | sudo -S /usr/bin/cat /etc/shadow"
[sudo] password for alice: Sorry, user alice is not allowed to execute '/usr/bin/cat /etc/shadow' as root on client-vm.ipa.pilot.internal.
# 不在 allow_commands 清單 → 正確拒絕

$ ssh -i bob.key bob@192.168.122.6 "whoami"
Connection closed by 192.168.122.6 port 22
# exit=255 — HBAC 拒絕登入（allow_all 已關閉，bob 沒有任何 HBAC rule 授權）
```

**Verdict: PASS** — allow（alice 登入 + 允許的 sudo 指令）跟 deny（alice
被拒絕的 sudo 指令、bob 完全被拒絕登入）四個路徑全部真實測過，結果符合
預期。

> **第一次測試 `sysops-systemctl` sudo rule 不生效**（`alice is not allowed to
> run sudo on client-vm`）——**但這不是 `freeipa-client-apply.yml` 的 bug，
> 是我自己這輪套用了 v1.0 一份已經過時、其實有害的手動修法**（詳見 §6
> 更正）。當時看到 `/etc/sssd/sssd.conf` 的 `services = nss, pam, ssh`
> 沒有 `sudo`，直接照 v1.0 舊指示補上並重啟 sssd——實際上這樣做會讓
> `sssd-sudo.socket` 進入 `failed` 狀態（`sssd_check_socket_activated_
> responders` 判定為錯誤設定）。把 `services=` 改回 playbook 原本產生的
> `nss, pam, ssh`（不含 `sudo`）、確認 socket 恢復 `active (listening)`
> 後，上面 §4.1 的 allow/deny 兩個測試才是在**正確設定**下測到的結果。
>
> 另外，roster 裡 `force_password: true` 的新使用者（alice/bob）第一次用
> 密碼過 sudo 前，必須先完成 FreeIPA 的強制換密碼流程（`kinit alice`，
> 依序輸入舊密碼、新密碼、新密碼再一次）——這不是 bug，是 FreeIPA 對
> 新帳號的既定行為，記錄在這裡避免下一個人以為 sudo 壞了。

### 4.2 Metric 可從 Grafana 查詢（Grafana → Thanos Query → Prometheus）

```bash
$ curl -s -u admin:*** "http://192.168.122.4:3000/api/datasources/proxy/uid/pilot-thanos-query/api/v1/query?query=up"
{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"up","instance":"localhost:9090","job":"prometheus","site":"monitor-vm-site"},"value":[1784256967.2,"1"]}],"analysis":{}}}
```

**Verdict: PASS** — 從 client-vm 的角度（`pilot vm-target exec`）打
Grafana 自己的 datasource proxy，拿到 `up{job="prometheus",
site="monitor-vm-site"} = 1`，`site` label 正確對應 `prometheus_site_label`
的設定值。

### 4.3 Log 可從 Grafana 查詢（Grafana → Loki ← Promtail on client-vm）

```bash
$ curl -s -G -u admin:*** "http://192.168.122.4:3000/api/datasources/proxy/uid/pilot-loki/loki/api/v1/query_range" \
    --data-urlencode 'query={job="pilot-siem"} |= "bob"' ...
type=USER_LOGIN msg=audit(1784256791.459:5617): ... acct="bob" exe="/usr/sbin/sshd" ... res=failed'
type=USER_ACCT msg=audit(1784256791.458:5616): ... acct="bob" exe="/usr/sbin/sshd" ... res=failed'
2026-07-17T02:53:11.462347+00:00 client-vm sshd[13010]: fatal: Access denied for user bob by PAM account configuration [preauth]
2026-07-17T02:53:11.461928+00:00 client-vm sshd[13010]: pam_sss(sshd:account): Access denied for user bob: 6 (Permission denied)
```

**Verdict: PASS** — §4.1 造成的 bob 登入被拒事件，真的能在 Grafana 的
Loki datasource 查到，證明「權限管理」跟「log 可從 Grafana 查詢」這兩件
事串成了同一條可觀測鏈路。

---

## 5. 跨系統驗證（identity → monitoring 串接）

```bash
$ pilot vm-target exec --name freeipa-server -- sh -c "echo '***' | kinit admin && ipa sudorule-show sysops-systemctl && ipa hbacrule-show allow-sysops-ssh"
  Rule name: sysops-systemctl
  Enabled: True
  Host category: all
  User Groups: sysops
  Sudo Allow Commands: /usr/bin/systemctl
  Rule name: allow-sysops-ssh
  Enabled: True
  User Groups: sysops
  Host Groups: clienthosts
  HBAC Services: sshd, sudo, sudo-i
```

伺服器端規則資料本身正確（跟 §4.1 client 端實測行為一致），確認 §4.1
的 allow/deny 結果是規則生效的結果，不是巧合。

---

## 6. Real bugs encountered

| # | Bug | 狀態 | 修法 |
|---|-----|------|------|
| 1 | `seaweedfs-s3-apply.yml` 預設 `seaweedfs_extra_buckets` 只有 `pilot-restic-backup`，Thanos 需要的 `pilot-thanos-metrics` bucket 不會自動建立 | **v1.1 更正：已修好**（v1.1 初稿誤寫「仍未修」——手動照抄 v1.0 的 `weed shell` 步驟，沒有先確認是否還需要）。`prometheus-apply.yml`/`thanos-query-apply.yml` 各自都已經有等冪的「Step: create Thanos S3 bucket if missing」task。**Regression test（v1.1 即時驗證）**：手動 `weed shell` 刪除 `pilot-thanos-metrics`，只重跑 `thanos-query` 單一元件，`TASK [Step: create Thanos S3 bucket if missing]` 顯示 `changed: [monitor-vm]`，`weed shell` 確認 bucket 重新自動建立 | 不需要手動步驟；讓 `prometheus`/`thanos-query` 任一支先跑就會自動建好 |
| 2 | `prometheus-apply.yml`（Thanos Sidecar）與 `thanos-query-apply.yml` 都把 host port 10902 寫死，單 VM 混搭會撞 | **v1.1 確認已修好** | `thanos-query-apply.yml`/`dashboard-apply.yml` 的 `thanos_query_http_port`/`thanos_query_port` 現在預設值就是 `10912`，v1.1 全程沒有手動覆寫也沒有撞埠 |
| 3 | `pilot edit` 的舊 vault 編輯器：空白 vault 檔解析成 `!!null` scalar 導致 `Editable()` 回 false，永遠無法新增第一個 key | v1.0 已修（`TestVaultYAMLDoc_EmptySkeletonIsEditable`），2026-07-17 這次 Bubble Tea 重寫把同一套邏輯搬進獨立的 `internal/vaultfile` 套件，行為不變（測試隨邏輯一起搬到 `internal/vaultfile/vaultfile_test.go`），v1.1 用新版 `pilot edit` 建空白 vault 檔一次成功 | — |
| 4 | HBAC rule 只給 `services: [sshd]` 時，sshd 登入成功但**任何** sudo 呼叫都回 `PAM account management error` | 記錄在案，v1.1 這次 roster 從一開始就寫 `services: [sshd, sudo, sudo-i]`，一次到位不用再補套用 | — |
| 5 | `audit-log-forwarding-apply.yml` 的 rsyslog forward 寫死 TCP，Wazuh manager 官方 image 沒有對應 syslog `<remote>` 監聽 | **v1.1 確認仍未修**（預期中的已知限制，見 §1） | 不修這支 playbook；改用 `log-shipping-apply.yml` 直接指向 `client-vm` 自己，繞過整條 log-server 路徑 |
| 6 | `freeipa-identity-apply.yml`「Disable the default allow_all HBAC rule」的 `changed_when` 邏輯有瑕疵，重跑永遠回報 changed | 未修（cosmetic，行為無害），v1.1 沒有做第二次重跑驗證，狀態沿用 v1.0 記錄 | — |
| 7 | `log-server-apply.yml` 的 `meta: end_play` guard 只要 inventory 任何地方有 wazuh-manager 就整個跳過 | 不是 bug，設計如此（見 §1） | — |

### 已無尚未解決項目 — v1.0 記錄的 SSSD sudo 缺口，v1.1 更正為「已修好、且原記錄有誤」

v1.0 記錄的「`sssd.conf` 沒把 `sudo` 加進 `[sssd] services=`」這條，v1.1
**初稿一度誤判成原封不動重現**，實際上是這次重新驗證過程中自己造成的
一個測試錯誤，記錄下來避免下一個人重蹈覆轍：

- 第一次測 alice 的 sudo 指令失敗（`not allowed to run sudo`）時，直接照
  v1.0 的舊指示 `sed -i` 把 `sudo` 加進 `services=` 並重啟 sssd——**這其實
  是錯誤的修法**。
- 檢查 `freeipa-client-apply.yml` 現在的原始碼才發現：它從 v1.0 之後就已
  經正確處理這件事了，只是修法**不是**把 `sudo` 加進 `services=`，而是
  （1）在 `/etc/nsswitch.conf` 加 `sudoers: files sss`、（2）**刻意不**在
  `services=` 明列 `sudo`，靠 SSSD ≥ 2.3 的 socket activation
  （`sssd-sudo.socket`）自動處理——程式碼本身有詳細註解說明「明列 `sudo`
  是一種已知的錯誤設定，會讓 `sssd_check_socket_activated_responders`
  拒絕啟動 socket」。
- 驗證：把 `services=` 改回 playbook 原本產生的 `nss, pam, ssh`（不含
  `sudo`）、重啟 sssd 後，`systemctl status sssd-sudo.socket` 顯示
  `active (listening)`（先前因為我自己加了 `sudo` 進去，這個 socket 是
  `failed`），alice 的 allow/deny sudo 測試兩個都正確通過。
- 換句話說：**`freeipa-client-apply.yml` 這裡沒有 bug**，`client-vm` 重建
  不會重新撞到這個問題；v1.0 記下的那條「尚未解決」在目前這版程式碼下
  已經不成立了，v1.1 這次會失敗純粹是我自己先套用了一個過時、其實有害的
  手動修法。

---

## 7. Common failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| （v1.0，promptui 時代）`pilot deploy` 選單畫面選錯元件 | 大型 `promptui.Select`（20 項）在系統負載高時，連續方向鍵操作偶發丟鍵 | **2026-07-17 起已不適用**——`pilot edit`/`pilot deploy` 已改寫成 Bubble Tea，同一個 20 項元件清單，v1.1 重新驗證時故意用 `--key-delay 1`（比 v1.0 建議的 150ms 快 150 倍）連續按 19 次方向鍵，8/8 次全部正確落在目標項目，沒有任何一次丟鍵。這條症狀不再是已知風險，保留在此僅供歷史對照。 |
| `pilot deploy` 的 `SELECT <label>` 選單導覽在**前一個畫面剛結束、目前選單才剛顯示**時可能選錯（pointer 卡在上一個畫面殘留的位置） | `pilot deploy` 每個 prompt 都是獨立的短命 `tea.Program`（跟 `pilot edit` 的單一長駐 Program 架構不同——見 `deploy_tui.go` 說明），trec 的 `SELECT` 掃描畫面找方向鍵指標時，偶爾抓到「前一個剛結束的 Program」還留在 scrollback 的殘影，判斷錯方向。v1.1 重新驗證實際踩到：`SELECT 核心基礎服務` 在 scope 選單剛選完「單一元件」後，直接卡死在元件清單最後一項 | 對 `pilot deploy` 的元件選單，改用 `DOWN <n>` 絕對計數（`cmd/pilot/cmd/deploy_catalog.go` 的 `Key:` 順序算 index），不要用 `SELECT`；`pilot edit`（單一長駐 Program）不受影響，那邊 `SELECT` 已確認可靠（見 `.agents/skills/pilot-trec-verification` §4）|
| `pilot deploy` 的 confirm 畫面（y/N）打完 `y`/`n` 後又多送一個 `ENTER`，導致下一個畫面被提早送出預設值 | 新版 `confirmModel` 單一按鍵（y/n）就直接送出、不需要 Enter——promptui 時代需要打完字再按 Enter 提交，這裡行為不同了 | `TEXT y`/`TEXT n` 之後不要再送 `ENTER`；只有真的要用「顯示的預設值」時才單獨送 `ENTER` |
| `pilot edit`/`pilot deploy` 卡住約 5 秒才動 | 沒有設定 `CI=1`——bubbletea 套件初始化時會查詢終端機背景色，在沒有真人終端機回應的 PTY 下會等到 timeout。**v1.1 起這對兩個指令的每一次呼叫都成立**（v1.0 只有角色勾選畫面會踩到，因為當時只有那一個畫面是 Bubble Tea） | 一律加 `CI=1` 環境變數 |
| `sudo -n`/`sudo -S` 回 `a password is required`，但帳號用 SSH key 登入成功 | roster 建的帳號是 key-only（沒有 `password:` 欄位），sudo 走 PAM 密碼驗證，key-only 帳號從未設密碼 | `ipa passwd <user>` 設一個初始密碼，首次用該密碼 `kinit <user>` 完成強制換密碼流程，之後才能用密碼過 sudo |
| `docker port <container>` 顯示某個 port 有 publish，但轉送過去連線被拒 | port 有 publish 不代表容器內的服務真的在監聽那個 port/protocol——要進容器看實際設定檔（如 `ossec.conf` 的 `<remote>`）才能確認 | 用 `docker exec <container> ...` 直接檢查服務自己的設定，不要只看 `docker port` |

---

## 8. Rollback

- 單一元件：對應 apply playbook 大多有 `rescue:` 區塊，失敗會盡量還原
  （移除新建的設定檔、還原 systemd 狀態）；細節見各 playbook 內的
  rollback 任務名稱（`ROLLBACK — ...`）。
- 整個 demo 環境：
  ```bash
  pilot vm-target down --name client-vm
  pilot vm-target down --name monitor-vm
  pilot vm-target down --name freeipa-server
  ```
  這會 destroy + undefine 三台 VM、清掉 `vm-targets.json` 裡的 state，
  qcow2 overlay/seed ISO 一併移除（base golden image 不受影響，下次
  `vm-target up` 直接重用快取）。
- disposable 工作區（`./tmp/pilot-verify-<slug>/`）底下的
  `hosts.yml`/`inventory.yml`/`group_vars/`/`.vault/`/SSH 測試金鑰是純本機
  檔案，直接 `rm -rf` 整個資料夾即可清除，不影響其他環境（`./tmp/` 已在
  `.gitignore`）。

---

## 9. Changelog

| Date | Version | Change | Author |
|------|---------|--------|--------|
| 2026-07-14 | v1.0 | 初版：3 VM demo 全流程 + idempotency + 兩項需求驗證 + 7 個真實發現的 bug | Claude Code (agent) |
| 2026-07-17 | v1.1 | 重新驗證：3 VM 全部砍掉重建，`pilot edit`/`pilot deploy` 改用 2026-07-17 的 Bubble Tea 重寫版本重新走一次 wizard；確認 §7 promptui.Select 丟鍵症狀不再適用（8/8 次 1ms 按鍵延遲測試零丟鍵）；發現並記錄 `pilot deploy` 多短命 Program 架構下 `SELECT` 的新盲點（改用 `DOWN <n>`）；確認 confirm 畫面單鍵送出的行為變化；確認 bug #2（thanos port 衝突）已在預設值層級修好；**初稿一度誤判 bug #1（SeaweedFS bucket）跟 SSSD sudo services 缺口依然存在，經 regression test 更正為兩者其實都已經修好**——bug #1 是照抄 v1.0 舊步驟沒有先確認，SSSD 那條是自己套用了一份過時、其實有害的手動修法（詳見 §4.1、§6）；確認 bug #5（Wazuh syslog TCP/UDP 不符）即時重測仍然存在；本輪未重跑 idempotency（範圍限定在 UI 引擎重寫的影響） | Claude Code (agent) |

---

## Checklist（提交前）

- [x] Fact snapshot（§0.5）是這次撰寫時重新執行的真實輸出
- [x] 每一支 playbook 都真的跑過，PLAY RECAP 是真實輸出（§3）
- [x] Summary 數字（ok/changed/failed）都是真實數字，不是預測
- [x] Verify verdict 是真實查詢結果（PASS，§4）
- [ ] Idempotency 有第二次重跑證明——**v1.1 本輪刻意跳過**：13 支 playbook
      的 ansible 邏輯這次沒有改動，idempotency 沿用 v1.0 的驗證結果；本輪
      範圍限定在確認 UI 引擎重寫（promptui → Bubble Tea）沒有改變佈署結果
- [x] 全文沒有「expected」/「should」/「應該」這類預測用語（dry-run 那段
      明確說明「這次沒做」而非假裝有做）
- [x] Secrets 只列 key 名稱，沒有值印在文件裡
- [x] 變數名稱跟實際指令逐字一致
- [x] 對齊決策（A/B）已記錄（§0.5：log-server group 故意留空）
- [x] Fact snapshot 時間戳記跟真實執行時間一致（2026-07-17T02:56:37Z）
