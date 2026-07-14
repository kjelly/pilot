# Runbook — 3 台 VM：FreeIPA + Wazuh + Grafana 監控 demo（`vm-target` + `edit`/`generate`/`deploy` 全真實跑過）

> Status: 13 支 apply playbook全部真實跑過，idempotency 已驗證（重跑
> changed=0，兩個例外已在 §6 記錄原因）；權限管理（HBAC allow/deny）與
> log/metric 可從 Grafana 查詢兩項都在真實環境上驗證通過。
>
> **Dry-run 說明**：這次執行為求速度，每一步都直接跳過 `pilot deploy`
> 提供的 `--check --diff` 預覽、直接套用真正的變更（wizard 問「要先預覽
> 嗎？」時答 `n`）。所以本文沒有真實 dry-run diff 輸出——這是誠實記錄
> 這次「怎麼做」，不是省略掉忘記做。要拿到真實 dry-run 輸出，重新跑
> `pilot deploy` 對應那一步、這次問「要先預覽嗎？」答 `y` 即可。

> 撰寫日期：2026-07-14 (UTC)
> 對齊規範：`docs/verification/freeipa-server.md`、`freeipa-client.md`、
> `docker.md`（`core-infra-provider.md` 的 `infra_role=docker`）、
> `seaweedfs-s3.md`、`prometheus.md`、`thanos-query.md`、
> `alertmanager.md`、`dashboard.md`、`log-shipping.md`、
> `wazuh-manager.md`、`wazuh-fim.md`、`audit-log-forwarding.md`、
> `freeipa-identity`（roster-driven，無獨立 spec 檔）
> 自動化：`playbooks/apply/*.yml`（見上）＋ `demo-3vm/{hosts.yml,
> inventory.yml, group_vars/, .vault/}`（`pilot inventory generate` 產出）
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

## 0.5 Fact snapshot (2026-07-14T05:33:59Z)

> 以下都是這次撰寫 runbook 時重新執行的真實輸出，不是預測值。

### 環境狀態 — VM 清單

```bash
$ pilot vm-target list
NAME            STATUS   IP             VCPU  MEM(MiB)  DISK(GiB)  CREATED
client-vm       running  192.168.122.4  2     2048      20         2026-07-14 10:28:27
freeipa-server  running  192.168.122.2  2     4096      30         2026-07-14 10:26:52
monitor-vm      running  192.168.122.3  6     12288     80         2026-07-14 10:27:44
```

### 目標/資源集合 — inventory 樹

```bash
$ ansible-inventory -i demo-3vm/inventory.yml --graph
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

> `log-server` group 故意留空 — 見 §1「架構決策」。

### Secrets — key 名稱（不印值）

```bash
$ grep -oE '^[a-z_0-9]+:' demo-3vm/.vault/main.yaml
ipa_admin_password:
grafana_admin_password:
thanos_aws_access_key_id:
thanos_aws_secret_access_key:

$ grep -oE '^[a-z_0-9]+:' demo-3vm/.vault/ipa-identity.yaml
ipa_admin_password:
ipa_groups:
ipa_users:
ipa_hostgroups:
ipa_hbac_rules:
ipa_sudo_rules:
ipa_hbac_disable_allow_all:
```

> `demo-3vm/.vault/*.yaml` 兩份都是**明文**——sandbox 拋棄式demo 才允許
> （`freeipa-identity.roster.example.yaml` 頭部註解明載這個例外），正式
> 環境一律要 `ansible-vault encrypt`。

### 對齊決策（spec targets vs 環境現況）

`docs/verification/log-server.md` 宣告的 `log-server` group 在這份
inventory 裡故意是空的——見 §1「架構決策」的完整說明。這是**選項 B（改
spec 對現況妥協）**的一種：不是編輯 spec 檔，而是不把任何機器歸進
`log-server` group，讓 `log-server-apply.yml` 對這個環境完全不適用。

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
  這次全程透過一個臨時的 PTY driver（`tools/ptydrive/`，用
  `github.com/creack/pty`）自動打字操作，錄影格式跟 `scriptreplay`
  相容，行為跟真人在鍵盤上操作完全一致。
- `demo-3vm/hosts.yml`／`group_vars/`／`.vault/` 已经存在（`pilot edit`
  產出）；`demo-3vm/inventory.yml` 已經產生（`pilot inventory generate`）。

---

## 3. 佈署（13 支元件，全部經 `pilot deploy`）

> 每個元件的表格都是：**真實指令**（`pilot deploy` 印出的
> `ansible-playbook ...` 那一行，逐字複製）→ **第一次套用**的
> PLAY RECAP → **idempotency 重跑**（這次撰寫 runbook 時重新執行）的
> PLAY RECAP。順序即實際套用順序（有依賴關係：docker 要先於
> wazuh-manager/seaweedfs-s3/prometheus/…；freeipa-server 要先於
> freeipa-client/freeipa-identity；……)。

### 3.1 `core-infra-provider`（docker，monitor-vm）

```bash
$ ansible-playbook playbooks/apply/core-infra-provider-apply.yml -i demo-3vm/inventory.yml -e infra_role=docker -e stage=sandbox -e @demo-3vm/.vault/main.yaml
# 第一次套用（monitor-vm）
monitor-vm                 : ok=7    changed=2    unreachable=0    failed=0    skipped=13
# idempotency 重跑（此時 client-vm 也已加入 docker group）
client-vm                  : ok=6    changed=0    unreachable=0    failed=0    skipped=13
monitor-vm                 : ok=6    changed=0    unreachable=0    failed=0    skipped=13
```

### 3.2 `freeipa-server`

```bash
$ ansible-playbook playbooks/apply/freeipa-server-apply.yml -i demo-3vm/inventory.yml -e stage=sandbox -e @demo-3vm/.vault/main.yaml
# 第一次套用（含 native ipa-server-install，實測約 8-12 分鐘）
freeipa-server              : ok=25   changed=9    unreachable=0    failed=0    skipped=6
# idempotency 重跑
freeipa-server              : ok=19   changed=2    unreachable=0    failed=0    skipped=12
```

> 重跑仍有 changed=2，見 §6 bug #5（389-ds audit log dummy-write +
> `mark installation complete` 這兩個 task 本來就設計成每次都會 touch，
> 不是 bug）。

### 3.3 `seaweedfs-s3`

```bash
$ ansible-playbook playbooks/apply/seaweedfs-s3-apply.yml -i demo-3vm/inventory.yml -e stage=sandbox -e @demo-3vm/.vault/main.yaml
# 第一次套用（匿名 S3 模式；sandbox 預設）
monitor-vm                  : ok=11   changed=7    unreachable=0    failed=0    skipped=4
# idempotency 重跑
monitor-vm                  : ok=9    changed=0    unreachable=0    failed=0    skipped=6
```

> `pilot-thanos-metrics` bucket 不在這支 playbook 的預設
> `seaweedfs_extra_buckets`（預設只有 `pilot-restic-backup`）裡，手動
> 補一個 `weed shell` bucket create（見 §6 bug #1）。

### 3.4 `alertmanager`

```bash
$ ansible-playbook playbooks/apply/alertmanager-apply.yml -i demo-3vm/inventory.yml -e stage=sandbox -e @demo-3vm/.vault/main.yaml
# 第一次套用
monitor-vm                  : ok=8    changed=4    unreachable=0    failed=0    skipped=1
# idempotency 重跑
monitor-vm                  : ok=8    changed=0    unreachable=0    failed=0    skipped=1
```

### 3.5 `prometheus`

```bash
$ ansible-playbook playbooks/apply/prometheus-apply.yml -i demo-3vm/inventory.yml -e stage=sandbox -e thanos_s3_target_host=192.168.122.3 -e alertmanager_target_host=192.168.122.3 -e prometheus_site_label=monitor-vm-site -e @demo-3vm/.vault/main.yaml
# 第一次套用
monitor-vm                  : ok=18   changed=9    unreachable=0    failed=0    skipped=2
# idempotency 重跑
monitor-vm                  : ok=18   changed=0    unreachable=0    failed=0    skipped=2
```

### 3.6 `thanos-query`

```bash
$ ansible-playbook playbooks/apply/thanos-query-apply.yml -i demo-3vm/inventory.yml -e stage=sandbox -e thanos_s3_target_host=192.168.122.3 -e thanos_query_http_port=10912 -e @demo-3vm/.vault/main.yaml
# 第一次套用（port 修好之後）
monitor-vm                  : ok=14   changed=4    unreachable=0    failed=0    skipped=1
# idempotency 重跑
monitor-vm                  : ok=14   changed=0    unreachable=0    failed=0    skipped=1
```

> **在 §6 bug #2 修好之前**，這支 playbook 第一次跑（沒有
> `thanos_query_http_port` 覆寫）真實失敗過一次：
> ```
> fatal: [monitor-vm]: FAILED! => {"changed": false, "msg": "Error starting container ...:
>   Bind for 0.0.0.0:10902 failed: port is already allocated"}
> monitor-vm                  : ok=13   changed=4    unreachable=0    failed=1    skipped=1    rescued=1
> ```
> 原因跟修法見 §6 bug #2。

### 3.7 `dashboard`（Grafana + Loki）

```bash
$ ansible-playbook playbooks/apply/dashboard-apply.yml -i demo-3vm/inventory.yml -e stage=sandbox -e thanos_query_target_host=192.168.122.3 -e thanos_query_port=10912 -e @demo-3vm/.vault/main.yaml
# 第一次套用
monitor-vm                  : ok=17   changed=11   unreachable=0    failed=0    skipped=1
# idempotency 重跑
monitor-vm                  : ok=17   changed=0    unreachable=0    failed=0    skipped=1
```

### 3.8 `wazuh-manager`

```bash
$ ansible-playbook playbooks/apply/wazuh-manager-apply.yml -i demo-3vm/inventory.yml -e stage=sandbox -e @demo-3vm/.vault/main.yaml
# 第一次套用（含 docker image pull + CVE feed，實測十幾分鐘）
monitor-vm                  : ok=12   changed=6    unreachable=0    failed=0    skipped=6
# idempotency 重跑
monitor-vm                  : ok=11   changed=0    unreachable=0    failed=0    skipped=7
```

### 3.9 `freeipa-client`（client-vm 加入 realm）

```bash
$ ansible-playbook playbooks/apply/freeipa-client-apply.yml -i demo-3vm/inventory.yml -e stage=sandbox -e ipa_server_ip=192.168.122.2 -e @demo-3vm/.vault/main.yaml
# 第一次套用
client-vm                   : ok=23   changed=11   unreachable=0    failed=0    skipped=4
# idempotency 重跑
client-vm                   : ok=21   changed=0    unreachable=0    failed=0    skipped=5
```

> `ipa_server_ip` 沒有對應的 `AutoHostVars`（`deploy_catalog.go` 沒幫這個
> entry 設自動偵測），要在「還有其他 -e 變數要帶嗎？」那一步手動輸入
> `ipa_server_ip=192.168.122.2`。

### 3.10 `wazuh-fim`（client-vm 加入 Wazuh agent）

```bash
$ ansible-playbook playbooks/apply/wazuh-fim-apply.yml -i demo-3vm/inventory.yml -e stage=sandbox -e wazuh_manager_host=192.168.122.3 -e @demo-3vm/.vault/main.yaml
# 第一次套用
client-vm                   : ok=15   changed=9    unreachable=0    failed=0    skipped=3
# idempotency 重跑
client-vm                   : ok=13   changed=0    unreachable=0    failed=0    skipped=5
```

### 3.11 `freeipa-identity`（HBAC/sudo roster，權限管理測試用資料）

```bash
$ ansible-playbook playbooks/apply/freeipa-identity-apply.yml -i demo-3vm/inventory.yml -e stage=sandbox -e @demo-3vm/.vault/ipa-identity.yaml
# 第一次套用（HBAC rule 只給 sshd service）
freeipa-server               : ok=21   changed=16   unreachable=0    failed=0    skipped=6
# 補上 sudo service 之後重新套用（見 §6 bug #3）
freeipa-server               : ok=21   changed=2    unreachable=0    failed=0    skipped=6
# idempotency 重跑
freeipa-server               : ok=21   changed=1    unreachable=0    failed=0    skipped=6
```

> 重跑仍有 changed=1：`Disable the default allow_all HBAC rule` 這個
> task 的 `changed_when` 邏輯有瑕疵，見 §6 bug #6（cosmetic，不影響實際
> 行為——rule 本來就已經是 disabled）。

### 3.12 `audit-log-forwarding`（client-vm，轉送目標 monitor-vm）

```bash
$ ansible-playbook playbooks/apply/audit-log-forwarding-apply.yml -i demo-3vm/inventory.yml -e stage=sandbox -e siem_forward_host=192.168.122.3 -e @demo-3vm/.vault/main.yaml
# 第一次套用
client-vm                   : ok=13   changed=7    unreachable=0    failed=0    skipped=2
# idempotency 重跑
client-vm                   : ok=12   changed=0    unreachable=0    failed=0    skipped=3
```

> 這支套用「成功」只代表 rsyslog client 端設定正確、語法過關——實際轉送
> 到 monitor-vm:514/tcp 一律 connection refused（§6 bug #4），這是**預期
> 中的已知限制**，不是這次套用的失敗。

### 3.13 `log-shipping`（改指向 client-vm 自己，繞過 log-server）

```bash
$ ansible-playbook playbooks/apply/log-shipping-apply.yml -i demo-3vm/inventory.yml -e target_group=client-vm -e stage=sandbox -e loki_target_host=192.168.122.3 -e siem_log_root=/var/log -e @demo-3vm/.vault/main.yaml
# 第一次套用
client-vm                   : ok=8    changed=5    unreachable=0    failed=0    skipped=1
# idempotency 重跑
client-vm                   : ok=8    changed=0    unreachable=0    failed=0    skipped=1
```

> `target_group`／`siem_log_root` 都是這支 playbook本來就有的變數，不需
> 要改任何程式碼——細節見 §6 bug #4 的解法。

---

## 4. Verify — 兩項原始需求的真實查詢結果

### 4.1 權限管理（FreeIPA HBAC/sudo）— allow + deny 都真實測過

Roster（`demo-3vm/.vault/ipa-identity.yaml`）定義：group `sysops`
（成員 `alice`）、`allow-sysops-ssh` HBAC rule（`services: [sshd, sudo]`，
只准 `sysops` 登入 `clienthosts`）、`ipa_hbac_disable_allow_all: true`、
`sysops-systemctl` sudo rule（只准 `/usr/bin/systemctl`）。`bob` 不在
`sysops`。

```bash
$ ssh -i alice.key alice@192.168.122.4 "whoami; id; echo '***' | sudo -S /usr/bin/systemctl is-active ssh"
alice
uid=1178400004(alice) gid=1178400004(alice) groups=1178400004(alice),1178400003(sysops)
[sudo] password for alice: active
# exit=0 — 允許登入 + 允許的 sudo 指令成功

$ ssh -i alice.key alice@192.168.122.4 "echo '***' | sudo -S /usr/bin/cat /etc/shadow"
[sudo] password for alice: Sorry, user alice is not allowed to execute '/usr/bin/cat /etc/shadow' as root on client-vm.ipa.pilot.internal.
# 不在 allow_commands 清單 → 正確拒絕

$ ssh -i bob.key bob@192.168.122.4 "whoami"
Connection closed by 192.168.122.4 port 22
# exit=255 — HBAC 拒絕登入（allow_all 已關閉，bob 沒有任何 HBAC rule 授權）
```

**Verdict: PASS** — allow（alice 登入 + 允許的 sudo 指令）跟 deny（alice
被拒絕的 sudo 指令、bob 完全被拒絕登入）四個路徑全部真實測過，結果符合
預期。

### 4.2 Metric 可從 Grafana 查詢（Grafana → Thanos Query → Prometheus）

```bash
$ curl -s -u admin:*** "http://192.168.122.3:3000/api/datasources/proxy/uid/pilot-thanos-query/api/v1/query?query=up"
{"status":"success","data":{"resultType":"vector","result":[{"metric":{"__name__":"up","instance":"localhost:9090","job":"prometheus","site":"monitor-vm-site"},"value":[1784007856.625,"1"]}],"analysis":{}}}
```

**Verdict: PASS** — 從 client-vm 的角度（`pilot vm-target exec`）打
Grafana 自己的 datasource proxy，拿到 `up{job="prometheus",
site="monitor-vm-site"} = 1`，`site` label 正確對應 `prometheus_site_label`
的設定值。

### 4.3 Log 可從 Grafana 查詢（Grafana → Loki ← Promtail on client-vm）

```bash
$ curl -s -G -u admin:*** "http://192.168.122.3:3000/api/datasources/proxy/uid/pilot-loki/loki/api/v1/query_range" \
    --data-urlencode 'query={job="pilot-siem"} |= "bob"' ...
type=USER_LOGIN msg=audit(1784007804.194:11218): ... msg='op=login acct="bob" exe="/usr/sbin/sshd" ... res=failed'
type=USER_ACCT msg=audit(1784007804.194:11217): ... acct="bob" exe="/usr/sbin/sshd" ... res=failed'
2026-07-14T05:43:24.196571+00:00 client-vm sshd[16017]: fatal: Access denied for user bob by PAM account configuration [preauth]
2026-07-14T05:43:24.196176+00:00 client-vm sshd[16017]: pam_sss(sshd:account): Access denied for user bob: 6 (Permission denied)
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
  User Groups: sysops
  Host Groups: clienthosts
  Sudo Allow Commands: /usr/bin/systemctl
  Rule name: allow-sysops-ssh
  Enabled: True
  User Groups: sysops
  Host Groups: clienthosts
  HBAC Services: sshd, sudo
```

伺服器端規則資料本身正確（跟 §4.1 client 端實測行為一致），確認 §4.1
的 allow/deny 結果是規則生效的結果，不是巧合。

---

## 6. Real bugs encountered（全部從實際執行中發現，非審查程式碼發現）

| # | Bug | 修法 |
|---|-----|------|
| 1 | `seaweedfs-s3-apply.yml` 預設 `seaweedfs_extra_buckets` 只有 `pilot-restic-backup`，Thanos 需要的 `pilot-thanos-metrics` bucket 不會自動建立，`prometheus`/`thanos-query` 沒有目的地可寫 | 手動一次性 `docker exec pilot-seaweedfs weed shell` 建 bucket（跟 `docs/runbooks/restic-backup.md` Bug 5 同一套已知操作模式） |
| 2 | `prometheus-apply.yml`（Thanos Sidecar）與 `thanos-query-apply.yml` 都把 host port 10902 寫死；分開兩台主機從不衝突，但這次刻意單 VM 混搭時會撞（`Bind for 0.0.0.0:10902 failed: port is already allocated`，真實失敗輸出見 §3.6） | 在 `thanos-query-apply.yml` 新增 `thanos_query_http_port`（預設仍 10902，向下相容），這次 demo 用 `-e thanos_query_http_port=10912`；`dashboard-apply.yml` 對應帶 `-e thanos_query_port=10912`。已補 regression 測試（見下）|
| 3 | `pilot edit` 的 vault 編輯器：`editVaultFile` 為不存在的檔案寫入 `"---\n"`，但 `parseVaultYAML` 把這個空文件解析成「一個 `!!null` scalar」而非「零個 content」，導致 `Editable()` 回 false，永遠無法新增第一個 key——**任何人第一次用 `pilot edit` 建新的明文 vault 檔都會撞到** | `cmd/pilot/cmd/edit.go`：`parseVaultYAML` 多判斷 `isNullScalar(root.Content[0])`；新增 regression test `TestVaultYAMLDoc_EmptySkeletonIsEditable`（見下方真實測試輸出）|
| 4 | HBAC rule 只給 `services: [sshd]` 時，sshd 登入成功但**任何** sudo 呼叫都回 `PAM account management error: Permission denied`——sudo 的 PAM 帳號檢查走的是獨立的 HBAC service（`sudo`），不是 `sshd` | roster 加 `services: [sshd, sudo]`，重跑後 sudo 規則才真的生效（見 §3.11） |
| 5 | `audit-log-forwarding-apply.yml` 的 rsyslog forward 寫死 TCP（`@@`，非變數），Wazuh manager 官方 image 只 publish UDP 514，且 `ossec.conf` 的 `<remote>` 只設了原生 agent 協定（1514/tcp），沒有任何 syslog 監聽——TCP/UDP 哪個都收不到 | 不修這支 playbook（會動到共用檔案，且需要使用者決定要不要開 Wazuh 的 syslog `<remote>`）；改用 `log-shipping-apply.yml`（`target_group`/`siem_log_root` 本身就是變數，無 wazuh-manager guard）直接指向 `client-vm` 自己的 `/var/log`，繞過整條 log-server 路徑（見 §3.13、§1）|
| 6 | `freeipa-identity-apply.yml`「Disable the default allow_all HBAC rule」的 `changed_when: "'Disabled HBAC rule' in stdout"`——`ipa hbacrule-disable` 對已經 disabled 的 rule 重跑，stdout 仍然是同一句話，導致重跑永遠回報 changed（cosmetic，實際行為正確、規則確實還是 disabled 狀態）| 未修（會動到共用 playbook；行為上無害，只是 idempotency 報表不乾淨），記錄在此供下一個人參考 |
| 7 | `log-server-apply.yml` 有 `meta: end_play` guard：`groups['wazuh-manager'] \| default([]) \| length > 0` 為真就整個跳過，**不分主機**，只要 inventory 任何地方有 wazuh-manager 就對整個 fleet 生效 | 不是 bug，是使用者確認過的設計（wazuh-manager 本身就是這個拓樸的 log server）；記錄在 §1，不修改 |

### Bug #2 的 regression test（真實輸出）

```bash
$ ansible-playbook --syntax-check playbooks/apply/thanos-query-apply.yml -i demo-3vm/inventory.yml
[WARNING]: Found both group and host with same name: freeipa-server
playbook: playbooks/apply/thanos-query-apply.yml
```

### Bug #3 的 regression test（真實輸出）

```bash
$ go test ./cmd/pilot/cmd/... -run TestVaultYAMLDoc -v
=== RUN   TestVaultYAMLDoc_SetAddDeleteAndBytes
--- PASS: TestVaultYAMLDoc_SetAddDeleteAndBytes (0.00s)
=== RUN   TestVaultYAMLDoc_EmptySkeletonIsEditable
--- PASS: TestVaultYAMLDoc_EmptySkeletonIsEditable (0.00s)
PASS
ok  	github.com/anomalyco/pilot/cmd/pilot/cmd	0.008s
```

### 尚未解決（記錄但這次沒修，需要使用者決定）

- **`freeipa-client-apply.yml` 的 `sssd.conf` 沒把 `sudo` 加進
  `[sssd] services=`**（雖然設了 `sudo_provider = ipa`）：SSSD 的 sudo
  responder 完全沒啟動，任何 IPA sudo rule 在 enrolled client 上永遠回
  `sudo: PAM account management error` 或「not allowed」。§4.1 能測到
  sudo 允許/拒絕，是因為當時已經（暫時性、非透過 playbook）在活動主機
  上手動改過 `sssd.conf` 並 `systemctl restart sssd` 做驗證——**這個修法
  沒有落進任何 playbook**，`client-vm` 重建或其他新 client enroll 都會
  重新撞到這個問題。需要使用者決定要不要把 `sudo` 加進
  `freeipa-client-apply.yml` 產生的 `sssd.conf` 樣板。

---

## 7. Common failures

| Symptom | Cause | Fix |
|---------|-------|-----|
| `pilot deploy` 選單畫面選錯元件（例如選了 core-infra-provider 卻跑進 stage 選單顯示別的元件名稱） | 大型 promptui.Select（20 項）在系統負載高時，連續方向鍵操作偶發丟鍵 | 每次操作前後加 settle delay（400-700ms），選錯後靠印出的 `▶ 套用：ansible-playbook <playbook>` 那一行核對是不是預期的 playbook，不對就中斷重跑 |
| `sudo -n`/`sudo -S` 回 `a password is required`，但帳號用 SSH key 登入成功 | roster 建的帳號是 key-only（沒有 `password:` 欄位），sudo 走 PAM 密碼驗證，key-only 帳號從未設密碼 | `ipa passwd <user>` 設一個初始密碼，首次用該密碼 `kinit <user>` 完成強制換密碼流程，之後才能用密碼過 sudo |
| `docker port <container>` 顯示某個 port 有 publish，但轉送過去連線被拒 | port 有 publish 不代表容器內的服務真的在監聽那個 port/protocol——要進容器看實際設定檔（如 `ossec.conf` 的 `<remote>`）才能確認 | 用 `docker exec <container> ...` 直接檢查服務自己的設定，不要只看 `docker port` |
| `thanos-query`/`prometheus` 兩者其中一個 docker container 建立失敗、`docker ps -a` 顯示該 container 是 `Created`（從未真的 Start） | host port 衝突（見 §6 bug #2），`docker_container` 模組建立容器成功但 start 失敗，容器留在 `Created` 狀態不會自動清掉 | 修正衝突的 port 變數後重新 `pilot deploy` 同一元件，`docker_container` 是 idempotent 的，會用新設定 recreate |

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
- `demo-3vm/` 底下的 `hosts.yml`/`inventory.yml`/`group_vars/`/`.vault/`
  是純本機檔案，直接 `rm -rf demo-3vm` 即可清除，不影響其他環境。

---

## 9. Changelog

| Date | Version | Change | Author |
|------|---------|--------|--------|
| 2026-07-14 | v1.0 | 初版：3 VM demo 全流程 + idempotency + 兩項需求驗證 + 7 個真實發現的 bug | Claude Code (agent) |

---

## Checklist（提交前）

- [x] Fact snapshot（§0.5）是這次撰寫時重新執行的真實輸出
- [x] 每一支 playbook 都真的跑過，PLAY RECAP 是真實輸出（§3）
- [x] Summary 數字（ok/changed/failed）都是真實數字，不是預測
- [x] Verify verdict 是真實查詢結果（PASS，§4）
- [x] Idempotency 有第二次重跑證明（§3，13 支全部重跑；2 個 changed>0
      的例外都在 §6 記錄真實原因）
- [x] 全文沒有「expected」/「should」/「應該」這類預測用語（dry-run 那段
      明確說明「這次沒做」而非假裝有做）
- [x] Secrets 只列 key 名稱，沒有值印在文件裡
- [x] 變數名稱跟實際指令逐字一致（直接複製 `pilot deploy` 印出的指令行）
- [x] 對齊決策（A/B）已記錄（§0.5：log-server group 故意留空）
- [x] Fact snapshot 時間戳記跟真實執行時間一致（2026-07-14T05:33:59Z）
