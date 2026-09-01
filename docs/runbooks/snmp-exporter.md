# Runbook — snmp-exporter（site-local Prometheus SNMP exporter）

> 撰寫日期：2026-09-01 (UTC)
> 對齊規範：`docs/verification/snmp-exporter.md`（v1.0），
> `docs/superpowers/specs/2026-09-01-snmp-monitoring-integration-spec.md`
> §15 Phase 1
> 維護者：sre

---

## 0. 目標與範圍

在一台 disposable VM 上真實部署 `snmp_exporter`（官方 pinned image
`quay.io/prometheus/snmp-exporter:v0.30.1`），並對另一台 disposable VM
上真實跑起來的 net-snmp `snmpd`（SNMPv3 authPriv，read-only view）做一次
端到端 scrape，證明 spec §15 Phase 1 exit gate 的五項要求：fresh VM apply
PASS、config negative tests PASS、real/lab SNMPv3 target scrape PASS、
second apply changed=0、secret scan PASS。

`snmp-dev`（跑 snmpd 的那台）**不是** Pilot managed role——它只是本次測試
臨時搭的 lab SNMP 裝置，用 `vm-target exec` 手動裝、手動設定，完全比照
spec §1「SNMP device != Pilot managed host」的邊界。

## 1. §0.5 事實快照（AGENTS.md §2）

```
$ pilot vm-target up --name snmp-exp --ssh-user ubuntu --disk 20 --memory 2048 --vcpus 2 --services local
✓ target snmp-exp up
  ip        : 192.168.122.2
  ssh_user  : ubuntu
  base_image: /var/lib/libvirt/images/pilot/images/ubuntu-24.04-golden.qcow2

$ pilot vm-target up --name snmp-dev --ssh-user ubuntu --disk 20 --memory 2048 --vcpus 2 --services local
✓ target snmp-dev up
  ip        : 192.168.122.3
```

`pilot vm-target wire` 失敗（`--ssh-user ubuntu` 沒有 root 直接寫
`/etc/hosts` 的權限，`sed: couldn't open temporary file ... Permission
denied`）——這是既有 `vm-target wire` 對非 root ssh_user 的已知限制，跟本次
SNMP 功能無關；改用兩台 VM 的固定內網 IP（192.168.122.2/.3）直接互連，
`ping`/`snmpwalk`/scrape 全部改用 IP，不依賴主機名解析。

兩台皆 Ubuntu 24.04、passwordless sudo 確認可用；`snmp-exp` 另外套用了
`playbooks/apply/docker-apply.yml`（依賴鏈：contract `dependencies:
[{component: docker, relation: sameHosts}]`）。

Tested revision：`playbooks/apply/snmp-exporter-apply.yml`、
`contracts/snmp-exporter.yaml`、`monitoring/snmp/catalog.yml` 於本檔撰寫
時的工作樹（Phase 1 首次落地真實 task）。

## 2. Lab SNMPv3 裝置（snmp-dev，非 Pilot 角色）

```
$ pilot vm-target exec --name snmp-dev -- sudo apt-get install -y snmpd snmp
INSTALL_OK

$ pilot vm-target exec --name snmp-dev -- sudo bash -c '
cat > /etc/snmp/snmpd.conf <<EOF
agentAddress udp:161
rouser lab-ro-user authPriv
view systemonly included .1
EOF
systemctl stop snmpd
rm -f /var/lib/snmp/snmpd.conf
net-snmp-create-v3-user -ro -A authpassword123 -a SHA-256 -X privpassword123 -x AES lab-ro-user
systemctl start snmpd
systemctl is-active snmpd
'
active
```

`rouser`（不是 `rwuser`）——read-only view，對應 spec §13.4。跨 VM 交叉
驗證（從 `snmp-exp` 對 `snmp-dev` 跑 snmpwalk，確認網路層與認證都通，
在套用 exporter 之前先排除「裝置本身沒設好」的可能性）：

```
$ pilot vm-target exec --name snmp-exp -- snmpwalk -v3 -u lab-ro-user -l authPriv \
    -a SHA-256 -A authpassword123 -x AES -X privpassword123 192.168.122.3 1.3.6.1.2.1.2.2.1.2
iso.3.6.1.2.1.2.2.1.2.1 = STRING: "lo"
iso.3.6.1.2.1.2.2.1.2.2 = STRING: "enp1s0"
```

## 3. 部署 snmp-exporter（fresh VM apply）

`monitoring/snmp/catalog.yml` 的 `if_mib` module 內容不是手寫的 OID
mapping——是從官方 image 自己內建的 generator 產出萃取（spec §6.5 rule
1/2：generator 只能在 development 環境跑，不得在 production host 執行）：

```
$ docker run --rm --entrypoint sh quay.io/prometheus/snmp-exporter:v0.30.1 \
    -c 'cat /etc/snmp_exporter/snmp.yml'
# 61034 行,含 if_mib 與 ~50 個 vendor module；取出 modules.if_mib 存成
# monitoring/snmp/generated/if_mib.yml
```

真實 apply（`ansible-playbook` 直接跑，非 `--sandbox`——sandbox 容器只
docker-cp 單一 playbook 檔案進去，沒有掛整個 repo checkout，
`monitoring_targets_file` 這類 `lookup('file', ...)` repo-relative 路徑
在 sandbox 下本來就無法解析，跟 prometheus-apply.yml 的既有限制一致，
不是本次新引入的問題）：

```
$ ansible-playbook -i <snmp-exp-inventory.yaml> playbooks/apply/snmp-exporter-apply.yml \
    -e target_group=snmp-exp \
    -e snmp_catalog_file=$(pwd)/monitoring/snmp/catalog.yml \
    -e @<vault-with-snmp_exporter_credentials>.yml

TASK [Ensure config/modules/data dirs exist] ***
changed: [snmp-exp] => (item=/etc/pilot/snmp-exporter)
changed: [snmp-exp] => (item=/etc/pilot/snmp-exporter/modules)
changed: [snmp-exp] => (item=/var/lib/pilot/snmp-exporter)
TASK [Copy catalog.yml (non-secret, for audit/reference)] ***
changed: [snmp-exp]
TASK [Copy each module file (non-secret, for audit/reference)] ***
changed: [snmp-exp] => (item=if_mib)
TASK [Render auths.yml ...] ***
changed: [snmp-exp]
TASK [Render snmp-exporter.env ...] ***
changed: [snmp-exp]
TASK [Run pilot-snmp-exporter container] ***
changed: [snmp-exp]
TASK [Wait for snmp_exporter self metrics to become ready] ***
ok: [snmp-exp]

PLAY RECAP *********************************************************************
snmp-exp   : ok=25   changed=6    unreachable=0    failed=0    skipped=3    rescued=0    ignored=0
```

容器狀態確認（hardening + 權限，全部在真實 VM 上直接查）：

```
$ pilot vm-target exec --name snmp-exp -- sudo docker inspect pilot-snmp-exporter \
    --format '{{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}} readonly={{.HostConfig.ReadonlyRootfs}}'
[ALL] [no-new-privileges:true] readonly=true

$ pilot vm-target exec --name snmp-exp -- sudo ss -tlnp | grep 9116
LISTEN 0 4096 127.0.0.1:9116 0.0.0.0:* users:(("docker-proxy",...))

$ pilot vm-target exec --name snmp-exp -- sudo stat -c '%U:%G %a' /etc/pilot/snmp-exporter
root:root 750
$ pilot vm-target exec --name snmp-exp -- sudo stat -c '%U:%G %a' /etc/pilot/snmp-exporter/snmp-exporter.env
root:root 600
$ pilot vm-target exec --name snmp-exp -- sudo stat -c '%U:%G %a' /etc/pilot/snmp-exporter/auths.yml
root:root 640
```

Port 只監聽 `127.0.0.1`（Docker 層 `-p 127.0.0.1:9116:9116`），而不是容器
內部也要求綁 loopback——容器內部保持預設（所有介面），靠 Docker 的
host-bind-address publish 做實際的對外限制，這樣 host 的 127.0.0.1 以外
完全連不到，同時容器仍能被 Docker NAT 轉發，兩者不衝突（實測驗證過容器
內部若改綁 `127.0.0.1`，Docker port-forward 反而連不到）。

## 4. 真實 SNMPv3 scrape（跨兩台 VM）

```
$ pilot vm-target exec --name snmp-exp -- curl -s \
    'http://127.0.0.1:9116/snmp?target=192.168.122.3&module=if_mib&auth=lab-switch-v3'
# HELP ifAdminStatus ...
ifAdminStatus{ifAlias="",ifDescr="enp1s0",ifIndex="2",ifName="enp1s0"} 1
...
# HELP ifHCInOctets ...
ifHCInOctets{ifAlias="",ifDescr="enp1s0",ifIndex="2",ifName="enp1s0"} 1.310822e+07
...
```

真實介面計數器（`ifHCInOctets`）、真實介面名稱（`enp1s0`）——不是假資料。
`snmp_scrape_pdus_returned{module="if_mib"}` 也回報非零值，確認整條鏈路
（exporter → UDP 161 → snmpd → 回應 → exporter 解析 → HTTP expositon）
全部通。

## 5. Read-only 裝置存取證據（spec §13.4）

```
$ pilot vm-target exec --name snmp-dev -- snmpset -v3 -u lab-ro-user -l authPriv \
    -a SHA-256 -A authpassword123 -x AES -X privpassword123 localhost 1.3.6.1.2.1.1.4.0 s hacked
Error in packet.
Reason: noAccess
Failed object: iso.3.6.1.2.1.1.4.0
```

`rouser`（read-only view）確實擋下寫入，不是設定了但沒生效。

## 6. Secret scan（spec §13.1/AC7）

```
$ pilot vm-target exec --name snmp-exp -- sudo grep -iE 'authpassword123|privpassword123|lab-ro-user' \
    /etc/pilot/snmp-exporter/auths.yml /etc/pilot/snmp-exporter/catalog.yml /etc/pilot/snmp-exporter/modules/if_mib.yml
CLEAN
```

`snmp-exporter.env`（0600 root:root）跟 `docker inspect
pilot-snmp-exporter --format '{{.Config.Env}}'`（同樣需要 root/docker
群組權限才能讀）才看得到已解析的密碼——這是 spec §13.1 允許的唯一路徑
（exporter host 的 root-owned secret path → 容器 process），不是外洩。

## 7. Idempotency（spec §17.2 positive lane 9）

同一份 apply 對同一台 VM 重跑一次：

```
$ ansible-playbook -i <snmp-exp-inventory.yaml> playbooks/apply/snmp-exporter-apply.yml \
    -e target_group=snmp-exp -e snmp_catalog_file=... -e @<vault>.yml
PLAY RECAP *********************************************************************
snmp-exp   : ok=24   changed=0    unreachable=0    failed=0    skipped=3    rescued=0    ignored=0
```

`changed=0`，且 scrape 重跑一次仍正常回應。

## 8. Config negative lanes（spec §17.3，於本機 `--check` 對真實 catalog 內容驗證）

四條負向路徑，皆用同一份 `playbooks/apply/snmp-exporter-apply.yml` 的
pre_tasks gate 驗證（Jinja 邏輯與目標主機無關，故用 `ansible_connection:
local` 對照組驗證，語意等同對 VM 驗證）：

| 場景 | 結果 |
|---|---|
| `snmp_exporter_credentials` 缺 `lab-switch-v3` 條目 | `assert` FAILED："credentialRef ... is missing or incomplete"（spec §12） |
| catalog 內混入 `community:` key | `assert` FAILED："must not contain community/username/password/privPassword"（spec §6.4 rule 3） |
| `stage=prod` + v2c auth profile、無 exception | `assert` FAILED："which prod rejects unless ... has a non-expired reason/owner/expiry"（spec §13.2） |
| 同上 + 一筆有效（未過期）`snmp_insecure_auth_profile_exceptions` | `assert` PASS |
| 同上但 `expiry` 設在過去 | `assert` FAILED（斷言重新失敗，確認過期判斷真的有效） |

## 9. `pilot verify` 正式驗收

```
$ pilot verify docs/verification/snmp-exporter.md -i <patched-inventory-with-snmp-exporter-group>.yaml
verdict: **PASS**  (pass=12 fail=0 skip=0)
```

`vm-target verify`（wrapper）對單一 bare `all.hosts.<name>` VM 會報
"spec targets matched zero inventory hosts"——這是既有、已知的
`TargetGroupOverride` 死代碼限制（見 pilot 內部 memory
`pilot-verify-single-vm-targetgroup-gap`），跟本次 SNMP 功能無關；workaround
是手動在 inventory 加 `children: {snmp-exporter: {hosts: {snmp-exp: {}}}}`
後改用 `pilot verify -i` 直接跑，同一套 verify pipeline，只是繞過
wrapper 的 group 推導。

## 10. 已知留白（不在 Phase 1 範圍）

- `snmp_catalog_file` 目前需要呼叫端自己組出絕對路徑（`-e
  snmp_catalog_file=$(pwd)/monitoring/snmp/catalog.yml`）；`pilot
  deploy`/`vm-target run` 尚未有類似 `autoFillMonitoringFiles` 的自動
  補完 wiring。Phase 2 的 CLI/TUI 落地時一併補上較合理。
- 真實廠牌設備（非 lab snmpd）與 24h staging soak 屬於 spec §17.4/§18
  (AC23) 的 production gate，明確不在本 Phase 1 範圍內。
- （已補）`internal/spec/snmp_exporter_regression_test.go` 鎖定 row ID
  contiguity 與幾個 cross-row invariant（C3/C4/C5 禁用 docker Go-template
  語法、C1 用 rc-based container-running 檢查等）。

## 11. Teardown

```
$ pilot vm-target down --name snmp-exp
$ pilot vm-target down --name snmp-dev
```
