# Runbook — freeipa-server-replica HA failover 演練計畫

> 撰寫日期：2026-07-09 (UTC)。**2026-09-17 全面改版**：`docs/tmp/now/freeipa-client-ha-spec.md`
> 的 Phase 0-5 落地後，client 端的 HA failover **不再需要任何手動 `sed`**——
> `playbooks/apply/freeipa-server-pool.yml`/`freeipa-client-server-failover.yml`/
> `freeipa-admin-endpoint-select.yml` 全部走 Pilot 自己的 playbook，本檔案的舊版第 6 節手動
> patch krb5.conf/sssd.conf 的步驟已經整段刪除，改成單純重跑
> `pilot vm-target run ... freeipa-client-apply.yml`。
>
> 舊版本歷史：2026-07-10（第一次）改用 `--sandbox`/`vm-target wire`/`--json`；
> 2026-07-10（第二次）改用宣告式 `vm-target topology`；2026-09-17（本次）驗證新的
> server-pool/failover-reconciliation/admin-endpoint-select 機制，涵蓋 S1/S2/H1-H6 全套
> acceptance matrix（H7/H8 未在本輪涵蓋，見 §12 說明）。
>
> 對齊：`docs/verification/freeipa-server-replica.md`（v1.0，C1-C16）、
> `docs/verification/freeipa-client.md`（v1.x，C1-C12）、
> `docs/verification/freeipa-server.md`、
> `playbooks/apply/freeipa-server-apply.yml`、
> `playbooks/apply/freeipa-server-replica-apply.yml`、
> `playbooks/apply/freeipa-client-apply.yml`、
> `playbooks/apply/tasks/freeipa-server-pool.yml`、
> `playbooks/apply/tasks/freeipa-client-server-failover.yml`、
> `playbooks/apply/tasks/freeipa-admin-endpoint-select.yml`
>
> 完整實測敘事（含真實輸出片段）見
> `docs/evidence/freeipa-client-ha/2026-09-17-phase7-full-drill/`——本檔是**可重複執行的步驟
> 清單**，抽掉逐字輸出，方便下次直接照抄重跑。
>
> 本檔每一步都已在真實 vm-target sandbox（`ipa-primary`/`ipa-replica`
> AlmaLinux 9、`ipa-ha-client` Ubuntu 24.04）實跑過，全程只用
> `go run ./cmd/pilot vm-target` 系列指令。

---

## 0. 目標

證明 FreeIPA 的 multi-master HA 真的能在**任一台**server 掛掉時讓 client 不中斷，
同時證明**兩台都掛時 client 真的無法登入**（不是靠巧合或快取誤判）——而且全程**不需要任何
人工編輯 client 的 krb5.conf/sssd.conf**：

1. primary + replica 都上線，client 正常登入/授權（基線，H1）。
2. 只關 primary，client 端 Kerberos 認證 + 身分查詢 + sudo 授權都繼續正常，用**從未在該
   client 查過的 principal**（H2）。
3. 復原 primary、只關 replica，對稱驗證另一個方向（H3）。
4. **兩台都關**，確認 `kinit` 立即失敗（無離線路徑，這是「無法登入」的權威證明），
   同時誠實記錄 SSSD 本機快取對「已查過身分」仍會回應的行為（H4）。
5. 復原至少一台，確認 client **不重跑 Pilot** 就自動恢復（H4 recovery）。
6. Primary 掛著的時候幫一台全新 client 上線，desired pool 仍然保留兩台
   （H5——這是 Phase 0 發現「installer 自己會把打不通的 server 從設定檔整個拿掉」之後，
   Phase 4 的 server-failover reconciliation 補回來的行為）。
7. 既有單機 client 加入 replica 後原地收斂成 HA，不需要 `--uninstall`（H6，見
   `docs/evidence/freeipa-client-ha/2026-09-17-phase4-existing-client-reconciliation/`，
   本檔不重複）。
8. 單機模式（不建 replica、不啟用 DNS 註冊）仍然完整可用，backward compatible（S1/S2）。

三台 vm-target 缺一不可：`ipa-primary`（EL9，realm 起點）、`ipa-replica`
（EL9，multi-master 第二台）、`ipa-ha-client`（Ubuntu，用來觀察「登入是否可能」
的第三方視角）——由 `docs/topologies/freeipa-ha-topology.yaml` 宣告式描述。

---

## 1. 前置確認

```bash
go run ./cmd/pilot vm-target list
```

**預期結果**：乾淨環境應該是空的（`no targets`）。若上次測試留了同名 VM，先
`vm-target topology down --topology docs/topologies/freeipa-ha-topology.yaml`
清掉再重來，避免 IP/狀態殘留。

準備一份 admin 密碼的 vault 檔（假密碼、放 repo 外，例如 scratchpad）：

```bash
cat > /tmp/ha-test-vault.yaml <<'EOF'
ipa_admin_password: "HaTest#Passw0rd123"
EOF
chmod 600 /tmp/ha-test-vault.yaml
```

**每個 `vm-target run` 都預設走 `--sandbox`**，所以還需要建一次控制節點 image
（`images/Dockerfile.pilot-cli`——已經包好 ansible-core + `AGENTS.md` 需要的 collections +
本 repo 的 playbook 範本，比隨便一個第三方 image 更貼近正式環境）：

```bash
docker build -t pilot-cli:latest -f images/Dockerfile.pilot-cli .
```

只需要建一次（除非改了 `pilot` 原始碼或 Dockerfile）。

三台 VM 的拓樸（image、ansible groups、`/etc/hosts` wiring）宣告在
`docs/topologies/freeipa-ha-topology.yaml` 裡（`services: local` 讓重複 `up`/`reset` 都走
host-local cache，見 `.agents/skills/vm-target-spec-testing` §0.1）：

```yaml
services: local
nodes:
  - name: ipa-primary
    base_image: almalinux-9
    memory: 3072
    ssh_timeout: 8m
    boot_timeout: 8m
    groups: [ipa_masters]
    wire: ["ipa-replica=ipa2.ipa.pilot.internal"]
  - name: ipa-replica
    base_image: almalinux-9
    memory: 3072
    ssh_timeout: 8m
    boot_timeout: 8m
    groups: [ipa_replicas]
  - name: ipa-ha-client
    base_image: ubuntu-24.04
    memory: 2048
    ssh_timeout: 8m
    boot_timeout: 8m
    groups: [ipa_clients]
    wire: ["ipa-replica=ipa2.ipa.pilot.internal"]
```

> `groups:` 這裡是 vm-target topology 自己的標籤（`ipa_masters`/`ipa_replicas`/
> `ipa_clients`），**不是** production 的 `freeipa-server`/`freeipa-server-replica`/
> `freeipa-client` group 名稱。§4 的 client apply 一律改用
> `pilot vm-target run --group freeipa-server=ipa-primary --group
> freeipa-server-replica=ipa-replica --group freeipa-client=ipa-ha-client`
> 組出「真正的」production role-group 名稱，這樣 `freeipa-server-pool.yml` 的
> inventory-driven 邏輯（讀 `groups['freeipa-server']`/`groups['freeipa-server-replica']`）
> 才會走到真實路徑，不是只靠 `-e ipa_server_ip=` override 繞過去。

---

## 2. 起 3 台 VM

```bash
go run ./cmd/pilot vm-target topology up --topology docs/topologies/freeipa-ha-topology.yaml
```

`topology up` 平行 `up` 每個尚未啟動的 node，完成後自動把 replica 的 IP 冪等 pin 進
primary 跟 client 的 `/etc/hosts`（`wire:` 宣告），不用再手動組 `wire` 指令。

```bash
go run ./cmd/pilot vm-target list
go run ./cmd/pilot vm-target topology status --topology docs/topologies/freeipa-ha-topology.yaml
```

> **已知環境 gotcha（每次 `up`/`reset` 後都要做，見 §12）**：這個 host 上的
> `vm-target reset`/`topology reset` 有時會讓 VM 系統時鐘落後真實時間（曾經測到落後
> 54-90 分鐘），`chronyd` 顯示 `active` 但從未真的同步過。Kerberos 對時鐘偏移 >5 分鐘零容忍，
> 這會讓 `ipa-client-install`/`ipa-replica-install` 用一個完全無關的錯誤訊息失敗
> （`ScriptError: Configuration of client side components failed!`）。**每次 `up` 或
> `reset` 之後、跑任何 FreeIPA playbook 之前**，先校正時鐘：
>
> ```bash
> # AlmaLinux（有 hwclock）
> go run ./cmd/pilot vm-target exec --name ipa-primary -- sudo hwclock -s
> go run ./cmd/pilot vm-target exec --name ipa-replica -- sudo hwclock -s
> # Ubuntu（沒有 hwclock，直接從 host 的 epoch 設定）
> EPOCH=$(date -u +%s)
> go run ./cmd/pilot vm-target exec --name ipa-ha-client -- sudo date -s "@$EPOCH"
> ```
>
> 同一個 host 上，Ubuntu client 的 apt-cacher-ng 快取索引也可能是幾個月前 image 建置時的
> 舊版本，導致 `apt-get install freeipa-client` 找不到（已被清掉的）舊版套件檔。每次
> `reset` 這台 Ubuntu client 之後，先手動 `apt-get update` 一次讓索引跟上：
>
> ```bash
> go run ./cmd/pilot vm-target exec --name ipa-ha-client -- sudo apt-get update -qq
> ```

---

## 3. 部署 primary（起 realm）

```bash
go run ./cmd/pilot vm-target run --name ipa-primary --sandbox --sandbox-image pilot-cli:latest \
    playbooks/apply/freeipa-server-apply.yml \
    -e target_group=all -e ipa_server_ip=<primary-ip-from-vm-target-list> \
    -e @/tmp/ha-test-vault.yaml

go run ./cmd/pilot vm-target verify --name ipa-primary \
    docs/verification/freeipa-server.md --timeout 40
```

**本輪實測**：`ok=40 changed=16 failed=0`；verify 20/20 PASS。

---

## 4. 部署 replica（加入既有 realm，DNS 現在預設跟 primary 一致）

`ipa-replica-install` 會叫 primary 反過來連回這台新 replica 做 conncheck；§2 的
`topology up` 已經自動把 replica 的 FQDN/IP pin 進 primary 的 `/etc/hosts`，不需要再手動
`vm-target wire`。

```bash
go run ./cmd/pilot vm-target run --name ipa-replica --sandbox --sandbox-image pilot-cli:latest \
    playbooks/apply/freeipa-server-replica-apply.yml \
    -e target_group=all -e ipa_server_ip=<primary-ip> -e ipa_replica_ip=<replica-ip> \
    -e @/tmp/ha-test-vault.yaml

go run ./cmd/pilot vm-target verify --name ipa-replica \
    docs/verification/freeipa-server-replica.md --timeout 40
```

**本輪實測**：`ok=18 changed=6 failed=0`；verify **16/16 PASS**（比舊版多一個 C16：DNS role
是否依政策生效——`ipa_setup_dns` 現在**預設跟 primary 一樣是 `true`**，見
`docs/evidence/freeipa-client-ha/2026-09-17-phase2-replica-dns-parity/`，這裡不重複那個
drill）。

> 舊版本這裡的 replica 預設 `ipa_setup_dns=false`，跟 primary 的 `true` 不一致，形成「只有
> primary 一台 DNS provider」的 SPOF——**已在 2026-09-17 修掉**，不用再自己記得帶
> `-e freeipa_setup_dns=true`。

---

## 5. 建立測試帳號 fixture

```bash
go run ./cmd/pilot vm-target run --name ipa-primary --sandbox --sandbox-image pilot-cli:latest \
    playbooks/test/fixtures/freeipa-client-fixtures.yml \
    -e fixtures_target_group=all -e @/tmp/ha-test-vault.yaml
```

**本輪實測**：`ok=7 changed=4 failed=0`——建立 `pilotuser` + sudo 規則 `pilot-all`
（hostcat=all cmdcat=all `!authenticate`）。**不要**在別處手刻 `ipa user-add`——這是本 repo
canonical 的 demo 帳號建立方式（`AGENTS.md` §4.1）。

---

## 6. Enroll client 向兩台 server（H1 基線）——全程沒有手動編輯任何檔案

```bash
go run ./cmd/pilot vm-target run --name ipa-ha-client \
    --group freeipa-server=ipa-primary \
    --group freeipa-server-replica=ipa-replica \
    --group freeipa-client=ipa-ha-client \
    --sandbox --sandbox-image pilot-cli:latest \
    playbooks/apply/freeipa-client-apply.yml \
    -e target_group=freeipa-client \
    -e @/tmp/ha-test-vault.yaml
```

**本輪實測**：`ok=146 changed=21 failed=0`。全程**沒有任何手動 `sed`**——
`freeipa-server-pool.yml`（算出 `freeipa_server_fqdns=[ipa1, ipa2]`）→
`ipa-client-install --server=ipa1 --server=ipa2 ...`（Pilot 自己組出重複 `--server`）→
`freeipa-client-server-failover.yml`（無條件收斂 krb5.conf/sssd.conf 到完整 desired pool）
一次到位。

驗證 `/etc/hosts`（pool-aware managed block，跟 client 自己的 self-pin 分開)：

```bash
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- cat /etc/hosts
```
```
192.168.122.6 ipa-ha-client.ipa.pilot.internal ipa-ha-client
# BEGIN PILOT FREEIPA SERVER POOL
192.168.122.8 ipa1.ipa.pilot.internal ipa1
192.168.122.7 ipa2.ipa.pilot.internal ipa2
# END PILOT FREEIPA SERVER POOL
```

驗證 sssd.conf/krb5.conf（Pilot 自己寫入,不是手動 sed）：

```bash
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- sudo grep ipa_server /etc/sssd/sssd.conf
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- sudo grep "kdc = " /etc/krb5.conf
```
```
ipa_server = _srv_, ipa1.ipa.pilot.internal, ipa2.ipa.pilot.internal
```
```
    kdc = ipa1.ipa.pilot.internal:88
    kdc = ipa2.ipa.pilot.internal:88
```

---

## 7. 建立基線（兩台都上線）

```bash
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- id pilotuser@ipa.pilot.internal
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- sudo -l -U pilotuser
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- \
    bash -c 'printf "%s" "HaTest#Passw0rd123" | kinit admin@IPA.PILOT.INTERNAL && klist -s && echo KINIT_OK && kdestroy'
go run ./cmd/pilot vm-target verify --name ipa-ha-client docs/verification/freeipa-client.md --timeout 40
```

**本輪實測**：`id`/`sudo -l`/`kinit` 全部 PASS；`pilot vm-target verify` **12/12 PASS**。

---

## 8. 演練 H2：關 primary，用「從未查過的 principal」驗證 failover

不要用已經查過的帳號（例如 `admin`/`pilotuser`）當「兩台都掛」判定依據——SSSD 本機快取對
已查過身分會在離線時繼續回應，容易誤判。先在 primary 建一個這次 drill **專用、之前從沒在
client 上查過**的帳號：

```bash
go run ./cmd/pilot vm-target exec --name ipa-primary -- bash -c '
printf "%s" "HaTest#Passw0rd123" | kinit admin@IPA.PILOT.INTERNAL
ipa user-add drilluser --first Drill --last User --password <<< $'"'"'DrillPass#456\nDrillPass#456\n'"'"'
ipa sudorule-add-user pilot-all --users=drilluser
'
# 新帳號的密碼是一次性、必須改密——用一次 kinit 順便改成長期密碼
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- bash -c '
printf "DrillPass#456\nDrillPass#789\nDrillPass#789\n" | kinit drilluser@IPA.PILOT.INTERNAL
kdestroy
'
```

關掉 primary，清票證+快取：

```bash
go run ./cmd/pilot vm-target exec --name ipa-primary -- sudo systemctl stop ipa
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- bash -c 'kdestroy; sudo sss_cache -E'
```

驗證（全部必須 PASS）：

```bash
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- id drilluser@ipa.pilot.internal
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- sudo -l -U drilluser
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- \
    bash -c 'printf "DrillPass#789" | kinit drilluser@IPA.PILOT.INTERNAL && echo KINIT_OK'
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- dig @<replica-ip> _kerberos._udp.ipa.pilot.internal SRV +short
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- sudo sssctl domain-status ipa.pilot.internal
```

**本輪實測**：全部 PASS（`sssctl domain-status` 顯示 `Active servers: IPA: ipa2...`，client
已切去 replica）。

> **本輪踩到的 gotcha**：`sudo -l -U drilluser` 第一次仍回報「not allowed」，即使
> `sudorule-add-user` 早就成功且已複寫到兩台（用 `ipa sudorule-show pilot-all` 在 replica 上
> 確認過)。單靠 `sss_cache -E` 沒能讓 SSSD 撿到這個「剛剛才加進去」的 sudo 規則成員——要
> `sudo systemctl stop sssd && sudo rm -rf /var/lib/sss/db/* && sudo systemctl start sssd`
> 整個重建快取才生效。這是 SSSD sudo 規則快取的既有限制，跟 primary 是否掛掉無關（同樣的坑
> 在 Phase 3 對 `pilotuser` 也踩過一次）；也順便證明了：即使快取整個歸零，client 仍然能只靠
> 活著的 replica 完整重建身分/sudo/DNS 資訊。

---

## 9. 演練 H3：復原 primary、關 replica，對稱驗證

```bash
go run ./cmd/pilot vm-target exec --name ipa-primary -- sudo systemctl start ipa
go run ./cmd/pilot vm-target exec --name ipa-replica -- sudo systemctl stop ipa
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- bash -c '
sudo systemctl stop sssd; sudo rm -rf /var/lib/sss/db/*; sudo systemctl start sssd
'
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- id drilluser@ipa.pilot.internal
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- sudo -l -U drilluser
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- \
    bash -c 'printf "%s" "HaTest#Passw0rd123" | kinit admin@IPA.PILOT.INTERNAL && echo KINIT_OK'
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- dig @<primary-ip> _kerberos._udp.ipa.pilot.internal SRV +short
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- sudo sssctl domain-status ipa.pilot.internal
```

**本輪實測**：同演練 H2，但 `Active servers` 變回 `ipa1.ipa.pilot.internal`——完全對稱。

---

## 10. 演練 H4：兩台都關，確認真的無法登入；復原後不重跑 Pilot 就自動恢復

```bash
go run ./cmd/pilot vm-target exec --name ipa-primary -- sudo systemctl stop ipa
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- bash -c 'kdestroy; sudo sss_cache -E'

# 權威證明：kinit 沒有離線路徑，兩台都掛必定立即失敗
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- \
    timeout 20 bash -c 'printf "DrillPass#789" | kinit drilluser@IPA.PILOT.INTERNAL; echo "rc=$?"'

# 對照組：從未查過的身分——沒有任何快取可用，必定失敗
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- \
    bash -c 'id neverseenuser@ipa.pilot.internal; echo "rc=$?"'

# 誠實補充：已快取過的身分/sudo 規則，離線期間仍會回應（SSSD 設計，不是 bug）
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- id drilluser@ipa.pilot.internal
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- sudo -l -U drilluser
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- sudo sssctl domain-status ipa.pilot.internal
```

**本輪實測**：
```
kinit: Cannot contact any KDC for realm 'IPA.PILOT.INTERNAL' while getting initial credentials
rc=1
id: 'neverseenuser@ipa.pilot.internal': no such user
rc=1
```
已快取身分/sudo 規則仍會成功；`sssctl domain-status` 顯示 `Online status: Offline`。

**復原、確認不用重跑 Pilot：**

```bash
go run ./cmd/pilot vm-target exec --name ipa-primary -- sudo systemctl start ipa
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- \
    bash -c 'printf "%s" "HaTest#Passw0rd123" | kinit admin@IPA.PILOT.INTERNAL && echo KINIT_OK_AUTO_RECOVERED'
```

**本輪實測**：`KINIT_OK_AUTO_RECOVERED`——primary 一恢復立刻可登入，全程沒有重跑任何
`freeipa-client-apply.yml`。

> **Gotcha**：`sssctl domain-status` 的 `Online status` 欄位在 `kinit` 已經成功之後仍可能
> 顯示 `Offline` 好一陣子（本輪甚至連另一台也復原了都還沒跳回來），要 `sudo systemctl
> restart sssd` 才會馬上刷新。**判斷「有沒有恢復」要用真的 `kinit`/`id`，不要只看這個欄位**。

記得把 replica 也啟動回來，恢復完整 HA 基線：

```bash
go run ./cmd/pilot vm-target exec --name ipa-replica -- sudo systemctl start ipa
```

---

## 11. 演練 H5：primary 掛著的時候幫全新 client 上線

```bash
go run ./cmd/pilot vm-target exec --name ipa-primary -- sudo systemctl stop ipa
go run ./cmd/pilot vm-target reset --name ipa-ha-client
# 記得先校正時鐘 + apt-get update（見 §2 的 gotcha）

go run ./cmd/pilot vm-target run --name ipa-ha-client \
    --group freeipa-server=ipa-primary \
    --group freeipa-server-replica=ipa-replica \
    --group freeipa-client=ipa-ha-client \
    --sandbox --sandbox-image pilot-cli:latest \
    playbooks/apply/freeipa-client-apply.yml \
    -e target_group=freeipa-client \
    -e @/tmp/ha-test-vault.yaml
```

**本輪實測**：`ok=144 changed=21 failed=0`——enrollment 透過 replica 成功。**關鍵驗證**：

```bash
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- sudo grep ipa_server /etc/sssd/sssd.conf
```
```
ipa_server = _srv_, ipa1.ipa.pilot.internal, ipa2.ipa.pilot.internal
```

即使 `ipa1` 在 enroll 當下打不通，desired pool 仍然是 `[ipa1, ipa2]` 兩台都在——這是
`freeipa-client-server-failover.yml` 無條件在 enrollment 後執行的結果（見 Phase 0 的發現：
`ipa-client-install` 自己只會把打不通的 server 整個從設定檔拿掉，不會保留；沒有這個
reconciliation 步驟的話，H5 一定會失敗）。`kinit`/`id` 透過 replica 正常；primary 復原後
`kinit` 依然正常，rerun `changed=0`。

```bash
go run ./cmd/pilot vm-target exec --name ipa-primary -- sudo systemctl start ipa
```

---

## 12. 已知未在本輪涵蓋的項目

- **H6（既有單機 client 加入 replica 後原地收斂成 HA）**：已驗證,但屬於 Phase 4 的獨立
  drill,見 `docs/evidence/freeipa-client-ha/2026-09-17-phase4-existing-client-reconciliation/`，
  本檔不重複。
- **H7（新增第三台 replica）/ H8（移除 replica）**：需要第三台 FreeIPA server VM（H7）或完整
  decommission 流程（H8），本輪礙於時間/資源沒有跑活體 3-VM 版本。Phase 1 的
  server-pool 事實運算邏輯（多 replica 需各自 `freeipa_replica_fqdn` 才能通過)已經用合成
  3-node inventory 跑過真實 ansible-playbook（見
  `docs/evidence/freeipa-client-ha/2026-09-17-phase1-server-pool/`），但沒有活體驗證過
  「新增/移除一台後 client rerun 正確更新清單」這件事本身。
- **Phase 6（contract provider pool，讓「primary down + replica up」不被 Pilot 自己的
  site-wide 自動化部署誤判成 dependency unavailable）**：這次完全沒做，設計方向已經在
  `docs/tmp/now/freeipa-client-ha-spec.md` 的 Phase 6 章節想清楚，留給之後。本檔證明的是
  「client 本身的 HA runtime」+「Pilot 對已選定 client 的 Day-2 CLI 操作」都撐得住 primary
  掛掉,不是「site-wide 自動化部署會不會跳過 freeipa-client」這個更上層的問題。
- **S2 的「primary 本身完全沒有 integrated DNS」**：本輪測的是 client 端
  `-e freeipa_client_register_dns=false`（client 不需要 DNS 也能正常運作),沒有另外搭一台
  真的關掉 DNS 的 primary。

---

## 13. Cluster reset：驗證整台叢集能回到乾淨狀態重跑

```bash
go run ./cmd/pilot vm-target topology reset --topology docs/topologies/freeipa-ha-topology.yaml
```

`topology reset` 對 3 台 VM 平行復原到 `up` 剛開完機的狀態，並自動對宣告了 `wire:` 的 node
重新跑一次 wiring——不用再手動對每台個別 `reset` + 補 `wire`。記得復原後照 §2 的 gotcha
校正時鐘、跑一次 `apt-get update`。

---

## 14. 收尾 Teardown

```bash
go run ./cmd/pilot vm-target topology down --topology docs/topologies/freeipa-ha-topology.yaml
go run ./cmd/pilot vm-target list   # 確認為空
rm -f /tmp/ha-test-vault.yaml
```

**這步過了，HA 演練就算成功。**

---

## 15. 已知 gotcha 一覽（跑之前先知道，少走冤枉路）

| 症狀 | 原因 | 解法 |
|---|---|---|
| `vm-target reset`/`up` 後 `ipa-client-install`/`ipa-replica-install` 失敗，錯誤訊息很籠統（`Configuration of client side components failed!`） | VM 系統時鐘落後真實時間（曾測到落後 54-90 分鐘），`chronyd` 顯示 `active` 但從未真的同步過；Kerberos 對時鐘偏移零容忍 | 每次 `up`/`reset` 後先校正時鐘：AlmaLinux `sudo hwclock -s`，Ubuntu `sudo date -s "@$(date -u +%s)"`（見 §2） |
| Ubuntu client 上 `apt-get install freeipa-client` 因為某個依賴套件 404 而失敗 | image 建置當下快取的 apt 索引已經過時，索引裡記的套件版本早被上游清掉 | `reset` 後先手動 `sudo apt-get update` 一次（見 §2） |
| 剛用 `ipa sudorule-add-user` 幫某帳號加了 sudo 規則，client 上 `sudo -l -U` 卻回報 not allowed，即使 `sss_cache -E` 也沒用 | SSSD 的 sudo 規則快取對「剛發生的成員異動」有時無法只靠 `sss_cache -E` 撿到，即使兩台 server 都已經複寫完成 | `sudo systemctl stop sssd && sudo rm -rf /var/lib/sss/db/* && sudo systemctl start sssd` 整個重建快取（見 §8） |
| `sssctl domain-status` 的 `Online status` 在 server 明明已經復原、`kinit` 也已經成功之後，還是顯示 `Offline` 好一陣子 | 這個欄位不是即時的，落後於真實連線狀態 | 判斷「有沒有恢復」要用真的 `kinit`/`id`，不要只看這個欄位；要馬上刷新可以 `sudo systemctl restart sssd`（見 §10） |
| 關掉 server 後 `id`/`sudo -l` 卻還是成功，一度誤判「HA 沒生效」或「根本沒關掉」 | SSSD 本機快取（`cache_credentials=True`）對**已經查過**的身分/sudo 規則會在離線時繼續回應，這是設計行為 | 別用 `id`/`sudo -l` 當「兩台都掛」的判定依據；改用 `kinit`（Kerberos 取票沒有離線路徑，一定會如實失敗），或查一個從未查過的身分（也會如實失敗），見 §10 |
| `ipa-replica-install` 失敗：`ERROR: Port check failed! Unable to resolve host name '<replica-fqdn>'` | primary 在 conncheck 時會反過來連回新 replica，沒有內建 DNS 時 primary 解析不到新節點 | `docs/topologies/freeipa-ha-topology.yaml` 裡 `ipa-primary` 節點的 `wire:` 宣告，`topology up` 會自動把新 replica 的 FQDN/IP 冪等 pin 進 primary 的 `/etc/hosts`（不需要再手動下 `vm-target wire`） |
| `sudo -l` 對任何人永遠回 `not allowed`，看起來像 sudo 規則沒生效（首次 enrollment 時） | `ipa-client-install` 在 Ubuntu 上若把 `sudo` 塞進 SSSD 的 `services=` 這行，會跟現代 SSSD（≥2.3）預設的 socket-activated sudo responder 衝突 | 已修：`freeipa-client-apply.yml` 的 `services=` 拿掉 `sudo`，交給 socket activation |
| `pilot vm-target run --name <某台> ...` 顯示 `skipping: no hosts matched` | apply playbook 的 `hosts:` 預設是角色 group 名（`freeipa-server`/`freeipa-server-replica`/`freeipa-client`），單一 `--name` 的 vm-target inventory 只有同名的 **host**、沒有這個 **group** | 一律加 `-e target_group=all`（單台 apply）或 `-e target_group=freeipa-client`（配合 `--group` 组出多角色 inventory 時，見 §6） |
| `--sandbox` 模式下 `-e @/tmp/xxx-vault.yaml` 報 `Unable to retrieve file contents` | `ansible-playbook` 是在容器**裡面**跑的，vault 檔案本來沒被複製進去 | 已修：`vtRunViaContainer` 會自動偵測 `-e @path` 形式，把對應的 host 檔案 `docker cp` 進容器 |

更完整的逐字真實輸出見
`docs/evidence/freeipa-client-ha/2026-09-17-phase7-full-drill/`（本輪）與
`docs/evidence/freeipa-client-ha/`（Phase 0-5 各自的子目錄）。
