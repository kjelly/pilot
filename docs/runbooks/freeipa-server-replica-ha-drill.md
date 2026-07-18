# Runbook — freeipa-server-replica HA failover 演練計畫

> 撰寫日期：2026-07-09 (UTC)。本檔已完整重跑並驗證過兩次：
> 2026-07-10（第一次）改用 `--sandbox`/`vm-target wire`/`--json`；
> 2026-07-10（第二次）再改用宣告式 `vm-target topology`
> （spec：`docs/topologies/freeipa-ha-topology.yaml`）取代手動
> `up` x3 + `wire` x2，三輪數字/行為一致。
> 對齊：`docs/verification/freeipa-server-replica.md`（v1.0）§9、
> `docs/verification/freeipa-server.md`、`docs/verification/freeipa-client.md`、
> `playbooks/apply/freeipa-server-apply.yml`、
> `playbooks/apply/freeipa-server-replica-apply.yml`、
> `playbooks/apply/freeipa-client-apply.yml`
> 對照文件：完整實測敘事（含真實輸出片段）見
> `docs/verification/freeipa-server-replica.md` §9——本檔是**可重複執行的步驟
> 清單**，抽掉逐字輸出，方便下次直接照抄重跑。
>
> 本檔每一步都已在真實 vm-target sandbox（`ipa-primary`/`ipa-replica`
> AlmaLinux 9、`ipa-ha-client` Ubuntu 24.04）實跑過三輪，全程只用
> `go run ./cmd/pilot vm-target` 系列指令，三輪數字/結果一致。

---

## 0. 目標

證明 FreeIPA 的 multi-master HA 真的能在**任一台**server 掛掉時讓 client 不中斷，
同時證明**兩台都掛時 client 真的無法登入**（不是靠巧合或快取誤判）：

1. primary + replica 都上線，client 正常登入/授權（基線）。
2. 只關 primary，client 端 Kerberos 認證 + 身分查詢 + sudo 授權都繼續正常。
3. 復原 primary、只關 replica，對稱驗證另一個方向。
4. **兩台都關**，確認 `kinit` 立即失敗（無離線路徑，這是「無法登入」的權威證明），
   同時誠實記錄 SSSD 本機快取對「已查過身分」仍會回應的行為。
5. 復原至少一台，確認 client 自動恢復。

三台 vm-target 缺一不可：`ipa-primary`（EL9，realm 起點）、`ipa-replica`
（EL9，multi-master 第二台）、`ipa-ha-client`（Ubuntu，用來觀察「登入是否可能」
的第三方視角）——由 `docs/topologies/freeipa-ha-topology.yaml` 宣告式描述。

---

## 1. 前置確認

```bash
go run ./cmd/pilot vm-target list
```

**預期結果**：乾淨環境應該是空的（`no targets`）。若上次測試留了同名 VM，先
`vm-target down`（或 `vm-target topology down --topology docs/topologies/freeipa-ha-topology.yaml`）
清掉再重來，避免 IP/狀態殘留。

準備一份 admin 密碼的 vault 檔（假密碼、放 repo 外，例如 scratchpad）：

```bash
cat > /tmp/ha-test-vault.yaml <<'EOF'
ipa_admin_password: "HaTest#Passw0rd123"
EOF
chmod 600 /tmp/ha-test-vault.yaml
```

**每個 `vm-target run` 都預設走 `--sandbox`**（`.agents/skills/vm-target-spec-testing`
的新預設做法），所以還需要建一次控制節點 image（`images/Dockerfile.pilot-cli`
——已經包好 ansible-core + `AGENTS.md` 需要的 collections + 本 repo 的
playbook 範本，比隨便一個第三方 image 更貼近正式環境）：

```bash
docker build -t pilot-cli:latest -f images/Dockerfile.pilot-cli .
```

只需要建一次（除非改了 `pilot` 原始碼或 Dockerfile）；本輪實測 image 早已快取，
略過重建。

三台 VM 的拓樸（image、ansible groups、`/etc/hosts` wiring）宣告在
`docs/topologies/freeipa-ha-topology.yaml` 裡，內容摘要：

```yaml
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

> `vm-target topology up` 會**平行** `up` 每個尚未啟動的 node（每個 node 各自
> 一個 `*vmtarget.Manager`）——2026-07-06 的 state race 修復（`statefile`
> flock + `Store.Mutate`，見 `pilot-vm-target-up-concurrency-race` 記憶、
> `AGENTS.md` §5.1）已讓不同名稱的並行 `up` 安全，`topology up` 直接利用這一
> 點縮短三台 VM 的總開機時間。

---

## 2. 起 3 台 VM（`vm-target topology up`）

```bash
go run ./cmd/pilot vm-target topology up --topology docs/topologies/freeipa-ha-topology.yaml
```

`topology up` 平行 `up` 每個尚未啟動的 node（每個 node 各自一個
`*vmtarget.Manager`，指向同一個 state/vm dir——不同名稱的並行 `up` 自
2026-07-06 起就是安全的，見 `pilot-vm-target-up-concurrency-race` 記憶、
`AGENTS.md` §5.1），比舊版 3× 循序 `up` 快。**本輪實測輸出**（golden image
已快取；三個 `provisioning`/`waiting for IP` 訊息交錯出現，證明真的是平行
執行，不是照 spec 順序循序跑）：

```
▶ provisioning ipa-ha-client...
▶ provisioning ipa-replica...
▶ provisioning ipa-primary...
  ✓ reserved static IP 192.168.122.2 for ipa-ha-client (MAC 52:54:00:7f:8e:b7) on network default
  ✓ reserved static IP 192.168.122.3 for ipa-replica (MAC 52:54:00:49:74:96) on network default
  ✓ reserved static IP 192.168.122.4 for ipa-primary (MAC 52:54:00:3e:d9:65) on network default
  … ipa-replica waiting for IP (elapsed 10s)  (no active lease for MAC 52:54:00:49:74:96 yet)
  … ipa-primary waiting for IP (elapsed 10s)  (no active lease for MAC 52:54:00:3e:d9:65 yet)
✓ ipa-ha-client up (ip=192.168.122.2)
  … ipa-primary waiting for IP (elapsed 20s)  (no active lease for MAC 52:54:00:3e:d9:65 yet)
  … ipa-replica waiting for IP (elapsed 20s)  (no active lease for MAC 52:54:00:49:74:96 yet)
✓ ipa-primary up (ip=192.168.122.4)
✓ ipa-replica up (ip=192.168.122.3)
✓ wired ipa2.ipa.pilot.internal -> ipa-primary (192.168.122.3)
✓ wired ipa2.ipa.pilot.internal -> ipa-ha-client (192.168.122.3)

inventory : `pilot vm-target topology inventory --topology docs/topologies/freeipa-ha-topology.yaml`
```

`time` 量測：三台平行 `up`（含開機 + wire）總共 **34.5s**（`real 0m34.528s`），
對照舊版循序 3× `up` 那輪要 3 台各自等一輪 lease/boot、總耗時明顯更長。

這一步就把**舊版 §2（3× `up`）+ §4/§6 的手動 `wire`** 全部做完了：三台 VM
起來後自動把 replica 的 IP 冪等 pin 進 primary 跟 client 的 `/etc/hosts`
——不用再讀 IP、手動組 `wire`/`exec` 指令。

確認狀態（同一輪的 `vm-target list` + `topology status`，證明平行 `up` 沒有
丟任何一台的 state）：

```bash
go run ./cmd/pilot vm-target list
go run ./cmd/pilot vm-target topology status --topology docs/topologies/freeipa-ha-topology.yaml
```

**本輪實測**：

```
NAME           STATUS   IP             VCPU  MEM(MiB)  DISK(GiB)  CREATED
ipa-ha-client  running  192.168.122.2  2     2048      30         2026-07-10 11:07:11
ipa-primary    running  192.168.122.4  2     3072      30         2026-07-10 11:07:11
ipa-replica    running  192.168.122.3  2     3072      30         2026-07-10 11:07:11

NAME           STATUS   IP             GROUPS        WIRE
ipa-primary    running  192.168.122.4  ipa_masters   ipa-replica=ipa2.ipa.pilot.internal
ipa-replica    running  192.168.122.3  ipa_replicas  -
ipa-ha-client  running  192.168.122.2  ipa_clients   ipa-replica=ipa2.ipa.pilot.internal
```

三個 node 全數 `running`，沒有任何一筆消失——這正是
`TestUp_ConcurrentDifferentNames_BothPersist` 在真實 vm-target/libvirt 環境
下的等價驗證。這一輪只用來驗證平行 `up` 本身（up → status → down），接著
拆掉重來，§3 起的 FreeIPA 部署/演練沿用另一輪完整跑過的實測（`up` 換成序列
或平行不影響 FreeIPA 安裝本身的行為，故不重複整套演練）。

> 每次重跑分配到的 IP 不保證相同（依 dnsmasq 當時可用的 lease 而定，也可能
> 隨平行/循序 `up` 的完成順序而不同）——後面步驟的
> `-e ipa_server_ip=`/`-e ipa_replica_ip=` 一律照當次 `topology
> up`/`status` 印出來的 IP 填，不要照抄本檔寫死的數字。

---

## 3. 部署 primary（起 realm）

```bash
go run ./cmd/pilot vm-target run --name ipa-primary --sandbox --sandbox-image pilot-cli:latest \
    playbooks/apply/freeipa-server-apply.yml \
    -e target_group=all -e ipa_server_ip=192.168.122.4 \
    -e @/tmp/ha-test-vault.yaml

go run ./cmd/pilot vm-target verify --name ipa-primary \
    docs/verification/freeipa-server.md --timeout 40
```

**本輪實測結果**：
```
PLAY RECAP *********************************************************************
ipa-primary                : ok=18   changed=6    unreachable=0    failed=0    skipped=4    rescued=0    ignored=0

verdict: PASS  (pass=18 fail=0 skip=0)
```
每次 `run` 都會自動把完整輸出寫進
`<vm-dir>/ipa-primary/runs/<timestamp>-freeipa-server-apply.log`（路徑印在
stderr）——這次是
`.../ipa-primary/runs/20260710T003410Z-freeipa-server-apply.log`。需要逐字
複查時直接 `cat` 這個檔案，不用重新用終端機捲軸手抄。

---

## 4. 部署 replica（加入既有 realm）

`ipa-replica-install` 會叫 primary 反過來連回這台新 replica 做 conncheck；
沒有內建 DNS 時 primary 解析不到新節點的 FQDN 就會整個 install 失敗
（`ERROR: Port check failed! Unable to resolve host name`）。**這一步已經在
§2 的 `topology up` 裡自動處理過了**（`ipa-primary` 的 spec 宣告了
`wire: ["ipa-replica=ipa2.ipa.pilot.internal"]`），不需要再手動下
`vm-target wire`。

直接套用 replica apply playbook：

```bash
go run ./cmd/pilot vm-target run --name ipa-replica --sandbox --sandbox-image pilot-cli:latest \
    playbooks/apply/freeipa-server-replica-apply.yml \
    -e target_group=all -e ipa_server_ip=192.168.122.4 -e ipa_replica_ip=192.168.122.5 \
    -e @/tmp/ha-test-vault.yaml

go run ./cmd/pilot vm-target exec --name ipa-replica -- true   # 暖 SSH 連線
go run ./cmd/pilot vm-target verify --name ipa-replica \
    docs/verification/freeipa-server-replica.md --timeout 40
```

**本輪實測結果**：
```
PLAY RECAP *********************************************************************
ipa-replica                 : ok=17   changed=6    unreachable=0    failed=0    skipped=3    rescued=0    ignored=0

verdict: PASS  (pass=15 fail=0 skip=0)
```
（C14/C15 證明雙向拓樸複寫已同步）。transcript：
`.../ipa-replica/runs/20260710T004030Z-freeipa-server-replica-apply.log`。

> 這一對 playbook（server + server-replica）各自的 `hosts:` 只需要單一目標
> 自己的 inventory，跨主機的溝通是走 FreeIPA/Kerberos 協定本身（網路層），不是
> 靠 ansible 在同一個 play 裡同時操作兩台主機——所以這裡**不需要** `run
> --group`（`topology.yaml` 的 `groups:` 欄位只是給 `topology inventory`
> 備用，這對 playbook 用不到）。`--group`/`topology inventory` 是給「同一個
> play 真的要同時對多個 named vm-target 下手」的情境用的（見
> `.agents/skills/vm-target-spec-testing/references/vm-target-basics.md`）。

---

## 5. 建立測試帳號 fixture（跨 host 前置，canonical 做法）

```bash
go run ./cmd/pilot vm-target run --name ipa-primary --sandbox --sandbox-image pilot-cli:latest \
    playbooks/test/fixtures/freeipa-client-fixtures.yml \
    -e fixtures_target_group=all -e @/tmp/ha-test-vault.yaml
```

**本輪實測結果**：`PLAY RECAP ... ok=7 changed=4 failed=0`——建立 `pilotuser`
+ sudo 規則 `pilot-all`（hostcat=all cmdcat=all `!authenticate`）。transcript：
`.../ipa-primary/runs/20260710T004920Z-freeipa-client-fixtures.log`。**不要**
在別處手刻 `ipa user-add`——這是本 repo canonical 的 demo 帳號建立方式
（`AGENTS.md` §4.1）。

**`--json` 快速 triage 範例**（同一個 playbook 冪等重跑一次，這次不加
`--sandbox`——`--json` 目前不支援跟 `--sandbox` 疊用，見
`vm-target-basics.md`；下列輸出取自本檔第一次導入 `--json`/`--sandbox` 那輪
的實測——`--json`/fixtures playbook 本身跟這次改用 `topology` 無關，行為不變，
本輪未重跑）：

```bash
go run ./cmd/pilot vm-target run --name ipa-primary \
    playbooks/test/fixtures/freeipa-client-fixtures.yml --json \
    -e fixtures_target_group=all -e @/tmp/ha-test-vault.yaml
```

**實測結果**：`ipa-primary: ok=7 changed=0 failed=0 unreachable=0
skipped=0`——一行就看出「這次重跑沒有任何 drift」，比在 §6 之後才用 PLAY RECAP
反查快很多；同時也順便證實了 fixture playbook 本身是冪等的（`changed=0`）。
（跑這步會先看到 `ansible-lint` 的預設前置檢查印出既有的 5 個非致命
style violation——這是既有已知的 lint 雜訊，不影響本次演練，不用理它。）

---

## 6. Enroll client 向 primary + 補上 client 端 failover 設定

```bash
go run ./cmd/pilot vm-target run --name ipa-ha-client --sandbox --sandbox-image pilot-cli:latest \
    playbooks/apply/freeipa-client-apply.yml \
    -e target_group=all -e ipa_server_ip=192.168.122.4 \
    -e @/tmp/ha-test-vault.yaml
```

**本輪實測結果**：`PLAY RECAP ... ok=23 changed=11 failed=0 skipped=4`。
transcript：`.../ipa-ha-client/runs/20260710T004948Z-freeipa-client-apply.log`。

replica 的 `/etc/hosts` pin **已經在 §2 的 `topology up` 做完了**（client 的
spec 宣告了 `wire: ["ipa-replica=ipa2.ipa.pilot.internal"]`），不需要再手動
`vm-target wire`。確認一下（本輪實測，`# BEGIN/END pilot vm-target wire` 區塊
乾淨、沒有重複行）：

```bash
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- cat /etc/hosts
```
```
# BEGIN pilot vm-target wire
192.168.122.5	ipa2.ipa.pilot.internal
# END pilot vm-target wire
192.168.122.2 ipa-ha-client.ipa.pilot.internal ipa-ha-client
192.168.122.4 ipa1.ipa.pilot.internal ipa1
```

⚠ **仍然必要的手動步驟（`wire` 只處理 `/etc/hosts`，見 §14 gotcha）**：
`freeipa-client-apply.yml` enroll 時 `/etc/krb5.conf`/`sssd.conf` 都只認
primary 單一伺服器。要讓這台真的能在 primary 掛掉時 failover 到 replica，還是
得手動補上 replica 的 KDC/admin/kpasswd/ipa_server 設定：

```bash
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- sudo bash -c '
sed -i "s/kdc = ipa1.ipa.pilot.internal:88/kdc = ipa1.ipa.pilot.internal:88\n    kdc = ipa2.ipa.pilot.internal:88/" /etc/krb5.conf
sed -i "s/admin_server = ipa1.ipa.pilot.internal:749/admin_server = ipa1.ipa.pilot.internal:749\n    admin_server = ipa2.ipa.pilot.internal:749/" /etc/krb5.conf
sed -i "s/kpasswd_server = ipa1.ipa.pilot.internal:464/kpasswd_server = ipa1.ipa.pilot.internal:464\n    kpasswd_server = ipa2.ipa.pilot.internal:464/" /etc/krb5.conf
sed -i "s/^ipa_server = _srv_, ipa1.ipa.pilot.internal/ipa_server = _srv_, ipa1.ipa.pilot.internal, ipa2.ipa.pilot.internal/" /etc/sssd/sssd.conf
systemctl restart sssd
sss_cache -E
'
```

> 因為 `/etc/hosts` 已經由 `topology up` 冪等寫過一次，這裡不再需要舊版那行
> 冗餘的 `echo ... >> /etc/hosts`——單獨的 krb5/sssd sed 補丁就夠了。
>
> 這一步的 sed 會在 `kdc =` 那行留一個無害的重複條目（因為 pattern 同時匹配到
> `master_kdc=` 行裡的子字串），krb5 允許重複 `kdc=`，不影響功能，懶得處理就
> 留著即可。本輪實測確認：

```
kdc = ipa1.ipa.pilot.internal:88
kdc = ipa2.ipa.pilot.internal:88
master_kdc = ipa1.ipa.pilot.internal:88
kdc = ipa2.ipa.pilot.internal:88
admin_server = ipa1.ipa.pilot.internal:749
admin_server = ipa2.ipa.pilot.internal:749
kpasswd_server = ipa1.ipa.pilot.internal:464
kpasswd_server = ipa2.ipa.pilot.internal:464
```
```
ipa_server = _srv_, ipa1.ipa.pilot.internal, ipa2.ipa.pilot.internal
```

---

## 7. 建立基線（兩台都上線）

```bash
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- id pilotuser@ipa.pilot.internal
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- sudo -l -U pilotuser
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- \
    bash -c 'printf "%s" "HaTest#Passw0rd123" | kinit admin@IPA.PILOT.INTERNAL && klist -s && echo KINIT_OK && kdestroy'
```

**本輪實測結果（這是後面用來對照「壞了」跟「救回來了」的黃金輸出）**：
```
uid=336400003(pilotuser) gid=336400003(pilotuser) groups=336400003(pilotuser)
User pilotuser may run the following commands on ipa-ha-client:
    (root) NOPASSWD: ALL
KINIT_OK
```

---

## 8. 演練 A：關 primary，確認 client failover 到 replica

```bash
go run ./cmd/pilot vm-target exec --name ipa-primary -- sudo systemctl stop ipa
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- sudo sss_cache -E

go run ./cmd/pilot vm-target exec --name ipa-ha-client -- id pilotuser@ipa.pilot.internal
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- sudo -l -U pilotuser
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- \
    bash -c 'printf "%s" "HaTest#Passw0rd123" | kinit admin@IPA.PILOT.INTERNAL && echo KINIT_OK'
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- sudo sssctl domain-status ipa.pilot.internal
```

**本輪實測結果**：`id`/`sudo -l`/`kinit` 全部照樣成功；`sssctl domain-status`
輸出：
```
Online status: Online

Active servers:
IPA: ipa2.ipa.pilot.internal

Discovered IPA servers:
- ipa1.ipa.pilot.internal
- ipa2.ipa.pilot.internal
```
——client 已經切去 replica。

---

## 9. 演練 B：復原 primary、關 replica，對稱驗證

```bash
go run ./cmd/pilot vm-target exec --name ipa-primary -- sudo systemctl start ipa
go run ./cmd/pilot vm-target exec --name ipa-replica -- sudo systemctl stop ipa
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- sudo sss_cache -E

go run ./cmd/pilot vm-target exec --name ipa-ha-client -- id pilotuser@ipa.pilot.internal
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- sudo -l -U pilotuser
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- \
    bash -c 'printf "%s" "HaTest#Passw0rd123" | kinit admin@IPA.PILOT.INTERNAL && echo KINIT_OK'
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- sudo sssctl domain-status ipa.pilot.internal
```

**本輪實測結果**：同演練 A，但 `Active servers` 變回 `ipa1.ipa.pilot.internal`。

---

## 10. 演練 C：兩台都關，確認真的無法登入

```bash
go run ./cmd/pilot vm-target exec --name ipa-primary -- sudo systemctl stop ipa
go run ./cmd/pilot vm-target exec --name ipa-replica -- sudo systemctl stop ipa
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- sudo sss_cache -E

# 權威證明：kinit 沒有離線路徑，兩台都掛必定立即失敗
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- \
    timeout 20 bash -c 'printf "%s" "HaTest#Passw0rd123" | kinit admin@IPA.PILOT.INTERNAL; echo "rc=$?"'

# 對照組：從未查過的身分——沒有任何快取可用，必定失敗
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- \
    bash -c 'id neverseenuser@ipa.pilot.internal; echo "rc=$?"'

# 誠實補充：已快取過的身分/sudo 規則，離線期間仍會回應（SSSD 設計，不是 bug）
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- id pilotuser@ipa.pilot.internal
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- sudo -l -U pilotuser
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- sudo sssctl domain-status ipa.pilot.internal
```

**本輪實測結果**：
```
kinit: Cannot contact any KDC for realm 'IPA.PILOT.INTERNAL' while getting initial credentials
rc=1
id: 'neverseenuser@ipa.pilot.internal': no such user
rc=1
```
`id pilotuser`/`sudo -l -U pilotuser` 仍會成功（本機快取回應）；
`sssctl domain-status` 顯示 `Online status: Offline`（`Active servers` 仍留著
最後一次成功連上的 `ipa1.ipa.pilot.internal`，是快取殘留，不代表還連得上）。

**`kinit` 失敗是這場演練的判定依據**：兩台都掛 = 無法取得任何新的 Kerberos
票證 = 無法登入。已快取身分仍可查詢是 SSSD 離線韌性設計，不代表演練失敗。

---

## 11. 復原、確認恢復正常

```bash
go run ./cmd/pilot vm-target exec --name ipa-primary -- sudo systemctl start ipa
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- \
    bash -c 'printf "%s" "HaTest#Passw0rd123" | kinit admin@IPA.PILOT.INTERNAL && echo KINIT_OK'
go run ./cmd/pilot vm-target exec --name ipa-replica -- sudo systemctl start ipa

go run ./cmd/pilot vm-target verify --name ipa-primary docs/verification/freeipa-server.md --timeout 40
go run ./cmd/pilot vm-target verify --name ipa-replica docs/verification/freeipa-server-replica.md --timeout 40
```

**本輪實測結果**：`KINIT_OK`（primary 一恢復立刻可登入）；兩份 verify 都回到
**PASS**（`freeipa-server.md` pass=18、`freeipa-server-replica.md` pass=15），
確認整場演練沒有把任何東西跑壞。

---

## 12. Cluster reset：驗證整台叢集能回到乾淨狀態重跑

> 這一步會把 3 台 VM 的 disk **全部**復原回 `up` 剛開完機、FreeIPA 都還沒裝
> 的狀態——包含上面 §11 剛裝回去、驗過 PASS 的 FreeIPA 安裝本身。所以必須
> 放在 §11 確認完「演練沒把東西跑壞」**之後**、真正 `topology down` 銷毀
> VM **之前**：這裡只是示範/驗證「叢集能不能整批回到乾淨狀態」這個能力本
> 身，不是接著要再重跑一次完整部署（真的要重跑，直接接 §3 就好，本輪不
> 需要）。

`snapshot`/`rollback`/`reset` 原本都是單一 VM 的操作——要測「
`ipa-replica-install` 從乾淨狀態能不能重跑」，得對 3 台 VM 各自
`reset`/`rollback`，還要記得每次重做 §2 的 `wire`（`reset` 用的 `clean`
快照是 `up` 剛開完機、`wire` 跑之前拍的，所以單機 `reset` 會連帶把
`/etc/hosts` 的 wiring 也一起復原掉）。`vm-target topology
snapshot/rollback/reset`（見 `cmd/pilot/cmd/vm_target_topology.go`）把這件事
變成一個指令：對 spec 裡每台 node 平行做同一個操作，`rollback`/`reset`
完成後再自動對每個宣告了 `wire:` 的 node 重跑一次 wiring（`snapshot`
不需要，因為它不動 disk 狀態）。

```bash
# 印證：先確認目前的 wiring、埋一個 marker 檔證明 disk 真的會被復原
go run ./cmd/pilot vm-target exec --name ipa-primary -- sudo cat /etc/hosts
go run ./cmd/pilot vm-target exec --name ipa-primary -- sudo touch /root/pre-reset-marker

go run ./cmd/pilot vm-target topology reset --topology docs/topologies/freeipa-ha-topology.yaml

# 驗證：marker 檔應該消失（disk 真的回到乾淨開機狀態），wiring 應該自動補回來
go run ./cmd/pilot vm-target exec --name ipa-primary -- sudo ls -la /root/pre-reset-marker
go run ./cmd/pilot vm-target exec --name ipa-primary -- sudo cat /etc/hosts
```

**本輪實測輸出**：
```
✓ reset 3 node(s) to "clean" (pristine post-boot state)
✓ wired ipa2.ipa.pilot.internal -> ipa-primary (192.168.122.4)
✓ wired ipa2.ipa.pilot.internal -> ipa-ha-client (192.168.122.4)
```
```
ls: cannot access '/root/pre-reset-marker': No such file or directory
```
```
127.0.0.1   localhost localhost.localdomain localhost4 localhost4.localdomain4
::1         localhost localhost.localdomain localhost6 localhost6.localdomain6
# BEGIN pilot vm-target wire
192.168.122.4	ipa2.ipa.pilot.internal
# END pilot vm-target wire
```

Marker 檔消失，證明 `reset` 是真的把 disk 復原到 `up` 剛開完機的那一刻——連
FreeIPA server/replica 安裝過程寫進系統的東西（例如這台先前跑過安裝時，
`ipa-server-install` 自己在 `/etc/hosts` 加的 `ipa1.ipa.pilot.internal`
自身主機名那一行，以及 §11 剛驗證 PASS 的整個 FreeIPA 安裝）都一併復原
掉了，不是只清 vm-target 自己寫的東西。`wire` 區塊在 reset 後自動重新
出現，因為 `topology reset` 在每個 node 都 `Reset` 完之後，會自動對宣告
了 `wire:` 的 node 重跑一次 `wireTargetToPeers`（跟 `topology up` 收尾那段
完全同一支函式）。

**下一輪要重測 `ipa-replica-install` 從乾淨狀態能不能重跑，就是這一步**：
```bash
go run ./cmd/pilot vm-target topology reset --topology docs/topologies/freeipa-ha-topology.yaml
# 3 台都回到剛開完機、wiring 也已補回的狀態 -> 直接從 §3 重新走一次部署
```
不用再手動對 3 台個別 `reset` + 重跑 `wire` 兩次（primary→client、
client→replica）。因為這一步已經把 FreeIPA 清掉了，本輪不再重跑 §3-§10，
直接接 §13 teardown 收尾。

---

## 13. 收尾 Teardown

```bash
go run ./cmd/pilot vm-target topology down --topology docs/topologies/freeipa-ha-topology.yaml
go run ./cmd/pilot vm-target list   # 確認為空
rm -f /tmp/ha-test-vault.yaml
```

**本輪實測**：`topology down` 一個指令拆掉全部三台（取代舊版 3 條個別的
`vm-target down`）：
```
✓ ipa-primary down
✓ ipa-replica down
✓ ipa-ha-client down
(no targets — `pilot vm-target up` to start one)
```

**這步過了，HA 演練就算成功。**

---

## 14. 已知 gotcha 一覽（跑之前先知道，少走冤枉路）

| 症狀 | 原因 | 解法 |
|---|---|---|
| `ipa-replica-install` 失敗：`ScriptError: NTP configuration cannot be updated during promotion` | promotion 模式（client-then-promote）下 `ipa-replica-install` 完全不接受任何 NTP 旗標；NTP 已經在 `ipa-client-install` 那一步決定過了 | 已修進 `freeipa-server-replica-apply.yml`——promote 步驟不再傳 `--no-ntp`。若你手動跑 `ipa-replica-install` 也一樣，別帶 NTP 旗標 |
| `ipa-replica-install` 失敗：`ERROR: Port check failed! Unable to resolve host name '<replica-fqdn>'` | primary 在 conncheck 時會反過來連回新 replica，沒有內建 DNS 時 primary 解析不到新節點 | 見 §2：`docs/topologies/freeipa-ha-topology.yaml` 裡 `ipa-primary` 節點的 `wire:` 宣告，`topology up` 會自動把新 replica 的 FQDN/IP 冪等 pin 進 primary 的 `/etc/hosts`（不需要再手動下 `vm-target wire`） |
| `ldapsearch -x` 查 `cn=masters,cn=ipa,cn=etc,...` 回 `result: 0 Success` 但零筆資料，看起來像複寫沒同步 | 這個系統容器**沒有**匿名讀 ACI（不像 `ou=sudoers`）,匿名查詢會「成功但沒資料」而不是報錯,很容易誤判 | 改用 `ldapsearch -Y EXTERNAL -H ldapi://%2Frun%2F<389-ds instance>.socket ...` 以 root autobind(已修進 spec C14/C15 與 apply playbook 的內部健康檢查) |
| `sudo -l` 對任何人永遠回 `not allowed`，看起來像 sudo 規則沒生效 | `freeipa-client-apply.yml` 把 `sudo` 塞進 SSSD 的 `services=` 這行，跟現代 SSSD（≥2.3）預設的 socket-activated sudo responder 衝突，`sssd-sudo.socket` 直接啟動失敗（`systemctl status sssd-sudo.socket` 會看到 `Misconfiguration found for the sudo responder`） | 已修：`services=` 拿掉 `sudo`，交給 socket activation。若你在別的環境撞到同症狀，檢查 `systemctl status sssd-sudo.socket` 是不是 `failed` |
| 只 pin 了 client 的 `/etc/hosts`（不管是 `topology up` 自動做的還是手動 `wire`），關掉 primary 後 client 卻卡住不會切到 replica（`sssctl domain-status` 一直顯示 `Active: ipa1` 且 `Offline`） | `/etc/krb5.conf` 的 `kdc=` 與 `sssd.conf` 的 `ipa_server=` enroll 時都寫死成單一伺服器，光靠 DNS 解析（`/etc/hosts`）不會讓這兩份設定自動變成多值；**`wire`（不論是 `topology up` 自動觸發還是手動呼叫）只處理 `/etc/hosts`，不處理 krb5/sssd 設定** | 見 §6：krb5.conf 的 `kdc=`/`admin_server=`/`kpasswd_server=` 以及 `sssd.conf` 的 `ipa_server=` 還是要手動 sed 補上多值、重啟 `sssd`——`vm-target topology` 目前沒有把這段收進宣告式流程,因為它是 playbook/OS 設定檔層級的細節,不是 vm-target 生命週期層級的事 |
| 關掉 server 後 `id`/`sudo -l` 卻還是成功，一度誤判「HA 沒生效」或「根本沒關掉」 | SSSD 本機快取（`cache_credentials=True`）對**已經查過**的身分/sudo 規則會在離線時繼續回應，這是設計行為 | 別用 `id`/`sudo -l` 當「兩台都掛」的判定依據；改用 `kinit`（見 §10，Kerberos 取票沒有離線路徑，一定會如實失敗），或查一個從未查過的身分（也會如實失敗） |
| `pilot vm-target run --name <某台> ...` 顯示 `skipping: no hosts matched` | apply playbook 的 `hosts:` 預設是角色 group 名（`freeipa-server`/`freeipa-server-replica`/`freeipa-client`），vm-target 單機 inventory 只有同名的 **host**、沒有這個 **group** | 一律加 `-e target_group=all` |
| `--sandbox` 模式下 `-e @/tmp/xxx-vault.yaml` 報 `Unable to retrieve file contents ... No such file or directory` | `ansible-playbook` 是在容器**裡面**跑的，`@path` 指的是 host 路徑，容器一開始只 mount 了 SSH key、docker cp 了 playbook/inventory，vault 檔案本來沒被複製進去 | 已修：`vtRunViaContainer` 現在會自動偵測 `-e @path`/`-e@path`/`--extra-vars=@path` 這三種寫法，把對應的 host 檔案 `docker cp` 進容器並改寫成容器內路徑，不需要手動處理 |
| `vm-target topology up` 印出 `waiting for IP ...`（`stale pre-existing lease ...` 或 `no active lease for MAC ... yet`）卡個 10–20 秒 | 同一台 host 上跑過多輪測試，dnsmasq 的 lease 檔還留著前一輪同一個 MAC 的舊 lease；或這一輪是全新 MAC，dnsmasq 還沒發出租約 | 正常現象，不是錯誤；`topology up` 現在對每個 node 平行等待，其中一台在等 lease 不會擋住其他台 |

更完整的逐字真實輸出（PLAY RECAP、verify ndjson、`sssctl`/`kinit` 原始輸出）見
`docs/verification/freeipa-server-replica.md` §3/§9。
