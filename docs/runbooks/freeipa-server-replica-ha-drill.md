# Runbook — freeipa-server-replica HA failover 演練計畫

> 撰寫日期：2026-07-09 (UTC)；2026-07-10 (UTC) 改用 `--sandbox`/`vm-target wire`/
> `--json` 重新整套跑過一輪，驗證新特性下步驟/數字不變。
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
> AlmaLinux 9、`ipa-ha-client` Ubuntu 24.04）實跑過兩輪：2026-07-09（host 直接跑
> ansible-playbook）與 2026-07-10（改用 `pilot vm-target run --sandbox`，
> ansible-playbook 全程在容器內執行；並用 `vm-target wire` 取代手動
> `/etc/hosts` 步驟）。全程只用 `go run ./cmd/pilot vm-target` 系列指令，兩輪
> 數字/結果一致。

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
的第三方視角）。

---

## 1. 前置確認

```bash
go run ./cmd/pilot vm-target list
```

**預期結果**：乾淨環境應該是空的（`no targets`）。若上次測試留了同名 VM，先
`vm-target down` 清掉再重來，避免 IP/狀態殘留。

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

只需要建一次（除非改了 `pilot` 原始碼或 Dockerfile）；本輪實測建置耗時約
1 分鐘。

> ⚠️ 三台 VM 依序 `up`，不要平行——已知 `vm-target up` 平行呼叫有 state file
> race bug（見 `pilot-vm-target-up-concurrency-race` 記憶/`AGENTS.md` §5.1；
> 該 race 本身已於 2026-07-06 修復，但本演練沿用既有的保守序列，沒有刻意去測
> 平行 up）。

---

## 2. 起 3 台 VM

```bash
go run ./cmd/pilot vm-target up --name ipa-primary --base-image almalinux-9 --memory 3072 --vcpus 2 --ssh-timeout 8m --boot-timeout 8m
go run ./cmd/pilot vm-target up --name ipa-replica --base-image almalinux-9 --memory 3072 --vcpus 2 --ssh-timeout 8m --boot-timeout 8m
go run ./cmd/pilot vm-target up --name ipa-ha-client --base-image ubuntu-24.04 --memory 2048 --vcpus 2 --ssh-timeout 8m --boot-timeout 8m
```

**預期結果**：三台都印出 `✓ target <name> up`，各自拿到一個 `192.168.122.x`
靜態 IP。記下三個 IP（後面步驟要用）：

```bash
go run ./cmd/pilot vm-target list
```

**本輪實測**（golden image 已快取，開機都在 30 秒內完成，沒有踩到
`libguestfs`/`virt-customize` 冷開機的 4–6 分鐘成本）：

```
NAME           STATUS   IP             VCPU  MEM(MiB)  DISK(GiB)  CREATED
ipa-ha-client  running  192.168.122.3  2     2048      30         2026-07-10 07:36:54
ipa-primary    running  192.168.122.5  2     3072      30         2026-07-10 07:35:30
ipa-replica    running  192.168.122.2  2     3072      30         2026-07-10 07:36:09
```

---

## 3. 部署 primary（起 realm）

```bash
go run ./cmd/pilot vm-target run --name ipa-primary --sandbox --sandbox-image pilot-cli:latest \
    playbooks/apply/freeipa-server-apply.yml \
    -e target_group=all -e ipa_server_ip=192.168.122.5 \
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
stderr）——這次是 `.../ipa-primary/runs/20260709T233940Z-freeipa-server-apply.log`。
需要逐字複查時直接 `cat` 這個檔案，不用重新用終端機捲軸手抄。

---

## 4. 部署 replica（加入既有 realm）

⚠ **必要前置步驟**：`ipa-replica-install` 會叫 primary 反過來連回這台新
replica 做 conncheck；沒有內建 DNS 時 primary 解析不到新節點的 FQDN 就會整個
install 失敗（`ERROR: Port check failed! Unable to resolve host name`）。用
`vm-target wire` 把 replica 的 FQDN/IP 冪等地 pin 進 primary 的 `/etc/hosts`
（取代舊版手動 `vm-target exec -- bash -c '... >> /etc/hosts'`，好處是重跑不會
留重複行,且 IP 直接從 vm-target 自己的 state 解出來,不必手動照抄）：

```bash
go run ./cmd/pilot vm-target wire --name ipa-primary --peer ipa-replica=ipa2.ipa.pilot.internal
```

**本輪實測**：`✓ wired ipa2.ipa.pilot.internal -> ipa-primary (192.168.122.2)`

再套用 replica apply playbook：

```bash
go run ./cmd/pilot vm-target run --name ipa-replica --sandbox --sandbox-image pilot-cli:latest \
    playbooks/apply/freeipa-server-replica-apply.yml \
    -e target_group=all -e ipa_server_ip=192.168.122.5 -e ipa_replica_ip=192.168.122.2 \
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
`.../ipa-replica/runs/20260709T234640Z-freeipa-server-replica-apply.log`。

> 這一對 playbook（server + server-replica）各自的 `hosts:` 只需要單一目標
> 自己的 inventory，跨主機的溝通是走 FreeIPA/Kerberos 協定本身（網路層），不是
> 靠 ansible 在同一個 play 裡同時操作兩台主機——所以這裡**不需要** `run
> --group`。`--group` 是給「同一個 play 真的要同時對多個 named vm-target 下
> 手」的情境用的（見 `.agents/skills/vm-target-spec-testing/references/vm-target-basics.md`）。

---

## 5. 建立測試帳號 fixture（跨 host 前置，canonical 做法）

```bash
go run ./cmd/pilot vm-target run --name ipa-primary --sandbox --sandbox-image pilot-cli:latest \
    playbooks/test/fixtures/freeipa-client-fixtures.yml \
    -e fixtures_target_group=all -e @/tmp/ha-test-vault.yaml
```

**本輪實測結果**：`PLAY RECAP ... ok=7 changed=4 failed=0`——建立 `pilotuser`
+ sudo 規則 `pilot-all`（hostcat=all cmdcat=all `!authenticate`）。**不要**在
別處手刻 `ipa user-add`——這是本 repo canonical 的 demo 帳號建立方式
（`AGENTS.md` §4.1）。

**`--json` 快速 triage 範例**（同一個 playbook 冪等重跑一次，這次不加
`--sandbox`——`--json` 目前不支援跟 `--sandbox` 疊用，見
`vm-target-basics.md`）：

```bash
go run ./cmd/pilot vm-target run --name ipa-primary \
    playbooks/test/fixtures/freeipa-client-fixtures.yml --json \
    -e fixtures_target_group=all -e @/tmp/ha-test-vault.yaml
```

**本輪實測結果**：`ipa-primary: ok=7 changed=0 failed=0 unreachable=0
skipped=0`——一行就看出「這次重跑沒有任何 drift」，比在 §6 之後才用 PLAY RECAP
反查快很多；同時也順便證實了 fixture playbook 本身是冪等的（`changed=0`）。
（跑這步會先看到 `ansible-lint` 的預設前置檢查印出既有的 5 個非致命
style violation——這是既有已知的 lint 雜訊，不影響本次演練，不用理它。）

---

## 6. Enroll client 向 primary + 補上 client 端 failover 設定

```bash
go run ./cmd/pilot vm-target run --name ipa-ha-client --sandbox --sandbox-image pilot-cli:latest \
    playbooks/apply/freeipa-client-apply.yml \
    -e target_group=all -e ipa_server_ip=192.168.122.5 \
    -e @/tmp/ha-test-vault.yaml
```

**本輪實測結果**：`PLAY RECAP ... ok=23 changed=11 failed=0`。

用 `vm-target wire` 把 replica 也 pin 進 client 的 `/etc/hosts`（取代舊版手動
`>> /etc/hosts`）：

```bash
go run ./cmd/pilot vm-target wire --name ipa-ha-client --peer ipa-replica=ipa2.ipa.pilot.internal
```

⚠ **仍然必要的手動步驟（`wire` 目前只處理 `/etc/hosts`，見 §12 gotcha）**：
`freeipa-client-apply.yml` enroll 時 `/etc/krb5.conf`/`sssd.conf` 都只認
primary 單一伺服器。要讓這台真的能在 primary 掛掉時 failover 到 replica，還是
得手動補上 replica 的 KDC/admin/kpasswd/ipa_server 設定：

```bash
go run ./cmd/pilot vm-target exec --name ipa-ha-client -- sudo bash -c '
echo "<ipa-replica IP> ipa2.ipa.pilot.internal ipa2" >> /etc/hosts
sed -i "s/kdc = ipa1.ipa.pilot.internal:88/kdc = ipa1.ipa.pilot.internal:88\n    kdc = ipa2.ipa.pilot.internal:88/" /etc/krb5.conf
sed -i "s/admin_server = ipa1.ipa.pilot.internal:749/admin_server = ipa1.ipa.pilot.internal:749\n    admin_server = ipa2.ipa.pilot.internal:749/" /etc/krb5.conf
sed -i "s/kpasswd_server = ipa1.ipa.pilot.internal:464/kpasswd_server = ipa1.ipa.pilot.internal:464\n    kpasswd_server = ipa2.ipa.pilot.internal:464/" /etc/krb5.conf
sed -i "s/^ipa_server = _srv_, ipa1.ipa.pilot.internal/ipa_server = _srv_, ipa1.ipa.pilot.internal, ipa2.ipa.pilot.internal/" /etc/sssd/sssd.conf
systemctl restart sssd
sss_cache -E
'
```

> 上面這段仍然保留一行冗餘的 `echo ... >> /etc/hosts`，是因為已經先跑過
> `vm-target wire`（已經冪等寫過一次同樣的條目），這裡純粹是延續舊版腳本的
> krb5/sssd 補丁一起做；若只想補 `/etc/hosts`，單獨的 `vm-target wire` 呼叫
> 已經足夠，這行可以省略。
>
> 這一步的 sed 會在 `kdc =` 那行留一個無害的重複條目（因為 pattern 同時匹配到
> `master_kdc=` 行裡的子字串），krb5 允許重複 `kdc=`，不影響功能，懶得處理就
> 留著即可。

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
uid=1935800003(pilotuser) gid=1935800003(pilotuser) groups=1935800003(pilotuser)
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

## 11. 復原、確認恢復正常、收尾 Teardown

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

```bash
go run ./cmd/pilot vm-target down --name ipa-ha-client
go run ./cmd/pilot vm-target down --name ipa-replica
go run ./cmd/pilot vm-target down --name ipa-primary
go run ./cmd/pilot vm-target list   # 確認為空
rm -f /tmp/ha-test-vault.yaml
```

**這步過了，HA 演練就算成功。**

---

## 12. 已知 gotcha 一覽（跑之前先知道，少走冤枉路）

| 症狀 | 原因 | 解法 |
|---|---|---|
| `ipa-replica-install` 失敗：`ScriptError: NTP configuration cannot be updated during promotion` | promotion 模式（client-then-promote）下 `ipa-replica-install` 完全不接受任何 NTP 旗標；NTP 已經在 `ipa-client-install` 那一步決定過了 | 已修進 `freeipa-server-replica-apply.yml`——promote 步驟不再傳 `--no-ntp`。若你手動跑 `ipa-replica-install` 也一樣，別帶 NTP 旗標 |
| `ipa-replica-install` 失敗：`ERROR: Port check failed! Unable to resolve host name '<replica-fqdn>'` | primary 在 conncheck 時會反過來連回新 replica，沒有內建 DNS 時 primary 解析不到新節點 | 見 §4：套用前先用 `vm-target wire --name <primary> --peer <replica>=<fqdn>` 把新 replica 的 FQDN/IP 冪等 pin 進 primary 的 `/etc/hosts` |
| `ldapsearch -x` 查 `cn=masters,cn=ipa,cn=etc,...` 回 `result: 0 Success` 但零筆資料，看起來像複寫沒同步 | 這個系統容器**沒有**匿名讀 ACI（不像 `ou=sudoers`）,匿名查詢會「成功但沒資料」而不是報錯,很容易誤判 | 改用 `ldapsearch -Y EXTERNAL -H ldapi://%2Frun%2F<389-ds instance>.socket ...` 以 root autobind(已修進 spec C14/C15 與 apply playbook 的內部健康檢查) |
| `sudo -l` 對任何人永遠回 `not allowed`，看起來像 sudo 規則沒生效 | `freeipa-client-apply.yml` 把 `sudo` 塞進 SSSD 的 `services=` 這行，跟現代 SSSD（≥2.3）預設的 socket-activated sudo responder 衝突，`sssd-sudo.socket` 直接啟動失敗（`systemctl status sssd-sudo.socket` 會看到 `Misconfiguration found for the sudo responder`） | 已修：`services=` 拿掉 `sudo`，交給 socket activation。若你在別的環境撞到同症狀，檢查 `systemctl status sssd-sudo.socket` 是不是 `failed` |
| 只 pin 了 client 的 `/etc/hosts`（不管是手動還是 `vm-target wire`），關掉 primary 後 client 卻卡住不會切到 replica（`sssctl domain-status` 一直顯示 `Active: ipa1` 且 `Offline`） | `/etc/krb5.conf` 的 `kdc=` 與 `sssd.conf` 的 `ipa_server=` enroll 時都寫死成單一伺服器，光靠 DNS 解析（`/etc/hosts`）不會讓這兩份設定自動變成多值；**`vm-target wire` 只處理 `/etc/hosts`，不處理 krb5/sssd 設定** | 見 §6：`wire` 只解掉 hostname 解析這一半，krb5.conf 的 `kdc=`/`admin_server=`/`kpasswd_server=` 以及 `sssd.conf` 的 `ipa_server=` 還是要手動 sed 補上多值、重啟 `sssd` |
| 關掉 server 後 `id`/`sudo -l` 卻還是成功，一度誤判「HA 沒生效」或「根本沒關掉」 | SSSD 本機快取（`cache_credentials=True`）對**已經查過**的身分/sudo 規則會在離線時繼續回應，這是設計行為 | 別用 `id`/`sudo -l` 當「兩台都掛」的判定依據；改用 `kinit`（見 §10，Kerberos 取票沒有離線路徑，一定會如實失敗），或查一個從未查過的身分（也會如實失敗） |
| `pilot vm-target run --name <某台> ...` 顯示 `skipping: no hosts matched` | apply playbook 的 `hosts:` 預設是角色 group 名（`freeipa-server`/`freeipa-server-replica`/`freeipa-client`），vm-target 單機 inventory 只有同名的 **host**、沒有這個 **group** | 一律加 `-e target_group=all` |
| `--sandbox` 模式下 `-e @/tmp/xxx-vault.yaml` 報 `Unable to retrieve file contents ... No such file or directory` | `ansible-playbook` 是在容器**裡面**跑的，`@path` 指的是 host 路徑，容器一開始只 mount 了 SSH key、docker cp 了 playbook/inventory，vault 檔案本來沒被複製進去 | 已修：`vtRunViaContainer` 現在會自動偵測 `-e @path`/`-e@path`/`--extra-vars=@path` 這三種寫法，把對應的 host 檔案 `docker cp` 進容器並改寫成容器內路徑，不需要手動處理 |

更完整的逐字真實輸出（PLAY RECAP、verify ndjson、`sssctl`/`kinit` 原始輸出）見
`docs/verification/freeipa-server-replica.md` §3/§9。
