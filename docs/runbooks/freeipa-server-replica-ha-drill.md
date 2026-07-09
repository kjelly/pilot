# Runbook — freeipa-server-replica HA failover 演練計畫

> 撰寫日期：2026-07-09 (UTC)
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
> AlmaLinux 9、`ipa-ha-client` Ubuntu 24.04）實跑過一輪（2026-07-09），全程只
> 用 `go run ./cmd/pilot vm-target` 系列指令。

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

> ⚠️ 三台 VM 依序 `up`，不要平行——已知 `vm-target up` 平行呼叫有 state file
> race bug（見 `pilot-vm-target-up-concurrency-race` 記憶/`AGENTS.md` §5.1）。

---

## 2. 起 3 台 VM

```bash
go run ./cmd/pilot vm-target up --name ipa-primary --base-image almalinux-9 --memory 3072 --vcpus 2
go run ./cmd/pilot vm-target up --name ipa-replica --base-image almalinux-9 --memory 3072 --vcpus 2
go run ./cmd/pilot vm-target up --name ipa-ha-client --base-image ubuntu-24.04 --memory 2048 --vcpus 2
```

**預期結果**：三台都印出 `✓ target <name> up`，各自拿到一個 `192.168.122.x`
靜態 IP。記下三個 IP（後面步驟要用）：

```bash
go run ./cmd/pilot vm-target list
```

---

## 3. 部署 primary（起 realm）

```bash
go run ./cmd/pilot vm-target run --name ipa-primary playbooks/apply/freeipa-server-apply.yml \
    -e target_group=all -e ipa_server_ip=<ipa-primary IP> \
    -e @/tmp/ha-test-vault.yaml

go run ./cmd/pilot vm-target verify --name ipa-primary \
    docs/verification/freeipa-server.md --timeout 40
```

**預期結果**：`PLAY RECAP ... failed=0`（首裝約 8–12 分鐘）；verify **PASS
pass=18 fail=0**。

---

## 4. 部署 replica（加入既有 realm）

⚠ **必要手動前置步驟**：`ipa-replica-install` 會叫 primary 反過來連回這台新
replica 做 conncheck；沒有內建 DNS 時 primary 解析不到新節點的 FQDN 就會整個
install 失敗（`ERROR: Port check failed! Unable to resolve host name`）。先手動
把 replica 的 FQDN/IP pin 進 primary 的 `/etc/hosts`：

```bash
go run ./cmd/pilot vm-target exec --name ipa-primary -- \
    bash -c 'echo "<ipa-replica IP> ipa2.ipa.pilot.internal ipa2" >> /etc/hosts'
```

再套用 replica apply playbook：

```bash
go run ./cmd/pilot vm-target run --name ipa-replica playbooks/apply/freeipa-server-replica-apply.yml \
    -e target_group=all -e ipa_server_ip=<ipa-primary IP> -e ipa_replica_ip=<ipa-replica IP> \
    -e @/tmp/ha-test-vault.yaml

go run ./cmd/pilot vm-target exec --name ipa-replica -- true   # 暖 SSH 連線
go run ./cmd/pilot vm-target verify --name ipa-replica \
    docs/verification/freeipa-server-replica.md --timeout 40
```

**預期結果**：`PLAY RECAP ... failed=0`（首次 promote 約 8–12 分鐘）；verify
**PASS pass=15 fail=0**（C14/C15 證明雙向拓樸複寫已同步）。

---

## 5. 建立測試帳號 fixture（跨 host 前置，canonical 做法）

```bash
go run ./cmd/pilot vm-target run --name ipa-primary \
    playbooks/test/fixtures/freeipa-client-fixtures.yml \
    -e fixtures_target_group=all -e @/tmp/ha-test-vault.yaml
```

**預期結果**：建立 `pilotuser` + sudo 規則 `pilot-all`（hostcat=all cmdcat=all
`!authenticate`），`changed=4`。**不要**在別處手刻 `ipa user-add`——這是本 repo
canonical 的 demo 帳號建立方式（`AGENTS.md` §4.1）。

---

## 6. Enroll client 向 primary + 補上 client 端 failover 設定

```bash
go run ./cmd/pilot vm-target run --name ipa-ha-client playbooks/apply/freeipa-client-apply.yml \
    -e target_group=all -e ipa_server_ip=<ipa-primary IP> \
    -e @/tmp/ha-test-vault.yaml
```

**預期結果**：`PLAY RECAP ... failed=0`。

⚠ **必要手動步驟（沒有寫進任何 playbook，見 §10 gotcha）**：`freeipa-client-apply.yml`
enroll 時只 pin 了 primary 的 `/etc/hosts`，且 `/etc/krb5.conf`/`sssd.conf` 都只
認 primary 單一伺服器。要讓這台真的能在 primary 掛掉時 failover 到 replica，
手動補上 replica：

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

**預期結果（這是後面用來對照「壞了」跟「救回來了」的黃金輸出）**：
```
uid=...(pilotuser) gid=...(pilotuser) groups=...(pilotuser)
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

**預期結果**：`id`/`sudo -l`/`kinit` 全部照樣成功；`sssctl domain-status` 顯示
`Online status: Online`、`Active servers: IPA: ipa2.ipa.pilot.internal`——client
已經切去 replica。

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

**預期結果**：同演練 A，但 `Active servers` 變回 `ipa1.ipa.pilot.internal`。

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

**預期結果**：
```
kinit: Cannot contact any KDC for realm 'IPA.PILOT.INTERNAL' while getting initial credentials
rc=1
id: 'neverseenuser@ipa.pilot.internal': no such user
rc=1
```
`id pilotuser`/`sudo -l -U pilotuser` 仍會成功（本機快取回應）；
`sssctl domain-status` 顯示 `Online status: Offline`。

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

**預期結果**：`KINIT_OK`（primary 一恢復立刻可登入）；兩份 verify 都回到
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
| `ipa-replica-install` 失敗：`ERROR: Port check failed! Unable to resolve host name '<replica-fqdn>'` | primary 在 conncheck 時會反過來連回新 replica，沒有內建 DNS 時 primary 解析不到新節點 | 見 §4：套用前先手動把新 replica 的 FQDN/IP pin 進 primary 的 `/etc/hosts` |
| `ldapsearch -x` 查 `cn=masters,cn=ipa,cn=etc,...` 回 `result: 0 Success` 但零筆資料，看起來像複寫沒同步 | 這個系統容器**沒有**匿名讀 ACI（不像 `ou=sudoers`）,匿名查詢會「成功但沒資料」而不是報錯,很容易誤判 | 改用 `ldapsearch -Y EXTERNAL -H ldapi://%2Frun%2F<389-ds instance>.socket ...` 以 root autobind(已修進 spec C14/C15 與 apply playbook 的內部健康檢查) |
| `sudo -l` 對任何人永遠回 `not allowed`，看起來像 sudo 規則沒生效 | `freeipa-client-apply.yml` 把 `sudo` 塞進 SSSD 的 `services=` 這行，跟現代 SSSD（≥2.3）預設的 socket-activated sudo responder 衝突，`sssd-sudo.socket` 直接啟動失敗（`systemctl status sssd-sudo.socket` 會看到 `Misconfiguration found for the sudo responder`） | 已修：`services=` 拿掉 `sudo`，交給 socket activation。若你在別的環境撞到同症狀，檢查 `systemctl status sssd-sudo.socket` 是不是 `failed` |
| 只 pin 了 client 的 `/etc/hosts`，關掉 primary 後 client 卻卡住不會切到 replica（`sssctl domain-status` 一直顯示 `Active: ipa1` 且 `Offline`） | `/etc/krb5.conf` 的 `kdc=` 與 `sssd.conf` 的 `ipa_server=` enroll 時都寫死成單一伺服器，光靠 DNS 解析（`/etc/hosts`）不會讓這兩份設定自動變成多值 | 見 §6：手動把 replica 補進 `krb5.conf` 的 `kdc=`/`admin_server=`/`kpasswd_server=` 以及 `sssd.conf` 的 `ipa_server=`，重啟 `sssd` |
| 關掉 server 後 `id`/`sudo -l` 卻還是成功，一度誤判「HA 沒生效」或「根本沒關掉」 | SSSD 本機快取（`cache_credentials=True`）對**已經查過**的身分/sudo 規則會在離線時繼續回應，這是設計行為 | 別用 `id`/`sudo -l` 當「兩台都掛」的判定依據；改用 `kinit`（見 §10，Kerberos 取票沒有離線路徑，一定會如實失敗），或查一個從未查過的身分（也會如實失敗） |
| `pilot vm-target run --name <某台> ...` 顯示 `skipping: no hosts matched` | apply playbook 的 `hosts:` 預設是角色 group 名（`freeipa-server`/`freeipa-server-replica`/`freeipa-client`），vm-target 單機 inventory 只有同名的 **host**、沒有這個 **group** | 一律加 `-e target_group=all` |

更完整的逐字真實輸出（PLAY RECAP、verify ndjson、`sssctl`/`kinit` 原始輸出）見
`docs/verification/freeipa-server-replica.md` §3/§9。
