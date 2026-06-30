# Runbook — core-infra (DNS + NTP + Keycloak)

> Status: **dual-spec pipeline live** on test-vm. Two specs run on the
> same inventory: `core-infra.md` (consumer) and `core-infra-provider.md`
> (provider). Verdict on dev test-vm today: consumer **4/8 pass**, provider
> **3/9 pass** — exactly the gap matrix you'd expect from a host that
> CONSUMES but does not SERVE infrastructure.

> 撰寫日期：2026-06-30 (UTC)
> 對齊規範：見 `docs/verification/core-infra.md` 與 `core-infra-provider.md`
> 維護者：sre

---

## 0. 環境快照

| 項目 | 值 |
|------|----|
| Pilot repo | `/home/ubuntu/nfs/github/pilot` |
| Target host | `test-vm` (libvirt 192.168.122.232) |
| SSH entry | `~/.ssh/config` (`Host test-vm`, key `~/.ssh/simple-20220321`) |
| Target OS | Ubuntu 24.04.4 LTS |
| Inventory | `inventory.yaml` (single-host, group=`all`) |
| Pilot pipeline | `lint → generate → apply → verify → status` |
| Consumer verdict | 4 pass / 4 fail (C3, C6, C7, C8 missing infra client-side) |
| Provider verdict | 3 pass / 6 fail (no DNS/NTP server daemon, no Keycloak) |

---

## 1. 一句話目標

「**infra 服務 mesh**」要完整，每台 host 不是 consumer 就是 provider（或兩者都是）；這份 runbook
示範如何**一張 inventory、兩個 group、兩條 spec 同時跑**，讓你看到 infra 上下游每個關節的真實狀態。

---

## 2. Pipeline（實際執行過的命令）

### 2.1 Lint（兩條都跑）

```bash
/tmp/pilot spec docs/verification/core-infra.md           --lint
/tmp/pilot spec docs/verification/core-infra-provider.md --lint
# spec core-infra:           8 rows, 0 findings (0 errors)
# spec core-infra-provider: 9 rows, 0 findings (0 errors)
```

### 2.2 Generate verify playbooks（兩條都產）

```bash
/tmp/pilot spec docs/verification/core-infra.md           --generate playbooks/verify/core-infra.yml
/tmp/pilot spec docs/verification/core-infra-provider.md --generate playbooks/verify/core-infra-provider.yml
# 兩份都被 generator 1-to-1 產出，inspect-only
```

### 2.3 跑 consumer-side verify

```bash
/tmp/pilot verify docs/verification/core-infra.md -i inventory.yaml -l test-vm --report-dir .verification
# verdict: **FAIL**  (pass=4 fail=4 skip=0)
```

| ID | Status | Reason |
|----|--------|--------|
| C1 ✅ | pass | `127.0.0.1` resolver |
| C2 ✅ | pass | systemd-resolved active |
| C4 ✅ | pass | timesyncd active |
| C5 ✅ | pass | `~Offset` substring matched (Stratum=2, Offset=-1.5ms) |
| C3 ❌ | fail | internal zone `infra.internal` / `keycloak.infra.internal` not seeded |
| C6 ❌ | fail | Keycloak discovery endpoint not 200 |
| C7 ❌ | fail | discovery JSON `issuer` field mismatch |
| C8 ❌ | fail | master realm `enabled` field unreachable |

### 2.4 跑 provider-side verify（同 inventory）

```bash
/tmp/pilot verify docs/verification/core-infra-provider.md -i inventory.yaml -l test-vm --report-dir .verification
# verdict: **FAIL**  (pass=3 fail=6 skip=0)
```

| ID | Status | Reason |
|----|--------|--------|
| C2 ✅ | pass | 53 LISTEN 漏過 stub exclusion（soft false positive — ref log） |
| C5 ✅ | pass | chronyd/ntpd status check |
| C6 ✅ | pass | Stratum substring matched |
| C1 ❌ | fail | no DNS server pkg installed (unbound / bind9 / dnsmasq) |
| C3 ❌ | fail | resolv.conf still points to 127.0.0.1 (= client not authoritive) |
| C4 ❌ | fail | no NTP server daemon installed |
| C7 ❌ | fail | no keycloak process |
| C8 ❌ | fail | no 8080 / 8443 listener |
| C9 ❌ | fail | keycloak unreachable |

### 2.5 Status（SQLite 覆蓋率）

```bash
/tmp/pilot spec status docs/verification/core-infra.md
# spec=.../core-infra.md  total=8 verified=8 (pass=4 fail=4) coverage=100.0%

/tmp/pilot spec status docs/verification/core-infra-provider.md
# spec=.../core-infra-provider.md  total=9 verified=9 (pass=3 fail=6) coverage=100.0%
```

---

## 3. 真實結果（兩條 spec）

### 3.1 Spec 並排設計目的

| 軸 | spec | target group | 測什麼 |
|----|------|--------------|-------|
| **consumer** | `core-infra.md` | `all-consumer` (每台 host) | 主機能否正確 *用到* DNS / NTP / IdP |
| **provider** | `core-infra-provider.md` | `all-provider` (只有服務端 host) | 主機能否 *發出* DNS / NTP / IdP |

> 同一台 host 可同時屬於 `all-consumer` 與 `all-provider`（若它既用也發）。

### 3.2 dev test-vm 上的 fail matrix，sane 故事

```
C1 dns-rcv      FAIL  (consumer) — infra zone 未送達此 host
C3 dns-rcv      FAIL  (consumer) — 同上另一種斷言
C6 idp-rcv      FAIL  (consumer) — Keycloak discovery 不可達
C7 idp-rcv      FAIL  (consumer) — issuer 不符
C8 idp-rcv      FAIL  (consumer) — realm enabled 不可達

C1 dns-srv      FAIL  (provider) — 沒有 server pkg
C3 dns-srv      FAIL  (provider) — resolv.conf 是 client 模式
C4 ntp-srv      FAIL  (provider) — 沒有 ntp server daemon
C7 idp-srv      FAIL  (provider) — 沒有 keycloak process
C8 idp-srv      FAIL  (provider) — 沒有 8080/8443 listener
C9 idp-srv      FAIL  (provider) — keycloak 完全不通
```

> 9 個 fail 都來自「dev box 沒裝**服務端** infra、也沒對接到任何**外部** infra」。任何 prod
> 套用到這條 pipeline 應該看到的：`consumer` 全綠、`provider` 在它真的 serve 的項目綠。

### 3.3 Spec 寫下來過程中踩到的 5 個盲點（**已寫進 regression**）

#### 盲點 #1：`dpkg -l` 的 dpkg -l 把「`bind9`」當 substring match

`dpkg -l | grep "^ii  bind9"` 會 match `bind9-host`、`bind9-libs`（client 工具包）— false positive。

修法：用 `dpkg-query -W -f=%{Package} bind9 unbound dnsmasq ... | grep -xE` 只 match exact 名稱。
**寫進**：`internal/spec/core_infra_provider_regression_test.go` 鎖 C1 必含 `unbound`/`bind9`/`dnsmasq`。

#### 盲點 #2：`bind9-dnsutils` 是 client tools 不是 server

就算分包 bind9-dnsutils 是 server 也 fail。Spec 用 `dpkg-query -W -f=%{Package}` 限定清單。

#### 盲點 #3：systemd-resolved stub 用 127.0.0.54 漏網

原本 `grep -v 127.0.0.53` 只擋掉 .53，但 systemd-resolved 同時 listen 在 .54。
修法：`grep -vE '127\.0\.0\.5[34]'` 一併排除整段 stub range。
**寫進**：`core-infra-provider.md` § 5 已知偏差。

#### 盲點 #4：`pgrep -af "keycloak"` 自匹配

`pgrep -f` 會 match 自己 shell 的 cmdline（內含字串 `"keycloak"`）→ dev box 永 PASS。
修法：改 `pidof keycloak`。
**寫進**：regression test 鎖 C7 必用 pidof 不可用 pgrep。

#### 盲點 #5：`present` semantic 被 rc-only 短路

`sh -c '... \| wc -l'` 即使印 `0` 也 rc=0 → `present` 視為通過。
修法：count-style check 一律用 `expected=1`（rc=0 + 數字解讀結合）。
**寫進**：core-infra-provider § 7 SOP 點名這個原則。

> 這 5 個盲點**對每個 spec 都有可能是坑**。把它寫進 `core-infra-provider.md` 是故意的 —
> 寫 spec 的人在看到「這邊有 5 個 false-positive trap」時就會避雷。

---

## 4. Playbook 對應

> apply playbook 還沒寫。`core-infra.md` 是 consumer，只有 verify 沒有 apply — 因為
> 從 consumer 角度測的是「infra 已經在那」是否工作，不應該讓 spec-driven pipeline 自己
> 裝 infra。如果要主動裝 infra，請用 provider-side spec + apply playbook 的鏈。

| 檔 | 用途 | 該誰寫 |
|----|------|--------|
| `playbooks/verify/core-infra.yml` | inspect-only — generator 產 | 不要手寫 |
| `playbooks/verify/core-infra-provider.yml` | inspect-only — generator 產 | 不要手寫 |
| `playbooks/apply/core-infra-provider-apply.yml` | **手寫、含 -e params + block/rescue** | sre |

---


## 6. Apply SOP（只 provider；consumer 不會「套 infra」、只驗證它已存在）

> 上一個 section 給你看的是「**驗證**目前 host 的 infra 健康」。本節示範**對 provider host
> 跑 apply** — 也就是把這台從「client」變成「DNS server / NTP server / Keycloak server」。
> Apply playbook 是手寫的（generator 不生成 mutation playbook）。

### 6.1 Apply playbook 總覽

`playbooks/apply/core-infra-provider-apply.yml`（251 行）：

- 同一份 playbook 處理三個 role（`dns` / `ntp` / `keycloak`），靠 `-e infra_role=...` 挑
- 每個 role 都有 install + configure + service-restart + post-check
- DNS role 有 block/rescue：動 `/etc/systemd/resolved.conf` 前先備份，
  fail 自動 restore（避免 DNS 黑洞把 host 連線切斷）
- Keycloak 用 `0600` 權限寫 `/etc/keycloak/pilot.env`，密碼絕不放上 CLI argv
- 所有 `-e` 參數有 safe default，所以 `--check --diff` 不需任何 flag 就能跑

### 6.2 Dry run（先看 diff）

```bash
ansible-playbook -i inventory-core-infra.yaml \
    playbooks/apply/core-infra-provider-apply.yml \
    -e infra_role=dns \
    -e dns_provider=unbound \
    -e dns_listen_addr=10.0.0.53 \
    --check --diff
# PLAY RECAP : ok=4 changed=1 skipped=14 failed=0
# changed=1 是 copy snapshot /etc/systemd/resolved.conf → .pre-core-infra.bak
```

### 6.3 真套用（sandbox）

```bash
# DNS provider
ansible-playbook -i inventory-core-infra.yaml \
    playbooks/apply/core-infra-provider-apply.yml \
    -e infra_role=dns \
    -e dns_provider=unbound \
    -e dns_listen_addr=10.0.0.53

# NTP provider（可在同一台 host 跑、不衝突）
ansible-playbook -i inventory-core-infra.yaml \
    playbooks/apply/core-infra-provider-apply.yml \
    -e infra_role=ntp \
    -e ntp_provider=chrony \
    -e ntp_pool="ntp.ubuntu.com pool.ntp.org"

# Keycloak provider（要先把 DB 密碼塞進 vault）
ansible-playbook -i inventory-core-infra.yaml \
    playbooks/apply/core-infra-provider-apply.yml \
    -e infra_role=keycloak \
    -e keycloak_admin_user=admin \
    -e @~/.vault/keycloak-sandbox.yaml   # contains keycloak_admin_password, keycloak_db_*
```

### 6.4 Staging / Prod gate

```bash
# Staging — 必須 explicit confirm
ansible-playbook -i inventory-staging.yaml ... \
    -e stage=staging -e confirm_staging=true

# Prod — 多一層 attestation gate
ansible-playbook -i inventory-prod.yaml ... \
    -e stage=prod -e confirm_prod=true \
    -e staging_attested_within_hours=24
```

兩道 gate 都會在 pre_tasks 的 `assert:` 階段 fail-closed，避免「忘了加 flag」誤套到 prod。

### 6.5 Sync 上游 + verify

```bash
# 重新跑 provider spec，看 host 是否真的 serve 起來了
/tmp/pilot verify docs/verification/core-infra-provider.md \
    -i inventory-core-infra.yaml -l test-vm
# expected: pass 從 3 → 7-9 之間（依 inf 缺幾條）

# 跑 consumer spec 確認客戶端仍能用
/tmp/pilot verify docs/verification/core-infra.md \
    -i inventory-core-infra.yaml -l test-vm
# 仍應 4/8 pass（consumer 不依賴此 host 的 infra state）

# 一次看全部
/tmp/pilot verify --dir docs/verification \
    -i inventory-core-infra.yaml -l test-vm
```

### 6.6 Reverse / rollback

- **DNS role**：block/rescue 自動還原 `/etc/systemd/resolved.conf` 從 backup（`backup_suffix: .pre-core-infra.bak`）
- **NTP role**：chrony 改 conf 但 fail 不太影響 client side；必要時 `apt remove chrony`
- **Keycloak role**：`/etc/keycloak/pilot.env` 沒自動刪除 — 這是故意的，你可能想保留以便事後 inspect。
  完全 reset：`systemctl stop keycloak && rm /etc/keycloak/pilot.env && apt remove keycloak*`

## 7. Order of operations（從 0 → provider host 的推進順序）

要把一台 host 從「client only」推到「provider + client」：

1. 第一次進場：host 是 bare Ubuntu，僅 `core-infra` 跑起來會 fail — 沒 infra 沒關係，**這是 gap matrix 訊號**
2. `apt install chrony` + `chronyd --config` → host 是 NTP source，consumer C4/C5 變 PASS
3. `apt install unbound` + unbound config → host 是 DNS source；consumer C1/C2/C3 變 PASS
4. 容器化 Keycloak（用 pre-installed image 或 docker） → consumer C6/C7/C8 變 PASS
5. 全部 PASS 之後，infra-as-a-service 化 → 上 inventory group `all-provider`
6. 之後任何新 host 加 cluster：只要 `-i inventory.yaml -l newhost` 跑同一條 `pilot verify --dir docs/verification`，
   consumer / provider relationship 自動驗證


## 8. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-06-30 | v1.0 | 初版（兩條 spec 並排 + 5 個盲點 SOP）| pilot |
