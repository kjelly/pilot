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

## 5. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-06-30 | v1.0 | 初版（兩條 spec 並排 + 5 個盲點 SOP）| pilot |
