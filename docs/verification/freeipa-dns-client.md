# Verification Spec — freeipa-dns-client（目標主機把 DNS resolver 指向 FreeIPA DNS）

> 版本：v1.0（2026-07-31 對兩台活體 vm-target 實跑：AlmaLinux 9
> `freeipa-dns-server`（FreeIPA server 自身，`--setup-dns`，自我指向案例，
> NetworkManager 路徑）與 Ubuntu 24.04 `freeipa-dns-ubuntu`（一般未納管
> client，systemd-resolved 路徑），C1-C6 兩台皆 6/6 PASS，含 idempotent
> 重跑 `changed=0`；過程中找到並修好 4 個 spec 命令 bug + 2 個 playbook bug
> + 1 個 sandbox image 缺 collection 的 gap，見 §0/§8）
> 對齊規範：pilot 通用基礎設施**使用端**規範；本 host 把系統 DNS resolver
> 指向已經在跑 DNS 的 FreeIPA server / replica（`freeipa-server.md` /
> `freeipa-server-replica.md`，兩者皆可用 `--setup-dns` 原生啟用 named）。
> 維護者：sre

> 對偶參照：本檔驗證的不是 FreeIPA server/replica 主機本身是否健康（見
> `docs/verification/freeipa-server.md` / `freeipa-server-replica.md`），也不是
> FreeIPA 自己的 DNS 控制平面資料是否正確（見 `docs/verification/freeipa-dns.md`
> ——那份驗證 zone/record reconciler 本身）。本檔驗證的是**任意目標主機**
> 的作業系統層級 DNS resolver 設定：是否確實把自己的 DNS 查詢導向這些
> 已經在提供 DNS 的 FreeIPA 主機。與 `freeipa-client.md`（AAA 身分納管）是
> **互不相依的獨立能力**——目標主機不需要先做 FreeIPA client enrollment
> 才能套用本檔；反之亦然。

## 0. 這份檔的狀態（先讀）

依 `AGENTS.md` §1「actual-run 規則」：寫進 `docs/verification/*.md` 步驟區塊的指令，
必須先在對應目標環境實際跑過並截真實輸出才算數。**本檔已完成這件事**：
2026-07-31 對兩台活體 vm-target 實跑（AlmaLinux 9 `freeipa-server`（自我指向
案例，NetworkManager 路徑）與 Ubuntu 24.04 一般未納管 client
（systemd-resolved 路徑）），C1-C6 兩台皆 6/6 PASS，含 idempotent 重跑
`changed=0`。詳細真實輸出見 `docs/runbooks/freeipa-dns-client.md` §3/§4。

**實跑過程找到並修好的真實 bug**（皆非顯而易見，見 runbook §5 完整踩雷紀錄）：
1. C3/C4/C6 三個 Command 誤用跳脫 `\|`／`grep -q`，在「完全沒套用」的狀態下
   仍然回報 PASS（vacuous check）——已修正（見下方 §2 各 row 備註）。
2. playbook 有一處 `tags: [always]` 縮排錯位、掉進 `assert:` 的參數區塊，
   導致 ansible 直接報 `Unsupported parameters`，任何主機都會壞。
3. `vars:` 區塊裡 `freeipa_domain`/`freeipa_dns_client_servers` 曾寫成
   「自我引用」的 Jinja 預設值（`X: "{{ X | default(...) }}"`），在 ansible-core
   會觸發 `Recursive loop detected in template` ——已改成 `pre_tasks` 裡的
   `set_fact` 正規化一次即可，不再用會自我引用的 `vars:`。

**這份 spec 解決的缺口**：`freeipa-server-apply.yml`/`freeipa-server-replica-apply.yml`
預設就用 `ipa-server-install --setup-dns`/`ipa-replica-install --setup-dns` 啟用
FreeIPA 自己的 named（`group_vars/freeipa.example.yml` 的 `freeipa_setup_dns`
預設 `true`），但直到本檔為止，pilot **沒有任何 playbook 讓其他主機的作業系統
resolver 真的去用這個 DNS**——`freeipa-client-apply.yml` 只把 server FQDN
pin 進 `/etc/hosts`（因為它的原始設計假設 `--no-host-dns`，見該檔 §0），
FreeIPA 自己建好的 DNS zone/record（`freeipa-dns-apply.yml` 管理）因此只有
FreeIPA server/replica 自己用得到。

**涵蓋範圍**：
- 目標主機平常以 **Ubuntu/Debian**（`systemd-resolved`）為主。
- **RHEL/EL9 主機只會是 FreeIPA 相關主機**（`freeipa-server` /
  `freeipa-server-replica` / EL9 上的 `freeipa-client`），用
  `NetworkManager`（`community.general.nmcli`）設定，**這些主機也要套用本
  playbook**——包含 FreeIPA server/replica 自己：若該主機本身就是一個有
  `freeipa_setup_dns: true` 的 DNS 提供者，playbook 會讓它的 resolver 優先
  指向自己（`127.0.0.1`），其餘 DNS 提供者作為 fallback；這與
  `ipa-server-install --setup-dns` 本來就會做的事一致，不衝突。

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Inventory group | `freeipa-dns-client`（day-2/opt-in；vm-target 測試時用 `-e target_group=all`）|
| OS / version | Ubuntu/Debian（`systemd-resolved`，primary）与 EL9（`NetworkManager`，FreeIPA 相關主機）皆支援 |
| 角色 | 任意目標主機的 DNS resolver 使用端；把系統 DNS 指向 FreeIPA server/replica 的 named |
| FreeIPA DNS 提供者 | 自動從 inventory 偵測：`freeipa-server` group（其 `freeipa_setup_dns` 預設 `true`）+ `freeipa-server-replica` group 裡 `freeipa_setup_dns: true` 的主機 |
| 套用範圍 | 任意主機（含 FreeIPA server/replica 自己）；多台各自套用同一 playbook |
| 風險等級 | Medium（誤設會讓本機所有 DNS 查詢失敗，但不影響其他主機）|

## 1.5 依賴變數契約

在套用或驗證此主機時，Playbook 與變數參數必須嚴格遵守以下命名，禁止擅自縮寫或發明新變數：

| 變數名稱 | 說明/用途 | 是否必填 |
|---------|----------|---------|
| `freeipa_domain` | Kerberos/DNS domain，預設 `ipa.pilot.internal`（**必須**與 `freeipa-server.md` §1.5 一致）| 否（有預設）|
| `freeipa_dns_client_servers` | 明確指定 nameserver IP 清單（list），**設了就完全略過 inventory 自動偵測** | 否（未設時走自動偵測）|
| `freeipa_setup_dns` | 沿用 `freeipa-server.md`/`freeipa-server-replica.md` 同名 hostvar，決定 inventory 裡哪些主機被視為「有在提供 DNS」；本 playbook 只讀取，不寫入 | 否（各自角色已有預設：`freeipa-server` group 預設 `true`，`freeipa-server-replica` group 預設 `false`）|

> 自動偵測邏輯：走訪 `groups['freeipa-server']`（`freeipa_setup_dns \| default(true)`）
> 與 `groups['freeipa-server-replica']`（`freeipa_setup_dns \| default(false)`），
> 用各主機自己的 `ansible_host` 組成 nameserver 清單；若本機自己也在清單內
> （本機就是 DNS 提供者），把 `127.0.0.1` 排到最前面、其餘提供者接在後面當
> fallback，其餘情況維持 inventory 偵測到的原始順序（`freeipa-server` 排最前）。
> 找不到任何 DNS 提供者、又沒給 `freeipa_dns_client_servers` → apply 直接
> fail-closed（見 §6 gate）。

## 2. Checklist

> 指令以 target 上的 **SSH 使用者**身分執行（`pilot verify` 走 ansible ad-hoc）；
> 讀 `/etc/resolv.conf`（world-readable）與 `dig`（一般使用者可執行）皆免 root。

| ID  | Category | Check                                                        | Expected                | Command |
|-----|----------|---------------------------------------------------------------|--------------------------|---------|
| C1  | package  | DNS 查詢工具 `dig` 已安裝（供本檔功能性驗證使用）              | 0                        | sh -c 'command -v dig' |
| C2  | service  | 該 OS 對應的 resolver 管理服務 active（Debian systemd-resolved／EL NetworkManager）| 0 | sh -c 'systemctl is-active systemd-resolved 2>/dev/null || systemctl is-active NetworkManager' |
| C3  | config   | resolver 設定確實由本 playbook 寫入，非 DHCP 預設（證據依 OS 而異，見下方備註）| pilot-managed | sh -c 'if command -v nmcli >/dev/null 2>&1 && [ -n "$(nmcli -t -f NAME connection show --active 2>/dev/null | head -n1)" ]; then conn=$(nmcli -t -f NAME connection show --active | head -n1); [ "$(nmcli -g ipv4.ignore-auto-dns connection show "$conn" 2>/dev/null)" = yes ] && echo pilot-managed || echo not-managed; else grep -q pilot-freeipa-dns-client /etc/resolv.conf && echo pilot-managed || echo not-managed; fi' |
| C4  | config   | `/etc/resolv.conf` 至少一行 `nameserver`                       | 0                        | sh -c 'grep -c "^nameserver " /etc/resolv.conf | grep -qv "^0$"' |
| C5  | config   | search domain 含 FreeIPA domain（未限定名稱可補 domain 解析）  | 0                        | grep -qE "^search .*ipa.pilot.internal" /etc/resolv.conf |
| C6  | dns      | FreeIPA server FQDN 真的透過 DNS 解析成功（非 `/etc/hosts` 短路）| 0                       | sh -c 'dig +short ipa1.ipa.pilot.internal | grep -qE "^[0-9]+\."' |

> **C1/C2/C4/C6 = rc 型 expected（`0`）**：`command -v`（C1）找到即回 0；
> `systemctl is-active`（C2）刻意用 rc 而非 `~active`——字串 `active` 也會命中
> `inactive`（同款陷阱見 freeipa-client.md §2 備註）；`grep -c ... | grep -qv "^0$"`
> （C4）用「不是 0 行」代替直接比對行數（行數會隨 DNS 提供者數量變動）；
> `dig +short | grep -qE '^[0-9]+\.'`（C6）用「回傳值第一段是數字」代替
> 比對確切 IP（IP 依 inventory 動態變化，寫死會在不同站台全部失效）。
> **C3/C5 = `~substring`**：對 inventory 驗證一律用 `~substring`（ad-hoc 輸出有
> `host | CHANGED | rc=0 >>` 前綴，`^…$` 錨點只在 `--local` 有效，見 spec 模板
> 「三個實測踩過的陷阱」）。**`~substring` 的 Command 絕對不能用 `grep -q`**：
> `-q`（quiet）本來就不印任何東西到 stdout，`~substring` 比對的正是 stdout，
> 兩者連用等於「stdout 恆為空字串」，成功狀態下 substring 永遠對不上、被
> 誤判成 fail（2026-07-31 vm-target 實跑時抓到：C3 用 `grep -q` + `~substring`，
> apply 之後 `/etc/resolv.conf` 明明已經真的寫入標記，`pilot vm-target verify`
> 仍回報 C3 fail——用 `--probe` 重現確認 `grep -q` 的 stdout 恆空，改成不帶
> `-q` 的 `grep`（讓匹配到的行印出來）後 PASS）。`~substring` 要嘛用不帶
> `-q` 的 `grep`（stdout 印出匹配行），要嘛把 Expected 改成單純 rc `0` 並保留
> `-q`——兩者不可混用。
> **C6 用固定字串 `ipa1.ipa.pilot.internal`**：這是本 repo 所有 FreeIPA spec
> 共用的預設 FQDN 慣例（`freeipa_server_fqdn` 預設值，見 `freeipa-server.md` §1.5）,
> 不是真正動態的值，vm-target 測試與其他站台只要沿用預設 domain 就直接成立；
> 若站台覆寫了 `freeipa_server_fqdn`，本 row 需要跟著改成該站台的值（例外見 §5）。
> **C2/C4/C6 的 pipe 一律用字面 `|`，不加 `\` 跳脫**：依
> `verification-spec-template.md` 與 `wazuh-manager.md`/`restic-backup.md` 已有的
> 約定，Command 欄位裡的 `|` 就算整段包在 `sh -c '...'` 的單引號內也不需要
> （也不可以）寫成 `\|`——`splitRow` 對單引號內的字元本來就不會切欄，`\|` 的
> 反斜線不會被 parser 還原掉，會原封不動留在真正執行的指令字串裡，讓 remote
> shell 把它解讀成「跳脫過的字面 pipe 字元」（等於把 `| grep ...` 整段從管線
> 變成 `dig`/`grep`/`systemctl` 自己的位置參數）。2026-07-31 vm-target 實跑時
> 靠這個活生生的差異抓到：v0.1 草稿的 C6 用 `\|` 讓 `grep` 從未真的執行，
> `dig` 對不存在的紀錄仍回 rc=0，導致 C6 在完全沒套用 playbook 的乾淨主機上
> 也會「PASS」（vacuous check，見 `docs/runbooks/freeipa-dns-client.md` 的
> negative-state 證據）；C4 同款 `\|` 也會讓「零筆 nameserver」的情況照樣回
> rc=0（同樣 vacuous，已用一份人工偽造的空白 resolv.conf 重現並驗證修復後
> 正確回報 fail）。C2 的 `\|\|` 剛好因為 `systemctl is-active <多個名字>`
> 本身就是「任一 active 即回 0」的邏輯，未造成誤判，但仍一併修正、統一遵守
> 本 repo 慣例。v1.0 起 C2/C4/C6 一律用未跳脫的字面 `|`。

## 3. 證據收集

- 工具：`pilot vm-target verify --name <vm> docs/verification/freeipa-dns-client.md`
  （真實主機：`pilot verify docs/verification/freeipa-dns-client.md -i inventory.yaml`）
- 原始輸出：gitignored `.verification/freeipa-dns-client-<UTC>.{ndjson,md}`
- Sanitized 摘要：`docs/evidence/freeipa-dns-client/<date>-<tested-revision>.md`
- 預期 row 數：6

**真實輸出摘要**（2026-07-31，兩台 vm-target：AlmaLinux 9 `freeipa-dns-server`
與 Ubuntu 24.04 `freeipa-dns-ubuntu`；完整指令與逐行輸出見
`docs/runbooks/freeipa-dns-client.md` §3/§4，本節依 AGENTS.md §1.16 只保留摘要）：

- Ubuntu（一般未納管 client）apply 前 negative-state verify：`pass=3 fail=3`
  （C1/C2/C4 剛好因 DHCP 預設值/工具預裝而 trivial pass，C3/C5/C6 正確 fail）
- Ubuntu apply 後 verify：**PASS pass=6 fail=0**；idempotent 重跑
  `changed=0`（resolver 相關 mutate task 皆回報 `ok`, 無 `changed`）
- AlmaLinux 9（FreeIPA server 自我指向案例）apply 後 verify：**PASS pass=6
  fail=0**（`/etc/resolv.conf`/`nmcli` 皆確認 `127.0.0.1` 排最前）；idempotent
  重跑 `changed=0`（`nmcli device reapply` 的 `when: ... is changed` gate
  正確 skip）

## 4. PASS / FAIL 規則

- C1–C6 全部 `status=pass`（或 §5 允許的 `skip`）→ **PASS**：本機 DNS 查詢確實
  導向 FreeIPA DNS。
- 任一 `fail` → **FAIL**，常見修法：
  - C1 fail → 套件安裝失敗（Debian `bind9-dnsutils`／EL `bind-utils`）；重跑 apply。
  - C2 fail → Debian 上 `systemd-resolved` 未啟用（罕見，多數 Ubuntu server image
    預設就有）；EL 上 `NetworkManager` 被停用（改用 `nmcli` 前必須先確認它在跑）。
  - C3/C4 fail → apply 沒有真的寫入（可能是 gate 擋下：找不到任何 DNS 提供者
    又沒給 `freeipa_dns_client_servers`，見 §1.5）；檢查 apply 輸出的 assert 訊息。
  - C5 fail → search domain 沒寫入；檢查 `freeipa_domain` 是否有正確傳入/預設。
  - C6 fail → resolver 設定寫了但實際查詢失敗：確認 nameserver IP 真的是
    FreeIPA server/replica 的可路由 IP（防火牆/路由問題），或 FreeIPA 自己的
    named 服務未起來（見 `freeipa-server.md` C 相關 row）。

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C6 | 若站台覆寫了 `freeipa_server_fqdn`（非預設 `ipa1.<domain>`），本 row 的
  Command 需要跟著改用該站台實際的 FQDN，否則永遠 fail | 覆寫過 `freeipa_server_fqdn` 的站台 | 依站台 |
| C2 | 若目標主機兩個 resolver 管理服務都不存在（例如手動管理 `/etc/resolv.conf`
  且兩個 service 都未安裝的特殊 minimal image），可標 `skip` 並改用 C3/C4/C6
  佐證設定確實生效 | 兩種 resolver 管理服務都不存在的主機 | 依站台 |

## 6. Playbook 對應

| Spec row | Apply task / tag |
|----------|-------------------|
| C1-C6 | 2026-08-14 起，實際邏輯抽到共用檔 `playbooks/apply/tasks/freeipa-dns-client-resolver.yml`（spec.md §26 point 1），`freeipa-dns-client-apply.yml` 本身只剩 stage gate + 一個
  `Apply the FreeIPA DNS resolver baseline to this host`／`tags: [C1, C3, C4, C5, C6]` 的
  `include_tasks`。同一份共用檔也被 `internal-endpoint-apply.yml` 的 fleet-wide
  baseline play 引用（docs/verification/internal-endpoint.md C9），比照
  `tasks/freeipa-ca-trust.yml` 已建立的共用慣例，兩份 playbook 不會分岔出兩套實作。 |
| C2 | 隨 Debian/`systemd-resolved` 或 EL/`NetworkManager` 既有服務健康，本 playbook
  不重複起停該服務、只在其已 active 的前提下設定 DNS（見 pre_tasks gate）|
| C3 | **2026-08-14 修正**：Debian 上用 `/etc/resolv.conf` 內的 pilot 標記字串
  證明；EL 上 `nmcli device reapply` 每次都會讓 NetworkManager 用自己的
  `# Generated by NetworkManager` 重新產生 `/etc/resolv.conf`，標記字串
  必然消失（實際 DNS 內容仍然正確，C6 功能性驗證仍會 PASS，純粹是 C3 這個
  探測本身找錯了持久證據）——改成偵測 nmcli 是否存在：存在就檢查該
  connection profile 的 `ipv4.ignore-auto-dns=yes`（唯一只有 pilot 會設定
  的持久欄位），否則才退回檢查 `/etc/resolv.conf` 標記。 |
| C6 | 驗證用途，無對應 mutate task（apply 完成後的功能性結果）|

## 7. 動態行為 SOP（fixture：確保有 DNS 提供者可偵測）

跑本檔驗證前，inventory 必須至少有一台 `freeipa-server`（或
`freeipa-server-replica` 且 `freeipa_setup_dns: true`）已完成
`freeipa-server-apply.yml`（`--setup-dns`）並健康（見 `freeipa-server.md` §2）。
本檔不建立/管理 FreeIPA server 本身，純粹消費它已經存在的 DNS 服務。

## 8. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-31 | v0.1 | 初版（DRAFT，尚未實跑，見 §0）| sre |
| 2026-07-31 | v1.0 | 對 AlmaLinux 9(FreeIPA server 自我指向)與 Ubuntu 24.04(一般 client) 兩台 vm-target 實跑,C1-C6 兩台皆 6/6 PASS + idempotent `changed=0`;修正 3 個 vacuous-check spec bug(C3/C4/C6)| sre |
| 2026-08-14 | v1.0 | internal-endpoint Phase 10 收尾:實際邏輯抽到共用檔 `tasks/freeipa-dns-client-resolver.yml`,同時被 internal-endpoint-apply.yml 的 fleet-wide baseline play 引用以修好 docs/verification/internal-endpoint.md 的 C9(見該檔 §26 point 1 的既有 gap)。3 台新 vm-target(AlmaLinux 9 自我指向 + AlmaLinux 9 一般 client + Ubuntu 24.04 一般 client)重跑,17/18 首次全過(1 個真的抽出時才引入的 --check 下 NetworkManager gate 誤判 bug,已修:read-only 的 `nmcli connection show --active` 缺 `check_mode: false`);另修好 C3 本身在 EL 上的探測設計缺陷(`nmcli device reapply` 每次都會讓 NetworkManager 重新產生 `/etc/resolv.conf`,pilot 寫入的標記字串必然消失,即便真實設定完全正確)。修正後 3 台 18/18 PASS + idempotent 重跑 `changed=0`,無 regression。| sre |
