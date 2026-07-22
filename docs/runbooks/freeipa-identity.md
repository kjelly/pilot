# Runbook — FreeIPA 使用者 / 權限管理（名冊與機密不進 git）

> 撰寫日期：2026-07-02 (UTC)；v1.1（2026-07-17）併入主機分權驗證演練
> （見 §5.3，原 `docs/runbooks/freeipa-hostauthz-test-plan.md`，該檔已歸檔）
> 對齊規範：`playbooks/apply/freeipa-identity-apply.yml`、`playbooks/apply/freeipa-identity.roster.example.yaml`
> 維護者：sre

---

## 0. 一句話目標

> **Git 放邏輯，repo 外放資料。** 使用者、群組、sudo 權限的「怎麼做」寫在 git 裡一支
> generic playbook；「是誰、什麼密碼、給什麼權限」放在 repo 外、用 `ansible-vault`
> 加密的名冊檔。任何人 clone 這個 repo 都拿不到你的真實帳號與密碼。

跟 `freeipa-server-apply.yml` 是同一套慣例（gate、`no_log`、冪等、stage gating），也
沿用 repo 既有的 `~/.vault/` 機密模式（見 `freeipa-server-apply.yml` 的 `-e @~/.vault/…`）。

已部署 FreeIPA 的日常 roster 調和入口是 **`pilot reconcile`**，不是全站 `pilot
deploy`：兩者同樣會先做 preflight、stage gate、preview 與人工確認，但前者只顯示
contract-backed 的 day-2 reconciler。此版本已實機跑過 `freeipa-identity` 的
preview→apply，PLAY RECAP 為 `freeipa-server: ok=31 changed=12 failed=0`；原始 trec
證據保留在 disposable verification workspace。未來 Nginx config 之類的設定型角色，
必須先具備自己的 contract、apply playbook、schema 與 verification evidence，才可加入
這個入口。

---

## 1. 檔案分工

| 檔案 | 進 git？ | 內容 |
|------|:---:|------|
| `playbooks/apply/freeipa-identity-apply.yml` | ✅ | Generic reconciler，loop 過 `ipa_users` / `ipa_groups` / `ipa_sudo_rules`，**本身不含任何真名字** |
| `playbooks/apply/freeipa-identity.roster.example.yaml` | ✅ | 只有 schema、無真資料，文件化名冊格式 |
| `~/.vault/ipa-identity.yaml` | ❌ | 你的**真實名冊 + `ipa_admin_password`**，`ansible-vault` 加密，永不進 repo |
| `~/.vault/vault-pass` | ❌ | vault 解密密碼（`.gitignore` 已擋 `*vault-password*`；放 repo 外更保險） |

> ⚠️ 真名冊放 `~/.vault/`（repo 外）。**不要** copy 進 repo 根目錄命名成
> `ipa-identity.yaml`——那個路徑沒被 `.gitignore` 擋（只擋 `*.vault`、`inventory*.yaml`）。

---

## 2. 前置需求

```bash
# 一台已裝好的 FreeIPA server（native EL9），例如 alma-vm（.5）。
# 見 docs/runbooks/... 的 freeipa-server 流程，或既有的 alma-vm。

ansible-vault --version    # ansible 內建
```

---

## 3. 一次性設定：建立加密名冊

```bash
mkdir -p ~/.vault

# 1. 從 example 複製 schema
cp playbooks/apply/freeipa-identity.roster.example.yaml ~/.vault/ipa-identity.yaml

# 2. 填入真實 users / groups / sudo rules 與真的 ipa_admin_password
$EDITOR ~/.vault/ipa-identity.yaml

# 3. 就地加密
ansible-vault encrypt ~/.vault/ipa-identity.yaml

# 4.（選）把 vault 密碼寫進檔案，之後免手打
printf '%s' 'YOUR-VAULT-PASSWORD' > ~/.vault/vault-pass
chmod 600 ~/.vault/vault-pass
```

名冊 schema（完整範例見 `freeipa-identity.roster.example.yaml`）：

```yaml
ipa_admin_password: "..."          # REQUIRED：kinit admin 用

ipa_groups:
  - { name: developers, desc: "Application developers" }

ipa_users:
  - name: alice
    first: Alice
    last: Wang
    password: "initial-pw"          # 初始密碼；可省略（改用 OTP 帶外設定）
    force_password: true            # 預設 false；首次 onboard 或刻意重設才要加這行
    groups: [developers]
    ssh_keys:                       # 選填；宣告式（見 §5.1）。密碼＋金鑰可並存
      - "ssh-ed25519 AAAA... alice@laptop"
  - name: carol                     # 純金鑰、無密碼帳號（省略 password:）
    first: Carol
    last: Chen
    ssh_keys:
      - "ssh-ed25519 AAAA... carol@workstation"

ipa_sudo_rules:
  - name: sysops-systemctl
    hostcat: all
    allow_commands: [/usr/bin/systemctl]
    groups: [sysops]                # 也可用 users: [alice]
  - name: developers-restart-web    # 主機分權：省略 hostcat，改用 hostgroups
    hostgroups: [webhosts]
    allow_commands: [/usr/bin/systemctl]
    groups: [developers]
  - name: devops-sudo               # 全指令：省略 allow_commands，改用 cmdcat: all
    hostcat: all
    cmdcat: all
    groups: [sysops]

ipa_hostgroups:
  - name: webhosts
    desc: "Front-end / web tier"
    hosts: [web1.ipa.pilot.internal, web2.ipa.pilot.internal]

ipa_hbac_rules:                     # 控制「誰能登入哪些主機」，見 §5.2
  - name: developers-login-web
    hostgroups: [webhosts]
    services: [sshd]
    groups: [developers]

# 待 ipa_hbac_rules 涵蓋所有需要的登入路徑後才設 true（見 §5.2）
# ipa_hbac_disable_allow_all: true
```

---

## 4. 日常操作：改權限就編輯名冊再套用

### 4.1 編輯名冊（不落地明文）

```bash
ansible-vault edit ~/.vault/ipa-identity.yaml
```

### 4.2 先 dry-run 看差異（強烈建議）

```bash
ansible-playbook -i inventory-freeipa.yaml \
    playbooks/apply/freeipa-identity-apply.yml \
    -e @~/.vault/ipa-identity.yaml \
    --vault-password-file ~/.vault/vault-pass \
    --check --diff
```

### 4.3 套用

透過 `pilot vm-target`（host 在 group `all`，非 `freeipa-server`）：

```bash
pilot vm-target run --name alma-vm \
    playbooks/apply/freeipa-identity-apply.yml \
    -e target_group=all \
    -e @~/.vault/ipa-identity.yaml \
    --vault-password-file ~/.vault/vault-pass
```

或直接對真 inventory 跑：

```bash
ansible-playbook -i inventory-freeipa.yaml \
    playbooks/apply/freeipa-identity-apply.yml \
    -e @~/.vault/ipa-identity.yaml \
    --vault-password-file ~/.vault/vault-pass
```

> 管權限 = 改 `~/.vault/ipa-identity.yaml` 再跑一次。Repo 永遠只有「怎麼做」，
> 沒有「是誰、什麼密碼」。

### 4.4 只跑一部分（tags）

```bash
# 只同步 sudo 權限，不動 users/groups
... playbooks/apply/freeipa-identity-apply.yml --tags sudo ...
# 只重新推 SSH 金鑰（換金鑰、撤金鑰時很方便）
... playbooks/apply/freeipa-identity-apply.yml --tags sshkeys ...
# 只同步主機分權（hostgroups + HBAC 登入規則）
... playbooks/apply/freeipa-identity-apply.yml --tags hostgroups,hbac ...
# 可用 tags：identity(全部)、groups、users、passwords、sshkeys、hostgroups、hbac、sudo
```

---

## 5. 冪等性

每個 task 都把「already exists / already a member」當 no-op（`changed_when` /
`failed_when` 對齊 `freeipa-server-apply.yml`）。重跑同一份名冊 → `PLAY RECAP`
的 `changed=0`。

例外：**密碼是設定就無條件套用**的（IPA 沒有可 diff 的 read-back），且 `ipa
passwd` 是 admin reset，不管密碼值有沒有變都會把帳號重新標成「下次登入強制改密
碼」。所以 `force_password` 預設 **false**：帶 `password:` 的 user 只有同時明講
`force_password: true` 時，這次 apply 才會真的執行 `ipa passwd`（並因此
`changed`）。首次幫某個 user 設密碼（onboard）或要刻意重設時才加這行；一旦
onboard 完成，把這行拿掉（或設 `false`），之後重跑同一份名冊就不會再動到他的密
碼／forced-change 狀態。

---

## 5.1 SSH 公鑰管理（免每台機器維護 authorized_keys）

在 user 底下加 `ssh_keys:`（一串完整公鑰行：type + base64 + 選填註解）。原理與注意事項：

- **集中存放**：金鑰寫進 IPA 的 `ipaSshPubKey` 屬性；**已 enroll 的 client** 上的
  sshd 透過 `AuthorizedKeysCommand /usr/bin/sss_ssh_authorizedkeys` 由 SSSD 動態取用。
  `ipa-client-install` 預設就設好 sshd + SSSD 這段，**不需要**在每台主機維護
  `~/.ssh/authorized_keys`。
- **宣告式（重要）**：`ssh_keys:` 列的就是該帳號**完整**的金鑰集合。playbook 用
  `ipa user-mod --sshpubkey=...` **整組取代**。所以：
  - 換金鑰 → 改 list 內容再套用。
  - **撤銷金鑰 → 從 list 拿掉再套用**（不是留著不管）。
  - 一次多把金鑰 → list 放多行即可。
- **純金鑰帳號**：省略 `password:`、只給 `ssh_keys:`，就是完全 key-based、無密碼登入
  （對齊 FreeIPA workshop 的 SSH key-management 流程）。
- 金鑰走 `argv`（非 shell）傳入，內含空格/base64 不會被 shell 破壞。

```bash
# 只推金鑰、不動其他
pilot vm-target run --name alma-vm \
    playbooks/apply/freeipa-identity-apply.yml \
    -e target_group=all \
    -e @~/.vault/ipa-identity.yaml \
    --vault-password-file ~/.vault/vault-pass \
    --tags sshkeys
```

> 產生新金鑰對：`ssh-keygen -t ed25519 -C 'alice@laptop'`，把 `*.pub` 內容整行貼進
> 名冊的 `ssh_keys:`。私鑰留在使用者自己機器上，**絕不**進名冊。

---

## 5.2 主機分權：不是每個人都能碰每一台主機

「權限」在 FreeIPA 裡分兩層，兩層都要設對，缺一層就不是真的分權：

| 層 | 管什麼 | 預設行為（不設規則時） |
|----|--------|----|
| **HBAC**（`ipa_hbac_rules`） | 能不能**登入**某台主機（SSH/PAM） | IPA 內建 `allow_all` 規則放行**所有已 enroll 使用者登入所有已 enroll 主機** |
| **sudo**（`ipa_sudo_rules`） | 登入後**能執行什麼** | 每條 rule 若沒給 `hosts:`/`hostgroups:`，預設 `hostcat: all`（套用到所有主機）；同理，沒給 `allow_commands:` 時預設 `cmdcat: all`（套用到所有指令） |

也就是說：只把 sudo rule 改成 host-scoped 是不夠的——沒關掉 `allow_all`，任何
enrolled 帳號還是能直接 SSH 到不該碰的主機（雖然到了那台可能沒有 sudo 權限，
但一般帳號本身的操作範圍就已經不該開放）。

### 5.2.1 先分組：`ipa_hostgroups`

```yaml
ipa_hostgroups:
  - name: webhosts
    desc: "Front-end / web tier"
    hosts: [web1.ipa.pilot.internal, web2.ipa.pilot.internal]
  - name: dbhosts
    hosts: [db1.ipa.pilot.internal]
```

`hosts:` 填的是**已 enroll**的 client FQDN（先跑過 `freeipa-client` 的 apply
把主機 enroll 進 IPA，這裡才有東西可分組；用 `ipa host-find` 確認名稱）。

### 5.2.2 控制登入：`ipa_hbac_rules`

```yaml
ipa_hbac_rules:
  - name: developers-login-web      # developers 只能 SSH 進 webhosts
    hostgroups: [webhosts]
    services: [sshd]
    groups: [developers]
  - name: sysops-login-all          # sysops 沒給 hosts/hostgroups → 全主機皆可登入
    services: [sshd]
    groups: [sysops]
```

- 省略 `hostgroups:`/`hosts:` → 該規則 `hostcat: all`（比照 sudo rule 的慣例）。
- 省略 `services:` → `servicecat: all`（不限存取方式）；通常明確給
  `services: [sshd]` 較安全、範圍清楚。
- 規則建好、涵蓋所有你要的登入路徑後，**務必**在名冊頂層（跟
  `ipa_admin_password` 同層）加：

  ```yaml
  ipa_hbac_disable_allow_all: true
  ```

  不然內建 `allow_all` 仍然放行所有人登入所有主機，前面的規則形同虛設。

  > 分階段上線建議：先加 HBAC 規則、`--check --diff` 確認涵蓋到位、實際登入
  > 測試沒問題，**最後一步**才把 `ipa_hbac_disable_allow_all` 設 `true` 套用，
  > 避免中途把自己鎖在門外。

  > **`services:` 只給 `sshd` 是不夠的，一旦真的關掉 `allow_all`。** SSSD 的
  > `access_provider = ipa` 對**每一個** PAM service 都各自做一次 HBAC 檢查，
  > 不是只在登入時檢查一次。內建的 `allow_all`（以及 `allow_systemd-user`，
  > 它自己的 `HBAC Services` 也含 `sshd`）平常會順便涵蓋 `sudo` 這個 PAM
  > service，讓人誤以為「登入規則對了、sudo 就會對」。實際關掉 `allow_all`
  > 後，只列 `services: [sshd]` 的規則仍然讓使用者登入成功，但主機上任何
  > `sudo` 呼叫都會失敗：`sudo: PAM account management error: Permission
  > denied`，即使 `ipa sudorule-show`/`ipa hbactest --service=sshd` 都顯示
  > 正常（2026-07-16 全新 3-VM 環境實測重現；`ipa hbactest --service=sudo`
  > 對同一個使用者/主機回報 `Access granted: False`，加上 `sudo`/`sudo-i`
  > 到 `services:` 後才變成 `True`，即時生效不需要重開機）。**只要規則需要
  > 讓使用者在該主機上執行 `sudo`，就把 `sudo`（用 `sudo -i` 就再加
  > `sudo-i`）一起列進 `services:`**，不要只靠 `sshd`。

### 5.2.3 控制主機上的權限：host-scoped `ipa_sudo_rules`

```yaml
ipa_sudo_rules:
  - name: developers-restart-web    # 省略 hostcat，改用 hostgroups
    hostgroups: [webhosts]
    allow_commands: [/usr/bin/systemctl]
    groups: [developers]
```

跟既有 `hostcat: all` 的寫法並存：一份名冊裡有些 rule 全主機適用（保留
`hostcat: all`），有些只在特定 hostgroup/host 生效（給 `hostgroups:`/`hosts:`）
即可，不用整批改。

---

## 5.3 主機分權驗證演練（實測，2026-07-17）

> 本節原為獨立文件 `docs/runbooks/freeipa-hostauthz-test-plan.md`
> （2026-07-03 首次撰寫），2026-07-17 整併進本檔並用當次整併驗證的環境
> **重新實跑**，下方為該次真實輸出。目的：證明 §5.2 定義的 hostgroup /
> HBAC / host-scoped sudo 三個資料維度組合起來，真的能做到「不同使用者在
> 不同主機擁有不同權限，且不是所有人都能碰所有主機」，並且驗證
> **infra-as-code reconciler 的撤銷語意**——從名冊移除一項、重新 apply，
> live state 必須真的被撤銷，不是留著不管。

### 5.3.0 拓撲

一台 server + 兩台 client（本次重測用既有 pool 中的 `freeipa-server`、
`client-vm`〔角色 webhosts〕、`nexus`〔角色 dbhosts，重測時把它從
Workstream A 的 S3 目的地重置後重新 enroll 成第二台 FreeIPA client〕）：

| 角色 | target 名稱 | FQDN |
|---|---|---|
| server | `freeipa-server` | ipa1.ipa.pilot.internal |
| webhosts client | `client-vm` | client-vm.ipa.pilot.internal |
| dbhosts client | `nexus` | nexus.ipa.pilot.internal |

測試名冊 `~/.vault/ipa-identity-test.yaml`（假帳號、repo 外，跟正式名冊分開）：

```yaml
---
ipa_groups:
  - { name: hz-web, desc: "TEST — web-tier access" }
  - { name: hz-db,  desc: "TEST — db-tier access" }

ipa_users:
  - { name: hz_web, first: Hz, last: Web, password: "TestWebPass123", groups: [hz-web] }
  - { name: hz_db,  first: Hz, last: Db,  password: "TestDbPass123",  groups: [hz-db] }

ipa_hostgroups:
  - { name: webhosts, desc: "TEST — web tier", hosts: [client-vm.ipa.pilot.internal] }
  - { name: dbhosts,  desc: "TEST — db tier",  hosts: [nexus.ipa.pilot.internal] }

ipa_hbac_rules:
  - { name: hz-login-web, hostgroups: [webhosts], services: [sshd, sudo, sudo-i], groups: [hz-web] }
  - { name: hz-login-db,  hostgroups: [dbhosts],  services: [sshd, sudo, sudo-i], groups: [hz-db] }

ipa_sudo_rules:
  - { name: hz-web-systemctl, hostgroups: [webhosts], allow_commands: [/usr/bin/systemctl], groups: [hz-web] }
  - { name: hz-db-systemctl,  hostgroups: [dbhosts],  allow_commands: [/usr/bin/systemctl], groups: [hz-db] }
```

> 跟 2026-07-03 原始名冊的差異：HBAC rule 的 `services` 這次直接帶
> `[sshd, sudo, sudo-i]`，不是只有 `[sshd]`——這是套用 §5.2.2 已經記載的
> gotcha（關掉 `allow_all` 後，只列 `sshd` 的規則會讓登入成功但 `sudo`
> 全部失敗）預先修正，不是本次演練才發現的新問題。

### 5.3.1 T1 — Dry-run

```bash
go run ./cmd/pilot vm-target run --name freeipa-server playbooks/apply/freeipa-identity-apply.yml \
    -e @~/.vault/main.yaml -e @~/.vault/ipa-identity-test.yaml --check --diff
```

真實輸出：所有 `command`/`shell` 類 task 在 `--check` 下如預期 `skipping`，
每個 loop item 的 label 正確印出（`hz-web-systemctl hostgroup webhosts` 等）；

```
PLAY RECAP *********************************************************************
freeipa-server             : ok=4    changed=0    unreachable=0    failed=0    skipped=51   rescued=0    ignored=0
```

### 5.3.2 T2 — 實際套用 + 冪等性

```bash
go run ./cmd/pilot vm-target run --name freeipa-server playbooks/apply/freeipa-identity-apply.yml \
    -e @~/.vault/main.yaml -e @~/.vault/ipa-identity-test.yaml
```

```
PLAY RECAP *********************************************************************
freeipa-server             : ok=36   changed=15   unreachable=0    failed=0    skipped=19   rescued=0    ignored=0
```

立刻重跑一次：

```
PLAY RECAP *********************************************************************
freeipa-server             : ok=36   changed=1    unreachable=0    failed=0    skipped=19   rescued=0    ignored=0
```

`changed=1` 只是密碼 task（`ipa passwd` 無法 diff，每次都視為 changed，
已知行為，見 §5）；hostgroup/HBAC/sudo 相關 task 全部 `ok`。

### 5.3.3 T3 + T4 — 結構驗證 + HBAC 決策引擎測試

```bash
go run ./cmd/pilot vm-target run --name freeipa-server playbooks/test/fixtures/freeipa-hostauthz-demo.yml \
    -e fixtures_target_group=all -e @~/.vault/main.yaml \
    -e webhost_fqdn=client-vm.ipa.pilot.internal -e dbhost_fqdn=nexus.ipa.pilot.internal \
    --tags fixtures,t3,hbactest
```

> **`webhost_fqdn`/`dbhost_fqdn` 這兩個 `-e` override 是本次整併新增的**：
> 本次重測用 `client-vm`/`nexus` 而非原始文件的 `freeipa-client`/
> `freeipa-client-2` 命名，`freeipa-hostauthz-demo.yml` 的 T3 結構驗證原本
> 有兩行把這兩台主機的 FQDN **寫死成字串**（`'freeipa-client.ipa.pilot.internal'
> in ...`），沒有走 `webhost_fqdn`/`dbhost_fqdn` 這兩個既有變數，導致當初
> 直接套用會在 T3 assert 卡住。已修正 `freeipa-hostauthz-demo.yml`，把這兩行
> 改成用變數比對（跟同檔案 T4 hbactest 的既有寫法一致），這是本次整併重測
> 發現並修好的真事故，不是繞過。

**T3 結構驗證**（三個 assert 全部通過）：

```
TASK [T3 — assert hostgroup membership matches the roster] ok: All assertions passed
TASK [T3 — assert HBAC rules reference the right hostgroup/service/group] ok: All assertions passed
TASK [T3 — assert sudo rules reference the right hostgroup/command/group] ok: All assertions passed
```

**T4 HBAC 決策引擎測試**（`ipa hbactest` 逐規則比對，真實輸出）：

```
TASK [T4 — assert HBAC decisions match expected host-scoping] ok: All assertions passed
TASK [T4 — summary] =>
  hz-login-web rule, hz_web -> client-vm.ipa.pilot.internal : MATCHED (expected MATCHED)
  hz-login-web rule, hz_web -> nexus.ipa.pilot.internal     : NOT MATCHED (expected NOT MATCHED)
  hz-login-db rule,  hz_db  -> nexus.ipa.pilot.internal     : MATCHED (expected MATCHED)
  hz-login-db rule,  hz_db  -> client-vm.ipa.pilot.internal : NOT MATCHED (expected NOT MATCHED)

PLAY RECAP *********************************************************************
freeipa-server             : ok=19   changed=2    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```

（`allow_all` 此時仍啟用，`hbactest` 整體 `Access granted` 一律 `True`，
host-scoping 的證據要看每條規則的 `Matched rules:`/`Not matched rules:`，
不是整體 granted/denied——跟 §5.2.2 的說明一致。）

### 5.3.4 T5 — 單機真實登入 + sudo 驗證（正向）

四組 SSH key 建立（含刻意的「錯主機」組合，負向測試會用到）：

```bash
go run ./cmd/pilot vm-target run --name client-vm playbooks/test/fixtures/freeipa-hostauthz-user-setup.yml -e target_group=all -e hostauthz_user=hz_web
go run ./cmd/pilot vm-target run --name client-vm playbooks/test/fixtures/freeipa-hostauthz-user-setup.yml -e target_group=all -e hostauthz_user=hz_db
go run ./cmd/pilot vm-target run --name nexus     playbooks/test/fixtures/freeipa-hostauthz-user-setup.yml -e target_group=all -e hostauthz_user=hz_db
go run ./cmd/pilot vm-target run --name nexus     playbooks/test/fixtures/freeipa-hostauthz-user-setup.yml -e target_group=all -e hostauthz_user=hz_web
```

四次都 `ok=2 changed=2 failed=0`。讓 SSSD 拿到剛設好的 `!authenticate`：

```bash
go run ./cmd/pilot vm-target exec --name client-vm -- sudo systemctl restart sssd
go run ./cmd/pilot vm-target exec --name nexus     -- sudo systemctl restart sssd
```

正向情境（真實輸出）：

```bash
go run ./cmd/pilot vm-target run --name client-vm playbooks/test/fixtures/freeipa-hostauthz-sim.yml \
    -e target_group=all -e sim_local_user=hz_web -e sim_local_password=TestWebPass123 -e sim_foreign_user=hz_db \
    --tags positive
```

```
TASK [Sim[+] — positive-phase summary] =>
  Host: client-vm
  hz_web login    : OK (expected OK)
  hz_web sudo     : OK (expected OK)
  hz_db sudo   : DENIED (expected DENIED)

PLAY RECAP *********************************************************************
client-vm                  : ok=10   changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```

```bash
go run ./cmd/pilot vm-target run --name nexus playbooks/test/fixtures/freeipa-hostauthz-sim.yml \
    -e target_group=all -e sim_local_user=hz_db -e sim_local_password=TestDbPass123 -e sim_foreign_user=hz_web \
    --tags positive
```

```
TASK [Sim[+] — positive-phase summary] =>
  Host: nexus
  hz_db login    : OK (expected OK)
  hz_db sudo     : OK (expected OK)
  hz_web sudo   : DENIED (expected DENIED)

PLAY RECAP *********************************************************************
nexus                       : ok=10   changed=0    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0
```

> **`target_group=all` 這兩次都必要**——playbook `hosts:` 預設群組名是
> `freeipa-client`，本次重測用的是 `client-vm`/`nexus` 兩個名稱，第一次沒帶
> 這個 override 時真的撞到 `skipping: no hosts matched`（見 §5.3.6 gotcha
> 表最後一列）。

### 5.3.5 T6 — 雙機交叉驗證（負向：錯主機登入必須被拒）+ reconciler 撤銷驗證

**T6.1 關閉 `allow_all`**：

```bash
go run ./cmd/pilot vm-target run --name freeipa-server playbooks/apply/freeipa-identity-apply.yml \
    -e @~/.vault/main.yaml -e @~/.vault/ipa-identity-test.yaml -e ipa_hbac_disable_allow_all=true
```

只有 `Disable the default allow_all HBAC rule` 顯示 `changed`，其餘 `ok`。

**T6.2 刷新兩台 client 的 SSSD**，**T6.3 負向情境**（真實輸出）：

```
TASK [Sim[-] — negative-phase summary] => Host: client-vm / hz_db login (wrong host) : DENIED (expected DENIED)
TASK [Sim[-] — negative-phase summary] => Host: nexus     / hz_web login (wrong host) : DENIED (expected DENIED)
```

**T6.4 立刻恢復 `allow_all`**：

```bash
go run ./cmd/pilot vm-target run --name freeipa-server playbooks/test/fixtures/freeipa-hostauthz-demo.yml \
    -e fixtures_target_group=all -e @~/.vault/main.yaml --tags restore
```

`ok=4 changed=1 failed=0`（`Restore — re-enable the default allow_all HBAC
rule` 顯示 `changed`）。恢復後重驗三份 spec 皆 PASS（server pass=18、兩台
client 各 pass=10），確認未受影響。

**Reconciler 撤銷語意驗證**（本節是 2026-07-17 整併時新增的演練步驟，原始
2026-07-03 測試計畫沒有這一段；補上的原因：`freeipa-identity-apply.yml`
的 reconciler 設計核心賣點就是「名冊移除一項，live state 真的被撤銷」，
之前只驗證過新增/修改路徑，沒驗證過移除路徑）：

1. 先確認 `hz_web` 目前 sudo 正常（`sudo -n systemctl status sssd` → rc=0）。
2. 把測試名冊 `hz_web` 的 `groups: [hz-web]` 改成 `groups: []`，重新 apply：

   ```
   TASK [Remove stale group memberships] changed: [freeipa-server] => (item=hz_web -/-> hz-web)
   ```

3. `ipa group-show hz-web` 確認 `hz_web` 真的不在成員清單裡了（只剩
   `Member of Sudo rule`/`Member of HBAC rule`，沒有 `Member users:` 那行）。
4. client 刷新 SSSD 後，`hz_web` 的 `sudo -n systemctl status sssd` 真的變成
   `sudo: a password is required`（rc=1）——**live 權限被真的撤銷了**，不是
   名冊改了但 server 端沒反應。
5. 把 `groups: [hz-web]` 加回去、重新 apply（`Ensure user group membership
   changed: [freeipa-server] => (item=hz_web -> hz-web)`），刷新 client SSSD
   後 `sudo -n systemctl status sssd` 恢復 rc=0——確認撤銷是可逆的，不是單向
   壞掉。

### 5.3.6 收尾：清掉測試資料

```bash
go run ./cmd/pilot vm-target run --name freeipa-server playbooks/test/fixtures/freeipa-hostauthz-demo.yml \
    -e fixtures_target_group=all -e @~/.vault/main.yaml --tags cleanup
```

真實輸出：第一次 `ok=9 changed=6`（sudo rule ×2、sudocmd ×1、HBAC rule
×2、hostgroup ×2、user ×2、group ×2 全部刪除，數字加總對得上）；重跑一次
`ok=9 changed=0`，確認 delete 本身冪等。

client 端清 home 目錄：

```bash
go run ./cmd/pilot vm-target exec --name client-vm -- sudo rm -rf /home/hz_web /home/hz_db
go run ./cmd/pilot vm-target exec --name nexus     -- sudo rm -rf /home/hz_web /home/hz_db
```

> **Cleanup 驗證本身又踩到跟 `restic-backup.md` §6.6、
> `freeipa-389ds-audit-log.md` §6.6 同一種 SSSD 快取陷阱**：`user-del` 後
> 沒清 client SSSD 快取就查 `id hz_web@ipa.pilot.internal`，一樣會先命中
> 舊快取。清掉 `/var/lib/sss/db/{cache,timestamps}_ipa.pilot.internal.ldb`
> 並 `systemctl restart sssd` 後才能正確觀察到 `no such user`。

清理後重驗三份 spec，確認未受影響（server pass=18、兩台 client 各
pass=10）。`~/.vault/ipa-identity-test.yaml` 可以留著（repo 外、假帳號，
下次重跑整套測試可直接重用）。

### 5.3.7 已知 gotcha 一覽（DR/audit 章節已有的 SSSD 快取類 gotcha不重複列，只列本演練專屬的）

| 症狀 | 原因 | 解法 |
|---|---|---|
| `sudo -n systemctl ...` 回 `a password is required` | server 端剛加的 `!authenticate` 選項還沒被 client SSSD 快取刷新 | `sudo systemctl restart sssd`（§5.3.4/§5.3.5） |
| `hbactest` 的 `Access granted` 每個組合都是 `True` | IPA 內建 `allow_all` 還開著，會蓋掉個別規則的效果 | 正常現象；看 `Matched rules:`/`Not matched rules:` 才準，或走 T6 把 allow_all 關掉測真正的登入 deny |
| `pilot vm-target run --name <非 freeipa-client 命名的 target> ...` 顯示 `no hosts matched` | playbook `hosts:` 預設群組名是 `freeipa-client`，target 名稱只要不叫這個就不會自動比對到 | 一律加 `-e target_group=all`（本次重測用 `client-vm`/`nexus`，兩個都需要） |
| `freeipa-hostauthz-demo.yml` 的 T3 assert 卡住，即使 `-e webhost_fqdn=...`/`-e dbhost_fqdn=...` 都給了 | T3 assert 原本兩行把 FQDN 寫死成字串，沒有真的讀 `webhost_fqdn`/`dbhost_fqdn` 變數（2026-07-17 整併重測時發現的真事故） | 已修：改成 `webhost_fqdn in ...`/`dbhost_fqdn in ...`，走變數比對 |
| §4（T3/T4）跑完後，T5.3 sudo 才在下游失敗，`sudorule-show` 顯示 hostgroup/選項不見了 | 命令沒帶 `--tags fixtures,t3,hbactest`，連同檔案裡的 `restore`/`cleanup` task block 一起跑了 | 一律加 `--tags fixtures,t3,hbactest` |
| 移除 roster 裡使用者的 `groups:` 項目後，`id <user>@<domain>` 查詢一時看不出變化 | 那是 client SSSD 身分快取，不是權限撤銷失敗；本演練驗證的是 **sudo**（無 allow_all 後備）而非整體身分解析 | 用 sudo 結果判斷撤銷是否生效，或先清 client SSSD 快取再查身分 |

更完整的技術細節見 memory `freeipa-hbac-sudo-cli-gotchas`。

---

## 6. 驗證套用結果

```bash
# 在 server 上（或透過 vm-target exec）
kinit admin
ipa user-find --all | grep -E 'User login|Member of groups'
ipa sudorule-show sysops-systemctl --all   # --all 才會列出 Command/Host/RunAs category
# 確認金鑰已寫進帳號（SSH public key: / fingerprint 應列出）
ipa user-show alice --all | grep -iE 'sshpub|fingerprint'
kdestroy
```

在**已 enroll 的 client** 上，確認 SSSD 真的吐得出金鑰（sshd 就是靠這支）：

```bash
sss_ssh_authorizedkeys alice     # 應印出 alice 的公鑰行
ssh alice@<enrolled-host>        # 無需該主機上有 authorized_keys 即可登入
```

**手動在 server 上下 `ipa` 指令一定要先 `kinit admin`**——任何 `ipa` CLI 呼叫都需要一個
有權限的 Kerberos ticket；沒有 ticket 會報 `did not receive Kerberos credentials`，
有 ticket 但權限不夠（例如剛好還留著一般使用者的 ticket）會報
`Insufficient access: Insufficient 'add' privilege ...`——這是 FreeIPA RBAC 本身的
正常行為，不是 playbook 的 bug（apply playbook 自己開頭就有一個 `Kinit admin` task，
同一次 play 內所有後續 `ipa` 指令都用這個 ticket，不受影響）。

**改完 sudo rule 的屬性（host/cmd/runas category、attach 的 host/command/使用者）後，
已經 enroll 過的 client 不會馬上反映**——SSSD 的 sudo provider 有自己的快取
TTL，即使 server 端 LDAP 已經是新值，client 上跑 `sudo` 可能還是照舊規則判斷，
在快取過期前一直看到（錯誤的）結果。要立刻驗證，在該 client 上執行：

```bash
sss_cache -E && systemctl restart sssd    # 強制清快取、重新從 server 拉 sudo 規則
```

---

## 7. Stage gating

跟 `freeipa-server-apply.yml` 同一套：

| stage | 條件 |
|-------|------|
| `sandbox`（預設） | 直接跑 |
| `staging` | `-e confirm_staging=true` |
| `prod` | `-e confirm_prod=true` 且 `staging_attested_within_hours<=168` |

---

## 8. 安全備註

- 名冊與 `ipa_admin_password` 全程只存在 `~/.vault/`（repo 外）且加密；`kinit` /
  `ipa passwd` 相關 task 都 `no_log: true`，不會出現在 ansible 輸出。
- 名冊改動要留版本歷史／多人審查時，可再開一個**獨立 private repo** 存加密名冊
  （密碼欄仍用 `ansible-vault`），本 repo 保持乾淨。
- 密碼想完全不落檔，可改用 IPA 的 OTP / 首次登入強制改密：名冊裡省略 `password:`，
  帶外發 enrollment token。

---

## 9. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-02 | v1.0 | 初版：roster 驅動的 users/groups/sudo/SSH 金鑰管理，`ipa_hostgroups`/`ipa_hbac_rules`/host-scoped `ipa_sudo_rules` 擴充（§5.2） | sre |
| 2026-07-17 | v1.1 | 文件整併：`freeipa-hostauthz-test-plan.md` 併入 §5.3（該檔已歸檔）。用整併驗證環境重新實跑 T1–T7 全部步驟，新增 reconciler 撤銷語意驗證（roster 移除 `hz_web` 的 group membership，重新 apply 後 live sudo 權限真的被撤銷，恢復後再確認可逆）。重測中發現並修好 `freeipa-hostauthz-demo.yml` T3 assert 寫死 FQDN 字串、沒有走 `webhost_fqdn`/`dbhost_fqdn` 變數的真事故 | sre |
