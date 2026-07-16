# Runbook — FreeIPA 使用者 / 權限管理（名冊與機密不進 git）

> 撰寫日期：2026-07-02 (UTC)
> 對齊規範：`playbooks/apply/freeipa-identity-apply.yml`、`playbooks/apply/freeipa-identity.roster.example.yaml`
> 維護者：sre

---

## 0. 一句話目標

> **Git 放邏輯，repo 外放資料。** 使用者、群組、sudo 權限的「怎麼做」寫在 git 裡一支
> generic playbook；「是誰、什麼密碼、給什麼權限」放在 repo 外、用 `ansible-vault`
> 加密的名冊檔。任何人 clone 這個 repo 都拿不到你的真實帳號與密碼。

跟 `freeipa-server-apply.yml` 是同一套慣例（gate、`no_log`、冪等、stage gating），也
沿用 repo 既有的 `~/.vault/` 機密模式（見 `freeipa-server-apply.yml` 的 `-e @~/.vault/…`）。

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
