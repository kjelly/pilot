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

## 0.5 目前有效的事實快照

- 最新驗證（2026-10-27，PR #138 review 修正）：candidate `2c35804fe552188f881496abe8ca4aeca1816f89`，
  tree `eba8be23b181597da990e1517c35d28c525a464e`；在乾淨、隔離 checkout 執行。
- 實際目標為三台拋棄式 AlmaLinux 9.8／FreeIPA 4.13.4 VM：`freeipa-server` group
  一台 provider，`freeipa-client` group 兩台已 enroll clients（`ansible-inventory --graph`
  讀回）。identity apply 走 playbook 預設的 `freeipa-server` group，target 是 provider。
- 外部輸入：vault 檔已確認有 `ipa_admin_password` key；測試名冊為 schema-v2 canonical
  roster（`schema_version`、`freeipa`、`users`、`groups`），管理密碼以 template 引用 vault。
  只記 key，不顯示密碼、名冊或私鑰內容。
- 非 key 授權快取：`--tags users`、`--tags C9`（含 IPA 已變更後 SIGKILL）、
  `--skip-tags client-cache` 與 `ipa_identity_refresh_sssd_cache=false` 的變更都留下待更新，
  兩台 client 實際仍回傳舊快取；之後相同名冊的完整 apply 或 `--tags client-cache`
  在 IPA 已無變更時仍更新兩台 clients，無變更 apply 不操作 clients（16/16 步驟）。
  Live SSH 新增／撤銷（撤銷後 0.19 秒兩台皆拒絕）、相同名冊零操作，以及 deferred 配對
  PARTIAL→重試皆通過。最後 topology test：syntax、dry-run、三機 snapshot、apply、
  identity verify **24/24 PASS（fail=0 skip=0）** 與冪等，apply／reapply 皆 `changed=0 failed=0`。
- 未在此 candidate 重跑的 SSH 失敗個案（timeout、unreachable、crash、ABA、historical scope）
  見 [e42f50c 紀錄](../evidence/freeipa-identity-ssh-cache/2026-10-22-e42f50c-live.md)。
  驗收後本次三台 disposable VM 已清理，非現存部署 inventory。Image digest、執行輸入
  hashes、真實失敗與恢復見
  [目前有效 evidence](../evidence/freeipa-identity-ssh-cache/2026-10-27-2c35804-live.md)。

已部署 FreeIPA 的日常 roster 調和入口是 **`pilot reconcile`**，不是全站 `pilot
deploy`：兩者同樣會先做 preflight、stage gate、preview 與人工確認，但前者只顯示
contract-backed 的 day-2 reconciler。其他設定型角色必須先具備自己的 contract、
apply playbook、schema 與 verification evidence，才可加入這個入口。

---

## 1. 檔案分工

| 檔案 | 進 git？ | 內容 |
|------|:---:|------|
| `playbooks/apply/freeipa-identity-apply.yml` | ✅ | Generic reconciler；canonical users/groups + legacy `ipa_*` authorization compatibility，**本身不含任何真名字** |
| `playbooks/apply/freeipa-identity.roster.example.yaml` | ✅ | 只有 schema、無真資料，文件化名冊格式 |
| `~/.vault/ipa-identity.yaml` | ❌ | 你的 canonical **真實名冊 + `freeipa.admin.password`**，`ansible-vault` 加密，永不進 repo |
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

Canonical schema（完整範例見 `freeipa-identity.roster.example.yaml`）：

```yaml
schema_version: 2
freeipa:
  server: ipa1.ipa.pilot.internal
  admin:
    principal: admin
    password: "..."               # vault secret

users:
  - name: alice
    state: present
    first: Alice
    last: Wang
    enabled: true
    ssh_keys:
      authoritative: true
      values: ["ssh-ed25519 AAAA... alice@laptop"]

groups:
  - name: team-developers
    state: present
    category: team
    type: posix
    membership:
      authoritative: true
      users: [alice]
      groups: []

hosts: []
hostgroups: []    # membership.hostgroups (nested) is authoritative too
hbac: {}
sudo: {}
netgroups: []     # optional, v2-only — see freeipa-identity.roster.example.yaml
```

新的 roster 直接寫 `schema_version: 2`；既有的 `schema_version: 1` roster
不需要手動改版本號——`pilot edit`/MCP roster driver/`pilot deploy`/`pilot
reconcile` 的 preflight 一開啟 roster 就會自動呼叫 `EnsureRosterCurrent`
升級（已驗證、有備份、atomic），或用 `pilot roster migrate <file>`
（加密 roster 補 `--vault-password-file <path>`）手動觸發。

`freeipa_domain` 唯一設定於 inventory 的 `group_vars/freeipa.yml`；roster
只保存 FreeIPA 身分、群組與授權規則（新 v2 roster 不要再寫
`freeipa.domain`/`freeipa.realm`——那兩個欄位只為了相容舊 v1 roster 保留）。
`realm` 由 domain 大寫推導，server FQDN 由 inventory/target facts 或 roster
的驗證欄位提供。

> Canonical roster 不可用 `-e @~/.vault/ipa-identity.yaml` 直接注入：top-level
> `groups`/`hosts` 是 Ansible magic variables。必須用下方的
> `-e freeipa_roster_file=/absolute/path`，讓 playbook namespaced 載入。

相容期 legacy schema 仍可使用（HBAC/sudo 目前也仍走這個模型）：

```yaml
ipa_admin_password: "..."          # REQUIRED：kinit admin 用

ipa_groups:
  - { name: developers, desc: "Application developers" }

ipa_users:
  - name: alice
    first: Alice
    last: Wang
    password: "initial-pw"          # 初始密碼；可省略（改用 OTP 帶外設定）
    force_password: true            # 預設 false；只有刻意重設已有的密碼才要加這行（新帳號不需要）
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
    -e freeipa_roster_file=/home/operator/.vault/ipa-identity.yaml \
    --vault-password-file ~/.vault/vault-pass \
    --check --diff
```

### 4.3 套用

透過 `pilot vm-target`（host 在 group `all`，非 `freeipa-server`）：

```bash
pilot vm-target run --name alma-vm \
    playbooks/apply/freeipa-identity-apply.yml \
    -e target_group=all \
    -e freeipa_roster_file=/home/operator/.vault/ipa-identity.yaml \
    --vault-password-file ~/.vault/vault-pass
```

或直接對真 inventory 跑：

```bash
ansible-playbook -i inventory-freeipa.yaml \
    playbooks/apply/freeipa-identity-apply.yml \
    -e freeipa_roster_file=/home/operator/.vault/ipa-identity.yaml \
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

非金鑰的授權變更（使用者資料、群組、HBAC、sudo…）要等 client 的 SSSD 快取更新才生效。
只有選到 `identity` 或 `client-cache` 的 run（含不帶 tags 的完整 apply）會對 enrolled
clients 執行 `sss_cache -E`。其他 tags（例如 `--tags sudo`、`--tags C9`）或
`--skip-tags client-cache` 仍會先在 provider 的 journal 記下「待更新」，不會連到 clients，
並印出 `Report deferred authorization cache refresh` 提示；下一次選到 `identity`/
`client-cache` 的 apply 即使 IPA 已無變更也會更新全部 clients。`-e
ipa_identity_refresh_sssd_cache=false` 時同樣只記錄、不更新，改回 `true` 後的下一次 apply
會補做。要立即生效（`client-cache` 也選到 SSH 金鑰 tasks，會一併以名冊調和金鑰並驗證
各主機快取，因此仍要帶同一份名冊）：

```bash
... playbooks/apply/freeipa-identity-apply.yml --tags client-cache ...
```

### 4.5 更換 FreeIPA admin 密碼

admin 密碼存在兩個地方，兩份必須相同：

- vault vars 檔（例如 `.vault/main.yaml`）的 `ipa_admin_password`：`pilot deploy`、`pilot reconcile` 載入它。
- 名冊的 `freeipa.admin.password`：`pilot access …`、`pilot identity drift`、`pilot roster remove-*`
  只載入名冊，用它登入 FreeIPA；`freeipa-nfs-server-apply.yml` 的 gate 會檢查它等於 `ipa_admin_password`。

在 FreeIPA 改完密碼後，用 `pilot edit` → `.vault/` → `main.yaml` → `ipa_admin_password` → 修改值 → 存檔。
存檔時，名冊裡仍是舊密碼的 `freeipa.admin.password` 會一併改成新密碼，畫面會列出每份名冊的結果。
只會自動改這個 workspace `.vault/` 目錄裡（不含子目錄）的 `*.yml`、`*.yaml` 名冊：預設的
`.vault/ipa-identity.yaml`，以及 `hosts.yml`、`group_vars/`、`host_vars/`（含子目錄裡的檔案）的
`freeipa_roster_file` 指到這裡的名冊；`pilot_edit_plan` 看到的名冊跟 apply 相同。名冊若是 symlink，
改的是它指向的檔案，link 本身保留。

下列名冊不會自動改，畫面會列為「未同步」；用 MCP 的 `pilot_edit_plan`／`pilot_edit_apply` 時，
同樣的內容會出現在結果的 warnings（只列路徑，不含密碼）：

- `.vault/` 以外或 `.vault/` 子目錄裡的名冊（例如 `~/.vault/ipa-identity.yaml`）；
- ansible-vault 加密的名冊或 `!vault` 加密值；
- 原本就跟舊密碼不同的名冊；
- 密碼沒加引號、而 YAML 可能把它讀成數字、日期或布林值的名冊（例如 `12345678`、`012345678`、
  `1e10`、`190:20:30`、`2024-01-01`、`yes`）：YAML 1.1（Ansible 載入 vars 檔所用）與 YAML 1.2 對這些值
  的判斷不一致，比對時可能不等於 vault 的字串。請把名冊與 vault 兩邊都寫成加上引號的值。`pilot edit`
  存進 vault 的新值一律是加引號的字串；vault 原本的值沒加引號時，pilot 無法判斷哪些名冊用的是它，同樣不會同步，
  畫面會提示逐一確認；
- 密碼經 YAML alias／merge key 取得，或寫成 flow mapping、多行 scalar（包括跨到下一行的加引號字串）的名冊；
- 新密碼含 `{{`、`{%`、`{#`：Ansible 會當成模板展開，pilot 無法得知實際密碼，所有名冊都不會改。
  vault 的值標成 `!unsafe` 時 Ansible 不展開它，pilot 會照常同步，名冊寫成 `!unsafe` 加引號的字串；
- 原本或新的 `ipa_admin_password` 是 `!vault` 加密值，或原本的值含 `{{`、`{%`、`{#`：pilot 不知道舊密碼，
  無法判斷哪些名冊用的是它，所有名冊都不會改，畫面會提示逐一確認。

**要跟著改的名冊正被另一個 `pilot` 名冊操作（`pilot roster remove-*`、schema 升級等）鎖住、lock 檔（名冊旁的
`*.pilot-migrate.lock`、`*.pilot-remove.lock`）不能用（這個使用者打不開或建不出來、是目錄或其他非一般檔案，
或因唯讀檔案系統、磁碟已滿、讀寫錯誤、不支援 flock 等原因開不了或鎖不了），或名冊本身這個使用者不能寫（例如
`0400`，root 除外）、不是一般檔案時，這次存檔會被拒絕**：vault 與名冊都不寫入，因為先存 vault 會讓名冊留在舊密碼，
而之後再存也不會補同步。pilot 會先鎖住每一份要跟著改的名冊並確認寫得進去，全部沒問題才寫 vault，再寫名冊。
在終端機會顯示「未存檔 …（修改還在）」與是哪一份名冊，畫面留在 vault 編輯器、修改沒有遺失，等那個操作結束
（或修好 lock 檔、名冊的權限）後再存一次即可。自動化時那一步會失敗，見下面的說明。只有上面清單裡的名冊
（加密、讀不懂、密碼形式 pilot 改不了、原本就不同）會列為「未同步」而讓存檔照常進行；要跟著改的名冊因為其他
任何原因寫不進去，存檔都會被拒絕。寫名冊時才發生的錯誤（例如磁碟已滿）無法事先知道：那時 vault 已經存好，
那份名冊會列為「未同步」。

**pilot edit 只在 `ipa_admin_password` 改變的那次存檔同步名冊。** 之後再存一次 vault 不會補同步，
所以名冊一旦跟 vault 不一致（上面列出的名冊、在 pilot edit 以外改了 vault，或加密的 `.vault/main.yaml`），
修正方式只有手動改名冊：把它的 `freeipa.admin.password` 改成 vault 的 `ipa_admin_password`
（明文名冊直接編輯該行；加密名冊用 `ansible-vault edit <名冊>`）。

只有 `.vault/main.yaml`（deploy 預設載入的 vault）會觸發同步；改其他 vault 檔的 `ipa_admin_password` 時只會提示。
`.vault/main.yaml` 本身是 ansible-vault 加密檔時，pilot 讀不到密碼：不會同步，preflight 也不會警告，名冊要自己更新。

lock 檔只由能寫這份名冊的使用者建立：不能寫名冊的使用者在建立 lock 檔之前就被拒絕，不會留下擋住別人的
lock 檔。pilot 建立的 lock 檔（只記錄 pid）讓所有能寫名冊的人都能開啟：名冊的 group 能讀或寫時 group 可讀，
other 能讀或寫、名冊帶 ACL，或 lock 檔擁有者不是名冊擁有者時 other 可讀（名冊還不存在時，看誰能在目錄裡建立
它）；只有擁有者能寫的名冊，lock 檔維持 `0600`。這個使用者擁有的既有 lock 檔若少了這些讀取權限（例如舊版 pilot 留下的 `0600`），會在下次取鎖時補上。
名冊旁的 lock 檔若是舊版 pilot 以 root（例如在 docker 裡）或其他使用者留下、這個使用者打不開，任何會寫名冊的
操作都會停下並說明是哪個 lock 檔：確認沒有 pilot 正在執行後，刪掉它或把它改回這個使用者擁有。
名冊被另一個 pilot 操作鎖住時，會先等最多約 0.25 秒再回報（plan 檢查真實名冊時只會短暫碰一下 lock 檔，
這段等待讓它不會害正在寫名冊的操作失敗）。
在終端機操作 `pilot edit` 時，遇到這種名冊、被鎖住的名冊或不能寫的名冊只顯示提示，不會結束編輯，稍後可以再試。
自動化時寫不進名冊的那一步會失敗，錯誤訊息列出名冊路徑與原因（被鎖住、lock 檔不能用或名冊不能寫，不含密碼），
不會回報成功；之後的處理依入口而不同：

- `pilot edit --actions`：停在失敗的那一步，之後的步驟不執行；**之前的步驟已寫入的內容保留，不會 rollback**。
- MCP `pilot_edit_apply`：整個 apply rollback，回傳錯誤而不是 `applied`。
- MCP `pilot_edit_plan`：plan 失敗。plan 在暫存複本上執行；存 vault 時會另外檢查要跟著改的真實名冊（鎖、
  能不能寫），所以這種 apply 會被拒絕的情況 plan 也會失敗。其他名冊寫入（例如新增使用者）plan 不檢查真實名冊，
  apply 時才會發現被鎖住或不能寫，並 rollback。

lock 檔是 symlink、FIFO 或另有其他名字（hard link）時一律拒絕使用。名冊本身有其他 hard link 時（例如備份工具留下的），
pilot 在 lock 檔之外再鎖名冊的 inode，所以經任何一個名稱寫入的 pilot 彼此互斥，檢查（plan 的探測）也一樣；
只有一個名稱的名冊不需要這把鎖。取鎖之後才多出 hard link 的名冊，這次寫入會被拒絕，請重試。

存檔留下的「未同步」名冊，`--actions` 會在 stderr 印成 `warning: …`（成功或之後某一步失敗都會印，因為
那次存檔已經保留下來）；`pilot_edit_plan`／`pilot_edit_apply` 放在結果的 warnings。都只列路徑，不含密碼。

MCP 的 `pilot_edit_plan`／`pilot_edit_apply` 只會寫這個 workspace `.vault/` 目錄裡的名冊（從其他地方以 symlink
指進 `.vault/` 的也算）：plan 無法預覽、apply 的 rollback 也無法還原 `.vault/` 以外的檔案。`freeipa_roster_file`
不論寫成絕對或相對路徑，plan 都照 apply 的方式解讀（相對於真實 workspace）。`freeipa_roster_file` 指到 `.vault/`
以外時，pilot 先在
暫存複本上試做那一步：真的要改名冊（例如啟用 freeipa-nfs-server 時補上還沒有的 `nfs.servers`、建立名冊）
就失敗並列出路徑，請改在終端機用 `pilot edit` 或手動修改；名冊已經是要的樣子（例如 `nfs.servers` 已有這台
主機）就照常通過，那份名冊只會被讀取，旁邊也不會留下 lock 檔。終端機與 `--actions` 不受這個限制。
plan 的暫存複本保留 `.vault/` 檔案之間的別名結構：指向同一個檔案的名稱（symlink、symlink 鏈、指向 workspace 外的
同一個檔案，或 hard link）在複本裡也是同一個檔案，寫其中一個名稱，plan 與 apply 列出的 `AffectedFiles`、diff 與
warnings 都包含它的所有名稱；複本裡的別名是指向複本內檔案的相對 symlink，不會指向複本以外，plan 仍然不會寫到任何真實檔案。
plan 的錯誤訊息、warnings 與檢查結果列的都是真實 workspace 的路徑，跟 apply 一樣，不會出現 plan 的暫存複本路徑。`hosts.yml` 記錄的 `freeipa_roster_file` 是
絕對路徑，plan 的 diff 顯示的也是真實 workspace 的路徑。

`pilot_edit_apply` 的某一步失敗而 rollback 時，名冊只還原「這次 apply 自己的寫入」蓋掉的內容。apply 開始前，
pilot 開始記錄這個 workspace `.vault/` 名冊（含 `.vault/` 裡 symlink 指到的檔案）的每一次寫入：在寫名冊的地方、
持有名冊鎖時記下寫入前與寫入後的內容。rollback 依這份紀錄逐一處理每份名冊（同一個檔案有兩個以上名字，例如
`.vault/` 裡的 symlink 或 hard link，只處理一次）。

哪些 `.vault/` 檔案算「名冊」，只看 apply **開始前**的狀態與這份紀錄，不看 apply 之後檔案裡有什麼內容（vault 編輯
可以讓任何檔案長得像名冊）：apply 開始前就存在，而且是 ansible-vault 加密檔、或名冊專屬的頂層 key（`schema_version`、
`freeipa`、`users`、`groups`、`hbac`、`sudo`、`nfs`）的值是 mapping 或 list（vault 編輯只寫 scalar，所以一般的 vault
檔不會這樣）、或是這個 workspace 指定的名冊（預設的 `.vault/ipa-identity.yaml` 與每個 `freeipa_roster_file`
指到的檔案，內容可以只有 scalar）；或者這次 apply 的紀錄裡有對它的寫入（這次建立的名冊也在內）。其他 `.vault/`
檔案（例如 `main.yaml`，即使這次 apply 加了 `groups` 之類的 key）不是名冊，一律還原成 apply 前的內容；這次建立、
紀錄裡沒有寫入的 `.vault/` 檔案直接移除。加密的非名冊檔（例如 `keycloak.yaml`）照名冊的方式處理，因為這次 apply
不會寫它：它在某一步執行期間被其他操作改過就保留給人工檢查。

名冊依下列規則處理：

- 已經是 apply 前的內容：不動。
- 這次沒寫過，而且不是在某一步執行期間被改的（在第一步之前、兩步之間或最後一步之後被其他 `pilot` 操作改過）：保留那個
  修改，不算 rollback 失敗。
- 這次寫過：還原成這次第一次寫入前的內容（這次建立的名冊則刪除），而且只在名冊仍是這次最後一次寫入的內容、
  沒被鎖住時才還原。其他操作在這次寫入**之前**存的修改（例如在 `save_vault` 之前，或同一步裡在同步寫入名冊
  之前）因此會保留。

保留了其他操作修改的名冊會列在結果的 warnings：MCP 回傳的錯誤訊息（`rollback kept: …`）與 audit 目錄的
`validation.json`，只列路徑，不含密碼。下列情況 pilot 不動那份名冊，改為回傳錯誤，逐一列出路徑與原因（不含密碼）：

- 這次寫過之後又被其他操作改過或刪掉，或正被鎖住、lock 檔不能用；
- 其他操作在這次的兩次寫入之間改過它：還原會連那個修改一起蓋掉；
- 這次的寫入是原地覆寫，而且中途失敗：名冊的內容不明；
- 它在某一步執行期間被改過，但這次沒有任何寫入紀錄：pilot 無法分辨是誰改的，所以不還原。

這些檔案可能同時有這次 apply 與其他操作的修改，請手動檢查；其中是明文名冊的，也要確認它的
`freeipa.admin.password` 跟 vault 的 `ipa_admin_password` 相同（加密檔沒有這項提示）；其他檔案照常 rollback。
上面定義之外的 `.vault/` 檔案（例如 `main.yaml`）與其他 managed files 照舊一律還原成 apply 前的內容。

同一個 `pilot mcp` process 裡兩個 apply 的名冊重疊時（例如一個 workspace 的 `.vault/` 名冊是 symlink，指到另一個
workspace 正在 apply 的名冊，或兩個 workspace 的名冊是同一個檔案的 hard link），後來的 apply 在寫入任何東西之前
就被拒絕，MCP 回傳 `workspace_locked`，等前一個結束後再試。這段保護涵蓋整個 apply，包括失敗時的 rollback：
rollback 開始時 pilot 只是停止記錄寫入（rollback 自己的還原寫入不算這次 apply 的），名冊仍保留給這次 apply，
rollback 做完才放掉，所以另一個 apply 不會在這段期間登記進來、把還原寫入當成自己的。

pilot 寫名冊的方式：

- 通常在名冊所在目錄建一個暫存檔（`.<名冊檔名>.pilot-tmp-*`），先設成名冊原本的擁有者與權限、確認它的延伸屬性
  （POSIX ACL、SELinux label、`user.*` 等）跟名冊相同，才寫入內容並換名取代名冊，其他程式不會讀到寫到一半的檔案。
- 名冊另有 hard link、帶 POSIX ACL、這個使用者不能在目錄裡建立暫存檔、暫存檔無法設成原本的擁有者（例如
  非 root 使用者寫別人的名冊），或暫存檔的延伸屬性跟名冊不同（例如目錄有 default ACL，新檔案會繼承它而讓更多人
  讀得到名冊；或名冊帶有新檔案沒有的 SELinux label、`user.*` 屬性）時，改為直接覆寫原檔：inode、權限、擁有者、
  hard link、ACL 與其他延伸屬性都不變，但沒有取鎖的讀者可能短暫讀到寫到一半的內容。換名本身因為名冊位置而被拒
  （`EBUSY`：名冊是單一檔案的 bind mount，例如 `docker run -v <名冊>:<名冊>`；`EXDEV`；`EPERM`／`EACCES`：例如別人
  擁有的 sticky 目錄）時也改為直接覆寫。直接覆寫會讓名冊變大時，先預留空間，磁碟或配額已滿會在改動任何內容前
  失敗、名冊保持原樣；寫入中途失敗時錯誤會說明名冊可能只寫了一部分，請手動檢查。暫存檔因為其他原因（磁碟或配額
  已滿、檔案描述子用完）建不出來或寫不進去，或換名因其他原因失敗時，寫入失敗、名冊保持原樣，不會改為直接覆寫。
- 這個使用者沒有寫入權的名冊（例如 `0400`）或不是一般檔案的名冊拒絕寫入（root 可以寫 `0400`）。
  schema 自動升級也一樣：在建立備份之前就拒絕，不留下備份檔；`pilot deploy`、`pilot reconcile` 印出
  warning 後繼續，要升級請先讓這個使用者可以寫名冊（或用 root 執行）。
- 寫入失敗時名冊保持原樣，只有直接覆寫原檔寫到一半時例外，錯誤訊息會說名冊可能只寫了一部分；
  schema 升級遇到這種情況會改回原本的內容（備份檔照樣保留）。
- 新建立的名冊權限是 `0600`；以 root 執行（例如 `docker run` 裡的 pilot-cli）時，擁有者跟所在目錄相同，
  schema 升級的備份檔則給名冊的擁有者。
- pilot 被中斷而留下的暫存檔，會在下一次有 pilot 取得這份名冊的鎖時清掉（只清超過兩分鐘的）。
- 含密碼的暫存副本——plan 的暫存複本（含 `.vault/` 檔案）、試做外部名冊時的副本、加密名冊（`pilot roster remove-*`
  等）解密後的明文——都放在系統暫存目錄下一個只有這個使用者能進入（權限 `0700`）的新目錄裡（`pilot-edit-plan-*`、
  `pilot-roster-scope-*`、`pilot-roster-decrypt-*`），用完連同 lock 檔整個刪掉；pilot 被中斷而留下時，下一次建立
  同類目錄時清掉（只清這個使用者、已經結束的 pilot 留下的）。

已知限制：

- rollback 的寫入紀錄記的是 pilot 這個 process 寫名冊的動作，不是哪個操作寫的：同一個 `pilot mcp` process 裡
  另一個工具在 apply 期間寫了同一份名冊，會被當成這次 apply 的寫入。
- 有 hard link 的名冊一律直接覆寫原檔（上面第二點），改的是同一個檔案：它的其他名稱（例如備份工具留下的 hard
  link）也會看到新內容，pilot 無法只改其中一個名稱。
- 名冊以單一檔案 bind mount 進容器時，容器裡的 pilot 把 lock 檔建在容器裡那個目錄，主機上的 pilot 建在主機的
  目錄，兩者不會互相排斥。不要讓容器內外的 pilot 同時寫同一份名冊（或改為 mount 整個 `.vault/` 目錄）。

不要把名冊的密碼改成 `"{{ ipa_admin_password }}"`：上面那些只載入名冊的指令會因變數未定義而失敗。
明文 vault 與名冊不一致時，`pilot deploy`、`pilot reconcile` 開始前會印出 warning；vault 的
`ipa_admin_password` 含 `{{`、`{%`、`{#` 或是 `!vault` 加密值時，warning 改為列出無法比對的名冊；vault 或名冊的密碼
沒加引號、YAML 可能把它讀成數字、日期或布林值時，warning 會說明要加引號。這個 preflight 一律拿名冊跟 inventory
旁的 `.vault/main.yaml` 比對：它在詢問這次要用哪個 vault 檔之前執行，所以這次改用別的 vault 檔時，它比對的不是那份檔案。
freeipa-nfs-server 的 gate 也會擋下，並指出是哪一份名冊。三者都不會顯示密碼，修正方式都是上面的手動修改；
例外是 Ansible 無法展開的值：vault 的 `ipa_admin_password` 或名冊的密碼含不成對的 Jinja 符號（例如
`Vault{{Secret9`）時，gate 展開它就失敗，ansible-core 2.19 會在錯誤的 Origin 段落印出那個檔案的那一行，密碼也在其中，
`no_log` 也擋不住（它只隱藏 task 的結果）。pilot edit 不會同步含 `{{`、`{%`、`{#` 的 vault 值，preflight 也會警告。

最新實機驗證（2026-10-28，candidate `3b4bdb1`，兩台全新 VM）：site chain 通過，gate 的通過、
失敗與手動修正後的復原都已驗證；`pilot edit --actions` 輪替成功，名冊被持有時拒絕存檔。見
[實跑紀錄](../evidence/freeipa-nfs-server/2026-10-28-3b4bdb1.md)。這份結果只對 candidate `3b4bdb1` 成立：
之後併入的修正（apply rollback 的寫入紀錄、lock 檔權限、換名被拒時的原地覆寫等）沒有在實機上重跑過。

---

## 5. 冪等性

每個 task 都把「already exists / already a member」當 no-op（`changed_when` /
`failed_when` 對齊 `freeipa-server-apply.yml`）。重跑同一份名冊 → `PLAY RECAP`
的 `changed=0`。

例外：密碼沒有可 diff 的 read-back，且 `ipa passwd` 是 admin reset，不管密碼值
有沒有變都會把帳號重新標成「下次登入強制改密碼」。所以 apply 只在下列情況執行
`ipa passwd`（並因此 `changed`）：

- 帳號在 FreeIPA 還沒有密碼（沒有 Kerberos key）：用 `password:` 初始化，不看
  `force_password`。
- `force_password: true`（canonical roster 是 `password.preserve_existing:
  false`）：要求重設已有的密碼。使用者還在用上次重設的密碼時不會重複重設；使用
  者自己改過之後，下一次 apply 會再重設一次，所以重設完成後把這行拿掉（或設
  `false`）。

判斷依據是 `ipa user-show --all --raw` 的 `krbLastPwdChange` 與
`krbPasswordExpiration`。查不到某個使用者的狀態時，apply 直接失敗，不會把它
當成「還沒有密碼」而重設。`ipa passwd` 本身失敗時，apply 也會失敗，並列出使用者
與 `ipa: ERROR:` 訊息（不含密碼）；其他使用者的密碼仍會先處理完。（2026-10-15 之前，`force_password: true` 的使用者每
次 apply 都會被重設，即使已經自己改過密碼；還沒完成首次改密碼的使用者也每次
都會被重設。）

2026-10-16 起，apply 不再發出已知是 no-op 的呼叫：
- 先用 `ipa user-find --pkey-only` 讀出全部使用者與停用的使用者。已存在的不再 `user-add`；已是名冊狀態的不再 `user-enable`／`user-disable`。
- 先用 `ipa group-find --pkey-only` 讀出全部群組，已存在的不再 `group-add`。
- 成員查詢已列出的直接成員不再 `group-add-member`。

成員比較不分大小寫：名冊寫 `team-Child`，FreeIPA 存成 `team-child`，兩者視為同一個成員，不會被撤銷再加回。sudo 指令路徑例外：FreeIPA 保留它的大小寫、也只認原本的寫法，所以名冊與 FreeIPA 的寫法要一致。

讀不完整時，apply 會在該清單所保護的使用者或群組變更前失敗：查詢被截斷，或
`Gate: the user listings were parsed completely`／`Gate: the group listing was parsed completely`
讀不懂輸出。後者通常是 `ipa` 輸出被翻成其他語言：ssh session 的 `LANG` 來自 server
的系統語系（`/etc/locale.conf`），不是英文且裝了該語言時，`ipa` 就印那個語言。這支
playbook 只認英文輸出。

120 位使用者、40 個群組的穩態重跑從 1,189 次 API 呼叫降到 642 次；交錯實測 base
為 812.0 秒，candidate 兩輪為 524.3／554.7 秒。混合大小寫的 nested-group 關係不再
被移除或重加；首次可能新增該 roster 寫法的 group-history marker，第二輪 `changed=0`。
見 candidate `d874c3f` 的[實跑摘要](../evidence/freeipa-identity/2026-10-19-d874c3f.md)。

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
  - **撤銷金鑰 → 從 list 拿掉再套用**（不是留著不管）。撤銷最後一把時寫成空 list
    （`ssh_keys: []`；canonical roster 是 `ssh_keys: {authoritative: true, values: []}`），
    playbook 會送 `--sshpubkey=` 清空。2026-10-15 之前空 list 不會清除任何金鑰
    （issue #113）。整個省略 `ssh_keys` 則表示不管理該帳號的金鑰，既有金鑰保持不變。
  - **主機端的生效時間（#114 已通過多主機 VM 驗收，2026-10-22）**：apply 在變更前
    將待辦寫入 provider 的 `/var/lib/pilot-identity/ssh-cache.json`，針對 inventory
    的 enrolled client/server/replica 與 provider 本身逐使用者失效快取，再比對
    SSSD 回傳的完整 key set。每個配對最多 45 秒；N 個待辦循序執行，不能承諾
    整個 fleet 固定 60 秒內完成。成功 apply 才表示全部 scope 已收斂；SSH 登入
    驗收要求完成後 10 秒內新連線拒絕舊 key。既有 session 不會被終止。
    失敗、離線或 deferred 主機保留待辦，apply 非零回報 PARTIAL；重跑同一份 roster
    僅重試待辦。首次採用會驗證所有 managed 配對，並對 enrolled clients 做一次非金鑰
    授權快取更新（journal 還沒有紀錄可證明先前的 run 已更新全部 clients）；完成後
    無變更 apply 不操作 clients。
    勿刪除 journal，也勿平行對同一 provider 執行 identity apply。完整邊界與驗收矩陣見
    [已驗收契約](../superpowers/specs/2026-10-22-ssh-key-cache-convergence.md) 與
    [目前有效 evidence](../evidence/freeipa-identity-ssh-cache/2026-10-27-2c35804-live.md)。
    `ipa_identity_refresh_sssd_cache` 僅控制既有非金鑰授權更新；SSH 流程不受它停用。
    原 #115 實測的約 60 秒至超過 16 分鐘延遲仍是歷史基線，不能當作本次修正的驗收證據。
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

- Canonical roster 的 `groups`/`hosts` 會撞 Ansible magic variables；必須用
  `freeipa_roster_file` namespaced loader。症狀是 validation loop 收到 inventory dict
  而非 roster list；根因不是 roster YAML 型別錯誤。
- vm-target inventory 若替同一台 VM 加了 role alias，`target_group=all` 會讓同一 play
  平行命中兩次。本次第一次 server bootstrap 因此出現 DNF cache race；正式 evidence
  改用精確 target name，避免重複 mutation。

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
| 2026-07-22 | v1.2 | Delivery batch 1：canonical v1 users/groups、legacy compatibility、12-row verification 與 immutable candidate evidence；新增 `freeipa_roster_file` namespaced 入口及 Ansible magic-variable/duplicate-alias gotcha | pilot |
| 2026-08-11 | v1.3 | Roster schema v2 交付：schema v1/v2 版本判定與自動升級（`pilot roster migrate`、`EnsureRosterCurrent`，含 ansible-vault 加密 roster 支援）、netgroups 首次成為 first-class 物件、hostgroup 巢狀 membership（`membership.hostgroups`）從完全未 reconcile 變成 authoritative、NFS export selector 新增 hostgroup/netgroup 型別（`@value` 渲染）。§0.5 快照更新、§3 canonical schema 範例改為 v2 並補上 netgroups/巢狀 hostgroup 說明。完整逐項證據、LDAP schema gotcha 見 `docs/verification/freeipa-identity.md` v1.6；`freeipa-identity.roster.example.yaml` 與 `.agents/skills/freeipa-roster-authoring/SKILL.md` 同步更新為 v2 | pilot |
| 2026-10-15 | v1.4 | §0.5 加上 `freeipa-identity.md` v1.12 的最新驗證（PR #89，candidate `decc613`）：ldapi row 以 root 執行、netgroup SOP 步驟 1 改走 ldapi | pilot |
| 2026-10-28 | v1.5 | 新增 §4.5 更換 FreeIPA admin 密碼（issue #146）：`pilot edit` 改 `.vault/main.yaml` 的 `ipa_admin_password` 時同步名冊、哪些名冊不會同步（含沒加引號、YAML 可能讀成數字／日期／布林值的密碼，打不開的 lock 檔）、名冊與 vault 不一致時只能手動修改名冊（再存一次不會補同步）、舊版 root 留下的 lock 檔如何處理、要跟著改的名冊被鎖住或不能寫時整次存檔拒絕、自動化遇到寫不進的名冊時該步失敗（MCP apply 會 rollback，`--actions` 停在那一步、保留之前的步驟，plan 失敗）、plan／MCP apply 只在真的要改 `.vault/` 以外的名冊時失敗、apply rollback 保留被其他操作改過的名冊、名冊的寫入方式；review 後修正：同一個名冊的多個 hard link 名稱共用 inode 鎖與同一個 journal 身分、plan 的暫存複本保留 `.vault/` 別名結構、rollback 以 apply 前的狀態與寫入紀錄判斷哪些檔案是名冊（一般 vault 檔一律還原）、rollback 期間保留對名冊的登記直到還原結束（這個樹尚未實跑，只有本機測試） | pilot |
