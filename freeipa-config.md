# FreeIPA Identity、Linux POSIX Group 與 NFS 權限管理完整實作規格

## 1. 文件目的

本規格定義一套以 Ansible 與 FreeIPA 為核心的集中式 Linux 身分、主機存取、sudo 權限及 NFS 檔案共享管理系統。

實作完成後，系統必須能以單一 declarative roster 描述：

* FreeIPA 使用者
* FreeIPA POSIX 群組
* 團隊成員關係
* 資料存取權限
* Linux 主機登入權限
* sudo 管理權限
* FreeIPA host groups
* HBAC rules
* NFS 共享目錄
* POSIX ACL
* NFS exports
* Kerberos NFS service principal
* FreeIPA automount maps
* Linux client 自動掛載
* 舊群組及舊權限遷移

此系統不得依賴各 Linux 主機上的本機使用者或本機群組作為共享資料的主要授權來源。

---

# 2. 設計原則

## 2.1 單一身分來源

FreeIPA 是以下資料的唯一權威來源：

* 使用者名稱
* UID
* 群組名稱
* GID
* 使用者群組關係
* 主機身分
* Kerberos principal
* HBAC policy
* sudo policy
* automount policy

Linux client 必須透過 SSSD 查詢 FreeIPA。

不得在 client 或 NFS server 上手動建立與 FreeIPA 同名的本機使用者或群組。

---

## 2.2 權限職責分離

群組必須依職責分為四類：

| 類別   | 名稱前綴      | 用途                |
| ---- | --------- | ----------------- |
| 團隊群組 | `team-`   | 表示組織或人員歸屬         |
| 資料群組 | `data-`   | 控制 Linux/NFS 檔案存取 |
| 登入群組 | `access-` | 控制 HBAC 主機登入      |
| 角色群組 | `role-`   | 控制 sudo 或管理權限     |

範例：

```text
team-developers
data-project-alpha-rw
data-project-alpha-ro
access-webhosts-ssh
role-web-service-admin
```

禁止使用單一群組同時承擔資料權限、登入權限與 sudo 權限。

---

## 2.3 Declarative ownership

Roster 是期望狀態的完整描述。

對於 roster 管理的物件：

* 缺少的物件必須建立。
* 屬性不一致時必須更新。
* membership 必須收斂到 roster 宣告的狀態。
* ACL 必須收斂到 roster 宣告的狀態。
* automount 必須收斂到 roster 宣告的狀態。
* 未經 roster 管理的物件預設不得刪除。
* 刪除行為必須透過明確的 prune 或 state 設定啟用。

---

## 2.4 安全預設

系統預設必須使用：

```text
NFSv4
Kerberos
sec=krb5i
root_squash
sync
setgid directories
default POSIX ACL
FreeIPA HBAC
FreeIPA sudo rules
```

不得預設使用：

```text
sec=sys
no_root_squash
chmod 777
匿名可寫 export
以 IP 位址掛載 Kerberos NFS
```

---

# 3. 建議專案結構

```text
project/
├── playbooks/
│   ├── apply/
│   │   ├── freeipa-identity-apply.yml
│   │   ├── freeipa-storage-apply.yml
│   │   ├── freeipa-full-apply.yml
│   │   └── freeipa-migration-apply.yml
│   ├── validate/
│   │   └── freeipa-roster-validate.yml
│   └── verify/
│       ├── freeipa-identity-verify.yml
│       ├── freeipa-storage-verify.yml
│       └── freeipa-full-verify.yml
├── roles/
│   ├── freeipa_roster_validate/
│   ├── freeipa_users/
│   ├── freeipa_groups/
│   ├── freeipa_hosts/
│   ├── freeipa_hostgroups/
│   ├── freeipa_hbac/
│   ├── freeipa_sudo/
│   ├── freeipa_nfs_service/
│   ├── freeipa_automount/
│   ├── nfs_server/
│   ├── nfs_share/
│   ├── nfs_client/
│   ├── freeipa_migration/
│   └── freeipa_verify/
├── filter_plugins/
│   ├── roster_validation.py
│   ├── group_graph.py
│   └── acl_normalize.py
├── module_utils/
│   └── freeipa_common.py
├── tests/
│   ├── schema/
│   ├── molecule/
│   ├── integration/
│   └── fixtures/
├── schemas/
│   └── freeipa-roster.schema.json
└── examples/
    └── freeipa-roster.example.yaml
```

---

# 4. 執行入口

## 4.1 完整套用

```bash
ansible-playbook \
  playbooks/apply/freeipa-full-apply.yml \
  -e @~/.vault/ipa-identity.yaml \
  --vault-password-file ~/.vault/vault-pass
```

完整執行順序：

```text
1. 驗證 roster
2. 驗證 FreeIPA 連線與 Kerberos
3. 建立 users
4. 建立 groups
5. 套用 group membership
6. 建立 hosts 與 hostgroups
7. 建立 HBAC service 與 HBAC rules
8. 建立 sudo commands 與 sudo rules
9. 建立 NFS service principal
10. 設定 NFS server
11. 建立 NFS 目錄與 ACL
12. 建立 exports
13. 建立 FreeIPA automount maps
14. 設定 NFS clients
15. 執行驗證
16. 輸出變更摘要
```

---

## 4.2 Dry run

必須支援：

```bash
ansible-playbook \
  playbooks/apply/freeipa-full-apply.yml \
  --check \
  --diff \
  -e @~/.vault/ipa-identity.yaml
```

若底層 IPA module 無法完整支援 check mode，role 必須實作 query-and-compare 模式，不得在 check mode 寫入。

---

# 5. 完整 roster schema

```yaml
---
schema_version: 1

freeipa:
  domain: ipa.pilot.internal
  realm: IPA.PILOT.INTERNAL
  server: ipa1.ipa.pilot.internal

  admin:
    principal: admin
    password: "VAULT_SECRET"

  defaults:
    group_type: posix
    nfs_security: krb5i
    automount_location: default
    managed_group_membership: authoritative
    managed_acl_mode: authoritative
    prune_unmanaged: false

  safety:
    disable_allow_all_hbac: true
    require_breakglass_rule: true
    forbid_no_root_squash: true
    forbid_sec_sys: true
    forbid_world_writable: true
    forbid_ip_nfs_server: true
    require_posix_data_groups: true

users:
  - name: alice
    state: present
    first: Alice
    last: Wang
    display_name: Alice Wang
    email: alice@example.internal

    uid: null
    gid: null

    login_shell: /bin/bash
    home_directory: /home/alice

    password:
      initial: "VAULT_SECRET"
      force_change: true
      preserve_existing: false

    ssh_keys:
      authoritative: true
      values:
        - "ssh-ed25519 AAAA... alice@laptop"

    enabled: true

  - name: bob
    state: present
    first: Bob
    last: Lee
    login_shell: /bin/bash
    home_directory: /home/bob

    password:
      preserve_existing: true

    ssh_keys:
      authoritative: true
      values: []

    enabled: true

groups:
  - name: team-developers
    state: present
    category: team
    type: posix
    description: Application development team

    gid: null

    membership:
      authoritative: true
      users:
        - alice
        - bob
      groups: []

  - name: team-sysops
    state: present
    category: team
    type: posix
    description: Systems operations team

    membership:
      authoritative: true
      users:
        - carol
      groups: []

  - name: data-project-alpha-rw
    state: present
    category: filesystem
    type: posix
    description: Project Alpha read-write access

    membership:
      authoritative: true
      users: []
      groups:
        - team-developers

  - name: data-project-alpha-ro
    state: present
    category: filesystem
    type: posix
    description: Project Alpha read-only access

    membership:
      authoritative: true
      users:
        - carol
      groups: []

  - name: access-webhosts-ssh
    state: present
    category: access
    type: posix
    description: SSH access to web hosts

    membership:
      authoritative: true
      users: []
      groups:
        - team-developers
        - team-sysops

  - name: role-web-service-admin
    state: present
    category: role
    type: posix
    description: Web service administrators

    membership:
      authoritative: true
      users:
        - alice
      groups: []

hosts:
  - name: web1.ipa.pilot.internal
    state: present
    ip_address: 192.168.50.11
    description: Web server 1

  - name: web2.ipa.pilot.internal
    state: present
    ip_address: 192.168.50.12
    description: Web server 2

  - name: nfs1.ipa.pilot.internal
    state: present
    ip_address: 192.168.50.20
    description: Primary NFS server

hostgroups:
  - name: webhosts
    state: present
    description: Web tier
    membership:
      authoritative: true
      hosts:
        - web1.ipa.pilot.internal
        - web2.ipa.pilot.internal
      hostgroups: []

  - name: nfsservers
    state: present
    description: NFS servers
    membership:
      authoritative: true
      hosts:
        - nfs1.ipa.pilot.internal
      hostgroups: []

  - name: nfsclients
    state: present
    description: Hosts allowed to mount managed NFS shares
    membership:
      authoritative: true
      hosts:
        - web1.ipa.pilot.internal
        - web2.ipa.pilot.internal
      hostgroups: []

hbac:
  disable_allow_all: true

  services:
    - name: sshd
      state: present

  rules:
    - name: webhosts-ssh-access
      state: present
      enabled: true

      subjects:
        users: []
        groups:
          - access-webhosts-ssh

      targets:
        hosts: []
        hostgroups:
          - webhosts

      services:
        - sshd

    - name: breakglass-admin-access
      state: present
      enabled: true

      subjects:
        users:
          - admin
        groups: []

      targets:
        hostcat: all

      services:
        - sshd

sudo:
  command_groups:
    - name: web-service-read
      state: present
      commands:
        - /usr/bin/systemctl status nginx
        - /usr/bin/journalctl -u nginx

    - name: web-service-manage
      state: present
      commands:
        - /usr/bin/systemctl restart nginx
        - /usr/bin/systemctl reload nginx

  rules:
    - name: web-service-administration
      state: present
      enabled: true

      subjects:
        users: []
        groups:
          - role-web-service-admin

      targets:
        hosts: []
        hostgroups:
          - webhosts

      allow:
        command_groups:
          - web-service-read
          - web-service-manage
        commands: []

      deny:
        command_groups: []
        commands: []

      run_as:
        users:
          - root
        groups: []

      options:
        - "!authenticate"

nfs:
  servers:
    - host: nfs1.ipa.pilot.internal
      state: present

      service_principal:
        ensure: true
        principal: nfs/nfs1.ipa.pilot.internal
        keytab: /etc/krb5.keytab

      packages:
        - nfs-utils
        - acl

      services:
        - nfs-server
        - rpc-gssd
        - rpc-svcgssd

      firewall:
        manage: true
        allowed_services:
          - nfs
          - mountd
          - rpc-bind

      shares:
        - name: project-alpha
          state: present

          source_path: /srv/nfs/projects/alpha

          ownership:
            owner: root
            group: data-project-alpha-rw
            mode: "2770"

          acl:
            mode: authoritative

            access:
              owner: rwx
              owning_group: rwx
              others: "---"
              mask: rwx

              named_users: []

              named_groups:
                - name: data-project-alpha-rw
                  permissions: rwx
                - name: data-project-alpha-ro
                  permissions: r-x

            default:
              enabled: true

              owner: rwx
              owning_group: rwx
              others: "---"
              mask: rwx

              named_users: []

              named_groups:
                - name: data-project-alpha-rw
                  permissions: rwx
                - name: data-project-alpha-ro
                  permissions: r-x

          export:
            pseudo_path: /projects/alpha

            clients:
              - type: network
                value: 192.168.50.0/24

            options:
              - rw
              - sync
              - root_squash
              - sec=krb5i

          automount:
            enabled: true
            location: default
            mount_root: /projects
            map: auto.projects
            key: alpha

            server: nfs1.ipa.pilot.internal
            remote_path: /projects/alpha

            options:
              - fstype=nfs4
              - sec=krb5i
              - hard
              - timeo=600
              - retrans=2

nfs_clients:
  - hostgroup: nfsclients
    state: present

    packages:
      - nfs-utils
      - autofs
      - sssd

    automount:
      location: default
      enable_service: true

    verification_mounts:
      - /projects/alpha

migration:
  enabled: false

  mappings:
    - old_group: developers
      new_group: team-developers

      copy_membership: true

      filesystem:
        enabled: true
        roots:
          - /srv/nfs
        replace_group_owner: false
        replace_acl_entries: false

  delete_old_groups: false
```

---

# 6. Schema 欄位定義

## 6.1 `schema_version`

用途：

* 支援未來 schema migration。
* Agent 必須拒絕未知的 major schema version。
* 可接受支援範圍內的 minor version。

初始版本：

```yaml
schema_version: 1
```

---

## 6.2 使用者物件

必要欄位：

```yaml
name
state
first
last
```

允許的 `state`：

```text
present
disabled
absent
```

語意：

### `present`

* 使用者必須存在。
* 若 `enabled: true`，帳號必須啟用。
* 更新 roster 管理的欄位。

### `disabled`

* 使用者必須存在。
* 帳號必須停用。
* 不刪除 UID、home 或既有檔案。

### `absent`

* 預設不得自動執行。
* 必須額外指定：

```yaml
allow_destructive_user_delete: true
```

* Agent 在刪除前必須檢查：

  * 群組 membership
  * sudo 規則
  * HBAC 規則
  * 擁有的檔案
  * NFS ACL
  * automount 無關，但仍須輸出依賴報告

---

## 6.3 SSH key 語意

```yaml
ssh_keys:
  authoritative: true
  values: [...]
```

`authoritative: true`：

* roster 是完整 key 集合。
* FreeIPA 中多出的 key 必須移除。
* roster 中缺少的 key 必須新增。

`authoritative: false`：

* 只新增 roster 中不存在的 key。
* 不刪除既有 key。

---

## 6.4 密碼語意

```yaml
password:
  initial: secret
  force_change: true
  preserve_existing: false
```

規則：

* `initial` 僅在新使用者建立或明確要求 reset 時使用。
* 重跑 playbook 不得每次重設密碼。
* `preserve_existing: true` 時忽略 `initial`。
* 真實密碼只能存在 Ansible Vault。
* Agent 輸出不得顯示密碼。
* Ansible task 必須使用 `no_log: true`。

---

# 7. 群組模型

## 7.1 群組類別

允許值：

```text
team
filesystem
access
role
service
```

`service` 可用於服務帳號或應用程式授權，但不得用於一般人員組織關係。

---

## 7.2 群組類型

允許值：

```text
posix
nonposix
external
```

規則：

* `filesystem` 必須是 `posix`。
* `team` 預設為 `posix`。
* `access` 可為 `posix` 或 `nonposix`。
* `role` 可為 `posix` 或 `nonposix`。
* 初始實作建議全部使用 `posix`。
* `external` 僅適用於 AD trust 等外部身分情境。

---

## 7.3 命名規則

```text
team-<name>
data-<resource>-ro
data-<resource>-rw
data-<resource>-admin
access-<target>-<protocol>
role-<scope>-<capability>
```

正規表示式：

```regex
^team-[a-z0-9][a-z0-9-]*$
^data-[a-z0-9][a-z0-9-]*-(ro|rw|admin)$
^access-[a-z0-9][a-z0-9-]*$
^role-[a-z0-9][a-z0-9-]*$
```

禁止名稱：

```text
users
admins
shared
developers-admin
general
common
temp
```

除非透過 policy exception 明確允許。

---

## 7.4 Membership authoritative mode

```yaml
membership:
  authoritative: true
```

Agent 必須：

1. 查詢現有 direct user members。
2. 查詢現有 direct group members。
3. 計算新增項目。
4. 計算移除項目。
5. 只修改 direct membership。
6. 不將 nested membership 展開為 direct membership。
7. 不移除由其他群組間接繼承的成員。

禁止以 `ipa group-add-member` 的結果直接推斷 authoritative 狀態，必須先讀取現況。

---

## 7.5 群組巢狀限制

最大建議深度：

```text
2
```

標準模型：

```text
user
  → team group
    → permission group
```

允許：

```text
team-developers
  → data-project-alpha-rw
```

禁止：

```text
team-developers
  → department-engineering
    → project-alpha
      → role-admin
        → access-production
```

Agent 必須在 apply 前建立群組 dependency graph，檢查：

* cycle
* self-membership
* 最大深度
* 不存在的群組
* 不允許的 category 關係

---

# 8. Category policy

預設限制：

| 來源 group category | 可成為以下 group 的 member           |
| ----------------- | ------------------------------ |
| `team`            | `filesystem`, `access`, `role` |
| `filesystem`      | 不建議成為其他群組 member               |
| `access`          | 不得成為 `filesystem` member       |
| `role`            | 不得成為 `filesystem` member       |
| `service`         | 僅依明確 policy                    |

禁止用途：

* `team-*` 直接作為 NFS 目錄 owning group。
* `data-*` 直接用於 HBAC。
* `access-*` 用於 sudo rule。
* `role-*` 用於一般共享目錄 ACL。
* `team-*` 直接用於 sudo rule。

允許透過：

```yaml
policy_exceptions:
  - object: ...
    reason: ...
```

進行明確例外，但 Agent 必須輸出 warning。

---

# 9. Host 與 Host Group

## 9.1 Host 必須使用 FQDN

合法：

```text
web1.ipa.pilot.internal
```

禁止：

```text
web1
192.168.50.11
```

理由：

* Kerberos principal 與 DNS 綁定。
* NFS service principal 使用 FQDN。
* HBAC 與 host identity 必須一致。

---

## 9.2 Hostgroup authoritative membership

與 user group 相同：

```yaml
membership:
  authoritative: true
```

Agent 只能管理 roster 宣告的 direct hosts 與 nested hostgroups。

---

# 10. HBAC 規格

## 10.1 預設 deny 模型

正式模式下必須：

```yaml
hbac:
  disable_allow_all: true
```

但在停用 `allow_all` 前，Agent 必須驗證：

* 至少存在一條 enabled break-glass 規則。
* admin 或指定管理群組可以登入所有必要主機。
* 所有受管理 hostgroup 至少有一條 SSH access rule。
* HBAC test 對管理員回傳 allowed。

若驗證失敗，不得停用 `allow_all`。

---

## 10.2 Break-glass 規則

必要規則：

```yaml
- name: breakglass-admin-access
  subjects:
    users: [admin]
  targets:
    hostcat: all
  services: [sshd]
```

更佳做法是建立：

```text
role-breakglass-admin
```

並將至少兩個受控管理帳號加入。

---

## 10.3 HBAC rule schema

```yaml
- name: rule-name
  state: present
  enabled: true

  subjects:
    users: []
    groups: []

  targets:
    hosts: []
    hostgroups: []
    hostcat: null

  services:
    - sshd
```

規則：

* `hostcat: all` 不得與 `hosts` 或 `hostgroups` 同時出現。
* subjects 至少有一個 user 或 group。
* targets 必須指定 host、hostgroup 或 hostcat。
* services 不得為空。
* HBAC group 預設必須是 `access` category。

---

# 11. sudo 規格

## 11.1 sudo command group

不得直接把所有命令寫在大量 sudo rule 中。

優先使用：

```yaml
sudo:
  command_groups:
```

這可減少重複並便於稽核。

---

## 11.2 禁止過寬命令

預設禁止：

```text
/bin/bash
/bin/sh
/usr/bin/su
/usr/bin/sudo
/usr/bin/env
/usr/bin/python*
/usr/bin/perl
/usr/bin/vim
/usr/bin/less
/usr/bin/systemctl
/usr/bin/journalctl
```

若命令未帶限制參數，可能形成 privilege escalation。

例如：

```text
/usr/bin/systemctl
```

幾乎等同 root shell 能力。

建議改為：

```text
/usr/bin/systemctl status nginx
/usr/bin/systemctl restart nginx
/usr/bin/systemctl reload nginx
/usr/bin/journalctl -u nginx
```

Agent 必須對高風險命令輸出錯誤或 warning。

---

## 11.3 sudo rule group category

sudo rule 預設只能引用：

```text
role-*
```

若引用 `team-*` 或 `access-*`，schema validation 必須失敗，除非有 policy exception。

---

# 12. NFS 架構

## 12.1 必須使用 NFSv4

系統需支援：

```text
NFSv4 pseudo filesystem
Kerberos security flavors
FreeIPA automount
POSIX ACL
```

不要求支援 NFSv3。

---

## 12.2 Kerberos service principal

每台 NFS server 必須存在：

```text
nfs/<server-fqdn>@REALM
```

例如：

```text
nfs/nfs1.ipa.pilot.internal@IPA.PILOT.INTERNAL
```

Agent 必須：

1. 確認 host 已存在 FreeIPA。
2. 確認 DNS 正向解析。
3. 確認 hostname -f 與 roster 一致。
4. 建立 `nfs/FQDN` service。
5. 將 principal 寫入 server keytab。
6. 驗證 `klist -k` 能看到 principal。
7. 限制 keytab 權限為 root readable。
8. 不在 log 中輸出 key material。

---

## 12.3 Export policy

允許的安全選項：

```text
rw
ro
sync
root_squash
sec=krb5
sec=krb5i
sec=krb5p
subtree_check
no_subtree_check
```

預設：

```text
rw
sync
root_squash
sec=krb5i
```

禁止：

```text
no_root_squash
insecure
anonuid=0
anongid=0
sec=sys
```

除非 safety policy 明確關閉並提供 exception reason。

---

## 12.4 NFS server 名稱

automount 的 server 必須為 FQDN：

```text
nfs1.ipa.pilot.internal
```

不得為：

```text
192.168.50.20
nfs1
```

Kerberos SPN 不應以 IP 位址匹配。

---

# 13. NFS 目錄與 ACL

## 13.1 Owning group

每個可寫共享目錄必須指定一個 `filesystem` category 的 POSIX group：

```yaml
ownership:
  owner: root
  group: data-project-alpha-rw
  mode: "2770"
```

Agent 必須驗證：

* group 存在。
* group 是 POSIX group。
* group category 是 filesystem。
* mode 包含 setgid。
* others 不可寫。

---

## 13.2 Setgid

所有共享資料目錄必須啟用：

```text
chmod 2xxx
```

標準值：

```text
2770
2750
```

確保新建立檔案或目錄繼承父目錄群組。

---

## 13.3 Access ACL

範例：

```yaml
acl:
  access:
    owner: rwx
    owning_group: rwx
    others: "---"
    mask: rwx

    named_groups:
      - name: data-project-alpha-rw
        permissions: rwx
      - name: data-project-alpha-ro
        permissions: r-x
```

轉換為：

```text
user::rwx
group::rwx
group:data-project-alpha-rw:rwx
group:data-project-alpha-ro:r-x
mask::rwx
other::---
```

---

## 13.4 Default ACL

可寫共享目錄必須有 default ACL：

```text
default:user::rwx
default:group::rwx
default:group:data-project-alpha-rw:rwx
default:group:data-project-alpha-ro:r-x
default:mask::rwx
default:other::---
```

Agent 不得只設定 access ACL 而忽略 default ACL。

---

## 13.5 ACL authoritative mode

```yaml
acl:
  mode: authoritative
```

語意：

* roster 是完整 ACL。
* 多餘的 named user/group ACL 必須移除。
* owner、group、mask、other 必須修正。
* default ACL 必須完全一致。

安全要求：

* apply 前輸出 ACL diff。
* 大量遞迴 ACL 修改預設禁止。
* 只有 share root 目錄預設 authoritative。
* 若要遞迴修復，必須顯式設定：

```yaml
acl:
  recursive:
    enabled: true
    include_files: true
    include_directories: true
    preserve_special_entries: true
```

---

# 14. Automount

## 14.1 FreeIPA automount 結構

範例：

```text
location: default

auto.master:
  /projects → auto.projects

auto.projects:
  alpha → -fstype=nfs4,sec=krb5i,hard,timeo=600,retrans=2 \
          nfs1.ipa.pilot.internal:/projects/alpha
```

---

## 14.2 Map ownership

Agent 必須管理：

* automount location
* auto.master key
* indirect map
* map key
* mount options
* remote path

不得直接修改各 client `/etc/fstab`。

---

## 14.3 Client 套用

對 `nfs_clients` 指定的 host 或 hostgroup，Agent 必須：

1. 安裝 `nfs-utils`。
2. 安裝 `autofs`。
3. 確認 SSSD 已配置。
4. 執行或等價處理 `ipa-client-automount`。
5. 啟用 `autofs`。
6. 重啟 SSSD/autofs，僅在設定變更時。
7. 存取 mount key 觸發掛載。
8. 驗證 mount security flavor。

---

# 15. Schema validation

## 15.1 必須在任何變更前完成

Validation 失敗時：

* 不得建立任何 IPA object。
* 不得修改 NFS server。
* 不得寫入 ACL。
* 不得修改 exports。
* 不得停用 HBAC allow_all。

---

## 15.2 必要驗證項目

### 基本 schema

* 必要欄位存在。
* 欄位型別正確。
* enum 合法。
* 名稱符合格式。
* 不允許未知欄位，除非 schema 明確支援 extension。

### Referential integrity

檢查以下參照存在：

* group membership users
* group membership groups
* hostgroup hosts
* hostgroup nested hostgroups
* HBAC users/groups/hosts/hostgroups/services
* sudo users/groups/hosts/hostgroups/commands
* NFS owning group
* ACL named users/groups
* automount server
* NFS client hostgroup

### Category constraints

* filesystem share group 必須是 filesystem。
* HBAC group 必須是 access。
* sudo group 必須是 role。
* team 不得直接用於 storage、HBAC、sudo。

### Graph validation

* group cycle
* hostgroup cycle
* self-membership
* 最大巢狀深度
* mutual recursion

### NFS safety

* 禁止 `sec=sys`
* 禁止 `no_root_squash`
* 禁止 IP server
* 禁止 world-writable mode
* 必須有 setgid
* 必須有 default ACL
* RW group 必須有 `rwx`
* RO group 不得有 `w`
* ACL mask 不得壓縮預期權限

### HBAC safety

* disable allow_all 時必須有 break-glass rule
* break-glass rule 必須 enabled
* break-glass target 必須覆蓋必要主機
* break-glass service 必須包含 sshd

### sudo safety

* 檢查 shell escape command
* 檢查 wildcard
* 檢查 unrestricted interpreter
* 檢查 unrestricted editor
* 檢查 unrestricted systemctl

---

# 16. 冪等性

每個 role 必須滿足：

```text
第一次執行：產生必要 changes
第二次執行：changed=0
第三次執行：changed=0
```

以下不應導致每次 changed：

* Kerberos kinit
* 讀取現有 IPA object
* 查詢 ACL
* exportfs -v
* klist -k
* systemctl is-active
* automount lookup

只有實際設定變化時才允許 handler 重啟服務。

---

# 17. 執行階段與 dependency ordering

## Phase 0：Preflight

檢查：

* roster schema
* vault 變數存在
* FreeIPA DNS
* Kerberos clock skew
* IPA API 可達
* inventory 與 roster host mapping
* target OS 支援

## Phase 1：Identity primitives

依序：

```text
users
groups
group membership
```

必須先建立所有 group，再處理 nested membership。

## Phase 2：Host primitives

依序：

```text
hosts
hostgroups
hostgroup membership
```

## Phase 3：Authorization

依序：

```text
HBAC services
HBAC rules
sudo commands
sudo command groups
sudo rules
```

## Phase 4：NFS identity

依序：

```text
NFS host
NFS service principal
keytab
GSS services
```

## Phase 5：Storage

依序：

```text
packages
directories
ownership
mode
access ACL
default ACL
exports
exportfs reload
```

## Phase 6：Automount

依序：

```text
location
map
master key
share key
client configuration
```

## Phase 7：Verification

執行所有驗證。

## Phase 8：HBAC lockdown

只有所有驗證通過後，才可停用 `allow_all`。

---

# 18. Error handling

任何 destructive 或 lockout-sensitive operation 必須使用 transaction-like flow。

例如停用 allow_all：

```text
1. 建立新 HBAC rules
2. ipa hbactest 驗證管理員
3. ipa hbactest 驗證一般使用者
4. 確認 break-glass
5. 停用 allow_all
6. 再次 hbactest
7. 若失敗，立即重新啟用 allow_all
```

NFS export 更新：

```text
1. 產生暫存 exports fragment
2. 執行 exportfs -ra 測試
3. 成功才保留
4. 失敗則還原前一版
```

ACL：

```text
1. 備份 getfacl output
2. 套用 ACL
3. 驗證 ACL
4. 失敗時還原 setfacl --restore
```

---

# 19. Migration 規格

## 19.1 遷移階段

### 階段 A：Discovery

Agent 必須產生報告：

* 舊 group 是否存在。
* 舊 group GID。
* direct members。
* nested members。
* sudo references。
* HBAC references。
* filesystem ownership。
* ACL references。
* script/config reference 無法自動完整找出，但須支援 grep paths。

### 階段 B：Create new model

建立：

```text
team-*
data-*
access-*
role-*
```

不修改舊群組。

### 階段 C：Copy membership

將舊 membership 複製到新的 team group。

### 階段 D：Switch policies

將：

* HBAC 改為 access group。
* sudo 改為 role group。
* NFS 改為 data group。

### 階段 E：Filesystem migration

支援：

```yaml
filesystem:
  replace_group_owner: true
  replace_acl_entries: true
```

必須以數字 GID 搜尋，避免群組解析切換後遺漏：

```bash
find /srv/nfs -gid OLD_GID
```

### 階段 F：Observation

預設 observation period 不由 Ansible 自動等待，但 roster 可標示 migration state：

```yaml
migration:
  phase: observe
```

### 階段 G：Retire old groups

只有在：

* 無 HBAC reference
* 無 sudo reference
* 無 direct membership
* 無 filesystem owner
* 無 ACL reference
* 無 roster reference

才允許刪除。

---

# 20. 驗證與測試

## 20.1 FreeIPA identity 測試

每個 user：

```bash
ipa user-show <user>
```

每個 group：

```bash
ipa group-show <group> --all
```

Client：

```bash
getent passwd alice
getent group data-project-alpha-rw
id alice
```

---

## 20.2 SSSD 測試

```bash
sssctl domain-status ipa.pilot.internal
sssctl user-checks alice
getent passwd alice
id alice
```

不得依賴 `sss_cache -E` 作為正常流程；只可用於 migration 或 troubleshooting。

---

## 20.3 HBAC 測試矩陣

至少測試：

| User  | Host    | Service | 預期    |
| ----- | ------- | ------- | ----- |
| alice | web1    | sshd    | allow |
| bob   | web1    | sshd    | allow |
| bob   | db1     | sshd    | deny  |
| admin | 任意受管理主機 | sshd    | allow |

使用：

```bash
ipa hbactest \
  --user=alice \
  --host=web1.ipa.pilot.internal \
  --service=sshd
```

---

## 20.4 sudo 測試

```bash
sudo -l -U alice
```

驗證：

* 允許的命令存在。
* 未允許命令不存在。
* 不得出現意外的 `ALL`。
* 不得允許 shell。

---

## 20.5 NFS principal 測試

```bash
klist -k /etc/krb5.keytab
```

必須包含：

```text
nfs/nfs1.ipa.pilot.internal@IPA.PILOT.INTERNAL
```

---

## 20.6 Automount 測試

```bash
ls /projects/alpha
findmnt /projects/alpha
nfsstat -m
```

必須確認：

```text
vers=4
sec=krb5i
```

---

## 20.7 NFS 權限測試

### RW 使用者

```bash
sudo -u alice touch /projects/alpha/alice-test
sudo -u bob sh -c 'echo ok >> /projects/alpha/alice-test'
```

預期成功。

### RO 使用者

```bash
sudo -u carol cat /projects/alpha/alice-test
```

預期成功。

```bash
sudo -u carol touch /projects/alpha/carol-test
```

預期失敗。

### 無權限使用者

```bash
sudo -u outsider ls /projects/alpha
```

預期 permission denied。

---

## 20.8 Inheritance 測試

```bash
sudo -u alice mkdir /projects/alpha/test-dir
sudo -u alice touch /projects/alpha/test-dir/test-file

stat -c '%U %G %a %n' \
  /projects/alpha/test-dir \
  /projects/alpha/test-dir/test-file

getfacl \
  /projects/alpha/test-dir \
  /projects/alpha/test-dir/test-file
```

必須確認：

* group 為 `data-project-alpha-rw`
* directory 保有 setgid
* RW group 有寫權限
* RO group 無寫權限
* others 無權限

---

# 21. 自動測試需求

## 21.1 Unit tests

針對 filter/plugin：

* group cycle detection
* max nesting depth
* category policy
* ACL normalization
* duplicate detection
* invalid reference
* unsafe NFS option
* unsafe sudo command

建議使用 `pytest`。

---

## 21.2 Molecule tests

至少建立：

```text
1 FreeIPA server
1 NFS server
2 Linux clients
```

若完整 FreeIPA container 測試成本過高，可分成：

```text
schema/unit pipeline
mocked IPA module integration
full VM-based nightly integration
```

---

## 21.3 Idempotence test

CI 必須執行：

```text
apply once
apply twice
assert second run changed=0
```

---

## 21.4 Negative tests

必須涵蓋：

* group cycle
* data group 為 nonposix
* NFS 使用 sec=sys
* export 使用 no_root_squash
* mode 2777
* HBAC allow_all disabled 但無 break-glass
* sudo 使用 `/bin/bash`
* automount server 使用 IP
* ACL RO group 有 write
* missing referenced user
* missing referenced hostgroup

---

# 22. 日誌與輸出

Agent 每次執行結束必須輸出摘要：

```text
Users:
  created: 2
  updated: 1
  disabled: 0

Groups:
  created: 6
  membership added: 8
  membership removed: 1

HBAC:
  created: 2
  updated: 0
  allow_all disabled: true

Sudo:
  command groups created: 2
  rules created: 1

NFS:
  service principals created: 1
  shares created: 1
  ACL updated: 1
  exports updated: 1

Automount:
  locations created: 0
  maps created: 1
  keys created: 2

Verification:
  passed: 24
  failed: 0
```

不得輸出：

* 密碼
* keytab 内容
* private key
* Kerberos ticket
* Ansible Vault 解密內容

---

# 23. 備份與 rollback

## 23.1 Apply 前備份

必須保存：

* IPA objects JSON export
* group memberships
* HBAC rules
* sudo rules
* automount maps
* `/etc/exports.d/` 管理片段
* `getfacl -R`，僅限受管理 share
* keytab metadata，不保存到普通 log

---

## 23.2 受管理檔案

Agent 應只管理專屬片段：

```text
/etc/exports.d/90-freeipa-managed.exports
```

不得整檔覆蓋：

```text
/etc/exports
```

autofs 主要透過 FreeIPA 管理，不直接覆蓋本機 map。

---

## 23.3 Rollback playbook

提供：

```text
playbooks/rollback/freeipa-last-apply-rollback.yml
```

至少可還原：

* exports fragment
* ACL
* automount keys
* HBAC allow_all 狀態
* 新建 HBAC/sudo rules

使用者與群組刪除不保證可完全 rollback，因此預設不得自動刪除。

---

# 24. Agent 實作要求

Agent 必須：

1. 先讀取並理解目前 playbook 與 role。
2. 不直接在單一大型 playbook 中堆疊所有邏輯。
3. 將驗證、identity、authorization、storage、automount 分成獨立 roles。
4. 優先使用 FreeIPA Ansible collection module。
5. module 不足時才使用 `ipa` CLI。
6. 使用 CLI 時必須：

   * 正確處理 return code
   * 不以文字 grep 判斷成功
   * 優先使用 JSON output
   * 設定 `changed_when`
   * 設定 `failed_when`
   * 避免 shell injection
7. 所有 secret task 使用 `no_log: true`。
8. 所有 destructive operation 需要明確 flag。
9. 支援 check mode。
10. 支援 diff summary。
11. 所有 role 必須有 defaults、README 與 tests。
12. 所有 schema 欄位必須在 JSON Schema 中定義。
13. example roster 不得包含真實 secret。
14. 第二次 apply 必須零變更。
15. 任何驗證失敗不得進入 apply 階段。

---

# 25. 建議 Agent 任務拆解

## Task 1：建立 schema 與 validation

產出：

```text
schemas/freeipa-roster.schema.json
roles/freeipa_roster_validate/
filter_plugins/group_graph.py
filter_plugins/acl_normalize.py
tests/schema/
```

## Task 2：重構 users 與 groups

產出：

```text
roles/freeipa_users/
roles/freeipa_groups/
```

支援 authoritative membership。

## Task 3：實作 hostgroups、HBAC、sudo

產出：

```text
roles/freeipa_hosts/
roles/freeipa_hostgroups/
roles/freeipa_hbac/
roles/freeipa_sudo/
```

## Task 4：實作 Kerberos NFS principal

產出：

```text
roles/freeipa_nfs_service/
```

## Task 5：實作 NFS server 與 ACL

產出：

```text
roles/nfs_server/
roles/nfs_share/
```

## Task 6：實作 automount 與 client

產出：

```text
roles/freeipa_automount/
roles/nfs_client/
```

## Task 7：實作 migration

產出：

```text
roles/freeipa_migration/
playbooks/apply/freeipa-migration-apply.yml
```

## Task 8：實作 verify 與 CI

產出：

```text
roles/freeipa_verify/
tests/molecule/
tests/integration/
```

---

# 26. 驗收標準

以下條件全部滿足才視為完成。

## Schema

* roster 可通過 JSON Schema。
* 所有無效 reference 會在 apply 前失敗。
* 所有 group cycle 會被阻止。
* category misuse 會被阻止。

## FreeIPA

* users、groups、membership 冪等。
* Linux client 可透過 SSSD 查詢使用者及群組。
* UID/GID 在所有主機一致。

## HBAC

* 非授權使用者無法登入受限主機。
* break-glass 帳號始終可登入。
* allow_all 僅在驗證完成後停用。

## sudo

* 使用者只能執行 roster 宣告命令。
* 不存在意外 `ALL` 或 shell escape。

## NFS

* 使用 NFSv4。
* 使用 `sec=krb5i` 或更高安全等級。
* 使用 FQDN。
* 啟用 root_squash。
* share mode 包含 setgid。
* access ACL 正確。
* default ACL 正確。
* RW、RO 與 deny 測試符合預期。

## Automount

* client 不需維護 `/etc/fstab`。
* 存取 mount path 時可自動掛載。
* IPA 暫時不可達時，SSSD cache 行為符合預期。

## Idempotence

* 第二次執行 `changed=0`。
* check mode 不造成任何寫入。

## Migration

* 舊 group 可平滑遷移。
* 舊 filesystem GID 與 ACL reference 可被偵測。
* 未明確開啟 destructive flag 時不刪除舊 group。

---

# 27. 最終權限模型

```text
User
 │
 ├─ member of team-developers
 │
 ├─ inherited member of data-project-alpha-rw
 │     └─ controls NFS/POSIX ACL
 │
 ├─ inherited member of access-webhosts-ssh
 │     └─ controls HBAC login
 │
 └─ direct member of role-web-service-admin
       └─ controls sudo
```

資料存取流程：

```text
User login
  │
  ├─ SSSD resolves UID/GID from FreeIPA
  ├─ Kerberos issues user ticket
  ├─ autofs retrieves map from FreeIPA
  ├─ client mounts NFSv4 using sec=krb5i
  └─ NFS server authorizes through POSIX group and ACL
```

---

# 28. 不在本期範圍

以下功能不屬於首版必要範圍：

* SMB/CIFS
* Windows ACL
* Active Directory trust
* NFS-Ganesha
* CephFS
* 多主 NFS cluster
* automatic user home directory provisioning over NFS
* quota management
* snapshot orchestration
* backup orchestration
* SELinux policy 自動生成
* NFSv4 rich ACL

後續可在 schema version 2 擴充。

