# 交付快速上手（給收到這份 playbook 的人）

這份文件只講「黃金路徑」：**填好 inventory → 前置檢查 → 套用**。
你不需要讀完整份 README，跟著下面四步走即可。

---

## 你只需要準備兩樣東西

1. **能 SSH 到目標機器的帳號 + 私鑰**（例如 `ubuntu` + `~/.ssh/id_ed25519`）。
2. **目標機器的 IP**。

其它內部參數都已經有合理預設。少數角色（PAM-OIDC、FreeIPA…）需要幾個設定值，
統一放在 group_vars（見步驟 1.5），設定一次即可，不用每次打 `-e`。

---

## 四步上手

### 1. 複製 inventory 範本，填入你的機器

```bash
cp inventory.example.yml inventory.yml
```

打開 `inventory.yml`，把每個 `"<FILL-ME>"` 換成真實值（每行右邊的 `#` 註解說明格式）。
**只有 `"<FILL-ME>"` 需要改；group 結構照留。用不到的角色 group 整段刪掉即可。**

> 觀念：`inventory.yml` **只放「主機 + 歸屬」**。每台機器只在 `all.hosts:` 定義一次
> （IP／連線），再把它列進 `children:` 底下對應的角色 group（`freeipa-server`、
> `linux-servers`…）。playbook 靠 group 自動找到目標。**角色的『設定值』另外放
> group_vars（見下一步）**，不要塞進 inventory。

### 1.5 （需要時）設定角色參數 → group_vars

有些角色需要幾個設定值（例如 PAM-OIDC 要 Keycloak 位址、FreeIPA 要 realm）。
這些**不寫進 inventory、也不用每次打一長串 `-e`**，改成放在 inventory 旁邊的
`group_vars/<group>.yml`，設定「一次」即可：

```bash
mkdir -p group_vars
# 只複製你會用到的角色。檔名必須等於 group 名(去掉 .example)才會生效。
cp group_vars/freeipa.example.yml        group_vars/freeipa.yml          # FreeIPA realm
cp group_vars/linux-servers.example.yml  group_vars/linux-servers.yml    # PAM-OIDC / Keycloak
cp group_vars/dns.example.yml            group_vars/dns.yml              # DNS 位址
cp group_vars/ntp.example.yml            group_vars/ntp.yml             # NTP 來源
cp group_vars/audit-log-forwarding.example.yml \
   group_vars/audit-log-forwarding.yml                                  # SIEM 轉送位址(選填)
cp group_vars/wazuh-manager.example.yml  group_vars/wazuh-manager.yml   # SIEM 轉送位址(選填)
cp group_vars/wazuh-fim.example.yml      group_vars/wazuh-fim.yml       # Wazuh manager 位址(選填)
```

打開複製出來的檔案，照註解填。沒用到的角色不用複製；不填的值會沿用內建預設。

> 為什麼分開？inventory 回答「有哪些機器、各是什麼」；group_vars 回答「每種角色怎麼設定」。
> 兩者分開後 inventory 保持精簡、設定集中一處，兩邊都更難填錯。
> 機密（密碼）仍走 ansible-vault，別寫進 group_vars 明文（見文末）。

### 2. 跑前置檢查（會告訴你哪裡填錯、連不連得到）

```bash
ansible-playbook -i inventory.yml playbooks/preflight.yml
```

- 全綠 → 繼續第 3 步。
- 紅字 → 照訊息修 `inventory.yml`（缺欄位、忘了換 `<FILL-ME>`、私鑰路徑錯、或 SSH 連不上）。

> 只想先檢查填寫、機器還沒開？加 `--tags static` 只做靜態檢查、不連線。

### 3.（選用）視覺確認 inventory 結構符合預期

```bash
ansible-inventory -i inventory.yml --graph
```

會畫出「哪台機器在哪個 group」的樹狀圖，確認你填的跟你想的一致。

### 4. 套用

**方式 A（推薦，一鍵）**：用 `site.yml` 一次跑全站，它會**自動先做 preflight**，
沒過就不會套用任何東西。你的 inventory 裡**空的 group 會自動跳過**，所以只會跑到
你實際填了機器的元件：

```bash
ansible-playbook -i inventory.yml playbooks/site.yml
```

只想跑某一類元件，用 tag 篩選（preflight 仍會先跑）：

```bash
ansible-playbook -i inventory.yml playbooks/site.yml --tags freeipa
ansible-playbook -i inventory.yml playbooks/site.yml --tags keycloak
```

**方式 B（granular）**：單獨跑某一支 playbook，各自作用在對應角色 group（見下表）：

```bash
# 把 web-1 / web-2（linux-servers group）納入補丁管理
ansible-playbook -i inventory.yml playbooks/apply/os-patch-sla-apply.yml

# 只想針對其中一台
ansible-playbook -i inventory.yml playbooks/apply/os-patch-sla-apply.yml --limit web-1
```

---

## Playbook 對照表

| 想做的事 | Playbook | 預設作用的 group |
|---|---|---|
| 建 FreeIPA 身份伺服器 | `playbooks/apply/freeipa-server-apply.yml` | `freeipa-server` |
| 把機器納入 FreeIPA（AAA） | `playbooks/apply/freeipa-client-apply.yml` | `freeipa-client` |
| 管理 FreeIPA 使用者／權限 | `playbooks/apply/freeipa-identity-apply.yml` | (見下方「機密」) |
| DNS／NTP 等核心服務 | `playbooks/apply/core-infra-provider-apply.yml` | 依 `-e infra_role=dns\|ntp` |
| Keycloak（IdP） | `playbooks/apply/keycloak-apply.yml` | `keycloak` |
| Keycloak 資料庫 | `playbooks/apply/keycloak-db-apply.yml` | `keycloak-db` |
| SSH 走 OIDC 登入 | `playbooks/apply/pam-oidc-sshd-apply.yml` | `linux-servers` |
| 中央稽核日誌接收(SIEM) | `playbooks/apply/log-server-apply.yml` | `log-server` |
| 主機稽核(auditd)+ 轉送到 log-server | `playbooks/apply/audit-log-forwarding-apply.yml` | `audit-log-forwarding` |
| Wazuh 中央伺服器(FIM/who-data 告警引擎 + CVE 弱點掃描) | `playbooks/apply/wazuh-manager-apply.yml` | `wazuh-manager`（需至少 4 vCPU/8GB RAM/50GB 磁碟，見 `docs/runbooks/wazuh-manager.md` §5.2） |
| Wazuh agent(檔案完整性監控 FIM + auditd who-data) | `playbooks/apply/wazuh-fim-apply.yml` | `wazuh-fim` |
| OS 補丁 SLA | `playbooks/apply/os-patch-sla-apply.yml` | 依 `-e patch_stage=` |

> 每支 apply playbook 的檔頭註解都有完整的參數與範例；`--limit <host>` 可把任何一次
> 執行縮到單一機器，`-e target_group='dns:&prod'` 可用「角色×環境」交集精準鎖定。

---

## 關於機密（密碼／管理員憑證）

需要密碼的 playbook（FreeIPA、Keycloak）**不要**把密碼寫進 inventory。放進一份
**加密的 vars 檔**、且不要進 git：

```bash
# 以 FreeIPA 身份管理為例
cp playbooks/apply/freeipa-identity.roster.example.yaml ~/.vault/ipa-identity.yaml
# 編輯填入真實使用者與密碼後加密：
ansible-vault encrypt ~/.vault/ipa-identity.yaml
# 套用時帶入：
ansible-playbook -i inventory.yml playbooks/apply/freeipa-identity-apply.yml \
    -e @~/.vault/ipa-identity.yaml --vault-password-file ~/.vault/vault-pass
```

各 `.roster.example.yaml` / apply playbook 檔頭都有該 playbook 所需機密的 schema 說明。

---

## 常見卡關

| 症狀 | 原因 / 解法 |
|---|---|
| preflight 報「殘留 `<FILL-ME>`」 | 有欄位忘了填，打開 `inventory.yml` 搜尋 `FILL-ME` |
| preflight ping 失敗 | 機器沒開 / IP 錯 / `ansible_user` 錯 / 私鑰不是該帳號的 / 22 埠被擋 |
| 私鑰檔找不到 | `ansible_ssh_private_key_file` 路徑錯（`~` 會展開成你的家目錄） |
| playbook 說少了某個 `-e` 變數 | 依錯誤訊息補上，或改用加密 vars 檔 `-e @...` 帶入 |
