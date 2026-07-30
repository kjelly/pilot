# Verification Spec — FreeIPA realm replacement client wave

> 版本：DRAFT v0.1（尚未完成實機 evidence run；不得作為正式 SOP）
> 對齊規範：FreeIPA client re-enrollment；新 FreeIPA server 必須先獨立驗證完成
> 維護者：sre

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Inventory group | `freeipa-client`（或明確的 `target_group` wave） |
| OS / version | Debian/Ubuntu 或 EL，且已經 enrollment 至舊 FreeIPA realm |
| 角色 | 將既有 client 從舊 realm 移除並 enrollment 至已重建的新 server |
| 套用範圍 | 一個明確選定的 client wave；不包含 server、identity roster 或 NFS overlay |
| 風險等級 | High（會移除現有 Kerberos keytab/SSSD trust；不可與 server rebuild 混為同一步） |

## 1.5 依賴變數契約

| 變數名稱 | 說明/用途 | 是否必填 |
|---------|----------|---------|
| `ipa_admin_password` | 新 realm enrollment principal 的密碼；僅由 vault 注入 | 是 |
| `freeipa_realm_replacement_old_realm` | client 目前所屬、準備離開的 realm | 是 |
| `freeipa_realm_replacement_new_domain` | 新 server 的 DNS domain | 是 |
| `freeipa_realm_replacement_new_realm` | 新 server 的 Kerberos realm | 是 |
| `freeipa_realm_replacement_new_server_fqdn` | 新 server FQDN | 是 |
| `freeipa_realm_replacement_new_server_ip` | 從 client 可路由的新 server IP | 是 |
| `freeipa_realm_replacement_client_fqdn` | client 在新 domain 的 FQDN | 是 |
| `freeipa_realm_replacement_verify_user` | 新 realm 中用於 SSSD 查詢的帳號；預設 `admin` | 否 |
| `freeipa_realm_replacement_ticket` | 變更單／核准識別；寫入本機 migration marker | 是 |
| `freeipa_realm_replacement_confirm` | 必須明確為 `true` 才允許 un-enroll | 是 |

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | migration | realm replacement completion marker exists | 0 | sudo test -f /etc/pilot/freeipa-realm-replacement.env |
| C2 | service | SSSD is active after re-enrollment | 0 | systemctl is-active sssd |
| C3 | config | `/etc/ipa/default.conf` contains the derived new realm line | 0 | sudo grep -Ff /etc/pilot/freeipa-realm-replacement.expected-realm /etc/ipa/default.conf |
| C4 | authn | host keytab contains the derived new host principal | 0 | sudo klist -k /etc/krb5.keytab | grep -Ff /etc/pilot/freeipa-realm-replacement.expected-host |
| C5 | authn | SSSD resolves the derived verification identity | 0 | sudo xargs -a /etc/pilot/freeipa-realm-replacement.expected-user getent passwd |
| C6 | rollback | root-only pre-migration archive remains available through stable link | 0 | sudo test -f /etc/pilot/freeipa-realm-replacement.backup |

## 3. 證據收集

- 工具：`pilot verify docs/verification/freeipa-realm-replacement.md -i <inventory>`
- 原始輸出：gitignored `.verification/freeipa-realm-replacement-<UTC>.{ndjson,md}` 或 pilot evidence store
- Sanitized 摘要：`docs/evidence/freeipa-realm-replacement/<date>-<tested-revision>.md`
- 狀態：**DRAFT — TODO: VERIFY**。2026-07-29 三 VM 實跑已證明 new
  `/etc/ipa/default.conf`、host keytab 與 `sssd` service 可被切換，但 C5
  `getent` 失敗（SSSD backend Offline；raw transcript/evidence 保留於
  `.verification/freeipa-realm-replacement-*`）。尚未有 immutable candidate 的全 PASS、rollback 或
  negative-path evidence；不得宣稱此 spec 已驗證。
- Row 數：6

## 4. PASS / FAIL 規則

- C1–C6 全部 pass → client wave 已完成新 realm enrollment，且保有本機 rollback archive。
- 任一 fail → 此 client 不得納入已完成 wave；先保留 archive 與 raw evidence，再依 runbook 的 rollback boundary 處置。

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|----------|----------|------|
| C5 | 若新 realm 禁止 `admin` 經 NSS 查詢，必須提供一個已建立、可解析的 `freeipa_realm_replacement_verify_user`；不得跳過有效 SSSD 查詢 | 有嚴格 admin policy 的站台 | 依站台 |
| C6 | archive 只可回復 client 的舊本機設定；若舊 FreeIPA server 已重裝或退役，它不能恢復舊 realm 的信任關係 | 所有 server replacement | 永久 |
| — | identity roster、HBAC/sudo、NFS automount 與其他 FreeIPA overlays 必須在 client wave 前於新 server 建好／wave 後另行驗收 | 所有站台 | 永久 |

## 6. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-29 | DRAFT v0.1 | 初版：明確切分 server readiness、client re-enrollment、local rollback archive 與 evidence boundary | sre |
