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
- 狀態：**DRAFT — TODO: VERIFY**（C1–C6 與 rollback 通過，仍有已知缺口）。2026-10-13，candidate `5c99075`（合併 #53 的修正：新 server 的 pin 在移除舊 pin 之後寫入，uninstall 之後移除 SSSD 為舊 domain 留下的 Kerberos realm mapping）：Ubuntu 24.04 client，新 server 沿用舊 server 的 FQDN 時，兩種失敗點（新 realm enrollment 失敗、enrollment 後 C5 失敗）rollback 後，舊 realm 的 `admin` 能以密碼 SSH 登入，`freeipa-client.md` 12/12；migration（含 rollback 之後）與新 server 使用自己 FQDN 的 migration，C1–C6 各 **6/6 PASS**。AlmaLinux 9 client 的 rollback 與 migration 最近一次通過是 `b9d82d9`（[evidence](../evidence/freeipa-realm-replacement/2026-10-12-b9d82d9.md)）。尚未修正：`--check --diff` 必定在 archive link 失敗、archive 名稱取自 fact cache 而可能重複。Evidence：[`docs/evidence/freeipa-realm-replacement/2026-10-13-5c99075.md`](../evidence/freeipa-realm-replacement/2026-10-13-5c99075.md)。上述缺口處理前，不得宣稱此 spec 已驗證。
- Row 數：6

## 4. PASS / FAIL 規則

- C1–C6 全部 pass → client wave 已完成新 realm enrollment，且保有本機 rollback archive。
- 任一 fail → 此 client 不得納入已完成 wave；先保留 archive 與 raw evidence，再依 runbook 的 rollback boundary 處置。

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|----------|----------|------|
| C5 | 若新 realm 禁止 `admin` 經 NSS 查詢，必須提供一個已建立、可解析的 `freeipa_realm_replacement_verify_user`；不得跳過有效 SSSD 查詢 | 有嚴格 admin policy 的站台 | 依站台 |
| C6 | rollback 以 archive 裡的 host keytab 重新 enroll 回舊 realm，需要舊 FreeIPA server 仍在運作、且舊 host entry 仍有效（migration 刻意不在舊 server 上 disable 它，見 runbook §3/§4）；若舊 server 已重裝或退役，archive 不能恢復舊 realm 的信任關係 | 所有 server replacement | 永久 |
| — | identity roster、HBAC/sudo、NFS automount 與其他 FreeIPA overlays 必須在 client wave 前於新 server 建好／wave 後另行驗收 | 所有站台 | 永久 |

## 6. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-07-29 | DRAFT v0.1 | 初版：明確切分 server readiness、client re-enrollment、local rollback archive 與 evidence boundary | sre |
| 2026-10-12 | DRAFT v0.2 | 仍是 DRAFT。pre_tasks 新增 gate：`ipa-client-install --uninstall` 與新 realm 的 enrollment 都會 restart sshd，`sshd -t` 失敗時在建立 archive 與任何變更之前就拒絕（之前 uninstall 的 restart 失敗會讓 sshd 停在 down、uninstall 做到一半，2026-10-12 在 freeipa-client decommission 實測）；`internal/spec/sshd_config_write_regression_test.go::TestRegression_IpaInstallersRunAfterAnSshdCheck`（allowlist 清空）與 `sshd_config_write_behavior_test.go::TestRegression_IpaInstallersCheckSshdFirst` 鎖住；實跑（含對照組）見 [`docs/evidence/sshd-config-writes/2026-10-12-2fe32c6.md`](../evidence/sshd-config-writes/2026-10-12-2fe32c6.md) | pilot |
