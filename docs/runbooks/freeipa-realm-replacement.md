# Runbook — FreeIPA realm/server replacement（client wave）

> 狀態：**DRAFT — TODO: VERIFY**。本 runbook 尚未完成 immutable candidate 的三節點
> 實跑、rollback 與 negative-path evidence；它不是可直接照做的正式 SOP。
> 對齊：[verification spec](../verification/freeipa-realm-replacement.md)、
> [migration playbook](../../playbooks/apply/freeipa-realm-replacement-apply.yml)。

## 0. 目標

在新 FreeIPA server 已重建且獨立驗證完成後，按小批次將既有 client 從舊 realm
un-enroll，再 enrollment 至新 realm。server rebuild、identity/HBAC/sudo 建立與 client
wave 是三個獨立變更，不得合併成一次不可觀察的操作。

## 0.5 目前有效的事實快照

**2026-07-29 disposable evidence snapshot（仍未通過）**：

- targets：`realm-replace-old`（old server，`192.168.122.3`）、
  `realm-replace-new`（new server，`192.168.122.2`）、`realm-replace-client`
 （client，`192.168.122.6`）。三者由 `pilot vm-target` 建立，非 production inventory。
- realms：`OLD.EXAMPLE.TEST`／`old.example.test` →
  `NEW.EXAMPLE.TEST`／`new.example.test`；server FQDN：
  `ipa1.old.example.test` → `ipa1.new.example.test`。
- old/new server `ipa` 服務均可啟動；client migration 已實際寫入 new
  `/etc/ipa/default.conf` 且 host keytab `kinit -k` 成功。
- acceptance 尚未 PASS：client 的 SSSD backend 仍為 Offline，`getent passwd
  admin@new.example.test` rc=2；backend log 顯示 `Cannot get a TGT`／`Bad address`
  與 LDAP connection failure。此結果保存在 vm-target transcript（例如
  `/var/lib/libvirt/images/pilot/realm-replace-client/runs/20260729T065052Z-freeipa-client-apply.log`）及
  `.verification/freeipa-realm-replacement-*`；因此不能把本輪當成成功 migration evidence。
- alignment decision：A（為 evidence 建立三台 disposable targets）；vault 只使用
  `ipa_admin_password`，不在文件或 transcript 摘要中記錄值。

## 1. 變更前不可省略的條件

1. 新 server 必須已完成自己的 install/verify，並已建立 client wave 所需的帳號、host
   records、HBAC、sudo rules、CA/DNS/NTP 前提及（如適用）automount 資料。
2. 選定一台 canary client；保有可用的本機 root/break-glass 登入。不要把唯一管理跳板當
   第一台。
3. 為本次 wave 提供唯一的變更單識別與 vault-backed 新 realm admin 密碼。migration
   playbook 預設 fail-closed，沒有 `freeipa_realm_replacement_confirm=true` 不會 un-enroll。
4. `freeipa_realm_replacement_old_realm` 必須不同於 new realm，且 new realm 必須等於
   new domain 的大寫值。此限制刻意防止把一般 client reapply 誤當成 migration。

## 2. 執行模型

playbook 會依序：確認 client 仍在宣告的 old realm → 建立 root-only archive → pin 新 server
→ 確認新 server 的 443 可達 → `ipa-client-install --uninstall` → 以新座標重新 enroll →
等待 SSSD 解析新 realm 帳號 → 寫入不含密碼的 completion marker。

每個正式命令都仍是 **TODO: VERIFY**；在 candidate 實跑完成前，請從 spec 的變數契約將
已驗證的精確命令、實際 PLAY RECAP 與 evidence link 取代進來。不得以本草稿推測參數或
輸出。

## 3. Rollback boundary

任何 enrollment 失敗都會嘗試自動解壓舊的 `/etc/ipa`、Kerberos keytab、SSSD、nsswitch 與
hosts snapshot，然後重啟 SSSD。這只是**本機組態 rollback**：若舊 FreeIPA server 已經
重裝或退役，舊 host principal/CA/trust 已不在，還原檔案不能恢復登入。

因此 server replacement 的安全 rollback 是在第一個 client wave 前保留可運作的舊 server
（或可驗證的 server-level restore），而不是依賴 client archive。新 server 或 client
wave 失敗時停止後續 wave、保留 raw evidence 與 archive，並由變更核准者決定恢復舊 server
或修復新 server；不得刪除 archive 後重跑。

## 4. 驗收與推進

canary 必須以 [verification spec](../verification/freeipa-realm-replacement.md) 的 C1–C6 全部
PASS，並額外驗證站台實際使用的 HBAC/sudo/NFS overlay，才可進入下一個 wave。每個 wave 都
要有自己的 immutable candidate evidence；不得將 canary 的結果套用到不同 inventory 或不同
realm/server 內容。

## 5. 已知限制

- 本 migration 不會重建新 server 的 identity roster；那必須先由 `pilot reconcile` 或已核准的
  server-side workflow 完成。
- 不會自動重套 FreeIPA NFS client/server overlay。重新 enrollment 後，依其獨立 spec 驗收。
- completion marker 存在時故意拒絕第二次 destructive run；這是避免重複 un-enroll 破壞可鑑識
  rollback material 的 safety boundary。
