# Runbook — FreeIPA realm/server replacement（client wave）

> 狀態：**DRAFT — TODO: VERIFY**。client wave 已在 disposable topology 對 immutable candidate
> 實跑（§0.5），但 rollback 不能恢復舊 realm 的登入（§3）、`--check --diff` 必定失敗等缺口仍未
> 處理；它不是可直接照做的正式 SOP。
> 對齊：[verification spec](../verification/freeipa-realm-replacement.md)、
> [migration playbook](../../playbooks/apply/freeipa-realm-replacement-apply.yml)。

## 0. 目標

在新 FreeIPA server 已重建且獨立驗證完成後，按小批次將既有 client 從舊 realm
un-enroll，再 enrollment 至新 realm。server rebuild、identity/HBAC/sudo 建立與 client
wave 是三個獨立變更，不得合併成一次不可觀察的操作。

## 0.5 目前有效的事實快照

**2026-10-13 disposable evidence snapshot**，candidate `dd69a2d`，詳見
[`docs/evidence/freeipa-realm-replacement/2026-10-13-dd69a2d.md`](../evidence/freeipa-realm-replacement/2026-10-13-dd69a2d.md)：

- targets：由 `pilot vm-target` 建立的 disposable VM（舊 realm server、兩台新 realm server、
  Ubuntu 24.04 client），非 production inventory。
- realms：`IPA.PILOT.INTERNAL`／`ipa.pilot.internal` → `NEW.EXAMPLE.TEST`／`new.example.test`。
  新 server 兩種情境：沿用舊 server 的 FQDN `ipa1.ipa.pilot.internal`，以及自己的 `ipa1.new.example.test`。
- 兩種情境的 migration 都 rc=0，`pilot verify` C1–C6 **6/6 PASS**；重跑被 completion marker gate
  擋下（設計如此）。新 server 沿用舊 FQDN 時，`/etc/hosts` 最後只有一行指向新 server；修正前的
  版本（`aa74524`）在同一個 topology 上把新 pin 跟舊 block 一起刪掉，enrollment 連不到新 server。
- AlmaLinux 9 client 最近一次通過是 candidate `9a189be`（新 server 使用自己的 FQDN），見
  [`docs/evidence/freeipa-realm-replacement/2026-10-12-9a189be.md`](../evidence/freeipa-realm-replacement/2026-10-12-9a189be.md)。
- negative path（新 realm enrollment 失敗）：rescue 還原了舊 realm 的本機檔案與 `/etc/hosts` 的舊
  pin，但舊 realm 的身分仍查不到（見 §3）。
- `--check --diff` 目前必定在「expose archive through a stable root-only link」失敗（check mode 不會建立
  archive），rescue 訊息並不代表真的還原過。
- archive 檔名取自 fact cache 的 `ansible_date_time`（一小時），一小時內重跑會沿用同一個檔名。
- alignment decision：A（為 evidence 建立 disposable targets）；vault 只使用
  `ipa_admin_password`，不在文件或摘要中記錄值。

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

playbook 會依序：確認 client 仍在宣告的 old realm → 建立 root-only archive → 確認新 server
的 443 可達 → 讀取舊 realm 的 server 清單 → `ipa-client-install --uninstall`（仍連舊 server）→
移除舊 domain 的 SSSD Kerberos realm mapping 與 `/etc/hosts` 裡舊 realm 的 server pin → pin 新
server → 以新座標重新 enroll → 等待 SSSD 解析新 realm 帳號 → 寫入不含密碼的 completion marker。

新 server 沿用舊 server 的 FQDN 時：
- 該 FQDN 原本在 `PILOT FREEIPA SERVER POOL` block 裡；新 pin 必須在 block 移除之後才寫入，否則
  會跟著 block 一起被刪掉。
- uninstall 會停掉 SSSD，但留下 SSSD 為舊 domain 寫的
  `/var/lib/sss/pubconf/krb5.include.d/domain_realm_<domain>`（krb5.conf 經
  `/etc/krb5.conf.d/enable_sssd_conf_dir` 引入），它把舊 DNS domain 對到舊 realm；不移除時，新
  enrollment 會向新 KDC 要舊 realm 的 cross-realm ticket 而失敗。

每個正式命令都仍是 **TODO: VERIFY**；在 candidate 實跑完成前，請從 spec 的變數契約將
已驗證的精確命令、實際 PLAY RECAP 與 evidence link 取代進來。不得以本草稿推測參數或
輸出。

## 3. Rollback boundary

任何 enrollment 失敗都會嘗試自動解壓舊的 `/etc/ipa`、Kerberos keytab、SSSD、nsswitch 與
hosts snapshot，然後重啟 SSSD。這只是**本機組態 rollback**，即使舊 FreeIPA server 仍在運作，
也不能恢復登入：`ipa-client-install --uninstall` 會在舊 server 上對這台 host 執行 `host_disable`，
舊的 host key 因此失效，還原回來的 keytab 無法再向舊 KDC 取得 TGT，SSSD 停在 Offline（2026-10-12
實跑確認）。讓這台 client 回到舊 realm 需要另外處理（例如對舊 realm 重新 enroll，尚未實跑驗證）；
若舊 server 已經重裝或退役，舊 host principal/CA/trust 已不在，還原檔案更不可能恢復登入。

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
