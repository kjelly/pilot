# Runbook — FreeIPA realm/server replacement（client wave）

> 狀態：**DRAFT — TODO: VERIFY**。client wave 與 rollback 已在 disposable topology 對 immutable
> candidate 實跑（§0.5），但 `--check --diff` 必定失敗、archive 名稱可能重複等缺口仍未處理；
> 它不是可直接照做的正式 SOP。
> 對齊：[verification spec](../verification/freeipa-realm-replacement.md)、
> [migration playbook](../../playbooks/apply/freeipa-realm-replacement-apply.yml)。

## 0. 目標

在新 FreeIPA server 已重建且獨立驗證完成後，按小批次將既有 client 從舊 realm
un-enroll，再 enrollment 至新 realm。server rebuild、identity/HBAC/sudo 建立與 client
wave 是三個獨立變更，不得合併成一次不可觀察的操作。

## 0.5 目前有效的事實快照

**2026-10-12 disposable evidence snapshot**，candidate `b9d82d9`，詳見
[`docs/evidence/freeipa-realm-replacement/2026-10-12-b9d82d9.md`](../evidence/freeipa-realm-replacement/2026-10-12-b9d82d9.md)：

- targets：四台由 `pilot vm-target` 建立的 disposable VM（舊 realm server、新 realm server、
  Ubuntu 24.04 client、AlmaLinux 9 client），非 production inventory。
- realms：`IPA.PILOT.INTERNAL`／`ipa.pilot.internal` → `NEW.EXAMPLE.TEST`／`new.example.test`；
  server FQDN：`ipa1.ipa.pilot.internal` → `ipa1.new.example.test`。
- rollback：兩台 client 在兩種失敗點（新 realm enrollment 失敗；enrollment 完成後 C5 失敗）都由
  rescue 重新 enroll 回舊 realm；之後舊 realm 的 `admin` 能以密碼 SSH 登入，`freeipa-client.md`
  12/12。修正前的版本（`aa74524`）同樣的 rollback 之後登入失敗、10/12。
- 舊 server 在 rescue 重新 enroll 時無法使用：rescue 改為還原整個 archive，並回報舊 realm 的登入
  路徑無法使用、需人工重新 enroll。
- migration：rollback 過的兩台 client 再跑 migration，rc=0，`pilot verify` C1–C6 各 **6/6 PASS**；
  重跑被 completion marker gate 擋下（設計如此）。舊 server 上的 host entry 仍啟用（§4）。
- `--check --diff` 目前必定在「expose archive through a stable root-only link」失敗（check mode 不會建立
  archive）。
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
的 443 可達 → 記錄舊 enrollment 的 domain、host 與 server（缺任何一項就停止）→ 用 `ipa-rmkeytab`
從 keytab 移除舊 realm 的 key（archive 仍保留）→ `ipa-client-install --uninstall`（仍連舊 server）
→ 移除 `/etc/hosts` 裡舊 realm 的 server pin → pin 新 server → 以新座標重新 enroll → 等待 SSSD
解析新 realm 帳號 → 寫入不含密碼的 completion marker（含 `old_host_still_enabled`）。新 server 沿用
舊 server 的 FQDN 時，該 FQDN 原本在 `PILOT FREEIPA SERVER POOL` block 裡；新 pin 必須在 block
移除之後才寫入，否則會跟著 block 一起被刪掉。

uninstall 會用 keytab 裡的 host key 對舊 server 執行 `ipa-join --unenroll`（`host_disable`）。
先移除舊 realm 的 key，這一步就無法認證：uninstall 記下
`Unenrolling host failed: Error obtaining initial credentials: Key table entry not found.`
後照常完成，舊 host 在舊 server 上維持有效，rollback 才能用 archive 裡的 keytab 重新 enroll。

每個正式命令都仍是 **TODO: VERIFY**；在 candidate 實跑完成前，請從 spec 的變數契約將
已驗證的精確命令、實際 PLAY RECAP 與 evidence link 取代進來。不得以本草稿推測參數或
輸出。

## 3. Rollback boundary

migration block 裡任何一步失敗，rescue 會看 `/etc/ipa/default.conf` 目前的 realm：

- 仍是舊 realm（uninstall 之前就失敗）：只解壓 archive（`/etc/ipa`、Kerberos 設定與 keytab、
  SSSD、nsswitch、hosts），然後啟用並重啟 SSSD。
- 不是舊 realm（uninstall 之後失敗）：只解壓 archive 不夠，因為 uninstall 也還原了 authselect/PAM、
  hostname、SSSD 與 sshd 的 IPA 設定、CA 信任與 installer 自己的狀態，並停用 SSSD。所以 rescue 會：
  1. 若新 realm 已 enroll，先 `ipa-client-install --uninstall` 移除；
  2. 從 archive 放回舊 server 的 pin；
  3. 把 archive 裡的 keytab 解到 `tempfile` 建立的私有目錄，用
     `ipa-client-install --keytab` 以舊 enrollment 的 domain、realm、host 與 server 重新 enroll
     （選項與 `freeipa-client-apply.yml` 相同）；
  4. 把 archive 解回這次 enrollment 上（keytab 除外：重新 enroll 已換了新 key），刪除暫存目錄，
     啟用並重啟 SSSD。

  2026-10-12 在 Ubuntu 24.04 與 AlmaLinux 9 實跑：rollback 之後舊 realm 的 `admin` 能以密碼 SSH
  登入，`freeipa-client.md` 12/12。

重新 enroll 需要舊 server 仍在運作、舊 host entry 仍有效。重新 enroll 失敗時（例如舊 server 已停止），
rescue 會解壓整個 archive（含 keytab），並在失敗訊息寫明舊 realm 的登入路徑無法使用、需人工重新
enroll。若舊 server 已經重裝或退役，舊 host principal/CA/trust 已不在，client 端無法恢復。

因此 server replacement 的安全 rollback 是在第一個 client wave 前保留可運作的舊 server
（或可驗證的 server-level restore），而不是依賴 client archive。新 server 或 client
wave 失敗時停止後續 wave、保留 raw evidence 與 archive，並由變更核准者決定恢復舊 server
或修復新 server；不得刪除 archive 後重跑。

## 4. 驗收與推進

canary 必須以 [verification spec](../verification/freeipa-realm-replacement.md) 的 C1–C6 全部
PASS，並額外驗證站台實際使用的 HBAC/sudo/NFS overlay，才可進入下一個 wave。每個 wave 都
要有自己的 immutable candidate evidence；不得將 canary 的結果套用到不同 inventory 或不同
realm/server 內容。

migration 成功後，舊 server 上這台 client 的 host entry 仍啟用，archive 裡的舊 keytab 也仍可在舊
realm 認證；completion marker 的 `old_host_still_enabled` 記錄了它的 principal。這是 rollback 能運作
的前提，也是刻意保留的狀態：wave 被接受、不再需要 rollback 之後，在舊 realm 以 admin 身分對每台
已完成的 client 執行 `ipa host-disable <old-host-fqdn>`（2026-10-12 實跑：輸出
`Disabled host "<old-host-fqdn>"`，之後 `ipa host-show` 為 `Keytab: False`），或直接退役舊 server。

## 5. 已知限制

- 本 migration 不會重建新 server 的 identity roster；那必須先由 `pilot reconcile` 或已核准的
  server-side workflow 完成。
- 不會自動重套 FreeIPA NFS client/server overlay。重新 enrollment 後，依其獨立 spec 驗收。
- completion marker 存在時故意拒絕第二次 destructive run；這是避免重複 un-enroll 破壞可鑑識
  rollback material 的 safety boundary。
