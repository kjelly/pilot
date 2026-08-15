# FreeIPA NFS Client Verification Spec v1.2

## 0. 目的

驗證 enrolled Linux client 透過 FreeIPA automount 取得 Kerberos NFSv4 map，且不寫入 `/etc/fstab`。

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Ansible group | `freeipa-nfs-client`（vm-target 以 `-e target_group=<exact-host>` 對齊） |
| OS | AlmaLinux 9 / Ubuntu 24.04 |
| Apply | `playbooks/apply/freeipa-nfs-client-apply.yml` |

## 1.5 依賴變數契約

主機必須已由 `freeipa-client-apply.yml` enrolled；`nfs_automount_location` 預設 `default`。

**新增 v1.1**：`freeipa_roster_file` 現在是**必要**變數（跟 `freeipa-nfs-server-apply.yml` 同一份 canonical
roster）。這個 apply playbook 現在是資料驅動的：套用前會先讀 roster 頂層的 `nfs_clients[]`，把
`hostgroup` 欄位（直接成員 + 至多一層 nested hostgroup）解析成真實主機清單，並要求「這台主機的真實 FQDN
必須落在某一筆 `state: present` 的 `nfs_clients` entry 的解析結果裡」，否則直接 fail-closed——單靠把主機
放進 `freeipa-nfs-client` inventory group 已經不夠。這筆 entry 的 `automount.location`/
`automount.enable_service` 現在也會覆蓋 `nfs_automount_location`/是否啟用 autofs 服務。

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | enrollment | FreeIPA client enrollment 存在 | 0 | test -f /etc/ipa/default.conf |
| C2 | package | autofs 已安裝 | 0 | sh -c 'command -v automount >/dev/null' |
| C3 | sssd | SSSD 啟用 autofs responder | ~autofs | grep -E '^services =.*autofs' /etc/sssd/sssd.conf |
| C4 | source | automount source 指向 SSSD/IPA | ~sss | grep -E '^automount:.*sss' /etc/nsswitch.conf |
| C5 | service | autofs 正在執行 | active | systemctl is-active autofs |
| C6 | safety | `/etc/fstab` 沒有 managed NFS share | 0 | ! grep -Eq 'nfs4|sec=krb5' /etc/fstab |

## 3. 證據收集

使用 `pilot vm-target verify --name <client-vm> docs/verification/freeipa-nfs-client.md`；預期 6 rows。

## 4. PASS / FAIL 規則

C1–C6 全 PASS 才通過。

**修正 v1.1**：mount security flavor 驗證原本完全交給 topology evidence 手動用 `findmnt`/`nfsstat -m`
確認，現在改為 apply playbook 自己的 `nfs-client-verify-mount-trigger`/`nfs-client-verify-mount-check`
兩個 tagged task 自動做（對 roster 該筆 `nfs_clients` entry 宣告的每個 `verification_mounts` 路徑，先
存取觸發 autofs 掛載，再用 `findmnt` 確認真的是 `nfs4` + `sec=krb5*`）——這兩個 tag **刻意不是
row-shaped**（不對應本檔任何一個 `Cx` row，也不需要對應，因為觸發路徑本身是 roster 專屬資料，不是每台
`freeipa-nfs-client` 主機共有的固定屬性；見 `tag_coverage_test.go` 的 orphan-tag 規則，只有 row-shaped
tag 才需要對應到 spec row）。topology evidence 仍可額外手動用 `findmnt`/`nfsstat -m` 交叉確認，但不再是
唯一驗證管道。

**修正 2026-08-15（round 25 現場發現）**：`nfs-client-verify-mount-check` 這個 task 帶
`ignore_errors: true`，**不會**讓這台主機的失敗往下擴散、擋掉 `site.yml` 剩下的所有 play。原因：這個
check 真正需要的兩個前置條件——IPA automount map/key（只有另外跑的 `freeipa-identity` day-2 reconcile
才會建立）、以及 NFS server FQDN 真的能被解析（需要另外跑的 `freeipa-dns-client` day-2 角色）——在單純跑
一次 `site.yml` 的時候都不保證存在，因為這兩者在這個專案既有的重建順序裡都排在 `site.yml` **之後**。第一
次實跑（round 25）在沒有 `ignore_errors` 的情況下，這個 task 的失敗讓 `client-vm` 被 Ansible 預設行為
排除在該次執行剩下的所有 play 之外，導致 `host-monitoring`/`wazuh-fim`/`restic-backup`/
`audit-log-forwarding` 全部靜默沒套用。因此這個 check 的最終判定會出現在 recap 的 `ignored=`，不是
`failed=`——真正要看它有沒有過，讀 task 本身的輸出（或另外對 `findmnt` 結果做 topology evidence 檢查），
不要只看 recap 的 `failed=0`。

## 5. 例外與已知偏差

RW/RO/deny 是跨主機動態行為，放在 topology evidence，不以單機靜態 row 取代。

## 6. Playbook 對應

Apply task 使用同名 C1–C5 tags；C6 是禁止 mutation 的 verify-only safety row。新增 v1.1：
`nfs-client-verify-mount-trigger`/`nfs-client-verify-mount-check`（非 row-shaped，見上）。

## 7. SOP

```bash
pilot vm-target test --name <client-vm> --playbook playbooks/apply/freeipa-nfs-client-apply.yml --spec docs/verification/freeipa-nfs-client.md -- -e target_group=<client-vm> -e freeipa_roster_file=<roster.yaml>
```

`freeipa_roster_file` 指向的 roster 必須含一筆 `nfs_clients` entry，其 `hostgroup`（直接或一層 nested）
解析結果要包含 `<client-vm>` 的真實 FQDN，否則 apply 會在新增的 gate 直接 fail-closed（見 §1.5）。

## 8. 變更紀錄

- v1.0：FreeIPA automount client acceptance contract。
- v1.1（2026-08-14）：`nfs_clients[]` 從「roster 接受但完全沒有任何程式讀取」的死欄位，補齊成真正的
  targeting 依據（hostgroup 解析 + fail-closed gate）與 `verification_mounts` 自動驗證
  (`freeipa-config.md` §14.3 步驟 7–8)。`freeipa_roster_file` 從此是必要變數。尚未對真實 VM 實跑驗證，
  見 `docs/runbooks/minimal-poc-architecture.md` 待辦的合併後 round。
- v1.2（2026-08-15，round 25 首次真實 VM 實跑）：修 2 個現場發現的真 bug——(a) fail-closed gate 原本沒
  加 `when: not ansible_check_mode`，導致全新、尚未真正 enroll 的主機在第一次 `--check` preview 就會誤
  fail-close（`hostname --fqdn` 在真正 enroll 前只會回短主機名，不會等於 roster 宣告的 FQDN）；比照
  `freeipa-nfs-server-apply.yml` 自己的同類 gate 補上 `when: not ansible_check_mode` + 對應的
  `nfs_client_matches | length > 0` 空清單防呆。(b) `nfs-client-verify-mount-check` 補上
  `ignore_errors: true`——這個 check 真正需要的兩個前置條件（IPA automount map/key 由另一個
  `freeipa-identity` day-2 reconcile 建立；NFS server FQDN 能被解析需要另一個 `freeipa-dns-client`
  day-2 角色）在單純跑一次 `site.yml` 時都不保證存在，沒加這個之前，第一次現場實跑讓失敗把
  `client-vm` 剩下的所有 site.yml play 都靜默排除掉。見 §4 修正說明。
