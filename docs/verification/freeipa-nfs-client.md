# FreeIPA NFS Client Verification Spec v1.0

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

C1–C6 全 PASS 才通過；另在 topology evidence 以 `findmnt`/`nfsstat -m` 驗證實際 mount security flavor。

## 5. 例外與已知偏差

RW/RO/deny 是跨主機動態行為，放在 topology evidence，不以單機靜態 row 取代。

## 6. Playbook 對應

Apply task 使用同名 C1–C5 tags；C6 是禁止 mutation 的 verify-only safety row。

## 7. SOP

```bash
pilot vm-target test --name <client-vm> --playbook playbooks/apply/freeipa-nfs-client-apply.yml --spec docs/verification/freeipa-nfs-client.md -- -e target_group=<client-vm> -e nfs_automount_location=default
```

## 8. 變更紀錄

- v1.0：FreeIPA automount client acceptance contract。
