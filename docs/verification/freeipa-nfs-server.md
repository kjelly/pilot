# FreeIPA Kerberos NFSv4 Server Verification Spec v1.0

## 0. 目的

驗證 canonical roster 指定的 NFS server 具有 FQDN service principal、受保護 keytab、NFSv4 service、setgid/ACL 與安全 exports。

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Ansible group | `freeipa-nfs-server`（vm-target 以 `-e target_group=<exact-host>` 對齊） |
| OS | AlmaLinux 9 |
| Apply | `playbooks/apply/freeipa-nfs-server-apply.yml` |

## 1.5 依賴變數契約

`freeipa_roster_file` 必須是 canonical schema v1；`nfs_server_fqdn` 必須與 roster `nfs.servers[].host` 及主機 FQDN 一致。

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| C1 | principal | NFS service principal 存在 | ~nfs/ | klist -k /etc/krb5.keytab |
| C2 | keytab | system keytab 僅 root 可讀 | ~600 root root | stat -c '%a %U %G' /etc/krb5.keytab |
| C3 | package | NFS server package 已安裝 | 0 | rpm -q nfs-utils |
| C4 | service | NFS server service 正在執行 | active | systemctl is-active nfs-server |
| C5 | ownership | fixture share 是 setgid 且 others 不可寫 | ~2770 | stat -c '%a' /srv/nfs/projects/fixture-alpha |
| C6 | acl | access 與 default ACL 都包含 read-only group | ~default:group:data-fixture-nfs-ro:r-x | getfacl -cp /srv/nfs/projects/fixture-alpha |
| C7 | export | managed NFSv4 pseudo root 使用 `fsid=0`、`root_squash` 與 `sec=krb5i` | ~root_squash,sec=krb5i,fsid=0,crossmnt | sed -n '1,20p' /etc/exports.d/90-freeipa-managed.exports |
| C8 | safety | managed fragment 不含不安全選項 | 0 | ! grep -Eq 'no_root_squash|insecure|sec=sys|anon(uid|gid)=0' /etc/exports.d/90-freeipa-managed.exports |

## 3. 證據收集

使用 `pilot vm-target verify --name <nfs-vm> docs/verification/freeipa-nfs-server.md`，保存 NDJSON 與報告；預期 8 rows。

## 4. PASS / FAIL 規則

C1–C8 全 PASS 才通過；principal、default ACL 或 export safety 任一失敗均不可上線。

## 5. 例外與已知偏差

無。

## 6. Playbook 對應

Apply task 使用同名 C1–C8 row tags；控制平面 automount 另由 `freeipa-identity-apply.yml` C18 管理。

## 7. SOP

```bash
pilot vm-target test --name <nfs-vm> --playbook playbooks/apply/freeipa-nfs-server-apply.yml --spec docs/verification/freeipa-nfs-server.md -- -e target_group=<nfs-vm> -e freeipa_roster_file=<roster.yaml> -e nfs_server_fqdn=<fqdn>
```

## 8. 變更紀錄

- v1.0：canonical Kerberos NFSv4 server acceptance contract。
