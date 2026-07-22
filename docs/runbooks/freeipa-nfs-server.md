# FreeIPA Kerberos NFSv4 Server Runbook

## 0. 目標

以獨立 playbook 將已 enrollment 的 Linux 主機收斂成 Kerberos NFSv4 server，管理 `nfs/FQDN` keytab、setgid/POSIX ACL 與 `/etc/exports.d/90-freeipa-managed.exports`。

## 0.5 目前有效的事實快照

- 目標：AlmaLinux 9 vm-target `freeipa-nfs-v2`，inventory 僅含同名 host；FreeIPA provider 是 `freeipa-authz-v2`。
- 對齊決定：A。NFS VM 的 `ansible_fqdn`、roster `nfs.servers[].host`、IPA host/DNS 與 principal 全部使用 `freeipa-nfs-v2.ipa.pilot.internal`。
- 外部 state：`/home/kjelly/.vault/main.yaml` 只確認存在 `ipa_admin_password` key，未保存值。
- 正式 immutable candidate（2026-07-22）：commit `9d7eeb4f29e24df28bd100867a161b170e8aca86`、tree `ea5461e6b6ac8c5fc861bea585dd6a158ee60ebb`。
- 正式結果：check `ok=14 changed=0 failed=0`；apply/idempotency 均 `ok=23 changed=0 failed=0`；server spec `8/8 PASS`；獨立 client 實際 automount 為 `nfs4,sec=krb5i`。
- Evidence：[2026-07-22 immutable candidate record](../evidence/freeipa-nfs-server/2026-07-22-9d7eeb4.md)。

## 1. 邊界與前置

這是獨立元件：

- Spec：`docs/verification/freeipa-nfs-server.md`
- Apply：`playbooks/apply/freeipa-nfs-server-apply.yml`
- Contract：`contracts/freeipa-nfs-server.yaml`
- FreeIPA control plane 前置：host object、DNS A/AAAA、filesystem groups 已由 canonical identity roster 收斂。
- NFS server 必須先由 `freeipa-client-apply.yml` enrollment；playbook 不會以 `--force` 略過 DNS/SPN 檢查。

不管理 `/etc/exports`，只管理獨立 fragment。任何 unsafe option（`no_root_squash`、`insecure`、`sec=sys`、root anon mapping）在 mutation 前 fail closed。

## 2. Roster

Canonical roster 的 `nfs.servers[]` 至少包含：

```yaml
nfs:
  servers:
    - host: nfs1.example.internal
      service_principal:
        principal: nfs/nfs1.example.internal
        keytab: /etc/krb5.keytab
      packages: [nfs-utils, acl]
      services: [nfs-server, rpc-gssd]
      shares:
        - name: project-alpha
          source_path: /srv/nfs/projects/alpha
          ownership: {owner: root, group: data-project-alpha-rw, mode: '2770'}
          export:
            clients: [{type: network, value: 10.0.0.0/24}]
            options: [rw, sync, root_squash, sec=krb5i]
```

完整 ACL/default ACL/automount schema 見 `playbooks/apply/freeipa-identity.roster.example.yaml`。

## 3. 套用與驗證

先讀 inventory 事實，再依序 check、apply、verify、第二次 apply：

```bash
pilot vm-target show-inventory --name freeipa-nfs-v2

pilot vm-target run --name freeipa-nfs-v2 playbooks/apply/freeipa-nfs-server-apply.yml \
  -e target_group=freeipa-nfs-v2 \
  -e freeipa_roster_file=/path/to/ipa-identity.yaml \
  -e nfs_server_fqdn=freeipa-nfs-v2.ipa.pilot.internal \
  -e @/path/to/vault.yaml --check --diff

pilot vm-target run --name freeipa-nfs-v2 playbooks/apply/freeipa-nfs-server-apply.yml \
  -e target_group=freeipa-nfs-v2 \
  -e freeipa_roster_file=/path/to/ipa-identity.yaml \
  -e nfs_server_fqdn=freeipa-nfs-v2.ipa.pilot.internal \
  -e @/path/to/vault.yaml

pilot vm-target verify --name freeipa-nfs-v2 docs/verification/freeipa-nfs-server.md
```

正式主機把 `show-inventory` 換成 `ansible-inventory -i <inventory> --graph`，並用同一份 inventory 跑 `ansible-playbook`。

## 4. Rollback

playbook 在 mutation 前保存 managed exports fragment；principal、ACL 或 export validation 失敗時，restore fragment、`exportfs -ra`，最後 fail loudly。它不刪除 share data，也不自動撤銷已簽發 principal；需要 decommission 時另行審核。

## 5. 踩過的雷

- 只有 `/etc/hosts` 可解析不夠：`ipa service-add nfs/FQDN` 會檢查 IPA DNS A/AAAA；缺 record 時真實回覆 `does not have corresponding DNS A/AAAA record`。修法是先收斂 IPA host/DNS，不使用 `--force`。
- Keytab 不可每次重取：重跑 `ipa-getkeytab` 會輪替 key。playbook 先 `klist -k`，只有 principal 不存在時才取回。
- ACL 必須同時設定 access 與 default entries；只設定 share root access ACL，後續新檔案不會繼承正確群組權限。
- NFSv4 pseudo-root 與 share 的父目錄必須可穿越。若把 share leaf 的 `2770`/ACL 套到 `/srv/nfs` 或中間目錄，`root_squash` 後會出現「pseudo-root 可掛載、子 export access denied」；playbook 固定 pseudo-root 與 managed share parent 為 `0755`，限制只放在 leaf。

## 6. 備份

`group_vars/restic-backup.example.yml` 提供 `/etc/exports.d`、`/srv/nfs` 與 `getfacl -R` manifest 範例。NFS 本身沒有資料庫 dump；應用需要 quiesce 時由資料擁有者在 backup pre-hook 前協調。
