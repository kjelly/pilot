# Runbook — `pilot vm-target` (QEMU/KVM VM as a disposable target host)

> 撰寫日期：2026-06-30 (UTC)
> 對齊規範：見 `internal/vmtarget/vmtarget.go`、`internal/vmtarget/domainxml.go` 與 `cmd/pilot/cmd/vm_target.go`
> 維護者：sre

---

## 0. 一句話目標

> **`docker-target` 的高保真版**：用一台真 KVM 虛擬機當 disposable ansible target。
> 容器共享 host kernel 測不準的東西（kernel module、reboot/bootloader、LVM/檔系統、
> SELinux enforcing、真網卡），VM 都能測。代價是開機慢一點、host 要有 `/dev/kvm`。

跟 `docker-target` 共用同一套子命令形狀（up/down/list/run/verify/exec/snapshot/rollback），
差別只在 connection plugin：vm-target 產生的 inventory 是 `ansible_connection: ssh`，
所以**實際的 ansible 工作走的是既有、已驗證的 SSH 路徑**。

---

## 1. 什麼時候用 vm-target（vs docker-target）

| 你的 playbook 動到… | docker-target 夠用？ | 要 vm-target？ |
|---|---|---|
| package / config file / systemd service | ✅（記得 `--systemd`） | 不必 |
| 載入 kernel module、`sysctl` 一部分 | ✗ 共享 kernel | ✅ |
| 真正 `reboot` / bootloader / GRUB / initramfs | ✗ | ✅ |
| LVM / 磁碟分割 / filesystem / swap | ✗ | ✅ |
| SELinux enforcing、完整 nftables、多網卡 | ✗ | ✅ |

**只動 service/config 就別開 VM**——docker-target 更快更輕。

---

## 2. 前置需求

```bash
# host 要有這些（本機已驗證）：
virsh qemu-img cloud-localds ssh ssh-keygen qemu-system-x86_64
[ -e /dev/kvm ]                       # nested virt；CI runner 常常沒有
virsh net-list --all | grep default   # 一個 active 的 libvirt NAT 網路

# 一份 qcow2 cloud image 當 base（read-only backing），例如：
#   https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-amd64.img
```

### 2.1 儲存目錄權限（重要）

per-target 的 `overlay.qcow2` / `seed.iso` 預設放在 `--vm-dir`
（default `/var/lib/libvirt/images/pilot`）。這個位置 **qemu(libvirt-qemu) 必須能存取**：

```bash
sudo mkdir -p /var/lib/libvirt/images/pilot
sudo chown "$USER":"$USER" /var/lib/libvirt/images/pilot
sudo chmod 0755 /var/lib/libvirt/images/pilot
# 父目錄 /var/lib/libvirt/images 是 0711 root → libvirt-qemu 可 traverse；
# disk 檔由 libvirt 的 dynamic-ownership 在 start 時自動 chown 給 qemu。
```

> 不要把 `--vm-dir` 指到 `$HOME` 深處：libvirt 的 AppArmor profile 通常擋掉
> 家目錄路徑，VM 會起不來。

---

## 3. 一次完整操作流程

```bash
export BASE=/var/lib/libvirt/images/pilot/noble-base.qcow2

# 3.1 起 VM（會 provision + 等開機 + 等 SSH 通才回）
pilot vm-target up --base-image "$BASE" --name infra-vm --ssh-user root
# ▶ provisioning VM infra-vm (this can take a minute while it boots)…
# ✓ target infra-vm up
#   ip        : 192.168.123.90
#   ssh_user  : root
#   inventory : `pilot vm-target show-inventory --name infra-vm`

# 3.2 exec（走 SSH，no host shell）
pilot vm-target exec --name infra-vm -- uname -r
pilot vm-target exec --name infra-vm -- sh -c 'lsmod | head'

# 3.3 跑 playbook（自動帶 -i <ssh-inventory> -l infra-vm）
pilot vm-target run --name infra-vm -- playbooks/apply/<x>.yml -e ...

# 3.4 spec 驗證
pilot vm-target verify --name infra-vm -- docs/verification/<x>.md

# 3.5 snapshot / rollback（libvirt qcow2 snapshot；correct-by-construction）
pilot vm-target snapshot --name infra-vm --tag baseline
# ... 玩壞了 ...
pilot vm-target rollback --name infra-vm --tag baseline   # 連 disk state 一起還原

# 3.6 拆掉（destroy + undefine + 刪 overlay/seed + 清 state）
pilot vm-target down --name infra-vm
```

預設值：`--ssh-user root`、`--vcpus 2`、`--memory 2048`、`--network default`。

### 3.7 多機一鍵鏈：`topology test`（2026-07-18 實跑過）

多機情境(site.yml、跨 host 角色)用 `vm-target topology test` 一條命令跑完
「全 cluster snapshot → apply → 逐 spec verify → 冪等 → 失敗全 node
rollback」。首次實跑用的 smoke 拓樸(2 台 ubuntu-24.04,各 2GB/2vcpu):

```yaml
# topo-smoke.yaml
nodes:
  - name: topo-docker
    base_image: ubuntu-24.04
    memory: 2048
    vcpus: 2
    groups: [docker]
  - name: topo-log
    base_image: ubuntu-24.04
    memory: 2048
    vcpus: 2
    groups: [log-server]
```

```bash
pilot vm-target topology up   --topology topo-smoke.yaml
pilot vm-target topology test --topology topo-smoke.yaml \
    --playbook playbooks/site.yml \
    --verify docs/verification/docker.md=docker \
    --verify docs/verification/log-server.md=log-server \
    --verify-timeout 90
```

這次(2026-07-18)實跑的輸出摘要——site.yml 對 topology inventory 全站套用,
空 group 自動跳過,只有填了機器的 docker/log-server 真的套:

```
=== [Step 1/5] L1 Syntax Check ===
✓ Syntax check passed
=== [Step 2/5] Cluster snapshot: 2 node(s) (tag: pre-test-1784332883) ===
✓ Cluster snapshot created
=== [Step 3/5] L4 Apply Playbook (topology inventory) ===
✓ Playbook apply completed
=== [Step 4/5] L5 Verification Specs (2) ===
verdict: **PASS**  (pass=8 fail=0 skip=0)     # docker.md @ docker group
verdict: **PASS**  (pass=12 fail=0 skip=0)    # log-server.md @ log-server group
=== [Step 5/5] L6 Idempotency Check ===
PLAY RECAP *********************************************************************
topo-docker                : ok=13   changed=0    ...
topo-log                   : ok=18   changed=0    ...
✓ Idempotency check passed (changed=0)
🎉 ALL TESTS PASSED SUCCESSFULLY!
```

同一天的第一輪跑就真的抓到一個 site.yml 組合 bug 並實測了 auto-rollback:
log-shipping-apply.yml 在「純 rsyslog、沒裝 docker」的 log-server 上無條件跑
`docker_container_info`,整個全站 apply 炸掉 → topology test 自動把兩台 node
全部 rollback 回 pre-test snapshot(✓ Rollback successful)。修法:log-shipping
加「無 Loki 目標就 end_host 乾淨跳過」+「docker info fail-early gate」兩道
pre_tasks(見該 playbook 檔頭與 site.yml 註解)。

---

## 4. correct-by-construction 設計（為什麼這條路寫得出正確的程式）

1. **不可變 base + per-target overlay**：base qcow2 唯讀，所有寫入落在
   `<dir>/overlay.qcow2`。每次 `up` 都是乾淨基底；rollback 還原 disk state
   是 libvirt 保證的精確還原（已用「建檔 → rollback → 檔案消失」E2E 驗證）。
2. **宣告式 provisioning**：cloud-init NoCloud seed 只注入 SSH 公鑰 + hostname，
   同輸入同結果。
3. **權威 IP，不用猜**：開機後問 libvirt（`virsh domifaddr --source lease`）拿
   dnsmasq 真實 lease，消掉「它拿到哪個 IP」的 race。
4. **固定 MAC**：由 name 雜湊出 `52:54:00:xx:xx:xx`，同 target 永遠同一個 lease。
5. **新風險面最小化**：新 code 只負責「生 VM + 等開機 + 給 (ip,user,key)」，
   接出來餵給既有 `ansible_connection: ssh` 路徑，ansible 那套完全沒動。

---

## 5. 踩過的坑（已寫進 code 註解 + 回歸測試，別再踩）

### 5.1 cloud-init seed 一定要走 **virtio disk**，不能用 cdrom ⚠️

`domainxml.go` 把 seed 掛成 **read-only virtio disk (`vdb`)**，不是 SATA/IDE cdrom。

> **症狀**：用 cdrom 時，q35 的 AHCI/sr 驅動在 early boot（cloud-init-local 跑
> `ds-identify` 時）還沒 ready → 找不到 datasource → **cloud-init 整個 boot 被
> 靜默停用** → 沒網路設定、沒 SSH key、沒 DHCP lease → `up` 卡 3 分鐘 timeout
> 且零線索。virtio-blk 一開機就在 → `ds-identify` 一定看得到 `cidata` label。
>
> 回歸測試：`TestRenderDomainXML_HasKeyBits`（assert `dev='vdb' bus='virtio'`
> 且不得出現 `device='cdrom'`）。

### 5.2 `undefine` 一定要帶 `--snapshots-metadata` ⚠️

`teardown` 用 `virsh undefine <name> --snapshots-metadata --managed-save --nvram`。

> **症狀**：只要 domain 被 snapshot 過，`virsh undefine`（不帶 flag）會拒絕，
> 而 teardown 又把錯誤吞掉 → `down` 之後留下一個**指向已刪 disk 的 dangling
> domain**。E2E 第一次就踩到（"DOMAIN STILL EXISTS"）。
>
> 回歸測試：`TestDown_UndefineClearsSnapshotMetadata`。

### 5.3 `up` 失敗一定要清乾淨

`Up` 在拿到 IP / SSH 前的任何一步失敗，deferred teardown 會
destroy+undefine+刪 dir。注意 cleanup 綁的是 local build target，不是 named
return——`return nil, err` 不能把 teardown 的對象 null 掉（這個 nil-deref 也被
測試抓到了：`TestUp_CleansUpOnBootTimeout`）。

---

## 6. State 檔在哪

- metadata（json）：`$DataDir/vm-targets.json`（versioned + atomic save，同 docker-target）
- 磁碟/seed/key：`--vm-dir/<name>/`（`overlay.qcow2` / `seed.iso` / `id_ed25519`）

---

## 7. 已知限制 / 後續可做

| 限制 | 影響 | 解法 / 後續 |
|------|------|------|
| 需要 `/dev/kvm` | CI runner 常常沒有 nested virt | 挑有 KVM 的 runner；或 CI 走雲 VM |
| 開機 ~30–60s | 比 docker exec 慢很多 | 對需要 kernel 保真才用；batch 注意資源 |
| base image 要自備 + qcow2 | minimal image 的 cloud-init 行為有雷 | 建議用 **standard** server cloudimg（非 minimal） |
| 沒有 pre-bake/golden image 流程 | 每次靠 cloud-init 裝東西 | 後續可加 `vm-target build`（packer / virt-customize 烤 golden image），對齊 docker 的 `--image-pilot` |
| 單 host | 一個 target = 一台 VM | `--hosts` alias 已支援（多 inventory key 指同一台）；真多機拓樸走 `vm-target topology`（宣告式 spec，up/inventory/snapshot/rollback/reset/test 全套，實跑範例見 `docs/runbooks/freeipa-server-replica-ha-drill.md`） |

---

## 8. 測試覆蓋

- `internal/vmtarget/vmtarget_test.go`：shim 化全部外部指令（`PILOT_VIRSH_BIN` /
  `PILOT_QEMU_IMG_BIN` / `PILOT_CLOUD_LOCALDS_BIN` / `PILOT_SSH_BIN` /
  `PILOT_SSH_KEYGEN_BIN`），不需要 hypervisor 就能跑 up/down/get/list/exec/
  snapshot/rollback/inventory + 上述三個回歸坑。
- `cmd/pilot/cmd/vm_target_test.go`：CLI 註冊 + flag 驗證。
- **真實 E2E（本機 KVM）已驗證**：up → exec(ssh) → `vm-target run` 跑 ansible
  （gather facts + **載入 `dummy` kernel module** + systemd module，`ok=6 failed=0`）
  → snapshot/mutate/rollback（mutation 消失）→ down（domain+dir 皆清乾淨）。

---

## 9. 變更紀錄

| 日期 | 版本 | 變更 |
|------|------|------|
| 2026-06-30 | v1.0 | 初版：QEMU/KVM vm-target（up/down/list/show-inventory/run/verify/exec/snapshot/rollback），cloud-init NoCloud + qcow2 overlay + 權威 IP；修 virtio-seed / undefine-snapshots-metadata / up-cleanup 三個坑 |
