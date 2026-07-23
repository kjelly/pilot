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
pilot 會在每個新 VM 的私有目錄上加最小 ACL（目錄 traverse、overlay 讀寫、seed ISO 唯讀），
因此不需要把 VM artifact 設成 world-readable 或 world-writable：

```bash
sudo mkdir -p /var/lib/libvirt/images/pilot
sudo chown "$USER":"$USER" /var/lib/libvirt/images/pilot
sudo chmod 0755 /var/lib/libvirt/images/pilot
# 父目錄 /var/lib/libvirt/images 是 0711 root → libvirt-qemu 可 traverse；
# pilot 對每個新 target 的私有 artifact 加 ACL，供 QEMU 存取。
```

> 不要把 `--vm-dir` 指到 `$HOME` 深處：libvirt 的 AppArmor profile 通常擋掉
> 家目錄路徑，VM 會起不來。

### 2.2 先起 `pilot services`，讓每台 VM 從第一次開機就走快取（建議預設做）

會重複起停同一批 VM（迭代開發、CI、重跑 spec）就該先起 host-side 快取，
不然每次 `apt install` / `docker pull` 都直接打公網，浪費頻寬也拖慢每一輪：

```bash
pilot services up --profile dev-lite   # 一次性、長駐；起 apt-cacher-ng + Pulp RPM + Harbor
pilot services status                  # 看 running/bind_ip/各服務健康狀態
```

服務資料放在 host（預設 `~/.local/share/pilot/cache/`），跟 VM 的 qcow2/state
分開；VM `down` 不會動到快取內容。起好之後，`vm-target up`/`topology` 帶
`--services local`（或 topology YAML 根層 `services: local`），新 VM 從
cloud-init 階段就把 APT/DNF repo 與 Docker Hub/Harbor proxy 指到這組本地快取：

```bash
pilot vm-target up --base-image "$BASE" --name infra-vm --ssh-user root \
  --services local
```

**fail-closed，不會偷偷退回公網**：沒先 `pilot services up`、服務不健康、或
選定的 libvirt network 探測不到 gateway，`--services local` 會直接讓 `up` 報錯
中止，而不是拿一台沒接快取的 VM 頂替。不需要快取（一次性、跑完即丟的 VM）就用
預設值 `--services none`。

```bash
pilot services down             # 停容器、保留快取資料（下次 up 重用）
pilot services purge --confirm  # 唯一會真的刪快取資料的動作
```

> **驗收狀態（2026-07-23）**：host 端 lifecycle（`up`/`status`/`down`/`purge`）
> 與 `vm-target`/`topology` 的 fail-closed 串接已實作並在 libvirt `default`
> network 上跑過健康檢查；VM 內實際透過快取安裝套件、拉 image 的完整
> disposable-VM 驗收（見 `docs/superpowers/specs/2026-07-23-host-local-services-design.md`
> 的 Task 8）仍待跑。跑完並補上真實 evidence 前，把 `--services local` 當
> 「省頻寬的建議預設」，別當成已驗收的路徑寫進 spec 的 Expected 行為。

---

## 3. 一次完整操作流程

```bash
export BASE=/var/lib/libvirt/images/pilot/noble-base.qcow2

# 3.1 起 VM（會 provision + 等開機 + 等 SSH 通才回）
# 會重複起停就先 `pilot services up`，再帶 --services local 吃本地快取（見 §2.2）；
# 一次性、跑完即丟就省略（等同 --services none）。
pilot vm-target up --base-image "$BASE" --name infra-vm --ssh-user root \
  --services local
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
rollback」。若沒有既有 topology，加入 `--ephemeral` 會先建立宣告的所有 VM，成功或失敗後
自動拆除；故障時加入 `--keep-on-failure`，會保留未 rollback 的 VM，供 SSH 檢查 apply 後現場。
這個組合拒絕採用既有同名 VM，避免意外接管或刪除既有測試環境。首次實跑用的 smoke 拓樸(2 台 ubuntu-24.04,各 2GB/2vcpu):

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

> 這次(2026-07-18)實跑早於 §2.2 的 `pilot services` 快取功能，`topo-smoke.yaml`
> 沒有 `services:` 欄位。之後重跑同一份 topology 想吃本地快取，先 `pilot
> services up`，再在檔案根層加一行 `services: local`（不必改 `nodes:` 任何欄位）。

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
| 沒有 pre-bake/golden image 流程 | 每次靠 cloud-init 裝東西，重複起停很浪費頻寬 | `pilot services up` + `--services local`（見 §2.2）快取 apt/RPM/image，不必等 pre-bake image 流程也能省下大部分重跑成本；golden image 本身仍待後續加 `vm-target build`（packer / virt-customize），對齊 docker 的 `--image-pilot` |
| 單 host | 一個 target = 一台 VM | `--hosts` alias 已支援（多 inventory key 指同一台）；真多機拓樸走 `vm-target topology`（宣告式 spec，up/inventory/snapshot/rollback/reset/test 全套，實跑範例見 `docs/runbooks/freeipa-server-replica-ha-drill.md`） |
| `--services local` 的 disposable-VM 端驗收仍待跑 | 目前只驗過 host-side lifecycle + fail-closed 串接，VM 內實際吃快取裝套件/拉 image 尚無實測 evidence | 見 `docs/superpowers/specs/2026-07-23-host-local-services-design.md` Task 8；補完前別把 `--services local` 寫進任何 spec 的 Expected 驗收行為 |

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
| 2026-07-23 | v1.1 | 補§2.2：文件化 `pilot services up/status/down/purge` + `vm-target --services local` / topology 根層 `services: local` 的 host-local 快取用法（apt-cacher-ng + Pulp RPM + Harbor，fail-closed，不會退回公網）；VM 端完整驗收仍待補（見 §7） |
