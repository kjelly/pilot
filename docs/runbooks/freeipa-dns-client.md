# FreeIPA DNS Client Runbook

## 0. 目標

讓任意目標主機的 OS 層級 DNS resolver 真的指向已經在跑 DNS 的 FreeIPA
server/replica（`ipa-server-install`/`ipa-replica-install --setup-dns`），
而不是只靠 `/etc/hosts` 靜態 pin。與 `freeipa-client-apply.yml`（AAA 身分
納管）是互不相依的獨立能力：目標主機不需要先做 FreeIPA client enrollment
就能套用本檔；FreeIPA server/replica 自己也適用（自動優先指向自己）。

- Spec：`docs/verification/freeipa-dns-client.md`
- Apply：`playbooks/apply/freeipa-dns-client-apply.yml`
- Contract：`contracts/freeipa-dns-client.yaml`
- 對偶：`docs/verification/freeipa-dns.md`（FreeIPA 自己的 DNS zone/record 控制平面；本檔只消費它已存在的 DNS 服務，不管理 zone/record 資料）

## 0.5 目前有效的事實快照

- 目標：兩台拋棄式 vm-target。
  - `freeipa-dns-server`：AlmaLinux 9，`freeipa-server-apply.yml`
    （`ipa_setup_dns` 預設 `true`，原生 `ipa-server-install --setup-dns`），
    IP `192.168.122.2`。**同時**是本檔的驗證目標之一（自我指向案例，
    NetworkManager 路徑）。
  - `freeipa-dns-ubuntu`：Ubuntu 24.04，**一般未納管**的 plain client
    （沒有跑過 `freeipa-client-apply.yml`），IP `192.168.122.3`，
    systemd-resolved 路徑。
- Inventory 組法：兩台 VM 各自 `pilot vm-target up` 起好後，用
  `pilot vm-target run --group freeipa-server=freeipa-dns-server
  --group dns-clients=freeipa-dns-ubuntu` 把兩台合成同一份 inventory 的
  ansible group，讓 playbook 自己的 `groups['freeipa-server']` 查詢能看到
  對方的 `ansible_host`——不需要手改 inventory YAML。
- Sandbox 控制平面 image：本檔是本 repo第一支用到
  `community.general.nmcli` 的 playbook；`pilot-cli:latest` 原本沒裝
  `community.general` collection，2026-07-31 已修 `images/Dockerfile.pilot-cli`
  補上（見 §5）。
- 正式結果（2026-07-31）：兩台 6/6 PASS + idempotent `changed=0`；
  過程中找到並修好 3 個 spec vacuous-check bug + 2 個 playbook bug + 1 個
  sandbox image gap（見 §5）。
- Vault：只需要 `freeipa-server-apply.yml` 本身的 `ipa_admin_password`
  （沿用 `~/.vault/main.yaml` 慣例）；`freeipa-dns-client-apply.yml`
  **不需要任何 vault 密碼**——它只讀 inventory IP，不碰 FreeIPA LDAP/Kerberos。

## 1. 邊界與前置

- 前置：inventory 至少要有一台 `freeipa-server`（或 `freeipa-server-replica`
  且 `freeipa_setup_dns: true`）已完成 `freeipa-server-apply.yml` 並健康。
- 本檔不建立/管理 FreeIPA server 本身，也不管理 DNS zone/record 資料
  （那是 `freeipa-dns-apply.yml` 的職責）。
- 套用範圍：任意主機，包含 FreeIPA server/replica 自己。day-2/opt-in，
  **不在 `site.yml`**（比照 `freeipa-dns`/`freeipa-server-replica`）。
- 兩種 OS 路徑：
  - Debian/Ubuntu：`systemd-resolved.conf.d` drop-in（nss-resolve/`resolvectl`
    路徑）+ 直寫 `/etc/resolv.conf`（`dig`/傳統 glibc resolver 路徑，繞過
    nss-resolve）。
  - EL/RHEL：`community.general.nmcli` 設定作用中 connection 的
    `dns4`/`dns4_search`，再用 `nmcli device reapply` 套用到活動裝置
    （不斷線）。

## 2. 套用與驗證（真實輸出）

```bash
# 兩台 VM 各自起好之後,合成同一份 inventory 的 ansible group:
pilot vm-target run \
  --group freeipa-server=freeipa-dns-server --group dns-clients=freeipa-dns-ubuntu \
  --sandbox --sandbox-image pilot-cli:latest \
  playbooks/apply/freeipa-dns-client-apply.yml -e target_group=dns-clients

pilot vm-target verify --name freeipa-dns-ubuntu docs/verification/freeipa-dns-client.md
```

**Step 1 — Ubuntu（一般 client）apply 前的 negative-state verify**（證明
checklist 真的能抓到「尚未套用」的狀態，不是恆為 PASS 的假檢查）：

```
verdict: FAIL  (pass=3 fail=3 skip=0)
{"id":"C1","status":"pass","detail":"rc=0 matches expected 0","stdout":"/usr/bin/dig"}
{"id":"C2","status":"pass","detail":"rc=0 matches expected 0","stdout":"active"}
{"id":"C3","status":"fail","detail":"probe_status=module_error: rc=1: non-zero return code"}
{"id":"C4","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C5","status":"fail","detail":"probe_status=module_error: rc=1: non-zero return code"}
{"id":"C6","status":"fail","detail":"probe_status=module_error: rc=1: non-zero return code"}
```

（C1/C2/C4 剛好因 `dig` 已預裝、systemd-resolved 預設 active、DHCP 本來就給
了某個 nameserver 而 trivial pass；C3/C5/C6 正確 fail：沒有 pilot 標記、沒有
search domain、DNS 查詢還沒真的指向 FreeIPA。）

**Step 2 — Ubuntu apply 後 verify**：

```
verdict: PASS  (pass=6 fail=0 skip=0)
{"id":"C1","status":"pass","detail":"rc=0 matches expected 0","stdout":"/usr/bin/dig"}
{"id":"C2","status":"pass","detail":"rc=0 matches expected 0","stdout":"active"}
{"id":"C3","status":"pass","detail":"typed matcher matched","stdout":"# pilot-freeipa-dns-client: managed by playbooks/apply/freeipa-dns-client-apply.yml — DO NOT EDIT BY HAND"}
{"id":"C4","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C5","status":"pass","detail":"rc=0 matches expected 0"}
{"id":"C6","status":"pass","detail":"rc=0 matches expected 0"}
```

Apply PLAY RECAP：`freeipa-dns-ubuntu : ok=15 changed=5 unreachable=0 failed=0 skipped=9`。
實地確認 `/etc/resolv.conf`：`nameserver 192.168.122.2`、
`search ipa.pilot.internal`、pilot 標記存在；`resolvectl status` 顯示
`DNS Servers: 192.168.122.2`。

**Step 3 — Ubuntu idempotent 重跑（同一條 apply 指令）**：

```
PLAY RECAP *********************************************************************
freeipa-dns-ubuntu         : ok=14   changed=0    unreachable=0    failed=0    skipped=9    rescued=0    ignored=0
```

resolved.conf.d/resolv.conf 的兩個 mutate task 皆回報 `ok`（無 `changed`），
handler 未被觸發。

**Step 4 — AlmaLinux 9（FreeIPA server 自我指向）apply + verify + idempotent 重跑**：

```
freeipa-dns-server : ok=17 changed=3 unreachable=0 failed=0 skipped=6
```

（3 個 change：寫 `/etc/resolv.conf`、`nmcli` 設定 `dns4`/`dns4_search`、
`nmcli device reapply`。）實地確認自我指向：

```
/etc/resolv.conf: nameserver 127.0.0.1   (search ipa.pilot.internal)
nmcli connection show: ipv4.dns: 127.0.0.1   ipv4.dns-search: ipa.pilot.internal
```

Verify：

```
verdict: PASS  (pass=6 fail=0 skip=0)
{"id":"C1","status":"pass",...,"stdout":"/usr/bin/dig"}
{"id":"C2","status":"pass",...,"stdout":"inactive\nactive"}
{"id":"C3","status":"pass","detail":"typed matcher matched","stdout":"# pilot-freeipa-dns-client: managed by ... — DO NOT EDIT BY HAND"}
{"id":"C4","status":"pass",...}
{"id":"C5","status":"pass",...}
{"id":"C6","status":"pass",...}
```

（C2 的 `inactive\nactive`：EL9 上 `systemd-resolved` unit 不存在故
`inactive`，`NetworkManager` 才是實際管理 resolver 的服務、回 `active`——
playbook 用 `||` fallback 正確處理兩種 OS。）

Idempotent 重跑：`freeipa-dns-server : ok=16 changed=0 unreachable=0 failed=0 skipped=7`
——`nmcli device reapply` 那個 task 正確被 `when: ... is changed` 擋掉、顯示
`skipping`，證明 `community.general.nmcli` 本身是 idempotent 的，而且
reapply 的 gate 邏輯正確。

VM 收尾：兩台 `pilot vm-target down`，乾淨釋放，無殘留。

## 3. Rollback

`block/rescue` 包住整個 resolver mutate 區塊：任一步驟失敗，rescue 從
`ansible.builtin.copy` 的自動 `backup: true` 備份還原 `/etc/resolv.conf`，
再明確 fail 並提示重跑。不會回退 `resolved.conf.d` drop-in或 `nmcli`
connection 設定本身（下一次重跑會用正確值覆蓋，屬於 forward-fix，不是
必須手動 rollback 的狀態）。

## 4. 與 freeipa-client / freeipa-dns 的關係

- `freeipa-client-apply.yml`（AAA 身分納管）：完全獨立，互不相依。一台
  host 可以只跑本檔（只要 DNS 解析對，不需要身分納管），也可以只跑
  `freeipa-client`（繼續靠 `/etc/hosts`），或兩者都跑。
- `freeipa-dns-apply.yml`（FreeIPA 自己的 DNS zone/record reconciler）：
  本檔的前置——沒有先讓 FreeIPA server 把 zone/record 建好，client 端指過
  去也查不到真正想要的紀錄；但 C6（FQDN 能解析）只依賴 FreeIPA server 安裝
  時就自動建立的自身 host record，不需要額外跑 `freeipa-dns-apply.yml`
  才能驗證本檔本身的 6 個 row。

## 5. 踩過的雷

- **spec 的 3 個 vacuous check（C3/C4/C6）**：`\|` 跳脫寫在已經被單引號包住
  的 `sh -c '...'` 裡完全多餘、而且有害——parser 不會把它還原掉，反斜線會
  原封不動送進真正執行的 remote shell，被解讀成「跳脫過的字面 pipe」，讓
  `grep` 從未真的接在管線後面執行。C6 因此在完全沒套用 playbook 的乾淨主機
  上也會 PASS（`dig` 對不存在的紀錄仍回 rc=0，沒有 `grep` 把它轉成 fail）；
  C4 同理，「零筆 nameserver」的情況也會誤判成 PASS。**這正是 negative-state
  檢查（本檔 §2 Step 1）存在的理由**：第一次跑 Step 1 時就是靠著「乾淨主機
  上 C6 不該 PASS 卻 PASS 了」抓到這個 bug。C3 是另一個獨立問題：
  `~substring` 型 Expected 配 `grep -q` 是絕對不能共存的組合——`-q`
  本來就不輸出到 stdout，`~substring` 比對的正是 stdout，兩者連用等於
  「stdout 恆空」，成功狀態下也會誤判成 fail（跟 vacuous-PASS 方向相反，
  是 false-negative）；apply 明明已經正確寫入標記，`pilot vm-target verify`
  卻回報 C3 fail，用 `pilot verify --probe` 重現才確認是 `-q` 的問題。三者
  修法：C3/C4/C6 全部拿掉 `\` 跳脫符、C3 額外拿掉 `-q`。
- **playbook 縮排錯位讓所有主機都壞掉**：`pre_tasks` 裡一個
  `tags: [always]` 多縮排了一層，掉進 `ansible.builtin.assert:` 自己的參數
  區塊，ansible 直接報 `Unsupported parameters for (...assert) module: tags`。
  這個 gate 沒有 `when` 條件、每台主機都會跑到，所以第一次對任何目標
  `--check` 就會整支炸掉——不是邊界案例。
- **`vars:` 自我引用的 Jinja 預設值觸發 ansible-core 無窮遞迴**：
  `freeipa_domain: "{{ freeipa_domain | default(...) }}"` 這種寫法看起來像
  「允許 `-e` 覆寫、又提供內建預設」，但因為左邊的 key 跟右邊模板引用的是
  同一個名字，ansible-core 在 play-level `vars:` 這層會遞迴嘗試對它自己
  求值，直接丟出 `Recursive loop detected in template: maximum recursion
  depth exceeded`——同樣是每台主機都會炸，而不是特例。這與
  `freeipa-server-apply.yml` 已經證明可行的寫法（`ipa_domain: "{{
  freeipa_domain | default(...) }}"`，**左右兩邊刻意用不同名字**）長得很
  像但關鍵不同。修法：把這兩個變數的正規化從 `vars:` 移到 `pre_tasks` 的一個
  `set_fact` task,只在執行時求值一次，不再用會自我引用的 lazily-templated
  `vars:`。
- **`pilot-cli:latest` 缺 `community.general` collection**：本檔是本 repo
  第一支用到 `community.general.nmcli` 的 playbook，沙盒控制平面 image
  之前只裝了 `community.docker`/`community.postgresql` 等,従未需要過
  `community.general`。實跑對 EL9 目標套用時 ansible 直接報
  `couldn't resolve module/action 'community.general.nmcli'`。修法：
  `images/Dockerfile.pilot-cli` 的 `ansible-galaxy collection install`
  補上 `community.general`,本機重建 image 後確認
  `ansible-galaxy collection list` 看得到它。
- **建議的 sandbox image 選擇要注意**：`vm-target-spec-testing`/
  `pilot-trec-verification` 兩份 skill 過去建議過的
  `geerlingguy/docker-ubuntu2204-ansible:latest` 這顆 image **完全沒有
  `ssh` client 二進位檔**——它是設計給「被 ansible 控制的目標容器」用的,不是
  控制端。凡是需要 `vm-target run --sandbox` 對外連線的情境(包含本檔),
  一律要用本 repo 自己的 `pilot-cli:latest`(控制平面 image),不能用那顆
  image 頂替。
