# Runbook — 主機分權（hostgroup/HBAC/host-scoped sudo）測試計畫

> 撰寫日期：2026-07-03 (UTC)
> 對齊：`playbooks/apply/freeipa-identity-apply.yml`（`ipa_hostgroups`/`ipa_hbac_rules`/
> host-scoped `ipa_sudo_rules` 擴充）、`playbooks/test/fixtures/freeipa-hostauthz-{demo,user-setup,sim}.yml`
> 對照文件：`docs/runbooks/freeipa-identity.md` §5.2
>
> 本檔每一步指令都已在真實 sandbox（`freeipa-server` + `freeipa-client` +
> `freeipa-client-2`）實跑過一輪（2026-07-03），輸出見各步驟下方「預期結果」。
> 照抄本檔指令即可重跑同一輪驗證。

---

## 0. 目標

證明 `freeipa-identity-apply.yml` 新增的三個資料維度組合起來，真的能做到
**「不同使用者在不同主機擁有不同權限，且不是所有人都能碰所有主機」**：

- `hz_web` 只能登入 + sudo `freeipa-client`（webhosts）
- `hz_db` 只能登入 + sudo `freeipa-client-2`（dbhosts）
- 兩邊互相不能越界（無論登入或 sudo）

---

## 1. 前置確認

```bash
./pilot vm-target list
```

**預期結果**：至少有 `freeipa-server`、`freeipa-client` 兩台 running；若要測 T6
（雙機交叉驗證）還需要 `freeipa-client-2`（沒有就先 `./pilot vm-target up
--base-image ubuntu-24.04 --name freeipa-client-2`，再用
`playbooks/apply/freeipa-client-apply.yml` enroll，見
`docs/verification/freeipa-client.md` §7.3）。

> ⚠️ VM 名稱/IP 會變（曾經換過），每次都用 `vm-target list` 現查，不要沿用舊筆記裡的 IP。

確認測試名冊存在：

```bash
ls -la ~/.vault/ipa-identity-test.yaml
```

沒有就用下面內容建立（**假帳號、repo 外、跟正式名冊分開**）：

```yaml
---
ipa_groups:
  - { name: hz-web, desc: "TEST — web-tier access" }
  - { name: hz-db,  desc: "TEST — db-tier access" }

ipa_users:
  - { name: hz_web, first: Hz, last: Web, password: "TestWebPass123", groups: [hz-web] }
  - { name: hz_db,  first: Hz, last: Db,  password: "TestDbPass123",  groups: [hz-db] }

ipa_hostgroups:
  - { name: webhosts, desc: "TEST — web tier", hosts: [freeipa-client.ipa.pilot.internal] }
  - { name: dbhosts,  desc: "TEST — db tier",  hosts: [freeipa-client-2.ipa.pilot.internal] }

ipa_hbac_rules:
  - { name: hz-login-web, hostgroups: [webhosts], services: [sshd], groups: [hz-web] }
  - { name: hz-login-db,  hostgroups: [dbhosts],  services: [sshd], groups: [hz-db] }

ipa_sudo_rules:
  - { name: hz-web-systemctl, hostgroups: [webhosts], allow_commands: [/usr/bin/systemctl], groups: [hz-web] }
  - { name: hz-db-systemctl,  hostgroups: [dbhosts],  allow_commands: [/usr/bin/systemctl], groups: [hz-db] }
```

```bash
chmod 600 ~/.vault/ipa-identity-test.yaml
```

---

## 2. T1 — Dry-run

```bash
./pilot vm-target run --name freeipa-server playbooks/apply/freeipa-identity-apply.yml \
    -e @~/.vault/freeipa-sandbox.yaml \
    -e @~/.vault/ipa-identity-test.yaml \
    --check --diff
```

**預期結果**：`command`/`shell` 類 task 在 `--check` 下全部 `skipping`（Ansible
對這兩個 module 的既定行為，非 bug），但每個 loop item 的 label 都要正確印出
（例如 `hz-login-web hostgroup webhosts`、`hz-web-systemctl hostgroup webhosts`），
代表模板/條件式 argv 渲染正確、沒有語法錯誤。`PLAY RECAP` 應該 `failed=0`。

---

## 3. T2 — 實際套用 + 冪等性

```bash
./pilot vm-target run --name freeipa-server playbooks/apply/freeipa-identity-apply.yml \
    -e @~/.vault/freeipa-sandbox.yaml \
    -e @~/.vault/ipa-identity-test.yaml
```

**預期結果（第一次，乾淨環境）**：`ok=19 changed=4 failed=0`（changed 是密碼
task + 4 個新增物件的首次建立）。

立刻重跑一次：

```bash
./pilot vm-target run --name freeipa-server playbooks/apply/freeipa-identity-apply.yml \
    -e @~/.vault/freeipa-sandbox.yaml \
    -e @~/.vault/ipa-identity-test.yaml
```

**預期結果（第二次）**：`ok=19 changed=1 failed=0`——`changed=1` 只會是密碼
task（`ipa passwd` 無法 diff、每次都視為 changed，是已知行為，見
`docs/runbooks/freeipa-identity.md` §5）；hostgroup/hbac/sudo 相關 task 全部
`ok`（no-op）。**如果這裡看到 `failed`，先看是不是又踩到下面 §7 的已知
gotcha。**

---

## 4. T3 + T4 — 結構驗證 + HBAC 決策引擎測試

```bash
./pilot vm-target run --name freeipa-server playbooks/test/fixtures/freeipa-hostauthz-demo.yml \
    -e fixtures_target_group=all -e @~/.vault/freeipa-sandbox.yaml \
    --tags fixtures,t3,hbactest
```

> ⚠️ **`--tags fixtures,t3,hbactest` 是必要的，不是可省略的裝飾**：這個檔案
> 還帶了 `restore`（重新啟用 allow_all）跟 `cleanup`（刪掉這個 fixture 建的
> 所有物件）兩個 task block，各自用獨立 tag 保護。Ansible 的規則是「沒帶
> `--tags`/`--skip-tags` 就跑全部 task，不管 tag 是什麼」——所以只要漏了
> `--tags`，這一步會在驗證完之後，**接著把 restore/cleanup 也一起靜默跑掉**：
> allow_all 被重新啟用、hz_web/hz_db 使用者、hz-web/hz-db 群組、
> webhosts/dbhosts hostgroup、hz-login-\*、hz-\*-systemctl sudo rule 全部被
> 刪除。因為當時 allow_all 還開著，§5 的 SSH 登入照樣會成功，只有沒有
> allow_all 這種後備機制的 sudo 會在下游 T5.3 才爆出來——症狀長得很像
> 「sudo 選項把 hostgroup 清空了」，實際上是整條 fixture 被砍掉又在 §6.1
> 重跑 `freeipa-identity-apply.yml` 時重新建回來（見 §8 gotcha 表）。

**預期結果**：`ok=19 changed<=2 failed=0`（`changed` 來自 kadmin.local 重設
`hz_web`/`hz_db` 密碼，這步是為了讓後面 `kinit` 免互動，每次跑都會顯示
changed，正常）。重點看兩個 assert：

- `T3 — assert hostgroup/HBAC/sudo rule 結構` 三個 assert 全部 `All assertions
  passed`
- `T4 — assert HBAC decisions match expected host-scoping` 也要
  `All assertions passed`；`T4 — summary` 應該印出：

  ```
  hz-login-web rule, hz_web -> freeipa-client.ipa.pilot.internal   : MATCHED (expected MATCHED)
  hz-login-web rule, hz_web -> freeipa-client-2.ipa.pilot.internal : NOT MATCHED (expected NOT MATCHED)
  hz-login-db rule,  hz_db  -> freeipa-client-2.ipa.pilot.internal : MATCHED (expected MATCHED)
  hz-login-db rule,  hz_db  -> freeipa-client.ipa.pilot.internal   : NOT MATCHED (expected NOT MATCHED)
  ```

  （此時 IPA 內建 `allow_all` 仍是啟用狀態，`hbactest` 的整體 `Access granted`
  一律是 `True`，這是正常的——host-scoping 的證據看的是上面這行「哪個規則
  matched」，不是整體 granted/denied。）

---

## 5. T5 — 單機真實登入 + sudo 驗證（正向）

### 5.1 幫兩個測試帳號在兩台主機上都建好 SSH key

**四次都要跑**（含刻意的「錯主機」組合，負向測試會用到）：

```bash
./pilot vm-target run --name freeipa-client   playbooks/test/fixtures/freeipa-hostauthz-user-setup.yml -e hostauthz_user=hz_web
./pilot vm-target run --name freeipa-client   playbooks/test/fixtures/freeipa-hostauthz-user-setup.yml -e hostauthz_user=hz_db
./pilot vm-target run --name freeipa-client-2 playbooks/test/fixtures/freeipa-hostauthz-user-setup.yml -e target_group=all -e hostauthz_user=hz_db
./pilot vm-target run --name freeipa-client-2 playbooks/test/fixtures/freeipa-hostauthz-user-setup.yml -e target_group=all -e hostauthz_user=hz_web
```

> `freeipa-client-2` 這兩行**必須帶 `-e target_group=all`**——playbook 的
> `hosts:` 預設群組名是 `freeipa-client`，不會自動比對到 `freeipa-client-2`。

> 這支 playbook 開頭現在會 import `freeipa-client-fixtures.yml`（標準的
> IPA 使用者建立入口，`ipa_fixture_manage_sudorule=false` 只建 user）。對
> client VM 跑時該 play 因 inventory 沒有 `freeipa-server` 群組而自動 skip，
> 上面四行的行為不變。若 identity-apply 還沒跑（帳號尚不存在），可先對
> server 補一次：
>
> ```bash
> ./pilot vm-target run --name freeipa-server playbooks/test/fixtures/freeipa-hostauthz-user-setup.yml \
>     -e fixtures_target_group=all -e hostauthz_user=hz_web -e @~/.vault/freeipa-sandbox.yaml
> ```
>
> （只建裸帳號；群組/HBAC/sudo 的掛載仍由 roster 驅動的 identity-apply 負責。）

**預期結果**：每次 `ok=2 changed=2 failed=0`。

### 5.2 讓 SSSD 拿到剛設好的 `!authenticate` sudo 選項（快取問題）

```bash
./pilot vm-target exec --name freeipa-client   -- sudo systemctl restart sssd
./pilot vm-target exec --name freeipa-client-2 -- sudo systemctl restart sssd
```

> 這是已知 gotcha：server 端幫 sudo rule 加 `!authenticate` 後，client 的
> SSSD 快取不會立刻反映，`sudo -n` 會卡在 `a password is required`，重啟
> sssd 才會即時生效。見 memory `freeipa-hbac-sudo-cli-gotchas`。

### 5.3 正向情境（allow_all 開著也能測，這一段不影響其他帳號）

```bash
./pilot vm-target run --name freeipa-client playbooks/test/fixtures/freeipa-hostauthz-sim.yml \
    -e sim_local_user=hz_web -e sim_local_password=TestWebPass123 -e sim_foreign_user=hz_db \
    --tags positive

./pilot vm-target run --name freeipa-client-2 playbooks/test/fixtures/freeipa-hostauthz-sim.yml \
    -e target_group=all -e sim_local_user=hz_db -e sim_local_password=TestDbPass123 -e sim_foreign_user=hz_web \
    --tags positive
```

**預期結果**：兩邊都 `ok=10 failed=0`，summary 各自印出：

```
hz_web login    : OK (expected OK)
hz_web sudo     : OK (expected OK)
hz_db sudo      : DENIED (expected DENIED)
```

（`freeipa-client-2` 那台把 `hz_web`/`hz_db` 對調）

---

## 6. T6 — 雙機交叉驗證（負向：錯主機登入必須被拒）

### 6.1 關閉 IPA 內建 `allow_all`（用剛擴充的開關，順便驗證這個新功能本身）

```bash
./pilot vm-target run --name freeipa-server playbooks/apply/freeipa-identity-apply.yml \
    -e @~/.vault/freeipa-sandbox.yaml \
    -e @~/.vault/ipa-identity-test.yaml \
    -e ipa_hbac_disable_allow_all=true
```

**預期結果**：只有「Disable the default allow_all HBAC rule」這個 task 顯示
`changed`，其餘全部 `ok`。

> ⚠️ 這一步會讓「沒有被任何自訂 HBAC rule 涵蓋」的帳號（例如既有 demo 用的
> `pilotuser`/`audituser`）暫時無法登入任何 enrolled 主機。§6.3 一定要做，
> 不要跳過或拖太久才做。

### 6.2 讓 client 的 SSSD 拿到最新 HBAC 狀態

```bash
./pilot vm-target exec --name freeipa-client   -- sudo systemctl restart sssd
./pilot vm-target exec --name freeipa-client-2 -- sudo systemctl restart sssd
```

### 6.3 負向情境（錯主機登入必須失敗）

```bash
./pilot vm-target run --name freeipa-client playbooks/test/fixtures/freeipa-hostauthz-sim.yml \
    -e sim_local_user=hz_web -e sim_local_password=TestWebPass123 -e sim_foreign_user=hz_db \
    --tags negative

./pilot vm-target run --name freeipa-client-2 playbooks/test/fixtures/freeipa-hostauthz-sim.yml \
    -e target_group=all -e sim_local_user=hz_db -e sim_local_password=TestDbPass123 -e sim_foreign_user=hz_web \
    --tags negative
```

**預期結果**：`ok=4 failed=0`，summary：

```
hz_db login (wrong host) : DENIED (expected DENIED)   # 在 freeipa-client 上
hz_web login (wrong host) : DENIED (expected DENIED)  # 在 freeipa-client-2 上
```

### 6.4 立刻重新啟用 `allow_all`（不要拖）

```bash
./pilot vm-target run --name freeipa-server playbooks/test/fixtures/freeipa-hostauthz-demo.yml \
    -e fixtures_target_group=all -e @~/.vault/freeipa-sandbox.yaml --tags restore
```

**預期結果**：`ok=4 changed=1 failed=0`（`Restore — re-enable the default
allow_all HBAC rule` 顯示 `changed`）。

---

## 7. 收尾：清掉測試資料

```bash
# server 端：刪掉 hz_web/hz_db、hz-web/hz-db、webhosts/dbhosts、hz-login-*、hz-*-systemctl
./pilot vm-target run --name freeipa-server playbooks/test/fixtures/freeipa-hostauthz-demo.yml \
    -e fixtures_target_group=all -e @~/.vault/freeipa-sandbox.yaml --tags cleanup

# client 端：清掉 §5.1 產生的本機帳號 home 目錄
./pilot vm-target exec --name freeipa-client   -- sudo rm -rf /home/hz_web /home/hz_db
./pilot vm-target exec --name freeipa-client-2 -- sudo rm -rf /home/hz_web /home/hz_db
```

**預期結果**：cleanup 第一次跑 `changed=6`，重跑一次應該全部 `ok`（`changed=0`），
代表確實清乾淨、且 delete task 本身冪等。

`~/.vault/ipa-identity-test.yaml` 可以留著（repo 外、假帳號，下次要重跑整套
測試可以直接重用）；不需要就手動刪掉。

---

## 8. 已知 gotcha 一覽（跑之前先知道，少走冤枉路）

| 症狀 | 原因 | 解法 |
|---|---|---|
| `ipa: ERROR: unknown command 'hbac-rule-add'` | FreeIPA CLI 是 `hbacrule-add`（無連字號），不是 `hbac-rule-add` | 已修在 `freeipa-identity-apply.yml`，不會再遇到 |
| `ipa: error: no such option: --command` | `sudorule-add-allow-command` 要用 `--sudocmds=` | 同上已修 |
| 重跑 `Attach allowed commands to sudo rules` failed，stderr 空、stdout 是 `Number of members added 0` | 這個指令的「已存在」訊號跟其他 attach task 不一樣（是 `rc=1` 不是 `rc=0`） | 已在 `failed_when` 特判，不會再遇到 |
| `sudo -n systemctl ...` 回 `a password is required` | server 端剛加的 `!authenticate` 選項還沒被 client SSSD 快取刷新 | `sudo systemctl restart sssd`（§5.2/§6.2） |
| `hbactest` 的 `Access granted` 每個組合都是 `True` | IPA 內建 `allow_all` 還開著，會蓋掉個別規則的效果 | 這是正常現象；看 `Matched rules:`/`Not matched rules:` 那行才準（§4），或走 §6 把 allow_all 關掉測真正的登入 deny |
| `pilot vm-target run --name freeipa-client-2 ...` 顯示 `no hosts matched` | playbook `hosts:` 預設群組名是 `freeipa-client` | 帶 `-e target_group=all` |
| `systemctl is-active sshd` 回 rc=4 | Ubuntu 24.04 的 SSH service 叫 `ssh` 不是 `sshd` | 驗證腳本改用保證存在的 unit（例如 `sssd`） |
| §4 跑完後，T5.3 sudo 才在下游失敗，`sudorule-show` 顯示 hostgroup/選項不見了 | §4 命令沒帶 `--tags`，連同檔案裡的 `restore`/`cleanup` task block 一起跑了——整條 fixture（含 sudo rule 本身）被砍掉，因為 allow_all 當時還開著，登入沒受影響，只有 sudo 在下游才會炸 | §4 一律加 `--tags fixtures,t3,hbactest`（已修在本檔與 `freeipa-hostauthz-demo.yml` 的 Usage 註解） |
| T5.3 sudo/SSH 驗證偶爾很慢或行為跟預期不符 | sim 的 loopback SSH 在 `kinit` 之後執行，client 端已有有效 Kerberos ticket，sshd 會優先嘗試 GSSAPI 協商（可能耗時數秒，且會蓋過原本要驗證的 pubkey 路徑） | `freeipa-hostauthz-sim.yml` 的 `sim_ssh_opts` 已加 `-o PreferredAuthentications=publickey`（2026-07-04 修），強制走 pubkey，不會再吃到 GSSAPI |

更完整的技術細節見 memory `freeipa-hbac-sudo-cli-gotchas` 與
`freeipa-audit-demo-gotchas`。
