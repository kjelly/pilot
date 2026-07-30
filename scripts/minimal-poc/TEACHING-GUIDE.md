# minimal-poc 教學手冊(對應 `casts/` 錄影)

> 本手冊是 [`docs/runbooks/minimal-poc-architecture.md`](../../docs/runbooks/minimal-poc-architecture.md)
> round 17(2026-07-27)的教學版本,搭配 `casts/` 目錄下的 `trec` 錄影使用。每一節對應一支
> `.cast`/`.html` 錄影,逐畫面說明「這一步在幹嘛」與「這個欄位要填什麼」——特別是
> `pilot edit` 的每一個選單,本手冊會列出**畫面文字、要選什麼、要打什麼值**的對照表,
> 不用再回去看 `.drive` 腳本原始碼。
>
> **播放方式**:`casts/html/*.html` 是自帶播放器的獨立 HTML 檔,雙擊或用瀏覽器開啟即可播放,
> 不需要安裝 `trec`。想看完整一輪從頭到尾,開 `casts/html/00-full-walkthrough.html`;
> 想個別看某一步,開對應編號的 HTML。有裝 `trec` 的話也可以 `trec play casts/<檔名>.cast`
> 在終端機裡播放。
>
> **這份手冊示範的是一次性、拋棄式的教學/測試環境**,所有帳號密碼都是隨機產生的測試值,
> 不是真實密碼;錄影檔裡的密碼輸入畫面已經用 `trec` 的 `--secret-env` 機制遮罩過
> (畫面上只會顯示 `<redacted:VAR_NAME>`,不會看到明文)。

## 0. 環境與名詞

| 名詞 | 說明 |
|---|---|
| `pilot edit` | 互動式精靈,用來建立/修改 `hosts.yml`、`group_vars/`、`.vault/`、FreeIPA roster |
| `pilot deploy` | 互動式精靈,把 `hosts.yml` 產生的 inventory 套用到真機(跑 `site.yml`) |
| `pilot reconcile` | 互動式精靈,跑 day-2 的 `freeipa-identity` 這種「資料驅動」元件(讀 roster 檔) |
| workspace | 一個資料夾,裡面放 `hosts.yml`、`group_vars/`、`.vault/`、`inventory.yml`;本輪用的是
`tmp/mpoc-ws-18/` |
| roster | FreeIPA 身分/權限的「唯一真相來源」YAML 檔(`.vault/ipa-identity.yaml`),放使用者、群組、
HBAC、sudo 規則 |

本輪三台機器與角色(`pilot vm-target topology up` 建出來的):

| 主機 | IP(本輪範例,每次重建都會變) | 角色(roles) |
|---|---|---|
| `freeipa-server` | 192.168.122.5 | `freeipa-server`, `audit-log-forwarding`, `restic-backup`, `wazuh-fim` |
| `nexus` | 192.168.122.6 | `alertmanager`, `audit-log-forwarding`, `dashboard`, `docker`, `freeipa-client`, `freeipa-nfs-server`, `prometheus`, `restic-backup`, `seaweedfs-s3`, `thanos-query`, `wazuh-fim`, `wazuh-manager` |
| `client-vm` | 192.168.122.2 | `audit-log-forwarding`, `docker`, `freeipa-client`, `freeipa-nfs-client`, `restic-backup`, `wazuh-fim` |

**IP 每次重建都會不一樣**(libvirt DHCP 重新配發),照著錄影做的時候,一定要先跑
`pilot vm-target topology status --topology docs/topologies/minimal-poc-topology.yaml`
拿到「你自己這一輪」的真實 IP,不要照抄本手冊或錄影裡的 IP。

---

## 錄影總覽表

| # | 檔名 | 內容 | 是否為 `pilot edit` 畫面 |
|---|---|---|---|
| 00 | `00-full-walkthrough` | 上面所有錄影依序接起來的完整流程(`trec merge`) | — |
| 01 | `01-edit-hosts` | 建立 `hosts.yml`:3 台主機、角色勾選、NFS roster 自動建立、`host_vars`、roster 使用者/群組 | ✅ |
| 01b | `01b-edit-group-vars` | 補兩個 `group_vars` 必填值(`thanos_s3_target_host`) | ✅ |
| 02 | `02-edit-vault-secrets` | 補 `.vault/main.yaml` 剩下的密碼 | ✅ |
| 03 | `03-deploy-sitewide` | `pilot deploy` 全站部署 | — |
| 04 | `04-reconcile-identity` | `pilot reconcile` 跑 `freeipa-identity`(初次套用) | — |
| 05 | `05-kinit-alice` | 幫 alice 做強制改密碼流程(`kinit`) | — |
| 06 | `06-verify-section4-spotcheck` | §4.1 HBAC 允許/拒絕、§4.2 Thanos 指標 | — |
| 07 | `07-verify-section4-3-backup-fim` | §4.3 restic 備份 + Wazuh FIM 即時告警 | — |
| 08 | `08-reconcile-remove-alice` | §4.4 步驟1:把 alice 從群組移除,reconcile | — |
| 09 | `09-verify-section4-4-remove-denied` | §4.4 步驟2:確認 alice 真的被擋下來 | — |
| 10 | `10-reconcile-restore-plus-drift` | §4.4 步驟3:恢復成員 + 新增一條 sudo 指令,reconcile | — |
| 11 | `11-verify-section4-4-restore-drift` | §4.4 步驟4:確認恢復 + 新指令都生效 | — |
| 12 | `12-reconcile-idempotency` | §4.4 步驟5:什麼都不改,再跑一次 reconcile,應該 `changed=0` | — |
| 13 | `13-verify-section4-2-loki` | §4.2 補充:Loki 日誌鏈路查詢 | — |

`.vault/` 裡的 HBAC/sudo/群組成員內容(下面第 6 節)**沒有對應錄影**——這是唯一容許
手動編輯的 YAML,用文字編輯器改,不是走 `pilot edit`,所以不會有 TUI 可以錄。

---

## 第 1 步(不錄影):建立 3 台 VM

```bash
./pilot vm-target topology up --topology docs/topologies/minimal-poc-topology.yaml
./pilot vm-target topology status --topology docs/topologies/minimal-poc-topology.yaml
```

這是純 CLI 指令、沒有互動選單,所以不錄影。跑完第二行,**把三台機器目前的 IP 抄下來**,
後面每一步都要用到。

---

## 第 2 步:`pilot edit` 建立 `hosts.yml`(對應 `01-edit-hosts.cast`)

啟動指令(工作目錄請換成你自己的 workspace 路徑):

```bash
./pilot edit --dir tmp/mpoc-ws-18
```

### 2.1 選擇要編輯什麼

| 畫面文字 | 要選什麼 |
|---|---|
| `要編輯什麼？` | **`hosts.yml — 機器清單與角色`** |
| `hosts.yml 路徑` | 直接 Enter(採用預設路徑) |
| `從空白清單開始嗎` | 直接 Enter(第一次建立,答 Yes) |

### 2.2 新增第一台主機:`freeipa-server`

| 畫面文字 | 要打/要選什麼 | 本輪範例值 |
|---|---|---|
| `選一台主機，或選下面的操作` | **`➕ 新增主機`** | — |
| `新主機名稱` | 主機的名字(**這個字串之後在 `roles` 裡也會用到**) | `freeipa-server` |
| 主機項目選單 → 選 | **`ansible_host(連線位址)`** | — |
| `ansible_host(可路由的 IP 或主機名)` | 這台機器**目前**的真實 IP(從 `topology status` 抄) | `192.168.122.5` |
| 主機項目選單 → 選 | **`ansible_user(登入帳號)`** | — |
| `ansible_user(登入帳號，留空...)` | SSH 登入帳號 | `root` |
| 主機項目選單 → 選 | **`SSH 私鑰路徑`** | — |
| `SSH 私鑰路徑(留空...)` | 這台 VM 專屬金鑰的絕對路徑 | `/var/lib/libvirt/images/pilot/freeipa-server/id_ed25519` |
| 主機項目選單 → 選 | **`角色(roles)`** | — |
| 角色選單 → 選 | **`☑ 逐項勾選角色`** | — |
| 角色勾選清單(space 勾選、enter 完成) | 用 ↓ 移到列、space 打勾,這台勾 4 個 | `freeipa-server`、`audit-log-forwarding`、`wazuh-fim`、`restic-backup` |
| 勾完 → 選 | **`✅ 完成`** | — |
| 主機項目選單 → 選 | **`其他變數`** → **`➕ 新增變數`** | — |
| `變數名稱` | 額外變數的 key 名稱(**這個名字是固定的,不能打別的**) | `freeipa_roster_file` |
| `變數值` | roster 檔的**絕對路徑**(要跟後面 nexus 那台設的一致) | `<workspace 絕對路徑>/.vault/ipa-identity.yaml` |
| 回到「其他變數」畫面 → 選 | **`↩ 返回`** | — |
| 主機項目選單 → 選 | **`↩ 返回主機清單`** | — |

> **為什麼 `freeipa-server` 要手動設 `freeipa_roster_file`?** 因為自動建立 roster 的機制
> (下面 2.3 節)只在勾選 `freeipa-nfs-server` 的那台主機上觸發,這裡是 `nexus`,不是
> `freeipa-server`。但 `freeipa-identity-apply.yml` 這支 playbook 也要在 `freeipa-server`
> 上讀同一份 roster,所以要手動把同一個路徑補上去。

### 2.3 新增第二台主機:`nexus`(這裡會自動跳出 NFS roster 精靈)

前面 4 個欄位(`ansible_host`/`ansible_user`/SSH 金鑰路徑)流程跟 2.2 一樣,只是換成 nexus
自己的值。角色勾選清單這次要勾 **12 個**:

`freeipa-client`、`docker`、`audit-log-forwarding`、`wazuh-manager`、`wazuh-fim`、
`seaweedfs-s3`、`restic-backup`、`prometheus`、`thanos-query`、`alertmanager`、
`dashboard`、`freeipa-nfs-server`

勾完按 `✅ 完成` 的瞬間,因為這台**第一次**勾選 `freeipa-nfs-server`,精靈會自動彈出：

| 畫面文字 | 要打什麼 | 說明 |
|---|---|---|
| `FreeIPA admin password(不會顯示；至少 8 字元)` | 你要設定的 FreeIPA 管理員密碼(輸入時螢幕不會顯示字元) | 這個密碼之後同時會變成:①roster 裡 `freeipa.admin.password`,②`.vault/main.yaml` 裡的 `ipa_admin_password` |
| （自動)`✅ 已建立最小 NFS roster ...` | 不用做任何事,這是精靈自己印出來的完成訊息 | 精靈幫你在 `.vault/ipa-identity.yaml` 寫入最小骨架(`schema_version`、`freeipa.admin`、一筆 `nfs.servers`) |

接著角色選單會多出一個新項目 **`host_vars/nexus.yml(必填、無安全預設值的設定)`**——只有
`nexus` 有這個項目,因為它是 `prometheus` 角色的機器,而 `prometheus_site_label` 這個值
「每一站都不同」,不能有安全的預設值:

| 畫面文字 | 要打/要選什麼 | 本輪範例值 |
|---|---|---|
| `選要編輯的項目` | **`host_vars/nexus.yml(必填、無安全預設值的設定)`** | — |
| 欄位清單 → 選 | **`prometheus_site_label`** | — |
| 欄位子選單 → 選 | **`修改值`** | — |
| `prometheus_site_label 的新值` | 這一站的站名(每一站要不一樣,不能沿用預設) | `site-nexus` |
| 存檔 → 選 | **`💾 存檔並離開`** | — |
| 回到主機項目選單 → 選 | **`↩ 返回主機清單`** | — |

> ⚠️ **這個欄位的輸入框會「預填目前的值、游標停在最後面」,不是空白框。** 如果你重跑同一步、
> 這個值之前已經填過,直接打字會變成「舊值+新值黏在一起」(例如 `site-nexussite-nexus`)。
> 保險作法:填之前先按住 Backspace 清空,或用支援「先清空再輸入」的輸入方式。這是本輪
> round 17 實際踩到、也修好的一個腳本 bug,細節見
> `.agents/skills/pilot-trec-verification/SKILL.md` §7。

### 2.4 新增第三台主機:`client-vm`

流程跟前面一樣,角色勾選這台勾 **6 個**:

`freeipa-client`、`docker`、`audit-log-forwarding`、`wazuh-fim`、`restic-backup`、
`freeipa-nfs-client`

勾完 `✅ 完成` → `↩ 返回主機清單` → 在主機清單畫面選 **`💾 存檔並離開`**,這一步才是真正把
`hosts.yml` 寫到磁碟上。

### 2.5 roster 管理員:新增群組與使用者

存完 `hosts.yml` 後精靈回到最上層「要編輯什麼？」,這次選 **`roster — FreeIPA`**:

| 畫面文字 | 要打/要選什麼 | 本輪範例值 |
|---|---|---|
| `要編輯什麼？` | **`roster — FreeIPA`** | — |
| `Roster 檔路徑` | 直接 Enter(採用剛剛自動建立的那份) | — |
| `管理 <roster 路徑>` | **`👥 Groups`** | — |
| Groups 畫面 → 選 | **`➕ 新增 Group`** | — |
| `新 group 的分類` | 4 選 1:`team-`/`data-`/`access-`/`role-` | 第一個群組選 **`access-*(存取權限)`** |
| `category=access` 後 → 打 | group 名稱(**名字前綴要跟上面選的分類對應**) | `access-poc-ssh` |
| （重複)`➕ 新增 Group` | 第二個群組分類選 **`role-*(職務角色)`** | 名稱 `role-poc-sudo` |
| 回到 Groups 畫面 → 選 | **`↩ 返回`** | — |
| `管理` 畫面 → 選 | **`👤 Users`** | — |
| Users 畫面 → 選 | **`➕ 新增 User`** | — |
| `新 user 的名稱` | 使用者帳號 | 先 `alice`,再重複一次新增 `bob` |
| 回到 Users 畫面 → 選 | **`↩ 返回`** | — |
| `管理` 畫面 → 選 | **`↩ 返回`** | — |
| `要編輯什麼？` → 選 | **`離開`** | — |

> ⚠️ **這裡容易搞混的地方**:Groups 畫面按一次「↩ 返回」回到的是「管理」選單
> (`👤 Users` / `👥 Groups` / `↩ 返回`),不是最上層的「要編輯什麼？」——Users 畫面也一樣,
> 也是先回到「管理」,要再按一次「↩ 返回」才會回到最上層。這是本輪另一個實際修好的
> 腳本 bug(第一版腳本漏了 Users 這邊的第二次「返回」)。

> **roster 管理員只能「新增」,不能設定成員關係(membership)、密碼、SSH 金鑰、HBAC/sudo
> 規則。** 這些欄位這一步先留空,下面第 6 節會說明怎麼手動補。這是刻意設計:
> `pilot edit` 拒絕碰巢狀 YAML 結構,只有這裡是官方認可的手動編輯例外。

到這裡整支 `01-edit-hosts.cast` 錄影結束,`hosts.yml` 和 roster 骨架都已經寫到磁碟上。

---

## 第 3 步(不錄影):`pilot inventory generate`

```bash
./pilot inventory generate --dir tmp/mpoc-ws-18
```

這一步沒有互動選單,純命令列。作用是根據 `hosts.yml` 裡選的角色,把對應的
`group_vars/<角色>.yml` 骨架(從 `.example.yml` 複製過來)和 `.vault/main.yaml` 的密碼骨架
補齊,已存在的檔案不會覆蓋。

---

## 第 4 步:`pilot edit` 補 `group_vars`(對應 `01b-edit-group-vars.cast`)

先問自己一個問題:**這一輪的角色組合裡,`group_vars` 到底哪些欄位是「真的必填」?**
不要憑印象或憑舊文件回答——用精靈自帶的檢查工具問它自己最準:

```
要編輯什麼？ → 🔍 檢查設定完整性
```

這份報告會列出每個 `group_vars/*.yml` 檔案是 ✅ 還是 ❌,❌ 的話會附一行說明缺什麼。本輪
唯二真的缺的是:

| 畫面文字 | 要打/要選什麼 | 本輪範例值 |
|---|---|---|
| `要編輯什麼？` | **`group_vars/ — 角色的設定值`** | — |
| `選一個 .../group_vars 底下的檔案` | **`📝 prometheus.yml`** | — |
| 欄位清單 → 選 | **`thanos_s3_target_host =`** | — |
| 子選單 → 選 | **`修改值`** | — |
| `thanos_s3_target_host 的新值` | 執行 `seaweedfs-s3` 角色那台主機的 IP(本例是 nexus) | `192.168.122.6` |
| 存檔 → 選 | **`💾 存檔並離開`** | — |
| 回到檔案清單 → 選 | **`📝 thanos-query.yml`** | — |
| （同樣流程)`thanos_s3_target_host` | 跟 prometheus.yml 設**一模一樣的值** | `192.168.122.6` |
| 存檔 → 選 | **`💾 存檔並離開`** | — |
| 回到檔案清單 → 選 | **`↩ 返回`** | — |
| `要編輯什麼？` → 選 | **`離開`** | — |

> **為什麼只有這兩個?** `restic-backup.yml`/`wazuh-fim.yml`/`audit-log-forwarding.yml` 等
> 其他角色的對應欄位,要嘛有「看到 `seaweedfs-s3`/`wazuh-manager` 角色就自動推導」的
> playbook 內建邏輯,要嘛本來就是選填。**每一輪都用「🔍 檢查設定完整性」重新確認一次**,
> 不要照抄舊 round 的清單——這份清單是 code 決定的事實,不是文件事實,程式改版可能會變。

---

## 第 5 步:`pilot edit` 補 `.vault/main.yaml` 密碼(對應 `02-edit-vault-secrets.cast`)

```
要編輯什麼？ → .vault/ — vault
選一個 → 📝 main.yaml
```

進到 `main.yaml` 編輯畫面後,清單最上面會先看到 `ipa_admin_password`(第 2.3 步驟自動建立
的,已經有值),下面 7 個要逐一新增:

| 順序 | 要選 | `新的 key 名稱` 打什麼 | `值` 打什麼 |
|---|---|---|---|
| 1 | **`➕ 新增 key`** | `grafana_admin_password` | Grafana 管理員密碼 |
| 2 | **`➕ 新增 key`** | `restic_aws_access_key_id` | restic 備份用的 S3 access key |
| 3 | **`➕ 新增 key`** | `restic_aws_secret_access_key` | restic 備份用的 S3 secret key |
| 4 | **`➕ 新增 key`** | `restic_password` | restic repository 加密密碼 |
| 5 | **`➕ 新增 key`** | `thanos_aws_access_key_id` | **必須跟第 2 項一模一樣** |
| 6 | **`➕ 新增 key`** | `thanos_aws_secret_access_key` | **必須跟第 3 項一模一樣** |
| 7 | **`➕ 新增 key`** | `alertmanager_config` | 一段多行 YAML(見下方) |

第 7 項 `alertmanager_config` 的值是一段內嵌 YAML(不是密碼,是設定內容),範例:

```yaml
route:
  receiver: "null"
  group_by: ['alertname']
  group_wait: 30s
  group_interval: 5m
  repeat_interval: 4h
receivers:
  - name: "null"
```

7 個都新增完 → 選 **`💾 存檔並離開`** → **`↩ 返回`** → `要編輯什麼？` 選 **`離開`**。

> ⚠️ **重要安全提醒(這份手冊自己在錄這一步時真的踩到)**:vault 的 key 清單畫面,**每次
> 打開都會把目前已經設定過的每一個 key 的值用明文顯示出來**——包括這支腳本沒有要動的
> `ipa_admin_password`。如果你在錄自己的教學影片,錄影工具的密碼遮罩清單一定要把
> **workspace 裡「目前已經有值」的每一個 vault key** 都列進去,不能只列這支腳本自己要
> 新增的那幾個,不然舊密碼會在畫面上曝光。

> **`thanos_aws_*` 為什麼要跟 `restic_aws_*` 完全一樣?** 因為本環境自建的 SeaweedFS S3
> gateway,唯一的身分是從 `restic_*` 這組憑證算出來的,Thanos 的 sidecar 是拿同一組身分
> 去認證,不是各自獨立的兩組。

---

## 第 6 步(手動編輯,沒有錄影):roster 的 HBAC / sudo / 成員關係

`pilot edit` 的 roster 管理員只能新增 Group/User 的「空殼」,不能設定：

- 使用者的密碼、SSH 金鑰
- 群組的成員關係(誰屬於哪個群組)
- HBAC 規則(誰可以登入哪台機器)
- sudo 規則(誰可以在哪台機器用 sudo 跑哪些指令)

這些要直接用文字編輯器改 `.vault/ipa-identity.yaml`(這是唯一容許手動編輯的 YAML 例外,
改完務必跑 `./pilot roster lint <檔案>` 驗證)。以下是本輪實際使用、驗證通過的完整範例
結構(密碼欄位以 `<請填入密碼>` 表示):

```yaml
# 這段是要「併入」pilot edit 已產生的骨架,不是整份取代——骨架裡已經有
# schema_version/freeipa.admin/nfs.servers 了。如果你是另外從零開始寫一份新檔
# (沒有先跑過 pilot edit 的 NFS role 精靈),最上面務必加這一行,不然
# `pilot roster lint` 會報「[schema_version] schema_version is required (must be 1)」:
schema_version: 1

groups:
  - name: access-poc-ssh
    state: present
    category: access
    membership:
      authoritative: true
      users: [alice]        # ← 誰可以登入,寫在這裡
      groups: []
  - name: role-poc-sudo
    state: present
    category: role
    membership:
      authoritative: true
      users: [alice]        # ← 誰可以 sudo,寫在這裡
      groups: []

users:
  - name: alice
    state: present
    password:
      initial: <請填入密碼>
      force_change: false    # 建議設 false,見下方「常見錯誤」
      preserve_existing: false
  - name: bob
    state: present            # bob 故意不給密碼/群組,示範「被拒絕」的情境

# --- 以下兩個欄位不是 pilot edit 自動建立的,round 17 發現要手動補,見附錄 A ---
freeipa:
  # ...(admin/domain 是 pilot edit 自動建的,不要動)
  realm: IPA.PILOT.INTERNAL
  server: ipa1.ipa.pilot.internal   # 用 `hostname -f` 到 freeipa-server 上確認,不要用猜的

hbac:
  disable_allow_all: true
  services:
    - {name: sshd, state: present}
    - {name: sudo, state: present}
    - {name: sudo-i, state: present}
  rules:
    - name: breakglass-admin-access   # 這條是安全防護閘門要求的,不能省
      state: present
      enabled: true
      subjects: {users: [admin], groups: []}
      targets: {hostcat: all, hosts: [], hostgroups: []}
      services: [sshd]
    - name: poc-ssh-access
      state: present
      enabled: true
      subjects: {users: [], groups: [access-poc-ssh]}
      targets: {hostcat: all, hosts: [], hostgroups: []}
      services: [sshd, sudo, sudo-i]   # sudo/sudo-i 也要列,不然 sudo 會被擋

sudo:
  command_groups:
    - name: poc-sudo-cmds
      state: present
      commands:
        - /usr/bin/systemctl status ssh   # Ubuntu 用 ssh,不是 sshd(見附錄 B)
  rules:
    - name: poc-sudo-rule
      state: present
      enabled: true
      subjects: {users: [], groups: [role-poc-sudo]}
      targets: {hostcat: all, hosts: [], hostgroups: []}
      allow: {command_groups: [poc-sudo-cmds], commands: []}
      deny: {command_groups: [], commands: []}
      run_as: {users: [root], groups: []}
      options: ['!authenticate']   # 讓 sudo -n 不用再問密碼
```

改完存檔後驗證:

```bash
./pilot roster lint tmp/mpoc-ws-18/.vault/ipa-identity.yaml
```

看到 `ok: no issues found` 才算過關。

---

## 第 7 步:`pilot deploy` 全站部署(對應 `03-deploy-sitewide.cast`)

```bash
./pilot deploy -i tmp/mpoc-ws-18/inventory.yml --timeout 90m
```

| 畫面文字 | 要打/要選什麼 |
|---|---|
| `Inventory 檔路徑` | 直接 Enter |
| `要不要先看一下這份 inventory 的拓樸圖？` | `n` |
| `要先跑前置檢查嗎` | 選 **`完整前置檢查(含 SSH 連線測試)`** |
| `要佈署什麼？` | 選 **`全站部署(site.yml)`** |
| `要套用到哪個 stage` | 選 **`sandbox（預設）`** |
| `--limit` | 直接 Enter(留空) |
| `--tags` | 直接 Enter(留空) |
| `main.yaml，這次佈署要用它當密碼變數檔嗎？` | **`y`**(不要選 n,見下方常見錯誤) |
| 一連串 `xxx_target_host=` 自動偵測值確認 | 每一個都輸入 **`y`**(接受精靈自動推導的值) |
| `還有其他 -e 變數要帶嗎？` | 直接 Enter(留空) |
| `要先預覽(--check --diff)再決定要不要真的套用嗎？` | **`y`** |
| `確定要執行以上指令嗎？`(第一次,預覽用) | **`y`** |
| （等預覽跑完,看到 `✅ 預覽完成，沒有錯誤。`) | — |
| `要接著套用真正的變更嗎？` | **`y`**(這一步答 N 或直接按 Enter 會變成「只預覽不套用」,不會有任何實際變更) |
| `確定要執行以上指令嗎？`(第二次,真的套用) | **`y`** |

跑完會看到每台主機的 `PLAY RECAP`,重點看 `failed=0`。本輪結果:
`client-vm ok=92 changed=41 failed=0`、`freeipa-server ok=78 changed=33 failed=0`、
`nexus ok=206 changed=95 failed=0`。

> ⚠️ **最容易教錯的地方**:上面那兩個「確定要執行以上指令嗎？」問的**不是同一件事**——
> 第一個是「要不要跑預覽」,第二個才是「要不要真的套用」。中間那句
> 「要接著套用真正的變更嗎？」預設值是 **No**,直接按 Enter 會在這裡停下來,
> 什麼都沒套用,但畫面看起來完全正常、exit code 也是 0——這是最容易「以為部署成功、
> 其實什麼都沒做」的陷阱。

---

## 第 8 步:`pilot reconcile` 跑 `freeipa-identity`(對應 `04-reconcile-identity.cast`)

```bash
./pilot reconcile -i tmp/mpoc-ws-18/inventory.yml --timeout 90m
```

| 畫面文字 | 要打/要選什麼 |
|---|---|
| `Inventory 檔路徑` | 直接 Enter |
| `要不要先看一下拓樸圖？` | `n` |
| `要先跑前置檢查嗎` | 選 **`完整前置檢查`** |
| `挑一個要調和的` | 選 **`管理 FreeIPA 使用者／權限 ... — freeipa-identity`** |
| `要限定只套用到哪個 group/host 嗎？` | 直接 Enter(留空,用預設的 `freeipa-server`) |
| `要套用到哪個 stage` | 選 **`sandbox（預設）`** |
| `--limit` / `--tags` | 都直接 Enter |
| `main.yaml，這次佈署要用它當密碼變數檔嗎？` | **`y`**(這裡的 y 只是滿足程式端「要有 bare `ipa_admin_password`」的檢查,roster 本身是靠 `freeipa_roster_file` 這個 host var 另外讀進來的,兩者互不影響) |
| `還有其他 -e 變數要帶嗎？` | 直接 Enter |
| `要先預覽...嗎？` → `y`,`確定要執行...` → `y`,等 `✅ 預覽完成` | 同上一節 |
| `要接著套用真正的變更嗎？` → `y`,`確定要執行...` → `y` | 同上一節 |

本輪初次套用結果:`changed=17 failed=0`。

> ⚠️ **千萬不要把上面 `main.yaml` 那句問題答成 `n` 再去改選 roster 檔路徑**——這是很舊
> (2026-07-17 之前)的一種 roster 格式才需要的操作方式,對現在這種標準 roster 格式反而會
> 直接失敗(`requires input "ipa_admin_password"`)。看到這句永遠答 `y`。

---

## 第 9 步:幫 alice 換密碼(對應 `05-kinit-alice.cast`)

alice 是全新建立的使用者,FreeIPA 規定「第一次指派密碼」一定會強制要求下次登入時改密碼,
跟 roster 裡 `force_change` 設 true 或 false 無關。所以在做任何用密碼登入的測試之前,
要先用 `kinit` 走一次強制改密碼流程:

```bash
ssh -t -o StrictHostKeyChecking=accept-new \
    -i /var/lib/libvirt/images/pilot/client-vm/id_ed25519 \
    root@<client-vm 的 IP> kinit alice
```

| 畫面文字 | 要打什麼 |
|---|---|
| `Password for alice@...` | alice 目前(舊)的密碼 |
| `Password expired` / `Enter new password` | 想改成的新密碼 |
| `Enter it again` | 再打一次同一組新密碼 |

**這個流程永遠剛好 3 行輸入**(舊密碼、新密碼、新密碼確認),多一行少一行都會出現看起來
像密碼打錯的錯誤。

---

## 第 9.5 步:`pilot reconcile` 跑 `freeipa-dns`(對應 `04b-reconcile-dns.cast`，round 18 新增)

`freeipa-dns` 是另一個獨立的 day-2 reconciler（`docs/specs/freeipa-dns.md`），管理 FreeIPA
原生 DNS 的 zones/records，跟第 8 步的 `freeipa-identity` 是同一個「挑一個要調和的
day-2 設定元件」選單裡的**第二個**選項（第一個永遠是 `freeipa-identity`）。

先決條件（跑這一步之前）：

1. `freeipa-server` 這台主機的「其他變數」要多設一個 `freeipa_dns_manifest_file`（跟
   `freeipa_roster_file` 是兩個獨立的 extra var，都要設），指向 workspace 頂層的
   `freeipa-dns.yaml`（**不是** `.vault/` 底下——manifest 本身不含密碼）。
2. 用 `pilot edit` 的「freeipa-dns manifest」頂層選單建立至少一個 zone、加幾筆
   A/AAAA/CNAME record（`target.inventory_host` 可以直接選 `nexus`，會自動解析成它的
   `ansible_host`）。

接著跟第 8 步幾乎一樣的流程：inventory 路徑 Enter、拓樸圖選 `n`、preflight 選預設、
day-2 元件選單這次選**第二項**（`管理 FreeIPA DNS zones／records`）、target_group/
stage/limit/tags 全部 Enter 採預設、密碼變數檔選 `y`（用 `.vault/main.yaml`）、預覽
`y` → `y`、確認套用 `y` → `y`。

| 畫面文字 | 要打什麼 |
|---|---|
| `挑一個要調和的 day-2 設定元件` | ↓ 一次，選到「管理 FreeIPA DNS zones／records」再 Enter |
| 其餘每一句 | 跟第 8 步同一套 Enter/y 節奏 |

過關的判斷跟第 8 步一樣看最後的 `PLAY RECAP`：第一次套用應該是
`changed=2 failed=0`（3 筆 A record 只算 1 個 changed 任務，因為同一個 task 迴圈處理
3 筆項目，recap 只算「這個 task 對這台主機有沒有回報 changed」，不是逐筆算）；`dig
+short <名稱>.<你的 zone> A @127.0.0.1` 應該回傳 `nexus` 的真實 IP；再跑一次同樣的
reconcile,應該是`changed=0 failed=0`。

---

## 第 10 步:§4 驗收(對應 `06`~`13` 錄影)

這幾支都是**唯讀查核**,沒有互動選單,直接看終端機輸出結果就好:

| 錄影 | 驗證的事 | 怎麼判斷過關 |
|---|---|---|
| `06-verify-section4-spotcheck` | alice 被允許登入+sudo、bob 被拒絕、Thanos 指標存在 | 8 項全部 `"status":"pass"` |
| `07-verify-section4-3-backup-fim` | restic 備份 timer 正常、有快照、Wazuh 即時抓到檔案異動 | 三台都 `enabled`/`active`;snapshots 清單非空;alerts.log 出現剛剛建立的檔名 |
| `08-reconcile-remove-alice` | 把 alice 從兩個群組移除,重跑 reconcile | `changed` 數字不為 0 |
| `09-verify-section4-4-remove-denied` | 確認 alice 真的被擋 | `hbactest` 顯示 `Access granted: False`,SSH 直接被拒絕連線 |
| `10-reconcile-restore-plus-drift` | 恢復 alice 成員資格 + 新增一條 sudo 指令 | `changed` 數字不為 0 |
| `11-verify-section4-4-restore-drift` | 確認恢復生效、新指令也能跑 | `hbactest` 回到 `True`;`sudo -n -l` 列出兩條指令 |
| `12-reconcile-idempotency` | 什麼都不改,再跑一次 reconcile | `changed=0` 才代表冪等性正常 |
| `13-verify-section4-2-loki` | 中央 Loki 查得到即時日誌 | 查詢回應裡看得到 `pilot-siem` stream 的真實事件 |

---

## 附錄 A:已知的產品缺陷(教學時要提醒學生「這不是你操作錯」)

`pilot reconcile` 在第 8 步做「調和」的時候,如果 roster 裡沒有 `freeipa.server` 這個欄位
(precisely 是 `pilot edit` 的 NFS bootstrap 機制**本來就不會**自動寫這個欄位),會直接
crash:

```
Error while resolving value for 'identity_hbac_test_host': object of type 'dict' has no attribute 'server'
```

這是已回報但**尚未修好**的實作缺陷(細節見 `docs/runbooks/minimal-poc-architecture.md` §6 和
`docs/evidence/minimal-poc-architecture/2026-07-27-round-17.md`)。教學時的暫時解法就是
第 6 步範例裡的做法:手動在 roster 補上 `freeipa.server`(用 `hostname -f` 到
freeipa-server 上確認真實值,本例是 `ipa1.ipa.pilot.internal`)和 `freeipa.realm`。

**round 18(2026-07-30)額外找到並修好了兩個獨立的真實 bug**(教學時可以對照著講「同一個
`freeipa.server` gap 附近,還藏了另一個更早就會擋下來的 gate」):

1. 就算照上面的方法補了 `freeipa.server`/`freeipa.realm`,第 8 步仍然可能在**更早**的
   gate 失敗:

   ```
   Canonical roster contains an unknown freeipa/admin field.
   ```

   原因是 `freeipa-identity-apply.yml` 自己的允許清單漏寫了 `domain`/`realm`,即使
   Go 那邊的 schema(`internal/inventory/roster_validate.go`)明明允許——而且
   `pilot edit` 的 NFS bootstrap 本來就會自動寫 `freeipa.domain`,所以**任何**照著
   官方精靈建出來的 roster,第一次跑 `freeipa-identity` reconcile 都會卡在這裡。
   這個已經修好了,升級到新版 `pilot` 就不會再遇到。
2. 第 9.5 步的 `freeipa-dns` 也有一個類似形狀的 bug:manifest 裡填的
   `freeipa.server` 就算跟 group_vars 對得上,如果**沒有手動填**
   `freeipa_server_fqdn`(教學上通常建議留空,用內建預設)、`pilot reconcile` 還是會
   在下面這句失敗:

   ```
   manifest freeipa.domain/realm/server must equal this deployment's freeipa_domain/freeipa_realm/freeipa_server_fqdn (§5.2)
   ```

   原因是 `freeipa-dns-apply.yml` 自己算「預期的 FQDN」時退回成 inventory 裡的短
   別名(例如 `freeipa-server`),而不是真正的 FQDN(`ipa1.<domain>`)。同樣已經修好。

## 附錄 B:操作上真的會踩到的坑

| 症狀 | 原因 | 對策 |
|---|---|---|
| `host_vars`/`group_vars`/vault 的某個值變成「新值黏在舊值後面」 | 這些輸入框都是「預填目前值、游標在最後」,不是空白框,直接打字是「接在後面」不是「取代」 | 打新值之前先清空欄位 |
| 存檔後精靈沒有回到你以為的畫面,腳本卡住等下一句 | 「儲存並離開」通常只退回**上一層選單**,不是最上層;不同深度的選單要退的次數不一樣 | 每存一次檔,實際看畫面上出現什麼,不要用記憶中的步驟數 |
| vault 密碼清單畫面上看到明文密碼 | 這個畫面本來就會把「所有已存在的 key」明文列出來,不分是不是你這次要改的 | 教學錄影前,先確認要遮罩的密碼清單涵蓋 workspace 裡**目前所有**已設定的 vault key |
| alice 第一次用密碼登入被拒絕、要求改密碼 | FreeIPA 對「第一次指派的密碼」永遠會要求強制改密碼,不看 roster 的 `force_change` 設定 | 見上面第 9 步,先跑一次 `kinit` |
| alice 的 sudo 指令第一次執行被拒絕(`sudo: a password is required`) | 剛套用的 sudo 規則,client 端的 SSSD 快取還沒更新 | 到該台機器上跑 `sss_cache -E && systemctl restart sssd`,不要去改 `sssd.conf` 的 `services=` 那行 |
| roster 授權的指令實際執行說「找不到這個 unit」 | AlmaLinux/RHEL 跟 Debian/Ubuntu 對同一個服務用不同的 systemd unit 名稱(例:`sshd` vs `ssh`) | 授權指令前,先到目標主機確認 `systemctl status <名稱>` 真的存在 |
| `pilot deploy`/`reconcile` 的兩個「確定要執行以上指令嗎？」搞混 | 同一句提示在流程裡出現兩次,分別對應「跑預覽」跟「真的套用」 | 看上下文:出現在 `要先預覽...嗎？y` 之後的,是跑預覽;出現在 `要接著套用真正的變更嗎？y` 之後的,才是真的套用 |

---

## 附錄 C:回放與分享

- 單支重播(終端機):`trec play casts/<檔名>.cast`
- 單支重播(瀏覽器,免裝 trec):直接開 `casts/html/<檔名>.html`
- 看純文字逐字稿(不用重播畫面):`trec transcript casts/<檔名>.cast`
- 確認錄影完整、沒有密碼外洩:`trec verify casts/<檔名>.cast` 且 `trec scan casts/<檔名>.cast`
  要顯示 0 筆疑似外洩
- `casts/` 目錄是 gitignored,不會被誤 commit;分享前務必自己再跑一次上面的 verify/scan。
