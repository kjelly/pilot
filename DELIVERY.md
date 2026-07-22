# 交付快速上手（給收到這份 playbook 的人）

這份文件只講「黃金路徑」：**填好 inventory → 前置檢查 → 套用**。
你不需要讀完整份 README，跟著下面的步驟走即可。

> **佈署方式只有一種：docker image。** 這台機器不需要裝 Python、
> ansible-core、Ansible collections，也不需要裝 Go —— 所有東西（`pilot`
> 執行檔、ansible-core、`ansible.posix`/`community.docker`/
> `community.postgresql` collections、playbooks、group_vars 範例）都已經
> bake 進一個 docker image（`pilot-cli`）。下面每一條指令都是
> `docker run ... pilot-cli:<tag> <實際指令>`；沒有另一種本機安裝的路徑。

> **不想手動組 `ansible-playbook` 指令？** 準備好 image 跟 `inventory.yml`
> 之後（第 0、1 步），可以改用 `pilot deploy` 互動精靈——它會用問答的方式
> 帶你完成「選 inventory → 前置檢查 → 選全站/單一元件 → 選 stage → 預覽 →
> 套用」全部步驟，行為跟下面手動組的指令完全一致（同一套 stage/confirm
> gate、同一份 Playbook 對照表），只是不需要自己記指令：
>
> ```bash
> docker run --rm -it \
>     -v "$HOME/.ssh:/root/.ssh:ro" \
>     -v "$(pwd)/inventory.yml:/pilot/inventory.yml:ro" \
>     pilot-cli:latest \
>     pilot deploy
> ```
>
> 熟悉 Ansible 的人，或需要精靈沒問到的細節（例如某個角色專屬的 group_vars）
> 時，仍照下面的手動步驟操作。

> **已部署服務的 day-2 宣告式設定**（例如 FreeIPA 使用者、群組、HBAC 與 sudo
> roster）改用 `pilot reconcile`。它和 `pilot deploy` 共用 preflight、stage gate、
> preview 與確認機制，但只列出已具 contract、apply playbook、schema 與驗證證據的
> reconciler；目前可用項目是 `freeipa-identity`。未來 Nginx config 也必須先具備這些
> 交付物才會出現在清單中。

---

## 0. 準備 pilot-cli image

先確認 Docker 能跑（Windows 用 Docker Desktop；macOS/Linux 用 Docker Desktop
或原生 `dockerd` 都可以）：

```bash
docker version
```

依你收到交付物的形式，三選一：

| 你收到的東西 | 指令 |
|---|---|
| 一個 image tar 檔（如 `pilot-cli.tar`） | `docker load -i pilot-cli.tar` |
| 內部 registry 的存取權 | `docker pull <registry>/pilot-cli:<tag>` 後 `docker tag <registry>/pilot-cli:<tag> pilot-cli:latest` |
| 這份 repo 的原始碼 | `docker build -t pilot-cli:latest -f images/Dockerfile.pilot-cli .`（在 repo 根目錄跑） |

下文所有指令都寫 `pilot-cli:latest`——如果你的 image tag 不是 `latest`，記得換成實際的 tag。

跑一次確認 image 正常：

```bash
docker run --rm pilot-cli:latest
# 應該印出 pilot 的 --help 說明
```

### 0.1 這個 image 怎麼用（唯一需要理解的概念）

image 沒有設固定 `ENTRYPOINT`——`docker run pilot-cli:latest <指令...>` 的
`<指令...>` 就是**直接要跑的指令本身**，可以是下面任何一種：

- `pilot ...`（bake 進去的 Go 執行檔，對應原本的 `go run ./cmd/pilot ...`）
- `ansible-playbook ...` / `ansible-inventory ...` / `ansible-vault ...`（ansible-core，都在 PATH 上）

`playbooks/`、`group_vars/*.example.yml`、`ansible.cfg`、`inventory.example.yml`、
`hosts.example.yml` 已經 bake 進 image 的 `/pilot` 目錄（容器啟動後的工作目錄
就是 `/pilot`）。**你只需要準備會變動的檔案**（`hosts.yml`、`inventory.yml`、
`group_vars/<角色>.yml`、SSH 私鑰、vault 密碼檔），用 `-v` 逐個掛進容器內
`/pilot/` 底下對應的**同名路徑**——不要把整個 `/pilot` 蓋掉，否則會連
baked-in 的 playbooks/ansible.cfg 一起蓋掉。

```
你的機器（host）                容器內（/pilot，已內建 playbooks/ansible.cfg/...）
./hosts.yml            -v->    /pilot/hosts.yml
./inventory.yml         -v->    /pilot/inventory.yml
./group_vars/xxx.yml     -v->    /pilot/group_vars/xxx.yml
~/.ssh/id_ed25519        -v->    /root/.ssh/id_ed25519
~/.vault/xxx.yaml        -v->    /root/.vault/xxx.yaml
```

**重要**：`hosts.yml`/`inventory.yml` 裡的 `ansible_ssh_private_key_file`要填
**容器內**的路徑（例如 `/root/.ssh/id_ed25519`），不是你主機上的路徑——這個
變數是給容器裡的 ansible 用的。

### 0.2 Windows 使用者請先看這裡

- 用 **PowerShell**（不是 `cmd.exe`）。下文每個指令都附 bash（Linux/macOS）
  跟 PowerShell（Windows）兩個版本，差異只有：換行符號（bash 用 `\`、
  PowerShell 用反引號 `` ` ``）、目前目錄變數（`$(pwd)` vs `${PWD}`）。
  Docker Desktop 預設（WSL2 backend）會自動把 `${PWD}`/`$HOME` 這類路徑
  轉成容器認得的格式，不需要手動換成 `/c/Users/...`。
- **SSH 私鑰權限**：Windows 檔案系統沒有 POSIX 權限位元，直接把
  `$HOME\.ssh` bind mount 進容器，容器裡看到的私鑰權限可能太寬鬆，
  OpenSSH 會直接拒絕（`UNPROTECTED PRIVATE KEY FILE`）。解法：先把私鑰複製
  進一個 docker named volume 修正權限，**只需要做一次**：

  ```powershell
  docker volume create pilot-ssh
  docker run --rm `
      -v pilot-ssh:/root/.ssh `
      -v "$HOME\.ssh:/tmp/hostssh:ro" `
      pilot-cli:latest `
      sh -c "cp /tmp/hostssh/id_ed25519 /root/.ssh/id_ed25519 && chmod 600 /root/.ssh/id_ed25519"
  ```

  之後所有指令把 `-v "$HOME\.ssh:/root/.ssh:ro"` 換成 `-v pilot-ssh:/root/.ssh`
  （不要加 `:ro`，且不用重做這一步）。Linux/macOS 直接 bind mount
  `$HOME/.ssh` 通常權限就是對的，不需要這個額外步驟。
- 需要寫回本機檔案的指令（例如 `ansible-vault encrypt`）在 Linux/macOS 上要
  加 `--user "$(id -u):$(id -g)" -e HOME=/tmp`，否則產生的檔案會變成
  `root` 擁有，之後你自己的帳號打不開（見「關於機密」段落）。**Windows 不需要
  加這個**——PowerShell 沒有 `id -u` 這個概念，Docker Desktop 的檔案共用層
  不會有這個 ownership 問題。

---

## 1. 準備 inventory，填入你的機器

**方式 A（推薦）**：寫一份簡表，讓工具展開成正式 inventory——你只需要維護
「這台機器要跑哪些角色」，不用手動把每台機器同步進一堆 `children:` group
（漏一個曾經是一次事故的根因，見 `AGENTS.md` §0）。

先從 image 把範本抽出來（不需要 clone 這份 repo）：

```bash
# bash (Linux/macOS)
docker run --rm pilot-cli:latest cat hosts.example.yml > hosts.yml
```

```powershell
# PowerShell (Windows)
docker run --rm pilot-cli:latest cat hosts.example.yml | Out-File -Encoding utf8 hosts.yml
```

打開 `hosts.yml`，把 `"<FILL-ME>"` 換成真實值，`roles:` 填這台機器要跑的角色：

```bash
# 合法角色清單
docker run --rm pilot-cli:latest pilot inventory roles
```

> 不熟悉終端機文字編輯器（vim/nano）、只習慣 VSCode 之類 GUI 介面的話，可以用
> `pilot edit` 取代「打開檔案改」這一步——選單式問答，挑主機、挑角色、填值，
> 存檔前會再問一次，不需要記 YAML 語法（見下方「`pilot inventory` 指令一覽」
> 後面的說明）。`go run ./cmd/pilot edit` 本機執行最直接；用 Docker 的話要加
> `-it`（互動終端機）並把 `hosts.yml`／`group_vars/` 掛成可寫（不加 `:ro`）。

展開成正式 inventory（展開前會先檢查角色名稱合法、欄位沒漏填、`<FILL-ME>`
沒殘留）。注意 `--out -` 印到 stdout、用主機端的 `>` 重定向寫檔——這樣容器
不需要對掛載進來的檔案做寫入，Windows/Linux 語法也一致。

**這一步也會自動幫你把用到的角色的 `group_vars/<role>.yml` 補齊**——對每個
`hosts.yml` 裡實際出現的 `roles:`，只要 `group_vars/<role>.yml` **還不存在**，
就從對應的 `group_vars/<role>.example.yml` 複製一份過去；已存在的檔案**永遠
不會被覆蓋**。狀態訊息印在 stderr（不會混進 `--out -` 導到 `inventory.yml`
的 stdout）。要讓補齊的檔案落地回 host，容器要多掛一個 `group_vars/` 目錄
（可寫、不加 `:ro`；沒有這個目錄就先 `mkdir -p group_vars` 再掛，即使裡面還
是空的）：

```bash
# bash (Linux/macOS)
mkdir -p group_vars
docker run --rm \
    -v "$(pwd)/hosts.yml:/pilot/hosts.yml:ro" \
    -v "$(pwd)/group_vars:/pilot/group_vars" \
    pilot-cli:latest \
    pilot inventory generate --in hosts.yml --out - > inventory.yml
```

```powershell
# PowerShell (Windows)
New-Item -ItemType Directory -Force group_vars | Out-Null
docker run --rm `
    -v "${PWD}\hosts.yml:/pilot/hosts.yml:ro" `
    -v "${PWD}\group_vars:/pilot/group_vars" `
    pilot-cli:latest `
    pilot inventory generate --in hosts.yml --out - | Out-File -Encoding utf8 inventory.yml
```

不想要這個自動補齊（例如想完全照 §1.5 手動控制），加 `--no-group-vars`。

> 補齊的 `group_vars/` 位置**跟隨 `--out` 所在的目錄**，不是永遠寫死 CWD。
> 上面 `--out -`（印到 stdout）沒有自己的目錄，所以退回 CWD；但若你把
> `--out` 指到一個子目錄，例如 `--out envs/staging/inventory.yml`，補齊的
> 檔案會落在 `envs/staging/group_vars/`，跟那份 `inventory.yml` 放一起——
> 適合同時維護多個環境（`envs/staging/`、`envs/prod/`…）各自一包完整的
> `{inventory.yml, group_vars/}`，彼此不會互相干擾。範本本身（`.example.yml`）
> 一律讀自固定的 `./group_vars/`（image 內建位置或 repo 根目錄），跟 `--out`
> 無關。

只想先檢查、不產生檔案：

```bash
docker run --rm -v "$(pwd)/hosts.yml:/pilot/hosts.yml:ro" pilot-cli:latest \
    pilot inventory lint --in hosts.yml
```

**方式 B（手改）**：直接抽出 inventory 範本自己編輯（跟方式 A 產出的格式相容，
挑一種維護即可）：

```bash
docker run --rm pilot-cli:latest cat inventory.example.yml > inventory.yml
```

打開 `inventory.yml`，把每個 `"<FILL-ME>"` 換成真實值（每行右邊的 `#` 註解說明格式）。
**只有 `"<FILL-ME>"` 需要改；group 結構照留。用不到的角色 group 整段刪掉即可。**

> 觀念：`inventory.yml` **只放「主機 + 歸屬」**。每台機器只在 `all.hosts:` 定義一次
> （IP／連線），再把它列進 `children:` 底下對應的角色 group（`freeipa-server`、
> `linux-servers`…）。playbook 靠 group 自動找到目標。**角色的『設定值』另外放
> group_vars（見下一步）**，不要塞進 inventory。每個角色 group 對應哪支
> playbook、有什麼前置條件，見下方「Playbook 對照表」。

### 1.5 （需要時）設定角色參數 → group_vars

有些角色需要幾個設定值（例如 PAM-OIDC 要 Keycloak 位址、FreeIPA 要 realm）。
這些**不寫進 inventory、也不用每次打一長串 `-e`**，改成放在跟 `inventory.yml`
同一個目錄下的 `group_vars/<group>.yml`，設定「一次」即可。

> **用了方式 A（`pilot inventory generate`）的話，這一步大概已經自動做完
> 一半**——你 `hosts.yml` 裡實際用到的角色，對應的 `group_vars/<role>.yml`
> 應該已經被複製好了（先 `ls group_vars/` 確認）。這裡剩下要做的只是**打開
> 檔案填值**；不需要重新複製。用了方式 B（手改 `inventory.yml`）或關掉了
> `--no-group-vars` 的話，才需要下面手動抽出範本這一段。

同樣先從 image 抽出你會用到的範本（檔名要等於 group 名，去掉 `.example` 才會生效）：

```bash
mkdir -p group_vars
docker run --rm pilot-cli:latest sh -c "ls group_vars/*.example.yml"   # 看有哪些範本
docker run --rm pilot-cli:latest cat group_vars/freeipa.example.yml       > group_vars/freeipa.yml
docker run --rm pilot-cli:latest cat group_vars/linux-servers.example.yml > group_vars/linux-servers.yml
docker run --rm pilot-cli:latest cat group_vars/dns.example.yml           > group_vars/dns.yml
docker run --rm pilot-cli:latest cat group_vars/ntp.example.yml           > group_vars/ntp.yml
docker run --rm pilot-cli:latest cat group_vars/audit-log-forwarding.example.yml > group_vars/audit-log-forwarding.yml
docker run --rm pilot-cli:latest cat group_vars/wazuh-manager.example.yml  > group_vars/wazuh-manager.yml
docker run --rm pilot-cli:latest cat group_vars/wazuh-fim.example.yml      > group_vars/wazuh-fim.yml
docker run --rm pilot-cli:latest cat group_vars/restic-backup.example.yml  > group_vars/restic-backup.yml
```

打開複製出來的檔案，照註解填。沒用到的角色不用複製；不填的值會沿用內建預設。
之後每支 apply/site 指令都要把用到的 `group_vars/xxx.yml` 逐個掛進
`/pilot/group_vars/xxx.yml`（見 §4 的範例），跟 `inventory.yml` 一樣是「只掛
會變動的檔案，不蓋掉整個目錄」。

> 為什麼分開？inventory 回答「有哪些機器、各是什麼」；group_vars 回答「每種角色怎麼設定」。
> 兩者分開後 inventory 保持精簡、設定集中一處，兩邊都更難填錯。
> 機密（密碼）仍走 ansible-vault，別寫進 group_vars 明文（見「關於機密」段落）。

## 2. 跑前置檢查（會告訴你哪裡填錯、連不連得到）

```bash
# bash (Linux/macOS)
docker run --rm -it \
    -v "$HOME/.ssh:/root/.ssh:ro" \
    -v "$(pwd)/inventory.yml:/pilot/inventory.yml:ro" \
    pilot-cli:latest \
    ansible-playbook -i inventory.yml playbooks/preflight.yml
```

```powershell
# PowerShell (Windows) — 若已用 §0.2 的 pilot-ssh volume，把第一個 -v 換成
# `-v pilot-ssh:/root/.ssh`
docker run --rm -it `
    -v "$HOME\.ssh:/root/.ssh:ro" `
    -v "${PWD}\inventory.yml:/pilot/inventory.yml:ro" `
    pilot-cli:latest `
    ansible-playbook -i inventory.yml playbooks/preflight.yml
```

- 全綠 → 繼續第 3 步。
- 紅字 → 照訊息修 `inventory.yml`（缺欄位、忘了換 `<FILL-ME>`、私鑰路徑錯 [記得是容器內路徑]、或 SSH 連不上）。

> 只想先檢查填寫、機器還沒開？加 `--tags static` 只做靜態檢查、不連線（這一步
> 甚至不需要掛 SSH 私鑰目錄，只需要私鑰檔本身存在於掛進去的路徑）。

## 3.（選用）視覺確認 inventory 結構符合預期

```bash
docker run --rm -v "$(pwd)/inventory.yml:/pilot/inventory.yml:ro" pilot-cli:latest \
    ansible-inventory -i inventory.yml --graph
```

會畫出「哪台機器在哪個 group」的樹狀圖，確認你填的跟你想的一致。

## 4. 套用

**方式 A（推薦，一鍵）**：用 `site.yml` 一次跑全站，它會**自動先做 preflight**，
沒過就不會套用任何東西。你的 inventory 裡**空的 group 會自動跳過**，所以只會跑到
你實際填了機器的元件：

```bash
# bash (Linux/macOS)
docker run --rm -it \
    -v "$HOME/.ssh:/root/.ssh:ro" \
    -v "$(pwd)/inventory.yml:/pilot/inventory.yml:ro" \
    -v "$(pwd)/group_vars/freeipa.yml:/pilot/group_vars/freeipa.yml:ro" \
    -v "$(pwd)/group_vars/linux-servers.yml:/pilot/group_vars/linux-servers.yml:ro" \
    pilot-cli:latest \
    ansible-playbook -i inventory.yml playbooks/site.yml
```

```powershell
# PowerShell (Windows)
docker run --rm -it `
    -v "$HOME\.ssh:/root/.ssh:ro" `
    -v "${PWD}\inventory.yml:/pilot/inventory.yml:ro" `
    -v "${PWD}\group_vars\freeipa.yml:/pilot/group_vars/freeipa.yml:ro" `
    -v "${PWD}\group_vars\linux-servers.yml:/pilot/group_vars/linux-servers.yml:ro" `
    pilot-cli:latest `
    ansible-playbook -i inventory.yml playbooks/site.yml
```

> 每支需要 group_vars 的角色都要多加一個對應的 `-v .../group_vars/<x>.yml:/pilot/group_vars/<x>.yml:ro`；
> 沒有客製化設定值的角色（用內建預設就好）不需要掛，容器裡本來就 bake 了對應的
> `group_vars/<x>.example.yml`（**注意**：只有去掉 `.example` 的檔名才會被
> Ansible 載入生效——這正是為什麼要用實際檔名掛進去，不能只掛 `.example.yml`）。

只想跑某一類元件，用 tag 篩選（preflight 仍會先跑）：

```bash
docker run --rm -it -v "$HOME/.ssh:/root/.ssh:ro" -v "$(pwd)/inventory.yml:/pilot/inventory.yml:ro" \
    pilot-cli:latest \
    ansible-playbook -i inventory.yml playbooks/site.yml --tags freeipa
```

**方式 B（granular）**：單獨跑某一支 playbook，各自作用在對應角色 group（見下表）：

```bash
# 把 web-1 / web-2（linux-servers group）納入補丁管理
docker run --rm -it -v "$HOME/.ssh:/root/.ssh:ro" -v "$(pwd)/inventory.yml:/pilot/inventory.yml:ro" \
    pilot-cli:latest \
    ansible-playbook -i inventory.yml playbooks/apply/os-patch-sla-apply.yml

# 只想針對其中一台
docker run --rm -it -v "$HOME/.ssh:/root/.ssh:ro" -v "$(pwd)/inventory.yml:/pilot/inventory.yml:ro" \
    pilot-cli:latest \
    ansible-playbook -i inventory.yml playbooks/apply/os-patch-sla-apply.yml --limit web-1
```

> **`-e target_group=...` 只能在方式 B（單獨跑一支 playbook）用，`site.yml` 不能帶。**
> 每支 apply playbook 都用同一個變數名 `target_group` 覆寫自己的預設目標 group；
> 但 `site.yml` 一次 `import_playbook` 串接全部元件，`-e` 是全域的，一旦帶了
> `target_group`，會**同時**覆寫全部子 playbook 的目標——等於讓「空 group 自動
> 跳過」這條核心保護整個失效。`site.yml` 開頭現在有一道安全閥會擋下這個誤用：
>
> ```bash
> docker run --rm -v "$(pwd)/inventory.yml:/pilot/inventory.yml:ro" pilot-cli:latest \
>     ansible-playbook -i inventory.yml playbooks/site.yml -e target_group=all
> # → 第一個 play 直接 fail："target_group 不能在全站入口使用 ..."
> ```
>
> 全站執行要限定機器，改用 `--limit <host>`；要用 `target_group` 做角色×環境
> 交集鎖定，直接跑對應的單一 apply playbook（方式 B）。

---

## 5. 驗收（交付證據）

套用完成不等於交付完成——**用 `pilot verify` 對照 spec 逐條驗收**，產出的
報告就是交付證據。每個元件對應一份 spec（`docs/verification/<元件>.md`，
對應關係見下方 Playbook 對照表），對你**實際部署的每個元件**跑一次：

```bash
# bash (Linux/macOS) — 掛一個本機目錄接住報告，驗完留檔
mkdir -p .verification
docker run --rm -it \
    -v "$HOME/.ssh:/root/.ssh:ro" \
    -v "$(pwd)/inventory.yml:/pilot/inventory.yml:ro" \
    -v "$(pwd)/.verification:/pilot/.verification" \
    pilot-cli:latest \
    pilot verify docs/verification/freeipa-server.md -i inventory.yml
# verdict: **PASS**  (pass=18 fail=0 skip=0)
```

- 每次執行落兩個檔在 `.verification/`：`<spec>-<UTC>.md`（PASS/FAIL 表格，
  **這就是驗收報告**，直接附進交付紀錄）與同名 `.ndjson`（原始輸出）。
- exit code：全部 row PASS 才是 0——可以直接接 CI / 腳本判斷。
- 部署了多個元件就逐一跑；inventory 覆蓋**全部**角色的全站部署，可以用
  `pilot verify --dir docs/verification -i inventory.yml` 一次驗完並印
  rollup 總表（注意：`--dir` 會跑目錄下**每一份** spec，只部署部分元件時
  沒部署的 spec 會 FAIL，這種情況請逐份指定）。

### 定期重驗（交付後的持續正確）

主機交付後仍會漂移（有人手動改設定、套件更新覆蓋檔案…）。建議在操作機
排一個每週重驗，exit code 非 0 就告警：

```bash
# /etc/cron.d/pilot-reverify — 每週一 06:00 重驗，失敗寫 syslog（接上你既有
# 的告警管道；部署了 alertmanager 的話也可以改打 webhook）
0 6 * * 1  ops  cd /opt/pilot-delivery && \
  docker run --rm -v "$HOME/.ssh:/root/.ssh:ro" \
      -v "$(pwd)/inventory.yml:/pilot/inventory.yml:ro" \
      -v "$(pwd)/.verification:/pilot/.verification" \
      pilot-cli:latest \
      pilot verify docs/verification/freeipa-server.md -i inventory.yml \
  || logger -p user.err -t pilot-reverify "spec re-verify FAILED — check .verification/"
```

---

## `pilot inventory` 指令一覽

方式 A（見步驟 1）用到的三個子指令，全部透過 `docker run pilot-cli:latest pilot inventory ...` 執行：

| 指令 | 做什麼 |
|---|---|
| `pilot inventory roles` | 列出所有合法的 `roles:` 值（19 個角色 group），每個附一行說明對應哪支 playbook |
| `pilot inventory lint --in hosts.yml` | 只檢查、不產生檔案：角色名稱合法、`ansible_host` 沒漏填、沒有殘留 `<FILL-ME>`、`env` 值合法 |
| `pilot inventory generate --in hosts.yml --out -` | 檢查通過後展開成正式 inventory，印到 stdout（用主機端 `>` 重定向寫檔）；檢查沒過會直接列出全部錯誤 |

```bash
docker run --rm pilot-cli:latest pilot inventory roles
docker run --rm -v "$(pwd)/hosts.yml:/pilot/hosts.yml:ro" pilot-cli:latest pilot inventory lint --in hosts.yml
docker run --rm -v "$(pwd)/hosts.yml:/pilot/hosts.yml:ro" pilot-cli:latest pilot inventory generate --in hosts.yml --out - > inventory.yml
```

> 這三個指令只碰掛進去的 `hosts.yml`（讀）跟 stdout（寫），不連線、不套用任何東西，可以隨時重跑。

### `pilot edit` — 選單式編輯 hosts.yml / group_vars（免文字編輯器）

不想／不熟悉直接改 YAML 檔的話，`pilot edit` 提供跟 `pilot deploy` 同一套
選單式問答介面，把「打開檔案、找到那一行、改值、存檔」變成「選主機→選欄位
→輸入新值」：

- **hosts.yml**：新增/刪除主機、逐欄編輯 `ansible_host`／`ansible_user`／SSH
  金鑰路徑／`env`、勾選角色、管理額外變數（如 `ipa_server_ip`）。存檔前會照
  `pilot inventory lint` 同一套規則跑一次檢查，但**檢查不通過也可以先存檔**
  （草稿模式，方便分次填）。
  角色編輯進「主機的角色」選單後有三個選項：
  - **逐項勾選角色**：方向鍵移動、space 勾選/取消、enter 完成——單一畫面
    持續操作，游標停在你上次的位置，不會像逐個確認的選單一樣每按一次就
    跳回清單最上面。
  - **套用常用角色範本**：未客製時提供與
    `docs/runbooks/minimal-poc-architecture.md` 實際 inventory 完全一致的三組：
    FreeIPA 身份伺服器、Nexus 中央服務節點、被監控的 Linux 主機。FreeIPA replica
    不在 minimal PoC；需要時從「管理角色範本」新增。
  - **管理角色範本**：新增、修改或刪除範本；第一次儲存時會在同一個 `--dir`
    建立 `role-presets.yml`。該檔案存在後會完整取代內建清單，因此每個環境可有
    不同的選單內容；也可從選單刪除檔案還原內建範本。
  - **複製自其他主機的角色**：直接整組複製 `hosts.yml` 裡任何一台已經設定好
    角色的主機——最適合「這批機器角色都跟那台一樣」的情境，一次選好之後
    再用逐項勾選微調即可。
  範本／複製兩個捷徑都只會**加進**目前已勾的角色，不會移除既有的，套錯了
  也不怕，用逐項勾選畫面移除即可。
  - 兩者都只會**加進**目前已勾的角色，不會移除既有的，套錯了也不怕。
- **group_vars/\*.yml**：列出檔案裡目前每個設定值（含尚未啟用、只是註解掉的
  範例值），選一項會先印出它上面的中文說明再讓你填新值；改值只會動那一行，
  其他註解、排版原樣保留。也可以「還原成內建預設」把某個值重新註解掉。

```bash
go run ./cmd/pilot edit          # 本機執行，最直接
```

預設編輯目前資料夾底下的 `hosts.yml`／`group_vars/`；加 `--dir <資料夾>`
可以改編輯另一個資料夾——適合同時維護多包環境。`pilot inventory generate`
也有同一個 `--dir`，兩個指令對同一包環境用同一個資料夾即可，不用分別記
`--in`/`--out`：

```bash
go run ./cmd/pilot edit --dir envs/staging               # 編輯 envs/staging/hosts.yml、envs/staging/group_vars/
go run ./cmd/pilot inventory generate --dir envs/staging # 讀 envs/staging/hosts.yml，展開成 envs/staging/inventory.yml
```

> `--dir` 只是換掉 `--in`/`--out`的預設值（分別變成 `<dir>/hosts.yml`、
> `<dir>/inventory.yml`）；額外指定 `--in`/`--out` 一樣會覆蓋掉 `--dir`
> 算出來的路徑，兩者不衝突。`--dir` 指到的資料夾不存在也沒關係，存檔/產生
> 時會自動建立。但「從範例建立 `group_vars/<role>.yml`」這一步的範例來源
> (`.example.yml`)一律讀自固定的 `./group_vars/`（image 內建位置或 repo 根
> 目錄），跟 `--dir` 無關——`edit` 跟 `inventory generate` 的 group_vars
> 補齊邏輯是同一套規則。

用 Docker 的話要加 `-it`（選單需要即時終端機）並把 `hosts.yml`／`group_vars/`
掛成可寫（不能是 `:ro`，因為存檔要寫回去）：

```bash
docker run --rm -it \
    -v "$(pwd)/hosts.yml:/pilot/hosts.yml" \
    -v "$(pwd)/group_vars:/pilot/group_vars" \
    pilot-cli:latest pilot edit
```

> `pilot edit` 改完 `hosts.yml` 後仍要照方式 A 跑一次
> `pilot inventory generate` 才會反映到正式 `inventory.yml`；它不會自動幫你展開。
> Render 回存 `hosts.yml` 時不會保留原本的中文說明註解（`hosts.example.yml`
> 那份導覽性質的頭尾註解會消失，欄位本身的值不受影響）——`group_vars/*.yml`
> 則沒有這個限制，逐行改寫會保留所有註解。

---

## Playbook 對照表

| 想做的事 | Playbook | 預設作用的 group |
|---|---|---|
| 建 FreeIPA 身份伺服器 | `playbooks/apply/freeipa-server-apply.yml` | `freeipa-server` |
| 把機器納入 FreeIPA（AAA） | `playbooks/apply/freeipa-client-apply.yml` | `freeipa-client` |
| 建 Kerberos NFSv4 server（目標須先納入 FreeIPA；支援 RedHat 與 Debian/Ubuntu） | `playbooks/apply/freeipa-nfs-server-apply.yml` | `freeipa-nfs-server` |
| 啟用 FreeIPA automount NFS client（目標須先納入 FreeIPA） | `playbooks/apply/freeipa-nfs-client-apply.yml` | `freeipa-nfs-client` |
| 管理 FreeIPA 使用者／權限 | `playbooks/apply/freeipa-identity-apply.yml` | (見下方「機密」) |
| 把第二台（或後續台）FreeIPA server 加入既有 realm（multi-master HA） | `playbooks/apply/freeipa-server-replica-apply.yml` | `freeipa-server-replica`（**v0.1 草稿、未實跑**，見 `docs/verification/freeipa-server-replica.md` §0；限制與已知偏差見該檔 §5）|
| DNS／NTP 等核心服務 | `playbooks/apply/core-infra-provider-apply.yml` | 依 `-e infra_role=dns\|ntp` |
| Container 引擎(Docker) | `playbooks/apply/docker-apply.yml` | `docker`（keycloak-db/keycloak、seaweedfs-s3、wazuh-manager、prometheus/thanos-query/alertmanager 等角色的前置） |
| Keycloak（IdP） | `playbooks/apply/keycloak-apply.yml` | `keycloak` |
| Keycloak 資料庫 | `playbooks/apply/keycloak-db-apply.yml` | `keycloak-db` |
| SSH 走 OIDC 登入 | `playbooks/apply/pam-oidc-sshd-apply.yml` | `linux-servers` |
| 中央稽核日誌接收(SIEM) | `playbooks/apply/log-server-apply.yml` | `log-server` |
| 主機稽核(auditd)+ 轉送到 log-server | `playbooks/apply/audit-log-forwarding-apply.yml` | `audit-log-forwarding` |
| Wazuh 中央伺服器(FIM/who-data 告警引擎 + CVE 弱點掃描；Docker 部署，主機需先過 docker preflight) | `playbooks/apply/wazuh-manager-apply.yml` | `wazuh-manager`（需至少 4 vCPU/8GB RAM/50GB 磁碟，見 `docs/runbooks/wazuh-manager.md` §5） |
| Wazuh agent(檔案完整性監控 FIM + auditd who-data) | `playbooks/apply/wazuh-fim-apply.yml` | `wazuh-fim` |
| S3 相容物件儲存(SeaweedFS) | `playbooks/apply/seaweedfs-s3-apply.yml` | `seaweedfs-s3` |
| 跨主機通用備份到 S3(restic) | `playbooks/apply/restic-backup-apply.yml` | `restic-backup`（需先有 S3 目的地，見 `docs/runbooks/restic-backup.md` §5 的 SeaweedFS 匿名模式/簽章相容性注意事項） |
| OS 補丁 SLA | `playbooks/apply/os-patch-sla-apply.yml` | 依 `-e patch_stage=` |

> 每支 apply playbook 的檔頭註解都有完整的參數與範例（用 `docker run --rm pilot-cli:latest cat playbooks/apply/<role>-apply.yml | head -50` 看）；
> `--limit <host>` 可把任何一次執行縮到單一機器，`-e target_group='dns:&prod'` 可用「角色×環境」交集精準鎖定。
> 注意：這裡的 `Wazuh 中央伺服器`「主機需先過 docker preflight」指的是**目標主機**要有 Docker（該角色本身用 Docker 部署），跟你這裡用來執行 pilot 的 `pilot-cli` 容器是兩件不相關的事。

---

## 上 staging / production 前要多做的事

上面「四步上手」預設跑在 `stage: sandbox`（每支 apply playbook 內建的預設值），
**不用加任何旗標就會直接套用**。要套到 `staging` / `production`，有支援的 apply
playbook 在 `pre_tasks` 就有 confirm gate，沒帶對應旗標會直接 `assert` 失敗、
不套用任何東西：

| 目標 stage | 要加的旗標 |
|---|---|
| `sandbox`（預設） | 不用加 |
| `staging` | `-e stage=staging -e confirm_staging=true` |
| `prod` | `-e stage=prod -e confirm_prod=true -e staging_attested_within_hours=<實際小時數>`（需 ≤168，即近 7 天內做過 staging 驗證） |

```bash
# 全站套到 staging
docker run --rm -it -v "$HOME/.ssh:/root/.ssh:ro" -v "$(pwd)/inventory.yml:/pilot/inventory.yml:ro" \
    pilot-cli:latest \
    ansible-playbook -i inventory.yml playbooks/site.yml \
        -e stage=staging -e confirm_staging=true

# 全站套到 prod（假設 3 天前做過 staging 驗證 → 72 小時）
docker run --rm -it -v "$HOME/.ssh:/root/.ssh:ro" -v "$(pwd)/inventory.yml:/pilot/inventory.yml:ro" \
    pilot-cli:latest \
    ansible-playbook -i inventory.yml playbooks/site.yml \
        -e stage=prod -e confirm_prod=true -e staging_attested_within_hours=72
```

`site.yml` 用 `import_playbook` 串接各元件，`-e` 是全域旗標，一次帶入就會套到
所有有支援 gate 的元件，不用每支各帶一次。

> **`staging_attested_within_hours` 預設值就是 168**——沒覆寫的話，gate 會用
> 「剛好卡在邊界」的預設值直接放行，等於沒檢查。要讓這道門檻有意義，自己量出
> 「上次 staging 驗證距今幾小時」的真實數字再帶入，別把預設值一路帶到 prod。

**`stage` 跟 `target_group`（或 inventory 裡的 `staging` / `prod` group）是兩件
不相關的事，但這兩件事現在會互相檢查**：

- `target_group` 決定**打哪些機器**（例如 `-e target_group='dns:&prod'`）。
- `stage` 決定**這次套用要不要過 confirm gate**。
- inventory 裡的 `staging` / `prod` group 純粹是給 `target_group` 篩選用的環境標籤，
  **不會自動決定 `stage`**——但每支有 stage gate 的 apply playbook，`pre_tasks`
  現在都多一道「stage 必須與這台機器所屬的環境 group 一致」的 `assert`：
  - 機器在 inventory 的 `staging` group,但 `stage` 不是 `staging` → 直接 fail。
  - 機器在 inventory 的 `prod` group,但 `stage` 不是 `prod` → 直接 fail。
  - 帶了 `-e stage=staging`/`prod`,但機器根本不在對應的環境 group 裡 → 直接 fail。

> **這正是用來擋下「忘了帶 `-e stage=`」這種誤會的安全網**——機器一旦被歸類
> 進 `staging`/`prod` group,同一條指令沒帶對的 `-e stage=` 會直接被 `assert`
> 擋下來,逼你明確帶對應旗標。

### 完整規則(常見誤解:「要套用就一定要指定 stage」——不對,要看這台機器有沒有被歸類)

> 對**有 stage gate** 的 playbook,服務會不會套用到某台機器 `H`,規則是:
>
> 1. **`H` 必須在該服務的角色 group 裡**(inventory 有填這台機器)——這條件永遠必要,
>    跟 stage 無關,沒填就不會被 Ansible 選中,連 gate 都不會跑到。
> 2. 再看 `H` 在 inventory 裡有沒有被歸進 `staging` / `prod` 環境 group:
>    - **沒被歸類**(既不在 `staging` 也不在 `prod`,例如剛開的測試機)
>      → **不用帶 `-e stage=`**,預設 `sandbox` 就會直接套用。
>    - **被歸類進 `staging`** → **必須**帶 `-e stage=staging -e confirm_staging=true`,
>      帶錯(或沒帶,預設 sandbox)都會被上面的 cross-check `assert` 擋下來,不會套用。
>    - **被歸類進 `prod`** → **必須**帶 `-e stage=prod -e confirm_prod=true
>      -e staging_attested_within_hours=<實際小時數>`,同樣帶錯就擋下來。
>
> 換句話說:**「指定 stage」不是永遠的必要條件,只有在機器已經被歸進 `staging`/
> `prod` 時才變成必填**;「服務角色 group 有填這台機器」則永遠必要。

**`playbooks/apply/*.yml` 全部 20 支都有這個 gate,規則一致,沒有例外**
（`os-patch-sla-apply.yml` 的旗標名稱不同,是 `-e patch_stage=`，不是
`-e stage=`,其餘用法一致,詳見該檔頭部註解）:

```bash
# 不管哪一支,一旦機器已歸類進 staging/prod,都要靠對的 stage 才會套用
docker run --rm -it -v "$HOME/.ssh:/root/.ssh:ro" \
    -v "$(pwd)/inventory.yml:/pilot/inventory.yml:ro" \
    pilot-cli:latest \
    ansible-playbook -i inventory.yml playbooks/apply/wazuh-fim-apply.yml \
        -e stage=staging -e confirm_staging=true -e wazuh_manager_host=<manager IP>
```

---

## 關於機密（密碼／管理員憑證）

需要密碼的 playbook（FreeIPA、Keycloak）**不要**把密碼寫進 inventory。放進一份
**加密的 vars 檔**、且不要進 git。

先從 image 抽出範本，編輯填入真實使用者與密碼：

```bash
docker run --rm pilot-cli:latest cat playbooks/apply/freeipa-identity.roster.example.yaml > ~/.vault/ipa-identity.yaml
# 編輯 ~/.vault/ipa-identity.yaml 填入真實值
```

加密（**注意**：`ansible-vault encrypt`/`edit`/`rekey` 是「就地改寫檔案」，
必須掛**該檔案所在的目錄**、不能只掛那一個檔案本身——單獨掛一個檔案時，
容器裡 vault 改寫檔案的暫存/rename 步驟會因為那個掛載點本身就是 mount
point 而失敗（`Device or resource busy`）。掛整個目錄就沒有這個問題）：

```bash
# bash (Linux/macOS) —— 加 --user + HOME=/tmp,產生的檔案才會是你自己的帳號擁有,
# 不會變成 root:root 讓你之後打不開
docker run --rm --user "$(id -u):$(id -g)" -e HOME=/tmp \
    -v "$HOME/.vault:/root/.vault" \
    pilot-cli:latest \
    ansible-vault encrypt /root/.vault/ipa-identity.yaml
```

```powershell
# PowerShell (Windows) —— 不需要 --user/HOME,Docker Desktop 的檔案共用層
# 沒有這個 ownership 問題
docker run --rm `
    -v "$HOME\.vault:/root/.vault" `
    pilot-cli:latest `
    ansible-vault encrypt /root/.vault/ipa-identity.yaml
```

套用時帶入（vault 密碼檔一樣要掛進去；同樣建議放一個獨立目錄，方便一次掛整個
`.vault` 目錄）：

```bash
docker run --rm -it \
    -v "$HOME/.ssh:/root/.ssh:ro" \
    -v "$(pwd)/inventory.yml:/pilot/inventory.yml:ro" \
    -v "$HOME/.vault:/root/.vault:ro" \
    pilot-cli:latest \
    ansible-playbook -i inventory.yml playbooks/apply/freeipa-identity-apply.yml \
        -e @/root/.vault/ipa-identity.yaml --vault-password-file /root/.vault/vault-pass
```

各 `.roster.example.yaml` / apply playbook 檔頭都有該 playbook 所需機密的 schema 說明
（用 `docker run --rm pilot-cli:latest cat <path> | head -60` 看）。

---

## 常見卡關

| 症狀 | 原因 / 解法 |
|---|---|
| preflight 報「殘留 `<FILL-ME>`」 | 有欄位忘了填，打開 `hosts.yml`/`inventory.yml` 搜尋 `FILL-ME`（用方式 A 的話：`docker run --rm -v "$(pwd)/hosts.yml:/pilot/hosts.yml:ro" pilot-cli:latest pilot inventory lint --in hosts.yml`） |
| `pilot inventory generate`/`lint` 報 unknown role | `hosts.yml` 的 `roles:` 打錯字或角色不存在，跑 `docker run --rm pilot-cli:latest pilot inventory roles` 看合法清單 |
| preflight ping 失敗 / `UNREACHABLE` | 機器沒開 / IP 錯 / `ansible_user` 錯 / 私鑰不是該帳號的 / 22 埠被擋——跟是否用 docker 無關 |
| preflight 報「私鑰檔不存在」，但你確定主機上有那個檔 | `ansible_ssh_private_key_file` 填的是**主機路徑**，但這個變數是給容器內的 ansible 讀的——要填**容器內**的路徑（例如 `/root/.ssh/id_ed25519`），並確認 `-v` 有把私鑰掛到那個路徑 |
| Windows 上 SSH 連線出現 `UNPROTECTED PRIVATE KEY FILE` / `Permission denied (publickey)`（其他都對） | Windows bind mount 私鑰的權限位不對，照 §0.2 用 named volume + `chmod 600` 的方式掛 |
| `docker run` 說某個檔案 `no such file or directory` | 忘了用 `-v` 把該檔案掛進容器，或掛的容器內路徑跟指令裡引用的路徑不一致（例如掛到 `/pilot/inv.yml` 但指令寫 `-i inventory.yml`） |
| `ansible-vault encrypt`/`edit` 報 `Device or resource busy` | 掛載時只掛了那一個檔案本身，改成掛**該檔案所在的目錄**（見「關於機密」段落） |
| `ansible-vault encrypt`/`pilot inventory generate` 產生的檔案之後用一般帳號打不開 | 容器預設用 root 執行；Linux/macOS 上寫回本機檔案的指令要加 `--user "$(id -u):$(id -g)" -e HOME=/tmp`（見「關於機密」段落）；或改用 `--out -`／stdout 重定向的寫法完全避開這個問題（見 §1） |
| playbook 說少了某個 `-e` 變數 | 依錯誤訊息補上，或改用加密 vars 檔 `-e @/root/.vault/...yaml` 帶入（記得先用 `-v` 把 vault 檔掛進容器） |
