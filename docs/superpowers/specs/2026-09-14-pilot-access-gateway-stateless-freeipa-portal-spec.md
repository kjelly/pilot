# Pilot Access Gateway — Stateless FreeIPA-backed Portal 實作規格

- 狀態：**已實作（Phase 0-8 全數完成，見下方 Implementation Status）**
- 日期：2026-09-14

## Implementation Status（2026-09-14 實作完成後補記）

§60 的 Phase 0-8 已全數依序實作完成，分 9 個 commit（各 Phase 各自可獨立 vm-target 驗收，符合 §0 G5 禁止大爆炸實作的規則）：

1. `feat(pilot-access-gateway): Phase 0 — validate Go SPNEGO FreeIPA transport spike`
2. `feat(pilot-access-gateway): Phase 1 — internal/freeipaaccess FreeIPA client`
3. `feat(pilot-access-gateway): Phase 2 — internal/accessportal scope resolver`
4. `feat(pilot-access-gateway): Phase 3 — peer identity + Gateway API`
5. `feat(pilot-access-gateway): Phase 4 — pilot portal read-only TUI`
6. `feat(pilot-access-gateway): Phase 5 — controlled SSH Connect`
7. `feat(pilot-access-gateway): Phase 6 — gateway scope publication`
8. `feat(pilot-access-gateway): Phase 7 — deployment integration`
9. `feat(pilot-access-gateway): Phase 8 — multi-gateway E2E`

每個 Phase 的實測證據都在 `docs/evidence/pilot-access-gateway/2026-09-14-phase{0..8}-*.md`；驗收 checklist 在
`docs/verification/pilot-access-gateway.md`（AG01-AG30 已實測，AG31 為站台網路層需求、明確不在本 repo 範圍）；contract 在
`contracts/pilot-access-gateway.yaml`。§60 每個 Phase 段落下方都有對應的完成度 blockquote，記錄該 Phase 實測時發現的
gotcha/deviation/bug（含幾個修正過的自我誤判，見 Phase 7 的 systemd/nsswitch 那段）。

過程中共發現並修正的重大 bug（詳見各 Phase evidence doc）：
- Phase 1：`raw` vs 非-`raw` FreeIPA API 回傳格式差異、`allow_all` 內建 HBAC rule 會讓驗證假陽性。
- Phase 3：`pkill -f` 自我誤殺、`/root` 目錄權限擋住非 root 使用者存取 socket。
- Phase 7：local fallback group 被 nsswitch `files` 來源永久遮蔽同名 FreeIPA 群組、`RuntimeDirectory=` 宣告在錯的 systemd unit 上、`ipa service-add` 要求正向 DNS record 先存在。
- Phase 8：`internal/freeipaaccess.NewClient` 原本同步載入 keytab 導致缺檔時整個 process crash、進而讓 socket-activated 的 systemd 單元卡進 start-rate-limit 永久失效；playbook 原本只能開不能關 ForceCommand 的不對稱性。

本文件其餘內容維持實作前的原始規格文字（含 §0 的 gate/修正記錄、§51 的 contract schema 修正說明），供之後回頭查證設計意圖時參照；
以上 Implementation Status 只是事後補記的完成度總覽，不是本文件唯一的真相來源——各 evidence doc 與 `docs/verification/`
才是逐項驗收結果的權威記錄。
> Date: 2026-09-08
> Revised: 2026-09-14 — 加入 §0 Implementation Readiness Gates，修正 §51 contract 欄位以符合 `internal/contract.Contract` 實際 schema，補 §11.1/§55/§60 的驗收門檻
> Repository: `https://github.com/kjelly/pilot`
> Baseline: `main@6ff866cd92961650e279dfb1b1967f1ef01fb104`
> Audience: Coding Agent / Pilot maintainers
> Scope: **使用者登入 Portal → 看自己能 SSH 哪些 Pilot-scope targets → 看 live sudo 權限 → SSH 到目標主機**
> Supersedes: `2026-09-08-pilot-stateless-freeipa-portal-spec.md`，並正式定名 Access Gateway / Gateway Scope 模型

---

## 0. Implementation Readiness Gates（先讀）

本規格審閱後，對照現有 repo（HEAD）事實查核，發現以下四點若不先處理，直接照單全收實作會有真實風險。這些 gate 是**強制**的，優先度高於後面任何章節的具體設計細節——後面章節若與這裡衝突，以這裡為準。

### G1 — Phase 0（transport spike）是 go/no-go gate，不是裝飾用的章節

> **2026-09-14 更新：Phase 0 已完成，見 `docs/evidence/pilot-access-gateway/2026-09-14-phase0-transport-spike.md`。** 決定：採用 direct Go SPNEGO（`github.com/jcmturner/gokrb5/v8`，MIT、無 cgo），不需要 `kinit`+`curl` fallback。額外發現一個坑：FreeIPA httpd 對**任何** `/ipa/session/*` 請求（含 `login_kerberos` 本身）若缺 `Referer` header 一律回 400 "denied"，`internal/freeipaaccess` 的 HTTP 層每個請求都要帶 `Referer: https://<fqdn>/ipa`。以下原文保留供對照。

`go.mod`/`go.sum` 目前沒有任何 Kerberos/SPNEGO 套件，而 `scripts/build-agent-controller.sh`、`scripts/build-detection-engine.sh` 已經對每個既有元件強制 `CGO_ENABLED=0` 的純 Go build policy。§54 已經自己承認這是未知數，但本文件其餘章節（§11-§35 的 API/config/資料模型）已經把細節寫死成 final 設計——這等於在驗證可行性之前就定案了架構。

**規則：**
1. `internal/freeipaaccess` 的 transport 必須先在一個獨立、小範圍的 spike 中對**真實 FreeIPA**（vm-target 或既有 freeipa-identity/freeipa-dns 測試拓樸）證明：service principal Kerberos 認證 + JSON-RPC 讀取可行。
2. 若純 Go SPNEGO library 不存在或會破壞 `CGO_ENABLED=0` policy，直接採用 §11.1 的 fallback（固定 argv 的 `kinit` + `curl --negotiate`），並把這個決定連同證據（實際跑過的 log/腳本）記錄下來。
3. 在 Phase 0 產出這份證據之前，§11-§21 的 interface/資料結構視為「暫定」，Coding Agent 不得假設可以不驗證就照抄實作。
4. Phase 0 的產出本身應該是一個可以獨立 review/merge 的小改動（例如 `internal/freeipaaccess` 的 `Ping`/`LoadUserContext` 兩個方法 + fixture），不要和 Phase 1 的其餘功能綁在同一個 PR。

### G2 — `internal/freeipaaccess` 是全新元件，repo 內沒有可重用的 FreeIPA client 先例

目前 repo 唯一的 Go FreeIPA package 是 `internal/freeipa/`（`probe.go`、`identity_probe.go` 等），但它並不直接呼叫 FreeIPA API——它是包一層 `ansible-playbook` 再解析輸出 JSON。所有實際的 FreeIPA 讀寫（`freeipa-identity-apply.yml` 等）都是 Ansible 呼叫 `ipa` CLI。

**規則：** §11 的 JSON-RPC/Kerberos client 是從零開始寫，不是重構既有 code。實作排期與 review 深度應該按「新元件」而非「延伸既有能力」估算；不要假設 `internal/freeipa/` 的任何程式碼可以被 `internal/freeipaaccess` 重用。

### G3 — Contract schema 現況：不要發明新欄位

`internal/contract/contract.go` 的 `Loader.LoadFile` 用 `yaml.Decoder.KnownFields(true)` 解析，任何 contract YAML 出現 schema 沒定義的欄位會直接 decode 失敗。目前 `Contract` struct（同檔 26-51 行）**沒有** `stateless` 或 `persistent_data` 欄位。

原始 §51 寫的：
```yaml
component = pilot-access-gateway
stateless = true
persistent_data = []
```
這兩個欄位不存在，照抄會讓 `pilot-access-gateway.yaml` 直接載入失敗。**§51 已經改寫**（見下方修訂版），改用既有 schema 已經提供的欄位（`lifecycle.decommission.class`、既有 `evidenceRequirement`、既有 verification rows AG17-AG19）表達「這個元件無持久狀態」，不再要求擴充 contract schema。若日後確實需要一個顯式的 `stateless` 欄位，那是一個獨立、影響所有 contract 的 schema 變更，需要另外立案，不應該夾帶在本 feature 裡。

### G4 — §33/§55 的 ForceCommand 是「登入路徑劫持」等級變更，repo 內沒有先例可循

`grep -rln "ForceCommand\|Match Group" playbooks/apply/` 目前是零結果。既有會碰 `sshd_config` 的 playbook（`pam-oidc-sshd-apply.yml`、`freeipa-client-apply.yml`）都只調整認證方式，從未把整個使用者群組的互動 shell 換成 captive command。一旦這段設定錯誤部署到真實主機，會直接把一群使用者的 SSH 鎖死。

**規則（已併入 §55，這裡重申為 gate）：**
1. 任何環境都不得對非 disposable 的主機部署 ForceCommand 設定，除非已經在 vm-target 上完整跑過一次「鎖定回歸測試」：apply 後，用**兩個獨立 SSH session**分別驗證 (a) `role-pilot-portal-user` 成員進入 `pilot-session` 而非一般 shell、(b) `role-pilot-admin` 成員仍然拿到一般互動 shell、(c) 回滾（移除 drop-in + reload sshd）之後兩者都恢復一般 shell。
2. 這個回歸測試必須留下 vm-target 證據（trec 錄影或等價紀錄），比照本專案既有 vm-target 測試慣例，而不是只靠 code review 判斷「這樣寫應該對」。
3. Production 部署前需要有人明確核准這一步（不是 CI 自動跑過就算數）。

### G5 — 禁止一次性大爆炸實作

本文件涵蓋 Phase 0 到 Phase 8（§60），總計 66 節、8 個 phase。每個 Phase 必須各自可以獨立 commit、獨立在 vm-target 上驗收，**不得**把多個 Phase 合成同一個大 PR 一次性生出。Phase 順序即依賴順序：後面 Phase 的設計細節，只有在前面 Phase 通過各自的驗收證據後才視為 final；如果 Phase 0/1 的實測結果和本文件目前寫死的細節衝突（例如 JSON-RPC 欄位形狀、cache TTL 是否夠用），以實測結果為準並回頭修正本文件，而不是硬套原始設計。

---

## 1. 核心決策與正式命名

本規格正式採用以下名稱：

| 對象 | 正式名稱 |
|---|---|
| 使用者 CLI/TUI | `pilot portal` |
| 背景 binary | `pilot-access-gateway` |
| systemd service | `pilot-access-gateway.service` |
| systemd socket | `pilot-access-gateway.socket` |
| Unix socket | `/run/pilot/access-gateway.sock` |
| Deployment component | `pilot-access-gateway` |
| Gateway host naming | `pilot-gw-<scope>-<nn>` |
| FreeIPA gateway hostgroup | `pilot-access-gateways` |
| FreeIPA target hostgroup | `pilot-target-<scope>` |
| Local service account | `pilot-gateway` |

**不使用 `pilotd`。**

原因：這個 daemon 的責任是特定且可水平複製的 SSH Access Gateway，不是 Pilot 的全域 daemon。Pilot repository 目前也採 component-specific binary 命名，例如 `pilot-agent-controller`、`pilot-detection-engine`；`pilot-access-gateway` 與此方向一致。

`pilot-access-gateway` 定義為：

> **read-only、stateless、FreeIPA-backed access gateway service**

每台 Gateway 有自己的 instance identity 與 access scope：

```yaml
gateway:
  id: gpu-01
  scope: gpu
  target_hostgroup: pilot-target-gpu
```

`gateway.id` 與 `gateway.scope` 必須分離：

```text
gpu-01 ─┐
gpu-02 ─┼── scope=gpu
gpu-03 ─┘
```

同 scope 的多台 Gateway 可以完全同質化部署；不同 scope 的 Gateway 必須得到不同 target hostgroup。

Runtime access formula：

```text
ConnectableHosts(user, gateway)
=
EffectiveFreeIPASSHHosts(user)
INTERSECT
EffectiveMembers(gateway.target_hostgroup)
```

若網路本身還有 egress ACL，實際可連線集合自然再受到網路限制；但 **network reachability 不是 access policy source**，不能用「連得到」取代 FreeIPA/HBAC 判斷。

`pilot-access-gateway` 的 runtime decision **只讀遠端 FreeIPA live state**。

Production 不得讀：

```text
canonical roster
inventory.yml / hosts.yml
grant JSON
breakglass activation JSON
SQLite
Git checkout
Ansible vars
```

允許本機存在：

```text
immutable gateway config
FreeIPA read-only service keytab
FreeIPA CA
root-managed SSH client policy
Unix socket
ephemeral /run credentials
in-memory TTL cache
```

這些都不屬於 persistent application state。

## 2. 目標使用流程

Gateway 主機例如：

```text
pilot-gw-gpu-01.linker.internal
pilot-gw-gpu-02.linker.internal
pilot-gw-dmz-01.linker.internal
```

使用者：

```bash
ssh alice@pilot-gw-gpu-01.linker.internal
```

流程：

```text
user workstation
       |
       v
pilot-gw-gpu-01
       |
       +-- sshd
       +-- PAM / SSSD / FreeIPA authentication
       +-- FreeIPA HBAC
       +-- Match Group
       +-- ForceCommand
       v
pilot portal
       |
       | /run/pilot/access-gateway.sock
       v
pilot-access-gateway
       |
       | remote FreeIPA JSON-RPC
       v
Effective SSH access
       INTERSECT
pilot-target-gpu
       |
       v
My Hosts / sudo
       |
       v
Connect
       |
       v
/usr/bin/ssh -F /etc/pilot/ssh_config <fqdn>
       |
       v
target sshd + SSSD + FreeIPA
```

Portal header 必須顯示目前 Gateway：

```text
Pilot Portal

Gateway  gpu-01
Scope    gpu
User     alice
────────────────────────────

> My Hosts
  My Identity
  Refresh
  Logout
```

`gpu` scope 下：

```text
pilot-target-gpu
├── gpu01.linker.internal
├── gpu02.linker.internal
└── gpu03.linker.internal
```

假設 Alice 的 FreeIPA HBAC 可登入：

```text
gpu01
gpu02
dev01
db01
```

這台 Gateway 最終只能顯示：

```text
gpu01
gpu02
```

因為：

```text
{gpu01,gpu02,dev01,db01}
INTERSECT
{gpu01,gpu02,gpu03}
=
{gpu01,gpu02}
```

退出 remote SSH 後回到同一個 `pilot portal`。

## 3. Source of Truth

### 3.1 Management plane

Pilot 現有：

```text
roster
inventory
pilot edit
pilot deploy
pilot reconcile
grant compiler
breakglass activation
```

仍負責：

> 「FreeIPA 應被設定成什麼狀態。」

Management plane 可以使用 roster、inventory、vault、Git、Ansible。

### 3.2 Runtime plane

FreeIPA 負責：

> 「現在實際存在什麼 access state。」

Runtime data：

```text
users
groups
hosts
hostgroups
HBAC
sudo rules
sudo commands / command groups
```

### 3.3 Final enforcement

目標主機的：

```text
sshd
PAM
SSSD
FreeIPA HBAC
sudo/SSSD
```

仍是 final enforcement。

Portal 只能：

```text
discover
explain
pre-authorize
launch ssh
```

---

## 4. Baseline Pilot 能力

Coding Agent 必須重新讀 HEAD：

```text
internal/inventory/roster_effective.go
internal/inventory/explain.go
internal/inventory/grant_compile.go
internal/accessgrants/explain.go
internal/accessgrants/breakglass.go
internal/sandbox/ssh.go
internal/tui/
cmd/pilot/cmd/access_*.go
cmd/pilot/cmd/edit_tui_roster_*.go
```

目前已存在：

1. nested user groups
2. nested hostgroups
3. static HBAC
4. static sudo
5. `temporary_grant -> managed HBAC`
6. `sudo_grant -> managed FreeIPA sudo rule`
7. breakglass activation -> managed HBAC
8. `sudoNotBefore / sudoNotAfter`
9. deterministic Pilot-managed rule names

新版 Portal 保留 semantics，但 input 改成 **FreeIPA live API objects**。

---

## 5. Goals

- `pilot-access-gateway` 不讀 roster。
- `pilot-access-gateway` 不讀 inventory。
- `pilot-access-gateway` 不保存 persistent application state。
- Runtime access data只來自 FreeIPA。
- 每台 Gateway 的 target scope由 `gateway.target_hostgroup` 定義。
- Default naming為 `pilot-target-<scope>`。
- Caller identity來自 `SO_PEERCRED`。
- User group/HBAC/sudo membership從 remote FreeIPA 查。
- `Connect` 每次 fresh authorize。
- Portal不實作 SSH protocol。
- 同 scope可部署多台 Gateway，不需 state sync。
- 不同 scope之間不共享 target set。
- Gateway scope與網路 egress boundary應做 defense-in-depth 對齊。
- 任一 Gateway instance可以直接 replace/restart，不需 migration。

## 6. Non-goals

v1 不做：

```text
Web UI
Portal mutation
grant request
breakglass activation UI
session history
SSH keystroke/output recording
SCP/SFTP portal
arbitrary SSH host
arbitrary remote command
agent forwarding
TCP forwarding
X11 forwarding
pilot deploy through portal
roster edit through portal
```

Portal v1 不要求顯示：

```text
grant reason
ticket
breakglass activated_by
activation history
```

---

## 7. Stateless 定義

允許：

```text
process memory
memory TTL cache
Kerberos ticket in memory
ephemeral files under /run
systemd runtime socket
FreeIPA session cookie in memory or /run
stdout/journald log
```

禁止：

```text
persistent local DB
persistent access snapshot
persistent app history
persistent decrypted roster
persistent inventory copy
```

---

## 8. High-level Architecture

```text
                              Management Plane

 roster / inventory / Git
          |
          v
 Pilot reconcile / deploy
          |
          +------------------------------+
          |                              |
          v                              v
+----------------------+        +----------------------+
|       FreeIPA        |        | Network / ACL Plane  |
|                      |        |                      |
| users / groups       |        | gpu gateways may SSH |
| hosts / hostgroups   |        | only GPU segment     |
| HBAC / sudo          |        |                      |
|                      |        +----------------------+
| pilot-access-gateways|
| pilot-target-gpu     |
| pilot-target-dmz     |
+----------+-----------+
           |
           | HTTPS JSON-RPC / Kerberos
           |
     +-----+--------------------------+
     |                                |
     v                                v
+----------------------+       +----------------------+
| pilot-gw-gpu-01     |       | pilot-gw-gpu-02     |
| gateway.id=gpu-01   |       | gateway.id=gpu-02   |
| gateway.scope=gpu   |       | gateway.scope=gpu   |
| target=pilot-target-|       | target=pilot-target-|
| gpu                  |       | gpu                  |
|                      |       |                      |
| pilot portal         |       | pilot portal         |
| pilot-access-gateway|       | pilot-access-gateway|
+----------+-----------+       +----------+-----------+
           |                              |
           +---------- SSH ---------------+
                          |
                          v
                 GPU target hosts
```

另一個 scope：

```text
pilot-gw-dmz-01
  scope=dmz
  target_hostgroup=pilot-target-dmz
```

其 Portal 絕對不能因使用者在 FreeIPA 還有 GPU 權限，就顯示 GPU hosts。

### 8.1 DNS / VIP 規則

允許同 scope 多台 Gateway 共用 service alias：

```text
pilot-gpu.linker.internal
  -> pilot-gw-gpu-01
  -> pilot-gw-gpu-02
```

也可：

```text
pilot-dmz.linker.internal
  -> pilot-gw-dmz-01
  -> pilot-gw-dmz-02
```

**禁止單一 DNS/VIP 將使用者隨機導到不同 scope：**

```text
pilot.linker.internal
  -> gpu gateway
  -> dmz gateway        # 禁止
```

否則同一入口會得到非 deterministic target set。

若要保留通用名稱 `pilot.linker.internal`，它後面的所有 Gateway 必須使用相同 `gateway.scope` **且相同 `gateway.target_hostgroup`**。不同 scope 不可共用同一個 random-balancing alias。

## 9. Gateway Target Scope

### 9.1 FreeIPA gateway hostgroup

所有 Portal Gateway 主機加入：

```text
pilot-access-gateways
```

例如：

```text
pilot-access-gateways
├── pilot-gw-gpu-01.linker.internal
├── pilot-gw-gpu-02.linker.internal
└── pilot-gw-dmz-01.linker.internal
```

這個 hostgroup主要用於控制：

```text
誰可以 SSH 到 Access Gateway
```

推薦 FreeIPA HBAC：

```text
subjects:
  role-pilot-portal-user

targets:
  pilot-access-gateways

services:
  sshd
```

管理員 shell 使用獨立 role/rule，例如：

```text
role-pilot-admin
 -> pilot-access-gateways
 -> sshd
```

`role-pilot-admin` 不應 nested 進 forced `role-pilot-portal-user`，避免管理員也被 `ForceCommand`。

**`pilot-access-gateways` 不代表 Gateway 可以跳到哪些 target。**
Gateway 的 inward target scope只由下一節的 `pilot-target-<scope>` 定義。

### 9.2 Scope-specific target hostgroup

每個 access scope 使用：

```text
pilot-target-<scope>
```

例如：

```text
pilot-target-gpu
pilot-target-dmz
pilot-target-hq
pilot-target-prod
```

Gateway config：

```yaml
gateway:
  id: gpu-01
  scope: gpu
  target_hostgroup: pilot-target-gpu
```

### 9.3 Runtime access formula

```text
ConnectableHosts(user, gateway)
=
EffectiveHBACSSHHosts(user)
INTERSECT
EffectiveMembers(gateway.target_hostgroup)
```

沒有全域 `pilot-managed-hosts` 依賴。

如果 management plane 另外需要 `pilot-managed-hosts` 作 inventory classification，可以保留，但 **Portal runtime不能依賴它**。

### 9.4 Nested target hostgroups

`pilot-target-<scope>` 可以 nested hostgroup：

```text
pilot-target-gpu
├── gpu-production
└── gpu-development
```

Gateway必須遞迴展開：

```text
member_host
member_hostgroup
```

具備：

```text
cycle guard
dedupe
stable sort
```

### 9.5 Fail closed

若 configured `gateway.target_hostgroup`：

```text
不存在
無法讀取
解析超過 graph limit
```

則：

```text
My Hosts = empty
Connect = denied
health = degraded
```

不得 fallback到：

```text
all IPA hosts
another scope
a global target hostgroup
```

### 9.6 Management-plane publication

`pilot-access-gateway` 不讀 inventory。

因此 Pilot management plane 負責：

```text
desired target set
 -> FreeIPA pilot-target-<scope>
```

新增：

```text
pilot gateway-scope plan --scope gpu
pilot gateway-scope reconcile --scope gpu
```

或等價 structured action。

對每個 scope輸出：

```text
add
remove
keep
```

Runtime Gateway只讀 FreeIPA結果。

## 10. Identity Model

有三個不同 identity/context，必須分開。

### 10.1 Portal caller identity

Portal連 Unix socket。

Server：

```text
SO_PEERCRED
 -> PID
 -> UID
 -> GID
```

再：

```text
getent passwd <uid>
```

只將 kernel UID映射成 username。

不得信任：

```text
$USER
$LOGNAME
request username
SSH_ORIGINAL_COMMAND
```

User access group membership仍由 remote FreeIPA查，不以 local `id -Gn` 作 runtime access truth。

### 10.2 Gateway instance identity

每台 Gateway有 immutable identity：

```yaml
gateway:
  id: gpu-01
  scope: gpu
  target_hostgroup: pilot-target-gpu
```

`id` 用於：

```text
logs
health
UI display
instance diagnostics
```

`scope` 用於：

```text
human-readable access zone
DNS/VIP grouping
deployment grouping
```

`target_hostgroup` 才是 runtime target scope的 machine-readable policy reference。

不得把 hostname本身 parse成 security policy；hostname naming只是 operational convention。

### 10.3 FreeIPA service identity

推薦 principal：

```text
pilot-access-gateway/pilot-gw-gpu-01.linker.internal@LINKER.INTERNAL
```

keytab：

```text
/etc/pilot/pilot-access-gateway.keytab
```

owner：

```text
pilot-gateway:pilot-gateway 0400
```

禁止：

```text
admin keytab
admin password
Directory Manager password
```

建立 FreeIPA read-only role：

```text
Pilot Access Gateway Reader
```

Required operations：

```text
ping
user_show
group_show
host_show
hostgroup_show
hbacrule_find
hbacrule_show
hbacsvcgroup_show
sudorule_find
sudorule_show
sudocmd_show
sudocmdgroup_show
optional hbactest
```

Deployment必須 probe：

```text
required reads succeed
mutations fail
```

至少：

```text
user_add -> denied
hbacrule_add -> denied
sudorule_add -> denied
```

## 11. FreeIPA Provider

新增：

```text
internal/freeipaaccess/
```

interface（原始草案）：

```go
type Provider interface {
    Ping(ctx context.Context) error
    LoadUserContext(ctx context.Context, username string) (UserContext, error)
    LoadAccessSnapshot(ctx context.Context, username string) (Snapshot, error)
    CheckSSH(ctx context.Context, username, fqdn string) (Decision, error)
}
```

> **Phase 1 實作修正（2026-09-14，見 `docs/evidence/pilot-access-gateway/2026-09-14-phase1-freeipaaccess.md`）：** 上面這個「已解析」介面（`LoadUserContext`/`LoadAccessSnapshot` 回傳 closure-expanded 資料）改放到 `internal/accessportal`（Phase 2），因為 §36 package layout 本來就把 group/hostgroup closure 展開與 HBAC/sudo 交集邏輯劃給 `accessportal`。`internal/freeipaaccess.Provider` 實際實作成一個 RPC method 對一個 Go method 的原始讀取介面（`Ping`/`UserShow`/`GroupShow`/`HostShow`/`HostgroupShow`/`HBACRuleFind`/`HBACServiceGroupShow`/`SudoRuleFind`/`SudoCommandShow`/`SudoCommandGroupShow`/`HBACTest`），回傳「已 normalize 但未展開 closure」的原始物件（例如 `User.DirectGroups` 只有直接成員，沒有展開）。`accessportal` 的 resolver 會在這些原始方法上組出 `UserContext`/`Snapshot`/`Decision`。好處：這個 package 的測試完全靠 fixture 就能跑，不需要引入 Phase 2 的 graph 概念。

Resolver / Portal 不可直接依賴 transport。

Production transport：

```text
FreeIPA HTTPS JSON-RPC
```

官方 endpoint：

```text
https://<ipa>/ipa/session/login_kerberos
https://<ipa>/ipa/session/json
```

TLS CA：

```text
/etc/ipa/ca.crt
```

禁止：

```text
InsecureSkipVerify
curl -k
```

### 11.1 Transport implementation

先做 capability spike（§0 G1 的強制 gate，不是選項）。

Spike 完成的判定標準（exit criteria，缺一不可）：

```text
1. 對一台真實/vm-target FreeIPA server 完成 service principal Kerberos 認證
2. 至少一次成功的 read-only JSON-RPC 呼叫（例如 ping 或 user_show）拿到解析後的結構化結果
3. 確認 CGO_ENABLED=0 build policy是否可維持；若否，明確記錄改走 fallback
4. 這次 spike 的程式碼/腳本與呼叫紀錄可作為後續 Phase 1 fixture 的依據
```

在以上 4 點都有證據之前，§11-§21 的 interface 與資料結構視為暫定草案，不得直接進入 Phase 2 以後的實作。

> **已於 2026-09-14 完成，全部 4 點通過**（見 `docs/evidence/pilot-access-gateway/2026-09-14-phase0-transport-spike.md`）。決定採用下面 Preferred 選項 1（direct Go SPNEGO），不需要 fallback。

Preferred：

1. direct Go JSON-RPC + Kerberos/SPNEGO，維持 `CGO_ENABLED=0`
2. 若不符合 dependency policy，fallback 為 fixed `kinit` + `curl --negotiate`

Fallback 必須：

```text
exec.CommandContext
fixed argv
no shell
credentials only in /run
parse JSON-RPC response only
```

禁止：

```text
parse human ipa CLI output
parse ipa -vv debug output
```

### 11.2 RPC allowlist

Provider 只允許 read method。

任何 method 不在 allowlist：

```text
reject locally
```

---

## 12. FreeIPA Server Discovery / Failover

config：

```yaml
gateway:
  id: gpu-01
  scope: gpu
  fqdn: pilot-gw-gpu-01.linker.internal
  target_hostgroup: pilot-target-gpu

  freeipa:
    servers:
      - ipa1.linker.internal
      - ipa2.linker.internal
    ca_file: /etc/ipa/ca.crt
    service_principal: pilot-access-gateway/pilot-gw-gpu-01.linker.internal@LINKER.INTERNAL
    keytab: /etc/pilot/pilot-access-gateway.keytab
```

若 `servers` 未提供，可讀：

```text
/etc/ipa/default.conf
```

只作 config discovery。

Failover：

```text
ipa1 timeout/5xx
 -> ipa2
```

Authorization/RPC permission error不可 retry 成另一種判定。


---

## 13. User Group Resolution

對 current user：

```text
user_show(username, all=true)
```

取得 direct groups，再用：

```text
group_show(group)
```

沿 parent group closure 展開 effective groups。

> **Phase 2 實作修正（2026-09-14，見 `docs/evidence/pilot-access-gateway/2026-09-14-phase2-accessportal.md`）：不需要遞迴呼叫 `group_show`。** 實測發現 FreeIPA 的 `memberof` plugin 已經在 server 端算好完整 transitive closure，直接掛在同一次 `user_show(username, all=true)` 回應裡：`memberof_group`(direct) + `memberofindirect_group`(所有層級的間接 parent group，一次到位)。用真實 3 層巢狀 group 鏈實測驗證過，包含刻意做出一個 cycle（group 互相巢狀）的情況——FreeIPA 沒有拒絕這個 cycle，`memberofindirect_group` 依然算出正確、有終止的結果（cycle 唯一的副作用是該 group 會出現在自己的 `memberindirect_group` 裡，這個欄位本來就不是我們拿來算 `EffectiveGroups` 用的）。因此 `EffectiveGroups = memberof_group ∪ memberofindirect_group`，是一次 RPC call + 集合聯集，不是 graph walk，也不需要自己做 cycle guard。

模型：

```go
type UserContext struct {
    Username        string
    DirectGroups    []string
    EffectiveGroups []string
}
```

要求：

```text
nested groups
cycle guard
dedupe
stable sort
max graph nodes
context cancellation
```

Portal Access 不依賴 local `id -Gn` 作 authorization source。

---

## 14. Gateway Target Host Expansion

Root hostgroup不是固定全域名稱，而是 config：

```text
gateway.target_hostgroup
```

例如：

```text
pilot-target-gpu
```

使用：

```text
hostgroup_show(gateway.target_hostgroup)
```

遞迴收集：

```text
member_host
member_hostgroup
```

> **Phase 2 實作修正：不需要遞迴。** 同 §13 的發現，`hostgroup_show(target_hostgroup, all=true)` 單一一次呼叫就給 `member_host`(direct) + `memberindirect_host`(FreeIPA 算好的完整 transitive host closure，不管巢狀幾層)。用真實的 `hg-parent ⊂ hg-child` 巢狀鏈實測過，也刻意做出 hostgroup 互相巢狀的 cycle（`hg-child` 又巢狀回 `hg-parent`）——FreeIPA 一樣沒拒絕，`memberindirect_host` 依然正確終止(cycle只會讓 hostgroup 出現在自己的 `memberindirect_hostgroup`，這欄位不影響我們算的 host 集合)。因此 `EffectiveHosts = member_host ∪ memberindirect_host`，同樣是一次 RPC + 集合聯集，§36 原規劃的 `graph.go`（generic cycle-guard walker）沒有實作，因為沒有東西需要 walk。

輸出（實作用 `map[string]struct{}` 取代 `ManagedHost`，v1 尚未有除了「存在」以外的 per-host metadata）：

```go
type GatewayScope struct {
    GatewayID      string
    Scope          string
    TargetHostgroup string
    Hosts          map[string]struct{}
}
```

FQDN canonicalization（已實作，見 `canonicalizeFQDN`，套用在每個 host 進入集合或被比較的地方）：

```text
lowercase
trim trailing dot for identity comparison
```

v1 不接受 IP literal作 Portal target。

任何 host不在此 expansion中：

```text
不可顯示
不可 detail
不可 Connect
```

即使 FreeIPA HBAC對該 host為 allow。

## 15. HBAC Snapshot

load：

```text
hbacrule_find(all=true, raw=true)
```

> **Phase 1 修正：不用 `raw=true`，只用 `all=true`。** 實測（見 `docs/evidence/pilot-access-gateway/2026-09-14-phase1-freeipaaccess.md`）：`raw=true` 把 member 屬性回傳成 LDAP DN（要自己解析 container 名稱分類 user/group/host/hostgroup），且 sudo command 只給不透明的 `ipaUniqueID`，拿不到指令文字。`all=true`（非 raw）直接給已分類、已解析成純文字的屬性（`memberuser_user`/`memberuser_group`/`memberhost_host`/`memberhost_hostgroup`/`memberservice_hbacsvc`/`memberservice_hbacsvcgroup`），完全不用解析 DN。以下沿用原文，但實作一律用 `all=true`。

必要時補：

```text
hbacrule_show
hbacsvcgroup_show
```

normalize：

```go
type HBACRule struct {
    Name    string
    Enabled bool

    UserCategoryAll bool
    Users           []string
    Groups          []string

    HostCategoryAll bool
    Hosts           []string
    Hostgroups      []string

    ServiceCategoryAll bool
    Services           []string
    ServiceGroups      []string
}
```

### 15.1 Subject match

match if：

```text
UserCategoryAll
OR username direct
OR rule.Groups intersects user.EffectiveGroups
```

### 15.2 Target match

match if：

```text
HostCategoryAll
OR host direct
OR host is effective member of referenced hostgroup
```

最終仍必須：

```text
host ∈ EffectiveMembers(gateway.target_hostgroup)
```

### 15.3 Service match

Portal v1只處理：

```text
sshd
```

match if：

```text
ServiceCategoryAll
OR sshd direct
OR sshd in referenced HBAC service group
```

disabled HBAC rule：

```text
never grants
```

---

## 16. Connect-time HBAC Verification

`GET /v1/access` 可以使用 snapshot cache。

真正按 `Connect`：

```text
POST /v1/connect/authorize
```

必須 fresh check。

推薦：

```text
hbactest
```

作 additional verification，前提是 target FreeIPA version與 reader permission實測可用。

若不採 `hbactest`：

```text
reload minimum fresh user/rule/host state
 -> resolve again
```

decision data最大年齡：

```text
default 5s
```

FreeIPA unreachable：

```text
DENY
```

不能使用 stale allow decision。

---

## 17. Sudo Snapshot

load：

```text
sudorule_find(all=true, raw=true)
```

> **Phase 1 修正：同 §15，不用 `raw=true`，只用 `all=true`。** 非 raw 給 `memberallowcmd_sudocmd`（指令文字本身）/`memberallowcmd_sudocmdgroup`/`memberdenycmd_sudocmd`/`memberdenycmd_sudocmdgroup`/`memberuser_user`/`memberuser_group`/`memberhost_host`/`memberhost_hostgroup`，一樣不用解析 DN。

normalize：

```go
type SudoRule struct {
    Name    string
    Enabled bool

    UserCategoryAll bool
    Users           []string
    Groups          []string

    HostCategoryAll bool
    Hosts           []string
    Hostgroups      []string

    CommandCategoryAll bool
    AllowCommands      []string
    AllowCommandGroups []string

    DenyCommands      []string
    DenyCommandGroups []string

    RunAsUsers  []string
    RunAsGroups []string
    Options     []string

    NotBefore *time.Time
    NotAfter  *time.Time
}
```

### 17.1 Time semantics

active iff：

```text
Enabled
AND now >= NotBefore if set
AND now < NotAfter if set
```

全部 timestamp normalize UTC。

### 17.2 Command groups

使用：

```text
sudocmdgroup_show
sudocmd_show
```

展開 command members。

同一 command group snapshot只 query一次。

### 17.3 Display scope

enum：

```text
none
limited
all
all_with_deny
```

規則：

- `none`: 無 active matching rule。
- `limited`: specific allow commands/groups。
- `all`: command category all 且無 deny。
- `all_with_deny`: allow all 但存在 deny。

若 allow/deny semantics複雜，UI顯示 rule-by-rule：

```text
Allow
Deny
Rule
```

不要過度宣稱已計算完整 shell-level final sudo set。

---

## 18. Pilot-managed Grant Runtime Semantics

目前 Pilot：

```text
temporary_grant -> managed HBAC
sudo_grant      -> managed FreeIPA sudo rule
breakglass      -> active managed HBAC
```

因此 stateless `pilot-access-gateway` 直接讀 FreeIPA：

```text
active runtime access自然可見
```

不需要 local grant/breakglass state。

### 18.1 Dynamic login rule

名稱：

```text
pilot-grant-login-...
```

Portal可標：

```text
Pilot-managed HBAC
```

但 v1 不假設可區分：

```text
temporary_grant vs breakglass
```

### 18.2 Dynamic sudo rule

名稱：

```text
pilot-grant-sudo-...
```

可標：

```text
Pilot-managed sudo
```

### 18.3 Intentionally unavailable metadata

Portal v1 不顯示：

```text
reason
ticket
activation history
activated_by
```

因這些不是 FreeIPA runtime access truth。

---

## 19. Access Result Model

新增：

```text
internal/accessportal/
```

模型：

```go
type UserAccess struct {
    User        string
    GeneratedAt time.Time
    Hosts       []HostAccess
}

type HostAccess struct {
    FQDN string
    SSH  SSHAccess
    Sudo SudoAccess
}

type SSHAccess struct {
    Allowed bool
    Rules   []RuleSource
}

type SudoAccess struct {
    Scope string

    AllowCommands []string
    DenyCommands  []string

    Rules []SudoRuleSource
}

type RuleSource struct {
    Rule          string
    Managed       bool
    DirectUser    bool
    ViaGroups     []string
    DirectHost    bool
    ViaHostgroups []string
}
```

---

## 20. Memory-only Cache

允許：

```text
in-memory cache
```

restart後全部消失。

default：

```text
user context TTL:       10s
scope targets TTL:      10s
HBAC TTL:               10s
sudo TTL:               10s
connect decision age:    5s max
```

同一 cache refresh 使用 singleflight/equivalent，避免 Portal request storm。

禁止：

```text
disk cache
snapshot restore
cache DB
```

如果 cache expired 且 FreeIPA query失敗：

```text
503
```

v1 不提供 stale access list，簡化 fail-closed semantics。

---

## 21. Query Plan

每個 `GET /v1/access` 不可 N × hosts 查詢。

推薦：

```text
1. user_show(current user)
2. resolve user group closure

3. hostgroup_show(gateway.target_hostgroup)
4. resolve managed host closure

5. hbacrule_find
6. collect referenced:
     user groups
     hostgroups
     service groups
7. batch/fetch graph nodes

8. sudorule_find
9. collect referenced:
     user groups
     hostgroups
     sudo command groups
10. batch/fetch graph nodes

11. normalize
12. resolve in memory
```

FreeIPA `batch` command若 target version實測可用，優先使用。

否則 bounded concurrency：

```text
max 8 RPCs default
```

---

## 22. `pilot-access-gateway` API

使用：

```text
HTTP over Unix domain socket
/run/pilot/access-gateway.sock
```

不 listen TCP。

### 22.1 `GET /v1/identity`

```json
{
  "uid": 145820001,
  "username": "alice",
  "gateway": {
    "id": "gpu-01",
    "scope": "gpu",
    "target_hostgroup": "pilot-target-gpu"
  }
}
```

### 22.2 `GET /v1/access`

只查 current socket peer user。

Response必須包含 Gateway context：

```json
{
  "user": "alice",
  "gateway": {
    "id": "gpu-01",
    "scope": "gpu",
    "target_hostgroup": "pilot-target-gpu"
  },
  "generated_at": "2026-09-08T10:00:00+08:00",
  "hosts": []
}
```

不提供：

```text
?user=bob
?scope=dmz
?target_hostgroup=...
```

Client不能覆寫 Gateway scope。

### 22.3 `GET /v1/access/{fqdn}`

要求：

```text
fqdn ∈ EffectiveMembers(gateway.target_hostgroup)
AND current user effective SSH access == allow
```

### 22.4 `POST /v1/connect/authorize`

body：

```json
{
  "target": "gpu02.linker.internal"
}
```

禁止 body指定：

```text
username
gateway_id
scope
target_hostgroup
SSH options
```

Server使用自己的 immutable config。

Response：

```json
{
  "allowed": true,
  "target": "gpu02.linker.internal",
  "username": "alice",
  "gateway_id": "gpu-01",
  "gateway_scope": "gpu",
  "checked_at": "2026-09-08T10:00:00+08:00",
  "rules": ["gpu-user-ssh"]
}
```

### 22.5 `GET /v1/health`

```json
{
  "status": "ok",
  "gateway_id": "gpu-01",
  "gateway_scope": "gpu",
  "target_hostgroup": "pilot-target-gpu",
  "freeipa": "reachable",
  "target_scope": "ok",
  "credential": "ok"
}
```

不回 secret/path content。

## 23. No Session State

前一版：

```text
session_id
SQLite session history
POST /sessions/{id}/finish
```

全部刪除。

原因：

```text
不符合 stateless goal
```

真正 SSH login lifecycle由：

```text
target sshd
target journal
central logging
```

負責。

`pilot-access-gateway`只輸出 decision log。

因此 Portal v1 **沒有 Session History menu**。

---

## 24. Logging

`pilot-access-gateway`只輸出 structured logs；不保存本機 session DB。

Access query：

```text
event=access_query
gateway_id=gpu-01
gateway_scope=gpu
peer_uid=145820001
username=alice
host_count=2
duration_ms=84
```

Connect：

```text
event=connect_authorize
gateway_id=gpu-01
gateway_scope=gpu
target_hostgroup=pilot-target-gpu
username=alice
target=gpu02.linker.internal
decision=allow
rules=gpu-user-ssh
```

不同 scope 的集中 log必須能用：

```text
gateway_scope
gateway_id
```

分群。

禁止 log：

```text
keytab
Kerberos ticket
session cookie
password
raw FreeIPA response
```

輸出：

```text
stdout/stderr -> journald
```

集中化 persistence屬平台 logging，不是 Gateway application state。

## 25. Local Filesystem

Production Gateway：

```text
/etc/pilot/
├── portal.yaml
├── access-gateway.yaml
├── pilot-access-gateway.keytab
├── ssh_config
└── ssh_known_hosts

/etc/ipa/
└── ca.crt

/run/pilot/
├── access-gateway.sock
├── optional krb5 ccache
└── optional IPA cookie jar
```

binary：

```text
/usr/bin/pilot
/usr/local/libexec/pilot-access-gateway
/usr/local/libexec/pilot-session
```

**不得要求：**

```text
/var/lib/pilot/access-gateway/
/var/lib/pilot/pilot-access-gateway/
```

Local service account：

```text
pilot-gateway
```

其 home可設定為：

```text
/nonexistent
```

或 distro-supported system-account home，不得用 home作 persistent state。

## 26. Config

`/etc/pilot/access-gateway.yaml`：

```yaml
gateway:
  id: gpu-01
  scope: gpu
  fqdn: pilot-gw-gpu-01.linker.internal
  target_hostgroup: pilot-target-gpu

  socket_path: /run/pilot/access-gateway.sock
  portal_user_group: role-pilot-portal-user

  freeipa:
    servers:
      - ipa1.linker.internal
      - ipa2.linker.internal

    ca_file: /etc/ipa/ca.crt

    service_principal: pilot-access-gateway/pilot-gw-gpu-01.linker.internal@LINKER.INTERNAL
    keytab: /etc/pilot/pilot-access-gateway.keytab

    request_timeout: 5s
    cache_ttl: 10s
    connect_max_age: 5s
```

Required：

```text
gateway.id
gateway.scope
gateway.fqdn
gateway.target_hostgroup
```

`scope` 不可由 hostname自動 parse後當 security truth。

Config **不能出現**：

```yaml
roster_file:
inventory_file:
vault_password_file:
state_dir:
audit_db:
```

### 26.1 Same-scope equivalence

以下兩台：

```text
pilot-gw-gpu-01
pilot-gw-gpu-02
```

除了：

```text
gateway.id
gateway.fqdn
service principal/keytab
```

之外，必須能使用相同：

```text
gateway.scope=gpu
gateway.target_hostgroup=pilot-target-gpu
```

這是 horizontal HA 的基本模型。

## 27. Portal TUI

使用者介面正式名稱維持：

```bash
pilot portal
```

不把使用者-facing command改名成：

```text
pilot gateway
pilot access-gateway
```

因 Portal 是人員操作入口；Gateway 是 backend/deployment role。

Home：

```text
Pilot Portal

Gateway  gpu-01
Scope    gpu
User     alice
────────────────────────

> My Hosts
  My Identity
  Refresh
  Logout
```

My Hosts只顯示：

```text
effective FreeIPA SSH allow
AND
host ∈ EffectiveMembers(gateway.target_hostgroup)
```

Host detail顯示：

```text
SSH rule names
user/group provenance
host/hostgroup provenance
sudo scope
allow commands
deny commands
sudo rule names
```

Portal不得提供 scope switcher。

例如登入 `scope=gpu` 的 Gateway後，不能在 TUI選：

```text
Switch scope -> dmz
```

要使用另一個 scope，必須登入對應 Gateway/service alias。

## 28. Portal Identity

Portal process自己不讀：

```text
roster
FreeIPA keytab
service credential
```

只連：

```text
/run/pilot/access-gateway.sock
```

`pilot-access-gateway`：

```text
SO_PEERCRED UID
 -> getent passwd UID
 -> username
 -> remote FreeIPA user/group query
```

---

## 29. Unix Socket / systemd

正式名稱：

```text
pilot-access-gateway.socket
/run/pilot/access-gateway.sock
```

推薦 socket activation：

```ini
[Unit]
Description=Pilot Access Gateway Socket

[Socket]
ListenStream=/run/pilot/access-gateway.sock
SocketUser=pilot-gateway
SocketGroup=role-pilot-portal-user
SocketMode=0660
RemoveOnStop=true

[Install]
WantedBy=sockets.target
```

Socket filesystem permission是第一層；application仍以 `SO_PEERCRED`建立 caller identity。

不同 Gateway host各有自己的 local socket，不共享。

## 30. `pilot-access-gateway` Service

正式 unit：

```text
pilot-access-gateway.service
```

example：

```ini
[Unit]
Description=Pilot Access Gateway
Requires=pilot-access-gateway.socket
After=network-online.target sssd.service
Wants=network-online.target

[Service]
Type=simple
User=pilot-gateway
Group=pilot-gateway

ExecStart=/usr/local/libexec/pilot-access-gateway \
  serve \
  --config /etc/pilot/access-gateway.yaml \
  --systemd-socket

NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

ReadOnlyPaths=/etc/pilot
ReadOnlyPaths=/etc/ipa

RuntimeDirectory=pilot

[Install]
WantedBy=multi-user.target
```

不設定：

```text
StateDirectory
CacheDirectory
ReadWritePaths=/var/lib/pilot
```

每台 Gateway是獨立 stateless instance。

## 31. Controlled SSH

`pilot portal` 由登入使用者 UID執行。

Connect流程：

```text
portal
 -> POST /v1/connect/authorize
 -> pilot-access-gateway
 -> FreeIPA fresh decision
 -> scope intersection
 -> ALLOW
 -> /usr/bin/ssh
```

SSH argv：

```text
/usr/bin/ssh
  -F /etc/pilot/ssh_config
  gpu02.linker.internal
```

不接受：

```text
free-text hostname
user@host
IP
port
SSH options
remote command
scope override
```

target只來自 `pilot-access-gateway` response。

Portal不使用 Gateway service keytab作 onward SSH。

Remote identity必須仍為：

```text
alice
```

### 31.1 Network defense-in-depth

若這台跳板機的設計本身要求「只能連特定區域」，應在 network/firewall 再限制：

```text
pilot-gw-gpu-* -> TCP/22 -> GPU target segment only
pilot-gw-dmz-* -> TCP/22 -> DMZ target segment only
```

Portal/FreeIPA scope是 application authorization；network ACL是第二道邊界。

Verification需至少有一個 out-of-scope target證明：

```text
Portal denies
AND
network path is unavailable when site policy requires it
```

## 32. SSH Config Isolation

**不可讀 `~/.ssh/config`。**

固定：

```text
-F /etc/pilot/ssh_config
```

root-owned baseline：

```sshconfig
Host *
    ForwardAgent no
    ClearAllForwardings yes

    PermitLocalCommand no
    EnableEscapeCommandline no
    EscapeChar none

    ProxyJump none
    ProxyCommand none

    StrictHostKeyChecking yes
    UserKnownHostsFile /dev/null
    GlobalKnownHostsFile /etc/pilot/ssh_known_hosts

    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials yes

    KbdInteractiveAuthentication yes
    PasswordAuthentication yes

    RequestTTY force
```

每個 option要在 supported OpenSSH執行：

```text
ssh -G -F /etc/pilot/ssh_config target
```

驗證。

Host key：

```text
StrictHostKeyChecking yes
```

Production不做 runtime TOFU。

---

## 33. ForceCommand

```sshconfig
Match Group role-pilot-portal-user
    ForceCommand /usr/local/libexec/pilot-session
    PermitTTY yes

    DisableForwarding yes
    AllowAgentForwarding no
    AllowTcpForwarding no
    X11Forwarding no
    PermitTunnel no
    PermitUserRC no
```

`pilot-session`：

```sh
#!/bin/sh
set -eu

[ -t 0 ] || exit 1

unset SSH_AUTH_SOCK
unset LD_PRELOAD
unset LD_LIBRARY_PATH
unset PILOT_CONFIG
unset PILOT_DATA_DIR

export PATH=/usr/bin:/bin

exec /usr/bin/pilot \
  --config /etc/pilot/portal.yaml \
  portal
```

不可解析/執行：

```text
SSH_ORIGINAL_COMMAND
```

Admin group必須與 forced portal group分開。


---

## 34. Error / Freshness Policy

### FreeIPA unavailable

```text
Access service unavailable.
New connections are disabled.
```

### Service keytab invalid

```text
Gateway service identity unavailable.
Contact infrastructure administrator.
```

### target hostgroup missing

```text
No scope targets are available.
```

### target access changed

Connect：

```text
Access changed.
Connection was not started.
```

Default timeout：

```text
FreeIPA request timeout: 5s
cache TTL:              10s
connect max age:         5s
```

所有 failure：

```text
fail closed
```

---

## 35. Resource Limits

JSON-RPC response size必須 bounded，例如：

```text
16 MiB default
```

Graph limits configurable：

```text
max scope targets
max groups
max hostgroups
max HBAC rules
max sudo rules
max graph depth
```

超過：

```text
fail closed
health degraded
```

避免 malformed directory graph造成 unbounded memory/cycle。

> **Phase 2 實作修正：`max graph depth` 沒有實作，因為沒有 recursion 可言。** 見 §13/§14——group/hostgroup closure 都改成單一 `user_show`/`hostgroup_show` call 讀 FreeIPA 已算好的 `memberofindirect_*`/`memberindirect_*`，不是遞迴 walk。這裡其餘的 limit（response size、max scope targets/groups/hostgroups/HBAC rules/sudo rules）依然適用，只是意義變成「單一 response 別大到不合理」的 sanity bound，不是「walk 太深」的 bound。

---

## 36. Package Layout

推薦：

```text
cmd/
├── pilot/
│   └── cmd/
│       ├── portal.go
│       ├── portal_client.go
│       ├── portal_tui.go
│       └── portal_ssh.go
└── pilot-access-gateway/
    └── main.go

internal/
├── freeipaaccess/
│   ├── provider.go
│   ├── jsonrpc.go
│   ├── kerberos.go
│   ├── normalize.go
│   └── testdata/
├── accessportal/
│   ├── model.go
│   ├── resolver.go
│   ├── hbac.go
│   └── sudo.go
│   # 原規劃有 graph.go；Phase 2 發現不需要（見 §13/§14 修正），沒有實作
├── gatewayapi/
│   ├── server.go
│   ├── client.go
│   ├── routes.go
│   └── authz.go
├── peercred/
├── identity/
└── systemdactivation/
```

不要把 domain logic塞進：

```text
cmd/pilot/cmd/portal.go
```

---

## 37. FreeIPA Fixtures

建立：

```text
internal/freeipaaccess/testdata/
```

至少：

```text
user_show.json
group_show.json
hostgroup_show.json
hbacrule_find.json
hbacrule_show.json
hbacsvcgroup_show.json
sudorule_find.json
sudorule_show.json
sudocmd_show.json
sudocmdgroup_show.json
hbactest_allow.json
hbactest_deny.json
rpc_error.json
```

Parser單元測試只依賴 JSON fixture，不需要 live IPA。

---

## 38. Resolver Test Matrix

### User groups

- direct group
- nested group
- multi-parent
- duplicate
- cycle

### Managed hosts

- direct host
- nested hostgroup
- duplicate
- cycle
- trailing dot canonicalization

### HBAC

- direct user
- user group
- nested user group
- direct host
- hostgroup
- nested hostgroup
- usercategory all
- hostcategory all
- servicecategory all
- direct sshd service
- HBAC service group
- disabled rule
- unmanaged host excluded

### Sudo

- no rule
- direct user
- group
- direct host
- hostgroup
- cmdcategory all
- specific command
- command group
- deny command
- deny command group
- notBefore future
- notAfter expired
- active window
- disabled rule

---

## 39. Connect Authorization Regression Tests

### Policy revoked after list

```text
GET /access -> allowed
FreeIPA rule removed
POST /connect/authorize
```

expected：

```text
deny
```

### Managed target removed

```text
HBAC still allowed
host removed from configured gateway target hostgroup
```

expected：

```text
deny
```

### FreeIPA unavailable

expected：

```text
deny
```

### Unknown target

expected：

```text
deny
```

---

## 40. Security Tests

### S1 — environment spoof

```text
USER=root
LOGNAME=root
```

identity仍為 socket peer UID user。

### S2 — target injection

```json
{"target":"gpu01;sh"}
```

deny。

### S3 — alternate user

```text
root@gpu01.linker.internal
```

deny。

### S4 — IP target

```text
10.0.0.1
```

deny v1。

### S5 — user SSH config escape

使用者：

```sshconfig
ProxyCommand /tmp/escape
LocalCommand /tmp/escape
```

Portal Connect仍使用：

```text
-F /etc/pilot/ssh_config
```

escape marker不得執行。

### S6 — forwarding

outer Gateway：

```text
-L
-R
-D
-A
-X
```

全部拒絕。

### S7 — TLS

錯誤 CA：

```text
FreeIPA query fail
```

不能 insecure retry。

### S8 — service credential mutation

reader principal：

```text
read allowed
mutation denied
```

---

## 41. Live FreeIPA E2E Topology

建立：

```text
ipa1

pilot-gw-gpu-01
pilot-gw-gpu-02
pilot-gw-dmz-01

gpu-a
gpu-b
dmz-a
dev-a
```

Gateway config：

```text
gpu-01 -> scope=gpu -> pilot-target-gpu
gpu-02 -> scope=gpu -> pilot-target-gpu
dmz-01 -> scope=dmz -> pilot-target-dmz
```

FreeIPA：

```text
pilot-access-gateways
├── pilot-gw-gpu-01
├── pilot-gw-gpu-02
└── pilot-gw-dmz-01

pilot-target-gpu
├── gpu-a
└── gpu-b

pilot-target-dmz
└── dmz-a
```

使用者 Alice HBAC：

```text
alice -> gpu-a
alice -> gpu-b
alice -> dmz-a
alice -> dev-a
```

Expected：

### Login gpu-01

```text
Portal shows:
  gpu-a
  gpu-b

Does not show:
  dmz-a
  dev-a
```

### Login gpu-02

結果必須與 gpu-01相同：

```text
gpu-a
gpu-b
```

證明 same-scope horizontal equivalence。

### Login dmz-01

```text
Portal shows:
  dmz-a

Does not show:
  gpu-a
  gpu-b
  dev-a
```

### Dynamic scope update

將 `gpu-b` 從 `pilot-target-gpu` 移除後：

```text
both gpu-01 and gpu-02 stop showing gpu-b after refresh/cache expiry
```

不需同步 Gateway state。

## 42. Live Sudo E2E

FreeIPA sudo：

```text
alice
target-a
/usr/bin/systemctl status nginx
```

Portal：

```text
SUDO = LIMITED
/usr/bin/systemctl status nginx
```

target：

```bash
sudo -l
```

應與 Portal呈現一致。

若 target SSSD cache較舊：

```text
target remains final enforcement
```

Portal不可 bypass。

---

## 43. Temporary Grant E2E

Management plane建立：

```text
temporary_grant
```

reconcile後 FreeIPA：

```text
pilot-grant-login-...
```

active：

```text
Portal sees target
```

disabled/expired：

```text
Portal does not see target
```

`pilot-access-gateway` 不讀 grant JSON。

---

## 44. Sudo Grant E2E

FreeIPA rule：

```text
pilot-grant-sudo-...
sudoNotBefore
sudoNotAfter
```

active：

```text
Portal shows sudo
```

window outside：

```text
Portal hides that sudo rule
```

`pilot-access-gateway` 不做 local lifecycle calculation from roster；只依 live FreeIPA fields。

---

## 45. Breakglass E2E

inactive：

```text
managed HBAC absent/disabled
Portal no access
```

activate management plane：

```text
managed HBAC appears/enabled
Portal access appears
```

deactivate：

```text
Portal access disappears
```

此規格不驗證：

```text
reason
ticket
history
```

---

## 46. Stateless E2E

必測：

```text
1. Portal shows alice access
2. `systemctl restart pilot-access-gateway.service`
3. all in-memory cache disappears
4. no local state restore
5. pilot-access-gateway re-authenticates to FreeIPA
6. Portal access rebuilds correctly
```

filesystem：

```bash
find /var/lib/pilot -maxdepth 3 -type f
```

此 component 不可新增：

```text
pilot-access-gateway.db
portal.db
snapshot.json
session.json
breakglass*.json
```

---

## 47. Service Credential Lifecycle

keytab rotation：

```text
provision new keytab
atomic replace
`systemctl restart pilot-access-gateway.service`
```

不需要：

```text
DB migration
state transfer
cache restore
```

`pilot-access-gateway` restart後重新取得 Kerberos session與 FreeIPA snapshot。

---

## 48. HA 與多 Gateway 拓撲

### 48.1 Same-scope HA

可以：

```text
pilot-gw-gpu-01
pilot-gw-gpu-02
pilot-gw-gpu-03
```

全部：

```text
scope=gpu
target_hostgroup=pilot-target-gpu
```

不需要：

```text
shared DB
shared filesystem
leader election
session replication
cache replication
```

可放在：

```text
pilot-gpu.linker.internal
```

同一 DNS/VIP 後。

### 48.2 Different scopes

```text
pilot-gw-gpu-01 -> scope=gpu
pilot-gw-dmz-01 -> scope=dmz
```

**不得放在同一個 random-balancing service alias後面。**

應使用：

```text
pilot-gpu.linker.internal
pilot-dmz.linker.internal
```

或直接 Gateway FQDN。

### 48.3 Replacement

任一 instance：

```text
stop
delete
rebuild
replace
```

只需重新：

```text
install immutable config
install read-only keytab
query FreeIPA
```

不需搬 application state。

## 49. Performance Targets

warm：

```text
GET /v1/identity  < 100ms
GET /v1/access    < 200ms
host detail       < 100ms
```

cold FreeIPA snapshot：

```text
goal < 2s
hard timeout 5s
```

Connect fresh authorize：

```text
goal < 500ms
hard timeout 5s
```

---

## 50. Formal Deployment Component

正式 deployment component：

```text
pilot-access-gateway
```

新增：

```text
contracts/pilot-access-gateway.yaml
docs/verification/pilot-access-gateway.md
playbooks/apply/pilot-access-gateway-apply.yml
playbooks/verify/pilot-access-gateway.yml
```

更新：

```text
cmd/pilot/cmd/deploy_catalog.go
DELIVERY.md
build artifact tests
site/deploy metadata
```

Default inventory role/group也使用：

```text
pilot-access-gateway
```

Gateway host naming convention：

```text
pilot-gw-<scope>-<nn>
```

例如：

```text
pilot-gw-gpu-01
pilot-gw-dmz-01
pilot-gw-hq-02
```

## 51. Contract Requirements

> 修正說明（§0 G3）：原版要求 `stateless: true` / `persistent_data: []` 兩個欄位，但 `internal/contract/contract.go` 的 `Contract` struct（schemaVersion 1）沒有這兩個欄位，且 loader 用 `KnownFields(true)` decode，未知欄位會直接讓 contract 載入失敗。以下改用現有 schema 已支援的欄位表達同樣的意圖。

`contracts/pilot-access-gateway.yaml` 必須符合現有 `schemaVersion: 1` schema，至少包含：

```yaml
schemaVersion: 1
id: pilot-access-gateway
role: access-gateway
hostCardinality: one-or-more   # 同 scope 可部署多台

specs:
  - path: docs/verification/pilot-access-gateway.md
    rows:
      all: true

playbooks:
  apply: playbooks/apply/pilot-access-gateway-apply.yml

stagePolicy:
  variable: pilot_access_gateway_stage
  default: disabled

evidenceRequirement:
  targetTest: topology       # gateway + target host + FreeIPA 至少三方拓樸
  idempotency: required

endpoints:
  - name: gateway-socket
    scheme: unix
    path: /run/pilot/access-gateway.sock

lifecycle:
  decommission:
    class: stateless          # 用既有欄位表達「無持久狀態」，取代發明的 stateless 欄位
    scope: both                # 本機 socket/service 清除 + FreeIPA 端 host/service principal 需一併移除
    externalState: true        # 有 FreeIPA host/service principal/hostgroup membership 需要清理
    requiresReachableHost: true
    retention: none            # stateless 元件不得宣告 required

verification:
  autoDeploy: false            # 高 blast radius 元件，不進自動部署白名單
```

`persistent_data = []` 這個意圖改由既有的 §52 verification rows（AG17 no roster dependency、AG18 no inventory dependency、AG19 no local DB/state）與上面的 `lifecycle.decommission` 承載，不再是 contract schema 欄位。若日後確定需要一個顯式的 contract 級 `stateless` 欄位（例如給 decommission/repair 邏輯用），那是影響所有既有 contract 的 schema 擴充，應該另立案處理，不要夾帶在這個元件的實作裡。

必須驗證 artifact：

```text
pilot-access-gateway binary
pilot CLI with portal command
pilot-session
access-gateway.yaml
portal.yaml
ssh_config
ssh_known_hosts
pilot-access-gateway.service
pilot-access-gateway.socket
sshd ForceCommand drop-in
```

不得新增：

```text
/var/lib/pilot/access-gateway
/var/lib/pilot/pilot-access-gateway
```

persistent data contract。

> **Phase 7 實作偏差記錄**（2026-09-14）：實際 `contracts/pilot-access-gateway.yaml` 與上面的範例有兩處刻意偏離，都是實測撞到既有 lint 規則後才發現：
>
> 1. **`stagePolicy` 用 `{variable: stage, default: sandbox}`，不是 `{variable: pilot_access_gateway_stage, default: disabled}`。** 全 repo 36 支 apply playbook 一律共用 `stage` 這個變數名（AGENTS.md §4.3 的 cross-check gate 也是針對 `stage`），沒有任何既有 playbook 用元件專屬的 stage 變數名;`disabled` 也不是這個 repo `stage` 慣例接受的值（合法值只有 `sandbox`/`staging`/`prod`）。跟著 repo 既有慣例走，不要為這個元件另立一套命名。
> 2. **完全省略 `lifecycle.decommission` block。** `internal/contract/lint.go` 的 `validateDecommissionPolicy` rule 1 規定：`externalState: true` 必須搭配 `playbooks.decommission` 或一個已登記的 bespoke Go provider（`componentsWithBespokeDecommissionProvider`），否則直接 fail-closed 拒絕載入。這個元件目前既沒有 decommission playbook 也沒有 bespoke provider——建置一條真正的 decommission 路徑不在這份 spec 的 8 個 Phase 範圍內。比照同樣會動到 FreeIPA hostgroup membership 的手足元件 `pilot-gateway-scope`（同樣完全不宣告 `lifecycle` block）,直接省略整個 block，而不是宣告一個會被 lint 擋下的假設。這不代表沒有需要清理的外部狀態（reader service principal、`pilot-access-gateways` hostgroup membership 都是真實需要清理的 FreeIPA 端狀態）——只是這條清理路徑目前刻意留白，日後若要做，應該連同一份 bespoke decommission provider 或 playbook 一起補上，而不是先宣告 policy 卻沒有對應實作。

## 52. Verification Rows

最低要求：

```text
AG01 gateway config has id/scope/target_hostgroup
AG02 pilot-gateway service account
AG03 service keytab owner/mode
AG04 FreeIPA CA present
AG05 service principal Kerberos auth
AG06 FreeIPA JSON-RPC ping
AG07 required read capabilities
AG08 mutation denied
AG09 Unix socket name/mode/group
AG10 SO_PEERCRED identity
AG11 $USER spoof blocked
AG12 configured target hostgroup exists
AG13 nested target hostgroup expansion
AG14 HBAC ∩ gateway scope correctness（**驗證前必須先確認 FreeIPA 內建的 `allow_all` HBAC rule 是 disabled** —— Phase 1 實測發現全新 `ipa-server-install` 預設會啟用一條 usercategory/hostcategory/servicecategory 全部 `all` 的 enabled `allow_all` 規則，這條規則在時只要有連線就一定 allow，會讓這裡的驗證即使 gateway 自己的 HBAC∩scope 邏輯是錯的也「看起來」PASS，見 `docs/evidence/pilot-access-gateway/2026-09-14-phase1-freeipaaccess.md`）
AG15 live sudo correctness
AG16 FreeIPA outage fail closed
AG17 no roster dependency
AG18 no inventory dependency
AG19 no local DB/state
AG20 portal ForceCommand
AG21 admin shell unaffected
AG22 ~/.ssh/config ignored
AG23 forwarding disabled
AG24 strict host key checking
AG25 remote whoami == portal user
AG26 same-scope gateways return equivalent target set
AG27 different-scope gateways return isolated target sets
AG28 service alias does not mix scopes
AG29 gateway restart rebuilds only from FreeIPA
AG30 second apply changed=0
```

若 site要求 network-restricted bastion：

```text
AG31 out-of-scope SSH egress blocked by network policy
```

## 53. Config Regression Contract

`internal/config.Config` 或 dedicated Gateway config model不得加入：

```text
RosterFile
InventoryFile
VaultPasswordFile
StateDir
AuditDB
```

Required Gateway fields：

```text
GatewayID
GatewayScope
GatewayFQDN
TargetHostgroup
SocketPath
PortalUserGroup
FreeIPA servers
CA
service principal
keytab
cache TTL
timeouts
```

Tests必須確認 client request無法覆寫：

```text
GatewayScope
TargetHostgroup
```

## 54. Build Artifact

新增：

```text
scripts/build-pilot-access-gateway.sh
```

output：

```text
dist/pilot-access-gateway-linux-amd64
dist/pilot-access-gateway-linux-amd64.sha256
```

沿用 repository pattern：

```text
CGO_ENABLED=0
GOOS=linux
GOARCH=amd64
-trimpath
version/commit ldflags
sha256
```

新增 main：

```text
cmd/pilot-access-gateway/main.go
```

若 Kerberos/SPNEGO library破壞 CGO-free：

```text
不可默默改整個 Pilot artifact policy
```

改用 approved pure-Go implementation或 fixed external `kinit`/`curl --negotiate` transport。

## 55. Apply Playbook

正式 playbook：

```text
playbooks/apply/pilot-access-gateway-apply.yml
```

順序：

```text
1. validate gateway.id / scope / fqdn / target_hostgroup
2. verify FreeIPA client enrollment
3. verify gateway host is in pilot-access-gateways
4. verify getent
5. verify sshd
6. verify systemd
7. verify /etc/ipa/ca.crt
8. install/provision read-only Gateway keytab
9. install pilot CLI
10. install pilot-access-gateway binary
11. install access-gateway.yaml / portal.yaml
12. install root SSH config
13. install trusted known_hosts
14. install pilot-session
15. install pilot-access-gateway.socket/service
16. start socket
17. capability probe FreeIPA
18. verify configured pilot-target-<scope>
19. only then install sshd ForceCommand drop-in
20. sshd -t
21. reload sshd
22. full verification
```

**ForceCommand一定最後才裝。**

避免先鎖使用者，再發現 Gateway config/FreeIPA reader/target scope有錯。

### 55.1 vm-target 鎖定回歸測試（§0 G4，production 前必過）

repo 目前沒有任何 playbook 用過 `ForceCommand`/`Match Group`（`pam-oidc-sshd-apply.yml`、`freeipa-client-apply.yml` 只碰認證方式，不碰互動 shell），所以第 19 步沒有既有先例可以照抄驗證方式。在 disposable vm-target 上，第 19-21 步之後必須**額外**跑：

```text
1. 用 role-pilot-portal-user 成員的獨立 SSH session 登入 gateway
   -> 預期直接進入 pilot-session/pilot portal，無法取得一般 shell
2. 用 role-pilot-admin 成員的另一個獨立 SSH session 登入同一台 gateway
   -> 預期仍拿到一般互動 shell（未被 ForceCommand 影響）
3. 手動或用 rollback 手段移除 ForceCommand drop-in 並 reload sshd
   -> 兩種角色都恢復一般互動 shell
```

三步都要留下 vm-target 證據（trec 或等價紀錄）。這一段沒有全部跑過、沒有留下證據之前，**不得**對任何非 disposable 主機執行第 19 步。Production 首次部署前，第 19 步需要人員明確核准，不視為 CI 自動跑過即可放行。

## 56. FreeIPA Provisioning

Management plane負責：

### Gateway host classification

```text
hostgroup: pilot-access-gateways
```

加入：

```text
pilot-gw-<scope>-<nn>
```

### Gateway service principal

例如：

```text
service-add pilot-access-gateway/pilot-gw-gpu-01.linker.internal
```

### Read-only RBAC

加入：

```text
Pilot Access Gateway Reader
```

### Target scope

建立：

```text
pilot-target-gpu
pilot-target-dmz
...
```

Provisioning必須 idempotent。

禁止每次 ordinary apply無條件 rotate keytab。

Keytab rotation必須 explicit lifecycle operation。

## 57. Gateway Scope Reconcile

新增 management commands：

```text
pilot gateway-scope plan --scope <scope>
pilot gateway-scope reconcile --scope <scope>
```

例如：

```text
pilot gateway-scope plan --scope gpu
```

target：

```text
FreeIPA hostgroup pilot-target-gpu
```

plan輸出：

```text
add
remove
keep
```

同 scope所有 Gateway立即共享同一 runtime target truth，因為都讀同一 FreeIPA hostgroup。

`pilot-access-gateway` 永遠不需要 inventory。

### 57.1 Optional global classification

若管理面需要，可另外維持：

```text
pilot-managed-hosts
```

但它只作 management inventory classification。

Portal access formula不得依賴它：

```text
HBAC(user) ∩ gateway.target_hostgroup
```

## 58. `pilot-access-gateway doctor`

新增：

```bash
pilot-access-gateway doctor --config /etc/pilot/access-gateway.yaml
```

檢查：

```text
gateway.id
gateway.scope
gateway.fqdn
gateway.target_hostgroup
config consistency

keytab
Kerberos
CA
FreeIPA servers
JSON-RPC
reader permission

pilot-access-gateways membership
target hostgroup
HBAC read
sudo read

socket/systemd config
SSH config parse
known_hosts availability
```

不檢查：

```text
roster
inventory
DB
```

Doctor output必須明確顯示：

```text
Gateway: gpu-01
Scope: gpu
Target hostgroup: pilot-target-gpu
```

## 59. Security Invariants

Coding Agent 必須將以下寫入 code comments/tests：

```text
SI-01 runtime authorization data comes only from FreeIPA.
SI-02 pilot-access-gateway does not read roster or inventory.
SI-03 pilot-access-gateway stores no persistent application state.
SI-04 caller identity comes from SO_PEERCRED.
SI-05 FreeIPA membership is queried remotely.
SI-06 target must belong to configured gateway.target_hostgroup.
SI-07 client cannot override gateway scope or target hostgroup.
SI-08 Connect is freshly re-authorized.
SI-09 FreeIPA failure is fail-closed.
SI-10 Gateway FreeIPA identity is read-only.
SI-11 portal launches OpenSSH as caller user.
SI-12 portal never reads user-controlled SSH config.
SI-13 target sshd/SSSD remains final enforcement.
SI-14 same-scope gateways are authorization-equivalent.
SI-15 different-scope gateways must not leak targets across scopes.
SI-16 one DNS/VIP must not mix different scopes.
SI-17 when site requires a restricted bastion, network egress must not be broader than the intended gateway boundary.
```

## 60. Implementation Phases

> §0 G5：每個 Phase 是一個獨立可 commit、獨立在 vm-target 上驗收的增量，**不得**合併成單一大 PR 一次生出。下一個 Phase 只能在前一個 Phase 的 Landing gate 有證據之後開始被視為「可繼續」；若某個 Phase 的實測結果和本文件其餘章節寫死的細節衝突，回頭修正文件，而不是硬套。

### Phase 0 — FreeIPA transport / naming contract spike

先固定正式名稱：

```text
pilot portal
pilot-access-gateway
pilot-gw-<scope>-<nn>
pilot-access-gateways
pilot-target-<scope>
```

再證明：

```text
service principal auth
JSON-RPC
read calls work
mutation denied
```

**Landing gate：** §11.1 定義的 4 條 exit criteria 全過，且已明確記錄 transport 是 direct Go SPNEGO 還是 `kinit`+`curl` fallback。這是唯一允許單獨先做、且結果可能推翻後續章節細節的 Phase。

### Phase 1 — `internal/freeipaaccess`

完成：

```text
JSON-RPC
Kerberos login
TLS
failover
read allowlist
normalization
fixtures
```

**Landing gate：** 單元測試只靠 §37 fixture 跑（不需 live IPA），且用 Phase 0 已證明可行的 transport；不重新展開一次可行性驗證。

> **已於 2026-09-14 完成**（見 `docs/evidence/pilot-access-gateway/2026-09-14-phase1-freeipaaccess.md`）。17 個 fixture-only 測試全過，另外用一次性 `manual`-tag 測試對活體 FreeIPA 驗證過（含 failover 跳過不可達 server）後刪除，不留在 repo 裡。實作與原文有兩處已記錄的偏離：Provider 介面改成原始讀取方法（closure 展開留給 Phase 2 `accessportal`），以及 hbacrule_find/sudorule_find 改用 `all=true` 而非 `raw=true`。

### Phase 2 — Gateway scope graph resolver

完成：

```text
gateway config model
user group closure
target hostgroup closure
HBAC resolver
sudo resolver
HBAC ∩ gateway scope
```

**Landing gate：** §38 Resolver Test Matrix 全過（含 cycle/dedupe/nested 案例），純靠 fixture，不需 Gateway API 或 Portal UI 存在。

> **已於 2026-09-14 完成**（見 `docs/evidence/pilot-access-gateway/2026-09-14-phase2-accessportal.md`）。28 個測試全過。最大的一個發現：group/hostgroup closure 完全不需要遞迴 walk（FreeIPA server 端已算好，見 §13/§14 修正），所以 `graph.go` 沒有實作；`hbac.go`/`sudo.go` 的 matching 邏輯用 fixture 真值（gpu-users/pilot-target-gpu/兩條 grant rule）加上針對個別 matrix cell 的建構值涵蓋 §38 全部案例。

### Phase 3 — Peer identity + Gateway API

完成：

```text
SO_PEERCRED
getent UID->username
/v1/identity
/v1/access
/v1/connect/authorize
/v1/health
```

API所有 response帶 Gateway identity。

**Landing gate：** §40 Security Tests 的 S1（`$USER`/`$LOGNAME` spoof 無效）與 S8（reader principal 只能讀不能寫）先在這個 Phase 過，不要延到 Phase 8 才第一次驗證身分信任邊界。

> **已於 2026-09-14 完成**（見 `docs/evidence/pilot-access-gateway/2026-09-14-phase3-gateway-api.md`）。65 個單元測試（跨 Phase 0-3 全部 package）全過；另外在 vm-target 上用真實編譯的 binary、真實 `curl`、真實第二個 Linux 使用者 `alice`（`runuser -u alice`）、真實 `systemd-socket-activate` 對活體 FreeIPA 跑過整條鏈，S1 現場驗證：`env USER=root LOGNAME=root` 完全不影響解析出的身分。找到一個環境坑（socket 放在 `/root/` 下非 root 使用者連不進去，純粹是目錄權限問題，不是程式碼問題——也印證了 §29 為什麼要把 socket 放 `/run/pilot/`）與一個規格缺口（§26 範例 YAML 沒有 `realm` 欄位；已改成 `internal/freeipaaccess.NewClient` 在沒指定時預設抓 `krb5.conf` 的 `default_realm`，不需要新增必填欄位）。

### Phase 4 — Portal read UI

完成：

```text
Gateway/Scope header
My Hosts
Host Detail
My Identity
Refresh
```

不得有 scope switcher。

**Landing gate：** 這個 Phase 完全 read-only、不涉及 SSH/ForceCommand，可以先在既有 pilot TUI 流程裡跑起來確認 UX，不需要等 Phase 5 的 controlled SSH。

> **已於 2026-09-14 完成**（見 `docs/evidence/pilot-access-gateway/2026-09-14-phase4-portal-ui.md`）。重用既有 `pilot deploy` 的 screen factory/prompt-automation 測試掛鉤，沒有發明新 UI 機制。單元測試（fake provider + 真實 `gatewayapi.Server`）之外，另外用 `trec` 對 vm-target 上真實跑起來的 `pilot-access-gateway` 全程真人（`alice`）走過 My Hosts→Host Detail→返回、My Identity、Refresh、Logout 整條路徑，畫面與資料完全吻合設計。找到 3 個操作坑：(1) 又一次 `/root` 目錄不可 traverse 問題(同 Phase 3)；(2) `pkill -f` 字串自我比對砍斷了下指令的 SSH session 本身；(3) `trec` 的自動 pointer 偵測在這個畫面上失效(可能因為 Huh 預設的 `┃ ` 邊框前綴)，改用手動方向鍵導航。

### Phase 5 — Controlled SSH

完成：

```text
fresh authorize
root SSH config
strict known_hosts
tea.ExecProcess
return to portal
```

**Landing gate：** §40 S2-S6（target injection / alternate user / IP target / SSH config escape / forwarding）在 vm-target 上逐項過，這個階段還沒有 ForceCommand，使用者仍是用一般方式進入 Portal 測試。

> **已於 2026-09-14 完成**（見 `docs/evidence/pilot-access-gateway/2026-09-14-phase5-controlled-ssh.md`）。S2-S6 全部有對應測試,其中 S2/S5 直接對本機真實安裝的 OpenSSH 跑 `ssh -G`(spec自己在 §32 訂的驗證方法),包含用「有毒」`~/.ssh/config`實測 `-F` 真的完全蓋過使用者設定。實作與 §60 原文有一處落差：Portal 不是單一連續的 tea.Program(deploy_tui.go 那種一次性 Program 序列的架構),兩個 prompt 之間沒有活躍的 raw-mode Program 需要 suspend,所以直接用 blocking `exec.Cmd.Run()`,沒有用到 `tea.ExecProcess`。真人對真主機的 SSH 連線(含真 known_hosts、真 GSSAPI)刻意留到 Phase 8(目前 fixture 主機都是 `ipa host-add --force` 假主機,沒有真機可連)。

### Phase 6 — Gateway scope publication

完成：

```text
pilot-access-gateways classification
pilot gateway-scope plan/reconcile
```

**Landing gate：** `pilot gateway-scope plan/reconcile` 對一個測試用 scope 跑出正確的 add/remove/keep，且 idempotent（第二次 apply changed=0）。

> **已於 2026-09-14 完成 `pilot-target-<scope>` 這一半**（見 `docs/evidence/pilot-access-gateway/2026-09-14-phase6-gateway-scope.md`）：真實 vm-target 上驗證過 add/remove/keep 三種路徑 + 兩輪 idempotent(changed=0)，CLI 與 playbook 直跑結果一致。**`pilot-access-gateways`（§9.1，Gateway 主機自己的 classification）刻意留給 Phase 7**——那是「新裝一台 gateway 主機時把自己加進這個 hostgroup」，自然屬於 Phase 7 apply playbook 的安裝步驟之一,不是這裡的 scope-hosts 發布邏輯。額外發現且已修正一個真的 bug：`-e gateway_scope_hosts=[...]` 這種寫法 Ansible 不會可靠解析成 list（會被當純字串逐字元跑掉),必須用 `-e '{"gateway_scope_hosts": [...]}'` 的 JSON 物件形式。新增這一支 playbook 也連帶觸發本 repo 既有的 6 項治理檢查(contract/spec/tag coverage/deploy catalog/role catalog/stage gate),已全部補齊,細節見 evidence doc。

### Phase 7 — Deployment integration

完成：

```text
pilot-access-gateway contract
verification
apply
build artifact
deploy catalog
docs
```

**Landing gate：** contract 依 §51 修訂版 schema 能被 `internal/contract.Loader` 成功載入；apply playbook 跑到第 18 步（ForceCommand 之前）在 vm-target 上 idempotent 過（AG30）。**到這裡為止都還沒裝 ForceCommand。**

> **已於 2026-09-14 完成**（見 `docs/evidence/pilot-access-gateway/2026-09-14-phase7-deployment-integration.md`）：`ag-gw01`（FreeIPA client）+ `ag-spike-ipa`（FreeIPA server）兩台 vm-target 上實測 `playbooks/apply/pilot-access-gateway-apply.yml` 全部 18 步，含活體驗證 alice=200/root=401（`/v1/identity`，defense-in-depth portal-group gate）、root=200（`/v1/health`，從不受 gate）、AG29(stateless restart 保留 health、`/var/lib/pilot` 從未存在)、AG30(第二次 apply changed=0)。過程中找到並修正 4 個真 bug：DNS record 必須先存在才能 `ipa service-add`、`/usr/local/libexec` 在 Ubuntu 上不存在、**local fallback group 會被 nsswitch `files` 來源永久遮蔽同名 FreeIPA 群組**(已改成 fail-closed 檢查、不再建 local 群組)、`RuntimeDirectory=` 裝在錯的 systemd unit 上(已從 `.service` 搬到 `.socket`)。過程中一度誤判成「systemd 無法可靠解析 SSSD 群組」，重新實測後已自行回頭修正相關程式碼註解為正確成因。新增這支 playbook 也連帶觸發本 repo 的全套治理檢查(contract/spec/tag coverage/deploy catalog/role catalog/AGENTS.md §4.3),已全部補齊，並新增 `cmd/pilot/cmd/portal_ssh_config_sync_test.go` 鎖住 playbook 的 `/etc/pilot/ssh_config` 內容與 `pilotSSHConfig` Go 常數不會漂移。

### Phase 8 — Multi-Gateway E2E

驗證：

```text
same scope / multiple instances
different scopes isolation
DNS/VIP scope grouping
HBAC
sudo
grant
breakglass active rule
FreeIPA outage
reader keytab failure
ForceCommand
SSH escape protection
stateless restart
network egress boundary if required
```

**Landing gate：** 這是唯一允許啟用 ForceCommand（第 19 步）的 Phase，前提是 §55.1 的鎖定回歸測試三步已經在 vm-target 上跑過且留有證據，並取得人員核准。在此之前的 Phase 全程用一般 SSH 登入方式驗證，不依賴 ForceCommand。

> **已於 2026-09-14 完成**（見 `docs/evidence/pilot-access-gateway/2026-09-14-phase8-multi-gateway-e2e.md`）：在取得明確人員核准後（啟用 ForceCommand、以及之後模擬 FreeIPA 斷線,兩者都被 auto-mode classifier 攔下要求人工確認),對 `ag-gw01`（disposable vm-target）完整跑過 §55.1 三步——alice（`role-pilot-portal-user`）SSH 登入直接進入 `pilot portal` TUI 且 Ctrl+C 只會關閉整個連線、`ssh alice@host whoami`(無 PTY) 不執行請求指令、root 登入拿到完全正常 shell、旗標設回 false 重新 apply 後兩者皆恢復正常 shell。新增第二台 gateway `ag-gw02` 對 AG26（同 scope 多實例回傳相同 target set）/AG27（不同 scope 回傳隔離的 target set，含一個使用者對兩個 scope 都有真實 HBAC 權限但兩台 gateway 仍正確互不外溢的強驗證）完整實測。額外對 `ag-spike-ipa` 模擬 FreeIPA 斷線,驗證 `/v1/health`/`/v1/access` fail-closed 且斷線恢復後自動復原（AG16）。過程中意外發現並修正一個真的 process-crash bug：`internal/freeipaaccess.NewClient` 原本同步載入 keytab 導致缺檔時整個 process 直接 exit,因為服務是 socket-activated 很快撞上 systemd start-rate-limit 讓**整個 socket 單元**卡死、修好 keytab 也不會自動恢復——已改成跟既有 session 建立一樣是 lazy + per-call retry,修好檔案後下一次請求就自動恢復,不需要重啟(見 `internal/freeipaaccess/kerberos_test.go` 新增的兩個回歸測試)。也發現並修正 playbook 原本只能把 ForceCommand 打開、不能透過旗標關閉的不對稱 gap（已補上對稱的 rollback tasks）。AG28/AG31/grant-breakglass 記錄為架構性質/站台操作規則,不是單一 task 可測試的程式行為。

## 61. Migration from Previous Portal Specification

本檔 supersede：

```text
2026-09-08-pilot-stateless-freeipa-portal-spec.md
```

正式變更：

```text
pilotd
 -> pilot-access-gateway

pilot-controller
 -> pilot-access-gateway

pilot-managed-hosts runtime boundary
 -> gateway.target_hostgroup
 -> pilot-target-<scope>

generic controller hostname
 -> pilot-gw-<scope>-<nn>

generic service backend naming
 -> component-specific Access Gateway naming
```

若舊版尚未實作，直接棄用：

```text
pilotd binary/service/socket names
pilot-controller component names
global pilot-managed-hosts as Portal runtime boundary
local roster loader
local inventory loader
local SQLite
session history
```

保留設計：

```text
stateless FreeIPA-backed runtime
SO_PEERCRED
Unix socket
pilot portal
ForceCommand
controlled OpenSSH
root-owned SSH config
```

新的核心 access formula：

```text
Effective FreeIPA SSH access
INTERSECT
Configured Gateway target hostgroup
```

## 62. Required Repository Inspection

Coding Agent 必須以實作當下 HEAD重新讀：

```text
go.mod
internal/config/config.go

internal/inventory/roster_effective.go
internal/inventory/explain.go
internal/inventory/grant_compile.go

internal/accessgrants/explain.go
internal/accessgrants/breakglass.go

internal/sandbox/ssh.go
internal/tui/

cmd/pilot/cmd/access_cli.go
cmd/pilot/cmd/access_explain_cli.go
cmd/pilot/cmd/access_breakglass_cli.go
cmd/pilot/cmd/edit_tui_roster_access.go
cmd/pilot/cmd/edit_tui_roster_grants.go
cmd/pilot/cmd/deploy_catalog.go

playbooks/apply/freeipa-identity-apply.yml
playbooks/apply/freeipa-identity.roster.example.yaml
playbooks/apply/agent-controller-apply.yml

contracts/agent-controller.yaml
```

---

## 63. External FreeIPA References

以官方文件為 transport/API reference：

- JSON-RPC API usage
  `https://freeipa.readthedocs.io/en/stable/api/jsonrpc_usage.html`

- API basic usage
  `https://freeipa.readthedocs.io/en/latest/api/basic_usage.html`

- JSON-RPC design
  `https://www.freeipa.org/page/V4/JSON-RPC`

- CLI/API `--all` / `--raw` semantics
  `https://www.freeipa.org/page/CLI_Overview`

禁止 runtime screen-scrape unofficial human output。

---

## 64. Acceptance Criteria

### Formal naming

- [ ] User TUI command是 `pilot portal`。
- [ ] Backend binary是 `pilot-access-gateway`。
- [ ] systemd units是 `pilot-access-gateway.service/.socket`。
- [ ] Gateway hosts遵循 `pilot-gw-<scope>-<nn>`。
- [ ] FreeIPA Gateway hostgroup是 `pilot-access-gateways`。
- [ ] Target scope hostgroup遵循 `pilot-target-<scope>`。
- [ ] 不建立 generic `pilotd`。

### Stateless

- [ ] Gateway不讀 roster。
- [ ] Gateway不讀 inventory。
- [ ] Gateway不讀 breakglass JSON。
- [ ] Gateway不用 local SQLite。
- [ ] restart不需 restore data。
- [ ] 不需要 `/var/lib/pilot/access-gateway`。

### Gateway scope

- [ ] config有 `gateway.id`。
- [ ] config有 `gateway.scope`。
- [ ] config有 `gateway.target_hostgroup`。
- [ ] My Hosts = FreeIPA HBAC allow ∩ target hostgroup。
- [ ] same-scope Gateway結果等價。
- [ ] different-scope Gateway不洩漏其他 scope targets。
- [ ] client不能 override scope。
- [ ] single DNS/VIP不混用不同 scopes。

### FreeIPA runtime

- [ ] current user查 remote FreeIPA。
- [ ] nested groups正確。
- [ ] target hostgroup nested expansion正確。
- [ ] HBAC live state正確。
- [ ] sudo live state正確。
- [ ] sudo time window正確。
- [ ] Pilot-managed dynamic rules可見。

### Security

- [ ] caller identity來自 SO_PEERCRED。
- [ ] `$USER`不能 spoof。
- [ ] service principal read-only。
- [ ] TLS verify。
- [ ] FreeIPA outage fail closed。
- [ ] out-of-scope host不能 Connect。
- [ ] raw host不能輸入。
- [ ] user SSH config不能影響 Portal。
- [ ] forwarding disabled。
- [ ] target host key strict verify。
- [ ] site若要求 restricted bastion，network egress對 out-of-scope SSH也阻擋。

### User flow

- [ ] SSH Gateway直接進 Portal。
- [ ] Portal顯示 Gateway ID與 Scope。
- [ ] My Hosts只列 allowed scope hosts。
- [ ] detail顯示 sudo。
- [ ] Connect前 fresh authorize。
- [ ] remote `whoami`為原 user。
- [ ] target FreeIPA可最終 deny。
- [ ] exit remote後回 Portal。
- [ ] Logout關閉 outer SSH session。

### Delivery

- [ ] `pilot-access-gateway` contract。
- [ ] verification。
- [ ] apply playbook。
- [ ] deploy catalog。
- [ ] build artifact。
- [ ] idempotent apply。
- [ ] multi-Gateway E2E。
- [ ] stateless restart test。

## 65. Definition of Done

完成標準：

```text
formal component naming
+
runtime truth only from FreeIPA
+
stateless pilot-access-gateway
+
immutable gateway.id / scope / target_hostgroup
+
HBAC(user) ∩ GatewayScope
+
same-scope horizontal scaling
+
different-scope isolation
+
trusted peer identity
+
fresh Connect authorization
+
controlled OpenSSH
+
target FreeIPA final enforcement
+
network defense-in-depth where required
+
reproducible deployment
+
automated verification
```

## 66. 最終架構原則

正式命名：

```text
pilot portal
    = 使用者 TUI

pilot-access-gateway
    = stateless read-only backend

pilot-gw-<scope>-<nn>
    = Gateway host

pilot-access-gateways
    = 所有 Gateway hosts 的 FreeIPA hostgroup

pilot-target-<scope>
    = 每個 Gateway scope 的 target hostgroup
```

責任：

```text
Pilot management plane:
    writes/reconciles desired state into FreeIPA
    publishes gateway target scopes

FreeIPA:
    stores live identity / HBAC / sudo / hostgroup truth

pilot-access-gateway:
    identifies caller via SO_PEERCRED
    reads FreeIPA
    intersects user access with this Gateway scope
    stores no persistent application state

pilot portal:
    displays current Gateway ID/scope
    displays current user's scoped access
    launches trusted OpenSSH

target sshd / SSSD:
    performs final enforcement

network ACL/firewall:
    optionally provides a second, independent gateway egress boundary
```

核心公式：

```text
ConnectableHosts(user, gateway)
=
EffectiveFreeIPASSHHosts(user)
INTERSECT
EffectiveMembers(gateway.target_hostgroup)
```

一句話：

> **每台 `pilot-access-gateway` 都是一個可隨時替換的 stateless access gateway；同 scope 的多台節點共享同一 FreeIPA target hostgroup，不同 scope 的節點彼此隔離。使用者看到的是「這個 Gateway 能帶他去哪裡」，而不是整個公司的所有 FreeIPA 權限。**


