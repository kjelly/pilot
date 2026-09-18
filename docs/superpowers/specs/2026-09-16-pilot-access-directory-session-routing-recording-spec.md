# Pilot Access Directory、Gateway Handoff 與 SSH Session Recording 實作規格

- 狀態：**DRAFT / Coding Agent Implementation Spec**
- 日期：2026-09-16（2026-09-18 修正 baseline drift，見下方「修正紀錄」）
- Repository：`https://github.com/kjelly/pilot`
- Baseline：`main@2608dbdf571d67f0bb4607b560cfd13f1cad9964`
- 前置規格：`docs/superpowers/specs/2026-09-14-pilot-access-gateway-stateless-freeipa-portal-spec.md`
- Audience：Pilot maintainers / Coding Agent / SRE
- 核心目標：**使用者只需要知道一個 `pilot-access-directory` 入口，即可看見跨 scope 的可存取主機，選擇後由 Directory 自動路由至正確 `pilot-access-gateway`，再由 Gateway fresh-authorize 後 SSH 到目標主機；整條路徑具備一致的 session correlation，並保留未來/選配的 terminal session recording 能力。**

---

## 修正紀錄（2026-09-18）

初版 baseline 是 `main@e910737`；同一天稍晚 main 又累積了 6 個 commit（含 3 個直接影響本規格假設的變更），因此在交付給 coding agent 前先做了一輪 baseline refresh：

1. **`internal/accessportal.LoadUserAccess` 現在每個 SSH-allowed host 會多呼叫一次 `HostShow`**（`fa5d37a` 為 My Hosts annotations 而加）。已更新 §9.3 的 query-complexity 要求，明確要求 shared snapshot 對這個呼叫也要做 cross-scope 去重。
2. **Gateway→target 的 `/etc/pilot/ssh_config` 已從 `ProxyCommand none` + apply-time `ssh-keyscan` 快照，改成 `ProxyCommand /usr/bin/sss_ssh_knownhostsproxy` + SSSD 自己動態維護的 `/var/lib/sss/pubconf/known_hosts`**（`c084b71`：舊做法對新加入 host 有 staleness gap，且 ssh-keyscan 是 blind TOFU）。原本 §15/§15.1/§19 對 Directory→Gateway 這一段抄的是舊（已被判定較弱）的 keyscan-snapshot 設計，已同步改用 SSSD 動態解析，徹底不需要 `/etc/pilot/directory_gateway_known_hosts` 這個檔案。
3. **Gateway→target 的 SSO 已從「依賴使用者 inbound SSH 連線的 `GSSAPIDelegateCredentials yes` 委派」，改成 Gateway process 自己用 `cmd/pilot/cmd/portal_kerberos.go`（`portalCredentialSession`/`portalKerberosSession`）管理 session-scoped Kerberos ticket cache，SSH 只用 `BatchMode yes` + GSSAPI-only 認證**（`f3e1cb3`：純委派在實務上不夠可靠）。原本 D5 對 Directory→Gateway 這一新 hop 提的仍是舊的委派做法，已改成明確要求重用/延伸同一套 self-managed ticket 機制。
4. 其餘兩個 commit（`3b9dd9e` portal_automember 預設開啟、`f7e1233` 讓 verification 探測 shell-safe）不影響本規格的架構假設，僅供 coding agent 知悉現況。

以下內文已依上述 4 點更新；被取代的舊設計以刪除線／改寫呈現，不再保留成兩套並存的說法。

---

## 0. 必須先遵守的架構決策

本節優先於後續所有細節；若實作過程發現後文與本節衝突，以本節為準。

### D1 — Directory 是 Discovery / Routing Plane，不是新的授權權威

`pilot-access-directory` 可以：

- 找出目前使用者跨所有 scope 的可存取 targets。
- 找出 target 所屬 scope。
- 找出該 scope 的 Gateway instance candidates。
- 建立 session correlation ID。
- 發起 Directory → Gateway 的受控 SSH handoff。

但 **Directory 的「allowed」結果永遠不能取代 Gateway 的 fresh authorization**。

真正 connect 前仍必須：

```text
authenticated user
        +
Gateway 固定 scope
        +
target ∈ pilot-target-<scope>
        +
live FreeIPA HBAC(sshd)
        ↓
allow / deny
```

Directory 查到的 access list 只是 discovery-time projection，不是 capability、ticket 或 grant token。

---

### D2 — 不修改既有 Gateway scope isolation semantics

現有 `pilot-access-gateway` 必須保留：

```text
My Hosts =
effective FreeIPA SSH allow
INTERSECT
gateway.target_hostgroup
```

既有 Gateway Portal 仍不得加入 scope switcher。

Directory 是一層新的 **global projection**；Gateway 仍是 scope-local enforcement point。

---

### D3 — Scope 不得從 Gateway hostname 推導

禁止：

```text
pilot-gw-gpu-01 -> 猜 scope=gpu
```

現有 Gateway config 已明確把：

```text
gateway.id
gateway.scope
gateway.target_hostgroup
```

當 machine-readable policy reference。

本規格新增：

```text
pilot-gateway-<scope>
```

FreeIPA hostgroup，作為：

```text
scope -> gateway instances
```

的 live source of truth。

例如：

```text
pilot-gateway-gpu
├── pilot-gw-gpu-01.linker.internal
└── pilot-gw-gpu-02.linker.internal

pilot-gateway-dmz
└── pilot-gw-dmz-01.linker.internal
```

Directory 不得讀 `hosts.yml`、inventory、roster 或 hostname pattern 來找 Gateway。

---

### D4 — Directory v1 使用單一 canonical ingress

v1 使用：

```text
access.<freeipa_domain>
```

作為唯一使用者入口，並先採：

```yaml
hostCardinality: exactly-one
```

**v1 要求 `access.<freeipa_domain>` 就是這台 Directory 主機實際 FreeIPA-enrolled FQDN，不是 CNAME / 額外 alias。**

原因：

- 使用者只需記一個 SSH endpoint。
- SSH host key identity 與 Kerberos `host/<fqdn>` principal 直接對齊，不需要為 alias 額外處理 host principal。
- 避免多台 Directory instance 共用 DNS 名稱時出現 SSH host-key identity 問題。
- Directory 本身是 stateless；日後 HA 可另外導入 SSH host certificate / stable L4 ingress，不在 v1 偷塞不完整方案。

若未來一定要用獨立 alias 或多 instance VIP，必須另行驗證：

```text
OpenSSH GSSAPI service principal
SSH host key / host certificate
DNS canonicalization
failover
```

不能只加一筆 CNAME 就宣稱支援。

Gateway 仍維持：

```yaml
hostCardinality: one-or-more
```

且同 scope 可有多 instance。

---

### D5 — Directory → Gateway 使用「真實使用者 SSH identity」

Directory 不得用 service account 代替使用者登入 Gateway，再用 header/token 宣稱：

```text
user=alice
```

正確模式：

```text
alice SSH -> Directory
Directory process 仍以 alice 執行
alice 的 process 再 SSH -> Gateway
Gateway sshd 認證到的仍然是 alice
```

因此 Gateway 現有：

- sshd / FreeIPA authentication
- `SO_PEERCRED`
- UID → username resolution
- Portal group defense-in-depth
- Gateway API fresh authorize

都可以繼續使用，不需要建立 delegated-identity 信任模型。

**Directory → Gateway 的 SSO 必須重用既有 `cmd/pilot/cmd/portal_kerberos.go` 的 self-managed ticket 模式，不得走純 `GSSAPIDelegateCredentials` 委派。**

原因：Gateway → target 這一段本來就是同一種「controlled SSH hop，使用者仍是 alice」場景，`f3e1cb3`（2026-09-16 同日）已經把它從「依賴使用者 inbound SSH session 委派的 `GSSAPIDelegateCredentials yes`」換成「Gateway process 自己用 `portalCredentialSession.Ensure(ctx, username)` 建立/重用一份 session-scoped Kerberos ticket cache（`kinit -c <cache> username`，必要時互動式要密碼），再把該 cache 透過 `KRB5CCNAME` 注入子行程」，因為純委派在實務上不可靠（使用者自己的 SSH client 是否有帶 `-K`/delegate 完全不受這端控制，且未必每個使用者環境都會委派）。Directory → Gateway 面對的是同一個問題，若照字面實作「靠 inbound `GSSAPIDelegateCredentials yes`」，等於重踩六小時前才在鄰近 hop 被放棄的做法。

正確做法：

```text
Directory process（以 alice 身分執行）
    |
    +-- portalCredentialSession.Ensure(ctx, "alice")
    |       -> 有效 cache 就重用；沒有就 kinit 取得新 ticket
    |       -> 回傳 "FILE:<session-cache-path>"
    |
    +-- exec ssh -F /etc/pilot/directory_ssh_config <gateway-fqdn> \
            -- pilot-connect <session-id> <target-fqdn>
        （KRB5CCNAME 指到上面的 cache；SSH config 見 §15，GSSAPI-only + BatchMode yes）
```

實作時把 `portalCredentialSession`/`portalKerberosSession`/`newPortalKerberosSession` 從 `cmd/pilot/cmd/portal_kerberos.go` 原地重用（`directory_ssh.go` 與 `portal_ssh.go` 同在 `cmd/pilot/cmd` package，可直接呼叫）；唯一必要的通用化：`newPortalKerberosSession` 內部 `os.MkdirTemp(s.runtimeBase, "pilot-portal-")` 的前綴目前寫死是 `"pilot-portal-"`，需要加一個 component 前綴參數（例如 `"pilot-directory-"`），否則 Directory 建立的 per-session cache 目錄會誤植 portal 字樣。不得為 Directory 另刻一份平行的 kinit/ticket 邏輯。

Gateway 端的 sshd/FreeIPA 認證與現有 defense-in-depth 不變；Directory 本身仍不得讀取或保存使用者密碼（密碼只在 `portalKerberosSession.Ensure` 內部、經由既有的 `readPortalKerberosPassword` 互動式輸入給 `kinit`，不落地、不經過 Directory 自己的程式碼路徑保存）。

---

### D6 — Handoff command 是 routing hint，不是授權 token

Directory → Gateway 的 remote command 固定為：

```text
pilot-connect <session-id> <fqdn>
```

例如：

```text
pilot-connect 0d33c638-83fa-4d77-9811-a97a7a7af1d5 gpu01.linker.internal
```

不得傳：

```text
user
scope
sudo
HBAC result
gateway ID
arbitrary SSH option
shell command
```

Gateway 只把：

```text
session-id
target fqdn
```

當 untrusted input。

即使使用者自行對 Gateway 發出合法格式的 `pilot-connect`，Gateway 仍必須用自己的 authenticated user + fixed scope 做完整 fresh authorize。

---

### D7 — `SSH_ORIGINAL_COMMAND` 永遠不得交給 shell

禁止：

```sh
sh -c "$SSH_ORIGINAL_COMMAND"
bash -c "$SSH_ORIGINAL_COMMAND"
eval "$SSH_ORIGINAL_COMMAND"
```

Gateway 的 ForceCommand wrapper 只能接受：

1. 空 command → 現有 `pilot portal`
2. 精確符合 handoff grammar 的 `pilot-connect <uuid> <fqdn>`
3. 其他全部拒絕

Parser 必須是 Go code 或等價的 strict parser，不得依賴 shell tokenization。

---

### D8 — Session Recording 預設不得保存 raw terminal input

預設：

```yaml
pilot_session_recording_mode: metadata
```

支援：

```text
metadata
terminal_output
terminal_io
```

其中：

- `metadata`：只記 session lifecycle / route / result。
- `terminal_output`：另記 target terminal output。
- `terminal_io`：另記 terminal input + output。

`terminal_io` 是高敏感模式，可能記錄：

- shell command
- API token
- `export SECRET=...`
- DB credential
- sudo/password prompt input
- passphrase
- TUI input

即使加入 echo-off redaction，也不能宣稱 100% secret masking。

因此 `terminal_io` 必須是 explicit opt-in，不得成為 default。

---

### D9 — Gateway 不得因 Session Recording 變成 persistent-state host

Gateway 可有 bounded transient buffers / runtime temp files，但不得把 recording 當 durable local state。

持久化 recording 必須送到中央 sink。

Gateway restart 後不得依賴本機 recording state 才能正確授權。

---

### D10 — 現有 `audit-log-forwarding` 是補充，不是完整 command recorder

目前 `playbooks/templates/audit.rules.j2` 實際監控：

- `/usr/bin/sudo` execution
- `/etc/passwd`
- `/etc/sudoers`
- setuid/setgid execve
- setuid/setgid mode changes

它**沒有記錄每個一般 `execve`**。

因此不得在文件宣稱現有 auditd 已經能還原使用者執行的所有 commands。

若日後需要 authoritative process execution audit，應新增獨立 opt-in audit profile，而不是把 terminal keystrokes 當成「執行過的 command」。

---

## 1. 現況事實

Baseline 已存在：

```text
cmd/pilot-access-gateway/
internal/freeipaaccess/
internal/accessportal/
internal/gatewayapi/
internal/peercred/
internal/identity/
internal/systemdactivation/

cmd/pilot/cmd/portal.go
cmd/pilot/cmd/portal_client.go
cmd/pilot/cmd/portal_tui.go
cmd/pilot/cmd/portal_ssh.go
cmd/pilot/cmd/portal_kerberos.go   # session-scoped Kerberos ticket acquisition — Directory 必須重用，見 D5

playbooks/apply/pilot-access-gateway-apply.yml
contracts/pilot-access-gateway.yaml
docs/verification/pilot-access-gateway.md
scripts/pilot-access-gateway-lockout-test.sh
```

`internal/accessportal.Resolver.LoadUserAccess` 現在對每個 SSH-allowed host 都會額外呼叫一次 `Provider.HostShow`（`fa5d37a`，2026-09-16，用於 My Hosts annotations）。這條 RPC 不是本規格新加的，但 §9.3 的 query-complexity 要求必須把它算進去並要求去重。

`role-pilot-portal-user` 目前預設由 Gateway apply 的 automember rule 自動涵蓋「所有 FreeIPA 帳號（`admin` 除外）」（`3b9dd9e`）。Directory §31 Step 7「ensure group 存在，但不管理 user membership」與此相容，不需要改；只是代表幾乎每個使用者一開始就會出現在 Directory 的登入群組裡。

Gateway API 是 HTTP-over-Unix-socket：

```text
/v1/identity
/v1/access
/v1/access/{fqdn}
/v1/connect/authorize
/v1/health
```

且不 listen TCP。

現有 `portal_ssh.go` 已使用 root-owned SSH config（`pilotSSHConfig`，已於 `c084b71`／`f3e1cb3` 更新過，以下是目前實際內容，**不是** 2026-09-16 早上的舊版）：

```text
ForwardAgent no
ClearAllForwardings yes

PermitLocalCommand no
EnableEscapeCommandline no
EscapeChar none

ProxyJump none
ProxyCommand /usr/bin/sss_ssh_knownhostsproxy -p %p %h

StrictHostKeyChecking yes
UserKnownHostsFile /dev/null
GlobalKnownHostsFile /var/lib/sss/pubconf/known_hosts

GSSAPIAuthentication yes
GSSAPIDelegateCredentials no
PreferredAuthentications gssapi-with-mic

BatchMode yes
PubkeyAuthentication no
KbdInteractiveAuthentication no
PasswordAuthentication no

RequestTTY force
```

關鍵差異（相對於本規格最初抄錄的舊版）：

- **host key 驗證改用 `sss_ssh_knownhostsproxy`**：透過 SSSD 即時解析對方 host 的 `ipaSshPubKey`，`GlobalKnownHostsFile` 指到 SSSD 自己動態維護的 `/var/lib/sss/pubconf/known_hosts`，不再用 apply-time `ssh-keyscan` 一次性快照（舊法有 staleness gap，且是 blind TOFU）。**Directory → Gateway 的 SSH config（§15）必須採用同一模式**，不得再用「apply 時 keyscan 寫入 root-owned known_hosts 檔」的舊設計。
- **認證改成 GSSAPI-only + `BatchMode yes`**：不再讓 OpenSSH 自己 fallback 到 keyboard-interactive/password，改由呼叫端（`portalCredentialSession`）預先用 `kinit` 準備好 ticket cache，SSH 只認 GSSAPI。**Directory → Gateway 必須重用同一套機制**，見 D5。

且 Connect 每次呼叫 `/v1/connect/authorize` 後才啟動 SSH。

Baseline `go.mod` 已包含：

```text
github.com/creack/pty
github.com/google/uuid
golang.org/x/term
```

所以 PTY recorder、UUID session ID 與 terminal raw-mode 不需要新增核心 dependency。

---

## 2. 目標

### 2.1 使用者目標

使用者只需要：

```bash
ssh alice@access.linker.internal
```

進入：

```text
Pilot Access Directory

User  alice
────────────────────────

> My Hosts
  My Identity
  Refresh
  Logout
```

`My Hosts` 顯示所有 scope 的 effective targets，例如：

```text
gpu-worker-01.linker.internal    scope=gpu
gpu-worker-02.linker.internal    scope=gpu
gitlab-prod.linker.internal      scope=dmz
db-dev-01.linker.internal        scope=dev
```

選擇：

```text
gpu-worker-01.linker.internal
```

後自動：

```text
Directory
   ↓ resolve route
pilot-gateway-gpu
   ↓ choose healthy instance
pilot-gw-gpu-02
   ↓ Gateway fresh authorize
gpu-worker-01
```

使用者不需要知道：

```text
pilot-gw-gpu-01
pilot-gw-gpu-02
pilot-gw-dmz-01
```

---

### 2.2 Security 目標

任何 Directory bug 都不能讓使用者：

- 跨 Gateway scope。
- 以其他 username 登入 target。
- 指定 IP 取代 FQDN。
- 注入 SSH option。
- 注入 shell command。
- 開啟 port forwarding。
- 開啟 ProxyCommand / ProxyJump。
- 透過自訂 session ID 取得權限。
- 使用 stale Directory cache 繞過 Gateway fresh authorization。

---

### 2.3 Audit 目標

至少能回答：

```text
誰
何時
由哪台 Directory
選哪個 target
路由到哪個 Gateway
Gateway authorization 結果
SSH 是否成功
session 何時結束
exit result
```

若啟用 terminal recording，再能依 `session_id` 還原：

```text
terminal output
或
terminal input + output
```

---

## 3. Non-goals

v1 不做：

- Directory 自己直接 SSH target，繞過 Gateway。
- Directory 成為 Gateway authorization cache。
- Directory 寫 FreeIPA access policy。
- scope switcher 加回既有 Gateway Portal。
- 依 Gateway hostname 推導 scope。
- SSH agent forwarding。
- arbitrary remote command forwarding。
- SCP/SFTP through captive Gateway。
- port forwarding。
- 100% secret-redaction 保證。
- 把 terminal input bytes 當 authoritative command audit。
- 自動修改企業 retention / privacy policy。
- 多 Directory HA ingress。
- 對使用者工作站強制安裝 Pilot binary。

---

## 4. 命名

### 4.1 Component

```text
pilot-access-directory
pilot-access-gateway        # existing
pilot-session-store         # optional recording persistence component
```

### 4.2 Binary

```text
/usr/local/bin/pilot
/usr/local/bin/pilot-access-directory
/usr/local/bin/pilot-access-gateway
/usr/local/bin/pilot-session-store       # optional
```

### 4.3 systemd

```text
pilot-access-directory.socket
pilot-access-directory.service

pilot-access-gateway.socket
pilot-access-gateway.service

pilot-session-store.socket               # admin/read Unix socket, optional
pilot-session-store.service
```

### 4.4 Unix socket

```text
/run/pilot/access-directory.sock
/run/pilot/access-gateway.sock
/run/pilot/session-store.sock
```

### 4.5 FreeIPA

```text
role-pilot-portal-user                   # existing user group

pilot-access-directories                 # Directory hosts
pilot-access-gateways                    # existing all Gateway hosts

pilot-gateway-<scope>                    # NEW: Gateway instances for one scope
pilot-target-<scope>                     # existing scope target hosts
```

### 4.6 SSH entrypoint

```text
access.<freeipa_domain>
```

例如：

```text
access.linker.internal
```

### 4.7 Service principals

```text
pilot-access-directory/<directory-fqdn>@REALM
pilot-access-gateway/<gateway-fqdn>@REALM     # existing
```

Directory reader principal加入既有 read-only FreeIPA reader role；不要新建 admin-equivalent role。

---

## 5. 邏輯架構

```text
                        +---------------------------+
                        |          FreeIPA          |
                        |---------------------------|
                        | users / groups            |
                        | HBAC / sudo               |
                        | pilot-target-*            |
                        | pilot-gateway-*           |
                        | pilot-access-gateways     |
                        +-------------+-------------+
                                      |
                               read-only JSON-RPC
                                      |
                    +-----------------+-----------------+
                    |                                   |
                    v                                   v
          +----------------------+          +----------------------+
          | pilot-access-directory|          | pilot-access-gateway |
          | global discovery     |          | scope-local enforce  |
          | route selection      |          | fresh authorize      |
          +----------+-----------+          +----------+-----------+
                     |                                 |
User SSH             | SSH as SAME user                | controlled SSH
                     |                                 |
     +---------------+--------------------+            v
     |                                    |        Target host
     v                                    |
access.<domain>                          Gateway instance
Directory TUI
```

---

## 6. Network boundary

最低 network requirements：

```text
User      -> Directory : TCP/22
Directory -> Gateway   : TCP/22
Gateway   -> Target    : TCP/22
Directory -> FreeIPA   : Kerberos/HTTPS/LDAP 等既有 FreeIPA client requirements
Gateway   -> FreeIPA   : existing
Gateway   -> Session Store HTTPS : only when terminal recording sink enabled
```

Directory **不需要**能直接連 target network。

建議正式環境最終可以用 firewall 把 Gateway ingress 限制成：

```text
Directory network -> Gateway TCP/22
```

但這不是本 feature correctness 的必要條件；即使使用者仍能直接 SSH Gateway，也不得取得額外權限。

---

## 7. FreeIPA scope / gateway publication

### 7.1 新增 `pilot-gateway-<scope>`

當 Gateway：

```yaml
gateway_scope: gpu
```

`pilot-access-gateway-apply.yml` 必須確保：

```text
pilot-access-gateways
  contains gateway fqdn

pilot-gateway-gpu
  contains gateway fqdn
```

### 7.2 Stale membership self-scrub

若 host 原本：

```text
pilot-gateway-dev
```

後來改為：

```yaml
gateway_scope: gpu
```

同一次 apply 必須：

```text
remove self from pilot-gateway-dev
add self to pilot-gateway-gpu
```

禁止同一 Gateway 因歷史配置殘留同時出現在多個 `pilot-gateway-*`。

例外：

- `pilot-access-gateways` 是 global classification，不移除。
- `pilot-target-*` 仍依目前既有 Step 3b 規則確保 Gateway 自己不是 target。

### 7.3 不允許 empty-scope group

scope 必須沿用 Gateway 目前 validator 的安全字元限制，並額外確保：

```text
pilot-gateway-<scope>
pilot-target-<scope>
```

可安全作為 FreeIPA object name。

---

## 8. FreeIPA discovery read primitive

目前 `internal/freeipaaccess.Provider` 只有：

```go
HostgroupShow(...)
```

沒有 hostgroup listing。

Directory 需要 discover：

```text
pilot-target-*
pilot-gateway-*
```

### 8.1 不擴大既有 `Provider` interface

避免讓所有現有 `accessportal` fake provider / tests 因一個 Directory feature 全部被迫新增 method。

新增窄 interface：

```go
type HostgroupFinder interface {
    HostgroupFind(ctx context.Context, prefix string) ([]freeipaaccess.HostgroupSummary, error)
}
```

或等價型別。

Concrete `freeipaaccess.Client` 實作：

```text
hostgroup_find
```

Directory resolver 同時依賴：

```go
freeipaaccess.Provider
HostgroupFinder
```

### 8.2 Phase 0 必須真實 FreeIPA 驗證

必須對真實 vm-target FreeIPA：

1. 使用現有 Gateway Reader 等級 service principal。
2. 呼叫 `hostgroup_find`.
3. 證明能讀到 `pilot-target-*` / `pilot-gateway-*`。
4. 確認 response 真實欄位格式。
5. 將真實 response sanitized 後放進 `internal/freeipaaccess/testdata/`。
6. 若現有 reader privilege 不足，只增加 hostgroup find 所需的最小 read permission。

不得從文件推測 JSON shape 後手刻 fixture。

---

## 9. Shared policy snapshot：避免第二套授權引擎

Directory 不得 copy/paste：

```text
resolveSSHAccess
resolveSudoAccess
expandReferencedHostgroups
...
```

建立第二套 global authorization implementation。

### 9.1 Refactor `internal/accessportal`

新增 reusable snapshot abstraction，名稱可微調，但責任需符合：

```go
type PolicySnapshot struct {
    User              UserContext
    HBACRules         []freeipaaccess.HBACRule
    SudoRules         []freeipaaccess.SudoRule
    HostgroupHosts    map[string]map[string]struct{}
    ServiceGroups     map[string]map[string]struct{}
    CommandGroups     map[string]map[string]struct{}
    GeneratedAt       time.Time
}
```

新增：

```go
func LoadPolicySnapshot(
    ctx context.Context,
    provider freeipaaccess.Provider,
    username string,
    now time.Time,
) (PolicySnapshot, error)

func ResolveScopeAccess(
    ctx context.Context,
    provider freeipaaccess.Provider,
    snapshot PolicySnapshot,
    gateway GatewayConfig,
) (UserAccess, error)
```

### 9.2 Existing Gateway behavior 不可 semantic regression

現有：

```go
Resolver.LoadUserAccess(...)
```

改成內部呼叫：

```text
LoadPolicySnapshot
ResolveScopeAccess
```

但輸出必須與 baseline 完全相同。

現有 `internal/accessportal/resolver_test.go` 必須全部保留並通過。

### 9.3 Directory query complexity

對一個使用者：

```text
1 x UserShow
1 x HBACRuleFind
1 x SudoRuleFind
N x distinct referenced hostgroup/servicegroup/commandgroup
M x pilot-target-<scope> HostgroupShow
K x distinct SSH-allowed host HostShow   # annotations，見 §1／fa5d37a
```

不得變成：

```text
M scopes × 全套 UserShow/HBACRuleFind/SudoRuleFind
M scopes × 同一個 host 重複 HostShow
```

避免 scope 數量增加後 RPC 線性放大。`K x HostShow` 這條是 `internal/accessportal.LoadUserAccess` 既有行為（annotations），Directory 的 shared snapshot 若對每個 scope 各自呼叫一次既有 `LoadUserAccess`，同一台 host 出現在多個 scope 時會被重複 `HostShow`；`LoadPolicySnapshot`/`ResolveScopeAccess` 必須在 snapshot 這一層對 `HostShow` 按 fqdn 去重快取一次，而不是每個 scope 各自重跑。

---

## 10. Directory resolver

新增：

```text
internal/accessdirectory/
    model.go
    catalog.go
    resolver.go
    resolver_test.go
    fake_provider_test.go
```

### 10.1 Scope catalog

從：

```text
HostgroupFind("pilot-target-")
HostgroupFind("pilot-gateway-")
```

建立：

```go
type ScopeRoute struct {
    Scope            string
    TargetHostgroup  string
    GatewayHostgroup string
    GatewayFQDNs     []string
}
```

### 10.2 Global access model

```go
type DirectoryAccess struct {
    User        string
    GeneratedAt time.Time
    Targets     []DirectoryTarget
}

type DirectoryTarget struct {
    FQDN  string
    SSH   accessportal.SSHAccess
    Sudo  accessportal.SudoAccess
    Routes []TargetRoute
}

type TargetRoute struct {
    Scope             string
    TargetHostgroup   string
    GatewayHostgroup  string
    GatewayCandidates []string
    RouteStatus       string // ready | no_gateway | stale_known_host
}
```

### 10.3 同一 target 出現在多個 scope

不得直接 duplicate 成無法辨識的多個 host rows。

合併成：

```text
DirectoryTarget
  FQDN
  Routes[]
```

Connect 時：

1. 優先 `route_status=ready`
2. candidate health 可用
3. scope lexical tie-break 只用於 deterministic selection
4. 第一條 route connect 失敗，可以 fallback 下一條同 target route
5. 每條 route 最終仍由對應 Gateway fresh authorize

---

## 11. Directory API

新增：

```text
internal/directoryapi/
    server.go
    types.go
    handlers.go
    server_test.go
    portal_group_test.go
```

與 `gatewayapi` 一樣：

- HTTP-over-Unix-socket
- 不 listen TCP
- caller identity 來自 `SO_PEERCRED`
- UID → username 使用現有 `internal/identity`
- Portal group defense-in-depth
- `/v1/health` 不需 per-user group gate
- user endpoints 必須 group gate

### 11.1 API

```text
GET  /v1/identity
GET  /v1/access
GET  /v1/access/{fqdn}
POST /v1/connect/resolve
GET  /v1/health
```

### 11.2 `/v1/connect/resolve`

Request：

```json
{
  "target": "gpu-worker-01.linker.internal"
}
```

Server 必須 fresh load：

```text
current user
current scopes
current target access
current gateway candidates
```

不得信任 `/v1/access` 的 cached row。

Response：

```json
{
  "allowed": true,
  "session_id": "0d33c638-83fa-4d77-9811-a97a7a7af1d5",
  "target": "gpu-worker-01.linker.internal",
  "route": {
    "scope": "gpu",
    "gateway_candidates": [
      "pilot-gw-gpu-01.linker.internal",
      "pilot-gw-gpu-02.linker.internal"
    ]
  }
}
```

`session_id` 使用：

```go
uuid.NewRandom()
```

或 `google/uuid` 等價 CSPRNG path。

---

## 12. Directory service

新增：

```text
cmd/pilot-access-directory/
    main.go
    config.go
    config_test.go
```

### 12.1 Config

建議：

```yaml
directory:
  id: access-01
  target_hostgroup_prefix: pilot-target-
  gateway_hostgroup_prefix: pilot-gateway-
  portal_user_group: role-pilot-portal-user

freeipa:
  servers:
    - ipa1.linker.internal
  ca_file: /etc/ipa/ca.crt
  service_principal: pilot-access-directory/access.linker.internal@LINKER.INTERNAL
  keytab: /etc/pilot/pilot-access-directory.keytab

routing:
  ssh_config: /etc/pilot/directory_ssh_config
  connect_timeout: 5s
```

沒有 `gateway_known_hosts` 欄位：host key 驗證改用 SSSD 動態維護的 `/var/lib/sss/pubconf/known_hosts`（見 §15），不需要 Directory 自己管理一份 known_hosts 快照檔。

YAML loader 必須：

```go
yaml.Decoder.KnownFields(true)
```

未知 key 必須 fail。

### 12.2 systemd hardening

比照 Gateway：

```text
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
RestrictAddressFamilies=...
```

Directory backend 不需要 shell write access。

---

## 13. Directory TUI

新增：

```text
cmd/pilot/cmd/directory.go
cmd/pilot/cmd/directory_client.go
cmd/pilot/cmd/directory_tui.go
cmd/pilot/cmd/directory_ssh.go
```

command：

```text
pilot directory
```

### 13.1 UI

```text
Pilot Access Directory

Directory access-01
User      alice
────────────────────────

> My Hosts
  My Identity
  Refresh
  Logout
```

My Hosts：

```text
gpu-worker-01.linker.internal    GPU
gpu-worker-02.linker.internal    GPU
gitlab-prod.linker.internal      DMZ
db-dev-01.linker.internal        DEV
```

對 `route_status != ready`：

```text
gpu-old-01.linker.internal   GPU   ⚠ no gateway available
```

保留顯示，但：

```text
Connect disabled
```

使使用者能分辨：

```text
有 policy access
vs
目前沒有 route
```

### 13.2 Reuse Pilot TUI primitives

沿用：

```text
runSelectPrompt
runConfirmPrompt
portal breadcrumb / screen factory pattern
activePromptAutomation test hook
```

不得建立第二套 TUI framework。

---

## 14. Directory ForceCommand

新增：

```text
/usr/local/libexec/pilot-directory-session
```

sshd：

```text
Match Group role-pilot-portal-user
    ForceCommand /usr/local/libexec/pilot-directory-session
    PermitTTY yes
    AllowTcpForwarding no
    X11Forwarding no
    PermitTunnel no
```

v1 支援兩種 command：

```text
SSH_ORIGINAL_COMMAND == ""
    -> exec pilot directory

SSH_ORIGINAL_COMMAND == "pilot-directory-connect <fqdn>"
    -> strict parse
    -> one-shot connect flow
```

其他：

```text
exit 1
```

這讓未來使用者本機若有 Pilot CLI，可以實作：

```text
pilot access connect <fqdn>
```

其實只是 fixed argv：

```text
ssh -tt access.<domain> pilot-directory-connect <fqdn>
```

但 v1 TUI 不依賴使用者端安裝 Pilot。

---

## 15. Directory → Gateway SSH config

新增 root-owned：

```text
/etc/pilot/directory_ssh_config
```

**不需要**額外的 `directory_gateway_known_hosts` 快照檔——host key 驗證比照現行（`c084b71` 之後的）Gateway → target 模式，改用 SSSD 動態維護的 known_hosts（見 §15.1）。Directory 本身依 D4/§33 一定是 FreeIPA-enrolled + `freeipa-client` sameHosts dependency，所以 `sss_ssh_knownhostsproxy` 與 `/var/lib/sss/pubconf/known_hosts` 在 Directory host 上必然可用。

最低 directives（比照 `cmd/pilot/cmd/portal_ssh.go` 現行 `pilotSSHConfig`，僅 target 由 Gateway FQDN 取代）：

```text
Host *
    ForwardAgent no
    ClearAllForwardings yes

    PermitLocalCommand no
    EnableEscapeCommandline no
    EscapeChar none

    ProxyJump none
    ProxyCommand /usr/bin/sss_ssh_knownhostsproxy -p %p %h

    StrictHostKeyChecking yes
    UserKnownHostsFile /dev/null
    GlobalKnownHostsFile /var/lib/sss/pubconf/known_hosts

    GSSAPIAuthentication yes
    GSSAPIDelegateCredentials no
    PreferredAuthentications gssapi-with-mic

    BatchMode yes
    PubkeyAuthentication no
    KbdInteractiveAuthentication no
    PasswordAuthentication no

    RequestTTY force
```

`GSSAPIDelegateCredentials no` + `BatchMode yes` + 停用 Pubkey/KbdInteractive/Password 是刻意的：認證憑證由呼叫端（D5 的 `portalCredentialSession`）預先透過 `KRB5CCNAME` 注入，SSH 本身不再需要、也不允許再走其他認證路徑或互動 fallback。

### 15.1 known_hosts / route readiness

不做 apply-time `ssh-keyscan` 快照（這是舊 Gateway → target 設計，已被 `c084b71` 判定有 staleness gap 且是 blind TOFU，因此淘汰）。改為：

- Directory host 的 SSSD（經由 `freeipa-client` 既有 role）在連線當下即時解析 Gateway FQDN 的 `ipaSshPubKey`，透過 `sss_ssh_knownhostsproxy` relay，`GlobalKnownHostsFile` 則指向 SSSD 自己持續更新的 `/var/lib/sss/pubconf/known_hosts`。
- 新加入 `pilot-gateway-<scope>` 的 Gateway 主機，只要本身已 FreeIPA-enrolled（有 `ipaSshPubKey`），**不需要等下一次 Directory apply** 就能被正確解析與驗證——這消除了舊設計裡「新 Gateway 要等 Directory 重新 keyscan 才進 known_hosts」的視窗。
- runtime 禁止 `StrictHostKeyChecking=no`；禁止自動 accept unknown key。SSSD 解析失敗（host 未 enroll / 沒有 `ipaSshPubKey`）時，SSH 連線本身會因無法驗證 host key 而失敗，等同拒絕連到未受信任主機。

Directory resolver 判斷 `route_status=ready` 的條件簡化為：

```text
target ∈ pilot-target-<scope>
AND
gateway candidate ∈ pilot-gateway-<scope> live membership
AND
gateway candidate 通過 bounded TCP/22 reachability probe（§19）
```

不再需要「Gateway membership INTERSECT known_hosts-known gateways」這個額外交集，因為 known_hosts 不再是 Directory apply-time 才建立的靜態集合。

---

## 16. Handoff execution

Directory TUI 選 target：

```text
POST /v1/connect/resolve
```

取得 fresh：

```text
target
scope
gateway candidates
session_id
```

選出 candidate 後：

```text
/usr/bin/ssh
-F /etc/pilot/directory_ssh_config
<gateway-fqdn>
--
pilot-connect <session-id> <target-fqdn>
```

**argv 必須固定建構**。

禁止：

```text
user@host
IP literal
-p
-o
-J
-W
-L
-R
-D
ProxyCommand
caller-supplied remote command
```

---

## 17. Gateway handoff parser

現有：

```text
/usr/local/libexec/pilot-session
```

需要改為：

```text
empty original command
    -> pilot portal

exact pilot-connect command
    -> controlled one-shot Gateway connect

anything else
    -> deny
```

### 17.1 Grammar

概念 grammar：

```text
pilot-connect SP UUID SP FQDN
```

UUID：

```text
canonical UUID
```

FQDN：

```text
ASCII DNS hostname only
lowercase canonicalization
no @
no :
no /
no whitespace
no leading "-"
no shell metacharacter
no trailing "."
```

IP literal一律拒絕。

### 17.2 不把 session ID 當 proof

Gateway：

```text
parse session ID
validate syntax
log correlation
```

但 authorization 完全不讀：

```text
session_id claims
Directory scope
Directory allow result
```

---

## 18. Gateway one-shot connect mode

新增一個不暴露 shell 的 internal CLI surface，例如：

```text
pilot portal --connect <fqdn> --session-id <uuid>
```

或：

```text
pilot gateway-session connect ...
```

名稱可依現有 Cobra layout 選擇，但必須：

1. 連 `/run/pilot/access-gateway.sock`
2. identity 仍由 local Unix socket `SO_PEERCRED` 決定
3. POST `/v1/connect/authorize`
4. `Allowed=false` → deny
5. `Allowed=true` → controlled SSH target
6. target session exit → process exit
7. Directory 的 nested SSH return
8. Directory TUI 恢復

不得跳過 Gateway API 直接信任 handoff target。

---

## 19. Gateway candidate selection

Directory 使用以下順序：

1. scope `pilot-gateway-<scope>` live members
2. FQDN canonicalize / dedupe / sort
3. 必須為 FreeIPA-enrolled host（`sss_ssh_knownhostsproxy` 可即時解析其 `ipaSshPubKey`，見 §15.1）；不依賴 apply-time 快照
4. bounded TCP/22 reachability probe
5. 使用 `session_id` 做 deterministic rotation，避免永遠壓第一台
6. 嘗試 SSH
7. connect transport failure → 下一 candidate
8. Gateway 明確 authorization deny → **不得**換另一台 same-scope Gateway 試圖繞過；直接視為 access denied

原因：

```text
same scope gateways 應有相同 authorization semantics
```

若一台 deny、一台 allow，這是 drift / bug，不應被 client-side retry 隱藏。

---

## 20. Race / TOCTOU 行為

### Case A — List 後 HBAC 被撤銷

```text
Directory My Hosts 顯示 host
↓
HBAC revoke
↓
使用者按 Connect
```

Directory `/v1/connect/resolve` fresh read → deny。

即使 Directory 還錯誤 allow，Gateway `/v1/connect/authorize` fresh read → deny。

### Case B — scope membership 被移除

Gateway fresh `target_hostgroup` → target 不在 scope → deny。

### Case C — Directory 選到 stale Gateway instance

transport fail → retry其他 same-scope instance。

### Case D — Gateway scope 配置錯誤

Gateway 只相信自己 local `gateway.scope` / `target_hostgroup`；Directory supplied scope 不存在於 protocol，因此不能 override。

---

## 21. Session correlation

### 21.1 Session ID

每次 Directory connect attempt fresh 產生：

```text
session_id UUID
```

同一 ID 出現在：

```text
Directory route audit
Directory SSH handoff
Gateway authorization audit
Gateway target-connect audit
Gateway terminal recording
Session Store
```

### 21.2 Metadata schema

```go
type SessionAuditEvent struct {
    SchemaVersion int       `json:"schema_version"`
    EventID       string    `json:"event_id"`
    SessionID     string    `json:"session_id"`
    Seq           uint64    `json:"seq"`
    Timestamp     time.Time `json:"timestamp"`

    Kind string `json:"kind"`

    User string `json:"user"`
    UID  int    `json:"uid,omitempty"`

    DirectoryID   string `json:"directory_id,omitempty"`
    GatewayID     string `json:"gateway_id,omitempty"`
    GatewayScope  string `json:"gateway_scope,omitempty"`
    GatewayFQDN   string `json:"gateway_fqdn,omitempty"`
    TargetFQDN    string `json:"target_fqdn,omitempty"`

    Result   string `json:"result,omitempty"`
    ExitCode *int   `json:"exit_code,omitempty"`

    RecordingMode string `json:"recording_mode,omitempty"`
}
```

最低 event kinds：

```text
directory_connect_requested
directory_route_resolved
directory_gateway_attempt
directory_gateway_connected
gateway_authorize_allowed
gateway_authorize_denied
target_connect_started
target_connect_failed
session_started
session_ended
recording_started
recording_gap
recording_failed
```

---

## 22. Metadata audit sink

metadata event 優先整合既有：

```text
audit-log-forwarding
log-server
```

使用 syslog：

```text
facility=local6
severity=info/warn
message=single-line JSON
```

不得把 raw terminal recording 塞進一般 syslog。

理由：

- metadata 小且結構化。
- 現有 `audit-log-forwarding` 已將 `local6.*` 送中央 log server。
- terminal I/O 容量/敏感度不同，需要專用 store。

---

## 23. Terminal recording modes

### 23.1 `metadata`

只記 §21 metadata。

### 23.2 `terminal_output`

記：

```text
PTY output bytes
resize events
timing
```

不記 user input。

### 23.3 `terminal_io`

記：

```text
PTY input bytes
PTY output bytes
resize events
timing
```

UI 在 connect confirmation 必須顯示：

```text
Session recording: input + output
```

不得隱藏錄製狀態。

---

## 24. 避免記錄 target SSH authentication secret

若直接從 session 一開始把 Gateway child SSH 放進 recorder PTY：

```text
Password:
```

輸入也會被 recorder 捕捉。

禁止這種實作。

註：Gateway → target 的 `pilotSSHConfig` 現在是 `GSSAPIAuthentication yes` + `BatchMode yes` + Pubkey/KbdInteractive/Password 全關（見 §1），所以正常路徑下不會再出現互動式 `Password:` 提示——認證失敗會直接讓 SSH fail closed，而不是掉進提示輸入。但本節的兩階段設計仍然必要：GSSAPI handshake 之外，PAM `session` 訊息、MOTD、login banner 等仍可能在 shell 就緒前輸出到 PTY，這些不是使用者輸入但仍是「認證/登入雜訊」，不應該混進 recorded channel 的起點；且若未來 target 的 SSH policy 改回允許互動式 fallback，兩階段設計已經是預設防線，不需要再另外補。

### 24.1 兩階段 SSH

先建立 authenticated ControlMaster：

```text
Phase A: authentication
Gateway user terminal
    |
    +-- ssh -M -S <private-control-socket> -o RequestTTY=no -fN target
```

此時 recorder 尚未開始。

現有 `/etc/pilot/ssh_config` 有 `RequestTTY force`，所以 pre-auth path **必須**使用：

- 一份 root-owned pre-auth SSH config，或
- 程式內固定、不可由使用者修改的 `-o RequestTTY=no`

覆蓋它。

這個固定 option 是 implementation-owned constant，不是 caller-supplied SSH option；仍然禁止把任意 `-o` 暴露給使用者。

成功後：

```text
Phase B: recorded interactive channel
Gateway recorder
    |
    +-- ssh -S <private-control-socket> -tt target
```

session 結束：

```text
ssh -S <control-socket> -O exit target
```

因此：

- target initial SSH password / KbdInteractive 不進 recording。
- Kerberos authentication 也在 recording 前完成。
- recorded channel 沿用同一 authenticated SSH connection。

Control socket：

- random pathname
- user-private directory
- mode 0700
- session end 必須 cleanup
- 不得放進可被其他 portal users traverse 的 shared writable dir

---

## 25. PTY recorder

新增：

```text
internal/sessionrecording/
    recorder.go
    event.go
    sink.go
    redaction.go
    recorder_test.go
```

使用 repo 已有：

```text
github.com/creack/pty
golang.org/x/term
```

### 25.1 Required behavior

Recorder：

1. 啟動 SSH child PTY。
2. outer terminal 進 raw mode。
3. relay outer stdin → child PTY。
4. relay child PTY → outer stdout。
5. 按 recording mode 複製 bytes 到 sink。
6. SIGWINCH 時同步 child PTY window size。
7. process exit / signal 時 restore terminal state。
8. sink failure 不得讓 terminal 留在 broken raw mode。

### 25.2 PTY stream semantics

PTY 模式下 stdout/stderr 會合併。

recording stream type 使用：

```text
tty_input
tty_output
resize
```

不要假裝能區分 stdout / stderr。

### 25.3 Event

```go
type TerminalEvent struct {
    SchemaVersion int    `json:"schema_version"`
    SessionID     string `json:"session_id"`
    Seq           uint64 `json:"seq"`
    OffsetNanos   int64  `json:"offset_nanos"`
    Stream        string `json:"stream"` // tty_input | tty_output | resize

    DataBase64 string `json:"data_base64,omitempty"`
    Rows       int    `json:"rows,omitempty"`
    Cols       int    `json:"cols,omitempty"`

    RedactedBytes int `json:"redacted_bytes,omitempty"`
}
```

`Seq` 必須 strictly monotonic。

---

## 26. Echo-off redaction

> **2026-09-18 Phase 7 實作後修正**：本節原本假設「child PTY 的 ECHO 狀態會
> 在 remote password prompt 期間專門切換」。對真實 target 活體驗證後發現這
> 個假設對 Gateway 實際的 child（`ssh -tt <target>`）不成立——OpenSSH client
> 會把自己的 local pty 在**整個 session 期間**都設成 raw（ECHO/ICANON 皆關），
> 從 session 建立到結束都不會因為 remote 端目前是不是在顯示 password prompt
> 而改變（20ms 取樣、對 alice 真實觸發 sudo password prompt 驗證：ECHO 在
> session 一開始就變 false，一路到 session 結束才變回 true，password prompt
> 前後完全沒有額外切換）。SSH wire protocol 本身在 session 建立後也沒有任何
> 「remote 剛關閉 echo」的訊號可供 client 端偵測（keyboard-interactive 認證
> 階段的 per-prompt echo 旗標不算——那是 Phase A 認證期間的事，不在這裡的
> recorded session 範圍內）。實務結果：目前實作下 `terminal_io` 幾乎每個
> input chunk 都會被判定成「echo off」而整段記成 `redacted_bytes`——安全（不
> 會漏記密碼），但沒有辦法真的重建使用者輸入的指令文字，這是這個 child-pty
> termios 檢查在此架構下的已知、已驗證限制，需要日後另外做 output-side
> prompt-text 啟發式偵測才能真正達到本節原本設想的行為。見
> `internal/sessionrecording/redaction.go` 的 `isEchoOff` doc comment 與
> Phase 7 evidence doc。

`terminal_io` 下實作 best-effort：

當 child PTY terminal mode：

```text
ECHO disabled
```

時，不保存 input content，改記：

```json
{
  "stream": "tty_input",
  "redacted_bytes": 12
}
```

用途：

- 一般 password prompt
- sudo password
- passphrase prompt

但文件必須明寫：

```text
這不是完整 DLP / secret redaction。
```

例如：

```bash
export TOKEN=plaintext-secret
```

通常 echo 開啟，仍會被錄到。

---

## 27. Recorder backpressure

禁止 unbounded memory buffer。

配置：

```yaml
pilot_session_recording_queue_events: 1024
pilot_session_recording_flush_interval: 500ms
pilot_session_recording_failure_policy: best_effort
```

failure policy：

```text
best_effort
fail_closed
```

### best_effort

sink timeout / queue full：

- session 繼續
- drop recording event
- 增加 dropped counter
- emit `recording_gap`
- metadata 必須留下 recording incomplete

### fail_closed

sink 無法持續：

- 不允許開始 recorded session，或
- active session 在 grace period 後終止
- metadata 明確 `recording_failed`

不得 silent loss 後仍標記：

```text
recording_complete=true
```

---

## 28. `pilot-session-store`（terminal recording persistence）

terminal recording persistence 作為獨立 optional component：

```text
pilot-session-store
```

Gateway 不直接寫 `/var/lib/...` durable state。

### 28.1 Ingest API

HTTPS：

```text
POST /v1/sessions/start
POST /v1/sessions/{session_id}/events
POST /v1/sessions/{session_id}/finish
```

Events 可 NDJSON batch。

必須支援 retry idempotency：

```text
UNIQUE(session_id, seq)
```

重送同 sequence：

- identical payload → no-op success
- different payload → conflict / audit error

### 28.2 Auth

最低 v1：

- TLS mandatory。
- trust `/etc/ipa/ca.crt`。
- dedicated ingest bearer token from vault。
- ingest credential只有 write/append 權限，不能 read/replay recordings。

不得把 token 放 CLI argument。

### 28.3 Storage

建議：

```text
/var/lib/pilot-session-store/index.db
/var/lib/pilot-session-store/recordings/<yyyy>/<mm>/<dd>/<session-id>.ndjson.enc
```

`index.db` 可用 repo 已存在的 `modernc.org/sqlite`。

index：

```text
session_id
user
directory_id
gateway_id
scope
target
started_at
ended_at
recording_mode
complete
bytes
event_count
key_id
```

### 28.4 Encryption at rest

recording payload 必須 encrypted at rest。

最低：

```text
AES-256-GCM
```

每 event / chunk 使用 unique nonce。

AAD 至少含：

```text
session_id
seq
stream
```

master key：

- vault 提供
- file mode 0600
- 不寫 log
- config 只 reference key file / key ID

### 28.5 Retention

不能硬編碼公司 policy。

Store deployment 必須要求：

```yaml
pilot_session_store_retention_days: <explicit>
```

cleanup：

- systemd timer 或內部 deterministic retention job
- 先更新 index
- 再刪 payload
- retention delete 產生 audit record

---

## 29. Session Store read/replay

admin read path 不與 ingest token共用。

建議 Unix socket：

```text
/run/pilot/session-store.sock
```

group：

```text
role-pilot-session-auditor
```

新增：

```text
pilot session list
pilot session show <session-id>
pilot session replay <session-id>
```

`replay`：

- decrypt
- verify sequence continuity
- respect `offset_nanos`
- output only
- 不重新執行任何 input

若 recording 有 gap：

```text
RECORDING INCOMPLETE
```

必須醒目顯示。

---

## 30. Command audit 與 terminal recording 的責任差異

### Terminal recorder 回答

```text
使用者看到什麼
使用者鍵盤送了什麼 bytes
```

### Linux audit 回答

```text
kernel / process 實際 exec 了什麼
sudo 是否發生
effective credential 是否改變
```

這兩者不可互相替代。

若要「所有 command/process execution」，另做 opt-in：

```text
pilot_exec audit profile
```

不能直接改現有 `audit.rules.j2` 全域記錄所有 execve，因為：

- event volume 可能非常大
- 影響 storage / SIEM
- 需要獨立 benchmark / retention policy
- 目前 spec 沒有要求全主機所有 process 都記錄

---

## 31. Directory deployment playbook

新增：

```text
playbooks/apply/pilot-access-directory-apply.yml
```

建議順序：

1. stage / prod confirmation gates。
2. artifact exists + version probe。
3. verify host 已 FreeIPA-enrolled。
4. verify Directory FQDN forward DNS。
5. ensure `pilot-access-directories` hostgroup。
6. add self to `pilot-access-directories`。
7. ensure `role-pilot-portal-user` exists，但不管理 user membership。
8. ensure `pilot-access-directory-login` HBAC rule：
   - users/groups: `role-pilot-portal-user`
   - target hostgroup: `pilot-access-directories`
   - service: `sshd`
9. provision read-only Directory service principal + keytab。
10. confirm reader role capability，包含 Phase 0 證明過的 `hostgroup_find`。
11. install `pilot` binary。
12. install `pilot-access-directory` binary。
13. render `/etc/pilot/access-directory.yaml`。
14. render `/etc/pilot/directory_ssh_config`（§15；host key 驗證交給既有 `freeipa-client` role 裝好的 SSSD + `sss_ssh_knownhostsproxy`，不需要在這裡另外 resolve `pilot-gateway-*` membership 或 keyscan 寫 known_hosts）。
15. install systemd socket/service。
16. health probe。
17. install `/usr/local/libexec/pilot-directory-session`。
18. install sshd drop-in。
19. `sshd -t`。
20. reload sshd。
21. post-apply lockout/identity probe。

所有 FreeIPA mutation 要遵守 repo 既有：

```text
changed_when
failed_when
no_log
idempotency
```

模式。

---

## 32. Gateway apply 修改

修改：

```text
playbooks/apply/pilot-access-gateway-apply.yml
```

新增：

1. ensure `pilot-gateway-<gateway_scope>`。
2. self-add。
3. self-remove from other `pilot-gateway-*`。
4. install新版 `pilot-session` strict handoff parser。
5. install recording config。
6. 若 session-store enabled，寫入 sink config / CA / token file。
7. health probe增加 handoff capability status。

不得讓新增的 Directory handoff 改掉：

```text
直接 SSH Gateway -> 現有 Portal
```

的 UX。

---

## 33. Contract：`pilot-access-directory`

新增：

```text
contracts/pilot-access-directory.yaml
```

概念內容：

```yaml
schemaVersion: 1
id: pilot-access-directory
role: pilot-access-directory

specs:
  - path: docs/verification/pilot-access-directory.md
    rows: {all: true}

playbooks:
  apply: playbooks/apply/pilot-access-directory-apply.yml

dependencies:
  - {component: freeipa-client, required: true, relation: sameHosts}

conflicts: []
hostCardinality: exactly-one

resources:
  minCPU: 1
  minRAMMiB: 512
  minDiskGiB: 5

groupVars:
  - {name: directory_id, type: string, required: true, secret: false}
  - {name: directory_fqdn, type: string, required: false, secret: false}
  - {name: freeipa_servers, type: stringList, required: false, secret: false}
  - {name: ipa_realm, type: string, required: false, secret: false}
  - {name: ipa_admin_password, type: string, required: true, secret: true}
  - {name: pilot_binary_path, type: string, required: true, secret: false}
  - {name: pilot_access_directory_binary_path, type: string, required: true, secret: false}
  - {name: directory_portal_user_group, type: string, required: false, default: role-pilot-portal-user, secret: false}
  - {name: pilot_access_directory_install_forcecommand, type: boolean, required: false, default: true, secret: false}

endpoints:
  - name: directory-socket
    scheme: unix
    path: /run/pilot/access-directory.sock

stagePolicy:
  variable: stage
  default: sandbox

evidenceRequirement:
  targetTest: topology
  idempotency: required

verification:
  autoDeploy: false
```

`site.order` 必須：

```text
freeipa-client 之後
pilot-access-gateway 之後
```

Baseline Gateway order=52，因此可優先評估 53，但 coding agent 必須先讀當下 catalog，禁止假設 slot 未被占用。

---

## 34. Gateway contract 新增 inputs

`contracts/pilot-access-gateway.yaml` 至少新增：

```text
pilot_gateway_handoff_enabled
pilot_session_recording_mode
pilot_session_recording_failure_policy
pilot_session_store_url
pilot_session_store_ingest_token
```

建議 defaults：

```yaml
pilot_gateway_handoff_enabled: true
pilot_session_recording_mode: metadata
pilot_session_recording_failure_policy: best_effort
```

`pilot_session_store_*` 只有：

```text
terminal_output
terminal_io
```

才必須。

不要新增 contract schema 不存在的欄位；現有 loader `KnownFields(true)`。

---

## 35. `pilot-session-store` contract

如果同一 delivery 實作 terminal persistence：

```text
contracts/pilot-session-store.yaml
playbooks/apply/pilot-session-store-apply.yml
docs/verification/pilot-session-store.md
```

Store 是 stateful：

```text
/var/lib/pilot-session-store
```

contract lifecycle 必須符合目前 `internal/contract` schema 與 lint，不得宣告假 decommission policy。

若 coding agent 不在本 delivery 完成 store lifecycle/decommission/backup contract，則：

```text
terminal_output / terminal_io 不得宣稱 production-ready
```

可以先以 test sink 驗證 recorder protocol，但 production default 保持 `metadata`。

---

## 36. Artifact / delivery integration

新增 binary 後必須同步：

```text
scripts/build-pilot-access-directory.sh
images/Dockerfile.pilot-cli
```

若 session store同 delivery：

```text
scripts/build-pilot-session-store.sh
images/Dockerfile.pilot-cli
```

現有：

```text
cmd/pilot/cmd/dockerfile_artifact_consistency_test.go
```

必須通過。

另外同步：

```text
internal/inventory/contracts.go
cmd/pilot/cmd/deploy_catalog.go
playbooks/site.yml
cmd/pilot/cmd/site_yml_consistency_test.go
cmd/pilot/cmd/tag_coverage_test.go
cmd/pilot/cmd/edit_role_catalog_coverage_test.go
group_vars/*.example.yml
DELIVERY.md（若 delivery surface 有新增）
AGENTS.md changelog / component governance（依當下 repo 慣例）
```

不得只新增 playbook 而漏 contract/site/catalog。

---

## 37. Verification Spec：Directory

新增：

```text
docs/verification/pilot-access-directory.md
```

最低 rows：

| ID | 驗收條件 |
|---|---|
| AD01 | config `KnownFields(true)`，未知欄位 fail |
| AD02 | Directory API 僅 Unix socket，不 listen TCP |
| AD03 | user identity 來自 SO_PEERCRED，不信 `$USER/$LOGNAME` |
| AD04 | 非 portal group user 無法呼叫 user-facing API |
| AD05 | global My Hosts = 所有 scope effective SSH allow 的 union |
| AD06 | Directory 不讀 roster / inventory / hosts.yml |
| AD07 | scope 來自 `pilot-target-*` / `pilot-gateway-*`，不是 hostname 推導 |
| AD08 | no-gateway target 顯示 unavailable、Connect disabled |
| AD09 | 同 target 多 scope 被合併成 Routes |
| AD10 | `/v1/connect/resolve` 每次 fresh evaluate |
| AD11 | denied target 不可由手動 API target injection resolve |
| AD12 | gateway candidate 必須為 `pilot-gateway-<scope>` member |
| AD13 | gateway candidate host key 經 `sss_ssh_knownhostsproxy`/SSSD 驗證通過（未 enroll/無 `ipaSshPubKey` 的 host 連線失敗，不 fallback 成 accept-unknown） |
| AD14 | Gateway transport failure可 retry下一 same-scope instance |
| AD15 | Gateway explicit authorization deny不得 retry繞過 |
| AD16 | FreeIPA outage fail closed |
| AD17 | restart後不需 local persistent state |
| AD18 | `ssh access` 進 Directory TUI |
| AD19 | arbitrary remote command無法取得 Directory shell |
| AD20 | Directory selection可 handoff到正確 scope Gateway |
| AD21 | remote target `whoami` 為原登入 user |
| AD22 | target exit 後回 Directory TUI |
| AD23 | HBAC 在 list/connect 間被 revoke → connect deny |
| AD24 | target移出 scope後 connect deny |
| AD25 | session_id 每次 connect fresh unique |
| AD26 | same session_id 出現在 Directory + Gateway metadata |
| AD27 | staging/prod stage gates符合 repo policy |
| AD28 | second apply changed=0 |
| AD29 | site-wide deploy實際跑到 component，不是假 success |
| AD30 | fresh vm-target topology E2E PASS |

---

## 38. Gateway verification 增補

在：

```text
docs/verification/pilot-access-gateway.md
```

新增 rows，編號從現有最後一列之後延續；不要硬覆蓋既有 AG01-AG30。

最低驗證：

```text
gateway加入 pilot-gateway-<scope>
scope change會 scrub stale gateway group
direct Portal仍正常
empty SSH_ORIGINAL_COMMAND -> Portal
valid pilot-connect grammar -> one-shot connect
invalid command -> deny
shell metacharacter -> deny
user@host -> deny
IP target -> deny
-leading-option -> deny
newline -> deny
session_id 不影響 auth
handoff connect仍 fresh authorize
wrong-scope target deny
FreeIPA outage deny
target exit正常
```

既有：

```text
scripts/pilot-access-gateway-lockout-test.sh
```

必須擴充，而不是另做一份互相漂移的測試腳本。

---

## 39. Session recording verification

若實作 recorder，新增：

```text
docs/verification/pilot-session-recording.md
```

最低：

| ID | 驗收條件 |
|---|---|
| SR01 | metadata mode不保存 terminal bytes |
| SR02 | terminal_output只保存 output |
| SR03 | terminal_io保存 input/output |
| SR04 | target初始 SSH password prompt發生在 recorder啟動前 |
| SR05 | ECHO-off input只記 `redacted_bytes` |
| SR06 | terminal resize可在 replay重現 |
| SR07 | event seq strictly monotonic |
| SR08 | sink retry不 duplicate event |
| SR09 | best_effort loss會產生 recording_gap |
| SR10 | fail_closed sink failure阻止/中止 session |
| SR11 | process crash後 terminal state可恢復/outer SSH結束 |
| SR12 | Gateway不留下 durable local recording |
| SR13 | store payload at rest不是 plaintext |
| SR14 | ingest token不能 read recordings |
| SR15 | replay只輸出、不執行 input |
| SR16 | incomplete recording replay顯示醒目警告 |
| SR17 | terminal_io connect前 UI 明示 recording |
| SR18 | `export TOKEN=...` 類型不宣稱會自動 redaction |
| SR19 | metadata可由既有 local6 forwarding送到 log-server |
| SR20 | existing audit-log-forwarding 不被誤宣稱成 full exec audit |

---

## 40. Security regression matrix

至少測：

### Directory ingress

```text
ssh user@directory whoami
ssh -tt user@directory 'sh'
ssh -L ...
ssh -R ...
ssh -D ...
ssh -W ...
sftp user@directory
scp ...
RemoteCommand override
```

除 exact supported command 外均不得 escape captive flow。

### Directory → Gateway target injection

targets：

```text
host;id
host$(id)
host`id`
user@host
1.2.3.4
[::1]
-oProxyCommand=...
-Jfoo
--help
host name
host\nid
```

全部拒絕。

### Gateway scope

user 同時有：

```text
GPU HBAC
DMZ HBAC
```

Directory 可同時列兩邊。

但：

```text
GPU Gateway + DMZ target
```

永遠 deny。

### Identity spoof

改：

```text
USER
LOGNAME
HOME
KRB5CCNAME
```

不得讓 API identity 變成另一個使用者。

---

## 41. Failure matrix

| Failure | Expected behavior |
|---|---|
| Directory FreeIPA unreachable | `/v1/access`/resolve fail closed；health degraded |
| Directory reader keytab missing | 不 crash-loop；lazy retry / 503，修復後 self-heal |
| Directory socket service restart | 不失去 persistent state，因為沒有 state |
| target有 access但沒有 gateway | 顯示 unavailable；Connect disabled |
| 第一 Gateway TCP/22 down | retry下一 same-scope candidate |
| Gateway host key mismatch | fail；不得 StrictHostKeyChecking=no |
| Gateway FreeIPA down | Gateway fresh authorize deny / 503 |
| HBAC revoke after Directory resolve | Gateway deny |
| Target DNS失敗 | session失敗後回 Directory |
| Target host key失敗 | session失敗後回 Directory |
| Target SSH exit nonzero | 顯示 session ended/error，回 Directory |
| recording sink down + best_effort | session可繼續，但 recording標 incomplete |
| recording sink down + fail_closed | target session不得無記錄繼續 |
| Session Store full disk | ingest fail；依 failure policy；store health critical |
| replay payload corrupt | fail closed，不輸出未驗證內容 |

---

## 42. Observability

### 42.1 Structured logs

Directory：

```text
directory_access_resolve
directory_route_selected
directory_gateway_attempt
directory_gateway_failure
directory_gateway_connected
```

Gateway：

```text
gateway_handoff_parse_denied
gateway_handoff_authorize_allowed
gateway_handoff_authorize_denied
target_session_started
target_session_ended
recording_gap
recording_failed
```

所有 event：

```text
session_id
user
target
scope
gateway
```

能填多少就填多少，不得 log password/token。

### 42.2 Metrics（若本 delivery已有 metrics plumbing）

建議：

```text
pilot_access_directory_resolve_total{result}
pilot_access_directory_handoff_total{result}
pilot_access_directory_gateway_candidates
pilot_access_directory_freeipa_errors_total

pilot_access_gateway_handoff_total{result}
pilot_access_gateway_recording_bytes_total{stream}
pilot_access_gateway_recording_dropped_events_total
pilot_access_gateway_recording_sink_errors_total

pilot_session_store_ingest_events_total
pilot_session_store_ingest_bytes_total
pilot_session_store_active_sessions
pilot_session_store_storage_bytes
```

若 repo 目前沒有對這兩個 daemon 的 Prometheus endpoint pattern，不要為了本 feature 臨時發明另一套 metrics server；structured logs 先成為 mandatory。

---

## 43. Performance / bounds

Directory 必須有 sanity limits：

```text
max discovered scopes
max target hostgroups
max gateway hostgroups
max total targets
max gateways per scope
max HBAC rules
max sudo rules
max API response bytes
```

超過 limit：

```text
fail closed
health degraded
structured error
```

不得 truncate 後假裝完整。

Gateway recorder：

```text
bounded queue
bounded batch size
bounded HTTP timeout
bounded reconnect retry
```

不得因 session store慢造成 unbounded RAM。

---

## 44. Implementation phases

### Phase 0 — FreeIPA discovery spike

完成：

- live `hostgroup_find`
- real fixture
- reader permission proof
- narrow `HostgroupFinder`

Landing gate：

- 真實 FreeIPA service principal 可讀 `pilot-target-*`
- 真實 FreeIPA service principal 可讀 `pilot-gateway-*`
- 無 write privilege

---

### Phase 1 — Shared policy snapshot refactor

完成：

- `PolicySnapshot`
- `LoadPolicySnapshot`
- `ResolveScopeAccess`
- 現有 Gateway `LoadUserAccess` 改走 shared path

Landing gate：

- 現有 `internal/accessportal` regression tests全綠
- Phase 8既有 same-scope / different-scope semantics 不變
- query count沒有 scope×rule-list放大

---

### Phase 2 — Gateway scope-instance publication

完成：

- `pilot-gateway-<scope>`
- Gateway apply self-add
- stale gateway-scope membership scrub
- tests / verification

Landing gate：

- 兩台 same-scope Gateway 正確出現在同一 hostgroup
- 改 scope 後舊 membership消失
- second apply changed=0

---

### Phase 3 — Directory backend

完成：

- `internal/accessdirectory`
- `internal/directoryapi`
- `cmd/pilot-access-directory`
- Unix socket
- SO_PEERCRED
- FreeIPA-backed global access list

Landing gate：

- fake provider unit tests
- real FreeIPA user access cross-scope result
- outage fail closed
- stateless restart

---

### Phase 4 — Directory TUI / deploy integration

完成：

- `pilot directory`
- My Hosts / detail / Identity / Refresh / Logout
- Directory apply playbook
- ForceCommand
- contract
- site/catalog/Dockerfile integration

Landing gate：

- 真人 SSH Directory TUI
- arbitrary remote command無 shell
- idempotent apply
- site-wide deployment實際執行 component

---

### Phase 5 — Directory → Gateway → Target handoff

完成：

- strict handoff protocol
- Gateway ForceCommand parser
- one-shot Gateway connect
- gateway candidate failover
- Directory return-after-target-exit

Landing gate：

真實 topology：

```text
user
  -> Directory
  -> GPU Gateway
  -> GPU Target
```

以及：

```text
user
  -> Directory
  -> DMZ Gateway
  -> DMZ Target
```

wrong-scope injection deny。

---

### Phase 6 — Session ID + metadata audit

完成：

- UUID session ID
- Directory / Gateway shared correlation
- local6 metadata
- log-server cross-check

Landing gate：

用一個 session ID 從中央 log 可重建：

```text
route selected
gateway allowed
target started
target ended
```

---

### Phase 7 — PTY recorder

完成：

- ControlMaster pre-auth
- PTY multiplexer
- input/output modes
- resize
- raw mode restore
- echo-off redaction
- bounded sink
- failure policy

Landing gate：

- 不記初始 target authentication secret
- output replay一致
- terminal_io input/output順序一致
- sink outage behavior符合 policy

---

### Phase 8 — Session Store / production recording

完成：

- encrypted persistence
- idempotent ingest
- retention
- auditor Unix API
- list/show/replay
- backup/decommission contract
- real failure injection

Landing gate：

- fresh topology end-to-end
- disk full
- store restart
- duplicate event retry
- corrupt payload
- retention
- second apply changed=0

若 Phase 8 未完成：

```text
metadata mode 可以 production-ready
terminal recording 不得標記 production-ready
```

---

## 45. vm-target topology

至少：

```text
ipa1
directory-01

gw-gpu-01
gw-gpu-02
gw-dmz-01

gpu-target-01
gpu-target-02
dmz-target-01

session-store-01   # Phase 8
```

Users：

```text
alice
bob
```

Policies：

```text
alice:
  GPU + DMZ SSH
  GPU limited sudo
  DMZ no sudo

bob:
  GPU only
```

Scope：

```text
pilot-target-gpu
  gpu-target-01
  gpu-target-02

pilot-target-dmz
  dmz-target-01

pilot-gateway-gpu
  gw-gpu-01
  gw-gpu-02

pilot-gateway-dmz
  gw-dmz-01
```

必須包含：

```text
same scope / multiple gateways
different scopes
user with both scopes
user with only one scope
gateway down
FreeIPA down
HBAC revoke between list/connect
```

---

## 46. Evidence policy

依 repo `AGENTS.md`：

- `docs/verification/*.md` 裡的可執行 command，在寫成「已驗證 SOP」前必須實跑。
- 每個 Phase 保留：
  - tested revision
  - target topology
  - actual output
  - PASS/FAIL
  - idempotency
- evidence 放：
  - `.verification/`
  - `docs/evidence/pilot-access-directory/...`
  - `docs/evidence/pilot-session-recording/...`

不得把「預期成功」寫成「已驗證」。

---

## 47. Migration

### Stage 1

現有 Gateway 完全不動 UX：

```text
ssh user@pilot-gw-gpu-01
-> existing Pilot Portal
```

新增 `pilot-gateway-<scope>` publication。

### Stage 2

部署 Directory：

```text
ssh user@access.<domain>
-> global Directory
```

仍允許直接 Gateway。

### Stage 3

驗證 Directory handoff穩定後，可選擇 network policy：

```text
User -> Directory only
Directory -> Gateway
Gateway -> target
```

### Stage 4

按公司 policy 決定：

```text
metadata
terminal_output
terminal_io
```

不得因導入 Directory 就自動啟用 raw recording。

---

## 48. Definition of Done

Core Directory delivery完成需同時滿足：

- [ ] `pilot-access-directory` binary。
- [ ] Directory Unix API。
- [ ] SO_PEERCRED identity。
- [ ] live FreeIPA hostgroup discovery。
- [ ] `pilot-gateway-<scope>` publication。
- [ ] shared policy snapshot，無 duplicate authorization engine。
- [ ] global My Hosts。
- [ ] one canonical Directory TUI ingress。
- [ ] fresh `/v1/connect/resolve`。
- [ ] same-user Directory → Gateway SSH。
- [ ] strict `pilot-connect` handoff grammar。
- [ ] Gateway fresh authorize。
- [ ] wrong scope deny。
- [ ] target exit回 Directory。
- [ ] session ID end-to-end metadata correlation。
- [ ] FreeIPA outage fail closed。
- [ ] Gateway outage same-scope failover。
- [ ] strict host key verification。
- [ ] arbitrary command / forwarding / SFTP / SCP escape regression。
- [ ] contract / catalog / site / Dockerfile integration。
- [ ] topology actual-run evidence。
- [ ] second apply `changed=0`。

Terminal recording production-ready需另外：

- [ ] target auth不被 recorder捕捉。
- [ ] PTY raw/resize/cleanup正確。
- [ ] bounded backpressure。
- [ ] explicit recording banner。
- [ ] echo-off best-effort redaction。
- [ ] encrypted central store。
- [ ] ingest auth。
- [ ] retry idempotency。
- [ ] retention。
- [ ] auditor-only read/replay。
- [ ] incomplete recording detection。
- [ ] store outage policy。
- [ ] backup/decommission lifecycle。
- [ ] Phase 8 actual-run evidence。

---

## 49. Coding Agent 禁止事項

不得：

1. 為了省事讓 Directory直接 SSH target。
2. 把 Directory access list當 Gateway authorization token。
3. 從 hostname parse scope。
4. 把 `SSH_ORIGINAL_COMMAND`送 shell。
5. 允許 user-supplied SSH options。
6. 開 agent forwarding。
7. 關 StrictHostKeyChecking。
8. 在 Gateway local disk建立 durable recording database。
9. 預設啟用 `terminal_io`。
10. 宣稱 echo-off redaction能擋所有 secrets。
11. 宣稱現有 audit-log-forwarding記錄所有 commands。
12. 複製 `accessportal` authorization logic到 `accessdirectory`。
13. 擴大 FreeIPA reader成 admin。
14. 為新 contract發明 `internal/contract.Contract` 不存在的欄位。
15. 跳過 `site_yml_consistency_test` / tag coverage / artifact consistency。
16. 在沒有真實 FreeIPA fixture 前猜 `hostgroup_find` response。
17. 把 vm-target 未跑過的 output 寫成已驗證 evidence。

---

## 50. 主要修改檔案清單

### New — Core

```text
internal/accessdirectory/model.go
internal/accessdirectory/catalog.go
internal/accessdirectory/resolver.go
internal/accessdirectory/resolver_test.go

internal/directoryapi/server.go
internal/directoryapi/types.go
internal/directoryapi/handlers.go
internal/directoryapi/server_test.go

cmd/pilot-access-directory/main.go
cmd/pilot-access-directory/config.go
cmd/pilot-access-directory/config_test.go

cmd/pilot/cmd/directory.go
cmd/pilot/cmd/directory_client.go
cmd/pilot/cmd/directory_tui.go
cmd/pilot/cmd/directory_ssh.go
cmd/pilot/cmd/directory_*_test.go

scripts/build-pilot-access-directory.sh
scripts/pilot-access-directory-lockout-test.sh

playbooks/apply/pilot-access-directory-apply.yml
group_vars/pilot-access-directory.example.yml
contracts/pilot-access-directory.yaml

docs/verification/pilot-access-directory.md
```

### Modify — Existing Gateway

```text
internal/freeipaaccess/*
internal/accessportal/*
cmd/pilot/cmd/portal_ssh.go
cmd/pilot/cmd/portal_ssh_test.go
cmd/pilot/cmd/portal_tui.go
cmd/pilot/cmd/portal_client.go
cmd/pilot/cmd/portal_kerberos.go        # 通用化 cache 目錄前綴（見 D5），供 directory_ssh.go 重用
cmd/pilot/cmd/portal_kerberos_test.go

playbooks/apply/pilot-access-gateway-apply.yml
group_vars/pilot-access-gateway.example.yml
contracts/pilot-access-gateway.yaml
docs/verification/pilot-access-gateway.md
scripts/pilot-access-gateway-lockout-test.sh
```

### New — Recording

```text
internal/sessionrecording/event.go
internal/sessionrecording/recorder.go
internal/sessionrecording/redaction.go
internal/sessionrecording/sink.go
internal/sessionrecording/*_test.go

docs/verification/pilot-session-recording.md
```

### Optional — Session Store

```text
internal/sessionstore/*
cmd/pilot-session-store/*
playbooks/apply/pilot-session-store-apply.yml
group_vars/pilot-session-store.example.yml
contracts/pilot-session-store.yaml
docs/verification/pilot-session-store.md
```

### Repo-wide integration

```text
images/Dockerfile.pilot-cli
playbooks/site.yml
internal/inventory/contracts.go
cmd/pilot/cmd/deploy_catalog.go
cmd/pilot/cmd/tag_coverage_test.go
cmd/pilot/cmd/site_yml_consistency_test.go
cmd/pilot/cmd/edit_role_catalog_coverage_test.go
cmd/pilot/cmd/dockerfile_artifact_consistency_test.go
DELIVERY.md
```

---

## 51. Source references used for this design

Baseline source-of-truth paths：

```text
docs/superpowers/specs/2026-09-14-pilot-access-gateway-stateless-freeipa-portal-spec.md
docs/verification/pilot-access-gateway.md
contracts/pilot-access-gateway.yaml
playbooks/apply/pilot-access-gateway-apply.yml

internal/freeipaaccess/provider.go
internal/accessportal/model.go
internal/accessportal/resolver.go
internal/gatewayapi/server.go

cmd/pilot/cmd/portal_tui.go
cmd/pilot/cmd/portal_ssh.go
cmd/pilot/cmd/portal_kerberos.go

scripts/pilot-access-gateway-lockout-test.sh

docs/runbooks/audit-log-forwarding.md
docs/verification/audit-log-forwarding.md
playbooks/templates/audit.rules.j2
docs/runbooks/log-server.md

internal/contract/contract.go
AGENTS.md
go.mod
```

Baseline-drift evidence（2026-09-18 修正時核對用，非本 feature 產出）：

```text
docs/evidence/pilot-access-gateway/2026-09-16-portal-usability-and-ssh-config-fixes.md   # ProxyCommand/known_hosts 改版
docs/evidence/pilot-access-gateway/2026-09-16-portal-automember.md                       # portal group automember 預設
```

本規格是對既有 Access Gateway 的 additive extension，不 supersede 現有 Gateway spec；若實作完成後需正式歸檔，建議放：

```text
docs/superpowers/specs/2026-09-16-pilot-access-directory-session-routing-recording-spec.md
```

