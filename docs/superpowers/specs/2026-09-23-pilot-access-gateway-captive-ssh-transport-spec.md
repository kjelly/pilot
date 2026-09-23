# Pilot Access Gateway — Captive SSH Transport Broker 實作規格

- **狀態**：READY FOR IMPLEMENTATION（rev 2）
- **日期**：2026-09-23
- **Repository**：`kjelly/pilot`
- **Baseline**：`main@c0890f66479c2aed189fd216ddeec87f72bb7306`（rev 1 的 `99a3a86` 之後只有 lint 修正，§3 事實已對 `c0890f6` 重新核對）
- **Audience**：Coding Agent（主要執行者）/ Pilot maintainers（review）
- **延伸既有規格**：`docs/superpowers/specs/2026-09-14-pilot-access-gateway-stateless-freeipa-portal-spec.md`
- **現有驗收基線**：`docs/verification/pilot-access-gateway.md` 已到 `AG40`
- **本規格新增驗收編號**：Gateway `AG41`–`AG73`；新 component `TP01`–`TP12`
- **核心目標**：在**不讓一般使用者取得 Access Gateway shell** 的前提下，讓 OpenSSH-compatible client 經 Gateway 對授權 target 建立**不解讀內容（opaque）的 SSH transport**，一次支援 SSH、SFTP、SCP、rsync，以及 VS Code Remote-SSH 需要的 OpenSSH 能力。
- **本文件範圍**：只列 coding agent 能獨立完成的工作（程式、playbook、測試、disposable vm-target 實跑、evidence、文件）。需要人或站台基礎設施的事項見 §2.3，**不是工作項**。

---

## 0. 使用方式

1. 依 §16 的 Phase 順序實作；每個 Phase 都有 landing gate，沒過不得進下一個 Phase。
2. 每個 Phase 依 AGENTS.md §1.5 產生**本地 candidate commit**，從乾淨 checkout 實跑，再用 evidence-only commit 提交 sanitized 摘要。
3. 解析外部 CLI / API 輸出（`sshd -T`、`ipa`、FreeIPA JSON-RPC `host_show`）的 fixture 與 expected string，**一律來自 Phase 0 的真實擷取**（AGENTS.md §5.6）。本文件中標 `〔實測定稿〕` 的字串是預期形狀，實作時以擷取結果為準；若擷取結果與本文件的**語意**不符，停止並回報，不得自行改語意。
4. §16 列出的「停止並回報」條件發生時，停止實作並向使用者回報（附實測輸出與建議做法），不得自行繞過。

---

## 1. 決策摘要

| # | 決策 | 理由 |
|---|------|------|
| D1 | Gateway 以 ForceCommand captive broker 提供 opaque byte transport；不終止 inner SSH、不啟動 `/usr/bin/ssh`、不實作 SFTP | SSH/SFTP/SCP/rsync/Remote-SSH 共用同一條 data plane；Gateway 不持有 target credential |
| D2 | 新增兩個 captive 指令：`pilot-transport-v1 <fqdn>`、`pilot-known-hosts-v1 <fqdn>`；其他一律拒絕 | 最小攻擊面；host key 必須有 FreeIPA 權威來源（D6） |
| D3 | Transport 永遠只連 TCP/22，port 是 protocol 常數 | 不得演變成 generic CONNECT proxy |
| D4 | Transport 授權重用 `/v1/connect/authorize` 的同一套 HBAC ∩ scope 判斷，由 **Gateway daemon 在 server 端**計算 `transport_allowed` | 不建第二套 ACL；policy 設定只存在 daemon 讀得到的 config |
| D5 | `transport_allowed` = 授權通過 ∧ `gateway.transport.enabled` ∧ target 屬於 FreeIPA hostgroup `pilot-transport-ready` | 只有已成功套用 target policy 的主機才可被 transport 到達，避免 inventory 與 FreeIPA scope 漂移造成「有 transport、沒限制」的主機 |
| D6 | Host key 由 Gateway 從 FreeIPA `ipaSshPubKey` 提供（`pilot-known-hosts-v1`，搭配 OpenSSH `KnownHostsCommand`）；建議設定不使用 TOFU | 延續基礎 spec「Production 不做 runtime TOFU」；workstation 不需要是 FreeIPA client |
| D7 | Target policy 以 `Match Address <Gateway 位址>` 套用，**不**以 `Match Group` 套用 | opaque 模式無法強制 inner username（§5.2）；以 group 限制時，用不在 group 的帳號登入即可繞過 |
| D8 | Transport 只在 recording mode 為 `""`/`metadata` 時允許（allowlist）；其他值一律拒絕 | 不得把加密的 inner SSH 冒充 terminal recording；未知的新 mode 也 fail closed |
| D9 | 先修 Gateway playbook 會覆寫 recording 設定的既有缺陷（Phase 1），再做 transport | 否則為了開 transport 重新 apply，會把 recording 靜默降回 metadata，D8 在部署層失效 |
| D10 | Transport 預設關閉（`pilot_access_gateway_transport_enabled: false`）；關閉即可停止新 transport，不影響 Portal / `pilot-connect` | 新 data plane 必須 opt-in；rollback 只需一個旗標 |
| D11 | 網路隔離（workstation↛target:22、target↛workstation）是 operator 前提，不是本功能的保證；E2E 以 test fixture 模擬隔離，證明流量確實經過 Gateway | Pilot 不管理站台防火牆（使用者決策，2026-09-23） |
| D12 | VS Code Remote-SSH 只驗 OpenSSH 層可機器驗證的能力，不含 GUI smoke | GUI 無法由 coding agent 執行（使用者決策，2026-09-23） |
| D13 | Staging/production 啟用時機與流程不在本規格；本規格只保證 default off 與一個旗標即可 rollback | 營運決策（使用者決策，2026-09-23） |

---

## 2. Scope

### 2.1 Goals

使用者 workstation 只需能連到 Access Gateway，即可：

```bash
ssh gpu01.example.internal
sftp gpu01.example.internal
scp ./file gpu01.example.internal:/tmp/
rsync -av ./src/ gpu01.example.internal:/workspace/
```

並讓使用 system OpenSSH 的工具（含 VS Code Remote-SSH）使用同一份 `ssh_config`。

### 2.2 Non-goals

- Gateway SFTP virtual filesystem、`/hosts/<fqdn>/...` path namespace。
- SOCKS4/5、HTTP CONNECT、arbitrary `CONNECT host:port`、generic `ProxyJump`/direct-tcpip relay。
- FTP/FTPS、RDP/VNC、Kubernetes API proxy、database proxy。
- Gateway filesystem upload/download、Gateway shell。
- Target terminal content 的 MITM recording。
- Inner SSH username 強制（§5.2）。
- 站台 firewall / routing controller（D11）。
- Access Directory 整合（Directory 自己不得成為 TCP relay；若要做須另立規格）。
- OpenSSH host CA、workstation FreeIPA enrollment。
- Session 最長時限、授權撤銷時中斷既有 session（§5.2）。

### 2.3 不屬本規格的工作（human-owned，不是工作項）

| 項目 | 擁有者 | 本規格的處理 |
|------|--------|--------------|
| Production 網路隔離（target:22 只對 Gateway 開放；target 不得對 workstation 網段建立新連線） | Operator / 網路團隊 | 列為部署前提（§5.3）；本規格不宣稱保證 |
| VS Code Remote-SSH GUI smoke | 使用者（可選） | 不列入完成條件（D12） |
| Staging/production 分批啟用、指標收集、緊急處置演練 | Operator | 不在本規格（D13） |
| `pilot-session-store` ingest token 檔的佈署 | Operator（維持現狀） | 本規格只讓 playbook 渲染路徑並在檔案不存在時 fail closed（§12.2） |

---

## 3. Baseline 事實（已對 `c0890f6` 核對）

| # | 事實 | 位置 |
|---|------|------|
| F1 | `pilot portal-session` dispatcher：空 command → 互動 Portal；`pilot-connect <uuid> <fqdn>` → one-shot connect；其他 → deny。Go 端**沒有** TTY 檢查 | `cmd/pilot/cmd/portal_session.go` |
| F2 | FQDN validator `parsePortalConnectFQDN`（lowercase、≥2 labels、無 `@:/\` 與 shell metacharacter、無 leading `-`、無 trailing `.`、非 IPv4 literal） | `cmd/pilot/cmd/portal_session.go:54` |
| F3 | 刻意不與 Directory 共用 parser（程式註解明文） | `cmd/pilot/cmd/portal_session.go:41` |
| F4 | ForceCommand wrapper 含 `[ -t 0 ] \|\| exit 1` 與 `exec /usr/bin/pilot portal-session`；不引用 `$SSH_ORIGINAL_COMMAND` | `playbooks/apply/pilot-access-gateway-apply.yml:896-917`（`:906`） |
| F5 | Gateway sshd drop-in `90-pilot-access-gateway.conf`：`Match Group` + `ForceCommand` + `PermitTTY yes` + `DisableForwarding yes` + `AllowAgentForwarding no` + `AllowTcpForwarding no` + `X11Forwarding no` + `PermitTunnel no` + `PermitUserRC no`。**沒有** `AllowStreamLocalForwarding`、`PermitUserEnvironment` | `apply.yml:1069-1086` |
| F6 | `/v1/connect/authorize`：SO_PEERCRED 身分、strict JSON `{"target"}`、每次 fresh `LoadUserAccess`；授權條件為 target 在 scope 內且 `SSH.Allowed`；resolve 失敗 → `Allowed=false`；recording 欄位只在 Allowed 時填 | `internal/gatewayapi/routes.go` `handleConnectAuthorize` |
| F7 | `ConnectAuthorizeResponse` 沒有任何 transport 欄位 | `internal/gatewayapi/types.go:68` |
| F8 | Step 11 每次**整份覆寫** `/etc/pilot/access-gateway.yaml`，不渲染 `recording:`；recording 目前靠手動加（`group_vars/pilot-session-store.example.yml` 明文）→ 任何 re-apply 都會把 recording 重設回 metadata（既有缺陷） | `apply.yml:741-765`；`cmd/pilot-access-gateway/config.go` `RecordingSection` |
| F9 | Config loader `KnownFields(true)`；recording 的 `mode`/`failure_policy` 有值域檢查；`session_store_url` 有值時 `session_store_ingest_token_file` 必填 | `cmd/pilot-access-gateway/config.go` |
| F10 | `pilot-connect` 路徑的 target host key 由 FreeIPA `ipaSshPubKey` 驗證（`sss_ssh_knownhostsproxy` + `/var/lib/sss/pubconf/known_hosts`，`StrictHostKeyChecking yes`）；基礎 spec 規定 production 不做 runtime TOFU | `apply.yml:793-826`；基礎 spec `:2151` |
| F11 | `freeipaaccess.Provider.HostShow`（`all=true`）已存在，但 `parseHost` 只讀 `fqdn`/`userclass` | `internal/freeipaaccess/normalize.go:177` |
| F12 | `HostgroupShow` 回傳 `MemberHosts` + `IndirectMemberHosts`，scope 展開已用此模式 | `internal/accessportal/resolver.go` `ResolveGatewayScope` |
| F13 | `SessionAuditEvent` 沒有 IP/bytes/duration 欄位；註解要求欄位形狀與對應 spec 同步 | `internal/sessionaudit/event.go:21` |
| F14 | Portal automember 預設開啟：除 `admin` 外所有 FreeIPA 帳號都是 `role-pilot-portal-user` 成員 | `apply.yml:611-620` |
| F15 | Target（freeipa-client）已安裝 `05-freeipa-client-password-auth.conf`（`PasswordAuthentication yes`、`KbdInteractiveAuthentication yes`）→ inner SSH 可用 FreeIPA 密碼或使用者 SSH key，不需 workstation TGT | `playbooks/apply/freeipa-client-apply.yml:753` |
| F16 | Gateway contract `traceability.rows: {all: true}`；不適合寫成 host checklist 的項目，既有慣例是放在 verification doc 的 checklist **之外**（§3/§4 章節） | `contracts/pilot-access-gateway.yaml:6`；`docs/verification/pilot-access-gateway.md` §3/§4 |
| F17 | Lockout script 已涵蓋：`-tt` 指令注入（process tree）、`RemoteCommand`、`-L`（server 端拒絕）、SFTP subsystem、`sshd -T -C`、`pilot-connect` grammar 拒絕 | `scripts/pilot-access-gateway-lockout-test.sh` |
| F18 | `rootCmd` 未設 `SilenceUsage`；RunE 失敗時 cobra 會把 usage 印到 stderr | `cmd/pilot/cmd/root.go` |
| F19 | `golang.org/x/term`、`github.com/google/uuid` 已是 direct dependency；`golang.org/x/crypto` 為 indirect v0.6.0 | `go.mod` |

---

## 4. 名詞

| 名稱 | 定義 |
|---|---|
| Outer SSH | Workstation → Access Gateway 的 SSH connection |
| Inner SSH | Workstation → Target、經 opaque transport 傳送的 SSH protocol |
| Transport broker | 授權後只做 TCP/22 byte bridge 的 captive process（`pilot portal-session` 的 State C） |
| Ready hostgroup | FreeIPA hostgroup `pilot-transport-ready`；只有 target policy 成功套用的主機才是成員 |
| Gateway 位址 | Gateway 連往 target 時使用的來源 IP；target policy 的 `Match Address` 以此判斷 |
| Strict profile | Target 對 Gateway 來的 session 禁止所有 sshd forwarding |
| Remote-dev profile | 另外允許 local forwarding 到 target loopback（VS Code Remote-SSH 需要） |

---

## 5. 架構與安全邊界

### 5.1 Data path

```text
Workstation                    Pilot Access Gateway                     Target
───────────                    ────────────────────                     ──────
ssh/sftp/scp/rsync/VS Code
  inner OpenSSH ──ProxyCommand──▶ sshd ─ ForceCommand ─ pilot portal-session
                  (outer SSH,        State C: pilot-transport-v1 <fqdn>
                   ssh -T)             fresh authorize + transport gate
                                       resolve once → dial exact IP:22 ──TCP/22──▶ sshd
                                       opaque byte bridge                        (SSH/SFTP/SCP/
  KnownHostsCommand ─outer SSH──▶     State D: pilot-known-hosts-v1 <fqdn>        rsync/Remote-SSH)
                                       FreeIPA ipaSshPubKey → known_hosts lines
                                     NO shell / NO direct-tcpip / NO SOCKS / NO arbitrary port
```

Gateway 看得到：outer user、target FQDN、實際連線 IP、byte 數、連線時間。
Gateway 看不到：inner command、inner username、SFTP 路徑、檔案內容、terminal 內容、密碼、private key、Remote-SSH payload。

### 5.2 Pilot 保證與不保證

**保證（由 §14 的驗收列證明）**：

1. Gateway：一般使用者拿不到 shell；只接受 §7 的精確 grammar；transport 無 PTY；Gateway sshd forwarding 維持關閉；只連 TCP/22；只接受 FQDN；每次 fresh authorize；只能到達 ready hostgroup 內的主機；resolve 一次並 dial 實際驗證過的 IP；拒絕特殊位址；recording 不相容時拒絕；預設關閉。
2. Target（已套用 policy 的主機）：**所有來自 Gateway 位址的 session**，不論 inner username，sshd 內建的 forwarding channel 都被拒絕——remote TCP/StreamLocal forwarding、agent、X11、tun；local TCP forwarding 在 strict 全拒、在 remote-dev 只允許 target loopback。
3. Host key：建議設定下，target host key 只來自 FreeIPA `ipaSshPubKey`，不做 TOFU；錯誤的 key 由 inner OpenSSH 拒絕，Gateway 不做 MITM。

**不保證（明文邊界，不得在文件或 UI 中假裝不存在）**：

1. **Inner identity**：Gateway 只能強制「outer user 可否到達該 target」；inner SSH 以哪個帳號登入由 target sshd 認證與授權。需要「outer 與 inner 身分必須相同」的環境不得啟用 transport，應繼續用 `pilot-connect`（基礎 spec AG25 的 `whoami == portal user` 只對 `pilot-connect` 成立）。
2. **使用者在 target 上有 shell 時的自建通道**：sshd forwarding 限制擋不住使用者在 target 上用 session 的 stdio 自建通道（例如 `ssh target 'socat - TCP:db.internal:5432'` 當 ProxyCommand 用，或反向透過 session stdio 轉送）。sshd_config(5) 的 `AllowTcpForwarding` 說明也寫明：使用者有 shell 時，關閉 forwarding 並不提升安全性。橫向移動與反向可達性的真正控制點是 target 的網路 egress 政策（operator 前提，§5.3）。
3. **L3 網路隔離**：不是本功能的保證（D11）。
4. **授權撤銷**：授權只在建立連線時檢查；已建立的 session（例如長時間開著的 VS Code）持續到結束，撤銷在下一次連線生效，與既有 `pilot-connect` 行為一致。
5. **Terminal 內容錄影**：transport 模式永遠只有 metadata。

### 5.3 Operator 部署前提（文件化即可，不是工作項）

Production 啟用前，operator 應確保：workstation → target:22 不可直連；target:22 只接受 Gateway 位址；target 不得對 workstation/VPN/Wi-Fi 網段建立新連線。未經 operator 驗證的環境，不得在文件中寫「target 無法連到 workstation」。

---

## 6. Workstation OpenSSH 介面

### 6.1 建議設定

```sshconfig
# Gateway 本身：互動 Portal 與 transport 共用。不要設 RequestTTY no（互動 Portal 需要 TTY）。
Host pilot-gw-gpu
    HostName gw-gpu.example.internal
    ForwardAgent no
    ClearAllForwardings yes
    ControlMaster auto
    ControlPath ~/.ssh/cm-%C
    ControlPersist 10m

# 經 Gateway transport 的 target。Pattern 不得 match 上面的 gateway alias（避免 ProxyCommand 遞迴）。
Host *.gpu.example.internal
    ProxyCommand ssh -T pilot-gw-gpu -- pilot-transport-v1 %h
    KnownHostsCommand ssh -T pilot-gw-gpu -- pilot-known-hosts-v1 %h
    StrictHostKeyChecking yes
    UserKnownHostsFile /dev/null
    GlobalKnownHostsFile /dev/null
    UpdateHostKeys no
    CheckHostIP no
    ForwardAgent no
    ForwardX11 no
```

說明：

- `ControlMaster`：每個 inner connection 都會開兩次 outer SSH（ProxyCommand 與 KnownHostsCommand）；沒有 multiplexing 時，密碼認證會重複提示。ForceCommand 對每個 multiplexed session 仍各自獨立執行。
- `UserKnownHostsFile /dev/null` + `GlobalKnownHostsFile /dev/null`：FreeIPA 是唯一的 host key 來源，永遠不會 TOFU 或寫入 known_hosts。
- Target DNS 解析發生在 Gateway；workstation 不需要能解析 target。
- `%h` 只是 FQDN；Gateway 端仍會嚴格驗證。

### 6.2 相容性邊界

- `KnownHostsCommand` 需要 OpenSSH ≥ 8.5。較舊的 client（例如較舊的 Windows 內建 OpenSSH）改為手動匯出：`ssh -T pilot-gw-gpu -- pilot-known-hosts-v1 <fqdn> >> ~/.ssh/pilot_known_hosts`，並把 `UserKnownHostsFile` 指向該檔。
- 保證：OpenSSH CLI，以及使用 system OpenSSH/`ssh_config` 的工具。
- 不保證：只接受 `host+port+user/password`、不支援 proxy command 的 SFTP library/GUI；只支援 SOCKS 或 direct-tcpip jump host 的 client。不得為了這些 client 在 Gateway 開 `AllowTcpForwarding`。

---

## 7. `pilot portal-session` dispatcher

### 7.1 Exact grammar

| State | `SSH_ORIGINAL_COMMAND` | TTY 要求 | 行為 |
|-------|------------------------|----------|------|
| A | `""` | stdin 必須是 TTY | 互動 Portal（行為不變） |
| B | `pilot-connect <uuid> <fqdn>` | stdin 必須是 TTY | 既有 one-shot（行為不變） |
| C | `pilot-transport-v1 <fqdn>` | **禁止** TTY | Transport broker（§9） |
| D | `pilot-known-hosts-v1 <fqdn>` | **禁止** TTY | 輸出 known_hosts（§10） |
| — | 其他任何字串 | — | deny |

### 7.2 Parser 要求

- 精確前綴比對（含單一空白）：`"pilot-transport-v1 "`、`"pilot-known-hosts-v1 "`；大小寫敏感。
- 前綴之後恰好一個 token，直接以 `parsePortalConnectFQDN`（F2）驗證。**不新增** `internal/accessfqdn` package——同一個 package 直接重用，Directory 端 parser 維持獨立（F3）。
- 回傳型別化結果，例如：

  ```go
  type portalSessionKind int // interactive | connect | transport | knownHosts

  type portalSessionCommand struct {
      Kind      portalSessionKind
      SessionID string // 只有 connect 使用
      Target    string
  }
  ```

  可重構 `parsePortalSSHOriginalCommand` 的簽名，但既有測試的語意必須保留（同步更新測試）。
- `SSH_ORIGINAL_COMMAND` 永遠不得傳入 `sh -c`、`bash -c`、`eval`、`system()` 或 `exec.Command("sh", "-c", ...)`。

### 7.3 TTY policy

- 新增可在測試中覆寫的 package 變數（例如 `portalSessionStdinIsTTY func() bool`，預設 `term.IsTerminal(int(os.Stdin.Fd()))`）。
- State A/B：stdin 不是 TTY → deny（取代 wrapper 的 `[ -t 0 ] || exit 1`，語意相同）。
- State C/D：stdin 是 TTY、stdout 是 TTY，或 `SSH_TTY` 非空，任一成立 → deny。
- Wrapper 移除 `[ -t 0 ] || exit 1`，且**必須與 Go 端檢查放在同一個 candidate**。Playbook 的 binary 安裝（Step 9）已在 wrapper（Step 14）之前，維持此順序。
- `portalSessionCmd` 設 `SilenceUsage: true`，讓 stderr 只出現一行錯誤（F18；ProxyCommand 的 stderr 會直接顯示在使用者終端）。

---

## 8. Gateway API 變更

### 8.1 `ConnectAuthorizeResponse` 新增欄位

```go
TransportAllowed    bool   `json:"transport_allowed,omitempty"`
TransportDenyReason string `json:"transport_deny_reason,omitempty"` // disabled | target_not_ready | ready_lookup_failed
```

- 只在 `Allowed == true` 時計算；`Allowed == false` 時兩者皆為零值。
- Client 端把欄位缺少視為 `false`（新 CLI 搭配舊 daemon 時 fail closed）。
- Request 維持 `{"target"}`，不新增欄位。

### 8.2 Server 端 transport gate

- `gatewayapi.Server` 新增 `Transport TransportPolicy`（`type TransportPolicy struct{ Enabled bool }`），在 `cmd/pilot-access-gateway/main.go` 建構後設定，比照 `RecordingPolicy`。
- 常數 `gatewayapi.TransportReadyHostgroup = "pilot-transport-ready"`（不可設定）。
- 計算規則（僅 Allowed 時）：
  1. `!Transport.Enabled` → `false`、`disabled`，不呼叫 FreeIPA。
  2. `HostgroupShow(TransportReadyHostgroup)` 失敗（含 hostgroup 不存在）→ `false`、`ready_lookup_failed`，並 `slog.Warn`。
  3. `CanonicalizeFQDN(target)` ∈ `MemberHosts ∪ IndirectMemberHosts` → `true`；否則 `false`、`target_not_ready`。
- Transport 開啟時，每次授權（含 `pilot-connect`）會多一次 `HostgroupShow`；v1 接受這個成本，不加快取（基礎 spec 不做 access 快取）。
- 把 `handleConnectAuthorize` 的授權邏輯抽成共用 helper（例如 `s.authorizeConnect(ctx, peer, target)`），供 §8.3 共用——**只有一套 HBAC semantics**。

### 8.3 新 endpoint：`POST /v1/transport/host-keys`

- Body：strict `{"target": "<fqdn>"}`（`decodeStrictJSON`）。
- Peer 驗證同 `authorizedPeer`；授權走 §8.2 的共用 helper 與 transport gate。
- 只有 `TransportAllowed == true` 時才呼叫 `HostShow(target)`。
- 回應：

  ```go
  type TransportHostKeysResponse struct {
      Allowed  bool     `json:"allowed"`
      Target   string   `json:"target"`
      HostKeys []string `json:"host_keys"` // 永不為 nil；deny 時為 []
  }
  ```

- 200：授權結果（deny 時 `allowed:false`，不回傳原因細節）；400：bad request；401：unauthorized；`HostShow` 失敗 → 503 `{"error":"access service unavailable"}`。

### 8.4 `freeipaaccess.Host` 新增 host key

- `Host.SSHPublicKeys []string`，由 `host_show(all=true)` 的 SSH public key 屬性解析。屬性名稱與值的格式〔實測定稿〕（預期為 `ipasshpubkey`）。
- `Provider` interface 不變（`HostShow` 已存在）；只是既有呼叫多了一個 additive 欄位。
- Fixture 必須來自 Phase 0 以 **Gateway service principal** 身分擷取的真實 `host_show` 回應。

### 8.5 Portal client

- `portalClient.TransportHostKeys(ctx, target) (gatewayapi.TransportHostKeysResponse, error)`，與 `ConnectAuthorize` 同樣走 Unix socket。

---

## 9. Transport broker（State C）

建議檔案：`cmd/pilot/cmd/portal_session_transport.go`（與 `_test.go`）。

### 9.1 Sequence

| 步驟 | 動作 | 失敗處理（stderr 固定字串見 §9.6） |
|------|------|------------------------------------|
| 1 | Parse（§7） | usage；不呼叫 API |
| 2 | TTY 檢查（§7.3） | usage |
| 3 | `sessionID := uuid.NewString()` | — |
| 4 | `GET /v1/identity` | unavailable |
| 5 | emit `gateway_transport_requested` | — |
| 6 | `POST /v1/connect/authorize {"target"}` | 呼叫失敗 → emit denied(`authorize_error`)，unavailable |
| 7 | `!authz.Allowed` | emit denied(`authorize_denied`)，access denied |
| 8 | `!authz.TransportAllowed` | emit denied(`transport_<reason>`)，not enabled |
| 9 | `authz.RecordingMode ∉ {"", "metadata"}` | emit denied(`recording_incompatible`)，recording policy |
| 10 | `LookupIPAddr(authz.Target)`，timeout 5s | 錯誤或空結果 → emit failed(`dns`)，unavailable |
| 11 | 過濾位址（§9.2） | 全數被拒 → emit denied(`no_valid_address`)，access denied |
| 12 | 依 resolver 回傳順序 dial `<ip>:22`，每次 timeout 5s，最多 3 個位址 | 全失敗 → emit failed(`dial`)，unavailable |
| 13 | emit `gateway_transport_connected`（含實際 IP） | — |
| 14 | Bridge（§9.3） | — |
| 15 | emit `gateway_transport_closed`（bytes、duration、result） | — |

之後所有步驟一律使用 `authz.Target`，不再使用原始輸入。

### 9.2 DNS 與 dial 安全

- 禁止 `net.Dial("tcp", "<hostname>:22")`；只能 dial 已驗證的 IP：`net.JoinHostPort(ip.String(), "22")`。
- 不得在 dial 失敗後改用 hostname 重試，也不得做第二次 lookup。
- 拒絕：unspecified、loopback、multicast（含 interface-local）、link-local unicast/multicast、帶 zone 的位址、IPv4-mapped IPv6 形式的上述位址（先 `To4()` 正規化），以及 Gateway 任一本機介面位址（`net.InterfaceAddrs()`；列舉失敗 → 全拒，fail closed）。
- 不得一律拒絕 RFC1918/ULA（target 通常在 private network）。
- Resolver 與 dialer 以 interface 注入，測試可替換：

  ```go
  type transportResolver interface {
      LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
  }
  type transportDialer interface {
      DialContext(ctx context.Context, network, address string) (net.Conn, error)
  }
  ```

- 常數（不可設定）：DNS timeout 5s、每次 dial timeout 5s、最多嘗試 3 個位址。
- 「resolve 一次」的作用是讓 audit 記錄的 IP 就是實際連線的 IP，並排除兩次 lookup 之間的差異；它**不**驗證 IP 是否屬於該 host（authorize 不看 IP）。port 固定 22，加上 target 端自己的認證，是這個風險的上限。

### 9.3 Bridge semantics

- Goroutine A：`stdin → conn`。收到 EOF → `conn.(*net.TCPConn).CloseWrite()`；遇到錯誤 → `conn.Close()`。
- Goroutine B：`conn → stdout`。收到 EOF 或錯誤 → session 結束。
- 主流程：等 B 結束；再等 A 最多 2 秒（Go 無法可靠取消阻塞中的 `os.Stdin.Read`，不得無限等待）；`conn.Close()`；回傳。
- `signal.NotifyContext`（SIGTERM、SIGHUP、SIGINT）或 context 取消 → `conn.Close()`，讓 B 解除阻塞。
- Byte 計數用 atomic counting reader/writer；duration 從 connected 起算。
- v1 沒有 idle timeout（inner SSH 自有 keepalive）。

### 9.4 stdout 零汙染

- 在 bridge 之前與之後，任何授權訊息、DNS 警告、audit、debug、session id 都不得寫入 stdout。
- 所有 deny/fail 路徑的 stdout 必須是 0 bytes（AG56 驗證）。
- 進入 bridge 後，只有 fatal transport error 可以寫 stderr。

### 9.5 Audit

見 §11。

### 9.6 Stderr 固定字串與 exit code

| 情況 | stderr 必含 | exit |
|------|-------------|------|
| grammar 錯誤 | `pilot-transport: usage: pilot-transport-v1 <target-fqdn>` | ≠0 |
| 有 TTY | `pilot-transport: a TTY is not allowed for transport` | ≠0 |
| authorize deny / 無有效位址 | `pilot-transport: access denied` | ≠0 |
| `transport_allowed=false` | `pilot-transport: transport not enabled for this target` | ≠0 |
| recording 不相容 | `pilot-transport: transport disabled by recording policy` | ≠0 |
| API/DNS/dial 失敗 | `pilot-transport: target unavailable` | ≠0 |
| 正常結束 | （無） | 0 |
| bridge 本機 I/O 錯誤 | `pilot-transport: transport error` | ≠0 |

上表的 usage 字串只用於「前綴完全符合 `pilot-transport-v1 `，但 target 不合法」的情況；其他無法辨識的指令（含沒有尾端空白的 `pilot-transport-v1`）沿用既有 `pilot-session:` 錯誤，dispatcher 不猜測使用者意圖。

---

## 10. Known-hosts 指令（State D）

建議檔案：`cmd/pilot/cmd/portal_session_known_hosts.go`（與 `_test.go`）。

1. Parse、TTY 檢查（同 State C）。錯誤訊息前綴為 `pilot-known-hosts:`，字串比照 §9.6（usage 為 `pilot-known-hosts: usage: pilot-known-hosts-v1 <target-fqdn>`；API 失敗與 `HostShow` 503 為 `pilot-known-hosts: target unavailable`）。
2. `GET /v1/identity`（不 emit requested 事件）。
3. `POST /v1/transport/host-keys {"target"}`。
4. `!Allowed` → stderr `pilot-known-hosts: access denied`，exit ≠0，stdout 0 bytes，emit `gateway_known_hosts_denied`。
5. 逐一驗證每把 key：key type ∈ {`ssh-ed25519`、`ecdsa-sha2-nistp256`、`ecdsa-sha2-nistp384`、`ecdsa-sha2-nistp521`、`ssh-rsa`}；base64 可解碼；blob 內嵌的 type 字串與宣告的 type 相同。可用 `golang.org/x/crypto/ssh.ParseAuthorizedKey`（改為 direct dependency），或自寫等價的最小 parser；二擇一，並在 PR 說明理由。
6. 對每把有效 key 輸出一行 `<authz target> <type> <base64>\n`（去掉 comment）。
7. 零把有效 key → stderr `pilot-known-hosts: no host key published for target`，exit ≠0，stdout 0 bytes。
8. emit `gateway_known_hosts_served`（key 數量）。

---

## 11. Audit

### 11.1 新 event kinds（`internal/sessionaudit`）

```text
gateway_transport_requested
gateway_transport_denied      # Result = authorize_error | authorize_denied | transport_disabled |
                              #          transport_target_not_ready | transport_ready_lookup_failed |
                              #          recording_incompatible | no_valid_address
gateway_transport_failed      # Result = dns | dial
gateway_transport_connected
gateway_transport_closed      # Result = ok | error
gateway_known_hosts_served
gateway_known_hosts_denied
```

### 11.2 欄位

`SessionAuditEvent` 新增 additive、`omitempty` 欄位（`SchemaVersion` 維持 1）：

```go
TargetIP            string `json:"target_ip,omitempty"`
BytesClientToTarget *int64 `json:"bytes_client_to_target,omitempty"`
BytesTargetToClient *int64 `json:"bytes_target_to_client,omitempty"`
DurationMS          *int64 `json:"duration_ms,omitempty"`
HostKeyCount        *int   `json:"host_key_count,omitempty"`
```

- 每個 transport 事件都帶 `SessionID`、`User`（outer）、`TargetFQDN`、`GatewayID`、`GatewayScope`、`RecordingMode`（已知時）。
- `SSH_CONNECTION` 的來源 IP 可以記錄，但只能用於 audit，不得作為授權依據。
- 同步更新 `event.go:21` 的註解，指向本規格的新增欄位。

### 11.3 禁止記錄

SFTP 檔名、target command、terminal 內容、密碼、private key、GSSAPI token、inner username、檔案內容。

---

## 12. Gateway config 與 playbook 變更

### 12.1 Config（`cmd/pilot-access-gateway/config.go`）

```yaml
gateway:
  transport:
    enabled: false
```

- `GatewaySection.Transport TransportSection`（`Enabled bool yaml:"enabled"`）。
- 缺少 `transport:` → `enabled=false`。
- `KnownFields(true)` 維持；`transport` 下出現未知欄位 → 載入失敗。

### 12.2 Recording 設定擁有權（Phase 1，先修 F8）

新增 group vars（全部可選）：

| 變數 | 預設 | 值域 |
|------|------|------|
| `pilot_access_gateway_recording_mode` | `metadata` | `metadata`、`terminal_output`、`terminal_io` |
| `pilot_access_gateway_recording_failure_policy` | `best_effort` | `best_effort`、`fail_closed` |
| `pilot_access_gateway_recording_session_store_url` | `""` | URL |
| `pilot_access_gateway_recording_session_store_ca_file` | `""` | 路徑 |
| `pilot_access_gateway_recording_session_store_ingest_token_file` | `""` | 路徑 |
| `pilot_access_gateway_recording_allow_downgrade` | `false` | bool |

Playbook 要求：

1. Step 11 之前：`stat` + `slurp` 既有 `/etc/pilot/access-gateway.yaml`（check mode 也要跑），`from_yaml` 取出既有 `recording.mode`（缺省 `metadata`）與 `recording.session_store_url`（缺省 `""`）。
2. 降級守門：rank `metadata=0 < terminal_output=1 < terminal_io=2`。若「新 rank < 既有 rank」，或「既有 url 非空而新 url 為空」，且 `pilot_access_gateway_recording_allow_downgrade` 不為 true → 在寫入任何檔案**之前**失敗，訊息指出既有值、新值與覆寫旗標。
3. 值域 assert；`session_store_url` 非空時，`ingest_token_file` 必須非空、檔案存在，且 mode 沒有 group/world bit（`stat`），否則失敗（與 `loadSessionStoreIngestToken` 的規則一致）。
4. Step 11 模板新增 `recording:` 區塊（mode、failure_policy；url 非空時才輸出 session_store_*），以及 `transport:` 區塊（§12.3）。
5. 同步更新：`group_vars/pilot-access-gateway.example.yml`、`group_vars/pilot-session-store.example.yml`（「手動對應設定」段落改寫成新 group vars）、`cmd/pilot/cmd/deploy_catalog.go` 的 pilot-session-store Note、`contracts/pilot-access-gateway.yaml` 的 `groupVars`。

### 12.3 Transport 旗標

- Group var `pilot_access_gateway_transport_enabled`（boolean，預設 `false`）→ 模板輸出 `transport:\n    enabled: true|false`（縮排依既有模板）。
- Contract `groupVars` 新增 `{name: pilot_access_gateway_transport_enabled, type: boolean, required: false, default: false, secret: false}`。
- 本規格不得把預設改成 `true`。

### 12.4 Gateway sshd drop-in（Step 19）

- 新增 `AllowStreamLocalForwarding no`（Match 內允許）。
- **不**把 `PermitUserEnvironment` 放進 Match 區塊（sshd_config(5) 的 Match 允許清單不含它，會讓 `sshd -t` 失敗）；它的全域預設已是 `no`，由 lockout script 以 `sshd -T` 驗證全域值。
- 其餘 directive 不變。Transport broker 的 outbound `net.Dial` 不是 sshd forwarding channel，**不得**開 `AllowTcpForwarding`。

### 12.5 Wrapper（Step 14）

移除 `[ -t 0 ] || exit 1`；其餘不變（仍然不得引用 `$SSH_ORIGINAL_COMMAND`）。

### 12.6 Tags

| Task | 新增 tag |
|------|----------|
| Step 11（config 模板） | `AG41`、`AG42` |
| Step 19（sshd drop-in） | `AG43` |
| Step 14（wrapper） | `AG44` |

`contracts/pilot-access-gateway.yaml` `traceability.rows` 新增 AG41–AG44 的對應；`regressionTests` 補上新測試檔。

---

## 13. 新 component：`pilot-access-target-policy`

### 13.1 檔案與登記（全部必做）

- `contracts/pilot-access-target-policy.yaml`：
  - `dependencies: [{component: freeipa-client, required: true, relation: sameHosts}]`
  - `conflicts: [pilot-access-gateway, pilot-access-directory]`
  - `hostCardinality: one-or-more`
  - `stagePolicy: {variable: stage, default: sandbox}`
  - `evidenceRequirement: {targetTest: topology, idempotency: required}`
  - `verification: {autoDeploy: false}`
  - `site: {include: false, order: 0, vars: {}, tags: [], optIn: true}`
  - `traceability: mapped`（TP01–TP05）
  - `groupVars`（§13.2）
- `playbooks/apply/pilot-access-target-policy-apply.yml`
- `group_vars/pilot-access-target-policy.example.yml`
- `docs/verification/pilot-access-target-policy.md`（TP01–TP05 checklist；TP06–TP12 放在 checklist 之外的章節，比照 F16）
- `internal/spec/pilot_access_target_policy_regression_test.go`
- `internal/inventory/contracts.go`（`roleContracts` 條目，`VaultSections: ["freeipa"]`）、`internal/inventory/catalog.go`（`topLevelOrder`，位置依既有排序慣例與其測試）
- `inventory.example.yml`（比照既有 `pilot-access-gateway` 條目的寫法）
- `cmd/pilot/cmd/deploy_catalog.go`（day-2/opt-in、不在 `site.yml`、需要 `pilot_access_target_gateway_addresses`）
- `cmd/pilot/cmd/tag_coverage_test.go` 的 `specTagMap` 條目
- `AGENTS.md` §4.3：apply playbook 清點 38 → 39，列入名單；§8 變更紀錄新增一列
- `DELIVERY.md`：若其 playbook 對照表涵蓋同類 opt-in playbook 則補上，否則不動（在 PR 說明判斷依據）
- §4.2 restic 備份範圍：此角色只寫 `/etc`，已被預設 `["/etc"]` 涵蓋，**不需要**新增範例（在 PR 說明）

### 13.2 變數

| 變數 | 型別 | 必填 | 預設 | 說明 |
|------|------|------|------|------|
| `pilot_access_target_policy_state` | string | 否 | `present` | `present` / `absent`（declarative rollback） |
| `pilot_access_target_forwarding_profile` | string | 否 | `strict` | `strict` / `remote-dev` |
| `pilot_access_target_gateway_addresses` | stringList | **是** | — | Gateway 連往 target 時使用的來源 IP 清單（單一位址，不收 CIDR） |
| `ipa_admin_password` | string（secret） | 是 | — | 只用於 ready hostgroup 的成員操作；來自 vault |
| `stage` / `confirm_staging` / `confirm_prod` / `staging_attested_within_hours` | — | 否 | 同其他 apply playbook | AGENTS.md §4.3 |

### 13.3 Drop-in 內容

路徑 `/etc/ssh/sshd_config.d/06-pilot-access-target-policy.conf`，root:root 0644（排在 `05-freeipa-client-password-auth.conf` 之後、cloud-init 的 `50-`/`60-` 之前；檔名順序只影響 Match 區塊之間的先後，以 §14 的 `sshd -T` 驗證為準）。

Strict：

```text
# Managed by pilot-access-target-policy-apply.yml — do not edit by hand.
# pilot-access-target-policy profile: strict
Match Address <addr1>,<addr2>
    AllowTcpForwarding no
    AllowStreamLocalForwarding no
    PermitOpen none
    PermitListen none
    GatewayPorts no
    AllowAgentForwarding no
    X11Forwarding no
    PermitTunnel no
```

Remote-dev（只列差異）：

```text
# pilot-access-target-policy profile: remote-dev
    AllowTcpForwarding local
    PermitOpen localhost:* 127.0.0.1:* [::1]:*
```

- `AllowTcpForwarding local` 同時涵蓋 `-L` 與 `-D`（兩者在 server 端都是 direct-tcpip）；`PermitOpen` 把目的地限制為 loopback；`PermitListen none` 再次封住 remote listen。
- 由 Gateway 發起的既有 `pilot-connect` session 也會落在這個 Match（`/etc/pilot/ssh_config` 已是 `ClearAllForwardings yes`，不受影響）。

### 13.4 Apply 順序（`present`）

0. `hosts: "{{ target_group | default('pilot-access-target-policy') }}"`；host 的 FreeIPA FQDN 取法比照 gateway playbook 的 `gateway_effective_fqdn`（預設 `ansible_fqdn`）。
1. `pre_tasks`：stage gate 三道 assert（照抄 `pilot-access-gateway-apply.yml` 的 gate）；`group_names` 不得含 `pilot-access-gateway`/`pilot-access-directory`；profile 值域；addresses 非空、每個元素只含 IPv4/IPv6 位址字元、不含 `*`/`/`/`,`/空白、不是 `0.0.0.0`/`::`，也不是 `192.0.2.1`（TP05 保留的 TEST-NET 位址）。
2. FreeIPA enrollment gate（比照 gateway 的 Step 2）。
3. 擷取 baseline：`sshd -T -C user=root,host=pilot-baseline,addr=192.0.2.1`（§13.3 受限的 8 個 key），以及完整的全域 `sshd -T`。
4. `block`：
   1. 既有 drop-in 備份為 `.pre-pilot-access-target-policy.bak`（AGENTS.md §4）。
   2. `copy` 寫入 drop-in，`validate: /usr/sbin/sshd -t -f %s`。
   3. `sshd -t`（完整設定）。
   4. 有效設定檢查：對每個 Gateway 位址，`sshd -T -C user=root,host=pilot-gateway,addr=<addr>` 符合所選 profile（TP03/TP04 的條件）；`addr=192.0.2.1` 的 8 個受限 key 與 baseline 相同；全域 `sshd -T` 在受限 key 以外與 baseline 相同（防止 Match 區塊外洩到後續設定）。
   5. reload sshd（Debian `ssh` / RHEL `sshd`，不 restart）；再跑一次 `sshd -t`。
   - `rescue`：還原備份（或刪除新檔）→ `sshd -t` → reload → fail。
5. `kinit admin`（`no_log`）→ `ipa hostgroup-add pilot-transport-ready`（已存在視為 ok）→ `ipa hostgroup-add-member pilot-transport-ready --hosts=<fqdn>`（已是成員視為 ok）。`changed_when`/`failed_when` 的字串〔實測定稿〕。
6. 所有 `command` task 依 AGENTS.md §4.0 處理 check mode（不得在 check mode 下對已跳過 task 的結果做 dot-access）。

### 13.5 Rollback（`absent`）

順序固定：**先**把 host 移出 `pilot-transport-ready`（不是成員視為 ok）→ **再**刪除 drop-in → `sshd -t` → reload。反過來做會出現「transport 仍可到達、但限制已解除」的窗口。

### 13.6 Tags

`TP01`：drop-in 寫入 task；`TP02`：`sshd -t` task；`TP03`/`TP04`：有效設定檢查 task；`TP05`：baseline 比對 task。另加粗標籤 `pilot-access-target-policy`。

---

## 14. Verification plan

分類：**[host]** = 寫進 verification doc §2 checklist、可由 `pilot verify` 在單一主機執行；**[unit]** = Go 測試；**[e2e]** = §15 topology 實跑，結果寫入 evidence。[unit]/[e2e] 列放在 verification doc checklist **之外**的新章節（F16 慣例），不進 contract `traceability`。

所有 [host] 列的 Command 欄必須先用 `pilot verify --probe` 確認，並通過 `pilot spec --lint` 與 `TestShellSyntax`。

### 14.1 Gateway — [host] checklist（`docs/verification/pilot-access-gateway.md` §2）

| ID | Check | Command（〔實測定稿〕） |
|----|-------|------------------------|
| AG41 | config 已渲染 `recording.mode`，值 ∈ metadata/terminal_output/terminal_io | 以 `awk`/`grep` 檢查 `/etc/pilot/access-gateway.yaml` 的 `recording:` 區塊與 `mode:` 行 |
| AG42 | config 已渲染 `transport.enabled`，值為 `true` 或 `false` | 同上，檢查 `transport:` 區塊與 `enabled:` 行 |
| AG43 | Gateway sshd drop-in 含 `AllowStreamLocalForwarding no`，且 Match 內沒有 `PermitUserEnvironment` | `grep` `/etc/ssh/sshd_config.d/90-pilot-access-gateway.conf` |
| AG44 | ForceCommand wrapper 已不含 `[ -t 0 ]`，且仍 `exec /usr/bin/pilot portal-session` | `grep` `/usr/local/libexec/pilot-session` |

### 14.2 Gateway — [unit]

| ID | 驗證內容 | 建議測試（檔案/名稱） |
|----|----------|----------------------|
| AG45 | `pilot-transport-v1 <fqdn>`、`pilot-known-hosts-v1 <fqdn>` 解析成功並得到正確 Kind/Target | `portal_session_test.go` `TestParsePortalSSHOriginalCommand_ValidTransport` / `_ValidKnownHosts` |
| AG46 | 拒絕清單（兩個指令都測）：無參數、只有尾端空白、雙空白、多一個 token、單一 label、`localhost`、IPv4、`::1`、`[::1]`、`user@host`、`host:22`、`host 22`、大寫、尾端 `.`、`;`/`$`/反引號、leading `-`（`-oProxyCommand=x`）、tab、內嵌換行、`pilot-transport-v2`、`PILOT-TRANSPORT-V1` | `TestParsePortalSSHOriginalCommand_RejectsTransport` |
| AG47 | TTY 矩陣：A/B 無 TTY → deny；C/D 有 stdin TTY、stdout TTY 或 `SSH_TTY` → deny 且零 API 呼叫 | `TestRunPortalSession_TTYPolicy` |
| AG48 | Server transport gate：disabled → false/`disabled` 且零 FreeIPA 呼叫；enabled+ready（直接與間接成員）→ true；enabled+非成員 → `target_not_ready`；hostgroup 錯誤 → `ready_lookup_failed`；Allowed=false → transport 欄位為零值 | `internal/gatewayapi/server_test.go` `TestConnectAuthorize_Transport*` |
| AG49 | Client gate：authorize 錯誤、Allowed=false、`transport_allowed` false 或缺少 → resolver 與 dialer 呼叫次數皆為 0 | `portal_session_transport_test.go` |
| AG50 | 每次 transport 都 fresh authorize：兩次呼叫之間撤銷權限，第二次被拒 | 同上（fake gateway） |
| AG51 | Recording allowlist：`""`/`metadata` 通過；`terminal_output`、`terminal_io`、未知值 → deny，零 resolve | 同上 |
| AG52 | Resolve 一次、只 dial `<ip>:22`、從不 dial hostname；多位址依序嘗試；第一個失敗會試下一個；最多 3 個；resolver 呼叫次數恰為 1 | 同上 |
| AG53 | 位址拒絕：`127.0.0.1`、`::1`、`0.0.0.0`、`::`、`169.254.0.0/16`、`fe80::/10`、multicast、`::ffff:127.0.0.1`、帶 zone、Gateway 本機介面位址；RFC1918/ULA 允許 | 同上 |
| AG54 | Byte-for-byte：隨機 binary（含 NUL、`0xff`、`\n`、≥16 MiB）雙向完全一致 | 同上（loopback TCP echo server） |
| AG55 | Half-close 兩種順序：stdin EOF 後 target 仍能送完剩餘 bytes；target EOF 後、stdin 從未關閉時，在 grace 內結束；context 取消會關閉 conn；沒有 goroutine 洩漏 | 同上（`-race`） |
| AG56 | 每條 deny/fail 路徑 stdout 為 0 bytes；stderr 含 §9.6/§10 的固定字串 | 同上、`portal_session_known_hosts_test.go` |
| AG57 | Audit：kind/Result/欄位正確；bytes 與 duration 正確；不含 §11.3 的禁止內容 | 同上（capturing emitter） |
| AG58 | Host keys：以 Phase 0 真實擷取的 `host_show` fixture 解析；輸出格式；type allowlist；不合法 key 被丟棄；零 key → deny、stdout 空；endpoint 走與 authorize 相同的 helper 與 gate | `internal/freeipaaccess/normalize_test.go`、`internal/gatewayapi/server_test.go`、`portal_session_known_hosts_test.go` |
| AG59 | Config：缺少 `transport:` → false；`transport` 下的未知欄位 → 載入失敗 | `cmd/pilot-access-gateway/config_test.go` |

### 14.3 Gateway — [e2e]（§15）

| ID | 驗證內容 |
|----|----------|
| AG60 | Recording 擁有權：同一組 vars 重新 apply 後 mode 不變；`terminal_output` → `metadata` 在未帶 `allow_downgrade` 時，於寫檔前失敗，且檔案 checksum 不變；帶 `allow_downgrade=true` 才成功 |
| AG61 | 擴充後的 lockout suite 全過（§15.4） |
| AG62 | 未設定 `pilot_access_gateway_transport_enabled` 時渲染為 `enabled: false`，transport 被拒（`transport not enabled`） |
| AG63 | Workstation 以 target **IP** 直連 `target:22` 失敗（證明是網路阻擋，不只是 DNS 解析不到）；經 transport 的 `ssh target whoami`、`ssh target 'echo ok'` 成功；Gateway 上該 session 的 `pilot portal-session` 沒有任何子行程（特別是 `ssh`/`sh`/`bash`） |
| AG64 | SFTP：put、get、rename、stat、remove 成功；Gateway 上找不到上傳的檔案（以唯一檔名 `find` Gateway 全檔案系統） |
| AG65 | SCP：upload + download，checksum 一致 |
| AG66 | rsync：小型目錄樹 + ≥64 MiB 大檔，`sha256sum` 一致 |
| AG67 | Host key：§6.1 設定、空的 known_hosts、`StrictHostKeyChecking yes` → 成功，且 workstation 上沒有任何 known_hosts 被寫入；把 KnownHostsCommand 換成輸出錯誤 key 的命令 → inner OpenSSH 回報 host key verification failed |
| AG68 | Target 不在 `pilot-transport-ready`（target policy `absent` 之後）→ transport 與 known-hosts 都被拒 |
| AG69 | Gateway `recording_mode=terminal_output` → transport 被拒（`recording policy`）；同一時間 `pilot-connect` 仍然產生 recording（local FileSink 檔案存在） |
| AG70 | 經真實 sshd：AG46 的代表性子集（IP literal、`host:22`、`user@host`、shell metacharacter、wrong-scope target）全數被拒，target 端 sshd 在該時段沒有來自 Gateway 的連線紀錄 |
| AG71 | Gateway journald 對一次成功 session 有 requested → connected → closed（含 target_ip、bytes、duration_ms）；對一次被拒的 session 有 denied；全部不含 §11.3 的禁止內容 |
| AG72 | Legacy 回歸：互動 Portal（`ssh -tt`）正常；`pilot-connect` one-shot 對 target 正常；既有 AG35–AG40 unit tests 通過；Directory handoff 以既有 unit tests + `pilot-connect` grammar 未變證明未退化 |
| AG73 | Rollback：`pilot_access_gateway_transport_enabled=false` 重新 apply → transport 被拒；Portal、`pilot-connect`、lockout suite 仍全過 |

（Gateway idempotency 沿用既有 AG30：第二次 apply `changed=0`。）

### 14.4 Target policy — [host] checklist（`docs/verification/pilot-access-target-policy.md` §2）

| ID | Check | Command 要點（〔實測定稿〕） |
|----|-------|---------------------------|
| TP01 | Drop-in 存在，root:root 644，含 managed header、profile marker、`Match Address` | `stat` + `grep` |
| TP02 | 完整 sshd 設定有效 | `sshd -t` |
| TP03 | 從 drop-in 的 `Match Address` 取第一個位址 `a`，`sshd -T -C user=root,host=pilot-gateway,addr=$a` 含：`permitlisten none`、`gatewayports no`、`allowagentforwarding no`、`x11forwarding no`、`permittunnel no`、`allowstreamlocalforwarding no` | `bash -c` 腳本 |
| TP04 | 依 profile marker：strict → `allowtcpforwarding no` 且 `permitopen none`；remote-dev → `allowtcpforwarding local` 且 permitopen 恰為 loopback 三項 | `bash -c` 腳本 |
| TP05 | 非 Gateway 位址不受影響：`sshd -T -C user=root,host=x,addr=192.0.2.1` 的 8 個受限 key 與全域 `sshd -T` 相同 | `bash -c` 腳本 |

### 14.5 Target policy — [e2e]

| ID | 驗證內容 |
|----|----------|
| TP06 | `present` 後 host 是 `pilot-transport-ready` 成員；`absent` 後不是（從 FreeIPA server 查詢） |
| TP07 | Strict：經 transport 的 inner `-L` 到 target loopback、`-D`、`-R`、`-A`（target 上 `SSH_AUTH_SOCK` 為空）、`-X`、`-w` 全部被拒（server 端 `administratively prohibited` 或等價拒絕〔實測定稿〕） |
| TP08 | Remote-dev：`-L <local>:localhost:<port>` 與 `-D` SOCKS 到 `127.0.0.1:<port>` 成功（target 上臨時的 loopback listener）；`-L` 到非 loopback（例如 FreeIPA server:443）被拒；`-R` 被拒 |
| TP09 | 非 Gateway 路徑不受影響：從 ansible controller 直接 SSH 到 target，`-L` 到 loopback 的行為與套用前的 baseline 相同 |
| TP10 | `absent`：先移出 hostgroup、後刪 drop-in（以 task 順序與 log 證明）；drop-in 不存在；`sshd -t` 通過；TP05 條件仍成立 |
| TP11 | Idempotency：strict 與 remote-dev 各自第二次 apply `changed=0`；strict → remote-dev 切換只改 drop-in |
| TP12 | 不合法輸入在寫檔前失敗且 `/etc/ssh/sshd_config.d/` checksum 不變：非法 profile、空的 addresses、`*`、`0.0.0.0`、CIDR、`192.0.2.1`、畸形 IPv6（例如 `1::2::3`，由 `validate` 擋下） |

---

## 15. E2E harness

### 15.1 Topology：`docs/topologies/pilot-access-transport-topology.yaml`

| Node | Image | Groups | Wire |
|------|-------|--------|------|
| `ipa` | almalinux-9 | `freeipa-server` | gw、target |
| `gw` | ubuntu-24.04 | `freeipa-client`、`pilot-access-gateway` | ipa、target |
| `target` | ubuntu-24.04 | `freeipa-client`、`pilot-access-target-policy` | ipa、gw |
| `ws` | ubuntu-24.04 | （無：**不** enroll FreeIPA） | 只有 gw |

`ws` 只知道 Gateway 的名稱，證明 workstation 不需要 FreeIPA，也不需要 target 的 DNS/route。記憶體大小比照 `docs/topologies/minimal-poc-topology.yaml` 的節點設定。

### 15.2 Fixtures：`playbooks/test/fixtures/pilot-access-transport-fixtures.yml`

冪等（重跑 `changed=0`）；敏感 task 加 `no_log`；使用者建立一律 `import_playbook: freeipa-client-fixtures.yml`（`ipa_fixture_manage_sudorule: false`，AGENTS.md §4.1）。內容：

1. 建立 FreeIPA 使用者 `transportuser`（canonical fixture）。
2. `ws`：為本機使用者 `wsuser` 產生 ed25519 key（已存在就跳過）；讀出 public key。
3. `ipa`：`ipa user-mod transportuser --sshpubkey=<pub>`（先比對再修改，維持冪等）；HBAC rule `pilot-transport-e2e`（user=`transportuser`、host=`target`、service=`sshd`）。Gateway 登入沿用 Gateway playbook 建立的 `pilot-access-gateway-login` 與 automember。
4. `target`：nftables 規則，丟棄來源為 `ws` IP 的 tcp/22（模擬 D11 的站台隔離；不影響 controller 與 gw）。

### 15.3 Wrapper playbook：`playbooks/test/pilot-access-transport-e2e.yml`

依序 import：`freeipa-server-apply` → `freeipa-client-apply` → fixtures（使用者/key/HBAC）→ `gateway-scope-apply`（把 `target` 發布進 `pilot-target-<scope>`，用法照 `docs/verification/pilot-gateway-scope.md`，JSON 形式傳 list，AGENTS.md v1.25 gotcha）→ `pilot-access-gateway-apply` → `pilot-access-target-policy-apply` → fixtures（nftables）。

執行順序（每一步的實際指令先實跑確認，再寫進 evidence）：

1. `pilot vm-target topology test --ephemeral --topology … --playbook playbooks/test/pilot-access-transport-e2e.yml --verify docs/verification/pilot-access-gateway.md=pilot-access-gateway --verify docs/verification/pilot-access-target-policy.md=pilot-access-target-policy -- -e pilot_access_gateway_transport_enabled=true …`：涵蓋 L3 check-mode（全新 VM）、apply、[host] 列、idempotency。
2. 另一次不帶 transport 變數的 gateway apply → AG62；之後恢復為 `true`。
3. 以 `topology inventory` 產生的 inventory 執行後續的變化步驟：strict 探測 → 切換 remote-dev → recording `terminal_output`（AG69）→ 不帶 `allow_downgrade` 改回 metadata（預期失敗，AG60）→ 帶 `allow_downgrade` 改回 → target policy `absent`（AG68/TP06/TP10）→ `transport_enabled=false`（AG73）→ TP12 各個負面輸入。

### 15.4 Scripts

- `scripts/pilot-access-gateway-lockout-test.sh` 擴充（保留既有 probes 與 `CONFIRM_DISPOSABLE=yes` 規則）：
  1. 無 TTY 的任意 command 仍被拒；
  2. `ssh -tt gw -- pilot-transport-v1 <t>`、`ssh -tt gw -- pilot-known-hosts-v1 <t>` 被拒；
  3. `scp`、`sftp` 直連 Gateway 被拒；
  4. `-L`、`-R`、`-D` 被 server 端拒絕；
  5. Transport 進行中的 process tree：只有 `pilot portal-session`，沒有 shell，也沒有 `/usr/bin/ssh` 子行程；
  6. `sshd -T -C user=<portal user>,…`：`disableforwarding yes`、`allowtcpforwarding no`、`allowstreamlocalforwarding no`、`allowagentforwarding no`、`permituserrc no`、`permittunnel no`、`x11forwarding no`；全域 `permituserenvironment no`。
- 新增 `scripts/pilot-access-gateway-transport-e2e.sh`：從 `ws` 以 `wsuser` 執行 AG63–AG71 與 TP07–TP09 的探測（TP09 從 controller 執行）；每個 probe 輸出一行 JSON（id/status/detail，比照 lockout script）；以 `--phase strict|remote-dev|recording|not-ready|disabled` 選擇探測組；需要 `CONFIRM_DISPOSABLE=yes`；不得把任何密碼放進 argv。`pilot-connect` 路徑（AG69、AG72）需要在 Portal 的 TTY 提示中輸入 Kerberos 密碼，以 PTY 自動化（例如 `expect`）處理，密碼只從環境變數讀取（來源為 vault）。

---

## 16. 實作 Phases 與 gates

每個 Phase：candidate commit → 乾淨 checkout 實跑 → evidence-only commit。Evidence 檔名依 `docs/actual-run-evidence.md`：`docs/evidence/pilot-access-gateway/<date>-<tested-revision>.md`、`docs/evidence/pilot-access-target-policy/<date>-<tested-revision>.md`；Phase 名稱寫在檔案內容裡。禁止 big-bang implementation。

### Phase 0 — Feasibility spike 與真實擷取（go/no-go）

在 disposable vm-target（可用放在 `tmp/`、未提交的暫時 topology）：

1. 以最小原型證明：真實 sshd ForceCommand 路徑下，`ssh -o ProxyCommand='ssh -T gw -- pilot-transport-v1 %h' target whoami` 成功，且與使用者 login shell 無關（記錄 portal user 的 `loginShell`，以及 Gateway 上 home 的來源）；同時確認 FreeIPA 使用者的 SSH key（`ipa user-mod --sshpubkey`）可同時用於 outer（Gateway）與 inner（target）認證——§15 的自動化依賴這點。
2. 以 Gateway service principal 身分擷取 `host_show(all=true)` 的真實回應，確認含 SSH public key 屬性 → 轉成 AG58 fixture。
3. 在 Ubuntu 24.04 target 擷取 strict/remote-dev 候選 drop-in 的 `sshd -T -C`（Gateway 位址與 `192.0.2.1`）與全域 `sshd -T` → TP03–TP05 的 expected 與 regression fixture；確認 drop-in 內的 Match 區塊不會外洩到後續設定，並確認 `sshd -t -f <drop-in>` 可作為 `copy` 的 `validate`。
4. 擷取 `ipa hostgroup-add` / `hostgroup-add-member` / `hostgroup-remove-member` 在「新增」「已存在」「不是成員」情況下的 stdout/stderr/rc。
5. 在 `ws`（OpenSSH 9.x）驗證 `KnownHostsCommand` + ProxyCommand + `/dev/null` known_hosts + `StrictHostKeyChecking yes` 的組合可用。
6. 驗證 `PermitUserEnvironment` 放在 Match 內會讓 `sshd -t` 失敗（確認 §12.4 的前提）。

原型程式碼可以丟棄；只提交 sanitized 擷取（轉成 testdata fixture）與 evidence 摘要。

**停止並回報使用者**（附實測輸出與建議做法），若：
- 第 1 項：無法穩定做到 binary-clean；
- 第 2 項：service principal 讀不到 SSH public key 屬性（需決定是否授予 FreeIPA 權限）；
- 第 3 項：Match 區塊會外洩，且無法用檔名順序解決；
- 第 5 項：`KnownHostsCommand` 組合不可用。

### Phase 1 — Recording 設定擁有權（§12.2）

- 範圍：playbook 守門與模板、contract/group_vars/deploy_catalog 同步、AG41 [host] 列、regression test 更新；新增 §15.1 的 topology 檔（Phase 1、3、4、5 共用）。
- Gate：在 §15.1 topology 上 AG41、AG60 通過；既有 AG01–AG40 不退化；gateway `changed=0`。

### Phase 2 — Go：dispatcher、broker、known-hosts、API、audit、config

- 範圍：§7–§11、§12.1；AG45–AG59 全部的 unit tests。**不 deploy。**
- Gate：`go build ./...`、`go test ./...`、`go test -race ./...`、`gofmt`/`make lint` 全綠；AG35–AG40 既有測試仍通過。

### Phase 3 — Gateway 部署整合

- 範圍：§12.3–§12.6、contract、verification doc（AG42–AG44 [host] 列 + AG45–AG73 章節）、lockout script 擴充、`internal/spec` regression（鎖住 AG41–AG44 存在；wrapper 不含 `[ -t 0 ]`；drop-in 含 `AllowStreamLocalForwarding no` 且 Match 內沒有 `PermitUserEnvironment`；`TransportReadyHostgroup` 字面值與 target policy playbook 一致）。
- Gate：在 §15.1 topology 上以 `pilot vm-target topology test`（含 L3 check-mode）通過；lockout suite（§15.4 第 1–4、6 項）全過（第 5 項需要 ready target，於 Phase 5 執行）；transport 預設關閉時，Portal 與 `pilot-connect` 行為與 baseline 相同。

### Phase 4 — Target policy component（§13）

- 範圍：§13.1 全部檔案與登記；TP01–TP05 [host] 列；regression test（row 連號、lint、tag 覆蓋、以 Phase 0 fixture 鎖住 drop-in 內容與 profile 差異）。
- Gate：在 §15.1 topology 上 strict、remote-dev、absent、TP12 負面輸入都實跑通過；各自 `changed=0`。

### Phase 5 — Topology E2E（§15）

- 範圍：topology、fixtures、wrapper playbook、E2E script；AG60–AG73、TP06–TP12。
- Gate：§15.3 全部步驟以 `--ephemeral` 對全新 VM 實跑通過；每個 probe 的 JSON 結果整理進 evidence。

### Phase 6 — 文件收尾

- 兩份 verification doc 更新目前有效摘要與 evidence 連結（連結必須指向 Git 追蹤的檔案）。
- 新增 `docs/runbooks/pilot-access-transport.md`：§0.5 事實快照、workstation `ssh_config`（§6.1）、啟用/停用旗標、target policy profile 選擇；只寫 Phase 5 實跑過的指令。
- `AGENTS.md` §4.3 清點與變更紀錄。
- Gate：`pilot spec --lint` 0 errors；`TestShellSyntax` PASS；`git grep` 沒有失效的連結。

---

## 17. 檔案變更清單

**Modify**

```text
cmd/pilot/cmd/portal_session.go
cmd/pilot/cmd/portal_session_test.go
cmd/pilot/cmd/portal_client.go
cmd/pilot-access-gateway/config.go
cmd/pilot-access-gateway/config_test.go
cmd/pilot-access-gateway/main.go
internal/gatewayapi/types.go
internal/gatewayapi/routes.go
internal/gatewayapi/server.go
internal/gatewayapi/server_test.go
internal/freeipaaccess/provider.go            # Host.SSHPublicKeys
internal/freeipaaccess/normalize.go
internal/freeipaaccess/normalize_test.go
internal/sessionaudit/event.go
internal/sessionaudit/emitter_test.go         # 若新增欄位需要
internal/spec/pilot_access_gateway_regression_test.go
internal/inventory/contracts.go
internal/inventory/catalog.go
cmd/pilot/cmd/deploy_catalog.go
cmd/pilot/cmd/tag_coverage_test.go
playbooks/apply/pilot-access-gateway-apply.yml
scripts/pilot-access-gateway-lockout-test.sh
contracts/pilot-access-gateway.yaml
group_vars/pilot-access-gateway.example.yml
group_vars/pilot-session-store.example.yml
inventory.example.yml
docs/verification/pilot-access-gateway.md
AGENTS.md                                    # §4.3 清點 + 變更紀錄
go.mod / go.sum                               # 僅在採用 x/crypto/ssh 時
```

**Add**

```text
cmd/pilot/cmd/portal_session_transport.go
cmd/pilot/cmd/portal_session_transport_test.go
cmd/pilot/cmd/portal_session_known_hosts.go
cmd/pilot/cmd/portal_session_known_hosts_test.go
contracts/pilot-access-target-policy.yaml
playbooks/apply/pilot-access-target-policy-apply.yml
group_vars/pilot-access-target-policy.example.yml
docs/verification/pilot-access-target-policy.md
internal/spec/pilot_access_target_policy_regression_test.go
internal/freeipaaccess/testdata/…             # Phase 0 真實擷取的 host_show fixture（路徑依既有慣例）
docs/topologies/pilot-access-transport-topology.yaml
playbooks/test/fixtures/pilot-access-transport-fixtures.yml
playbooks/test/pilot-access-transport-e2e.yml
scripts/pilot-access-gateway-transport-e2e.sh
docs/runbooks/pilot-access-transport.md
docs/evidence/pilot-access-gateway/<date>-<rev>.md          # 每個 Phase
docs/evidence/pilot-access-target-policy/<date>-<rev>.md
```

**Do not modify（除非本規格明列）**：互動 Portal 行為、`pilot-connect` one-shot 行為、session recording 實作、Access Directory route semantics、`playbooks/site.yml` 的 `target_group` 安全閥。

---

## 18. Security invariants（release 前全部成立）

```text
S1  Gateway 一般使用者拿不到 Gateway shell。
S2  SSH_ORIGINAL_COMMAND 永遠不進 shell interpreter。
S3  只接受 §7.1 的精確 grammar。
S4  Transport 與 known-hosts 不使用 PTY。
S5  Gateway sshd forwarding 維持關閉（含 StreamLocal）。
S6  目的 port 永遠是 22。
S7  每次 transport 都 fresh 通過 FreeIPA HBAC ∩ Gateway scope 授權。
S8  只能到達 pilot-transport-ready 內的 target。
S9  永遠不接受呼叫者提供的 IP 作為 target。
S10 DNS 只解析一次，只 dial 已驗證的 IP；特殊位址與 Gateway 本機位址被拒。
S11 Recording mode 不是 metadata 時 transport 被拒；re-apply 不會靜默降級 recording。
S12 已套用 policy 的 target：所有來自 Gateway 位址的 session，sshd remote forwarding、agent、X11、tun 被拒，與 inner username 無關。
S13 已套用 policy 的 target：local forwarding 在 strict 全拒、在 remote-dev 只允許 loopback。
S14 非 Gateway 來源的 session 不受 target policy 影響。
S15 建議設定下，target host key 只來自 FreeIPA，不做 TOFU。
S16 Transport 預設關閉，關閉後不影響 Portal / pilot-connect。
S17 既有 Portal 與 pilot-connect 行為相容。
```

§5.2 列出的「不保證」項目不得被改寫成 invariant。

---

## 19. Compatibility matrix

| Capability | Result | Notes |
|---|---|---|
| Interactive SSH / remote command | YES | inner OpenSSH |
| SFTP / SCP / rsync | YES | target 端的 subsystem/binary（rsync 需安裝在 target） |
| VS Code Remote-SSH | OpenSSH 層已驗證 | 需要 `remote-dev`；GUI 未驗證（D12） |
| Local forwarding 到 target loopback | `remote-dev` only | `-L` 與 `-D` 皆可 |
| Local forwarding 到任意 LAN | NO（sshd 層） | shell 自建通道見 §5.2 |
| Remote forwarding / agent / X11 / tun | NO | target policy |
| 直接 SFTP/SCP 到 Gateway filesystem | NO | ForceCommand deny |
| Shell on Gateway | NO | ForceCommand |
| Generic TCP proxy | NO | 固定 TCP/22 |
| Terminal 內容錄影 | NO | 改用 `pilot-connect` |
| 既有 recorded `pilot-connect` | YES | 不變 |
| OpenSSH < 8.5（無 KnownHostsCommand） | 可用 | 手動匯出 known_hosts（§6.2） |

---

## 20. 變更紀錄

| 版本 | 日期 | 變更 |
|------|------|------|
| rev 1 | 2026-09-23 | 初稿（DRAFT） |
| rev 2 | 2026-09-23 | 對 `c0890f6` 核對 baseline 後修訂為可實作版本：新增 `pilot-known-hosts-v1` 與 FreeIPA 權威 host key（取代未定義的 host key 分發）；target policy 改為 `Match Address`，並以 `pilot-transport-ready` hostgroup 由 server 端 gate transport（修正以 group 限制可被繞過、以及 inventory 與 FreeIPA scope 漂移）；新增 Phase 1 修正 recording 設定被 re-apply 覆寫的既有缺陷；安全宣稱改為誠實邊界（stdio 自建通道、inner identity、撤銷時機）；移除 Match 內不合法的 `PermitUserEnvironment`；驗收重新編號為 AG41–AG73 + TP01–TP12，並區分 host/unit/e2e；bridge 改為不會卡住的 half-close 語意；recording 改為 allowlist；補齊新 component 的登記清單與 AGENTS.md 規則；移除 human-owned 工作（網路隔離、GUI smoke、staging/production rollout），改列於 §2.3 |
