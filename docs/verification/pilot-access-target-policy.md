# Verification Spec — Pilot Access Target Policy

> 版本：v0.1（2026-09-23，captive-transport spec Phase 4）
> 對齊規範：docs/superpowers/specs/2026-09-23-pilot-access-gateway-captive-ssh-transport-spec.md §13/§14.4/§14.5
> 維護者：sre

## 1. 目標系統

| 項目 | 值 |
|------|----|
| Inventory group | `pilot-access-target-policy`（或明確 `target_group`） |
| 角色 | Pilot Access Gateway captive SSH transport（`pilot-transport-v1`）的 target 端政策：對「來自 Gateway 位址」的每個 SSH session（不論 inner 以哪個帳號登入）拒絕 sshd 內建的 forwarding channel，驗證通過後才把主機加入 FreeIPA hostgroup `pilot-transport-ready`——gateway 只會對這個 hostgroup 內的主機開 transport |
| 前置需求 | 已是 FreeIPA client（`freeipa-client-apply.yml`）；`pilot_access_target_gateway_addresses` 列出 gateway 連往 target 時的來源 IP |
| 套用範圍 | transport target 主機；**不得**套在 `pilot-access-gateway`/`pilot-access-directory` 主機上（pre_tasks 與 contract `conflicts` 都擋） |
| 風險等級 | **Medium**（改 sshd 設定；寫檔前 `sshd -t -f` 驗證、失敗自動還原、只 reload 不 restart；非 Gateway 位址的 session 每次實跑都驗證不受影響） |

**限制（誠實邊界，spec §5.2）**：sshd forwarding 設定擋不住已在 target 上取得 shell 的使用者透過 session stdio 自建通道；這份政策也不是 L3 網路隔離——target egress 政策由 operator 負責（spec §5.3）。

## 1.5 依賴變數契約

| 變數名稱 | 說明 | 必填 |
|---|---|---|
| `pilot_access_target_gateway_addresses` | Gateway 的單一來源 IP 清單（不收 CIDR/hostname/`0.0.0.0`/`::`/`192.0.2.1`）；以 JSON 傳，例如 `-e '{"pilot_access_target_gateway_addresses": ["10.10.0.21"]}'` | 是 |
| `pilot_access_target_forwarding_profile` | `strict`（預設：拒絕所有 sshd forwarding）或 `remote-dev`（另外允許 local forwarding 到 target loopback，給 VS Code Remote-SSH） | 否 |
| `pilot_access_target_policy_state` | `present`（預設）或 `absent`（先移出 `pilot-transport-ready`，再移除 drop-in） | 否 |
| `ipa_admin_password` | 只用於 `pilot-transport-ready` 成員管理；來自 vault | 是（secret） |

## 2. Checklist

| ID | Category | Check | Expected | Command |
|----|----------|-------|----------|---------|
| TP01 | dropin | `/etc/ssh/sshd_config.d/06-pilot-access-target-policy.conf` 存在、root:root 644，含 managed header、profile marker 與 `Match Address <gateway addresses>` | 0 | sh -c 'f=/etc/ssh/sshd_config.d/06-pilot-access-target-policy.conf; test "$(stat -c "%U:%G %a" "$f")" = "root:root 644" && grep -q "^# Managed by pilot-access-target-policy-apply.yml" "$f" && grep -Eq "^# pilot-access-target-policy profile: (strict|remote-dev)$" "$f" && grep -Eq "^Match Address [0-9A-Fa-f:.,]+$" "$f"' |
| TP02 | sshd | 完整 sshd 設定有效 | 0 | sshd -t |
| TP03 | forwarding | 對 drop-in 第一個 Gateway 位址的有效設定：remote/StreamLocal forwarding、agent、X11、tun、GatewayPorts 全部關閉 | 0 | bash -c 'f=/etc/ssh/sshd_config.d/06-pilot-access-target-policy.conf; a=$(sed -n "s/^Match Address \([^,]*\).*/\1/p" "$f"); [ -n "$a" ] || exit 1; v=$(sshd -T -C "user=root,host=pilot-gateway,addr=$a"); for l in "allowstreamlocalforwarding no" "permitlisten none" "gatewayports no" "allowagentforwarding no" "x11forwarding no" "permittunnel no"; do grep -Fqx "$l" <<< "$v" || exit 1; done' |
| TP04 | forwarding | 依 profile marker：strict → `allowtcpforwarding no` 且 `permitopen none`；remote-dev → `allowtcpforwarding local` 且 permitopen 恰為 loopback 三項 | 0 | bash -c 'f=/etc/ssh/sshd_config.d/06-pilot-access-target-policy.conf; a=$(sed -n "s/^Match Address \([^,]*\).*/\1/p" "$f"); p=$(sed -n "s/^# pilot-access-target-policy profile: //p" "$f"); v=$(sshd -T -C "user=root,host=pilot-gateway,addr=$a"); case "$p" in strict) grep -Fqx "allowtcpforwarding no" <<< "$v" && grep -Fqx "permitopen none" <<< "$v";; remote-dev) grep -Fqx "allowtcpforwarding local" <<< "$v" && grep -Fqx "permitopen localhost:* 127.0.0.1:* [::1]:*" <<< "$v";; *) exit 1;; esac' |
| TP05 | isolation | 非 Gateway 位址（TEST-NET-1 `192.0.2.1`）的 8 個受限 key 與全域 `sshd -T` 完全相同——政策只作用在 Gateway 來的 session | 0 | bash -c 'k="^(allowtcpforwarding|allowstreamlocalforwarding|permitopen|permitlisten|gatewayports|allowagentforwarding|x11forwarding|permittunnel) "; diff <(sshd -T -C "user=root,host=x,addr=192.0.2.1" | grep -E "$k") <(sshd -T | grep -E "$k") >/dev/null' |

## 3. 拓樸實跑（[e2e]，不在 checklist 逐行覆蓋）

依 F16 慣例列在 checklist 之外，由 `docs/topologies/pilot-access-transport-topology.yaml` 上的實跑證明，結果寫入對應 Phase 的 evidence（`docs/evidence/pilot-access-target-policy/`）。

| ID | 驗證內容 |
|----|----------|
| TP06 | `present` 後主機是 `pilot-transport-ready` 成員；`absent` 後不是（從 FreeIPA server 查詢） |
| TP07 | strict：經 transport 的 inner `-L` 到 target loopback、`-D`、`-R`、`-A`（target 上沒有 `SSH_AUTH_SOCK`）、`-X`、`-w` 全部被拒 |
| TP08 | remote-dev：`-L`／`-D` 到 target loopback 成功；`-L` 到非 loopback 與 `-R` 被拒 |
| TP09 | 非 Gateway 路徑不受影響：從 controller 直接 SSH 到 target，`-L` 到 loopback 的行為與套用前的 baseline 相同 |
| TP10 | `absent`：先移出 hostgroup、再刪 drop-in；drop-in 與 snapshot 都不存在；`sshd -t` 通過；TP05 條件仍成立 |
| TP11 | 冪等：strict 與 remote-dev 的第二次 apply 都是 `changed=0`；strict → remote-dev 切換只改 drop-in |
| TP12 | 不合法輸入在寫檔前失敗，且 `/etc/ssh/sshd_config.d/` 的 checksum 不變：非法 profile、空的 addresses、`*`、`0.0.0.0`、CIDR、`192.0.2.1`、畸形 IPv6（例如 `1::2::3`，由 `sshd -t -f` 擋下，並經 `rescue` 還原） |

## 4. Gotcha 記錄

- **為什麼是 `Match Address` 而不是 `Match Group`**：opaque transport 無法強制 inner SSH username（spec §5.2）；以 group 限制時，用不在 group 的帳號（admin、本機帳號、服務帳號）登入就能繞過。以 Gateway 來源位址比對，所有經 Gateway 進來的 session 都受限。由 Gateway 發起的既有 `pilot-connect` session 也落在同一個 Match，不受影響（`/etc/pilot/ssh_config` 本來就是 `ClearAllForwardings yes`）。
- **PermitOpen 的輸出格式**：`sshd -T` 把 remote-dev 的設定印成 `permitopen localhost:* 127.0.0.1:* [::1]:*`（真實擷取，`docs/evidence/pilot-access-gateway/2026-09-23-ad6d552.md` §3），TP04 以固定字串比對整行。
- **Match 區塊不外洩**：drop-in 內的 `Match` 範圍止於該 include 檔；playbook 每次 apply 都以「非 Gateway 位址與全域 `sshd -T` 在套用前後逐 byte 相同」驗證（TP05），不同就 `rescue` 還原並失敗。
