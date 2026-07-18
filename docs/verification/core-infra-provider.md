# Verification Spec — core-infra-provider (Internal DNS + NTP server)

> 版本：v2.2
> 對齊規範：pilot 通用基礎設施**服務端**規範（這份 host 是要提供 internal DNS / NTP 的那台，而不是使用端）
> 維護者：sre

> 對偶參照：使用端健康見 `core-infra.md`；本檔是提供者健康。
>
> v2.0：Keycloak C7–C9 從本 spec 拆出到 **`docs/verification/keycloak.md`**；
> Keycloak 的 PostgreSQL backing store 仍走 `core-infra-provider-db.md`（獨立）。
> 本 spec 只負責 DNS（C1–C3）+ NTP（C4–C6）兩個 provider role。

## 1. 目標系統

| Hostname     | Group          | Address          | User   | Port | IdentityFile  |
|--------------|----------------|------------------|--------|------|---------------|
| infra-1      | infra-provider |                  |        |      |               |
| core         | dns            |                  |        |      |               |
| core         | ntp            |                  |        |      |               |

> `infra-provider` 是 aggregate group（dns + ntp + keycloak + keycloak-db）；
> 本 spec 預設目標是其子集 `dns` / `ntp`。`core` 是 vm-target 情境下
> sibling-of-vm-target 的 host alias（sibling 還會帶 `keycloak` /
> `keycloak-db`，但本 spec 不驗證那兩個 — 見 `keycloak.md` /
> `core-infra-provider-db.md`）。

## 2. Checklist

| ID | Category  | Check                                                                              | Expected    | Command |
|----|-----------|------------------------------------------------------------------------------------|-------------|---------|
| C1 | dns       | DNS 服務 daemon 已安裝（unbound / bind9 / dnsmasq 三擇一；至少一個）                       | ~1          | sh -c 'dpkg-query -l bind9 bind9-dnsutils bind9-host bind9-libs unbound dnsmasq 2>/dev/null | awk "/^ii/ && /unbound|bind9|dnsmasq/{f=1} END{print f+0}" ' |
| C2 | dns       | DNS 服務在本機 listening，且不是 systemd-resolved stub (`127.0.0.53`)                  | present     | sh -c 'ss -tulnH \| grep ":53 " \| grep -v "127.0.0.53" \| head -n1' |
| C3 | dns       | 本機是 authoritive（本機 resolv.conf 第一個 nameserver 不是 127.0.0.1）                     | 0           | sh -c 'grep -qE "^nameserver[[:space:]]+(127\.[0-9]+\.[0-9]+\.[0-9]+|::1)$" /etc/resolv.conf' |
| C4 | ntp       | NTP daemon 已安裝（chrony / ntp / ntpsec 三擇一；至少一個）                              | ~1          | sh -c 'dpkg-query -l chrony ntp ntpsec 2>/dev/null | awk "/^ii/ && /chrony|ntp|ntpsec/{f=1} END{print f+0}" ' |
| C5 | ntp       | chronyd 或 ntpd active                                                            | ~active     | systemctl is-active chronyd ntpd 2>&1 \| head -n1 |
| C6 | ntp       | Stratum ≤ 5（本機沒被上上游設成 leaf-of-leaf；chrony 用 `chronyc tracking`，ntpd/ntpsec 用 `timedatectl show-timesync` 三擇一） | ~Stratum    | sh -c 'chronyc tracking 2>/dev/null \| grep -oE "Stratum[[:space:]]*:[[:space:]]*[0-5]" \|\| timedatectl show-timesync 2>&1 \| grep -oE "Stratum=[0-5]"' |
| C7 | dns       | 自訂內部網域可解析（**選用**；只在設 `$DNS_PROBE_NAME` 時真的探測，否則 SKIP-as-pass）           | present     | sh -c 'if [ -z "${DNS_PROBE_NAME:-}" ]; then echo SKIP-no-probe; else dig +short "$DNS_PROBE_NAME" @127.0.0.1; fi' |

> Keycloak provider 健康（process / HTTP listener / OIDC discovery）已
> 拆到 **`docs/verification/keycloak.md`**（C7–C9），不在本 spec 範圍。

### 補上 env 變數（跑 spec 前先 `export`）

> v2.0：DNS/NTP 六條核心 check 不需要任何 env var（Keycloak 段已拆走）。
>
> v2.1（**選用**，僅 C7）：若這台 host 有服務自訂內部網域，設下面兩個變數就能
> 讓 C7 真的用 `dig` 探測一筆記錄；不設則 C7 自動 SKIP-as-pass，純轉發解析器
> 不會因此變紅。
>
> ```bash
> export DNS_PROBE_NAME=core.pilot.lan   # 要探測的 FQDN（你在 dns_zones 設過的）
> # C7 只檢查「解得出非空答案」；要比對特定 IP 請用 runbook 裡的 dig 手動驗。
> ```

## 3. 證據收集

- 工具：`pilot verify docs/verification/core-infra-provider.md -i inventory-core-infra.yaml -l dns`
- 格式：`.verification/core-infra-provider-<UTC>.{ndjson,md}`
- Row 數：7（C1–C6 核心 + C7 選用自訂網域探測）

範例輸出（dev box 沒裝任何 DNS / NTP → 6/6 fail，這正是預期）：

```json
{"id":"C1","status":"fail","detail":"rc=1 — no dns package installed"}
{"id":"C4","status":"fail","detail":"rc=1 — no ntp package installed"}
```

## 4. PASS / FAIL 規則

- C1–C6 全部 `status=pass` → **PASS**：本機已準備好提供 internal DNS / NTP 服務
  （C7 沒設 `$DNS_PROBE_NAME` 時 SKIP-as-pass，不影響 verdict）
- 任一 fail → **FAIL**，常見修法：
  - C1 fail → `apt install unbound`（推薦）或 `bind9` / `dnsmasq`
  - C4 fail → `apt install chrony`（推薦，NTS 支援）
  - C6 fail → NTP 上游設定錯誤，重檢 `pool.ntp.org` / `ntp.ubuntu.com`
  - C7 fail（有設 `$DNS_PROBE_NAME`）→ 該 FQDN 沒解出來：確認 `dns_zones`
    有這筆記錄、apply 後 unbound 有 restart、且探的是本機 `@127.0.0.1`。
    見 `docs/runbooks/core-infra-provider-dns-zones.md`

## 5. 例外與已知偏差

| ID | 例外內容                                              | 適用環境   | 期限      |
|----|------------------------------------------------------|-----------|----------|
| C2 | 在 docker-desktop / kind node 內跑時會誤抓到 host DNS service  | laptop/VM | 排除 local DNS |
| C5 | RHEL 套件名為 `chronyd`，systemd unit 為 `chronyd.service` 不是 `chrony`；spec 用 `chronyd ntpd` 兩個名字涵蓋      | RHEL    | 永久     |

## 6. Playbook 對應

對應的 verify playbook（`playbooks/verify/core-infra-provider.yml`）**已於 2026-07-17 棄用**（僅存檔參考，見該目錄 README.md）；驗收直接 `pilot verify` 吃本 spec 執行。

對應手寫的 **apply** playbook：`playbooks/apply/core-infra-provider-apply.yml`

| Spec ID | Apply task (示例)                              | 備註 |
|---------|-----------------------------------------------|------|
| C1-C3   | `apt` install unbound + `block/rescue` 切 dns | stage=sandbox 跑一次 dry-run；backup `/etc/systemd/resolved.conf` 防 lockout |
| C4-C6   | `apt` install chrony + NTP pool 上游          | chrony 預設接 ubuntu pool + NTS |
| C7      | `DNS — write unbound config` 展開 `dns_zones` `local-zone`/`local-data`（或 `stub-zone`） | 資料驅動：`dns_zones` 來自 out-of-git inventory 旁的 `group_vars/dns/`；schema 見 `group_vars/dns/zones.example.yaml` |

> Apply playbook 必須 `block/rescue` 保護：例如關閉 systemd-resolved stub 改 server 模式失敗，
> 自動還原 `/etc/systemd/resolved.conf` 的 backup，避免 DNS 黑洞把 host 連線全斷。
>
> Keycloak apply 段已從本 playbook 拆到 `playbooks/apply/keycloak-apply.yml`
> （對應 `docs/verification/keycloak.md`）。Keycloak 的 PostgreSQL backing
> store 段已拆到 `playbooks/apply/keycloak-db-apply.yml`
> （對應 `docs/verification/core-infra-provider-db.md`）。

## 7. 把 FAIL 變 PASS 的 SOP

```bash
# 1. 套前先看這台 host 是哪一個 group
ansible infra-1 -i inventory.yaml -m shell -a "id; hostname"

# 2. 套 dns provider（以 unbound 為例）
ansible-playbook -i inventory.yaml \
    playbooks/apply/core-infra-provider-apply.yml \
    -e provider_stage=sandbox \
    -e dns_provider=unbound \
    -e dns_upstream='1.1.1.1#cloudflare-dns.com 9.9.9.9#quad9.net'

# 3. 套 ntp provider
ansible-playbook -i inventory.yaml \
    playbooks/apply/core-infra-provider-apply.yml \
    -e provider_stage=sandbox \
    -e ntp_provider=chrony \
    -e ntp_pool='ntp.ubuntu.com pool.ntp.org'
```

> 設 `provider_stage=prod` 額外需要 `-e confirm_prod=true` 確認 gate。
> 第一次 dry-run 一律 `--check --diff`。
>
> Keycloak / DB 段：見 `docs/runbooks/keycloak.md` 與
> `docs/runbooks/core-infra-provider-db.md`（已拆出）。

## 8. 變更紀錄

| 日期       | 版本 | 變更                                                                                                  | 變更者 |
|------------|------|------------------------------------------------------------------------------------------------------|--------|
| 2026-06-30 | v1.0 | 初版（C1–C9；DNS / NTP / Keycloak 三個 provider 混一份）                                                  | pilot  |
| 2026-07-02 | v2.0 | 拆出 Keycloak C7–C9 到 `keycloak.md`；spec §1 對齊 inventory `infra-provider` aggregate；本 spec 縮為 6 row | sre    |
| 2026-07-02 | v2.1 | 新增 C7（選用）自訂內部網域探測；apply 改為資料驅動 `dns_zones`（`group_vars/dns/`）；見 `core-infra-provider-dns-zones.md` runbook | sre    |
| 2026-07-17 | v2.2 | 修正 C6：`timedatectl show-timesync` 需要 `systemd-timesyncd` 提供的 dbus 介面，但 apply playbook 的 NTP 預設 provider 是 chrony（`ntp_provider: chrony`）——chrony 啟用時 `systemd-timesyncd` 是 inactive,`show-timesync` 回 `Failed to parse bus message: No route to host`,C6 在任何一台照預設值跑過 apply 的全新主機上必 fail。改成 `chronyc tracking` 優先、`timedatectl show-timesync` 為 ntpd/ntpsec 主機的 fallback。docker 從 `core-infra-provider-apply.yml` 拆出後重新對 vm-target 全面 re-verify 時發現（與 docker 拆分本身無關的既有 bug，見 `docs/runbooks/core-infra-provider-end-to-end.md`） | pilot  |
