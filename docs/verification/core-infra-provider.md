# Verification Spec — core-infra-provider (NTP server)

> 版本：v3.0
> 對齊規範：pilot 通用基礎設施**服務端**規範（這份 host 是要提供 NTP 的那台，而不是使用端）
> 維護者：sre

> 對偶參照：使用端健康見 `core-infra.md`；本檔是提供者健康。
>
> v3.0：DNS provider rows（舊 C1–C3、C7）拆到 **`docs/verification/dns.md`**，
> 對應的 apply 也從本 playbook 拆到 `playbooks/apply/dns-apply.yml`。本 spec 只剩
> NTP，row 重新編號為 C1–C3（舊 C4–C6，內容不變）。
> v2.0：Keycloak 拆到 `docs/verification/keycloak.md`；PostgreSQL 走
> `core-infra-provider-db.md`。

## 1. 目標系統

| Hostname     | Group          | Address          | User   | Port | IdentityFile  |
|--------------|----------------|------------------|--------|------|---------------|
| infra-1      | infra-provider |                  |        |      |               |
| core         | ntp            |                  |        |      |               |

> `infra-provider` 是 aggregate group（dns + ntp + keycloak + keycloak-db）；
> 本 spec 預設目標是其子集 `ntp`。`core` 是 vm-target 情境下
> sibling-of-vm-target 的 host alias。

## 2. Checklist

| ID | Category  | Check                                                                              | Expected    | Command |
|----|-----------|------------------------------------------------------------------------------------|-------------|---------|
| C1 | ntp       | NTP daemon 已安裝（chrony / ntp / ntpsec 三擇一；至少一個）                              | ~1          | sh -c 'dpkg-query -l chrony ntp ntpsec 2>/dev/null | awk "/^ii/ && /chrony|ntp|ntpsec/{f=1} END{print f+0}" ' |
| C2 | ntp       | chronyd 或 ntpd active（`systemctl is-active` 至少一個 active 才回 0）              | 0           | systemctl is-active chronyd ntpd |
| C3 | ntp       | Stratum ≤ 5（本機沒被上上游設成 leaf-of-leaf；chrony 用 `chronyc tracking`，ntpd/ntpsec 用 `timedatectl show-timesync` 三擇一） | ~Stratum    | sh -c 'chronyc tracking 2>/dev/null \| grep -oE "Stratum[[:space:]]*:[[:space:]]*[0-5]" \|\| timedatectl show-timesync 2>&1 \| grep -oE "Stratum=[0-5]"' |

## 3. 證據收集

- 工具：`pilot verify docs/verification/core-infra-provider.md -i inventory-core-infra.yaml -l ntp`
- 格式：`.verification/core-infra-provider-<UTC>.{ndjson,md}`
- Row 數：3

## 4. PASS / FAIL 規則

- C1–C3 全部 `status=pass` → **PASS**：本機已準備好提供 NTP 服務
- 任一 fail → **FAIL**，常見修法：
  - C1 fail → `apt install chrony`（推薦，NTS 支援）
  - C3 fail → NTP 上游設定錯誤，重檢 `pool.ntp.org` / `ntp.ubuntu.com`

## 5. 例外與已知偏差

| ID | 例外內容                                              | 適用環境   | 期限      |
|----|------------------------------------------------------|-----------|----------|
| C2 | RHEL 套件名為 `chronyd`，systemd unit 為 `chronyd.service` 不是 `chrony`；spec 用 `chronyd ntpd` 兩個名字涵蓋      | RHEL    | 永久     |

## 6. Playbook 對應

對應手寫的 **apply** playbook：`playbooks/apply/core-infra-provider-apply.yml`（`-e infra_role=ntp`）

| Spec ID | Apply task                                    | 備註 |
|---------|-----------------------------------------------|------|
| C1      | `NTP — install chrony`（tag `ntp-C1`）         | 走 apt framework |
| C2      | `NTP — enable + start chronyd`（tag `ntp-C2`） | |
| C3      | `NTP — write chrony.conf`（tag `ntp-C3`）      | chrony 預設接 ubuntu pool |

## 7. 把 FAIL 變 PASS 的 SOP

```bash
ansible-playbook -i inventory.yaml \
    playbooks/apply/core-infra-provider-apply.yml \
    -e infra_role=ntp \
    -e ntp_provider=chrony \
    -e ntp_pool='ntp.ubuntu.com pool.ntp.org'
```

> `stage=staging`/`prod` 額外需要 `-e confirm_staging=true`／`-e confirm_prod=true`。
> 第一次一律先加 `--check --diff`。DNS provider 見 `docs/verification/dns.md`。

## 8. 變更紀錄

| 日期       | 版本 | 變更                                                                                                  | 變更者 |
|------------|------|------------------------------------------------------------------------------------------------------|--------|
| 2026-06-30 | v1.0 | 初版（C1–C9；DNS / NTP / Keycloak 三個 provider 混一份）                                                  | pilot  |
| 2026-07-02 | v2.0 | 拆出 Keycloak C7–C9 到 `keycloak.md`；spec §1 對齊 inventory `infra-provider` aggregate；本 spec 縮為 6 row | sre    |
| 2026-07-02 | v2.1 | 新增 C7（選用）自訂內部網域探測；apply 改為資料驅動 `dns_zones`（`group_vars/dns/`）；見 `core-infra-provider-dns-zones.md` runbook | sre    |
| 2026-07-17 | v2.2 | 修正 C6：`timedatectl show-timesync` 需要 `systemd-timesyncd` 提供的 dbus 介面，但 apply playbook 的 NTP 預設 provider 是 chrony（`ntp_provider: chrony`）——chrony 啟用時 `systemd-timesyncd` 是 inactive,`show-timesync` 回 `Failed to parse bus message: No route to host`,C6 在任何一台照預設值跑過 apply 的全新主機上必 fail。改成 `chronyc tracking` 優先、`timedatectl show-timesync` 為 ntpd/ntpsec 主機的 fallback。docker 從 `core-infra-provider-apply.yml` 拆出後重新對 vm-target 全面 re-verify 時發現（與 docker 拆分本身無關的既有 bug，見 `docs/runbooks/core-infra-provider-end-to-end.md`） | pilot  |
| 2026-10-01 | v3.0 | DNS rows（C1–C3、C7）與 `infra_role=dns` 拆到 `docs/verification/dns.md`／`playbooks/apply/dns-apply.yml`；NTP rows 由 C4–C6 重新編號為 C1–C3（tag `ntp-C1`–`ntp-C3`）。C2 的 expected 由 `~active` 改成 rc `0`：舊寫法在 chronyd、ntpd 都沒跑時，輸出 `inactive` 也會命中 `active`，誤判 PASS（2026-10-01 對兩台 vm-target 用 `pilot verify --probe` 確認：有跑 chronyd 的主機 PASS，都沒跑的主機 FAIL） | sre    |
