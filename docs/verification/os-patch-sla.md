# Verification Spec — os-patch-sla (Ubuntu/Debian periodic OS patching)

> 版本：v1.0
> 對齊規範：pilot 通用 OS 套件定期更新規範（Critical 15 天、High 30 天、Medium 90 天修補週期；更新前非生產環境驗證；自動化推送更新）
> 維護者：sre

## 1. 目標系統

| Hostname | Group    | Address          | User   | Port | IdentityFile                |
|----------|----------|------------------|--------|------|------------------------------|
| test-vm  | all      |                  |        |      |                              |
| staging  | staging  |                  |        |      |                              |
| prod     | prod     |                  |        |      |                              |

> 各 host 的 Address/User/IdentityFile 留空、靠 `--from-ssh-config` 從 `~/.ssh/config` 補；
> 實際位址在 deployment repo 的 inventory 維護，這份 spec 留在工具的通用 repo。

## 2. Checklist

| ID  | Category     | Check                                                       | Expected      | Command |
|-----|--------------|-------------------------------------------------------------|---------------|---------|
| C1  | pkg          | 目前可升級套件數量 = 0                                       | 0             | apt list --upgradable 2>/dev/null | wc -l |
| C2  | security     | 沒有未套用的 security 補丁（PASS 條件：grep 找不到 security 行） | 0             | apt list --upgradable 2>/dev/null | grep security | wc -l | tr -d " " |
| C3  | timestamps   | apt history.log 檔案存在                                    | 0             | test -f /var/log/apt/history.log |
| C4  | timestamps   | 上次套件升級在 90 天內                                       | 0             | sh -c 'find /var/log/apt/history.log -mtime -90 > /tmp/m.tmp; test -s /tmp/m.tmp' |
| C5  | service      | unattended-upgrades 服務在跑                                | ~active       | systemctl is-active unattended-upgrades |
| C6  | config       | unattended-upgrades 設定檔含 Allowed-Origins 啟用行          | present       | grep -q Allowed-Origins /etc/apt/apt.conf.d/50unattended-upgrades |
| C7  | separation   | prod 不應被 marker 標記為允許直接推送                       | 0             | test ! -f /etc/no-prod-direct-push |

> 預期值為具體數字 / 字串：C1/C2/C3/C4/C7=rc 0；C5=字串 `active`；C6=rc 0 (`present`)。
> All concrete values; no vague words.## 3. 證據收集

- 工具：`pilot verify docs/verification/os-patch-sla.md --inventory <inv.yaml>`
- 輸出格式：NDJSON
- 預期 row 數：7
- 範例輸出（dev box 套用前 → 預期 FAIL on C2/C6 等依主機狀態而定）：

```json
{"id":"C1","status":"pass","detail":"0 upgradeable packages"}
{"id":"C6","status":"fail","detail":"grep: /etc/apt/apt.conf.d/50unattended-upgrades: No such file or directory"}
```

## 4. PASS / FAIL 規則

- 全部 C1–C7 `status=pass` → **PASS**：host 套件 SLA 全綠
- 任一 row fail → **FAIL**，列出 fail id + actual + want
- C7 fail → 立即把 host 從 prod rollout 名單中隔離（手動或 auto-pause）

## 5. 例外與已知偏差

| ID | 例外內容 | 適用環境 | 期限 |
|----|---------|---------|------|
| C1 | 新裝完的 host 在 24h 內可能有 5–10 個 upgradeable | 全新VM | 24h 寬限期，由手動 |
| C3 | Critical CVE 補丁在紅色警戒時例外 ≤ 7 天 | OS vendor 公告 critical emergency | 公告結束即撤 |
| C6 | RHEL/CentOS 用 dnf-automatic 而非 unattended-upgrades；spec 不適用 | RHEL 系列 | 暫停支援 |

## 6. Playbook 對應

對應的 **apply** playbook：`playbooks/apply/os-patch-sla-apply.yml`（手寫）

對應的 verify playbook（`playbooks/verify/os-patch-sla.yml`）**已於 2026-07-17 棄用**（僅存檔參考，見該目錄 README.md）；驗收直接 `pilot verify` 吃本 spec 執行。

| Spec ID | Playbook task       | 備註 |
|---------|---------------------|------|
| C1      | `C1 — apt list upgradable count` | apt list |
| C2      | `C2 — security upgradeable count` | apt list + grep -security |
| C3      | `C3 — high cve within 30 days` | uptime check |
| C4      | `C4 — apt history mtime` | find /var/log/apt/history.log |
| C5      | `C5 — unattended-upgrades active` | systemd |
| C6      | `C6 — unattended-upgrades security origins` | grep config |
| C7      | `C7 — no prod direct push marker` | file existence |

> Apply playbook 區分 stage：
>   - `sandbox` group：每次跑都直接 `apt upgrade -y`
>   - `staging` group：runner 收到驗證通知才升
>   - `prod` group：必須先在 staging 完成至少 24h 觀察期才推；block/rescue 自動回滾

## 7. 把 FAIL 變 PASS 的 SOP

1. **先在 sandbox 驗證**：
   ```bash
   ansible-playbook -i inventory-sandbox.yaml \
       playbooks/apply/os-patch-sla-apply.yml \
       -e patch_stage=sandbox --check --diff
   ansible-playbook -i inventory-sandbox.yaml \
       playbooks/apply/os-patch-sla-apply.yml \
       -e patch_stage=sandbox
   ```
2. **推 staging**（仍可手動；`pilot spec --apply` 已於 2026-07-17 棄用，
   套用一律走手寫 apply playbook）：
   ```bash
   ansible-playbook -i inventory-staging.yaml \
       playbooks/apply/os-patch-sla-apply.yml \
       -e patch_stage=staging
   ```
3. **觀察 24h**：再跑一次 `pilot verify`，確認 C2/C3 都 PASS。
4. **推 prod**（promote gate 在 playbook 本身：`confirm_prod` + staging 佐證時效）：
   ```bash
   ansible-playbook -i inventory-prod.yaml \
       playbooks/apply/os-patch-sla-apply.yml \
       -e patch_stage=prod -e confirm_prod=true \
       -e staging_attested_within_hours=24
   ```
   沒帶 `confirm_prod=true`、或 staging 佐證超過時效，playbook 的
   pre_tasks assert 會直接擋下（fail-closed），不會套用。
5. **事後回填 SQLite**：對 prod inventory 再跑一次 `pilot verify
   docs/verification/os-patch-sla.md -i inventory-prod.yaml`，
   `spec_checkpoints.status` 翻成 `verified-pass`。

## 8. Commit / 版控

- ✅ 進版控：`docs/verification/os-patch-sla.md`、`playbooks/apply/os-patch-sla-apply.yml`（`playbooks/verify/os-patch-sla.yml` 已於 2026-07-17 棄用，不再更新）
- ❌ 不進版控：`.verification/*.md`、`.verification/*.ndjson`、本地 inventory.yaml、`~/.local/share/pilot/history.db`

## 9. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-06-30 | v1.0 | 初版（C1–C7）| pilot |
