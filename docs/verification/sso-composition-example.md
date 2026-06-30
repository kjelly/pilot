# Verification Spec — sso-composition (範例：spec 之間的 supplier 關係)

> 版本：v1.0
> 對齊規範：pilot 通用 spec supplier 模式（把 N 條獨立 spec 的 row 用「supplier 變數」接起來）
> 維護者：sre

> 本檔**是範例**，不是真正要套的 spec。它示範一個 pattern：要驗證某條 service
> 確實在用某個 IdP 時，spec 之間如何引用。

## 1. 目標系統

| Hostname | Group | Address | User | Port | IdentityFile |
|----------|-------|---------|------|------|--------------|
| test-vm  | all   |         |      |      |              |

## 2. Checklist

| ID  | Category   | Check                                                                        | Expected | Command |
|-----|-----------|-----------------------------------------------------------------------------|----------|---------|
| C1  | sso        | 這台主機的 `pam-oidc-sshd` 套件裝起來後，config.yaml 內的 issuer 能在 Keycloak discovery 找到 | 0        | sh -c 'curl -fsS -o /dev/null -w "%{http_code}" "https://$(awk "/^issuer:/ {print \\$2}" /etc/kc-ssh-pam/config.yaml)/.well-known/openid-configuration"' |
| C2  | sso        | 上一步拿到的 discovery 有 `issuer` 欄位，且值與 config.yaml 內一致                              | 0        | sh -c 'ISSUER=$(awk "/^issuer:/ {print \\$2}" /etc/kc-ssh-pam/config.yaml) && curl -fsS https://$ISSUER/.well-known/openid-configuration \| grep -q "\"issuer\": \"$ISSUER\""' |
| C3  | sso        | config.yaml 的 `client_id` 在 Keycloak realm 內已存在                                              | 0        | sh -c 'CLIENT=$(awk "/^client_id:/ {print \\$2}" /etc/kc-ssh-pam/config.yaml) && REALM=$(basename $(dirname $(awk "/^issuer:/ {print \\$2}" /etc/kc-ssh-pam/config.yaml))) && grep -q "\"clientId\": \"$CLIENT\"" <(curl -fsS https://$(dirname $(awk "/^issuer:/ {print \\$2}" /etc/kc-ssh-pam/config.yaml))/realms/$REALM/.well-known/uma2-configuration 2>/dev/null)' |

## 3. 證據收集

- 工具：`pilot verify docs/verification/sso-composition-example.md -i inventory.yaml`
- 格式：`.verification/sso-composition-example-<UTC>.{ndjson,md}`

## 4. 解釋（為什麼這不是「真正 deploy 用的 spec」）

本檔示範「**spec composition**」這個 pattern — 即一條 spec 的 row 引用其他 spec 留下的
產物：

- **C1** / **C2** 是 `pam-oidc-sshd` 的 apply playbook 寫進 `/etc/kc-ssh-pam/config.yaml` 的 `issuer:`
  行；本 spec 只**讀**出來再對 Keycloak 端做 round-trip
- **C3** 進一步驗證 config.yaml 的 `client_id` 是 Keycloak realm 真的認得（不是寫死一個 client）

這示範「`apply/` playbook 與 `verify/` spec 可以**雙向 cross-reference**」 — 同一台 host 上的多條
spec 不是各自獨立：它們之間透過**檔案** + **服務**自然耦合，spec 寫的人應該把耦合寫進
自己的 row 而不是忽略。

> 真正要 deploy 時，apply playbook (`playbooks/apply/pam-oidc-sshd-apply.yml`) 的
> `KEYCLOAK_ISSUER` 變數要符合這條 spec 的 issuer 抽取邏輯，否則 C1 會 fail —
> 這就是 spec → playbook → spec 的**閉環**，跟「寫 spec 的時候順便檢查 service 之間相容性」。

## 5. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-06-30 | v1.0 | 初版（supplier 變數示範，非 deploy 規格）| pilot |
