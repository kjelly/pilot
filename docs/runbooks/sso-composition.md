# Runbook — sso-composition (spec-to-spec supplier pattern)

> Status: **example demonstrated**。ssocomposition 概念已落地成
> `docs/verification/sso-composition-example.md`：一條 verify-only spec
> 把另一條 spec 的 apply 產物（`/etc/kc-ssh-pam/config.yaml`）當作檢查點，
> 反向對 Keycloak discovery 對應。本 runbook 解釋為什麼這樣寫、怎麼讀它。

> 撰寫日期：2026-06-30 (UTC)
> 對齊規範：見 `docs/verification/sso-composition-example.md`、`pam-oidc-sshd.md`、`core-infra.md`
> 維護者：sre

---

## 0. 動機：spec 之間不是孤島

> 一台 host 在同一時間跑 N 條 spec：consumer / provider / 應用層健康檢查。
> 它們之間**透過 host 上的檔案 + 服務自然耦合**。spec 寫得不引用這些耦合，
> 等於強迫人用眼睛交叉比對 — 一旦 spec 多了就崩。

**真實範例**：`pam-oidc-sshd.md` 的 apply playbook 寫 `/etc/kc-ssh-pam/config.yaml`，
裡面有 `issuer: https://keycloak.example/realms/eng`。如果 Keycloak 端**改了** issuer，
本機**應該偵測到** — 而不是還能 SSH 登入但 OIDC discovery 一直 200。

`docs/verification/sso-composition-example.md` 就是把這條 cross-check 寫進 spec：

- **C1** 反向讀 config.yaml 的 `issuer:`、curl discovery 端點、確認能達 200
- **C2** 再深一步：檢查 discovery 端點回傳的 `issuer:` 跟 config.yaml 內**完全一致**——形成**閉環**
- **C3** 確認 config.yaml 的 `client_id` 在 Keycloak realm 存在

---

## 1. 怎麼讀這條 example spec

該 spec 的 row Command 都有點技巧：

```
C1: sh -c 'curl -fsS -o /dev/null -w "%{http_code}" \
      "https://$(awk "/^issuer:/ {print \$2}" /etc/kc-ssh-pam/config.yaml)/.well-known/openid-configuration"'
```

這個 row 在做的事：
1. `awk` 從 `/etc/kc-ssh-pam/config.yaml` 抽出 `issuer:` 行後的值（playbook apply 寫進去的）
2. 用抽出的值組出 discovery endpoint URL
3. `curl` 驗證 endpoint 是 200
4. Expected `0`（curl 退出碼）

> 這就是 **「spec supplier 變數」** 的具體應用：把另一條 spec 的產物當作這條 spec 的輸入。

---

## 2. 怎麼寫自己的跨 spec 檢查

三步：

### Step 1 — 設計 stage

在腦中想清楚：
- 主機上的哪一份檔（或哪一個服務端點）由 spec A 的 apply 寫入？
- spec B 的 verify 應該讀哪一個欄位？
- spec B 應該對遠端做什麼驗證？

### Step 2 — 寫 row

範本（讀 config 檔 + 對外部對應）：

```
| ID | sso | config.yaml 的 issuer 在 Keycloak OIDC 存在 | 0 |
      sh -c 'curl -fsS https://$(awk "/^issuer:/{print \$2}" /etc/my-app/config.yaml)/.well-known/openid-configuration'
```

**注意**：spec 字串裡的 `\|` 在 markdown table cell 內會被視為欄位分隔；用 verbatim
反斜線脫出或拆 column（parser 自動接 — 見 internal/spec/parser.go 的 `len(cols) > 5` join 邏輯）。

### Step 3 — apply playbook 配套

apply playbook 寫進去的檔案格式要**穩定**：yaml 的 key:value pattern、no comment drift、
不可被使用者手動編輯（不然 spec 讀到不同 layout 就壞）。

> 建議 spec 用 `awk` 讀不依賴 yaml 解析器，理由：awk 是 POSIX、host 一定有，
> 每次讀都得到**同一條**輸出；python-yaml parsing 風險更高（key 大小寫 / alias / 順序）。

---

## 3. 跟「secret 進版控」政策的關係

> 核心原則：spec 與 spec-runbook **不**直接放 secret / token。
> 但 spec row Command 可能引用 `${KEYCLOAK_ISSUER}` — 這是 env var 不是 secret，OK。

- `${KEYCLOAK_ISSUER}`、`${KEYCLOAK_TOKEN}` 從環境帶入，跑 verify 前 `export`。
- Apply playbook 的 vault 機制（`-e @~/.vault/keycloak-sandbox.yaml`）
  注入 secret；spec **看見不到**這些 vault 檔，只看見 apply 留下來的結果。

---

## 4. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|------|------|------|--------|
| 2026-06-30 | v1.0 | 初版 | pilot |
