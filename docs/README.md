# docs/

> 從這裡開始：**讀 spec 範例、用 spec template、讀現有 runbook、開發 ansible playbook**。

## 入口地圖

| 你想做什麼 | 從這裡開始 |
|----------|-----------|
| 第一次接觸 pilot 的 spec-driven 工作流 | [README.md §「Spec-driven 工作流」](../README.md#-spec-driven-工作流寫需求--套用--驗證) |
| **寫第一份 spec** | [`verification-spec-template.md`](./verification-spec-template.md)（先 copy 再改） |
| 讀一份已有的 spec 學作者風格 | [`verification/hello-localhost.md`](./verification/hello-localhost.md)（3 row 最小）、[`verification/os-patch-sla.md`](./verification/os-patch-sla.md)（stage-aware 範例） |
| **寫 apply playbook** | 範本在 `playbooks/apply/pam-oidc-sshd-apply.yml` 跟 `playbooks/apply/os-patch-sla-apply.yml`（必含 `-e` vars + `block/rescue` + stage gate） |
| **跑完整閉環** | 從 `verification/<name>.md` → `apply/<name>-apply.yml` → 對 inventory 跑 ansible-playbook | 
| 看一份完整的「spec → apply → verify → 失敗 → 修」| [`runbooks/pam-oidc-sshd.md`](./runbooks/pam-oidc-sshd.md) |
| spec-to-spec supplier pattern（同一 host 多 spec 如何 cross-check）| [`runbooks/sso-composition.md`](./runbooks/sso-composition.md) |
| 開發 ansible playbook 的心法 | [`ansible-playbook-development.md`](./ansible-playbook-development.md) |
| 跑測試 | [`../TESTING.md`](../TESTING.md) |

## 怎麼用各目錄

### `verification/` — Spec 範本（給人讀 + 給 LLM 讀）

每檔是**一條功能需求的合約**。寫 spec 詳 `verification-spec-template.md`。
驗證：「apply 完之後主機有沒有符合 spec？用 `pilot verify` 跑」。

- `hello-localhost.md` — 3 row smoke test
- `pam-oidc-sshd.md` — Keycloak Device Flow + lockout safety
- `os-patch-sla.md` — Critical 15d / High 30d / Medium 90d policy

### `runbooks/` — 從 spec 跑完 apply → verify 的完整記錄

每一份是「**真實跑過**一遍 SOP」的文檔：每一條命令、每一個截錄的 `PLAY RECAP`、
SQLite 寫入、恢復 SOP 都進來。**讀 runbook 比看範例更有教學價值** — 你會看到
實際碰撞的 bug 與解法。

### `ansible-playbook-development.md`

不是命令手冊，是**心法**：spec 為什麼先寫、idempotency 三原則、spec-driven vs 純
`ansible-playbook` 的選擇細節。

## 命名 / layout 約定

- spec 檔：`docs/verification/<verb-or-feature>.md`（例：`pam-oidc-sshd.md`,
  `os-patch-sla.md`, `disable-root-ssh.md`）
- apply playbook：`playbooks/apply/<name>-apply.yml`（**必加 `-apply` 後綴**跟
  inspect playbooks 區分）
- inspect playbook：`playbooks/verify/<name>.yml`（generator 產的，不要手寫）
- runbook：`docs/runbooks/<name>.md`（每份 spec 對應一份 runbook 是合理 expectation）

## 跟 `.gitignore` 的協作

`inventory*.yaml`、`.verification/`、`playbooks/generated/`、SQLite DB
都不進版控。本地跑產物、spec 與 apply 是 source of truth 入版控。
詳見 [`../TESTING.md`](../TESTING.md) 的「Repository layout & version control policy」。
