# docs/

> pilot 的實際工作流是 **自然語言需求 → Codex/Claude authoring spec + apply
> playbook → pilot 確定性 lint/test/deploy/verify**。外部 coding agent 負責把
> 需求落成 repo 內可 review 的產物；pilot runtime 不呼叫 LLM，而是用
> `vm-target`/`docker-target`、TUI `deploy`/`reconcile`/`edit` 與真實證據解決「如何正確
> 交付軟體」。本目錄從這裡開始：**讀 spec 範例、用 spec template、讀現有
> runbook、開發 ansible playbook**。

## 入口地圖

| 你想做什麼 | 從這裡開始 |
|----------|-----------|
| 第一次接觸 pilot 的 coding-agent-assisted、spec-driven 工作流 | [README.md §「Spec-driven 工作流」](../README.md) |
| 請 Codex/Claude 從需求新增功能 | 先讀 [`../AGENTS.md`](../AGENTS.md) 的 authoring model，再依序產出 spec、apply playbook、regression test 與 actual-run evidence |
| **寫第一份 spec** | [`verification-spec-template.md`](./verification-spec-template.md)（先 copy 再改） |
| 讀一份已有的 spec 學作者風格 | [`verification/hello-localhost.md`](./verification/hello-localhost.md)（3 row 最小）、[`verification/os-patch-sla.md`](./verification/os-patch-sla.md)（stage-aware 範例） |
| **寫 apply playbook** | 範本在 `playbooks/apply/pam-oidc-sshd-apply.yml` 跟 `playbooks/apply/os-patch-sla-apply.yml`（必含 `-e` vars + `block/rescue` + stage gate） |
| **跑完整閉環** | 從 `verification/<name>.md` → `apply/<name>-apply.yml` → 對 inventory 跑 ansible-playbook | 
| **保存 actual-run evidence** | [`actual-run-evidence.md`](./actual-run-evidence.md)：candidate revision、raw artifact、sanitized summary 與文件內容預算 |
| 看一份完整的「spec → apply → verify → 失敗 → 修」| [`runbooks/pam-oidc-sshd.md`](./runbooks/pam-oidc-sshd.md) |
| spec-to-spec supplier pattern（同一 host 多 spec 如何 cross-check）| [`runbooks/sso-composition.md`](./runbooks/sso-composition.md) |
| **管 FreeIPA 使用者/權限（名冊與機密不進 git）** | [`runbooks/freeipa-identity.md`](./runbooks/freeipa-identity.md)；已部署後以 `pilot reconcile` 調和 roster |
| **把 FreeIPA NFS clients 接到 NetApp、Synology 或 QNAP** | [`external-nfs-provider-integration.md`](./external-nfs-provider-integration.md)；未經硬體實跑的 provider readiness 與安全邊界指南 |
| **開啟 FreeIPA 目錄服務（389-ds）稽核日誌** | [`runbooks/freeipa-389ds-audit-log.md`](./runbooks/freeipa-389ds-audit-log.md) |
| **DNS 服務自訂內部網域（網域資料不進公開 git）** | [`runbooks/core-infra-provider-dns-zones.md`](./runbooks/core-infra-provider-dns-zones.md) |
| **部署中央 SIEM 日誌接收端（rsyslog）** | [`runbooks/log-server.md`](./runbooks/log-server.md) |
| **主機 auditd 稽核規則 + 轉送日誌到 SIEM** | [`runbooks/audit-log-forwarding.md`](./runbooks/audit-log-forwarding.md) |
| **Wazuh 中央伺服器（FIM/who-data 告警引擎 + CVE 弱點掃描；Docker 部署）** | [`runbooks/wazuh-manager.md`](./runbooks/wazuh-manager.md) |
| **Wazuh agent：檔案完整性監控(FIM) + auditd who-data** | [`runbooks/wazuh-fim.md`](./runbooks/wazuh-fim.md) |
| **S3 相容物件儲存（SeaweedFS）** | [`runbooks/seaweedfs-s3.md`](./runbooks/seaweedfs-s3.md) |
| **跨主機通用備份到 S3（restic），含 FreeIPA 災難復原(DR)演練** | [`runbooks/restic-backup.md`](./runbooks/restic-backup.md) |
| **跨機房指標彙總 + 中央告警（Prometheus + Thanos 全局查詢 + Alertmanager）** | [`runbooks/metrics-alerting.md`](./runbooks/metrics-alerting.md) |
| **觀測畫面（Grafana + Loki 看 Prometheus/log-server 資料）** | [`runbooks/dashboard.md`](./runbooks/dashboard.md) |
| 開發 ansible playbook 的心法 | [`ansible-playbook-development.md`](./ansible-playbook-development.md) |
| 跑測試 | [`../TESTING.md`](../TESTING.md) |

## 怎麼用各目錄

### `verification/` — Spec 範本（coding agent 起草 + reviewer 確認）

每檔是**一條功能需求的 acceptance contract**。Codex/Claude 可以依自然語言
需求直接起草，但 spec 必須先被 lint、review 並確認驗收行為，之後才依它撰寫
apply playbook；不准為了讓既有實作過關而靜默放寬 Expected。格式詳
`verification-spec-template.md`。
驗證：「apply 完之後主機有沒有符合 spec？用 `pilot verify` 跑」。

- `hello-localhost.md` — 3 row smoke test
- `pam-oidc-sshd.md` — Keycloak Device Flow + lockout safety
- `os-patch-sla.md` — Critical 15d / High 30d / Medium 90d policy

### `runbooks/` — 從 spec 跑完 apply → verify 的完整記錄

每一份是「**真實跑過**一遍 SOP」的文檔：每一條命令、每一個截錄的 `PLAY RECAP`、
SQLite 寫入、恢復 SOP 都進來。**讀 runbook 比看範例更有教學價值** — 你會看到
實際碰撞的 bug 與解法。純散文，不會被任何 `pilot` 指令解析執行。

### `topologies/` — `vm-target topology` 用的宣告式多 VM spec（`.yaml`）

跟 `verification/*.md` 一樣是機器可讀的輸入，但格式是 `TopologySpec`
（`internal/vmtarget/topology.go`）：宣告一個多 VM 情境裡每個 node 的
provisioning 參數、`groups:`（給 `RenderGroupedInventory` 用，也是
`topology test --verify <spec>.md=<group>` 的 limit 值來源）、`wire:`
（互相寫 `/etc/hosts` 的對象）。由 `pilot vm-target topology
up/down/status/inventory/snapshot/rollback/reset/test` 直接讀取執行，
不是給人讀的文件——每份通常對應一份 `runbooks/*.md`（描述同一場景的
prose SOP），但兩者是分開維護的機器輸入 vs 人類文件。

- `minimal-poc-topology.yaml` ↔ `runbooks/minimal-poc-architecture.md`
- `freeipa-ha-topology.yaml` ↔ `runbooks/freeipa-server-replica-ha-drill.md`

### `ansible-playbook-development.md`

不是命令手冊，是**心法**：spec 為什麼先寫、idempotency 三原則、spec-driven vs 純
`ansible-playbook` 的選擇細節。

## 命名 / layout 約定

- spec 檔：`docs/verification/<verb-or-feature>.md`（例：`pam-oidc-sshd.md`,
  `os-patch-sla.md`, `disable-root-ssh.md`）
- apply playbook：`playbooks/apply/<name>-apply.yml`（**必加 `-apply` 後綴**跟
  inspect playbooks 區分）
- inspect：不再有獨立 playbook——`pilot verify docs/verification/<name>.md` 直接吃 spec 執行
  （`playbooks/verify/` 已於 2026-07-17 棄用，見該目錄 README.md）
- runbook：`docs/runbooks/<name>.md`（每份 spec 對應一份 runbook 是合理 expectation）
- topology spec：`docs/topologies/<name>-topology.yaml`（多 VM 情境才需要；單機
  spec 不用）

## 跟 `.gitignore` 的協作

`inventory*.yaml`、`.verification/`、`playbooks/generated/`、SQLite DB
都不進版控。本地跑產物不進版控；經 review 的 spec、apply playbook 與
regression test 才是可追溯的 repo 產物。`playbooks/generated/` 只是診斷輸出，
不是正式 apply 來源。
詳見 [`../TESTING.md`](../TESTING.md) 的「Repository layout & version control policy」。
