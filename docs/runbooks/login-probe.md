# Runbook — login-probe（外部 SSH/PAM 登入探測與主機 I/O 告警）

> 對應 issue：GitHub kjelly/pilot#11
> 對應 spec：[`docs/verification/login-probe.md`](../verification/login-probe.md)、
> [`docs/verification/prometheus.md`](../verification/prometheus.md) C20–C24、
> [`docs/verification/alertmanager.md`](../verification/alertmanager.md) §1.7/C10
> 維護者：sre

## 0. 一句話目標

每站一台 `pilot-login-probe` 以最小權限 FreeIPA canary 帳號，每 60 秒從主機外部真實
SSH 登入每台 FreeIPA client，把「卡在哪一個 stage」寫成 metrics；Prometheus 以確定性
規則對 PAM account 拒絕、認證失敗、登入卡住、host key 不符、連線失敗、I/O stall、
磁碟延遲與監控資料缺口分別告警，Alertmanager 以 inhibit 規則避免同一個根因重複通知。

## 0.5 目前有效的事實快照

| 項目 | 值 |
|---|---|
| 最新驗證 | 2026-10-19；login-probe 三 VM candidate `121ee4b`（tree `9ede0f3b7f0a5952cb4ef6756428f90315bf8c90`）；Prometheus tagged runtime candidate `0294b1a`（tree `2d3dc96f0ef9cd401a144c626810b3fa04182f59`），最終 test-only `5adeec0`（tree `0909aa87fba58960a66f472500e78f900caad39d`）。各自使用乾淨隔離 checkout，範圍與檔案指紋見 evidence。 |
| 目標與 inventory | `r80-ipa`（AlmaLinux 9.8）屬 freeipa-server；`r80-mon`、`r80-target`（Ubuntu 24.04）屬 freeipa-client/host-monitoring；login-probe={r80-mon}。由 vm-target topology inventory 讀實際集合，對齊決定 A。此輪三機沒有 Prometheus/Alertmanager group；新 Prometheus 修正另由 pinned container 有效態測試驗證。 |
| 外部狀態 | 既有 dev-lite cache 保持 running/healthy；一次性 vault 僅含 `ipa_admin_password`、`node_exporter_basic_auth_password`，parent 0700/file 0600。node_exporter 1.12.1、IPA 4.13.4；base image、binary、topology 指紋見 evidence。三台專用 VM 已清除，未動其他 session 的 VM。 |
| Fresh chain | 121ee4b 的 L1–L6 rc=0：L3/L4 三機 failed=0；login-probe 14 PASS/0 FAIL/0 SKIP；L6 三機 changed=0；tagged scenarios 完成後再次 14/14 PASS。 |
| Tagged activation | 真實 systemd 驗證 C3 target 增刪/user/interval、90s interval、磁碟新但 daemon 舊的無 changed 修復、中斷重試、health 失敗 rollback/retry、C1 loaded binary version、C6/C12 live executable/hardening；full apply 與重跑 changed=0。 |
| Prometheus | C23/C24 真 Ansible selection + pinned Prometheus API 驗證 threshold 更新、各自停用/重新啟用、磁碟新但記憶體舊的修復、無 restart 的 changed=0 reload 與 data mount 保留；這是本次新修正的 container 範圍，並非重新跑完整 Thanos/告警拓樸。 |
| Repository checks | aa1e69b 全庫 race 59 packages、rc=0；0294b1a mandatory suite 27 PASS/0 SKIP、rc=0；5adeec0 focused race PASS、pinned lint 0 issues、build/spec/shell/tag/secret/prerequisite/rescue guards PASS。最終 CI 另作 ready gate。 |
| Evidence | [本次修正與驗證](../evidence/login-probe/2026-10-19-5adeec0.md)。[歷史四 VM 告警演練](../evidence/login-probe/2026-10-16-8b9d3ca.md) 僅屬其原 candidate，本次未重跑；[classifier captures 來源](../evidence/login-probe/2026-10-13-phase0-ssh-capture.md) 保留獨立追溯。 |

## 1. 為什麼

`sssd.service` 是 `active` 並不代表使用者登得進去：SSSD 的某個 process 卡住、HBAC
規則被改、帳號被停用、儲存裝置卡 I/O，都會讓登入失敗或卡住，而 service 狀態照樣是
綠的。唯一能回答「現在 SSH 登得進去嗎」的是真的從外部登入一次。`sssctl user-checks`
可以在主機上重現 PAM account 判斷，但它是輔助診斷，不是 availability signal（它不經過
sshd、不經過網路、也不會卡在 SSSD 的 ssh responder）。

探測器不自己實作 SSH：它 spawn 系統 OpenSSH，以 `-F` 指定固定的 `ssh_config`，host key
一律由 SSSD 向 FreeIPA 查（`ProxyCommand /usr/bin/sss_ssh_knownhostsproxy`、
`StrictHostKeyChecking yes`），跟 `pilot-access-gateway` 是同一條信任路徑，不在 apply 時
用 `ssh-keyscan` 抓快照（AGENTS.md §5.9）。

## 2. 部署

前提：探測主機已套用 `freeipa-client-apply.yml` 與 `host-monitoring-apply.yml`
（contract 的 sameHosts 依賴；playbook 的 pre_tasks 會擋）。

```bash
# 拋棄式 topology（本 runbook 驗證時的作法）
pilot vm-target topology up --topology docs/topologies/login-probe-topology.yaml
pilot vm-target topology inventory --topology docs/topologies/login-probe-topology.yaml > <inv>
scripts/build-login-probe.sh            # pilot-cli image 已內建，不在 image 內才需要
ansible-playbook -i <inv> playbooks/test/login-probe-chain.yml -e @<vault.yaml>

# 真實環境：單一元件
ansible-playbook -i <inventory> playbooks/apply/login-probe-apply.yml --check --diff
ansible-playbook -i <inventory> playbooks/apply/login-probe-apply.yml
```

C1/C2/C3/C6/C7/C12 的 tagged 更新會走相同的 config 驗證、systemd reload、activation 與 health 鏈。root-owned activation record 綁定 binary/config/unit hash 與 InvocationID；磁碟已是新內容但 daemon 仍舊時，重跑仍會修復。只有新 process 寫出較新的 metrics generation 後才記錄成功，失敗會還原並可重試；無變更 C7 仍驗證實際 metrics 檔案與 metric 存在。C4/C5 的 key/ssh_config 則由每次 SSH 讀取。Prometheus 的 C23/C24 會驗證並 reload 目前規則，並確認新的成功 reload timestamp；無變更重跑維持 changed=0。

apply 會在探測主機產生 ed25519 金鑰對（除非 vault 提供 `login_probe_ssh_private_key`），
私鑰 `0600` 只屬於 `pilot-login-probe` 帳號，公鑰留在
`/etc/pilot/login-probe/id_ed25519.pub`。**接著要把公鑰登記到 canary 帳號**：正式環境走
freeipa-identity roster（`users[].ssh_keys`），並加一條只允許 `sshd`、目標是被探測主機的
HBAC 規則（範例見 `playbooks/apply/freeipa-identity.roster.example.yaml` 的
`pilot-login-canary` 使用者與 `login-probe-canary` 規則）；canary 不可掛任何 sudo 規則（spec C9，apply 的 Step 17 也會擋）。測試環境用
`playbooks/test/fixtures/login-probe-fixtures.yml`。公鑰還沒登記前，所有 target 都會是
`stage=auth`——apply 不會因此失敗，Step 16 的 health round 會把每台的 stage 印出來。

驗收：

```bash
pilot verify docs/verification/login-probe.md -i <inventory> -l login-probe
pilot verify docs/verification/prometheus.md -i <inventory> -l prometheus
pilot verify docs/verification/alertmanager.md -i <inventory> -l alertmanager
```

## 3. 告警處置

第一步永遠先在探測主機跑一輪單次探測，看每台 target 停在哪個 stage：

```bash
sudo -u pilot-login-probe /usr/local/bin/pilot-login-probe probe \
    --config /etc/pilot/login-probe/config.yml --json      # exit 2 = 至少一台失敗
```

| 告警 | stage | 先看什麼 |
|---|---|---|
| `PilotLoginProbeAccountDenied`（critical） | `account`：sshd 已接受 key，PAM account 拒絕 | 在 target 上 `timeout 20 sudo sssctl user-checks -a acct -s sshd <canary>`（輸出的 `pam_acct_mgmt:` 在 **stderr**，結束碼一律 0；`pilot diagnose` 的 login 檢查會解析它）；FreeIPA 上 HBAC 規則是否停用/移除、帳號是否被 `user-disable` |
| `PilotLoginProbeAuthFailed`（critical） | `auth`：key 被拒 | target 上 `sss_ssh_authorizedkeys <canary>` 是否回傳探測主機的公鑰；剛換過 key 見 §4 |
| `PilotLoginProbeLoginStalled`（critical） | `timeout`：連上了但登入卡住 | target 上 `ps -o pid,stat,comm -C sssd_be,sssd_pam,sssd_nss`（`T`=stopped）、`journalctl -u sssd`；同時看 `HostIOStall`/`HostDiskLatencyHigh`。這時 `sssctl user-checks` 本身也會卡住（2026-10-13 實測 `sssd_be` 被凍結時 20 秒逾時），一律包 `timeout 20` 執行 |
| `PilotLoginProbeHostKeyMismatch`（warning） | `hostkey` | 主機是否重裝/重產 host key 而沒重新 enroll；名字是否指到別台機器 |
| `PilotLoginProbeSessionFailed`（warning） | `session` | 認證與 account 都過了，指令或 session 失敗（home、shell） |
| `PilotLoginProbeTransportFailed`（warning） | `transport` | sshd、防火牆、DNS。node_exporter 也抓不到的主機不會觸發這個告警，只會有 `HostDown` |
| `PilotLoginProbeStale`（warning，`action_required`） | — | 探測主機 `systemctl status pilot-login-probe`。它觸發時，**這台 probe**（`probe_host`）的其他 `PilotLoginProbe*` 會被 inhibit，其他 probe 的告警不受影響 |
| `HostMetricsMissing`（warning，`action_required`） | — | SSH 登得進去但 `up{job="node"}==0`：node_exporter 停了、9100 被擋、或 Basic Auth 不符。它觸發時同主機的 `HostDown{job="node"}` 會被 inhibit（主機還活著）；probe 單輪失敗或重啟不會讓它中斷（`keep_firing_for`），所以 node_exporter 恢復後最多約 6m15s 才 resolve（實測 5m40s） |
| `HostIOStall` / `HostDiskLatencyHigh` / `HostDiskQueueDeep`（warning） | — | `node_disk_*` 依 device 拆開看；EL9 預設沒有 PSI，只會有後兩者 |
| `HostPSIUnavailable`（info） | — | 這台主機沒有 PSI metrics，`HostIOStall` 不會在這台觸發 |

不要用 `sss_cache` 讓告警「消失」：需要清快取才正確的結果要當 bug 追根因（AGENTS.md §5.9）。

## 4. canary 金鑰輪替

SSSD 從**使用者快取**提供 authorized keys：FreeIPA 上換掉 canary 的公鑰後，已經查詢過
canary 的主機會繼續用舊 key，直到該主機的快取項目更新。2026-10-13 實測（`entry_cache_timeout`
預設 90 分鐘）：`lp-target-el` 在快取項目建立 46 分鐘後的第一次探測仍回 `auth`、下一輪
（1 分鐘後）就恢復——與 SSSD 預設 `entry_cache_nowait_percentage=50`（項目過了一半壽命後的
查詢會觸發背景更新）一致；`lp-target` 則在一次 `sssctl user-checks`（PAM account 檢查）後的
下一輪就恢復。換句話說，探測每分鐘都在查詢 canary 的情況下，直接換 key 最多約 45 分鐘
（`entry_cache_timeout` 的一半）會是 `auth`，這段期間 `PilotLoginProbeAuthFailed` 會觸發。
所以輪替要分兩步：

1. 把新公鑰**加在舊公鑰旁邊**登記到 canary（roster 的 `users[].ssh_keys.values` 同時列兩把）。
2. 等至少 `entry_cache_timeout` 的一半（預設 45 分鐘；保守起見等滿 `entry_cache_timeout`），再換探測主機的私鑰（vault 的 `login_probe_ssh_private_key`
   後重新 apply），確認所有 target 回到 `ok` 後才從 roster 移除舊公鑰。

> 這個兩步流程在 2026-10-13 只驗證了「直接替換會造成 auth 失敗直到快取更新」的那一半；
> 兩把 key 並存的完整流程尚未在 topology 上實跑，執行前先在 sandbox 走一次。

## 4.5 主機退役（`pilot host decommission`）

探測器的 target 清單是 apply 時從 inventory 渲染的，退役一台被探測的主機時，
`pilot host decommission` 會自動加一個 `login-probe-targets` central step（host-decommission
spec §19 的「仍會連線到退役主機的告警目標」）：在每台 login-probe 主機上以
`-e login_probe_exclude_targets=[<退役主機>]` 重新套用 `login-probe-apply.yml`，用的是 login-probe
主機自己的 stage（staging/prod 需要對應的 `--confirm-*`），不需要退役主機本身還連得上；
`hosts.yml` 不會被提早修改。plan 只列步驟，不跑任何 playbook；apply 時先用唯讀的
`playbooks/decommission/login-probe-target-query.yml` 確認是否還列在清單上，已經不在就跳過，
最後 verify 再查一次，任何一台 login-probe 主機沒有回報都算失敗，不會當成已清除。

這個 step 會像 `pilot deploy` 一樣帶 workspace 的 `.vault/main.yaml`（`-e @<path>`，只傳檔案路徑），
因為 `login-probe-apply.yml` 的 gate 需要 `node_exporter_basic_auth_password`。

退役 login-probe 主機**本身**目前不支援（plan 會因 `login-probe` 沒有 decommission provider
而 fail closed，跟 prometheus/detection-engine 主機一樣）。

## 5. 營運副作用

- 每台 target 每天多 1440 次 canary 登入（`interval=60s`）。sshd journal、
  `audit-log-forwarding`、Wazuh 都會看到；建議在 SIEM 端對 `pilot-login-canary` 的
  `Accepted publickey`/`session opened` 降級，但保留 `Access denied ... by PAM account
  configuration` 與 `Invalid user`（那正是探測要抓的失敗）。降噪規則不在本次交付內。
- 第一次登入時 `pam_mkhomedir` 會在每台 target 建 `/home/<canary>`。
- canary 私鑰外洩的影響：可以用無 sudo 帳號登入被探測主機。FreeIPA 公鑰的 `command=`
  等 options **對 SSSD client 無效**（實測 `sss_ssh_authorizedkeys` 不傳遞 options），
  所以限制只能靠只開 sshd 的 HBAC 規則、無 sudo，必要時在 target 加 sshd `Match User`
  drop-in（本次未實作）。
- 停用 `sssd.service` 的 Ubuntu client 上，連 root 的 key 登入都會卡到 sshd
  `LoginGraceTime`（120 秒）——演練 SSSD 故障時，先在 target 上排一個會自動復原的
  `systemd-run --on-active=...` timer（注意 transient timer 預設精準度是 1 分鐘）。

## 6. 已知限制

- 第一版 opt-in（`site.include: false`），但已 import 進 `playbooks/site.yml`，主機被加進
  `login-probe` group 後全站部署會套用。
- 目標名稱必須是小寫 inventory 名稱（`probe_target` 要等於 Prometheus 的
  `pilot_host`，否則 login 告警永遠對不上主機）；自動展開時 playbook 會 fail closed。
  明確設定 `login_probe_targets` 時 playbook 無法檢查：`name=` 必須寫成該主機的
  inventory 名稱，否則 `HostMetricsMissing` 的 join，以及「主機掛掉時不送
  `PilotLoginProbeTransportFailed`」的排除，都會靜默失效（`alertmanager.md` §1.7）。
- node scrape target 要由 inventory 的 `host-monitoring` group 自動展開（帶 `pilot_host`）。
  用 `node_exporter_targets` 明確列 target 時沒有 `pilot_host`，`HostMetricsMissing` 不會觸發，
  主機掛掉時也會多送 `PilotLoginProbeTransportFailed`（`alertmanager.md` §1.7 的前提）。
- `login_probe_stale_seconds` 至少要 3 × `prometheus_scrape_interval`，`host_metrics_missing_for` 最多 9m，
  `host_metrics_missing_success_window`（預設 150s）+ 15s 不得超過 `host_metrics_missing_for`：這三項由
  `prometheus-apply.yml` 檢查。每台 login-probe 主機的 `login_probe_interval` + `login_probe_total_timeout`
  + 15s + 2 × `prometheus_scrape_interval` 不得超過時間窗：`prometheus-apply.yml`（對每台 login-probe 主機）與
  `login-probe-apply.yml`（對每台 Prometheus 主機）都會擋，所以單獨部署 login-probe 改長 probe 間隔也會被
  擋下（`alertmanager.md` §1.7）。改 probe 間隔時要一起調整時間窗與 `host_metrics_missing_for`。
  這道 gate 沒有算進 `login_probe_concurrency` 的排隊：同時卡住的嘗試多到佔滿 concurrency 時（例如大量
  主機同時掛掉），健康主機的資料缺口告警可能中斷，改由 `HostDown` 送出（fail-safe）。
  gate 目前還有幾個限制（強化項目見 GitHub issue #123）：
  - 兩邊的交叉檢查只讀**對方 inventory 裡的 hostvars**。只在一邊用 `-e` 覆寫（例如
    `prometheus-apply.yml -e host_metrics_missing_success_window=...`）時，另一邊下次 apply 時看不到這個值。
    這些值請寫在 inventory，不要只用 `-e` 帶。
  - gate 接受剛好相等（interval + timeout + 15s + 2 × scrape = 時間窗）。真實的 Prometheus 在等號邊界上，
    會留下一段約等於 probe 主機那次 scrape 耗時的空隙；設定時請留餘裕（預設留 15s）。
  - `login_probe_alert_keep_firing_for` 沒有上限。它也決定資料缺口變成主機掛掉之後，`HostDown` 還要被
    抑制多久：預設 5m 約 8m，設成 30m 時主機掛掉 20m 後仍被抑制。
  - duration 的 regex 會把 `60s` 後面帶換行的值、以及超過 Go duration 上限的值當成可解析；兩者目前都無害
    （inventory 的值不會帶結尾換行，溢位的值會因為需要的時間窗太長而被擋下）。
- login-probe 主機**自己**的 node_exporter 停掉時（SSH 正常），這台 probe 的 series 全部消失：它回報的
  登入告警都不見了，`PilotLoginProbeStale` 也不會觸發，只有它的 `HostDown` 在 10m 送出（GitHub issue #121，
  `alertmanager.md` §1.7）。看到 probe 主機的 `HostDown` 時，先確認它的 SSH 與 node_exporter，並當作
  這台 probe 的登入探測已經失明。
- 解析不到的 target 不會擋下部署：它留在設定裡，apply 印出 WARNING，probe 回報
  `transport`，觸發 `PilotLoginProbeTransportFailed`。全部 target 都解析不到時才會
  fail closed（通常是 `login_probe_domain` 寫錯，或探測主機本身的 DNS 壞了）。
- 從 `hosts.yml` 拿掉某台主機的 `login-probe` role（主機本身沒有退役）時，沒有任何
  playbook 會移除它：`pilot-login-probe.service` 會繼續跑，也繼續寫 textfile。請在那台
  主機上手動清掉：`systemctl disable --now pilot-login-probe`，再刪除
  `/var/lib/node_exporter/textfile/pilot_login_probe.prom`。刪掉 textfile 之後，
  這台 probe 的 series 會消失，Prometheus 上也不會再有它的告警。
- `prometheus.md` 的 C16–C19（GPU）在沒有 dcgm-exporter 主機的站台一定 FAIL，跟本功能無關。
- C22 要等 Prometheus head 約 3 小時切出第一個 2h block，再由 Thanos Sidecar 上傳；fresh topology 剛部署時預期 FAIL，至少等待約 3 小時後再驗收此 row。
- candidate `8b9d3ca` 重跑了 L1–L6、C10、I/O stall、資料缺口（含 probe 重啟與單輪失敗）、整台主機停擺、
  SSSD 後端卡住、全站 HBAC 拒絕、兩台 probe 其中一台停擺、時間 gate（兩個 apply、帶與不帶 `--tags C1`）拒絕錯誤設定，以及退役
  （HD36-LIVE）。AlmaLinux 9（沒有 PSI）的 `dm-delay` 磁碟延遲演練只跑在 2026-10-13 未 commit 的
  working tree（`2026-10-13-drills.md`），不是目前的證據；`HostDiskLatencyHigh`/`HostDiskQueueDeep`
  目前只有 promtool 測試。
- `pilot host decommission` 不會移除 Prometheus 的 scrape target（host-decommission spec §19 尚未
  實作的部分，與本元件無關）；`prometheus-apply.yml` 只改 `prometheus.yml` 時不會重啟 Prometheus
  （既有 bug，見 candidate evidence §4）。

## 7. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|---|---|---|---|
| 2026-10-13 | v0.1 | 初版：Phase 0 擷取、元件、告警規則、inhibit 規則與 topology 演練（issue #11） | pilot |
| 2026-10-14 | v0.2 | 更新至 candidate `5f7c13b` 的 fresh topology 證據，記錄 image fingerprints 與 Prometheus C16–C19/C22 環境限制 | pilot |
| 2026-10-15 | v0.3 | 更新至 candidate `0882d2c`：`HostIOStall` 改讀沒有 `kind` label 的 PSI full series，並在 fresh topology 上實際觸發；`services: local` 可用 | pilot |
| 2026-10-15 | v0.4 | 更新至 candidate `dc883b3`（PR #80 review）：§3 的 inhibit 行為改寫（`HostMetricsMissing` 抑制同主機 `HostDown{job="node"}`、`PilotLoginProbeStale` 只抑制同 `probe_host`）、§4.5 退役 re-render 帶 vault、§6 補明確 target 名稱、解析不到的 target 與手動移除 role；§0.5 換成新一輪實測 | pilot |
| 2026-10-15 | v0.5 | PR #80 第三輪 review：`HostMetricsMissing` 的 `keep_firing_for`、inhibit 帶 `site`、probe 新鮮度改用 `changes()`；§6 補 `node_exporter_targets` 與 probe 間隔的前提 | pilot |
| 2026-10-15 | v0.6 | PR #80 第四輪 review：§6 補 probe 新鮮度與 `host_metrics_missing_for` 的兩道 gate；§3 `HostMetricsMissing` 恢復後的延遲改寫 | pilot |
| 2026-10-15 | v0.7 | PR #80 第五輪 review：§3 `HostMetricsMissing` 恢復延遲改為最多約 6m15s | pilot |
| 2026-10-15 | v0.8 | PR #80 第六輪 review：§6 改寫 `host_metrics_missing_success_window` 的前提 | pilot |
| 2026-10-16 | v0.9 | PR #80 第七輪 review：§6 寫明 `host_metrics_missing_success_window` 的兩道 gate（含讀 login-probe 主機設定的交叉檢查） | pilot |
| 2026-10-16 | v0.10 | PR #80 第八輪 review：§6 的時間窗 gate 改為 interval + timeout + 15s + 2 × scrape，`login-probe-apply.yml` 也會擋；寫明 `host_metrics_missing_for` 最多 9m、concurrency 排隊不在 gate 內，以及 login-probe 主機自己的監控資料缺口（#121） | pilot |
| 2026-10-16 | v0.11 | PR #80 第八輪 review 後續：§6 寫明 gate 的四個已知限制（只讀對方 inventory、等號邊界、`keep_firing_for` 沒有上限、duration regex 錨定），強化追蹤於 #123 | pilot |
