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
| 最新驗證 | 2026-10-15，merge candidate `a381ac3d338ed755eb85ee7344ff23c4b9b2239f`（tree `ca023f5d490f4825d48dc410c3aa8be4026c4075`；`f764131` 合併 `main` `cc38f58`），乾淨 detached worktree，執行前 `git status --short --ignored` 為 0 筆；所有輸入（inventory、vault、workspace、probe artifact）都在 checkout 外；operator 為維護者工作站上的 OS 使用者 `kjelly`（由 coding agent 執行）。告警演練與 HD36 跑在 `f764131`，合併沒有改到它們用到的任何檔案（見 evidence 的 manifest 比對） |
| 目標環境 | 四台 ephemeral VM（topology 副本把 `lp-` 改名為 `pr80-`，`services: local`）：`pr80-ipa`（AlmaLinux 9.8，FreeIPA 4.13.4）、`pr80-mon`（Ubuntu 24.04.4：freeipa-client、host-monitoring、docker、seaweedfs-s3、prometheus、alertmanager、login-probe）、`pr80-target`（Ubuntu 24.04.4，有 PSI）、`pr80-target-el`（AlmaLinux 9.8，EL9 預設沒有 PSI）。node_exporter 1.12.1；`pr80-mon` 上 container 的 image digest 在 run 當下擷取，見 evidence。 |
| base image | 每台 VM 都是 `overlay.qcow2` 疊在 golden image 上（run 當下 07:38:54–07:38:56 UTC 計算）：`almalinux-9-golden.qcow2` SHA-256 `b780998adca7c69ff6dbd41a05b51769ef6ab6708a7defbd286195186fbcc8ac`；`ubuntu-24.04-golden.qcow2` SHA-256 `bfab799e2c50a83f77c607e50290646c07628a67ed73fe90c28658a28b0a5394` |
| inventory host 集合 | `pilot vm-target topology inventory` 產生：`freeipa-server`={pr80-ipa}；`freeipa-client`/`host-monitoring`={pr80-mon, pr80-target, pr80-target-el}；`docker`/`seaweedfs-s3`/`prometheus`/`alertmanager`/`login-probe`={pr80-mon} |
| vault 依賴（只列 key） | `ipa_admin_password`、`node_exporter_basic_auth_password`、`thanos_aws_access_key_id`、`thanos_aws_secret_access_key`、`restic_aws_access_key_id`、`restic_aws_secret_access_key`（此輪用一次性 vault）。login-probe 本身需要 `node_exporter_basic_auth_password`（跟同主機 host-monitoring 同一個值，apply 用它確認 node_exporter 有讀到 textfile）；`login_probe_ssh_private_key` 選填 |
| 對齊決定 | A（改 inventory）：topology 檔就是 spec §1 宣告的 group 集合 |
| candidate topology test | `a381ac3`：2026-10-15 08:55:06–09:17:23 UTC，`topology test` rc=0（cluster snapshot `pre-test-1792054919`）：L1 syntax PASS；L3 `--check --diff` 四台 `failed=0`；L4 四台 `failed=0`；L5 login-probe 14/14（run `a0243584-d572-4560-9e35-ffa72969abdc`）、Alertmanager 10/10（run `b043b8df-5d2b-4d1f-ac7f-81c25b5c149f`）；L6 四台 `changed=0`。`f764131` 同樣 PASS（07:38:56–08:03:48 UTC），之前的嘗試因 #99、#100、ansible-core 內部例外與一次 `ipa-client-install` 失敗而重跑，見 evidence。 |
| `HostIOStall` 實測 | candidate `f764131`，08:04–08:17 UTC：預設門檻（0.25、10m）下，`pr80-target` 跑 `dd oflag=dsync`，stalled rate 約 0.5，08:07:18 pending、08:17:13 firing，Alertmanager 收到（`site=lp-site`）；沒有負載的主機約 0。node_exporter 的 PSI series 沒有 `kind` label（`stalled`=full、`waiting`=some），規則不得加 `kind=` matcher。 |
| 演練 | candidate `f764131`，真實 Prometheus + Alertmanager（時間見 evidence）：(1) `pr80-target-el` 停 node_exporter（SSH 正常）期間重啟 probe、再讓 probe 一輪失敗（停 sshd 約 2 分鐘）→ `HostMetricsMissing` 持續 firing，10 分鐘後的 `HostDown{job="node"}` 在 Alertmanager 為 suppressed；(2) 兩台 probe：停擺的 probe 只抑制自己（`probe_host`、`site`）的告警，另一台的 critical `AccountDenied` 維持 active；(3) C10 經真實 verify pipeline：已部署的 Alertmanager PASS，載入 `a742ad9` 舊規則的 Alertmanager FAIL；(4) HD36-LIVE：`pilot host decommission` 退役 `pr80-target`，re-render 帶 vault 與 checkout 外的 artifact 通過 gate，probe 設定不再列它 |
| verify（fresh topology） | `a381ac3`：`login-probe.md` 14/14 PASS；`alertmanager.md` 10/10 PASS；另行跑 `prometheus.md`（run `7defb702-0aff-4f20-947e-7183de3e625a`）為 19/24：C1–C15、C20/C21、C23/C24 PASS；C16–C19 因此拓樸沒有 GPU/dcgm-exporter、C22 因 fresh Thanos 尚未累積可上傳的 2h block 而 FAIL（見 §6）。`thanos_aws_*` 必須等於 `restic_aws_*`，否則 C9 也會 FAIL。 |
| 冪等 | `login-probe-apply.yml` 第二次 apply `changed=0`；整條 chain 在全新 VM 上 L6 `changed=0` |
| evidence | 最新：[`2026-10-15-a381ac3.md`](../evidence/login-probe/2026-10-15-a381ac3.md)（hash manifest：[`2026-10-15-a381ac3-files.sha256`](../evidence/login-probe/2026-10-15-a381ac3-files.sha256)），告警演練、`HostIOStall` 與 HD36 見同一輪的 [`2026-10-15-f764131.md`](../evidence/login-probe/2026-10-15-f764131.md)；歷史 evidence（不是目前的證據）：`docs/evidence/login-probe/2026-10-15-dc883b3.md`、`2026-10-15-0882d2c.md`、`2026-10-14-5f7c13b.md`、`2026-10-13-6bcfb8a.md`、`2026-10-13-phase0-ssh-capture.md`、`2026-10-13-drills.md` |

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
| `HostMetricsMissing`（warning，`action_required`） | — | SSH 登得進去但 `up{job="node"}==0`：node_exporter 停了、9100 被擋、或 Basic Auth 不符。它觸發時同主機的 `HostDown{job="node"}` 會被 inhibit（主機還活著）；probe 單輪失敗或重啟不會讓它中斷（`keep_firing_for`），所以恢復後最多晚 5m 才 resolve |
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
- `login_probe_interval` + `login_probe_total_timeout` 要明顯短於 `host_metrics_missing_for`
  （預設 60s + 30s 對 3m）；兩邊屬於不同 role，playbook 沒有交叉檢查。
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
- I/O、SSSD 卡住、metrics 缺口、probe 停擺、全站 HBAC 拒絕這幾個演練跑在 candidate 之前的
  working tree（`2026-10-13-drills.md`）。candidate `f764131` 重跑了 L1–L6、I/O stall、資料缺口
  （含 probe 重啟與單輪失敗）、兩台 probe 其中一台停擺，以及退役（HD36-LIVE）；整台主機停擺
  只產生 `HostDown` 的實測在 `dc883b3`（該規則此後未變），本輪由 promtool 鎖住。
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
