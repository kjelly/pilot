# Runbook — login-probe（外部 SSH/PAM 登入探測與主機 I/O 告警）

> 對應 issue：GitHub kjelly/pilot#11
> 對應 spec：[`docs/verification/login-probe.md`](../verification/login-probe.md)、
> [`docs/verification/prometheus.md`](../verification/prometheus.md) C20/C21、
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
| 最新驗證 | 2026-10-13，working tree on `db10268`（未凍結 candidate，見 §6） |
| 目標環境 | `docs/topologies/login-probe-topology.yaml`：`lp-ipa`（AlmaLinux 9.8，FreeIPA 4.13.4）、`lp-mon`（Ubuntu 24.04：freeipa-client、host-monitoring、docker、seaweedfs-s3、prometheus、alertmanager、login-probe）、`lp-target`（Ubuntu 24.04）、`lp-target-el`（AlmaLinux 9.8）；以 `pilot vm-target topology up` 建立 |
| inventory host 集合 | `pilot vm-target topology inventory --topology docs/topologies/login-probe-topology.yaml`：`freeipa-server`={lp-ipa}；`freeipa-client`/`host-monitoring`={lp-mon, lp-target, lp-target-el}；`docker`/`seaweedfs-s3`/`prometheus`/`alertmanager`/`login-probe`={lp-mon} |
| vault 依賴（只列 key） | `ipa_admin_password`、`node_exporter_basic_auth_password`、`restic_aws_access_key_id`、`restic_aws_secret_access_key`、`thanos_aws_access_key_id`、`thanos_aws_secret_access_key`；login-probe 本身不需要 secret（`login_probe_ssh_private_key` 選填） |
| 對齊決定 | A（改 inventory）：topology 檔就是 spec §1 宣告的 group 集合 |
| 全新 VM 測試 | `pilot vm-target topology test --ephemeral`（topology 的 per-run 改名副本，`playbooks/test/login-probe-chain.yml`）：L3 `--check --diff` 四台 `failed=0`、L4 apply `failed=0`、L5 `login-probe.md` 14/14 + `alertmanager.md` 10/10 PASS、L6 四台 `changed=0` |
| verify（演練 topology） | `login-probe.md` 14/14 PASS；`alertmanager.md` 10/10 PASS；`prometheus.md` 17/21（C16–C19 是 GPU/dcgm-exporter row，此 topology 沒有 GPU 主機，不適用；C20/C21 PASS） |
| 冪等 | `login-probe-apply.yml` 第二次 apply `changed=0`；整條 chain 在全新 VM 上 L6 `changed=0` |
| evidence | Phase 0 擷取：`docs/evidence/login-probe/2026-10-13-phase0-ssh-capture.md`；演練：`docs/evidence/login-probe/2026-10-13-drills.md` |

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
| `PilotLoginProbeTransportFailed`（warning） | `transport` | sshd、防火牆、DNS；同主機 `HostDown` 也在時會被 inhibit |
| `PilotLoginProbeStale`（warning） | — | 探測主機 `systemctl status pilot-login-probe`；它觸發時同 site 的其他 `PilotLoginProbe*` 會被 inhibit |
| `HostMetricsMissing`（warning） | — | SSH 登得進去但 `up{job="node"}==0`：node_exporter 停了、9100 被擋、或 Basic Auth 不符 |
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
  `pilot_host`，否則 login 告警永遠對不上主機）；playbook 會 fail closed。
- `prometheus.md` 的 C16–C19（GPU）在沒有 dcgm-exporter 主機的站台一定 FAIL，跟本功能無關。
- 本 runbook 的驗證是 working tree 開發 run，不是凍結的 candidate commit（AGENTS.md §1.5）；
  正式 candidate run 要在 commit 後以 `pilot vm-target topology test --ephemeral` 重跑。

## 7. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|---|---|---|---|
| 2026-10-13 | v0.1 | 初版：Phase 0 擷取、元件、告警規則、inhibit 規則與 topology 演練（issue #11） | pilot |
