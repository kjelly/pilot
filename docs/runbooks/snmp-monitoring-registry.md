# Runbook — SNMP monitoring registry (Phase 2: schema v2 + compiler)

> 撰寫日期：2026-09-02 (UTC)
> 對齊規範：`docs/superpowers/specs/2026-09-01-snmp-monitoring-integration-spec.md`
> §15 Phase 2；`docs/verification/snmp-monitoring-integration.md` C1/C2/C5/C6
> 維護者：sre

---

## 0. 目標與範圍

證明 Phase 2 exit gate 的五項要求全部成立：v1 golden 不變、v2 SNMP golden
PASS、`promtool config` PASS、`up{pilot_protocol="snmp"}=1`、wrong-site
target 不被編譯進去。前兩項是 Go 測試（`internal/monitoring`），後三項需要
一條真實鏈路：`snmp-exporter`（Phase 1 產物）→ Prometheus（本 Phase 新增
`kind: snmp` scrape job 編譯邏輯）→ 一台真實 lab SNMPv3 裝置。

## 1. §0.5 事實快照

兩台 disposable VM：`prom-site`（Prometheus + Thanos Sidecar + SeaweedFS
S3 + snmp-exporter，全部 co-locate）、`snmp-dev`（lab SNMPv3 裝置，同
Phase 1 手法）。`pilot vm-target wire` 對 `--ssh-user ubuntu` 失敗（已知
限制，見 `docs/runbooks/snmp-exporter.md` §1），改用固定內網 IP
（192.168.122.2/.3）。

依賴鏈：`docker-apply.yml` → `seaweedfs-s3-apply.yml`（anonymous mode，
Thanos S3 目的地）→ `snmp-exporter-apply.yml` → `prometheus-apply.yml`。

Tested revision：本檔對應的 `internal/monitoring`
schema/validate/compile v2 變更、`playbooks/apply/prometheus-apply.yml`
的 `kind: snmp` 編譯邏輯、`playbooks/apply/snmp-exporter-apply.yml` 加入
`pilot-metrics` docker network 的變更。

## 2. 註冊 registry（schemaVersion 2）

```yaml
# monitoring/scrape-profiles.yml
schemaVersion: 2
profiles:
  core-switch:
    kind: snmp
    jobName: snmp-core-switch
    subjectKind: network_device
    diagnosticProfile: network-device-ifmib-v1
    scrapeInterval: 30s
    scrapeTimeout: 20s
    snmp: {modules: [if_mib], authProfile: lab-switch-v3}

# monitoring/targets.yml
schemaVersion: 2
targets:
  - {name: core-sw-01, address: 192.168.122.3, profile: core-switch, site: hq,
     detectionCohort: lab-cohort, labels: {vendor: lab}}
  - {name: core-sw-wrongsite, address: 192.168.122.3, profile: core-switch,
     site: branch-1, detectionCohort: lab-cohort}
```

```
$ pilot monitoring validate --dir <workspace>
warning: address "192.168.122.3" is used by more than one enabled target: [core-sw-01 core-sw-wrongsite]
OK
```

(該 warning 是預期的——兩個 target 刻意共用同一台 lab 裝置的 IP 來測試
site 過濾，不是一個真的重複裝置。)

## 3. 部署 Prometheus（真實 apply）

```
$ ansible-playbook -i <prom-site-inv.yaml> playbooks/apply/prometheus-apply.yml \
    -e target_group=prom-site -e prometheus_site_label=hq \
    -e thanos_s3_target_host=127.0.0.1 \
    -e thanos_aws_access_key_id=anonymous -e thanos_aws_secret_access_key=anonymous \
    -e monitoring_targets_file=<abs>/targets.yml \
    -e monitoring_profiles_file=<abs>/scrape-profiles.yml

PLAY RECAP *********************************************************************
prom-site   : ok=46  changed=12  unreachable=0  failed=0  skipped=18  rescued=0  ignored=0
```

**真實踩到的 bug（已修）**：

1. `rule_files` 的 SNMP 規則行原本用手刻字串插入一個 `\n  - ...`
   escape，結果被 `>-` folded scalar + Ansible 自己的 YAML/Jinja
   雙重模板處理成字面上的 `\n` 兩個字元，導致 `promtool check config`
   把整段字串當成「一個檔名」而報 `does not point to an existing
   file`。改用跟 `scrape_configs` 一樣的「建真正的 Jinja list +
   `to_nice_yaml`」手法，不再手刻含跳脫字元的字串（同一類坑，
   `prometheus_node_exporter_scrape_block` 本來就有文件記載過）。
2. 新增的 `snmp-alert-rules.yml` 只寫到 HOST，但容器沒有對應的
   `volumes:` bind-mount，导致 `promtool` 在容器內找不到檔案——修法是
   在既有的 volumes 條件式清單（跟 `node_exporter`/`monitoring_secrets`
   同一個手法）多加一條，只在 `prometheus_has_snmp_profile` 為真時掛載。
3. **最大的一個**：預設 `snmp_exporter_endpoint: 127.0.0.1:9116`
   在兩邊都跑在各自 Docker container 時完全連不到——`127.0.0.1` 對
   `pilot-prometheus` 容器來說是它自己的 loopback，不是 host 的。實測
   `lastError: dial tcp 127.0.0.1:9116: connect: connection refused`。
   修法：讓 `snmp-exporter` 也加入 `pilot-metrics` docker network（跟
   `alertmanager`/`thanos-query` 用同一個網路名稱的既有慣例一致），
   `snmp_exporter_endpoint` 預設改成該 container 名稱
   `pilot-snmp-exporter:9116`，靠 Docker 內建 DNS 解析。這不影響
   Phase 1 的 hardening 邊界（host 層 port 仍只 publish 到
   127.0.0.1，只是額外加入了一個既有的可信 docker 網路）。

## 4. Exit gate 逐項證據

```
$ docker exec pilot-prometheus promtool check config /etc/prometheus/prometheus.yml
Checking /etc/prometheus/prometheus.yml
  SUCCESS: 2 rule files found
 SUCCESS: /etc/prometheus/prometheus.yml is valid prometheus config file syntax
Checking /etc/prometheus/alert-rules.yml
  SUCCESS: 3 rules found
Checking /etc/prometheus/snmp-alert-rules.yml
  SUCCESS: 2 rules found
```

```
$ cat /etc/pilot/prometheus/targets/snmp-core-switch.json
[
  {
    "targets": ["192.168.122.3"],
    "labels": {"pilot_target": "core-sw-01", "pilot_source": "external",
      "pilot_protocol": "snmp", "pilot_subject_kind": "network_device",
      "site": "hq", "detection_cohort": "lab-cohort", "vendor": "lab"}
  }
]
```

只有 `core-sw-01`（site: hq）；`core-sw-wrongsite`（site: branch-1）完全
沒有出現——不是「compile 出來但被 Prometheus 丟棄」，是根本沒被寫進
file_sd JSON。

```
$ curl -s 'http://127.0.0.1:9090/api/v1/query?query=up{pilot_protocol="snmp"}'
{"status":"success","data":{"resultType":"vector","result":[{"metric":{
  "__name__":"up","detection_cohort":"lab-cohort","instance":"192.168.122.3",
  "job":"snmp-core-switch","pilot_protocol":"snmp","pilot_source":"external",
  "pilot_subject_kind":"network_device","pilot_target":"core-sw-01","site":"hq",
  "vendor":"lab"},"value":[1788312847.901,"1"]}]}}
```

`up{pilot_protocol="snmp"}` 回 **1**——relabel 鏈（`__address__` →
`__param_target` → `instance`，`__address__` 再換成 exporter 位址）跟
真實 lab 裝置的完整 scrape 都通了。

```
$ curl -s 'http://127.0.0.1:9090/api/v1/targets' | grep -o 'core-sw-[a-z0-9-]*'
core-sw-01
core-sw-01
```

`core-sw-wrongsite` 從未出現在 Prometheus 自己的 target 清單裡——site
過濾在真實 API 層面也確認生效，不只是靜態檔案層面。

```
$ curl -s 'http://127.0.0.1:9090/api/v1/rules' | grep -o '"name":"SNMP[A-Za-z]*"'
"name":"SNMPTargetDown"
"name":"SNMPExporterDown"
```

## 5. Idempotency

```
$ ansible-playbook ... playbooks/apply/prometheus-apply.yml ... (same args)
PLAY RECAP: prom-site : ok=47 changed=0 ...

$ ansible-playbook ... playbooks/apply/snmp-exporter-apply.yml ... (same args)
PLAY RECAP: prom-site : ok=25 changed=0 ...
```

## 6. 已知留白（不在本次範圍）

- CLI/TUI 的 `--kind snmp`/`--detection-cohort`/`--snmp-catalog` 已在
  `internal/monitoring` + `cmd/pilot/cmd` 落地並有單元測試/CLI 端對端測試，
  但 `pilot edit` TUI 選單本身（互動式畫面）尚未針對 `kind: snmp` 特化
  （spec §11.2 的 select/multi-select 需求）；MCP resources
  （`pilot://monitoring/*`）也還沒延伸 SNMP 欄位。
- `monitoring_targets_file`/`monitoring_profiles_file` 沿用既有
  「路徑相對於呼叫端 CWD，需為絕對路徑或由 `pilot deploy`
  的日後 CLI wiring 自動補完」限制——跟 `snmp_catalog_file` 一樣的既有
  留白（見 `docs/runbooks/snmp-exporter.md` §10）。

## 7. Teardown

```
$ pilot vm-target down --name prom-site
$ pilot vm-target down --name snmp-dev
```
