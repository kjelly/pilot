Pilot Detection Engine — Implementation-Ready Specification

文件用途：直接交付 coding agent 實作
狀態：IMPLEMENTATION_READY — Stage A-0 may begin; verification and production gates remain pending
版本：v1.5
日期：2026-08-28
目標 repository：kjelly/pilot
核心 component：detection-engine
Runtime binary：pilot-detection-engine
Runtime service：pilot-detection-engine.service
MVP metrics source：central Thanos Query only
Model integration：optional Stage B，HTTP API only
核心 invariant：Detection 可以 probabilistic；infrastructure mutation 必須維持 Pilot 的 deterministic / gated / audited / verified 邊界。

0. 本 revision 的目的

v1.3 將先前的 Architecture / Requirement Brief 收斂成 coding agent 不需要自行補完
核心語意的 implementation spec。

以下事項為 normative requirements，實作者不得自行替換成另一套「合理做法」：

Core Statistical MVP 與 Model Integration 的 stage boundary。

pilot_host 的 inventory → Prometheus producer 規則。

scheduler cadence、evaluation timestamp、overrun。

feature list、required/optional、valid ranges。

missing / stale / duplicate / NaN / future sample 行為。

historical baseline、cold start、median/MAD、zero-MAD。

cohort peer set、自我排除與 minimum peers。

baseline/cohort score 公式。

candidate score 與 Model Provider gating。

local/model fusion。

warning / critical / recovery state machine。

SignalEvent fingerprint、episode、revision、dedup。

SQLite schema、migration、transaction boundary。

outbox lease/retry/dead semantics。

Alertmanager refresh、escalation、resolution。

Model Provider single/batch contract。

OpenAI Responses extraction/refusal/incomplete。

Ollama native JSON-schema adapter。

OS / arch / role / site.yml / artifact provenance。

API key 唯一 secret ownership path。

backup policy。

Pilot inventory catalog 與 MCP registration。

Spec v2 verification topology / fixtures / evidence plan。

existing unrelated repository baseline failure 的隔離政策。

如果 implementation 需要改變其中任一 normative requirement：

STOP
→ 更新本 spec
→ review
→ 再實作

不要由 coder 在 code 中默默做不同決策。

1. Scope Split

1.1 Stage A — Core Statistical MVP

Stage A 必須先獨立完成並驗收。

包含：

Prometheus canonical host identity
Thanos ingestion
feature normalization
historical bootstrap
robust-baseline-v1
cohort-outlier-v1
local candidate computation
SignalEvent lifecycle
SQLite state
Alertmanager durable outbox
Prometheus textfile health
Pilot role / inventory / site integration
pilot_diagnose_detection
restic backup integration
Spec v2 verification

Stage A 不需要：

OpenAI
Ollama
LLM
NPU
GPU
model runtime

Stage A 是 production-valid Detection Plane 的實作範圍；在取得本文件定義的
VERIFICATION_READY 與 PRODUCTION_READY 證據前，不得宣稱它已完成 production gate。

1.2 Stage B — Model Integration

只有 Stage A 全部 acceptance gate PASS 後才能開始。

增加：

ModelProvider interface
openai-responses adapter
ollama-chat adapter
candidate batching
JSON Schema validation
semantic response validation
retry
circuit breaker
rate limiting
model-assisted-anomaly-v1
fusion
provider observability

預設：

detection_model_provider_enabled: false

Provider failure 不可讓 Stage A 停止。

1.3 Readiness and status transition

本文件的狀態只表示規格與證據門檻，不表示任何 target output、PLAY RECAP、verify
結果或 real-provider proof 已存在：

| 狀態 | 精確含義 | 必要條件 |
| --- | --- | --- |
| IMPLEMENTATION_READY | 規格自洽，Stage A-0 可以開始 | Stage boundary、owners、contracts、acceptance semantics 與實作順序已明確；不要求 verification evidence |
| VERIFICATION_READY | Stage A 的可觀察 acceptance 已在目標環境驗證 | On the same immutable candidate revision/tree, every C1-C12 row has its corresponding lane's actual target PASS evidence; the required fake lane evidence is complete and §51 real metrics-chain acceptance is PASS with actual target evidence. Verification-spec lint must also be clean, but lint is an additional condition and never substitutes for any row's target PASS evidence. Any missing/FAIL C row or partial fake/real lane rejects this status; it still does not equal production enablement |
| PRODUCTION_READY | 可依 production gate 評估啟用 Stage A | Stage A 的 real metrics chain、部署/安全/backup/idempotency、必要 staging soak 與 release gate 證據均通過；本文件目前不宣稱達成 |
| STAGE_B_READY | 可以開始 Stage B provider implementation | Stage A 已達 VERIFICATION_READY；Stage B contract delta、schemas、secret ownership、fake/real lane boundary 與 production permission boundary 已完成 review，並沿用 Stage A 的 target evidence。此狀態不宣稱 Stage B fake lane、real-provider proof 或 production enablement 已完成 |

Stage A path 只能由 IMPLEMENTATION_READY → VERIFICATION_READY →
PRODUCTION_READY；Stage B path 則可在 Stage A 達到 VERIFICATION_READY 後轉為
STAGE_B_READY，再依 Stage B 自己的 verification/production gates 推進。缺少
evidence 時保持目前狀態，不得以規格文字代替執行結果。

2. Non-Goals

v1.3 明確不做：

Detection Engine 不直接連 managed host。

不 SSH managed host。

不直接 scrape node_exporter。

不直接讀 managed host /proc。

不支援 direct Prometheus deployment path。

MVP 只使用 central Thanos Query。

不從 Loki/Wazuh 取 detection features。

不內建模型 runtime。

不載入 ONNX / GGUF / model weights。

不管理 Ollama。

不管理 NPU/GPU/XRT/CUDA。

不做 online learning。

不做 fine tuning。

不做 auto-remediation。

不提供 model tool-calling。

不提供 Detection Engine inbound HTTP API。

不支援 HA / active-active。

MVP 每個 host 同時最多一個 adaptive anomaly episode。

MVP Signal sink 只有 Alertmanager。

Webhook / Kafka / other sinks 是 future work。

不做 OpenAI → Ollama 自動 model failover。

不讓 model output 直接控制 Pilot。

3. Architecture Boundary

Managed Hosts
    │
    │ existing exporters / instrumentation
    ▼
Per-site Prometheus
    │
    ├── deterministic known-condition rules
    │
    ▼
Thanos
    │
    │ Prometheus-compatible query API
    ▼
pilot-detection-engine
    │
    ├── robust baseline
    ├── cohort outlier
    ├── candidate gate
    │
    └── optional Model Provider API
             │
             ├── OpenAI
             ├── Ollama
             └── other future provider
    │
    ▼
SignalEvent
    │
    ▼
Alertmanager
    │
    ▼
SRE Agent / Human / Incident Consumer
    │ optional controlled action
    ▼
Pilot

Detection Engine 的正式輸出邊界是 SignalEvent。

下游 consumer 不屬於本 component contract。

4. Current Pilot Facts the Coding Agent Must Respect

實作前必須重新讀 local current worktree。

本 spec 建立時已確認 current repository 有以下 shape：

internal/inventory/contracts.go：role catalog hard-coded。

internal/inventory/catalog.go：top-level render order hard-coded。

inventory.example.yml：手動列所有 group。

playbooks/site.yml：手動 import component。

cmd/pilot/cmd/mcp.go：只有 --enable-diagnose 時註冊 diagnose family。

cmd/pilot/cmd/mcp_diagnose_tools.go::registerDiagnoseTools()：逐 tool 手動註冊。

Component Contract schema current version = 1。

Contract group-var types current only：
string|stringList|integer|boolean|duration。

Spec v2 需要 YAML front matter + ## Checks fenced YAML + typed expect。

AGENTS.md §4.2：新增 persistent data role 必須評估 restic backup。

current Prometheus node-exporter auto-discovery只產生 <ansible_host>:9100，沒有
pilot_host。

local worktree 與 default branch不同時：

local worktree = implementation source of truth

本 spec 的 path/line number 只能當定位提示，不可取代重新讀 code。

5. Deployment Matrix

5.1 Detection Engine Host

v1.3 production support：

Inventory role: detection-engine
Host cardinality: exactly-one

OS: Ubuntu 24.04
Architecture: amd64 / x86_64

其他 OS/arch：

unsupported

不要順便加入沒有 actual-run evidence 的平台。

5.2 Resource Floor

resources:
  minCPU: 2
  minRAMMiB: 512
  minDiskGiB: 5

5.3 Required Components

Detection Engine host 必須同時有：

host-monitoring

但此 dependency 只用來透過 node_exporter textfile collector 發布 Detection
Engine 自己的 health metrics。

它不是 managed-host telemetry ingestion path。

Detection source dependency：

thanos-query — required providerEndpoint
alertmanager — required providerEndpoint

MVP 不實作 source fallback。

6. Implementation Language and Artifact

6.1 Language

使用 Go，放在 current Pilot Go module：

cmd/pilot-detection-engine/
internal/detection/

不使用 Python runtime。

理由：

repo 已是 Go。

Stage A 統計運算不需要 ML library。

Stage B 只有 HTTP API。

避免 wheel / PyPI / Python version provenance。

production 可用單一 pinned static binary。

SQLite driver 必須 pure-Go 並可在：

CGO_ENABLED=0

build。

建議：

modernc.org/sqlite

若要換 driver，必須先修改 spec 並證明同樣可 static build。

6.2 Release Build

新增：

scripts/build-detection-engine.sh

contract shape：

CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
go build -trimpath \
  -ldflags "-s -w -X main.version=<semver> -X main.commit=<git-sha>" \
  -o dist/pilot-detection-engine-linux-amd64 \
  ./cmd/pilot-detection-engine

sha256sum dist/pilot-detection-engine-linux-amd64 \
  > dist/pilot-detection-engine-linux-amd64.sha256

6.3 Deployment Artifact

production apply 不在 target build。

禁止：

go install
curl latest
download unpinned release

required inputs：

detection_engine_artifact_path
detection_engine_artifact_sha256

artifact_path：

absolute path → as-is
relative path → repository root relative

mutation 前 controller-side：

artifact exists。

SHA256 = input。

<artifact> version 成功。

version output符合 binary contract。

copy target後：

SHA256 再驗一次

7. Binary CLI Contract

單一 binary：

pilot-detection-engine version

pilot-detection-engine serve --config <path>

pilot-detection-engine config validate --config <path>

pilot-detection-engine status --json
pilot-detection-engine status --field <dot.path>

pilot-detection-engine db check --db <path>
pilot-detection-engine db backup --db <path> --output <path>

pilot-detection-engine signals list --json
pilot-detection-engine signals show <signal-id> --json

pilot-detection-engine provider probe --config <path>

status 讀：

/run/pilot/detection-engine/status.json

不連 daemon socket。

禁止增加：

exec
shell
restart-host
resolve-force
model-pull
model-load

8. Filesystem and systemd

/usr/local/bin/pilot-detection-engine

/etc/pilot/detection-engine/
  config.yaml
  provider.env
  feature-profile.yaml
  prompt.txt
  schemas/
    model-detection-batch-response-v1.json

/var/lib/pilot/detection-engine/
  state.db
  state.db-wal
  state.db-shm

/run/pilot/detection-engine/
  status.json

/var/lib/node_exporter/textfile/
  pilot_detection_engine.prom

service account：

pilot-detect
nologin
no home

minimum systemd hardening：

User=pilot-detect
Group=pilot-detect
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
ProtectSystem=strict
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=/var/lib/pilot/detection-engine
ReadWritePaths=/run/pilot/detection-engine
ReadWritePaths=/var/lib/node_exporter/textfile

需要 outbound：

Thanos Query：`http://<detection_metrics_source_host>:10912`
Alertmanager：`http://<detection_alertmanager_target_host>:9093`
optional configured Model Provider

10902 只是 Thanos container-internal port；Detection-facing endpoint 永遠是
10912。Detection Engine 永不連 10902，也不做 10902/10912 fallback。

不得 LISTEN TCP/UDP。

9. Canonical pilot_host Producer

這是 Stage A-0 prerequisite。

9.1 Current Problem

current auto-discovery概念：

static_configs:
  - targets:
      - 10.0.0.21:9100
      - 10.0.0.22:9100

只可靠得到：

instance=10.0.0.21:9100

不能用 IP猜 inventory hostname。

9.2 New Rendering Rule

host-monitoring auto-discovery path 必須逐 host render：

static_configs:
  - targets: ["10.0.0.21:9100"]
    labels:
      pilot_host: web-1

  - targets: ["10.0.0.22:9100"]
    labels:
      pilot_host: web-2

exact rules：

pilot_host = inventory_hostname
target address =
    hostvars[inventory_hostname].ansible_host
    fallback inventory_hostname

host iteration：

sort by inventory_hostname ASC

確保 rendered config deterministic。

9.3 Explicit Targets Compatibility

current node_exporter_targets string-list override沒有 hostname mapping。

v1.3：

explicit targets照舊 scrape。

不自動加 pilot_host。

沒 pilot_host 的 series 不進 Detection Engine。

不 reverse DNS。

不用 instance猜 inventory。

future typed target mapping另開 spec。

9.4 Required Changes

Stage A-0 owns only the Prometheus `pilot_host` producer, its regression coverage,
the real Thanos identity evidence, and the provider-contract endpoint correction
described below. It must not add the detector or any Detection delivery surface.

playbooks/apply/prometheus-apply.yml
docs/verification/prometheus.md
docs/runbooks/metrics-alerting.md
internal/spec/prometheus_regression_test.go

`contracts/thanos-query.yaml` must correct the provider-owned `query` endpoint
from `10902` to `10912`; its corresponding provider-contract regression belongs
to the same A-0 change. The Thanos apply/spec files below provide the real
identity-evidence path:

contracts/thanos-query.yaml
playbooks/apply/thanos-query-apply.yml
docs/verification/thanos-query.md
internal/spec/thanos_query_regression_test.go

All of these owners must agree that the Detection-facing endpoint is
`http://<detection_metrics_source_host>:10912`; 10902 remains container-internal only.

Detection Engine source/endpoint tests are A-1 core work, not A-0 work. Detection
role/catalog/contract/site/deploy/MCP changes are A-2 delivery work, not A-0 work.

mandatory regression：

web-1 target IP正確。

pilot_host: web-1。

Basic Auth不變。

multiple host各自 label正確。

explicit override舊行為不變。

real Thanos query可見 pilot_host + site。

10. Metrics Source

v1.3 固定：

Detection Engine → central thanos-query

Contract binding：

component: thanos-query
endpoint: query
sourceSelection: exactlyOne

Detection Engine code只使用：

GET http://<detection_metrics_source_host>:10912/api/v1/query
GET http://<detection_metrics_source_host>:10912/api/v1/query_range

不得使用 Thanos proprietary API。

這保留 future direct Prometheus可能性，但 v1.3 不實作 source選擇。

Detection-facing source URL 固定為：

```text
http://<detection_metrics_source_host>:10912
```

`10902` 僅可出現在 Thanos container 的內部 wiring 說明，不能成為 Detection
Engine、contract、playbook、verification 或 endpoint test 的連線目標。

10.1 Data flow and implementation stages

```text
Stage A-0:
inventory hostname
  → Prometheus pilot_host label
  → real Thanos Query :10912

Stage A-1:
Thanos source
  → normalize
  → baseline / cohort
  → lifecycle
  → SQLite / outbox

Stage A-2:
SQLite / outbox
  → delivery / verification lanes
  → Alertmanager

Stage B:
local candidate
  → provider request / response
  → validated model fusion
```

Stage A-0 的 producer identity 是後續所有 Detection subject discovery 的前提；
Stage A-1 不可繞過 Thanos 直接查 managed host；Stage A-2 的 fixture 與 real
provider lane 必須分開定義（見 §49）。

11. Scheduler — Exact Semantics

constants：

cycle_interval        = 15s
evaluation_delay      = 20s
query_timeout         = 5s
query_concurrency     = 8
max_sample_age        = 45s
future_skew_tolerance = 5s

11.1 Evaluation Timestamp

每 cycle：

raw = wall_clock_utc_now - evaluation_delay

evaluation_time =
  floor(raw_unix_seconds / cycle_interval_seconds)
  * cycle_interval_seconds

所有 instant feature query：

time=<same evaluation_time>

11.2 Cadence

等待使用 monotonic clock。

若下一 deadline 到時上一 cycle未完成：

skip new cycle
pilot_detection_cycle_overrun_total++

不排 backlog。

下一 deadline仍沿 fixed cadence。

12. MVP Feature Profile

file：

monitoring/detection/feature-profiles/linux-host-v1.yaml

Feature

Required

Category

scale_floor

Cohort

cpu_utilization

yes

cpu

0.02

yes

load1_per_cpu

yes

cpu

0.05

yes

memory_used_ratio

yes

memory

0.02

yes

rootfs_used_ratio

yes

storage

0.01

yes

disk_io_busy

yes

storage

0.05

yes

thermal_max_celsius

no

thermal

2.0

yes

12.1 PromQL

以下為 normative query intention，但 coding agent 必須先對 current node_exporter actual
exposition驗證 metric name。若 metric name不符：

STOP → update spec → review

不要直接改 query而不更新 spec。

cpu_utilization

1 - avg by (pilot_host, site) (
  rate(node_cpu_seconds_total{
    job="node",
    mode="idle",
    pilot_host!=""
  }[1m])
)

load1_per_cpu

max by (pilot_host, site) (
  node_load1{job="node",pilot_host!=""}
)
/
on (pilot_host, site)
count by (pilot_host, site) (
  node_cpu_seconds_total{
    job="node",
    mode="idle",
    pilot_host!=""
  }
)

memory_used_ratio

1 -
max by (pilot_host, site) (
  node_memory_MemAvailable_bytes{job="node",pilot_host!=""}
)
/
max by (pilot_host, site) (
  node_memory_MemTotal_bytes{job="node",pilot_host!=""}
)

rootfs_used_ratio

1 -
max by (pilot_host, site) (
  node_filesystem_avail_bytes{
    job="node",
    pilot_host!="",
    mountpoint="/",
    fstype!~"tmpfs|overlay"
  }
)
/
max by (pilot_host, site) (
  node_filesystem_size_bytes{
    job="node",
    pilot_host!="",
    mountpoint="/",
    fstype!~"tmpfs|overlay"
  }
)

disk_io_busy

sum by (pilot_host, site) (
  rate(node_disk_io_time_seconds_total{
    job="node",
    pilot_host!="",
    device!~"^(loop|ram|fd|sr)[0-9]*$"
  }[1m])
)

thermal_max_celsius

max by (pilot_host, site) (
  node_hwmon_temp_celsius{
    job="node",
    pilot_host!=""
  }
)

12.2 Valid Ranges

out-of-range = invalid，不 clip：

cpu_utilization      [0, 1.05]
load1_per_cpu        [0, 64]
memory_used_ratio    [0, 1]
rootfs_used_ratio    [0, 1]
disk_io_busy         [0, 64]
thermal_max_celsius  [-50, 200]

13. Query Result Normalization

logical key：

(pilot_host, site)

對一個 feature/query/key：

Situation

Result

0 sample

missing

exactly 1 sample

candidate value

>1 sample

invalid ambiguous_series

NaN/Inf

invalid non_finite

timestamp > evaluation + 5s

invalid future_sample

evaluation - timestamp >45s

invalid stale

outside valid range

invalid out_of_range

任何 required feature invalid：

host Stage-A cycle invalid

optional thermal missing：

不 invalid core cycle

Thanos/query failure：

telemetry/source failure
NOT host anomaly

14. Historical Baseline

14.1 Bootstrap

startup每 feature：

query_range.end   = evaluation_time - 60s
query_range.start = end - 24h
query_range.step  = 60s

per：

(pilot_host, feature)

最多：

1440 one-minute buckets

minimum ready：

120 valid buckets

少於120：

baseline state = learning
baseline detector invalid for that feature

14.2 Runtime Downsample

runtime cycle 15s，但 baseline最多每 UTC minute一筆。

bucket = floor(evaluation_time / 60s)

同 minute有多個 valid sample：

保留 evaluation timestamp最大的那筆

eviction：

bucket_time < evaluation_time - 24h
→ delete

15. robust-baseline-v1 Formula

對 feature f history H_f：

m_f = median(H_f)

MAD_f =
  median(
    abs(x - m_f)
    for x in H_f
  )

scale：

sigma_f = max(
  1.4826 * MAD_f,
  feature.scale_floor,
  abs(m_f) * 0.01
)

因此 zero-MAD 行為已完全定義，不需要 hidden heuristic。

current value：

d_f = abs(x_f - m_f) / sigma_f

feature anomaly score：

d_f <= 3.5:
    s_f = 0

d_f >= 8.0:
    s_f = 1

otherwise:
    s_f = (d_f - 3.5) / (8.0 - 3.5)

host baseline score：

baseline_score =
  max(
    s_f
    over valid + ready features
  )

contributors：

score DESC
feature name ASC
top 5
score > 0 only

category：

highest contributor feature category
tie → feature name ASC
no contributor → unknown

16. Baseline Update / Contamination Protection

baseline sample只有在：

lifecycle state == normal
AND local_score < 0.65
AND all required features valid

才可寫入 current minute bucket。

任一 false：

freeze whole host baseline for that minute

不是只 freeze單一 feature。

目的：

異常事件不能快速被 baseline 學成正常

恢復 normal後下一 minute再更新。

17. cohort-outlier-v1 Formula

cohort metadata：

detection_cohort: gpu-workers-a

沒有 cohort：

detector = not applicable

對 host H / feature f：

peers =
  other hosts where:
    peer.cohort == H.cohort
    peer.host != H.host
    peer feature f valid
    peer evaluation_time == H evaluation_time

subject自身必須排除。

minimum：

peer_count >= 3

少於3：

feature cohort score invalid

peer statistics：

cm_f = median(peer values)

cMAD_f =
  median(
    abs(peer - cm_f)
  )

cSigma_f = max(
  1.4826 * cMAD_f,
  feature.scale_floor,
  abs(cm_f) * 0.01
)

cd_f =
  abs(H.value - cm_f) / cSigma_f

cd_f 用與 §15 完全相同的 3.5 / 8.0 mapping。

host cohort score：

cohort_score =
  max(valid cohort feature scores)

沒有任何 feature滿足 minimum peers：

cohort detector = not applicable

不是 score 0。

18. Local Score and Candidate

local_score =
  max(
    baseline_score if valid,
    cohort_score if valid
  )

兩者皆 invalid：

host cycle invalid

candidate：

MODEL_TRIGGER = 0.65

local_score >= 0.65
→ candidate=true

tie：

baseline detector wins
then feature name ASC

這只是 deterministic tie-break。

candidate state不產生 SignalEvent。

19. Model-Assisted Fusion

Provider disabled/unavailable/invalid：

fused_score = local_score

provider result：

status=ok

則：

effective_model_score =
  model_score * model_confidence

fused_score =
  max(
    local_score,
    effective_model_score
  )

Model只能 escalate，不能 suppress local detection。

status=insufficient_data：

ignore model
fused_score=local_score

category/contributors：

if effective_model_score >= local_score + 0.05:
    use model category/contributors
else:
    use local category/contributors

model contributor feature必須存在該 candidate的：

current

若有 unknown feature：

whole batch invalid
all candidates fallback local

20. Lifecycle State Machine

每 host：

state:
  normal
  candidate
  firing
  recovering

active severity:
  warning
  critical

counters：

warning_history: last 4 valid cycle booleans
critical_streak
recovery_streak
candidate_clear_streak

thresholds：

candidate >= 0.65
warning   >= 0.80
critical  >= 0.95
recovery  <  0.60

20.1 Valid Cycle Counter Update

每 valid fused score：

warning_history.append(score >= 0.80)
keep only latest 4

critical_streak =
  critical_streak + 1
  if score >= 0.95
  else 0

recovery_streak =
  recovery_streak + 1
  if score < 0.60
  else 0

20.2 normal

priority：

critical_streak >= 2
→ create episode → firing critical

else count_true(last4 warning_history) >= 3
→ create episode → firing warning

else score >= .65
→ candidate

else remain normal

20.3 candidate

same firing rules。

若：

score < .65

則：

candidate_clear_streak++

否則：

candidate_clear_streak=0

candidate_clear_streak >= 2：

normal

candidate不建立 SignalEvent。

20.4 firing warning

critical_streak >=2
→ firing critical

else recovery_streak >=1
→ recovering，remember prior severity=warning

else stay warning

20.5 firing critical

同 episode：

never downgrade to warning

recovery_streak>=1：

recovering
remember prior severity=critical

20.6 recovering

recovery_streak>=4：

resolve episode
state=normal

如果4次前：

score >= .60

則：

return prior firing severity
recovery_streak=0

20.7 Invalid Cycle

invalid telemetry/source cycle：

do not advance warning history
do not advance critical streak
do not advance recovery streak
do not create candidate
do not fire
do not resolve

active SignalEvent保持 active。

21. SignalEvent Identity / Dedup

v1.3：

每 host同時最多一個 adaptive anomaly episode

fingerprint：

SHA256(
  "pilot-detection/v1" + "\n" +
  pilot_host + "\n" +
  feature_profile_id + "\n" +
  decimal(feature_profile_version)
)

不包含：

score
timestamp
category
severity
model
provider

signal_id：

ULID

建立時間：

normal/candidate → firing

revision：

starts at 1

increment：

warning → critical

notification-worthy category/contributor update

resolved

active相同 fingerprint：

update same episode

resolved後再次 firing：

new signal_id
same fingerprint

22. Alertmanager Semantics

MVP sink只有：

Alertmanager

labels：

alertname: PilotAdaptiveAnomaly
source: detection-engine
pilot_host: <host>
site: <site>
severity: warning|critical

不要把 category放 label。

annotations：

signal_id
score
confidence
category_hint
top_contributors
profile

22.1 Refresh

active episode每：

60s

refresh：

startsAt = original firing time
endsAt   = now + 180s

22.2 Warning → Critical

因 severity是 Alertmanager label，escalation transaction必須 enqueue：

sequence 1: resolve warning
sequence 2: fire critical

worker不得在 sequence1：

delivered OR dead

前送 sequence2。

critical episode不降 warning。

22.3 Resolution

enqueue：

resolve current severity
endsAt=now

delivery guarantee：

at-least-once

23. SQLite PRAGMA

startup：

PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
PRAGMA foreign_keys=ON;
PRAGMA busy_timeout=5000;

DB：

/var/lib/pilot/detection-engine/state.db
pilot-detect:pilot-detect
0600

24. SQLite Schema v1

implementation DDL語意必須等價：

CREATE TABLE schema_migrations (
  version INTEGER PRIMARY KEY,
  applied_at TEXT NOT NULL
);

CREATE TABLE baseline_samples (
  pilot_host TEXT NOT NULL,
  feature TEXT NOT NULL,
  bucket_ts INTEGER NOT NULL,
  value REAL NOT NULL,
  PRIMARY KEY (pilot_host, feature, bucket_ts)
);

CREATE TABLE signal_episodes (
  signal_id TEXT PRIMARY KEY,
  fingerprint TEXT NOT NULL,
  pilot_host TEXT NOT NULL,
  site TEXT NOT NULL,
  profile_id TEXT NOT NULL,
  profile_version INTEGER NOT NULL,
  state TEXT NOT NULL,
  severity TEXT,
  category_hint TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  revision INTEGER NOT NULL,
  last_score REAL,
  last_confidence REAL,
  warning_bits INTEGER NOT NULL DEFAULT 0,
  warning_count INTEGER NOT NULL DEFAULT 0,
  critical_streak INTEGER NOT NULL DEFAULT 0,
  recovery_streak INTEGER NOT NULL DEFAULT 0,
  candidate_clear_streak INTEGER NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX ux_signal_active_fingerprint
ON signal_episodes(fingerprint)
WHERE state <> 'resolved';

CREATE TABLE signal_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  signal_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  event_type TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(signal_id) REFERENCES signal_episodes(signal_id)
);

CREATE TABLE outbox (
  id TEXT PRIMARY KEY,
  signal_id TEXT NOT NULL,
  revision INTEGER NOT NULL,
  sequence INTEGER NOT NULL,
  kind TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  status TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  next_attempt_at TEXT NOT NULL,
  lease_until TEXT,
  last_error_code TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(signal_id, revision, sequence, kind),
  FOREIGN KEY(signal_id) REFERENCES signal_episodes(signal_id)
);

CREATE TABLE provider_requests (
  request_id TEXT PRIMARY KEY,
  provider_id TEXT NOT NULL,
  model_id TEXT NOT NULL,
  prompt_version INTEGER NOT NULL,
  candidate_count INTEGER NOT NULL,
  request_hash TEXT NOT NULL,
  status TEXT NOT NULL,
  latency_ms INTEGER,
  input_tokens INTEGER,
  output_tokens INTEGER,
  error_code TEXT,
  created_at TEXT NOT NULL
);

raw prompt/API key不存 DB。

25. Transaction Boundary

任何 lifecycle transition：

update/insert signal_episodes
insert signal_history
insert required outbox rows

必須：

same SQLite transaction

transaction commit前：

NO HTTP delivery

commit fail：

no in-memory published transition
no Alertmanager POST

restart時：

DB is source of truth

26. Migration / Upgrade / Rollback

migration：

integer versions
one transaction per migration

failure：

ROLLBACK
service exits non-zero

binary upgrade前：

pilot-detection-engine db backup \
  --db /var/lib/pilot/detection-engine/state.db \
  --output /var/backups/pilot-detection-engine/pre-upgrade.db

upgrade health fail：

stop new service。

restore previous binary。

restore pre-upgrade DB。

start previous binary。

verify previous healthy。

Ansible task最後仍 fail，保留 rollback evidence。

首次 install DB不存在時skip backup。

27. Outbox Worker — Exact Semantics

guarantee：

at-least-once

claim：

transaction select lowest eligible (next_attempt_at, created_at, sequence)。

set status=sending。

set lease_until=now+30s。

commit。

HTTP POST outside transaction。

result transaction → delivered|retry|dead。

startup：

sending AND lease_until < now
→ retry

retryable：

network error
timeout
HTTP 429
HTTP 5xx

dead：

HTTP 400
401
403
404
other 4xx except 429

backoff seconds：

1,2,4,8,16,30,60,120,300,300,...

dead：

engine health=degraded
detection still runs

duplicate POST允許；同 Alertmanager labels/payload refresh可安全重送。

28. Model Provider Boundary

Model Provider：

pure scorer/classifier

它沒有：

Pilot tools
MCP tools
shell
Prometheus query
SSH
Ansible
mutation permission

Detection Engine只傳 compact candidate data。

Model response：

untrusted probabilistic input

只能進 fusion。

29. Model Batch Request Contract

companion schema：

model-detection-batch-request-v1.schema.json

repo target path：

monitoring/detection/schemas/model-detection-batch-request-v1.json

invariants：

schema_version=1
request_id required
1 <= candidates <= 4
every candidate has candidate_id
candidate_id unique within request
window_seconds=600

single candidate：

same envelope
candidates length=1

沒有第二套 single schema。

30. Model Batch Response Contract

companion：

model-detection-batch-response-v1.schema.json

repo target：

monitoring/detection/schemas/model-detection-batch-response-v1.json

JSON Schema pass後，semantic validation：

response.request_id == request.request_id

set(response candidate_ids)
==
set(request candidate_ids)

candidate_ids unique

each contributor.feature
exists in matching request candidate.current

任一失敗：

discard whole batch
all candidates fallback local
error=schema_semantic_mismatch

v1.3 不做 partial batch acceptance。

status=insufficient_data 必須：

score=0
confidence=0
contributors=[]

否則 invalid batch。

31. OpenAI Responses Adapter

protocol：

openai-responses

HTTP：

POST <base_url>/responses
Authorization: Bearer <api-key>   # auth=bearer only
Content-Type: application/json

payload contract：

{
  "model": "<model>",
  "instructions": "<versioned prompt>",
  "input": [
    {
      "role": "user",
      "content": [
        {
          "type": "input_text",
          "text": "<ModelDetectionBatchRequest JSON>"
        }
      ]
    }
  ],
  "text": {
    "format": {
      "type": "json_schema",
      "name": "pilot_detection_batch_response_v1",
      "strict": true,
      "schema": {}
    }
  },
  "tools": [],
  "tool_choice": "none",
  "store": false,
  "stream": false,
  "max_output_tokens": 2048
}

schema填 response companion JSON Schema。

禁止：

conversation
previous_response_id
background
web search
function tools
MCP tools

31.1 Response Extraction

non-2xx：

provider HTTP error

2xx後：

status=completed → continue
status=incomplete → provider_incomplete, fallback
status=failed|cancelled → failure
status=queued|in_progress in synchronous non-stream call → invalid_response
error != null → failure

output：

找 assistant message output。

必須 exactly one completed assistant message。

若 content含 refusal：
provider_refusal，fallback local，不算 circuit health failure。

必須 exactly one output_text。

parse output_text.text JSON。

JSON Schema validate。

semantic validate。

不要依賴 SDK convenience output_text aggregate。

32. Ollama Adapter

protocol：

ollama-chat

v1.3 不使用 Ollama /v1/responses 建立 structured-output parity 假設。

使用 native：

POST <base_url>/api/chat

payload：

{
  "model": "<model>",
  "messages": [
    {
      "role": "system",
      "content": "<versioned prompt>"
    },
    {
      "role": "user",
      "content": "<ModelDetectionBatchRequest JSON>"
    }
  ],
  "format": {},
  "stream": false,
  "options": {
    "temperature": 0
  }
}

format：

response companion JSON Schema

response：

message.content
→ JSON parse
→ JSON Schema
→ semantic validation

client-side validation永遠 mandatory。

Detection Engine不：

ollama pull

model由 model-service operator先準備。

33. Secret Ownership — Stage B only

Stage A role 不擁有 provider secret 或 `detection-model-provider` Vault section；
provider disabled 的 Stage A apply 不得要求、讀取、建立或 prompt API key。
以下 flow 只有在 Stage B contract delta 啟用且 bearer provider enabled 時適用：

API key唯一 flow：

Ansible Vault
  ↓
detection_model_provider_api_key
  ↓ no_log
/etc/pilot/detection-engine/provider.env
  root:root 0600
  ↓ systemd EnvironmentFile
DETECTION_MODEL_API_KEY
  ↓
process environment

config.yaml只寫：

api_key_env: DETECTION_MODEL_API_KEY

不寫 secret。

vars：

detection_model_provider_enabled
detection_model_provider_protocol
detection_model_provider_base_url
detection_model_provider_model
detection_model_provider_auth
detection_model_provider_api_key
detection_model_provider_external
detection_allow_external_provider

gates：

disabled → provider其他欄位不 required。

enabled → protocol/base_url/model required。

auth=bearer → key required。

external=true + prod → allow_external_provider=true required。

protocol名稱不推測 network trust。

disabled/auth=none：

provider.env absent

若上一版存在：

delete residual secret file
restart service

34. Provider Retry / Circuit / Rate

default timeout：

OpenAI 15s
Ollama 30s

retries：

max 2
1s then 2s

retry：

network
timeout
429
5xx

no retry：

400
401
403
404
schema mismatch
refusal

circuit：

5 health failures within rolling 2m
→ open 5m

health failures包含：

network
timeout
429
5xx
repeated invalid structured response

不包含：

refusal
insufficient_data

open期間：

no provider requests
local detector continues

35. Candidate Batching / Cost Bound

每 cycle candidates：

local_score >= .65

sort：

local_score DESC
pilot_host ASC

take：

max 16 candidates

其餘：

drop for this cycle
fallback local
increment dropped metric

batch：

4 candidates/request
max 4 requests/cycle
max concurrency=4

global：

60 requests/minute token bucket

rate limit時：

no persistent candidate backlog
next cycle reevaluates

36. Prompt Contract

repo：

monitoring/detection/model-prompts/host-anomaly-v1.txt

content：

You are a telemetry anomaly scoring service.

Use only the supplied telemetry and baseline/cohort statistics.
Do not infer infrastructure facts that are not in the request.
Do not propose remediation.
Do not call tools.
score is anomaly severity, not probability of failure.
confidence is confidence in your score from the supplied data.
category_hint is an investigation hint, not root cause.
contributors must name only features present in candidate.current.
If data is insufficient, return status=insufficient_data, score=0,
confidence=0, contributors=[].
Return only the required structured result.

prompt version：

1

request audit保存：

prompt_version
prompt_hash

不保存 raw prompt body。

37. Status Contract

path：

/run/pilot/detection-engine/status.json

atomic temp + rename。

minimum：

{
  "schema_version": 1,
  "state": "healthy",
  "source": {
    "healthy": true
  },
  "subjects": {
    "active": 4
  },
  "model_provider": {
    "enabled": false,
    "healthy": false,
    "protocol": "",
    "circuit": "closed"
  },
  "signals": {
    "active": 0
  },
  "last_cycle": {
    "success": true
  }
}

provider disabled：

model_provider.healthy
does not affect engine health

38. Prometheus Operational Metrics

Detection Engine host本身重用：

node_exporter textfile collector

這不是 managed-host detection telemetry agent。

file：

/var/lib/node_exporter/textfile/pilot_detection_engine.prom

write：

tmp
fsync if appropriate
rename

required metrics：

pilot_detection_engine_up
pilot_detection_cycle_duration_seconds
pilot_detection_cycle_overrun_total
pilot_detection_last_success_timestamp_seconds

pilot_detection_subjects_total
pilot_detection_subject_skipped_total{reason}
pilot_detection_feature_invalid_total{feature,reason}

pilot_detection_anomaly_score{pilot_host,detector}
pilot_detection_active_signals{severity}
pilot_detection_signal_total{transition}

pilot_detection_model_provider_up
pilot_detection_model_request_total{provider,result}
pilot_detection_model_request_duration_seconds{provider}
pilot_detection_model_candidates_total
pilot_detection_model_candidates_dropped_total{reason}
pilot_detection_model_circuit_open

pilot_detection_outbox_pending
pilot_detection_alertmanager_send_failure_total{reason}

reason 必須 finite enum。

不放 raw error。

39. Detection Engine Health Rules

known operational failure仍用 deterministic alert：

DetectionEngineStale:
  time() - pilot_detection_last_success_timestamp_seconds > 180

DetectionEngineOutboxBacklog:
  pilot_detection_outbox_pending > 0
  for 10m

DetectionModelProviderDown:
  provider enabled
  AND pilot_detection_model_provider_up == 0
  for 10m

provider down：

severity warning

因 Stage A still works。

40. Backup Policy

state.db 是 persistent operational state。

必須同步：

group_vars/restic-backup.example.yml
inventory.example.yml
contract.lifecycle.backup

example：

# host_vars/detection-1.yml
restic_backup_paths:
  - "/etc/pilot/detection-engine"
  - "/var/backups/pilot-detection-engine"

restic_backup_pre_hook: >-
  install -d -m 0700 /var/backups/pilot-detection-engine &&
  /usr/local/bin/pilot-detection-engine db backup
  --db /var/lib/pilot/detection-engine/state.db
  --output /var/backups/pilot-detection-engine/state.db

不要把 live DB/WAL direct copy當唯一一致性備份。

db backup 必須使用 SQLite consistent snapshot mechanism。

41. Component Contract — Stage A contract

`contracts/detection-engine.yaml` 是 Stage A-2 Delivery PR 才新增的 canonical
contract artifact；Stage A-0 與 Stage A-1 不得先建立或要求這個 Detection contract。
Stage A contract 只能引用 `docs/verification/detection-engine.md` 的 C1-C12；
不得引用 provider spec、provider schema 或 provider Vault section。以下是
Stage A contract 的 normative shape：

```yaml
schemaVersion: 1
id: detection-engine
role: detection-engine
specs:
  - path: docs/verification/detection-engine.md
    rows: {all: true} # C1-C12
playbooks:
  apply: playbooks/apply/detection-engine-apply.yml
regressionTests:
  - internal/spec/detection_engine_regression_test.go
  - cmd/pilot/cmd/tag_coverage_test.go
conflicts: []
dependencies:
  - {component: host-monitoring, required: true, relation: sameHosts,
     reason: "Detection host uses node_exporter textfile collector only for engine health; managed-host telemetry still comes from Thanos."}
  - {component: thanos-query, required: true, relation: providerEndpoint}
  - {component: alertmanager, required: true, relation: providerEndpoint}
bindings:
  - input: detection_metrics_source_host
    requiredWhenDependencySelected: true
    sourceSelection: exactlyOne
    from: {component: thanos-query, endpoint: query}
  - input: detection_alertmanager_target_host
    requiredWhenDependencySelected: true
    sourceSelection: exactlyOne
    from: {component: alertmanager, endpoint: api}
os:
  - {distro: ubuntu, versions: ["24.04"]}
hostCardinality: exactly-one
resources: {minCPU: 2, minRAMMiB: 512, minDiskGiB: 5}
groupVars:
  - {name: detection_engine_artifact_path, type: string, required: true, secret: false}
  - {name: detection_engine_artifact_sha256, type: string, required: true, secret: false, validation: "^[a-f0-9]{64}$"}
  - {name: detection_metrics_source_host, type: string, required: true, secret: false}
  - {name: detection_alertmanager_target_host, type: string, required: true, secret: false}
  - {name: detection_cycle_interval, type: duration, required: false, default: "15s", secret: false}
  - {name: detection_evaluation_delay, type: duration, required: false, default: "20s", secret: false}
inputRules: []
endpoints: []
stagePolicy: {variable: stage, default: sandbox}
experimental: false
evidenceRequirement: {targetTest: topology, idempotency: required}
lifecycle:
  backup:
    provider: restic
    preHook: >-
      install -d -m 0700 /var/backups/pilot-detection-engine &&
      /usr/local/bin/pilot-detection-engine db backup
      --db /var/lib/pilot/detection-engine/state.db
      --output /var/backups/pilot-detection-engine/state.db
    paths:
      - /etc/pilot/detection-engine
      - /var/backups/pilot-detection-engine
  upgrade: null
  decommission: null
traceability:
  mode: rowTags
  tag: {kind: rolePrefixed, prefix: detection-engine}
verification: {autoDeploy: false}
site:
  include: true
  order: 130 # use the next unused integer if current catalog validation requires it
  vars: {}
  tags: [observability, detection-engine]
  optIn: true
  targetGroupExpression: null
```

The `Binding` entries above deliberately use only the fields supported by the
current strict contract loader: `input`, `requiredWhenDependencySelected`,
`sourceSelection`, and `from`. Endpoint ownership remains with the provider
contracts: `contracts/thanos-query.yaml` owns the `query` endpoint exposed to
Detection on port `10912`, and `contracts/alertmanager.yaml` owns the `api`
endpoint on port `9093`. The Detection contract binding selects those provider
endpoints by name and does not duplicate an endpoint URL or port.

Stage A role owns no `detection-model-provider` Vault section and has no provider
group vars. Provider-disabled Stage A therefore never requires or prompts for a
provider secret.

41.1 Stage B contract delta

Only after Stage A reaches `VERIFICATION_READY`, add the Stage B delta to the same
component contract: reference `docs/verification/detection-engine-model-provider.md`
M1-M5; add the model request/response schemas in Appendix B; add the provider group
vars and provider input rules below; and add the `detection-model-provider` Vault
section. The Stage B delta is not part of the Stage A contract:

```yaml
groupVars:
  - {name: detection_model_provider_enabled, type: boolean, required: false, default: false, secret: false}
  - {name: detection_model_provider_protocol, type: string, required: false, default: "openai-responses", secret: false, validation: "^(openai-responses|ollama-chat)$"}
  - {name: detection_model_provider_base_url, type: string, required: false, default: "", secret: false}
  - {name: detection_model_provider_model, type: string, required: false, default: "", secret: false}
  - {name: detection_model_provider_auth, type: string, required: false, default: "none", secret: false, validation: "^(none|bearer)$"}
  - {name: detection_model_provider_api_key, type: string, required: false, secret: true}
  - {name: detection_model_provider_external, type: boolean, required: false, default: false, secret: false}
  - {name: detection_allow_external_provider, type: boolean, required: false, default: false, secret: false}
inputRules:
  - any:
      - {input: detection_model_provider_enabled, operator: equals, value: false}
      - {input: detection_model_provider_base_url, operator: nonEmpty}
    reason: enabled provider requires a non-empty base URL
  - any:
      - {input: detection_model_provider_enabled, operator: equals, value: false}
      - {input: detection_model_provider_model, operator: nonEmpty}
    reason: enabled provider requires a non-empty model
  - any:
      - {input: detection_model_provider_enabled, operator: equals, value: false}
      - {input: detection_model_provider_auth, operator: notEquals, value: bearer}
      - {input: detection_model_provider_api_key, operator: nonEmpty}
    reason: an enabled bearer provider requires a non-empty API key
```

Each rule is a loader-executable pass condition. The `any` form expresses the
corresponding disabled/non-bearer exception or the required non-empty input;
there are no untyped expression strings. The apply gate remains the owner of
production permission for an external provider:
`external=true` in `prod` requires `detection_allow_external_provider=true` and
the matching stage confirmation. It is not replaced by schema validation.

42. Inventory / Catalog Integration

42.1 internal/inventory/contracts.go

新增：

{
    Name:          "detection-engine",
    Description:   "中央 Detection Plane：從 Thanos metrics 建立 adaptive SignalEvent (detection-engine-apply.yml)",
    GroupVarsStem: "detection-engine",
    VaultSections: []string{},
}

這是 Stage A owner；不得因 provider disabled 而加入 provider Vault section。
Stage B 才在同一 owner 上新增 `detection-model-provider`，並同步更新
`internal/inventory/vault.go` 的 `vaultSectionOrder`、
`inventory_test.go`、`contracts.go` 及其 owner/ordering tests。Stage B 的
`detection_model_provider_api_key` 是 optional Vault key，只有 bearer auth 的
enabled provider 才需要它。

42.2 internal/inventory/catalog.go

current topLevelOrder（inventory render order）：

host-monitoring
dcgm-exporter
alertmanager
prometheus
thanos-query
dashboard

2026-08-28 已將 `alertmanager` 移到 `prometheus`/`thanos-query` 之前，使這份
inventory render order 與 §43 的 `site.yml` execution order 完全一致（此改動
與其 regression 已驗證：兩份 order 只做成員存在檢查，未鎖定相對順序，故重排
不影響既有 `internal/inventory` 測試；`inventory.example.yml` 已同步移動
`alertmanager` 區塊位置）。

具體規則：

detection-engine 必須出現在 topLevelOrder
且與 roleContracts render order一致

順序固定為：

`host-monitoring → dcgm-exporter → alertmanager → prometheus → thanos-query → detection-engine → dashboard`

`roleContracts` 與 `topLevelOrder` 必須同步，並由 catalog/order regression
鎖定；若 current validator 不接受既有 order 數字，使用下一個未使用的正整數，
不得改變上述相對順序。

42.3 inventory.example.yml

新增：

detection-engine:
  hosts: {}

comment：

exactly-one central Detection Engine

42.4 hosts.example.yml

若 current file列 role示例/allowlist：

加入 detection-engine

42.5 group_vars

新增：

group_vars/detection-engine.example.yml

不放 API key。

Stage A 不產生 provider Vault skeleton。Stage B 開始後才由
`internal/inventory/vault.go` 的 `vaultSectionOrder` 與既有 generator pattern
產生 `detection-model-provider`，並以 regression test 確認 optional key 不會
在 provider disabled 時被要求。

43. site.yml Policy

Detection Engine 加入 playbooks/site.yml。

current playbooks/site.yml execution order（實測確認；2026-08-28 起與 §42.2 的
`internal/inventory/catalog.go` `topLevelOrder` 已對齊為同一條 chain）：

host-monitoring → dcgm-exporter → alertmanager → prometheus → thanos-query → dashboard

新增：

- import_playbook: apply/detection-engine-apply.yml
  tags: [observability, detection-engine]

放在：

`thanos-query`之後、`dashboard`之前。

site execution order 的實際 owner 是 `playbooks/site.yml` 與
`internal/inventory/catalog.go`；兩者都必須遵守上述完整順序。

group empty：

按 existing site.yml semantics skip

component opt-in：

由 inventory role決定

43.1 Deploy catalog owner and AutoHostVars

`cmd/pilot/cmd/deploy_catalog.go` 及其 tests 必須新增 detection-engine
entry，至少明確提供：

| 欄位 | canonical value |
| --- | --- |
| key | `detection-engine` |
| playbook | `playbooks/apply/detection-engine-apply.yml` |
| default group | `detection-engine` |
| stage | `stage`，default `sandbox`，遵守 staging/prod confirmation gate |
| AutoHostVars | `detection_metrics_source_host` ← `thanos-query`；`detection_alertmanager_target_host` ← `alertmanager` |

AutoHostVars 不得無條件 prompt provider Vault section。Provider vars 與
`detection-model-provider` Vault prompt 只能在 Stage B 且 provider enabled 的
條件下出現；Stage A catalog/deploy flow 不得要求 secret。

44. Apply Playbook Preflight

playbooks/apply/detection-engine-apply.yml

target：

hosts: "{{ target_group | default('detection-engine') }}"

mutation前依序：

stage gate。

stage/inventory environment cross-check。

Ubuntu 24.04。

x86_64/amd64。

host-monitoring textfile directory exists/effective。

artifact exists on controller。

artifact controller SHA256。

artifact version。

exactly-one Thanos source binding。

exactly-one Alertmanager binding。

`GET http://<detection_metrics_source_host>:10912/api/v1/query` 回傳 vector(1)
成功；10902 不得作為 Detection source。

Alertmanager readiness success。

feature profile syntax。

config schema。

Stage B provider conditional gates（Stage A 不執行且不要求 provider Vault section）。

Stage B enabled + bearer 的 secret presence。

Stage B prod external-provider explicit allow。

only then mutation。

mutation：

service account。

dirs。

backup existing DB before upgrade。

binary copy + target hash。

config render。

prompt/schema copy。

provider.env create/remove。

systemd unit。

daemon-reload。

restart only if effective deployment changed。

service active。

status healthy。

DB integrity。

textfile valid。

second apply：

changed=0

45. Provider EnvironmentFile — Stage B only

本節不屬於 Stage A contract。Stage A 永遠以 provider disabled 運作，不擁有
provider Vault section，也不要求 API key。

enabled + bearer：

/etc/pilot/detection-engine/provider.env
root:root
0600

content：

DETECTION_MODEL_API_KEY=<secret>

Ansible task：

no_log: true

systemd：

EnvironmentFile=-/etc/pilot/detection-engine/provider.env

disabled/auth none：

provider.env must not exist

46. pilot_diagnose_detection

新增：

internal/diagnose/detection.go
internal/diagnose/detection_test.go

但這不代表 MCP已註冊。

必須修改：

cmd/pilot/cmd/mcp_diagnose_tools.go

在：

registerDiagnoseTools()

實際：

addRecoveredTool(... pilot_diagnose_detection ...)

也修改：

cmd/pilot/cmd/mcp.go

comments

--enable-diagnose description

user-facing docs/tests

tests：

cmd/pilot/cmd/mcp_diagnose_tools_test.go

input：

{
  "signal_id": "optional",
  "pilot_host": "optional"
}

至少一個。

fixed commands只能：

pilot-detection-engine status --json
pilot-detection-engine signals show <validated-id> --json
pilot-detection-engine signals list --json
bounded journalctl -u pilot-detection-engine

不接受 arbitrary command。

mandatory diagnose audit沿 existing framework。

47. Stage A Spec v2 Acceptance Semantics

`docs/verification/detection-engine.md` 是未來 Stage A verification spec 的
canonical rendering。現在只有本節的 normative acceptance contract，沒有 target
output、PLAY RECAP、verify verdict 或 evidence artifact；不得把本節當成已完成
驗證。未來 verification doc 必須保留下列 row IDs 與 semantics：

| Row | Stage A C1-C12 normative acceptance semantics |
| --- | --- |
| C1 | deployment artifact exists, controller-side SHA256 equals the supplied hash, target-side hash matches again, and `version` output has the required version/commit format |
| C2 | service account is `pilot-detect` with nologin/no home; service is active under the required systemd hardening and writable-path boundary |
| C3 | config, feature profile, and installed schema validation pass before mutation; invalid configuration fails closed |
| C4 | SQLite migration completes transactionally; `PRAGMA integrity_check` is `ok`, required WAL/foreign-key settings are effective, and DB ownership/mode are correct |
| C5 | Detection Engine has no TCP/UDP listener; it only makes outbound connections to `http://<detection_metrics_source_host>:10912` and `http://<detection_alertmanager_target_host>:9093` |
| C6 | status JSON and textfile metrics are atomically published, parseable, and report service/cycle/subject health without secrets |
| C7 | `http://<detection_metrics_source_host>:10912/api/v1/query` source health succeeds with the expected Prometheus-compatible vector response; no 10902 fallback exists |
| C8 | canonical discovery contains `pilot_host` equal to the inventory hostname and the expected `site`; subjects are derived from this identity, never from an IP guess |
| C9 | missing required, stale, future, non-finite, out-of-range, and duplicate samples follow §13 exactly; invalid telemetry is not converted into an anomaly score |
| C10 | cold-start history below 120 valid buckets remains learning/invalid and produces no false anomaly; baseline/cohort formulas and contamination protection follow §§14-18 |
| C11 | fixture lane proves lifecycle transitions, SQLite/outbox atomicity, lease/retry/dead behavior, Alertmanager delivery/ordering, refresh, and resolution without using real provider roles |
| C12 | with provider disabled, no provider secret is required, prompted, written, loaded, logged, exposed in status/metrics/DB/diagnose output, or included in evidence/runbook artifacts |

Stage A implementation may begin at C1-C12. The detection verification document
is authored and linted as an A-2 delivery gate; it is not an A-0 prerequisite.
Its eventual target results must be captured by actual execution under the
repository's evidence rules, not authored in this spec.

48. Algorithm Regression Tests

Stage A至少：

internal/detection/baseline_test.go
internal/detection/cohort_test.go
internal/detection/lifecycle_test.go
internal/detection/scheduler_test.go
internal/detection/store_test.go
internal/detection/outbox_test.go
internal/detection/source_test.go

mandatory test names / behaviors：

TestRobustBaseline_ColdStartBelow120IsInvalid
TestRobustBaseline_MedianMADFormula
TestRobustBaseline_ZeroMADUsesScaleFloor
TestRobustBaseline_RelativeFloorWinsWhenLarger
TestRobustBaseline_ScoreBelow3Point5IsZero
TestRobustBaseline_ScoreAt8IsOne
TestBaselineUpdate_FreezesAtCandidateThreshold
TestBaselineUpdate_FreezesWhileFiringAndRecovering
TestBaselineWindow_KeepsLatestSamplePerUTCMinute
TestBaselineWindow_EvictsOlderThan24Hours

TestCohort_ExcludesSubjectItself
TestCohort_RequiresThreePeers
TestCohort_UsesSameScoreMapping
TestCohort_MissingPeerFeatureDoesNotBecomeZero

TestSource_MissingRequiredFeatureInvalidatesHostCycle
TestSource_OptionalThermalMissingDoesNotInvalidateCore
TestSource_DuplicateSeriesIsInvalid
TestSource_StaleAfter45Seconds
TestSource_FutureMoreThan5SecondsInvalid
TestSource_NaNInfInvalid

TestLifecycle_WarningRequiresThreeOfFour
TestLifecycle_CriticalRequiresTwoConsecutive
TestLifecycle_SingleSpikeDoesNotFire
TestLifecycle_RecoveryRequiresFourBelowPoint6
TestLifecycle_InvalidCycleDoesNotAdvanceCounters
TestLifecycle_CriticalNeverDowngradesWithinEpisode
TestLifecycle_ResolvedThenRefireGetsNewSignalID

TestFingerprint_CategoryAndSeverityDoNotChangeFingerprint
TestFingerprint_ProfileVersionChangesFingerprint

TestScheduler_UsesFlooredEvaluationTime
TestScheduler_OverrunSkipsInsteadOfBacklogging

TestStore_SignalHistoryAndOutboxAreAtomic
TestStore_MigrationFailureRollsBack

TestOutbox_ExpiredLeaseReturnsToRetry
TestOutbox_429Retries
TestOutbox_401BecomesDead
TestOutbox_WarningToCriticalOrdersResolveBeforeFire

Stage B：

TestModelBatch_AllCandidatesHaveUniqueCandidateID
TestModelBatch_ResponseSetMustExactlyMatchRequestSet
TestModelBatch_UnknownContributorInvalidatesBatch

TestFusion_ModelCanEscalateButNeverSuppress
TestFusion_InsufficientDataUsesLocalScore

TestProvider_OpenAICompletedSingleOutputText
TestProvider_OpenAIIncompleteRejected
TestProvider_OpenAIRefusalFallsBackWithoutCircuitFailure
TestProvider_OpenAIMultipleOutputTextRejected

TestProvider_OllamaChatSchemaValidatedClientSide

TestProvider_TimeoutFallsBackLocal
TestProvider_CircuitOpensAfterFiveFailures
TestProvider_CircuitDoesNotOpenOnRefusal

TestProvider_CandidateLimitDropsLowestScoresDeterministically

48.1 Readiness and lane-isolation regression requirements

Future regression coverage must build a readiness matrix keyed by immutable
candidate revision/tree, C1-C12 row, and assigned lane. It must reject
`VERIFICATION_READY` when any C row is missing target evidence or has a FAIL,
when the fake lane is partial, or when the real lane/§51 metrics chain is
partial or failing. A clean lint result alone must never make a row PASS.

The same regression set must assert that every Detection-facing Thanos endpoint
is `:10912` (with `:10902` allowed only for container-internal wiring), and that
fake and real topology artifacts are isolated: fake artifacts contain no real
`thanos-query`/`alertmanager` groups, while real artifacts contain no
`detection-fixture-source`, `detection-fixture-sink`, or fake-provider groups.
It must also reject a readiness matrix assembled from mixed candidate/tree
identities.

49. Fixture Topology

新增 test-only：

tests/fixtures/detection/
playbooks/test/detection-engine-fixtures.yml
playbooks/test/detection-engine-fake-topology.yml
playbooks/test/detection-engine-real-topology.yml
tmp/detection-engine-fake-topology.example.yaml
tmp/detection-engine-real-topology.example.yaml

The current VM topology schema uses `nodes[].groups`; it does not use a
role-list field. The two lanes below are separate, mutually exclusive topology
artifacts. Neither artifact may use a topology role-list field. Group membership
describes topology wiring only; it does not prove that a role has been installed
or that a real service is available.

Fake protocol lane（Stage A fixture lane）：

```yaml
nodes:
  - name: detection-engine-fixture
    groups: [detection-engine, host-monitoring]
  - name: detection-fixture-source
    groups: [detection-fixture-source]
  - name: detection-fixture-sink
    groups: [detection-fixture-sink]
```

The fixture-service groups are `detection-fixture-source` and
`detection-fixture-sink`; they must never be named or assigned as
`thanos-query` or `alertmanager`. The fake Prometheus-compatible
Query/query_range service provides `:10912`; its implementation may use a
container-internal port, but Detection never connects to that internal port.
The fake Alertmanager API/readiness service provides `:9093`. A fake provider
may provide `:19100` only for Stage B protocol tests. This lane does not apply
the real `thanos-query`, `alertmanager`, or model-provider components, and
production playbooks must not install fixture services. Fake metrics must at
least fix `site=fixture-site` and `pilot_host=fixture-host-1` so fixture subject
count is deterministic. The fake topology artifact must contain no
`thanos-query`, `alertmanager`, `monitored-subject`, or other real-provider
group.

Future fake-lane execution uses only its own artifact and attributes its
verification report and evidence record to the fake lane:

```bash
go run ./cmd/pilot vm-target topology test \
  --topology tmp/detection-engine-fake-topology.example.yaml \
  --playbook playbooks/apply/detection-engine-apply.yml \
  --verify docs/verification/detection-engine.md=detection-engine
```

The fake-lane record may prove only the C rows assigned to the fake protocol /
fixture lane; it must not be cited as §51 real metrics-chain evidence.

Real provider lane（Stage A §51 real metrics-chain lane；Stage B may extend it）：

```yaml
nodes:
  - name: detection-provider
    groups:
      - detection-engine
      - host-monitoring
      - prometheus
      - thanos-query
      - alertmanager
      - docker
      - seaweedfs-s3
  - name: monitored-subject-1
    groups:
      - monitored-subject
      - host-monitoring
```

The real lane must include `detection-engine`, `host-monitoring`, `prometheus`,
the scraped `monitored-subject`, `thanos-query`, and `alertmanager`. It must
also include the transitive dependencies declared by the current contracts and
apply playbooks: `docker` for the containerized roles, `seaweedfs-s3` for the
Prometheus/Thanos object store, and the Prometheus provider links to
`alertmanager` and optional `host-monitoring` targets. Run real apply without
fake source, fake sink, or fake provider listeners; Detection connects to the
provider-owned Thanos `query` endpoint at
`http://<detection_metrics_source_host>:10912` and Alertmanager `api` endpoint
at `http://<detection_alertmanager_target_host>:9093`. This lane supplies the
§51 evidence; provider-enabled proof still requires the Stage B gate and cannot
be represented by the fake lane. The real topology artifact must contain no
`detection-fixture-source`, `detection-fixture-sink`, or fake-provider group.

Future real-lane execution uses only its own artifact and attributes its
verification report and §51 real metrics-chain evidence to the real lane:

```bash
go run ./cmd/pilot vm-target topology test \
  --topology tmp/detection-engine-real-topology.example.yaml \
  --playbook playbooks/site.yml \
  --verify docs/verification/detection-engine.md=detection-engine \
  --verify docs/verification/prometheus.md=prometheus \
  --verify docs/verification/thanos-query.md=thanos-query
```

The real-lane record must not cite fake source/sink/provider results. The two
topology commands and their evidence records are independent; one shared
topology artifact is not a valid substitute.

50. Algorithm Fixtures

至少：

normal.json
single-spike.json
warning-3-of-4.json
critical-2-consecutive.json
recovery-4.json
zero-mad.json
cohort-outlier.json
missing-required.json
stale.json
thermal-drift.json

thermal：

replay fixture only

不得故意讓實體硬體過熱。

51. Real Metrics Chain Cross-Check

這是 real provider lane 的 required acceptance，不能由 fake protocol lane 取代；
目前尚未有 target evidence。必須實際證明：

* host-monitoring target 被 Prometheus scrape；
* generated target 帶 `pilot_host`；
* Prometheus scrape healthy；
* `http://<detection_metrics_source_host>:10912/api/v1/query` 結果帶
  `pilot_host=<inventory hostname>` 與 `site=<site>`；
* Detection Engine `subjects.active >= 1`。

這條鏈的 canonical flow 是 `inventory hostname → Prometheus pilot_host → real
Thanos :10912 → Detection Engine`。fake topology 只證明 protocol/lifecycle
contract，不證明 topology 中列出的 real roles 已安裝，也不證明 real chain 已接起來。

52. Backup Acceptance

coding agent：

更新 restic example。

更新 inventory backup membership suggestion。

disposable target建立 state DB。

db backup。

backup SQLite PRAGMA integrity_check = ok。

若 current restic fixture可用，做 snapshot path smoke。

full disaster restore若未做，runbook明列為 post-MVP operational limitation。

53. Inventory / Site Regression

mandatory：

pilot inventory roles

包含：

detection-engine

hosts source：

roles:
  - detection-engine

generate後：

all.children.detection-engine.hosts

正確。

另外：

playbooks/site.yml --syntax-check

PASS。

tag coverage：

detection-engine
detection-engine-C*
detection-engine-M*

符合 current convention。

54. Secret Regression

必測：

provider disabled
→ provider.env absent

provider enabled, auth=none
→ provider.env absent

provider enabled, auth=bearer
→ provider.env root:root 0600

secret不得出現：

Ansible stdout
journal
status JSON
Prometheus textfile
SQLite provider_requests
MCP diagnose
verification evidence
runbook

55. Baseline Repository Failure Policy

若 coding agent開始時：

go test ./internal/spec

已因 unrelated pre-existing failure fail——現況確認為：

TestRegression_LogShippingPlaybookAutoDetectsDashboardHost
(internal/spec/log_shipping_regression_test.go)
fails with: "/etc/hosts pin must use the effective Loki target"

（`playbooks/apply/freeipa-realm-replacement-apply.yml` 現況實際存在，並非
missing；coding agent 開始實作時必須重新跑一次 `go test ./internal/spec`
確認當下真正的 baseline failure 是什麼，不得逕自沿用本節列出的具體測試名稱，
上例僅為本 revision 撰寫時的實測快照）

則：

保存 pre-change failing output。

保存 failing test/path。

不在 Detection Engine workstream修 unrelated FreeIPA。

完成後證明 Detection targeted tests全綠。

證明 baseline failure沒有增加或改變 root cause。

如果 repository owner先修 baseline，則恢復要求 full suite green。

不能用 Detection Engine PR 掩蓋 existing failure。

56. Files to Add

cmd/pilot-detection-engine/**

internal/detection/**

scripts/build-detection-engine.sh

monitoring/detection/
  feature-profiles/linux-host-v1.yaml
  model-prompts/host-anomaly-v1.txt                         # Stage B
  schemas/model-detection-batch-request-v1.json             # Stage B
  schemas/model-detection-batch-response-v1.json            # Stage B

playbooks/apply/detection-engine-apply.yml
playbooks/test/detection-engine-fixtures.yml
playbooks/test/detection-engine-fake-topology.yml
playbooks/test/detection-engine-real-topology.yml

tmp/detection-engine-fake-topology.example.yaml
tmp/detection-engine-real-topology.example.yaml

contracts/detection-engine.yaml

group_vars/detection-engine.example.yml

docs/verification/detection-engine.md
docs/verification/detection-engine-model-provider.md        # Stage B
docs/runbooks/detection-engine.md
docs/architecture/detection-plane.md

internal/spec/detection_engine_regression_test.go

internal/diagnose/detection.go
internal/diagnose/detection_test.go

57. Files to Modify

Stage A-0 owner — Prometheus producer and Thanos provider identity only:

playbooks/apply/prometheus-apply.yml
docs/verification/prometheus.md
docs/runbooks/metrics-alerting.md
internal/spec/prometheus_regression_test.go

contracts/thanos-query.yaml
playbooks/apply/thanos-query-apply.yml
docs/verification/thanos-query.md
internal/spec/thanos_query_regression_test.go

The `contracts/thanos-query.yaml` change is limited to correcting the
provider-owned `query` endpoint from `10902` to `10912`, with the corresponding
regression above. A-0's real identity evidence proves the Prometheus
`pilot_host`/`site` labels are visible through real Thanos. A-0 must not add a
detector and must not modify Detection role/catalog/contract/site/deploy/MCP
surfaces or Detection source tests.

Stage A-1 core owner:

cmd/pilot-detection-engine/**
internal/detection/**
scripts/build-detection-engine.sh
Detection source/endpoint tests, including the fixed `:10912` binding

Stage A-2 Detection delivery surface owner — inventory/catalog/site/deploy/
contract/apply/backup/MCP/verification:

internal/inventory/contracts.go
internal/inventory/catalog.go
internal/inventory/inventory_test.go

cmd/pilot/cmd/deploy_catalog.go
cmd/pilot/cmd/deploy_catalog_test.go
contract/tag coverage tests
DELIVERY.md (if it mirrors the deploy catalog or site order)

inventory.example.yml
hosts.example.yml      # if current file enumerates roles

playbooks/site.yml

playbooks/apply/detection-engine-apply.yml
contracts/detection-engine.yaml
docs/verification/detection-engine.md
docs/runbooks/detection-engine.md
docs/architecture/detection-plane.md
playbooks/test/detection-engine-fixtures.yml
playbooks/test/detection-engine-fake-topology.yml
playbooks/test/detection-engine-real-topology.yml
tmp/detection-engine-fake-topology.example.yaml
tmp/detection-engine-real-topology.example.yaml

contracts/prometheus.yaml
  # only if traceability/spec ownership needs change for A-2 delivery

group_vars/restic-backup.example.yml

cmd/pilot/cmd/mcp.go
cmd/pilot/cmd/mcp_diagnose_tools.go
cmd/pilot/cmd/mcp_diagnose_tools_test.go

README.md
docs/network-firewall-matrix.md

Stage B-only inventory ownership (after the Stage A gate):

internal/inventory/vault.go (provider section/order)
internal/inventory/inventory_test.go (Stage B Vault ownership/order tests)

search current tree for所有 hard-coded expected role lists，同步修正。

10912 must be consistent across the Thanos contract, Thanos apply/spec/regression,
Detection source client, fake/real endpoint tests, deploy catalog AutoHostVars, and
documentation. No Detection-facing owner or test may use 10902 or introduce a
10902/10912 fallback.

58. Delivery Order

Approved implementation order：先 Stage A-0，再 Stage A core/delivery；只有 Stage A
達到 `VERIFICATION_READY` 後，才可開始 Stage B。任何未實際執行的 evidence、
PLAY RECAP、verify verdict、idempotency 或 real-provider proof 都不得建立或寫成
已完成。

Stage A-0 — Identity Prerequisite PR

只做：

pilot_host Prometheus rendering
regression
`contracts/thanos-query.yaml` query endpoint correction `10902` → `10912`
corresponding Thanos provider-contract regression
real Thanos identity evidence

gate：

實際 real Thanos Query `:10912` sees canonical `pilot_host` and `site`。

不得同 PR加入 detector，也不得加入 Detection role/catalog/contract/site/
deploy/backup/MCP/verification surface 或 Detection source tests。

Stage A-1 — Engine Core PR

做：

Go binary
source client
features
scheduler
baseline
cohort
SQLite
lifecycle
unit tests

provider disabled。

Stage A-2 — Pilot Delivery PR

做：

Detection contract
inventory/catalog/deploy catalog
playbook/site
backup
Alertmanager outbox
verification spec and lint
MCP diagnose
fake/real topology artifacts and fixture delivery

gate：

Spec v2 PASS
topology PASS
idempotency changed=0

以上是待取得的 execution gates，不是目前已存在的結果。

Stage B-1 — Model Provider PR

前置：Stage A 已達 `VERIFICATION_READY`，並完成 §60/Appendix B 的 contract
準備。Stage B 不得提前混入 Stage A-0 或 Stage A core/delivery。

做：

schemas
OpenAI adapter
Ollama adapter
batch
fusion
fake provider
provider verification

gate：

provider disabled core still PASS
fake provider PASS

Stage B-2 — Real Provider Evidence

至少一個：

Ollama native
OR
OpenAI secret-gated

不把 SaaS key變 CI hard requirement。

本 repo 已知的 unrelated baseline failure（見 §55 現況快照）：
`TestRegression_LogShippingPlaybookAutoDetectsDashboardHost`
（internal/spec/log_shipping_regression_test.go）目前 fail，與
Detection Engine workstream 無關，也與 log-shipping/dashboard 的 host 自動
偵測邏輯有關而非 FreeIPA。這是 baseline failure；Detection workstream 必須
保存起始失敗輸出與 root cause，不能修復、掩蓋或把它寫成 Detection 的
evidence。coding agent 開始時仍須重新實測確認，不得假設本節快照仍與當下
worktree 一致。

59. Core Verification Contract

未來建立 `docs/verification/detection-engine.md`，其 row IDs 與 semantics 必須
逐一對應 §47 的 C1-C12；這是 Stage A-2 delivery gate，不能倒置成 A-0
的 prerequisite。建立後才執行：

```bash
go run ./cmd/pilot spec docs/verification/detection-engine.md --lint
```

這只是未來 verification 的 lint gate，不是現在的 target execution。文件加入
repo 前後都不得偽造 actual output、PLAY RECAP、verify verdict 或 evidence link；
真正結果必須依 AGENTS.md actual-run/evidence 規則產生。

60. Stage B Provider Acceptance Semantics

Stage B 僅在 Stage A 達到 `VERIFICATION_READY` 後開始。未來
`docs/verification/detection-engine-model-provider.md` 必須保留下列 M1-M5
normative semantics；Stage A provider disabled 時，這些 rows 是 not applicable，
不是 Stage A failure：

| Row | Stage B normative acceptance semantics |
| --- | --- |
| M1 | provider configuration obeys §41.1 inputRules; enabled provider has a non-empty base URL and model, and production external-provider permission is enforced by apply gate |
| M2 | request/response pass Appendix B schema and semantic validation; request ID equality, exact candidate-ID set equality, and no partial batch acceptance are enforced |
| M3 | OpenAI Responses and native Ollama Chat protocol behavior follows §§31-32, including structured output, incomplete/refusal handling, and client-side schema validation |
| M4 | retry, timeout, rate limit, circuit breaker, candidate cap/batching, and local fallback follow §§34-35; provider failure never suppresses local detection |
| M5 | API key has one Vault → provider.env → systemd environment ownership path; disabled/non-bearer cases do not require a secret and no secret appears in status, metrics, DB, logs, diagnose output, or evidence |

未來 verification doc 的 lint command 為：

```bash
go run ./cmd/pilot spec docs/verification/detection-engine-model-provider.md --lint
```

該文件與其 target output 目前不存在於本 spec 所代表的工作結果中；不得以它們
已存在或已通過來描述目前狀態。

61. Appendix B — Canonical Model Batch Schema Definitions

以下是 Stage B 的 canonical schema definition。未來 JSON files 是本 appendix 的
canonical rendering，不宣稱目前已存在；Go implementation 可以 embed 相同 schema，
但不得另造 single-candidate schema。

Request root（`model-detection-batch-request-v1.json`）：

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version", "request_id", "prompt_version", "window_seconds", "candidates"],
  "properties": {
    "schema_version": {"const": 1},
    "request_id": {"type": "string", "minLength": 1},
    "prompt_version": {"type": "integer", "const": 1},
    "window_seconds": {"const": 600},
    "candidates": {
      "type": "array", "minItems": 1, "maxItems": 4,
      "items": {
        "type": "object", "additionalProperties": false,
        "required": ["candidate_id", "pilot_host", "site", "evaluation_time", "current"],
        "properties": {
          "candidate_id": {"type": "string", "minLength": 1},
          "pilot_host": {"type": "string", "minLength": 1},
          "site": {"type": "string", "minLength": 1},
          "evaluation_time": {"type": "integer"},
          "current": {"type": "object", "additionalProperties": {"type": "number"}}
        }
      }
    }
  }
}
```

Response root（`model-detection-batch-response-v1.json`）：

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema_version", "request_id", "status", "candidates"],
  "properties": {
    "schema_version": {"const": 1},
    "request_id": {"type": "string", "minLength": 1},
    "status": {"enum": ["ok", "insufficient_data"]},
    "candidates": {
      "type": "array", "minItems": 1, "maxItems": 4,
      "items": {
        "type": "object", "additionalProperties": false,
        "required": ["candidate_id", "score", "confidence", "category_hint", "contributors"],
        "properties": {
          "candidate_id": {"type": "string", "minLength": 1},
          "score": {"type": "number", "minimum": 0, "maximum": 1},
          "confidence": {"type": "number", "minimum": 0, "maximum": 1},
          "category_hint": {"type": "string"},
          "contributors": {
            "type": "array",
            "items": {
              "type": "object", "additionalProperties": false,
              "required": ["feature", "score"],
              "properties": {
                "feature": {"type": "string", "minLength": 1},
                "score": {"type": "number", "minimum": 0, "maximum": 1}
              }
            }
          }
        }
      }
    }
  }
}
```

The JSON Schema dialect does not itself provide a portable `finite` keyword; the
implementation MUST additionally reject NaN/Inf. Semantic validation MUST enforce:

* response `request_id` equals request `request_id` exactly;
* response candidate IDs are unique and their set equals the request candidate ID set;
* every `contributors[].feature` exists in the matching request candidate's `current`;
* `status=insufficient_data` has `score=0`, `confidence=0`, and `contributors=[]`
  for every candidate; any other value is an invalid batch;
* candidate count is 1-4 in the same envelope for both single and batched requests;
* unknown fields are rejected at every defined object boundary (`additionalProperties: false`).

62. Definition of Done — Stage A (future gate)

以下是待完成的 Stage A gate，不是目前已完成的 verification 或 production
結果；每一項都需要依 §47 與 actual-run evidence 規則實際證明。

全部完成：

pilot_host 有真正 Prometheus producer。

real Thanos query有 canonical identity。

exact baseline formula。

zero-MAD regression。

cold-start regression。

exact cohort/self-exclusion。

missing/stale semantics。

exact lifecycle。

fingerprint/dedup。

SQLite migration。

signal/history/outbox atomic transaction。

outbox lease/retry/dead。

Alertmanager refresh。

warning→critical ordered transition。

resolution。

Go binary pinned + SHA256。

Ubuntu24 amd64 gate。

role catalog。

inventory generator。

inventory example。

site.yml。

backup integration。

pilot_diagnose_detection actually MCP-registered。

Spec v2 lint。

topology verify。

second apply changed=0。

real metrics chain cross-check。

24h staging soak completed before production enablement，或被 release gate明確阻擋。

63. Definition of Done — Stage B (future gate)

以下是待完成的 Stage B gate，不是目前已完成的 provider verification 或
real-provider proof。

every candidate has candidate_id。

batch schemas committed。

exact candidate-id set equality。

no partial batch acceptance。

OpenAI completed/incomplete/refusal handling。

OpenAI strict json_schema request。

Ollama native /api/chat schema mode。

no Ollama /v1/responses strict parity assumption。

no tools。

API key single ownership path。

max16 candidates/cycle。

max4 per batch。

no persistent candidate backlog。

exact retry/circuit。

model can escalate only。

provider failure local detection continues。

fake-provider verification PASS。

at least one real-provider evidence before production model enablement。

64. External API Baseline

coding agent implementation day必須重新確認 official docs。

OpenAI Responses

本 spec所依賴的 API shape：

POST /v1/responses
Structured Outputs under text.format json_schema
strict schema
response status / error / incomplete handling

Reference：

https://developers.openai.com/api/reference/resources/responses/methods/create

如果 OpenAI API在 implementation day改變：

update spec first

Ollama

本 spec不假設 OpenAI Responses strict parity。

使用：

POST /api/chat
format=<JSON Schema>

References：

https://docs.ollama.com/api/chat
https://docs.ollama.com/api/openai-compatibility

65. Coding Agent Start Checklist

在寫 production code前依序：

git status。

記錄 current revision / worktree diff。

讀 root AGENTS.md。

讀 current README。

讀 internal/spec/v2.go。

讀一份 current Spec v2 example。

讀 internal/contract/contract.go。

讀 inventory role catalog/render。

讀 Prometheus apply/spec/regression。

讀 Thanos/Alertmanager contract。

讀 MCP diagnose registration。

保存 current test baseline。

依 §58 完全相同的順序執行：

1. Stage A-0：只實作 `pilot_host` Prometheus producer、其 regression、
   `contracts/thanos-query.yaml` 的 `query` endpoint `10902` → `10912`
   provider-contract 修正與對應 regression，以及 real Thanos identity
   acceptance。保存 real Thanos evidence；這是待執行 gate，不是目前已有
   evidence。A-0 不加入 detector、Detection delivery surface、Detection
   source tests，也不要求先 lint 尚不存在的 Detection spec。
2. Stage A-1：完成 Engine Core（含 source client、features、scheduler、
   baseline、cohort、SQLite、lifecycle 與 unit tests），provider disabled。
3. Stage A-2：才 author `docs/verification/detection-engine.md`，依 §47/§60
   的 normative semantics 執行 Spec v2 lint，並完成 Detection contract、
   inventory/catalog/deploy、playbook/site、backup、Alertmanager outbox、
   fake/real topology、verification 與 MCP delivery gates。

Stage B provider spec 仍只能在 Stage A 達到 `VERIFICATION_READY` 後 author。

runbook所有 command只有 actual-run後才能寫入。

66. Final Invariants

1. Detection Engine 不直接查 managed hosts。
2. Managed-host metrics 經 Prometheus → Thanos。
3. pilot_host 由 inventory producer明確生成，不猜 IP。
4. Core Statistical MVP 不依賴模型。
5. Provider failure不是 Detection Plane outage。
6. Detection Engine 不執行模型 runtime。
7. NPU/GPU/CPU是 external model service implementation detail。
8. Model Provider沒有 tools或 mutation能力。
9. SignalEvent不是 root cause。
10. SignalEvent不直接觸發 infrastructure command。
11. Persistent transition + outbox atomic。
12. Pilot仍是 infrastructure mutation owner。
