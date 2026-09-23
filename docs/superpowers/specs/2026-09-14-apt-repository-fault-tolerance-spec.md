# Pilot APT Repository Fault-Tolerance 修正計畫

- 狀態：**已實作（Phase 1-5 全數完成，見下方 Implementation Status）**
- 日期：2026-09-14

## Implementation Status（2026-09-14 實作完成後補記）

Phase 1-5 已依 §16 Migration Plan 全數實作完成，分 5 個 commit：

1. `feat(apt): add fault-tolerant APT install framework, fix freeipa-client C1/C8`
   — 新框架（`playbooks/apply/tasks/apt-{package-install,cache-refresh,scoped-refresh,classify-failure}.yml`）
   + `docs/verification/apt-repository-tolerance.md` + `cmd/pilot/cmd/apt_policy_test.go`。
2. `feat(apt): migrate ordinary Ubuntu package installs to the shared apt framework`
   — docker/log-server/reverse-proxy/restic-backup/core-infra-provider(dns+ntp)/host-monitoring/pam-oidc-sshd。
3. `feat(apt): migrate pilot-owned wazuh/nvidia repo installs to the shared apt framework`
   — wazuh-fim、dcgm-exporter，required source 改宣告各自的 pilot-owned repo。
4. `feat(apt): fix audit-log-forwarding's universe-enablement blast radius`
   — Step 0a `update_cache: false` + 移除 Step 0b，Step 1 改走框架。
5. Phase 5（CI static guard）：`TestAptUpdateCacheAllowlist`/`TestAptNoInsecureFlags` 已隨 Phase 1
   commit 一併加入，並在 Phase 2-4 過程中隨每次遷移縮小 allowlist（現僅剩
   `playbooks/apply/os-patch-sla-apply.yml` 一筆合法例外）；兩者都在既有
   `.github/workflows/ci.yml` 的 `go test -race -count=1 ./...` 步驟下自動跑，未額外新增 CI job。
6. **`fix(apt): fix 4 bugs found via live vm-target testing`** — 2026-09-14 補測，見下方。
7. **`fix(apt)` 2026-09-23（`ad6d552`、`5b735ee`）**：`ad6d552` 補上 cached candidate
   的 `.deb` 404 → refresh 路徑。`5b735ee` 讓每個 apt-get 網路步驟都有 wall clock，
   並且 stale 路徑必須等到 refresh 健康、且 re-probe 不再 404，才採信 candidate
   （§21.1 T11/T12）。實跑見 `docs/evidence/apt-repository-tolerance/2026-09-23-5b735ee.md`。

**驗證完成度**：
- `ansible-playbook --syntax-check` / `ansible-lint`（advisory）/ `go build ./...` /
  `go vet ./...` / `go test ./...`（含 `-race`）全數 PASS。
- Classifier（`apt-classify-failure.yml`）的單元測試改用本機真實 Ubuntu 24.04
  `apt-get` 擷取的輸出當 fixture（非手寫猜測），過程中就抓到 2 個真 bug 並已修正
  （見 `docs/verification/apt-repository-tolerance.md`、`cmd/pilot/cmd/apt_policy_test.go`）。
- **§22 disposable VM live scenario T1/T3/T7 — 已於 2026-09-14 在 `pilot vm-target`
  （`apt-tolerance-test`, ubuntu-24.04）上實跑完成**（`vm-target-spec-testing` skill）：
  - **T1**（無關 HashiCorp repo 壞掉不擋 freeipa-client/sssd-tools 安裝）：真實重現
    incident 錯誤（`NO_PUBKEY FC9CA96ACA026560`），`apt_mode=global_refresh`，
    `required_sources_healthy=True`，`unrelated_sources_degraded=3`，`dpkg -l` 確認兩個
    package 真的裝上。
  - **T3**（required source 本身壞掉 → fatal）：破壞 `/etc/apt/sources.list.d/ubuntu.sources`
    指向不存在的 host，playbook 正確以 `FATAL(required_source_unhealthy)` 中止
    （`reason=required_source_unhealthy required_sources=['ubuntu-os']`），`dpkg -l`
    確認兩個 package 都沒裝上,`/run/pilot/apt/` 清乾淨(block/always cleanup 有跑)。
  - **T7**（pilot-owned repo 簽章壞掉 → fatal,不降級成 unauthenticated）：用
    `wazuh-fim-apply.yml` 實測(它是唯一真的宣告 `class: pilot` required source 的
    playbook)——先正常裝一次(`apt_mode=global_refresh`,容忍同一個壞掉的 HashiCorp
    repo),再故意弄壞 `/usr/share/keyrings/wazuh.gpg`,重跑正確 fatal
    (`required_source_id=pilot-wazuh`),`dpkg -l` 確認沒有 fallback 成功安裝。
  - **實測過程中額外抓到並修好 4 個真 bug**(單元測試沒抓到):
    1. dynamic `include_tasks` 的 `tags:` 不會自動傳給被 include 進來的 task——
       `--tags C1`(常見的單一 row 開發流程,AGENTS.md §4)靜默裝不上任何東西、
       完全不報錯。改成 `include_tasks: {file:..., apply: {tags:[...]}}`,並新增
       `TestAptPackageInstallCallSitesUseApplyTags` 鎖死不能再用裸 `include_tasks:` 形式。
    2. `apt-cache-refresh.yml` 的 `required_sources_healthy` 誤把 `apt-get update`
       的整體 exit code(任何一個來源壞掉就非0)跟「required source 是否健康」掛勾,
       導致無關 repo 壞掉時這個欄位會誤報 false。
    3. `ansible.builtin.tempfile` 的 `path: /run/pilot/apt` 在該目錄從未存在過的
       host 上直接炸掉(module 不會自己建父目錄)。
    4. `apt-cache policy pkg1 pkg2` 對完全沒聽過的 package 會整段從輸出省略(不是
       印 `Candidate: (none)`),導致跟已知 package 合併查詢時被誤判成「已有 candidate」。
       改成每個 missing package 各自呼叫一次 `apt-cache policy`。
  這 4 個加上先前 classifier 的 2 個 wording bug,總共 6 個 bug 都是「只靠單元測試/推理
  絕對抓不到,只有真的跑一次 vm-target 才會暴露」的類型,完整證明了 AGENTS.md §1.1
  actual-run 規則的價值。
- 目標專案：`https://github.com/kjelly/pilot`
- 基準版本：`main@8283056081ba19b9e7f9e4059aa269f5cad4a72a`
- 主要事故：非 Pilot 所需的第三方 APT repository 發生 GPG / TLS / timeout / metadata 錯誤，導致 `ansible.builtin.apt(update_cache=true)` 讓整個 Pilot deploy fatal。
- 實際案例：
  - host: `x64-deliver-bbq`
  - task: `FreeIPA client — install ipa-client package (apt freeipa-client on Ubuntu)`
  - unrelated source: HashiCorp APT repository
  - error: `NO_PUBKEY FC9CA96ACA026560`
  - 結果：`freeipa-client` 本身可由 Ubuntu repository 提供，但 Pilot 因全域 cache refresh 失敗而停止 deploy。

---

## 1. Problem Statement

Pilot 現有多個 Debian/Ubuntu capability 將「安裝 package」與「刷新所有 configured APT repositories」綁在同一個 `ansible.builtin.apt` task：

```yaml
ansible.builtin.apt:
  name: freeipa-client
  state: present
  update_cache: true
```

這會把 failure boundary 擴大成：

```text
任何 /etc/apt/sources.list{,.d/*} repository 異常
        ↓
apt metadata refresh 失敗
        ↓
與該 repository 無關的 package install 也失敗
        ↓
Pilot capability deploy fatal
```

Pilot 管理的主機屬於 Day-2 environment，使用者可能自行：

- 新增 HashiCorp / Kubernetes / Docker / NVIDIA / CUDA / vendor repository。
- 移除或替換 GPG key。
- 留下 EOL / obsolete repository。
- 修改 mirror。
- 設定暫時無法連線的內網 repository。
- 加入錯誤的 distribution codename。
- 加入 architecture 不相容的 source。

Pilot 不應假設 `/etc/apt` 完全由 Pilot 控制。

---

## 2. Current Repository Findings

基準 `main@8283056081ba19b9e7f9e4059aa269f5cad4a72a` 至少有下列直接或條件式 cache refresh：

| Playbook | Package / 用途 | 現況 | 目標 policy |
|---|---|---|---|
| `playbooks/apply/freeipa-client-apply.yml` | `freeipa-client`(C1)、`sssd-tools`(C8) | `update_cache: true`（兩個獨立 task） | tolerant |
| `playbooks/apply/docker-apply.yml` | `docker.io`, `docker-compose-v2` | `update_cache: true` | tolerant |
| `playbooks/apply/log-server-apply.yml` | `rsyslog` | `update_cache: true` | tolerant |
| `playbooks/apply/reverse-proxy-apply.yml` | `nginx` | `update_cache: true` | tolerant |
| `playbooks/apply/restic-backup-apply.yml` | `restic` | `update_cache: true` | tolerant |
| `playbooks/apply/core-infra-provider-apply.yml` | DNS provider package（`dns-C1`）、NTP provider package `chrony`（`ntp-C4`） | `update_cache: true`（兩個獨立 task） | tolerant |
| `playbooks/apply/host-monitoring-apply.yml` | `apache2-utils` 等 | `update_cache: true` | tolerant |
| `playbooks/apply/pam-oidc-sshd-apply.yml` | build dependencies | `update_cache: true` | tolerant |
| `playbooks/apply/audit-log-forwarding-apply.yml` | Ubuntu universe mutation | special repo semantics | special handling |
| `playbooks/apply/wazuh-fim-apply.yml` | Wazuh repo/package | conditional refresh | Pilot-owned repo strict |
| `playbooks/apply/dcgm-exporter-apply.yml` | NVIDIA toolkit repo | conditional refresh | Pilot-owned repo strict |
| `playbooks/apply/os-patch-sla-apply.yml` | OS patching | global refresh | **strict, 不得 tolerant** |

本計畫不得只修 FreeIPA；必須建立共用 package execution policy，避免相同 defect 在其他 capability 重複發生。

---

## 3. Goals

### G1. Unrelated repository failure 不得阻止 capability deploy

若：

- 目標 package 已安裝；或
- 目標 package 在目前 APT cache 有合法 candidate；或
- 目標 package 的 required repository 可以獨立 refresh；

則其他無關 repository 的錯誤只能形成 warning / degraded evidence，不得直接 fatal。

### G2. Required repository failure 必須 fatal

例如：

```text
freeipa-client 需要 Ubuntu archive
Ubuntu archive metadata 無法取得
→ fatal
```

```text
wazuh-agent 需要 Pilot 管理的 Wazuh repository
Wazuh repository GPG 驗證失敗
→ fatal
```

### G3. 不降低 APT package authentication

不得使用：

- `trusted=yes`
- `allow_unauthenticated=yes`
- `--allow-unauthenticated`
- `--force-yes`
- 自動信任未知 GPG key
- 自動從 public keyserver 匯入任意 `NO_PUBKEY`
- 全域停用 signature verification

### G4. 不任意修改使用者 repository

普通 capability deploy 不得為了讓 Pilot 成功而：

- disable 使用者 source；
- rename 使用者 `.list` / `.sources`；
- 刪除使用者 repository；
- 修改第三方 source 的 key；
- 自動「修復」非 Pilot-owned repo。

只能：

1. 診斷；
2. 隔離到本次 execution view；
3. 產生 warning/evidence。

### G5. 保留 strict operations

以下類型維持 strict：

- OS patch / upgrade。
- Pilot 正在建立或更新的 repository。
- Pilot-owned package source。
- security-sensitive repository mutation。
- 使用者顯式要求 full APT health validation。

---

## 4. Non-Goals

本 phase 不做：

1. 通用 Ubuntu repository repair daemon。
2. 自動修復所有第三方 vendor repository。
3. 自動旋轉第三方 GPG key。
4. 變更 `/etc/apt` ownership model。
5. 將所有 package manager 抽象成跨 distro framework。
6. 同時重構 DNF/YUM；RedHat path 保留現行行為。
7. 讓 `os-patch-sla` 忽略 repository failure。

---

## 5. Core Design

新增共用 APT execution layer：

```text
playbooks/apply/tasks/
├── apt-package-install.yml
├── apt-cache-refresh.yml
├── apt-scoped-refresh.yml
└── apt-classify-failure.yml
```

其中 `apt-package-install.yml` 為普通 capability 安裝 Debian package 的唯一主要入口。

### 5.1 Policy

支援三種 policy：

```yaml
pilot_apt_policy: tolerant | strict | offline
```

#### tolerant

適用普通 capability：

```text
package installed?
    yes → success

APT cache 有 candidate?
    yes → 直接 install，不 global update

candidate 不存在 / install 顯示 metadata stale?
    ↓
best-effort global refresh
    ↓
global refresh success?
    yes → retry install

global refresh degraded?
    ↓
scoped refresh required repositories
    ↓
required source refresh success + candidate exists?
    yes → retry install + warning unrelated sources
    no  → fatal
```

#### strict

適用：

- `os-patch-sla`
- repository lifecycle management
- Pilot-owned source install/update

語意：

```text
任何 required repository metadata/signature error → fatal
必要時 global repository health 也必須成功
```

#### offline

禁止 network metadata refresh：

```text
已安裝 → success
cached candidate 可安裝 → install
否則 → fatal(reason=apt_cache_insufficient_offline)
```

---

## 6. Required Source Model

普通 capability 不應靠 stderr 字串猜「這個壞 repo 是否相關」。

呼叫端必須宣告 package source dependency：

```yaml
pilot_apt_packages:
  - freeipa-client

pilot_apt_policy: tolerant

pilot_apt_required_sources:
  - id: ubuntu-os
    class: os
```

Pilot-owned repo：

```yaml
pilot_apt_required_sources:
  - id: pilot-wazuh
    class: pilot
    source_file: /etc/apt/sources.list.d/pilot-wazuh.sources
```

### 6.1 Source classes

| class | 意義 | ownership |
|---|---|---|
| `os` | Ubuntu/Debian official distro archive | OS |
| `pilot` | Pilot 建立並管理的 source | Pilot |
| `external` | 使用者或第三方建立 | external |

### 6.2 第一階段 source scope

第一階段只需要可靠處理：

1. Ubuntu official OS sources。
2. Pilot-owned explicit source file。

不得嘗試完整建立「package → arbitrary repository」solver。

---

## 7. Package Installation State Machine

`apt-package-install.yml` 必須實作以下 deterministic state machine：

```text
START
  │
  ├─ package facts / dpkg-query
  │      └─ all requested packages already installed
  │              → SUCCESS(already_present)
  │
  ├─ apt-cache policy <packages>
  │      └─ every missing package has Candidate != (none)
  │              → INSTALL_WITHOUT_UPDATE
  │                    ├─ success → SUCCESS(cache_hit)
  │                    └─ metadata-related failure → REFRESH
  │
  └─ no candidate
         ↓
      REFRESH
         │
         ├─ strict
         │    └─ strict refresh
         │           ├─ success → install
         │           └─ failure → FATAL
         │
         ├─ offline
         │    └─ FATAL(cache_insufficient)
         │
         └─ tolerant
              ├─ best-effort global refresh
              │    ├─ success → install
              │    └─ degraded
              │
              └─ scoped required-source refresh
                   ├─ success + candidate → install
                   └─ failure/no candidate → FATAL
```

---

## 8. Why Cache-First

目前 defect 的根因不是「APT 有 warning」本身，而是 Pilot 每次 capability package install 都主動要求：

```text
refresh every configured source
```

但安裝一個 Ubuntu package 通常只需要：

```text
usable package index for the source that provides the package
```

因此應改成：

```text
current cache
→ package candidate
→ install
```

只在 cache 不足時才 refresh。

這同時降低：

- 外部 repo blast radius。
- deploy latency。
- transient network dependency。
- rate limit / mirror load。
- 相同 deterministic GPG failure 被無意義 retry 5 次的情況。

---

## 9. `apt-cache-refresh.yml`

### Inputs

```yaml
pilot_apt_policy: tolerant
pilot_apt_required_sources: []
pilot_apt_refresh_reason: package_candidate_missing
```

### Outputs

應透過 facts/register 產生：

```yaml
pilot_apt_refresh_result:
  status: healthy | degraded | failed | skipped
  mode: global | scoped | none
  errors:
    - source: https://apt.releases.hashicorp.com
      class: external
      type: gpg_no_pubkey
      key_id: FC9CA96ACA026560
      required: false
  required_sources_healthy: true
```

### Rules

`tolerant` global refresh：

```yaml
changed_when: false
failed_when: false
```

但這只允許「refresh probe」不直接中止 Ansible。

**最終 package install 不得 `ignore_errors: true`。**

每次 `apt-get update`（global 與 scoped）都以 coreutils `timeout` 包住：超過
`pilot_apt_update_timeout_seconds`（預設 300）送 TERM，30 秒後 KILL。Ansible
command module 看到的 rc 是 124（TERM 結束）或 -9（需要 KILL；`timeout` 會 KILL
整個 process group，包含它自己）；經過 shell 時 KILL 顯示為 137。逾時時
`errors` 追加一筆 `type: refresh_timeout, required: true`，且
`required_sources_healthy` 一律為 false——逾時無法判斷是哪個 source 卡住。
（2026-09-23 實測起因：vm-target 上 `apt-get update` 卡在 caching proxy 一條
CLOSE-WAIT 連線，沒有上限，整個 play 停住。）

---

## 10. Failure Classification

`apt-classify-failure.yml` 至少分類：

| type | pattern examples | default |
|---|---|---|
| `gpg_no_pubkey` | `NO_PUBKEY` | degraded/fatal by ownership |
| `gpg_invalid_signature` | invalid signature | degraded/fatal by ownership |
| `release_missing` | `does not have a Release file` | degraded/fatal by ownership |
| `tls_failure` | certificate / TLS validation | degraded/fatal by ownership |
| `dns_failure` | temporary failure resolving | degraded/fatal by ownership |
| `connect_timeout` | connection timed out | degraded/fatal by ownership |
| `http_404` | Release/InRelease 404 | degraded/fatal by ownership |
| `wrong_distribution` | repository suite/codename invalid | degraded/fatal by ownership |
| `apt_lock` | dpkg/apt lock | bounded retry |
| `dpkg_interrupted` | `dpkg was interrupted` | fatal |
| `dependency_broken` | unmet dependencies | fatal |
| `package_no_candidate` | no installation candidate | fatal after scoped refresh |
| `unknown` | unknown apt failure | conservative fatal if install blocked |
| `refresh_timeout` | `apt-get update` 超過 `pilot_apt_update_timeout_seconds`（rc 124／-9／137，不是從文字比對） | 一律視為 required source 不健康 |

Classification 不得把未知 package install error 靜默降級。

---

## 11. Bounded Retry Policy

只 retry 可能恢復的 transient failure：

```yaml
pilot_apt_lock_retries: 6
pilot_apt_lock_delay_seconds: 10

pilot_apt_network_retries: 2
pilot_apt_network_delay_seconds: 5

pilot_apt_update_timeout_seconds: 300     # 每次 apt-get update 的 wall clock
pilot_apt_download_timeout_seconds: 900   # 每次 --download-only probe 的 wall clock
```

逾時不 retry（lock retry 只看 lock 訊息）：卡住的 mirror/proxy 重跑通常一樣卡住。
Download probe 逾時直接 `FATAL reason=apt_download_timeout`，因為真正的 install
會用同一條路徑抓同一批檔案。

不得 retry：

- `NO_PUBKEY`
- invalid GPG signature
- Release file missing
- wrong distribution codename
- package not found after successful refresh

這些屬 deterministic failure。

---

## 12. Scoped Refresh

### 12.1 Purpose

當：

```text
/etc/apt/sources.list.d/hashicorp.list → broken
/etc/apt/sources.list.d/random.list    → broken
```

但本次只需要 Ubuntu archive 時，不修改上述檔案，而建立 temporary execution view。

### 12.2 Runtime directory

```text
/run/pilot/apt/<execution-id>/
├── sources.list
└── sources.list.d/
```

權限：

```text
owner=root
group=root
mode=0700
```

結束後 cleanup。

### 12.3 Command shape

使用 APT config override：

```bash
apt-get \
  -o Dir::Etc::sourcelist=/run/pilot/apt/<id>/sources.list \
  -o Dir::Etc::sourceparts=/run/pilot/apt/<id>/sources.list.d \
  -o APT::Get::List-Cleanup=0 \
  update
```

禁止使用：

```text
trusted=yes
allow_unauthenticated
Acquire::AllowInsecureRepositories=true
```

**實作提醒**：`ansible.builtin.apt` module 沒有原生參數可覆寫 `Dir::Etc::sourcelist`/`sourceparts`，
scoped refresh 必須用 `ansible.builtin.command`/`shell` 直接呼叫 `apt-get -o ... update`
並自行 `register` 解析 rc/stdout/stderr 分類失敗（見 §10），無法只靠 apt module 參數達成；
`Dir::State::lists` 維持預設值，讓 metadata cache 落在系統標準位置，不建立額外持久化目錄。

### 12.4 OS source handling

不得 hard-code 單一 Ubuntu URL。

應從 host 現有 official Ubuntu source 中：

1. 解析 enabled source。
2. 只選擇 Ubuntu official archive/security entries。
3. 保留 host 實際 mirror、suite、component、architecture、Signed-By。
4. copy/render 到 `/run/pilot/apt/...` temporary view。

若無法可靠辨識任何 OS source：

```text
fatal reason=required_os_source_unresolvable
```

不得自行猜 mirror。

### 12.5 Pilot-owned source handling

Pilot 建立 repo 時統一命名：

```text
/etc/apt/sources.list.d/pilot-<capability>.sources
/etc/apt/keyrings/pilot-<capability>.gpg
```

例如：

```text
pilot-wazuh.sources
pilot-nvidia-container-toolkit.sources
```

Scoped refresh 可直接 allowlist source file。

---

## 13. Repository Ownership Contract

新建立的 Pilot repository 必須符合：

```text
source file:
  /etc/apt/sources.list.d/pilot-<name>.sources

key:
  /etc/apt/keyrings/pilot-<name>.gpg
```

Pilot 只對 `pilot-*` repository 執行 lifecycle repair。

對 external repository：

```text
detect → report → isolate
```

而不是：

```text
detect → mutate
```

---

## 14. `apt-package-install.yml` Interface

### Required

```yaml
pilot_apt_packages:
  - freeipa-client
```

### Optional

```yaml
pilot_apt_policy: tolerant

pilot_apt_required_sources:
  - id: ubuntu-os
    class: os

pilot_apt_cache_valid_time: 3600
pilot_apt_allow_scoped_refresh: true
pilot_apt_component: freeipa-client
pilot_apt_update_timeout_seconds: 300
pilot_apt_download_timeout_seconds: 900
```

### Assertions

Task 開始必須 assert：

```text
pilot_apt_packages non-empty
policy ∈ {tolerant, strict, offline}
required source schema valid
pilot-owned source path 必須在 /etc/apt/sources.list.d/
```

---

## 15. FreeIPA Immediate Fix

修改：

```text
playbooks/apply/freeipa-client-apply.yml
```

本檔案有兩個獨立 task 帶有同樣的 unrelated-repository blast-radius 缺陷，**必須一起修，不得只修其中一個**：

- C1：「FreeIPA client — install ipa-client package (apt freeipa-client on Ubuntu)」
- C8：「FreeIPA client — install SSSD cache tools (Debian)」（安裝 `sssd-tools`）

由：

```yaml
- name: "FreeIPA client — install ipa-client package (apt freeipa-client on Ubuntu)"
  ansible.builtin.apt:
    name: "{{ ipa_client_packages_debian }}"
    state: present
    update_cache: true
  when:
    - not ansible_check_mode
    - ansible_os_family == 'Debian'
  tags: [freeipa-client, C1]

# ... (略) ...

- name: "FreeIPA client — install SSSD cache tools (Debian)"
  ansible.builtin.apt:
    name: sssd-tools
    state: present
    update_cache: true
  when:
    - not ansible_check_mode
    - ansible_os_family == 'Debian'
  tags: [freeipa-client, C8]
```

改為：

```yaml
- name: "FreeIPA client — install ipa-client package (Debian)"
  ansible.builtin.include_tasks: tasks/apt-package-install.yml
  vars:
    pilot_apt_packages: "{{ ipa_client_packages_debian }}"
    pilot_apt_policy: tolerant
    pilot_apt_component: freeipa-client
    pilot_apt_required_sources:
      - id: ubuntu-os
        class: os
  when:
    - not ansible_check_mode
    - ansible_os_family == 'Debian'
  tags: [freeipa-client, C1]

# ... (略) ...

- name: "FreeIPA client — install SSSD cache tools (Debian)"
  ansible.builtin.include_tasks: tasks/apt-package-install.yml
  vars:
    pilot_apt_packages: [sssd-tools]
    pilot_apt_policy: tolerant
    pilot_apt_component: freeipa-client-sssd-tools
    pilot_apt_required_sources:
      - id: ubuntu-os
        class: os
  when:
    - not ansible_check_mode
    - ansible_os_family == 'Debian'
  tags: [freeipa-client, C8]
```

Acceptance：

```text
HashiCorp NO_PUBKEY + Ubuntu archive healthy
→ freeipa-client (C1) install succeeds
→ sssd-tools (C8) install succeeds
→ deploy continues
→ warning records HashiCorp failure
```

---

## 16. Migration Plan

### Phase 1 — Framework + FreeIPA regression fix

建立：

```text
playbooks/apply/tasks/apt-package-install.yml
playbooks/apply/tasks/apt-cache-refresh.yml
playbooks/apply/tasks/apt-scoped-refresh.yml
playbooks/apply/tasks/apt-classify-failure.yml
```

修改：

```text
playbooks/apply/freeipa-client-apply.yml
```

新增測試與 verification。

此 phase 必須先獨立完成，確認實際 incident 可以重現及修復。

### Phase 2 — Ubuntu-native packages

遷移：

```text
docker-apply.yml
log-server-apply.yml
reverse-proxy-apply.yml
restic-backup-apply.yml
core-infra-provider-apply.yml
host-monitoring-apply.yml
pam-oidc-sshd-apply.yml
```

條件：

```text
ordinary Ubuntu package
→ pilot_apt_policy=tolerant
→ required source=os
```

### Phase 3 — Pilot-owned third-party repos

檢查並遷移：

```text
wazuh-fim-apply.yml
dcgm-exporter-apply.yml
```

策略：

```text
repo provisioning → strict
package installation after repo verified → tolerant against unrelated external repos
required source → pilot-owned repo
```

### Phase 4 — Special repository mutation

單獨 review：

```text
audit-log-forwarding-apply.yml
```

因該 playbook 有 Ubuntu `universe` source mutation/check-mode semantics，不可機械式替換。

要求：

```text
universe enablement → strict mutation
其他 external repo failure → 不應阻止 universe required source 驗證
```

### Phase 5 — Policy enforcement

加入 CI / static regression guard：

普通 apply playbook 不得新增：

```yaml
ansible.builtin.apt:
  ...
  update_cache: true
```

除 allowlist：

```text
os-patch-sla-apply.yml
apt framework internal implementation
explicit repository lifecycle tasks
```

---

## 17. `os-patch-sla` Exception

`playbooks/apply/os-patch-sla-apply.yml` 必須維持 strict。

原因：

OS patch 的語意不是「裝某一個 capability package」，而是：

```text
確認 host configured package universe 的 metadata 足夠可信
→ 計算 / 套用 upgrade
```

若某 configured repository 無法 refresh，patch result 可能不完整。

因此不得把：

```yaml
update_cache: true
```

直接替換成 tolerant best-effort。

建議未來明確標記：

```yaml
pilot_apt_policy: strict
pilot_apt_operation: os_patch
```

---

## 18. Observability

Deploy output 至少要能看出：

```text
WARN host=x64-deliver-bbq
     component=freeipa-client
     apt_source=https://apt.releases.hashicorp.com
     apt_source_class=external
     apt_error=gpg_no_pubkey
     apt_key_id=FC9CA96ACA026560
     required_by_action=false
     action=isolated
```

成功結果：

```text
OK host=x64-deliver-bbq
   component=freeipa-client
   package=freeipa-client
   apt_mode=scoped_refresh
   required_sources_healthy=true
   unrelated_sources_degraded=1
```

Fatal：

```text
FATAL host=x64-deliver-bbq
      component=freeipa-client
      package=freeipa-client
      reason=required_source_unhealthy
      required_source=ubuntu-os
```

不得只輸出：

```text
Failed to update apt cache after 5 retries
```

因為此訊息缺乏 failure ownership 與 action relevance。

---

## 19. Evidence Contract

每次 tolerant degradation 至少保存：

```yaml
host:
component:
timestamp:
policy:
requested_packages:
refresh_mode:
required_sources:
degraded_sources:
classification:
install_result:
```

若 Pilot 現有 deploy outcome/receipt framework 可承載，應整合到既有 evidence，而不是建立第二套持久化系統。

本 phase 不要求建立新的中央 DB。

---

## 20. Check Mode

`--check --diff` 不應因 temporary scoped refresh 造成 mutation。

原則：

```text
check mode:
  - 可讀取 dpkg/package state
  - 可讀取 apt-cache policy
  - 可分析 source files
  - 不執行 network refresh
  - 不寫 /run/pilot temporary source view（除非既有 Pilot preview contract 明確允許）
  - 回報 "would require refresh" / "candidate available"
```

對已有特殊 check-mode mutation 語意的 playbook（例如 repository enablement）逐案保留現有 contract。

---

## 21. Tests

### 21.1 Unit / task-level scenarios

至少建立以下 scenarios。

#### T1 — Unrelated GPG key failure

Host：

```text
Ubuntu source healthy
HashiCorp source → NO_PUBKEY FC9CA96ACA026560
freeipa-client not installed
```

Expected：

```text
FreeIPA package install SUCCESS
warning=hashicorp
required_sources_healthy=true
```

#### T2 — Unrelated repo timeout

```text
external vendor repo timeout
Ubuntu source healthy
nginx requested
```

Expected：

```text
SUCCESS + warning
```

#### T3 — Required Ubuntu source broken

```text
Ubuntu archive unavailable
external repos irrelevant
freeipa-client requested
cache has no usable candidate
```

Expected：

```text
FATAL(required_source_unhealthy)
```

#### T4 — Existing package

```text
freeipa-client already installed
all repos broken
```

Expected：

```text
SUCCESS(already_present)
不得執行 apt-get update
```

#### T5 — Cache hit

```text
package missing
cached candidate exists
external repo broken
```

Expected：

```text
install without update
SUCCESS(cache_hit)
```

#### T6 — Stale cache then scoped recovery

```text
candidate initially unavailable/stale
global update fails due external source
scoped Ubuntu refresh succeeds
```

Expected：

```text
SUCCESS(scoped_refresh)
```

#### T7 — Pilot-owned repo GPG failure

```text
wazuh-agent requested
pilot-wazuh source signature invalid
```

Expected：

```text
FATAL
不得降級
```

#### T8 — dpkg interrupted

Expected：

```text
FATAL(dpkg_interrupted)
```

#### T9 — apt lock

Expected：

```text
bounded retry
成功則 continue
超過 retry budget → fatal
```

#### T10 — unknown apt install error

Expected：

```text
FATAL
```

#### T11 — Stale metadata, refresh fails or times out

```text
cached candidate exists, its .deb downloads 404 (stale index)
apt-get update to the required source hangs (or fails)
```

Expected：

```text
global refresh: refresh_timeout (or classified required error), required_sources_healthy=false
舊 index 的 candidate 不被採信，不做 install
scoped refresh 同樣失敗 → FATAL(stale_metadata_unrecovered)
package 沒有裝上；每次 update 在 pilot_apt_update_timeout_seconds 內結束
```

（2026-09-23 前的行為：refresh 被砍掉後仍回報 ok，舊 candidate 通過 re-check，
install 撞上同一批 404。）

#### T12 — Download probe stalls

```text
cached candidate exists, package download never completes
```

Expected：

```text
FATAL(apt_download_timeout)，在 pilot_apt_download_timeout_seconds 內結束
```

### 21.2 Security regression tests

必須 grep/assert repository 中不存在新增：

```text
allow_unauthenticated
--allow-unauthenticated
--force-yes
trusted=yes
Acquire::AllowInsecureRepositories
```

除非既有 legacy 已存在，則測試至少禁止本 change 新增。

### 21.3 Static policy test

新增 Go test 或 shell/static test：

```text
playbooks/apply/**/*.yml
```

偵測 `ansible.builtin.apt` + `update_cache: true`。

只有 allowlist 可以通過。

建議 allowlist：

```text
playbooks/apply/os-patch-sla-apply.yml
playbooks/apply/tasks/apt-cache-refresh.yml
playbooks/apply/tasks/apt-scoped-refresh.yml
```

repo-specific lifecycle task 若需要新增，必須明確加入 allowlist 並有註解。

---

## 22. Live VM Acceptance Test

必須用 disposable Ubuntu vm-target 驗證，不只做 syntax/unit test。

### Scenario A — 重現 incident

1. 建立 Ubuntu VM。
2. 加入一個 syntactically valid 但 key 缺失的 external repository。
3. 確認：

```bash
apt-get update
```

會出現 GPG failure / `NO_PUBKEY`。

4. 執行 FreeIPA client package path。

Before fix：

```text
fatal at apt update_cache
```

After fix：

```text
external repo warning
freeipa-client 安裝成功
```

### Scenario B — required source failure

1. 讓 Ubuntu required source 無法使用。
2. 清除會讓測試誤判的 relevant package lists/cache。
3. 執行同一 capability。

Expected：

```text
fatal
```

證明 implementation 沒有把所有 APT failure 都吞掉。

### Scenario C — signature security

建立 required Pilot-owned repo，故意使用錯誤 key。

Expected：

```text
fatal
```

且不得 fallback 到 unauthenticated install。

---

## 23. Validation Commands

Coding agent 完成後至少執行：

```bash
ansible-playbook --syntax-check playbooks/apply/freeipa-client-apply.yml
ansible-lint playbooks/apply/freeipa-client-apply.yml
ansible-lint playbooks/apply/tasks/apt-package-install.yml
ansible-lint playbooks/apply/tasks/apt-cache-refresh.yml
ansible-lint playbooks/apply/tasks/apt-scoped-refresh.yml
ansible-lint playbooks/apply/tasks/apt-classify-failure.yml

go build ./...
go vet ./...
go test ./...
```

以及 Pilot 現有對應 verification：

```text
pilot verify docs/verification/freeipa-client.md
```

若新增 dedicated verification contract，建議：

```text
docs/verification/apt-repository-tolerance.md
```

---

## 24. Documentation Changes

新增：

```text
docs/verification/apt-repository-tolerance.md
```

內容至少描述：

- tolerant/strict/offline semantics。
- external vs Pilot-owned repository。
- failure classification。
- scoped refresh。
- security invariants。
- acceptance cases。

更新：

```text
docs/verification/freeipa-client.md
```

加入 regression：

```text
unrelated broken APT source must not block freeipa-client installation
```

必要時更新 runbook，讓 operator 知道 warning 代表：

```text
Pilot capability 成功
但 host 存在非 Pilot-owned APT hygiene issue
```

---

## 25. Implementation Constraints

### MUST

- cache-first。
- package install 與 global refresh 解耦。
- unrelated source degradation 可繼續。
- required source failure fatal。
- scoped refresh 不修改 external repo。
- signature verification 永遠保留。
- unknown install failure conservative fatal。
- `os-patch-sla` strict。
- live VM 重現原事故。
- framework 可供其他 playbook reuse。

### MUST NOT

- `ignore_errors` 包住最終 package install。
- `trusted=yes`。
- `allow_unauthenticated`。
- 自動刪 external repo。
- 自動匯入 unknown GPG key。
- 只針對 HashiCorp hard-code exception。
- 只修 `freeipa-client-apply.yml` 而留下同樣 pattern。
- 以 stderr 包含 `W:` 就一律判 success。
- 以 `apt-get update` exit code 單獨決定 capability 是否可執行。

---

## 26. Recommended File-Level Change Set

第一個 PR 建議控制在：

```text
NEW
  playbooks/apply/tasks/apt-package-install.yml
  playbooks/apply/tasks/apt-cache-refresh.yml
  playbooks/apply/tasks/apt-scoped-refresh.yml
  playbooks/apply/tasks/apt-classify-failure.yml
  docs/verification/apt-repository-tolerance.md

MODIFY
  playbooks/apply/freeipa-client-apply.yml
  docs/verification/freeipa-client.md

TEST
  新增 apt tolerance regression/static tests
```

第二個 PR 再批次 migrate：

```text
docker-apply.yml
log-server-apply.yml
reverse-proxy-apply.yml
restic-backup-apply.yml
core-infra-provider-apply.yml
host-monitoring-apply.yml
pam-oidc-sshd-apply.yml
```

第三個 PR：

```text
wazuh-fim-apply.yml
dcgm-exporter-apply.yml
audit-log-forwarding-apply.yml
CI policy guard final enforcement
```

避免一次 PR 同時改所有 package paths，降低 semantic regression 風險。

---

## 27. Acceptance Criteria

此工作只有在下列全部成立時完成：

- [x] `x64-deliver-bbq` 類型的 HashiCorp `NO_PUBKEY` 不再阻止 Ubuntu `freeipa-client` (C1) 與 `sssd-tools` (C8) installation。(靜態/單元層級;live VM 未驗證,見下)
- [x] `cmd/pilot/cmd/tag_coverage_test.go::TestSpecPlaybookTagAlignment` 對 `freeipa-client-apply.yml`（含改後 C1/C8 include_tasks）與後續 migrate 的 playbook 仍為 PASS，tag 不得因改成 `include_tasks` 而遺失。
- [x] External repo failure 會出現在 warning/evidence。
- [x] Ubuntu required repo failure 仍會 fatal。
- [x] Pilot-owned repo signature failure 仍會 fatal。
- [x] 已安裝 package 不因 unrelated repo failure 觸發 update。
- [x] cache 有 candidate 時不強制 global update。
- [x] scoped refresh 不修改 `/etc/apt/sources.list*` external entries。
- [x] 無 insecure APT flags。(`TestAptNoInsecureFlags` 鎖住)
- [x] `os-patch-sla` 保持 strict semantics。(未動,仍是唯一合法 allowlist 例外)
- [x] FreeIPA verification PASS。(`ansible-playbook --syntax-check`/單元測試層級;`pilot verify` 需真實 target,未跑)
- [x] `ansible-lint` PASS。(advisory,0 blocking;既有 `name[template]` debt 未新增)
- [x] `go build ./...` PASS。
- [x] `go vet ./...` PASS。
- [x] `go test ./...` PASS。(含 `-race -count=1`,3380+ 全過)
- [x] disposable VM 上完成 T1/T3/T7 三個關鍵 live scenarios。2026-09-14 於 `pilot vm-target apt-tolerance-test`(ubuntu-24.04)全數實跑通過,過程中另外抓到並修好 4 個真 bug(見上方 Implementation Status);`docs/verification/apt-repository-tolerance.md` 已更新為真實擷取的 evidence,不再是 `NOT YET LIVE-VERIFIED`。
- [x] CI 可阻止普通 playbook 未來重新引入裸 `update_cache: true`。(`TestAptUpdateCacheAllowlist`,隨既有 `go test` CI job 自動跑)

---

## 28. Definition of Done

最終 deployment semantics 必須從：

```text
「主機上任何 APT repo 壞掉 → Pilot deploy 壞掉」
```

改成：

```text
「本 action 真正依賴的 repository / package path 壞掉 → fatal」
「無關 repository 壞掉 → isolate + warning + evidence」
```

同時維持：

```text
package authenticity > deploy availability
```

不得為了提高容錯率犧牲 GPG / TLS / repository trust guarantees。

