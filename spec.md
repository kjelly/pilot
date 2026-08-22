SPEC: FreeIPA Client Enrollment 自動註冊 Host DNS Record

Project: kjelly/pilot

Feature ID: freeipa-client-host-dns-registration

Status: Proposed

Target component: freeipa-client

Primary implementation: playbooks/apply/freeipa-client-apply.yml

Related components: freeipa-server, freeipa-dns, freeipa-dns-client

Risk level: Medium

Primary goal: 主機加入 FreeIPA realm 時，自動在 FreeIPA authoritative DNS 中建立該主機的 A/AAAA record，並對既有已 enroll 主機提供安全、idempotent 的 DNS backfill。

Design principle: Host DNS record 的 ownership 屬於 host enrollment lifecycle，而不是 service DNS manifest lifecycle。

1. 背景

Pilot 目前已具備以下 FreeIPA DNS 能力：

freeipa-server 預設可使用 FreeIPA native DNS（ipa-server-install --setup-dns）。

freeipa-dns 已存在獨立的 day-2 declarative zone / record reconciler。

freeipa-dns-client 可將一般主機 resolver 指向 FreeIPA DNS。

freeipa-client 已負責：

設定 client FQDN。

設定 /etc/hosts。

執行 ipa-client-install。

建立 FreeIPA host object / host principal。

設定 SSSD / HBAC / sudo integration。

目前缺口：

FreeIPA client enrollment
        │
        ├── FreeIPA host object         ✅
        ├── host/<fqdn> principal       ✅
        └── <fqdn> A/AAAA DNS record    ❌

因此可能發生：

node01.ipa.pilot.internal

在 FreeIPA DNS zone 已存在時仍回傳 authoritative NXDOMAIN。

本 feature 要讓 host enrollment 同時建立正確 DNS record。

2. 設計決策

2.1 新 enrollment 使用 ipa-client-install --ip-address

新主機加入 FreeIPA 時，應以 FreeIPA 原生 enrollment 能力建立 host DNS record：

ipa-client-install
  --hostname=node01.ipa.pilot.internal
  --ip-address=10.20.30.41

若同時有 IPv4 / IPv6：

--ip-address=10.20.30.41
--ip-address=2001:db8:30::41

不得為了此功能自行建立新的 DNS component。

2.2 不預設啟用 Dynamic DNS

第一版不得預設加入：

--enable-dns-updates

原因：

此 option 代表 enrollment 後持續 dynamic DNS update。

機房 managed host 預期使用固定 management address。

DHCP / roaming / notebook / cloud ephemeral host 並非此 feature 第一版主場景。

Dynamic DNS 涉及額外 GSS-TSIG / SSSD DNS update policy。

未來如需要，可獨立設計：

freeipa_client_dynamic_dns_updates: true

但不屬於本規格 mandatory scope。

2.3 不將 host record 寫入 freeipa-dns.yaml

freeipa-dns 是 service DNS / day-2 declarative DNS control plane。

Host enrollment record 必須由 freeipa-client lifecycle 擁有。

禁止要求 operator 為每一台 client 同時維護：

freeipa-client

和：

freeipa-dns.yaml

兩份 desired state。

3. Scope

3.1 In Scope

本 feature 必須支援：

新 FreeIPA client enrollment 自動建立 A record。

可選 AAAA record。

自動選擇合理的 client IP。

支援 operator 明確覆寫 DNS address。

DNS conflict preflight。

fail-closed mutation semantics。

idempotent rerun。

existing enrolled client DNS backfill。

native FreeIPA DNS disabled 時安全 skip。

authoritative DNS verification。

/etc/hosts 與 DNS address selection 使用相同 address source。

regression tests。

verification spec 更新。

stale documentation cleanup。

3.2 Out of Scope

第一版不處理：

DHCP lease integration。

--enable-dns-updates 自動開啟。

PTR / reverse DNS。

SSHFP record。

CNAME。

arbitrary service DNS。

跨 realm DNS。

public DNS provider。

automatic DNS delegation。

自動管理 external DNS server。

自動選擇所有 interface address。

Kubernetes Pod / Service DNS。

多 site geo DNS。

DNS TTL customization per host。

4. Required User-Facing Configuration

4.1 新增變數

freeipa_client_register_dns

freeipa_client_register_dns: true

型別：

boolean

用途：

控制 FreeIPA client enrollment 是否建立 host DNS A/AAAA record。

4.2 Effective default

若 operator 沒有明確設定 freeipa_client_register_dns，effective behavior 必須依 FreeIPA server DNS capability 決定：

selected FreeIPA server
        │
        ├── freeipa_setup_dns == true
        │       → register DNS
        │
        └── freeipa_setup_dns == false
                → skip DNS registration

不得假設所有 deployment 都使用 FreeIPA native DNS。

4.3 freeipa_client_dns_addresses

允許 operator 明確指定要寫入 DNS 的 address：

freeipa_client_dns_addresses:
  - 10.20.30.41

IPv4 + IPv6：

freeipa_client_dns_addresses:
  - 10.20.30.41
  - 2001:db8:30::41

型別：

stringList

4.4 Address priority

effective DNS addresses 的選擇順序必須是：

1. freeipa_client_dns_addresses
2. ansible_default_ipv4.address
3. fail

若未來加入 IPv6 auto-detection，必須另外設計明確規則；本版不得任意掃描所有 interface。

4.5 禁止 --all-ip-addresses

不得使用：

ipa-client-install --all-ip-addresses

因為機房主機常存在：

management NIC

storage NIC

Kubernetes bridge

Docker bridge

VPN

loopback

temporary IPv6

service network

自動註冊全部 address 會污染 authoritative DNS。

5. FQDN Contract

client FQDN 的 source of truth 維持現行：

ipa_client_fqdn: "{{ ansible_hostname | lower }}.{{ ipa_domain }}"

若現有程式已有 operator override，必須繼續支援。

5.1 FQDN requirements

DNS registration 前必須檢查：

FQDN 非空。

FQDN 非 localhost。

FQDN 位於 ipa_domain 下。

FQDN normalized lowercase。

不接受裸 short hostname 作為 DNS owner。

不允許 client FQDN 等於 FreeIPA server FQDN。

不允許 client FQDN 等於 realm domain apex。

6. DNS Address Validation

每個 freeipa_client_dns_addresses value 必須：

是合法 IPv4 或 IPv6 literal。

不得為 loopback。

不得為 unspecified：

0.0.0.0

::

不得為 multicast。

第一版 SHOULD reject link-local：

IPv4 169.254.0.0/16

IPv6 fe80::/10

去除 duplicate。

preserve deterministic order。

若 effective address list 為空：

fail before enrollment mutation

7. DNS Capability Detection

需要判斷 selected FreeIPA server 是否真的提供 native DNS。

優先使用 inventory / component contract information，不應以 client 本機猜測。

7.1 Expected logic

freeipa_client_register_dns explicitly set?
        │
        ├── yes
        │     ├── false → skip
        │     └── true
        │            │
        │            └── server freeipa_setup_dns == false
        │                    → fail closed
        │
        └── no
              │
              ├── server freeipa_setup_dns == true → enable
              └── server freeipa_setup_dns == false → disable

若 operator 明確要求：

freeipa_client_register_dns: true

但 selected server：

freeipa_setup_dns: false

必須 fail，不能 silent skip。

錯誤訊息需指出：

FreeIPA client DNS registration requested but selected FreeIPA server does not provide native DNS.

8. DNS Conflict Policy

這是 mandatory safety requirement。

8.1 Preflight

在任何 DNS mutation 或 ipa-client-install --ip-address 前，必須查 authoritative FreeIPA DNS 的目前 record。

例如：

node01.ipa.pilot.internal
desired: 10.20.30.41

8.2 Required behavior

Current authoritative RRset

Desired addresses

Behavior

不存在

[10.20.30.41]

allow create

[10.20.30.41]

[10.20.30.41]

allow / no-op

[10.20.30.99]

[10.20.30.41]

fail

[10.20.30.41, 10.20.30.99]

[10.20.30.41]

fail

[10.20.30.41]

[10.20.30.41, 2001:db8::41]

allow add missing AAAA

CNAME exists

A/AAAA desired

fail

owner 有 incompatible RR type

A/AAAA desired

fail

8.3 No implicit takeover

--force-join 不代表 DNS record 可以強制 takeover。

禁止：

existing DNS mismatch
        ↓
silent overwrite

8.4 Future override

若未來需要 takeover，可另增：

freeipa_client_dns_replace_existing: true

但此 feature 第一版：

MUST NOT implement implicit replacement

可選擇完全不實作 replace flag。

9. New Enrollment Flow

預期流程：

Prepare
  │
  ├── resolve ipa_client_fqdn
  ├── resolve selected FreeIPA server
  ├── detect native DNS capability
  ├── resolve effective DNS addresses
  ├── validate addresses
  ├── query authoritative DNS
  └── conflict check
        │
        ▼
Local host preparation
  │
  ├── protect /etc/hosts from cloud-init
  ├── write own FQDN mapping
  ├── write FreeIPA server mapping if still required
  └── set hostname
        │
        ▼
Enrollment
  │
  └── ipa-client-install
         --hostname=<fqdn>
         --ip-address=<addr1>
         [--ip-address=<addr2>]
        │
        ▼
Post verify
  │
  ├── /etc/ipa/default.conf exists
  ├── host principal exists
  └── authoritative DNS == desired addresses

9.1 Installer argv

當 DNS registration enabled：

ipa-client-install
  -U
  --server=<ipa_server_fqdn>
  --domain=<ipa_domain>
  --realm=<ipa_realm>
  --principal=<ipa_enroll_principal>
  --password=<secret>
  --hostname=<ipa_client_fqdn>
  --ip-address=<address>
  --mkhomedir
  --no-ntp
  --no-dns-sshfp
  --force-join

多 address 時，重複 --ip-address=。

當 DNS registration disabled：

保持現有 argv，不加入 --ip-address。

10. /etc/hosts Consistency

目前 client enrollment 在執行 installer 前會將 own FQDN 寫入 /etc/hosts。

本 feature 要求：

/etc/hosts canonical IP
==
DNS desired A address

不能：

/etc/hosts → 10.20.30.41
DNS        → 10.20.99.41

若 operator 提供：

freeipa_client_dns_addresses:

且第一個 IPv4 與：

ansible_default_ipv4.address

不同，必須明確決定 own /etc/hosts canonical mapping。

建議規則：

若 DNS addresses 有 IPv4：
    own /etc/hosts canonical IP = 第一個 DNS IPv4
否則：
    使用 ansible_default_ipv4.address

若 implementation 認為 changing current /etc/hosts semantics 風險過高，可選擇 fail closed：

explicit DNS IPv4 != ansible_default_ipv4.address
→ fail and require future multi-NIC policy

Coding agent 不得自行 silent divergence。

第一版優先採用 fail closed。

11. Existing Enrolled Client Backfill

目前 enrollment task 使用：

creates: /etc/ipa/default.conf

因此已 enroll client 不會重新跑 ipa-client-install。

本 feature 必須同時支援 existing client。

11.1 Detect state

/etc/ipa/default.conf exists
        │
        ├── no  → new enrollment path
        └── yes → DNS backfill path

11.2 Backfill behavior

existing client：

不得重新執行 ipa-client-install。

不得 re-enroll。

不得 regenerate host keytab。

不得使用 enrollment password 做不必要 mutation。

使用 FreeIPA CLI / API 做 DNS read + idempotent record creation。

建議使用 repo 現有 freeipa-dns-apply.yml 的模式：

kinit
  ↓
dnsrecord-show
  ↓
diff
  ↓
dnsrecord-add
  ↓
verify
  ↓
destroy temporary ccache

不得要求 operator 把 existing clients 寫進 freeipa-dns.yaml。

11.3 Backfill idempotency

若 authoritative DNS 已等於 desired：

changed=0

若缺 record：

changed=1

再次執行：

changed=0

12. Authentication for DNS Backfill

若 backfill 需要 FreeIPA admin credential：

必須沿用 ipa_admin_password vault source。

所有 password-bearing task 必須 no_log: true。

使用 dedicated temporary Kerberos credential cache。

結束後無論 success / fail 都要 destroy ccache。

不可使用 default user ccache。

不可將 secret 寫進 command output、artifact、debug message。

若可安全使用 host principal 完成 self-owned DNS record mutation，coding agent 可以評估，但不得降低 FreeIPA ACL 安全性。

第一版允許使用 existing admin credential，以降低 implementation risk。

13. Check Mode

13.1 --check

check mode 必須：

執行 read-only DNS discovery。

計算 DNS diff。

顯示將建立的 A/AAAA records。

不做：

DNS mutation。

enrollment mutation。

hostname mutation。

/etc/hosts mutation。

若因 Ansible module limitations 無法完整 preview installer argv，至少必須輸出 deterministic plan。

13.2 Example plan

FreeIPA client DNS plan:
  fqdn: node01.ipa.pilot.internal
  current A: []
  desired A: [10.20.30.41]
  action: CREATE

14. Idempotency Requirements

以下情境第二次 apply 必須 changed=0：

新 client 已 enroll 且 DNS 正確。

existing client backfill 已完成。

IPv4-only DNS record 正確。

IPv4 + IPv6 DNS records 正確。

DNS registration disabled。

不得因 read-only：

dig
ipa dnsrecord-show
kinit

產生 changed。

15. Failure Semantics

以下情況必須 fail closed：

freeipa_client_register_dns=true 但 server 沒有 native DNS。

effective address 無法決定。

address invalid。

DNS owner 已存在 CNAME。

DNS A/AAAA 與 desired address 不一致。

DNS owner 屬於其他 host / service，且無法證明 ownership。

authoritative DNS query 失敗。

FreeIPA authentication 失敗。

DNS mutation 後 verification 不一致。

FQDN 不在 realm domain。

explicit DNS IPv4 與 local canonical IPv4 衝突且沒有明確 multi-NIC policy。

不得：

warning + continue enrollment

如果會留下「host 已 enroll 但 DNS 錯誤」的 split state。

16. Transaction / Partial Failure

理想順序：

DNS preflight
   ↓
local preparation
   ↓
enrollment with --ip-address
   ↓
DNS verify

若 enrollment 成功但 DNS verify 失敗：

apply 必須回報 failure。

不得自動執行 ipa-client-install --uninstall。

不得自動刪除 host object。

error 必須指出：

enrollment 已成功。

DNS verify 失敗。

下一次 rerun 應進入 existing-client backfill path。

原因：

對 Kerberos enrollment 做 destructive rollback 的風險高於留下可修復的 partial state。

下一次 rerun 必須能收斂。

17. Verification Spec Changes

修改：

docs/verification/freeipa-client.md

新增 DNS verification row。

建議 ID：

C11

C11

Category:

dns

Check:

FreeIPA authoritative DNS contains this client's expected A/AAAA record.

重要：

不得使用：

getent hosts <fqdn>
ping <fqdn>

因為 /etc/hosts 會造成 false positive。

必須直接 query authoritative FreeIPA DNS。

例如：

dig @<freeipa_dns_server_ip> +short node01.ipa.pilot.internal A

Expected：

10.20.30.41

若支援 AAAA：

dig @<freeipa_dns_server_ip> +short node01.ipa.pilot.internal AAAA

18. Documentation Cleanup

目前 FreeIPA client 文件中仍可能存在舊架構描述：

NO built-in DNS in this pilot

但目前 FreeIPA server 已支援且預設可啟用 native DNS。

本 feature 實作時必須：

更新 freeipa-client runbook / verification spec。

移除已不正確的「無 FreeIPA DNS」描述。

說明：

native DNS enabled → enrollment 可 auto-register host record。

native DNS disabled → 維持 external DNS model。

不得誤寫為 freeipa-dns-client 是 enrollment prerequisite。

freeipa-dns-client 是 resolver consumer configuration。

freeipa-client 是 identity enrollment。

兩者是獨立能力。

19. Component Contract Changes

修改：

contracts/freeipa-client.yaml

新增：

groupVars:
  - name: freeipa_client_register_dns
    type: boolean
    required: false
    secret: false

  - name: freeipa_client_dns_addresses
    type: stringList
    required: false
    secret: false

若 contract schema 支援 conditional/default semantics，應表達：

freeipa_client_register_dns default:
  inherit selected freeipa-server.freeipa_setup_dns

若 schema 無法直接表達，保留在 playbook effective-value logic，並透過 regression test 固定行為。

20. FreeIPA Server Contract Improvement

建議一併修正：

contracts/freeipa-server.yaml

目前 FreeIPA server verification 已涵蓋 native DNS port，但 component endpoint model 應明確暴露：

endpoints:
  - name: dnsTcp
    scheme: tcp
    port: 53

  - name: dnsUdp
    scheme: udp
    port: 53

這項修改不是 DNS registration 核心 blocker，但建議同一 PR 完成，以避免 capability model 與 runtime 不一致。

若 contract framework 不允許 conditional endpoint，需以目前專案慣例表達：

endpoint available only when freeipa_setup_dns == true

不要自行發明未存在的 contract schema。

21. Required File Changes

至少評估並修改以下檔案：

playbooks/apply/freeipa-client-apply.yml
docs/verification/freeipa-client.md
contracts/freeipa-client.yaml
internal/spec/freeipa_client_regression_test.go
group_vars/freeipa.example.yml

建議：

contracts/freeipa-server.yaml
cmd/pilot/cmd/tag_coverage_test.go

視現有 repo traceability requirement 決定。

如需要重用 DNS reconciliation logic，可新增：

playbooks/apply/tasks/freeipa-client-host-dns.yml

或其他清楚命名的 task include。

不要把大量 DNS logic 全部塞進單一 enrollment command task。

22. Implementation Structure

建議拆成四個 logical blocks：

Block A — Resolve desired state

effective register_dns
ipa_client_fqdn
dns addresses
dns provider

Block B — Preflight

validate FQDN
validate IPs
query DNS
detect conflict

Block C — Apply

new client:
  ipa-client-install --ip-address

existing client:
  idempotent DNS backfill

Block D — Verify

FreeIPA enrollment health
authoritative DNS
idempotency

23. Regression Tests

internal/spec/freeipa_client_regression_test.go 必須新增至少以下 coverage。

T1 — installer contains --ip-address

Given:

freeipa_setup_dns: true

Expected generated / static playbook contract contains logic for:

--ip-address

T2 — DNS disabled compatibility

Given:

freeipa_setup_dns: false

Expected:

no mandatory --ip-address

T3 — no --all-ip-addresses

Regression test 必須確保：

--all-ip-addresses

不存在。

T4 — no dynamic DNS default

Regression test 必須確保預設不加入：

--enable-dns-updates

T5 — existing enrollment backfill

必須有 clear logic：

/etc/ipa/default.conf exists

不會導致 DNS feature 永遠 skip。

T6 — conflict fail closed

測試 playbook / helper 中存在 mismatch gate。

T7 — authoritative verification

確保 verification spec 直接 query DNS server，而不是：

getent

T8 — secrets

確保 DNS backfill auth task：

no_log: true

24. Target / Integration Test Matrix

至少測試：

Case

Client OS

DNS

State

Expected

A

Ubuntu 24.04

native DNS

clean

enroll + A created

B

EL9

native DNS

clean

enroll + A created

C

Ubuntu

native DNS

already enrolled, no A

backfill A

D

Ubuntu

native DNS

already enrolled, A correct

changed=0

E

Ubuntu

native DNS

A conflict

fail

F

Ubuntu

DNS disabled

clean

enroll succeeds, no DNS mutation

G

Ubuntu

native DNS

explicit IPv4

correct record

H

Ubuntu

native DNS

IPv4+IPv6

A + AAAA

I

Ubuntu

native DNS

CNAME collision

fail

J

Ubuntu

native DNS

second rerun

changed=0

25. Required Live Verification

遵守 Pilot repository 的 actual-run / evidence 規則。

至少完成一次 clean topology：

FreeIPA server with native DNS
+
Ubuntu client

流程：

1. clean client
2. confirm DNS owner absent
3. run freeipa-client apply
4. verify enrollment
5. query FreeIPA authoritative DNS
6. rerun apply
7. confirm changed=0

至少再跑：

existing enrolled client with missing DNS

確認 backfill path。

不得只靠 unit test 宣稱 feature complete。

26. Acceptance Criteria

本 feature 完成必須同時滿足：

Functional

新 FreeIPA client enrollment 後 authoritative DNS 出現 client A record。

explicit IPv6 時建立 AAAA。

existing enrolled host 可以 backfill。

FreeIPA native DNS disabled 時不破壞 enrollment。

DNS mismatch fail closed。

Safety

不使用 --all-ip-addresses。

不預設使用 --enable-dns-updates。

不 silent overwrite existing mismatched DNS。

secrets 不出現在 log。

authoritative DNS query 失敗不能繼續當成功。

Idempotency

clean second apply changed=0。

existing correct DNS changed=0。

Verification

docs/verification/freeipa-client.md 有 authoritative DNS check。

check 不受 /etc/hosts false positive 影響。

regression tests pass。

live vm-target / topology evidence 完成。

Documentation

移除 stale「Pilot 無 FreeIPA DNS」描述。

group_vars/freeipa.example.yml 記錄新的 configuration contract。

27. Non-Negotiable Rules for Coding Agent

Coding agent 實作時必須遵守：

先完整閱讀目前 freeipa-client-apply.yml、freeipa-server-apply.yml、freeipa-dns-apply.yml、相關 contracts 與 verification specs，再修改。

不可假設舊規格仍成立。

不可新增第二套 host DNS source of truth。

不可把 host record 塞進 service DNS manifest。

不可預設 Dynamic DNS。

不可自動註冊所有 NIC。

DNS conflict 必須 fail closed。

existing enrolled client 必須有 migration/backfill path。

不可透過重新 enrollment 解 existing-client DNS 缺漏。

不可因 DNS feature 移除現有 enrollment idempotency sentinel。

不可因 rollback 嘗試自動 uninstall 已成功加入 realm 的 client。

所有新增 behavior 都需有 regression coverage。

必須完成實際 topology/live verification 後才可標示 done。

若實作過程發現本 spec 與目前 repo contract framework 不相容，優先維持本 spec 的 safety semantics；schema 表達方式應依目前 repo pattern調整，不得自行發明不相容格式。

28. Expected Final State

實作完成後：

Pilot inventory
  node01
  ansible_default_ipv4.address = 10.20.30.41
            │
            ▼
freeipa-client
            │
            ├── FQDN
            │     node01.ipa.pilot.internal
            │
            ├── DNS preflight
            │
            ├── enrollment
            │     --hostname=node01.ipa.pilot.internal
            │     --ip-address=10.20.30.41
            │
            └── authoritative DNS verify
                    │
         ┌──────────┴──────────┐
         ▼                     ▼
FreeIPA Host Object       FreeIPA DNS
node01...                 node01...
host/node01...            A 10.20.30.41

對既有 client：

already enrolled
      │
      ▼
DNS discovery
      │
      ├── correct → no-op
      ├── missing → backfill
      └── conflict → fail closed

這就是本 feature 的最終 desired behavior。
