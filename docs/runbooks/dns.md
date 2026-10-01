# Runbook — dns（FreeIPA 前的第一層快取 DNS）

> 對齊規範：`docs/verification/dns.md`
> 對應 apply：`playbooks/apply/dns-apply.yml`
> 維護者：sre

## 0. 一句話目標

在 FreeIPA DNS 前面放一層 unbound：inventory 有 FreeIPA DNS 時，內部網域自動送到
FreeIPA，其餘送到你設定的外部 upstream；consumer 先問這一層，最後才退回 FreeIPA。

## 0.5 目前有效的事實快照

最新驗證：2026-10-01，candidate `cbe95b8`（tree `b807a6af6a0e68a45e4b5ad0cb7e1138f617937e`），
**PASS**。完整摘要：[`docs/evidence/dns/2026-10-01-cbe95b8.md`](../evidence/dns/2026-10-01-cbe95b8.md)。

| 項目 | 事實 |
|---|---|
| 目標環境 | `pilot vm-target topology`（`docs/topologies/dns-tier-topology.yaml`），5 台由 `topology up` 新建的 VM，測完已移除 |
| inventory host 集合 | `dns`: dt-dns-1, dt-dns-2；`freeipa-server`: dt-ipa；`freeipa-dns-client`: dt-dns-2, dt-client, dt-client-el |
| 外部 state | `~/.vault/main.yaml` 的 `ipa_admin_password`（只給 FreeIPA server 安裝與測試 fixture 用）；dns 設定在 workspace 的 `group_vars/dns.yml`，由 `pilot edit` 寫入 |
| 結果 | L3 check mode（全新 VM）`failed=0`；L4 `failed=0`；verify `dns.md` 37 pass / 0 fail / 2 not_applicable、`freeipa-dns-client.md` 18 pass；L6 `changed=0`。真實 `pilot deploy` 全站部署 + `--limit dt-dns-2` + `pilot reconcile`（`freeipa-dns-client`）之後 `dns.md` 31 / 0 / 8、`freeipa-dns-client.md` 18 / 0 |
| 對齊決定 | 不需要：spec 的目標 role `dns` 與 inventory 的 `dns` group 一致 |

## 1. 為什麼

- FreeIPA 的 named 用 bind-dyndb-ldap，回答內部名稱很便宜；它真正的負擔是替整個
  fleet 解析外部網域。這一層把外部解析與快取移出 FreeIPA。
- 這是預防性的部署（沒有量測到 FreeIPA DNS 壓力），所以 cache 上限保守：一般回應
  300 秒、查無此名稱 60 秒。實測：FreeIPA 新建紀錄 59 秒後可從 tier 查到，刪除後
  300 秒 tier 不再回答。
- FreeIPA 的 forwarders 與 recursion 設定不變；tier 全部失聯時，consumer 仍會退回
  FreeIPA。

## 2. 設定（pilot edit）

全部設定在 workspace 的 `group_vars/dns.yml`，由 `group_vars/dns.example.yml` 建立。
註解掉的行就是內建預設值。各變數的意義見 `dns.example.yml` 與 `docs/verification/dns.md` §3。

`hosts.yml` 有 `dns` 角色的主機時，`pilot inventory generate` 會建立 `group_vars/dns.yml`
（2026-10-01 實際執行過）：

```bash
pilot inventory generate --dir <workspace> --no-vault
```

設定可以在 `pilot edit` 的 group_vars 畫面互動修改；以下是這次驗證實際用的非互動
寫法（`pilot edit --actions`），scenario 檔放在 workspace 以外：

```bash
pilot edit --dir <workspace> --actions <scenario.json>
```

```json
{"version": 1, "title": "dns tier settings", "steps": [
  {"action": "set_group_var_list", "file": "dns.yml", "key": "dns_upstream", "values": ["1.1.1.1", "9.9.9.9"]},
  {"action": "set_group_var_list", "file": "dns.yml", "key": "dns_freeipa_zones", "values": ["svc.pilot.internal", "<server /24>.in-addr.arpa"]},
  {"action": "set_group_var_list", "file": "dns.yml", "key": "dns_stub_zones", "values": ["stub.pilot.internal=<authoritative IP>"]},
  {"action": "set_group_var", "file": "dns.yml", "key": "dns_cache_max_ttl", "value": "300"},
  {"action": "set_group_var", "file": "dns.yml", "key": "dns_cache_max_negative_ttl", "value": "60"},
  {"action": "save_group_vars", "file": "dns.yml"}
]}
```

確認 Ansible 實際看到的值（型別應是清單與整數）：

```bash
ansible-inventory -i <workspace>/inventory.yml --playbook-dir <workspace> --host <dns host>
```

注意：

- 不要在 `group_vars/dns.yml` 設 `dns_listen_addr`。服務位址預設是每台主機的
  `ansible_host`；要覆寫單一主機，寫在它的 `host_vars/<host>.yml`。共用的位址會被
  G10 擋下。
- 不要建立 `group_vars/dns/` 目錄：它存在時 Ansible 只載入目錄、整個忽略 `dns.yml`。
  `pilot inventory lint` 會把這種情況報成 error。
- `dns_zones`（本地紀錄）是巢狀結構，只能直接編輯檔案。需要用 `pilot edit` 管理的
  內部紀錄，放到 FreeIPA。
- 舊 workspace 的 `dns.yml` 沒有新變數時，在 `pilot edit` 開啟該檔，選「從範例補上
  缺少的設定」，再存檔。

## 3. 套用

先 dry-run，再套用（2026-10-01 在 Ubuntu 24.04 vm-target 上實際執行過）：

```bash
ansible-playbook -i <workspace>/inventory.yml playbooks/apply/dns-apply.yml --check --diff
ansible-playbook -i <workspace>/inventory.yml playbooks/apply/dns-apply.yml
```

FreeIPA DNS 必須已經在服務：tier 會先確認 FreeIPA 對每個要轉送的 zone 回答權威
SOA（G5）。全站部署時 `site.yml` 已經把 dns 排在 freeipa-server 之後。

接著讓 consumer 改指向 tier（同一支 resolver baseline 也被 `internal-endpoint` 使用）：

```bash
ansible-playbook -i <workspace>/inventory.yml playbooks/apply/freeipa-dns-client-apply.yml
```

套用後每台 consumer 的 nameserver 依序是各 tier 節點，最後是 FreeIPA，最多 3 筆。

多機驗證用的完整鏈（這次的正式 evidence run）：

```bash
pilot vm-target topology test \
    --topology docs/topologies/dns-tier-topology.yaml \
    --playbook playbooks/test/dns-tier-chain.yml \
    --verify docs/verification/dns.md=dns \
    --verify docs/verification/freeipa-dns-client.md=freeipa-dns-client \
    --verify-timeout 60 \
    -- -i <workspace>/inventory.yml -e @~/.vault/<sandbox>.yaml -e stage=sandbox
```

`dns.md` 的 inputs 用 `PILOT_INPUT_<NAME>` 環境變數提供；`pilot_inventory_path` 由
`topology test` 自動填入。FreeIPA 的 IP 要等 VM 建好才知道，所以這條鏈是先
`topology up`、寫好 workspace，再對全新 VM 跑 `topology test`。

## 4. 驗收

對單一環境驗收時，所有 input 都要給；沒用到的功能填 `none`（2026-10-01 實際執行過）：

```bash
pilot verify docs/verification/dns.md -i <inventory> -l dns \
  --input dns_mode=freeipa-split --input dns_upstream_servers=1.1.1.1 \
  --input "dns_access_control=10.0.0.0/8 172.16.0.0/12 192.168.0.0/16" \
  --input dns_cache_max_ttl=300 --input dns_cache_max_negative_ttl=60 --input dns_dnssec_validation=true \
  --input external_probe_name=isc.org --input freeipa_domain=ipa.pilot.internal --input freeipa_dns_server_ips=<FreeIPA IP> \
  --input freeipa_probe_fqdn=ipa1.ipa.pilot.internal --input freeipa_extra_zone_probe_fqdn=none --input freeipa_reverse_probe_ip=none \
  --input dns_zone_probe_fqdn=none --input pilot_inventory_path=<inventory 絕對路徑> --input dns_consumer_pattern=freeipa-dns-client
```

## 5. gate 與 rollback（實測）

| 情況 | 結果 |
|---|---|
| `dns_freeipa_zones` 有 FreeIPA 沒有的 zone | G5 擋下：「FreeIPA did not answer SOA authoritatively」，設定不變 |
| upstream 不可達 | G6 擋下：「Upstream check failed」，設定不變；upstream 會剝掉 DNSSEC 時改設 `dns_dnssec_validation: false` |
| 共用的 `dns_listen_addr` | G10 擋下：「is not an IPv4 address of <host>」，設定不變 |
| `dns_zones` 寫了無效的紀錄 | checkconf 失敗，rescue 還原：「Rollback: …/pilot-dns.conf restored; unbound restarted」 |
| 重啟後 tier 連不到 FreeIPA | 自我檢查失敗，rescue 還原舊設定並重啟 |
| ACL 設 `0.0.0.0/0`、dns_stub_zones 少了 `=`、zone 重複、cache 上限不是整數 | G4 擋下，任何檔案都還沒寫 |

## 6. 從舊 core-infra-provider dns role 遷移（實測）

- `-e infra_role=dns` 已經不能用（gate 會擋），改用 `dns-apply.yml`。
- 舊 role 留下的 `/etc/unbound/unbound.conf.d/infra-pilot.conf` 會被新 playbook 移除；
  舊 role 改過的 `/etc/systemd/resolved.conf`（`DNSStubListener=no`）不需要還原。
- 舊 workspace 若同時有 `group_vars/dns.yml` 與 `group_vars/dns/`，把目錄裡的
  `dns_zones` 搬進 `dns.yml`，再刪掉目錄。目錄裡如果是 scaffold 複製來的範例假資料
  （`pilot.lan`、`corp.internal`），直接刪掉即可。
- 2026-10-01 對一台先套舊 role 的 Ubuntu 24.04 VM 套用新 playbook：`changed=3`、
  重跑 `changed=0`，unbound 改綁 `<IP>:53` 與 `127.0.0.1:53`，主機自己的解析正常。

## 7. 已知限制

- 第一台 tier 整台失聯（封包被丟棄）時，consumer 每次查詢會等 resolver 逾時再換下一台：
  實測 5～20 秒，Ubuntu 與 AlmaLinux 相同。只停掉 unbound、主機還在時，大多數查詢
  幾毫秒內就換到下一台。縮短 resolver 逾時會改變所有 `freeipa-dns-client` 主機的
  設定，尚未決定（`docs/verification/dns.md` §8）。
- 只支援 Ubuntu 22.04/24.04 的 tier 主機；tier 主機不可同時是 FreeIPA server/replica。

## 8. 變更紀錄

| 日期 | 版本 | 變更 | 變更者 |
|---|---|---|---|
| 2026-10-01 | v1.0 | 初版：取代 `core-infra-provider-dns-zones.md`；candidate `3f781fb` 對 5 台全新 vm-target 實跑 PASS | sre |
| 2026-10-01 | v1.1 | §0.5 改指向 candidate `cbe95b8` 的驗證；加上真實 `pilot deploy` 全站部署、`--limit`、`pilot reconcile` 的結果 | sre |
