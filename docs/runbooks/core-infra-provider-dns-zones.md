# Runbook — 自訂內部 DNS 網域（`core-infra-provider` dns role, 資料驅動）

> 撰寫日期：2026-07-02 (UTC)
> 對齊規範：`docs/verification/core-infra-provider.md`（C7）
> 對應 apply：`playbooks/apply/core-infra-provider-apply.yml`（`infra_role=dns`）
> 維護者：sre

---

## 0. 一句話目標

> 讓 `core-infra-provider` 的 unbound 從「純轉發解析器」升級成「**也**服務你自己的
> 內部網域」（例如 `core.pilot.lan → 10.0.0.53`），而且**網域資料不進這個公開 repo**。

同一套「**邏輯在 git、資料在 git 外**」範式，跟 `freeipa-identity.md` 一致：
playbook 是通用 reconciler，資料（`dns_zones`）從 repo 外的 `group_vars/` 餵進來。

---

## 1. 資料放哪（公開 repo 的關鍵）

這個 repo 是**公開**的，所以內部主機名→IP 不能進 repo 樹。做法是把真資料放在
**repo 樹外**、你（本來就 git-ignored 的）inventory 旁邊 —— Ansible 會自動載入
inventory 同目錄下的 `group_vars/`，**零 `-e`**：

```
~/.infra/pilot/
├── inventory-core-infra.yaml     # 你的真 inventory（git-ignored）
└── group_vars/
    └── dns/                       # group 名 = inventory 裡的 dns group
        ├── pilot-lan.yaml         # dns_zones: [...]  （同 group 多檔自動合併）
        └── corp-internal.yaml     # dns_zones: [...]
```

> **為什麼放 repo 外而不是 gitignore repo 內的檔**：repo 內就算 gitignore，仍可能被
> `git add -f` 手滑提交、或留在 history。檔案根本不在 repo 樹裡，才是公開 repo 的鐵保證。
> `.gitignore` 另有一道 `/group_vars/dns/*.yaml`（保留 `zones.example.yaml`）當防手滑保險。

schema 範例（committed，可照抄）：[`group_vars/dns/zones.example.yaml`](../../group_vars/dns/zones.example.yaml)

---

## 2. 資料格式（`dns_zones`）

```yaml
# ~/.infra/pilot/group_vars/dns/pilot-lan.yaml
dns_zones:
  # (a) 權威本地 zone：unbound 直接回答，其餘該 zone 下的名字回 NXDOMAIN
  - name: pilot.lan
    mode: static                     # static(預設) | transparent | redirect
    records:
      - { name: core,     type: A, value: 10.0.0.53 }
      - { name: keycloak, value: 10.0.0.10 }        # type 省略 = A
      - { name: www,      type: CNAME, value: git.pilot.lan. }

  # (b) 委派（規模化路徑）：整個 zone 丟給上游權威 server，records 被忽略
  - name: corp.internal
    stub_addr: 10.0.1.2
```

- **多網域**：每個檔一個 `dns_zones:`，平鋪在 `group_vars/dns/` 下，Ansible 自動合併
  （zone 名跨檔不要重複）。
- **`mode: transparent`**：zone 內查不到的名字**改往轉發器**（不回 NXDOMAIN），適合
  只想補幾筆 override、其餘照常對外解析。
- **`stub_addr`**：一旦設了就是委派模式，`records` 被忽略；這是網域大到不想用
  inline `local-data`（大約低千筆以上）時的升級路徑。

---

## 3. 套用（apply）

```bash
# 先 dry-run（第一次一律 --check --diff）
ansible-playbook -i ~/.infra/pilot/inventory-core-infra.yaml \
    playbooks/apply/core-infra-provider-apply.yml \
    -e infra_role=dns -e dns_provider=unbound -e dns_listen_addr=10.0.0.53 \
    --check --diff
#   TASK [DNS — write unbound config] 的 diff 會顯示 local-zone/local-data 被寫進
#   /etc/unbound/unbound.conf.d/infra-pilot.conf

# 真的套（會 notify: restart unbound）
ansible-playbook -i ~/.infra/pilot/inventory-core-infra.yaml \
    playbooks/apply/core-infra-provider-apply.yml \
    -e infra_role=dns -e dns_provider=unbound -e dns_listen_addr=10.0.0.53
```

> `dns_zones` 不用打 `-e` —— 它從 `group_vars/dns/` 自動就位。
> 沒有 `dns_zones`（空）時，unbound 退回原本的純轉發設定（完全 backward compatible）。

vm-target 情境同理，`-i` 指到外部 inventory 即可：
```bash
go run ./cmd/pilot vm-target run --name core \
    -i ~/.infra/pilot/inventory-core-infra.yaml \
    playbooks/apply/core-infra-provider-apply.yml \
    -e infra_role=dns -e dns_listen_addr=10.0.0.53
```

---

## 4. 驗證（verify / C7）

C7 是**選用**的：不設 `$DNS_PROBE_NAME` 就 SKIP-as-pass，純轉發 host 不會變紅。
要真的驗自訂網域解得出來：

```bash
# 手動 dig（最直接）
go run ./cmd/pilot vm-target exec --name core -- dig +short core.pilot.lan @127.0.0.1
# 10.0.0.53

# 走 spec：export 探測名，跑 verify
export DNS_PROBE_NAME=core.pilot.lan
go run ./cmd/pilot vm-target verify --name core docs/verification/core-infra-provider.md
# C7 status=pass（有解出非空答案）
```

委派 zone（`stub_addr`）驗法一樣，改探委派 zone 下一個實際存在的名字。

---

## 5. 常見失敗

| 症狀 | 原因 | 修法 |
|------|------|------|
| `dig` 回空 / NXDOMAIN | apply 後 unbound 沒 restart | 重跑 apply（handler 會 restart），或 `systemctl restart unbound` |
| `dns_zones` 沒生效 | inventory 不是外部那份，group_vars 沒被載入 | `-i` 要指到 `~/.infra/pilot/inventory-core-infra.yaml`；host 要在 `dns` group |
| zone 內其他名字全 NXDOMAIN | `mode: static` 的預期行為 | 想 fall-through 對外解析改 `mode: transparent` |
| CNAME 解析怪 | value 忘了結尾的 `.`（FQDN） | `value: git.pilot.lan.`（帶尾點） |
| 記錄破千後 reload 變慢 | inline `local-data` 到規模上限 | 該 zone 改用 `stub_addr` 委派給 bind9/PowerDNS |

---

## 6. 變更紀錄

| 日期       | 版本 | 變更                                                             | 變更者 |
|------------|------|------------------------------------------------------------------|--------|
| 2026-07-02 | v1.0 | 初版：資料驅動 `dns_zones`（local-zone/local-data + stub-zone 委派） | sre    |
