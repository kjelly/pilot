# Pilot 改善計畫：SSH Key 登入時強制更新已過期的 FreeIPA 密碼

> **狀態：階段 1（spec + contract）、階段 2（apply + regression）與階段 3（Ubuntu 24.04 一般 client 的 `topology test` evidence 與活體矩陣）已完成；`renew` 另寫 `[pam] pam_initgroups_scheme = always`（spec v1.16 C19／C20，#262／#263 的根因修正）。A10（六節點：gateway／directory／target-policy）、A12（HA／offline）與 A16 也已實跑。結果、tested candidate 與限制都在 evidence record，本檔不重複：[一般 client](../../evidence/freeipa-client-password-renewal/LATEST.md)、[gateway／directory／target-policy](../../evidence/freeipa-client-password-expiry-gateways/LATEST.md)、[HA／offline](../../evidence/freeipa-client-password-expiry-ha/LATEST.md)。preflight 對 gateway／directory／target-policy 主機的 `renew` 拒絕**尚未解除**。** `freeipa-client-apply.yml` 實作 C13／C14／C19／C20（含修正 SSSD restart task 只標 `C8` 的既有 bug），`playbooks/test/fixtures/freeipa-client-pwexpiry-fixtures.yml` 建 fixture 帳號（`docs/verification/freeipa-client.md` §0、§5、§9）。階段 2 期間的 `ansible-playbook` 開發期實跑不是 evidence chain；正式 evidence 只有上面三份 record。
> 日期：2026-11-05（Asia/Taipei）
> 修訂：2026-11-05 依程式碼 review 修正：支援 OS 只有 Ubuntu 24.04；補上 roster 預設密碼的影響、OpenSSH 實際行為、canary 作法、既有 SSSD restart tag 問題；政策改為未設定／`warn`／`renew`／`off`；縮小主 PR 範圍。同日再依 SSSD 2.9.4 原始碼修正：沒有密碼的帳號（含目前的 canary）在 `warn`／`renew` 下會被拒絕，見 §1.3。
> Repository：[`kjelly/pilot`](https://github.com/kjelly/pilot)
> 分析基準：`main` commit [`60a1f618ec1c9b3302e02bfc6a566b0024374ed9`](https://github.com/kjelly/pilot/commit/60a1f618ec1c9b3302e02bfc6a566b0024374ed9)（查詢當下 HEAD）
> 落地檔：本檔（`docs/superpowers/plans/2026-11-05-freeipa-ssh-key-password-renewal.md`）；驗收列在 `docs/verification/freeipa-client.md` C13–C18
> **目標：人員以 SSH public key 驗證成功，但 FreeIPA 密碼已過期時，在取得互動式 Shell 前，透過 PAM 立即完成密碼修改；未成功前不得存取正常 Shell。**

## 1. 決策與實施原則

**採用 SSSD IPA provider 原生的 `ipa_access_order = expire, pwd_expire_policy_renew`，由既有 `freeipa-client` component 管理，不引入 SSH `ForceCommand` 攔截、額外 privileged shell wrapper 或 sudo 權限繞過。**

- **預設不變（opt-in）**：既有 host 不因升級 Pilot 自動進入強制密碼更新；以 `pilot edit` 管理可選的 component 變數，經 `pilot generate`／`pilot deploy` 收斂。
- **主要效益與最大影響面是同一群人：還在用預設密碼的使用者。** roster 不設定使用者自己的密碼，只放預設（初始）密碼；freeipa-identity 以管理員 reset 寫入，FreeIPA 一律把它標成「立即過期」（`playbooks/apply/freeipa-identity-apply.yml:1199`，已實測）。只用 SSH key 登入的人永遠不會被要求修改，這組預設密碼就一直是可用的憑證：知道它的人可以用密碼 SSH 登入，再改成自己的密碼。啟用 `renew` 後，這些人下一次用 key 登入就會被要求修改，窗口縮到本人第一次登入為止。反過來說，對一台主機啟用 `renew`，所有還沒改過預設密碼的人都會在下一次登入時被擋下來改密碼；這不是「密碼陸續到期」的少數人，而可能是大部分使用者，啟用前必須先列出並通知（§5 階段 0）。
- **強制政策只在可驗證條件下生效**：`access_provider = ipa`、SSSD/PAM/SSHD 有效配置、FreeIPA 可達、互動式 PAM password-change 對話在目標 OS（Ubuntu 24.04）確實工作；不把 man page 的理論支援視為已驗收。
- **不弱化原授權**：保留 FreeIPA HBAC、sudo provider、帳號停用／到期檢查；不修改 `sudo` PAM 以繞過密碼過期，也不把 IPA provider 改為 LDAP provider。
- **非互動式 SSH 是額外風險**：`pilot-login-canary`、自動化 SSH、SCP/SFTP、SSH 遠端命令和 gateway ForceCommand 流程可能被迫改密碼而中斷（依 §1.1，沒有 TTY 時 sshd 直接以 exit 1 結束）。正式啟用前須完成其相容性驗證。
- **須有恢復通道**：保留不依賴 FreeIPA 的 break-glass 管理管道；預先完成可還原前像（preimage）與 atomic rollback，禁止在管理存取中斷後才試圖人工修檔。

### 1.1 原生機制與狀態機

```text
SSH publickey 驗證成功
    │
    ▼
sshd → PAM account → pam_sss → SSSD IPA access provider
    │
    ├─ HBAC / account 不允許 ──────────────> 拒絕；不可因密碼更新而放行
    │
    ├─ 密碼未過期 ────────────────────────> 照既有 SSH 授權流程進入 Shell／執行命令
    │
    └─ 密碼過期（renew）
            │
            ▼
       pam_acct_mgmt 回 PAM_NEW_AUTHTOK_REQD
       （sshd 設 force_pwchange，並關閉 port／agent／X11 forwarding）
            │
            ├─ 有 TTY ─────────────> 不執行 shell／ForceCommand／命令，改執行 passwd；
            │                        passwd 結束後一律斷線，修改成功後重新登入才進 shell
            └─ 沒有 TTY ───────────> 遠端命令、sftp/scp、BatchMode：印出
                                     "Password change required but no TTY available"，exit 1
```

**OpenSSH 行為：** 上圖依 OpenSSH portable 原始碼：`auth-pam.c` 的 `do_pam_account()`／`sshpam_password_change_required()`，以及 `session.c` 的 `do_child()`／`do_pwchange()`。publickey 驗證後 PAM account 回 `PAM_NEW_AUTHTOK_REQD` 時，sshd 在執行任何命令之前，有 TTY 就改跑 `passwd`，沒有 TTY 就直接 exit 1。所以「改完後在同一個 session 繼續」不會發生，修改後一定要重新登入；ForceCommand、sftp subsystem、遠端命令都不會被執行。這些是 spec 的預期 Expected，仍由 A04／A08／A09／A10 實機確認。password／keyboard-interactive 驗證是在驗證階段就由 PAM 對話完成修改，不走這條路。

**2026-11-05 Ubuntu 24.04（OpenSSH 9.6p1）實測**：沒有 TTY 印 `WARNING: Your password has expired.` + `Password change required but no TTY available.`、rc=1、命令沒執行；`ssh -tt` 時 sshd 改跑 `passwd`（`Current Password:` → `New password:` → `Retype new password:` → `passwd: password updated successfully`），結束後斷線，FreeIPA 的 `krbPasswordExpiration` 延到 90 天後；sftp rc=255。**新發現**：改完後短時間內重新登入仍被要求修改，之後才正常（SSSD PAM responder 短時間沿用舊快取）。不要用清快取當修法；根因修正是 spec v1.16 的 `pam_initgroups_scheme = always`（C19／C20、A18），見 `docs/verification/freeipa-client.md` §0。

**文件依據：** `sssd-ipa(5)` 將 `pwd_expire_policy_warn`、`pwd_expire_policy_reject`、`pwd_expire_policy_renew` 明確定位於 SSH Key 等非密碼驗證場景；`renew` 表示已過期時提示立即更改，且必須使用 `access_provider = ipa`。該文件不等於 Pilot 的目標 OS（Ubuntu 24.04）與其 OpenSSH 已實機通過。參見 [SSSD IPA provider manual](https://man.archlinux.org/man/sssd-ipa.5.en)、[PAM `pam_chauthtok(3)`](https://man7.org/linux/man-pages/man3/pam_chauthtok.3.html)。

### 1.2 建議的有效 SSSD 設定（示意；不是已部署產物）

```ini
[domain/ipa.pilot.internal]
access_provider = ipa
# Pilot 整行管理這個值；IPA provider 的合法值只有 expire 與三個 pwd_expire_policy_*
ipa_access_order = expire, pwd_expire_policy_renew
pwd_expiration_warning = 14
```

`[domain/…]` **必須使用目標機器實際的 SSSD domain section**；不可照抄範例 realm。ipa-client-install 只產生一個 `[domain/<ipa_domain>]`，而且不寫 `ipa_access_order`（預設值就是 `expire`）。所以 preflight 先 assert sssd.conf 恰好一個 `[domain/` section，`ipa_access_order`、`pwd_expiration_warning` 各最多一行，再沿用現有 hardening task 的寫法（`lineinfile` + `insertafter: '^ipa_domain\s*='`）整行寫入，不需要 INI parser。

### 1.3 SSSD 原始碼確認的行為（2.9.4，Ubuntu 24.04 的版本；master 相同）

讀 `src/providers/ipa/ipa_access.c`、`src/providers/ldap/sdap_access.c`、`src/providers/ldap/ldap_auth.c` 得到：

- **HBAC 仍然會檢查**：`ipa_pam_access_handler_sdap_done()` 對 `ERR_PASSWORD_EXPIRED_WARN`（設 `PAM_SUCCESS`）與 `ERR_PASSWORD_EXPIRED_RENEW`（設 `PAM_NEW_AUTHTOK_REQD`）都是 `break`，接著做 HBAC；HBAC 拒絕時改成 `PAM_PERM_DENIED`。所以 `warn` 不會讓 HBAC 拒絕的人登入，`renew` 也不會讓 HBAC 拒絕的人跑到 `passwd`（A06）。帳號停用／`reject` 在 HBAC 之前就結束。
- **沒有密碼的帳號會被拒絕**：IPA provider 固定用 MIT Kerberos 政策（`find_password_expiration_attributes()`），讀 SSSD 快取裡使用者的 `krbLastPwdChange` 與 `krbPasswordExpiration`。快取裡**沒有 `krbLastPwdChange`**（帳號從沒設過密碼）時回 `EACCES`（log：「No Kerberos password expiration attributes found, but MIT Kerberos password policy was requested. Access will be denied.」），IPA access handler 把它當成 `PAM_SYSTEM_ERR`，登入失敗。這對 `warn`、`renew`、`reject` 都一樣。所以：**啟用 `warn`／`renew` 的主機上，所有能登入的 FreeIPA 帳號都必須設過密碼**；純金鑰帳號（roster 省略 `password:`）與目前的 login canary 都會被拒絕。
- **設計前提已實機確認（2026-11-05）**：在拋棄式 AlmaLinux 9 FreeIPA server + Ubuntu 24.04 client（SSSD 2.9.4）上，`id <user>` 之後 client 的 SSSD 快取（`cache_<domain>.ldb`）有 `krbLastPwdChange`／`krbPasswordExpiration`；沒有密碼的帳號兩者都沒有。`renew` 下三種帳號的 PAM account 結果與原始碼一致：過期 → `Authentication token is no longer valid; new one required`、有效 → `Success`、沒有密碼 → `System error`（`warn` 下過期帳號 `Success`、沒有密碼仍 `System error`）。實測輸出摘要見 `docs/verification/freeipa-client.md` §3 v1.14。

## 2. Pilot 現狀與 PR 對應

| 目前機制／變更 | 已確認的程式或 PR | 對本計畫的影響 |
|---|---|---|
| Client enrollment、SSSD、SSH 配置 | [`playbooks/apply/freeipa-client-apply.yml`](https://github.com/kjelly/pilot/blob/60a1f618ec1c9b3302e02bfc6a566b0024374ed9/playbooks/apply/freeipa-client-apply.yml) | **主要修改點**；在已 enroll 的 client 重跑時亦須 Day-2 收斂，而非只處理新裝機。 |
| Component 輸入與驗收映射 | [`contracts/freeipa-client.yaml`](https://github.com/kjelly/pilot/blob/60a1f618ec1c9b3302e02bfc6a566b0024374ed9/contracts/freeipa-client.yaml)、[`docs/verification/freeipa-client.md`](https://github.com/kjelly/pilot/blob/60a1f618ec1c9b3302e02bfc6a566b0024374ed9/docs/verification/freeipa-client.md) | 新變數必須有型別／範圍驗證與對應 acceptance row／tag，不得塞進未納管的 inventory 欄位。 |
| **既有 SSH 密碼登入設定** | `freeipa-client-apply.yml` 管理 `05-freeipa-client-password-auth.conf`，目前寫入 `PasswordAuthentication yes`、`KbdInteractiveAuthentication yes` | **重要現況**：Pilot 自身並非預設 Key-only。此案不得假設 SSH 密碼登入已關閉，更不得在未授權的情況下默默改變登入方式；Key-only 硬化應另作明確政策及測試。 |
| 既有 SSSD hardening 可選參數 | `freeipa_client_sssd_cache_credentials`、`freeipa_client_sssd_offline_credentials_expiration` | 照既有 *unset 不修改* 慣例設計新參數；不要變更 `services =` 與 `sssd-sudo.socket` 既有處理。**既有 bug**：這兩個 task 標 `sssd_hardening`（`freeipa-client-apply.yml:832`、`:846`），但 SSSD restart 只標 `C8`（`:848`），`--tags sssd_hardening` 會改 sssd.conf 卻不重啟 SSSD，設定不生效。本案不可照抄，並在同一個 PR 修掉（AGENTS.md §5.10）。 |
| Roster 預設密碼 | `playbooks/apply/freeipa-identity-apply.yml:1183-1205`（roster 的 password 以管理員 reset 寫入） | roster 不設定使用者自己的密碼，只放預設密碼；FreeIPA 對管理員 reset 一律標成立即過期。啟用 `renew` 後，所有還在用預設密碼的人下一次 SSH 登入都會被要求修改（§1）。`preserve_existing: false`（或舊格式 `force_password: true`）沒改回來的使用者會進入「reset → 登入被迫修改 → 下次 identity apply 又 reset」的循環（§3 P3 第 5 點）。 |
| sudo refresh 收斂 | [PR #222](https://github.com/kjelly/pilot/pull/222)、[Issue #214](https://github.com/kjelly/pilot/issues/214) | 區分「因密碼過期被 PAM 擋」與「SSSD sudo 規則尚未 full refresh」。驗收不得把兩種失敗混為一談。 |
| SSH Key cache／退役 durable obligations | [PR #245](https://github.com/kjelly/pilot/pull/245)、[Issue #114](https://github.com/kjelly/pilot/issues/114) | 不使用永久全域清快取作為修法；不可干擾既有 identity、retirement、offline/deferred pending 狀態機。 |
| SSH/PAM 真實登入探測 | [`docs/verification/login-probe.md`](https://github.com/kjelly/pilot/blob/60a1f618ec1c9b3302e02bfc6a566b0024374ed9/docs/verification/login-probe.md)、[`contracts/login-probe.yaml`](https://github.com/kjelly/pilot/blob/60a1f618ec1c9b3302e02bfc6a566b0024374ed9/contracts/login-probe.yaml) | `pilot-login-canary` 使用 `BatchMode yes`、SSH Key、`KbdInteractiveAuthentication no`、非互動命令。canary 目前是純金鑰帳號（測試 fixture 建立時不帶密碼，`playbooks/test/fixtures/freeipa-client-fixtures.yml:100`）；依 §1.3，啟用 `warn`／`renew` 的主機會拒絕它（PAM system error，login-probe 記為 `account`），login-probe 永遠不會是 `ok`。canary 必須有密碼，且到期日在遠未來（`ipa user-mod --password-expiration`）；若給的是預設密碼（一開始就過期），依 §1.1 每一輪都會落在 `session`（已 Authenticated、rc=1）。 |
| Gateway、Directory 的 SSH ForceCommand | [`contracts/pilot-access-gateway.yaml`](https://github.com/kjelly/pilot/blob/60a1f618ec1c9b3302e02bfc6a566b0024374ed9/contracts/pilot-access-gateway.yaml)、[`docs/verification/pilot-access-target-policy.md`](https://github.com/kjelly/pilot/blob/60a1f618ec1c9b3302e02bfc6a566b0024374ed9/docs/verification/pilot-access-target-policy.md) | 必須測試 SSH Gateway → Target、ForceCommand、portal／recording 路徑是否被 chauthtok 中斷；不可用全域 `sshd_config` 蓋掉 Match 規則。依 §1.1，密碼過期的使用者連到套用 `renew` 的主機時，有 TTY 會以 `passwd` 取代 ForceCommand，沒有 TTY 的 transport 直接 exit 1。 |
| 非互動 component deploy | [PR #253](https://github.com/kjelly/pilot/pull/253) | 支援選定 component 的 CI／批次部署，保留 provider prerequisites、stage gate、變更預覽、第二次冪等性驗收。 |
| 必要驗證與回滾紀律 | [PR #243](https://github.com/kjelly/pilot/pull/243)、[PR #225](https://github.com/kjelly/pilot/pull/225)、[PR #209](https://github.com/kjelly/pilot/pull/209) | `--tags`/`always` 安全、`changed=0`、真實執行 evidence、VM ownership-safe cleanup、rollback 需回到*本次*前像。 |
| Agent / PR 流程 | [PR #205](https://github.com/kjelly/pilot/pull/205)、[PR #249](https://github.com/kjelly/pilot/pull/249) | 依當前規範：單次 skill 處理一個 Issue／PR、乾淨 checkout；Ready 前整合最新 `main` 並重新驗證／獨立 review。 |

**與現有規範一致**：[`AGENTS.md`](https://github.com/kjelly/pilot/blob/60a1f618ec1c9b3302e02bfc6a566b0024374ed9/AGENTS.md) 要求 spec-first、真實 target 測試與 evidence；**不手動修改 inventory／vault**，只透過 Pilot 管理的 edit/generate/deploy 流程。這份文件是 implementation plan，未聲稱其中測試已通過。

## 3. 具體設計

### P0 — 定義可設定的政策契約（先完成 Spec）

修改：

1. `contracts/freeipa-client.yaml` 新增 `groupVars`（名稱為**建議契約**，實作須與現有命名審查一致）：
   - `freeipa_client_sssd_password_expiry_policy`：string，允許 `warn|renew|off`；**未設定就不動**（比照 `freeipa_client_sssd_cache_credentials`，不另設 `preserve` 值）。值由 playbook 標 `always` 的 assert 檢查。
   - `freeipa_client_sssd_password_expiry_warning_days`：integer，建議範圍 `1..30`；未設定時用 `14`，在 stage gate 之後標 `always` 的 `set_fact` 補預設值，不寫在 play `vars:`（AGENTS.md §4.5 第 3 點）。只在 `warn`／`renew` 模式由 Pilot 管理。
2. `docs/verification/freeipa-client.md` 先增加 acceptance rows（建議 C13–C17，**正式編號以當時現有 spec 最大 row 為準**；目前最大是 C12），將 mutation tag、verify-only row、支援 OS（只有 Ubuntu 24.04）與驗收方法寫清楚。
3. `internal/spec/freeipa_client_regression_test.go` 追加 contract／tag／config 驗收；若需新的幫助程式，另加純函式、fixture 與拒絕不合法狀態的測試。

**政策語意**：

| 值 | 寫入目標 `[domain/…]` 的內容 | 約束 |
|---|---|---|
| 未設定（預設） | 不建立、不改寫 `ipa_access_order` 與 `pwd_expiration_warning` | **不是回滾**；先前設過 `renew`，取消設定不會關閉。 |
| `warn` | `ipa_access_order = expire, pwd_expire_policy_warn`，加上 `pwd_expiration_warning` | 已過期仍可登入但顯示警告；作為 renew 故障時的降級／灰度部署選項。 |
| `renew` | `ipa_access_order = expire, pwd_expire_policy_renew`，加上 `pwd_expiration_warning` | 必須通過真正 SSH Key + expired-password 的活體互動驗收後才允許生產採用。 |
| `off` | `ipa_access_order = expire`；不動 `pwd_expiration_warning` | 回滾用；`expire` 就是 ipa-client-install 不寫這行時的預設值，IPA account expiration 檢查保留。 |

現有的 `ipa_access_order` 不是已知形式（沒有這行、`expire`、`expire, pwd_expire_policy_reject|warn|renew`）或出現多行時，在修改前 fail-closed。IPA provider 的合法值只有 `expire` 與三個 `pwd_expire_policy_*`，ipa-client-install 也不寫這行，沒有需要保護的「非 Pilot 自訂 token」，所以不需要 ownership 紀錄。

`warn/renew/off` 是 **host 端 SSSD policy**，對該 host 上經 PAM 帳號檢查的其他服務也可能產生影響，**不是僅限 SSHD 的 per-user/per-service 例外**。要限制套用範圍，應使用 Pilot host/component rollout；無人值守帳號必須有密碼且到期日設在遠未來（見 P3；純金鑰帳號依 §1.3 會被拒絕），而非局部跳過 PAM。

### P1 — 實作 SSSD 設定收斂與安全回滾

主要修改：`playbooks/apply/freeipa-client-apply.yml`，可新增 `playbooks/apply/tasks/freeipa-client-ssh-password-expiration.yml`（若 helper 需新增，置於 `playbooks/apply/files/`）。

- **Preflight**：確認 host 確實 enroll、`/etc/sssd/sssd.conf` 存在且 `0600`、偵測到唯一的 IPA domain section、`access_provider = ipa`、主機是 Ubuntu 24.04（本功能唯一支援的 OS；非 24.04 主機設定本功能任何非預設值時，在修改前拒絕）、沒有重複或未知衝突的 `ipa_access_order`。缺少確證即 fail-closed（修改前就失敗）。
- **寫入方式**：preflight assert sssd.conf 恰好一個 `[domain/` section、`ipa_access_order`／`pwd_expiration_warning` 各最多一行、現有值是已知形式（見 P0）；通過後沿用現有 hardening task 的 `lineinfile` + `insertafter: '^ipa_domain\s*='` 整行寫入。只有一個 domain section 時，整檔 regex 不會改錯 section，不需要 INI parser 或 ownership 契約；檔案註解與不相關鍵不動。
- **最小變更**：未設定時不產生 mutation；already converged 時無改變、無重啟；更新 `pwd_expiration_warning` 只針對目標 domain，不要改全域 `[pam]` 以波及其他 realm。
- **實際順序**（apply 已實作）：`slurp` 目前的 sssd.conf（快照在 Ansible 變數裡，不寫前像檔）→ preflight 檔案形狀 → `lineinfile` 整行寫入 → `sssctl config-check`（檢查的是已寫入的檔案，失敗由 rescue 把快照寫回）→ 依既有 SSSD restart gate 只重啟一次（另加 confdb 與檔案不一致時也重啟）→ 確認 SSSD active、`sssctl config-check`、confdb 與檔案一致。前像不可使用歷史 `.prev` 模糊回退；變更腳本中斷後，下次 apply 以 confdb 與檔案的比對補上重啟。PAM account 結果（C15–C17）由 verify 檢查，不在 apply 的 block 內。
- **失敗時**：兩個 block 各有 `always` 的 rescue。(a) 寫入階段（preflight、寫入、`sssctl config-check`）失敗：rescue 把本次快照寫回（內容、mode `0600`、owner root），SSSD 此時還沒重啟，run 失敗。(b) 重啟**成功之後**的驗證（SSSD active、`sssctl config-check`、confdb 與檔案一致）失敗：rescue 寫回快照、在還原的檔案上重啟 SSSD，run 失敗。**不在 rescue 內**：兩個 SSSD 重啟 task（「restart SSSD after wiring responders」與「enable + start SSSD」）。`systemctl restart sssd` 自己失敗時不會回滾，sssd.conf 保留新政策、SSSD 可能停著，由操作者處理（`journalctl -u sssd`、修檔後重跑 apply），這是 spec §5 的已知限制。只帶 `--tags C14`／`C20` 而略過快照的 run 沒有可還原的前像，失敗訊息會明說沒有還原。還原後 playbook 不另外跑 `sssctl config-check`，也不確認管理連線，沒有 `PARTIAL` 狀態：還原的 copy 或重啟自己失敗時，該 task 失敗，由操作者處理。敏感檔的內容、密碼、PAM 輸入、Kerberos ticket 不得出現在 CI、log、diff、evidence。
- **標籤與 idempotency**：沿用 `freeipa-client`、`sssd_hardening` 及新 spec row tag，注意 [PR #243](https://github.com/kjelly/pilot/pull/243) 對 `always` task 的收斂限制。第二次 apply 必須 `changed=0`，不能因為備份／健康檢查而永遠報 changed。新 row tag 與 `sssd_hardening` 都要加到 SSSD restart task（`freeipa-client-apply.yml:848`）；restart 的 `when:` 讀其他 register 一律改成 `(x | default({})) is changed`，否則 `--tags <新 row>` 會因 `ipa_sssd_services` undefined 而失敗（§2 的既有 bug，同一個 PR 修掉）。rescue 每個 task 標 `always`（AGENTS.md §4.4）。
- **保留既有支援**：不能更動 `services = nss, pam, ssh...`、Ubuntu `sssd-sudo.socket` 與 AlmaLinux responder 差異；不能倒退 [PR #222](https://github.com/kjelly/pilot/pull/222) 的 sudo full-refresh 邏輯。

### P2 — SSHD/PAM 有效配置驗證（不默默放寬認證）

實作前後應於目標主機檢查：

```bash
# 以下是 P2 要在實作後檢查的指令；C18（`sshd -T` 的 `usepam yes`）與 C15–C17（`sssctl user-checks`）已在 Ubuntu 24.04 實跑並寫進 spec，其餘隨階段 3 實跑
sshd -T -C user=<interactive-ipa-user>,host=<client-fqdn>,addr=<test-client-ip> \
  | grep -Ei 'usepam|pubkeyauthentication|passwordauthentication|kbdinteractiveauthentication|authenticationmethods|forcecommand'
sssctl config-check
sssctl user-checks -a acct -s sshd <interactive-ipa-user>
sssctl user-checks -a acct -s sudo <interactive-ipa-user>
```

- 要求 `UsePAM yes`、`PubkeyAuthentication yes`、`/etc/pam.d/sshd` 具備 SSSD account/password-change 流程（Debian/Ubuntu 通常透過 `common-account`、`common-password`）。必須驗證**實際** `sshd -T -C`，因為 `Match`、`Include` 的優先序可能覆蓋預期。
- Pilot 目前 `PasswordAuthentication yes` + `KbdInteractiveAuthentication yes` 是**既有行為**。這次新增的 `renew` 不得聲稱系統已 Key-only；也不得為完成密碼更新而無審核地再開放任何 SSH 登入方式。若需求包含「SSH Key-only」，必須另定義能在 `PasswordAuthentication no` 下完成 PAM `chauthtok` 的實機驗收與顯式選項，不能直接將 `KbdInteractiveAuthentication yes` 視為安全。
- 驗收互動登入採 OpenSSH `ssh -tt -o PreferredAuthentications=publickey -o PasswordAuthentication=no -o KbdInteractiveAuthentication=no -o GSSAPIAuthentication=no ...` 搭配獨立測試帳號，確保不靠第二種 SSH 認證方式過關；**公開金鑰驗證成功不等於密碼修改已完成**，需同時觀察 PAM 對話、FreeIPA 的 `krbPasswordExpiration` 更新，以及後續 SSH/sudo 的真實結果。
- 依 §1.1，sshd 在 `passwd` 結束後一定斷線，要重新登入。Expected 寫成：修改前沒有 shell、`passwd` 結束後斷線、修改成功後重新以 key 登入可以進 shell。不要把「同一 session 立即進 Shell」寫成 Expected。

### P3 — 兼容 Pilot 非互動流程／服務帳號

**此項是正式啟用 `renew` 前的硬性 gate，不得排除於交付範圍。**

1. **`pilot-login-canary`**：已存在的 [`login-probe`](https://github.com/kjelly/pilot/blob/60a1f618ec1c9b3302e02bfc6a566b0024374ed9/docs/verification/login-probe.md) 每 60 秒執行非互動式 SSH；不能因為部署新政策就無法回報真正的 `ok`。依 §1.3，純金鑰帳號在 `warn`／`renew` 下會被拒絕，所以 canary **必須有密碼**，而且密碼不能是過期狀態：給一組隨機密碼（vault 保存、平常不使用）後，用 `ipa user-mod <canary> --password-expiration=<遠未來>` 把到期日設到遠未來。roster 的預設密碼是管理員 reset，一開始就過期，canary 若只拿到預設密碼，依 §1.1 每一輪都會落在 `session`。**測試**：fixture playbook（`playbooks/test/fixtures/`）直接對 FreeIPA 下 `ipa passwd`／`ipa user-mod --password-expiration=<遠未來>` 建出各類狀態的帳號；**不修改 freeipa-identity／roster 去支援測試**（決定：2026-11-05）。**正式環境**：canary 的密碼與到期日是啟用 `renew` 前的操作前置（§8 DoD、A07 驗證），本功能不新增 roster 欄位；若之後要讓 roster 管理密碼到期日，另開獨立需求。**不得**取消 HBAC 限制或授予 canary sudo。
2. **服務／自動化**：盤點 SSH deploy、MCP、批次 SSH、CI runner、SCP/SFTP、Git-over-SSH、定時維護、無 TTY 遠端命令。這些程序可能無法處理 chauthtok；要明訂為 human-interactive 範圍、適當的 FreeIPA service principal／專用帳號，或明確不啟用 `renew` 的 target 群組。
3. **Portal/Gateway/Directory**：驗證 `pilot-access-gateway` 與 `pilot-access-directory` 的 ForceCommand、GSSAPI delegation、錄製／session 流程，確保 `renew` 沒有把原本可用的路徑變成不可恢復的 account/session 拒絕。不得為本案移除原有 ForceCommand 或弱化 session recording gate。
4. **離線／HA**：FreeIPA primary down、replica 存活、全部 IPA unreachable、SSSD offline cache 等場景需明確記錄結果。無法核實到期狀態時不宣稱「已強制完成」，並確保 break-glass 管道存在。
5. **roster 重設循環**：`preserve_existing: false`（或舊格式 `force_password: true`）沒改回來的使用者，在他自己改過密碼之後，下一次 freeipa-identity apply 會再 reset 回預設密碼（`playbooks/apply/freeipa-identity-apply.yml:1188`）。以前只用 key 的人感覺不到，開了 `renew` 就會每次 apply 之後都被要求修改。啟用前列出這類使用者，改回 `preserve_existing: true`。

## 4. Acceptance Matrix（實機通過才 Ready）

| ID | 測試情境 | 必要觀察／驗收標準 |
|---|---|---|
| A01 | 既有主機未設定新變數 | `sssd.conf` 不變、`sshd -T` 不變、SSSD 無重啟；既有 `freeipa-client` spec PASS。 |
| A02 | `warn`、密碼仍有效但接近到期 | SSH Key 可登入；在支援的 PAM 終端顯示正確警告；不洩露使用者密碼。 |
| A03 | `renew`、密碼仍有效 | SSH Key 正常登入；既有 HBAC/sudo 行為不變。 |
| **A04** | **`renew`、密碼已過期、使用者知道舊密碼（fixture 用管理員 `ipa passwd`，等同 roster 預設密碼的狀態）** | **真實 SSH publickey（`-tt`）→ sshd 不給 shell、改執行 `passwd` → 修改後斷線 → 重新以 key 登入進 shell → 原授權 sudo 正常；FreeIPA 的 `krbPasswordExpiration` 已更新。** |
| A05 | 已過期、舊密碼錯誤／使用者取消／終端中斷 | 不得進入正常 Shell；可由 FreeIPA 管理員或獨立管道恢復，不發生特權提升。 |
| A06 | 帳號停用、`krbPrincipalExpiration`、HBAC deny | 不能透過改密碼繞過原來的帳號限制；需實際 SSH allow/deny。 |
| A07 | 非互動式 canary（有密碼、到期日在遠未來） | login-probe 每輪維持 `ok`；`ipa user-show --all` 的 `krbPasswordExpiration` 在未來；不新增 stdin prompt，無額外 sudo 權限。 |
| A08 | 非互動式帳號密碼已過期（BatchMode、沒有 TTY） | client 看到 `Authenticated` 之後出現 `Password change required but no TTY available`、rc=1；login-probe 記為 `session`，不誤報成健康；可由管理員 reset 或本人互動修改恢復。 |
| A09 | 密碼已過期：SSH remote command、SFTP／SCP | 命令與 sftp subsystem 都不執行，rc=1，不會進入 Shell；密碼未過期的帳號行為不變。 |
| A10 | Gateway/Directory + ForceCommand | 密碼未過期：既有 portal／recording／GSSAPI／HBAC 流程仍滿足各自 spec。密碼已過期：有 TTY 時 ForceCommand 被 `passwd` 取代、沒有 TTY 的 transport rc=1，且不產生繞過 recording 的 session。在 gateway／directory／target-policy 主機啟用 `renew` 前必須通過（§5）。 |
| A11 | SSSD 設定無效、設定鍵重複、目標 domain 不唯一 | 變更前拒絕或本次備份原子回滾，`sssd` active、原 SSH 管理入口可用。 |
| A12 | IPA primary 中斷、replica 可用／全部 offline | 以實際 target 取得的結果標明 PASS／FAIL／UNTESTED，不將 cache lookup 代替 Kerberos/PAM 驗證。 |
| A13 | `--check --diff`，單一 row tag，整個 component | Preview 不 mutate；選擇性 tag 不意外套用其他組件；失敗 rescue 恢復本次狀態。 |
| A14 | 重複 apply + `off` 回退 | 同策略重跑 `changed=0`；`off` 寫回 `ipa_access_order = expire`，過期密碼的帳號可再以 key 登入，帳號 HBAC/sudo/SSH Key 仍正常。 |
| A15 | 支援 OS：只有 Ubuntu 24.04 | vm-target 與實際主機都是 Ubuntu 24.04，只在 24.04 實測並宣告支援。**不支援** Ubuntu 22.04（其 SSSD 沒有 `ipa_access_order`）；其他 OS（含 EL9、Ubuntu 26.04）不在範圍內。非 24.04 主機設定本功能時由 preflight 在修改前拒絕。 |
| A16 | sudo cache fresh/stale 與密碼過期交叉案例 | 分開診斷 PAM expiry 與 sudo rule refresh；不透過 `sss_cache -E` 當永久修法。 |
| A17 | 沒有密碼的帳號（純金鑰） | 未設定／`off`：照常登入。`warn`／`renew`：依 §1.3 被拒絕（PAM system error，SSSD log 有「No Kerberos password expiration attributes found」）。記錄實際結果，作為「啟用前所有帳號都要有密碼」的依據。 |
| A18 | 改密碼後重新登入、管理員 reset 偵測（`renew`，spec C19／C20） | 同一帳號在 `renew` 下完成 `passwd` 後：只用 TTY 的重試（每次停在 `Current Password` 再中斷）與非互動式重試都在 30 秒內重新登入成功；使用者有一個開著的 session 時，管理員 reset 在 10 秒內被發現。比較預設 `no_session`（#262／#263 的失敗行為）與 `always`。同時量代價（每個 PAM 請求多一次後端查詢：sudo／登入延遲、LDAP 請求數）。 |

**A11 的實際涵蓋**：沒有單一名為 A11 的活體 arm。設定無效與輸入不合法由負向對照組（非法值、非 24.04、gateway 群組、天數、重複或未知的 `ipa_access_order`、`sssctl config-check` 失敗、`pam_initgroups_scheme` 的非法形式）在 VM 上觸發；sssd.conf 有不只一個 `[domain/` 區段或 `access_provider` 不是 `ipa` 由 preflight 在修改前拒絕，由 `internal/spec` 的單元層 runtime 測試（真 ansible 跑真的 preflight，sssd.conf 位元組不變）覆蓋，不是 VM arm。

**重要：** A04 必須是正規的 **活體端到端測試**（真實 FreeIPA KDC/LDAP + 真實 SSSD/PAM + 真實 sshd + user SSH Key + 密碼更新），單純 `grep ipa_access_order`、`sssctl config-check` 或 mock PAM 均不足以宣告已實現需求。使用可拋棄測試帳號，**不得修改正式人員密碼到期狀態**。

## 5. 實施階段與 PR 切分

| 階段 | 預計交付 | 進入下一階段的 Gate |
|---|---|---|
| **0. Baseline** | 固定 `main` revision；讀現有 `sssd.conf`、`sshd -T`、PAM、FreeIPA 版本、canary 政策、實際 inventory；列出 `krbPasswordExpiration <= now` 的使用者（還在用預設密碼的人）與 `preserve_existing: false` 的使用者；記錄風險清單。 | 確認目標主機都是 Ubuntu 24.04；清楚列出原有 SSH 密碼驗證設定、受影響自動化帳號；影響名單已通知；主機上能登入的 FreeIPA 帳號都有密碼（含 canary，到期日在遠未來）；已確認 client 的 SSSD 快取有 `krbLastPwdChange`／`krbPasswordExpiration`（§1.3）。 |
| **1. Spec + contract（已完成 2026-11-05）** | 完成 spec acceptance rows、變數契約與回滾語意；先獨立 review。 | Spec 沒有把預期 config 視為端到端證據；未設定／`warn`／`renew`／`off` 精確定義；§1.1 的 OpenSSH 行為寫成 Expected。 |
| **2. Apply + regression（已完成 2026-11-05）** | 新增 SSSD 收斂 task（單一 domain assert + 整行寫入）、preflight、SSSD/SSHD/PAM 有效設定檢查、失敗恢復、tags（含 restart task 的 tag 修正）、測試。 | lint、unit/regression、negative controls、check-mode、idempotency 全 PASS。 |
| **3. Native topology（主 PR）** | FreeIPA server + Ubuntu 24.04 一般 client（不是 gateway／directory／target-policy 主機）+ login-probe；A01–A09、A13–A15、A17 實機矩陣與負向對照組（非法值、非 24.04、gateway 群組、天數、重複或未知的 `ipa_access_order`、`sssctl config-check` 失敗、`pam_initgroups_scheme` 的非法形式），產生 evidence record。sssd.conf 有不只一個 `[domain/` 區段或 `access_provider` 不是 `ipa` 由 preflight 拒絕，由單元層 runtime 測試覆蓋，不是 VM 對照組。 | 上述全部 PASS。 |
| **3b. 擴大適用範圍（後續 PR）** | 解除 preflight 對 gateway／directory／target-policy 主機 `renew` 的拒絕（A10、A12、A16 的實機結果已在階段 3 的 evidence，但 A10 是用不含這三個群組的 inventory 套用取得的，解除拒絕要改 playbook 並重做證據）。| 解除前，spec 寫明不支援，preflight 在屬於這些 component 的主機設定 `renew` 時拒絕。 |
| **4. Rollout** | 先 sandbox → 單一 staging canary host（**非** login-probe 監測帳號）→ 分批正式 host；每批 live SSH、sudo、login-probe 驗證。 | 每批成功率、故障回滾與 break-glass 演練有紀錄；失敗即暫停下一批。 |

**建議 Issue／PR 規劃**：

- **主 Issue / 主 PR（必要）**：「FreeIPA SSH-key expired password renewal」— 在 Ubuntu 24.04 一般主機上，spec、contract、apply、regression、native evidence（階段 3）同一個完整交付閉環；解除 preflight 對 gateway／directory／target-policy 的 `renew` 拒絕留給階段 3b 的後續 PR；遵守 `issue-to-pr` 一次一項、先 spec 後 implement、最終 Ready 前獨立 review。切勿把僅修改 SSSD 一行的 PR 提前當作功能完成。
- **後續獨立 PR（選配）**：「FreeIPA password expiry EPN notifications／login-probe 密碼政策監控」— 可以使用 `ipa-epn` 主動 Email，但不取代 SSH 登入強制修改，也不阻塞核心功能的第一個 PR（除非環境無法保證人員操作時有恢復管道）。
- **若實測發現 Key-only requirement**：另開明確 scope 的 SSH password-login hardening PR；不得順手改動現行 `05-freeipa-client-password-auth.conf`，因為可能影響仍未部署 SSH Key 的新使用者。

> 每份 PR 按 [PR #249](https://github.com/kjelly/pilot/pull/249) 的 gate 對齊最新 `main` 祖先鏈、重新驗證受影響的測試與 CI。依 [PR #205](https://github.com/kjelly/pilot/pull/205)，目前 skill 是**單一 Issue／PR、同一乾淨 checkout**，不是早期的「多 worktree 並行」流程。

## 6. 測試、證據與回滾細節

### 測試資產

- 以 Pilot 的 `vm-target` 建立有 FreeIPA（realm）、已 enroll Ubuntu 24.04 client、至少兩個 FreeIPA 測試帳號的隔離 topology；實際採用的 inventory 需由 `vm-target show-inventory` 取得，不能依文件猜測 group membership。
- 使用 **有 sudo 權限的人員測試帳號** 與 **無 sudo、有密碼且到期日在遠未來的 login-probe canary 帳號**；同時準備 valid、near-expiry、expired、no-password（A17）、disabled／HBAC-denied 五類 fixture。
- expired fixture：測試 FreeIPA 管理員對測試帳號執行 `ipa passwd`。管理員 reset 的密碼會立即過期（`playbooks/apply/freeipa-identity-apply.yml:1199` 已實測），也就是 roster 預設密碼的狀態，不需要直接改 `krbPasswordExpiration`。valid 與 near-expiry fixture 在設定密碼後用 `ipa user-mod --password-expiration=<時間>` 設到期日（FreeIPA 4.13.4 有這個選項）；先記錄原值，測後復原或直接銷毀測試 realm。禁止使用 Production 帳號、密碼、私鑰錄製 evidence。
- 對 SSH Key 登入，採 `ssh -vv -tt` 證明 publickey 已 accepted；在 host journald/PAM message 記錄 account/password-change 轉移。輸出需去識別／遮蔽秘密。
- 套用後再執行 `pilot verify`、完整 spec、`changed=0`；結果依 [`docs/actual-run-evidence.md`](https://github.com/kjelly/pilot/blob/60a1f618ec1c9b3302e02bfc6a566b0024374ed9/docs/actual-run-evidence.md) 產出 `docs/evidence/freeipa-client-password-renewal/` 來源 revision、tree、target/image、真實 PASS/FAIL/SKIP、failure/rollback、未涵蓋範圍與 `LATEST.md`。嚴禁未實跑就填寫 PASS。
- 不讓測試清理誤刪其他 session 的 VM；採 [PR #209](https://github.com/kjelly/pilot/pull/209) 確立的 `--fresh` 與 ownership-safe cleanup 語意。

### 正式回滾策略

1. 部署前記錄 host identity、targeted SSSD domain、`sssd.conf` checksum／權限、SSHD effective config、SSSD health、仍可用的本機 root/console/break-glass 通路。
2. **當次 apply 失敗**：寫入階段（preflight、寫入、config-check）失敗，與重啟成功之後的驗證（SSSD active、config-check、confdb 與檔案一致）失敗，都由 Ansible rescue 還原本次快照（後者並在還原的檔案上重啟 SSSD），run 失敗；操作者確認 SSSD active 與原 SSH／PAM allow/deny 行為後，才可繼續 rollout，失敗即停批。**SSSD 重啟本身失敗不回滾**（兩個重啟 task 在 rescue 之外，spec §5）：sssd.conf 保留新政策、SSSD 可能停著，要由操作者處理（`journalctl -u sssd`、修檔後重跑 apply），所以 rollout 先在單一 staging canary 上做，並備好 break-glass（§1、§5 階段 4）。
3. **部署已成功但後續相容性失敗**：由 `pilot edit` 將該 host 政策改為 `warn`（保持可登入）或 `off`（寫回 `ipa_access_order = expire`），經 `pilot generate/deploy` 重新套用；再以 live SSH+sudo+login-probe 驗證。取消設定（回到未設定）**不能當作 rollback**。
4. 變更責任邊界是 **client-host** 的 SSSD/SSHD；不修改 FreeIPA global password policy、HBAC roster、sudo rule 作為回滾捷徑。若測試帳號密碼真的過期，優先透過 FreeIPA password-change／admin reset 恢復。

## 7. 不包含於本次核心範圍

- 不變更全域 FreeIPA 密碼到期天數、密碼複雜度或 MFA policy。
- 不提供跳過過期密碼的 sudo 特權或 `NOPASSWD` 繞過 PAM 的捷徑。
- 不把 SSH `ForceCommand` 或 shell RC（`.bashrc`）寫成強制改密碼方案；其可被 non-interactive/其他 shell/命令模式規避，且容易影響 Gateway。
- 不宣稱只因 `ipa_access_order` 生效就能完成所有 SSH client 的互動式 password-change；OS、PAM、SSHD、TTY 與 FreeIPA policy 都是實測前提。
- 不修改 GitHub repo；本文件只提供**改善計畫**，供後續 `issue-to-pr` 執行。

## 8. 完成定義（Definition of Done）

- [x] 階段 2：apply（`always` 輸入 gate、快照→preflight→整行寫入→`sssctl config-check`、confdb drift 檢查、post-restart 驗證與 rescue）、fixture playbook、`TestRegression_FreeipaClientApplyPlaybook_PasswordExpiryPolicy`／`_PwexpiryFixtures`；`TestSpecPlaybookTagAlignment` 通過；restart task 的 tag 修正有反向測試證明會失敗。
- [x] 階段 1：`docs/verification/freeipa-client.md` v1.14 新增 C13–C18（隨主機政策判斷的列）；contract 宣告 `freeipa_client_sssd_password_expiry_policy`（`^(warn|renew|off)$`）與 `freeipa_client_sssd_password_expiry_warning_days`；regression test 鎖住列與契約；spec lint 0 errors。`TestSpecPlaybookTagAlignment` 在 C13/C14 失敗是預期的，直到階段 2 的 apply playbook 加上 tag。
- [x] `freeipa-client` contract 支援 `warn/renew/off`，未設定時不動；預設與既有 host 行為完全相容。
- [x] 單一 domain assert + 整行寫入的 SSSD edit、有效設定檢查、fail-closed、冪等性全部通過；當次前像回滾涵蓋寫入階段與重啟成功之後的驗證失敗，**不含** SSSD 重啟本身失敗（兩個重啟 task 在 rescue 之外，spec §5 已知限制）。
- [x] SSSD restart task 帶新 row tag 與 `sssd_hardening`，`--tags` 只選其中一個時設定也會生效。
- [x] 真實 SSH Key + 已過期密碼出現互動修改，修改前不能進正常 Shell，`passwd` 結束後斷線，重新 SSH 與 sudo 正常。
- [x] HBAC deny、停用帳號、SCP/SFTP／遠端命令、login-probe 沒有未授權的存取回歸；gateway／directory／target-policy 主機在 A10 通過前，由 preflight 拒絕 `renew`。
- [x] A10（gateway／directory／target-policy 主機）已實跑（`always` 之後）：密碼有效時既有 portal／Directory／transport／recording 流程通過（e2e `strict` 階段有偶發失敗，非本功能造成，#272），過期時由 `passwd` 取代 ForceCommand、沒有 TTY 的 transport 失敗且沒有繞過 recording 的 session（`docs/evidence/freeipa-client-password-expiry-gateways/LATEST.md`）。**preflight 的拒絕仍保留**：解除需要改 playbook、新 candidate 與完整證據。
- [x] A12（HA／offline）已實跑：primary 停止、replica 停止、全部停止、恢復（`docs/evidence/freeipa-client-password-expiry-ha/LATEST.md`）。
- [x] A18（改密碼後重新登入、管理員 reset 偵測）與 `always` 的代價量測：`docs/evidence/freeipa-client-password-renewal/LATEST.md`。
- [x] A16（sudo cache 交叉，#267）已實跑：PAM 過期狀態與 sudo 規則分開診斷，規則變更等 `SUDO Smart Refresh`（預設 900 秒），與 `renew`、`pam_initgroups_scheme` 無關，沒有用清快取指令（`docs/evidence/freeipa-client-password-renewal/LATEST.md`）。
- [ ] 啟用前已列出並通知還在用預設密碼的使用者；主機上能登入的 FreeIPA 帳號都有密碼，canary 的密碼到期日在遠未來。
- [x] Ubuntu 24.04 產出真實實跑 evidence；spec 明寫只支援 Ubuntu 24.04（不支援 22.04），非 24.04 主機設定本功能時在修改前拒絕。
- [x] `--check --diff`（已 enroll 的主機不預覽政策變更，spec §5）、選定 row tag／component、第二次 apply `changed=0`、失敗恢復（寫入階段與重啟成功之後的驗證失敗由 rescue 還原；SSSD 重啟本身失敗不回滾，spec §5）與 CI／negative controls 完成。
- [ ] 可由 `pilot edit/generate/deploy` 執行 staging rollout 與 `warn/off` rollback；沒有任何必要的人工作業去直接編修 inventory/vault。
- [ ] 獨立 reviewer PASS，PR HEAD 含最新 `main` 祖先且 CI 與 native evidence 對齊最新 candidate；才標記 Ready for Review。

## 9. 參考資料

- [SSSD IPA provider：`ipa_access_order` 與 SSH key expired password policy](https://man.archlinux.org/man/sssd-ipa.5.en)
- [Linux PAM `pam_chauthtok(3)`](https://man7.org/linux/man-pages/man3/pam_chauthtok.3.html)
- [OpenSSH portable `session.c`（`do_child()`／`do_pwchange()`）](https://github.com/openssh/openssh-portable/blob/master/session.c)、[`auth-pam.c`（`do_pam_account()`）](https://github.com/openssh/openssh-portable/blob/master/auth-pam.c)
- SSSD 2.9.4 原始碼：[`ipa_access.c`](https://github.com/SSSD/sssd/blob/2.9.4/src/providers/ipa/ipa_access.c)、[`sdap_access.c`](https://github.com/SSSD/sssd/blob/2.9.4/src/providers/ldap/sdap_access.c)、[`ldap_auth.c`](https://github.com/SSSD/sssd/blob/2.9.4/src/providers/ldap/ldap_auth.c)
- [Ubuntu 24.04 `sssd-ipa(5)`](https://manpages.ubuntu.com/manpages/noble/man5/sssd-ipa.5.html)（有 `ipa_access_order`；22.04 的版本沒有）
- [FreeIPA Group Password Policy](https://www.freeipa.org/page/V2/Group_Password_Policy)
- [FreeIPA Administrators Guide：無密碼帳號／SSH Key 驗證](https://www.freeipa.org/page/Administrators_Guide)
- [Pilot Pull Requests](https://github.com/kjelly/pilot/pulls)
- [Pilot `main` baseline](https://github.com/kjelly/pilot/tree/60a1f618ec1c9b3302e02bfc6a566b0024374ed9)

---

**交付判定：** 本文件是 `kjelly/pilot` 的**實作計畫**，也記錄這個 PR 的交付狀態。階段 1–3 已完成：spec 列（C13–C20）、contract、regression test、`freeipa-client-apply.yml` 的 SSSD 政策 block（含 `renew` 的 `pam_initgroups_scheme = always`）與 fixture playbook，並在 Ubuntu 24.04 真實 topology 上實跑；結果、tested candidate 與限制都在 evidence record（見上方三份 LATEST），本檔不重複。最關鍵的不確定性「Ubuntu 24.04 的 sshd 是否如 §1.1 所述，在 publickey 登入後執行 `passwd` 完成修改」已由實機確認（A04）。**尚未完成**：preflight 對 gateway／directory／target-policy 主機的 `renew` 拒絕仍在（解除要改 playbook 並重做證據，階段 3b）；啟用前通知還在用預設密碼的使用者，與 staging rollout／`warn`、`off` rollback（階段 0／4）是操作者的前置，不在這個 PR 內完成。已知限制（SSSD 重啟本身失敗不回滾、不讀 `conf.d`、`--check --diff` 不預覽政策變更、純金鑰帳號被拒絕、`always` 是主機全域）見 `docs/verification/freeipa-client.md` §5。
