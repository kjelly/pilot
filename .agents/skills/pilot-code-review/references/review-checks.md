# Pilot review 檢查方向

本檔整理 2026-09-30～2026-10-14 修復紀錄中的漏檢原因。只讀與此次 diff 有關的段落。
下列程式、測試與 evidence 路徑皆相對 repo root；先確認當前版本的內容與符號。

## A. CLI、inventory 與執行目標

- 計畫選定的 hosts 是否就是實際 Ansible argv、inventory 與 recap 的 hosts？
  `-e @vars-file` 可能覆蓋更早的 `-e target_group=...`；同時查 preview、apply、
  idempotency、rollback 與 gateway-scope builders。
- exit 0 不保證有部署：辨識 missing/empty recap、no hosts matched 與 dependency
  只命中部分 planned hosts；controller localhost 不算 provider 已 apply。
- 查每一次 run 的目標 stage。decommission 的 client、FreeIPA server、Wazuh
  manager 可能位於不同 stage；純 read-only inspect 的 gate 例外不能擴大到 mutation。
- 同一實體 target 不應因 aliases 變成多個 Ansible hosts；alias/group 與 spec scope
  要一致。檢查重建後 fact cache、SSH ControlPath 隔離與實際 option precedence。
- topology test 繞過的入口檢查要另行核對：例如配置 RAM 不等於 guest 可見 RAM，
  topology test 通過不代表實際 deploy 的 resource preflight 通過。

參考：`cmd/pilot/cmd/deploy_target_override_test.go`、`internal/targetalias/`、
`internal/factcache/`、`internal/sshcontrol/`、`internal/decommission/stage.go`、
`cmd/pilot/cmd/topology_resources_test.go`。
實跑案例：`docs/evidence/dashboard/2026-10-13-0966ced-delivery.md`、
`docs/evidence/vm-target/2026-10-01-198fb03.md`。

## B. Ansible 的部分執行與語意

- 沿 reader 找 `register` / `set_fact` 來源，包含 `pre_tasks` 與 shared include。
  tag selection 要能執行來源；`default` 不能補做必要的 snapshot、kinit 或安全檢查。
- Mutation 前記錄舊值／拒絕危險操作的 task 要被 mutation 的每個 tag 選到，即使
  mutation 沒讀它的 register。cleanup 要確認 restart/health 前提真的成立。
- rescue 與 block 的 `always:` 也受 tags 篩選。查 restore、它使用的備份與最後
  `fail`；只還原而跳過 fail 可能讓失敗 run 回報成功。
- skipped task 仍 register `changed: false`；不要 `combine()` 互斥 task 的結果
  來決定 restart。單一 run 的 changed 也不代表 runtime 已載入設定。
- fresh check mode 不產生後續所需的 enrollment、CA 或帳號。preview 要說明無法
  判定的部分；真實 apply 仍 fail closed。shared include 不能無意間 `end_host`
  跳過 caller 的其他獨立步驟。
- 查 vars precedence、重複 include 的 fact 殘留、block `when` 每個 task 重判，
  以及 YAML → Jinja → Python regex / shell 跳脫。`--syntax-check` 不證明匹配正確。

參考：`AGENTS.md` §4.4/§4.5；`internal/spec/` 中的
`tagged_run_gates_regression_test.go`、`tagged_prerequisite_regression_test.go`、
`rescue_tags_regression_test.go`、`ipa_kinit_regression_test.go`、
`registered_result_combine_regression_test.go`、`template_backslash_regression_test.go`、
`regex_args_backslash_regression_test.go`、`freeipa_ca_trust_checkmode_test.go`。

## C. Effective state、重跑與回滾

- 列出 disk files、runtime、credential、remote registration 與 pending bookkeeping。
  對可能失敗的位置，查拒絕、rollback 與 retry 後這些狀態是否一致。
- copy/template 原子換檔後，單檔 bind mount 可能仍指向舊 inode；reload 會再讀舊檔。
  比較 container 實際看到的內容，涵蓋「前次已寫檔但未 restart」的修復路徑。
- sshd config 檢查要早於最早可能 restart 的動作，包含 package install 的隱含
  restart。查整份配置驗證、reload 失敗、restore 順序與新連線的 allow/deny。
- reload 後若 cleanup 失敗，rescue 是否只還原 disk、daemon 卻繼續用新設定？
  區分 rollback boundary 與已完成 reload 後的清理責任。
- uninstall/migration 會改遠端身分及本機 PAM、SSSD、hostname、CA trust 等。
  archive 還原成功不等於登入恢復；以實際 old-realm login 與授權判斷恢復。
- realm 切換涵蓋同 FQDN、大小寫、舊 server pool pins、SSSD Kerberos mapping。
  新 pin 不可被稍後的舊 block 移除；uninstall 不能被提前導向新 server。
- 保護路徑與待刪 token 不能只比字串：`//`、`/./`、symlinked directory 或 hard
  link 可能指向同檔。查 normalization、device/inode 與 symlink 最後一節的契約。
- diagnostics / inspect / checksum 也可能洩漏 secrets。查 callback 與 verbosity
  下的輸出；password 的 unsalted hash 不能當安全的公開摘要。

參考：`internal/spec/container_file_mount_regression_test.go`、
`internal/spec/sshd_config_write_behavior_test.go`、
`internal/spec/sshd_config_write_regression_test.go`、
`internal/spec/pilot_access_gateway_ag82_regression_test.go`、
`internal/spec/realm_replacement_rescue_regression_test.go`。
實跑案例：`docs/evidence/prometheus/2026-10-12-c12c4a8.md`、
`docs/evidence/sshd-config-writes/2026-10-13-4aa0dab.md`、
`docs/evidence/freeipa-realm-replacement/2026-10-12-b9d82d9.md`、
`docs/evidence/freeipa-realm-replacement/2026-10-13-dd69a2d.md`。

## D. Spec、parser 與授權 gate

- 把 checklist command 放回 Markdown parser → shell → matcher 的實際管線。
  escaped pipe、error stdout 或不限定區塊的 grep，可能讓壞狀態也 PASS。
- 驗收讀 effective state：glibc options 依序覆蓋與數字解析、unbound 等價網段、
  `global.external_labels.site` 都不能用「某字串存在」代替。
- Gate 對等價輸入做相同安全判斷：兩個 /1 可合成 allow-all；不同路徑拼法可指向
  protected file；日期符合 regex 仍可能不存在於日曆。
- 時效 gate 查時計來源、UTC/目標 timezone、fact cache 年齡、有效截止點與 YAML
  quoted string / bare date 型別。非法輸入依契約拒絕，不變成 permissive default。
- Spec 與 apply 同一作者時，oracle 仍須來自 acceptance 或外部工具行為；兩份程式
  採同一錯誤假設不是獨立驗收。

參考：`internal/spec/core_infra_provider_stratum_regression_test.go`、
`internal/spec/freeipa_dns_client_resolver_timeout_regression_test.go`、
`internal/spec/dns_acl_regression_test.go`、
`internal/spec/prometheus_site_selector_behavior_test.go`、
`internal/spec/snmp_exception_expiry_regression_test.go`。

## E. Go lifecycle、交易與時間

- 以資料 invariant 判斷 atomicity。Session ingest、finish、start 的 check/write
  是否同一 write transaction？Replay 的 summary/events 是否同一 snapshot？
  Go race detector 不會替你證明 SQLite 的業務 invariant。
- baseline learning 與 eviction 是否一起 freeze？active episode 超過視窗或重啟後，
  是否仍可評分與恢復？缺 telemetry 不推進 recovery，resolved 才回 rolling eviction，
  subject kind 不混用 history，live 與 replay 一致。
- retention 除 flags 還要查資料是否已有 downsample 副本：short-lived、stopped、
  relabeled site 的尾端 raw blocks，不能刪唯一副本後聲稱保留 90 天。
- retry test 時計要超過實際 backoff，考慮 persistence 時間精度。關 stop channel
  不表示 goroutine 已退出；查 PTY/FD cleanup 正常結束與 `t.Fatal` 時的 join。

參考：`internal/sessionstore/concurrency_test.go`、
`internal/detection/engine_baseline_recovery_test.go`、
`cmd/pilot-detection-engine/replay_test.go`、`scripts/thanos-retention-behavior-test.sh`。
歷史修復：`63f4cdc`、`215d4f0`、`f4d4db9`、`09b9164`、`e0c2475`。

## F. 測試與證據

- Repo-wide lint 要查語意覆蓋範圍：include expansion、pre_tasks、tag inheritance、
  when、allowlist 與新 caller。test 存在不表示涵蓋新路徑。
- Mock 保留 invariant 依賴的特性：Ansible no-hosts exit 0、skipped register、
  extra-vars precedence、glibc parsing、installer 的遠端副作用。
- 結構測試可鎖順序與禁止寫法；effective state、authorization、migration 的承諾
  需要能判別反例的 behavior test 或 target evidence。缺 evidence 與重現 bug 分開。
- 核對 tested revision/tree 與 execution-affecting hashes；不把舊 candidate PASS
  沿用到新內容。列 FAIL、topology 例外與未執行情境，不把部分 PASS 擴大成 full PASS。
- 功能入口的承諾要看該入口的 evidence：單一 playbook/topology test 不證明
  deploy/reconcile 的 scope、resource preflight 與 vars-file 合併行為。

參考：`docs/actual-run-evidence.md`、`AGENTS.md` §1.5/§5.10、
`.github/workflows/ci.yml`；依目前 CI 與測試源碼判斷哪些檢查確實會執行。
