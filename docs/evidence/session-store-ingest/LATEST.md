# Session-store ingest：目前驗證狀態

Issue #77 的修復候選尚未完成原生 target 驗收；此頁不表示候選已通過。

2026-11-03 已在不可變基準 `07f55a6e11cb39be0988e3b032bfa144ed5ec387`
重現原始問題：AlmaLinux 9 FreeIPA server 與 Ubuntu 24.04 client，後者同時執行
真實 Wazuh。Wazuh dashboard 佔用主機 8443，session-store 以相同預設埠啟動時
journal 回報 `address already in use`；apply 為 ok=51、changed=16、failed=1，
五次 ingest 探測後 curl rc=60。FreeIPA 憑證狀態為 MONITORING。

新的成功紀錄將由候選的正式 topology test 產生後更新本頁。
