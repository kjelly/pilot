# Runbook — vm-target → core-infra-provider 9/9 PASS (real KVM)

> 撰寫日期：2026-07-01 (UTC)
> 對齊 commit：HEAD `19c4ac2`（`fix(verify): stage /etc/pilot-verify.env ...`）
> 維護者：sre

---

## 0. 一句話目標

> 在 **真 KVM VM** 上跑完 `core-infra-provider` apply + verify 全鏈，
> 從 DNS / NTP / Keycloak 三個 provider 角色到 9 條 spec 全部 PASS。

需要直接登入看狀態：

```bash
pilot vm-target ssh --name core                              # 互動 ssh (real PTY, sudo / resize 都 OK)
pilot vm-target shell --name core                           # 互動 shell (預設 bash -l, 沒 bash 退 sh)
pilot vm-target shell --name core -- bash -c "uname -a; ip a" # 跑一行指令
pilot vm-target exec --name core -- systemctl is-active unbound  # 不開 PTY, 給 ansible 用
```

也有一層更簡的 wrapper — `pilot target` — 自動判斷 docker 或 vm target，
不用記哪個子指令對哪種 backend：

```bash
pilot target up     --target core                          # auto-detect docker/vm
pilot target run    --target core \
    --playbook playbooks/apply/core-infra-provider-apply.yml --role dns  # 自動帶 -i, -l, -e target_group
pilot target verify --target core --spec docs/verification/core-infra-provider.md
pilot target shell  --target core -- bash -c "uname -a; ip a"
pilot target exec   --target core -- systemctl is-active unbound
pilot target down   --target core
pilot target list                                          # 列出 docker + vm
```

對比原本三行指令，現在一行的 wrapper 就夠了。
commit `abbafa7` 加這個 wrapper。

這份 runbook 是 `pilot vm-target` + `core-infra-provider` apply +
verify 的 **end-to-end 一次跑通**紀錄。對應的 commit chain 在
`19c4ac2` 之前，verify 只能拿 5/9（沒裝東西）或 7/9（裝了
DNS+NTP 但 Keycloak 的 env var 過不去 SSH target）。

---

## 1. 起 vm-target：`core`

```bash
go build -o /tmp/pilot ./cmd/pilot/
/tmp/pilot vm-target up \
    --base-image /var/lib/libvirt/images/pilot/noble-base.qcow2 \
    --name core \
    --ssh-user ubuntu \
    --hosts dns,ntp,keycloak \
    --vcpus 2 --memory 2048
# ▶ provisioning VM core (this can take a minute while it boots)…
# ✓ target core up
#   ip        : 192.168.123.232
#   ssh_user  : ubuntu
#   base_image: /var/lib/libvirt/images/pilot/noble-base.qcow2
#   vcpus/mem : 2 / 2048 MiB
#   inventory : `pilot vm-target show-inventory --name core`
```

`/var/lib/libvirt/images/pilot/noble-base.qcow2` 是 dev box 已經
pre-bake 的 ubuntu 24.04 cloud image（含 `python3` + `systemd-resolved`，
詳見 `docs/runbooks/docker-target.md` § 4）。**新 repo** 第一次跑這
條會自己下載 `noble-base.qcow2` 並 chown 到 `libvirt-qemu:kvm`。

> `--hosts dns,ntp,keycloak` 是 sibling-of-docker 的 `multi-host`
> 機制：同一台 VM 在 inventory 裡面同時有 `core`、`dns`、`ntp`、
> `keycloak` 4 個 host entry，全部指向同一個 IP。對 core-infra
> 三角色 apply 來說剛好。

---

## 2. Inventory：直接 `show-inventory`，不用手寫

```bash
# 自動生成。每個 alias 都是獨立的 host entry，所以 `hosts: dns`
# / `hosts: ntp` / `hosts: keycloak` 三種 role-gated apply 都能跑
# （ansible 直接 match host，不必透過 group）：
pilot vm-target show-inventory --name core > /tmp/inv-core.yaml
```

產出：

```yaml
all:
  hosts:
    core:    { ansible_connection: ssh, ansible_host: 192.168.123.232, ... }
    dns:     { ... 同一個 IP + 同一把 key ... }
    ntp:     { ... }
    keycloak:{ ... }
# 沒有 `children:` 區塊 — 早期版本有，但因為 alias name 同時
# 出現在 `all.hosts` 跟 `all.children.<alias>` 兩個地方，會觸發
# ansible 的 [WARNING] "Found both group and host with same name:
# <alias>"。host entry 已經能 cover `hosts: dns` / `-l dns` 兩種用法，
# 所以後來直接不 emit children 區塊了。
```

> 早期版本（commit `da74bde`）會 emit children 區塊強制讓
> `hosts: dns` 透過 group 命中，但 2026-07 後（commit 見下）改成
> 全靠 host entry 直接命中，少 4 條 ansible warning。

---

## 3. snapshot pre-apply（出事可秒回）

```bash
/tmp/pilot vm-target snapshot --name core --tag pre-apply
# ✓ snapshotted core as pre-apply

# 出事要回：
/tmp/pilot vm-target rollback --name core --tag pre-apply
# ✓ rolled back core to pre-apply
```

libvirt qcow2 snapshot 是 **byte-clean**：回到 tag = 該時間點的
disk + memory 完整狀態，比 docker commit 更強。

---

## 4. 套 apply：三個 role 一次過

```bash
# 4.1 DNS role
ansible-playbook -i /tmp/inv-core.yaml \
    playbooks/apply/core-infra-provider-apply.yml \
    -e infra_role=dns -e target_group=dns -e dns_listen_addr=127.0.0.1
# ok=12 changed=7 skipped=9  (含 3 個角色全部 gate + dns 子樹)

# 4.2 NTP role
ansible-playbook -i /tmp/inv-core.yaml \
    playbooks/apply/core-infra-provider-apply.yml \
    -e infra_role=ntp -e target_group=ntp -e 'ntp_pool=ntp.ubuntu.com pool.ntp.org'
# ok=8 changed=3 skipped=13  (dns 跳過、keycloak 跳過)

# 4.3 Keycloak role：sandbox 跑時需要先在 target 裝 java + Keycloak tarball
#     + 建本地 mariadb + 起 kc.sh start-dev。
#     apply playbook 還沒包這段（sandbox-only），先用 vm-target exec：
/tmp/pilot vm-target exec --name core -- bash -c '
  sudo apt-get install -y openjdk-21-jre-headless wget netcat-openbsd
  cd /opt && sudo wget -q https://github.com/keycloak/keycloak/releases/download/25.0.6/keycloak-25.0.6.tar.gz -O /tmp/kc.tgz
  sudo tar -xzf /tmp/kc.tgz && sudo mv keycloak-25.0.6 keycloak
  sudo mkdir -p /etc/keycloak
  echo "127.0.0.1 idp.infra.internal" | sudo tee -a /etc/hosts
'
/tmp/pilot vm-target exec --name core -- bash -c '
  sudo -u root KEYCLOAK_ADMIN=admin KEYCLOAK_ADMIN_PASSWORD=admin \
    nohup /opt/keycloak/bin/kc.sh start-dev \
      --http-port=8080 --hostname-strict=false \
      --db=dev-mem \
      > /tmp/kc.log 2>&1 &
'
# 等 30–60s，直到 :8080 LISTEN
```

> dev / sandbox 這層故意沒寫進 apply playbook：Keycloak binary + java
> 11→21 + DB driver 都要從外部下載，production 套用應該是另一個
> repository 處理 image build。apply playbook 目前只負責 **config 層**
> （env file + systemd unit + 服務存在性 check），適用於「Keycloak
> 已經有，但缺 config」的場景。

---

## 5. verify：9/9 PASS

```bash
KEYCLOAK_ISSUER='http://127.0.0.1:8080/realms/master' \
    /tmp/pilot verify docs/verification/core-infra-provider.md \
    -i /tmp/inv-core.yaml
# ✔ NDJSON:   .../core-infra-provider-20260701-003803.ndjson
# ✔ Report:   .../core-infra-provider-20260701-003803.md
# verdict: **PASS**  (pass=9 fail=0 skip=0)
```

`/etc/pilot-verify.env` 由 `stageVerifyEnv` 在 `pilot verify` 起跑時
自動寫到每台 inventory host 上（best-effort 30s），所以 spec row 的
`source /etc/pilot-verify.env` 拿到正確的 `KEYCLOAK_ISSUER`。

詳見 commit `19c4ac2`：`fix(verify): stage /etc/pilot-verify.env ...`。

---

## 6. 真實 9/9 報告

```text
# Verification Report — Verification Spec — core-infra-provider (Internal DNS + NTP + Keycloak server)
- generated: 2026-07-01T00:38:03Z
- spec:      /home/ubuntu/nfs/github/pilot/docs/verification/core-infra-provider.md
- total:     9  pass: 9  fail: 0  skip: 0
- verdict:   **PASS**

| ID | Status | Detail |
|----|--------|--------|
| C1 | pass | stdout contains "1" |           # unbound installed
| C2 | pass | expected: present (rc=0) |     # 53 LISTEN (not 127.0.0.53 stub)
| C3 | pass | rc=0 matches expected 0 |     # resolv.conf has 127.0.0.1 nameserver
| C4 | pass | stdout contains "1" |          # chrony installed
| C5 | pass | stdout contains "active" |     # chronyd active
| C6 | pass | stdout contains "Stratum" |    # timedatectl show Stratum
| C7 | pass | expected: present (rc=0) |     # pidof java || pidof kc.sh → 0
| C8 | pass | stdout contains "1" |          # 8080 LISTEN
| C9 | pass | stdout contains "200" |        # OIDC discovery 200
```

---

## 7. 對照之前失敗的 row

| 失敗 row | 之前為什麼 fail | 修在哪個 commit |
|----------|----------------|------------------|
| C1 / C4 | 沒裝 unbound / chrony 套件 | 跑 § 4.1 / § 4.2 apply |
| C2 / C3 | 系統還在 stub 模式（`127.0.0.53`）| apply 翻 `/etc/systemd/resolved.conf` + swap resolv.conf |
| C5 / C6 | chronyd 沒起 / timedatectl 沒值 | 跑 § 4.2 apply |
| C7 / C8 | 沒起 Keycloak process / 8080 沒 LISTEN | 跑 § 4.3 install + start-dev |
| C9 | `KEYCLOAK_ISSUER` 沒過 SSH 到 target | `19c4ac2` stageVerifyEnv |

---

## 8. 拆解後的可重現命令（一次跑完）

```bash
go build -o /tmp/pilot ./cmd/pilot/

# 0) inventory 自動生成（`show-inventory` 已含 children，無需手寫）
pilot vm-target show-inventory --name core > /tmp/inv-core.yaml

# 1) 起 VM
/tmp/pilot vm-target up --base-image /var/lib/libvirt/images/pilot/noble-base.qcow2 \
    --name core --ssh-user ubuntu --hosts dns,ntp,keycloak

# 2) 套 DNS / NTP
ansible-playbook -i /tmp/inv-core.yaml \
    playbooks/apply/core-infra-provider-apply.yml \
    -e infra_role=dns -e target_group=dns -e dns_listen_addr=127.0.0.1
ansible-playbook -i /tmp/inv-core.yaml \
    playbooks/apply/core-infra-provider-apply.yml \
    -e infra_role=ntp -e target_group=ntp -e 'ntp_pool=ntp.ubuntu.com pool.ntp.org'

# 3) 裝 + 起 Keycloak（sandbox 一行裝）
/tmp/pilot vm-target exec --name core -- bash -c '
  sudo apt-get install -y openjdk-21-jre-headless wget
  cd /opt && sudo wget -q https://github.com/keycloak/keycloak/releases/download/25.0.6/keycloak-25.0.6.tar.gz -O /tmp/kc.tgz
  sudo tar -xzf /tmp/kc.tgz && sudo mv keycloak-25.0.6 keycloak
  echo "127.0.0.1 idp.infra.internal" | sudo tee -a /etc/hosts
  sudo KEYCLOAK_ADMIN=admin KEYCLOAK_ADMIN_PASSWORD=admin \
    nohup /opt/keycloak/bin/kc.sh start-dev \
      --http-port=8080 --hostname-strict=false --db=dev-mem \
      > /tmp/kc.log 2>&1 &
'

# 4) 等 Keycloak ready + verify
until ansible -i /tmp/inv-core.yaml core -b -m shell \
    -a 'ss -tulnH | awk "/:8080/ {f=1} END{print f+0}"' 2>&1 | tail -1 | grep -q '^1$'; do
  sleep 5
done

KEYCLOAK_ISSUER='http://127.0.0.1:8080/realms/master' \
    /tmp/pilot verify docs/verification/core-infra-provider.md -i /tmp/inv-core.yaml
# → 9/9 PASS
```

---

## 9. 變更紀錄

| 日期 | 版本 | 變更 |
|------|------|------|
| 2026-07-01 | v1.0 | 初版：在 real KVM VM（`pilot vm-target up --name core`）上跑完 core-infra-provider 9 條 spec，9/9 PASS |
