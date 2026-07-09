---
name: delivery-test
description: |
  Perform delivery verification testing based on DELIVERY.md. Guides the creation
  of a multi-VM test environment (AlmaLinux 9 for FreeIPA server, Ubuntu for main
  services server, and Ubuntu for client verification), configuration of inventory,
  group_vars, vault secrets, running playbooks via site.yml, and validating
  multi-node features (FreeIPA authentication/sudo, log/metric collection, restic
  backups to S3, and Wazuh FIM).
---

# delivery-test

> Recipe for executing a full integration and delivery test of the pilot codebase, using KVM VMs managed by `pilot vm-target`. It validates that all components (FreeIPA, Prometheus, Rsyslog, Restic S3 Backups, and Wazuh FIM) deploy together and interoperate correctly across a multi-node layout.

## 0. Hard Preconditions

Read `AGENTS.md` and `DELIVERY.md` before executing. 
Make sure your host environment meets the prerequisites for KVM VM provisioning (libvirt, kvm, QEMU, cloud-localds).

---

## 1. Setup the Multi-VM Test Environment

We provision three KVM nodes using `pilot vm-target`:
- **`ipa-1`**: AlmaLinux 9 (`almalinux-9`). Role: FreeIPA identity provider (server).
- **`web-1`**: Ubuntu 24.04 (`ubuntu-24.04`). Role: Central services server. Hosts Prometheus metrics stack, Wazuh Manager (syslog receiver & FIM controller), SeaweedFS S3 storage, and Grafana.
- **`web-2`**: Ubuntu 24.04 (`ubuntu-24.04`). Role: Client node. Integrates into FreeIPA realm, ships logs/metrics to `web-1`, backs up config files to SeaweedFS S3 on `web-1`, and runs Wazuh FIM agent reporting to `web-1`.

### 1.1 Provisioning VMs

Execute the following commands to spin up the VMs:

```bash
# 1. Provision AlmaLinux 9 VM for FreeIPA Server (needs at least 4096 MiB Memory)
go run ./cmd/pilot vm-target up --name ipa-1 --base-image almalinux-9 --memory 4096 --vcpus 2 --disk 30 --ssh-user root

# 2. Provision Ubuntu 24.04 VM for Central Services Server (needs 8192 MiB Memory, 4 vCPUs for Wazuh/Containers)
go run ./cmd/pilot vm-target up --name web-1 --base-image ubuntu-24.04 --memory 8192 --vcpus 4 --disk 50 --ssh-user ubuntu

# 3. Provision Ubuntu 24.04 VM for Client verification
go run ./cmd/pilot vm-target up --name web-2 --base-image ubuntu-24.04 --memory 2048 --vcpus 2 --disk 30 --ssh-user ubuntu
```

### 1.2 Gather IPs and Verify Connectivity

After provisioning, retrieve their IP addresses:
```bash
go run ./cmd/pilot vm-target list
```

> **IMPORTANT**: Use the **actual IPs** shown by `vm-target list` in the steps below — do NOT hardcode `192.168.122.2/3/4`. IPs are assigned dynamically by libvirt.

Verify SSH connectivity and passwordless sudo on all nodes:
```bash
go run ./cmd/pilot vm-target exec --name ipa-1 -- ip -4 a
go run ./cmd/pilot vm-target exec --name web-1 -- sudo -n id
go run ./cmd/pilot vm-target exec --name web-2 -- sudo -n id
```

Get the pilot VM-specific SSH keys (these are different from your personal `~/.ssh/id_rsa`):
```bash
ls /var/lib/libvirt/images/pilot/
# You will see per-VM key directories: ipa-1/, web-1/, web-2/
```

---

## 2. Configure Inventory, Group Vars, and Vault

### 2.1 Inventory Setup (`/tmp/pilot-delivery-test/inventory.yml`)

> **CRITICAL**: Use the **actual IPs** from `vm-target list` output. Static IPs like `192.168.122.2/3/4` may not match your actual VM assignments. Do not overwrite an existing repo `inventory.yml`; generate a temporary delivery inventory from the current VM facts.

Capture the actual IPs and create the target inventory:
```bash
mkdir -p /tmp/pilot-delivery-test
IPA_IP=$(go run ./cmd/pilot vm-target list | awk '$1 == "ipa-1" {print $3}')
WEB1_IP=$(go run ./cmd/pilot vm-target list | awk '$1 == "web-1" {print $3}')
WEB2_IP=$(go run ./cmd/pilot vm-target list | awk '$1 == "web-2" {print $3}')

cat > /tmp/pilot-delivery-test/inventory.yml <<EOF
---
all:
  hosts:
    ipa-1:
      ansible_host: ${IPA_IP}
      ansible_user: root
      ansible_ssh_private_key_file: /var/lib/libvirt/images/pilot/ipa-1/id_ed25519
      ansible_ssh_common_args: -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
      ipa_server_ip: ${IPA_IP}
    web-1:
      ansible_host: ${WEB1_IP}
      ansible_user: ubuntu
      ansible_ssh_private_key_file: /var/lib/libvirt/images/pilot/web-1/id_ed25519
      ansible_ssh_common_args: -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
    web-2:
      ansible_host: ${WEB2_IP}
      ansible_user: ubuntu
      ansible_ssh_private_key_file: /var/lib/libvirt/images/pilot/web-2/id_ed25519
      ansible_ssh_common_args: -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null
  vars:
    ansible_python_interpreter: /usr/bin/python3
  children:
    freeipa:
      children:
        freeipa-server:
          hosts:
            ipa-1:
        freeipa-client:
          hosts:
            web-2:
    docker:
      hosts:
        web-1:
    wazuh-manager:
      hosts:
        web-1:
    wazuh-fim:
      hosts:
        ipa-1:
        web-1:
        web-2:
    seaweedfs-s3:
      hosts:
        web-1:
    restic-backup:
      hosts:
        web-1:
        web-2:
        ipa-1:
    prometheus:
      hosts:
        web-1:
    audit-log-forwarding:
      hosts:
        ipa-1:
        web-1:
        web-2:
    linux-servers:
      hosts:
        web-1:
        web-2:
EOF

ansible-inventory -i /tmp/pilot-delivery-test/inventory.yml --graph
```

> [!NOTE]
> Since `wazuh-manager` is enabled, the `log-server` (rsyslog SIEM receiver) is omitted to prevent port 514/udp binding conflicts. Wazuh Manager serves as the primary syslog receiver instead.
> Keycloak and PAM OIDC are excluded from delivery verification.

### 2.2 Runtime Vars

For this disposable delivery test, pass the VM-specific values as `-e` flags instead of modifying repo `group_vars/*.yml`:

```bash
-e freeipa_server_ip=${IPA_IP} \
-e siem_forward_host=${WEB1_IP} \
-e wazuh_manager_host=${WEB1_IP} \
-e restic_s3_target_host=${WEB1_IP} \
-e seaweedfs_s3_config_path=/etc/seaweedfs/s3.json \
-e prometheus_site_label=site-test \
-e thanos_s3_target_host=${WEB1_IP}
```

This keeps the working tree clean and prevents stale `group_vars` IPs from accidentally targeting the wrong VM.

### 2.3 Vault Setup

Prepare secrets required by FreeIPA and backups:
```bash
mkdir -p ~/.vault
echo "testpassword" > ~/.vault/vault-pass
cp vault.example.all.yaml ~/.vault/vault.yaml
```

Edit `~/.vault/vault.yaml` and populate the following required passwords:
- `ipa_admin_password`: FreeIPA admin password (>= 8 chars)
- `restic_aws_access_key_id`: S3 access key (must match `s3.json` identity)
- `restic_aws_secret_access_key`: S3 secret key (must match `s3.json` identity)
- `restic_password`: Restic repository encryption password

Then encrypt it:
```bash
ansible-vault encrypt ~/.vault/vault.yaml --vault-password-file ~/.vault/vault-pass
```

---

## 3. Apply the Site Playbook

### 3.1 S3 Credentials Handling

Do **not** manually create or scp `s3.json`. `playbooks/apply/seaweedfs-s3-apply.yml` creates `/etc/seaweedfs`, renders `s3.json` from the vaulted `restic_aws_access_key_id` / `restic_aws_secret_access_key`, and mounts it into SeaweedFS when `-e seaweedfs_s3_config_path=/etc/seaweedfs/s3.json` is passed.

Manual `/tmp/s3.json` handling leaks secrets into shell history/temp files and fails on fresh hosts before `/etc/seaweedfs` exists.

### 3.2 Execute complete site rollout

Deploy the core code while skipping `keycloak` and `pam-oidc-sshd`:

```bash
ansible-playbook -e "ansible_python_interpreter=/usr/bin/python3" \
  playbooks/site.yml -i /tmp/pilot-delivery-test/inventory.yml \
  -e @~/.vault/vault.yaml --vault-password-file ~/.vault/vault-pass \
  -e freeipa_server_ip=${IPA_IP} \
  -e siem_forward_host=${WEB1_IP} \
  -e wazuh_manager_host=${WEB1_IP} \
  -e restic_s3_target_host=${WEB1_IP} \
  -e seaweedfs_s3_config_path=/etc/seaweedfs/s3.json \
  -e prometheus_site_label=site-test \
  -e thanos_s3_target_host=${WEB1_IP} \
  --skip-tags "keycloak,keycloak-db,keycloak-idp,pam,oidc,pam-oidc-sshd"
```

> **NOTE**: The `seaweedfs_s3_config_path` parameter tells `seaweedfs-s3-apply.yml` to render and start SeaweedFS with the credentials file, enabling signed S3 requests that restic requires. Do not omit it when `restic-backup` is in the inventory.

---

## 4. Post-Deployment Verification

### 4.1 Verification 1: FreeIPA Authentication & Sudo Rules (Allow & Deny)

1. Run the fixtures playbook on the FreeIPA server (`ipa-1`) to configure `pilotuser`:
   ```bash
   ansible-playbook -e "ansible_python_interpreter=/usr/bin/python3" \
     playbooks/test/fixtures/freeipa-client-fixtures.yml \
     -i /tmp/pilot-delivery-test/inventory.yml \
     -e @~/.vault/vault.yaml --vault-password-file ~/.vault/vault-pass
   ```

2. Enable the newly created sudo rule on the FreeIPA server (use the password from `vault.yaml`):
   ```bash
   IPA_IP=$(go run ./cmd/pilot vm-target list | grep ipa-1 | awk '{print $3}')
   # Read password from vault and enable sudo rule
   IPA_ADMIN_PWD=$(ansible-vault view ~/.vault/vault.yaml --vault-password-file ~/.vault/vault-pass 2>/dev/null | grep '^ipa_admin_password:' | awk -F'"' '{print $2}')
   go run ./cmd/pilot vm-target exec --name ipa-1 -- sh -c "printf %s \"${IPA_ADMIN_PWD}\" | kinit admin@IPA.PILOT.INTERNAL && ipa sudorule-enable pilot-all"
   ```

3. Test **Authorized Sudo** on the client (`web-2`):
   ```bash
   go run ./cmd/pilot vm-target exec --name web-2 -- bash -c "sudo runuser -u pilotuser -- sudo -n id"
   # Expected Output: uid=0(root) gid=0(root) groups=0(root)
   ```

4. Create and test an **Unauthorized User** on the client (`web-2`):
   ```bash
   # Add user to server (use password from vault):
   IPA_ADMIN_PWD=$(ansible-vault view ~/.vault/vault.yaml --vault-password-file ~/.vault/vault-pass 2>/dev/null | grep '^ipa_admin_password:' | awk -F'"' '{print $2}')
   go run ./cmd/pilot vm-target exec --name ipa-1 -- sh -c "printf %s \"${IPA_ADMIN_PWD}\" | kinit admin@IPA.PILOT.INTERNAL && ipa user-add denieduser --first=Denied --last=User"

   # Test sudo on client (should be denied):
   go run ./cmd/pilot vm-target exec --name web-2 -- bash -c "sudo runuser -u denieduser -- sudo -n id"
   # Expected Output: sudo: a password is required (fails/exits non-zero)
   ```

### 4.2 Verification 2: Metric Shipping

1. **Prometheus Deployment**: Prometheus requires `prometheus_site_label` to be set. To deploy Prometheus:
   ```bash
   ansible-playbook -e "ansible_python_interpreter=/usr/bin/python3" \
     playbooks/apply/prometheus-apply.yml -i /tmp/pilot-delivery-test/inventory.yml \
     -e @~/.vault/vault.yaml --vault-password-file ~/.vault/vault-pass \
     -e seaweedfs_s3_config_path=/etc/seaweedfs/s3.json \
     -e prometheus_site_label=site-test \
     -e thanos_s3_target_host=${WEB1_IP}
   ```

2. **Query Prometheus** (after deployment):
   ```bash
   go run ./cmd/pilot vm-target exec --name web-1 -- curl -fsS http://localhost:9090/api/v1/query?query=up
   # Expected Output: {"status":"success","data":{"resultType":"vector","result":[...]}}
   ```

### 4.3 Verification 3: Config Backup to S3 (SeaweedFS via Restic)

After `site.yml` completes successfully, verify restic snapshots exist:
```bash
# Check web-2 for snapshots
go run ./cmd/pilot vm-target exec --name web-2 -- bash -c "sudo sh -c '. /etc/pilot/restic-env && restic snapshots'"
# Expected Output: lists at least 1 backup snapshot of path `/etc`
```

> **If restic fails with `ciphertext verification failed`**: This means the S3 bucket was previously initialized with a different password, or an older playbook allowed multiple hosts to race through `restic init` on the same fresh repository. Fix the playbook to initialize the repository once, then delete the disposable test bucket and re-run `site.yml`.
>
> To delete and recreate the bucket:
> ```bash
> WEB1_IP=$(go run ./cmd/pilot vm-target list | grep 'web-1 ' | awk '{print $3}')
> # Delete bucket via SeaweedFS S3 API (use credentials from s3.json)
> go run ./cmd/pilot vm-target exec --name web-1 -- curl -s -X DELETE \
>   -H "x-amz-access-key-id: your-access-key" \
>   -H "x-amz-secret-access-key: your-secret-key" \
>   "http://localhost:8333/pilot-restic-backup?force=true"
> # Then re-run site.yml to re-initialize everything cleanly
> ```

### 4.4 Verification 4: Wazuh File Integrity Monitoring (FIM)

1. Create a dummy file in the monitored `/etc` directory on the client (`web-2`):
   ```bash
   go run ./cmd/pilot vm-target exec --name web-2 -- sudo touch /etc/wazuh_test_fim_trigger
   ```

2. Wait a few seconds for the alert to propagate, then check the Wazuh Manager alerts log on `web-1`:
   ```bash
   go run ./cmd/pilot vm-target exec --name web-1 -- sudo docker exec single-node-wazuh.manager-1 tail -n 200 /var/ossec/logs/alerts/alerts.log | grep wazuh_test_fim_trigger
   # Expected Output: File '/etc/wazuh_test_fim_trigger' added
   ```

---

## 5. Cleanup

Always clean up the VMs when testing is complete to free up host resources:
```bash
go run ./cmd/pilot vm-target down --name web-2
go run ./cmd/pilot vm-target down --name web-1
go run ./cmd/pilot vm-target down --name ipa-1
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `restic-backup` fails with `Signed request requires setting up SeaweedFS S3 authentication` | `seaweedfs_s3_config_path` was omitted or SeaweedFS started without the rendered identity config | Pass `-e seaweedfs_s3_config_path=/etc/seaweedfs/s3.json` so `seaweedfs-s3-apply.yml` renders and mounts `s3.json`, then re-run `site.yml` |
| `restic-backup` fails with `ciphertext verification failed` | Either the bucket was initialized with a different `restic_password`, or multiple hosts raced to initialize the same fresh repository | Ensure `restic-backup-apply.yml` has single-host repository initialization, then delete/recreate the test bucket and re-run `site.yml` |
| `preflight` fails with `Permission denied (publickey)` | Wrong SSH key used | Use pilot VM-specific key: `/var/lib/libvirt/images/pilot/<name>/id_ed25519` |
| `prometheus-apply.yml` fails with `prometheus_site_label is required` | Missing required variable | Add `-e prometheus_site_label=site-test` to the command |
| FreeIPA sudo test fails with `user does not exist` | Wrong shell used to run `sudo runuser` | Use `bash -c "sudo runuser -u pilotuser -- sudo -n id"` (SSH escape issue with `sudo runuser` via `pilot exec`) |
| FreeIPA sudo test says `User pilotuser is not allowed` | Client sudo policy cache or SSSD sudo provider did not converge | Confirm `/etc/nsswitch.conf` has `sudoers: files sss`, `/etc/sssd/sssd.conf` has `services = nss, pam, ssh, sudo` and `sudo_provider = ipa`, then restart SSSD / run `sss_cache -E` if available |
